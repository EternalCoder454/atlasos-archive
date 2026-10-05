//! The staging audit (docs/DESIGN.md, "Extraction rules"): what is actually
//! in a staging folder, whoever wrote it (the libarchive writer, `7z`,
//! `unrar`, or a compromised worker), brought back in line with the
//! extraction rules before anything moves out.
//!
//! The walk describes staging as archive entries and builds a `Tree` from
//! them, so the same rules decide: anything but files, folders and links
//! goes; a link that escapes, or a hard link to a file outside, goes; a name
//! that isn't its own disk form is renamed to it; setuid, setgid and sticky
//! bits go, the umask applies, launchers lose their execute bits.
//!
//! Run it only once whatever wrote staging has exited: nothing may change
//! between the walk and the fixes, nor between the audit and the move.

use std::collections::{HashMap, VecDeque};
use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;

use crate::name::{self, NameEncoding};
use crate::path::{self, MAX_DEPTH, MAX_PATH_BYTES};
use crate::proto::{Entry, Format, Kind};
use crate::tree::{MAX_NODES, ROOT, Tree};

/// What the audit removed, for the report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Removed {
    /// The path as found, in display form.
    pub path: String,
    pub reason: String,
}

/// Staging, audited.
pub struct Audit {
    /// What stays, with `lone_top` for the move out.
    pub tree: Tree,
    pub removed: Vec<Removed>,
    /// Items renamed to their disk form.
    pub renamed: u32,
}

impl Audit {
    /// The disk names at the top of staging: what moves out.
    pub fn top_level(&self) -> Vec<String> {
        self.tree.nodes[ROOT as usize]
            .children
            .iter()
            .map(|&c| self.tree.nodes[c as usize].name.disk.clone())
            .collect()
    }
}

/// One item found in staging.
struct Found {
    /// Relative to staging, as on disk.
    path: Vec<u8>,
    /// The name, as on disk.
    name: Vec<u8>,
    /// The folder it is in (`None`: staging itself).
    parent: Option<usize>,
    depth: usize,
    kind: Kind,
    st: libc::stat,
    link: Option<Vec<u8>>,
}

const RESOLVE: u64 = libc::RESOLVE_BENEATH
    | libc::RESOLVE_NO_SYMLINKS
    | libc::RESOLVE_NO_MAGICLINKS
    | libc::RESOLVE_NO_XDEV;

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

fn cstring(bytes: &[u8]) -> io::Result<CString> {
    CString::new(bytes).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))
}

fn check(r: libc::c_int) -> io::Result<()> {
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Opens the folder `path` (relative; empty for staging itself) below
/// `staging`, never through a link.
fn open_dir(staging: BorrowedFd<'_>, path: &[u8]) -> io::Result<OwnedFd> {
    let c = cstring(if path.is_empty() { b"." } else { path })?;
    let how = OpenHow {
        flags: (libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC) as u64,
        mode: 0,
        resolve: RESOLVE,
    };
    loop {
        // SAFETY: valid descriptor, C string and open_how of the right size.
        let fd = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                staging.as_raw_fd(),
                c.as_ptr(),
                &how as *const OpenHow,
                std::mem::size_of::<OpenHow>(),
            )
        };
        if fd >= 0 {
            // SAFETY: a new descriptor we own.
            return Ok(unsafe { OwnedFd::from_raw_fd(fd as i32) });
        }
        let e = io::Error::last_os_error();
        if e.kind() != io::ErrorKind::Interrupted {
            return Err(e);
        }
    }
}

/// The items in the folder `dir`, with their `lstat` and link targets.
fn read_dir(dir: OwnedFd) -> io::Result<Vec<(Vec<u8>, libc::stat, Option<Vec<u8>>)>> {
    let raw = dir.as_raw_fd();
    // SAFETY: fdopendir takes over the descriptor (closed by closedir).
    let dp = unsafe { libc::fdopendir(raw) };
    if dp.is_null() {
        return Err(io::Error::last_os_error());
    }
    std::mem::forget(dir);
    let mut out = Vec::new();
    let result = loop {
        // SAFETY: errno is thread-local; readdir sets it only on error.
        unsafe { *libc::__errno_location() = 0 };
        // SAFETY: a valid DIR stream.
        let ent = unsafe { libc::readdir64(dp) };
        if ent.is_null() {
            let e = io::Error::last_os_error();
            break if e.raw_os_error() == Some(0) {
                Ok(())
            } else {
                Err(e)
            };
        }
        // SAFETY: d_name is NUL-terminated within the entry.
        let name = unsafe { std::ffi::CStr::from_ptr((*ent).d_name.as_ptr()) };
        if matches!(name.to_bytes(), b"." | b"..") {
            continue;
        }
        let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: the stream's descriptor, a C string, a stat buffer.
        if unsafe {
            libc::fstatat(
                raw,
                name.as_ptr(),
                st.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } < 0
        {
            break Err(io::Error::last_os_error());
        }
        // SAFETY: filled by the successful call.
        let st = unsafe { st.assume_init() };
        let link = if st.st_mode & libc::S_IFMT == libc::S_IFLNK {
            let mut buf = vec![0u8; MAX_PATH_BYTES + 1];
            // SAFETY: buffer of the given length.
            let n =
                unsafe { libc::readlinkat(raw, name.as_ptr(), buf.as_mut_ptr().cast(), buf.len()) };
            if n < 0 {
                break Err(io::Error::last_os_error());
            }
            buf.truncate(n as usize);
            Some(buf)
        } else {
            None
        };
        out.push((name.to_bytes().to_vec(), st, link));
    };
    // SAFETY: the stream opened above, closed once.
    unsafe { libc::closedir(dp) };
    result.map(|()| out)
}

fn too_many() -> io::Error {
    io::Error::other("The extracted folder holds more items than Atlas Archive can check.")
}

/// Every item below staging, breadth first, one descriptor open at a time.
fn walk(staging: BorrowedFd<'_>) -> io::Result<Vec<Found>> {
    let mut found: Vec<Found> = Vec::new();
    let mut queue: VecDeque<Option<usize>> = VecDeque::from([None]);
    while let Some(dir) = queue.pop_front() {
        let (dir_path, depth) = dir.map_or((Vec::new(), 0), |i| {
            (found[i].path.clone(), found[i].depth + 1)
        });
        let fd = open_dir(staging, &dir_path)?;
        for (name, st, link) in read_dir(fd)? {
            if found.len() >= MAX_NODES {
                return Err(too_many());
            }
            let mut path = dir_path.clone();
            if !path.is_empty() {
                path.push(b'/');
            }
            path.extend_from_slice(&name);
            if depth >= MAX_DEPTH || path.len() > MAX_PATH_BYTES {
                return Err(io::Error::other(
                    "The extracted folder nests deeper than Atlas Archive can check.",
                ));
            }
            let kind = match st.st_mode & libc::S_IFMT {
                libc::S_IFREG => Kind::File,
                libc::S_IFDIR => Kind::Dir,
                libc::S_IFLNK => Kind::Symlink,
                _ => Kind::Special,
            };
            if kind == Kind::Dir {
                if st.st_mode & 0o700 != 0o700 {
                    // Ours, but locked: the owner gets in again.
                    let parent = open_dir(staging, &dir_path)?;
                    let c = cstring(&name)?;
                    // SAFETY: valid descriptor and C string; a folder, so
                    // no link is followed.
                    check(unsafe {
                        libc::fchmodat(
                            parent.as_raw_fd(),
                            c.as_ptr(),
                            (st.st_mode & 0o777) | 0o700,
                            0,
                        )
                    })?;
                }
                queue.push_back(Some(found.len()));
            }
            found.push(Found {
                path,
                name,
                parent: dir,
                depth,
                kind,
                st,
                link,
            });
        }
    }
    Ok(found)
}

/// The name is already what the extraction rules would write.
fn is_disk_form(name: &[u8]) -> bool {
    std::str::from_utf8(name).is_ok_and(|s| {
        path::parse(name, NameEncoding::Utf8, false)
            .is_ok_and(|p| p.components.len() == 1 && !p.dir_hint && p.components[0].disk == s)
    })
}

fn shown(path: &[u8]) -> String {
    name::display_text(&String::from_utf8_lossy(path))
}

fn is_launcher_bytes(name: &[u8]) -> bool {
    name::is_launcher(&String::from_utf8_lossy(name))
}

fn file_mode(st: &libc::stat, umask: u32, launcher: bool) -> u32 {
    let m = (st.st_mode & 0o777 & !umask) | 0o600;
    if launcher { m & !0o111 } else { m }
}

/// Audits `staging` (see the module comment). An error leaves staging half
/// fixed: the caller must then delete it, never move it out.
pub fn audit(staging: BorrowedFd<'_>, umask: u32) -> io::Result<Audit> {
    let found = walk(staging)?;
    let mut removed = Vec::new();
    let mut drop_it = vec![None::<String>; found.len()];

    // Hard links: every name of a file must be in staging, or a fix below
    // (a mode) would reach a file outside.
    let mut inodes: HashMap<(u64, u64), Vec<usize>> = HashMap::new();
    for (i, f) in found.iter().enumerate() {
        if f.kind == Kind::File && f.st.st_nlink > 1 {
            inodes
                .entry((f.st.st_dev, f.st.st_ino))
                .or_default()
                .push(i);
        }
    }
    for names in inodes.values() {
        if (names.len() as u64) < found[names[0]].st.st_nlink {
            for &i in names {
                drop_it[i] = Some("It is linked to a file outside the extracted folder.".into());
            }
        }
    }

    // Entries: names already in disk form first, so they keep their names
    // and any clash numbers the others.
    let mut order: Vec<usize> = (0..found.len()).filter(|&i| drop_it[i].is_none()).collect();
    order.sort_by_key(|&i| !is_disk_form(&found[i].name));
    // A hard link names an earlier entry: the first name in that order is
    // the file, the others link to it.
    let mut position = vec![usize::MAX; found.len()];
    for (p, &i) in order.iter().enumerate() {
        position[i] = p;
    }
    let mut hardlink_to: HashMap<usize, usize> = HashMap::new();
    for names in inodes.values() {
        if drop_it[names[0]].is_some() {
            continue;
        }
        let first = *names
            .iter()
            .min_by_key(|&&i| position[i])
            .expect("not empty");
        for &i in names {
            if i != first {
                hardlink_to.insert(i, first);
            }
        }
    }
    let entries: Vec<Entry> = order
        .iter()
        .enumerate()
        .map(|(p, &i)| {
            let f = &found[i];
            let (kind, link) = match hardlink_to.get(&i) {
                Some(&to) => (Kind::Hardlink, Some(found[to].path.clone())),
                None => (f.kind, f.link.clone()),
            };
            Entry {
                // Entry order: a hard link must come after its file.
                index: p as u32,
                utf8: std::str::from_utf8(&f.path).is_ok(),
                path: f.path.clone(),
                kind,
                size: (f.kind == Kind::File).then_some(f.st.st_size as u64),
                packed: None,
                mtime: Some(f.st.st_mtime),
                mode: f.st.st_mode & 0o7777,
                encrypted: false,
                link,
            }
        })
        .collect();
    let format = Format {
        name: "folder".into(),
        encrypted: false,
        encrypted_names: false,
        solid: false,
        compressed_file: false,
        volumes: 1,
        made_on_dos: false,
        comment: None,
    };
    let tree = Tree::build(format, &entries, Some(NameEncoding::Utf8));
    let mut node_of = vec![None::<u32>; found.len()];
    for (id, n) in tree.nodes.iter().enumerate().skip(1) {
        if let Some(e) = n.entry {
            node_of[order[e as usize]] = Some(id as u32);
        }
    }
    for (i, slot) in drop_it.iter_mut().enumerate() {
        if slot.is_some() {
            continue;
        }
        match node_of[i].map(|n| &tree.nodes[n as usize]) {
            None => {
                let reason = tree
                    .skipped
                    .iter()
                    .find(|s| s.index as usize == position[i])
                    .map(|s| s.reason.clone());
                *slot = Some(reason.unwrap_or_else(|| "It breaks the extraction rules.".into()));
            }
            Some(n) if n.kind == Kind::Special || found[i].kind == Kind::Special => {
                *slot = Some("Devices, pipes and sockets are never extracted.".into());
            }
            Some(n) => {
                if let Some(r) = &n.refused {
                    *slot = Some(r.reason());
                }
            }
        }
    }

    // Removals first, so nothing removed is in a rename's way. Never a
    // folder: those always parse and are never refused, and unlinkat
    // without AT_REMOVEDIR fails on one, failing the audit.
    for (i, f) in found.iter().enumerate() {
        let Some(reason) = &drop_it[i] else { continue };
        let parent = open_dir(
            staging,
            f.parent.map_or(&[][..], |p| found[p].path.as_slice()),
        )?;
        let old = cstring(&f.name)?;
        // SAFETY: valid descriptor and C string.
        check(unsafe { libc::unlinkat(parent.as_raw_fd(), old.as_ptr(), 0) })?;
        removed.push(Removed {
            path: shown(&f.path),
            reason: reason.clone(),
        });
    }

    // Renames, deepest first, so a folder's path holds until its contents
    // are done.
    let mut by_depth: Vec<usize> = (0..found.len()).filter(|&i| drop_it[i].is_none()).collect();
    by_depth.sort_by_key(|&i| std::cmp::Reverse(found[i].depth));
    let mut renamed = 0;
    for i in by_depth {
        let f = &found[i];
        let Some(id) = node_of[i] else { continue };
        let new_name = tree.nodes[id as usize].name.disk.as_bytes();
        if new_name == f.name.as_slice() {
            continue;
        }
        let parent = open_dir(
            staging,
            f.parent.map_or(&[][..], |p| found[p].path.as_slice()),
        )?;
        let old = cstring(&f.name)?;
        let new = cstring(new_name)?;
        // SAFETY: valid descriptors and C strings.
        let r = unsafe {
            libc::renameat2(
                parent.as_raw_fd(),
                old.as_ptr(),
                parent.as_raw_fd(),
                new.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        };
        if r == 0 {
            renamed += 1;
            continue;
        }
        if f.kind == Kind::Dir {
            // One that can't be renamed fails the audit rather than stay
            // misnamed.
            return Err(io::Error::other(format!(
                "A folder couldn't be checked: {}.",
                shown(&f.path)
            )));
        }
        // SAFETY: valid descriptor and C string; flags 0: never a folder.
        check(unsafe { libc::unlinkat(parent.as_raw_fd(), old.as_ptr(), 0) })?;
        let reason = "Its name couldn't be made safe.".to_string();
        removed.push(Removed {
            path: shown(&f.path),
            reason: reason.clone(),
        });
        drop_it[i] = Some(reason);
    }

    // Modes, on the audited paths. A file's mode belongs to its inode: every
    // name of it that is left gets the same mode, a launcher's if any of its
    // names is one.
    let launchers: std::collections::HashSet<u32> = tree.launcher_files().into_iter().collect();
    let mut launcher_inodes: std::collections::HashSet<(u64, u64)> =
        std::collections::HashSet::new();
    for (i, f) in found.iter().enumerate() {
        let id = node_of[i].or_else(|| hardlink_to.get(&i).and_then(|&to| node_of[to]));
        if f.kind == Kind::File && id.is_some_and(|id| launchers.contains(&id))
            || f.kind == Kind::File && is_launcher_bytes(&f.name)
        {
            launcher_inodes.insert((f.st.st_dev, f.st.st_ino));
        }
    }
    for (i, f) in found.iter().enumerate() {
        let Some(id) = node_of[i] else { continue };
        if drop_it[i].is_some() {
            continue;
        }
        let want = match f.kind {
            Kind::File => file_mode(
                &f.st,
                umask,
                launcher_inodes.contains(&(f.st.st_dev, f.st.st_ino)),
            ),
            Kind::Dir => (f.st.st_mode & 0o777 & !umask) | 0o700,
            _ => continue,
        };
        if f.st.st_mode & 0o7777 == want {
            continue;
        }
        let n = &tree.nodes[id as usize];
        let parent = open_dir(staging, tree.disk_path(n.parent).as_bytes())?;
        let c = cstring(n.name.disk.as_bytes())?;
        // SAFETY: valid descriptor and C string. Nothing has changed since
        // the walk, so this is the file or folder it found, never a link.
        check(unsafe { libc::fchmodat(parent.as_raw_fd(), c.as_ptr(), want, 0) })?;
    }

    Ok(Audit {
        tree,
        removed,
        renamed,
    })
}

/// For callers holding a path (tests, the CLI's `--check-staging`).
pub fn audit_path(dir: &std::path::Path, umask: u32) -> io::Result<Audit> {
    let c = cstring(dir.as_os_str().as_bytes())?;
    // SAFETY: a C string; a new descriptor we own.
    let fd = unsafe {
        libc::open(
            c.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: as above.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    audit(std::os::fd::AsFd::as_fd(&fd), umask)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
    use std::path::{Path, PathBuf};

    struct Scratch(PathBuf);

    impl Scratch {
        fn new(tag: &str) -> Scratch {
            let base = std::env::var_os("ATLAS_ARCHIVE_TEST_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|| {
                    std::env::current_exe()
                        .unwrap()
                        .parent()
                        .unwrap()
                        .join("../test-scratch")
                });
            let p = base.join(format!("atlas-audit-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&p);
            std::fs::create_dir_all(p.join("staging")).unwrap();
            Scratch(p)
        }
        fn staging(&self) -> PathBuf {
            self.0.join("staging")
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn mode(p: &Path) -> u32 {
        std::fs::symlink_metadata(p).unwrap().permissions().mode() & 0o7777
    }

    #[test]
    fn a_clean_tree_is_left_alone() {
        let s = Scratch::new("clean");
        let st = s.staging();
        std::fs::create_dir_all(st.join("top/sub")).unwrap();
        std::fs::write(st.join("top/sub/f.txt"), b"x").unwrap();
        std::fs::set_permissions(st.join("top/sub/f.txt"), PermissionsExt::from_mode(0o644))
            .unwrap();
        symlink("sub/f.txt", st.join("top/l")).unwrap();
        std::fs::hard_link(st.join("top/sub/f.txt"), st.join("top/h")).unwrap();
        let a = audit_path(&st, 0o022).unwrap();
        assert!(a.removed.is_empty(), "{:?}", a.removed);
        assert_eq!(a.renamed, 0);
        assert_eq!(a.top_level(), ["top"]);
        assert_eq!(a.tree.lone_top, a.tree.find(["top"]));
        assert_eq!(
            std::fs::read_link(st.join("top/l")).unwrap(),
            Path::new("sub/f.txt")
        );
        assert_eq!(std::fs::metadata(st.join("top/h")).unwrap().nlink(), 2);
    }

    #[test]
    fn what_a_compromised_writer_leaves_is_fixed() {
        let s = Scratch::new("hostile");
        let st = s.staging();
        std::fs::create_dir_all(st.join("d")).unwrap();
        // Escaping links, absolute or relative.
        symlink("/etc/passwd", st.join("d/abs")).unwrap();
        symlink("../../outside", st.join("d/rel")).unwrap();
        // A launcher that would run, setuid, a FIFO.
        std::fs::write(st.join("d/run.desktop"), b"[Desktop Entry]").unwrap();
        std::fs::set_permissions(st.join("d/run.desktop"), PermissionsExt::from_mode(0o755))
            .unwrap();
        std::fs::write(st.join("d/suid"), b"x").unwrap();
        std::fs::set_permissions(st.join("d/suid"), PermissionsExt::from_mode(0o4755)).unwrap();
        let fifo = CString::new(st.join("d/fifo").as_os_str().as_bytes()).unwrap();
        // SAFETY: a C string.
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o644) }, 0);
        // A hard link to a file outside staging.
        std::fs::write(s.0.join("victim"), b"v").unwrap();
        std::fs::set_permissions(s.0.join("victim"), PermissionsExt::from_mode(0o755)).unwrap();
        std::fs::hard_link(s.0.join("victim"), st.join("d/x.desktop")).unwrap();
        // A name that isn't its disk form, and a locked folder.
        std::fs::write(st.join("d/bad\u{202E}txt.exe"), b"x").unwrap();
        std::fs::create_dir(st.join("locked")).unwrap();
        std::fs::write(st.join("locked/in"), b"x").unwrap();
        std::fs::set_permissions(st.join("locked"), PermissionsExt::from_mode(0o000)).unwrap();

        let a = audit_path(&st, 0o022).unwrap();
        let gone: Vec<&str> = a.removed.iter().map(|r| r.path.as_str()).collect();
        for p in ["d/abs", "d/rel", "d/fifo", "d/x.desktop"] {
            assert!(gone.contains(&p), "{p} not removed: {gone:?}");
            assert!(
                std::fs::symlink_metadata(st.join(p)).is_err(),
                "{p} still there"
            );
        }
        assert_eq!(mode(&st.join("d/run.desktop")), 0o644);
        assert_eq!(mode(&st.join("d/suid")), 0o755);
        assert_eq!(
            mode(&s.0.join("victim")),
            0o755,
            "the file outside is untouched"
        );
        assert_eq!(a.renamed, 1);
        assert!(st.join("d/badtxt.exe").exists());
        assert_eq!(mode(&st.join("locked")), 0o700);
        assert!(st.join("locked/in").exists());
        assert_eq!(a.tree.lone_top, None);
    }

    #[test]
    fn clashing_disk_forms_are_numbered() {
        let s = Scratch::new("clash");
        let st = s.staging();
        std::fs::write(st.join("a_"), b"1").unwrap();
        std::fs::write(st.join("a\u{1}"), b"2").unwrap();
        let a = audit_path(&st, 0o022).unwrap();
        assert!(a.removed.is_empty(), "{:?}", a.removed);
        assert_eq!(
            std::fs::read(st.join("a_")).unwrap(),
            b"1",
            "the clean name keeps its file"
        );
        let mut top = a.top_level();
        top.sort();
        assert_eq!(top.len(), 2);
        assert!(top.iter().all(|n| st.join(n).exists()), "{top:?}");
    }

    #[test]
    fn hard_links_keep_every_name_and_one_mode() {
        let s = Scratch::new("links");
        let st = s.staging();
        // The name needing a rename may come first in the walk; the link to
        // it must survive either way, and the setuid bit go from the inode.
        std::fs::write(st.join("bad\u{202E}name"), b"x").unwrap();
        std::fs::set_permissions(
            st.join("bad\u{202E}name"),
            PermissionsExt::from_mode(0o4755),
        )
        .unwrap();
        std::fs::hard_link(st.join("bad\u{202E}name"), st.join("plain")).unwrap();
        std::fs::hard_link(st.join("plain"), st.join("go.desktop")).unwrap();
        let a = audit_path(&st, 0o022).unwrap();
        assert!(a.removed.is_empty(), "{:?}", a.removed);
        assert_eq!(a.renamed, 1);
        assert!(st.join("badname").exists());
        let m = std::fs::metadata(st.join("plain")).unwrap();
        assert_eq!(m.nlink(), 3);
        assert_eq!(
            m.permissions().mode() & 0o7777,
            0o644,
            "no setuid, no exec: a launcher shares it"
        );
    }

    #[test]
    fn caps_hold() {
        let s = Scratch::new("deep");
        let mut p = s.staging();
        for _ in 0..(MAX_DEPTH + 1) {
            p.push("d");
        }
        std::fs::create_dir_all(&p).unwrap();
        assert!(audit_path(&s.staging(), 0o022).is_err());
    }
}
