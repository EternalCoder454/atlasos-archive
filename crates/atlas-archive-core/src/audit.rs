//! The staging audit (docs/DESIGN.md, "Extraction rules"): what is actually
//! in a staging folder, whoever wrote it (the libarchive writer, `7z`,
//! `unrar`, or a compromised worker), brought back in line with the
//! extraction rules before anything moves out.
//!
//! The walk describes staging as archive entries and builds a `Tree` from
//! them, so the same rules decide: anything but files, folders and links
//! goes; a link that escapes, or a hard link to a file outside, goes; a name
//! that isn't its own disk form is renamed to it; setuid, setgid and sticky
//! bits go, the umask applies, extended attributes (ACLs included) go, and
//! every name of a file that a launcher name reaches loses its execute bits.
//!
//! Run it only once whatever wrote staging, and everything that could have
//! started, has exited: the worker can't start processes (its seccomp
//! filter), and the client kills and reaps it first. Each fix still goes
//! through a descriptor checked to be the item the walk found, so a change
//! fails the audit instead of redirecting a fix.

use std::cmp::Reverse;
use std::collections::{HashMap, HashSet, VecDeque};
use std::ffi::{CStr, CString};
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;

use crate::name::{self, NameEncoding};
use crate::path::{self, MAX_DEPTH, MAX_PATH_BYTES};
use crate::proto::{Entry, Format, Kind};
use crate::tree::{MAX_NODES, ROOT, Tree};

/// The most path bytes the walk keeps, all items' paths together.
const MAX_PATH_TOTAL: usize = 256 << 20;
/// The one extended attribute left alone: the system's own label.
const KEPT_XATTR: &[u8] = b"security.selinux";

/// What the audit removed, for the report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Removed {
    /// The path as found, in display form.
    pub path: String,
    pub reason: String,
}

/// Staging, audited.
pub struct Audit {
    /// What is in staging now: every node is on disk under its name, none is
    /// refused. `lone_top` decides the move out.
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

/// One item found in staging. Its name is kept apart (`names`), as it
/// changes when renamed.
struct Found {
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

fn changed() -> io::Error {
    io::Error::other("The extracted files changed while they were being checked.")
}

fn too_many() -> io::Error {
    io::Error::other("The extracted folder holds more items than Atlas Archive can check.")
}

/// `openat2` below `dir` (`path` relative; empty for `dir` itself).
fn openat2(dir: BorrowedFd<'_>, path: &[u8], flags: i32, resolve: u64) -> io::Result<OwnedFd> {
    let c = cstring(if path.is_empty() { b"." } else { path })?;
    let how = OpenHow {
        flags: (flags | libc::O_CLOEXEC) as u64,
        mode: 0,
        resolve,
    };
    loop {
        // SAFETY: valid descriptor, C string and open_how of the right size.
        let fd = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                dir.as_raw_fd(),
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

/// The folder `path` below `staging`, never through a link.
fn open_dir(staging: BorrowedFd<'_>, path: &[u8]) -> io::Result<OwnedFd> {
    openat2(
        staging,
        path,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW,
        RESOLVE,
    )
}

/// The item `name` in the folder `dir` itself, as a handle (`O_PATH`):
/// opening it neither needs read rights nor touches a FIFO.
fn open_item(dir: BorrowedFd<'_>, name: &[u8]) -> io::Result<OwnedFd> {
    openat2(dir, name, libc::O_PATH | libc::O_NOFOLLOW, RESOLVE)
}

fn fstat(fd: BorrowedFd<'_>) -> io::Result<libc::stat> {
    let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: a valid descriptor and a stat buffer.
    check(unsafe { libc::fstat(fd.as_raw_fd(), st.as_mut_ptr()) })?;
    // SAFETY: filled by the successful call.
    Ok(unsafe { st.assume_init() })
}

/// The descriptor is the item the walk found.
fn same(fd: BorrowedFd<'_>, walked: &libc::stat) -> io::Result<()> {
    let st = fstat(fd)?;
    if st.st_dev == walked.st_dev
        && st.st_ino == walked.st_ino
        && st.st_mode & libc::S_IFMT == walked.st_mode & libc::S_IFMT
    {
        Ok(())
    } else {
        Err(changed())
    }
}

/// The item behind `fd` as a path the kernel resolves to that very inode,
/// for calls that take only paths (chmod and the xattr calls on `O_PATH`).
fn proc_path(fd: BorrowedFd<'_>) -> CString {
    CString::new(format!("/proc/self/fd/{}", fd.as_raw_fd())).expect("no NUL")
}

fn chmod_fd(fd: BorrowedFd<'_>, mode: u32) -> io::Result<()> {
    // SAFETY: a C string.
    check(unsafe { libc::chmod(proc_path(fd).as_ptr(), mode) })
}

/// Removes every extended attribute but the SELinux label: ACLs would
/// override the umask, and nothing extracted carries any.
fn strip_xattrs(fd: BorrowedFd<'_>) -> io::Result<()> {
    let p = proc_path(fd);
    // SAFETY: a C string; size 0 asks for the length.
    let n = unsafe { libc::listxattr(p.as_ptr(), std::ptr::null_mut(), 0) };
    if n < 0 {
        let e = io::Error::last_os_error();
        return if e.raw_os_error() == Some(libc::ENOTSUP) {
            Ok(())
        } else {
            Err(e)
        };
    }
    if n == 0 {
        return Ok(());
    }
    let mut buf = vec![0u8; n as usize];
    // SAFETY: a C string and a buffer of the given length.
    let n = unsafe { libc::listxattr(p.as_ptr(), buf.as_mut_ptr().cast(), buf.len()) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    buf.truncate(n as usize);
    for attr in buf.split(|&b| b == 0).filter(|a| !a.is_empty()) {
        if attr == KEPT_XATTR {
            continue;
        }
        let c = cstring(attr)?;
        // SAFETY: C strings.
        check(unsafe { libc::removexattr(p.as_ptr(), c.as_ptr()) })?;
    }
    Ok(())
}

type Listed = (Vec<u8>, libc::stat, Option<Vec<u8>>);

/// The items in the folder `dir`, with their `lstat` and link targets; at
/// most `budget` of them.
fn read_dir(dir: BorrowedFd<'_>, budget: usize) -> io::Result<Vec<Listed>> {
    let raw = dir.as_raw_fd();
    // SAFETY: plain fcntl; the copy is ours.
    let copy = unsafe { libc::fcntl(raw, libc::F_DUPFD_CLOEXEC, 0) };
    if copy < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fdopendir takes over the copy (closed by closedir).
    let dp = unsafe { libc::fdopendir(copy) };
    if dp.is_null() {
        let e = io::Error::last_os_error();
        // SAFETY: still ours.
        unsafe { libc::close(copy) };
        return Err(e);
    }
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
        let name = unsafe { CStr::from_ptr((*ent).d_name.as_ptr()) };
        if matches!(name.to_bytes(), b"." | b"..") {
            continue;
        }
        if out.len() >= budget {
            break Err(too_many());
        }
        let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: the folder's descriptor, a C string, a stat buffer.
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
            let mut buf = [0u8; MAX_PATH_BYTES + 1];
            // SAFETY: a buffer of the given length.
            let n =
                unsafe { libc::readlinkat(raw, name.as_ptr(), buf.as_mut_ptr().cast(), buf.len()) };
            if n < 0 {
                break Err(io::Error::last_os_error());
            }
            Some(buf[..n as usize].to_vec())
        } else {
            None
        };
        out.push((name.to_bytes().to_vec(), st, link));
    };
    // SAFETY: the stream opened above, closed once.
    unsafe { libc::closedir(dp) };
    result.map(|()| out)
}

/// The path of item `i` relative to staging, from the current names.
fn path_of(found: &[Found], names: &[Vec<u8>], i: usize) -> Vec<u8> {
    let mut chain = vec![i];
    while let Some(p) = found[*chain.last().expect("not empty")].parent {
        chain.push(p);
    }
    let mut path = Vec::new();
    for &c in chain.iter().rev() {
        if !path.is_empty() {
            path.push(b'/');
        }
        path.extend_from_slice(&names[c]);
    }
    path
}

/// Every item below staging, breadth first, with their names; one folder
/// open at a time.
fn walk(staging: BorrowedFd<'_>) -> io::Result<(Vec<Found>, Vec<Vec<u8>>)> {
    let mut found: Vec<Found> = Vec::new();
    let mut names: Vec<Vec<u8>> = Vec::new();
    let mut path_total = 0usize;
    let mut queue: VecDeque<Option<usize>> = VecDeque::from([None]);
    while let Some(dir) = queue.pop_front() {
        let (dir_path, depth) = match dir {
            None => (Vec::new(), 0),
            Some(i) => (path_of(&found, &names, i), found[i].depth + 1),
        };
        let fd = open_dir(staging, &dir_path)?;
        for (name, st, link) in read_dir(fd.as_fd(), MAX_NODES - found.len())? {
            let len = dir_path.len() + usize::from(!dir_path.is_empty()) + name.len();
            if depth >= MAX_DEPTH || len > MAX_PATH_BYTES {
                return Err(io::Error::other(
                    "The extracted folder nests deeper than Atlas Archive can check.",
                ));
            }
            path_total += len;
            if path_total > MAX_PATH_TOTAL {
                return Err(too_many());
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
                    let child = open_item(fd.as_fd(), &name)?;
                    same(child.as_fd(), &st)?;
                    chmod_fd(child.as_fd(), (st.st_mode & 0o777) | 0o700)?;
                }
                queue.push_back(Some(found.len()));
            }
            found.push(Found {
                parent: dir,
                depth,
                kind,
                st,
                link,
            });
            names.push(name);
        }
    }
    Ok((found, names))
}

/// The open folder of the last item asked for; items sorted by folder open
/// each folder once.
struct Folders {
    open: Option<(Option<usize>, OwnedFd)>,
}

impl Folders {
    fn new() -> Folders {
        Folders { open: None }
    }

    fn get<'a>(
        &'a mut self,
        staging: BorrowedFd<'_>,
        found: &[Found],
        names: &[Vec<u8>],
        dir: Option<usize>,
    ) -> io::Result<BorrowedFd<'a>> {
        if self.open.as_ref().is_none_or(|(d, _)| *d != dir) {
            let path = dir.map_or_else(Vec::new, |d| path_of(found, names, d));
            self.open = Some((dir, open_dir(staging, &path)?));
        }
        Ok(self.open.as_ref().expect("just set").1.as_fd())
    }
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

fn file_mode(st: &libc::stat, umask: u32, launcher: bool) -> u32 {
    let m = (st.st_mode & 0o777 & !umask) | 0o600;
    if launcher { m & !0o111 } else { m }
}

fn folder_format() -> Format {
    Format {
        name: "folder".into(),
        encrypted: false,
        encrypted_names: false,
        solid: false,
        compressed_file: false,
        volumes: 1,
        made_on_dos: false,
        comment: None,
    }
}

/// The items `order` lists as entries, in that order (an entry's index is
/// its place), with the paths of `names`.
fn entries(
    found: &[Found],
    names: &[Vec<u8>],
    order: &[usize],
    hardlink_to: &HashMap<usize, usize>,
) -> Vec<Entry> {
    order
        .iter()
        .enumerate()
        .map(|(p, &i)| {
            let f = &found[i];
            let path = path_of(found, names, i);
            let (kind, link) = match hardlink_to.get(&i) {
                Some(&to) => (Kind::Hardlink, Some(path_of(found, names, to))),
                None => (f.kind, f.link.clone()),
            };
            Entry {
                index: p as u32,
                utf8: std::str::from_utf8(&path).is_ok(),
                path,
                kind,
                size: (f.kind == Kind::File).then_some(f.st.st_size as u64),
                packed: None,
                mtime: Some(f.st.st_mtime),
                mode: f.st.st_mode & 0o7777,
                encrypted: false,
                link,
            }
        })
        .collect()
}

/// Audits `staging` (see the module comment). An error leaves staging half
/// fixed: the caller must then delete it, never move it out.
pub fn audit(staging: BorrowedFd<'_>, umask: u32) -> io::Result<Audit> {
    // Staging itself: the owner's alone while it is checked (the move out
    // gives the folder its final mode), with no ACL.
    // SAFETY: a valid descriptor.
    check(unsafe { libc::fchmod(staging.as_raw_fd(), 0o700) })?;
    strip_xattrs(staging)?;

    let (found, mut names) = walk(staging)?;
    let mut removed = Vec::new();
    let mut drop_it = vec![None::<String>; found.len()];

    // Hard links: every name of a file must be in staging, or a fix below
    // (a mode) would reach a file outside. Those go by every name first.
    let mut inodes: HashMap<(u64, u64), Vec<usize>> = HashMap::new();
    for (i, f) in found.iter().enumerate() {
        if f.kind == Kind::File && f.st.st_nlink > 1 {
            inodes
                .entry((f.st.st_dev, f.st.st_ino))
                .or_default()
                .push(i);
        }
    }
    for group in inodes.values() {
        #[allow(clippy::unnecessary_cast, clippy::useless_conversion)]
        let links = u64::from(found[group[0]].st.st_nlink);
        if (group.len() as u64) < links {
            for &i in group {
                drop_it[i] = Some("It is linked to a file outside the extracted folder.".into());
            }
        }
    }

    // Entries: names already in disk form first, so they keep their names
    // and any clash numbers the others.
    let mut order: Vec<usize> = (0..found.len()).filter(|&i| drop_it[i].is_none()).collect();
    // A path is in disk form when every folder on the way is too (the walk
    // lists folders before what is in them), or an entry inside a misnamed
    // folder would make it under the folder's disk name first.
    let mut disk_form = vec![false; found.len()];
    for i in 0..found.len() {
        disk_form[i] = found[i].parent.is_none_or(|p| disk_form[p]) && is_disk_form(&names[i]);
    }
    order.sort_by_key(|&i| !disk_form[i]);
    // A hard link names an earlier entry: the first name in that order is
    // the file, the others link to it.
    let mut position = vec![usize::MAX; found.len()];
    for (p, &i) in order.iter().enumerate() {
        position[i] = p;
    }
    let mut hardlink_to: HashMap<usize, usize> = HashMap::new();
    for group in inodes.values() {
        if drop_it[group[0]].is_some() {
            continue;
        }
        let first = *group
            .iter()
            .min_by_key(|&&i| position[i])
            .expect("not empty");
        for &i in group {
            if i != first {
                hardlink_to.insert(i, first);
            }
        }
    }
    let tree = Tree::build(
        folder_format(),
        &entries(&found, &names, &order, &hardlink_to),
        Some(NameEncoding::Utf8),
    );
    let mut node_of = vec![None::<u32>; found.len()];
    for (id, n) in tree.nodes.iter().enumerate().skip(1) {
        if let Some(e) = n.entry {
            node_of[order[e as usize]] = Some(id as u32);
        }
    }
    let skip_reason: HashMap<u32, &str> = tree
        .skipped
        .iter()
        .map(|s| (s.index, s.reason.as_str()))
        .collect();
    for (i, slot) in drop_it.iter_mut().enumerate() {
        if slot.is_some() {
            continue;
        }
        match node_of[i].map(|n| &tree.nodes[n as usize]) {
            None => {
                let reason = skip_reason.get(&(position[i] as u32));
                *slot = Some(
                    reason.map_or("It breaks the extraction rules.".into(), |r| r.to_string()),
                );
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
    // folder: folders always parse and are never refused, and unlinkat
    // without AT_REMOVEDIR fails on one, failing the audit.
    let mut gone: Vec<usize> = (0..found.len()).filter(|&i| drop_it[i].is_some()).collect();
    gone.sort_by_key(|&i| found[i].parent);
    let mut folders = Folders::new();
    for i in gone {
        let dir = folders.get(staging, &found, &names, found[i].parent)?;
        let c = cstring(&names[i])?;
        // SAFETY: a valid descriptor and C string.
        check(unsafe { libc::unlinkat(dir.as_raw_fd(), c.as_ptr(), 0) })?;
        removed.push(Removed {
            path: shown(&path_of(&found, &names, i)),
            reason: drop_it[i].clone().expect("dropped"),
        });
    }

    // Renames, folder by folder, deepest first (a folder's path holds until
    // its contents are done), each through a temporary name first so that
    // no order of clashing names can make one fail.
    let mut moves: Vec<usize> = (0..found.len())
        .filter(|&i| {
            drop_it[i].is_none()
                && node_of[i]
                    .is_some_and(|n| tree.nodes[n as usize].name.disk.as_bytes() != names[i])
        })
        .collect();
    moves.sort_by_key(|&i| (Reverse(found[i].depth), found[i].parent));
    let mut renamed = 0;
    let mut spare = 0u64;
    for group in moves.chunk_by(|&a, &b| found[a].parent == found[b].parent) {
        let dir = open_dir(
            staging,
            &found[group[0]]
                .parent
                .map_or_else(Vec::new, |d| path_of(&found, &names, d)),
        )?;
        let rename = |from: &CStr, to: &CStr| {
            // SAFETY: a valid descriptor and C strings.
            check(unsafe {
                libc::renameat2(
                    dir.as_raw_fd(),
                    from.as_ptr(),
                    dir.as_raw_fd(),
                    to.as_ptr(),
                    libc::RENAME_NOREPLACE,
                )
            })
        };
        let mut temps = Vec::with_capacity(group.len());
        for &i in group {
            let old = cstring(&names[i])?;
            let temp = loop {
                // Not a disk form, so never a name the audit keeps.
                let t = CString::new(format!("\u{1}atlas-audit-{spare}")).expect("no NUL");
                spare += 1;
                match rename(&old, &t) {
                    Ok(()) => break t,
                    Err(e) if e.raw_os_error() == Some(libc::EEXIST) && spare < 1 << 20 => {}
                    Err(e) => return Err(e),
                }
            };
            temps.push(temp);
        }
        for (&i, temp) in group.iter().zip(&temps) {
            let new = tree.nodes[node_of[i].expect("kept") as usize]
                .name
                .disk
                .as_bytes();
            rename(temp, &cstring(new)?)?;
            names[i] = new.to_vec();
            renamed += 1;
        }
    }

    // Launchers, by what is on disk now: every name of a file shares its
    // inode, and a launcher-named link reaches what the kernel would open
    // for it (never out of staging).
    let mut launchers: HashSet<(u64, u64)> = HashSet::new();
    for (i, f) in found.iter().enumerate() {
        if drop_it[i].is_some() || !name::is_launcher(&String::from_utf8_lossy(&names[i])) {
            continue;
        }
        match f.kind {
            Kind::File => {
                launchers.insert((f.st.st_dev, f.st.st_ino));
            }
            Kind::Symlink => {
                let target = openat2(
                    staging,
                    &path_of(&found, &names, i),
                    libc::O_PATH,
                    libc::RESOLVE_BENEATH | libc::RESOLVE_NO_MAGICLINKS | libc::RESOLVE_NO_XDEV,
                );
                if let Ok(fd) = target {
                    let st = fstat(fd.as_fd())?;
                    if st.st_mode & libc::S_IFMT == libc::S_IFREG {
                        launchers.insert((st.st_dev, st.st_ino));
                    }
                }
            }
            _ => {}
        }
    }

    // Modes and extended attributes, through a handle on each item checked
    // to be the one the walk found.
    let mut fix: Vec<usize> = (0..found.len())
        .filter(|&i| drop_it[i].is_none() && matches!(found[i].kind, Kind::File | Kind::Dir))
        .collect();
    fix.sort_by_key(|&i| found[i].parent);
    let mut folders = Folders::new();
    for i in fix {
        let f = &found[i];
        let dir = folders.get(staging, &found, &names, f.parent)?;
        let item = open_item(dir, &names[i])?;
        same(item.as_fd(), &f.st)?;
        let want = if f.kind == Kind::File {
            file_mode(
                &f.st,
                umask,
                launchers.contains(&(f.st.st_dev, f.st.st_ino)),
            )
        } else {
            (f.st.st_mode & 0o777 & !umask) | 0o700
        };
        if f.st.st_mode & 0o7777 != want {
            chmod_fd(item.as_fd(), want)?;
        }
        strip_xattrs(item.as_fd())?;
    }

    // What is left, as a tree of its own, so the caller sees only what is
    // on disk. Every name is a disk form now; anything this tree doesn't
    // take as it is means staging isn't what the audit made it.
    let kept: Vec<usize> = order
        .iter()
        .copied()
        .filter(|&i| drop_it[i].is_none())
        .collect();
    let hardlink_to: HashMap<usize, usize> = hardlink_to
        .into_iter()
        .filter(|&(i, to)| drop_it[i].is_none() && drop_it[to].is_none())
        .collect();
    let tree = Tree::build(
        folder_format(),
        &entries(&found, &names, &kept, &hardlink_to),
        Some(NameEncoding::Utf8),
    );
    let placed = tree.nodes.iter().filter(|n| n.entry.is_some()).count();
    if placed != kept.len()
        || !tree.skipped.is_empty()
        || tree.skipped_more > 0
        || tree.nodes.iter().any(|n| n.refused.is_some())
    {
        return Err(io::Error::other("The extracted files couldn't be checked."));
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
    audit(fd.as_fd(), umask)
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
    fn launchers_are_found_by_inode_and_on_disk() {
        let s = Scratch::new("launch");
        let st = s.staging();
        // One inode, named "a\x01" and "z.desktop\u{202E}" (a launcher only
        // once renamed), beside "a_", the disk form of the first name.
        std::fs::write(st.join("a\u{1}"), b"i").unwrap();
        std::fs::set_permissions(st.join("a\u{1}"), PermissionsExt::from_mode(0o755)).unwrap();
        std::fs::hard_link(st.join("a\u{1}"), st.join("z.desktop\u{202E}")).unwrap();
        std::fs::write(st.join("a_"), b"j").unwrap();
        std::fs::set_permissions(st.join("a_"), PermissionsExt::from_mode(0o755)).unwrap();
        // A launcher at the end of a chain of links.
        std::fs::write(st.join("t"), b"t").unwrap();
        std::fs::set_permissions(st.join("t"), PermissionsExt::from_mode(0o755)).unwrap();
        symlink("t", st.join("m")).unwrap();
        symlink("m", st.join("l.desktop")).unwrap();
        let a = audit_path(&st, 0o022).unwrap();
        assert!(a.removed.is_empty(), "{:?}", a.removed);
        assert_eq!(std::fs::read(st.join("z.desktop")).unwrap(), b"i");
        assert_eq!(mode(&st.join("z.desktop")), 0o644);
        assert_eq!(mode(&st.join("a_")), 0o755, "not a launcher");
        assert_eq!(mode(&st.join("t")), 0o644);
    }

    #[test]
    fn attributes_and_the_root_mode_are_reset() {
        let s = Scratch::new("xattr");
        let st = s.staging();
        std::fs::set_permissions(&st, PermissionsExt::from_mode(0o777)).unwrap();
        std::fs::create_dir(st.join("d")).unwrap();
        std::fs::write(st.join("d/f"), b"x").unwrap();
        let set = |p: &Path| {
            let c = CString::new(p.as_os_str().as_bytes()).unwrap();
            // SAFETY: C strings and a buffer of the given length.
            unsafe {
                libc::setxattr(
                    c.as_ptr(),
                    c"user.atlas".as_ptr(),
                    b"1".as_ptr().cast(),
                    1,
                    0,
                )
            }
        };
        let has = |p: &Path| {
            let c = CString::new(p.as_os_str().as_bytes()).unwrap();
            // SAFETY: as above; size 0 asks for the length.
            unsafe {
                libc::getxattr(c.as_ptr(), c"user.atlas".as_ptr(), std::ptr::null_mut(), 0) >= 0
            }
        };
        let xattrs = set(&st.join("d/f")) == 0 && set(&st.join("d")) == 0 && set(&st) == 0;
        audit_path(&st, 0o022).unwrap();
        assert_eq!(mode(&st), 0o700);
        if xattrs {
            assert!(!has(&st.join("d/f")) && !has(&st.join("d")) && !has(&st));
        }
    }

    #[test]
    fn clashing_renames_never_depend_on_order() {
        let s = Scratch::new("order");
        let st = s.staging();
        for k in 0..24 {
            std::fs::write(st.join(format!("x{k}")), b"f").unwrap();
            std::fs::create_dir(st.join(format!("x{k}\u{202E}"))).unwrap();
            std::fs::write(st.join(format!("x{k}\u{202E}/in")), b"i").unwrap();
        }
        let a = audit_path(&st, 0o022).unwrap();
        assert!(a.removed.is_empty(), "{:?}", a.removed);
        // A folder keeps the plain name (the tree's rule); every file and
        // folder survives whatever order the walk met them in.
        assert_eq!(a.renamed, 48);
        let top = a.top_level();
        assert_eq!(top.len(), 48);
        let (mut files, mut dirs) = (0, 0);
        for n in &top {
            let p = st.join(n);
            if p.is_dir() {
                assert_eq!(std::fs::read(p.join("in")).unwrap(), b"i", "{n}");
                dirs += 1;
            } else {
                assert_eq!(std::fs::read(&p).unwrap(), b"f", "{n}");
                files += 1;
            }
        }
        assert_eq!((files, dirs), (24, 24));
    }

    #[test]
    fn the_tree_holds_only_what_is_left() {
        let s = Scratch::new("left");
        let st = s.staging();
        std::fs::create_dir(st.join("only")).unwrap();
        std::fs::write(st.join("only/f"), b"x").unwrap();
        symlink("/etc/passwd", st.join("bad")).unwrap();
        let a = audit_path(&st, 0o022).unwrap();
        assert_eq!(a.removed.len(), 1);
        assert_eq!(a.top_level(), ["only"]);
        assert_eq!(a.tree.lone_top, a.tree.find(["only"]));
        assert!(a.tree.nodes.iter().all(|n| n.refused.is_none()));
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
