//! The extraction writer (docs/DESIGN.md, "Extraction rules").
//!
//! Everything is written below one descriptor, the staging folder, through
//! `openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS |
//! RESOLVE_NO_XDEV)`. Paths come from `core::tree`, already checked; the
//! kernel checks them again, so even a path the tree got wrong cannot leave
//! staging or pass through a link.
//!
//! Order: folders and files as the archive streams them (folders made 0700),
//! then hard links, then symbolic links, then folder modes and times, deepest
//! first. Files are created 0600 and get their mode and time when complete
//! (a cpio hard link's first name, empty until the data of the last name
//! comes, when it is complete).

use std::collections::{HashMap, HashSet};
use std::ffi::CString;
use std::fs::File;
use std::io::{self, Write};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd};

use atlas_archive_core::proto::Kind;
use atlas_archive_core::tree::{Moved, ROOT, Tree};

const RESOLVE: u64 = libc::RESOLVE_BENEATH
    | libc::RESOLVE_NO_SYMLINKS
    | libc::RESOLVE_NO_MAGICLINKS
    | libc::RESOLVE_NO_XDEV;

/// `struct open_how` (libc's is `non_exhaustive`).
#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

/// `openat2` below `dir` with the writer's resolve flags. `path` is relative.
fn openat2(dir: &OwnedFd, path: &str, flags: i32, mode: u32) -> io::Result<OwnedFd> {
    let c = cstr(if path.is_empty() { "." } else { path })?;
    let how = OpenHow {
        flags: (flags | libc::O_CLOEXEC) as u64,
        mode: mode.into(),
        resolve: RESOLVE,
    };
    loop {
        // SAFETY: valid C string and open_how of the size passed.
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

fn cstr(s: &str) -> io::Result<CString> {
    CString::new(s)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "a name holds a NUL byte"))
}

fn check(r: libc::c_int) -> io::Result<()> {
    if r == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn timespec(mtime: Option<i64>) -> [libc::timespec; 2] {
    let omit = libc::timespec {
        tv_sec: 0,
        tv_nsec: libc::UTIME_OMIT,
    };
    let m = match mtime {
        Some(s) => libc::timespec {
            tv_sec: s as libc::time_t,
            tv_nsec: 0,
        },
        None => omit,
    };
    [omit, m]
}

/// Errors that stop the whole job rather than one entry: the drive is full,
/// read-only or failing, so every later entry would fail the same way.
pub fn is_fatal(e: &io::Error) -> bool {
    matches!(
        e.raw_os_error(),
        Some(libc::ENOSPC | libc::EDQUOT | libc::EROFS | libc::EIO)
    )
}

/// What a drive says when it can't keep modes or times (FAT, some network and
/// FUSE file systems). The entry is still there, without them.
/// (`EOPNOTSUPP` is the same number as `ENOTSUP` on Linux.)
fn mode_unsupported(e: &io::Error) -> bool {
    matches!(
        e.raw_os_error(),
        Some(libc::EPERM | libc::ENOTSUP | libc::EINVAL)
    )
}

/// The process umask, read once while the worker is single-threaded.
pub fn read_umask() -> u32 {
    // SAFETY: umask has no failure; the old value is put straight back.
    unsafe {
        let old = libc::umask(0o077);
        libc::umask(old);
        old
    }
}

/// A file's final permissions: no setuid, setgid or sticky bit, the umask
/// applied, the owner's read and write kept.
pub fn file_mode(stored: u32, umask: u32) -> u32 {
    (stored & 0o777 & !umask) | 0o600
}

/// A folder's final permissions: as a file's, with the owner's search kept.
pub fn dir_mode(stored: u32, umask: u32) -> u32 {
    (stored & 0o777 & !umask) | 0o700
}

/// Why one entry couldn't be written, for the report; the job goes on.
#[derive(Debug)]
pub struct EntryFailed {
    pub node: u32,
    pub error: io::Error,
}

/// Writes one tree into a staging folder.
pub struct Writer {
    staging: OwnedFd,
    umask: u32,
    /// Folders made (node ids), for their modes at the end.
    dirs: Vec<u32>,
    made: HashSet<u32>,
    /// Regular files written completely (node ids): hard link targets.
    files: HashSet<u32>,
    /// Files complete but for their mode and time, which wait for data that
    /// comes later (writing it would change the time): given at the end if
    /// no data came.
    meta_pending: HashSet<u32>,
    failed: Vec<EntryFailed>,
    /// Said once that the drive keeps no modes or times.
    mode_logged: bool,
}

impl Writer {
    pub fn new(staging: OwnedFd, umask: u32) -> Writer {
        Writer {
            staging,
            umask,
            dirs: Vec::new(),
            made: HashSet::new(),
            files: HashSet::new(),
            meta_pending: HashSet::new(),
            failed: Vec::new(),
            mode_logged: false,
        }
    }

    /// `fchmod` and `futimens` results: a drive that can't keep modes or
    /// times is no reason to stop; anything else (a full or failing drive)
    /// is. Logged once per job, without a path.
    fn lenient(&mut self, r: io::Result<()>) -> io::Result<()> {
        match r {
            Err(e) if mode_unsupported(&e) => {
                if !self.mode_logged {
                    self.mode_logged = true;
                    crate::log_line!(
                        "the drive keeps no modes or times (errno {}); going on without",
                        e.raw_os_error().unwrap_or(0)
                    );
                }
                Ok(())
            }
            r => r,
        }
    }

    /// Makes the folder `id` and every folder above it.
    pub fn dir(&mut self, tree: &Tree, id: u32) -> io::Result<()> {
        if id == ROOT || self.made.contains(&id) {
            return Ok(());
        }
        let node = &tree.nodes[id as usize];
        debug_assert_eq!(node.kind, Kind::Dir);
        self.dir(tree, node.parent)?;
        let parent = openat2(
            &self.staging,
            &tree.disk_path(node.parent),
            libc::O_PATH | libc::O_DIRECTORY,
            0,
        )?;
        let name = cstr(&node.name.disk)?;
        // SAFETY: valid descriptor and C string.
        match check(unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) }) {
            Ok(()) => {}
            // Made already by this run: the tree has one node per path, so an
            // existing folder here is ours unless the file system folds case.
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                openat2(
                    &self.staging,
                    &tree.disk_path(id),
                    libc::O_PATH | libc::O_DIRECTORY,
                    0,
                )?;
            }
            Err(e) => return Err(e),
        }
        self.made.insert(id);
        self.dirs.push(id);
        Ok(())
    }

    /// Creates the regular file `id` (and its folders) for writing.
    /// `declared`: the size the archive states, when it does; writing more is
    /// refused as a corrupt entry.
    pub fn file(&mut self, tree: &Tree, id: u32, declared: Option<u64>) -> io::Result<FileOut> {
        let node = &tree.nodes[id as usize];
        debug_assert_eq!(node.kind, Kind::File);
        self.dir(tree, node.parent)?;
        let fd = openat2(
            &self.staging,
            &tree.disk_path(id),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW,
            0o600,
        )?;
        Ok(FileOut {
            file: File::from(fd),
            id,
            written: 0,
            declared,
        })
    }

    /// Completes a file: mode and time, then the close, whose error counts
    /// (network and FUSE drives report a full disk or a failed write there),
    /// then the size check. Only a complete file is a hard link target. On
    /// `Err` the file is closed and still on disk: the caller removes it.
    pub fn finish_file(&mut self, tree: &Tree, out: FileOut) -> io::Result<()> {
        self.complete(tree, out, false)
    }

    /// As `finish_file`, but the mode and time are left for later: more data
    /// is to come into this file (`reopen`), which would change the time. If
    /// none does, `finish` gives them.
    pub fn finish_file_for_data_to_come(&mut self, tree: &Tree, out: FileOut) -> io::Result<()> {
        self.complete(tree, out, true)
    }

    fn complete(&mut self, tree: &Tree, out: FileOut, defer_meta: bool) -> io::Result<()> {
        let node = &tree.nodes[out.id as usize];
        let FileOut {
            file,
            id,
            written,
            declared,
        } = out;
        let fd = file.as_raw_fd();
        let meta = if defer_meta {
            Ok(())
        } else {
            self.meta_pending.remove(&id);
            self.set_meta(fd, node.mode, node.mtime)
        };
        let closed = close_checked(file);
        // A full or failing drive outranks anything else that went wrong.
        match (meta, closed) {
            (_, Err(e)) if is_fatal(&e) => return Err(e),
            (Err(e), _) | (_, Err(e)) => return Err(e),
            _ => {}
        }
        if declared.is_some_and(|d| written != d) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "the item holds less data than the archive says it does",
            ));
        }
        if defer_meta {
            self.meta_pending.insert(id);
        }
        self.files.insert(id);
        Ok(())
    }

    /// A file's final mode and time, on its descriptor.
    fn set_meta(&mut self, fd: i32, mode: u32, mtime: Option<i64>) -> io::Result<()> {
        // SAFETY: valid descriptor; times array of two.
        let r = check(unsafe { libc::fchmod(fd, file_mode(mode, self.umask)) });
        self.lenient(r)?;
        let r = check(unsafe { libc::futimens(fd, timespec(mtime).as_ptr()) });
        self.lenient(r)
    }

    /// Whether node `id` is a regular file written completely.
    pub fn is_written(&self, id: u32) -> bool {
        self.files.contains(&id)
    }

    /// Whether node `id` is a complete file still waiting for the data that
    /// comes with a later name of it (`finish_file_for_data_to_come`).
    pub fn is_pending(&self, id: u32) -> bool {
        self.meta_pending.contains(&id)
    }

    /// Opens the finished, empty file `id` again, to write the data that came
    /// with another name of it (cpio keeps the data of a set of hard links
    /// with the last). `declared`: as for `file`.
    pub fn reopen(&mut self, tree: &Tree, id: u32, declared: Option<u64>) -> io::Result<FileOut> {
        let fd = openat2(
            &self.staging,
            &tree.disk_path(id),
            libc::O_WRONLY | libc::O_TRUNC | libc::O_NOFOLLOW,
            0,
        )?;
        Ok(FileOut {
            file: File::from(fd),
            id,
            written: 0,
            declared,
        })
    }

    /// Follows a node the tree moved to make room for a folder: renames what
    /// was written at its old path, if anything was.
    pub fn moved(&mut self, tree: &Tree, m: &Moved) -> io::Result<()> {
        let node = &tree.nodes[m.node as usize];
        let (from_dir, from_name) = m.from.rsplit_once('/').unwrap_or(("", &m.from));
        let dir = openat2(&self.staging, from_dir, libc::O_PATH | libc::O_DIRECTORY, 0)?;
        let from = cstr(from_name)?;
        let to = cstr(&node.name.disk)?;
        // SAFETY: valid descriptor and C strings. Same folder: a move only
        // renames within it.
        let r = unsafe {
            libc::renameat2(
                dir.as_raw_fd(),
                from.as_ptr(),
                dir.as_raw_fd(),
                to.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        };
        match check(r) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            r => r,
        }
    }

    /// Removes what was written for an entry the archive stores again.
    pub fn replace(&mut self, tree: &Tree, id: u32) -> io::Result<()> {
        self.files.remove(&id);
        self.meta_pending.remove(&id);
        self.unlink(tree, id)
    }

    /// Unlinks the node's path (never a folder); gone already is fine.
    fn unlink(&mut self, tree: &Tree, id: u32) -> io::Result<()> {
        let node = &tree.nodes[id as usize];
        let dir = openat2(
            &self.staging,
            &tree.disk_path(node.parent),
            libc::O_PATH | libc::O_DIRECTORY,
            0,
        )?;
        let name = cstr(&node.name.disk)?;
        // SAFETY: valid descriptor and C string. Never a folder (flags 0).
        match check(unsafe { libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), 0) }) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            r => r,
        }
    }

    /// Records an entry that failed; the job goes on with the next one.
    pub fn failed(&mut self, node: u32, error: io::Error) {
        self.failed.push(EntryFailed { node, error });
    }

    /// Makes hard links, then symbolic links, then gives folders their modes
    /// and times. Links are made only for entries in `selected` (every one
    /// when `None`). Returns the entries that failed; an error that says the
    /// drive is full, read-only or failing (`is_fatal`) is returned at once.
    /// `step` is called after each item made, so the caller can report
    /// progress: there can be a million of them.
    pub fn finish(
        &mut self,
        tree: &Tree,
        selected: Option<&HashSet<u32>>,
        step: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<Vec<EntryFailed>> {
        let chosen = |n: &atlas_archive_core::tree::Node| {
            selected.is_none_or(|set| n.entry.is_some_and(|i| set.contains(&i)))
        };
        // Files that were to get more data and never did.
        let mut pending: Vec<u32> = std::mem::take(&mut self.meta_pending).into_iter().collect();
        pending.sort_unstable();
        for id in pending {
            if !self.files.contains(&id) {
                continue;
            }
            let node = &tree.nodes[id as usize];
            let r = openat2(
                &self.staging,
                &tree.disk_path(id),
                libc::O_RDONLY | libc::O_NOFOLLOW,
                0,
            )
            .and_then(|fd| self.set_meta(fd.as_raw_fd(), node.mode, node.mtime));
            if let Err(e) = r {
                if is_fatal(&e) {
                    return Err(e);
                }
                self.failed(id, e);
            }
        }
        for (id, n) in tree.nodes.iter().enumerate() {
            let id = id as u32;
            if n.refused.is_some() || !chosen(n) {
                continue;
            }
            let r = match (n.kind, n.hardlink, &n.symlink) {
                (Kind::Hardlink, Some(to), _) if self.files.contains(&to) => {
                    self.hardlink(tree, id, to)
                }
                (Kind::Hardlink, _, _) => Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "the file it links to wasn't extracted",
                )),
                _ => continue,
            };
            if let Err(e) = r {
                if is_fatal(&e) {
                    return Err(e);
                }
                self.failed(id, e);
            }
            step()?;
        }
        for (id, n) in tree.nodes.iter().enumerate() {
            let id = id as u32;
            if n.refused.is_some() || n.kind != Kind::Symlink || !chosen(n) {
                continue;
            }
            let Some(target) = &n.symlink else { continue };
            if let Err(e) = self.symlink(tree, id, &target.disk) {
                if is_fatal(&e) {
                    return Err(e);
                }
                self.failed(id, e);
            }
            step()?;
        }
        // Launchers never run: their files lose the execute bits, whatever
        // name reached them (folders are still writable here). Every file
        // written under a launcher name is stripped too, whatever the tree
        // says about how it is reached. A file that can't be stripped is
        // removed: never leave a launcher that runs.
        let mut launchers = tree.launcher_files();
        launchers.extend(self.files.iter().copied().filter(|&id| {
            atlas_archive_core::name::is_launcher(&tree.nodes[id as usize].name.disk)
        }));
        launchers.sort_unstable();
        launchers.dedup();
        // Every name of a file, by the node holding its data: built when a
        // strip first fails (rare), then reused.
        let mut names: Option<HashMap<u32, Vec<u32>>> = None;
        for id in launchers {
            if !self.files.contains(&id) {
                continue;
            }
            let r = openat2(
                &self.staging,
                &tree.disk_path(id),
                libc::O_RDONLY | libc::O_NOFOLLOW,
                0,
            )
            .and_then(|fd| {
                let mode = file_mode(tree.nodes[id as usize].mode, self.umask) & !0o111;
                // SAFETY: valid descriptor.
                let r = check(unsafe { libc::fchmod(fd.as_raw_fd(), mode) });
                match r {
                    // A drive that keeps no modes (FAT, exFAT) shows every
                    // file as executable or none: if none is, it is as safe
                    // as stripped.
                    Err(e) if mode_unsupported(&e) && !has_execute_bit(&fd)? => Ok(()),
                    r => r,
                }
            });
            if let Err(e) = r {
                // Every name of it: the hard links made above share the
                // mode that couldn't be fixed.
                let names = names.get_or_insert_with(|| {
                    let mut m: HashMap<u32, Vec<u32>> = HashMap::new();
                    for (link, n) in tree.nodes.iter().enumerate() {
                        if let (Kind::Hardlink, Some(to)) = (n.kind, n.hardlink) {
                            m.entry(to).or_default().push(link as u32);
                        }
                    }
                    m
                });
                for &link in names.get(&id).map_or(&[][..], Vec::as_slice) {
                    self.unlink(tree, link)?;
                }
                self.unlink(tree, id)?;
                self.files.remove(&id);
                self.failed(id, e);
            }
            step()?;
        }
        // Deepest first: a folder made read-only must not stop its children.
        let mut dirs = std::mem::take(&mut self.dirs);
        dirs.sort_by_cached_key(|&d| std::cmp::Reverse(depth(tree, d)));
        for d in dirs {
            let n = &tree.nodes[d as usize];
            let fd = openat2(
                &self.staging,
                &tree.disk_path(d),
                libc::O_RDONLY | libc::O_DIRECTORY,
                0,
            )?;
            // SAFETY: valid descriptor; times array of two.
            let r = self
                .lenient(check(unsafe {
                    libc::fchmod(fd.as_raw_fd(), dir_mode(n.mode, self.umask))
                }))
                .and_then(|()| {
                    self.lenient(check(unsafe {
                        libc::futimens(fd.as_raw_fd(), timespec(n.mtime).as_ptr())
                    }))
                });
            if let Err(e) = r {
                if is_fatal(&e) {
                    return Err(e);
                }
                self.failed(d, e);
            }
            step()?;
        }
        Ok(std::mem::take(&mut self.failed))
    }

    /// The root's children that exist in staging, by disk name.
    pub fn top_level(&self, tree: &Tree) -> Vec<String> {
        tree.nodes[ROOT as usize]
            .children
            .iter()
            .map(|&c| &tree.nodes[c as usize].name.disk)
            .filter(|name| {
                let Ok(c) = cstr(name) else { return false };
                let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
                // SAFETY: valid descriptor, C string and stat buffer.
                unsafe {
                    libc::fstatat(
                        self.staging.as_raw_fd(),
                        c.as_ptr(),
                        st.as_mut_ptr(),
                        libc::AT_SYMLINK_NOFOLLOW,
                    ) == 0
                }
            })
            .cloned()
            .collect()
    }

    fn hardlink(&mut self, tree: &Tree, id: u32, to: u32) -> io::Result<()> {
        let n = &tree.nodes[id as usize];
        self.dir(tree, n.parent)?;
        let from_dir = openat2(
            &self.staging,
            &tree.disk_path(tree.nodes[to as usize].parent),
            libc::O_PATH | libc::O_DIRECTORY,
            0,
        )?;
        let to_dir = openat2(
            &self.staging,
            &tree.disk_path(n.parent),
            libc::O_PATH | libc::O_DIRECTORY,
            0,
        )?;
        let from = cstr(&tree.nodes[to as usize].name.disk)?;
        let name = cstr(&n.name.disk)?;
        // SAFETY: valid descriptors and C strings. Flags 0: a symlink at the
        // source is linked itself, never followed.
        check(unsafe {
            libc::linkat(
                from_dir.as_raw_fd(),
                from.as_ptr(),
                to_dir.as_raw_fd(),
                name.as_ptr(),
                0,
            )
        })
    }

    fn symlink(&mut self, tree: &Tree, id: u32, target: &str) -> io::Result<()> {
        let n = &tree.nodes[id as usize];
        self.dir(tree, n.parent)?;
        let dir = openat2(
            &self.staging,
            &tree.disk_path(n.parent),
            libc::O_PATH | libc::O_DIRECTORY,
            0,
        )?;
        let target = cstr(target)?;
        let name = cstr(&n.name.disk)?;
        // SAFETY: valid descriptor and C strings.
        check(unsafe { libc::symlinkat(target.as_ptr(), dir.as_raw_fd(), name.as_ptr()) })
    }
}

/// Whether the file on `fd` has any execute permission bit.
fn has_execute_bit(fd: &OwnedFd) -> io::Result<bool> {
    let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: valid descriptor and stat buffer; initialised on success.
    check(unsafe { libc::fstat(fd.as_raw_fd(), st.as_mut_ptr()) })?;
    let st = unsafe { st.assume_init() };
    Ok(st.st_mode & 0o111 != 0)
}

/// Closes `file` and reports the error, which `drop` would lose.
fn close_checked(file: File) -> io::Result<()> {
    let fd = file.into_raw_fd();
    // SAFETY: the descriptor is ours and closed once; Linux releases it even
    // when close fails, so it is never retried.
    if unsafe { libc::close(fd) } == 0 {
        return Ok(());
    }
    let e = io::Error::last_os_error();
    if e.raw_os_error() == Some(libc::EINTR) {
        Ok(())
    } else {
        Err(e)
    }
}

fn depth(tree: &Tree, mut id: u32) -> u32 {
    let mut d = 0;
    while id != ROOT {
        id = tree.nodes[id as usize].parent;
        d += 1;
    }
    d
}

/// A file being written. Counts its bytes; more than the declared size is an
/// error.
pub struct FileOut {
    file: File,
    id: u32,
    written: u64,
    declared: Option<u64>,
}

impl FileOut {
    pub fn written(&self) -> u64 {
        self.written
    }
}

impl Write for FileOut {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let after = self.written.saturating_add(buf.len() as u64);
        if self.declared.is_some_and(|d| after > d) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "the item holds more data than the archive says it does",
            ));
        }
        let n = self.file.write(buf)?;
        self.written += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

/// Opens a folder as the writer's root (tests and the worker's start).
pub fn open_dir(path: &std::path::Path) -> io::Result<OwnedFd> {
    use std::os::unix::ffi::OsStrExt;
    let c = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "a path holds a NUL byte"))?;
    // SAFETY: valid C string.
    let fd = unsafe {
        libc::open(
            c.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a new descriptor we own.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use atlas_archive_core::proto::{Entry, Format};
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::path::{Path, PathBuf};

    struct Scratch(PathBuf);

    impl Scratch {
        fn new(tag: &str) -> Scratch {
            // On disk, in the cargo target dir, never in tmpfs.
            let base = std::env::var_os("ATLAS_ARCHIVE_TEST_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|| {
                    std::env::current_exe()
                        .unwrap()
                        .parent()
                        .unwrap()
                        .join("../test-scratch")
                });
            let p = base.join(format!("atlas-archive-test-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&p);
            std::fs::create_dir_all(&p).unwrap();
            Scratch(p)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn fmt() -> Format {
        Format {
            name: "tar".into(),
            encrypted: false,
            encrypted_names: false,
            solid: true,
            compressed_file: false,
            volumes: 1,
            made_on_dos: false,
            comment: None,
        }
    }

    fn e(index: u32, path: &str, kind: Kind, mode: u32, link: Option<&str>) -> Entry {
        Entry {
            index,
            path: path.as_bytes().to_vec(),
            kind,
            size: Some(5),
            packed: None,
            mtime: Some(1_000_000_000),
            mode,
            encrypted: false,
            utf8: true,
            link: link.map(|l| l.as_bytes().to_vec()),
        }
    }

    /// Writes a tree the way the worker does: files and folders in archive
    /// order, then `finish`.
    fn extract(dir: &Path, entries: &[Entry]) -> Vec<EntryFailed> {
        let tree = Tree::build(fmt(), entries, None);
        let mut w = Writer::new(open_dir(dir).unwrap(), 0o022);
        for (id, n) in tree.nodes.iter().enumerate().skip(1) {
            let id = id as u32;
            if n.refused.is_some() {
                continue;
            }
            match n.kind {
                Kind::Dir => w.dir(&tree, id).unwrap(),
                Kind::File => {
                    let mut out = w.file(&tree, id, Some(5)).unwrap();
                    out.write_all(b"hello").unwrap();
                    w.finish_file(&tree, out).unwrap();
                }
                _ => {}
            }
        }
        w.finish(&tree, None, &mut || Ok(())).unwrap()
    }

    #[test]
    fn drives_without_modes_are_tolerated_and_full_ones_are_not() {
        for errno in [libc::EPERM, libc::ENOTSUP, libc::EOPNOTSUPP, libc::EINVAL] {
            assert!(mode_unsupported(&io::Error::from_raw_os_error(errno)));
            assert!(!is_fatal(&io::Error::from_raw_os_error(errno)));
        }
        for errno in [libc::ENOSPC, libc::EDQUOT, libc::EROFS, libc::EIO] {
            assert!(!mode_unsupported(&io::Error::from_raw_os_error(errno)));
            assert!(is_fatal(&io::Error::from_raw_os_error(errno)));
        }
        assert!(!mode_unsupported(&io::Error::from_raw_os_error(
            libc::EACCES
        )));
        let s = Scratch::new("lenient");
        let mut w = Writer::new(open_dir(&s.0).unwrap(), 0o022);
        assert!(
            w.lenient(Err(io::Error::from_raw_os_error(libc::EPERM)))
                .is_ok()
        );
        assert!(w.mode_logged);
        assert_eq!(
            w.lenient(Err(io::Error::from_raw_os_error(libc::ENOSPC)))
                .unwrap_err()
                .raw_os_error(),
            Some(libc::ENOSPC)
        );
    }

    #[test]
    fn a_short_file_is_an_error_and_not_a_link_target() {
        let s = Scratch::new("short");
        let tree = Tree::build(
            fmt(),
            &[
                e(0, "f", Kind::File, 0o644, None),
                e(1, "g", Kind::File, 0o644, None),
            ],
            None,
        );
        let mut w = Writer::new(open_dir(&s.0).unwrap(), 0o022);
        let mut out = w.file(&tree, 1, Some(5)).unwrap();
        out.write_all(b"hel").unwrap();
        let err = w.finish_file(&tree, out).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(!is_fatal(&err));
        assert!(!w.files.contains(&1));
        let mut out = w.file(&tree, 2, Some(5)).unwrap();
        out.write_all(b"hello").unwrap();
        w.finish_file(&tree, out).unwrap();
        assert!(w.files.contains(&2));
    }

    #[test]
    fn writes_files_folders_and_modes() {
        let s = Scratch::new("modes");
        let failed = extract(
            &s.0,
            &[
                e(0, "a/b/c.txt", Kind::File, 0o4755, None),
                e(1, "a/ro/", Kind::Dir, 0o555, None),
                e(2, "a/ro/x", Kind::File, 0o000, None),
            ],
        );
        assert!(failed.is_empty(), "{failed:?}");
        let m = std::fs::metadata(s.0.join("a/b/c.txt")).unwrap();
        assert_eq!(m.permissions().mode() & 0o7777, 0o755, "setuid dropped");
        assert_eq!(m.mtime(), 1_000_000_000);
        assert_eq!(std::fs::read(s.0.join("a/b/c.txt")).unwrap(), b"hello");
        let x = std::fs::metadata(s.0.join("a/ro/x")).unwrap();
        assert_eq!(
            x.permissions().mode() & 0o777,
            0o600,
            "owner keeps read and write"
        );
        let ro = std::fs::metadata(s.0.join("a/ro")).unwrap();
        assert_eq!(ro.permissions().mode() & 0o777, 0o755);
    }

    #[test]
    fn launchers_lose_their_execute_bits() {
        let s = Scratch::new("launchers");
        let failed = extract(
            &s.0,
            &[
                e(0, "app.desktop", Kind::File, 0o755, None),
                e(1, "run", Kind::File, 0o755, None),
                e(2, "Open me.desktop", Kind::Symlink, 0o777, Some("run")),
                e(3, "tool", Kind::File, 0o755, None),
            ],
        );
        assert!(failed.is_empty(), "{failed:?}");
        for (name, mode) in [("app.desktop", 0o644), ("run", 0o644), ("tool", 0o755)] {
            assert_eq!(
                std::fs::metadata(s.0.join(name))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                mode,
                "{name}"
            );
        }
    }

    #[test]
    fn a_launcher_that_cannot_be_stripped_is_removed() {
        let s = Scratch::new("failclosed");
        let outside = Scratch::new("failclosed-outside");
        let tree = Tree::build(
            fmt(),
            &[
                e(0, "x.desktop", Kind::File, 0o755, None),
                e(1, "y", Kind::Hardlink, 0o755, Some("x.desktop")),
            ],
            None,
        );
        let mut w = Writer::new(open_dir(&s.0).unwrap(), 0o022);
        let mut out = w.file(&tree, 1, Some(5)).unwrap();
        out.write_all(b"hello").unwrap();
        w.finish_file(&tree, out).unwrap();
        // Something swaps the file for a link: opening it for the strip fails.
        let victim = outside.0.join("victim");
        std::fs::write(&victim, b"v").unwrap();
        std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::remove_file(s.0.join("x.desktop")).unwrap();
        std::os::unix::fs::symlink(&victim, s.0.join("x.desktop")).unwrap();
        let failed = w.finish(&tree, None, &mut || Ok(())).unwrap();
        assert_eq!(failed.len(), 1, "{failed:?}");
        assert!(std::fs::symlink_metadata(s.0.join("x.desktop")).is_err());
        assert!(
            std::fs::symlink_metadata(s.0.join("y")).is_err(),
            "its other names go too"
        );
        let m = std::fs::metadata(&victim).unwrap();
        assert_eq!(m.permissions().mode() & 0o777, 0o755, "never followed");
    }

    #[test]
    fn only_selected_links_are_made() {
        let s = Scratch::new("selected");
        let entries = [
            e(0, "f", Kind::File, 0o644, None),
            e(1, "hard", Kind::Hardlink, 0o644, Some("f")),
            e(2, "sym", Kind::Symlink, 0o777, Some("f")),
            e(3, "other/sym2", Kind::Symlink, 0o777, Some("../f")),
        ];
        let tree = Tree::build(fmt(), &entries, None);
        let mut w = Writer::new(open_dir(&s.0).unwrap(), 0o022);
        let mut out = w.file(&tree, tree.find(["f"]).unwrap(), Some(5)).unwrap();
        out.write_all(b"hello").unwrap();
        w.finish_file(&tree, out).unwrap();
        let selected: HashSet<u32> = [0, 2].into();
        assert!(
            w.finish(&tree, Some(&selected), &mut || Ok(()))
                .unwrap()
                .is_empty()
        );
        assert!(s.0.join("f").is_file());
        assert!(std::fs::symlink_metadata(s.0.join("sym")).is_ok());
        assert!(std::fs::symlink_metadata(s.0.join("hard")).is_err());
        assert!(
            std::fs::symlink_metadata(s.0.join("other")).is_err(),
            "no folder made for an unselected link"
        );
    }

    #[test]
    fn links_are_made_last_and_checked() {
        let s = Scratch::new("links");
        let failed = extract(
            &s.0,
            &[
                e(0, "f", Kind::File, 0o644, None),
                e(1, "hard", Kind::Hardlink, 0o644, Some("f")),
                e(2, "sub/rel", Kind::Symlink, 0o777, Some("../f")),
                e(3, "abs", Kind::Symlink, 0o777, Some("/etc/passwd")),
                e(4, "fifo", Kind::Special, 0o644, None),
            ],
        );
        assert!(failed.is_empty(), "{failed:?}");
        assert_eq!(
            std::fs::metadata(s.0.join("hard")).unwrap().ino(),
            std::fs::metadata(s.0.join("f")).unwrap().ino()
        );
        assert_eq!(
            std::fs::read_link(s.0.join("sub/rel")).unwrap(),
            Path::new("../f")
        );
        assert!(
            std::fs::symlink_metadata(s.0.join("abs")).is_err(),
            "refused links are not made"
        );
        assert!(
            std::fs::symlink_metadata(s.0.join("fifo")).is_err(),
            "no FIFOs"
        );
    }

    #[test]
    fn symlink_then_file_lands_inside() {
        let s = Scratch::new("slip");
        let outside = Scratch::new("slip-outside");
        let target = outside.0.to_str().unwrap().to_string();
        let failed = extract(
            &s.0,
            &[
                e(0, "l", Kind::Symlink, 0o777, Some(&target)),
                e(1, "l/pwned", Kind::File, 0o644, None),
            ],
        );
        assert!(failed.is_empty(), "{failed:?}");
        assert!(s.0.join("l/pwned").is_file(), "written in a real folder");
        assert!(
            std::fs::read_dir(&outside.0).unwrap().next().is_none(),
            "nothing outside"
        );
    }

    #[test]
    fn the_kernel_refuses_what_the_tree_would_miss() {
        // A symlink planted in staging by someone else is never followed.
        let s = Scratch::new("kernel");
        let outside = Scratch::new("kernel-outside");
        std::os::unix::fs::symlink(&outside.0, s.0.join("d")).unwrap();
        let tree = Tree::build(fmt(), &[e(0, "d/x", Kind::File, 0o644, None)], None);
        let mut w = Writer::new(open_dir(&s.0).unwrap(), 0o022);
        let id = tree.find(["d", "x"]).unwrap();
        assert!(w.file(&tree, id, None).is_err());
        assert!(std::fs::read_dir(&outside.0).unwrap().next().is_none());
    }

    #[test]
    fn one_pass_follows_moves_and_replacements() {
        use atlas_archive_core::name::NameEncoding;
        use atlas_archive_core::tree::Added;
        let s = Scratch::new("onepass");
        let mut tree = Tree::new(fmt(), NameEncoding::Utf8);
        let mut w = Writer::new(open_dir(&s.0).unwrap(), 0o022);
        let entries = [
            e(0, "x", Kind::File, 0o644, None),
            e(1, "x/y", Kind::File, 0o644, None),
            e(2, "x/y", Kind::File, 0o644, None),
        ];
        for (i, en) in entries.iter().enumerate() {
            let Added::Node {
                id,
                moved,
                replaced,
            } = tree.add(en)
            else {
                panic!()
            };
            if let Some(m) = moved {
                w.moved(&tree, &m).unwrap();
            }
            if replaced.is_some() {
                w.replace(&tree, id).unwrap();
            }
            let mut out = w.file(&tree, id, None).unwrap();
            write!(out, "v{i}").unwrap();
            w.finish_file(&tree, out).unwrap();
        }
        tree.finish();
        assert!(w.finish(&tree, None, &mut || Ok(())).unwrap().is_empty());
        assert_eq!(std::fs::read(s.0.join("x (2)")).unwrap(), b"v0");
        assert_eq!(std::fs::read(s.0.join("x/y")).unwrap(), b"v2");
    }

    #[test]
    fn more_than_declared_is_refused() {
        let s = Scratch::new("declared");
        let tree = Tree::build(fmt(), &[e(0, "f", Kind::File, 0o644, None)], None);
        let mut w = Writer::new(open_dir(&s.0).unwrap(), 0o022);
        let mut out = w.file(&tree, 1, Some(3)).unwrap();
        assert!(out.write_all(b"hello").is_err());
    }
}
