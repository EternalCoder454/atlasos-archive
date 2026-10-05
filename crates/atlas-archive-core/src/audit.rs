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

/// The most path bytes the walk looks at, all items' paths together: a bound
/// on its work. Nothing holds them all at once: a path is built for one
/// entry at a time, as the tree takes it, and dropped.
const MAX_PATH_TOTAL: usize = 256 << 20;
/// The most link target bytes the audit holds, all links together: symlink
/// targets as the walk reads them, and the target path of every hard link
/// (each tree keeps a copy until it is finished, a kept symlink a few
/// more), so this bounds the client's memory against a staging folder of a
/// million long links.
const MAX_LINK_TOTAL: usize = 64 << 20;
/// The longest path the kernel resolves is `PATH_MAX` - 1 bytes (the NUL
/// counts); a longer one is refused by the walk, as nesting too deep.
const MAX_PATH_LEN: usize = 4095;
/// How many removals `Audit::removed` lists; the rest are only counted.
pub const MAX_REMOVED_LISTED: usize = 1000;
/// The longest path shown in a report, in bytes.
const MAX_SHOWN: usize = 1024;
/// Tries for a temporary name that is taken.
const TEMP_TRIES: u32 = 8;
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
    /// The first `MAX_REMOVED_LISTED` removals.
    pub removed: Vec<Removed>,
    /// Removals past those listed in `removed`, counted only.
    pub removed_more: usize,
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

/// A sentence the audit made for the user. It is its own error type so the
/// client can tell it from an OS error or any other `io::Error` by type, not
/// by how the text looks. It may hold archive names (cleaned for display).
#[derive(Debug)]
pub struct AuditMessage(String);

impl std::fmt::Display for AuditMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for AuditMessage {}

pub(crate) fn message(words: impl Into<String>) -> io::Error {
    io::Error::other(AuditMessage(words.into()))
}

fn failed_check() -> io::Error {
    message("The extracted files couldn't be checked.")
}

fn changed() -> io::Error {
    message("The extracted files changed while they were being checked.")
}

fn too_many() -> io::Error {
    message("The extracted folder holds more items than Atlas Archive can check.")
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

/// `chmod` by the handle. On a file system that keeps no modes (`modes_kept`
/// false: FAT, CIFS, SSHFS and other FUSE mounts, which answer EPERM, ENOTSUP
/// or EINVAL; ENOTSUP is EOPNOTSUPP on Linux) a refusal is no error: there is no mode to fix. Where modes are
/// kept, any failure is one.
fn chmod_fd(fd: BorrowedFd<'_>, mode: u32, modes_kept: bool) -> io::Result<()> {
    // SAFETY: a C string.
    let r = check(unsafe { libc::chmod(proc_path(fd).as_ptr(), mode) });
    match r {
        Err(e)
            if !modes_kept
                && matches!(
                    e.raw_os_error(),
                    Some(libc::EPERM | libc::ENOTSUP | libc::EINVAL)
                ) =>
        {
            Ok(())
        }
        r => r,
    }
}

/// The audit was cancelled (`stop` said so): not a failure of the files.
fn stopped() -> io::Error {
    io::Error::new(io::ErrorKind::Interrupted, "the audit was cancelled")
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
/// `links_left`: the symlink target bytes still allowed, spent as each
/// target is read, so one folder of long links can't fill memory first.
fn read_dir(dir: BorrowedFd<'_>, budget: usize, links_left: &mut usize) -> io::Result<Vec<Listed>> {
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
            let Some(left) = links_left.checked_sub(n as usize) else {
                break Err(too_many());
            };
            *links_left = left;
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

/// The length of `path_of(found, names, i)`, without building it.
fn path_len(found: &[Found], names: &[Vec<u8>], i: usize) -> usize {
    let mut len = names[i].len();
    let mut at = found[i].parent;
    while let Some(p) = at {
        len += names[p].len() + 1;
        at = found[p].parent;
    }
    len
}

/// Fails when the hard links' target paths, which a tree holds until it is
/// finished, would pass what is left of the link budget.
fn hardlinks_fit(
    found: &[Found],
    names: &[Vec<u8>],
    hardlink_to: &HashMap<usize, usize>,
    links_left: usize,
) -> io::Result<()> {
    let mut left = links_left;
    for &to in hardlink_to.values() {
        left = left
            .checked_sub(path_len(found, names, to))
            .ok_or_else(too_many)?;
    }
    Ok(())
}

/// Every item below staging, breadth first, with their names; one folder
/// open at a time.
fn walk(
    staging: BorrowedFd<'_>,
    links_left: &mut usize,
    modes_kept: bool,
    stop: &dyn Fn() -> bool,
) -> io::Result<(Vec<Found>, Vec<Vec<u8>>)> {
    let mut found: Vec<Found> = Vec::new();
    let mut names: Vec<Vec<u8>> = Vec::new();
    let mut path_total = 0usize;
    let mut queue: VecDeque<Option<usize>> = VecDeque::from([None]);
    while let Some(dir) = queue.pop_front() {
        if stop() {
            return Err(stopped());
        }
        let (dir_path, depth) = match dir {
            None => (Vec::new(), 0),
            Some(i) => (path_of(&found, &names, i), found[i].depth + 1),
        };
        let fd = open_dir(staging, &dir_path)?;
        for (name, st, link) in read_dir(fd.as_fd(), MAX_NODES - found.len(), links_left)? {
            let len = dir_path.len() + usize::from(!dir_path.is_empty()) + name.len();
            if depth >= MAX_DEPTH || len > MAX_PATH_LEN {
                return Err(message(
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
                    chmod_fd(child.as_fd(), (st.st_mode & 0o777) | 0o700, modes_kept)?;
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

/// A path as shown in a report: safe to display, and short.
fn shown(path: &[u8]) -> String {
    let mut s = name::display_text(&String::from_utf8_lossy(path));
    if s.len() > MAX_SHOWN {
        let mut end = MAX_SHOWN;
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        s.truncate(end);
        s.push('\u{2026}');
    }
    s
}

/// A random 64-bit number for this audit's temporary names, so no name in
/// staging can be made to match one.
fn nonce() -> io::Result<u64> {
    let mut buf = [0u8; 8];
    loop {
        // SAFETY: a buffer of the given length.
        let n = unsafe { libc::getrandom(buf.as_mut_ptr().cast(), buf.len(), 0) };
        if n == buf.len() as isize {
            return Ok(u64::from_le_bytes(buf));
        }
        let e = io::Error::last_os_error();
        if n >= 0 || e.kind() != io::ErrorKind::Interrupted {
            return Err(if n >= 0 {
                io::Error::other("short getrandom")
            } else {
                e
            });
        }
    }
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

/// Entry `p` of the listing `order` (an entry's index is its place), with
/// the paths of `names`.
fn entry_at(
    found: &[Found],
    names: &[Vec<u8>],
    order: &[usize],
    hardlink_to: &HashMap<usize, usize>,
    p: usize,
) -> Entry {
    let i = order[p];
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
}

/// The tree of the items `order` lists, one entry built at a time (with its
/// full path) and dropped once placed, so the paths never exist together.
fn build_tree(
    found: &[Found],
    names: &[Vec<u8>],
    order: &[usize],
    hardlink_to: &HashMap<usize, usize>,
) -> Tree {
    let mut tree = Tree::new(folder_format(), NameEncoding::Utf8);
    for p in 0..order.len() {
        tree.add(&entry_at(found, names, order, hardlink_to, p));
    }
    tree.finish();
    tree
}

/// Audits `staging` (see the module comment). An error leaves staging half
/// fixed: the caller must then delete it, never move it out.
pub fn audit(staging: BorrowedFd<'_>, umask: u32) -> io::Result<Audit> {
    audit_with(staging, umask, true, &|| false)
}

/// `audit`, asking `stop` between folders and every few hundred items: when
/// it says yes the audit ends with an `ErrorKind::Interrupted` error (and
/// staging is half fixed, as after any error).
pub fn audit_with(
    staging: BorrowedFd<'_>,
    umask: u32,
    modes_kept: bool,
    stop: &dyn Fn() -> bool,
) -> io::Result<Audit> {
    audit_fd(staging, umask, modes_kept, stop).map_err(|e| {
        // A rename to a longer disk form (an invalid byte becomes U+FFFD)
        // can push a name or path past the kernel's limits.
        if e.raw_os_error() == Some(libc::ENAMETOOLONG) {
            message("A name in the extracted files is too long to check.")
        } else {
            e
        }
    })
}

fn audit_fd(
    staging: BorrowedFd<'_>,
    umask: u32,
    modes_kept: bool,
    stop: &dyn Fn() -> bool,
) -> io::Result<Audit> {
    // Staging itself: the owner's alone while it is checked (the move out
    // gives the folder its final mode), with no ACL. `modes_kept` is what
    // the staging folder's creation measured: where the file system keeps no
    // modes, a refusal is no error here or in the mode fixes below.
    // SAFETY: a valid descriptor.
    match check(unsafe { libc::fchmod(staging.as_raw_fd(), 0o700) }) {
        Err(e)
            if !modes_kept
                && matches!(
                    e.raw_os_error(),
                    Some(libc::EPERM | libc::ENOTSUP | libc::EINVAL)
                ) => {}
        r => r?,
    }
    strip_xattrs(staging)?;

    let mut links_left = MAX_LINK_TOTAL;
    let (found, mut names) = walk(staging, &mut links_left, modes_kept, stop)?;
    let mut removed = Vec::new();
    let mut removed_more = 0usize;
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
    hardlinks_fit(&found, &names, &hardlink_to, links_left)?;
    let mut tree = build_tree(&found, &names, &order, &hardlink_to);
    let mut node_of = vec![None::<u32>; found.len()];
    for (id, n) in tree.nodes.iter().enumerate().skip(1) {
        if let Some(e) = n.entry {
            node_of[order[e as usize]] = Some(id as u32);
        }
    }
    // A link's target path is built from raw names, which can clash with
    // another name's disk form (and so name another node, or none). The
    // target is known: the first name of the file. Point the link at its
    // node, so no legitimate name is refused and unlinked for it.
    for (&i, &first) in &hardlink_to {
        if let (Some(n), Some(t)) = (node_of[i], node_of[first]) {
            tree.set_hardlink(n, t);
        }
    }
    let tree_skips_full = tree.skipped_more > 0;
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
    // Two folders whose names have the same disk form are one folder in the
    // tree, and the other has no place in it. Merging them is no job for an
    // audit that can't see what they hold: the extraction fails, in words.
    // A folder the tree skipped for its own reasons (depth, length, count)
    // fails the same way, with that reason.
    if let Some(&i) = gone.iter().find(|&&i| found[i].kind == Kind::Dir) {
        let path = shown(&path_of(&found, &names, i));
        return Err(message(match skip_reason.get(&(position[i] as u32)) {
            Some(r) => format!("A folder in the extracted files ({path}) can't be kept: {r}"),
            // Past MAX_SKIPPED the tree keeps no reason: say less.
            None if tree_skips_full => {
                format!("A folder in the extracted files ({path}) can't be kept.")
            }
            None => format!(
                "Two folders in the extracted files ({path}) would end up with the same name, and Atlas Archive won't merge them."
            ),
        }));
    }
    gone.sort_by_key(|&i| found[i].parent);
    let mut folders = Folders::new();
    for i in gone {
        let dir = folders.get(staging, &found, &names, found[i].parent)?;
        let c = cstring(&names[i])?;
        // SAFETY: a valid descriptor and C string.
        check(unsafe { libc::unlinkat(dir.as_raw_fd(), c.as_ptr(), 0) })?;
        if removed.len() < MAX_REMOVED_LISTED {
            removed.push(Removed {
                path: shown(&path_of(&found, &names, i)),
                reason: drop_it[i].clone().expect("dropped"),
            });
        } else {
            removed_more += 1;
        }
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
    // Temporary names: a random number for this audit, so a name already in
    // staging can't be one.
    let nonce = nonce()?;
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
            let mut tries = 0;
            let temp = loop {
                // Not a disk form, so never a name the audit keeps.
                let t =
                    CString::new(format!("\u{1}atlas-audit-{nonce:016x}-{spare}")).expect("no NUL");
                spare += 1;
                tries += 1;
                match rename(&old, &t) {
                    Ok(()) => break t,
                    // Only a guess at the random number gets here.
                    Err(e) if e.raw_os_error() == Some(libc::EEXIST) && tries < TEMP_TRIES => {}
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

    // The first tree is done with; the last one is built from the names now
    // on disk.
    drop(tree);

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
                match target {
                    Ok(fd) => {
                        let st = fstat(fd.as_fd())?;
                        if st.st_mode & libc::S_IFMT == libc::S_IFREG {
                            launchers.insert((st.st_dev, st.st_ino));
                        }
                    }
                    // Reaches nothing in staging: not a launcher's target.
                    Err(e)
                        if matches!(
                            e.raw_os_error(),
                            Some(libc::ENOENT | libc::ELOOP | libc::ENOTDIR | libc::EXDEV)
                        ) => {}
                    // Anything else means the walk can't tell: fail, never
                    // leave a launcher that might run.
                    Err(e) => return Err(e),
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
    for (n, i) in fix.into_iter().enumerate() {
        if n % 256 == 0 && stop() {
            return Err(stopped());
        }
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
            chmod_fd(item.as_fd(), want, modes_kept)?;
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
    // Names are in disk form now, which can be longer.
    hardlinks_fit(&found, &names, &hardlink_to, links_left)?;
    let tree = build_tree(&found, &names, &kept, &hardlink_to);
    let placed = tree.nodes.iter().filter(|n| n.entry.is_some()).count();
    if placed != kept.len()
        || !tree.skipped.is_empty()
        || tree.skipped_more > 0
        || tree.nodes.iter().any(|n| n.refused.is_some())
    {
        return Err(failed_check());
    }
    // Every node is on disk under the name it has: a kept item the tree
    // placed under another name (a clash it numbered again) isn't.
    for n in &tree.nodes[1..] {
        if let Some(e) = n.entry
            && n.name.disk.as_bytes() != names[kept[e as usize]]
        {
            return Err(failed_check());
        }
    }
    Ok(Audit {
        tree,
        removed,
        removed_more,
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
    fn the_removed_list_is_capped() {
        let s = Scratch::new("many");
        let st = s.staging();
        for k in 0..MAX_REMOVED_LISTED + 5 {
            symlink("/etc/passwd", st.join(format!("l{k}"))).unwrap();
        }
        let a = audit_path(&st, 0o022).unwrap();
        assert_eq!(a.removed.len(), MAX_REMOVED_LISTED);
        assert_eq!(a.removed_more, 5);
        assert!(a.top_level().is_empty());
    }

    #[test]
    fn shown_paths_are_short() {
        let long = "d/".repeat(3000);
        let s = shown(long.as_bytes());
        assert!(s.len() <= MAX_SHOWN + '\u{2026}'.len_utf8());
        assert!(s.ends_with('\u{2026}'));
        assert_eq!(shown(b"a/b"), "a/b");
        // Cut on a character boundary.
        let wide = "\u{e9}".repeat(2000);
        assert!(shown(wide.as_bytes()).ends_with('\u{2026}'));
    }

    #[test]
    fn two_folders_with_one_disk_form_fail_in_words() {
        let s = Scratch::new("dirs");
        let st = s.staging();
        std::fs::create_dir(st.join("x\u{202E}")).unwrap();
        std::fs::write(st.join("x\u{202E}/a"), b"1").unwrap();
        std::fs::create_dir(st.join("x\u{202D}")).unwrap();
        std::fs::write(st.join("x\u{202D}/b"), b"2").unwrap();
        let e = audit_path(&st, 0o022).err().expect("fails");
        assert!(e.to_string().contains("same name"), "{e}");
    }

    #[test]
    fn a_clashing_target_name_keeps_every_link() {
        let s = Scratch::new("target");
        let st = s.staging();
        // Both names of one file are misnamed, and another file already has
        // the disk form of the first.
        std::fs::write(st.join("x\u{1}"), b"f").unwrap();
        std::fs::hard_link(st.join("x\u{1}"), st.join("x\u{2}")).unwrap();
        std::fs::write(st.join("x_"), b"other").unwrap();
        let a = audit_path(&st, 0o022).unwrap();
        assert!(a.removed.is_empty(), "{:?}", a.removed);
        assert_eq!(std::fs::read(st.join("x_")).unwrap(), b"other");
        let top = a.top_level();
        assert_eq!(top.len(), 3, "{top:?}");
        let linked = top
            .iter()
            .filter(|n| std::fs::metadata(st.join(n)).unwrap().nlink() == 2)
            .count();
        assert_eq!(linked, 2);
    }

    #[test]
    fn temporary_names_survive_decoys() {
        let s = Scratch::new("decoys");
        let st = s.staging();
        for k in 0..40 {
            std::fs::write(st.join(format!("\u{1}atlas-audit-{k}")), b"d").unwrap();
            std::fs::write(st.join(format!("\u{1}atlas-audit-{k:016x}-0")), b"d").unwrap();
        }
        let a = audit_path(&st, 0o022).unwrap();
        assert!(a.removed.is_empty(), "{:?}", a.removed);
        assert_eq!(a.top_level().len(), 80);
    }

    #[test]
    fn launcher_links_that_reach_nothing_are_not_an_error() {
        let s = Scratch::new("dangling");
        let st = s.staging();
        std::fs::write(st.join("t"), b"t").unwrap();
        symlink("t", st.join("ok.desktop")).unwrap();
        symlink("nowhere", st.join("gone.desktop")).unwrap();
        symlink("loop.desktop", st.join("loop.desktop")).unwrap();
        symlink("t/x", st.join("notdir.desktop")).unwrap();
        let a = audit_path(&st, 0o022).unwrap();
        assert!(st.join("ok.desktop").exists());
        assert!(a.removed.len() <= 3, "{:?}", a.removed);
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

    #[test]
    fn link_targets_have_a_budget() {
        let s = Scratch::new("link-budget");
        let st = s.staging();
        let target = "t".repeat(4000);
        for i in 0..(MAX_LINK_TOTAL / 4000 + 1) {
            std::os::unix::fs::symlink(&target, st.join(format!("{i}"))).unwrap();
        }
        let e = audit_path(&st, 0o022).err().expect("fails");
        assert_eq!(e.to_string(), too_many().to_string());
    }

    #[test]
    fn link_targets_are_budgeted_as_they_are_read() {
        // One folder of long links fails while it is read, not after.
        let s = Scratch::new("link-one-dir");
        let st = s.staging();
        let target = "t".repeat(4000);
        for i in 0..(MAX_LINK_TOTAL / 4000 + 1) {
            std::os::unix::fs::symlink(&target, st.join(format!("{i}"))).unwrap();
        }
        let mut left = MAX_LINK_TOTAL;
        let fd = std::fs::File::open(&st).unwrap();
        let e = read_dir(fd.as_fd(), MAX_NODES, &mut left).expect_err("fails");
        assert_eq!(e.to_string(), too_many().to_string());
    }

    #[test]
    fn hard_link_targets_count_against_the_budget() {
        let s = Scratch::new("hardlink-budget");
        let st = s.staging();
        // A file at a long path, and many names for it below that folder
        // (the walk's first name is the target, so the file comes first).
        let mut deep = st.clone();
        for _ in 0..15 {
            deep.push("d".repeat(250));
        }
        std::fs::create_dir_all(&deep).unwrap();
        let file = deep.join("f");
        std::fs::write(&file, b"1").unwrap();
        let target_len = file.strip_prefix(&st).unwrap().as_os_str().len();
        let needed = MAX_LINK_TOTAL / target_len + 1;
        std::fs::create_dir(deep.join("l")).unwrap();
        for i in 0..needed {
            std::fs::hard_link(&file, deep.join("l").join(format!("{i}"))).unwrap();
        }
        let e = audit_path(&st, 0o022).err().expect("fails");
        assert_eq!(e.to_string(), too_many().to_string());
    }

    #[test]
    fn a_long_invalid_name_is_fixed_into_one_that_fits() {
        // 255 bytes that aren't UTF-8: the disk form stays within NAME_MAX,
        // so the rename can't fail as too long (the audit maps that error
        // to words anyway, should a disk form ever grow past it).
        let s = Scratch::new("long");
        let st = s.staging();
        let name = std::ffi::OsStr::from_bytes(&[0xB0; 255]);
        std::fs::write(st.join(name), b"1").unwrap();
        let a = audit_path(&st, 0o022).unwrap();
        assert_eq!(a.renamed, 1);
        for e in std::fs::read_dir(&st).unwrap() {
            let n = e.unwrap().file_name();
            assert!(n.len() <= 255 && n.to_str().is_some(), "{n:?}");
        }
    }
}
