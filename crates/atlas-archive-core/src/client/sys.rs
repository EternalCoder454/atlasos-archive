//! Thin, checked wrappers over the Linux calls the client makes. Everything
//! that touches a name takes a descriptor and a single name, never a path
//! joined from parts.

use std::ffi::CString;
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::path::Path;

/// How every open below a descriptor resolves: never out of it, never through
/// a link, never across a mount.
pub const RESOLVE: u64 = libc::RESOLVE_BENEATH
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

pub fn cstr(bytes: &[u8]) -> io::Result<CString> {
    CString::new(bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "a name holds a NUL byte"))
}

pub fn check(r: libc::c_int) -> io::Result<()> {
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Runs `f` again while it fails with EINTR.
pub fn retry<T>(mut f: impl FnMut() -> io::Result<T>) -> io::Result<T> {
    loop {
        match f() {
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            r => return r,
        }
    }
}

fn owned(fd: libc::c_int) -> OwnedFd {
    // SAFETY: `fd` is a new descriptor returned by a successful call, owned
    // by nothing else.
    unsafe { OwnedFd::from_raw_fd(fd) }
}

/// `openat2` below `dir` with the client's resolve flags. `name` is relative.
pub fn openat2(dir: BorrowedFd<'_>, name: &[u8], flags: i32) -> io::Result<OwnedFd> {
    let c = cstr(name)?;
    let how = OpenHow {
        flags: (flags | libc::O_CLOEXEC) as u64,
        mode: 0,
        resolve: RESOLVE,
    };
    retry(|| {
        // SAFETY: valid descriptor, C string and open_how of the size passed.
        let fd = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                dir.as_raw_fd(),
                c.as_ptr(),
                &how as *const OpenHow,
                std::mem::size_of::<OpenHow>(),
            )
        };
        if fd < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(owned(fd as i32))
        }
    })
}

/// Opens the folder `name` below `dir`, never through a link.
pub fn open_subdir(dir: BorrowedFd<'_>, name: &[u8]) -> io::Result<OwnedFd> {
    openat2(
        dir,
        name,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW,
    )
}

/// Opens a folder the caller named by path (links in it are the caller's own).
pub fn open_dir(path: &Path) -> io::Result<OwnedFd> {
    use std::os::unix::ffi::OsStrExt;
    let c = cstr(path.as_os_str().as_bytes())?;
    retry(|| {
        // SAFETY: a C string; a new descriptor we own.
        let fd = unsafe {
            libc::open(
                c.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(owned(fd))
        }
    })
}

pub fn mkdirat(dir: BorrowedFd<'_>, name: &[u8], mode: u32) -> io::Result<()> {
    let c = cstr(name)?;
    // SAFETY: valid descriptor and C string.
    check(unsafe { libc::mkdirat(dir.as_raw_fd(), c.as_ptr(), mode) })
}

pub fn unlinkat(dir: BorrowedFd<'_>, name: &[u8], flags: i32) -> io::Result<()> {
    let c = cstr(name)?;
    // SAFETY: valid descriptor and C string.
    check(unsafe { libc::unlinkat(dir.as_raw_fd(), c.as_ptr(), flags) })
}

/// Moves `from` in `from_dir` to `to` in `to_dir`, failing with EEXIST when
/// `to` is there.
///
/// Where the file system has no `RENAME_NOREPLACE` (FAT and exFAT, some FUSE,
/// NFS and SMB mounts: EINVAL, ENOSYS or EOPNOTSUPP) this looks first with
/// `fstatat(AT_SYMLINK_NOFOLLOW)` and then renames. That guarantee is weaker:
/// a name created by someone else between the two calls is replaced. The
/// destination folder is the user's own (checked by the caller), so only a
/// process of the same user can win that race.
pub fn rename_noreplace(
    from_dir: BorrowedFd<'_>,
    from: &[u8],
    to_dir: BorrowedFd<'_>,
    to: &[u8],
) -> io::Result<()> {
    let (f, t) = (cstr(from)?, cstr(to)?);
    let r = retry(|| {
        // SAFETY: valid descriptors and C strings.
        check(unsafe {
            libc::renameat2(
                from_dir.as_raw_fd(),
                f.as_ptr(),
                to_dir.as_raw_fd(),
                t.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        })
    });
    match r {
        Err(e)
            if matches!(
                e.raw_os_error(),
                Some(libc::EINVAL | libc::ENOSYS | libc::EOPNOTSUPP)
            ) =>
        {
            match lstatat(to_dir, to) {
                Ok(_) => return Err(io::Error::from_raw_os_error(libc::EEXIST)),
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
            rename(from_dir, from, to_dir, to)
        }
        r => r,
    }
}

/// A plain `renameat`: replaces `to` when it is a file, or an empty folder.
pub fn rename(
    from_dir: BorrowedFd<'_>,
    from: &[u8],
    to_dir: BorrowedFd<'_>,
    to: &[u8],
) -> io::Result<()> {
    let (f, t) = (cstr(from)?, cstr(to)?);
    retry(|| {
        // SAFETY: valid descriptors and C strings.
        check(unsafe {
            libc::renameat(
                from_dir.as_raw_fd(),
                f.as_ptr(),
                to_dir.as_raw_fd(),
                t.as_ptr(),
            )
        })
    })
}

/// Whether two `stat`s name the same file.
pub fn same_file(a: &libc::stat, b: &libc::stat) -> bool {
    a.st_dev == b.st_dev
        && a.st_ino == b.st_ino
        && (a.st_mode & libc::S_IFMT) == (b.st_mode & libc::S_IFMT)
}

pub fn getuid() -> u32 {
    // SAFETY: getuid has no failure.
    unsafe { libc::getuid() }
}

pub fn getegid() -> u32 {
    // SAFETY: getegid has no failure.
    unsafe { libc::getegid() }
}

/// Opens `name` in `dir` as an `O_PATH` descriptor (by `openat2` with the
/// client's resolve flags, so not across a mount either), never through a link:
/// good for `fstat` and `fchmod_path`, nothing else.
pub fn open_path_nofollow(dir: BorrowedFd<'_>, name: &[u8]) -> io::Result<OwnedFd> {
    openat2(dir, name, libc::O_PATH | libc::O_NOFOLLOW)
}

/// `fchmod` for an `O_PATH` descriptor (which `fchmod` refuses), through
/// `/proc/self/fd/N`: it names the opened file itself, not a path to resolve.
pub fn fchmod_path(fd: BorrowedFd<'_>, mode: u32) -> io::Result<()> {
    let c = cstr(format!("/proc/self/fd/{}", fd.as_raw_fd()).as_bytes())?;
    // SAFETY: a valid C string.
    check(unsafe { libc::chmod(c.as_ptr(), mode) })
}

/// `fchmod` where the file system may not keep modes (FAT, some network
/// mounts: EPERM, ENOTSUP, EINVAL): that is not an error there.
pub fn fchmod_soft(fd: BorrowedFd<'_>, mode: u32) -> io::Result<()> {
    match fchmod(fd, mode) {
        Err(e)
            if matches!(
                e.raw_os_error(),
                Some(libc::EPERM | libc::ENOTSUP | libc::EINVAL)
            ) =>
        {
            log::debug!("This file system doesn't keep modes: {e}");
            Ok(())
        }
        r => r,
    }
}

/// Opens a folder by path without following a link in its last component.
pub fn open_dir_nofollow(path: &Path) -> io::Result<OwnedFd> {
    use std::os::unix::ffi::OsStrExt;
    let c = cstr(path.as_os_str().as_bytes())?;
    retry(|| {
        // SAFETY: a C string; a new descriptor we own.
        let fd = unsafe {
            libc::open(
                c.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(owned(fd))
        }
    })
}

/// The path the kernel says `fd` is at now (`/proc/self/fd/N`), when it can.
pub fn fd_path(fd: BorrowedFd<'_>) -> Option<std::path::PathBuf> {
    let p = std::fs::read_link(format!("/proc/self/fd/{}", fd.as_raw_fd())).ok()?;
    p.is_absolute().then_some(p)
}

/// The bytes a non-root user can still write on the file system of `fd`;
/// `ErrorKind::Unsupported` when the file system gives no figures.
pub fn free_bytes(fd: BorrowedFd<'_>) -> io::Result<u64> {
    let mut v = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: a valid descriptor; `v` is filled on success.
    check(unsafe { libc::fstatvfs(fd.as_raw_fd(), v.as_mut_ptr()) })?;
    // SAFETY: initialised by the successful call.
    let v = unsafe { v.assume_init() };
    // Some file systems (FUSE and network mounts) answer with zeros for
    // everything: that is "no figure", and reading it as "no space free"
    // would be as wrong as reading it as plenty. A full drive still has its
    // blocks counted.
    if v.f_frsize == 0 || v.f_blocks == 0 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "the file system gives no free-space figures",
        ));
    }
    Ok(v.f_bavail.saturating_mul(v.f_frsize))
}

/// This boot's id, when `/proc` says.
pub fn boot_id() -> Option<String> {
    let t = std::fs::read_to_string("/proc/sys/kernel/random/boot_id").ok()?;
    let t = t.trim();
    (!t.is_empty() && t.len() <= 64 && t.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-'))
        .then(|| t.to_string())
}

/// Whether `c` is one that must not reach a screen or a log from an
/// untrusted source: a control character (Cc), a format character (Cf: bidi
/// overrides and isolates, zero-width, joiners, tags), or a line or paragraph
/// separator (Zl, Zp).
pub fn is_unsafe_char(c: char) -> bool {
    let u = c as u32;
    c.is_control()
        || matches!(
            u,
            0x00AD
                | 0x0600..=0x0605
                | 0x061C
                | 0x06DD
                | 0x070F
                | 0x0890..=0x0891
                | 0x08E2
                | 0x180E
                | 0x200B..=0x200F
                | 0x2028..=0x202E
                | 0x2060..=0x2064
                | 0x2066..=0x206F
                | 0xFEFF
                | 0xFFF9..=0xFFFB
                | 0x110BD
                | 0x110CD
                | 0x13430..=0x1343F
                | 0x1BCA0..=0x1BCA3
                | 0x1D173..=0x1D17A
                | 0xE0001
                | 0xE0020..=0xE007F
        )
}

/// `text` cut to `max` characters with every unsafe character replaced.
pub fn sanitize(text: &str, max: usize, with: char) -> String {
    text.chars()
        .take(max)
        .map(|c| if is_unsafe_char(c) { with } else { c })
        .collect()
}

/// A path for a log line: lossy, capped, nothing unsafe in it.
pub fn log_path(p: &Path) -> String {
    sanitize(&p.to_string_lossy(), 512, '?')
}

/// `lstat` of `name` in `dir`.
pub fn lstatat(dir: BorrowedFd<'_>, name: &[u8]) -> io::Result<libc::stat> {
    let c = cstr(name)?;
    let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: valid descriptor and C string; `st` is filled on success.
    check(unsafe {
        libc::fstatat(
            dir.as_raw_fd(),
            c.as_ptr(),
            st.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    })?;
    // SAFETY: initialised by the successful call.
    Ok(unsafe { st.assume_init() })
}

pub fn fstat(fd: BorrowedFd<'_>) -> io::Result<libc::stat> {
    let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: a valid descriptor; `st` is filled on success.
    check(unsafe { libc::fstat(fd.as_raw_fd(), st.as_mut_ptr()) })?;
    // SAFETY: initialised by the successful call.
    Ok(unsafe { st.assume_init() })
}

pub fn fchmod(fd: BorrowedFd<'_>, mode: u32) -> io::Result<()> {
    // SAFETY: a valid descriptor.
    check(unsafe { libc::fchmod(fd.as_raw_fd(), mode) })
}

/// A copy of `fd` numbered at least `min`, close-on-exec.
pub fn dup_above(fd: BorrowedFd<'_>, min: RawFd) -> io::Result<OwnedFd> {
    // SAFETY: a valid descriptor; the result is a new one we own.
    let r = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, min) };
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(owned(r))
    }
}

pub fn set_nonblocking(fd: BorrowedFd<'_>) -> io::Result<()> {
    // SAFETY: F_GETFL/F_SETFL take no pointers.
    unsafe {
        let flags = libc::fcntl(fd.as_raw_fd(), libc::F_GETFL);
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        check(libc::fcntl(
            fd.as_raw_fd(),
            libc::F_SETFL,
            flags | libc::O_NONBLOCK,
        ))
    }
}

/// 16 hex digits from the kernel's random source.
pub fn random_hex() -> io::Result<String> {
    let mut buf = [0u8; 8];
    let mut got = 0;
    while got < buf.len() {
        // SAFETY: writes at most `buf.len() - got` bytes into the rest of `buf`.
        let n = unsafe { libc::getrandom(buf[got..].as_mut_ptr().cast(), buf.len() - got, 0) };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.kind() != io::ErrorKind::Interrupted {
                return Err(e);
            }
        } else {
            got += n as usize;
        }
    }
    Ok(buf.iter().map(|b| format!("{b:02x}")).collect())
}

/// The process umask, from `/proc` so no other thread's `open` ever sees it
/// changed; 022 when `/proc` can't say.
pub fn read_umask() -> u32 {
    let text = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    text.lines()
        .find_map(|l| l.strip_prefix("Umask:"))
        .and_then(|v| u32::from_str_radix(v.trim(), 8).ok())
        .map(|m| m & 0o777)
        .unwrap_or_else(|| {
            log::warn!("The umask couldn't be read; assuming 022.");
            0o022
        })
}

/// The start time of process `pid` (clock ticks since boot), to tell a
/// process from a later one that got its number.
pub fn proc_start(pid: u32) -> io::Result<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
    // The name (field 2) may hold anything, ')' included: count from the last.
    let rest = stat
        .rfind(')')
        .map(|i| &stat[i + 1..])
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?;
    // `rest` starts at field 3; the start time is field 22.
    rest.split_whitespace()
        .nth(19)
        .and_then(|v| v.parse().ok())
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))
}

/// Percent-encodes `bytes`, keeping letters, digits and `-_.~/`.
pub fn pct_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    for &b in bytes {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~' | b'/') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// The reverse of `pct_encode`; `None` on a malformed escape.
pub fn pct_decode(text: &str) -> Option<Vec<u8>> {
    let b = text.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let hex = text.get(i + 1..i + 3)?;
            if !hex.bytes().all(|c| c.is_ascii_hexdigit()) {
                return None;
            }
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    Some(out)
}

/// A shorthand for the borrowed form of an owned descriptor.
pub fn bfd(fd: &OwnedFd) -> BorrowedFd<'_> {
    fd.as_fd()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn free_space_of_a_drive_with_no_figures_is_unsupported() {
        // /proc reports no blocks at all.
        let proc = std::fs::File::open("/proc").unwrap();
        let e = free_bytes(proc.as_fd()).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::Unsupported);
        let here = std::fs::File::open(std::env::temp_dir()).unwrap();
        assert!(free_bytes(here.as_fd()).is_ok());
    }

    #[test]
    fn percent_encoding_round_trips() {
        let raw = "/home/a b/ä%x\n".as_bytes();
        let enc = pct_encode(raw);
        assert_eq!(enc, "/home/a%20b/%C3%A4%25x%0A");
        assert_eq!(pct_decode(&enc).unwrap(), raw);
        assert_eq!(pct_decode("%zz"), None);
        assert_eq!(pct_decode("%4"), None);
    }

    #[test]
    fn sanitize_removes_controls_bidi_and_separators() {
        let evil = "a\u{202E}b\u{2066}c\u{200B}d\u{2028}e\u{2029}f\u{7}g\u{FEFF}h";
        assert_eq!(sanitize(evil, 100, '?'), "a?b?c?d?e?f?g?h");
        assert_eq!(sanitize("héllo wörld", 5, '?'), "héllo");
        assert!(!is_unsafe_char('é') && !is_unsafe_char('日'));
    }

    #[test]
    fn random_names_differ() {
        let (a, b) = (random_hex().unwrap(), random_hex().unwrap());
        assert_eq!(a.len(), 16);
        assert_ne!(a, b);
    }

    #[test]
    fn own_start_time_and_umask_are_readable() {
        assert!(proc_start(std::process::id()).unwrap() > 0);
        assert!(read_umask() <= 0o777);
    }
}
