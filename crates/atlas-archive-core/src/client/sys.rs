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
pub fn rename_noreplace(
    from_dir: BorrowedFd<'_>,
    from: &[u8],
    to_dir: BorrowedFd<'_>,
    to: &[u8],
) -> io::Result<()> {
    let (f, t) = (cstr(from)?, cstr(to)?);
    retry(|| {
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
    })
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
    fn percent_encoding_round_trips() {
        let raw = "/home/a b/ä%x\n".as_bytes();
        let enc = pct_encode(raw);
        assert_eq!(enc, "/home/a%20b/%C3%A4%25x%0A");
        assert_eq!(pct_decode(&enc).unwrap(), raw);
        assert_eq!(pct_decode("%zz"), None);
        assert_eq!(pct_decode("%4"), None);
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
