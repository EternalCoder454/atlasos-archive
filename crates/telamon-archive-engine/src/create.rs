//! Creating an archive (docs/DESIGN.md, "The API other apps call"): zip, 7z
//! and tar with a gzip, xz or zstd filter, written by libarchive into a file
//! in the staging folder. Runs only in the worker, inside its sandbox.
//!
//! The sources are folders the client opened and passed (`proto::ROOT_FD`
//! and up) and names inside them. Everything is read through those
//! descriptors, below them (`openat2` with `RESOLVE_BENEATH |
//! RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS`), and never by following a
//! link: a link is stored as a link. Devices, FIFOs and sockets are left
//! out and reported. The walk looks at every item twice, once to count and
//! once to write, so the client has a total to show.

use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};

use telamon_archive_core::compress::{CompressFormat, Level};
use telamon_archive_core::proto::{MAX_ROOTS, Reply, Source};
use telamon_archive_core::tree::MAX_NODES;

use crate::extract::openat2;
use crate::job::{Clock, Conn, OUT_OF_TURN, SkipOut, plain_io, progress};

#[allow(non_camel_case_types)]
type archive = c_void;
#[allow(non_camel_case_types)]
type archive_entry = c_void;

const ARCHIVE_OK: c_int = 0;
const ARCHIVE_WARN: c_int = -20;
const AE_IFREG: u32 = 0o100000;
const AE_IFLNK: u32 = 0o120000;
const AE_IFDIR: u32 = 0o040000;

#[link(name = "archive")]
unsafe extern "C" {
    fn archive_write_new() -> *mut archive;
    fn archive_write_set_format_zip(a: *mut archive) -> c_int;
    fn archive_write_set_format_7zip(a: *mut archive) -> c_int;
    fn archive_write_set_format_pax_restricted(a: *mut archive) -> c_int;
    fn archive_write_add_filter_gzip(a: *mut archive) -> c_int;
    fn archive_write_add_filter_xz(a: *mut archive) -> c_int;
    fn archive_write_add_filter_zstd(a: *mut archive) -> c_int;
    fn archive_write_set_option(
        a: *mut archive,
        module: *const c_char,
        option: *const c_char,
        value: *const c_char,
    ) -> c_int;
    fn archive_write_open_fd(a: *mut archive, fd: c_int) -> c_int;
    fn archive_write_header(a: *mut archive, e: *mut archive_entry) -> c_int;
    fn archive_write_data(a: *mut archive, buf: *const c_void, size: usize) -> isize;
    fn archive_write_finish_entry(a: *mut archive) -> c_int;
    fn archive_write_close(a: *mut archive) -> c_int;
    fn archive_write_free(a: *mut archive) -> c_int;
    fn archive_error_string(a: *mut archive) -> *const c_char;
    fn archive_errno(a: *mut archive) -> c_int;

    fn archive_entry_new() -> *mut archive_entry;
    fn archive_entry_free(e: *mut archive_entry);
    fn archive_entry_update_pathname_utf8(e: *mut archive_entry, name: *const c_char) -> c_int;
    fn archive_entry_set_filetype(e: *mut archive_entry, t: u32);
    fn archive_entry_set_perm(e: *mut archive_entry, mode: u32);
    fn archive_entry_set_size(e: *mut archive_entry, size: i64);
    fn archive_entry_set_mtime(e: *mut archive_entry, sec: libc::time_t, nsec: libc::c_long);
    fn archive_entry_set_uid(e: *mut archive_entry, id: i64);
    fn archive_entry_set_gid(e: *mut archive_entry, id: i64);
    fn archive_entry_update_symlink_utf8(e: *mut archive_entry, target: *const c_char) -> c_int;
}

/// The deepest folder nesting that is read (a descriptor is held per level).
pub const MAX_DEPTH: usize = 100;
/// The longest path an item may have inside the archive.
const MAX_PATH: usize = 4096;
const CHUNK: usize = 256 * 1024;

const WALK_FLAGS: u64 =
    libc::RESOLVE_BENEATH | libc::RESOLVE_NO_SYMLINKS | libc::RESOLVE_NO_MAGICLINKS;

// ---- libarchive's writer ----

/// A failed write, in plain words (the detail went to the log).
#[derive(Debug)]
pub struct WriteError(pub String);

/// One archive being written.
struct Out {
    a: *mut archive,
    entry: *mut archive_entry,
    closed: bool,
}

/// What `Out::header` stores for an item.
struct Header<'a> {
    /// Valid UTF-8, no leading or trailing slash.
    path: &'a str,
    kind: Stored<'a>,
    mode: u32,
    mtime: (i64, i64),
}

enum Stored<'a> {
    File { size: u64 },
    Dir,
    Link { target: &'a [u8] },
}

impl Out {
    fn new(format: CompressFormat, level: Level, fd: BorrowedFd<'_>) -> Result<Out, WriteError> {
        // SAFETY: plain constructors; checked for null.
        let (a, entry) = unsafe { (archive_write_new(), archive_entry_new()) };
        if a.is_null() || entry.is_null() {
            // SAFETY: freeing what was made, null-safe for the entry.
            unsafe {
                if !a.is_null() {
                    archive_write_free(a);
                }
                if !entry.is_null() {
                    archive_entry_free(entry);
                }
            }
            return Err(WriteError("The computer ran out of memory.".into()));
        }
        let mut out = Out {
            a,
            entry,
            closed: false,
        };
        out.setup(format, level, fd)?;
        Ok(out)
    }

    fn setup(
        &mut self,
        format: CompressFormat,
        level: Level,
        fd: BorrowedFd<'_>,
    ) -> Result<(), WriteError> {
        // SAFETY: `a` is a live write handle in each call below.
        unsafe {
            let r = match format {
                CompressFormat::Zip => archive_write_set_format_zip(self.a),
                CompressFormat::SevenZip => archive_write_set_format_7zip(self.a),
                CompressFormat::TarGz | CompressFormat::TarXz | CompressFormat::TarZst => {
                    archive_write_set_format_pax_restricted(self.a)
                }
            };
            self.check(r, "format")?;
            let r = match format {
                CompressFormat::TarGz => archive_write_add_filter_gzip(self.a),
                CompressFormat::TarXz => archive_write_add_filter_xz(self.a),
                CompressFormat::TarZst => archive_write_add_filter_zstd(self.a),
                _ => ARCHIVE_OK,
            };
            self.check(r, "filter")?;
        }
        for (module, option, value) in options(format, level) {
            let (m, o, v) = (cstr(module), cstr(option), cstr(&value));
            // SAFETY: live handle and C strings.
            let r = unsafe { archive_write_set_option(self.a, m.as_ptr(), o.as_ptr(), v.as_ptr()) };
            self.check(r, "option")?;
        }
        // SAFETY: a live handle and a descriptor the caller keeps open.
        let r = unsafe { archive_write_open_fd(self.a, fd.as_raw_fd()) };
        self.check(r, "open")
    }

    /// Turns a libarchive result into an error with plain words.
    fn check(&self, r: c_int, what: &str) -> Result<(), WriteError> {
        if r >= ARCHIVE_OK || r == ARCHIVE_WARN {
            return Ok(());
        }
        Err(self.error(what))
    }

    fn error(&self, what: &str) -> WriteError {
        // SAFETY: a live handle; the string is copied at once.
        let (code, msg) = unsafe {
            let p = archive_error_string(self.a);
            (
                archive_errno(self.a),
                (!p.is_null()).then(|| CStr::from_ptr(p).to_string_lossy().into_owned()),
            )
        };
        // The message may name paths: it goes to the log only.
        crate::log_line!("create: {what} failed: code={code}");
        let _ = msg;
        if code > 0 {
            WriteError(plain_io(&io::Error::from_raw_os_error(code)))
        } else {
            WriteError("The archive couldn't be written.".into())
        }
    }

    fn header(&mut self, h: &Header<'_>) -> Result<(), WriteError> {
        let e = self.entry;
        // A fresh entry each time: nothing of the last item may remain.
        // SAFETY: both pointers are ours and live.
        unsafe {
            archive_entry_free(e);
            self.entry = archive_entry_new();
        }
        let e = self.entry;
        if e.is_null() {
            return Err(WriteError("The computer ran out of memory.".into()));
        }
        let path = match h.kind {
            Stored::Dir => format!("{}/", h.path),
            _ => h.path.to_string(),
        };
        let path = CString::new(path).map_err(|_| WriteError("A name holds a NUL.".into()))?;
        // SAFETY: a live entry and C strings.
        unsafe {
            if archive_entry_update_pathname_utf8(e, path.as_ptr()) == 0 {
                return Err(WriteError("A name couldn't be stored.".into()));
            }
            archive_entry_set_perm(e, h.mode & 0o777);
            archive_entry_set_mtime(e, h.mtime.0 as libc::time_t, h.mtime.1 as libc::c_long);
            // The user's numbers and names aren't stored.
            archive_entry_set_uid(e, 0);
            archive_entry_set_gid(e, 0);
            match h.kind {
                Stored::File { size } => {
                    archive_entry_set_filetype(e, AE_IFREG);
                    archive_entry_set_size(e, i64::try_from(size).unwrap_or(i64::MAX));
                }
                Stored::Dir => {
                    archive_entry_set_filetype(e, AE_IFDIR);
                    archive_entry_set_size(e, 0);
                }
                Stored::Link { target } => {
                    let t = CString::new(target)
                        .map_err(|_| WriteError("A link holds a NUL.".into()))?;
                    archive_entry_set_filetype(e, AE_IFLNK);
                    archive_entry_set_size(e, 0);
                    if archive_entry_update_symlink_utf8(e, t.as_ptr()) == 0 {
                        return Err(WriteError("A link's target couldn't be stored.".into()));
                    }
                }
            }
        }
        // SAFETY: live handle and entry.
        let r = unsafe { archive_write_header(self.a, e) };
        self.check(r, "header")
    }

    fn data(&mut self, buf: &[u8]) -> Result<(), WriteError> {
        let mut at = 0;
        while at < buf.len() {
            // SAFETY: a live handle and a buffer of the length passed.
            let n =
                unsafe { archive_write_data(self.a, buf[at..].as_ptr().cast(), buf.len() - at) };
            if n < 0 {
                return Err(self.error("data"));
            }
            at += n as usize;
        }
        Ok(())
    }

    fn finish_entry(&mut self) -> Result<(), WriteError> {
        // SAFETY: a live handle.
        let r = unsafe { archive_write_finish_entry(self.a) };
        self.check(r, "finish")
    }

    fn close(&mut self) -> Result<(), WriteError> {
        self.closed = true;
        // SAFETY: a live handle.
        let r = unsafe { archive_write_close(self.a) };
        self.check(r, "close")
    }
}

impl Drop for Out {
    fn drop(&mut self) {
        // SAFETY: both are ours; freeing an unclosed writer closes it.
        unsafe {
            archive_entry_free(self.entry);
            archive_write_free(self.a);
        }
    }
}

fn cstr(s: &str) -> CString {
    // Only fixed option text goes through here.
    CString::new(s).unwrap_or_default()
}

/// The libarchive options for a format and level: (module, option, value).
fn options(format: CompressFormat, level: Level) -> Vec<(&'static str, &'static str, String)> {
    let n = |fast: u8, normal: u8, best: u8| match level {
        Level::Store | Level::Fast => fast,
        Level::Normal => normal,
        Level::Best => best,
    };
    match format {
        CompressFormat::Zip => {
            if level == Level::Store {
                vec![("zip", "compression", "store".into())]
            } else {
                vec![
                    ("zip", "compression", "deflate".into()),
                    ("zip", "compression-level", n(1, 6, 9).to_string()),
                ]
            }
        }
        CompressFormat::SevenZip => {
            if level == Level::Store {
                vec![("7zip", "compression", "copy".into())]
            } else {
                vec![
                    ("7zip", "compression", "lzma2".into()),
                    ("7zip", "compression-level", n(1, 6, 9).to_string()),
                ]
            }
        }
        CompressFormat::TarGz => vec![(
            "gzip",
            "compression-level",
            if level == Level::Store { 0 } else { n(1, 6, 9) }.to_string(),
        )],
        CompressFormat::TarXz => vec![(
            "xz",
            "compression-level",
            if level == Level::Store { 0 } else { n(1, 6, 9) }.to_string(),
        )],
        CompressFormat::TarZst => vec![(
            "zstd",
            "compression-level",
            match level {
                Level::Store | Level::Fast => 1,
                Level::Normal => 3,
                Level::Best => 19,
            }
            .to_string(),
        )],
    }
}

// ---- the walk ----

/// What the walk found.
enum Found {
    Dir,
    File,
    Link(Vec<u8>),
}

struct Node<'a> {
    /// Path inside the archive: valid UTF-8, no slash at either end.
    path: &'a str,
    parent: BorrowedFd<'a>,
    name: &'a [u8],
    st: &'a libc::stat,
    found: Found,
}

trait Visitor {
    fn node(&mut self, n: &Node<'_>) -> io::Result<()>;
    /// An item that is left out, with the reason; `path` is lossy text.
    fn skipped(&mut self, path: &str, why: &str) -> io::Result<()>;
}

struct Walk<'a> {
    roots: &'a [OwnedFd],
    /// The staging folder: never compressed into itself.
    avoid: (u64, u64),
    path: Vec<u8>,
    count: usize,
}

fn fstatat(dir: RawFd, name: &[u8]) -> io::Result<libc::stat> {
    let c = CString::new(name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "a name holds a NUL"))?;
    let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: a valid C string and a stat buffer.
    let r = unsafe { libc::fstatat(dir, c.as_ptr(), st.as_mut_ptr(), libc::AT_SYMLINK_NOFOLLOW) };
    if r != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: filled by the successful call.
    Ok(unsafe { st.assume_init() })
}

fn fstat(fd: RawFd) -> io::Result<libc::stat> {
    let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: a stat buffer.
    if unsafe { libc::fstat(fd, st.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: filled by the successful call.
    Ok(unsafe { st.assume_init() })
}

fn readlinkat(dir: RawFd, name: &[u8]) -> io::Result<Vec<u8>> {
    let c = CString::new(name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "a name holds a NUL"))?;
    let mut buf = vec![0u8; 4097];
    // SAFETY: a valid C string and a buffer of the length passed.
    let n = unsafe { libc::readlinkat(dir, c.as_ptr(), buf.as_mut_ptr().cast(), buf.len()) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    buf.truncate(n as usize);
    Ok(buf)
}

/// The names in a folder, sorted, without `.` and `..`.
fn names_in(dir: &OwnedFd) -> io::Result<Vec<Vec<u8>>> {
    // SAFETY: dup of a live descriptor; fdopendir takes ownership of the copy.
    let copy = unsafe { libc::fcntl(dir.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
    if copy < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `copy` is a new descriptor of a folder.
    let d = unsafe { libc::fdopendir(copy) };
    if d.is_null() {
        let e = io::Error::last_os_error();
        // SAFETY: fdopendir failed, so the copy is still ours.
        unsafe { libc::close(copy) };
        return Err(e);
    }
    let mut names = Vec::new();
    loop {
        // SAFETY: errno is reset to tell the end from an error.
        unsafe { *libc::__errno_location() = 0 };
        // SAFETY: a live DIR.
        let ent = unsafe { libc::readdir(d) };
        if ent.is_null() {
            let e = io::Error::last_os_error();
            // SAFETY: closes the DIR and its descriptor.
            unsafe { libc::closedir(d) };
            return if e.raw_os_error().unwrap_or(0) == 0 {
                names.sort_unstable();
                Ok(names)
            } else {
                Err(e)
            };
        }
        // SAFETY: d_name is a NUL-terminated array in a live dirent.
        let name = unsafe { CStr::from_ptr((*ent).d_name.as_ptr()) }.to_bytes();
        if name != b"." && name != b".." {
            names.push(name.to_vec());
        }
    }
}

fn lossy(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

impl<'a> Walk<'a> {
    fn run(&mut self, sources: &[Source], v: &mut dyn Visitor) -> io::Result<()> {
        for s in sources {
            let Some(root) = self.roots.get(s.root as usize) else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "A source folder is missing.",
                ));
            };
            self.path.clear();
            self.path.extend_from_slice(&s.name);
            self.visit(root.as_fd(), &s.name, 0, v)?;
        }
        Ok(())
    }

    fn visit(
        &mut self,
        parent: BorrowedFd<'_>,
        name: &[u8],
        depth: usize,
        v: &mut dyn Visitor,
    ) -> io::Result<()> {
        let shown = lossy(&self.path);
        let Ok(text) = std::str::from_utf8(&self.path).map(str::to_owned) else {
            return v.skipped(&shown, "its name isn't valid text");
        };
        if self.path.len() > MAX_PATH {
            return v.skipped(&shown, "its path is too long");
        }
        // Another job's staging folder (this one is skipped by its inode
        // below) is not the user's: a project folder compressed beside an
        // archive being made must not take its half-written file.
        if is_staging_name(name) {
            return Ok(());
        }
        let st = match fstatat(parent.as_raw_fd(), name) {
            Ok(st) => st,
            Err(e) => return v.skipped(&shown, &why_unreadable(&e)),
        };
        if (st.st_dev as u64, st.st_ino as u64) == self.avoid {
            return Ok(());
        }
        self.count += 1;
        if self.count > MAX_NODES {
            return Err(io::Error::other(
                "There are too many items to compress at once.",
            ));
        }
        match st.st_mode & libc::S_IFMT {
            libc::S_IFDIR => {
                v.node(&Node {
                    path: &text,
                    parent,
                    name,
                    st: &st,
                    found: Found::Dir,
                })?;
                if depth >= MAX_DEPTH {
                    return v.skipped(&shown, "it is nested too deeply to be read");
                }
                let dir = match openat2_beneath(
                    parent,
                    name,
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW,
                ) {
                    Ok(d) => d,
                    Err(e) => return v.skipped(&shown, &why_unreadable(&e)),
                };
                match fstat(dir.as_raw_fd()) {
                    Ok(now) if now.st_ino == st.st_ino && now.st_dev == st.st_dev => {}
                    _ => return v.skipped(&shown, "it changed while it was being read"),
                }
                let names = match names_in(&dir) {
                    Ok(n) => n,
                    Err(e) => return v.skipped(&shown, &why_unreadable(&e)),
                };
                let keep = self.path.len();
                for n in names {
                    self.path.push(b'/');
                    self.path.extend_from_slice(&n);
                    let r = self.visit(dir.as_fd(), &n, depth + 1, v);
                    self.path.truncate(keep);
                    r?;
                }
                Ok(())
            }
            libc::S_IFREG => v.node(&Node {
                path: &text,
                parent,
                name,
                st: &st,
                found: Found::File,
            }),
            libc::S_IFLNK => match readlinkat(parent.as_raw_fd(), name) {
                Ok(target) if std::str::from_utf8(&target).is_ok() => v.node(&Node {
                    path: &text,
                    parent,
                    name,
                    st: &st,
                    found: Found::Link(target),
                }),
                Ok(_) => v.skipped(&shown, "the link's target isn't valid text"),
                Err(e) => v.skipped(&shown, &why_unreadable(&e)),
            },
            _ => v.skipped(&shown, "it isn't a file, a folder or a link"),
        }
    }
}

/// `.<name>.telamon-partial-<hex>` (or the older `.atlas-partial-`).
fn is_staging_name(name: &[u8]) -> bool {
    name.first() == Some(&b'.')
        && [&b".telamon-partial-"[..], b".atlas-partial-"]
            .iter()
            .any(|m| name.windows(m.len()).any(|w| w == *m))
}

/// `openat2` below `dir` that follows no link.
fn openat2_beneath(dir: BorrowedFd<'_>, name: &[u8], flags: i32) -> io::Result<OwnedFd> {
    #[repr(C)]
    struct OpenHow {
        flags: u64,
        mode: u64,
        resolve: u64,
    }
    let c = CString::new(name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "a name holds a NUL"))?;
    let how = OpenHow {
        flags: (flags | libc::O_CLOEXEC | libc::O_NOCTTY) as u64,
        mode: 0,
        resolve: WALK_FLAGS,
    };
    loop {
        // SAFETY: a valid C string and an open_how of the size passed.
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

/// Why an item couldn't be read, in words that fit "<item> isn't included because ...".
fn why_unreadable(e: &io::Error) -> String {
    match e.raw_os_error() {
        Some(libc::EACCES | libc::EPERM) => "Telamon Archive isn't allowed to read it".into(),
        Some(libc::ENOENT) => "it was removed while the archive was being made".into(),
        Some(libc::ELOOP | libc::EXDEV) => "it changed while it was being read".into(),
        Some(libc::EIO) => "the drive reported an error reading it".into(),
        Some(libc::ENAMETOOLONG) => "its name is too long".into(),
        _ => "it couldn't be read".into(),
    }
}

// ---- the two passes ----

/// First pass: counts what the second will write.
struct Scan<'c, C: Conn> {
    conn: &'c mut C,
    clock: Clock,
    bytes: u64,
    items: u64,
}

impl<C: Conn> Visitor for Scan<'_, C> {
    fn node(&mut self, n: &Node<'_>) -> io::Result<()> {
        self.items += 1;
        if matches!(n.found, Found::File) {
            self.bytes = self.bytes.saturating_add(n.st.st_size.max(0) as u64);
        }
        if self.clock.due() {
            if self.conn.unexpected_request()? {
                return Err(io::Error::new(io::ErrorKind::InvalidData, OUT_OF_TURN));
            }
            self.conn.send(&Reply::Scanned {
                bytes: self.bytes,
                items: self.items,
                done: false,
            })?;
        }
        Ok(())
    }

    fn skipped(&mut self, _path: &str, _why: &str) -> io::Result<()> {
        // Reported by the second pass, which may find it differently.
        Ok(())
    }
}

/// Second pass: writes.
struct Write<'c, C: Conn> {
    conn: &'c mut C,
    out: Out,
    clock: Clock,
    buf: Vec<u8>,
    bytes: u64,
    items: u64,
    skips: SkipOut,
    skipped: u32,
}

/// Why the second pass stopped.
enum Fatal {
    Io(io::Error),
    Write(WriteError),
}

impl From<io::Error> for Fatal {
    fn from(e: io::Error) -> Fatal {
        Fatal::Io(e)
    }
}

impl From<WriteError> for Fatal {
    fn from(e: WriteError) -> Fatal {
        Fatal::Write(e)
    }
}

impl<C: Conn> Write<'_, C> {
    fn left_out(&mut self, path: &str, why: &str) -> io::Result<()> {
        self.skipped += 1;
        let name = path.rsplit('/').next().unwrap_or(path);
        self.skips.send(
            self.conn,
            self.skipped,
            format!("“{name}” isn't included because {why}."),
        )
    }

    fn tick(&mut self) -> io::Result<()> {
        if self.clock.due() {
            progress(self.conn, self.bytes, self.items)?;
        }
        Ok(())
    }

    fn file(&mut self, n: &Node<'_>) -> Result<(), Fatal> {
        let fd = match openat2_beneath(
            n.parent,
            n.name,
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        ) {
            Ok(fd) => fd,
            Err(e) => {
                self.left_out(n.path, &why_unreadable(&e))?;
                return Ok(());
            }
        };
        let st = fstat(fd.as_raw_fd())?;
        if st.st_mode & libc::S_IFMT != libc::S_IFREG
            || st.st_ino != n.st.st_ino
            || st.st_dev != n.st.st_dev
        {
            self.left_out(n.path, "it changed while it was being read")?;
            return Ok(());
        }
        let size = st.st_size.max(0) as u64;
        self.out.header(&Header {
            path: n.path,
            kind: Stored::File { size },
            mode: st.st_mode,
            mtime: (st.st_mtime, st.st_mtime_nsec),
        })?;
        let mut left = size;
        let mut short = false;
        while left > 0 {
            let want = left.min(CHUNK as u64) as usize;
            // SAFETY: reads into a live buffer of at least `want` bytes.
            let got = unsafe { libc::read(fd.as_raw_fd(), self.buf.as_mut_ptr().cast(), want) };
            if got < 0 {
                let e = io::Error::last_os_error();
                match e.kind() {
                    io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock => continue,
                    _ => return Err(Fatal::Io(e)),
                }
            }
            if got == 0 {
                short = true;
                break;
            }
            let got = got as usize;
            self.out.data(&self.buf[..got])?;
            left -= got as u64;
            self.bytes += got as u64;
            self.tick()?;
        }
        if short {
            // It shrank: the header promised `left` more bytes.
            let zeros = vec![0u8; CHUNK.min(left as usize)];
            while left > 0 {
                let n = left.min(zeros.len() as u64) as usize;
                self.out.data(&zeros[..n])?;
                left -= n as u64;
            }
            self.left_out_note(
                n.path,
                "it got shorter while it was being read, so the rest is empty",
            )?;
        }
        self.out.finish_entry()?;
        self.items += 1;
        self.tick()?;
        Ok(())
    }

    /// Like `left_out`, for an item that is in the archive after all.
    fn left_out_note(&mut self, path: &str, what: &str) -> io::Result<()> {
        self.skipped += 1;
        let name = path.rsplit('/').next().unwrap_or(path);
        self.skips.send(
            self.conn,
            self.skipped,
            format!("“{name}” is incomplete: {what}."),
        )
    }
}

/// Carries a `Fatal` out of the `Visitor` interface, which speaks `io::Error`.
#[derive(Default)]
struct Carried(Option<Fatal>);

struct WriteVisitor<'a, 'c, C: Conn> {
    w: &'a mut Write<'c, C>,
    carried: &'a mut Carried,
}

impl<C: Conn> Visitor for WriteVisitor<'_, '_, C> {
    fn node(&mut self, n: &Node<'_>) -> io::Result<()> {
        let w = &mut *self.w;
        let r: Result<(), Fatal> = match &n.found {
            Found::Dir => w
                .out
                .header(&Header {
                    path: n.path,
                    kind: Stored::Dir,
                    mode: n.st.st_mode,
                    mtime: (n.st.st_mtime, n.st.st_mtime_nsec),
                })
                .and_then(|()| w.out.finish_entry())
                .map_err(Fatal::from)
                .and_then(|()| {
                    w.items += 1;
                    w.tick().map_err(Fatal::from)
                }),
            Found::Link(target) => w
                .out
                .header(&Header {
                    path: n.path,
                    kind: Stored::Link { target },
                    mode: n.st.st_mode,
                    mtime: (n.st.st_mtime, n.st.st_mtime_nsec),
                })
                .and_then(|()| w.out.finish_entry())
                .map_err(Fatal::from)
                .and_then(|()| {
                    w.items += 1;
                    w.tick().map_err(Fatal::from)
                }),
            Found::File => w.file(n),
        };
        r.map_err(|f| {
            // The walk only needs to stop; the cause is kept for the reply.
            let stop = io::Error::other("stopped");
            self.carried.0 = Some(f);
            stop
        })
    }

    fn skipped(&mut self, path: &str, why: &str) -> io::Result<()> {
        self.w.left_out(path, why)
    }
}

// ---- the job ----

/// One compression.
pub struct CreateJob {
    /// The folders the sources are in, in the order `Source::root` counts.
    pub roots: Vec<OwnedFd>,
    pub sources: Vec<Source>,
    /// The staging folder.
    pub staging: OwnedFd,
    pub out_name: String,
    pub format: CompressFormat,
    pub level: Level,
}

/// Validates a name that arrives from the client (which is trusted, but a
/// bug there must not become a path trick here).
pub fn good_name(name: &[u8]) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && name != b"."
        && name != b".."
        && !name.contains(&b'/')
        && !name.contains(&0)
}

/// Creates the archive in staging. Sends `Scanned`, `Progress`, `Skipped` and
/// `Done` (or `Failed`).
pub fn create(conn: &mut impl Conn, job: CreateJob) -> io::Result<()> {
    match run(conn, job) {
        Ok(name) => conn.send(&Reply::Done {
            written: vec![name.into_bytes()],
        }),
        Err(reason) => {
            crate::log_line!("create stopped");
            conn.send(&Reply::Failed { reason })
        }
    }
}

fn run(conn: &mut impl Conn, job: CreateJob) -> Result<String, String> {
    let io_words = |e: io::Error| plain_io(&e);
    if job.roots.len() > MAX_ROOTS
        || job.sources.is_empty()
        || job.sources.iter().any(|s| !good_name(&s.name))
        || !good_name(job.out_name.as_bytes())
    {
        return Err("The request to make an archive wasn't valid.".into());
    }
    // Two sources with one name would be two entries with one path.
    let mut seen = std::collections::HashSet::new();
    if !job.sources.iter().all(|s| seen.insert(s.name.clone())) {
        return Err("Two of the items have the same name, so they can't go in one archive.".into());
    }
    let staging = fstat(job.staging.as_raw_fd()).map_err(io_words)?;
    let avoid = (staging.st_dev as u64, staging.st_ino as u64);
    let mut walk = Walk {
        roots: &job.roots,
        avoid,
        path: Vec::new(),
        count: 0,
    };

    // Pass one: how much there is.
    let mut scan = Scan {
        conn,
        clock: Clock::new(),
        bytes: 0,
        items: 0,
    };
    walk.run(&job.sources, &mut scan).map_err(io_words)?;
    let (total_bytes, total_items) = (scan.bytes, scan.items);
    let conn = scan.conn;
    conn.send(&Reply::Scanned {
        bytes: total_bytes,
        items: total_items,
        done: true,
    })
    .map_err(io_words)?;
    if total_items == 0 {
        return Err("None of the items could be read.".into());
    }

    // libarchive's 7z writer keeps its data in a temporary file first: in
    // staging, the one place the worker may write. TMPDIR is process-wide:
    // the worker runs one job and is single-threaded (the tests below take
    // a lock, since they run many jobs in one process).
    // SAFETY: the worker is single-threaded here; the value is a fixed string.
    unsafe {
        std::env::set_var(
            "TMPDIR",
            format!("/proc/self/fd/{}", job.staging.as_raw_fd()),
        );
    }
    // Pass two: write.
    let out_fd = openat2(
        &job.staging,
        &job.out_name,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW,
        0o600,
    )
    .map_err(io_words)?;
    let out = Out::new(job.format, job.level, out_fd.as_fd()).map_err(|e| e.0)?;
    let mut w = Write {
        conn,
        out,
        clock: Clock::new(),
        buf: vec![0u8; CHUNK],
        bytes: 0,
        items: 0,
        skips: SkipOut::default(),
        skipped: 0,
    };
    let mut carried = Carried::default();
    let walked = walk.run(
        &job.sources,
        &mut WriteVisitor {
            w: &mut w,
            carried: &mut carried,
        },
    );
    match (walked, carried.0.take()) {
        (_, Some(Fatal::Write(e))) => return Err(e.0),
        (_, Some(Fatal::Io(e))) => return Err(io_words(e)),
        (Err(e), None) => return Err(io_words(e)),
        (Ok(()), None) => {}
    }
    w.out.close().map_err(|e| e.0)?;
    // SAFETY: a live descriptor of the output file.
    if unsafe { libc::fsync(out_fd.as_raw_fd()) } != 0 {
        return Err(io_words(io::Error::last_os_error()));
    }
    progress(w.conn, w.bytes, w.items).map_err(io_words)?;
    let skips = std::mem::take(&mut w.skips);
    skips.finish(w.conn, 0).map_err(io_words)?;
    Ok(job.out_name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use telamon_archive_core::proto::Request;

    struct Fake {
        replies: Vec<Reply>,
    }

    impl Conn for Fake {
        fn send(&mut self, r: &Reply) -> io::Result<()> {
            self.replies.push(r.clone());
            Ok(())
        }
        fn recv(&mut self) -> io::Result<Option<Request>> {
            Ok(None)
        }
    }

    fn scratch(tag: &str) -> PathBuf {
        let base = std::env::var_os("TELAMON_ARCHIVE_TEST_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                std::env::current_exe()
                    .unwrap()
                    .parent()
                    .unwrap()
                    .join("../test-scratch")
            });
        let p = base.join(format!("telamon-create-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn open(p: &Path) -> OwnedFd {
        crate::extract::open_dir(p).unwrap()
    }

    /// The worker sets the C.UTF-8 locale before it reads a byte.
    fn utf8_locale() {
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| {
            // SAFETY: a static C string, once, before any test reads names.
            let p = unsafe { libc::setlocale(libc::LC_ALL, c"C.UTF-8".as_ptr()) };
            assert!(!p.is_null());
        });
    }

    fn make(
        src: &Path,
        staging: &Path,
        names: &[&str],
        format: CompressFormat,
        level: Level,
    ) -> Fake {
        utf8_locale();
        // One job at a time: `create` sets TMPDIR for the process, and a
        // second job's descriptor number would be read by the first's
        // writer (or reused by another test's file: ENOTDIR on close).
        static ONE_AT_A_TIME: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _one = ONE_AT_A_TIME.lock().unwrap_or_else(|p| p.into_inner());
        let mut c = Fake { replies: vec![] };
        create(
            &mut c,
            CreateJob {
                roots: vec![open(src)],
                sources: names
                    .iter()
                    .map(|n| Source {
                        root: 0,
                        name: n.as_bytes().to_vec(),
                    })
                    .collect(),
                staging: open(staging),
                out_name: "out.part".into(),
                format,
                level,
            },
        )
        .unwrap();
        c
    }

    fn tree(src: &Path) {
        std::fs::create_dir_all(src.join("docs/deep")).unwrap();
        std::fs::write(src.join("docs/a.txt"), b"hello\n").unwrap();
        std::fs::write(src.join("docs/deep/b.bin"), vec![7u8; 300_000]).unwrap();
        std::fs::write(src.join("single.txt"), b"one\n").unwrap();
        std::fs::create_dir(src.join("empty")).unwrap();
        std::os::unix::fs::symlink("a.txt", src.join("docs/link")).unwrap();
        std::os::unix::fs::symlink("/etc/passwd", src.join("docs/abs-link")).unwrap();
    }

    fn listing(archive: &Path) -> String {
        let out = Command::new("bsdtar")
            .env("LC_ALL", "C.UTF-8")
            .arg("-tf")
            .arg(archive)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let mut lines: Vec<String> = String::from_utf8(out.stdout)
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect();
        lines.sort();
        lines.join("\n")
    }

    #[test]
    fn every_format_makes_a_readable_archive() {
        let d = scratch("formats");
        let (src, st) = (d.join("src"), d.join("st"));
        std::fs::create_dir_all(&src).unwrap();
        tree(&src);
        for fmt in CompressFormat::ALL {
            for level in [Level::Store, Level::Fast, Level::Normal, Level::Best] {
                let _ = std::fs::remove_dir_all(&st);
                std::fs::create_dir_all(&st).unwrap();
                let c = make(&src, &st, &["docs", "single.txt", "empty"], fmt, level);
                assert!(
                    matches!(c.replies.last(), Some(Reply::Done { .. })),
                    "{fmt:?} {level:?}: {:?}",
                    c.replies.last()
                );
                assert!(c.replies.iter().any(
                    |r| matches!(r, Reply::Scanned { done: true, items: 8, bytes } if *bytes == 300_010)
                ), "{:?}", c.replies);
                let got = listing(&st.join("out.part"));
                assert_eq!(
                    got,
                    "docs/\ndocs/a.txt\ndocs/abs-link\ndocs/deep/\ndocs/deep/b.bin\ndocs/link\nempty/\nsingle.txt"
                        .to_string(),
                    "{fmt:?} {level:?}"
                );
            }
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn contents_modes_links_and_times_survive() {
        let d = scratch("roundtrip");
        let (src, st, out) = (d.join("src"), d.join("st"), d.join("out"));
        for p in [&src, &st, &out] {
            std::fs::create_dir_all(p).unwrap();
        }
        tree(&src);
        std::fs::set_permissions(
            src.join("single.txt"),
            std::os::unix::fs::PermissionsExt::from_mode(0o751),
        )
        .unwrap();
        let t = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_500_000_000);
        std::fs::File::options()
            .write(true)
            .open(src.join("single.txt"))
            .unwrap()
            .set_modified(t)
            .unwrap();
        for fmt in [
            CompressFormat::Zip,
            CompressFormat::SevenZip,
            CompressFormat::TarZst,
        ] {
            let _ = std::fs::remove_dir_all(&st);
            let _ = std::fs::remove_dir_all(&out);
            std::fs::create_dir_all(&st).unwrap();
            std::fs::create_dir_all(&out).unwrap();
            let c = make(&src, &st, &["docs", "single.txt"], fmt, Level::Normal);
            assert!(matches!(c.replies.last(), Some(Reply::Done { .. })));
            let ok = Command::new("bsdtar")
                .arg("-xf")
                .arg(st.join("out.part"))
                .arg("-C")
                .arg(&out)
                .status()
                .unwrap();
            assert!(ok.success());
            use std::os::unix::fs::MetadataExt;
            assert_eq!(std::fs::read(out.join("docs/a.txt")).unwrap(), b"hello\n");
            assert_eq!(
                std::fs::read(out.join("docs/deep/b.bin")).unwrap().len(),
                300_000
            );
            let m = std::fs::metadata(out.join("single.txt")).unwrap();
            assert_eq!(m.mode() & 0o777 & !0o022, 0o751 & !0o022, "{fmt:?}");
            assert_eq!(m.mtime(), 1_500_000_000, "{fmt:?}");
            assert_eq!(
                std::fs::read_link(out.join("docs/link")).unwrap(),
                Path::new("a.txt")
            );
            // Not the user's numbers.
            assert!(m.uid() == unsafe { libc::getuid() } || m.uid() == 0);
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn links_are_stored_never_followed_and_specials_are_left_out() {
        let d = scratch("links");
        let (src, st) = (d.join("src"), d.join("st"));
        std::fs::create_dir_all(src.join("f")).unwrap();
        std::fs::create_dir_all(&st).unwrap();
        std::fs::write(d.join("secret"), b"top secret").unwrap();
        std::os::unix::fs::symlink("../../secret", src.join("f/escape")).unwrap();
        std::os::unix::fs::symlink(&d, src.join("f/dir-link")).unwrap();
        let fifo = std::ffi::CString::new(src.join("f/fifo").into_os_string().into_encoded_bytes())
            .unwrap();
        // SAFETY: a C string path.
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        let c = make(&src, &st, &["f"], CompressFormat::Zip, Level::Normal);
        assert!(matches!(c.replies.last(), Some(Reply::Done { .. })));
        let skipped: Vec<_> = c
            .replies
            .iter()
            .filter_map(|r| match r {
                Reply::Skipped { reason, .. } => Some(reason.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(skipped.len(), 1, "{skipped:?}");
        assert!(skipped[0].contains("fifo"), "{skipped:?}");
        assert_eq!(listing(&st.join("out.part")), "f/\nf/dir-link\nf/escape");
        // The secret's bytes are nowhere in the archive.
        let bytes = std::fs::read(st.join("out.part")).unwrap();
        assert!(!bytes.windows(10).any(|w| w == b"top secret"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn the_staging_folder_is_never_compressed_into_itself() {
        let d = scratch("selfref");
        std::fs::create_dir_all(d.join("proj/.staging")).unwrap();
        std::fs::write(d.join("proj/a.txt"), b"a").unwrap();
        let c = make(
            &d,
            &d.join("proj/.staging"),
            &["proj"],
            CompressFormat::TarGz,
            Level::Normal,
        );
        assert!(matches!(c.replies.last(), Some(Reply::Done { .. })));
        assert_eq!(
            listing(&d.join("proj/.staging/out.part")),
            "proj/\nproj/a.txt"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn bad_requests_and_empty_results_fail_in_words() {
        let d = scratch("bad");
        let (src, st) = (d.join("src"), d.join("st"));
        std::fs::create_dir_all(&src).unwrap();
        std::fs::create_dir_all(&st).unwrap();
        // Nothing named: not valid.
        let c = make(&src, &st, &[], CompressFormat::Zip, Level::Normal);
        assert!(matches!(c.replies.last(), Some(Reply::Failed { .. })));
        // A missing item is skipped; with nothing left the job fails.
        let c = make(&src, &st, &["nope"], CompressFormat::Zip, Level::Normal);
        match c.replies.last() {
            Some(Reply::Failed { reason }) => assert!(reason.contains("None"), "{reason}"),
            other => panic!("{other:?}"),
        }
        // A name with a slash is a client bug, refused.
        let c = make(&src, &st, &["a/b"], CompressFormat::Zip, Level::Normal);
        assert!(matches!(c.replies.last(), Some(Reply::Failed { .. })));
        // Two sources with the same name.
        let c = make(&src, &st, &["x", "x"], CompressFormat::Zip, Level::Normal);
        assert!(matches!(c.replies.last(), Some(Reply::Failed { .. })));
        assert!(!st.join("out.part").exists());
        let _ = (VecDeque::<u8>::new(), std::fs::remove_dir_all(&d));
    }

    #[test]
    fn names_that_are_not_text_are_reported() {
        use std::os::unix::ffi::OsStrExt;
        let d = scratch("names");
        let (src, st) = (d.join("src"), d.join("st"));
        std::fs::create_dir_all(src.join("f")).unwrap();
        std::fs::create_dir_all(&st).unwrap();
        std::fs::write(src.join("f/ok.txt"), b"ok").unwrap();
        std::fs::write(src.join("f/ünï.txt"), b"ok").unwrap();
        std::fs::write(
            src.join(std::ffi::OsStr::from_bytes(b"f/bad\xff.txt")),
            b"bad",
        )
        .unwrap();
        let c = make(&src, &st, &["f"], CompressFormat::Zip, Level::Normal);
        assert!(
            matches!(c.replies.last(), Some(Reply::Done { .. })),
            "{:?}",
            c.replies
        );
        let skipped = c
            .replies
            .iter()
            .filter(|r| matches!(r, Reply::Skipped { .. }))
            .count();
        assert_eq!(skipped, 1);
        assert_eq!(listing(&st.join("out.part")), "f/\nf/ok.txt\nf/ünï.txt");
        let _ = std::fs::remove_dir_all(&d);
    }
}
