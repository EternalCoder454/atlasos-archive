//! The staging folder, the job records that let a later start clean up after
//! a crash, and the recursive delete that never follows a link
//! (docs/DESIGN.md, "Extraction rules").

use std::ffi::CStr;
use std::io::{self, Write};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use super::sys::{self, bfd, cstr};
use crate::name::{self, MAX_COMPONENT_BYTES};

/// What follows the archive's name in a staging folder's name.
const TAG: &str = ".atlas-partial-";
/// Folders deeper than this are not entered by the delete: a worker that
/// nested them that far (the audit's own limit is 256) is hostile, and one
/// descriptor per level must stay well under the process limit.
const MAX_REMOVE_DEPTH: usize = 512;
/// The longest job record read back: they are a few hundred bytes.
const MAX_RECORD: u64 = 64 * 1024;

/// A staging folder's name for `archive`: `.<name>.atlas-partial-<hex>`, the
/// archive's name in disk form and shortened so the whole fits `NAME_MAX`.
pub fn staging_name(archive: &[u8], hex: &str) -> String {
    let mut pieces = Vec::new();
    name::decode(archive, name::NameEncoding::Utf8, |p| pieces.push(p));
    let (mut base, _) = name::disk(&pieces);
    let room = MAX_COMPONENT_BYTES - 1 - TAG.len() - hex.len();
    if base.len() > room {
        let mut cut = room;
        while !base.is_char_boundary(cut) {
            cut -= 1;
        }
        base.truncate(cut);
    }
    format!(".{base}{TAG}{hex}")
}

/// `$XDG_STATE_HOME`, or `~/.local/state`. `None` when neither is usable.
pub fn default_state_dir() -> Option<PathBuf> {
    let absolute = |v: std::ffi::OsString| {
        let p = PathBuf::from(v);
        p.is_absolute().then_some(p)
    };
    std::env::var_os("XDG_STATE_HOME")
        .and_then(absolute)
        .or_else(|| {
            std::env::var_os("HOME")
                .and_then(absolute)
                .map(|h| h.join(".local/state"))
        })
}

fn jobs_dir(state_dir: &Path) -> PathBuf {
    state_dir.join("atlas-archive/jobs")
}

// ---- job records ----

/// What a later start needs to remove a dead job's staging folder.
#[derive(Debug, PartialEq, Eq)]
struct Record {
    pid: u32,
    start: u64,
    /// The destination folder, as the job was given it.
    dest: PathBuf,
    /// The destination's device and inode: the path may lead elsewhere by
    /// the time it is used.
    dev: u64,
    ino: u64,
    /// The staging folder's name in the destination.
    staging: String,
}

impl Record {
    fn encode(&self) -> String {
        format!(
            "pid={}\nstart={}\ndev={}\nino={}\ndest={}\nstaging={}\n",
            self.pid,
            self.start,
            self.dev,
            self.ino,
            sys::pct_encode(self.dest.as_os_str().as_bytes()),
            sys::pct_encode(self.staging.as_bytes()),
        )
    }

    /// `None` for anything that isn't exactly what `encode` writes.
    fn parse(text: &str) -> Option<Record> {
        let mut f = std::collections::HashMap::new();
        for line in text.lines() {
            let (k, v) = line.split_once('=')?;
            f.insert(k, v);
        }
        let dest = sys::pct_decode(f.get("dest")?)?;
        let staging = String::from_utf8(sys::pct_decode(f.get("staging")?)?).ok()?;
        // It is used as a name below the destination: nothing else will do.
        if !staging.starts_with('.')
            || !staging.contains(TAG)
            || staging.contains('/')
            || staging.contains('\0')
            || staging.len() > MAX_COMPONENT_BYTES
            || dest.first() != Some(&b'/')
            || dest.contains(&0)
        {
            return None;
        }
        Some(Record {
            pid: f.get("pid")?.parse().ok()?,
            start: f.get("start")?.parse().ok()?,
            dev: f.get("dev")?.parse().ok()?,
            ino: f.get("ino")?.parse().ok()?,
            dest: PathBuf::from(std::ffi::OsStr::from_bytes(&dest)),
            staging,
        })
    }
}

/// Writes `data` to `path` atomically: a new 0600 file beside it, then a rename.
fn write_atomic(path: &Path, data: &[u8]) -> io::Result<()> {
    let tmp = path.with_extension("tmp");
    let result = (|| {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
        std::fs::rename(&tmp, path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

// ---- the staging folder ----

/// One job's staging folder. Dropping it removes the folder and the record
/// unless the folder was moved out (`forget`).
pub struct Staging {
    dest: OwnedFd,
    name: String,
    fd: OwnedFd,
    record: Option<PathBuf>,
    gone: bool,
}

impl Staging {
    /// Makes the folder in `dest` and records the job below `state_dir`. A
    /// record that can't be written is logged, not fatal: the job still runs,
    /// only a crash would then leave the hidden folder behind for good.
    pub fn create(
        dest: OwnedFd,
        dest_path: &Path,
        archive_name: &[u8],
        state_dir: Option<&Path>,
    ) -> io::Result<Staging> {
        let st = sys::fstat(bfd(&dest))?;
        let mut record = None;
        if let Some(state) = state_dir {
            match record_path(state) {
                Ok(p) => record = Some(p),
                Err(e) => log::warn!("The job record folder couldn't be made: {e}"),
            }
        }
        let mut tries = 0;
        let name = loop {
            let name = staging_name(archive_name, &sys::random_hex()?);
            if let Some(path) = &record {
                let rec = Record {
                    pid: std::process::id(),
                    start: sys::proc_start(std::process::id()).unwrap_or(0),
                    dest: dest_path.to_path_buf(),
                    dev: st.st_dev,
                    ino: st.st_ino,
                    staging: name.clone(),
                };
                if let Err(e) = write_atomic(path, rec.encode().as_bytes()) {
                    log::warn!("The job record couldn't be written: {e}");
                    record = None;
                }
            }
            match sys::mkdirat(bfd(&dest), name.as_bytes(), 0o700) {
                Ok(()) => break name,
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists && tries < 8 => tries += 1,
                Err(e) => {
                    if let Some(p) = &record {
                        let _ = std::fs::remove_file(p);
                    }
                    return Err(e);
                }
            }
        };
        let opened = sys::open_subdir(bfd(&dest), name.as_bytes()).and_then(|fd| {
            // mkdirat applied the umask; the folder is the user's alone until
            // it is moved out.
            sys::fchmod(bfd(&fd), 0o700)?;
            Ok(fd)
        });
        match opened {
            Ok(fd) => Ok(Staging {
                dest,
                name,
                fd,
                record,
                gone: false,
            }),
            Err(e) => {
                let _ = sys::unlinkat(bfd(&dest), name.as_bytes(), libc::AT_REMOVEDIR);
                if let Some(p) = &record {
                    let _ = std::fs::remove_file(p);
                }
                Err(e)
            }
        }
    }

    pub fn fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }

    /// The descriptor itself, for handing to a worker.
    pub fn fd_owned(&self) -> &OwnedFd {
        &self.fd
    }

    pub fn dest(&self) -> BorrowedFd<'_> {
        self.dest.as_fd()
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// Empties the folder (a new attempt needs it so).
    pub fn clear(&self) -> io::Result<()> {
        remove_contents(self.fd.as_fd(), 0)
    }

    /// Removes the folder and the record. The folder is gone even on `Err`
    /// only as far as the delete got; the record then stays for the next
    /// start's cleanup.
    pub fn remove(&mut self) -> io::Result<()> {
        if self.gone {
            return Ok(());
        }
        remove_tree(self.dest.as_fd(), self.name.as_bytes())?;
        self.forget();
        Ok(())
    }

    /// The folder itself was moved out: nothing is left to remove.
    pub fn forget(&mut self) {
        self.gone = true;
        if let Some(p) = self.record.take()
            && let Err(e) = std::fs::remove_file(&p)
        {
            log::warn!("The job record couldn't be removed: {e}");
        }
    }
}

impl Drop for Staging {
    fn drop(&mut self) {
        if let Err(e) = self.remove() {
            log::warn!(
                "The staging folder {} couldn't be removed: {e}",
                self.name.escape_debug()
            );
        }
    }
}

/// The new record's path, below the jobs folder (made 0700 if need be).
fn record_path(state_dir: &Path) -> io::Result<PathBuf> {
    let dir = jobs_dir(state_dir);
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&dir)?;
    Ok(dir.join(format!("{}-{}.job", std::process::id(), sys::random_hex()?)))
}

// ---- cleaning up after a crash ----

/// What `clean_stale` did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Cleaned {
    /// Records of dead jobs, whose staging folders are gone.
    pub removed: u32,
    /// Records of jobs still running.
    pub live: u32,
    /// Records whose folder couldn't be removed; they stay for next time.
    pub failed: u32,
}

/// Whether the job that wrote `rec` may still be running. Only "no such
/// process" or a different start time says it isn't; anything unreadable
/// counts as alive, so a folder in use is never taken.
fn alive(rec: &Record) -> bool {
    match sys::proc_start(rec.pid) {
        Ok(start) => start == rec.start || rec.start == 0,
        Err(e) if e.kind() == io::ErrorKind::NotFound => false,
        Err(e) => {
            log::warn!("Process {} couldn't be looked up: {e}", rec.pid);
            true
        }
    }
}

/// Removes the staging folders of jobs that are dead, by the records in
/// `<state_dir>/atlas-archive/jobs`. Call it at start.
pub fn clean_stale(state_dir: &Path) -> io::Result<Cleaned> {
    let dir = jobs_dir(state_dir);
    let mut out = Cleaned::default();
    let entries = match std::fs::read_dir(&dir) {
        Ok(e) => e,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(e),
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().is_none_or(|e| e != "job") {
            continue;
        }
        let Some(rec) = read_record(&path) else {
            log::warn!("Removing an unreadable job record.");
            let _ = std::fs::remove_file(&path);
            continue;
        };
        if alive(&rec) {
            out.live += 1;
            continue;
        }
        match remove_dead(&rec) {
            Ok(()) => {
                let _ = std::fs::remove_file(&path);
                out.removed += 1;
            }
            Err(e) => {
                log::warn!(
                    "A leftover staging folder {} couldn't be removed: {e}",
                    rec.staging.escape_debug()
                );
                out.failed += 1;
            }
        }
    }
    Ok(out)
}

fn read_record(path: &Path) -> Option<Record> {
    use std::io::Read;
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .ok()?;
    if !f.metadata().ok()?.is_file() {
        return None;
    }
    let mut text = String::new();
    f.take(MAX_RECORD).read_to_string(&mut text).ok()?;
    Record::parse(&text)
}

fn remove_dead(rec: &Record) -> io::Result<()> {
    let dest = match sys::open_dir(&rec.dest) {
        Ok(d) => d,
        // The destination is gone, and the folder with it.
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    let st = sys::fstat(bfd(&dest))?;
    if st.st_dev != rec.dev || st.st_ino != rec.ino {
        // The path leads somewhere else now: nothing of ours is there.
        log::warn!("A job's destination was replaced; its staging folder is left alone.");
        return Ok(());
    }
    remove_tree(bfd(&dest), rec.staging.as_bytes())
}

// ---- the delete ----

/// Removes `name` below `parent` and everything in it, by descriptor, never
/// following a link: a link is unlinked, not entered. Goes on past an error
/// to remove what it can, then returns the first one.
pub fn remove_tree(parent: BorrowedFd<'_>, name: &[u8]) -> io::Result<()> {
    remove_entry(parent, name, 0)
}

fn remove_entry(parent: BorrowedFd<'_>, name: &[u8], depth: usize) -> io::Result<()> {
    if depth > MAX_REMOVE_DEPTH {
        return Err(io::Error::other("the folders are nested too deeply"));
    }
    let opened = match sys::open_subdir(parent, name) {
        // Owned by us but locked: unlock and look again.
        Err(e) if e.raw_os_error() == Some(libc::EACCES) => {
            if let Ok(c) = cstr(name) {
                // SAFETY: valid descriptor and C string; without
                // AT_SYMLINK_NOFOLLOW honoured the call fails on a link.
                unsafe {
                    libc::fchmodat(
                        parent.as_raw_fd(),
                        c.as_ptr(),
                        0o700,
                        libc::AT_SYMLINK_NOFOLLOW,
                    )
                };
            }
            sys::open_subdir(parent, name)
        }
        r => r,
    };
    let dir = match opened {
        Ok(d) => d,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        // Not a folder (a file, or a link, which O_NOFOLLOW refuses).
        Err(e) if matches!(e.raw_os_error(), Some(libc::ENOTDIR | libc::ELOOP)) => {
            return ignore_missing(sys::unlinkat(parent, name, 0));
        }
        Err(e) => return Err(e),
    };
    let first = remove_contents(bfd(&dir), depth + 1);
    drop(dir);
    let last = ignore_missing(sys::unlinkat(parent, name, libc::AT_REMOVEDIR));
    first.and(last)
}

fn ignore_missing(r: io::Result<()>) -> io::Result<()> {
    match r {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        r => r,
    }
}

/// Removes everything in the folder `dir`.
fn remove_contents(dir: BorrowedFd<'_>, depth: usize) -> io::Result<()> {
    // Search and write for the owner, or nothing below can go.
    let _ = sys::fchmod(dir, 0o700);
    let names = list_names(dir)?;
    let mut first = Ok(());
    for n in names {
        if let Err(e) = remove_entry(dir, &n, depth)
            && first.is_ok()
        {
            first = Err(e);
        }
    }
    first
}

/// The names in the folder `dir`.
fn list_names(dir: BorrowedFd<'_>) -> io::Result<Vec<Vec<u8>>> {
    // A fresh open, not a dup: a dup shares its read position with every
    // other holder (a worker that read the folder would hide its content).
    let copy = sys::openat2(dir, b".", libc::O_RDONLY | libc::O_DIRECTORY)?;
    // SAFETY: fdopendir takes over the descriptor (closed by closedir).
    let dp = unsafe { libc::fdopendir(copy.as_raw_fd()) };
    if dp.is_null() {
        return Err(io::Error::last_os_error());
    }
    std::mem::forget(copy);
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
        let n = unsafe { CStr::from_ptr((*ent).d_name.as_ptr()) }.to_bytes();
        if n != b"." && n != b".." {
            out.push(n.to_vec());
        }
    };
    // SAFETY: closes the stream and the descriptor it owns.
    unsafe { libc::closedir(dp) };
    result.map(|()| out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn staging_names_fit_and_are_in_disk_form() {
        let hex = "0123456789abcdef";
        assert_eq!(
            staging_name(b"a.zip", hex),
            ".a.zip.atlas-partial-0123456789abcdef"
        );
        let long = "é".repeat(300);
        let n = staging_name(long.as_bytes(), hex);
        assert!(n.len() <= 255, "{}", n.len());
        assert!(n.starts_with(".é") && n.ends_with(hex));
        // A control character, a slash and a bad byte never reach the name.
        let n = staging_name(b"a\x01b\xffc", hex);
        assert!(!n.contains('\u{1}') && !n.contains('/'));
        assert!(n.starts_with(".a_b_c"));
    }

    #[test]
    fn records_round_trip_and_refuse_bad_names() {
        let r = Record {
            pid: 7,
            start: 99,
            dest: PathBuf::from("/home/u/a b"),
            dev: 3,
            ino: 4,
            staging: ".x.zip.atlas-partial-0123456789abcdef".into(),
        };
        assert_eq!(Record::parse(&r.encode()), Some(r));
        let bad = "pid=1\nstart=1\ndev=1\nino=1\ndest=/a\nstaging=..%2F..%2Fetc\n";
        assert_eq!(Record::parse(bad), None);
        let bad = "pid=1\nstart=1\ndev=1\nino=1\ndest=a\nstaging=.x.atlas-partial-1\n";
        assert_eq!(Record::parse(bad), None);
    }
}
