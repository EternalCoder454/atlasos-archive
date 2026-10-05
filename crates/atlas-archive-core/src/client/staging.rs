//! The staging folder, the job records that let a later start clean up after
//! a crash, and the delete that never follows a link and never keeps more
//! than a handful of descriptors (docs/DESIGN.md, "Extraction rules").

use std::ffi::CStr;
use std::io::{self, Write};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

use super::sys::{self, bfd, cstr};
use crate::name::{self, MAX_COMPONENT_BYTES};

/// What follows the archive's name in a staging folder's name.
const TAG: &str = ".atlas-partial-";
/// The hex digits that end a staging folder's name.
const HEX_LEN: usize = 16;
/// The delete holds at most this many folders open below the top one. A
/// deeper subtree is moved up to the top (`move_to_top`) and walked from
/// there, so no depth leaves anything behind and the descriptors stay few.
const DELETE_DEPTH: usize = 32;
/// Names read from a folder at a time by the delete.
const BATCH: usize = 4096;
/// The longest job record read back: they are a few hundred bytes.
const MAX_RECORD: u64 = 64 * 1024;
/// The most records one `clean_stale` looks at.
const MAX_RECORDS: usize = 100_000;
/// A record's temporary file older than this is left over from a crash.
const STALE_TMP: Duration = Duration::from_secs(60);
/// How long dropping a `Staging` may spend deleting. Past it the folder and
/// its record stay for the next start's `clean_stale`.
const REMOVE_BUDGET: Duration = Duration::from_secs(300);

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

/// Whether `name` is one `staging_name` could have made: `^\..*\.atlas-partial-[0-9a-f]{16}$`,
/// one component.
fn is_staging_name(name: &str) -> bool {
    let Some(at) = name.len().checked_sub(HEX_LEN) else {
        return false;
    };
    let (head, hex) = name.split_at_checked(at).unwrap_or(("", ""));
    head.len() > TAG.len()
        && head.starts_with('.')
        && head.ends_with(TAG)
        && hex.len() == HEX_LEN
        && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        && name.len() <= MAX_COMPONENT_BYTES
        && !name.contains(['/', '\0'])
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

/// Opens the jobs folder (made 0700 when `create`): it must be a real folder
/// of ours, and one that is wider than 0700 is narrowed.
fn open_jobs_dir(state_dir: &Path, create: bool) -> io::Result<OwnedFd> {
    let dir = jobs_dir(state_dir);
    if create {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&dir)?;
    }
    let fd = sys::open_dir_nofollow(&dir)?;
    let st = sys::fstat(bfd(&fd))?;
    if st.st_mode & libc::S_IFMT != libc::S_IFDIR || st.st_uid != sys::getuid() {
        return Err(io::Error::other(
            "the job record folder isn't a folder of yours",
        ));
    }
    if st.st_mode & 0o077 != 0 {
        sys::fchmod(bfd(&fd), 0o700)?;
    }
    Ok(fd)
}

// ---- job records ----

/// What a later start needs to remove a dead job's staging folder.
#[derive(Debug, PartialEq, Eq)]
struct Record {
    pid: u32,
    start: u64,
    /// This boot's id: a record from another boot is dead whatever its pid.
    boot: Option<String>,
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
        let boot = self
            .boot
            .as_ref()
            .map(|b| format!("boot={b}\n"))
            .unwrap_or_default();
        format!(
            "pid={}\nstart={}\n{boot}dev={}\nino={}\ndest={}\nstaging={}\n",
            self.pid,
            self.start,
            self.dev,
            self.ino,
            sys::pct_encode(self.dest.as_os_str().as_bytes()),
            sys::pct_encode(self.staging.as_bytes()),
        )
    }

    /// `None` for anything that isn't what `encode` writes. A record proves
    /// nothing by itself: `remove_dead` checks the folder it names.
    fn parse(text: &str) -> Option<Record> {
        let mut f = std::collections::HashMap::new();
        for line in text.lines() {
            let (k, v) = line.split_once('=')?;
            f.insert(k, v);
        }
        let dest = sys::pct_decode(f.get("dest")?)?;
        let staging = String::from_utf8(sys::pct_decode(f.get("staging")?)?).ok()?;
        // It is used as a name below the destination: nothing else will do.
        if !is_staging_name(&staging) || dest.first() != Some(&b'/') || dest.contains(&0) {
            return None;
        }
        let boot = match f.get("boot") {
            None => None,
            Some(b)
                if !b.is_empty()
                    && b.len() <= 64
                    && b.bytes().all(|c| c.is_ascii_hexdigit() || c == b'-') =>
            {
                Some(b.to_string())
            }
            Some(_) => return None,
        };
        Some(Record {
            pid: f.get("pid")?.parse().ok()?,
            start: f.get("start")?.parse().ok()?,
            boot,
            dev: f.get("dev")?.parse().ok()?,
            ino: f.get("ino")?.parse().ok()?,
            dest: PathBuf::from(std::ffi::OsStr::from_bytes(&dest)),
            staging,
        })
    }
}

/// A record file: its folder, held open, and its name in it.
struct RecordFile {
    dir: OwnedFd,
    file: String,
}

impl RecordFile {
    /// Writes `data` atomically: a new 0600 file beside it, synced, a rename,
    /// then a sync of the folder. A failed write leaves no temporary file.
    fn write(&self, data: &[u8]) -> io::Result<()> {
        let tmp = format!("{}.tmp", self.file);
        let result = (|| {
            let fd = create_new(bfd(&self.dir), tmp.as_bytes(), 0o600)?;
            let mut f = std::fs::File::from(fd);
            f.write_all(data)?;
            f.sync_all()?;
            drop(f);
            sys::rename(
                bfd(&self.dir),
                tmp.as_bytes(),
                bfd(&self.dir),
                self.file.as_bytes(),
            )?;
            // SAFETY: a valid descriptor; a failed sync only costs durability.
            if unsafe { libc::fsync(self.dir.as_raw_fd()) } < 0 {
                log::debug!(
                    "The job folder couldn't be synced: {}",
                    io::Error::last_os_error()
                );
            }
            Ok(())
        })();
        if result.is_err() {
            let _ = sys::unlinkat(bfd(&self.dir), tmp.as_bytes(), 0);
        }
        result
    }

    fn remove(&self) -> io::Result<()> {
        sys::unlinkat(bfd(&self.dir), self.file.as_bytes(), 0)
    }
}

/// A new file `name` in `dir`: `O_EXCL | O_NOFOLLOW`, so a name is never shared.
fn create_new(dir: BorrowedFd<'_>, name: &[u8], mode: u32) -> io::Result<OwnedFd> {
    let c = cstr(name)?;
    let fd = sys::retry(|| {
        // SAFETY: a valid descriptor and C string; a new descriptor we own.
        let fd = unsafe {
            libc::openat(
                dir.as_raw_fd(),
                c.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                mode as libc::c_uint,
            )
        };
        if fd < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(fd)
        }
    })?;
    // SAFETY: a new descriptor returned by a successful call.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

// ---- the staging folder ----

/// Whether others can change the folder `st` describes and could therefore
/// swap names in it under us: write for others without the sticky bit.
/// (Group write is left alone: on most systems a user's group is theirs.)
/// Residual risk, documented in DESIGN.md: a process of the same user, or
/// anyone who can write the destination, can still race the name-based moves.
pub fn dest_is_shared(st: &libc::stat) -> bool {
    st.st_mode & libc::S_IWOTH != 0 && st.st_mode & libc::S_ISVTX == 0
}

/// One job's staging folder. Dropping it removes the folder and the record
/// unless the folder was moved out (`forget`) or left for the next start
/// (`leave_for_cleanup`).
pub struct Staging {
    dest: OwnedFd,
    name: String,
    fd: OwnedFd,
    record: Option<RecordFile>,
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
        // The path the kernel knows the folder by is the one a later start
        // can open without a link in the way.
        let recorded_dest = sys::fd_path(bfd(&dest)).unwrap_or_else(|| dest_path.to_path_buf());
        let mut record = None;
        if let Some(state) = state_dir {
            let made = open_jobs_dir(state, true).and_then(|dir| {
                Ok(RecordFile {
                    dir,
                    file: format!("{}-{}.job", std::process::id(), sys::random_hex()?),
                })
            });
            match made {
                Ok(r) => record = Some(r),
                Err(e) => log::warn!("The job record folder couldn't be made: {e}"),
            }
        }
        let boot = sys::boot_id();
        let mut tries = 0;
        let name = loop {
            let name = staging_name(archive_name, &sys::random_hex()?);
            if let Some(r) = &record {
                let rec = Record {
                    pid: std::process::id(),
                    start: sys::proc_start(std::process::id()).unwrap_or(0),
                    boot: boot.clone(),
                    dest: recorded_dest.clone(),
                    dev: st.st_dev,
                    ino: st.st_ino,
                    staging: name.clone(),
                };
                if let Err(e) = r.write(rec.encode().as_bytes()) {
                    log::warn!("The job record couldn't be written: {e}");
                    record = None;
                }
            }
            match sys::mkdirat(bfd(&dest), name.as_bytes(), 0o700) {
                Ok(()) => break name,
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists && tries < 8 => tries += 1,
                Err(e) => {
                    if let Some(r) = &record {
                        let _ = r.remove();
                    }
                    return Err(e);
                }
            }
        };
        let opened = sys::open_subdir(bfd(&dest), name.as_bytes()).and_then(|fd| {
            // mkdirat applied the umask; the folder is the user's alone until
            // it is moved out. (A file system without modes keeps what it has.)
            sys::fchmod_soft(bfd(&fd), 0o700)?;
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
                if let Some(r) = &record {
                    let _ = r.remove();
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

    /// Whether the staging name in the destination still names this folder.
    pub fn name_is_ours(&self) -> io::Result<bool> {
        let ours = sys::fstat(self.fd.as_fd())?;
        match sys::lstatat(self.dest.as_fd(), self.name.as_bytes()) {
            Ok(n) => Ok(sys::same_file(&n, &ours)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Empties the folder (a new attempt needs it so).
    pub fn clear(&self) -> io::Result<()> {
        purge(self.fd.as_fd(), None)
    }

    /// Removes the folder and the record. The content goes by descriptor and
    /// the name only if it still names this folder, so a swapped name is never
    /// followed. Past `REMOVE_BUDGET`, or on an error, the folder and the
    /// record stay for the next start's cleanup.
    pub fn remove(&mut self) -> io::Result<()> {
        if self.gone {
            return Ok(());
        }
        purge(self.fd.as_fd(), Some(Instant::now() + REMOVE_BUDGET))?;
        if self.name_is_ours()? {
            sys::unlinkat(self.dest.as_fd(), self.name.as_bytes(), libc::AT_REMOVEDIR)?;
        } else {
            log::warn!("The staging folder's name was changed; its content was removed in place.");
        }
        self.forget();
        Ok(())
    }

    /// The folder itself was moved out (or is kept for the user): nothing is
    /// left to remove, and the record goes.
    pub fn forget(&mut self) {
        self.gone = true;
        if let Some(r) = self.record.take()
            && let Err(e) = r.remove()
        {
            log::warn!("The job record couldn't be removed: {e}");
        }
    }

    /// Keeps the folder and its record, for the next start's `clean_stale`:
    /// used when the drive stopped answering and nothing may touch it now.
    pub fn leave_for_cleanup(&mut self) {
        self.gone = true;
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

// ---- cleaning up after a crash ----

/// What `clean_stale` did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Cleaned {
    /// Records of dead jobs, whose staging folders are gone.
    pub removed: u32,
    /// Records of jobs still running.
    pub live: u32,
    /// Records whose folder couldn't be removed or proven; they stay for next time.
    pub failed: u32,
}

/// Whether the job that wrote `rec` (the record file last changed at `mtime`)
/// may still be running. Another boot, no such process or a different start
/// time say it isn't; anything unreadable counts as alive, so a folder in use
/// is never taken.
fn alive(rec: &Record, mtime: SystemTime) -> bool {
    if let (Some(then), Some(now)) = (&rec.boot, sys::boot_id())
        && *then != now
    {
        return false;
    }
    match sys::proc_start(rec.pid) {
        Ok(start) if rec.start != 0 => start == rec.start,
        // The job couldn't read its own start time: a process that began
        // after the record was written is a later one with the number.
        Ok(start) => !started_after(start, mtime),
        Err(e) if e.kind() == io::ErrorKind::NotFound => false,
        Err(e) => {
            log::warn!("Process {} couldn't be looked up: {e}", rec.pid);
            true
        }
    }
}

/// Whether a process that started `start` clock ticks after boot began after `mtime`.
fn started_after(start: u64, mtime: SystemTime) -> bool {
    let up = std::fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|t| t.split_whitespace().next()?.parse::<f64>().ok());
    // SAFETY: sysconf takes no pointers.
    let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    let (Some(up), true, Ok(age)) = (up, hz > 0, SystemTime::now().duration_since(mtime)) else {
        return false;
    };
    let running = up - start as f64 / hz as f64;
    running + 2.0 < age.as_secs_f64()
}

/// Removes the staging folders of jobs that are dead, by the records in
/// `<state_dir>/atlas-archive/jobs`. Call it at start, **off the UI thread**:
/// it may block for as long as a dead mount or a huge tree takes. Stale
/// temporary files of the record writer go too.
pub fn clean_stale(state_dir: &Path) -> io::Result<Cleaned> {
    let mut out = Cleaned::default();
    let dir = match open_jobs_dir(state_dir, false) {
        Ok(d) => d,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(e),
    };
    for name in read_names(bfd(&dir), MAX_RECORDS)? {
        if name.ends_with(b".tmp") {
            if let Ok(st) = sys::lstatat(bfd(&dir), &name) {
                let age = SystemTime::now()
                    .duration_since(
                        SystemTime::UNIX_EPOCH + Duration::from_secs(st.st_mtime.max(0) as u64),
                    )
                    .unwrap_or_default();
                if age > STALE_TMP {
                    let _ = sys::unlinkat(bfd(&dir), &name, 0);
                }
            }
            continue;
        }
        if !name.ends_with(b".job") {
            continue;
        }
        let Some((rec, mtime)) = read_record(bfd(&dir), &name) else {
            log::warn!("Removing an unreadable job record.");
            let _ = sys::unlinkat(bfd(&dir), &name, 0);
            continue;
        };
        if alive(&rec, mtime) {
            out.live += 1;
            continue;
        }
        match remove_dead(&rec) {
            Ok(Dead::Removed) => {
                let _ = sys::unlinkat(bfd(&dir), &name, 0);
                out.removed += 1;
            }
            Ok(Dead::NotOurs) => {
                log::warn!(
                    "A job record named {}, which is no staging folder of ours; it was left alone.",
                    rec.staging.escape_debug()
                );
                let _ = sys::unlinkat(bfd(&dir), &name, 0);
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

/// The record `name` in the jobs folder, when it is a plain file of ours that
/// no one else could have written, and when it was last written.
fn read_record(dir: BorrowedFd<'_>, name: &[u8]) -> Option<(Record, SystemTime)> {
    use std::io::Read;
    let fd = sys::openat2(
        dir,
        name,
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK,
    )
    .ok()?;
    let st = sys::fstat(bfd(&fd)).ok()?;
    if st.st_mode & libc::S_IFMT != libc::S_IFREG
        || st.st_uid != sys::getuid()
        || st.st_mode & 0o022 != 0
    {
        return None;
    }
    let mut text = String::new();
    std::fs::File::from(fd)
        .take(MAX_RECORD)
        .read_to_string(&mut text)
        .ok()?;
    let mtime = SystemTime::UNIX_EPOCH + Duration::from_secs(st.st_mtime.max(0) as u64);
    Some((Record::parse(&text)?, mtime))
}

enum Dead {
    Removed,
    NotOurs,
}

/// A staging folder that the job made: a folder of ours, mode exactly 0700
/// (it is that until it moves out, so nothing a user made matches).
fn is_proven_staging(st: &libc::stat) -> bool {
    st.st_mode & libc::S_IFMT == libc::S_IFDIR
        && st.st_uid == sys::getuid()
        && st.st_mode & 0o7777 == 0o700
}

fn remove_dead(rec: &Record) -> io::Result<Dead> {
    // Without following a link at the end; if the user's own path is a link
    // (a folder reached through one), follow it but then demand the exact
    // device and inode.
    let (dest, followed) = match sys::open_dir_nofollow(&rec.dest) {
        Ok(d) => (d, false),
        Err(e) if e.raw_os_error() == Some(libc::ELOOP) => (sys::open_dir(&rec.dest)?, true),
        // The destination is gone, and the folder with it.
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Dead::Removed),
        Err(e) => return Err(e),
    };
    let st = sys::fstat(bfd(&dest))?;
    // The pinned inode must always match. The device may differ across boots
    // (btrfs subvolumes are numbered at mount): then the inode and the
    // staging proof below carry it. With the device the same, a different
    // inode means the path leads elsewhere now: keep the record.
    if st.st_ino != rec.ino || (followed && st.st_dev != rec.dev) {
        return Err(io::Error::other(
            "the destination isn't the folder the job was given",
        ));
    }
    match remove_proven(bfd(&dest), rec.staging.as_bytes(), None, &is_proven_staging)? {
        true => Ok(Dead::Removed),
        false => Ok(Dead::NotOurs),
    }
}

// ---- the delete ----

/// Removes the folder `name` below `parent` and everything in it, by
/// descriptor, never following a link (a link is unlinked, not entered), but
/// only if `prove` accepts what the opened folder is. `Ok(false)`: it is
/// something else (or the name was swapped): nothing was removed. Gone
/// already is `Ok(true)`. With a `deadline`, a delete that runs past it
/// stops with a `TimedOut` error and leaves the rest.
fn remove_proven(
    parent: BorrowedFd<'_>,
    name: &[u8],
    deadline: Option<Instant>,
    prove: &dyn Fn(&libc::stat) -> bool,
) -> io::Result<bool> {
    let dir = match sys::open_subdir(parent, name) {
        Ok(d) => d,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(true),
        // Not a folder (a file, or a link, which O_NOFOLLOW refuses).
        Err(e) if matches!(e.raw_os_error(), Some(libc::ENOTDIR | libc::ELOOP)) => {
            return Ok(false);
        }
        Err(e) => return Err(e),
    };
    let ours = sys::fstat(bfd(&dir))?;
    if !prove(&ours) {
        return Ok(false);
    }
    purge(bfd(&dir), deadline)?;
    drop(dir);
    match sys::lstatat(parent, name) {
        Ok(n) if sys::same_file(&n, &ours) => {}
        Ok(_) => return Ok(false),
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(true),
        Err(e) => return Err(e),
    }
    ignore_missing(sys::unlinkat(parent, name, libc::AT_REMOVEDIR))?;
    Ok(true)
}

fn ignore_missing(r: io::Result<()>) -> io::Result<()> {
    match r {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        r => r,
    }
}

/// What became of one name in a folder being emptied.
enum Leaf {
    Gone,
    NotEmpty,
    Err(io::Error),
}

fn remove_leaf(dir: BorrowedFd<'_>, name: &[u8]) -> Leaf {
    match sys::unlinkat(dir, name, 0) {
        Ok(()) => Leaf::Gone,
        Err(e) if e.kind() == io::ErrorKind::NotFound => Leaf::Gone,
        Err(e) if matches!(e.raw_os_error(), Some(libc::EISDIR | libc::EPERM)) => {
            match sys::unlinkat(dir, name, libc::AT_REMOVEDIR) {
                Ok(()) => Leaf::Gone,
                Err(e) if e.kind() == io::ErrorKind::NotFound => Leaf::Gone,
                Err(e) if matches!(e.raw_os_error(), Some(libc::ENOTEMPTY | libc::EEXIST)) => {
                    Leaf::NotEmpty
                }
                Err(e) => Leaf::Err(e),
            }
        }
        Err(e) => Leaf::Err(e),
    }
}

/// Opens the folder `name` below `dir` for emptying: owned by us but locked is
/// unlocked, and it is made searchable and writable for its owner.
fn open_for_delete(dir: BorrowedFd<'_>, name: &[u8]) -> io::Result<OwnedFd> {
    let fd = match sys::open_subdir(dir, name) {
        Err(e) if e.raw_os_error() == Some(libc::EACCES) => {
            if let Ok(c) = cstr(name) {
                // SAFETY: valid descriptor and C string; with
                // AT_SYMLINK_NOFOLLOW the call fails on a link.
                unsafe {
                    libc::fchmodat(
                        dir.as_raw_fd(),
                        c.as_ptr(),
                        0o700,
                        libc::AT_SYMLINK_NOFOLLOW,
                    )
                };
            }
            sys::open_subdir(dir, name)?
        }
        r => r?,
    };
    let _ = sys::fchmod(bfd(&fd), 0o700);
    Ok(fd)
}

/// Moves the folder `name` of `dir` up to `root` under a fresh name, so the
/// walk goes on from there at depth one.
fn move_to_top(dir: BorrowedFd<'_>, name: &[u8], root: BorrowedFd<'_>) -> io::Result<()> {
    // Moving a folder to another parent needs write access to the folder.
    drop(open_for_delete(dir, name)?);
    let mut last = io::Error::other("no free name for a folder being deleted");
    for _ in 0..8 {
        let to = format!(".atlas-delete-{}", sys::random_hex()?);
        match sys::rename_noreplace(dir, name, root, to.as_bytes()) {
            Ok(()) => return Ok(()),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => last = e,
            Err(e) => return Err(e),
        }
    }
    Err(last)
}

/// Removes everything in the folder `root`, keeping `root` itself. Iterative
/// and without depth limit: it holds at most `DELETE_DEPTH` + 2 descriptors,
/// reads names `BATCH` at a time (so a folder of millions never sits in
/// memory), and moves a subtree that gets deeper than `DELETE_DEPTH` up to
/// `root` to be walked from there. Never follows a link; every open resolves
/// below the folder it starts from (`sys::RESOLVE`).
fn purge(root: BorrowedFd<'_>, deadline: Option<Instant>) -> io::Result<()> {
    // Search and write for the owner, or nothing below can go.
    let _ = sys::fchmod(root, 0o700);
    // The folders being emptied below `root`, deepest last, with their names.
    let mut stack: Vec<(Vec<u8>, OwnedFd)> = Vec::new();
    loop {
        if deadline.is_some_and(|d| Instant::now() >= d) {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "removing the folders took too long",
            ));
        }
        let cur_raw: RawFd = stack
            .last()
            .map_or(root.as_raw_fd(), |(_, fd)| fd.as_raw_fd());
        // SAFETY: `cur_raw` is `root` or a descriptor in `stack`; pushing to
        // the stack moves the OwnedFd, not the descriptor, and a pop below
        // happens only after the last use of `cur`.
        let cur = unsafe { BorrowedFd::borrow_raw(cur_raw) };
        let names = read_names(cur, BATCH)?;
        if names.is_empty() {
            let Some((name, fd)) = stack.pop() else {
                return Ok(());
            };
            drop(fd);
            let parent = stack.last().map_or(root, |(_, fd)| fd.as_fd());
            ignore_missing(sys::unlinkat(parent, &name, libc::AT_REMOVEDIR))?;
            continue;
        }
        let mut progressed = false;
        let mut first: Option<io::Error> = None;
        for n in &names {
            match remove_leaf(cur, n) {
                Leaf::Gone => progressed = true,
                Leaf::Err(e) => {
                    first.get_or_insert(e);
                }
                Leaf::NotEmpty if stack.len() >= DELETE_DEPTH => match move_to_top(cur, n, root) {
                    Ok(()) => progressed = true,
                    Err(e) => {
                        first.get_or_insert(e);
                    }
                },
                Leaf::NotEmpty => match open_for_delete(cur, n) {
                    Ok(fd) => {
                        stack.push((n.clone(), fd));
                        // The rest of this batch is read again later.
                        progressed = true;
                        break;
                    }
                    Err(e) if e.kind() == io::ErrorKind::NotFound => progressed = true,
                    Err(e) => {
                        first.get_or_insert(e);
                    }
                },
            }
        }
        if !progressed {
            // Nothing in this pass could go: reading again would loop.
            return Err(first.unwrap_or_else(|| io::Error::other("a folder couldn't be emptied")));
        }
    }
}

/// Up to `max` names in the folder `dir`.
fn read_names(dir: BorrowedFd<'_>, max: usize) -> io::Result<Vec<Vec<u8>>> {
    // A fresh open, not a dup: a dup shares its read position with every
    // other holder (a worker that read the folder would hide its content).
    let copy = sys::openat2(dir, b".", libc::O_RDONLY | libc::O_DIRECTORY)?;
    let raw = copy.into_raw_fd();
    // SAFETY: fdopendir takes over the descriptor (closed by closedir) on success.
    let dp = unsafe { libc::fdopendir(raw) };
    if dp.is_null() {
        let e = io::Error::last_os_error();
        // SAFETY: fdopendir failed, so the descriptor is still ours.
        unsafe { libc::close(raw) };
        return Err(e);
    }
    let mut out = Vec::new();
    let result = loop {
        if out.len() >= max {
            break Ok(());
        }
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
        let n = staging_name(b"a\x01b/\xffc", hex);
        assert!(!n.contains('\u{1}') && !n.contains('/'), "{n}");
        assert!(n.starts_with(".a_b"), "{n}");
        assert!(is_staging_name(&n));
    }

    #[test]
    fn only_names_staging_could_make_are_accepted() {
        assert!(is_staging_name(".x.zip.atlas-partial-0123456789abcdef"));
        assert!(is_staging_name("..atlas-partial-0123456789abcdef"));
        for bad in [
            "x.zip.atlas-partial-0123456789abcdef",
            ".x.zip.atlas-partial-0123456789abcde",
            ".x.zip.atlas-partial-0123456789ABCDEF",
            ".x.zip.atlas-partial-0123456789abcdeg",
            ".x.zip.atlas-partial-0123456789abcdef0",
            ".x.atlas-partial-1",
            ".atlas-partial-0123456789abcdef",
            ".a/b.atlas-partial-0123456789abcdef",
            "Documents",
            "",
        ] {
            assert!(!is_staging_name(bad), "{bad:?}");
        }
    }

    #[test]
    fn records_round_trip_and_refuse_bad_names() {
        let r = Record {
            pid: 7,
            start: 99,
            boot: Some("0f0e-1234".into()),
            dest: PathBuf::from("/home/u/a b"),
            dev: 3,
            ino: 4,
            staging: ".x.zip.atlas-partial-0123456789abcdef".into(),
        };
        assert_eq!(Record::parse(&r.encode()), Some(r));
        let old =
            "pid=1\nstart=1\ndev=1\nino=1\ndest=/a\nstaging=.x.atlas-partial-0123456789abcdef\n";
        let p = Record::parse(old).expect("a record without a boot id");
        assert_eq!(p.boot, None);
        let bad = "pid=1\nstart=1\ndev=1\nino=1\ndest=/a\nstaging=..%2F..%2Fetc\n";
        assert_eq!(Record::parse(bad), None);
        let bad =
            "pid=1\nstart=1\ndev=1\nino=1\ndest=a\nstaging=.x.atlas-partial-0123456789abcdef\n";
        assert_eq!(Record::parse(bad), None);
        // A plain folder name, even with the tag in it, is not a staging name.
        let bad = "pid=1\nstart=1\ndev=1\nino=1\ndest=/a\nstaging=Documents.atlas-partial-1\n";
        assert_eq!(Record::parse(bad), None);
        let bad = "pid=1\nstart=1\nboot=zz\ndev=1\nino=1\ndest=/a\nstaging=.x.atlas-partial-0123456789abcdef\n";
        assert_eq!(Record::parse(bad), None);
    }

    fn scratch(tag: &str) -> PathBuf {
        let base = std::env::var_os("ATLAS_ARCHIVE_TEST_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let p = base.join(format!("atlas-staging-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn open_fds() -> usize {
        std::fs::read_dir("/proc/self/fd").unwrap().count()
    }

    #[test]
    fn a_chain_of_two_thousand_folders_is_removed_without_a_trace() {
        let base = scratch("deep");
        let top = sys::open_dir(&base).unwrap();
        sys::mkdirat(bfd(&top), b"s", 0o700).unwrap();
        // One folder per level, made relative to the one before: a path this
        // long can't be given to the kernel whole.
        let mut cur = sys::open_subdir(bfd(&top), b"s").unwrap();
        for _ in 0..2000 {
            sys::mkdirat(bfd(&cur), b"d", 0o755).unwrap();
            cur = sys::open_subdir(bfd(&cur), b"d").unwrap();
        }
        drop(cur);
        let before = open_fds();
        assert!(remove_proven(bfd(&top), b"s", None, &|_| true).unwrap());
        assert_eq!(open_fds(), before, "no descriptor is left open");
        assert_eq!(
            sys::lstatat(bfd(&top), b"s").unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        assert_eq!(
            std::fs::read_dir(&base).unwrap().count(),
            0,
            "no moved folder is left"
        );
        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn a_folder_of_two_hundred_thousand_files_is_removed() {
        let base = scratch("flat");
        let top = sys::open_dir(&base).unwrap();
        sys::mkdirat(bfd(&top), b"s", 0o700).unwrap();
        let s = sys::open_subdir(bfd(&top), b"s").unwrap();
        for i in 0..200_000u32 {
            drop(create_new(bfd(&s), i.to_string().as_bytes(), 0o600).unwrap());
        }
        drop(s);
        assert!(remove_proven(bfd(&top), b"s", None, &|_| true).unwrap());
        assert_eq!(std::fs::read_dir(&base).unwrap().count(), 0);
        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn a_proof_that_fails_removes_nothing_and_a_deadline_stops_the_delete() {
        let base = scratch("proof");
        let top = sys::open_dir(&base).unwrap();
        sys::mkdirat(bfd(&top), b"s", 0o700).unwrap();
        let s = sys::open_subdir(bfd(&top), b"s").unwrap();
        drop(create_new(bfd(&s), b"f", 0o600).unwrap());
        assert!(!remove_proven(bfd(&top), b"s", None, &|_| false).unwrap());
        assert!(sys::lstatat(bfd(&s), b"f").is_ok());
        let past = Instant::now() - Duration::from_secs(1);
        let e = remove_proven(bfd(&top), b"s", Some(past), &|_| true).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::TimedOut);
        assert!(sys::lstatat(bfd(&s), b"f").is_ok());
        std::fs::remove_dir_all(&base).unwrap();
    }
}
