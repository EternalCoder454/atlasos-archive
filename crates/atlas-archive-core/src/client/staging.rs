//! The staging folder, the job records that let a later start clean up after
//! a crash, and the delete that never follows a link and never keeps more
//! than a handful of descriptors (docs/DESIGN.md, "Extraction rules").

use std::ffi::CStr;
use std::io::{self, Write};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
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
/// The time one `clean_stale` spends deleting, over all records. A record
/// whose delete doesn't finish stays for the next start.
const CLEAN_BUDGET: Duration = Duration::from_secs(20);
/// How long a record whose destination is missing or different is kept (by
/// the record's own age) before it is dropped.
const WAIT_LIMIT: Duration = Duration::from_secs(30 * 24 * 3600);

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

/// The staging name that doesn't depend on the archive's name, for a drive
/// that refuses the archive's (FAT, exFAT and NTFS reject `: ? * " < > |`).
pub fn plain_staging_name(hex: &str) -> String {
    format!(".archive{TAG}{hex}")
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
    /// Whether the file system kept the folder's 0700 mode when it was made.
    /// False on FAT and the like: the mode then proves nothing.
    modes: bool,
}

impl Record {
    fn encode(&self) -> String {
        let boot = self
            .boot
            .as_ref()
            .map(|b| format!("boot={b}\n"))
            .unwrap_or_default();
        let modes = if self.modes { "" } else { "modes=0\n" };
        format!(
            "pid={}\nstart={}\n{boot}dev={}\nino={}\ndest={}\nstaging={}\n{modes}",
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
        // Older records have no such line: their folders kept their modes.
        let modes = match f.get("modes") {
            None | Some(&"1") => true,
            Some(&"0") => false,
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
            modes,
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
    /// The temporary name is this write's own, so two writers never remove
    /// each other's, and one a killed writer left is swept as stale.
    fn write(&self, data: &[u8]) -> io::Result<()> {
        let tmp = format!(
            "{}.{}-{}.tmp",
            self.file,
            std::process::id(),
            sys::random_hex()?
        );
        let mut made = false;
        let result = (|| {
            let fd = create_new(bfd(&self.dir), tmp.as_bytes(), 0o600)?;
            made = true;
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
        if result.is_err() && made {
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
/// swap names in it under us: write for others without the sticky bit, or
/// write for a group that isn't our own (group write on the user's own
/// private group stays allowed). The caveat: a user's primary group is
/// taken to be private to them, as on Fedora; where it is a shared group
/// (a `users` group everyone is in) group write is not seen as shared.
/// POSIX ACLs are looked at by `acl_is_shared`, which needs the descriptor.
/// Residual risk, documented in DESIGN.md: a process of the same user, or
/// anyone who can write the destination, can still race the name-based moves.
pub fn dest_is_shared(st: &libc::stat) -> bool {
    shared_for(st, sys::getuid(), sys::getegid())
}

/// Also shared: a folder another user owns and can write, even when sticky
/// (an owner may rename anything in it). Root is left out: it can do
/// anything anyway.
fn shared_for(st: &libc::stat, uid: u32, egid: u32) -> bool {
    let foreign_owner = st.st_uid != uid && st.st_uid != 0 && st.st_mode & libc::S_IWUSR != 0;
    foreign_owner
        || st.st_mode & libc::S_ISVTX == 0
            && (st.st_mode & libc::S_IWOTH != 0
                || (st.st_mode & libc::S_IWGRP != 0 && st.st_gid != egid))
}

/// `system.posix_acl_access`: version 2, then 8-byte entries (tag, permission, id).
const ACL_XATTR: &CStr = c"system.posix_acl_access";
const ACL_VERSION: u32 = 2;
const ACL_USER: u16 = 2;
const ACL_GROUP: u16 = 8;
const ACL_MASK: u16 = 0x10;
const ACL_WRITE: u16 = 2;

/// Whether the access ACL `acl` (as the xattr holds it) lets a user other
/// than `uid`, or any named group, write: with the mask letting it through.
/// Anything malformed counts as shared.
fn acl_grants_others(acl: &[u8], uid: u32) -> bool {
    if acl.len() < 4
        || !(acl.len() - 4).is_multiple_of(8)
        || u32::from_le_bytes([acl[0], acl[1], acl[2], acl[3]]) != ACL_VERSION
    {
        return true;
    }
    let entries = || {
        acl[4..].as_chunks::<8>().0.iter().map(|e| {
            (
                u16::from_le_bytes([e[0], e[1]]),
                u16::from_le_bytes([e[2], e[3]]),
                u32::from_le_bytes([e[4], e[5], e[6], e[7]]),
            )
        })
    };
    let mask = entries().find(|e| e.0 == ACL_MASK).map(|e| e.1);
    let through = mask.is_none_or(|m| m & ACL_WRITE != 0);
    through
        && entries().any(|(tag, perm, id)| {
            perm & ACL_WRITE != 0 && (tag == ACL_GROUP || (tag == ACL_USER && id != uid))
        })
}

/// Whether the folder `fd`'s POSIX ACL lets others write in it. No ACL, or a
/// file system without them, is not shared; an ACL that can't be read is an
/// error, so the answer is never a guess.
pub fn acl_is_shared(fd: BorrowedFd<'_>) -> io::Result<bool> {
    let mut buf = [0u8; 4096];
    // SAFETY: a valid descriptor, name and a buffer of the length passed.
    let n = unsafe {
        libc::fgetxattr(
            fd.as_raw_fd(),
            ACL_XATTR.as_ptr(),
            buf.as_mut_ptr().cast(),
            buf.len(),
        )
    };
    if n < 0 {
        let e = io::Error::last_os_error();
        return match e.raw_os_error() {
            Some(libc::ENODATA | libc::ENOTSUP) => Ok(false),
            // More entries than 4 KiB hold: surely shared.
            Some(libc::ERANGE) => Ok(true),
            _ => Err(e),
        };
    }
    Ok(acl_grants_others(&buf[..n as usize], sys::getuid()))
}

/// A folder of ours: what a staging folder we just made must be.
pub fn is_our_dir(st: &libc::stat) -> bool {
    st.st_mode & libc::S_IFMT == libc::S_IFDIR && st.st_uid == sys::getuid()
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
    /// A delete ran out of time: the folder and record stay for the next
    /// start and nothing retries it (`clear` has only `&self`).
    stuck: AtomicBool,
    /// The file system kept the folder's 0700 mode when it was made (what
    /// `Record::modes` says): where it didn't, mode changes may be refused.
    modes_kept: bool,
}

impl Staging {
    /// Whether the drive keeps modes (measured when the folder was made).
    pub fn modes_kept(&self) -> bool {
        self.modes_kept
    }

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
        if acl_is_shared(bfd(&dest))? {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "other users can change this folder (it has an access list), so it isn't safe to extract into",
            ));
        }
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
        // The archive's name goes into the staging name, unless the drive
        // refuses it (EINVAL below: FAT, exFAT, NTFS), and then it doesn't.
        let mut plain = false;
        let name = loop {
            let hex = sys::random_hex()?;
            let mut name = staging_name(archive_name, &hex);
            if plain {
                name = plain_staging_name(&hex);
            }
            if let Some(r) = &record {
                let rec = Record {
                    pid: std::process::id(),
                    start: sys::proc_start(std::process::id()).unwrap_or(0),
                    boot: boot.clone(),
                    dest: recorded_dest.clone(),
                    dev: st.st_dev,
                    ino: st.st_ino,
                    staging: name.clone(),
                    modes: true,
                };
                if let Err(e) = r.write(rec.encode().as_bytes()) {
                    log::warn!("The job record couldn't be written: {e}");
                    record = None;
                }
            }
            match sys::mkdirat(bfd(&dest), name.as_bytes(), 0o700) {
                Ok(()) => break name,
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists && tries < 8 => tries += 1,
                // Untested: provoking this EINVAL needs a FAT mount.
                Err(e) if e.raw_os_error() == Some(libc::EINVAL) && !plain => {
                    log::debug!("The drive refused the staging name, trying a plain one: {e}");
                    plain = true;
                }
                Err(e) => {
                    if let Some(r) = &record {
                        let _ = r.remove();
                    }
                    return Err(e);
                }
            }
        };
        let opened = sys::open_subdir(bfd(&dest), name.as_bytes()).and_then(|fd| {
            // The name must lead to the folder we just made: a folder of ours,
            // and a new one, so empty (not one that was there before).
            if !is_our_dir(&sys::fstat(bfd(&fd))?) {
                return Err(io::Error::other("the new staging folder isn't ours"));
            }
            if !read_names(bfd(&fd), 1)?.is_empty() {
                return Err(io::Error::other("the new staging folder isn't empty"));
            }
            // mkdirat applied the umask; the folder is the user's alone until
            // it is moved out. (A file system without modes keeps what it has;
            // that is tolerated only here, for a folder that is ours.)
            sys::fchmod_soft(bfd(&fd), 0o700)?;
            let kept = sys::fstat(bfd(&fd))?.st_mode & 0o777 == 0o700;
            Ok((fd, kept))
        });
        match opened {
            Ok((fd, kept)) => {
                if !kept && let Some(r) = &record {
                    // The mode proves nothing on this file system: say so in
                    // the record, so a later start doesn't demand it.
                    let rec = Record {
                        pid: std::process::id(),
                        start: sys::proc_start(std::process::id()).unwrap_or(0),
                        boot,
                        dest: recorded_dest,
                        dev: st.st_dev,
                        ino: st.st_ino,
                        staging: name.clone(),
                        modes: false,
                    };
                    if let Err(e) = r.write(rec.encode().as_bytes()) {
                        log::warn!("The job record couldn't be updated: {e}");
                    }
                }
                Ok(Staging {
                    dest,
                    name,
                    fd,
                    record,
                    gone: false,
                    stuck: AtomicBool::new(false),
                    modes_kept: kept,
                })
            }
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

    /// Empties the folder (a new attempt needs it so), within `REMOVE_BUDGET`.
    pub fn clear(&self) -> io::Result<()> {
        self.clear_within(REMOVE_BUDGET)
    }

    /// Empties the folder within `budget`. Past it the folder is left for the
    /// next start's cleanup and never deleted again by this job.
    pub fn clear_within(&self, budget: Duration) -> io::Result<()> {
        let r = purge(self.fd.as_fd(), Some(Instant::now() + budget));
        if r.is_err() {
            // Out of time or failed: one try is all this job makes.
            self.stuck.store(true, Ordering::Relaxed);
        }
        r
    }

    /// Removes the folder and the record. The content goes by descriptor and
    /// the name only if it still names this folder, so a swapped name is never
    /// followed. Past `REMOVE_BUDGET`, or on an error, the folder and the
    /// record stay for the next start's cleanup.
    pub fn remove(&mut self) -> io::Result<()> {
        if self.gone || self.stuck.load(Ordering::Relaxed) {
            return Ok(());
        }
        // On any error the folder and record stay and `Drop` doesn't try again
        // (a second try would spend a second budget).
        let r = self.clear_within(REMOVE_BUDGET).and_then(|()| {
            if self.name_is_ours()? {
                sys::unlinkat(self.dest.as_fd(), self.name.as_bytes(), libc::AT_REMOVEDIR)?;
            } else {
                log::warn!(
                    "The staging folder's name was changed; its content was removed in place."
                );
            }
            Ok(())
        });
        match r {
            Ok(()) => self.forget(),
            Err(_) => self.stuck.store(true, Ordering::Relaxed),
        }
        r
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
    /// Records kept because their delete ran out of the time budget; the next
    /// start goes on.
    pub unfinished: u32,
    /// Records kept because the destination isn't there (an unmounted drive)
    /// or isn't the folder the job was given; they are dropped after
    /// `WAIT_LIMIT`.
    pub waiting: u32,
    /// Records of that kind dropped for being older than `WAIT_LIMIT`.
    pub aged_out: u32,
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
        // Without /proc (not mounted) no process can be told from another:
        // alive, so a folder in use is never taken.
        Err(e) if e.kind() == io::ErrorKind::NotFound && proc_mounted() => false,
        Err(e) => {
            log::warn!("Process {} couldn't be looked up: {e}", rec.pid);
            true
        }
    }
}

/// Whether /proc answers: our own entry is always there when it does.
fn proc_mounted() -> bool {
    sys::proc_start(std::process::id()).is_ok()
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
    clean_stale_within(state_dir, CLEAN_BUDGET)
}

/// `clean_stale` with its own total time `budget` for deleting, over all
/// records. Past it the records left are kept and counted `unfinished`.
pub fn clean_stale_within(state_dir: &Path, budget: Duration) -> io::Result<Cleaned> {
    let deadline = Instant::now() + budget;
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
        if Instant::now() >= deadline {
            out.unfinished += 1;
            continue;
        }
        match remove_dead(&rec, Some(deadline)) {
            Ok(Dead::Removed) => {
                let _ = sys::unlinkat(bfd(&dir), &name, 0);
                out.removed += 1;
            }
            Ok(Dead::Waiting(why)) => {
                let age = SystemTime::now().duration_since(mtime).unwrap_or_default();
                if age > WAIT_LIMIT {
                    log::warn!(
                        "Dropping the job record after over 30 days: {why}. The hidden folder {} may still be there; it can be deleted by hand.",
                        sys::log_path(&rec.dest.join(&rec.staging))
                    );
                    let _ = sys::unlinkat(bfd(&dir), &name, 0);
                    out.aged_out += 1;
                } else {
                    log::debug!(
                        "Keeping the job record of {}: {why}.",
                        rec.staging.escape_debug()
                    );
                    out.waiting += 1;
                }
            }
            Err(e) if e.kind() == io::ErrorKind::TimedOut => {
                log::warn!(
                    "The leftover staging folder {} wasn't removed in time; it stays for the next start.",
                    rec.staging.escape_debug()
                );
                out.unfinished += 1;
            }
            Err(e) => {
                let age = SystemTime::now().duration_since(mtime).unwrap_or_default();
                if age > WAIT_LIMIT {
                    log::warn!(
                        "Dropping the job record after over 30 days of failing to remove {}: {e}. It can be deleted by hand.",
                        sys::log_path(&rec.dest.join(&rec.staging))
                    );
                    let _ = sys::unlinkat(bfd(&dir), &name, 0);
                    out.aged_out += 1;
                } else {
                    log::warn!(
                        "A leftover staging folder {} couldn't be removed: {e}",
                        sys::log_path(&rec.dest.join(&rec.staging))
                    );
                    out.failed += 1;
                }
            }
        }
    }
    Ok(out)
}

/// The file in the jobs folder whose time says when a sweep last began. It
/// ends in neither `.job` nor `.tmp`, so the sweep leaves it alone.
const STAMP: &str = "sweep.stamp";
/// The least time between two sweeps started by `clean_stale_if_due`.
const SWEEP_EVERY: Duration = Duration::from_secs(10 * 60);

/// The file whose `flock` says a sweep is running. Like the stamp it is
/// neither `.job` nor `.tmp`, so the sweep leaves it alone.
const LOCK: &str = "sweep.lock";

/// A sweep's claim: the `flock` on `LOCK`, held until this is dropped (and
/// released by the kernel if the process dies). `None` inside when the lock
/// file couldn't be had: the sweep then runs unlocked, as often as the stamp
/// allows.
struct SweepClaim(#[allow(dead_code)] Option<OwnedFd>);

/// Takes the sweep lock: `Ok(None)` when another start holds it.
fn lock_sweep(dir: BorrowedFd<'_>) -> io::Result<Option<OwnedFd>> {
    let c = sys::cstr(LOCK.as_bytes())?;
    let fd = sys::retry(|| {
        // SAFETY: a valid descriptor and C string; a new descriptor we own.
        let fd = unsafe {
            libc::openat(
                dir.as_raw_fd(),
                c.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600 as libc::c_uint,
            )
        };
        if fd < 0 {
            Err(io::Error::last_os_error())
        } else {
            // SAFETY: a new descriptor returned by a successful call.
            Ok(unsafe { OwnedFd::from_raw_fd(fd) })
        }
    })?;
    let st = sys::fstat(bfd(&fd))?;
    if st.st_mode & libc::S_IFMT != libc::S_IFREG || st.st_uid != sys::getuid() {
        return Err(io::Error::other("the sweep lock isn't a file of yours"));
    }
    // The mode is ours to set; a file system that keeps none is fine.
    let _ = sys::fchmod_soft(bfd(&fd), 0o600);
    match sys::retry(|| {
        sys::check(unsafe { libc::flock(fd.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) })
    }) {
        Ok(()) => Ok(Some(fd)),
        Err(e) if e.raw_os_error() == Some(libc::EWOULDBLOCK) => Ok(None),
        Err(e) => Err(e),
    }
}

/// Whether a sweep is due, and if so claims it: the `flock` on `LOCK` (two
/// starts at once: the one that can't take it backs off) held for the whole
/// sweep, and the stamp written (atomic, 0600, never through a link: the stamp
/// is replaced by rename and read with `lstat`).
fn claim_sweep(state_dir: &Path) -> io::Result<Option<SweepClaim>> {
    let dir = match open_jobs_dir(state_dir, false) {
        Ok(d) => d,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let lock = match lock_sweep(bfd(&dir)) {
        Ok(Some(fd)) => Some(fd),
        Ok(None) => return Ok(None),
        Err(e) => {
            log::warn!("The sweep lock couldn't be taken: {e}");
            None
        }
    };
    if let Ok(st) = sys::lstatat(bfd(&dir), STAMP.as_bytes())
        && st.st_mode & libc::S_IFMT == libc::S_IFREG
        && st.st_uid == sys::getuid()
    {
        let then = SystemTime::UNIX_EPOCH + Duration::from_secs(st.st_mtime.max(0) as u64);
        // A time in the future (a clock that was wrong) is not a recent sweep.
        if SystemTime::now()
            .duration_since(then)
            .is_ok_and(|age| age < SWEEP_EVERY)
        {
            return Ok(None);
        }
    }
    let stamp = RecordFile {
        dir,
        file: STAMP.to_string(),
    };
    match stamp.write(b"") {
        Ok(()) => {}
        // The sweep still runs: without a stamp it is only more frequent.
        Err(e) => log::warn!("The sweep stamp couldn't be written: {e}"),
    }
    Ok(Some(SweepClaim(lock)))
}

/// `clean_stale`, but only when none began in the last ten minutes. Blocks as
/// long as `clean_stale` does: call it off the UI thread, or use
/// `clean_stale_in_background`. `None` when it wasn't due.
pub fn clean_stale_if_due(state_dir: &Path) -> io::Result<Option<Cleaned>> {
    // Held until the sweep ends.
    let Some(_claim) = claim_sweep(state_dir)? else {
        return Ok(None);
    };
    clean_stale(state_dir).map(Some)
}

/// Starts `clean_stale_if_due` on a thread of its own and returns at once. The
/// thread is detached and nothing waits for it: a dead network mount in a
/// record can hold it forever, and a process that ends meanwhile just leaves
/// the rest for the next sweep (the delete works by descriptor and the records
/// stay until their folders are gone). Only the log hears of the result.
pub fn clean_stale_in_background(state_dir: &Path) {
    let dir = state_dir.to_path_buf();
    let spawned = std::thread::Builder::new()
        .name("stale-sweep".into())
        .spawn(move || match clean_stale_if_due(&dir) {
            Ok(Some(c)) => log::debug!("stale jobs: {c:?}"),
            Ok(None) => log::debug!("stale jobs: swept recently, nothing to do"),
            Err(e) => log::debug!("couldn't look for stale jobs: {e}"),
        });
    if let Err(e) = spawned {
        log::warn!("The sweep for stale jobs couldn't be started: {e}");
    }
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
    /// The destination can't be checked now (gone, a different folder, no
    /// longer a folder, not reachable), or the folder isn't one that can be
    /// proven to be a staging folder: it may still exist, so the record waits
    /// and is dropped (with a log line naming the folder) after `WAIT_LIMIT`.
    Waiting(&'static str),
}

/// Why an error opening the destination means "not now" rather than a failure
/// of the delete.
fn dest_unavailable(e: &io::Error) -> Option<&'static str> {
    match e.raw_os_error() {
        Some(libc::ENOENT) => Some("the destination isn't there"),
        Some(libc::ENOTDIR) => Some("the destination is no longer a folder"),
        Some(libc::EACCES) => Some("the destination can't be opened"),
        Some(libc::ENAMETOOLONG) => Some("the destination's path is too long"),
        Some(libc::ELOOP) => Some("the destination's path leads through a link loop"),
        _ => None,
    }
}

/// A staging folder that the job made: a folder of ours whose mode is 0700
/// (setgid from the destination aside: a crash between making it and setting
/// its mode leaves 02700). Where the file system keeps no modes (`modes`
/// false, noted in the record) the mode proves nothing and any folder of ours
/// with the record's staging name will do; the name is the tag's 64 random
/// bits.
fn is_proven_staging(st: &libc::stat, modes: bool) -> bool {
    st.st_mode & libc::S_IFMT == libc::S_IFDIR
        && st.st_uid == sys::getuid()
        && (!modes || st.st_mode & 0o5777 == 0o700)
}

fn remove_dead(rec: &Record, deadline: Option<Instant>) -> io::Result<Dead> {
    // Without following a link at the end; if the user's own path is a link
    // (a folder reached through one), follow it but then demand the exact
    // device and inode.
    let (dest, followed) = match sys::open_dir_nofollow(&rec.dest) {
        Ok(d) => (d, false),
        Err(e) if e.raw_os_error() == Some(libc::ELOOP) => match sys::open_dir(&rec.dest) {
            Ok(d) => (d, true),
            Err(e) => return unavailable(e),
        },
        // Gone, or on a drive that isn't mounted: the hidden folder may still
        // be there, so the record waits.
        Err(e) => return unavailable(e),
    };
    let st = sys::fstat(bfd(&dest))?;
    // The pinned inode must always match. The device may differ across boots
    // (btrfs subvolumes are numbered at mount): then the inode and the
    // staging proof below carry it. With the device the same, a different
    // inode means the path leads elsewhere now: keep the record.
    if st.st_ino != rec.ino || (followed && st.st_dev != rec.dev) {
        return Ok(Dead::Waiting(
            "the destination isn't the folder the job was given",
        ));
    }
    match remove_proven(bfd(&dest), rec.staging.as_bytes(), deadline, &|st| {
        is_proven_staging(st, rec.modes)
    })? {
        true => Ok(Dead::Removed),
        false => Ok(Dead::Waiting(
            "the folder isn't one that can be proven to be a staging folder of ours",
        )),
    }
}

fn unavailable(e: io::Error) -> io::Result<Dead> {
    match dest_unavailable(&e) {
        Some(why) => Ok(Dead::Waiting(why)),
        None => Err(e),
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
/// unlocked, and it is made searchable and writable for its owner. The unlock
/// goes by a descriptor that was checked (a folder, ours), never by name.
fn open_for_delete(dir: BorrowedFd<'_>, name: &[u8]) -> io::Result<OwnedFd> {
    let fd = match sys::open_subdir(dir, name) {
        Err(e) if e.raw_os_error() == Some(libc::EACCES) => {
            let held = sys::open_path_nofollow(dir, name)?;
            let st = sys::fstat(bfd(&held))?;
            if st.st_mode & libc::S_IFMT != libc::S_IFDIR || st.st_uid != sys::getuid() {
                return Err(e);
            }
            sys::fchmod_path(bfd(&held), 0o700)?;
            drop(held);
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

/// Non-empty child folders a frame keeps to descend into before it reads its
/// folder again. Bounds the memory of the walk and, with `BATCH` and
/// `DELETE_DEPTH`, its descriptors.
const PENDING: usize = 256;

/// A folder being emptied: `fd` is `None` for the root, whose descriptor the
/// caller holds.
struct Frame {
    name: Vec<u8>,
    fd: Option<OwnedFd>,
    /// Names that were non-empty folders at the last read, to descend into.
    pending: Vec<Vec<u8>>,
    /// A read's names are being worked off (its pending list not yet done).
    round_open: bool,
    /// Something in this round went away.
    progressed: bool,
    first: Option<io::Error>,
}

impl Frame {
    fn new(name: Vec<u8>, fd: Option<OwnedFd>) -> Frame {
        Frame {
            name,
            fd,
            pending: Vec::new(),
            round_open: false,
            progressed: false,
            first: None,
        }
    }
}

/// Removes everything in the folder `root`, keeping `root` itself. Iterative
/// and without depth limit: it holds at most `DELETE_DEPTH` + 2 descriptors,
/// reads names `BATCH` at a time (so a folder of millions never sits in
/// memory), and moves a subtree that gets deeper than `DELETE_DEPTH` up to
/// `root` to be walked from there. A folder keeps up to `PENDING` non-empty
/// children from one read and descends into them in turn, so a folder of
/// many folders is read once per `PENDING` of them, not once per child. Never
/// follows a link; every open resolves below the folder it starts from
/// (`sys::RESOLVE`).
fn purge(root: BorrowedFd<'_>, deadline: Option<Instant>) -> io::Result<()> {
    // Search and write for the owner, or nothing below can go.
    let _ = sys::fchmod(root, 0o700);
    // The folders being emptied, the root first, the deepest last.
    let mut stack: Vec<Frame> = vec![Frame::new(Vec::new(), None)];
    loop {
        if deadline.is_some_and(|d| Instant::now() >= d) {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "removing the folders took too long",
            ));
        }
        let cur_raw: RawFd = stack
            .last()
            .and_then(|f| f.fd.as_ref())
            .map_or(root.as_raw_fd(), |fd| fd.as_raw_fd());
        // SAFETY: `cur_raw` is `root` or a descriptor in `stack`; pushing to
        // the stack moves the OwnedFd, not the descriptor, and a pop below
        // happens only after the last use of `cur`.
        let cur = unsafe { BorrowedFd::borrow_raw(cur_raw) };
        let deep = stack.len() > DELETE_DEPTH;
        let top = stack.last_mut().expect("the root frame is never popped");
        if let Some(n) = top.pending.pop() {
            match open_for_delete(cur, &n) {
                Ok(fd) => stack.push(Frame::new(n, Some(fd))),
                Err(e) if e.kind() == io::ErrorKind::NotFound => top.progressed = true,
                Err(e) => {
                    top.first.get_or_insert(e);
                }
            }
            continue;
        }
        if top.round_open {
            top.round_open = false;
            if !top.progressed {
                // Nothing in this round could go: reading again would loop.
                return Err(top
                    .first
                    .take()
                    .unwrap_or_else(|| io::Error::other("a folder couldn't be emptied")));
            }
        }
        let names = read_names(cur, BATCH)?;
        if names.is_empty() {
            if stack.len() == 1 {
                return Ok(());
            }
            let done = stack.pop().expect("checked above");
            drop(done.fd);
            let parent = stack.last_mut().expect("the root frame is left");
            let pfd = match &parent.fd {
                Some(fd) => fd.as_fd(),
                None => root,
            };
            ignore_missing(sys::unlinkat(pfd, &done.name, libc::AT_REMOVEDIR))?;
            parent.progressed = true;
            continue;
        }
        top.round_open = true;
        top.progressed = false;
        top.first = None;
        for n in names {
            // A batch of slow deletes (a network mount) must not run past
            // the budget: the next round's check ends it.
            if deadline.is_some_and(|d| Instant::now() >= d) {
                break;
            }
            match remove_leaf(cur, &n) {
                Leaf::Gone => top.progressed = true,
                Leaf::Err(e) => {
                    top.first.get_or_insert(e);
                }
                Leaf::NotEmpty if deep => match move_to_top(cur, &n, root) {
                    Ok(()) => top.progressed = true,
                    Err(e) => {
                        top.first.get_or_insert(e);
                    }
                },
                Leaf::NotEmpty => {
                    top.pending.push(n);
                    // The rest of the batch is read again later.
                    if top.pending.len() >= PENDING {
                        break;
                    }
                }
            }
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
    fn a_name_the_drive_may_refuse_has_a_plain_fallback() {
        let hex = "0123456789abcdef";
        let plain = plain_staging_name(hex);
        assert_eq!(plain, ".archive.atlas-partial-0123456789abcdef");
        assert!(is_staging_name(&plain));
        // The archive's name stays in the first name, whatever it holds.
        assert!(staging_name(b"a:b.zip", hex).contains("a:b.zip"));
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
            modes: true,
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

    /// The descriptor counts below need the file tests one at a time.
    fn serial() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Descriptors this process holds on `base` or below it (other tests
    /// may hold others of their own at the same time).
    fn open_fds(base: &Path) -> usize {
        std::fs::read_dir("/proc/self/fd")
            .unwrap()
            .filter_map(|e| std::fs::read_link(e.ok()?.path()).ok())
            .filter(|p| p.starts_with(base))
            .count()
    }

    #[test]
    fn a_chain_of_two_thousand_folders_is_removed_without_a_trace() {
        let _g = serial();
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
        let before = open_fds(&base);
        assert!(remove_proven(bfd(&top), b"s", None, &|_| true).unwrap());
        assert_eq!(open_fds(&base), before, "no descriptor is left open");
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
        let _g = serial();
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
        let _g = serial();
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

    fn fake_stat(mode: u32, gid: u32) -> libc::stat {
        // SAFETY: an all-zero `stat` is a valid value.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        st.st_mode = libc::S_IFDIR | mode;
        st.st_gid = gid;
        st
    }

    #[test]
    fn shared_destinations_are_told_by_other_write_or_a_foreign_group() {
        let me = 1000;
        assert!(!shared_for(&fake_stat(0o755, 7), me, me));
        assert!(shared_for(&fake_stat(0o757, me), me, me));
        assert!(!shared_for(&fake_stat(0o1777, me), me, me), "sticky");
        // Group write on our own group is allowed; on another group it isn't.
        assert!(!shared_for(&fake_stat(0o775, me), me, me));
        assert!(shared_for(&fake_stat(0o775, 7), me, me));
        assert!(!shared_for(&fake_stat(0o1775, 7), me, me), "sticky");
        assert!(!shared_for(&fake_stat(0o755, 7), me, me), "group read only");
        // Another user's folder that it can write: its owner can swap names.
        let mut bobs = fake_stat(0o755, me);
        bobs.st_uid = 1001;
        assert!(shared_for(&bobs, me, me));
        bobs.st_mode = libc::S_IFDIR | 0o1777;
        assert!(shared_for(&bobs, me, me), "sticky doesn't bind the owner");
        bobs.st_mode = libc::S_IFDIR | 0o555;
        assert!(!shared_for(&bobs, me, me), "an owner without write");
        let mut ours = fake_stat(0o755, me);
        ours.st_uid = me;
        assert!(!shared_for(&ours, me, me));
    }

    #[test]
    fn a_folder_of_twenty_thousand_folders_is_removed_quickly() {
        let _g = serial();
        let base = scratch("wide");
        let top = sys::open_dir(&base).unwrap();
        sys::mkdirat(bfd(&top), b"s", 0o700).unwrap();
        let s = sys::open_subdir(bfd(&top), b"s").unwrap();
        for i in 0..20_000u32 {
            let n = i.to_string();
            sys::mkdirat(bfd(&s), n.as_bytes(), 0o700).unwrap();
            let d = sys::open_subdir(bfd(&s), n.as_bytes()).unwrap();
            drop(create_new(bfd(&d), b"f", 0o600).unwrap());
        }
        drop(s);
        let t = Instant::now();
        assert!(remove_proven(bfd(&top), b"s", None, &|_| true).unwrap());
        assert!(t.elapsed() < Duration::from_secs(20), "{:?}", t.elapsed());
        assert_eq!(std::fs::read_dir(&base).unwrap().count(), 0);
        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn a_locked_folder_of_ours_is_unlocked_by_descriptor_and_removed() {
        let _g = serial();
        let base = scratch("locked");
        let top = sys::open_dir(&base).unwrap();
        sys::mkdirat(bfd(&top), b"s", 0o700).unwrap();
        let s = sys::open_subdir(bfd(&top), b"s").unwrap();
        sys::mkdirat(bfd(&s), b"l", 0o700).unwrap();
        let l = sys::open_subdir(bfd(&s), b"l").unwrap();
        drop(create_new(bfd(&l), b"f", 0o600).unwrap());
        sys::fchmod(bfd(&l), 0).unwrap();
        drop((l, s));
        assert!(remove_proven(bfd(&top), b"s", None, &|_| true).unwrap());
        assert_eq!(std::fs::read_dir(&base).unwrap().count(), 0);
        std::fs::remove_dir_all(&base).unwrap();
    }

    /// A record of a dead job in `state`, for the staging `name` in `dest`
    /// (which is told to be device `dev`, inode `ino`).
    fn dead_record(state: &Path, dest: &Path, dev: u64, ino: u64, name: &str) -> PathBuf {
        let dir = open_jobs_dir(state, true).unwrap();
        let file = format!("dead-{name}.job");
        let rec = Record {
            pid: 0x7fff_fff0,
            start: 1,
            boot: None,
            dest: dest.to_path_buf(),
            dev,
            ino,
            staging: name.to_string(),
            modes: true,
        };
        RecordFile {
            dir,
            file: file.clone(),
        }
        .write(rec.encode().as_bytes())
        .unwrap();
        jobs_dir(state).join(file)
    }

    fn back_date(path: &Path, days: u64) {
        let then = SystemTime::now() - Duration::from_secs(days * 24 * 3600);
        let secs = then
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let ts = libc::timespec {
            tv_sec: secs as libc::time_t,
            tv_nsec: 0,
        };
        let c = cstr(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: a valid C string and two valid timespecs.
        let r = unsafe { libc::utimensat(libc::AT_FDCWD, c.as_ptr(), [ts, ts].as_ptr(), 0) };
        assert_eq!(r, 0, "{}", io::Error::last_os_error());
    }

    fn stat_of(p: &Path) -> libc::stat {
        sys::fstat(bfd(&sys::open_dir(p).unwrap())).unwrap()
    }

    const STAGE: &str = ".x.zip.atlas-partial-0123456789abcdef";

    #[test]
    fn a_tiny_budget_leaves_a_big_leftover_and_its_record() {
        let _g = serial();
        let base = scratch("budget");
        let dest = base.join("dest");
        let state = base.join("state");
        std::fs::create_dir_all(dest.join(STAGE)).unwrap();
        std::fs::set_permissions(
            dest.join(STAGE),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        let sd = sys::open_dir(&dest.join(STAGE)).unwrap();
        for i in 0..5000u32 {
            drop(create_new(bfd(&sd), i.to_string().as_bytes(), 0o600).unwrap());
        }
        drop(sd);
        let st = stat_of(&dest);
        let rec = dead_record(&state, &dest, st.st_dev, st.st_ino, STAGE);
        let c = clean_stale_within(&state, Duration::ZERO).unwrap();
        assert_eq!((c.removed, c.unfinished, c.failed), (0, 1, 0), "{c:?}");
        assert!(rec.exists(), "the record stays");
        assert!(dest.join(STAGE).join("0").exists(), "the folder stays");
        // With time, the next start finishes it.
        let c = clean_stale_within(&state, Duration::from_secs(60)).unwrap();
        assert_eq!((c.removed, c.unfinished), (1, 0), "{c:?}");
        assert!(!rec.exists() && !dest.join(STAGE).exists());
        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn records_of_a_missing_or_different_destination_wait_thirty_days() {
        let _g = serial();
        let base = scratch("wait");
        let dest = base.join("dest");
        let state = base.join("state");
        std::fs::create_dir_all(&dest).unwrap();
        let st = stat_of(&dest);
        let gone = dead_record(&state, &base.join("unmounted"), 1, 1, STAGE);
        let other = dead_record(
            &state,
            &dest,
            st.st_dev,
            st.st_ino + 1,
            ".y.zip.atlas-partial-0123456789abcdef",
        );
        let c = clean_stale(&state).unwrap();
        assert_eq!(
            (c.waiting, c.failed, c.aged_out, c.removed),
            (2, 0, 0, 0),
            "{c:?}"
        );
        assert!(gone.exists() && other.exists());
        // Still waiting after 29 days, dropped after 31.
        back_date(&gone, 29);
        back_date(&other, 29);
        let c = clean_stale(&state).unwrap();
        assert_eq!((c.waiting, c.aged_out), (2, 0), "{c:?}");
        back_date(&gone, 31);
        back_date(&other, 31);
        let c = clean_stale(&state).unwrap();
        assert_eq!((c.waiting, c.aged_out, c.failed), (0, 2, 0), "{c:?}");
        assert!(!gone.exists() && !other.exists());
        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn a_timed_out_remove_is_not_tried_again_by_drop() {
        let _g = serial();
        let base = scratch("stuck");
        let dest = sys::open_dir(&base).unwrap();
        let state = base.join("state");
        let mut st = Staging::create(dest, &base, b"a.zip", Some(&state)).unwrap();
        let name = st.name().to_string();
        let sfd = sys::openat2(st.fd(), b".", libc::O_RDONLY | libc::O_DIRECTORY).unwrap();
        drop(create_new(bfd(&sfd), b"f", 0o600).unwrap());
        let e = st.clear_within(Duration::ZERO).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::TimedOut);
        assert!(st.remove().is_ok(), "a stuck folder isn't retried");
        drop(st);
        assert!(
            base.join(&name).join("f").exists(),
            "left for the next start"
        );
        assert_eq!(std::fs::read_dir(jobs_dir(&state)).unwrap().count(), 1);
        std::fs::remove_dir_all(&base).unwrap();
    }

    fn acl(entries: &[(u16, u16, u32)]) -> Vec<u8> {
        let mut v = 2u32.to_le_bytes().to_vec();
        for (t, p, i) in entries {
            v.extend(t.to_le_bytes());
            v.extend(p.to_le_bytes());
            v.extend(i.to_le_bytes());
        }
        v
    }

    #[test]
    fn acls_that_let_others_write_count_as_shared() {
        let me = 1000;
        let base = [(1, 7, u32::MAX), (4, 5, u32::MAX), (0x20, 0, u32::MAX)];
        let with = |extra: &[(u16, u16, u32)]| {
            let mut e = base.to_vec();
            e.extend(extra);
            acl(&e)
        };
        assert!(!acl_grants_others(&acl(&base), me));
        // A named user who can write, another user or a group.
        assert!(acl_grants_others(&with(&[(2, 7, 2000), (0x10, 7, 0)]), me));
        assert!(acl_grants_others(&with(&[(8, 2, 50), (0x10, 7, 0)]), me));
        // Read only, our own entry, or a mask that takes write away.
        assert!(!acl_grants_others(&with(&[(2, 4, 2000), (0x10, 7, 0)]), me));
        assert!(!acl_grants_others(&with(&[(2, 7, me), (0x10, 7, 0)]), me));
        assert!(!acl_grants_others(&with(&[(2, 7, 2000), (0x10, 5, 0)]), me));
        // Malformed is shared.
        assert!(acl_grants_others(b"", me));
        assert!(acl_grants_others(&[3, 0, 0, 0], me));
        assert!(acl_grants_others(&[2, 0, 0, 0, 1, 2, 3], me));
    }

    #[test]
    fn a_plain_folder_has_no_shared_acl() {
        let base = scratch("acl");
        let d = sys::open_dir(&base).unwrap();
        assert!(!acl_is_shared(bfd(&d)).unwrap());
        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn a_folder_is_proven_by_owner_and_mode_unless_modes_are_not_kept() {
        let mut st = fake_stat(0o700, 0);
        st.st_uid = sys::getuid();
        assert!(is_proven_staging(&st, true));
        st.st_mode = libc::S_IFDIR | 0o2700;
        assert!(is_proven_staging(&st, true), "setgid from the destination");
        st.st_mode = libc::S_IFDIR | 0o755;
        assert!(!is_proven_staging(&st, true));
        assert!(is_proven_staging(&st, false), "a file system without modes");
        st.st_uid += 1;
        assert!(!is_proven_staging(&st, false), "not ours");
        st.st_uid -= 1;
        st.st_mode = libc::S_IFREG | 0o700;
        assert!(!is_proven_staging(&st, false), "not a folder");
    }

    #[test]
    fn records_without_a_modes_line_keep_modes_and_zero_says_none() {
        let old = format!("pid=1\nstart=1\ndev=1\nino=1\ndest=/a\nstaging={STAGE}\n");
        assert!(Record::parse(&old).unwrap().modes);
        assert!(!Record::parse(&format!("{old}modes=0\n")).unwrap().modes);
        assert_eq!(Record::parse(&format!("{old}modes=x\n")), None);
    }

    #[test]
    fn leftovers_are_removed_by_mode_or_by_name_where_modes_are_not_kept() {
        let _g = serial();
        let base = scratch("modes");
        let dest = base.join("dest");
        let state = base.join("state");
        let st = {
            std::fs::create_dir_all(&dest).unwrap();
            stat_of(&dest)
        };
        let set = |name: &str, mode: u32| {
            std::fs::create_dir_all(dest.join(name)).unwrap();
            std::fs::set_permissions(
                dest.join(name),
                std::os::unix::fs::PermissionsExt::from_mode(mode),
            )
            .unwrap();
        };
        let a = ".a.atlas-partial-0000000000000001";
        let b = ".b.atlas-partial-0000000000000002";
        set(a, 0o2700);
        set(b, 0o755);
        dead_record(&state, &dest, st.st_dev, st.st_ino, a);
        let rb = dead_record(&state, &dest, st.st_dev, st.st_ino, b);
        let c = clean_stale(&state).unwrap();
        assert_eq!((c.removed, c.waiting, c.failed), (1, 1, 0), "{c:?}");
        assert!(!dest.join(a).exists());
        assert!(dest.join(b).exists() && rb.exists(), "kept, not dropped");
        // The same folder, its record saying modes aren't kept there.
        let dir = open_jobs_dir(&state, false).unwrap();
        let rec = Record {
            pid: 0x7fff_fff0,
            start: 1,
            boot: None,
            dest: dest.clone(),
            dev: st.st_dev,
            ino: st.st_ino,
            staging: b.to_string(),
            modes: false,
        };
        RecordFile {
            dir,
            file: "dead-".to_string() + b + ".job",
        }
        .write(rec.encode().as_bytes())
        .unwrap();
        let c = clean_stale(&state).unwrap();
        assert_eq!(c.removed, 1, "{c:?}");
        assert!(!dest.join(b).exists());
        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn a_destination_that_became_a_file_waits_and_ages_out() {
        let _g = serial();
        let base = scratch("enotdir");
        let state = base.join("state");
        let file = base.join("file");
        std::fs::write(&file, b"x").unwrap();
        let direct = dead_record(&state, &file, 1, 1, STAGE);
        let below = dead_record(
            &state,
            &file.join("sub"),
            1,
            1,
            ".y.zip.atlas-partial-0123456789abcdef",
        );
        let c = clean_stale(&state).unwrap();
        assert_eq!((c.waiting, c.failed), (2, 0), "{c:?}");
        back_date(&direct, 31);
        back_date(&below, 31);
        let c = clean_stale(&state).unwrap();
        assert_eq!((c.aged_out, c.failed), (2, 0), "{c:?}");
        assert!(!direct.exists() && !below.exists());
        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn the_sweep_runs_at_most_once_in_ten_minutes_and_never_follows_the_stamp() {
        let _g = serial();
        let base = scratch("stamp");
        let state = base.join("state");
        // No jobs folder, nothing to sweep.
        assert!(claim_sweep(&state).unwrap().is_none());
        drop(open_jobs_dir(&state, true).unwrap());
        assert!(claim_sweep(&state).unwrap().is_some());
        assert!(claim_sweep(&state).unwrap().is_none(), "too soon");
        let stamp = jobs_dir(&state).join(STAMP);
        let mode = std::fs::metadata(&stamp).unwrap();
        assert_eq!(
            std::os::unix::fs::PermissionsExt::mode(&mode.permissions()) & 0o777,
            0o600
        );
        back_date(&stamp, 1);
        // A sweep that is still running holds its claim: no second one starts,
        // even with the stamp old.
        let held = claim_sweep(&state).unwrap().expect("ten minutes passed");
        back_date(&stamp, 1);
        assert!(claim_sweep(&state).unwrap().is_none(), "the lock is held");
        drop(held);
        assert!(
            claim_sweep(&state).unwrap().is_some(),
            "the lock was let go"
        );
        let lock = std::fs::metadata(jobs_dir(&state).join(LOCK)).unwrap();
        assert_eq!(
            std::os::unix::fs::PermissionsExt::mode(&lock.permissions()) & 0o777,
            0o600
        );
        back_date(&stamp, 1);
        // A link in its place is replaced, and what it pointed at is not touched.
        let target = base.join("target");
        std::fs::write(&target, b"keep").unwrap();
        std::fs::remove_file(&stamp).unwrap();
        std::os::unix::fs::symlink(&target, &stamp).unwrap();
        assert!(claim_sweep(&state).unwrap().is_some());
        assert_eq!(std::fs::read(&target).unwrap(), b"keep");
        assert!(!std::fs::symlink_metadata(&stamp).unwrap().is_symlink());
        let c = clean_stale_if_due(&state).unwrap();
        assert!(c.is_none(), "just swept");
        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn a_failed_clear_is_not_retried_by_drop() {
        let _g = serial();
        let base = scratch("failed");
        let dest = sys::open_dir(&base).unwrap();
        let mut st = Staging::create(dest, &base, b"a.zip", None).unwrap();
        // A stuck flag from any error: `remove` leaves the folder alone.
        st.stuck.store(true, Ordering::Relaxed);
        assert!(st.remove().is_ok());
        assert!(base.join(st.name()).exists());
        st.forget();
        let _ = std::fs::remove_dir_all(&base);
    }
}
