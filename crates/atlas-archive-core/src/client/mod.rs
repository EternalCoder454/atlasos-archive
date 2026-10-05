//! The client side of the sandboxed worker: what the CLI, the window and the
//! D-Bus service all use to run a job and bring its result out safely
//! (docs/DESIGN.md, "The sandbox" and "Extraction rules").
//!
//! One job is one thread: `Worker::list`, `test` and `extract` block that
//! thread, driving a fresh worker over its pipes, and call the front end's
//! `Callbacks` from it. `Cancel` is the one handle for another thread.
//!
//! Every reply is untrusted. Totals, counts, lengths and indices are capped
//! here; paths go through `Tree`; staging is audited after the worker is
//! killed and reaped, and only the audited top level is moved out.

mod extract;
mod spawn;
mod staging;
mod sys;
mod trash;

use std::fmt;
use std::io;
use std::os::fd::BorrowedFd;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

pub use extract::{default_name, numbered_name};
pub use spawn::Cancel;
pub use staging::{
    Cleaned, clean_stale, clean_stale_if_due, clean_stale_in_background, clean_stale_within,
    default_state_dir,
};
pub use trash::Trash;

use crate::audit::{self, Removed};
use crate::limits::{Exceeded, Kind, Limits, reserve_for};
use crate::name::NameEncoding;
use crate::proto::{
    Entry, Format, MAX_FRAME, MAX_LISTING, MAX_PASSWORD, MAX_SELECTED, Reply, Request,
};
use crate::tree::{MAX_NODES, MAX_SKIPPED, Tree};
use spawn::{Running, Stop};
use staging::Staging;
use std::os::unix::ffi::OsStrExt;

/// The installed worker.
pub const SYSTEM_WORKER: &str = "/usr/libexec/atlas-archive/atlas-archive-worker";
/// The longest a worker may go without advancing, by default: no progress
/// (a Progress with more bytes or items, a listing batch) and no answer to a
/// question. Frames that don't advance don't restart the clock.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
/// The most entries one listing may hold: what the tree holds. Past it the
/// archive is refused.
pub const MAX_ENTRIES: usize = MAX_NODES;
/// Passwords asked for, and tried, in one job before giving up.
const MAX_PASSWORD_TRIES: u32 = 5;
/// The most frames one worker may send in one job.
const MAX_FRAMES: u64 = 4_000_000;
/// The most Skipped and SkippedMore frames in one job.
const MAX_SKIP_FRAMES: u64 = 1_000_000;
/// The most `Callbacks::skipped_more` calls in one job.
const MAX_SKIP_MORE_CALLBACKS: u64 = 1_000;
/// How often the staging folder's drive is looked at, at least.
const WATCH_EVERY: Duration = Duration::from_millis(250);
/// Progress is passed on at most this often.
const PROGRESS_EVERY: Duration = Duration::from_millis(50);
/// A selection that doesn't fit in the request.
const TOO_MANY_SELECTED: &str =
    "Too many items are selected to extract at once. Select fewer, or extract everything.";
/// The longest reason kept from a reply, in characters.
const MAX_REASON: usize = 1000;

/// Why a job didn't finish. `Display` is a sentence for the user; the detail
/// for debugging went to the log.
#[derive(Debug)]
pub enum Error {
    /// `Cancel::cancel` was called; nothing was left behind.
    Cancelled,
    /// The archive needs a password and none was given.
    PasswordRequired,
    /// A limit stopped it (the answer was "stop", or it can't be gone past).
    LimitRefused(Exceeded),
    Failed(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Cancelled => f.write_str("The job was cancelled."),
            Error::PasswordRequired => f.write_str("This archive needs a password."),
            Error::LimitRefused(_) => f.write_str(
                "This archive is larger than the safety limits allow, so it was not unpacked.",
            ),
            Error::Failed(why) => f.write_str(why),
        }
    }
}

impl std::error::Error for Error {}

/// A failure with a sentence for the user and detail for the log.
fn fail(words: impl Into<String>, detail: impl fmt::Display) -> Error {
    let words = words.into();
    log::warn!("{words} ({detail})");
    Error::Failed(words)
}

/// The audit failed. Its own messages (a folder that can't be kept, too many
/// items, nested too deep, a name too long) are `audit::AuditMessage`s: fixed
/// sentences made for the user, with no OS error behind them. Those are shown,
/// cleaned, because the archive's names and the worker's reasons are in some
/// of them. Any other error is an OS error (whatever its text looks like): its
/// cause is told in plain words when the table knows it, and its detail goes
/// to the log.
fn audit_error(e: &io::Error) -> Error {
    let own = e
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<audit::AuditMessage>());
    let words = if let Some(own) = own {
        let shown = clean(&own.to_string(), MAX_REASON);
        format!("The extracted files couldn't be checked, so nothing was kept. {shown}")
    } else if let Some(why) = cause(e) {
        format!("The extracted files couldn't be checked, so nothing was kept, because {why}.")
    } else {
        "The extracted files couldn't be checked, so nothing was kept.".to_string()
    };
    fail(words, format!("audit: {e}"))
}

/// What an OS error means in plain words ("the drive is full"), for a
/// sentence "... because <cause>."; `None` when it is no one the table knows
/// or carries no code.
fn cause(e: &io::Error) -> Option<&'static str> {
    Some(match e.raw_os_error()? {
        libc::ENOSPC | libc::EDQUOT => "the drive is full",
        libc::EROFS => "the folder is read-only",
        libc::EACCES | libc::EPERM => "Atlas Archive isn't allowed to write there",
        libc::ENOENT => "the folder isn't there any more",
        libc::ENOTDIR => "a folder on the way is a file now",
        libc::ENAMETOOLONG => "a name is too long for this drive",
        libc::EIO => "the drive reported an error",
        libc::ESTALE => "the folder is no longer available on the network",
        libc::ETIMEDOUT => "the drive took too long to answer",
        libc::EMFILE | libc::ENFILE => "too many files are open",
        libc::ENOMEM => "the computer ran out of memory",
        libc::EXDEV => "the folder is on another drive than expected",
        _ => return None,
    })
}

/// A failed system call in plain words, "<what couldn't be done> because...".
fn io_words(what: &str, e: &io::Error) -> Error {
    let why = cause(e).unwrap_or("of an unexpected error");
    fail(format!("Couldn't {what} because {why}."), e)
}

/// What a front end answers to a name clash.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Clash {
    Replace,
    Skip,
    KeepBoth,
}

/// A clash answer, with Explorer's "Do this for all conflicts".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClashAnswer {
    pub action: Clash,
    pub all: bool,
}

/// The front end, called on the job thread. Every method has a do-nothing
/// default; the defaults for questions are the safe answers (no password,
/// stop at a limit, Keep Both).
pub trait Callbacks {
    /// Bytes written and items done so far (at most every 50 ms).
    fn progress(&mut self, _bytes: u64, _items: u64) {}
    /// What the archive is, as soon as the worker says.
    fn format(&mut self, _format: &Format) {}
    /// A batch of the listing, as the worker sends it.
    fn entries(&mut self, _batch: &[Entry]) {}
    /// An entry that won't be extracted, with the reason. `index` comes from
    /// the worker and is untrusted: never use it to index an array unchecked.
    /// At most `tree::MAX_SKIPPED` calls are made per job.
    fn skipped(&mut self, _index: u32, _reason: &str) {}
    /// More entries skipped than are reported one by one.
    fn skipped_more(&mut self, _count: u64) {}
    /// A limit was reached: go on past it? The job waits for the answer and
    /// its timeout doesn't run meanwhile. Each kind is asked at most once.
    fn limit(&mut self, _exceeded: &Exceeded) -> bool {
        false
    }
    /// The archive needs a password (`wrong`: the last one didn't work; the
    /// worker says so, so it is untrusted: a hint for the words, nothing
    /// more). `None` gives up. At most 5 are asked for in one job.
    fn password(&mut self, _wrong: bool) -> Option<Zeroizing<Vec<u8>>> {
        None
    }
    /// Extract here met an item of this name (display form).
    fn clash(&mut self, _name: &str) -> ClashAnswer {
        ClashAnswer {
            action: Clash::KeepBoth,
            all: false,
        }
    }
}

/// The result of `list`.
#[derive(Debug)]
pub struct Listing {
    pub format: Format,
    pub tree: Tree,
    /// The archive broke part way: `tree` holds the entries read before that
    /// and this says why (a sentence for the user). `None` for a whole
    /// listing. When the worker never got to name the format, `format` is
    /// the placeholder `unknown`.
    pub broken: Option<String>,
}

/// The format of a listing that broke before the worker named it.
fn unknown_format() -> Format {
    Format {
        name: "unknown".into(),
        encrypted: false,
        encrypted_names: false,
        solid: false,
        compressed_file: false,
        volumes: 1,
        made_on_dos: false,
        comment: None,
    }
}

/// Where to put an extraction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Into a folder of this name (Extract All uses `default_name`). The
    /// archive's one top folder of that name is the folder itself.
    ExtractTo { name: String },
    /// One item at the top comes out as it is, anything else goes into a
    /// folder named like the archive.
    ExtractHere,
}

/// One extraction.
#[derive(Clone, Debug)]
pub struct ExtractRequest<'a> {
    pub archive: &'a Path,
    pub dest_dir: &'a Path,
    pub mode: Mode,
    /// Entry indices from the listing, or everything.
    pub selection: Option<Vec<u32>>,
    pub encoding: NameEncoding,
    /// The name for a compressed file that is no archive (`notes.txt.gz`).
    pub raw_name: String,
    /// A standing answer from "do this for all conflicts" on an earlier archive.
    pub clash_all: Option<Clash>,
}

/// An entry the worker didn't extract.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SkippedEntry {
    pub index: u32,
    pub reason: String,
}

/// What an extraction produced.
#[derive(Clone, Debug)]
pub struct Extracted {
    /// The folder or item made, for "Show Files". The destination itself when
    /// nothing was moved (`left_out`).
    pub path: PathBuf,
    /// The user chose Skip for the one clashing item.
    pub left_out: bool,
    /// Set when the user said "do this for all conflicts".
    pub clash_all: Option<Clash>,
    /// What the audit took out of the result.
    pub removed: Vec<Removed>,
    /// Removals past the first `audit::MAX_REMOVED_LISTED` in `removed`.
    pub removed_more: usize,
    pub skipped: Vec<SkippedEntry>,
    /// Skipped past the ones listed.
    pub skipped_more: u64,
    /// The files were moved into place, but the move couldn't be confirmed
    /// (a file system whose inode numbers change): a sentence for the user,
    /// which names the hidden folder to look in if `path` is wrong. Nothing
    /// was deleted. Front ends show it with the result.
    pub unconfirmed: Option<String>,
}

/// The worker, and the per-user places a job touches. Values are for tests
/// to inject; `at` and `system` take the real ones from the environment.
#[derive(Clone, Debug)]
pub struct Worker {
    exe: PathBuf,
    timeout: Duration,
    state_dir: Option<PathBuf>,
    trash: Option<Trash>,
    /// The most an extraction may write without the user having said yes to
    /// more: what the worker's own total limit is.
    size_ceiling: u64,
}

impl Worker {
    /// The installed worker. No environment variable can name another.
    pub fn system() -> Worker {
        Worker::at(SYSTEM_WORKER)
    }

    /// The worker at `path` (made absolute, so it is never searched for).
    pub fn at(path: impl AsRef<Path>) -> Worker {
        let path = path.as_ref();
        Worker {
            exe: std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf()),
            timeout: DEFAULT_TIMEOUT,
            state_dir: staging::default_state_dir(),
            trash: Trash::from_environment(),
            size_ceiling: Limits::new(None).total_bytes,
        }
    }

    /// The most bytes an extraction may write before the client stops the
    /// worker on its own (a margin is allowed on top), unless the user went
    /// past the worker's total-size limit. For tests; the default is the
    /// worker's own limit.
    pub fn with_size_ceiling(mut self, bytes: u64) -> Worker {
        self.size_ceiling = bytes;
        self
    }

    /// How long the worker may go without advancing (see `DEFAULT_TIMEOUT`).
    pub fn with_timeout(mut self, timeout: Duration) -> Worker {
        self.timeout = timeout;
        self
    }

    /// Where job records go (`<dir>/atlas-archive/jobs`); `None` keeps none.
    pub fn with_state_dir(mut self, dir: Option<PathBuf>) -> Worker {
        self.state_dir = dir;
        self
    }

    /// The Trash Replace uses; `None`: Replace fails rather than delete.
    pub fn with_trash(mut self, trash: Option<Trash>) -> Worker {
        self.trash = trash;
        self
    }

    /// Lists an archive. `encoding`: the user's choice, or detected.
    ///
    /// Like `test` and `extract` this blocks the calling thread, which must
    /// not be the UI thread: opening the archive can wait on a dead mount, and
    /// so can the end of the job (a worker stuck in I/O that won't die;
    /// that ends with "The archive's drive isn't responding." after 10 s).
    /// The worker is bound to the calling *thread* (`PR_SET_PDEATHSIG`): it
    /// dies when that thread ends, so the thread must live until the call
    /// returns. `SIGCHLD` must not be `SIG_IGN` in this process.
    pub fn list(
        &self,
        archive: &Path,
        encoding: Option<NameEncoding>,
        cb: &mut dyn Callbacks,
        cancel: &Cancel,
    ) -> Result<Listing, Error> {
        let mut col = Collected::default();
        self.run_job(
            Op::List,
            archive,
            None,
            &Request::List,
            cancel,
            cb,
            &mut col,
        )?;
        let format = match (col.format.take(), &col.broken) {
            (Some(f), _) => f,
            // The entries came and the archive broke before the format did.
            (None, Some(_)) => unknown_format(),
            (None, None) => {
                return Err(fail(
                    "The archive reader sent something unexpected.",
                    "no format",
                ));
            }
        };
        let tree = Tree::build(format.clone(), &col.entries, encoding);
        Ok(Listing {
            format,
            tree,
            broken: col.broken.take(),
        })
    }

    /// Reads every entry and checks it, writing nothing. Same thread rules as `list`.
    pub fn test(
        &self,
        archive: &Path,
        cb: &mut dyn Callbacks,
        cancel: &Cancel,
    ) -> Result<(), Error> {
        let mut col = Collected::default();
        self.run_job(
            Op::Test,
            archive,
            None,
            &Request::Test,
            cancel,
            cb,
            &mut col,
        )
    }

    /// Extracts into a staging folder in the destination, audits it, and
    /// moves the result out. On any failure or cancel the staging folder is
    /// removed and the destination is as it was; when the drive stops
    /// answering it is left for `clean_stale` instead. Same thread rules as
    /// `list`. The destination must not be writable by others (unless
    /// sticky); a same-user process that can write there can still race the
    /// name-based moves (docs/DESIGN.md).
    pub fn extract(
        &self,
        req: &ExtractRequest<'_>,
        cb: &mut dyn Callbacks,
        cancel: &Cancel,
    ) -> Result<Extracted, Error> {
        if cancel.is_cancelled() {
            return Err(Error::Cancelled);
        }
        let dest = sys::open_dir(req.dest_dir).map_err(|e| {
            let words = match e.raw_os_error() {
                Some(libc::ENOENT) => "The folder to extract into isn't there.",
                Some(libc::EACCES | libc::EPERM) => {
                    "Atlas Archive isn't allowed to open the folder to extract into."
                }
                Some(libc::ENOTDIR) => "The place to extract into isn't a folder.",
                _ => "The folder to extract into couldn't be opened.",
            };
            fail(words, format!("{}: {e}", sys::log_path(req.dest_dir)))
        })?;
        let dest_st =
            sys::fstat(sys::bfd(&dest)).map_err(|e| io_words("look at the folder", &e))?;
        // An access list that can't be read counts as shared, like a
        // malformed one.
        if staging::dest_is_shared(&dest_st)
            || staging::acl_is_shared(sys::bfd(&dest)).unwrap_or(true)
        {
            return Err(fail(
                "Other users can change this folder, so extracting into it isn't safe. Pick a folder of your own.",
                format!("{} is writable by others", sys::log_path(req.dest_dir)),
            ));
        }
        let dest_abs =
            std::path::absolute(req.dest_dir).map_err(|e| io_words("find the folder", &e))?;
        let file_name = req
            .archive
            .file_name()
            .map(|n| n.as_bytes().to_vec())
            .unwrap_or_else(|| b"archive".to_vec());
        let request = Request::Extract {
            encoding: req.encoding.label().to_string(),
            entries: req.selection.clone(),
            raw_name: req.raw_name.clone(),
        };
        // Before anything is made: a selection too scattered for one frame
        // is the user's to narrow, not the reader's fault.
        if req
            .selection
            .as_ref()
            .is_some_and(|l| crate::proto::selection_len(l) > MAX_SELECTED)
            || request.encode().len() > MAX_FRAME
        {
            return Err(fail(TOO_MANY_SELECTED, "the request is over one frame"));
        }
        let mut staging = Staging::create(dest, &dest_abs, &file_name, self.state_dir.as_deref())
            .map_err(|e| io_words("make a folder to extract into", &e))?;
        let mut col = Collected::default();
        if let Err(e) = self.run_job(
            Op::Extract,
            req.archive,
            Some(&staging),
            &request,
            cancel,
            cb,
            &mut col,
        ) {
            if col.hung {
                // Nothing may touch a folder on a drive that doesn't answer.
                staging.leave_for_cleanup();
            }
            return Err(e);
        }
        // The worker is dead and reaped: staging can't change under us.
        if cancel.is_cancelled() {
            log::info!("The extraction was cancelled before the audit.");
            return Err(Error::Cancelled);
        }
        let umask = sys::read_umask();
        // The audit of a million items takes a while: it looks at the cancel
        // as it goes, and again when it is done (staging goes when dropped).
        let audited = audit::audit_with(staging.fd(), umask, staging.modes_kept(), &|| {
            cancel.is_cancelled()
        });
        if cancel.is_cancelled() {
            log::info!("The extraction was cancelled during the audit.");
            return Err(Error::Cancelled);
        }
        let audit = audited.map_err(|e| audit_error(&e))?;
        cross_check(&col.written, &audit.top_level());

        let default = default_name(&file_name);
        let placed = extract::move_out(
            &mut staging,
            &audit,
            &extract::MoveOut {
                dest_path: &dest_abs,
                mode: &req.mode,
                default_name: &default,
                umask,
                trash: self.trash.as_ref(),
                clash_all: req.clash_all,
                cancel,
            },
            cb,
        )?;
        Ok(Extracted {
            path: placed.path,
            left_out: placed.left_out,
            clash_all: placed.clash_all,
            removed: audit.removed,
            removed_more: audit.removed_more,
            skipped: col.skipped,
            skipped_more: col.skipped_more,
            unconfirmed: placed.unconfirmed,
        })
    }

    /// Runs the job's worker, asking for a password as often as it is needed.
    #[allow(clippy::too_many_arguments)]
    fn run_job(
        &self,
        op: Op,
        archive: &Path,
        staging: Option<&Staging>,
        request: &Request,
        cancel: &Cancel,
        cb: &mut dyn Callbacks,
        col: &mut Collected,
    ) -> Result<(), Error> {
        let mut password: Option<Zeroizing<Vec<u8>>> = None;
        // One try with no password, then one for each that is given.
        for attempt in 0..=MAX_PASSWORD_TRIES {
            if cancel.is_cancelled() {
                return Err(Error::Cancelled);
            }
            if attempt > 0
                && let Some(s) = staging
            {
                s.clear()
                    .map_err(|e| io_words("clear the extraction folder", &e))?;
            }
            *col = Collected::default();
            let a = Attempt {
                op,
                archive,
                staging,
                password: password.as_ref(),
                request,
                size_ceiling: self.size_ceiling,
            };
            match self.attempt(&a, cancel, cb, col)? {
                Final::NeedPassword(_) if attempt == MAX_PASSWORD_TRIES => break,
                Final::NeedPassword(wrong) => match cb.password(wrong) {
                    Some(p) if p.len() > MAX_PASSWORD => {
                        return Err(fail(
                            "That password is too long.",
                            "over the length limit",
                        ));
                    }
                    Some(p) => password = Some(p),
                    None => return Err(Error::PasswordRequired),
                },
                Final::Finished => return Ok(()),
            }
        }
        Err(fail("Too many passwords were tried.", "password loop cap"))
    }

    /// One worker, from start to its reaping.
    fn attempt(
        &self,
        a: &Attempt<'_>,
        cancel: &Cancel,
        cb: &mut dyn Callbacks,
        col: &mut Collected,
    ) -> Result<Final, Error> {
        // Before the archive is opened, which can itself wait on a dead drive.
        spawn::check_capacity().map_err(|e| fail(spawn::TOO_MANY_STUCK, e))?;
        let file = spawn::open_archive(a.archive).map_err(|e| {
            if e.kind() == io::ErrorKind::InvalidInput {
                Error::Failed(e.to_string())
            } else {
                let words = match e.kind() {
                    io::ErrorKind::NotFound => "The archive isn't there.",
                    io::ErrorKind::PermissionDenied => "The archive can't be read.",
                    _ => "The archive couldn't be opened.",
                };
                fail(words, e)
            }
        })?;
        let mut col_hung = false;
        let mut running = spawn::spawn(
            &self.exe,
            self.timeout,
            &file,
            a.staging.map(|s| s.fd_owned()),
        )
        .map_err(|e| {
            let words = if e.kind() == io::ErrorKind::NotFound {
                "The archive reader isn't installed."
            } else if e.kind() == io::ErrorKind::ResourceBusy {
                spawn::TOO_MANY_STUCK
            } else {
                "The archive reader couldn't be started."
            };
            fail(words, format!("{}: {e}", sys::log_path(&self.exe)))
        })?;
        let driven = drive(&mut running, a, cancel, cb, col);
        // Dead and reaped before anything looks at staging, on every path.
        let status = running.finish();
        if let Err(e) = &status
            && e.kind() == io::ErrorKind::TimedOut
        {
            col_hung = true;
        }
        col.hung = col_hung;
        if col_hung {
            return Err(fail(
                "The archive's drive isn't responding.",
                "the archive reader didn't end after SIGKILL",
            ));
        }
        let what = || {
            let kind = col.format.as_ref().map(|f| f.name.clone()).or_else(|| {
                a.archive
                    .extension()
                    .map(|e| e.to_string_lossy().to_ascii_lowercase())
            });
            format!(
                "{} of a {} archive",
                a.op.name(),
                kind.as_deref().unwrap_or("?")
            )
        };
        match driven {
            Ok(f) => Ok(f),
            // The reasons are the worker's or the client's own words; the
            // log gets them with what was being done.
            Err(Halt::Failed(reason)) => {
                log::warn!("The {} stopped: {reason}", what());
                Err(Error::Failed(reason))
            }
            Err(Halt::Refused(e)) => {
                log::warn!("The {} was refused at a limit: {e:?}", what());
                Err(Error::LimitRefused(e))
            }
            Err(Halt::Bad(why)) => Err(fail("The archive reader sent something unexpected.", why)),
            Err(Halt::Stop(Stop::Cancelled)) => {
                log::info!("The {} was cancelled.", what());
                Err(Error::Cancelled)
            }
            Err(Halt::Stop(Stop::Timeout)) => Err(fail(
                "The archive reader stopped responding.",
                format!("no reply for {:?}", self.timeout),
            )),
            Err(Halt::Stop(Stop::Eof)) => {
                let words = spawn::died(&status);
                Err(fail(words, format!("replies ended; status {status:?}")))
            }
            Err(Halt::Stop(Stop::Proto(p))) => Err(fail(p.to_string(), format!("{p:?}"))),
            Err(Halt::Stop(Stop::Io(e))) => Err(fail(
                "The archive reader couldn't be talked to.",
                format!("pipe: {e}"),
            )),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Op {
    List,
    Test,
    Extract,
}

impl Op {
    fn name(self) -> &'static str {
        match self {
            Op::List => "listing",
            Op::Test => "test",
            Op::Extract => "extraction",
        }
    }
}

struct Attempt<'a> {
    op: Op,
    archive: &'a Path,
    staging: Option<&'a Staging>,
    password: Option<&'a Zeroizing<Vec<u8>>>,
    request: &'a Request,
    /// The most that may be written before the user said yes to more.
    size_ceiling: u64,
}

/// How a worker's last reply ended it.
enum Final {
    NeedPassword(bool),
    Finished,
}

/// Why driving a worker stopped short of a final reply.
enum Halt {
    Stop(Stop),
    /// The worker said it failed.
    Failed(String),
    /// A limit was declined and the worker stopped for it.
    Refused(Exceeded),
    /// The worker broke the protocol.
    Bad(&'static str),
}

impl From<Stop> for Halt {
    fn from(s: Stop) -> Halt {
        Halt::Stop(s)
    }
}

/// What one attempt collected.
#[derive(Default)]
struct Collected {
    format: Option<Format>,
    entries: Vec<Entry>,
    listing_bytes: u64,
    written: Vec<Vec<u8>>,
    skipped: Vec<SkippedEntry>,
    skipped_more: u64,
    /// The worker couldn't be reaped: its drive doesn't answer.
    hung: bool,
    /// A listing the archive broke part way: why (the entries are in
    /// `entries`).
    broken: Option<String>,
}

/// A reply's text with a length cap and without controls, bidi overrides and
/// isolates, zero-width and separator characters: it goes to the user.
fn clean(text: &str, max: usize) -> String {
    sys::sanitize(text, max, ' ').trim().to_string()
}

/// Failed reads of the free space in a row that stop a job, when they also
/// span `READ_FAILURE_SPAN`: checks come with every Progress frame too, so a
/// count alone would let a 150 ms hiccup of a network mount end a job.
const MAX_READ_FAILURES: u8 = 3;
const READ_FAILURE_SPAN: Duration = Duration::from_secs(2);

/// Watches the free space of the staging folder's drive, from outside the
/// worker, which is the thing under test: the worker's own bomb limits are
/// not trusted to hold.
///
/// It fails closed: a file system with no usable free-space figure (some FUSE
/// and network mounts, which answer with zeros) can't be watched, and an
/// extraction there is refused before the worker is asked. A read that fails
/// in the middle of a job is tolerated (logged); the third in a row, at
/// least `READ_FAILURE_SPAN` after the first, stops the job.
struct SpaceWatch<'a> {
    fd: BorrowedFd<'a>,
    start_free: u64,
    floor: u64,
    last: Instant,
    /// Reads of the free space that failed in a row, and when the first did.
    failures: u8,
    first_failure: Option<Instant>,
}

impl<'a> SpaceWatch<'a> {
    fn new(fd: BorrowedFd<'a>) -> Result<SpaceWatch<'a>, io::Error> {
        match sys::free_bytes(fd) {
            Ok(free) => Ok(SpaceWatch {
                fd,
                start_free: free,
                floor: reserve_for(free),
                last: Instant::now(),
                failures: 0,
                first_failure: None,
            }),
            Err(e) => {
                log::warn!("The free space can't be watched, so the job is refused: {e}");
                Err(e)
            }
        }
    }

    fn due(&self) -> bool {
        self.last.elapsed() >= WATCH_EVERY
    }

    /// `Err(words)` when the worker has to be stopped: the drive is below the
    /// reserve the worker's own rule keeps, or more was written than was
    /// approved plus a margin (an eighth, at least 16 MiB: other programs
    /// write to the drive too).
    fn check(&mut self, approved: Option<u64>) -> Result<(), String> {
        self.last = Instant::now();
        let free = match sys::free_bytes(self.fd) {
            Ok(f) => f,
            Err(e) => {
                self.failures = self.failures.saturating_add(1);
                let first = *self.first_failure.get_or_insert_with(Instant::now);
                log::warn!(
                    "The free space couldn't be read ({} in a row): {e}",
                    self.failures
                );
                if self.failures >= MAX_READ_FAILURES && first.elapsed() >= READ_FAILURE_SPAN {
                    log::warn!(
                        "The job was stopped: the free space couldn't be read {} times in {:?} (it started with {} free).",
                        self.failures,
                        first.elapsed(),
                        self.start_free
                    );
                    return Err("Atlas Archive can no longer tell how much space is free on this drive, so the job was stopped.".into());
                }
                return Ok(());
            }
        };
        self.failures = 0;
        self.first_failure = None;
        if free < self.floor {
            log::warn!(
                "The job was stopped: {free} bytes free is under the reserve of {} (it started with {} free; approved {approved:?}).",
                self.floor,
                self.start_free
            );
            return Err("There isn't enough space on this drive, so the job was stopped.".into());
        }
        if let Some(a) = approved {
            let used = self.start_free.saturating_sub(free);
            let allowed = a.saturating_add((a / 8).max(16 * 1024 * 1024));
            if used > allowed {
                log::warn!(
                    "The job was stopped: {used} bytes used on the drive is over the {a} approved plus its margin ({allowed} allowed; it started with {} free, now {free}, reserve {}). Other programs' writes count too.",
                    self.start_free,
                    self.floor
                );
                return Err(
                    "The archive unpacked to much more than it said it would, so the job was stopped."
                        .into(),
                );
            }
        }
        Ok(())
    }
}

/// Talks to the worker until its final reply.
fn drive(
    running: &mut Running,
    a: &Attempt<'_>,
    cancel: &Cancel,
    cb: &mut dyn Callbacks,
    col: &mut Collected,
) -> Result<Final, Halt> {
    let watch = a
        .staging
        .filter(|_| a.op == Op::Extract)
        .map(|s| SpaceWatch::new(s.fd()));
    // Fail closed: no figures, no extraction (and the worker is not asked).
    let mut watch = match watch {
        Some(Err(e)) => {
            return Err(Halt::Failed(if e.kind() == io::ErrorKind::Unsupported {
                "This drive doesn't report its free space, so Atlas Archive can't extract here safely."
                    .into()
            } else {
                let why = cause(&e).unwrap_or("of an unexpected error");
                format!(
                    "Atlas Archive couldn't check the free space on this drive because {why}, so it can't extract here safely."
                )
            }));
        }
        Some(Ok(w)) => Some(w),
        None => None,
    };
    if let Some(p) = a.password {
        running.send(&Request::Password(p.clone()).encode(), cancel)?;
    }
    let request = a.request.encode();
    // Not the reader's doing: `extract` checks too, before it starts one.
    if request.len() > MAX_FRAME {
        return Err(Halt::Failed(TOO_MANY_SELECTED.into()));
    }
    running.send(&request, cancel)?;

    let timeout = running.timeout();
    // The clock restarts only when the job advances: more bytes or items
    // reported, a listing batch, or the answer to a question.
    let mut deadline = Instant::now() + timeout;
    let mut declined: Option<Exceeded> = None;
    // After any "no", the worker may only say it failed.
    let mut stopped = false;
    let mut asked: Vec<Kind> = Vec::new();
    // What the job may write: the worker's total limit, or no ceiling once
    // the user went past it. The free-space floor applies either way.
    let mut ceiling = Some(a.size_ceiling);
    let mut last_progress: Option<Instant> = None;
    let mut seen = (0u64, 0u64);
    let (mut frames, mut skip_frames, mut skip_calls, mut more_calls) = (0u64, 0u64, 0usize, 0u64);
    loop {
        if let Some(w) = watch.as_mut()
            && w.due()
        {
            w.check(ceiling).map_err(Halt::Failed)?;
        }
        let tick = watch.as_ref().map(|_| WATCH_EVERY);
        let Some((reply, frame_len)) = running.recv(cancel, deadline, tick)? else {
            continue;
        };
        frames += 1;
        if frames > MAX_FRAMES {
            return Err(Halt::Bad("too many replies"));
        }
        if stopped && !matches!(reply, Reply::Failed { .. }) {
            return Err(Halt::Bad("the worker went on after a declined limit"));
        }
        match reply {
            Reply::Format(f) if a.op == Op::List && col.format.is_none() => {
                deadline = Instant::now() + timeout;
                cb.format(&f);
                col.format = Some(f);
            }
            Reply::Entries(batch) if a.op == Op::List => {
                // An empty batch is no progress: a worker can't keep itself
                // alive with them.
                if !batch.is_empty() {
                    deadline = Instant::now() + timeout;
                }
                col.listing_bytes += frame_len as u64;
                if col.listing_bytes > MAX_LISTING {
                    return Err(Halt::Failed(
                        "This archive has too many items to list.".into(),
                    ));
                }
                if col.entries.len() + batch.len() > MAX_ENTRIES {
                    return Err(Halt::Failed(
                        "This archive has too many items to list.".into(),
                    ));
                }
                if batch.iter().any(|e| e.index as usize >= MAX_ENTRIES) {
                    return Err(Halt::Bad("an entry index is out of range"));
                }
                // Grow by a quarter, never past the cap: a doubling Vec could
                // briefly hold twice what the cap allows.
                let len = col.entries.len();
                if col.entries.capacity() - len < batch.len() {
                    let want = (len / 4).max(batch.len()).min(MAX_ENTRIES - len);
                    col.entries.reserve_exact(want);
                }
                cb.entries(&batch);
                col.entries.extend(batch);
            }
            Reply::Listed { entries } if a.op == Op::List => {
                if entries as usize != col.entries.len() || col.format.is_none() {
                    return Err(Halt::Bad("the listing doesn't match its own count"));
                }
                return Ok(Final::Finished);
            }
            Reply::Progress { bytes, items } => {
                if bytes < seen.0 || items < seen.1 {
                    return Err(Halt::Bad("the progress went backwards"));
                }
                if bytes > seen.0 || items > seen.1 {
                    deadline = Instant::now() + timeout;
                }
                seen = (bytes, items);
                // The loop's own check is every WATCH_EVERY; a Progress frame
                // adds none of its own (on a network drive each is a round trip).
                if let Some(w) = watch.as_mut()
                    && w.due()
                {
                    w.check(ceiling).map_err(Halt::Failed)?;
                }
                let now = Instant::now();
                if last_progress.is_none_or(|t| now.duration_since(t) >= PROGRESS_EVERY) {
                    last_progress = Some(now);
                    cb.progress(bytes, items);
                }
            }
            // Only a listing's very first header asks, before any entry: one
            // that comes later broke the front end's view of the list.
            Reply::NeedPassword { .. } if a.op == Op::List && !col.entries.is_empty() => {
                return Err(Halt::Bad("a password was asked for after entries"));
            }
            Reply::NeedPassword { wrong } => return Ok(Final::NeedPassword(wrong)),
            // A test meters bytes like an extraction, so a bomb asks there too.
            Reply::Limit(e) if a.op != Op::List => {
                if asked.contains(&e.kind) {
                    return Err(Halt::Bad("the same limit was asked twice"));
                }
                asked.push(e.kind);
                // The ones that can't be gone past are never asked.
                let go_on = if e.kind.askable() {
                    // The worker (and its group) stands still while the user
                    // is asked: the space watch can't look during the dialog,
                    // and nothing may be written meanwhile.
                    if !running.pause() {
                        return Err(Halt::Failed(
                            "Atlas Archive couldn't pause the archive reader to ask, so it stopped."
                                .into(),
                        ));
                    }
                    // What was written up to the stop may already be too much.
                    if let Some(w) = watch.as_mut() {
                        w.check(ceiling).map_err(Halt::Failed)?;
                    }
                    let answer = cb.limit(&e);
                    if cancel.is_cancelled() {
                        // Left stopped: the kill that follows works on it.
                        return Err(Halt::Stop(Stop::Cancelled));
                    }
                    running.resume();
                    answer
                } else {
                    false
                };
                if go_on {
                    if e.kind == Kind::TotalSize {
                        ceiling = None;
                    }
                } else {
                    stopped = true;
                    if e.kind.askable() {
                        declined = Some(e);
                    }
                }
                running.send(&Request::GoOn(go_on).encode(), cancel)?;
                // The user's time isn't the worker's.
                deadline = Instant::now() + timeout;
            }
            Reply::Skipped { index, reason } if a.op != Op::List => {
                skip_frames += 1;
                if skip_frames > MAX_SKIP_FRAMES {
                    return Err(Halt::Bad("too many skipped entries"));
                }
                let reason = clean(&reason, 300);
                if skip_calls < MAX_SKIPPED {
                    skip_calls += 1;
                    cb.skipped(index, &reason);
                }
                if col.skipped.len() < MAX_SKIPPED {
                    col.skipped.push(SkippedEntry { index, reason });
                } else {
                    col.skipped_more = col.skipped_more.saturating_add(1);
                }
            }
            Reply::SkippedMore { count } if a.op != Op::List => {
                skip_frames += 1;
                if skip_frames > MAX_SKIP_FRAMES {
                    return Err(Halt::Bad("too many skipped entries"));
                }
                col.skipped_more = col.skipped_more.saturating_add(count);
                if more_calls < MAX_SKIP_MORE_CALLBACKS {
                    more_calls += 1;
                    cb.skipped_more(count);
                }
            }
            Reply::Done { written } if a.op != Op::List => {
                if written.len() > MAX_ENTRIES {
                    return Err(Halt::Bad("too many names written"));
                }
                col.written = written;
                return Ok(Final::Finished);
            }
            Reply::Failed { reason } => {
                if let Some(e) = declined {
                    return Err(Halt::Refused(e));
                }
                let reason = clean(&reason, MAX_REASON);
                let reason = if reason.is_empty() {
                    "The archive reader failed.".to_string()
                } else {
                    reason
                };
                // A listing that broke after some entries keeps them: the
                // front end shows what was readable, and where it broke.
                if a.op == Op::List && !col.entries.is_empty() {
                    log::warn!(
                        "The listing broke after {} entries: {reason}",
                        col.entries.len()
                    );
                    col.broken = Some(reason);
                    return Ok(Final::Finished);
                }
                return Err(Halt::Failed(reason));
            }
            _ => return Err(Halt::Bad("a reply that doesn't belong to this job")),
        }
    }
}

/// `Done` names what the worker wrote; the audit's walk is what counts. A
/// difference is a worker fault worth a log line, never more.
fn cross_check(written: &[Vec<u8>], top: &[String]) {
    let mut a: Vec<&[u8]> = written.iter().map(Vec::as_slice).collect();
    let mut b: Vec<&[u8]> = top.iter().map(|s| s.as_bytes()).collect();
    a.sort_unstable();
    b.sort_unstable();
    if a != b {
        log::warn!(
            "The worker named {} top-level items; the audit found {}.",
            a.len(),
            b.len()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(e: &Error) -> &str {
        match e {
            Error::Failed(w) => w,
            _ => panic!("not a Failed: {e}"),
        }
    }

    #[test]
    fn only_the_audits_own_type_is_shown() {
        let generic = "The extracted files couldn't be checked, so nothing was kept.";
        let own = audit_error(&audit::message("A folder (a) can't be kept."));
        assert_eq!(
            words(&own),
            format!("{generic} A folder (a) can't be kept.")
        );
        // Capital letter, kind Other, no OS code: the old heuristic's match.
        let lookalike = audit_error(&io::Error::other("Permission denied by /secret/path"));
        assert_eq!(words(&lookalike), generic);
        // An OS error the table knows is told in words; one it doesn't isn't.
        let os = audit_error(&io::Error::from_raw_os_error(libc::EIO));
        assert_eq!(
            words(&os),
            "The extracted files couldn't be checked, so nothing was kept, because the drive reported an error."
        );
        let odd = audit_error(&io::Error::from_raw_os_error(libc::EBADF));
        assert_eq!(words(&odd), generic);
        let plain = audit_error(&io::Error::new(io::ErrorKind::InvalidData, "Bad"));
        assert_eq!(words(&plain), generic);
    }
}
