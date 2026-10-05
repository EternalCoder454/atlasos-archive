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
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

pub use extract::{default_name, numbered_name};
pub use spawn::Cancel;
pub use staging::{Cleaned, clean_stale, default_state_dir};
pub use trash::Trash;

use crate::audit::{self, Removed};
use crate::limits::Exceeded;
use crate::name::NameEncoding;
use crate::proto::{Entry, Format, MAX_LISTING, Reply, Request};
use crate::tree::{MAX_SKIPPED, Tree};
use spawn::{Running, Stop};
use staging::Staging;
use std::os::unix::ffi::OsStrExt;

/// The installed worker.
pub const SYSTEM_WORKER: &str = "/usr/libexec/atlas-archive-worker";
/// The longest wait for a reply, by default.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
/// The most entries one listing may hold. Past it the archive is refused:
/// the tree stops at a million nodes anyway.
pub const MAX_ENTRIES: usize = 2_000_000;
/// Passwords asked for in one job before giving up.
const MAX_PASSWORD_TRIES: u32 = 50;
/// Limit questions in one job: each kind is asked once.
const MAX_LIMIT_QUESTIONS: u32 = 12;
/// Progress is passed on at most this often.
const PROGRESS_EVERY: Duration = Duration::from_millis(50);
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

/// A failed system call in plain words, "<what couldn't be done> because...".
fn io_words(what: &str, e: &io::Error) -> Error {
    let why = match e.raw_os_error() {
        Some(libc::ENOSPC | libc::EDQUOT) => "the drive is full",
        Some(libc::EROFS) => "the folder is read-only",
        Some(libc::EACCES | libc::EPERM) => "Atlas Archive isn't allowed to write there",
        Some(libc::ENOENT) => "the folder isn't there any more",
        Some(libc::ENAMETOOLONG) => "a name is too long for this drive",
        _ => "of an unexpected error",
    };
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
    /// An entry that won't be extracted, with the reason.
    fn skipped(&mut self, _index: u32, _reason: &str) {}
    /// More entries skipped than are reported one by one.
    fn skipped_more(&mut self, _count: u64) {}
    /// A limit was reached: go on past it? The job waits for the answer and
    /// its timeout doesn't run meanwhile.
    fn limit(&mut self, _exceeded: &Exceeded) -> bool {
        false
    }
    /// The archive needs a password (`wrong`: the last one didn't work).
    /// `None` gives up.
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
    pub skipped: Vec<SkippedEntry>,
    /// Skipped past the ones listed.
    pub skipped_more: u64,
}

/// The worker, and the per-user places a job touches. Values are for tests
/// to inject; `at` and `system` take the real ones from the environment.
#[derive(Clone, Debug)]
pub struct Worker {
    exe: PathBuf,
    timeout: Duration,
    state_dir: Option<PathBuf>,
    trash: Option<Trash>,
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
        }
    }

    /// How long a reply may take (restarting with each one).
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
        let format = col
            .format
            .take()
            .ok_or_else(|| fail("The archive reader sent something unexpected.", "no format"))?;
        let tree = Tree::build(format.clone(), &col.entries, encoding);
        Ok(Listing { format, tree })
    }

    /// Reads every entry and checks it, writing nothing.
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
    /// removed and the destination is as it was.
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
            fail(
                "The folder to extract into couldn't be opened.",
                format!("{}: {e}", req.dest_dir.display()),
            )
        })?;
        let dest_abs =
            std::path::absolute(req.dest_dir).map_err(|e| io_words("find the folder", &e))?;
        let file_name = req
            .archive
            .file_name()
            .map(|n| n.as_bytes().to_vec())
            .unwrap_or_else(|| b"archive".to_vec());
        let mut staging = Staging::create(dest, &dest_abs, &file_name, self.state_dir.as_deref())
            .map_err(|e| io_words("make a folder to extract into", &e))?;

        let request = Request::Extract {
            encoding: req.encoding.label().to_string(),
            entries: req.selection.clone(),
            raw_name: req.raw_name.clone(),
        };
        let mut col = Collected::default();
        self.run_job(
            Op::Extract,
            req.archive,
            Some(&staging),
            &request,
            cancel,
            cb,
            &mut col,
        )?;
        // The worker is dead and reaped: staging can't change under us.
        if cancel.is_cancelled() {
            return Err(Error::Cancelled);
        }
        let umask = sys::read_umask();
        let audit = audit::audit(staging.fd(), umask).map_err(|e| {
            fail(
                "The extracted files couldn't be checked, so nothing was kept.",
                format!("audit: {e}"),
            )
        })?;
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
            },
            cb,
        )?;
        Ok(Extracted {
            path: placed.path,
            left_out: placed.left_out,
            clash_all: placed.clash_all,
            removed: audit.removed,
            skipped: col.skipped,
            skipped_more: col.skipped_more,
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
        for attempt in 0..MAX_PASSWORD_TRIES {
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
            };
            match self.attempt(&a, cancel, cb, col)? {
                Final::NeedPassword(wrong) => match cb.password(wrong) {
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
        let mut running = spawn::spawn(
            &self.exe,
            self.timeout,
            &file,
            a.staging.map(|s| s.fd_owned()),
        )
        .map_err(|e| {
            let words = if e.kind() == io::ErrorKind::NotFound {
                "The archive reader isn't installed."
            } else {
                "The archive reader couldn't be started."
            };
            fail(words, format!("{}: {e}", self.exe.display()))
        })?;
        let driven = drive(&mut running, a, cancel, cb, col);
        // Dead and reaped before anything looks at staging, on every path.
        let status = running.finish();
        match driven {
            Ok(f) => Ok(f),
            Err(Halt::Failed(reason)) => Err(Error::Failed(reason)),
            Err(Halt::Refused(e)) => Err(Error::LimitRefused(e)),
            Err(Halt::Bad(why)) => Err(fail("The archive reader sent something unexpected.", why)),
            Err(Halt::Stop(Stop::Cancelled)) => Err(Error::Cancelled),
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

struct Attempt<'a> {
    op: Op,
    archive: &'a Path,
    staging: Option<&'a Staging>,
    password: Option<&'a Zeroizing<Vec<u8>>>,
    request: &'a Request,
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
}

/// A reply's text with controls gone and a length cap: it goes to the user.
fn clean(text: &str, max: usize) -> String {
    let t: String = text
        .chars()
        .take(max)
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    t.trim().to_string()
}

/// Talks to the worker until its final reply.
fn drive(
    running: &mut Running,
    a: &Attempt<'_>,
    cancel: &Cancel,
    cb: &mut dyn Callbacks,
    col: &mut Collected,
) -> Result<Final, Halt> {
    if let Some(p) = a.password {
        running.send(&Request::Password(p.clone()).encode(), cancel)?;
    }
    running.send(&a.request.encode(), cancel)?;

    let mut declined: Option<Exceeded> = None;
    let mut questions = 0u32;
    let mut last_progress: Option<Instant> = None;
    loop {
        let (reply, frame_len) = running.recv(cancel)?;
        match reply {
            Reply::Format(f) if a.op == Op::List && col.format.is_none() => {
                cb.format(&f);
                col.format = Some(f);
            }
            Reply::Entries(batch) if a.op == Op::List => {
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
                let now = Instant::now();
                if last_progress.is_none_or(|t| now.duration_since(t) >= PROGRESS_EVERY) {
                    last_progress = Some(now);
                    cb.progress(bytes, items);
                }
            }
            Reply::NeedPassword { wrong } => return Ok(Final::NeedPassword(wrong)),
            Reply::Limit(e) if a.op == Op::Extract => {
                questions += 1;
                if questions > MAX_LIMIT_QUESTIONS {
                    return Err(Halt::Bad("too many limit questions"));
                }
                // The ones that can't be gone past are never asked.
                let go_on = e.kind.askable() && cb.limit(&e);
                if !go_on && e.kind.askable() {
                    declined = Some(e);
                }
                running.send(&Request::GoOn(go_on).encode(), cancel)?;
            }
            Reply::Skipped { index, reason } if a.op != Op::List => {
                let reason = clean(&reason, 300);
                cb.skipped(index, &reason);
                if col.skipped.len() < MAX_SKIPPED {
                    col.skipped.push(SkippedEntry { index, reason });
                } else {
                    col.skipped_more = col.skipped_more.saturating_add(1);
                }
            }
            Reply::SkippedMore { count } if a.op != Op::List => {
                col.skipped_more = col.skipped_more.saturating_add(count);
                cb.skipped_more(count);
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
                return Err(Halt::Failed(if reason.is_empty() {
                    "The archive reader failed.".into()
                } else {
                    reason
                }));
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
