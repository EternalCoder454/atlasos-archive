//! Telamon Archive's job service (docs/DESIGN.md, "The API other apps call"),
//! without Qt: validating what a caller sent, queueing jobs (a few at once,
//! the rest waiting, a cap on how many wait), driving each through the
//! sandboxed worker on its own thread, and holding the state the D-Bus job
//! objects and the job windows show. Whoever embeds it (the app) learns of
//! changes through a `Notifier`.
//!
//! Nothing here touches archive bytes: that is the worker's, through
//! `telamon_archive_core::client`.

#[doc(hidden)]
pub mod json;
mod run;
pub mod uri;
pub mod validate;

use std::collections::{BTreeMap, VecDeque};
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::{Duration, Instant};

use telamon_archive_core::client::{self, Cancel, Clash, ClashAnswer, Worker};
use telamon_archive_core::compress::{CompressFormat, Level};
use telamon_archive_core::name;
use zeroize::Zeroizing;

pub use json::string as json_string;
pub use validate::FileId;

/// Jobs that run at once; the rest wait (extraction is disk-bound).
pub const MAX_RUNNING: usize = 2;
/// Jobs that may wait; past that a call fails with `TooManyJobs`.
pub const MAX_WAITING: usize = 16;
/// How long an Extract All or Compress dialog may stay unanswered.
pub const DIALOG_TTL: Duration = Duration::from_secs(10 * 60);
/// How long a finished job's object stays for callers that come late.
pub const LINGER: Duration = Duration::from_secs(60);
/// The most archives or items one call names.
pub const MAX_ITEMS: usize = 10_000;
/// The most archives one call names.
pub const MAX_ARCHIVES: usize = 64;
/// The most entries one `ExtractEntries` call names.
pub const MAX_ENTRIES: usize = 100_000;
/// The longest option text kept.
const MAX_OPTION: usize = 4096;

/// Why a call was refused, with the D-Bus error name's last part and a
/// sentence for the caller.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ApiError {
    InvalidArgs(String),
    TooManyJobs(String),
}

impl ApiError {
    /// The error's name under `net.eterneon.telamon.Archive1.Error.`.
    pub fn name(&self) -> &'static str {
        match self {
            ApiError::InvalidArgs(_) => "InvalidArgs",
            ApiError::TooManyJobs(_) => "TooManyJobs",
        }
    }

    pub fn message(&self) -> &str {
        match self {
            ApiError::InvalidArgs(m) | ApiError::TooManyJobs(m) => m,
        }
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.message())
    }
}

impl std::error::Error for ApiError {}

/// The `a{sv}` options every call takes.
#[derive(Clone, Debug)]
pub struct Options {
    /// Show the job in Archive's own window (default). A caller with its own
    /// queue passes false; questions are still asked in Archive's window.
    pub show_progress: bool,
    /// For the window to take focus on Wayland (`xdg-activation`).
    pub activation_token: Option<String>,
    /// `wayland:<xdg-foreign handle>` or `x11:<hex id>`: Archive's windows
    /// stack on it.
    pub parent_window: Option<String>,
}

impl Default for Options {
    fn default() -> Options {
        Options {
            show_progress: true,
            activation_token: None,
            parent_window: None,
        }
    }
}

impl Options {
    /// Text options are kept only when short and printable: they go to the
    /// window system.
    pub fn clean(mut self) -> Options {
        let ok = |s: &String| {
            !s.is_empty()
                && s.len() <= MAX_OPTION
                && s.chars().all(|c| c.is_ascii_graphic() || c == ':')
        };
        self.activation_token = self.activation_token.filter(ok);
        self.parent_window = self
            .parent_window
            .filter(|p| ok(p) && (p.starts_with("wayland:") || p.starts_with("x11:")));
        self
    }
}

/// What a job is doing, as the `State` property says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Queued,
    Running,
    Paused,
    WaitingForUser,
    Done,
    Failed,
    Cancelled,
}

impl State {
    pub fn as_str(self) -> &'static str {
        match self {
            State::Queued => "queued",
            State::Running => "running",
            State::Paused => "paused",
            State::WaitingForUser => "waiting-for-user",
            State::Done => "done",
            State::Failed => "failed",
            State::Cancelled => "cancelled",
        }
    }

    pub fn is_over(self) -> bool {
        matches!(self, State::Done | State::Failed | State::Cancelled)
    }
}

/// What a job asks while it waits for the user.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ask {
    /// A password (only Archive's own window can answer: it is never an
    /// argument of a D-Bus call). `wrong`: the last one didn't work.
    Password { archive: String, wrong: bool },
    /// A safety limit was reached; go on or stop.
    Limit(String),
    /// An item of this name is already there.
    Conflict(String),
    /// The Extract All… dialog, waiting for a folder.
    ExtractDialog,
    /// The Compress… dialog, waiting for a name, place and format.
    CompressDialog,
}

impl Ask {
    /// The `Question` property: "password", "limit", "conflict", "dialog".
    pub fn kind(&self) -> &'static str {
        match self {
            Ask::Password { .. } => "password",
            Ask::Limit(_) => "limit",
            Ask::Conflict(_) => "conflict",
            Ask::ExtractDialog | Ask::CompressDialog => "dialog",
        }
    }

    /// The `QuestionText` property: plain words (never a password).
    pub fn text(&self) -> String {
        match self {
            Ask::Password { archive, .. } => format!("{archive} is password-protected."),
            Ask::Limit(t) => t.clone(),
            Ask::Conflict(n) => {
                format!("“{n}” is already here. Replace it, skip it, or keep both?")
            }
            Ask::ExtractDialog => "Choose where to extract.".into(),
            Ask::CompressDialog => "Choose how to compress.".into(),
        }
    }
}

/// What the user answers.
pub enum Answer {
    /// `None`: gave up.
    Password(Option<Zeroizing<Vec<u8>>>),
    Limit(bool),
    Conflict(ClashAnswer),
}

/// What a dialog job is waiting for, with what it starts from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Dialog {
    Extract {
        archives: Vec<PathBuf>,
        /// Which file each path named when the dialog was asked for; the job
        /// stops if one is another file when the answer comes.
        ids: Vec<FileId>,
        folder: PathBuf,
    },
    Compress {
        sources: Vec<PathBuf>,
        folder: PathBuf,
        name: String,
        format: CompressFormat,
    },
}

/// What the Compress… dialog chose.
#[derive(Clone, Debug)]
pub struct CompressChoice {
    pub folder: PathBuf,
    /// The archive's file name; the format's extension is added if it lacks it.
    pub name: String,
    pub format: CompressFormat,
    pub level: Level,
}

/// What kind of job this is, for the `Kind` property and the window's words.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Extract,
    ExtractEntries,
    Compress,
    Test,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Extract => "extract",
            Kind::ExtractEntries => "extract-entries",
            Kind::Compress => "compress",
            Kind::Test => "test",
        }
    }
}

/// A job as it is now. The D-Bus properties and the windows read this.
#[derive(Clone, Debug)]
pub struct Snapshot {
    pub id: u32,
    pub kind: Kind,
    pub title: String,
    pub state: State,
    pub processed_bytes: u64,
    pub total_bytes: u64,
    pub processed_items: u32,
    pub total_items: u32,
    /// Plain words, safe to show; "" for none.
    pub error: String,
    /// `file://` URIs of what was made.
    pub results: Vec<String>,
    pub ask: Option<Ask>,
    pub dialog: Option<Dialog>,
    /// What was skipped or taken out: (name, why).
    pub details: Vec<(String, String)>,
    /// Details past the ones kept.
    pub details_more: u64,
    /// A sentence to show under the result (a move that couldn't be proven).
    pub warning: String,
    /// "Archive 2 of 3" while several are done one after another.
    pub queue_note: String,
    /// What was made, as a path to show; "" for none.
    pub result_path: String,
    pub show_progress: bool,
    pub activation_token: Option<String>,
    pub parent_window: Option<String>,
}

/// Who hears of changes. Called on any thread, never with a lock held; keep
/// the calls short (post to the thread that owns the front end).
pub trait Notifier: Send + Sync {
    /// A job exists (called before the call that made it returns, and before
    /// any other event of the job).
    fn added(&self, id: u32);
    /// Something about the job changed (often: progress).
    fn changed(&self, id: u32);
    /// The job is over, after its last `changed`.
    fn finished(&self, id: u32, state: State, results: &[String]);
    /// The job waits for the user and a window should show it.
    fn needs_user(&self, id: u32);
    /// The job's object is no longer kept.
    fn removed(&self, id: u32);
}

/// A `Notifier` that ignores everything.
pub struct Silent;

impl Notifier for Silent {
    fn added(&self, _: u32) {}
    fn changed(&self, _: u32) {}
    fn finished(&self, _: u32, _: State, _: &[String]) {}
    fn needs_user(&self, _: u32) {}
    fn removed(&self, _: u32) {}
}

/// How the service runs.
#[derive(Clone, Debug)]
pub struct Config {
    pub worker: Worker,
    pub max_running: usize,
    pub max_waiting: usize,
    pub linger: Duration,
    /// How long a dialog may wait for its answer.
    pub dialog_ttl: Duration,
}

impl Config {
    pub fn new(worker: Worker) -> Config {
        Config {
            worker,
            max_running: MAX_RUNNING,
            max_waiting: MAX_WAITING,
            linger: LINGER,
            dialog_ttl: DIALOG_TTL,
        }
    }
}

// ---- jobs ----

/// What a job does, once it runs.
#[derive(Clone, Debug)]
pub(crate) enum Work {
    Extract {
        items: Vec<run::ExtractItem>,
        here: bool,
    },
    Entries {
        archive: PathBuf,
        id: FileId,
        tokens: Vec<String>,
        folder: PathBuf,
    },
    Compress {
        sources: Vec<PathBuf>,
        folder: PathBuf,
        file_name: String,
        format: CompressFormat,
        level: Level,
        ask_on_clash: bool,
    },
    Test {
        archives: Vec<(PathBuf, FileId)>,
    },
    /// A dialog is open; `confirm_*` turns this into one of the above.
    Dialog,
}

pub(crate) struct Data {
    pub title: String,
    pub state: State,
    pub processed_bytes: u64,
    pub total_bytes: u64,
    pub processed_items: u64,
    pub total_items: u64,
    pub error: String,
    pub results: Vec<String>,
    pub ask: Option<Ask>,
    pub dialog: Option<Dialog>,
    pub details: Vec<(String, String)>,
    pub details_more: u64,
    pub warning: String,
    pub queue_note: String,
    pub result_path: String,
    pub finished_at: Option<Instant>,
    pub created: Instant,
    pub user_paused: bool,
    pub started: bool,
    pub work: Option<Work>,
    pub kind: Kind,
}

pub(crate) struct Job {
    pub id: u32,
    pub show_progress: bool,
    pub activation_token: Option<String>,
    pub parent_window: Option<String>,
    pub cancel: Cancel,
    pub data: Mutex<Data>,
    /// Where answers to questions are sent while the job thread waits.
    pub answers: Mutex<Option<Sender<Answer>>>,
}

impl Job {
    pub(crate) fn lock(&self) -> MutexGuard<'_, Data> {
        // A panic in a job thread must not take the service with it.
        self.data.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub(crate) fn snapshot(&self) -> Snapshot {
        let d = self.lock();
        Snapshot {
            id: self.id,
            kind: d.kind,
            title: d.title.clone(),
            state: d.state,
            processed_bytes: d.processed_bytes,
            total_bytes: d.total_bytes,
            processed_items: d.processed_items.min(u64::from(u32::MAX)) as u32,
            total_items: d.total_items.min(u64::from(u32::MAX)) as u32,
            error: d.error.clone(),
            results: d.results.clone(),
            ask: d.ask.clone(),
            dialog: d.dialog.clone(),
            details: d.details.clone(),
            details_more: d.details_more,
            warning: d.warning.clone(),
            queue_note: d.queue_note.clone(),
            result_path: d.result_path.clone(),
            show_progress: self.show_progress,
            activation_token: self.activation_token.clone(),
            parent_window: self.parent_window.clone(),
        }
    }
}

#[derive(Default)]
struct Registry {
    jobs: BTreeMap<u32, Arc<Job>>,
    queue: VecDeque<u32>,
    running: usize,
    next_id: u32,
}

pub(crate) struct Inner {
    pub cfg: Config,
    pub notifier: Arc<dyn Notifier>,
    reg: Mutex<Registry>,
}

impl Inner {
    fn reg(&self) -> MutexGuard<'_, Registry> {
        self.reg.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub(crate) fn changed(&self, job: &Job) {
        self.notifier.changed(job.id);
    }

    /// Starts queued jobs while there is room. Call without any lock held.
    fn schedule(self: &Arc<Self>) {
        loop {
            // Lock order everywhere: the registry, then a job.
            let (next, work) = {
                let mut reg = self.reg();
                if reg.running >= self.cfg.max_running {
                    return;
                }
                let mut picked = None;
                for (pos, id) in reg.queue.iter().enumerate() {
                    let Some(job) = reg.jobs.get(id) else {
                        continue;
                    };
                    let mut d = job.lock();
                    if d.state != State::Queued {
                        continue;
                    }
                    d.state = State::Running;
                    d.started = true;
                    picked = Some((pos, Arc::clone(job), d.work.take()));
                    break;
                }
                let Some((pos, job, work)) = picked else {
                    // Whatever is left in the queue is paused, cancelled or gone.
                    let Registry { queue, jobs, .. } = &mut *reg;
                    queue.retain(|id| {
                        jobs.get(id).is_some_and(|j| {
                            matches!(j.lock().state, State::Queued | State::Paused)
                        })
                    });
                    return;
                };
                reg.queue.remove(pos);
                reg.running += 1;
                (job, work)
            };
            self.notifier.changed(next.id);
            let Some(work) = work else {
                self.end(
                    &next,
                    Err(client::Error::Failed("The job had nothing to do.".into())),
                );
                return;
            };
            let inner = Arc::clone(self);
            let job = Arc::clone(&next);
            let spawned = std::thread::Builder::new()
                .name("archive-job".into())
                .spawn(move || {
                    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        run::execute(&inner, &job, work)
                    }))
                    .unwrap_or_else(|p| {
                        let what = p
                            .downcast_ref::<&str>()
                            .map(|s| s.to_string())
                            .or_else(|| p.downcast_ref::<String>().cloned())
                            .unwrap_or_default();
                        log::error!("a job thread panicked: {what}");
                        Err(client::Error::Failed(
                            "Something went wrong inside Telamon Archive.".into(),
                        ))
                    });
                    inner.end(&job, result);
                });
            if let Err(e) = spawned {
                log::error!("couldn't start a job thread: {e}");
                self.end(
                    &next,
                    Err(client::Error::Failed(
                        "Telamon Archive is out of resources to start this job.".into(),
                    )),
                );
            }
        }
    }

    /// A job's thread is done (or never started): record how it ended, tell
    /// the notifier, and start the next waiting job.
    pub(crate) fn end(self: &Arc<Self>, job: &Arc<Job>, result: Result<(), client::Error>) {
        {
            let mut d = job.lock();
            if !d.state.is_over() {
                match result {
                    Ok(()) => d.state = State::Done,
                    Err(client::Error::Cancelled) => d.state = State::Cancelled,
                    // A question cut short by Cancel ends the job some other
                    // way; the caller asked for a cancel, so that is what it was.
                    Err(_) if job.cancel.is_cancelled() => d.state = State::Cancelled,
                    Err(e) => {
                        d.state = State::Failed;
                        d.error = run::words(&e);
                    }
                }
            }
            d.ask = None;
            d.finished_at = Some(Instant::now());
            d.user_paused = false;
        }
        *job.answers.lock().unwrap_or_else(|p| p.into_inner()) = None;
        {
            let mut reg = self.reg();
            reg.running = reg.running.saturating_sub(1);
        }
        self.announce_end(job);
        self.schedule();
    }

    /// The `changed` and `finished` events of a job that is over.
    fn announce_end(&self, job: &Job) {
        let (state, results) = {
            let d = job.lock();
            (d.state, d.results.clone())
        };
        self.notifier.changed(job.id);
        self.notifier.finished(job.id, state, &results);
    }
}

/// The service. Cheap to clone; every clone is the same service.
#[derive(Clone)]
pub struct Service {
    inner: Arc<Inner>,
}

impl Service {
    pub fn new(cfg: Config, notifier: Arc<dyn Notifier>) -> Service {
        let inner = Arc::new(Inner {
            cfg,
            notifier,
            reg: Mutex::new(Registry::default()),
        });
        let weak: Weak<Inner> = Arc::downgrade(&inner);
        // Forgets finished jobs once they have lingered.
        let janitor = std::thread::Builder::new()
            .name("archive-janitor".into())
            .spawn(move || {
                loop {
                    std::thread::sleep(Duration::from_millis(500));
                    let Some(inner) = weak.upgrade() else { return };
                    inner.sweep();
                }
            });
        if let Err(e) = janitor {
            log::warn!("no thread to forget finished jobs: {e}");
        }
        Service { inner }
    }

    // ---- the API ----

    /// `ExtractHere`.
    pub fn extract_here(&self, archives: &[String], opts: Options) -> Result<u32, ApiError> {
        let items = run::archives(archives, None)?;
        let title = run::extract_title(&items);
        self.add(
            Kind::Extract,
            title,
            Work::Extract { items, here: true },
            &opts,
            None,
        )
    }

    /// `ExtractTo`: `folder` empty means next to each archive.
    pub fn extract_to(
        &self,
        archives: &[String],
        folder: &str,
        opts: Options,
    ) -> Result<u32, ApiError> {
        let folder = (!folder.is_empty())
            .then(|| validate::folder(folder))
            .transpose()?;
        let items = run::archives(archives, folder.as_deref())?;
        let title = run::extract_title(&items);
        self.add(
            Kind::Extract,
            title,
            Work::Extract { items, here: false },
            &opts,
            None,
        )
    }

    /// `ExtractAll`: a dialog job, `waiting-for-user` until `confirm_extract_all`.
    pub fn extract_all(&self, archives: &[String], opts: Options) -> Result<u32, ApiError> {
        let items = run::archives(archives, None)?;
        let folder = items
            .first()
            .map(|i| i.dest_dir.clone())
            .unwrap_or_default();
        let dialog = Dialog::Extract {
            archives: items.iter().map(|i| i.archive.clone()).collect(),
            ids: items.iter().map(|i| i.id).collect(),
            folder,
        };
        let title = run::extract_title(&items);
        self.add(
            Kind::Extract,
            title,
            Work::Dialog,
            &opts,
            Some((Ask::ExtractDialog, dialog)),
        )
    }

    /// The dialog's answer: where to extract. Starts the job.
    pub fn confirm_extract_all(&self, id: u32, folder: PathBuf) -> Result<(), ApiError> {
        validate::check_folder(&folder)?;
        let job = self.dialog_job(id, Kind::Extract)?;
        let Some(Dialog::Extract { archives, ids, .. }) = job.lock().dialog.clone() else {
            return Err(ApiError::InvalidArgs(
                "That job isn't waiting for a folder.".into(),
            ));
        };
        let mut items = Vec::new();
        for (a, asked) in archives.iter().zip(&ids) {
            let meta = std::fs::metadata(a).map_err(|_| {
                ApiError::InvalidArgs(format!("“{}” isn't there any more.", validate::shown(a)))
            })?;
            // The dialog can stay open for minutes: a name now on another
            // file is not the archive that was asked about.
            if FileId::of(&meta) != *asked {
                return Err(ApiError::InvalidArgs(format!(
                    "“{}” has been replaced since the question was asked.",
                    validate::shown(a)
                )));
            }
            items.push(run::ExtractItem {
                archive: a.clone(),
                id: *asked,
                dest_dir: folder.clone(),
            });
        }
        self.start_dialog_job(&job, Work::Extract { items, here: false })
    }

    /// `ExtractEntries`: the drop half of drag-out.
    pub fn extract_entries(
        &self,
        archive: &str,
        entries: &[String],
        folder: &str,
        opts: Options,
    ) -> Result<u32, ApiError> {
        let (archive, id) = validate::archive(archive)?;
        let folder = validate::folder(folder)?;
        if entries.is_empty() || entries.len() > MAX_ENTRIES {
            return Err(ApiError::InvalidArgs(
                "Choose at least one item to extract (and not more than 100,000).".into(),
            ));
        }
        if entries.iter().any(|t| !run::token_shape(t)) {
            return Err(ApiError::InvalidArgs(
                "One of the items isn't one Telamon Archive gave out.".into(),
            ));
        }
        let title = format!("Extracting from {}", validate::shown(&archive));
        self.add(
            Kind::ExtractEntries,
            title,
            Work::Entries {
                archive,
                id,
                tokens: entries.to_vec(),
                folder,
            },
            &opts,
            None,
        )
    }

    /// `Compress`.
    pub fn compress(
        &self,
        files: &[String],
        format: &str,
        destination: &str,
        opts: Options,
    ) -> Result<u32, ApiError> {
        let format = run::format(format)?;
        let sources = run::sources(files)?;
        let (folder, file_name, ask_on_clash) = run::target(&sources, format, destination)?;
        let title = run::compress_title(&sources, format);
        self.add(
            Kind::Compress,
            title,
            Work::Compress {
                sources,
                folder,
                file_name,
                format,
                level: Level::Normal,
                ask_on_clash,
            },
            &opts,
            None,
        )
    }

    /// `CompressDialog`: a dialog job, `waiting-for-user` until `confirm_compress`.
    pub fn compress_dialog(&self, files: &[String], opts: Options) -> Result<u32, ApiError> {
        let sources = run::sources(files)?;
        let format = CompressFormat::Zip;
        let (folder, file_name, _) = run::target(&sources, format, "")?;
        let name = file_name
            .strip_suffix(format.extension())
            .unwrap_or(&file_name)
            .to_string();
        let title = run::compress_title(&sources, format);
        let dialog = Dialog::Compress {
            sources,
            folder,
            name,
            format,
        };
        self.add(
            Kind::Compress,
            title,
            Work::Dialog,
            &opts,
            Some((Ask::CompressDialog, dialog)),
        )
    }

    /// The dialog's answer. Starts the job.
    pub fn confirm_compress(&self, id: u32, choice: CompressChoice) -> Result<(), ApiError> {
        validate::check_folder(&choice.folder)?;
        let name = validate::file_name(&choice.name)?;
        let ext = choice.format.extension();
        let file_name = if name.to_ascii_lowercase().ends_with(ext) && name.len() > ext.len() {
            name
        } else {
            format!("{name}{ext}")
        };
        validate::file_name(&file_name)?;
        let job = self.dialog_job(id, Kind::Compress)?;
        let Some(Dialog::Compress { sources, .. }) = job.lock().dialog.clone() else {
            return Err(ApiError::InvalidArgs(
                "That job isn't waiting for a name.".into(),
            ));
        };
        for s in &sources {
            if std::fs::symlink_metadata(s).is_err() {
                return Err(ApiError::InvalidArgs(format!(
                    "“{}” isn't there any more.",
                    validate::shown(s)
                )));
            }
        }
        job.lock().title = run::compress_title(&sources, choice.format);
        self.start_dialog_job(
            &job,
            Work::Compress {
                sources,
                folder: choice.folder,
                file_name,
                format: choice.format,
                level: choice.level,
                ask_on_clash: true,
            },
        )
    }

    /// `Test`.
    pub fn test(&self, archives: &[String], opts: Options) -> Result<u32, ApiError> {
        let items = run::archives(archives, None)?;
        let title = if items.len() == 1 {
            format!("Testing {}", validate::shown(&items[0].archive))
        } else {
            format!("Testing {} archives", items.len())
        };
        let archives = items.into_iter().map(|i| (i.archive, i.id)).collect();
        self.add(Kind::Test, title, Work::Test { archives }, &opts, None)
    }

    /// `Open`: checks the archive; the window is the embedder's to show.
    pub fn open(&self, archive: &str) -> Result<PathBuf, ApiError> {
        validate::archive(archive).map(|(p, _)| p)
    }

    // ---- jobs ----

    /// The job as it is now; `None` once it is forgotten.
    pub fn snapshot(&self, id: u32) -> Option<Snapshot> {
        self.inner.reg().jobs.get(&id).map(|j| j.snapshot())
    }

    /// Every job that is kept, finished ones too.
    pub fn ids(&self) -> Vec<u32> {
        self.inner.reg().jobs.keys().copied().collect()
    }

    /// No job exists, not even a finished one that lingers.
    pub fn is_idle(&self) -> bool {
        self.inner.reg().jobs.is_empty()
    }

    /// Pauses: a running job's worker stops (`SIGSTOP`), a waiting one is held.
    pub fn pause(&self, id: u32) -> bool {
        let Some(job) = self.job(id) else {
            return false;
        };
        {
            let mut d = job.lock();
            if d.state.is_over() {
                return false;
            }
            // A dialog has nothing running to stop.
            if d.dialog.is_some() {
                return true;
            }
            d.user_paused = true;
            job.cancel.pause();
            if matches!(d.state, State::Running | State::Queued) {
                d.state = State::Paused;
            }
        }
        self.inner.changed(&job);
        true
    }

    pub fn resume(&self, id: u32) -> bool {
        let Some(job) = self.job(id) else {
            return false;
        };
        {
            let mut d = job.lock();
            if d.state.is_over() {
                return false;
            }
            if d.dialog.is_some() {
                return true;
            }
            d.user_paused = false;
            job.cancel.resume();
            if d.state == State::Paused {
                d.state = if d.started {
                    State::Running
                } else {
                    State::Queued
                };
            }
        }
        self.inner.changed(&job);
        self.inner.schedule();
        true
    }

    /// Cancels: a waiting job ends at once; a running one is stopped, its
    /// staging removed, and ends when the thread is done.
    pub fn cancel(&self, id: u32) -> bool {
        self.inner.cancel(id)
    }

    /// The user's answer to a question. A password can only come from here
    /// (the window), never from D-Bus. `false` when the job asks nothing of
    /// that kind.
    pub fn answer(&self, id: u32, answer: Answer) -> bool {
        let Some(job) = self.job(id) else {
            return false;
        };
        let fits = {
            let d = job.lock();
            matches!(
                (&d.ask, &answer),
                (Some(Ask::Password { .. }), Answer::Password(_))
                    | (Some(Ask::Limit(_)), Answer::Limit(_))
                    | (Some(Ask::Conflict(_)), Answer::Conflict(_))
            )
        };
        if !fits {
            return false;
        }
        let tx = job.answers.lock().unwrap_or_else(|p| p.into_inner());
        tx.as_ref().is_some_and(|tx| tx.send(answer).is_ok())
    }

    /// `AnswerConflict` on D-Bus: `action` is "replace", "skip" or "keep-both".
    pub fn answer_conflict(&self, id: u32, action: &str, all: bool) -> Result<bool, ApiError> {
        let action = match action {
            "replace" => Clash::Replace,
            "skip" => Clash::Skip,
            "keep-both" => Clash::KeepBoth,
            _ => {
                return Err(ApiError::InvalidArgs(
                    "The answer must be “replace”, “skip” or “keep-both”.".into(),
                ));
            }
        };
        Ok(self.answer(id, Answer::Conflict(ClashAnswer { action, all })))
    }

    /// Cancels every job and waits (a while) for their threads to take their
    /// staging folders away. For the app's exit.
    pub fn shutdown(&self, wait: Duration) {
        for id in self.ids() {
            self.cancel(id);
        }
        let end = Instant::now() + wait;
        while Instant::now() < end {
            if self.inner.reg().running == 0 {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        log::warn!("a job was still stopping when the app closed");
    }

    // ---- internals ----

    fn job(&self, id: u32) -> Option<Arc<Job>> {
        self.inner.reg().jobs.get(&id).cloned()
    }

    fn dialog_job(&self, id: u32, kind: Kind) -> Result<Arc<Job>, ApiError> {
        let job = self
            .job(id)
            .ok_or_else(|| ApiError::InvalidArgs("That job isn't there any more.".into()))?;
        {
            let d = job.lock();
            if d.kind != kind || d.dialog.is_none() || d.state != State::WaitingForUser || d.started
            {
                return Err(ApiError::InvalidArgs(
                    "That job isn't waiting for an answer.".into(),
                ));
            }
        }
        Ok(job)
    }

    fn start_dialog_job(&self, job: &Arc<Job>, work: Work) -> Result<(), ApiError> {
        {
            let mut d = job.lock();
            // A cancel may have come between the check and now.
            if d.state != State::WaitingForUser || d.started || d.dialog.is_none() {
                return Err(ApiError::InvalidArgs(
                    "That job isn't waiting for an answer.".into(),
                ));
            }
            d.work = Some(work);
            d.dialog = None;
            d.ask = None;
            d.state = State::Queued;
            d.processed_bytes = 0;
        }
        self.inner.reg().queue.push_back(job.id);
        self.inner.changed(job);
        self.inner.schedule();
        Ok(())
    }

    fn add(
        &self,
        kind: Kind,
        title: String,
        work: Work,
        opts: &Options,
        dialog: Option<(Ask, Dialog)>,
    ) -> Result<u32, ApiError> {
        let opts = opts.clone().clean();
        let job = {
            let mut reg = self.inner.reg();
            let waiting = reg
                .jobs
                .values()
                .filter(|j| {
                    let d = j.lock();
                    !d.started
                        && matches!(
                            d.state,
                            State::Queued | State::Paused | State::WaitingForUser
                        )
                })
                .count();
            if waiting >= self.inner.cfg.max_waiting {
                return Err(ApiError::TooManyJobs(
                    "Archive is busy. Try again when a job finishes.".into(),
                ));
            }
            reg.next_id = reg.next_id.wrapping_add(1).max(1);
            while reg.jobs.contains_key(&reg.next_id) {
                reg.next_id = reg.next_id.wrapping_add(1).max(1);
            }
            let id = reg.next_id;
            let (state, ask, dlg, work) = match dialog {
                Some((ask, dlg)) => (State::WaitingForUser, Some(ask), Some(dlg), None),
                None => (State::Queued, None, None, Some(work)),
            };
            let job = Arc::new(Job {
                id,
                show_progress: opts.show_progress,
                activation_token: opts.activation_token,
                parent_window: opts.parent_window,
                cancel: Cancel::new(),
                data: Mutex::new(Data {
                    title: name::display_text(&title),
                    state,
                    processed_bytes: 0,
                    total_bytes: 0,
                    processed_items: 0,
                    total_items: 0,
                    error: String::new(),
                    results: Vec::new(),
                    ask,
                    dialog: dlg,
                    details: Vec::new(),
                    details_more: 0,
                    warning: String::new(),
                    queue_note: String::new(),
                    result_path: String::new(),
                    finished_at: None,
                    created: Instant::now(),
                    user_paused: false,
                    started: false,
                    work,
                    kind,
                }),
                answers: Mutex::new(None),
            });
            reg.jobs.insert(id, Arc::clone(&job));
            if job.lock().state == State::Queued {
                reg.queue.push_back(id);
            }
            job
        };
        // `added` before anything else of the job is announced.
        self.inner.notifier.added(job.id);
        if job.lock().ask.is_some() {
            self.inner.notifier.needs_user(job.id);
        }
        self.inner.schedule();
        Ok(job.id)
    }
}

impl Inner {
    fn job(&self, id: u32) -> Option<Arc<Job>> {
        self.reg().jobs.get(&id).cloned()
    }

    fn cancel(&self, id: u32) -> bool {
        let Some(job) = self.job(id) else {
            return false;
        };
        let ends_now = {
            let mut d = job.lock();
            if d.state.is_over() {
                return false;
            }
            let ends_now = !d.started;
            if ends_now {
                d.state = State::Cancelled;
                d.work = None;
            }
            ends_now
        };
        job.cancel.cancel();
        if ends_now {
            {
                let mut reg = self.reg();
                reg.queue.retain(|&q| q != id);
            }
            let mut d = job.lock();
            d.ask = None;
            d.finished_at = Some(Instant::now());
            drop(d);
            self.announce_end(&job);
        }
        true
    }

    /// Forgets the jobs that finished more than `linger` ago, and gives up on
    /// dialogs nobody answered for `dialog_ttl`.
    fn sweep(&self) {
        let stale: Vec<u32> = {
            let reg = self.reg();
            reg.jobs
                .iter()
                .filter(|(_, j)| {
                    let d = j.lock();
                    d.dialog.is_some() && !d.started && d.created.elapsed() >= self.cfg.dialog_ttl
                })
                .map(|(&id, _)| id)
                .collect()
        };
        for id in stale {
            self.cancel(id);
        }
        let gone: Vec<u32> = {
            let mut reg = self.reg();
            let ids: Vec<u32> = reg
                .jobs
                .iter()
                .filter(|(_, j)| {
                    j.lock()
                        .finished_at
                        .is_some_and(|t| t.elapsed() >= self.cfg.linger)
                })
                .map(|(&id, _)| id)
                .collect();
            for id in &ids {
                reg.jobs.remove(id);
            }
            ids
        };
        for id in gone {
            self.notifier.removed(id);
        }
    }
}

/// A channel for a job's answers (used by the job thread).
pub(crate) fn answer_channel(job: &Job) -> Receiver<Answer> {
    let (tx, rx) = std::sync::mpsc::channel();
    *job.answers.lock().unwrap_or_else(|p| p.into_inner()) = Some(tx);
    rx
}
