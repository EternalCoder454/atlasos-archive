//! The window's backend: what a launch asks for, the open archive's folders,
//! and the one running job. `main.cpp` calls `activate` with the first
//! launch's arguments and with each forwarded second launch's.
//!
//! Everything slow runs on a job thread (`job.rs`); its results come back
//! here through `qt_thread().queue`, tagged with the job's generation so the
//! answer of a job that was replaced or cancelled is dropped. This object
//! lives on the GUI thread and never blocks.

#[cxx_qt::bridge]
pub mod qobject {
    unsafe extern "C++" {
        include!("cxx-qt-lib/qstring.h");
        type QString = cxx_qt_lib::QString;
        include!("cxx-qt-lib/qstringlist.h");
        type QStringList = cxx_qt_lib::QStringList;
    }

    extern "RustQt" {
        #[qobject]
        #[namespace = "telamon_archive"]
        /// "" (no archive), "loading", "archive" or "job".
        #[qproperty(QString, view)]
        /// A plain sentence about the last launch (a refused argument, a
        /// busy window); "" for none.
        #[qproperty(QString, notice)]
        /// Why the last archive couldn't be opened; "" for none.
        #[qproperty(QString, open_error, cxx_name = "openError")]
        #[qproperty(QString, archive_path, cxx_name = "archivePath")]
        #[qproperty(QString, archive_name, cxx_name = "archiveName")]
        /// Why the listing stopped short, "" for a whole listing.
        #[qproperty(QString, broken)]
        /// JSON: the rows of the folder shown (`view.rs`).
        #[qproperty(QString, folder)]
        /// JSON: the breadcrumb segments.
        #[qproperty(QString, crumbs)]
        #[qproperty(bool, can_up, cxx_name = "canUp")]
        #[qproperty(bool, can_back, cxx_name = "canBack")]
        /// Started with --extract-here or --extract-to-folder into an empty
        /// window: only the job is shown, and the window closes after a
        /// success.
        #[qproperty(bool, job_only, cxx_name = "jobOnly")]
        /// "", "running", "done", "failed" or "cancelled".
        #[qproperty(QString, job_state, cxx_name = "jobState")]
        #[qproperty(QString, job_title, cxx_name = "jobTitle")]
        #[qproperty(QString, job_text, cxx_name = "jobText")]
        /// 0 to 1, or -1 while the total isn't known.
        #[qproperty(f64, job_fraction, cxx_name = "jobFraction")]
        #[qproperty(QString, job_result, cxx_name = "jobResult")]
        /// The result folder cleaned for display (`jobResult` is for Show Files).
        #[qproperty(QString, job_result_shown, cxx_name = "jobResultShown")]
        /// How many items were left out of the finished extraction.
        #[qproperty(i32, job_left, cxx_name = "jobLeft")]
        #[qproperty(QString, job_error, cxx_name = "jobError")]
        /// A message under the password field, "" for none.
        #[qproperty(QString, password_note, cxx_name = "passwordNote")]
        /// JSON: what was skipped or taken out, and why.
        #[qproperty(QString, job_details, cxx_name = "jobDetails")]
        #[qproperty(QString, job_warning, cxx_name = "jobWarning")]
        /// "Archive 2 of 3" while several are extracted one after another.
        #[qproperty(QString, job_queue, cxx_name = "jobQueue")]
        /// What the job waits on: "", "password", "limit" or "clash".
        #[qproperty(QString, question)]
        #[qproperty(QString, question_text, cxx_name = "questionText")]
        /// The last password didn't work.
        #[qproperty(bool, question_wrong, cxx_name = "questionWrong")]
        type Backend = super::BackendRust;
    }

    unsafe extern "RustQt" {
        /// Handles a launch's arguments (without the program name), relative
        /// paths read against `cwd`.
        #[qinvokable]
        fn activate(self: Pin<&mut Backend>, args: &QStringList, cwd: &QString);

        /// Opens an archive (a path or a `file:` URL).
        #[qinvokable]
        #[cxx_name = "openArchive"]
        fn open_archive(self: Pin<&mut Backend>, location: &QString);

        #[qinvokable]
        fn enter(self: Pin<&mut Backend>, id: i32);
        #[qinvokable]
        fn up(self: Pin<&mut Backend>);
        #[qinvokable]
        fn back(self: Pin<&mut Backend>);
        #[qinvokable]
        #[cxx_name = "goTo"]
        fn go_to(self: Pin<&mut Backend>, id: i32);

        /// Forgets the open archive and the job: the window closed.
        #[qinvokable]
        fn reset(self: Pin<&mut Backend>);

        /// Extracts the whole archive into `<folder>/<name>/`.
        #[qinvokable]
        #[cxx_name = "extractAll"]
        fn extract_all(self: Pin<&mut Backend>, folder: &QString);
        /// The folder the extraction dialog starts in.
        #[qinvokable]
        #[cxx_name = "defaultFolder"]
        fn default_folder(self: &Backend) -> QString;
        #[qinvokable]
        #[cxx_name = "cancelJob"]
        fn cancel_job(self: Pin<&mut Backend>);
        /// Leaves the finished job's view.
        #[qinvokable]
        #[cxx_name = "closeJob"]
        fn close_job(self: Pin<&mut Backend>);
        #[qinvokable]
        #[cxx_name = "showFiles"]
        fn show_files(self: Pin<&mut Backend>);

        #[qinvokable]
        #[cxx_name = "answerPassword"]
        fn answer_password(self: Pin<&mut Backend>, password: &QString);
        #[qinvokable]
        #[cxx_name = "cancelPassword"]
        fn cancel_password(self: Pin<&mut Backend>);
        #[qinvokable]
        #[cxx_name = "answerLimit"]
        fn answer_limit(self: Pin<&mut Backend>, go_on: bool);
        /// `action`: 0 Replace, 1 Skip, 2 Keep Both.
        #[qinvokable]
        #[cxx_name = "answerClash"]
        fn answer_clash(self: Pin<&mut Backend>, action: i32, all: bool);

        /// The finished job's folder should be shown in the file manager
        /// (`main.cpp` does it).
        #[qsignal]
        #[cxx_name = "showFilesRequested"]
        fn show_files_requested(self: Pin<&mut Backend>, path: QString);
    }

    impl cxx_qt::Threading for Backend {}

    #[namespace = "rust::cxxqtlib1"]
    unsafe extern "C++" {
        include!("cxx-qt-lib/common.h");

        #[cxx_name = "make_unique"]
        fn backend_make_unique() -> UniquePtr<Backend>;
    }
}

use core::pin::Pin;
use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::mpsc::Sender;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use cxx_qt::{CxxQtType, Threading};
use cxx_qt_lib::{QString, QStringList};
use telamon_archive_core::client::{Cancel, Clash, ClashAnswer};
use telamon_archive_core::proto::MAX_PASSWORD;
use telamon_archive_core::tree::{ROOT, Tree};
use zeroize::Zeroizing;

use crate::job::{self, Answer, Done, ExtractJob, Failure, Front, Question};
use crate::view::{self, Action};

/// How long closing the app waits for a cancelled job to clean up.
const SHUTDOWN_WAIT: Duration = Duration::from_secs(15);

/// The running job, as the GUI thread holds it.
struct Control {
    cancel: Cancel,
    answers: Sender<Answer>,
}

#[derive(Default)]
pub struct BackendRust {
    view: QString,
    notice: QString,
    open_error: QString,
    archive_path: QString,
    archive_name: QString,
    broken: QString,
    folder: QString,
    crumbs: QString,
    can_up: bool,
    can_back: bool,
    job_only: bool,
    job_state: QString,
    job_title: QString,
    job_text: QString,
    job_fraction: f64,
    job_result: QString,
    job_result_shown: QString,
    job_left: i32,
    job_error: QString,
    password_note: QString,
    job_details: QString,
    job_warning: QString,
    job_queue: QString,
    question: QString,
    question_text: QString,
    question_wrong: bool,

    // Not shown to QML.
    archive: Option<PathBuf>,
    tree: Option<Arc<Tree>>,
    current: u32,
    history: Vec<u32>,
    /// The password that opened the archive, kept (zeroized) for its jobs.
    secret: Option<Zeroizing<Vec<u8>>>,
    /// Bumped for every job; a result tagged with an older one is dropped.
    generation: u64,
    control: Option<Control>,
    thread: Option<JoinHandle<()>>,
    total: u64,
    /// Archives still to extract one after another, and how they go.
    queue: VecDeque<PathBuf>,
    batch_here: bool,
    batch_size: usize,
    clash_all: Option<Clash>,
}

impl Drop for BackendRust {
    /// Closing the app cancels the job, and waits (a while) for it to take
    /// its staging folder away.
    fn drop(&mut self) {
        if let Some(c) = self.control.take() {
            c.cancel.cancel();
        }
        if let Some(handle) = self.thread.take() {
            let end = Instant::now() + SHUTDOWN_WAIT;
            while !handle.is_finished() && Instant::now() < end {
                std::thread::sleep(Duration::from_millis(20));
            }
            if handle.is_finished() {
                let _ = handle.join();
            } else {
                log::warn!("a job was still stopping when the app closed");
            }
        }
    }
}

fn q(text: &str) -> QString {
    QString::from(text)
}

/// "photos.zip" for the path, cleaned for display.
fn shown_name(path: &std::path::Path) -> String {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "archive".into());
    view::clean(&name)
}

impl qobject::Backend {
    pub fn activate(mut self: Pin<&mut Self>, args: &QStringList, cwd: &QString) {
        // Arguments are untrusted: parsed in `view`, never logged.
        let mut list = Vec::new();
        for i in 0..args.len().max(0) {
            if let Some(a) = args.get(i) {
                list.push(String::from(a));
            }
        }
        if list.is_empty() {
            return;
        }
        let launch = view::parse_launch(&list, &String::from(cwd));
        let mut notice = launch.problem.clone();
        if launch.files.is_empty() {
            return;
        }
        match launch.action {
            Action::Open => {
                if launch.files.len() > 1 {
                    notice = Some(
                        "Telamon Archive opens one archive at a time, so only the first was opened."
                            .into(),
                    );
                }
                let first = launch.files.into_iter().next().unwrap_or_default();
                self.as_mut().start_open(first);
                if let Some(n) = notice {
                    self.as_mut().set_notice(q(&n));
                }
            }
            Action::ExtractHere => {
                self.as_mut().start_batch(true, launch.files);
                if let Some(n) = notice {
                    self.as_mut().set_notice(q(&n));
                }
            }
            Action::ExtractToFolder => {
                self.as_mut().start_batch(false, launch.files);
                if let Some(n) = notice {
                    self.as_mut().set_notice(q(&n));
                }
            }
        }
    }

    pub fn reset(mut self: Pin<&mut Self>) {
        if let Some(c) = self.as_mut().rust_mut().control.take() {
            c.cancel.cancel();
        }
        {
            let mut r = self.as_mut().rust_mut();
            // Whatever the stopped job reports is dropped.
            r.generation = r.generation.wrapping_add(1);
            r.tree = None;
            r.archive = None;
            r.secret = None;
            r.current = ROOT;
            r.history.clear();
            r.queue.clear();
            r.clash_all = None;
        }
        self.as_mut().set_view(QString::default());
        self.as_mut().set_job_state(QString::default());
        self.as_mut().set_question(QString::default());
        self.as_mut().set_open_error(QString::default());
        self.as_mut().set_notice(QString::default());
        self.as_mut().set_broken(QString::default());
        self.as_mut().set_folder(QString::default());
        self.as_mut().set_job_only(false);
        self.as_mut().set_archive_path(QString::default());
        self.as_mut().set_archive_name(QString::default());
    }

    pub fn open_archive(self: Pin<&mut Self>, location: &QString) {
        match view::local_path(&String::from(location), "") {
            Some(p) => self.start_open(p),
            None => {
                let mut me = self;
                me.as_mut()
                    .set_notice(q("Only files on this computer can be opened."));
            }
        }
    }

    /// Stops what runs and starts a new generation; the new job's cancel
    /// handle and answers channel.
    fn begin(mut self: Pin<&mut Self>) -> (u64, Cancel, std::sync::mpsc::Receiver<Answer>) {
        if let Some(c) = self.as_mut().rust_mut().control.take() {
            c.cancel.cancel();
        }
        let cancel = Cancel::new();
        let (tx, rx) = job::channel();
        let generation = {
            let mut r = self.as_mut().rust_mut();
            r.generation = r.generation.wrapping_add(1);
            r.control = Some(Control {
                cancel: cancel.clone(),
                answers: tx,
            });
            r.generation
        };
        self.as_mut().set_question(QString::default());
        (generation, cancel, rx)
    }

    fn extracting(&self) -> bool {
        self.job_state().to_string() == "running"
    }

    pub fn start_open(mut self: Pin<&mut Self>, path: PathBuf) {
        if self.extracting() {
            self.as_mut()
                .set_notice(q("Finish or cancel the current extraction first."));
            return;
        }
        let (generation, cancel, rx) = self.as_mut().begin();
        {
            let mut r = self.as_mut().rust_mut();
            r.tree = None;
            r.secret = None;
            r.archive = Some(path.clone());
            r.current = ROOT;
            r.history.clear();
            r.queue.clear();
            r.clash_all = None;
        }
        self.as_mut().set_open_error(QString::default());
        self.as_mut().set_notice(QString::default());
        self.as_mut().set_broken(QString::default());
        self.as_mut().set_job_state(QString::default());
        self.as_mut().set_archive_path(q(&path.to_string_lossy()));
        self.as_mut().set_archive_name(q(&shown_name(&path)));
        self.as_mut().set_view(q("loading"));
        let qt = self.qt_thread();
        let spawned = std::thread::Builder::new()
            .name("archive-list".into())
            .spawn(move || {
                let front = Front::new(qt.clone(), generation, rx, cancel.clone(), None);
                let run = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    job::list(front, path.clone(), cancel)
                }));
                let (result, secret) = run.unwrap_or_else(|p| (Err(job::panicked(p)), None));
                let _ = qt.queue(move |o| o.list_done(generation, result, secret));
            });
        self.finish_spawn(spawned, "open the archive");
    }

    /// Keeps the thread's handle, or says why there is none.
    fn finish_spawn(
        mut self: Pin<&mut Self>,
        spawned: std::io::Result<JoinHandle<()>>,
        what: &str,
    ) {
        match spawned {
            Ok(h) => self.as_mut().rust_mut().thread = Some(h),
            Err(e) => {
                log::error!("couldn't start a job thread: {e}");
                self.as_mut().rust_mut().control = None;
                self.as_mut().set_view(QString::default());
                self.as_mut().set_job_state(QString::default());
                self.as_mut().set_open_error(q(&format!(
                    "Couldn't {what}: the computer is out of resources."
                )));
            }
        }
    }

    pub fn list_done(
        mut self: Pin<&mut Self>,
        generation: u64,
        result: Result<telamon_archive_core::client::Listing, Failure>,
        secret: Option<Zeroizing<Vec<u8>>>,
    ) {
        if generation != self.rust().generation {
            return;
        }
        self.as_mut().rust_mut().control = None;
        self.as_mut().set_question(QString::default());
        match result {
            Ok(listing) => {
                let overflow = listing.tree.overflow;
                {
                    let mut r = self.as_mut().rust_mut();
                    r.tree = Some(Arc::new(listing.tree));
                    r.secret = secret;
                    r.current = ROOT;
                }
                self.as_mut().set_broken(q(&listing
                    .broken
                    .map(|b| view::clean(&b))
                    .unwrap_or_default()));
                if overflow {
                    self.as_mut().set_notice(q(
                        "This archive holds more items than can be shown; the rest are left out.",
                    ));
                }
                self.as_mut().set_view(q("archive"));
                self.refresh_folder();
            }
            Err(Failure::Cancelled) => {
                self.as_mut().set_view(QString::default());
            }
            Err(Failure::Words(why)) => {
                self.as_mut().set_view(QString::default());
                self.as_mut().set_open_error(q(&why));
            }
        }
    }

    fn refresh_folder(mut self: Pin<&mut Self>) {
        let Some(tree) = self.rust().tree.clone() else {
            return;
        };
        let (id, back) = (self.rust().current, !self.rust().history.is_empty());
        let name = self.archive_name().to_string();
        self.as_mut().set_folder(q(&view::folder_json(&tree, id)));
        self.as_mut()
            .set_crumbs(q(&view::crumbs_json(&tree, id, &name)));
        self.as_mut().set_can_up(id != ROOT);
        self.as_mut().set_can_back(back);
    }

    fn move_to(mut self: Pin<&mut Self>, id: u32) {
        let Some(tree) = self.rust().tree.clone() else {
            return;
        };
        if id != ROOT && !view::is_folder(&tree, id) {
            return;
        }
        let from = self.rust().current;
        if from == id {
            return;
        }
        {
            let mut r = self.as_mut().rust_mut();
            r.history.push(from);
            // A long wander keeps the newest steps.
            if r.history.len() > 1000 {
                r.history.remove(0);
            }
            r.current = id;
        }
        self.refresh_folder();
    }

    pub fn enter(self: Pin<&mut Self>, id: i32) {
        if let Ok(id) = u32::try_from(id) {
            self.move_to(id);
        }
    }

    pub fn go_to(self: Pin<&mut Self>, id: i32) {
        self.enter(id);
    }

    pub fn up(self: Pin<&mut Self>) {
        let Some(tree) = self.rust().tree.clone() else {
            return;
        };
        let parent = view::parent_of(&tree, self.rust().current);
        self.move_to(parent);
    }

    pub fn back(mut self: Pin<&mut Self>) {
        let previous = self.as_mut().rust_mut().history.pop();
        if let Some(id) = previous {
            self.as_mut().rust_mut().current = id;
            self.refresh_folder();
        }
    }

    pub fn default_folder(&self) -> QString {
        let dir = self
            .rust()
            .archive
            .as_deref()
            .and_then(|a| a.parent())
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();
        q(&dir)
    }

    pub fn extract_all(mut self: Pin<&mut Self>, folder: &QString) {
        if self.extracting() {
            return;
        }
        let (Some(tree), Some(archive)) = (self.rust().tree.clone(), self.rust().archive.clone())
        else {
            return;
        };
        let Some(dest_dir) = view::local_path(&String::from(folder), "") else {
            self.as_mut()
                .set_notice(q("Pick a folder on this computer."));
            return;
        };
        self.as_mut().rust_mut().queue.clear();
        self.as_mut().rust_mut().batch_size = 0;
        self.as_mut().set_job_only(false);
        self.start_extract(ExtractJob {
            archive,
            dest_dir,
            here: false,
            tree: Some(tree),
            clash_all: None,
        });
    }

    /// `--extract-here` / `--extract-to-folder`: each archive in turn.
    fn start_batch(mut self: Pin<&mut Self>, here: bool, files: Vec<PathBuf>) {
        if self.extracting() && self.rust().batch_size > 0 && self.rust().batch_here == here {
            // The same kind of job is under way: these wait their turn.
            let mut r = self.as_mut().rust_mut();
            r.batch_size = r.batch_size.saturating_add(files.len());
            r.queue.extend(files);
            return;
        }
        if self.extracting() {
            self.as_mut()
                .set_notice(q("Finish or cancel the current extraction first."));
            return;
        }
        // Into an empty window only the job is shown, and it closes itself.
        let empty = self.view().to_string().is_empty();
        self.as_mut().set_job_only(empty);
        {
            let mut r = self.as_mut().rust_mut();
            r.batch_here = here;
            r.batch_size = files.len();
            r.queue = files.into();
            r.clash_all = None;
        }
        self.run_next();
    }

    fn run_next(mut self: Pin<&mut Self>) {
        let Some(archive) = self.as_mut().rust_mut().queue.pop_front() else {
            return;
        };
        let (here, size, left) = {
            let r = self.rust();
            (r.batch_here, r.batch_size, r.queue.len())
        };
        let dest_dir = match archive.parent() {
            Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
            _ => PathBuf::from("."),
        };
        let clash_all = self.rust().clash_all;
        let label = if size > 1 {
            format!("Archive {} of {}", size - left, size)
        } else {
            String::new()
        };
        self.as_mut().set_job_queue(q(&label));
        self.start_extract(ExtractJob {
            archive,
            dest_dir,
            here,
            tree: None,
            clash_all,
        });
    }

    fn start_extract(mut self: Pin<&mut Self>, job: ExtractJob) {
        let (generation, cancel, rx) = self.as_mut().begin();
        self.as_mut().rust_mut().total = 0;
        self.as_mut()
            .set_job_title(q(&format!("Extracting {}", shown_name(&job.archive))));
        self.as_mut().set_job_text(QString::default());
        self.as_mut().set_job_fraction(-1.0);
        self.as_mut().set_job_result(QString::default());
        self.as_mut().set_job_result_shown(QString::default());
        self.as_mut().set_job_left(0);
        self.as_mut().set_job_error(QString::default());
        self.as_mut().set_job_details(QString::default());
        self.as_mut().set_job_warning(QString::default());
        self.as_mut().set_notice(QString::default());
        self.as_mut().set_job_state(q("running"));
        self.as_mut().set_view(q("job"));
        let saved = if job.tree.is_some() {
            self.rust().secret.clone()
        } else {
            None
        };
        let qt = self.qt_thread();
        let spawned = std::thread::Builder::new()
            .name("archive-extract".into())
            .spawn(move || {
                let front = Front::new(qt.clone(), generation, rx, cancel.clone(), saved);
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    job::extract(front, job, cancel, &qt, generation)
                }))
                .unwrap_or_else(|p| Err(job::panicked(p)));
                let _ = qt.queue(move |o| o.extract_done(generation, result));
            });
        self.finish_spawn(spawned, "start the extraction");
    }

    pub fn job_total(mut self: Pin<&mut Self>, generation: u64, total: u64) {
        if generation != self.rust().generation {
            return;
        }
        self.as_mut().rust_mut().total = total;
        if total > 0 {
            self.as_mut().set_job_fraction(0.0);
        }
        self.as_mut().set_job_text(q(&job::bytes_text(0, total)));
    }

    pub fn job_progress(mut self: Pin<&mut Self>, generation: u64, bytes: u64, _items: u64) {
        if generation != self.rust().generation || !self.extracting() {
            return;
        }
        let total = self.rust().total;
        if total > 0 {
            self.as_mut()
                .set_job_fraction((bytes as f64 / total as f64).clamp(0.0, 1.0));
        }
        self.as_mut()
            .set_job_text(q(&job::bytes_text(bytes, total)));
    }

    pub fn extract_done(mut self: Pin<&mut Self>, generation: u64, result: Result<Done, Failure>) {
        if generation != self.rust().generation {
            return;
        }
        self.as_mut().rust_mut().control = None;
        self.as_mut().set_question(QString::default());
        match result {
            Ok(done) => {
                self.as_mut().rust_mut().clash_all = done.clash_all;
                if !self.rust().queue.is_empty() {
                    self.run_next();
                    return;
                }
                self.as_mut().set_job_fraction(1.0);
                self.as_mut().set_job_text(QString::default());
                self.as_mut().set_job_result(q(&done.path));
                self.as_mut()
                    .set_job_result_shown(q(&view::clean(&done.path)));
                self.as_mut()
                    .set_job_left(i32::try_from(done.left).unwrap_or(i32::MAX));
                self.as_mut().set_job_details(q(&done.details));
                self.as_mut()
                    .set_job_warning(q(&done.unconfirmed.unwrap_or_default()));
                if done.left_out {
                    self.as_mut().set_job_error(q(
                        "Nothing was extracted, because you chose to skip the one item that was already there.",
                    ));
                }
                self.as_mut().set_job_state(q("done"));
            }
            Err(Failure::Cancelled) => {
                self.as_mut().rust_mut().queue.clear();
                self.as_mut().set_job_state(q("cancelled"));
                if !self.job_only() {
                    self.leave_job();
                }
            }
            Err(Failure::Words(why)) => {
                let rest = self.rust().queue.len();
                self.as_mut().rust_mut().queue.clear();
                let why = match rest {
                    0 => why,
                    1 => format!("{why} The next archive wasn't extracted."),
                    n => format!("{why} The other {n} archives weren't extracted."),
                };
                self.as_mut().set_job_error(q(&why));
                self.as_mut().set_job_state(q("failed"));
            }
        }
    }

    pub fn cancel_job(mut self: Pin<&mut Self>) {
        self.as_mut().rust_mut().queue.clear();
        if let Some(c) = &self.rust().control {
            c.cancel.cancel();
        }
        if self.extracting() {
            self.as_mut().set_job_text(q("Cancelling…"));
        }
    }

    /// Back from a finished job to the archive, or to the empty window.
    fn leave_job(mut self: Pin<&mut Self>) {
        self.as_mut().set_job_state(QString::default());
        let has_tree = self.rust().tree.is_some();
        self.as_mut().set_view(if has_tree {
            q("archive")
        } else {
            QString::default()
        });
        if has_tree {
            self.refresh_folder();
        }
    }

    pub fn close_job(self: Pin<&mut Self>) {
        if !self.extracting() {
            self.leave_job();
        }
    }

    pub fn show_files(self: Pin<&mut Self>) {
        let path = self.job_result().to_string();
        if path.starts_with('/') {
            self.show_files_requested(q(&path));
        }
    }

    /// Shows a question the job asked (called from the job thread's queue).
    pub fn show_question(mut self: Pin<&mut Self>, generation: u64, question: Question) {
        if generation != self.rust().generation {
            return;
        }
        let name = self.archive_name().to_string();
        let (kind, text, wrong) = match question {
            Question::Password { wrong } => {
                let name = self
                    .rust()
                    .archive
                    .as_deref()
                    .map(shown_name)
                    .unwrap_or(name);
                ("password", format!("{name} is password-protected."), wrong)
            }
            Question::Limit(text) => ("limit", text, false),
            Question::Clash(name) => ("clash", name, false),
        };
        self.as_mut().set_password_note(QString::default());
        self.as_mut().set_question_text(q(&text));
        self.as_mut().set_question_wrong(wrong);
        self.as_mut().set_question(q(kind));
    }

    /// Sends the answer to the parked job and takes the question down. The
    /// answer is dropped when no such question is open.
    fn answer(mut self: Pin<&mut Self>, kind: &str, answer: Answer) {
        if self.question().to_string() != kind {
            return;
        }
        if let Some(c) = &self.rust().control {
            let _ = c.answers.send(answer);
        }
        self.as_mut().set_question(QString::default());
        self.as_mut().set_question_text(QString::default());
        self.as_mut().set_question_wrong(false);
    }

    pub fn answer_password(mut self: Pin<&mut Self>, password: &QString) {
        // The text goes straight into a buffer that is wiped when dropped.
        let bytes = Zeroizing::new(String::from(password).into_bytes());
        if bytes.is_empty() || bytes.len() > MAX_PASSWORD {
            let note = if bytes.is_empty() {
                "Type the password first."
            } else {
                "That password is too long."
            };
            self.as_mut().set_password_note(q(note));
            return;
        }
        self.as_mut().set_password_note(QString::default());
        self.answer("password", Answer::Password(Some(bytes)));
    }

    pub fn cancel_password(self: Pin<&mut Self>) {
        self.answer("password", Answer::Password(None));
    }

    pub fn answer_limit(self: Pin<&mut Self>, go_on: bool) {
        self.answer("limit", Answer::Limit(go_on));
    }

    pub fn answer_clash(self: Pin<&mut Self>, action: i32, all: bool) {
        let action = match action {
            0 => Clash::Replace,
            1 => Clash::Skip,
            _ => Clash::KeepBoth,
        };
        self.answer("clash", Answer::Clash(ClashAnswer { action, all }));
    }
}
