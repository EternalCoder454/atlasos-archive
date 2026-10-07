//! The job thread: one thread per job drives the sandboxed worker through
//! `telamon_archive_core::client` and hands every result to the GUI thread with
//! `qt_thread().queue`. A question (password, limit, name clash) parks the
//! thread on a channel until QML answers; Cancel wakes it. Nothing here
//! touches a QObject except through the queue.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender};
use std::time::Duration;

use cxx_qt::CxxQtThread;
use telamon_archive_core::client::{
    self, Callbacks, Cancel, Clash, ClashAnswer, Error, ExtractRequest, Listing, Mode, Worker,
};
use telamon_archive_core::limits::{Exceeded, format_size};
use telamon_archive_core::tree::{ROOT, Tree};
use zeroize::Zeroizing;

use crate::backend::qobject::Backend;
use crate::view;

/// What QML answers to a question.
pub enum Answer {
    /// `None`: the user gave up.
    Password(Option<Zeroizing<Vec<u8>>>),
    Limit(bool),
    Clash(ClashAnswer),
}

/// What a job is asked.
pub enum Question {
    Password { wrong: bool },
    Limit(String),
    Clash(String),
}

/// How long a parked job waits between looks at Cancel.
const PARK_SLICE: Duration = Duration::from_millis(100);

/// The front end the client calls on the job thread.
pub struct Front {
    qt: CxxQtThread<Backend>,
    generation: u64,
    answers: Receiver<Answer>,
    cancel: Cancel,
    /// The password that opened the archive, for the next job on it.
    saved: Option<Zeroizing<Vec<u8>>>,
}

impl Front {
    pub fn new(
        qt: CxxQtThread<Backend>,
        generation: u64,
        answers: Receiver<Answer>,
        cancel: Cancel,
        saved: Option<Zeroizing<Vec<u8>>>,
    ) -> Front {
        Front {
            qt,
            generation,
            answers,
            cancel,
            saved,
        }
    }

    /// The password that worked, if one was used.
    pub fn take_saved(&mut self) -> Option<Zeroizing<Vec<u8>>> {
        self.saved.take()
    }

    /// Shows a question and waits for the answer; `None` when the job was
    /// cancelled or the window is gone.
    fn ask(&self, q: Question) -> Option<Answer> {
        // An answer left over from an earlier question is no answer to this.
        while self.answers.try_recv().is_ok() {}
        let generation = self.generation;
        self.qt
            .queue(move |o| o.show_question(generation, q))
            .ok()?;
        loop {
            match self.answers.recv_timeout(PARK_SLICE) {
                Ok(a) => return Some(a),
                Err(RecvTimeoutError::Timeout) if self.cancel.is_cancelled() => return None,
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => return None,
            }
        }
    }
}

impl Callbacks for Front {
    fn progress(&mut self, bytes: u64, items: u64) {
        let generation = self.generation;
        let _ = self
            .qt
            .queue(move |o| o.job_progress(generation, bytes, items));
    }

    fn limit(&mut self, exceeded: &Exceeded) -> bool {
        if !exceeded.kind.askable() {
            return false;
        }
        matches!(
            self.ask(Question::Limit(exceeded.question())),
            Some(Answer::Limit(true))
        )
    }

    fn password(&mut self, wrong: bool) -> Option<Zeroizing<Vec<u8>>> {
        if !wrong && let Some(p) = &self.saved {
            return Some(p.clone());
        }
        match self.ask(Question::Password { wrong }) {
            Some(Answer::Password(Some(p))) if !p.is_empty() => {
                self.saved = Some(p.clone());
                Some(p)
            }
            _ => None,
        }
    }

    fn clash(&mut self, name: &str) -> ClashAnswer {
        match self.ask(Question::Clash(view::clean(name))) {
            Some(Answer::Clash(a)) => a,
            // Cancelled: whatever is chosen, the job stops next.
            _ => ClashAnswer {
                action: Clash::Skip,
                all: false,
            },
        }
    }
}

/// How a job ended, for the GUI thread.
pub enum Failure {
    Cancelled,
    /// A sentence for the user.
    Words(String),
}

impl From<Error> for Failure {
    fn from(e: Error) -> Failure {
        match e {
            Error::Cancelled => Failure::Cancelled,
            other => Failure::Words(view::clean(&other.to_string())),
        }
    }
}

/// A job thread panicked: logged, and a plain failure for the window.
pub fn panicked(p: Box<dyn std::any::Any + Send>) -> Failure {
    let what = p
        .downcast_ref::<&str>()
        .map(|s| s.to_string())
        .or_else(|| p.downcast_ref::<String>().cloned())
        .unwrap_or_default();
    log::error!("a job thread panicked: {what}");
    Failure::Words("Something went wrong inside Telamon Archive.".into())
}

/// The worker to use: the installed one. Only the `dev-worker` feature (tests,
/// never a shipped build) lets `TELAMON_ARCHIVE_WORKER` name another.
pub fn worker() -> Worker {
    #[cfg(feature = "dev-worker")]
    if let Some(p) = std::env::var_os("TELAMON_ARCHIVE_WORKER") {
        return Worker::at(p);
    }
    Worker::system()
}

/// Lists the archive (job thread).
pub fn list(
    mut front: Front,
    path: PathBuf,
    cancel: Cancel,
) -> (Result<Listing, Failure>, Option<Zeroizing<Vec<u8>>>) {
    let r = worker().list(&path, None, &mut front, &cancel);
    (r.map_err(Failure::from), front.take_saved())
}

/// One extraction.
pub struct ExtractJob {
    pub archive: PathBuf,
    pub dest_dir: PathBuf,
    pub here: bool,
    /// The listing, when the window has it; else the job lists first.
    pub tree: Option<Arc<Tree>>,
    pub clash_all: Option<Clash>,
}

/// What an extraction produced, as the GUI shows it.
pub struct Done {
    pub path: String,
    pub left_out: bool,
    /// Items skipped or taken out.
    pub left: u64,
    pub clash_all: Option<Clash>,
    pub unconfirmed: Option<String>,
    /// (name, reason) of what was skipped or taken out, as JSON for QML.
    pub details: String,
}

/// Lists if needed, then extracts (job thread). `qt` and `generation` tell the
/// GUI the total once it is known.
pub fn extract(
    mut front: Front,
    job: ExtractJob,
    cancel: Cancel,
    qt: &CxxQtThread<Backend>,
    generation: u64,
) -> Result<Done, Failure> {
    let worker = worker();
    let tree = match job.tree {
        Some(t) => t,
        None => {
            let l = worker.list(&job.archive, None, &mut front, &cancel)?;
            if let Some(why) = l.broken {
                return Err(Failure::Words(view::clean(&why)));
            }
            if l.tree.overflow {
                return Err(Failure::Words(
                    "This archive holds too many items to extract safely.".into(),
                ));
            }
            Arc::new(l.tree)
        }
    };
    let total = tree.nodes.get(ROOT as usize).map_or(0, |n| n.size);
    let _ = qt.queue(move |o| o.job_total(generation, total));

    let file_name = job
        .archive
        .file_name()
        .map(|n| n.as_encoded_bytes().to_vec())
        .unwrap_or_default();
    let default = client::default_name(&file_name);
    let mode = if job.here {
        Mode::ExtractHere
    } else {
        Mode::ExtractTo {
            name: default.clone(),
        }
    };
    let req = ExtractRequest {
        archive: &job.archive,
        dest_dir: &job.dest_dir,
        mode,
        selection: None,
        encoding: tree.encoding,
        raw_name: default,
        clash_all: job.clash_all,
    };
    let got = worker.extract(&req, &mut front, &cancel)?;

    let wanted: Vec<u32> = got.skipped.iter().map(|s| s.index).collect();
    let names = view::names_for(&tree, &wanted);
    let mut rows: Vec<(String, String)> = got
        .skipped
        .iter()
        .map(|s| {
            let name = names
                .get(&s.index)
                .cloned()
                .unwrap_or_else(|| format!("Item {}", s.index));
            (name, view::clean(&s.reason))
        })
        .collect();
    rows.extend(
        got.removed
            .iter()
            .map(|r| (view::clean(&r.path), view::clean(&r.reason))),
    );
    let more = got.skipped_more.saturating_add(got.removed_more as u64);
    Ok(Done {
        path: got.path.to_string_lossy().into_owned(),
        left_out: got.left_out,
        left: (rows.len() as u64).saturating_add(more),
        clash_all: got.clash_all,
        unconfirmed: got.unconfirmed.as_deref().map(view::clean),
        details: view::details_json(&rows, more),
    })
}

/// "1.2 MiB of 3.4 GiB" for the job view.
pub fn bytes_text(done: u64, total: u64) -> String {
    if total == 0 {
        format_size(done)
    } else {
        format!("{} of {}", format_size(done.min(total)), format_size(total))
    }
}

/// The channel a job's questions are answered on.
pub fn channel() -> (Sender<Answer>, Receiver<Answer>) {
    std::sync::mpsc::channel()
}
