//! Runs jobs through `atlas_archive_core::client`. This is the only module
//! that touches the client: the rest of the program sees plain results.
//!
//! The CLI never parses archive bytes. Every reply the worker sends is
//! untrusted; the client has checked it, and what is printed from it goes
//! through the safe-text functions.

use std::collections::HashMap;
#[cfg(feature = "dev-worker")]
use std::ffi::OsStr;
use std::os::fd::RawFd;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

pub use atlas_archive_core::client::Cancel;
use atlas_archive_core::client::{
    self, Callbacks, Clash, ClashAnswer, Error, ExtractRequest, Mode, Worker,
};
use atlas_archive_core::limits::{Exceeded, format_size};
use atlas_archive_core::name::NameEncoding;
use atlas_archive_core::proto::{Entry, Format};
use atlas_archive_core::tree::Tree;
use zeroize::Zeroizing;

use crate::args::{Common, ExtractArgs, OnClash};
use crate::error::CliError;
use crate::select;
use crate::sig::Signals;
use crate::term::{self, Line, Tty};

/// Progress is drawn at most this often.
const DRAW_EVERY: Duration = Duration::from_millis(100);
/// Skipped items kept from a test, which has no result list of its own.
const MAX_TEST_SKIPS: usize = 1000;

/// What an entry looked like as the archive stores it, for the JSON listing.
pub struct Raw {
    pub utf8: bool,
    pub path: Vec<u8>,
    pub link: Option<Vec<u8>>,
}

/// A finished listing.
pub struct Loaded {
    pub format: Format,
    pub tree: Tree,
    /// By archive index; filled for `list` only.
    pub raw: HashMap<u32, Raw>,
    /// How many entries the worker listed.
    pub entries: u64,
    /// The archive broke part way: why, safe to print. The entries are those
    /// read before that.
    pub broken: Option<String>,
}

/// A finished test.
pub struct Tested {
    /// Items the test left out, with the reason.
    pub skipped: Vec<(u32, String)>,
    pub skipped_more: u64,
}

impl Tested {
    /// Every item could be read.
    pub fn ok(&self) -> bool {
        self.skipped.is_empty() && self.skipped_more == 0
    }
}

/// A finished extraction.
pub struct Extraction {
    pub path: PathBuf,
    /// Skip was chosen for the one clashing item.
    pub left_out: bool,
    /// What the audit took out: path and reason, safe to print.
    pub removed: Vec<(String, String)>,
    /// What was not extracted: name and reason, safe to print.
    pub skipped: Vec<(String, String)>,
    pub skipped_more: u64,
    /// The move couldn't be proven: a sentence, safe to print.
    pub unconfirmed: Option<String>,
}

/// Starts the sweep of dead jobs' staging folders and returns at once: it runs
/// on a detached thread (at most every ten minutes) that nothing waits for, so
/// a dead mount or a big leftover never holds up the command. Quiet: only the
/// log hears.
pub fn clean_stale_jobs() {
    let Some(dir) = client::default_state_dir() else {
        log::debug!("no state folder, so no stale jobs to clean");
        return;
    };
    client::clean_stale_in_background(&dir);
}

/// Where the password question stands, for the exit code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Pw {
    Fine,
    /// No descriptor and no terminal.
    NoSource,
    /// The one from `--password-fd` didn't work.
    Rejected,
    /// The user gave up at the prompt.
    GaveUp,
    /// The terminal hung up, or a signal came, at the prompt.
    Interrupted,
}

/// The exit code and sentence for a client error.
fn map_error(err: Error, pw: Pw, interrupted: bool) -> CliError {
    if interrupted {
        return CliError::Cancelled;
    }
    match err {
        Error::Cancelled => CliError::Cancelled,
        Error::PasswordRequired => CliError::NeedsPassword(
            match pw {
                Pw::NoSource | Pw::Fine => {
                    "This archive needs a password: run in a terminal or use --password-fd."
                }
                Pw::Rejected => "That password didn't work.",
                Pw::GaveUp | Pw::Interrupted => "This archive needs a password.",
            }
            .into(),
        ),
        Error::LimitRefused(e) => {
            let q = e.question();
            let statement = q.strip_suffix(" Unpack it anyway?").unwrap_or(&q);
            CliError::LimitRefused(term::safe(&format!(
                "{statement} Use --allow-large to go past it."
            )))
        }
        Error::Failed(why) => CliError::Failed(term::safe(&why)),
    }
}

/// The one updating progress line on stderr, when stderr is a terminal.
struct Progress {
    enabled: bool,
    label: &'static str,
    last: Option<Instant>,
    drawn: bool,
}

impl Progress {
    fn new(label: &'static str) -> Progress {
        Progress {
            enabled: term::is_tty(libc::STDERR_FILENO),
            label,
            last: None,
            drawn: false,
        }
    }

    fn draw(&mut self, bytes: u64, items: u64) {
        if !self.enabled {
            return;
        }
        let now = Instant::now();
        if self
            .last
            .is_some_and(|t| now.duration_since(t) < DRAW_EVERY)
        {
            return;
        }
        self.last = Some(now);
        self.drawn = true;
        let word = if items == 1 { "item" } else { "items" };
        let line = format!(
            "\r{}: {}, {items} {word}\x1b[K",
            self.label,
            format_size(bytes)
        );
        let _ = std::io::Write::write_all(&mut std::io::stderr(), line.as_bytes());
    }

    /// Takes the line off the screen.
    fn clear(&mut self) {
        if self.drawn {
            let _ = std::io::Write::write_all(&mut std::io::stderr(), b"\r\x1b[K");
            self.drawn = false;
        }
    }
}

/// The front end the client calls on the job thread.
struct Front {
    tty: Option<Tty>,
    /// Questions are asked only when stdin is a terminal too.
    interactive: bool,
    saved: Option<Zeroizing<Vec<u8>>>,
    from_fd: bool,
    pw: Pw,
    /// How many times the client asked for a password.
    asked: u32,
    allow_large: bool,
    on_clash: Option<OnClash>,
    progress: Progress,
    capture: bool,
    raw: HashMap<u32, Raw>,
    entries: u64,
    skipped: Vec<(u32, String)>,
    skipped_more: u64,
}

impl Front {
    fn new(wake: RawFd, label: &'static str, from_fd: Option<Zeroizing<Vec<u8>>>) -> Front {
        let tty = Tty::open(wake);
        Front {
            interactive: tty.is_some() && term::is_tty(libc::STDIN_FILENO),
            tty,
            from_fd: from_fd.is_some(),
            saved: from_fd,
            pw: Pw::Fine,
            asked: 0,
            allow_large: false,
            on_clash: None,
            progress: Progress::new(label),
            capture: false,
            raw: HashMap::new(),
            entries: 0,
            skipped: Vec::new(),
            skipped_more: 0,
        }
    }

    /// Says for the `-v` log where the password came from and how often it
    /// was asked for. Never the password.
    fn log_password(&self) {
        let source = if self.from_fd {
            "from a descriptor"
        } else if self.tty.is_some() {
            "from the terminal, if asked"
        } else {
            "no way to ask"
        };
        log::debug!("password: {source}, asked for {} time(s)", self.asked);
    }

    /// Asks on the terminal; `None` when there is none, or on a signal.
    fn ask(&mut self, prompt: &str) -> Option<String> {
        self.progress.clear();
        self.tty.as_ref()?.ask(prompt)
    }
}

impl Callbacks for Front {
    fn progress(&mut self, bytes: u64, items: u64) {
        self.progress.draw(bytes, items);
    }

    fn entries(&mut self, batch: &[Entry]) {
        self.entries = self.entries.saturating_add(batch.len() as u64);
        if self.capture {
            for e in batch {
                self.raw.insert(
                    e.index,
                    Raw {
                        utf8: e.utf8,
                        path: e.path.clone(),
                        link: e.link.clone(),
                    },
                );
            }
        }
    }

    fn skipped(&mut self, index: u32, reason: &str) {
        if self.skipped.len() < MAX_TEST_SKIPS {
            self.skipped.push((index, reason.to_string()));
        } else {
            self.skipped_more = self.skipped_more.saturating_add(1);
        }
    }

    fn skipped_more(&mut self, count: u64) {
        self.skipped_more = self.skipped_more.saturating_add(count);
    }

    fn limit(&mut self, exceeded: &Exceeded) -> bool {
        if self.allow_large {
            return exceeded.kind.askable();
        }
        if !self.interactive {
            return false;
        }
        let answer = self.ask(&format!("{} [y/N] ", exceeded.question()));
        matches!(answer.as_deref(), Some("y" | "yes"))
    }

    fn password(&mut self, wrong: bool) -> Option<Zeroizing<Vec<u8>>> {
        self.asked = self.asked.saturating_add(1);
        if !wrong && let Some(p) = &self.saved {
            return Some(p.clone());
        }
        if self.from_fd {
            // One line was all the descriptor held.
            self.pw = Pw::Rejected;
            return None;
        }
        self.progress.clear();
        let Some(tty) = &self.tty else {
            self.pw = Pw::NoSource;
            return None;
        };
        let prompt = if wrong {
            "That password didn't work. Password: "
        } else {
            "Password: "
        };
        match tty.password(prompt) {
            Ok(Line::Text(p)) if !p.is_empty() => {
                self.saved = Some(p.clone());
                Some(p)
            }
            Ok(Line::Interrupted) => {
                self.pw = Pw::Interrupted;
                None
            }
            Ok(_) => {
                self.pw = Pw::GaveUp;
                None
            }
            Err(e) => {
                // The terminal can't hide what is typed: no prompt at all.
                log::warn!("can't turn echo off: {e}");
                self.pw = Pw::NoSource;
                None
            }
        }
    }

    fn clash(&mut self, name: &str) -> ClashAnswer {
        let action = match self.on_clash {
            Some(OnClash::Replace) => Clash::Replace,
            Some(OnClash::Skip) => Clash::Skip,
            Some(OnClash::KeepBoth) => Clash::KeepBoth,
            None if self.interactive => {
                let mut action = Clash::KeepBoth;
                for _ in 0..3 {
                    let q = format!(
                        "\"{name}\" is already here. [R]eplace, [S]kip or [K]eep Both? [k] "
                    );
                    match self.ask(&q).as_deref() {
                        Some("r" | "replace") => action = Clash::Replace,
                        Some("s" | "skip") => action = Clash::Skip,
                        Some("" | "k" | "keep" | "keep both") => {}
                        Some(_) => continue,
                        None => {}
                    }
                    break;
                }
                action
            }
            None => Clash::KeepBoth,
        };
        ClashAnswer { action, all: false }
    }
}

/// What a command runs with.
pub struct Job<'a> {
    worker: Worker,
    cancel: Cancel,
    sigs: &'a Signals,
}

impl<'a> Job<'a> {
    /// The installed, sandboxed worker, and no other.
    #[cfg(not(feature = "dev-worker"))]
    pub fn new(cancel: Cancel, sigs: &'a Signals) -> Job<'a> {
        Job {
            worker: Worker::system(),
            cancel,
            sigs,
        }
    }

    /// `worker`: the executable to use (tests); the installed one if `None`.
    #[cfg(feature = "dev-worker")]
    pub fn with_worker(worker: Option<&OsStr>, cancel: Cancel, sigs: &'a Signals) -> Job<'a> {
        let worker = match worker {
            Some(p) => Worker::at(p),
            None => Worker::system(),
        };
        Job {
            worker,
            cancel,
            sigs,
        }
    }

    fn front(&self, label: &'static str, pw: Option<Zeroizing<Vec<u8>>>) -> Front {
        Front::new(self.sigs.wake_fd(), label, pw)
    }

    fn fail(&self, e: Error, front: &mut Front) -> CliError {
        front.progress.clear();
        front.log_password();
        log::debug!("job ended: {e:?}");
        let hung = front.pw == Pw::Interrupted || front.tty.as_ref().is_some_and(Tty::hung_up);
        map_error(e, front.pw, self.sigs.interrupted() || hung)
    }

    fn list_with(
        &self,
        archive: &Path,
        encoding: Option<NameEncoding>,
        front: &mut Front,
    ) -> Result<Loaded, CliError> {
        log::debug!("opening {}", term::safe_os(archive.as_os_str()));
        match self.worker.list(archive, encoding, front, &self.cancel) {
            Ok(l) => {
                front.log_password();
                log::debug!(
                    "listed: format {}, {} entries, name encoding {}",
                    term::safe(&l.format.name),
                    front.entries,
                    l.tree.encoding.label()
                );
                Ok(Loaded {
                    format: l.format,
                    tree: l.tree,
                    raw: std::mem::take(&mut front.raw),
                    entries: front.entries,
                    broken: l.broken.as_deref().map(term::safe),
                })
            }
            Err(e) => Err(self.fail(e, front)),
        }
    }

    pub fn list(
        &self,
        c: &Common,
        pw: Option<Zeroizing<Vec<u8>>>,
        want_raw: bool,
    ) -> Result<Loaded, CliError> {
        let _busy = self.sigs.busy();
        let mut front = self.front("Listing", pw);
        front.capture = want_raw;
        self.list_with(Path::new(&c.archive), c.encoding, &mut front)
    }

    pub fn test(&self, c: &Common, pw: Option<Zeroizing<Vec<u8>>>) -> Result<Tested, CliError> {
        let _busy = self.sigs.busy();
        let mut front = self.front("Testing", pw);
        match self
            .worker
            .test(Path::new(&c.archive), &mut front, &self.cancel)
        {
            Ok(()) => {
                front.progress.clear();
                front.log_password();
                Ok(Tested {
                    skipped: std::mem::take(&mut front.skipped)
                        .into_iter()
                        .map(|(i, r)| (i, term::safe(&r)))
                        .collect(),
                    skipped_more: front.skipped_more,
                })
            }
            Err(e) => Err(self.fail(e, &mut front)),
        }
    }

    pub fn extract(
        &self,
        a: &ExtractArgs,
        pw: Option<Zeroizing<Vec<u8>>>,
    ) -> Result<Extraction, CliError> {
        let _busy = self.sigs.busy();
        let archive = Path::new(&a.common.archive);
        let mut front = self.front("Extracting", pw);
        front.allow_large = a.allow_large;
        front.on_clash = a.on_clash;

        // The listing first: it detects the names' encoding, so the files
        // are named as the listing showed them, and it resolves ENTRY.
        let loaded = self.list_with(archive, a.common.encoding, &mut front)?;
        if let Some(why) = &loaded.broken {
            // Half a listing can't say what to extract: nothing is written.
            return Err(CliError::Failed(why.clone()));
        }
        let selection = if a.entries.is_empty() {
            None
        } else {
            Some(select::resolve(&loaded.tree, &a.entries).map_err(CliError::Failed)?)
        };

        let file_name = archive
            .file_name()
            .map(|n| n.as_bytes().to_vec())
            .unwrap_or_default();
        let default = client::default_name(&file_name);
        let dest_dir: &Path = match (&a.to, archive.parent()) {
            (Some(to), _) => Path::new(to),
            (None, Some(p)) if !p.as_os_str().is_empty() => p,
            (None, _) => Path::new("."),
        };
        let mode = if a.here {
            Mode::ExtractHere
        } else {
            Mode::ExtractTo {
                name: a.name.clone().unwrap_or_else(|| default.clone()),
            }
        };
        let req = ExtractRequest {
            archive,
            dest_dir,
            mode,
            selection,
            encoding: loaded.tree.encoding,
            raw_name: default,
            clash_all: a.on_clash.map(|c| match c {
                OnClash::Replace => Clash::Replace,
                OnClash::Skip => Clash::Skip,
                OnClash::KeepBoth => Clash::KeepBoth,
            }),
        };
        log::debug!(
            "extracting into {} ({}), {}",
            term::safe_os(dest_dir.as_os_str()),
            match &req.mode {
                Mode::ExtractHere => "here".to_string(),
                Mode::ExtractTo { name } => format!("folder {}", term::safe(name)),
            },
            req.selection
                .as_ref()
                .map_or("everything".to_string(), |s| format!(
                    "{} selected",
                    s.len()
                ))
        );
        let got = match self.worker.extract(&req, &mut front, &self.cancel) {
            Ok(g) => g,
            Err(e) => return Err(self.fail(e, &mut front)),
        };
        front.progress.clear();
        front.log_password();

        // Names only for the items that are printed.
        let names = select::names_for(&loaded.tree, got.skipped.iter().map(|s| s.index).collect());
        let name_of = |i: u32| {
            names
                .get(&i)
                .map_or_else(|| format!("item {i}"), |n| n.clone())
        };
        Ok(Extraction {
            path: got.path,
            left_out: got.left_out,
            removed: got
                .removed
                .iter()
                .map(|r| (term::safe(&r.path), term::safe(&r.reason)))
                .collect(),
            skipped: got
                .skipped
                .iter()
                .map(|s| (name_of(s.index), term::safe(&s.reason)))
                .collect(),
            skipped_more: got.skipped_more,
            // Already escaped by the core's `display_text`.
            unconfirmed: got.unconfirmed,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use atlas_archive_core::limits::Kind;

    fn limit() -> Error {
        Error::LimitRefused(Exceeded {
            kind: Kind::TotalSize,
            limit: 48 << 30,
        })
    }

    #[test]
    fn each_error_gets_its_code() {
        let code = |e, pw, int| map_error(e, pw, int).code();
        assert_eq!(code(Error::Cancelled, Pw::Fine, false), 130);
        assert_eq!(code(Error::PasswordRequired, Pw::NoSource, false), 3);
        assert_eq!(code(Error::PasswordRequired, Pw::Rejected, false), 3);
        assert_eq!(code(limit(), Pw::Fine, false), 4);
        assert_eq!(code(Error::Failed("x".into()), Pw::Fine, false), 1);
    }

    #[test]
    fn a_signal_wins_over_any_error() {
        for e in [
            Error::PasswordRequired,
            limit(),
            Error::Failed("The reader was killed.".into()),
        ] {
            assert_eq!(map_error(e, Pw::Fine, true), CliError::Cancelled);
        }
    }

    #[test]
    fn password_words_say_what_is_missing() {
        let m = |pw| {
            map_error(Error::PasswordRequired, pw, false)
                .message()
                .unwrap()
                .to_string()
        };
        assert_eq!(
            m(Pw::NoSource),
            "This archive needs a password: run in a terminal or use --password-fd."
        );
        assert!(m(Pw::Rejected).contains("didn't work"));
    }

    #[test]
    fn limit_words_name_the_flag_and_drop_the_question() {
        let m = map_error(limit(), Pw::Fine, false);
        let text = m.message().unwrap();
        assert!(text.contains("--allow-large"), "{text}");
        assert!(!text.contains("anyway?"), "{text}");
        assert!(text.contains("48 GiB"), "{text}");
    }

    #[test]
    fn worker_text_is_made_safe() {
        let m = map_error(Error::Failed("bad \x1b[2J name".into()), Pw::Fine, false);
        assert!(!m.message().unwrap().contains('\x1b'));
    }
}
