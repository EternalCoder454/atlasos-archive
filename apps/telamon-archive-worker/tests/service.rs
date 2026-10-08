//! The job service (what the D-Bus methods call) against the real, sandboxed
//! worker: each method, the job lifecycle, Pause/Resume/Cancel, conflicts and
//! questions, the cap on waiting jobs, and hostile archives.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use telamon_archive_core::client::{Trash, Worker};
use telamon_archive_core::compress::{CompressFormat, Level};
use telamon_archive_service::{
    Answer, Ask, CompressChoice, Config, Dialog, Notifier, Options, Service, Snapshot, State, uri,
};
use zeroize::Zeroizing;

const WORKER: &str = env!("CARGO_BIN_EXE_telamon-archive-worker");

/// What the notifier heard.
#[derive(Default)]
struct Heard {
    log: Mutex<Vec<String>>,
    finished: Mutex<HashMap<u32, (State, Vec<String>)>>,
    asked: Mutex<Vec<u32>>,
    cv: Condvar,
}

impl Notifier for Heard {
    fn added(&self, id: u32) {
        self.log.lock().unwrap().push(format!("added {id}"));
        self.cv.notify_all();
    }
    fn changed(&self, _: u32) {
        self.cv.notify_all();
    }
    fn finished(&self, id: u32, state: State, results: &[String]) {
        self.log
            .lock()
            .unwrap()
            .push(format!("finished {id} {}", state.as_str()));
        self.finished
            .lock()
            .unwrap()
            .insert(id, (state, results.to_vec()));
        self.cv.notify_all();
    }
    fn needs_user(&self, id: u32) {
        self.asked.lock().unwrap().push(id);
        self.cv.notify_all();
    }
    fn removed(&self, id: u32) {
        self.log.lock().unwrap().push(format!("removed {id}"));
        self.cv.notify_all();
    }
}

struct Env {
    root: PathBuf,
    /// Where archives and sources are made.
    src: PathBuf,
    /// The destination.
    dest: PathBuf,
    heard: Arc<Heard>,
    svc: Service,
}

impl Env {
    fn new(tag: &str) -> Env {
        Env::with(tag, |_| {})
    }

    fn with(tag: &str, tweak: impl FnOnce(&mut Config)) -> Env {
        let base = std::env::var_os("TELAMON_ARCHIVE_TEST_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                std::env::current_exe()
                    .unwrap()
                    .parent()
                    .unwrap()
                    .join("../test-scratch")
            });
        let root = base.join(format!("telamon-service-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        // The API refuses `..`, which the default base has.
        let root = root.canonicalize().unwrap();
        let (src, dest) = (root.join("src"), root.join("dest"));
        std::fs::create_dir_all(&src).unwrap();
        std::fs::create_dir_all(&dest).unwrap();
        let worker = Worker::at(WORKER)
            .with_state_dir(Some(root.join("state")))
            .with_trash(Some(Trash::at(root.join("trash"))));
        let mut cfg = Config::new(worker);
        cfg.linger = Duration::from_secs(2);
        tweak(&mut cfg);
        let heard = Arc::new(Heard::default());
        let svc = Service::new(cfg, heard.clone());
        Env {
            root,
            src,
            dest,
            heard,
            svc,
        }
    }

    fn u(&self, p: impl AsRef<Path>) -> String {
        uri::from_path(p.as_ref())
    }

    /// Waits until `pred` holds for the job, or fails with where it was.
    fn wait(&self, id: u32, what: &str, pred: impl Fn(&Snapshot) -> bool) -> Snapshot {
        let end = Instant::now() + Duration::from_secs(60);
        let mut g = self.heard.log.lock().unwrap();
        loop {
            if let Some(s) = self.svc.snapshot(id)
                && pred(&s)
            {
                return s;
            }
            assert!(
                Instant::now() < end,
                "waiting for {what}: {:?}",
                self.svc.snapshot(id).map(|s| (s.state, s.error))
            );
            g = self
                .heard
                .cv
                .wait_timeout(g, Duration::from_millis(50))
                .unwrap()
                .0;
        }
    }

    fn done(&self, id: u32) -> Snapshot {
        let s = self.wait(id, "the end", |s| s.state.is_over());
        // The Finished event comes with the end.
        let end = Instant::now() + Duration::from_secs(5);
        while !self.heard.finished.lock().unwrap().contains_key(&id) {
            assert!(Instant::now() < end, "no finished event");
            std::thread::sleep(Duration::from_millis(10));
        }
        s
    }

    fn ok(&self, id: u32) -> Snapshot {
        let s = self.done(id);
        assert_eq!(s.state, State::Done, "{}", s.error);
        s
    }

    fn tar_gz(&self, name: &str, files: &[(&str, &str)]) -> PathBuf {
        let stage = self.root.join(format!("stage-{name}"));
        let mut tops: Vec<String> = Vec::new();
        for (path, text) in files {
            let p = stage.join(path);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(&p, text).unwrap();
            let top = path.split('/').next().unwrap().to_string();
            if !tops.contains(&top) {
                tops.push(top);
            }
        }
        let out = self.src.join(name);
        assert!(
            Command::new("tar")
                .arg("-czf")
                .arg(&out)
                .arg("-C")
                .arg(&stage)
                .args(&tops)
                .status()
                .unwrap()
                .success()
        );
        out
    }

    fn ls(&self) -> Vec<String> {
        ls(&self.dest)
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn ls(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .map(|d| {
            d.map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    v.sort();
    v
}

fn opts() -> Options {
    Options::default()
}

fn python(script: &str, args: &[&Path]) {
    let out = Command::new("python3")
        .arg("-I")
        .arg("-c")
        .arg(script)
        .args(args)
        .output()
        .expect("python3");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// ---- the methods ----

#[test]
fn extract_here_runs_a_job_and_reports_the_result() {
    let e = Env::new("here");
    let a = e.tar_gz(
        "photos.tar.gz",
        &[("photos/a.txt", "a"), ("photos/b.txt", "b")],
    );
    let id = e.svc.extract_here(&[e.u(&a)], opts()).unwrap();
    let s = e.ok(id);
    // The archive's own folder is where it goes, and what was made is named.
    assert_eq!(s.results, [e.u(e.src.join("photos"))]);
    assert_eq!(
        std::fs::read_to_string(e.src.join("photos/a.txt")).unwrap(),
        "a"
    );
    assert!(
        s.title.starts_with("Extracting photos.tar.gz"),
        "{}",
        s.title
    );
    assert!(s.total_bytes == 2 && s.processed_bytes == 2, "{s:?}");
    assert_eq!((s.total_items, s.processed_items), (3, 3), "{s:?}");
    assert!(s.error.is_empty() && s.ask.is_none());
    // The events: added first, finished once, after the last change.
    let log = e.heard.log.lock().unwrap().clone();
    assert_eq!(log, [format!("added {id}"), format!("finished {id} done")]);
}

#[test]
fn extract_here_asks_on_a_name_clash_and_the_caller_can_answer() {
    let e = Env::new("clash");
    // One lone top-level file: moved out as it is, so it can clash.
    let a = e.tar_gz("note.tar.gz", &[("note.txt", "new")]);
    std::fs::write(e.src.join("note.txt"), "old").unwrap();
    let id = e.svc.extract_here(&[e.u(&a)], opts()).unwrap();
    let s = e.wait(id, "the question", |s| s.state == State::WaitingForUser);
    assert!(
        matches!(&s.ask, Some(Ask::Conflict(n)) if n == "note.txt"),
        "{:?}",
        s.ask
    );
    assert_eq!(s.ask.as_ref().unwrap().kind(), "conflict");
    assert!(e.heard.asked.lock().unwrap().contains(&id));
    // Nothing is replaced while it waits.
    assert_eq!(
        std::fs::read_to_string(e.src.join("note.txt")).unwrap(),
        "old"
    );
    // A bad answer is refused; the wrong kind of answer finds no question.
    assert!(e.svc.answer_conflict(id, "overwrite", false).is_err());
    assert!(!e.svc.answer(id, Answer::Limit(true)));
    assert!(!e.svc.answer(id, Answer::Password(None)));
    assert!(e.svc.answer_conflict(id, "keep-both", false).unwrap());
    let s = e.ok(id);
    assert_eq!(s.results, [e.u(e.src.join("note (2).txt"))]);
    assert_eq!(
        std::fs::read_to_string(e.src.join("note.txt")).unwrap(),
        "old"
    );
    assert_eq!(
        std::fs::read_to_string(e.src.join("note (2).txt")).unwrap(),
        "new"
    );
}

#[test]
fn replace_goes_through_the_trash_and_skip_leaves_everything() {
    let e = Env::new("replace");
    let a = e.tar_gz("note.tar.gz", &[("note.txt", "new")]);
    std::fs::write(e.src.join("note.txt"), "old").unwrap();
    let id = e.svc.extract_here(&[e.u(&a)], opts()).unwrap();
    e.wait(id, "the question", |s| s.state == State::WaitingForUser);
    assert!(e.svc.answer_conflict(id, "replace", false).unwrap());
    e.ok(id);
    assert_eq!(
        std::fs::read_to_string(e.src.join("note.txt")).unwrap(),
        "new"
    );
    assert_eq!(ls(&e.root.join("trash/files")), ["note.txt"]);

    let id = e.svc.extract_here(&[e.u(&a)], opts()).unwrap();
    e.wait(id, "the question", |s| s.state == State::WaitingForUser);
    assert!(e.svc.answer_conflict(id, "skip", true).unwrap());
    let s = e.ok(id);
    assert!(s.results.is_empty());
    assert!(s.error.contains("Nothing was extracted"), "{}", s.error);
}

#[test]
fn extract_to_makes_a_folder_in_the_chosen_place_or_beside_the_archive() {
    let e = Env::new("to");
    let a = e.tar_gz("data.tar.gz", &[("x.txt", "x"), ("y.txt", "y")]);
    let b = e.tar_gz("more.tar.gz", &[("z.txt", "z"), ("w.txt", "w")]);
    let id = e
        .svc
        .extract_to(&[e.u(&a), e.u(&b)], &e.u(&e.dest), opts())
        .unwrap();
    let s = e.ok(id);
    assert_eq!(e.ls(), ["data", "more"]);
    assert_eq!(
        s.results,
        [e.u(e.dest.join("data")), e.u(e.dest.join("more"))]
    );
    // Two archives: one total, and the progress reached it.
    assert_eq!((s.total_bytes, s.processed_bytes), (4, 4), "{s:?}");
    assert!(s.title.contains("2 archives"), "{}", s.title);
    // An empty folder: beside the archive.
    let id = e.svc.extract_to(&[e.u(&a)], "", opts()).unwrap();
    let s = e.ok(id);
    assert_eq!(s.results, [e.u(e.src.join("data"))]);
    // A taken name is numbered, never asked.
    let id = e.svc.extract_to(&[e.u(&a)], "", opts()).unwrap();
    assert_eq!(e.ok(id).results, [e.u(e.src.join("data (2)"))]);
}

#[test]
fn extract_all_is_a_dialog_job_that_starts_when_confirmed() {
    let e = Env::new("all");
    let a = e.tar_gz("data.tar.gz", &[("x.txt", "x"), ("y.txt", "y")]);
    let id = e.svc.extract_all(&[e.u(&a)], opts()).unwrap();
    let s = e.svc.snapshot(id).unwrap();
    assert_eq!(s.state, State::WaitingForUser);
    assert_eq!(s.ask, Some(Ask::ExtractDialog));
    assert_eq!(s.ask.as_ref().unwrap().kind(), "dialog");
    assert!(matches!(&s.dialog, Some(Dialog::Extract { folder, .. }) if folder == &e.src));
    assert!(e.heard.asked.lock().unwrap().contains(&id));
    // Not a folder, not one that can't be written: refused, the dialog stays.
    assert!(
        e.svc
            .confirm_extract_all(id, e.src.join("data.tar.gz"))
            .is_err()
    );
    assert!(e.svc.confirm_extract_all(id, e.root.join("nope")).is_err());
    assert_eq!(e.svc.snapshot(id).unwrap().state, State::WaitingForUser);
    e.svc.confirm_extract_all(id, e.dest.clone()).unwrap();
    let s = e.ok(id);
    assert_eq!(s.results, [e.u(e.dest.join("data"))]);
    // The dialog is over: a second confirmation finds nothing to answer.
    assert!(e.svc.confirm_extract_all(id, e.dest.clone()).is_err());
    // Dismissing the dialog is Cancel.
    let id = e.svc.extract_all(&[e.u(&a)], opts()).unwrap();
    assert!(e.svc.cancel(id));
    let s = e.done(id);
    assert_eq!(s.state, State::Cancelled);
    assert_eq!(e.heard.finished.lock().unwrap()[&id].0, State::Cancelled);
    assert_eq!(e.ls(), ["data"]);
}

#[test]
fn extract_entries_puts_the_items_in_the_folder() {
    let e = Env::new("entries");
    let a = e.tar_gz(
        "tree.tar.gz",
        &[
            ("top/a.txt", "a"),
            ("top/sub/b.txt", "b"),
            ("top/c.txt", "c"),
        ],
    );
    // What a window would hold: the listing's tokens.
    let listing = Worker::at(WORKER)
        .list(
            &a,
            None,
            &mut telamon_archive_core::client::NoCallbacks,
            &telamon_archive_core::client::Cancel::new(),
        )
        .unwrap();
    let t = &listing.tree;
    let a_txt = t.token(t.find(["top", "a.txt"]).unwrap());
    let sub = t.token(t.find(["top", "sub"]).unwrap());
    let id = e
        .svc
        .extract_entries(
            &e.u(&a),
            &[a_txt.clone(), sub.clone()],
            &e.u(&e.dest),
            opts(),
        )
        .unwrap();
    let s = e.ok(id);
    assert_eq!(e.ls(), ["a.txt", "sub"]);
    assert_eq!(
        s.results,
        [e.u(e.dest.join("a.txt")), e.u(e.dest.join("sub"))]
    );
    assert_eq!(
        std::fs::read_to_string(e.dest.join("sub/b.txt")).unwrap(),
        "b"
    );
    // A token from another archive (or a stale one) finds nothing.
    let id = e
        .svc
        .extract_entries(&e.u(&a), &["3-00000000".into()], &e.u(&e.dest), opts())
        .unwrap();
    let s = e.done(id);
    assert_eq!(s.state, State::Failed);
    assert!(s.error.contains("has changed"), "{}", s.error);
    // Malformed ones are refused at the call.
    for bad in [vec![], vec!["nope".to_string()], vec!["1-2".to_string()]] {
        let r = e.svc.extract_entries(&e.u(&a), &bad, &e.u(&e.dest), opts());
        assert_eq!(r.unwrap_err().name(), "InvalidArgs");
    }
}

#[test]
fn compress_names_the_archive_like_the_design_and_numbers_a_clash() {
    let e = Env::new("compress");
    std::fs::create_dir_all(e.src.join("Photos/sub")).unwrap();
    std::fs::write(e.src.join("Photos/a.jpg"), "a").unwrap();
    std::fs::write(e.src.join("Photos/sub/b.jpg"), "b").unwrap();
    std::fs::write(e.src.join("report.pdf"), "pdf").unwrap();
    std::fs::write(e.src.join("notes.txt"), "txt").unwrap();
    let list = |p: &Path| {
        let out = Command::new("bsdtar").arg("-tf").arg(p).output().unwrap();
        let mut v: Vec<String> = String::from_utf8(out.stdout)
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect();
        v.sort();
        v
    };
    // A folder keeps its name; the archive is beside it.
    let id = e
        .svc
        .compress(&[e.u(e.src.join("Photos"))], "zip", "", opts())
        .unwrap();
    let s = e.ok(id);
    assert_eq!(s.results, [e.u(e.src.join("Photos.zip"))]);
    assert_eq!(
        list(&e.src.join("Photos.zip")),
        ["Photos/", "Photos/a.jpg", "Photos/sub/", "Photos/sub/b.jpg"]
    );
    // A file loses its extension.
    let id = e
        .svc
        .compress(&[e.u(e.src.join("report.pdf"))], "7z", "", opts())
        .unwrap();
    assert_eq!(e.ok(id).results, [e.u(e.src.join("report.7z"))]);
    // Several: Archive.<ext>, and a clash is numbered, not asked.
    let two = [e.u(e.src.join("report.pdf")), e.u(e.src.join("notes.txt"))];
    let id = e.svc.compress(&two, "tar.gz", "", opts()).unwrap();
    assert_eq!(e.ok(id).results, [e.u(e.src.join("Archive.tar.gz"))]);
    let id = e.svc.compress(&two, "tar.gz", "", opts()).unwrap();
    assert_eq!(e.ok(id).results, [e.u(e.src.join("Archive (2).tar.gz"))]);
    assert_eq!(
        list(&e.src.join("Archive.tar.gz")),
        ["notes.txt", "report.pdf"]
    );
    // A destination: used as given (plus the extension), and a clash is asked.
    let dst = e.dest.join("mine.zip");
    let id = e.svc.compress(&two, "zip", &e.u(&dst), opts()).unwrap();
    let s = e.ok(id);
    assert_eq!(s.results, [e.u(&dst)]);
    let id = e
        .svc
        .compress(&two, "zip", &e.u(e.dest.join("mine")), opts())
        .unwrap();
    e.wait(id, "the clash", |s| s.state == State::WaitingForUser);
    assert!(e.svc.answer_conflict(id, "keep-both", false).unwrap());
    assert_eq!(e.ok(id).results, [e.u(e.dest.join("mine (2).zip"))]);
    assert_eq!(e.ls(), ["mine (2).zip", "mine.zip"]);
    // No hidden leftovers anywhere.
    for d in [&e.src, &e.dest] {
        assert!(!ls(d).iter().any(|n| n.starts_with(".")), "{:?}", ls(d));
    }
}

#[test]
fn compress_dialog_starts_when_confirmed() {
    let e = Env::new("cdialog");
    std::fs::write(e.src.join("a.txt"), "a").unwrap();
    std::fs::write(e.src.join("b.txt"), "b").unwrap();
    let files = [e.u(e.src.join("a.txt")), e.u(e.src.join("b.txt"))];
    let id = e.svc.compress_dialog(&files, opts()).unwrap();
    let s = e.svc.snapshot(id).unwrap();
    assert_eq!(s.state, State::WaitingForUser);
    assert_eq!(
        s.dialog,
        Some(Dialog::Compress {
            sources: vec![e.src.join("a.txt"), e.src.join("b.txt")],
            folder: e.src.clone(),
            name: "Archive".into(),
            format: CompressFormat::Zip,
        })
    );
    let bad = |name: &str, folder: &Path| CompressChoice {
        folder: folder.to_path_buf(),
        name: name.into(),
        format: CompressFormat::SevenZip,
        level: Level::Best,
    };
    assert!(e.svc.confirm_compress(id, bad("", &e.dest)).is_err());
    assert!(e.svc.confirm_compress(id, bad("a/b", &e.dest)).is_err());
    assert!(
        e.svc
            .confirm_compress(id, bad("x", &e.root.join("nope")))
            .is_err()
    );
    assert_eq!(e.svc.snapshot(id).unwrap().state, State::WaitingForUser);
    e.svc.confirm_compress(id, bad("both", &e.dest)).unwrap();
    let s = e.ok(id);
    assert_eq!(s.results, [e.u(e.dest.join("both.7z"))]);
    assert_eq!(s.total_items, 2);
    let ok = Command::new("7z")
        .arg("t")
        .arg(e.dest.join("both.7z"))
        .output()
        .unwrap();
    assert!(ok.status.success());
}

#[test]
fn test_checks_an_archive_and_says_what_is_wrong() {
    let e = Env::new("test");
    let a = e.tar_gz("fine.tar.gz", &[("a.txt", "a")]);
    let id = e.svc.test(&[e.u(&a)], opts()).unwrap();
    let s = e.ok(id);
    assert!(
        s.results.is_empty() && s.title == "Testing fine.tar.gz",
        "{}",
        s.title
    );
    // Damaged: the tail is cut off.
    let bad = e.src.join("cut.tar.gz");
    let bytes = std::fs::read(&a).unwrap();
    std::fs::write(&bad, &bytes[..bytes.len() / 2]).unwrap();
    let id = e.svc.test(&[e.u(&bad)], opts()).unwrap();
    let s = e.done(id);
    assert_eq!(s.state, State::Failed);
    assert!(
        s.error.starts_with("“cut.tar.gz” didn't pass"),
        "{}",
        s.error
    );
}

#[test]
fn passwords_are_asked_in_the_window_never_over_the_bus() {
    let e = Env::new("password");
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../crates/telamon-archive-engine/tests/data/aes256-secret.zip");
    let a = e.src.join("secret.zip");
    std::fs::copy(fixture, &a).unwrap();
    let id = e.svc.extract_to(&[e.u(&a)], &e.u(&e.dest), opts()).unwrap();
    let s = e.wait(id, "the question", |s| s.state == State::WaitingForUser);
    assert!(
        matches!(&s.ask, Some(Ask::Password { archive, wrong: false }) if archive == "secret.zip"),
        "{:?}",
        s.ask
    );
    assert_eq!(
        s.ask.as_ref().unwrap().text(),
        "secret.zip is password-protected."
    );
    // The only way to answer is the window's: the D-Bus answer finds nothing.
    assert!(
        e.svc
            .answer_conflict(id, "keep-both", false)
            .is_ok_and(|took| !took)
    );
    // A wrong one is asked again.
    assert!(
        e.svc
            .answer(id, Answer::Password(Some(Zeroizing::new(b"nope".to_vec()))))
    );
    let s = e.wait(id, "the second question", |s| {
        matches!(&s.ask, Some(Ask::Password { wrong: true, .. }))
    });
    assert!(!format!("{s:?}").contains("nope"));
    assert!(e.svc.answer(
        id,
        Answer::Password(Some(Zeroizing::new(b"secret".to_vec())))
    ));
    let s = e.ok(id);
    assert_eq!(s.results.len(), 1);
    assert_eq!(
        std::fs::read(e.dest.join("secret/f.txt")).unwrap(),
        b"secret text\n"
    );
    assert!(!format!("{s:?}").contains("secret text"));
    // Giving up fails the job and leaves nothing.
    let id = e
        .svc
        .extract_to(&[e.u(&a)], &e.u(&e.dest.join("..").join("dest")), opts());
    assert!(id.is_err(), "a path with .. is refused");
    let id = e.svc.extract_to(&[e.u(&a)], &e.u(&e.src), opts()).unwrap();
    e.wait(id, "the question", |s| s.state == State::WaitingForUser);
    assert!(e.svc.answer(id, Answer::Password(None)));
    let s = e.done(id);
    assert_eq!(s.state, State::Failed);
    assert!(s.error.contains("needs a password"), "{}", s.error);
    assert!(
        !ls(&e.src).iter().any(|n| n.starts_with('.')),
        "{:?}",
        ls(&e.src)
    );
}

// ---- arguments ----

#[test]
fn every_argument_is_checked_before_a_job_exists() {
    let e = Env::new("args");
    let a = e.tar_gz("ok.tar.gz", &[("a.txt", "a")]);
    let ua = e.u(&a);
    let bad_uris = [
        "",
        "/abs/path",
        "relative.zip",
        "https://example.com/a.zip",
        "file:relative",
        "file://otherhost/a.zip",
        "file:///a/../b.zip",
        "file:///a/./b.zip",
        "file:///a%00b.zip",
        "file:///nope/missing.zip",
    ];
    for bad in bad_uris {
        let err = e.svc.extract_here(&[bad.to_string()], opts()).unwrap_err();
        assert_eq!(err.name(), "InvalidArgs", "{bad:?}");
        assert!(!err.message().is_empty());
    }
    // A mix: one good, one bad, nothing starts.
    assert!(
        e.svc
            .extract_here(&[ua.clone(), "nope".into()], opts())
            .is_err()
    );
    assert!(e.svc.extract_here(&[], opts()).is_err());
    assert!(e.svc.extract_here(&vec![ua.clone(); 65], opts()).is_err());
    // A folder is no archive; a file is no folder.
    assert!(e.svc.extract_here(&[e.u(&e.dest)], opts()).is_err());
    assert!(e.svc.extract_to(&[ua.clone()], &ua, opts()).is_err());
    assert!(
        e.svc
            .extract_to(&[ua.clone()], &e.u(e.root.join("missing")), opts())
            .is_err()
    );
    // Devices and pipes are no archives.
    assert!(
        e.svc
            .extract_here(&["file:///dev/null".into()], opts())
            .is_err()
    );
    assert!(
        e.svc
            .test(&["file:///proc/self/mem".into()], opts())
            .is_err()
    );
    // Compress: format, sources, destination.
    let one = [e.u(&a)];
    for fmt in ["", "rar", "ZIP", "zip ", "tar", "tar.bz2"] {
        assert!(e.svc.compress(&one, fmt, "", opts()).is_err(), "{fmt:?}");
    }
    assert!(e.svc.compress(&[], "zip", "", opts()).is_err());
    assert!(
        e.svc
            .compress(&[e.u(e.src.join("missing"))], "zip", "", opts())
            .is_err()
    );
    assert!(e.svc.compress(&[e.u("/")], "zip", "", opts()).is_err());
    assert!(e.svc.compress(&one, "zip", "not-a-uri", opts()).is_err());
    assert!(
        e.svc
            .compress(&one, "zip", &e.u(e.root.join("missing/x.zip")), opts())
            .is_err()
    );
    std::fs::create_dir(e.dest.join("folder.zip")).unwrap();
    assert!(
        e.svc
            .compress(&one, "zip", &e.u(e.dest.join("folder.zip")), opts())
            .is_err(),
        "a folder as the file"
    );
    assert!(
        e.svc.compress(&one, "tar.gz", &e.u(&a), opts()).is_err(),
        "over the item itself"
    );
    let twice = [
        e.u(&a),
        e.u(e.dest.join("..").join("src").join("ok.tar.gz")),
    ];
    assert!(e.svc.compress(&twice, "zip", "", opts()).is_err());
    assert!(e.svc.open("nope").is_err());
    assert_eq!(e.svc.open(&ua).unwrap(), a);
    assert!(e.svc.snapshot(999).is_none());
    assert!(!e.svc.cancel(999) && !e.svc.pause(999) && !e.svc.resume(999));
    // Nothing above made a job.
    assert!(e.svc.ids().is_empty());
}

#[test]
fn a_link_to_an_archive_works_and_one_swapped_after_the_call_does_not() {
    let e = Env::new("link");
    let a = e.tar_gz("real.tar.gz", &[("a.txt", "a")]);
    std::os::unix::fs::symlink(&a, e.src.join("link.tar.gz")).unwrap();
    let id = e
        .svc
        .extract_to(&[e.u(e.src.join("link.tar.gz"))], &e.u(&e.dest), opts())
        .unwrap();
    e.ok(id);
    assert_eq!(e.ls(), ["link"]);
    // The file is pinned when the call is made; a job that waits its turn
    // finds another file under the name and stops.
    let e = Env::with("swap", |c| c.max_running = 1);
    let (first, _) = big_job(&e);
    e.wait(first, "running", |s| s.state == State::Running);
    let a = e.tar_gz("real.tar.gz", &[("a.txt", "a")]);
    let other = e.tar_gz("other.tar.gz", &[("evil.txt", "e")]);
    let id = e.svc.extract_to(&[e.u(&a)], &e.u(&e.dest), opts()).unwrap();
    std::fs::rename(&other, &a).unwrap();
    assert!(e.svc.cancel(first));
    let s = e.done(id);
    assert_eq!(s.state, State::Failed);
    assert!(
        s.error.contains("was replaced by another file"),
        "{}",
        s.error
    );
    assert!(e.ls().is_empty());
}

// ---- limits, states ----

#[test]
fn only_so_many_jobs_wait() {
    // Nothing runs, so every job waits.
    let e = Env::with("cap", |c| c.max_running = 0);
    let a = e.tar_gz("a.tar.gz", &[("a.txt", "a")]);
    let mut ids = Vec::new();
    for _ in 0..16 {
        ids.push(e.svc.test(&[e.u(&a)], opts()).unwrap());
    }
    let err = e.svc.test(&[e.u(&a)], opts()).unwrap_err();
    assert_eq!(err.name(), "TooManyJobs");
    assert_eq!(
        err.message(),
        "Archive is busy. Try again when a job finishes."
    );
    // Dialogs wait too.
    assert_eq!(
        e.svc.extract_all(&[e.u(&a)], opts()).unwrap_err().name(),
        "TooManyJobs"
    );
    assert!(
        ids.iter()
            .all(|&i| e.svc.snapshot(i).unwrap().state == State::Queued)
    );
    // Cancelling one makes room.
    assert!(e.svc.cancel(ids[0]));
    assert_eq!(e.svc.snapshot(ids[0]).unwrap().state, State::Cancelled);
    e.svc.test(&[e.u(&a)], opts()).unwrap();
    // Everything is cancelled on the way out.
    e.svc.shutdown(Duration::from_secs(5));
}

#[test]
fn two_jobs_run_at_once_and_the_rest_in_turn() {
    let e = Env::new("turns");
    let a = e.tar_gz("a.tar.gz", &[("a.txt", "a")]);
    let ids: Vec<u32> = (0..5)
        .map(|_| e.svc.test(&[e.u(&a)], opts()).unwrap())
        .collect();
    // Never more than two at a time.
    let mut peak = 0;
    for _ in 0..200 {
        let running = ids
            .iter()
            .filter(|&&i| matches!(e.svc.snapshot(i).map(|s| s.state), Some(State::Running)))
            .count();
        peak = peak.max(running);
        if ids
            .iter()
            .all(|&i| e.svc.snapshot(i).is_none_or(|s| s.state.is_over()))
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(peak <= 2, "{peak} at once");
    for id in ids {
        e.ok(id);
    }
}

fn big_job(e: &Env) -> (u32, PathBuf) {
    // Incompressible data, slow to compress at the best xz level.
    let mut data = vec![0u8; 32 << 20];
    let mut x = 0x2545_F491_4F6C_DD1Du64;
    for b in data.iter_mut() {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *b = x as u8;
    }
    std::fs::write(e.src.join("big.bin"), &data).unwrap();
    let dst = e.dest.join("big.tar.xz");
    // The dialog's choice is the only way to ask for the best level.
    let id = e
        .svc
        .compress_dialog(&[e.u(e.src.join("big.bin"))], opts())
        .unwrap();
    e.svc
        .confirm_compress(
            id,
            CompressChoice {
                folder: e.dest.clone(),
                name: "big".into(),
                format: CompressFormat::TarXz,
                level: Level::Best,
            },
        )
        .unwrap();
    (id, dst)
}

#[test]
fn pause_stops_progress_and_resume_goes_on() {
    let e = Env::new("pause");
    let (id, dst) = big_job(&e);
    e.wait(id, "progress", |s| {
        s.state == State::Running && s.processed_bytes > 0
    });
    assert!(e.svc.pause(id));
    let s = e.wait(id, "paused", |s| s.state == State::Paused);
    // Give the stop a moment to take hold, then nothing moves.
    std::thread::sleep(Duration::from_millis(500));
    let at = e.svc.snapshot(id).unwrap();
    assert_eq!(at.state, State::Paused);
    std::thread::sleep(Duration::from_millis(1000));
    let later = e.svc.snapshot(id).unwrap();
    assert_eq!(later.state, State::Paused);
    assert_eq!(
        later.processed_bytes, at.processed_bytes,
        "it moved while paused"
    );
    assert!(later.processed_bytes < later.total_bytes);
    assert!(s.processed_bytes <= at.processed_bytes);
    assert!(!dst.exists(), "nothing is placed while it is paused");
    assert!(e.svc.resume(id));
    e.wait(id, "running again", |s| {
        s.state == State::Running || s.state.is_over()
    });
    let s = e.ok(id);
    assert_eq!(s.results, [e.u(&dst)]);
    assert_eq!(s.processed_bytes, s.total_bytes);
    // Pause and resume of something over do nothing.
    assert!(!e.svc.pause(id) && !e.svc.resume(id) && !e.svc.cancel(id));
}

#[test]
fn cancel_leaves_no_partial_output() {
    let e = Env::new("cancel");
    let (id, dst) = big_job(&e);
    e.wait(id, "progress", |s| {
        s.state == State::Running && s.processed_bytes > 0
    });
    assert!(e.svc.cancel(id));
    let s = e.done(id);
    assert_eq!(s.state, State::Cancelled);
    assert!(s.results.is_empty());
    assert!(!dst.exists());
    assert!(e.ls().is_empty(), "{:?}", e.ls());
    assert_eq!(e.heard.finished.lock().unwrap()[&id].0, State::Cancelled);
    // Cancelling a paused job works too.
    let (id, _) = big_job(&e);
    e.wait(id, "progress", |s| {
        s.state == State::Running && s.processed_bytes > 0
    });
    assert!(e.svc.pause(id));
    e.wait(id, "paused", |s| s.state == State::Paused);
    assert!(e.svc.cancel(id));
    assert_eq!(e.done(id).state, State::Cancelled);
    assert!(e.ls().is_empty(), "{:?}", e.ls());
    let hidden: Vec<_> = ls(&e.dest)
        .into_iter()
        .filter(|n| n.starts_with('.'))
        .collect();
    assert!(hidden.is_empty(), "{hidden:?}");
}

#[test]
fn a_queued_job_can_be_held_and_cancelled() {
    let e = Env::with("held", |c| c.max_running = 1);
    let (first, _) = big_job(&e);
    e.wait(first, "running", |s| s.state == State::Running);
    let a = e.tar_gz("a.tar.gz", &[("a.txt", "a")]);
    let second = e.svc.test(&[e.u(&a)], opts()).unwrap();
    let third = e.svc.test(&[e.u(&a)], opts()).unwrap();
    assert_eq!(e.svc.snapshot(second).unwrap().state, State::Queued);
    // Held: it is skipped when its turn comes.
    assert!(e.svc.pause(second));
    assert_eq!(e.svc.snapshot(second).unwrap().state, State::Paused);
    assert!(e.svc.cancel(first));
    assert_eq!(e.done(first).state, State::Cancelled);
    e.ok(third);
    assert_eq!(e.svc.snapshot(second).unwrap().state, State::Paused);
    assert!(e.svc.resume(second));
    e.ok(second);
}

#[test]
fn finished_jobs_are_forgotten_after_a_while() {
    let e = Env::with("linger", |c| c.linger = Duration::from_millis(600));
    let a = e.tar_gz("a.tar.gz", &[("a.txt", "a")]);
    let id = e.svc.test(&[e.u(&a)], opts()).unwrap();
    e.ok(id);
    assert!(!e.svc.is_idle());
    let end = Instant::now() + Duration::from_secs(10);
    while e.svc.snapshot(id).is_some() {
        assert!(Instant::now() < end, "never forgotten");
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(e.svc.is_idle());
    assert!(
        e.heard
            .log
            .lock()
            .unwrap()
            .contains(&format!("removed {id}"))
    );
}

#[test]
fn options_are_cleaned() {
    let e = Env::new("options");
    let a = e.tar_gz("a.tar.gz", &[("a.txt", "a")]);
    let id = e
        .svc
        .test(
            &[e.u(&a)],
            Options {
                show_progress: false,
                activation_token: Some("tok\nbad".into()),
                parent_window: Some("x11:1a00004".into()),
            },
        )
        .unwrap();
    let s = e.ok(id);
    assert!(!s.show_progress);
    assert_eq!(
        s.activation_token, None,
        "a token with a line break is dropped"
    );
    assert_eq!(s.parent_window.as_deref(), Some("x11:1a00004"));
    let id = e
        .svc
        .test(
            &[e.u(&a)],
            Options {
                show_progress: true,
                activation_token: Some("xdg-token-123".into()),
                parent_window: Some("gtk:1".into()),
            },
        )
        .unwrap();
    let s = e.ok(id);
    assert_eq!(s.activation_token.as_deref(), Some("xdg-token-123"));
    assert_eq!(
        s.parent_window, None,
        "an unknown kind of window handle is dropped"
    );
}

// ---- hostile archives ----

#[test]
fn zip_slip_absolute_and_link_tricks_never_leave_the_folder() {
    let e = Env::new("hostile");
    let evil = e.src.join("evil.zip");
    python(
        r#"
import sys, zipfile, stat
z = zipfile.ZipFile(sys.argv[1], "w")
z.writestr("../zip-slip.txt", "x")
z.writestr("a/../../zip-slip2.txt", "x")
z.writestr("/abs-path.txt", "x")
z.writestr("..\\backslash.txt", "x")
z.writestr("C:\\drive.txt", "x")
z.writestr("good.txt", "good")
# a link, then a file written "through" it
info = zipfile.ZipInfo("lnk")
info.create_system = 3
info.external_attr = (stat.S_IFLNK | 0o777) << 16
z.writestr(info, "../outside")
z.writestr("lnk/pwned.txt", "x")
info = zipfile.ZipInfo("abs")
info.create_system = 3
info.external_attr = (stat.S_IFLNK | 0o777) << 16
z.writestr(info, "/etc")
z.writestr("abs/passwd", "x")
z.close()
"#,
        &[&evil],
    );
    let id = e
        .svc
        .extract_to(&[e.u(&evil)], &e.u(&e.dest), opts())
        .unwrap();
    let s = e.ok(id);
    // Only the good file (and nothing the archive named outside) exists.
    let outside: Vec<String> = ls(&e.root)
        .into_iter()
        .chain(ls(&e.src))
        .filter(|n| {
            n.contains("slip")
                || n.contains("abs-path")
                || n.contains("pwned")
                || n.contains("backslash")
                || n.contains("drive")
        })
        .collect();
    assert!(outside.is_empty(), "{outside:?}");
    assert!(!Path::new("/etc/pwned.txt").exists() && !Path::new("/pwned.txt").exists());
    assert!(!e.root.join("outside/pwned.txt").exists());
    assert_eq!(
        std::fs::read_to_string(e.dest.join("evil/good.txt")).unwrap(),
        "good"
    );
    // What was left out is reported, with reasons.
    assert!(s.details.len() >= 4, "{:?}", s.details);
    assert!(s.details.iter().all(|(_, why)| !why.is_empty()));
    // Nothing anywhere holds the link tricks' content.
    let mut found = Vec::new();
    fn walk(p: &Path, out: &mut Vec<PathBuf>) {
        for e in std::fs::read_dir(p).into_iter().flatten().flatten() {
            let path = e.path();
            if path
                .file_name()
                .is_some_and(|n| n == "pwned.txt" || n == "passwd")
            {
                out.push(path.clone());
            }
            if e.file_type().is_ok_and(|t| t.is_dir()) {
                walk(&path, out);
            }
        }
    }
    walk(&e.root, &mut found);
    // The links were refused, so their names are plain folders inside the
    // extracted folder, and that is the only place such names exist.
    let inside = e.dest.join("evil");
    found.retain(|p| !p.starts_with(&inside));
    assert!(found.is_empty(), "{found:?}");
    for d in ["lnk", "abs"] {
        let m = std::fs::symlink_metadata(inside.join(d)).unwrap();
        assert!(m.is_dir() && !m.is_symlink(), "{d}");
    }
}

#[test]
fn an_archive_bomb_asks_and_stops_when_refused() {
    let e = Env::new("bomb");
    let bomb = e.src.join("bomb.zip");
    // 1 GiB of zeros in one entry: deflated to about 1 MB, a ratio far over
    // the 100:1 the worker asks about once it is past 256 MiB.
    python(
        r#"
import sys, zipfile
with zipfile.ZipFile(sys.argv[1], "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
    with z.open("zeros.bin", "w", force_zip64=True) as f:
        chunk = bytes(1 << 20)
        for _ in range(1024):
            f.write(chunk)
"#,
        &[&bomb],
    );
    let id = e
        .svc
        .extract_to(&[e.u(&bomb)], &e.u(&e.dest), opts())
        .unwrap();
    let s = e.wait(id, "the limit question", |s| {
        s.state == State::WaitingForUser
    });
    assert!(
        matches!(&s.ask, Some(Ask::Limit(t)) if t.contains("Unpack it anyway?")),
        "{:?}",
        s.ask
    );
    assert_eq!(s.ask.as_ref().unwrap().kind(), "limit");
    assert!(e.svc.answer(id, Answer::Limit(false)));
    let s = e.done(id);
    assert_eq!(s.state, State::Failed);
    assert!(
        s.error.contains("larger than the safety limits"),
        "{}",
        s.error
    );
    // Nothing of it stays, hidden or not.
    assert!(ls(&e.dest).is_empty(), "{:?}", ls(&e.dest));
    assert!(
        !ls(&e.src).iter().any(|n| n.starts_with('.')),
        "{:?}",
        ls(&e.src)
    );
}
