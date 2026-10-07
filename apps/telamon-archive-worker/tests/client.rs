//! The client (`core::client`) against the real worker, and against fake
//! workers (shell scripts) that misbehave.

use std::collections::VecDeque;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use telamon_archive_core::client::{
    Callbacks, Cancel, Clash, ClashAnswer, Error, ExtractRequest, Mode, Trash, Worker, clean_stale,
};
use telamon_archive_core::limits::{Exceeded, Kind};
use telamon_archive_core::name::NameEncoding;
use telamon_archive_core::proto::{self, Reply};
use zeroize::Zeroizing;

const WORKER: &str = env!("CARGO_BIN_EXE_telamon-archive-worker");

/// A scratch folder on disk (never tmpfs), removed when dropped.
struct Scratch {
    root: PathBuf,
    dest: PathBuf,
    state: PathBuf,
    trash: PathBuf,
}

impl Scratch {
    fn new(tag: &str) -> Scratch {
        let base = std::env::var_os("TELAMON_ARCHIVE_TEST_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                std::env::current_exe()
                    .unwrap()
                    .parent()
                    .unwrap()
                    .join("../test-scratch")
            });
        let root = base.join(format!("telamon-client-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let s = Scratch {
            dest: root.join("dest"),
            state: root.join("state"),
            trash: root.join("trash"),
            root,
        };
        std::fs::create_dir_all(&s.dest).unwrap();
        s
    }

    /// The real worker, with every per-user place inside the scratch folder.
    fn worker(&self) -> Worker {
        Worker::at(WORKER)
            .with_state_dir(Some(self.state.clone()))
            .with_trash(Some(Trash::at(&self.trash)))
    }

    /// A fake worker: a shell script. `body` runs with `$DIR` set to the
    /// scratch folder and descriptor 4 (staging) open. The timeout is
    /// generous, so a slow shell start on a busy machine can't turn into
    /// "stopped responding"; a test of a hang asks for `short`.
    fn fake(&self, body: &str) -> Worker {
        let path = self.root.join("fake-worker.sh");
        let script = format!(
            "#!/bin/sh\nexport PATH=/usr/bin:/bin\nulimit -c 0\nDIR={}\n{body}\n",
            self.root.display()
        );
        std::fs::write(&path, script).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        Worker::at(&path)
            .with_state_dir(Some(self.state.clone()))
            .with_trash(Some(Trash::at(&self.trash)))
            .with_timeout(Duration::from_secs(10))
    }

    /// A fake worker for a test of a hang, flood or empty batch: the deadline
    /// is what ends the job, so it is short.
    fn short(&self, body: &str) -> Worker {
        self.fake(body).with_timeout(Duration::from_millis(500))
    }

    /// A fake worker for a job that must succeed: a longer timeout still.
    fn fake_ok(&self, body: &str) -> Worker {
        self.fake(body).with_timeout(Duration::from_secs(30))
    }

    /// Writes a reply as the frame a fake worker `cat`s.
    fn frame(&self, file: &str, reply: &Reply) {
        let payload = reply.encode();
        let mut bytes = (payload.len() as u32).to_le_bytes().to_vec();
        bytes.extend_from_slice(&payload);
        std::fs::write(self.root.join(file), bytes).unwrap();
    }

    /// Makes `name` in the scratch folder: a tar.gz of `files` (paths with
    /// their text), whose top-level names are the first path components.
    fn tar(&self, name: &str, files: &[(&str, &str)]) -> PathBuf {
        let src = self.root.join(format!("src-{name}"));
        let mut tops: Vec<String> = Vec::new();
        for (path, text) in files {
            let p = src.join(path);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(&p, text).unwrap();
            let top = path.split('/').next().unwrap().to_string();
            if !tops.contains(&top) {
                tops.push(top);
            }
        }
        let out = self.root.join(name);
        let ok = Command::new("tar")
            .arg("-czf")
            .arg(&out)
            .arg("-C")
            .arg(&src)
            .args(&tops)
            .status()
            .unwrap();
        assert!(ok.success());
        out
    }

    /// What is in the destination, by name.
    fn ls(&self) -> Vec<String> {
        ls(&self.dest)
    }

    fn jobs(&self) -> Vec<String> {
        ls(&self.state.join("telamon-archive/jobs"))
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn ls(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = match std::fs::read_dir(dir) {
        Ok(d) => d
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect(),
        Err(_) => Vec::new(),
    };
    v.sort();
    v
}

/// A front end that answers from a script.
#[derive(Default)]
struct Rec {
    passwords: VecDeque<&'static [u8]>,
    wrong_seen: Vec<bool>,
    clash: Option<ClashAnswer>,
    clashes: Vec<String>,
    progress: u32,
    entries: usize,
    formats: u32,
    cancel_on_progress: Option<Cancel>,
    accept_limits: bool,
    on_clash: Option<Box<dyn FnMut()>>,
}

impl Callbacks for Rec {
    fn progress(&mut self, _: u64, _: u64) {
        self.progress += 1;
        if let Some(c) = &self.cancel_on_progress {
            c.cancel();
        }
    }
    fn format(&mut self, _: &telamon_archive_core::proto::Format) {
        self.formats += 1;
    }
    fn entries(&mut self, batch: &[telamon_archive_core::proto::Entry]) {
        self.entries += batch.len();
    }
    fn password(&mut self, wrong: bool) -> Option<Zeroizing<Vec<u8>>> {
        self.wrong_seen.push(wrong);
        self.passwords
            .pop_front()
            .map(|p| Zeroizing::new(p.to_vec()))
    }
    fn limit(&mut self, _: &Exceeded) -> bool {
        self.accept_limits
    }
    fn clash(&mut self, name: &str) -> ClashAnswer {
        if let Some(hook) = &mut self.on_clash {
            hook();
        }
        self.clashes.push(name.to_string());
        self.clash.expect("no answer for a clash")
    }
}

fn request<'a>(archive: &'a Path, dest: &'a Path, mode: Mode) -> ExtractRequest<'a> {
    ExtractRequest {
        archive,
        dest_dir: dest,
        mode,
        selection: None,
        encoding: NameEncoding::Utf8,
        raw_name: "data".into(),
        clash_all: None,
    }
}

fn to(name: &str) -> Mode {
    Mode::ExtractTo { name: name.into() }
}

fn extract(
    s: &Scratch,
    archive: &Path,
    mode: Mode,
    rec: &mut Rec,
) -> Result<telamon_archive_core::client::Extracted, Error> {
    s.worker()
        .extract(&request(archive, &s.dest, mode), rec, &Cancel::new())
}

fn read(p: impl AsRef<Path>) -> String {
    std::fs::read_to_string(p).unwrap()
}

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../crates/telamon-archive-engine/tests/data")
        .join(name)
}

// ---- the real worker ----

#[test]
fn lists_an_archive() {
    let s = Scratch::new("list");
    let a = s.tar(
        "top.tar.gz",
        &[("top/sub/f.txt", "content"), ("top/g.txt", "g")],
    );
    let mut rec = Rec::default();
    let l = s.worker().list(&a, None, &mut rec, &Cancel::new()).unwrap();
    assert_eq!(l.format.name, "tar.gz");
    assert_eq!(rec.formats, 1);
    assert_eq!(rec.entries, 4);
    let top = l.tree.lone_top.expect("one folder at the top");
    assert_eq!(l.tree.nodes[top as usize].name.disk, "top");
    assert_eq!(l.tree.find(["top", "sub", "f.txt"]).map(|_| ()), Some(()));
    // Nothing is made by listing.
    assert!(s.ls().is_empty() && s.jobs().is_empty());
}

#[test]
fn a_missing_or_wrong_archive_says_so() {
    let s = Scratch::new("nofile");
    let mut rec = Rec::default();
    let e = s
        .worker()
        .list(&s.root.join("none.zip"), None, &mut rec, &Cancel::new())
        .unwrap_err();
    assert_eq!(e.to_string(), "The archive isn't there.");
    let e = s
        .worker()
        .list(&s.root, None, &mut rec, &Cancel::new())
        .unwrap_err();
    assert!(e.to_string().contains("not an archive file"), "{e}");
    let junk = s.root.join("junk.zip");
    std::fs::write(&junk, b"not an archive at all").unwrap();
    let e = s
        .worker()
        .test(&junk, &mut rec, &Cancel::new())
        .unwrap_err();
    assert!(matches!(e, Error::Failed(_)), "{e}");
    let e = Worker::at(s.root.join("nonexistent-worker"))
        .test(&junk, &mut rec, &Cancel::new())
        .unwrap_err();
    assert_eq!(e.to_string(), "The archive reader isn't installed.");
}

#[test]
fn tests_an_archive() {
    let s = Scratch::new("test");
    let a = s.tar("t.tar.gz", &[("a.txt", "a")]);
    s.worker()
        .test(&a, &mut Rec::default(), &Cancel::new())
        .unwrap();
}

#[test]
fn extract_to_collapses_a_lone_folder_of_the_same_name() {
    let s = Scratch::new("collapse");
    let a = s.tar("top.tar.gz", &[("top/sub/f.txt", "content")]);
    let r = extract(&s, &a, to("top"), &mut Rec::default()).unwrap();
    assert_eq!(s.ls(), ["top"]);
    assert_eq!(read(s.dest.join("top/sub/f.txt")), "content");
    assert_eq!(r.path, s.dest.join("top"));
    assert!(!r.left_out && r.removed.is_empty());
    // No hidden leftovers, no record.
    assert!(s.jobs().is_empty());
}

#[test]
fn extract_to_keeps_a_folder_with_another_name_inside() {
    let s = Scratch::new("inside");
    let a = s.tar("top.tar.gz", &[("top/sub/f.txt", "content")]);
    let r = extract(&s, &a, to("other"), &mut Rec::default()).unwrap();
    assert_eq!(s.ls(), ["other"]);
    assert_eq!(read(s.dest.join("other/top/sub/f.txt")), "content");
    assert_eq!(r.path, s.dest.join("other"));
    // The folder is the user's to use: not left at the staging folder's 0700.
    let mode = std::fs::metadata(s.dest.join("other")).unwrap().mode() & 0o777;
    assert_eq!(mode & 0o700, 0o700);
    assert_ne!(mode, 0o700, "the umask-based mode was applied");
}

#[test]
fn a_name_in_use_gets_a_number() {
    let s = Scratch::new("number");
    let a = s.tar("top.tar.gz", &[("top/f.txt", "new")]);
    std::fs::create_dir(s.dest.join("top")).unwrap();
    std::fs::write(s.dest.join("top/old.txt"), "old").unwrap();
    let r = extract(&s, &a, to("top"), &mut Rec::default()).unwrap();
    assert_eq!(s.ls(), ["top", "top (2)"]);
    assert_eq!(r.path, s.dest.join("top (2)"));
    assert_eq!(read(s.dest.join("top (2)/f.txt")), "new");
    assert_eq!(read(s.dest.join("top/old.txt")), "old");
    // And once more, with a staging rename instead of a moved folder.
    let r = extract(&s, &a, to("top (2)"), &mut Rec::default()).unwrap();
    assert_eq!(r.path, s.dest.join("top (2) (2)"));
    let a2 = s.tar("two.tar.gz", &[("a.txt", "a"), ("b.txt", "b")]);
    extract(&s, &a2, to("pair"), &mut Rec::default()).unwrap();
    let r = extract(&s, &a2, to("pair"), &mut Rec::default()).unwrap();
    assert_eq!(r.path, s.dest.join("pair (2)"));
    assert_eq!(read(s.dest.join("pair (2)/b.txt")), "b");
    assert!(s.ls().iter().all(|n| !n.starts_with('.')));
}

#[test]
fn extract_here_moves_a_lone_file_and_a_lone_folder_out() {
    let s = Scratch::new("here1");
    let one = s.tar("one.tar.gz", &[("note.txt", "hello")]);
    let r = extract(&s, &one, Mode::ExtractHere, &mut Rec::default()).unwrap();
    assert_eq!(s.ls(), ["note.txt"]);
    assert_eq!(r.path, s.dest.join("note.txt"));
    let dir = s.tar("proj.tar.gz", &[("proj/src/main.rs", "fn main() {}")]);
    let r = extract(&s, &dir, Mode::ExtractHere, &mut Rec::default()).unwrap();
    assert_eq!(s.ls(), ["note.txt", "proj"]);
    assert_eq!(r.path, s.dest.join("proj"));
    assert_eq!(read(s.dest.join("proj/src/main.rs")), "fn main() {}");
}

#[test]
fn extract_here_puts_many_items_in_a_folder() {
    let s = Scratch::new("here-many");
    let a = s.tar("many.tar.gz", &[("a.txt", "a"), ("b.txt", "b")]);
    let r = extract(&s, &a, Mode::ExtractHere, &mut Rec::default()).unwrap();
    assert_eq!(s.ls(), ["many"]);
    assert_eq!(r.path, s.dest.join("many"));
    assert_eq!(read(s.dest.join("many/a.txt")), "a");
    assert_eq!(read(s.dest.join("many/b.txt")), "b");
}

#[test]
fn a_lone_dot_file_goes_into_a_folder() {
    let s = Scratch::new("dot");
    let a = s.tar("dots.tar.gz", &[(".bashrc", "alias x=y")]);
    let r = extract(&s, &a, Mode::ExtractHere, &mut Rec::default()).unwrap();
    assert_eq!(s.ls(), ["dots"]);
    assert_eq!(r.path, s.dest.join("dots"));
    assert_eq!(read(s.dest.join("dots/.bashrc")), "alias x=y");
}

fn clash_setup(tag: &str) -> (Scratch, PathBuf) {
    let s = Scratch::new(tag);
    let a = s.tar("one.tar.gz", &[("note.txt", "new")]);
    std::fs::write(s.dest.join("note.txt"), "old").unwrap();
    (s, a)
}

fn answer(action: Clash, all: bool) -> Rec {
    Rec {
        clash: Some(ClashAnswer { action, all }),
        ..Rec::default()
    }
}

#[test]
fn clash_skip_leaves_the_old_item_and_nothing_else() {
    let (s, a) = clash_setup("skip");
    let mut rec = answer(Clash::Skip, true);
    let r = extract(&s, &a, Mode::ExtractHere, &mut rec).unwrap();
    assert_eq!(rec.clashes, ["note.txt"]);
    assert!(r.left_out);
    assert_eq!(r.clash_all, Some(Clash::Skip));
    assert_eq!(r.path, s.dest);
    assert_eq!(s.ls(), ["note.txt"]);
    assert_eq!(read(s.dest.join("note.txt")), "old");
    assert!(s.jobs().is_empty());
}

#[test]
fn clash_keep_both_numbers_the_new_item() {
    let (s, a) = clash_setup("keep");
    let mut rec = answer(Clash::KeepBoth, false);
    let r = extract(&s, &a, Mode::ExtractHere, &mut rec).unwrap();
    assert_eq!(s.ls(), ["note (2).txt", "note.txt"]);
    assert_eq!(r.path, s.dest.join("note (2).txt"));
    assert_eq!(r.clash_all, None);
    assert_eq!(read(s.dest.join("note (2).txt")), "new");
    assert_eq!(read(s.dest.join("note.txt")), "old");
    // A standing answer means no question.
    let mut again = Rec::default();
    let mut req = request(&a, &s.dest, Mode::ExtractHere);
    req.clash_all = Some(Clash::KeepBoth);
    let r = s
        .worker()
        .extract(&req, &mut again, &Cancel::new())
        .unwrap();
    assert!(again.clashes.is_empty());
    assert_eq!(r.path, s.dest.join("note (3).txt"));
}

#[test]
fn clash_replace_moves_the_old_item_to_the_trash() {
    let (s, a) = clash_setup("replace");
    let mut rec = answer(Clash::Replace, false);
    let r = extract(&s, &a, Mode::ExtractHere, &mut rec).unwrap();
    assert_eq!(r.path, s.dest.join("note.txt"));
    assert_eq!(read(s.dest.join("note.txt")), "new");
    assert_eq!(s.ls(), ["note.txt"]);
    assert_eq!(read(s.trash.join("files/note.txt")), "old");
    let info = read(s.trash.join("info/note.txt.trashinfo"));
    let lines: Vec<&str> = info.lines().collect();
    assert_eq!(lines[0], "[Trash Info]");
    // The trash records the folder as the kernel knows it: resolved, so a
    // scratch path through `deps/..` reads differently.
    let want = format!("Path={}/note.txt", s.dest.canonicalize().unwrap().display());
    assert_eq!(lines[1], want);
    let date = lines[2].strip_prefix("DeletionDate=").expect(&info);
    assert_eq!(date.len(), 19);
    assert_eq!(&date[10..11], "T");
    // A second Replace: the trash name is numbered, nothing is overwritten.
    let a2 = s.tar("one.tar.gz", &[("note.txt", "newer")]);
    extract(&s, &a2, Mode::ExtractHere, &mut rec).unwrap();
    assert_eq!(read(s.dest.join("note.txt")), "newer");
    assert_eq!(read(s.trash.join("files/note.txt")), "old");
    assert_eq!(read(s.trash.join("files/note (2).txt")), "new");
    assert!(s.trash.join("info/note (2).txt.trashinfo").exists());
}

#[test]
fn replace_without_a_trash_fails_and_deletes_nothing() {
    let (s, a) = clash_setup("notrash");
    let mut rec = answer(Clash::Replace, false);
    let w = s.worker().with_trash(None);
    let e = w
        .extract(
            &request(&a, &s.dest, Mode::ExtractHere),
            &mut rec,
            &Cancel::new(),
        )
        .unwrap_err();
    assert!(e.to_string().contains("not replaced"), "{e}");
    assert_eq!(s.ls(), ["note.txt"]);
    assert_eq!(read(s.dest.join("note.txt")), "old");
}

#[test]
fn cancel_mid_extract_leaves_the_destination_as_it_was() {
    let s = Scratch::new("cancel");
    s.frame("progress.bin", &Reply::Progress { bytes: 1, items: 1 });
    let w = s.fake(
        "echo partial > /proc/self/fd/4/partial.txt\nmkdir /proc/self/fd/4/d\ncat \"$DIR/progress.bin\"\nexec sleep 30",
    );
    let a = s.tar("a.tar.gz", &[("a.txt", "a")]);
    std::fs::write(s.dest.join("keep.txt"), "mine").unwrap();
    let cancel = Cancel::new();
    let mut rec = Rec {
        cancel_on_progress: Some(cancel.clone()),
        ..Rec::default()
    };
    let t = Instant::now();
    let e = w
        .with_timeout(Duration::from_secs(20))
        .extract(&request(&a, &s.dest, Mode::ExtractHere), &mut rec, &cancel)
        .unwrap_err();
    assert!(matches!(e, Error::Cancelled), "{e}");
    assert!(t.elapsed() < Duration::from_secs(10));
    assert_eq!(s.ls(), ["keep.txt"]);
    assert!(s.jobs().is_empty());
}

#[test]
fn cancel_from_another_thread_wakes_a_waiting_job() {
    let s = Scratch::new("cancel2");
    let w = s
        .fake("exec sleep 30")
        .with_timeout(Duration::from_secs(20));
    let a = s.tar("a.tar.gz", &[("a.txt", "a")]);
    let cancel = Cancel::new();
    let c2 = cancel.clone();
    let t = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(200));
        c2.cancel();
    });
    let start = Instant::now();
    let e = w
        .extract(
            &request(&a, &s.dest, Mode::ExtractHere),
            &mut Rec::default(),
            &cancel,
        )
        .unwrap_err();
    t.join().unwrap();
    assert!(matches!(e, Error::Cancelled), "{e}");
    assert!(start.elapsed() < Duration::from_secs(5));
    assert!(s.ls().is_empty());
    // Already cancelled: it doesn't even start.
    let e = w.list(&a, None, &mut Rec::default(), &cancel).unwrap_err();
    assert!(matches!(e, Error::Cancelled));
}

#[test]
fn passwords_are_asked_again_when_wrong() {
    for fixture_name in ["aes256-secret.zip", "zipcrypto-secret.zip"] {
        let s = Scratch::new("password");
        let a = fixture(fixture_name);
        let mut rec = Rec {
            passwords: VecDeque::from([&b"wrong"[..], &b"secret"[..]]),
            ..Rec::default()
        };
        let r = extract(&s, &a, to("out"), &mut rec).unwrap();
        assert_eq!(rec.wrong_seen, [false, true], "{fixture_name}");
        assert_eq!(
            read(r.path.join("f.txt")),
            "secret text\n",
            "{fixture_name}"
        );
        assert_eq!(s.ls(), ["out"]);
        assert!(s.jobs().is_empty());
    }
}

#[test]
fn no_password_given_is_its_own_error() {
    let s = Scratch::new("nopw");
    let a = fixture("aes256-secret.zip");
    let e = extract(&s, &a, to("out"), &mut Rec::default()).unwrap_err();
    assert!(matches!(e, Error::PasswordRequired), "{e}");
    assert!(s.ls().is_empty());
    let e = s
        .worker()
        .test(&a, &mut Rec::default(), &Cancel::new())
        .unwrap_err();
    assert!(matches!(e, Error::PasswordRequired), "{e}");
    // Test with the password.
    let mut rec = Rec {
        passwords: VecDeque::from([&b"secret"[..]]),
        ..Rec::default()
    };
    s.worker().test(&a, &mut rec, &Cancel::new()).unwrap();
}

// ---- fake workers ----

/// Runs `job`, again when the script that was just written was "busy" because
/// a sibling test forked while it was open for writing.
fn retried<T>(mut job: impl FnMut() -> Result<T, Error>) -> Result<T, Error> {
    for _ in 0..5 {
        match job() {
            Err(Error::Failed(m)) if m.contains("couldn't be started") => {
                std::thread::sleep(Duration::from_millis(100));
            }
            r => return r,
        }
    }
    job()
}

fn failing(s: &Scratch, w: &Worker, a: &Path) -> String {
    for _ in 0..5 {
        match w.extract(
            &request(a, &s.dest, Mode::ExtractHere),
            &mut Rec::default(),
            &Cancel::new(),
        ) {
            // A script just written can be "busy" while a sibling test forks.
            Err(Error::Failed(m)) if m.contains("couldn't be started") => {
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => return e.to_string(),
            Ok(_) => panic!("should have failed"),
        }
    }
    panic!("never started");
}

#[test]
fn a_worker_that_hangs_is_killed_after_the_timeout() {
    let s = Scratch::new("hang");
    let a = s.tar("a.tar.gz", &[("a.txt", "a")]);
    let w = s.short("echo $$ > \"$DIR/pid\"\nexec sleep 30");
    let t = Instant::now();
    let m = failing(&s, &w, &a);
    assert_eq!(m, "The archive reader stopped responding.");
    assert!(t.elapsed() < Duration::from_secs(10));
    let pid = read(s.root.join("pid")).trim().to_string();
    assert!(
        !Path::new(&format!("/proc/{pid}")).exists(),
        "the worker is gone"
    );
    assert!(s.ls().is_empty() && s.jobs().is_empty());
}

#[test]
fn a_worker_that_sends_garbage_gives_a_plain_error() {
    let s = Scratch::new("garbage");
    let a = s.tar("a.tar.gz", &[("a.txt", "a")]);
    let w = s.fake("printf 'garbage garbage garbage'; exec sleep 30");
    let m = failing(&s, &w, &a);
    assert!(
        m.starts_with("The archive reader sent something unexpected"),
        "{m}"
    );
    // A well-formed frame with an unknown tag.
    let w = s.fake("printf '\\001\\000\\000\\000\\377'; exec sleep 30");
    let m = failing(&s, &w, &a);
    assert!(
        m.starts_with("The archive reader sent something unexpected"),
        "{m}"
    );
    // A frame that belongs to another job.
    s.frame("listed.bin", &Reply::Listed { entries: 0 });
    let w = s.fake("cat \"$DIR/listed.bin\"; exec sleep 30");
    let m = failing(&s, &w, &a);
    assert_eq!(m, "The archive reader sent something unexpected.");
    assert!(s.ls().is_empty());
}

#[test]
fn a_worker_that_exits_early_is_a_crash() {
    let s = Scratch::new("early");
    let a = s.tar("a.tar.gz", &[("a.txt", "a")]);
    let w = s.fake("exit 3");
    assert_eq!(
        failing(&s, &w, &a),
        "The archive reader stopped unexpectedly."
    );
    // The worker's own refusal to start, and its sandbox's kill.
    let w = s.fake("exit 2");
    assert_eq!(
        failing(&s, &w, &a),
        "The archive reader couldn't be set up safely, so it didn't run."
    );
    let w = s.fake("kill -SYS $$\nsleep 5");
    assert_eq!(
        failing(&s, &w, &a),
        "The archive reader broke one of its safety rules and was stopped."
    );
    let w = s.fake("kill -SEGV $$\nsleep 5");
    assert_eq!(failing(&s, &w, &a), "The archive reader crashed.");
    assert!(s.ls().is_empty() && s.jobs().is_empty());
}

#[test]
fn a_broken_listing_keeps_the_entries_it_read() {
    let s = Scratch::new("broken");
    let a = s.tar("a.tar.gz", &[("a.txt", "a")]);
    let entry = |name: &str| proto::Entry {
        index: 0,
        path: name.as_bytes().to_vec(),
        kind: proto::Kind::File,
        size: Some(1),
        packed: None,
        mtime: None,
        mode: 0o644,
        encrypted: false,
        utf8: true,
        link: None,
    };
    s.frame("e.bin", &Reply::Entries(vec![entry("kept.txt")]));
    s.frame(
        "f.bin",
        &Reply::Failed {
            reason: "The archive is damaged here.".into(),
        },
    );
    let w = s.fake("cat \"$DIR/e.bin\" \"$DIR/f.bin\"; exec sleep 30");
    let mut rec = Rec::default();
    let l = retried_list(&w, &a, &mut rec).unwrap();
    assert_eq!(rec.entries, 1);
    assert_eq!(l.broken.as_deref(), Some("The archive is damaged here."));
    assert_eq!(l.format.name, "unknown");
    assert!(l.tree.find(["kept.txt"]).is_some());
    // Nothing read before the failure: it is a plain error.
    let w = s.fake("cat \"$DIR/f.bin\"; exec sleep 30");
    let e = retried_list(&w, &a, &mut Rec::default()).unwrap_err();
    assert_eq!(e.to_string(), "The archive is damaged here.");
}

fn retried_list(
    w: &Worker,
    a: &Path,
    rec: &mut Rec,
) -> Result<telamon_archive_core::client::Listing, Error> {
    retried(|| w.list(a, None, rec, &Cancel::new()))
}

#[test]
fn a_listing_that_needs_a_password_asks_like_the_other_jobs() {
    let s = Scratch::new("listpw");
    let a = s.tar("a.tar.gz", &[("a.txt", "a")]);
    s.frame("n.bin", &Reply::NeedPassword { wrong: false });
    let w = s.fake("cat \"$DIR/n.bin\"; exec sleep 30");
    let mut rec = Rec {
        passwords: VecDeque::from([&b"pw"[..]]),
        ..Rec::default()
    };
    // The fake asks again every time; the second ask has no password left.
    let e = retried_list(&w, &a, &mut rec).unwrap_err();
    assert!(matches!(e, Error::PasswordRequired), "{e}");
    assert_eq!(rec.wrong_seen, [false, false]);
}

#[test]
fn a_selection_too_big_for_one_request_is_refused_plainly() {
    let s = Scratch::new("bigsel");
    let a = s.tar("a.tar.gz", &[("a.txt", "a")]);
    // Every other index: runs can't squeeze these under one frame.
    let mut req = request(&a, &s.dest, Mode::ExtractHere);
    req.selection = Some((0..400_000u32).map(|i| i * 2).collect());
    let e = s
        .worker()
        .extract(&req, &mut Rec::default(), &Cancel::new())
        .unwrap_err();
    assert_eq!(
        e.to_string(),
        "Too many items are selected to extract at once. Select fewer, or extract everything."
    );
    assert!(s.ls().is_empty() && s.jobs().is_empty());
}

/// A front end that answers every password question with `len` bytes, once.
struct BigPassword {
    len: usize,
    given: bool,
}

impl Callbacks for BigPassword {
    fn password(&mut self, _: bool) -> Option<Zeroizing<Vec<u8>>> {
        if std::mem::replace(&mut self.given, true) {
            return None;
        }
        Some(Zeroizing::new(vec![b'x'; self.len]))
    }
}

#[test]
fn a_password_over_64_kib_is_refused_before_it_is_sent() {
    let s = Scratch::new("bigpw");
    let a = s.tar("a.tar.gz", &[("a.txt", "a")]);
    s.frame("n.bin", &Reply::NeedPassword { wrong: false });
    // The requests are drained, so a 64 KiB password never blocks the pipe.
    let w =
        s.fake("echo x >> \"$DIR/runs\"\ncat <&0 > /dev/null &\ncat \"$DIR/n.bin\"\nexec sleep 30");
    let run = |len: usize| {
        let _ = std::fs::remove_file(s.root.join("runs"));
        let mut cb = BigPassword { len, given: false };
        let e = retried(|| w.test(&a, &mut cb, &Cancel::new())).unwrap_err();
        (e, read(s.root.join("runs")).lines().count())
    };
    let (e, runs) = run(proto::MAX_PASSWORD + 1);
    assert_eq!(e.to_string(), "That password is too long.");
    assert_eq!(runs, 1, "no second worker, so nothing was sent");
    // Exactly the cap goes through: the worker is started again with it.
    let (e, runs) = run(proto::MAX_PASSWORD);
    assert!(matches!(e, Error::PasswordRequired), "{e}");
    assert_eq!(runs, 2);
}

#[test]
fn a_cut_short_frame_is_not_a_hang() {
    let s = Scratch::new("cut");
    let a = s.tar("a.tar.gz", &[("a.txt", "a")]);
    // A length of 100 and four bytes, then the end.
    let w = s.fake("printf 'd\\000\\000\\000abcd'");
    let m = failing(&s, &w, &a);
    assert!(
        m.starts_with("The archive reader sent something unexpected"),
        "{m}"
    );
}

#[test]
fn what_a_compromised_worker_leaves_in_staging_is_fixed_before_the_move() {
    let s = Scratch::new("evil");
    s.frame("done.bin", &Reply::Done { written: vec![] });
    let w = s.fake_ok(
        "echo fine > /proc/self/fd/4/ok.txt\n\
         echo x > /proc/self/fd/4/suid\n\
         chmod 4755 /proc/self/fd/4/suid\n\
         ln -s ../../../../etc/passwd /proc/self/fd/4/escape\n\
         ln -s /etc /proc/self/fd/4/abs\n\
         mkfifo /proc/self/fd/4/fifo\n\
         cat \"$DIR/done.bin\"",
    );
    let a = s.tar("a.tar.gz", &[("a.txt", "a")]);
    let mut result = None;
    for _ in 0..5 {
        match w.extract(
            &request(&a, &s.dest, to("out")),
            &mut Rec::default(),
            &Cancel::new(),
        ) {
            Err(Error::Failed(m)) if m.contains("couldn't be started") => {
                std::thread::sleep(Duration::from_millis(100));
            }
            r => {
                result = Some(r);
                break;
            }
        }
    }
    let r = result.unwrap().unwrap();
    assert_eq!(s.ls(), ["out"]);
    let out = s.dest.join("out");
    assert_eq!(ls(&out), ["ok.txt", "suid"], "links and the fifo are gone");
    assert_eq!(
        std::fs::metadata(out.join("suid")).unwrap().mode() & 0o7000,
        0
    );
    let mut gone: Vec<&str> = r.removed.iter().map(|m| m.path.as_str()).collect();
    gone.sort_unstable();
    assert_eq!(gone, ["abs", "escape", "fifo"], "{:?}", r.removed);
}

// ---- cleaning up after a crash ----

fn dead_pid() -> u32 {
    let mut c = Command::new("true").spawn().unwrap();
    let pid = c.id();
    c.wait().unwrap();
    pid
}

fn record(s: &Scratch, name: &str, pid: u32, start: u64, staging: &str) -> PathBuf {
    let md = std::fs::metadata(&s.dest).unwrap();
    let jobs = s.state.join("telamon-archive/jobs");
    std::fs::create_dir_all(&jobs).unwrap();
    let path = jobs.join(name);
    std::fs::write(
        &path,
        format!(
            "pid={pid}\nstart={start}\ndev={}\nino={}\ndest={}\nstaging={staging}\n",
            md.dev(),
            md.ino(),
            s.dest.display()
        ),
    )
    .unwrap();
    path
}

#[test]
fn clean_stale_removes_a_dead_jobs_staging_and_only_that() {
    let s = Scratch::new("stale");
    let outside = s.root.join("outside");
    std::fs::create_dir(&outside).unwrap();
    std::fs::write(outside.join("precious.txt"), "keep").unwrap();

    let dead = ".a.zip.telamon-partial-0000000000000001";
    let reused = ".b.zip.telamon-partial-0000000000000002";
    let live = ".c.zip.telamon-partial-0000000000000003";
    for n in [dead, reused, live] {
        let d = s.dest.join(n);
        std::fs::create_dir_all(d.join("x/y")).unwrap();
        // The mode every staging folder has until it moves out.
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(d.join("x/y/f"), "f").unwrap();
        // A link to a folder outside, and a locked folder: neither is followed
        // or left behind.
        symlink(&outside, d.join("x/link")).unwrap();
        std::fs::create_dir(d.join("locked")).unwrap();
        std::fs::write(d.join("locked/g"), "g").unwrap();
        std::fs::set_permissions(d.join("locked"), std::fs::Permissions::from_mode(0o0)).unwrap();
    }
    let me = std::process::id();
    record(&s, "1.job", dead_pid(), 5, dead);
    // Our own number, but another start time: a later process got it.
    record(&s, "2.job", me, 1, reused);
    // Alive: our own number and start time (0 means "any").
    let start = std::fs::read_to_string("/proc/self/stat")
        .unwrap()
        .rsplit_once(')')
        .unwrap()
        .1
        .split_whitespace()
        .nth(19)
        .unwrap()
        .parse()
        .unwrap();
    record(&s, "3.job", me, start, live);
    // Garbage, and a record that tries to name a path.
    std::fs::write(s.state.join("telamon-archive/jobs/4.job"), "nonsense").unwrap();
    record(&s, "5.job", dead_pid(), 5, "../outside");

    let c = clean_stale(&s.state).unwrap();
    assert_eq!((c.removed, c.live, c.failed), (2, 1, 0), "{c:?}");
    assert_eq!(s.ls(), [live]);
    assert_eq!(s.jobs(), ["3.job"]);
    assert_eq!(read(outside.join("precious.txt")), "keep");
    assert!(outside.exists());
    // Nothing to do the second time, and no state folder is no error.
    assert_eq!(clean_stale(&s.state).unwrap().removed, 0);
    assert_eq!(clean_stale(&s.root.join("none")).unwrap().removed, 0);
    // Let the scratch folder go: unlock what the test locked.
    std::fs::set_permissions(
        s.dest.join(live).join("locked"),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
}

#[test]
fn a_running_job_has_a_record_that_clean_stale_leaves_alone() {
    let s = Scratch::new("running");
    let w = s
        .fake("exec sleep 30")
        .with_timeout(Duration::from_secs(20));
    let a = s.tar("a.tar.gz", &[("a.txt", "a")]);
    let cancel = Cancel::new();
    let c2 = cancel.clone();
    let dest = s.dest.clone();
    let t = std::thread::spawn(move || {
        w.extract(
            &request(&a, &dest, Mode::ExtractHere),
            &mut Rec::default(),
            &c2,
        )
    });
    let start = Instant::now();
    while s.jobs().is_empty() || s.ls().is_empty() {
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "no record appeared"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    let name = s.ls()[0].clone();
    assert!(name.starts_with(".a.tar.gz.telamon-partial-"), "{name}");
    let c = clean_stale(&s.state).unwrap();
    assert_eq!((c.removed, c.live), (0, 1));
    assert_eq!(s.ls(), [name]);
    let mode = std::fs::metadata(s.dest.join(&s.ls()[0])).unwrap().mode() & 0o777;
    assert_eq!(mode, 0o700);
    let rec_mode = std::fs::metadata(s.state.join("telamon-archive/jobs").join(&s.jobs()[0]))
        .unwrap()
        .mode()
        & 0o777;
    assert_eq!(rec_mode, 0o600);
    cancel.cancel();
    assert!(matches!(t.join().unwrap(), Err(Error::Cancelled)));
    assert!(s.ls().is_empty() && s.jobs().is_empty());
}

#[test]
fn proto_frames_for_fakes_are_well_formed() {
    // The helper's frames are what read_frame expects.
    let mut bytes = Vec::new();
    proto::write_frame(&mut bytes, &Reply::Listed { entries: 0 }.encode()).unwrap();
    assert!(proto::read_frame(&mut &bytes[..]).unwrap().is_some());
}

// ---- the audit round: what the client no longer trusts ----

fn limit_reply(kind: Kind) -> Reply {
    Reply::Limit(Exceeded { kind, limit: 5 })
}

fn start_time() -> u64 {
    std::fs::read_to_string("/proc/self/stat")
        .unwrap()
        .rsplit_once(')')
        .unwrap()
        .1
        .split_whitespace()
        .nth(19)
        .unwrap()
        .parse()
        .unwrap()
}

const SIGPIPE_CHILD: &str = "TELAMON_TEST_SIGPIPE_CHILD";

/// Runs in a child whose SIGPIPE is at its default, as a C++ `main` leaves it
/// (the Rust test harness ignores it, which would hide the bug).
fn sigpipe_scenarios() {
    let s = Scratch::new("sigpipe");
    let a = s.tar("a.tar.gz", &[("a.txt", "a")]);
    // A worker that closes its stdin and then asks a question: the answer is
    // written to a pipe nobody reads.
    s.frame("limit.bin", &limit_reply(Kind::Entries));
    let w = s.fake("exec 0<&-\ncat \"$DIR/limit.bin\"\nexec sleep 30");
    for _ in 0..3 {
        let r = w.extract(
            &request(&a, &s.dest, Mode::ExtractHere),
            &mut Rec::default(),
            &Cancel::new(),
        );
        assert!(r.is_err());
    }
    // A worker that is gone before the first request is written.
    let w = s.fake("exit 0");
    for _ in 0..30 {
        let r = w.test(&a, &mut Rec::default(), &Cancel::new());
        assert!(r.is_err());
    }
    assert!(s.ls().is_empty());
}

#[test]
fn a_closed_request_pipe_cannot_kill_the_client() {
    if std::env::var_os(SIGPIPE_CHILD).is_some() {
        // SAFETY: sets the default disposition, as a C++ main leaves it.
        unsafe { libc::signal(libc::SIGPIPE, libc::SIG_DFL) };
        sigpipe_scenarios();
        return;
    }
    let out = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "a_closed_request_pipe_cannot_kill_the_client",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(SIGPIPE_CHILD, "1")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "the client died: {:?}\n{}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn progress_that_does_not_advance_does_not_extend_the_deadline() {
    let s = Scratch::new("flood");
    let a = s.tar("a.tar.gz", &[("a.txt", "a")]);
    s.frame("p.bin", &Reply::Progress { bytes: 1, items: 1 });
    let w = s.short("while :; do cat \"$DIR/p.bin\" || exit 0; sleep 0.05; done");
    let t = Instant::now();
    let m = failing(&s, &w, &a);
    assert_eq!(m, "The archive reader stopped responding.");
    assert!(t.elapsed() < Duration::from_secs(5), "{:?}", t.elapsed());
    assert!(s.ls().is_empty() && s.jobs().is_empty());
}

#[test]
fn progress_that_goes_backwards_is_a_bad_worker() {
    let s = Scratch::new("back");
    let a = s.tar("a.tar.gz", &[("a.txt", "a")]);
    s.frame("p5.bin", &Reply::Progress { bytes: 5, items: 5 });
    s.frame("p1.bin", &Reply::Progress { bytes: 1, items: 9 });
    let w = s.fake("cat \"$DIR/p5.bin\" \"$DIR/p1.bin\"; exec sleep 30");
    let m = failing(&s, &w, &a);
    assert_eq!(m, "The archive reader sent something unexpected.");
}

#[test]
fn a_limit_of_one_kind_is_asked_once() {
    let s = Scratch::new("twice");
    let a = s.tar("a.tar.gz", &[("a.txt", "a")]);
    s.frame("l.bin", &limit_reply(Kind::Entries));
    let w = s.fake("cat \"$DIR/l.bin\" \"$DIR/l.bin\"; exec sleep 30");
    let mut rec = Rec {
        accept_limits: true,
        ..Rec::default()
    };
    let e = w
        .extract(
            &request(&a, &s.dest, Mode::ExtractHere),
            &mut rec,
            &Cancel::new(),
        )
        .unwrap_err();
    assert_eq!(
        e.to_string(),
        "The archive reader sent something unexpected."
    );
    assert!(s.ls().is_empty());
}

#[test]
fn done_after_a_declined_limit_is_refused() {
    let s = Scratch::new("declined");
    let a = s.tar("a.tar.gz", &[("a.txt", "a")]);
    s.frame("l.bin", &limit_reply(Kind::TotalSize));
    s.frame("done.bin", &Reply::Done { written: vec![] });
    let w = s.fake("cat \"$DIR/l.bin\" \"$DIR/done.bin\"; exec sleep 30");
    let m = failing(&s, &w, &a);
    assert_eq!(m, "The archive reader sent something unexpected.");
    assert!(s.ls().is_empty());
    // The honest way: the limit declined, then Failed.
    s.frame(
        "failed.bin",
        &Reply::Failed {
            reason: "stopped".into(),
        },
    );
    let w = s.fake("cat \"$DIR/l.bin\" \"$DIR/failed.bin\"; exec sleep 30");
    let e = w
        .extract(
            &request(&a, &s.dest, Mode::ExtractHere),
            &mut Rec::default(),
            &Cancel::new(),
        )
        .unwrap_err();
    assert!(matches!(e, Error::LimitRefused(_)), "{e}");
}

#[test]
fn a_test_job_asks_about_limits_too() {
    let s = Scratch::new("testlimit");
    let a = s.tar("a.tar.gz", &[("a.txt", "a")]);
    s.frame("l.bin", &limit_reply(Kind::TotalSize));
    s.frame("done.bin", &Reply::Done { written: vec![] });
    s.frame(
        "failed.bin",
        &Reply::Failed {
            reason: "stopped".into(),
        },
    );
    // Accepted: the test goes on to its end.
    let w = s.fake_ok("cat \"$DIR/l.bin\" \"$DIR/done.bin\"; exec sleep 30");
    let mut rec = Rec {
        accept_limits: true,
        ..Rec::default()
    };
    retried(|| w.test(&a, &mut rec, &Cancel::new())).unwrap();
    // Declined: the worker stops, and the client says why.
    let w = s.fake("cat \"$DIR/l.bin\" \"$DIR/failed.bin\"; exec sleep 30");
    let e = w.test(&a, &mut Rec::default(), &Cancel::new()).unwrap_err();
    assert!(matches!(e, Error::LimitRefused(_)), "{e}");
}

#[test]
fn the_worker_gets_only_its_descriptors_a_clean_cwd_and_no_text_tricks() {
    let s = Scratch::new("hygiene");
    let a = s.tar("a.tar.gz", &[("a.txt", "a")]);
    let marker = s.root.join("marker");
    std::fs::write(&marker, "m").unwrap();
    let c = std::ffi::CString::new(marker.to_str().unwrap()).unwrap();
    // Open without close-on-exec, as careless code would leave it.
    // SAFETY: a C string; the descriptor is closed below.
    // (Moved above 4: sibling tests close descriptors, so a plain open can
    // get a low number.)
    let low = unsafe { libc::open(c.as_ptr(), libc::O_RDONLY) };
    assert!(low >= 0);
    let leaked = unsafe { libc::fcntl(low, libc::F_DUPFD, 20) };
    unsafe { libc::close(low) };
    assert!(leaked > 4);
    s.frame("done.bin", &Reply::Done { written: vec![] });
    let w = s.fake_ok(&format!(
        "pwd > \"$DIR/cwd\"\n[ -e /proc/$$/fd/{leaked} ] && echo leaked > \"$DIR/leak\"\n\
         for f in /proc/$$/fd/*; do case \"$f\" in */0|*/1|*/2|*/3|*/4) ;; *) [ -e \"$f\" ] && echo \"$f\" >> \"$DIR/extra\";; esac; done\n\
         cat \"$DIR/done.bin\""
    ));
    // The script must have run to its end for the checks below to mean anything.
    let r = retried(|| {
        let _ = std::fs::remove_file(s.root.join("extra"));
        w.extract(
            &request(&a, &s.dest, to("out")),
            &mut Rec::default(),
            &Cancel::new(),
        )
    });
    // SAFETY: closes the descriptor opened above.
    unsafe { libc::close(leaked) };
    r.unwrap();
    assert_eq!(read(s.root.join("cwd")).trim(), "/");
    assert!(
        !s.root.join("leak").exists(),
        "an inherited descriptor reached the worker"
    );
    // Only the shell's own script descriptor may be above 4.
    let extra = std::fs::read_to_string(s.root.join("extra")).unwrap_or_default();
    assert!(extra.lines().count() <= 1, "{extra}");
}

#[test]
fn a_worker_that_writes_past_the_approved_size_is_stopped_by_the_client() {
    let s = Scratch::new("size");
    let a = s.tar("a.tar.gz", &[("a.txt", "a")]);
    s.frame("p1.bin", &Reply::Progress { bytes: 1, items: 1 });
    s.frame("p2.bin", &Reply::Progress { bytes: 2, items: 2 });
    // Random data: a compressing file system would otherwise not notice it.
    // The client sees the drive's free space, which other programs change too
    // (on this machine other jobs write and delete big trees at the same
    // time): so the worker keeps writing until it is stopped, up to 1 GB, and
    // a run in which a concurrent deleter hid the growth (the job ended some
    // other way) is tried again, at most three times. The whole test is
    // bounded by that.
    let w = s
        .fake(
            "cat \"$DIR/p1.bin\"\ni=0\nwhile [ $i -lt 12 ]; do\n\
             head -c 80000000 /dev/urandom > /proc/self/fd/4/big$i\n\
             sync -f \"$DIR\"\ncat \"$DIR/p2.bin\"\ni=$((i+1))\ndone\nexec sleep 30",
        )
        .with_size_ceiling(1 << 20)
        // `sync -f` can take long on a busy disk; the check is on the client.
        .with_timeout(Duration::from_secs(40));
    let t = Instant::now();
    let mut last = String::new();
    let mut stopped = false;
    for _ in 0..3 {
        let r = retried(|| {
            w.extract(
                &request(&a, &s.dest, Mode::ExtractHere),
                &mut Rec::default(),
                &Cancel::new(),
            )
        });
        match r {
            Err(e) if e.to_string().contains("more than it said") => {
                stopped = true;
                break;
            }
            Err(e) => last = e.to_string(),
            Ok(_) => last = "the job finished".into(),
        }
        // Nothing of a masked run may stay behind.
        assert!(s.ls().is_empty() && s.jobs().is_empty(), "{:?}", s.ls());
    }
    assert!(stopped, "never stopped by the client: {last}");
    assert!(t.elapsed() < Duration::from_secs(150));
    assert!(s.ls().is_empty() && s.jobs().is_empty());
}

/// The front end for the questions: what it saw while it was asked.
struct Asker {
    grow: PathBuf,
    cancel: Option<Cancel>,
    sizes: Option<(u64, u64)>,
    asked: u32,
}

impl Callbacks for Asker {
    fn limit(&mut self, _: &Exceeded) -> bool {
        self.asked += 1;
        let size = |p: &Path| std::fs::metadata(p).map_or(0, |m| m.len());
        // Time for the stop to land, then a long look.
        std::thread::sleep(Duration::from_millis(300));
        let before = size(&self.grow);
        if let Some(c) = &self.cancel {
            c.cancel();
            return true;
        }
        std::thread::sleep(Duration::from_secs(2));
        self.sizes = Some((before, size(&self.grow)));
        true
    }
}

#[test]
fn the_worker_stands_still_while_the_user_is_asked() {
    let s = Scratch::new("pause");
    let a = s.tar("a.tar.gz", &[("a.txt", "a")]);
    s.frame("l.bin", &limit_reply(Kind::Entries));
    s.frame("done.bin", &Reply::Done { written: vec![] });
    // A writer keeps adding to staging and to a file outside it; the main
    // script waits out the question and then ends the job.
    let w = s.fake_ok(
        "( while :; do printf x >> /proc/self/fd/4/grow; printf x >> \"$DIR/grow\"; sleep 0.02; done ) &\n\
         W=$!\nprintf x >> \"$DIR/grow\"\ncat \"$DIR/l.bin\"\nsleep 4\nkill $W\ncat \"$DIR/done.bin\"",
    );
    let mut asker = Asker {
        grow: s.root.join("grow"),
        cancel: None,
        sizes: None,
        asked: 0,
    };
    retried(|| {
        let _ = std::fs::remove_file(s.root.join("grow"));
        w.extract(&request(&a, &s.dest, to("out")), &mut asker, &Cancel::new())
    })
    .unwrap();
    let (before, after) = asker.sizes.expect("asked");
    assert!(before > 0, "the writer never ran");
    assert_eq!(
        before, after,
        "the worker wrote while the question was open"
    );
    let end = std::fs::metadata(s.root.join("grow")).unwrap().len();
    assert!(end > after, "the worker was never let go on");
}

#[test]
fn a_cancel_during_a_question_kills_the_stopped_worker() {
    let s = Scratch::new("pausecancel");
    let a = s.tar("a.tar.gz", &[("a.txt", "a")]);
    s.frame("l.bin", &limit_reply(Kind::Entries));
    let w = s.fake_ok("echo $$ > \"$DIR/pid\"\ncat \"$DIR/l.bin\"\nexec sleep 60");
    let cancel = Cancel::new();
    let mut asker = Asker {
        grow: s.root.join("grow"),
        cancel: Some(cancel.clone()),
        sizes: None,
        asked: 0,
    };
    let t = Instant::now();
    let e = retried(|| {
        w.extract(
            &request(&a, &s.dest, Mode::ExtractHere),
            &mut asker,
            &cancel,
        )
    })
    .unwrap_err();
    assert!(matches!(e, Error::Cancelled), "{e}");
    assert!(t.elapsed() < Duration::from_secs(10));
    let pid = read(s.root.join("pid")).trim().to_string();
    assert!(
        !Path::new(&format!("/proc/{pid}")).exists(),
        "the stopped worker is gone"
    );
    assert!(s.ls().is_empty() && s.jobs().is_empty());
}

#[test]
fn empty_listing_batches_do_not_extend_the_deadline() {
    let s = Scratch::new("empty");
    let a = s.tar("a.tar.gz", &[("a.txt", "a")]);
    s.frame("e.bin", &Reply::Entries(vec![]));
    let w = s.short("while :; do cat \"$DIR/e.bin\" || exit 0; sleep 0.05; done");
    let t = Instant::now();
    let e = w
        .list(&a, None, &mut Rec::default(), &Cancel::new())
        .unwrap_err();
    assert_eq!(e.to_string(), "The archive reader stopped responding.");
    assert!(t.elapsed() < Duration::from_secs(5), "{:?}", t.elapsed());
}

#[test]
fn every_password_asked_for_is_tried() {
    let s = Scratch::new("pwcap");
    let a = s.tar("a.tar.gz", &[("a.txt", "a")]);
    s.frame("n.bin", &Reply::NeedPassword { wrong: true });
    let w = s.fake_ok("echo x >> \"$DIR/runs\"\ncat \"$DIR/n.bin\"\nexec sleep 30");
    let mut rec = Rec {
        passwords: VecDeque::from([&b"1"[..], b"2", b"3", b"4", b"5", b"6"]),
        ..Rec::default()
    };
    let e = w
        .extract(
            &request(&a, &s.dest, Mode::ExtractHere),
            &mut rec,
            &Cancel::new(),
        )
        .unwrap_err();
    assert_eq!(e.to_string(), "Too many passwords were tried.");
    assert_eq!(rec.wrong_seen.len(), 5, "five asked");
    assert_eq!(rec.passwords.len(), 1, "five taken");
    assert_eq!(
        read(s.root.join("runs")).lines().count(),
        6,
        "one run each, and the first"
    );
    assert!(s.ls().is_empty());
}

/// The state letter of `pid` from /proc, or `None` when it is gone.
fn proc_state(pid: i32) -> Option<char> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    stat.rsplit_once(')')?.1.trim().chars().next()
}

/// Notes who is stopped while the user is asked about a limit.
struct Probe {
    sentinel: i32,
    worker_pid_file: PathBuf,
    asked: bool,
    worker_state: Option<char>,
    sentinel_state: Option<char>,
}

impl Callbacks for Probe {
    fn limit(&mut self, _: &Exceeded) -> bool {
        self.asked = true;
        let worker: i32 = std::fs::read_to_string(&self.worker_pid_file)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        // The stop is delivered at once, but not in the same instant.
        let until = Instant::now() + Duration::from_secs(5);
        while proc_state(worker) != Some('T') && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(10));
        }
        self.worker_state = proc_state(worker);
        // Time for a misdirected signal to land.
        std::thread::sleep(Duration::from_millis(200));
        self.sentinel_state = proc_state(self.sentinel);
        false
    }
}

#[test]
fn a_worker_that_joins_another_group_cannot_stop_or_kill_it() {
    use std::os::unix::process::CommandExt;
    // The fake worker joins the group with a few lines of Python (the shell
    // has no setpgid): without it there is nothing to test.
    if Command::new("python3").arg("--version").output().is_err() {
        eprintln!("skipped: python3 isn't installed");
        return;
    }
    let s = Scratch::new("regroup");
    let a = s.tar("a.tar.gz", &[("a.txt", "a")]);
    // Stands for the client's own group: same session, a group of its own.
    let mut sentinel = Command::new("sleep")
        .arg("30")
        .process_group(0)
        .spawn()
        .unwrap();
    let pgid = sentinel.id() as i32;
    s.frame("limit.bin", &limit_reply(Kind::Entries));
    s.frame(
        "failed.bin",
        &Reply::Failed {
            reason: "stopped".into(),
        },
    );
    // The fake worker isn't sandboxed, so it can do what the filter forbids
    // the real one: join the sentinel's group, then ask a question.
    std::fs::write(
        s.root.join("w.py"),
        format!(
            "import os, sys, time\n\
             d = {dir:?}\n\
             os.setpgid(0, {pgid})\n\
             open(d + '/wpgid', 'w').write(str(os.getpgid(0)))\n\
             open(d + '/wpid', 'w').write(str(os.getpid()))\n\
             os.read(0, 65536)\n\
             sys.stdout.buffer.write(open(d + '/limit.bin', 'rb').read())\n\
             sys.stdout.buffer.flush()\n\
             os.read(0, 65536)\n\
             sys.stdout.buffer.write(open(d + '/failed.bin', 'rb').read())\n\
             sys.stdout.buffer.flush()\n\
             time.sleep(30)\n",
            dir = s.root.to_str().unwrap()
        ),
    )
    .unwrap();
    let w = s.fake_ok("exec python3 \"$DIR/w.py\"");
    let mut probe = Probe {
        sentinel: pgid,
        worker_pid_file: s.root.join("wpid"),
        asked: false,
        worker_state: None,
        sentinel_state: None,
    };
    let r = retried(|| {
        w.extract(
            &request(&a, &s.dest, Mode::ExtractHere),
            &mut probe,
            &Cancel::new(),
        )
    });
    let after = proc_state(pgid);
    let _ = sentinel.kill();
    let _ = sentinel.wait();
    assert!(
        matches!(r, Err(Error::LimitRefused(_))),
        "{:?}",
        r.map(|_| ())
    );
    assert_eq!(read(s.root.join("wpgid")), pgid.to_string(), "it joined");
    assert!(probe.asked);
    assert_eq!(probe.worker_state, Some('T'), "the worker stood still");
    assert!(
        matches!(probe.sentinel_state, Some('S' | 'R')),
        "the sentinel was touched while asked: {:?}",
        probe.sentinel_state
    );
    assert!(
        matches!(after, Some('S' | 'R')),
        "the sentinel was touched at the end: {after:?}"
    );
}

#[test]
fn the_audits_own_words_reach_the_user() {
    let s = Scratch::new("auditwords");
    let a = s.tar("a.tar.gz", &[("a.txt", "a")]);
    s.frame("done.bin", &Reply::Done { written: vec![] });
    let w = s.fake_ok(
        "cd /proc/self/fd/4\ni=0\nwhile [ $i -lt 300 ]; do mkdir d && cd d; i=$((i+1)); done\n\
         cat \"$DIR/done.bin\"",
    );
    let e = retried(|| {
        w.extract(
            &request(&a, &s.dest, Mode::ExtractHere),
            &mut Rec::default(),
            &Cancel::new(),
        )
    })
    .unwrap_err();
    let m = e.to_string();
    assert!(m.contains("nests deeper"), "{m}");
    assert!(s.ls().is_empty() && s.jobs().is_empty());
}

#[test]
fn a_destination_others_can_write_is_refused() {
    let s = Scratch::new("shared");
    let a = s.tar("a.tar.gz", &[("a.txt", "a")]);
    std::fs::set_permissions(&s.dest, std::fs::Permissions::from_mode(0o777)).unwrap();
    let e = extract(&s, &a, Mode::ExtractHere, &mut Rec::default()).unwrap_err();
    assert!(e.to_string().contains("Pick a folder of your own"), "{e}");
    assert!(s.ls().is_empty() && s.jobs().is_empty());
    // Sticky, like /tmp: allowed.
    std::fs::set_permissions(&s.dest, std::fs::Permissions::from_mode(0o1777)).unwrap();
    extract(&s, &a, Mode::ExtractHere, &mut Rec::default()).unwrap();
    assert_eq!(s.ls(), ["a.txt"]);
}

#[test]
fn replace_puts_the_old_item_back_when_the_new_one_cannot_be_moved() {
    let s = Scratch::new("rollback");
    let a = s.tar("one.tar.gz", &[("note.txt", "new")]);
    std::fs::write(s.dest.join("note.txt"), "old").unwrap();
    let dest = s.dest.clone();
    let mut rec = Rec {
        clash: Some(ClashAnswer {
            action: Clash::Replace,
            all: false,
        }),
        // Between the question and the move, the new item vanishes from
        // staging, so the rename after the Trash step fails.
        on_clash: Some(Box::new(move || {
            for e in std::fs::read_dir(&dest).unwrap().flatten() {
                if e.file_name().to_string_lossy().starts_with('.') {
                    std::fs::remove_file(e.path().join("note.txt")).unwrap();
                }
            }
        })),
        ..Rec::default()
    };
    let e = s
        .worker()
        .extract(
            &request(&a, &s.dest, Mode::ExtractHere),
            &mut rec,
            &Cancel::new(),
        )
        .unwrap_err();
    assert!(matches!(e, Error::Failed(_)), "{e}");
    assert_eq!(
        s.ls(),
        ["note.txt"],
        "staging is gone, the old item is back"
    );
    assert_eq!(read(s.dest.join("note.txt")), "old");
    assert!(
        ls(&s.trash.join("files")).is_empty(),
        "nothing is left in the Trash"
    );
    assert!(ls(&s.trash.join("info")).is_empty());
}

fn record_full(
    s: &Scratch,
    name: &str,
    pid: u32,
    start: u64,
    boot: Option<&str>,
    (dev, ino): (u64, u64),
    staging: &str,
) -> PathBuf {
    let jobs = s.state.join("telamon-archive/jobs");
    std::fs::create_dir_all(&jobs).unwrap();
    let path = jobs.join(name);
    let boot = boot.map(|b| format!("boot={b}\n")).unwrap_or_default();
    std::fs::write(
        &path,
        format!(
            "pid={pid}\nstart={start}\n{boot}dev={dev}\nino={ino}\ndest={}\nstaging={staging}\n",
            s.dest.display()
        ),
    )
    .unwrap();
    path
}

fn make_staging(s: &Scratch, name: &str, mode: u32) {
    let d = s.dest.join(name);
    std::fs::create_dir_all(d.join("sub")).unwrap();
    std::fs::write(d.join("sub/f"), "f").unwrap();
    std::fs::set_permissions(&d, std::fs::Permissions::from_mode(mode)).unwrap();
}

const OTHER_BOOT: &str = "00000000-0000-0000-0000-000000000000";

#[test]
fn a_new_boot_or_device_number_still_cleans_up_what_is_proven() {
    let s = Scratch::new("reboot");
    let md = std::fs::metadata(&s.dest).unwrap();
    let me = std::process::id();
    let (dev, ino) = (md.dev(), md.ino());
    let n1 = ".a.zip.telamon-partial-0000000000000011";
    let n2 = ".b.zip.telamon-partial-0000000000000012";
    let n3 = ".c.zip.telamon-partial-0000000000000013";
    let n4 = ".d.zip.telamon-partial-0000000000000014";
    for n in [n1, n2, n3, n4] {
        make_staging(&s, n, 0o700);
    }
    // Another boot: dead whatever the pid says (this very process's own).
    record_full(
        &s,
        "1.job",
        me,
        start_time(),
        Some(OTHER_BOOT),
        (dev, ino),
        n1,
    );
    // The device number changed (btrfs subvolumes across boots), the inode didn't.
    record_full(&s, "2.job", dead_pid(), 5, None, (dev + 7, ino), n2);
    // Same device, another folder now: not ours to touch, and kept.
    record_full(&s, "3.job", dead_pid(), 5, None, (dev, ino + 1), n3);
    // Nothing matches: kept too.
    record_full(&s, "4.job", dead_pid(), 5, None, (dev + 7, ino + 1), n4);
    let c = clean_stale(&s.state).unwrap();
    // A different folder at the path isn't a failure: the record waits (and
    // is dropped after 30 days).
    assert_eq!(
        (c.removed, c.live, c.failed, c.waiting),
        (2, 0, 0, 2),
        "{c:?}"
    );
    assert_eq!(s.ls(), [n3, n4]);
    assert_eq!(
        s.jobs(),
        ["3.job", "4.job"],
        "records that couldn't be proven stay"
    );
}

#[test]
fn a_record_cannot_name_a_folder_that_isnt_a_staging_folder() {
    let s = Scratch::new("notours");
    let md = std::fs::metadata(&s.dest).unwrap();
    let ids = (md.dev(), md.ino());
    // A user's own folder with the tag in its name, made the ordinary way.
    let plain = ".Photos.telamon-partial-0000000000000021";
    let wide = ".Wide.telamon-partial-0000000000000022";
    let tagless = "Documents";
    make_staging(&s, plain, 0o755);
    make_staging(&s, wide, 0o770);
    make_staging(&s, tagless, 0o700);
    record_full(&s, "1.job", dead_pid(), 5, None, ids, plain);
    record_full(&s, "2.job", dead_pid(), 5, None, ids, wide);
    record_full(&s, "3.job", dead_pid(), 5, None, ids, tagless);
    // A record anyone else could have written.
    let n = ".Mine.telamon-partial-0000000000000023";
    make_staging(&s, n, 0o700);
    let path = record_full(&s, "4.job", dead_pid(), 5, None, ids, n);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
    // A job folder anyone could read is narrowed.
    std::fs::set_permissions(
        s.state.join("telamon-archive/jobs"),
        std::fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    let c = clean_stale(&s.state).unwrap();
    assert_eq!((c.removed, c.live, c.failed), (0, 0, 0), "{c:?}");
    assert_eq!(s.ls(), [n, plain, wide, tagless]);
    for d in [plain, wide, tagless, n] {
        assert_eq!(read(s.dest.join(d).join("sub/f")), "f", "{d}");
    }
    // Folders that can't be proven ours wait (and age out); records that
    // are unusable in themselves are dropped.
    assert_eq!(s.jobs(), ["1.job", "2.job"], "{c:?}");
    assert_eq!(c.waiting, 2, "{c:?}");
    let mode = std::fs::metadata(s.state.join("telamon-archive/jobs"))
        .unwrap()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o700);
}

#[test]
fn a_record_with_no_start_time_is_dead_once_a_later_process_has_its_pid() {
    let s = Scratch::new("nostart");
    let md = std::fs::metadata(&s.dest).unwrap();
    let ids = (md.dev(), md.ino());
    let n = ".a.zip.telamon-partial-0000000000000031";
    let m = ".b.zip.telamon-partial-0000000000000032";
    make_staging(&s, n, 0o700);
    make_staging(&s, m, 0o700);
    let me = std::process::id();
    // Written long ago: this process (started minutes ago at most) isn't its job.
    let old = record_full(&s, "1.job", me, 0, None, ids, n);
    let f = std::fs::File::options().write(true).open(&old).unwrap();
    f.set_modified(std::time::SystemTime::now() - Duration::from_secs(30 * 24 * 3600))
        .unwrap();
    // Written just now: it may well be this process.
    record_full(&s, "2.job", me, 0, None, ids, m);
    let c = clean_stale(&s.state).unwrap();
    assert_eq!((c.removed, c.live, c.failed), (1, 1, 0), "{c:?}");
    assert_eq!(s.ls(), [m]);
}
