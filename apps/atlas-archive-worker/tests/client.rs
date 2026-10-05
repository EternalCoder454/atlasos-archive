//! The client (`core::client`) against the real worker, and against fake
//! workers (shell scripts) that misbehave.

use std::collections::VecDeque;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use atlas_archive_core::client::{
    Callbacks, Cancel, Clash, ClashAnswer, Error, ExtractRequest, Mode, Trash, Worker, clean_stale,
};
use atlas_archive_core::name::NameEncoding;
use atlas_archive_core::proto::{self, Reply};
use zeroize::Zeroizing;

const WORKER: &str = env!("CARGO_BIN_EXE_atlas-archive-worker");

/// A scratch folder on disk (never tmpfs), removed when dropped.
struct Scratch {
    root: PathBuf,
    dest: PathBuf,
    state: PathBuf,
    trash: PathBuf,
}

impl Scratch {
    fn new(tag: &str) -> Scratch {
        let base = std::env::var_os("ATLAS_ARCHIVE_TEST_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                std::env::current_exe()
                    .unwrap()
                    .parent()
                    .unwrap()
                    .join("../test-scratch")
            });
        let root = base.join(format!("atlas-client-{tag}-{}", std::process::id()));
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
    /// scratch folder and descriptor 4 (staging) open.
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
            .with_timeout(Duration::from_millis(500))
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
        ls(&self.state.join("atlas-archive/jobs"))
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
}

impl Callbacks for Rec {
    fn progress(&mut self, _: u64, _: u64) {
        self.progress += 1;
        if let Some(c) = &self.cancel_on_progress {
            c.cancel();
        }
    }
    fn format(&mut self, _: &atlas_archive_core::proto::Format) {
        self.formats += 1;
    }
    fn entries(&mut self, batch: &[atlas_archive_core::proto::Entry]) {
        self.entries += batch.len();
    }
    fn password(&mut self, wrong: bool) -> Option<Zeroizing<Vec<u8>>> {
        self.wrong_seen.push(wrong);
        self.passwords
            .pop_front()
            .map(|p| Zeroizing::new(p.to_vec()))
    }
    fn clash(&mut self, name: &str) -> ClashAnswer {
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
) -> Result<atlas_archive_core::client::Extracted, Error> {
    s.worker()
        .extract(&request(archive, &s.dest, mode), rec, &Cancel::new())
}

fn read(p: impl AsRef<Path>) -> String {
    std::fs::read_to_string(p).unwrap()
}

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../crates/atlas-archive-engine/tests/data")
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
    let want = format!("Path={}/note.txt", s.dest.display());
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
    let w = s.fake("echo $$ > \"$DIR/pid\"\nexec sleep 30");
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
        "The archive reader stopped unexpectedly (exit code 3)."
    );
    let w = s.fake("kill -SEGV $$\nsleep 5");
    assert_eq!(
        failing(&s, &w, &a),
        "The archive reader crashed (signal 11)."
    );
    assert!(s.ls().is_empty() && s.jobs().is_empty());
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
    let w = s.fake(
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
    let jobs = s.state.join("atlas-archive/jobs");
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

    let dead = ".a.zip.atlas-partial-0000000000000001";
    let reused = ".b.zip.atlas-partial-0000000000000002";
    let live = ".c.zip.atlas-partial-0000000000000003";
    for n in [dead, reused, live] {
        let d = s.dest.join(n);
        std::fs::create_dir_all(d.join("x/y")).unwrap();
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
    std::fs::write(s.state.join("atlas-archive/jobs/4.job"), "nonsense").unwrap();
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
    assert!(name.starts_with(".a.tar.gz.atlas-partial-"), "{name}");
    let c = clean_stale(&s.state).unwrap();
    assert_eq!((c.removed, c.live), (0, 1));
    assert_eq!(s.ls(), [name]);
    let mode = std::fs::metadata(s.dest.join(&s.ls()[0])).unwrap().mode() & 0o777;
    assert_eq!(mode, 0o700);
    let rec_mode = std::fs::metadata(s.state.join("atlas-archive/jobs").join(&s.jobs()[0]))
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
