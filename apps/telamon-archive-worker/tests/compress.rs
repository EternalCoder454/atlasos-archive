//! Making archives and extracting selected items, through the client and the
//! real, sandboxed worker.

use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use telamon_archive_core::client::{
    Callbacks, Cancel, Clash, ClashAnswer, ClashPolicy, CompressRequest, Error, ExtractRequest,
    Mode, Trash, Worker,
};
use telamon_archive_core::compress::{CompressFormat, Level};
use telamon_archive_core::name::NameEncoding;

const WORKER: &str = env!("CARGO_BIN_EXE_telamon-archive-worker");

struct Scratch {
    root: PathBuf,
    src: PathBuf,
    dest: PathBuf,
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
        let root = base.join(format!("telamon-compress-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let s = Scratch {
            src: root.join("src"),
            dest: root.join("dest"),
            root,
        };
        std::fs::create_dir_all(&s.src).unwrap();
        std::fs::create_dir_all(&s.dest).unwrap();
        s
    }

    fn worker(&self) -> Worker {
        Worker::at(WORKER)
            .with_state_dir(Some(self.root.join("state")))
            .with_trash(Some(Trash::at(self.root.join("trash"))))
    }

    fn files(&self) {
        std::fs::create_dir_all(self.src.join("Work/sub")).unwrap();
        std::fs::write(self.src.join("Work/a.txt"), b"alpha\n").unwrap();
        std::fs::write(self.src.join("Work/sub/b.txt"), b"beta\n").unwrap();
        std::fs::write(self.src.join("note.txt"), b"note\n").unwrap();
        symlink("a.txt", self.src.join("Work/link")).unwrap();
    }

    fn ls(&self) -> Vec<String> {
        ls(&self.dest)
    }
}

impl Drop for Scratch {
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

#[derive(Default)]
struct Rec {
    totals: Vec<(u64, u64)>,
    progress: Vec<(u64, u64)>,
    skipped: Vec<String>,
    clash: Option<ClashAnswer>,
    clashes: Vec<String>,
    cancel_on_total: Option<Cancel>,
    pause_on_progress: Option<Cancel>,
    paused_at: Option<(u64, Instant)>,
}

impl Callbacks for Rec {
    fn total(&mut self, bytes: u64, items: u64) {
        self.totals.push((bytes, items));
        if let Some(c) = &self.cancel_on_total {
            c.cancel();
        }
    }
    fn progress(&mut self, bytes: u64, items: u64) {
        self.progress.push((bytes, items));
        if let Some(c) = self.pause_on_progress.take() {
            c.pause();
            self.paused_at = Some((bytes, Instant::now()));
        }
    }
    fn skipped(&mut self, _: u32, reason: &str) {
        self.skipped.push(reason.to_string());
    }
    fn clash(&mut self, name: &str) -> ClashAnswer {
        self.clashes.push(name.to_string());
        self.clash.expect("no answer for a clash")
    }
}

fn request<'a>(
    sources: &'a [PathBuf],
    dest: &'a Path,
    file_name: &'a str,
    format: CompressFormat,
) -> CompressRequest<'a> {
    CompressRequest {
        sources,
        dest_dir: dest,
        file_name,
        format,
        level: Level::Normal,
        clash: ClashPolicy::Number,
        clash_all: None,
    }
}

fn bsdtar_list(archive: &Path) -> Vec<String> {
    let out = Command::new("bsdtar")
        .env("LC_ALL", "C.UTF-8")
        .arg("-tf")
        .arg(archive)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let mut v: Vec<String> = String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect();
    v.sort();
    v
}

#[test]
fn every_format_through_the_sandbox() {
    let s = Scratch::new("formats");
    s.files();
    let sources = [s.src.join("Work"), s.src.join("note.txt")];
    for fmt in CompressFormat::ALL {
        let name = format!("out{}", fmt.extension());
        let mut rec = Rec::default();
        let got = s
            .worker()
            .compress(
                &request(&sources, &s.dest, &name, fmt),
                &mut rec,
                &Cancel::new(),
            )
            .unwrap_or_else(|e| panic!("{fmt:?}: {e}"));
        assert_eq!(got.path, s.dest.join(&name));
        assert!(!got.left_out && got.skipped.is_empty());
        assert_eq!(rec.totals, [(16, 6)], "{fmt:?}");
        assert_eq!(
            bsdtar_list(&got.path),
            [
                "Work/",
                "Work/a.txt",
                "Work/link",
                "Work/sub/",
                "Work/sub/b.txt",
                "note.txt"
            ],
            "{fmt:?}"
        );
        // Nothing but the archive, no hidden leftovers.
        assert!(
            !ls(&s.dest).iter().any(|n| n.starts_with('.')),
            "{:?}",
            ls(&s.dest)
        );
    }
    assert_eq!(s.ls().len(), 5);
    // The tools that make the formats read them back.
    let ok = Command::new("unzip")
        .arg("-tq")
        .arg(s.dest.join("out.zip"))
        .status()
        .unwrap();
    assert!(ok.success());
    let ok = Command::new("7z")
        .arg("t")
        .arg(s.dest.join("out.7z"))
        .output()
        .unwrap();
    assert!(
        ok.status.success(),
        "{}",
        String::from_utf8_lossy(&ok.stdout)
    );
}

#[test]
fn the_archive_extracts_back_the_same() {
    let s = Scratch::new("roundtrip");
    s.files();
    let sources = [s.src.join("Work")];
    let got = s
        .worker()
        .compress(
            &request(&sources, &s.dest, "Work.zip", CompressFormat::Zip),
            &mut Rec::default(),
            &Cancel::new(),
        )
        .unwrap();
    let out = s.root.join("out");
    std::fs::create_dir(&out).unwrap();
    let r = s
        .worker()
        .extract(
            &ExtractRequest {
                archive: &got.path,
                dest_dir: &out,
                mode: Mode::ExtractTo {
                    name: "Work".into(),
                },
                selection: None,
                encoding: NameEncoding::Utf8,
                raw_name: "Work".into(),
                clash_all: None,
            },
            &mut Rec::default(),
            &Cancel::new(),
        )
        .unwrap();
    assert_eq!(r.path, out.join("Work"));
    assert_eq!(
        std::fs::read(out.join("Work/sub/b.txt")).unwrap(),
        b"beta\n"
    );
    assert_eq!(
        std::fs::read_link(out.join("Work/link")).unwrap(),
        Path::new("a.txt")
    );
}

#[test]
fn a_taken_name_gets_a_number_or_asks() {
    let s = Scratch::new("clash");
    s.files();
    let sources = [s.src.join("note.txt")];
    let make = |s: &Scratch, req: CompressRequest<'_>, rec: &mut Rec| {
        s.worker().compress(&req, rec, &Cancel::new())
    };
    let first = make(
        &s,
        request(&sources, &s.dest, "note.zip", CompressFormat::Zip),
        &mut Rec::default(),
    )
    .unwrap();
    assert_eq!(first.path, s.dest.join("note.zip"));
    // Numbered when the name wasn't chosen.
    let second = make(
        &s,
        request(&sources, &s.dest, "note.zip", CompressFormat::Zip),
        &mut Rec::default(),
    )
    .unwrap();
    assert_eq!(second.path, s.dest.join("note (2).zip"));
    assert_eq!(s.ls(), ["note (2).zip", "note.zip"]);
    // Asked when it was: Keep Both, Skip, Replace.
    let ask = |action| {
        let mut rec = Rec {
            clash: Some(ClashAnswer { action, all: false }),
            ..Rec::default()
        };
        let mut req = request(&sources, &s.dest, "note.zip", CompressFormat::Zip);
        req.clash = ClashPolicy::Ask;
        let r = make(&s, req, &mut rec).unwrap();
        assert_eq!(rec.clashes, ["note.zip"]);
        r
    };
    assert_eq!(ask(Clash::KeepBoth).path, s.dest.join("note (3).zip"));
    let skipped = ask(Clash::Skip);
    assert!(skipped.left_out);
    assert_eq!(s.ls(), ["note (2).zip", "note (3).zip", "note.zip"]);
    let before = std::fs::read(s.dest.join("note.zip")).unwrap();
    std::fs::write(s.dest.join("note.zip"), b"old and precious").unwrap();
    let replaced = ask(Clash::Replace);
    assert_eq!(replaced.path, s.dest.join("note.zip"));
    assert_eq!(
        std::fs::read(s.dest.join("note.zip")).unwrap().len(),
        before.len()
    );
    // The old one is in the Trash, not gone.
    let trashed = ls(&s.root.join("trash/files"));
    assert_eq!(trashed.len(), 1, "{trashed:?}");
    assert_eq!(
        std::fs::read(s.root.join("trash/files").join(&trashed[0])).unwrap(),
        b"old and precious"
    );
}

#[test]
fn a_cancel_leaves_nothing() {
    let s = Scratch::new("cancel");
    s.files();
    let sources = [s.src.join("Work")];
    let cancel = Cancel::new();
    let mut rec = Rec {
        cancel_on_total: Some(cancel.clone()),
        ..Rec::default()
    };
    let e = s
        .worker()
        .compress(
            &request(&sources, &s.dest, "Work.zip", CompressFormat::Zip),
            &mut rec,
            &cancel,
        )
        .unwrap_err();
    assert!(matches!(e, Error::Cancelled), "{e}");
    assert!(s.ls().is_empty(), "{:?}", s.ls());
    assert!(
        !s.root.join("state").exists() || ls(&s.root.join("state/telamon-archive/jobs")).is_empty()
    );
}

#[test]
fn unreadable_and_odd_items_are_left_out_and_reported() {
    let s = Scratch::new("odd");
    s.files();
    let fifo = std::ffi::CString::new(
        s.src
            .join("Work/pipe")
            .into_os_string()
            .into_encoded_bytes(),
    )
    .unwrap();
    // SAFETY: a C string path.
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
    std::fs::write(s.src.join("Work/locked"), b"x").unwrap();
    std::fs::set_permissions(
        s.src.join("Work/locked"),
        std::os::unix::fs::PermissionsExt::from_mode(0),
    )
    .unwrap();
    let sources = [s.src.join("Work")];
    let mut rec = Rec::default();
    let got = s
        .worker()
        .compress(
            &request(&sources, &s.dest, "Work.zip", CompressFormat::Zip),
            &mut rec,
            &Cancel::new(),
        )
        .unwrap();
    // Running as root in some containers reads the locked file anyway.
    let root = unsafe { libc::geteuid() } == 0;
    assert_eq!(
        got.skipped.len(),
        if root { 1 } else { 2 },
        "{:?}",
        got.skipped
    );
    assert!(got.skipped.iter().any(|k| k.reason.contains("pipe")));
    assert!(
        bsdtar_list(&got.path).iter().all(|n| !n.ends_with("pipe")),
        "{:?}",
        bsdtar_list(&got.path)
    );
}

#[test]
fn bad_requests_fail_in_words() {
    let s = Scratch::new("bad");
    s.files();
    let w = s.worker();
    let run = |sources: &[PathBuf], dest: &Path, name: &str| {
        w.compress(
            &request(sources, dest, name, CompressFormat::Zip),
            &mut Rec::default(),
            &Cancel::new(),
        )
        .unwrap_err()
        .to_string()
    };
    let one = [s.src.join("note.txt")];
    assert_eq!(run(&[], &s.dest, "a.zip"), "There is nothing to compress.");
    assert_eq!(
        run(&one, &s.dest, "a/b.zip"),
        "That isn't a name a file can have."
    );
    assert_eq!(
        run(&one, &s.dest, ".."),
        "That isn't a name a file can have."
    );
    assert!(run(&one, &s.root.join("nope"), "a.zip").contains("isn't there"));
    assert!(run(&[s.src.join("missing")], &s.dest, "a.zip").contains("“missing” isn't there"));
    assert!(run(&[PathBuf::from("relative")], &s.dest, "a.zip").contains("full paths"));
    let twice = [s.src.join("note.txt"), s.src.join("Work/../note.txt")];
    assert!(
        run(&twice, &s.dest, "a.zip").contains("same name")
            || run(&twice, &s.dest, "a.zip").contains("Two of the items")
    );
    // A destination others can write to.
    let open = s.root.join("open");
    std::fs::create_dir(&open).unwrap();
    std::fs::set_permissions(&open, std::os::unix::fs::PermissionsExt::from_mode(0o777)).unwrap();
    assert!(run(&one, &open, "a.zip").contains("Pick a folder of your own"));
    assert!(s.ls().is_empty());
}

#[test]
fn a_big_job_pauses_and_goes_on() {
    let s = Scratch::new("pause");
    // Incompressible data, slow to compress at the best xz level.
    let mut data = vec![0u8; 24 << 20];
    let mut x = 0x9E37_79B9_7F4A_7C15u64;
    for b in data.iter_mut() {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *b = x as u8;
    }
    std::fs::write(s.src.join("big.bin"), &data).unwrap();
    let sources = [s.src.join("big.bin")];
    let cancel = Cancel::new();
    let mut rec = Rec {
        pause_on_progress: Some(cancel.clone()),
        ..Rec::default()
    };
    let resumer = {
        let cancel = cancel.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(1500));
            cancel.resume();
        })
    };
    let mut req = request(&sources, &s.dest, "big.tar.xz", CompressFormat::TarXz);
    req.level = Level::Best;
    let started = Instant::now();
    let got = s.worker().compress(&req, &mut rec, &cancel).unwrap();
    resumer.join().unwrap();
    assert!(started.elapsed() >= Duration::from_millis(1500));
    // No progress was reported while it was stopped (give the pipe a moment
    // before the pause took hold).
    let (at, when) = rec.paused_at.unwrap();
    assert!(at < data.len() as u64, "the job was over before it paused");
    assert!(got.path.exists());
    assert_eq!(bsdtar_list(&got.path), ["big.bin"]);
    let _ = when;
}

#[test]
fn selected_items_land_straight_in_the_destination() {
    let s = Scratch::new("items");
    s.files();
    // An archive with a folder holding two files and a folder.
    let sources = [s.src.join("Work")];
    let a = s
        .worker()
        .compress(
            &request(&sources, &s.root, "Work.tar.gz", CompressFormat::TarGz),
            &mut Rec::default(),
            &Cancel::new(),
        )
        .unwrap();
    let listing = s
        .worker()
        .list(&a.path, None, &mut Rec::default(), &Cancel::new())
        .unwrap();
    let t = &listing.tree;
    let a_txt = t.find(["Work", "a.txt"]).unwrap();
    let sub = t.find(["Work", "sub"]).unwrap();
    let b_txt = t.find(["Work", "sub", "b.txt"]).unwrap();
    let selection: Vec<u32> = [a_txt, sub, b_txt]
        .iter()
        .filter_map(|&n| t.nodes[n as usize].entry)
        .collect();
    let run = |mode: Mode, rec: &mut Rec| {
        s.worker().extract(
            &ExtractRequest {
                archive: &a.path,
                dest_dir: &s.dest,
                mode,
                selection: Some(selection.clone()),
                encoding: NameEncoding::Utf8,
                raw_name: "x".into(),
                clash_all: None,
            },
            rec,
            &Cancel::new(),
        )
    };
    let items = || Mode::Items {
        dir: vec!["Work".into()],
        names: vec!["a.txt".into(), "sub".into()],
    };
    let got = run(items(), &mut Rec::default()).unwrap();
    // Not Work/a.txt: the items themselves.
    assert_eq!(s.ls(), ["a.txt", "sub"]);
    assert_eq!(got.paths, [s.dest.join("a.txt"), s.dest.join("sub")]);
    assert_eq!(std::fs::read(s.dest.join("sub/b.txt")).unwrap(), b"beta\n");
    // Again: both names are taken, each asks.
    let mut rec = Rec {
        clash: Some(ClashAnswer {
            action: Clash::KeepBoth,
            all: true,
        }),
        ..Rec::default()
    };
    let got = run(items(), &mut rec).unwrap();
    assert_eq!(
        rec.clashes.len(),
        1,
        "the standing answer covers the second"
    );
    assert_eq!(
        got.paths,
        [s.dest.join("a (2).txt"), s.dest.join("sub (2)")]
    );
    assert_eq!(s.ls(), ["a (2).txt", "a.txt", "sub", "sub (2)"]);
    // Skip all.
    let mut rec = Rec {
        clash: Some(ClashAnswer {
            action: Clash::Skip,
            all: true,
        }),
        ..Rec::default()
    };
    let got = run(items(), &mut rec).unwrap();
    assert!(got.left_out && got.paths.is_empty());
    assert_eq!(s.ls().len(), 4);
    // No hidden leftovers.
    assert!(!s.ls().iter().any(|n| n.starts_with('.')));
}
