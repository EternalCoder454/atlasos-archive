//! The Archive1 D-Bus API against the real app on a private session bus: the
//! app is started by D-Bus activation (never by the test), runs headless
//! (`--service`, offscreen), and every method, the job objects, the old
//! `net.eterneon.atlas` names, errors, Pause/Resume/Cancel, conflicts and
//! hostile archives are tried through zbus.
//!
//! Needs a build with the `dev-worker` feature (the CMake option
//! `-DTELAMON_ARCHIVE_FEATURES=dev-worker`) and, in the environment,
//! `TELAMON_ARCHIVE_APP` (the `telamon-archive` program) and
//! `TELAMON_ARCHIVE_WORKER` (the `telamon-archive-worker` next to it); without
//! them every test says so and passes. `dbus-daemon` must be installed.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{Receiver, channel};
use std::time::{Duration, Instant};

use zbus::MatchRule;
use zbus::blocking::{Connection, MessageIterator, connection::Builder};
use zbus::message::Type;
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};

const NAME: &str = "net.eterneon.telamon.archive";
const ROOT: &str = "/net/eterneon/telamon/archive";
const IFACE: &str = "net.eterneon.telamon.Archive1";
const JOB: &str = "net.eterneon.telamon.Archive1.Job";
const ATLAS_NAME: &str = "net.eterneon.atlas.archive";
const ATLAS_ROOT: &str = "/net/eterneon/atlas/archive";
const ATLAS_IFACE: &str = "net.eterneon.atlas.Archive1";
const ATLAS_JOB: &str = "net.eterneon.atlas.Archive1.Job";

type Opts<'a> = HashMap<&'a str, Value<'a>>;

struct Env {
    root: PathBuf,
    src: PathBuf,
    dest: PathBuf,
    bus: Child,
    conn: Connection,
    app: PathBuf,
    addr: String,
}

macro_rules! env_or_skip {
    ($tag:expr) => {
        match Env::new($tag) {
            Some(e) => e,
            None => {
                eprintln!("skipped: TELAMON_ARCHIVE_APP and TELAMON_ARCHIVE_WORKER are not set");
                return;
            }
        }
    };
}

impl Env {
    fn new(tag: &str) -> Option<Env> {
        let app = PathBuf::from(std::env::var_os("TELAMON_ARCHIVE_APP")?);
        let worker = PathBuf::from(std::env::var_os("TELAMON_ARCHIVE_WORKER")?);
        let base = std::env::var_os("TELAMON_ARCHIVE_TEST_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let root = base.join(format!("telamon-dbus-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let root = root.canonicalize().unwrap();
        let (src, dest) = (root.join("src"), root.join("dest"));
        for d in [
            &src,
            &dest,
            &root.join("home"),
            &root.join("run"),
            &root.join("services"),
        ] {
            std::fs::create_dir_all(d).unwrap();
        }
        std::fs::set_permissions(
            root.join("run"),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        // Activation, as the RPM installs it: the app is started by the bus.
        for name in [NAME, ATLAS_NAME] {
            std::fs::write(
                root.join(format!("services/{name}.service")),
                format!(
                    "[D-BUS Service]\nName={name}\nExec={} --service\n",
                    app.display()
                ),
            )
            .unwrap();
        }
        let conf = format!(
            "<!DOCTYPE busconfig PUBLIC \"-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN\" \"http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd\">\n<busconfig>\n<type>session</type>\n<listen>unix:tmpdir={}</listen>\n<auth>EXTERNAL</auth>\n<servicedir>{}</servicedir>\n<policy context=\"default\"><allow send_destination=\"*\" eavesdrop=\"true\"/><allow eavesdrop=\"true\"/><allow own=\"*\"/></policy>\n</busconfig>\n",
            root.join("run").display(),
            root.join("services").display()
        );
        std::fs::write(root.join("bus.conf"), conf).unwrap();
        let mut bus = Command::new("dbus-daemon")
            .args(["--nofork", "--print-address", "--config-file"])
            .arg(root.join("bus.conf"))
            // Activated programs get the test's own world, not the runner's.
            .env("HOME", root.join("home"))
            .env("XDG_RUNTIME_DIR", root.join("run"))
            .env("XDG_STATE_HOME", root.join("home/state"))
            .env("XDG_DATA_HOME", root.join("home/data"))
            .env("XDG_CONFIG_HOME", root.join("home/config"))
            .env("XDG_CACHE_HOME", root.join("home/cache"))
            .env("QT_QPA_PLATFORM", "offscreen")
            .env("TELAMON_ARCHIVE_WORKER", &worker)
            .env("TELAMON_ARCHIVE_LINGER_MS", "2500")
            .stdout(Stdio::piped())
            .spawn()
            .expect("dbus-daemon");
        let mut addr = String::new();
        {
            use std::io::BufRead;
            let out = bus.stdout.take().unwrap();
            std::io::BufReader::new(out).read_line(&mut addr).unwrap();
        }
        let addr = addr.trim().to_string();
        let conn = Builder::address(addr.as_str())
            .unwrap()
            .build()
            .expect("connect to the private bus");
        Some(Env {
            root,
            src,
            dest,
            bus,
            conn,
            app,
            addr,
        })
    }

    /// Another process of the user on the same bus.
    fn other(&self) -> Connection {
        Builder::address(self.addr.as_str())
            .unwrap()
            .build()
            .expect("a second connection")
    }

    fn u(&self, p: impl AsRef<Path>) -> String {
        let mut out = String::from("file://");
        for &b in p.as_ref().as_os_str().as_encoded_bytes() {
            if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~' | b'/') {
                out.push(b as char);
            } else {
                out.push_str(&format!("%{b:02X}"));
            }
        }
        out
    }

    /// A method of the API on the Telamon or the Atlas names.
    fn call<B>(&self, atlas: bool, method: &str, body: &B) -> zbus::Result<zbus::Message>
    where
        B: serde::Serialize + zbus::zvariant::DynamicType,
    {
        let (name, root, iface) = if atlas {
            (ATLAS_NAME, ATLAS_ROOT, ATLAS_IFACE)
        } else {
            (NAME, ROOT, IFACE)
        };
        self.conn
            .call_method(Some(name), root, Some(iface), method, body)
    }

    /// A call that returns a job: its object path.
    fn job<B>(&self, method: &str, body: &B) -> OwnedObjectPath
    where
        B: serde::Serialize + zbus::zvariant::DynamicType,
    {
        let m = self
            .call(false, method, body)
            .unwrap_or_else(|e| panic!("{method}: {e}"));
        m.body().deserialize().unwrap()
    }

    fn error_name<B>(&self, atlas: bool, method: &str, body: &B) -> (String, String)
    where
        B: serde::Serialize + zbus::zvariant::DynamicType,
    {
        match self.call(atlas, method, body) {
            Err(zbus::Error::MethodError(name, msg, _)) => {
                (name.to_string(), msg.unwrap_or_default())
            }
            other => panic!("{method} should fail, got {other:?}"),
        }
    }

    fn prop<T: TryFrom<OwnedValue>>(&self, path: &str, prop: &str) -> T
    where
        T::Error: std::fmt::Debug,
    {
        let m = self
            .conn
            .call_method(
                Some(NAME),
                path,
                Some("org.freedesktop.DBus.Properties"),
                "Get",
                &(JOB, prop),
            )
            .unwrap_or_else(|e| panic!("Get {prop}: {e}"));
        let v: OwnedValue = m.body().deserialize().unwrap();
        T::try_from(v).unwrap()
    }

    fn state(&self, path: &str) -> String {
        self.prop(path, "State")
    }

    /// Waits until the job's State satisfies `pred`; returns it.
    fn wait_state(&self, path: &str, what: &str, pred: impl Fn(&str) -> bool) -> String {
        let end = Instant::now() + Duration::from_secs(90);
        loop {
            let s = self.state(path);
            if pred(&s) {
                return s;
            }
            assert!(Instant::now() < end, "waiting for {what}: state {s}");
            std::thread::sleep(Duration::from_millis(40));
        }
    }

    fn done(&self, path: &str) -> String {
        self.wait_state(path, "the end", |s| {
            matches!(s, "done" | "failed" | "cancelled")
        })
    }

    fn results(&self, path: &str) -> Vec<String> {
        self.prop(path, "Results")
    }

    /// The `Finished` signals on the bus, from now on.
    fn signals(&self) -> Receiver<(String, String, Vec<String>)> {
        let rule = MatchRule::builder()
            .msg_type(Type::Signal)
            .interface(JOB)
            .unwrap()
            .member("Finished")
            .unwrap()
            .build();
        let it = MessageIterator::for_match_rule(rule, &self.conn, Some(64)).unwrap();
        let (tx, rx) = channel();
        std::thread::spawn(move || {
            for m in it.flatten() {
                let path = m
                    .header()
                    .path()
                    .map(ToString::to_string)
                    .unwrap_or_default();
                if let Ok((state, results)) = m.body().deserialize::<(String, Vec<String>)>() {
                    let _ = tx.send((path, state, results));
                }
            }
        });
        rx
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

    fn app_running(&self) -> bool {
        self.conn
            .call_method(
                Some("org.freedesktop.DBus"),
                "/org/freedesktop/DBus",
                Some("org.freedesktop.DBus"),
                "NameHasOwner",
                &(NAME,),
            )
            .ok()
            .and_then(|m| m.body().deserialize::<bool>().ok())
            .unwrap_or(false)
    }

    fn ls(&self) -> Vec<String> {
        ls(&self.dest)
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        // The app stays up for as long as a window of it is open (offscreen
        // here): it is stopped by hand, then its bus goes.
        let pid = self
            .conn
            .call_method(
                Some("org.freedesktop.DBus"),
                "/org/freedesktop/DBus",
                Some("org.freedesktop.DBus"),
                "GetConnectionUnixProcessID",
                &(NAME,),
            )
            .ok()
            .and_then(|m| m.body().deserialize::<u32>().ok());
        if let Some(pid) = pid {
            let _ = Command::new("kill")
                .args(["-TERM", &pid.to_string()])
                .status();
            std::thread::sleep(Duration::from_millis(300));
        }
        let _ = self.bus.kill();
        let _ = self.bus.wait();
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

fn no_opts() -> Opts<'static> {
    HashMap::new()
}

fn python(script: &str, arg: &Path) {
    let out = Command::new("python3")
        .arg("-I")
        .arg("-c")
        .arg(script)
        .arg(arg)
        .output()
        .expect("python3");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// ---- tests ----

#[test]
fn the_bus_starts_the_app_headless_and_it_leaves_when_idle() {
    let e = env_or_skip!("activate");
    assert!(!e.app_running(), "nothing is running before the first call");
    let a = e.tar_gz(
        "photos.tar.gz",
        &[("photos/a.txt", "a"), ("photos/b.txt", "b")],
    );
    let sig = e.signals();
    let job = e.job("ExtractHere", &(vec![e.u(&a)], no_opts()));
    assert!(
        job.as_str()
            .starts_with("/net/eterneon/telamon/archive/job/"),
        "{job}"
    );
    assert!(e.app_running());
    assert_eq!(e.done(job.as_str()), "done");
    assert_eq!(e.results(job.as_str()), [e.u(e.src.join("photos"))]);
    assert_eq!(
        std::fs::read_to_string(e.src.join("photos/b.txt")).unwrap(),
        "b"
    );
    // The same job, as properties.
    let kind: String = e.prop(job.as_str(), "Kind");
    let title: String = e.prop(job.as_str(), "Title");
    let total: u64 = e.prop(job.as_str(), "TotalBytes");
    let items: u32 = e.prop(job.as_str(), "ProcessedItems");
    assert_eq!(
        (kind.as_str(), title.as_str(), total, items),
        ("extract", "Extracting photos.tar.gz", 2, 3)
    );
    // Finished came once, after the last property, with the same results.
    let (path, state, results) = sig.recv_timeout(Duration::from_secs(10)).unwrap();
    assert_eq!((path.as_str(), state.as_str()), (job.as_str(), "done"));
    assert_eq!(results, e.results(job.as_str()));
    // No window was made: it ran offscreen with nothing to show, and it goes
    // when the job object does (2.5 s here) and a few seconds more.
    let end = Instant::now() + Duration::from_secs(30);
    while e.app_running() {
        assert!(Instant::now() < end, "the app never left");
        std::thread::sleep(Duration::from_millis(200));
    }
    // And it is started again for the next call.
    let job = e.job("Test", &(vec![e.u(&a)], no_opts()));
    assert_eq!(e.done(job.as_str()), "done");
}

#[test]
fn the_old_atlas_names_answer_the_same() {
    let e = env_or_skip!("atlas");
    let a = e.tar_gz("data.tar.gz", &[("x.txt", "x"), ("y.txt", "y")]);
    // The old name alone starts the app too.
    let m = e
        .call(true, "ExtractTo", &(vec![e.u(&a)], e.u(&e.dest), no_opts()))
        .unwrap();
    let job: OwnedObjectPath = m.body().deserialize().unwrap();
    assert_eq!(job.as_str(), "/net/eterneon/atlas/archive/job/1");
    let end = Instant::now() + Duration::from_secs(60);
    loop {
        let m = e
            .conn
            .call_method(
                Some(ATLAS_NAME),
                job.as_str(),
                Some("org.freedesktop.DBus.Properties"),
                "Get",
                &(ATLAS_JOB, "State"),
            )
            .unwrap();
        let v: OwnedValue = m.body().deserialize().unwrap();
        if String::try_from(v).unwrap() == "done" {
            break;
        }
        assert!(Instant::now() < end);
        std::thread::sleep(Duration::from_millis(40));
    }
    assert_eq!(e.ls(), ["data"]);
    // The new name's object for the same job.
    assert_eq!(e.state("/net/eterneon/telamon/archive/job/1"), "done");
    // Errors under the old name.
    let (name, _) = e.error_name(true, "ExtractHere", &(vec!["nope".to_string()], no_opts()));
    assert_eq!(name, "net.eterneon.atlas.Archive1.Error.InvalidArgs");
}

#[test]
fn errors_carry_the_designs_names_and_plain_words() {
    let e = env_or_skip!("errors");
    let a = e.tar_gz("ok.tar.gz", &[("a.txt", "a")]);
    for bad in [
        "",
        "/etc/passwd",
        "relative.zip",
        "https://x/y.zip",
        "file://host/x.zip",
        "file:///a/../b.zip",
        "file:///nope.zip",
        "file:///a%00b",
    ] {
        let (name, msg) = e.error_name(false, "ExtractHere", &(vec![bad.to_string()], no_opts()));
        assert_eq!(
            name, "net.eterneon.telamon.Archive1.Error.InvalidArgs",
            "{bad}"
        );
        assert!(msg.len() > 10 && !msg.contains("0x"), "{bad}: {msg}");
    }
    let one = vec![e.u(&a)];
    let none: Vec<String> = vec![];
    assert_eq!(
        e.error_name(false, "ExtractHere", &(none.clone(), no_opts()))
            .0,
        "net.eterneon.telamon.Archive1.Error.InvalidArgs"
    );
    assert_eq!(
        e.error_name(
            false,
            "ExtractTo",
            &(one.clone(), "file:///nope".to_string(), no_opts())
        )
        .0,
        "net.eterneon.telamon.Archive1.Error.InvalidArgs"
    );
    assert_eq!(
        e.error_name(false, "Compress", &(one.clone(), "rar", "", no_opts()))
            .0,
        "net.eterneon.telamon.Archive1.Error.InvalidArgs"
    );
    assert_eq!(
        e.error_name(false, "Compress", &(none, "zip", "", no_opts()))
            .0,
        "net.eterneon.telamon.Archive1.Error.InvalidArgs"
    );
    assert_eq!(
        e.error_name(
            false,
            "ExtractEntries",
            &(e.u(&a), vec!["junk".to_string()], e.u(&e.dest), no_opts())
        )
        .0,
        "net.eterneon.telamon.Archive1.Error.InvalidArgs"
    );
    assert_eq!(
        e.error_name(false, "Open", &("nope", no_opts())).0,
        "net.eterneon.telamon.Archive1.Error.InvalidArgs"
    );
    // Unknown options are ignored; a wrong-typed one doesn't break the call.
    let mut o = no_opts();
    o.insert("whatever", Value::from(7u32));
    o.insert("show_progress", Value::from(false));
    let job = e.job("Test", &(one, o));
    assert_eq!(e.done(job.as_str()), "done");
    // The job object refuses what it doesn't know.
    let m = e.conn.call_method(
        Some(NAME),
        job.as_str(),
        Some(JOB),
        "AnswerConflict",
        &("overwrite", false),
    );
    assert!(
        matches!(m, Err(zbus::Error::MethodError(n, ..)) if n.as_str() == "net.eterneon.telamon.Archive1.Error.InvalidArgs")
    );
}

#[test]
fn at_most_sixteen_jobs_wait() {
    let e = env_or_skip!("cap");
    let a = e.tar_gz("a.tar.gz", &[("a.txt", "a")]);
    // Dialogs wait for the user, so they pile up.
    let mut jobs = Vec::new();
    for _ in 0..16 {
        jobs.push(e.job("ExtractAll", &(vec![e.u(&a)], no_opts())));
    }
    let (name, msg) = e.error_name(false, "ExtractAll", &(vec![e.u(&a)], no_opts()));
    assert_eq!(name, "net.eterneon.telamon.Archive1.Error.TooManyJobs");
    assert_eq!(msg, "Archive is busy. Try again when a job finishes.");
    let (name, _) = e.error_name(false, "Compress", &(vec![e.u(&a)], "zip", "", no_opts()));
    assert_eq!(name, "net.eterneon.telamon.Archive1.Error.TooManyJobs");
    // Each is a dialog waiting for an answer, and Cancel ends it.
    assert_eq!(e.state(jobs[0].as_str()), "waiting-for-user");
    let q: String = e.prop(jobs[0].as_str(), "Question");
    assert_eq!(q, "dialog");
    let sig = e.signals();
    e.conn
        .call_method(Some(NAME), jobs[0].as_str(), Some(JOB), "Cancel", &())
        .unwrap();
    assert_eq!(e.state(jobs[0].as_str()), "cancelled");
    let (path, state, _) = sig.recv_timeout(Duration::from_secs(10)).unwrap();
    assert_eq!(
        (path.as_str(), state.as_str()),
        (jobs[0].as_str(), "cancelled")
    );
    // Room again.
    e.job("Test", &(vec![e.u(&a)], no_opts()));
}

#[test]
fn compress_makes_archives_and_the_dialog_variants_return_jobs() {
    let e = env_or_skip!("compress");
    std::fs::create_dir_all(e.src.join("Work/sub")).unwrap();
    std::fs::write(e.src.join("Work/a.txt"), "a").unwrap();
    std::fs::write(e.src.join("Work/sub/b.txt"), "b").unwrap();
    std::fs::write(e.src.join("c.txt"), "c").unwrap();
    for (fmt, ext) in [
        ("zip", "zip"),
        ("7z", "7z"),
        ("tar.gz", "tar.gz"),
        ("tar.xz", "tar.xz"),
        ("tar.zst", "tar.zst"),
    ] {
        let job = e.job(
            "Compress",
            &(
                vec![e.u(e.src.join("Work")), e.u(e.src.join("c.txt"))],
                fmt,
                "",
                no_opts(),
            ),
        );
        assert_eq!(e.done(job.as_str()), "done", "{fmt}");
        let want = e.u(e.src.join(format!("Archive.{ext}")));
        assert_eq!(e.results(job.as_str()), [want], "{fmt}");
        let out = Command::new("bsdtar")
            .arg("-tf")
            .arg(e.src.join(format!("Archive.{ext}")))
            .output()
            .unwrap();
        assert!(
            String::from_utf8_lossy(&out.stdout).contains("Work/sub/b.txt"),
            "{fmt}"
        );
    }
    // A destination, and the dialog's name for a single file.
    let job = e.job(
        "Compress",
        &(
            vec![e.u(e.src.join("c.txt"))],
            "zip",
            e.u(e.dest.join("mine.zip")),
            no_opts(),
        ),
    );
    assert_eq!(e.done(job.as_str()), "done");
    assert_eq!(e.ls(), ["mine.zip"]);
    let job = e.job(
        "Compress",
        &(vec![e.u(e.src.join("c.txt"))], "zip", "", no_opts()),
    );
    assert_eq!(e.done(job.as_str()), "done");
    assert!(e.src.join("c.zip").exists());
    // CompressDialog returns the job whose dialog is open; Cancel ends it.
    let job = e.job(
        "CompressDialog",
        &(vec![e.u(e.src.join("c.txt"))], no_opts()),
    );
    assert_eq!(e.state(job.as_str()), "waiting-for-user");
    let kind: String = e.prop(job.as_str(), "Kind");
    assert_eq!(kind, "compress");
    e.conn
        .call_method(Some(NAME), job.as_str(), Some(JOB), "Cancel", &())
        .unwrap();
    assert_eq!(e.done(job.as_str()), "cancelled");
    assert!(e.results(job.as_str()).is_empty());
}

#[test]
fn a_name_clash_waits_for_the_callers_answer() {
    let e = env_or_skip!("clash");
    let a = e.tar_gz("note.tar.gz", &[("note.txt", "new")]);
    std::fs::write(e.src.join("note.txt"), "old").unwrap();
    let job = e.job("ExtractHere", &(vec![e.u(&a)], no_opts()));
    e.wait_state(job.as_str(), "the question", |s| s == "waiting-for-user");
    let q: String = e.prop(job.as_str(), "Question");
    let t: String = e.prop(job.as_str(), "QuestionText");
    assert_eq!(q, "conflict");
    assert!(t.contains("note.txt") && t.contains("already here"), "{t}");
    assert_eq!(
        std::fs::read_to_string(e.src.join("note.txt")).unwrap(),
        "old"
    );
    // A limit answer to a conflict is not taken.
    let m = e
        .conn
        .call_method(Some(NAME), job.as_str(), Some(JOB), "AnswerLimit", &(true,))
        .unwrap();
    assert!(!m.body().deserialize::<bool>().unwrap());
    let m = e
        .conn
        .call_method(
            Some(NAME),
            job.as_str(),
            Some(JOB),
            "AnswerConflict",
            &("keep-both", false),
        )
        .unwrap();
    assert!(m.body().deserialize::<bool>().unwrap());
    assert_eq!(e.done(job.as_str()), "done");
    assert_eq!(e.results(job.as_str()), [e.u(e.src.join("note (2).txt"))]);
    assert_eq!(
        std::fs::read_to_string(e.src.join("note.txt")).unwrap(),
        "old"
    );
}

#[test]
fn the_application_object_is_not_on_the_bus() {
    let e = env_or_skip!("mainapp");
    // Start the app (a call that is answered).
    let a = e.tar_gz("a.tar.gz", &[("a.txt", "a")]);
    let job = e.job("Test", &(vec![e.u(&a)], no_opts()));
    e.done(job.as_str());
    // KDBusService's /MainApplication has quit() and closeAllWindows() for
    // everyone on the bus; it is not served.
    for (iface, method) in [
        ("org.qtproject.Qt.QCoreApplication", "quit"),
        ("org.qtproject.Qt.QApplication", "closeAllWindows"),
    ] {
        let r = e
            .other()
            .call_method(Some(NAME), "/MainApplication", Some(iface), method, &());
        // refused because there is no such object, not because anything else went wrong
        match r {
            Err(zbus::Error::MethodError(name, _, _)) => assert!(
                name.contains("Unknown"),
                "{iface}.{method} failed with {name}"
            ),
            other => panic!("{iface}.{method} should not be there: {other:?}"),
        }
    }
    assert!(e.app_running(), "the app is still there");
    // The program holds the passwords people type: it writes no core file.
    let pid: u32 = e
        .conn
        .call_method(
            Some("org.freedesktop.DBus"),
            "/org/freedesktop/DBus",
            Some("org.freedesktop.DBus"),
            "GetConnectionUnixProcessID",
            &(NAME,),
        )
        .unwrap()
        .body()
        .deserialize()
        .unwrap();
    let limits = std::fs::read_to_string(format!("/proc/{pid}/limits")).unwrap();
    let core = limits
        .lines()
        .find(|l| l.starts_with("Max core file size"))
        .unwrap();
    assert!(core.split_whitespace().rev().nth(2) == Some("0"), "{core}");
}

#[test]
fn only_the_program_that_started_a_job_controls_or_answers_it() {
    let e = env_or_skip!("owner");
    let a = e.tar_gz("note.tar.gz", &[("note.txt", "new")]);
    std::fs::write(e.src.join("note.txt"), "old").unwrap();
    let job = e.job("ExtractHere", &(vec![e.u(&a)], no_opts()));
    e.wait_state(job.as_str(), "the question", |s| s == "waiting-for-user");
    // Another process of the same user answers first: refused, and nothing
    // is replaced.
    let other = e.other();
    let denied = |r: zbus::Result<zbus::Message>| match r {
        Err(zbus::Error::MethodError(name, _, _)) => name.to_string(),
        other => panic!("should have been refused: {other:?}"),
    };
    assert_eq!(
        denied(other.call_method(
            Some(NAME),
            job.as_str(),
            Some(JOB),
            "AnswerConflict",
            &("replace", true)
        )),
        "net.eterneon.telamon.Archive1.Error.AccessDenied"
    );
    assert_eq!(
        denied(other.call_method(Some(NAME), job.as_str(), Some(JOB), "AnswerLimit", &(true,))),
        "net.eterneon.telamon.Archive1.Error.AccessDenied"
    );
    for m in ["Pause", "Resume", "Cancel"] {
        assert_eq!(
            denied(other.call_method(Some(NAME), job.as_str(), Some(JOB), m, &())),
            "net.eterneon.telamon.Archive1.Error.AccessDenied"
        );
    }
    assert_eq!(e.state(job.as_str()), "waiting-for-user");
    assert_eq!(
        std::fs::read_to_string(e.src.join("note.txt")).unwrap(),
        "old"
    );
    // The starter still can.
    let m = e
        .conn
        .call_method(
            Some(NAME),
            job.as_str(),
            Some(JOB),
            "AnswerConflict",
            &("skip", false),
        )
        .unwrap();
    assert!(m.body().deserialize::<bool>().unwrap());
    e.done(job.as_str());
    assert_eq!(
        std::fs::read_to_string(e.src.join("note.txt")).unwrap(),
        "old"
    );
}

fn random_file(path: &Path, mib: usize) {
    let mut data = vec![0u8; mib << 20];
    let mut x = 0x9E37_79B9_7F4A_7C15u64;
    for b in data.iter_mut() {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *b = x as u8;
    }
    std::fs::write(path, data).unwrap();
}

#[test]
fn pause_resume_and_cancel_work_over_the_bus() {
    let e = env_or_skip!("pause");
    random_file(&e.src.join("big.bin"), 40);
    let call = |job: &OwnedObjectPath, m: &str| {
        e.conn
            .call_method(Some(NAME), job.as_str(), Some(JOB), m, &())
            .unwrap();
    };
    // tar.xz at Normal: slow enough to catch.
    let job = e.job(
        "Compress",
        &(
            vec![e.u(e.src.join("big.bin"))],
            "tar.xz",
            e.u(e.dest.join("big.tar.xz")),
            no_opts(),
        ),
    );
    e.wait_state(job.as_str(), "running", |s| s == "running");
    let end = Instant::now() + Duration::from_secs(30);
    while e.prop::<u64>(job.as_str(), "ProcessedBytes") == 0 {
        assert!(Instant::now() < end, "no progress");
        std::thread::sleep(Duration::from_millis(50));
    }
    call(&job, "Pause");
    e.wait_state(job.as_str(), "paused", |s| s == "paused");
    std::thread::sleep(Duration::from_millis(600));
    let at: u64 = e.prop(job.as_str(), "ProcessedBytes");
    std::thread::sleep(Duration::from_millis(1200));
    assert_eq!(
        e.prop::<u64>(job.as_str(), "ProcessedBytes"),
        at,
        "it moved while paused"
    );
    assert_eq!(e.state(job.as_str()), "paused");
    call(&job, "Resume");
    e.wait_state(job.as_str(), "running again", |s| {
        s == "running" || s == "done"
    });
    assert_eq!(e.done(job.as_str()), "done");
    assert!(e.dest.join("big.tar.xz").exists());
    let total: u64 = e.prop(job.as_str(), "TotalBytes");
    assert_eq!(e.prop::<u64>(job.as_str(), "ProcessedBytes"), total);

    // Cancel while it runs: nothing is left.
    std::fs::remove_file(e.dest.join("big.tar.xz")).unwrap();
    let job = e.job(
        "Compress",
        &(
            vec![e.u(e.src.join("big.bin"))],
            "tar.xz",
            e.u(e.dest.join("big.tar.xz")),
            no_opts(),
        ),
    );
    e.wait_state(job.as_str(), "running", |s| s == "running");
    std::thread::sleep(Duration::from_millis(500));
    call(&job, "Cancel");
    assert_eq!(e.done(job.as_str()), "cancelled");
    assert!(e.ls().is_empty(), "{:?}", e.ls());
    assert!(
        !ls(&e.src).iter().any(|n| n.starts_with('.')),
        "{:?}",
        ls(&e.src)
    );
    // Pause and Cancel on a finished job are quiet.
    call(&job, "Pause");
    call(&job, "Cancel");
    // The job object goes after its time (2.5 s here).
    let end = Instant::now() + Duration::from_secs(20);
    loop {
        let r = e.conn.call_method(
            Some(NAME),
            job.as_str(),
            Some("org.freedesktop.DBus.Properties"),
            "Get",
            &(JOB, "State"),
        );
        if r.is_err() {
            break;
        }
        assert!(Instant::now() < end, "the job object stayed");
        std::thread::sleep(Duration::from_millis(200));
    }
}

#[test]
fn property_changes_are_rate_limited_and_end_with_the_last_state() {
    let e = env_or_skip!("rate");
    random_file(&e.src.join("big.bin"), 16);
    let rule = MatchRule::builder()
        .msg_type(Type::Signal)
        .interface("org.freedesktop.DBus.Properties")
        .unwrap()
        .member("PropertiesChanged")
        .unwrap()
        .build();
    let it = MessageIterator::for_match_rule(rule, &e.conn, Some(512)).unwrap();
    let (tx, rx) = channel();
    std::thread::spawn(move || {
        for m in it.flatten() {
            if let Ok((iface, changed, _)) =
                m.body()
                    .deserialize::<(String, HashMap<String, OwnedValue>, Vec<String>)>()
                && iface == JOB
            {
                let _ = tx.send((Instant::now(), changed.keys().cloned().collect::<Vec<_>>()));
            }
        }
    });
    let job = e.job(
        "Compress",
        &(vec![e.u(e.src.join("big.bin"))], "zip", "", no_opts()),
    );
    assert_eq!(e.done(job.as_str()), "done");
    std::thread::sleep(Duration::from_millis(500));
    let seen: Vec<_> = rx.try_iter().collect();
    assert!(!seen.is_empty());
    // Never more than ten in any second.
    for (i, (t, _)) in seen.iter().enumerate() {
        let n = seen[i..]
            .iter()
            .take_while(|(u, _)| u.duration_since(*t) < Duration::from_secs(1))
            .count();
        assert!(n <= 11, "{n} changes in a second");
    }
    // The last change says it is done.
    let last = seen.last().unwrap();
    assert!(last.1.iter().any(|k| k == "State"), "{:?}", last.1);
}

#[test]
fn extract_entries_takes_the_items_a_window_hands_out() {
    use telamon_archive_core::client::{Cancel, NoCallbacks, Worker};
    let e = env_or_skip!("entries");
    let a = e.tar_gz(
        "tree.tar.gz",
        &[
            ("top/a.txt", "a"),
            ("top/sub/b.txt", "b"),
            ("top/c.txt", "c"),
        ],
    );
    let worker = Worker::at(std::env::var_os("TELAMON_ARCHIVE_WORKER").unwrap());
    let l = worker
        .list(&a, None, &mut NoCallbacks, &Cancel::new())
        .unwrap();
    let t = &l.tree;
    let tokens = vec![
        t.token(t.find(["top", "a.txt"]).unwrap()),
        t.token(t.find(["top", "sub"]).unwrap()),
    ];
    let job = e.job(
        "ExtractEntries",
        &(e.u(&a), tokens.clone(), e.u(&e.dest), no_opts()),
    );
    assert_eq!(e.done(job.as_str()), "done");
    assert_eq!(e.ls(), ["a.txt", "sub"]);
    assert_eq!(
        e.results(job.as_str()),
        [e.u(e.dest.join("a.txt")), e.u(e.dest.join("sub"))]
    );
    // A changed archive: the same numbers name other things.
    let b = e.tar_gz("tree2.tar.gz", &[("zzz/q.txt", "q"), ("zzz/r.txt", "r")]);
    let job = e.job(
        "ExtractEntries",
        &(e.u(&b), tokens, e.u(&e.dest), no_opts()),
    );
    assert_eq!(e.done(job.as_str()), "failed");
    let err: String = e.prop(job.as_str(), "Error");
    assert!(err.contains("has changed"), "{err}");
    assert_eq!(e.ls(), ["a.txt", "sub"]);
}

#[test]
fn hostile_archives_stay_inside_through_the_bus() {
    let e = env_or_skip!("hostile");
    let evil = e.src.join("evil.zip");
    python(
        r#"
import sys, zipfile, stat
z = zipfile.ZipFile(sys.argv[1], "w")
z.writestr("../zip-slip.txt", "x")
z.writestr("a/../../zip-slip2.txt", "x")
z.writestr("/abs-path.txt", "x")
z.writestr("..\\backslash.txt", "x")
z.writestr("good.txt", "good")
info = zipfile.ZipInfo("lnk"); info.create_system = 3
info.external_attr = (stat.S_IFLNK | 0o777) << 16
z.writestr(info, "../outside")
z.writestr("lnk/pwned.txt", "x")
info = zipfile.ZipInfo("abs"); info.create_system = 3
info.external_attr = (stat.S_IFLNK | 0o777) << 16
z.writestr(info, "/etc")
z.writestr("abs/passwd", "x")
z.close()
"#,
        &evil,
    );
    let job = e.job("ExtractTo", &(vec![e.u(&evil)], e.u(&e.dest), no_opts()));
    assert_eq!(e.done(job.as_str()), "done");
    assert_eq!(
        std::fs::read_to_string(e.dest.join("evil/good.txt")).unwrap(),
        "good"
    );
    for p in [
        "zip-slip.txt",
        "zip-slip2.txt",
        "abs-path.txt",
        "backslash.txt",
    ] {
        assert!(
            !e.root.join(p).exists() && !e.src.join(p).exists() && !e.dest.join(p).exists(),
            "{p}"
        );
    }
    for d in ["lnk", "abs"] {
        let m = std::fs::symlink_metadata(e.dest.join("evil").join(d)).unwrap();
        assert!(m.is_dir() && !m.is_symlink(), "{d}");
    }
    assert!(!Path::new("/etc/pwned.txt").exists());
    // A bomb asks; the caller can see the question but a limit can only be
    // answered "no" by Cancel.
    let bomb = e.src.join("bomb.zip");
    python(
        r#"
import sys, zipfile
with zipfile.ZipFile(sys.argv[1], "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
    with z.open("zeros.bin", "w", force_zip64=True) as f:
        chunk = bytes(1 << 20)
        for _ in range(1024):
            f.write(chunk)
"#,
        &bomb,
    );
    let job = e.job("ExtractTo", &(vec![e.u(&bomb)], e.u(&e.src), no_opts()));
    e.wait_state(job.as_str(), "the limit", |s| s == "waiting-for-user");
    let q: String = e.prop(job.as_str(), "Question");
    assert_eq!(q, "limit");
    let m = e
        .conn
        .call_method(
            Some(NAME),
            job.as_str(),
            Some(JOB),
            "AnswerLimit",
            &(false,),
        )
        .unwrap();
    assert!(m.body().deserialize::<bool>().unwrap());
    assert_eq!(e.done(job.as_str()), "failed");
    let err: String = e.prop(job.as_str(), "Error");
    assert!(err.contains("larger than the safety limits"), "{err}");
    assert!(!e.src.join("bomb").exists());
}

#[test]
fn a_password_is_never_a_bus_argument() {
    let e = env_or_skip!("password");
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../crates/telamon-archive-engine/tests/data/aes256-secret.zip");
    let a = e.src.join("secret.zip");
    std::fs::copy(fixture, &a).unwrap();
    let job = e.job("ExtractTo", &(vec![e.u(&a)], e.u(&e.dest), no_opts()));
    e.wait_state(job.as_str(), "the question", |s| s == "waiting-for-user");
    let q: String = e.prop(job.as_str(), "Question");
    assert_eq!(q, "password");
    // Nothing on the job object takes one: it has no such method.
    for m in ["AnswerPassword", "Password", "SetPassword"] {
        assert!(
            e.conn
                .call_method(Some(NAME), job.as_str(), Some(JOB), m, &("secret",))
                .is_err()
        );
    }
    // And a conflict answer is not a password answer.
    let r = e
        .conn
        .call_method(
            Some(NAME),
            job.as_str(),
            Some(JOB),
            "AnswerConflict",
            &("keep-both", false),
        )
        .unwrap();
    assert!(!r.body().deserialize::<bool>().unwrap());
    e.conn
        .call_method(Some(NAME), job.as_str(), Some(JOB), "Cancel", &())
        .unwrap();
    assert_eq!(e.done(job.as_str()), "cancelled");
    assert!(e.ls().is_empty());
    let _ = e.app;
}
