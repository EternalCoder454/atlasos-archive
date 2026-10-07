//! The CLI binary against the real worker. Archives are made here (a small
//! zip writer, and `gzip` for the one bomb), or taken from the engine's
//! fixtures. Everything lives under `TELAMON_ARCHIVE_TEST_DIR`, never /tmp.

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const CLI: &str = env!("CARGO_BIN_EXE_telamon-archive-cli");

/// The worker built next to the CLI (`cargo build -p telamon-archive-worker`).
fn worker() -> Option<PathBuf> {
    let w = Path::new(CLI).parent()?.join("telamon-archive-worker");
    w.exists().then_some(w)
}

/// Fails the test, saying why, when the worker isn't built: a silent skip
/// would pass a run that tested nothing.
macro_rules! scratch {
    ($tag:expr) => {{
        match Scratch::new($tag) {
            Some(s) => s,
            None => panic!(
                "build the worker first: cargo build -p telamon-archive-worker \
                 (same target dir as this test)"
            ),
        }
    }};
}

struct Scratch {
    root: PathBuf,
    worker: PathBuf,
}

impl Scratch {
    fn new(tag: &str) -> Option<Scratch> {
        let worker = worker()?;
        let base = std::env::var_os("TELAMON_ARCHIVE_TEST_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| Path::new(CLI).parent().unwrap().join("../test-scratch"));
        let root = base.join(format!("telamon-cli-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        for d in ["state", "data", "cache", "config", "home", "dest"] {
            std::fs::create_dir_all(root.join(d)).unwrap();
        }
        Some(Scratch { root, worker })
    }

    fn path(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }

    fn dest(&self) -> PathBuf {
        self.path("dest")
    }

    fn write(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let p = self.path(name);
        std::fs::write(&p, bytes).unwrap();
        p
    }

    fn fixture(&self, name: &str) -> PathBuf {
        let from = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../crates/telamon-archive-engine/tests/data")
            .join(name);
        let to = self.path(name);
        std::fs::copy(from, &to).unwrap();
        to
    }

    /// Runs the CLI with the real worker, no terminal, and every per-user
    /// place inside the scratch folder. `password` arrives on descriptor 3.
    fn run(&self, args: &[&str], password: Option<&str>) -> Run {
        self.run_os(
            args.iter().map(|a| a.to_string().into()).collect(),
            password,
        )
    }

    fn run_os(&self, args: Vec<std::ffi::OsString>, password: Option<&str>) -> Run {
        self.run_full(args, password, None)
    }

    /// The command with the real worker and every per-user place inside the
    /// scratch folder; no terminal, no display.
    fn base(&self, args: Vec<std::ffi::OsString>) -> Command {
        self.base_with(&self.worker, args)
    }

    /// Like `base`, with another executable as the worker.
    fn base_with(&self, worker: &Path, args: Vec<std::ffi::OsString>) -> Command {
        let mut cmd = Command::new(CLI);
        cmd.arg("--worker")
            .arg(worker)
            .args(args)
            .env("HOME", self.path("home"))
            .env("XDG_STATE_HOME", self.path("state"))
            .env("XDG_DATA_HOME", self.path("data"))
            .env("XDG_CACHE_HOME", self.path("cache"))
            .env("XDG_CONFIG_HOME", self.path("config"))
            .env_remove("DISPLAY")
            .env_remove("WAYLAND_DISPLAY");
        cmd
    }

    fn run_full(
        &self,
        args: Vec<std::ffi::OsString>,
        password: Option<&str>,
        cwd: Option<&Path>,
    ) -> Run {
        let mut cmd = self.base(args);
        cmd.stdin(Stdio::null());
        if let Some(c) = cwd {
            cmd.current_dir(c);
        }
        let mut keep_open = None;
        let mut read_fd = -1;
        if let Some(p) = password {
            let mut fds = [0; 2];
            // SAFETY: pipe2 fills two descriptors.
            assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
            // SAFETY: both are new descriptors we own.
            let (r, w) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
            let line = format!("{p}\n");
            // SAFETY: writes from a live buffer into a pipe with room.
            let n = unsafe { libc::write(w.as_raw_fd(), line.as_ptr().cast(), line.len()) };
            assert_eq!(n as usize, line.len());
            read_fd = r.as_raw_fd();
            keep_open = Some(r);
        }
        // SAFETY: only async-signal-safe calls (setsid, dup2, fcntl).
        unsafe {
            cmd.pre_exec(move || {
                // No controlling terminal: nothing can be prompted.
                libc::setsid();
                if read_fd >= 0 {
                    if read_fd == 3 {
                        libc::fcntl(3, libc::F_SETFD, 0);
                    } else if libc::dup2(read_fd, 3) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                Ok(())
            });
        }
        let out = cmd.output().expect("the CLI starts");
        drop(keep_open);
        Run {
            code: out.status.code().unwrap_or(-1),
            out: out.stdout,
            err: String::from_utf8_lossy(&out.stderr).into_owned(),
        }
    }

    /// What is in `dir`, by name.
    fn ls(&self, dir: &Path) -> Vec<String> {
        let mut v: Vec<String> = match std::fs::read_dir(dir) {
            Ok(d) => d
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .collect(),
            Err(_) => Vec::new(),
        };
        v.sort();
        v
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

struct Run {
    code: i32,
    out: Vec<u8>,
    err: String,
}

impl Run {
    fn text(&self) -> String {
        String::from_utf8(self.out.clone()).expect("stdout is UTF-8")
    }

    /// Nothing that moves a cursor or recolours text reached either stream.
    fn assert_clean(&self) {
        assert!(
            !self.out.contains(&0x1b),
            "ESC on stdout: {:?}",
            self.text()
        );
        assert!(!self.err.contains('\x1b'), "ESC on stderr: {:?}", self.err);
    }

    fn assert_ok(&self) {
        assert_eq!(
            self.code,
            0,
            "stdout: {}\nstderr: {}",
            self.text(),
            self.err
        );
    }
}

// ---- archives ----

fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xEDB8_8320 & (!(crc & 1)).wrapping_add(1));
        }
    }
    !crc
}

struct Z<'a> {
    name: &'a [u8],
    data: &'a [u8],
    /// The name is flagged as UTF-8.
    utf8: bool,
    mode: u32,
}

fn z<'a>(name: &'a str, data: &'a str) -> Z<'a> {
    Z {
        name: name.as_bytes(),
        data: data.as_bytes(),
        utf8: true,
        mode: 0o100644,
    }
}

fn u16le(v: &mut Vec<u8>, n: u16) {
    v.extend_from_slice(&n.to_le_bytes());
}

fn u32le(v: &mut Vec<u8>, n: u32) {
    v.extend_from_slice(&n.to_le_bytes());
}

/// A zip with stored entries, except `deflated`: (raw deflate, crc, size).
fn zip(entries: &[Z<'_>]) -> Vec<u8> {
    zip_with(entries, None)
}

fn zip_with(entries: &[Z<'_>], deflated: Option<(&str, &[u8], u32, u32)>) -> Vec<u8> {
    // 2024-03-05 12:30:00
    let (date, time) = (((2024 - 1980) << 9) | (3 << 5) | 5, (12 << 11) | (30 << 5));
    let mut out = Vec::new();
    let mut central = Vec::new();
    let mut count = 0u16;
    let mut add =
        |name: &[u8], data: &[u8], utf8: bool, mode: u32, method: u16, crc: u32, size: u32| {
            let offset = out.len() as u32;
            let flags: u16 = if utf8 { 0x800 } else { 0 };
            out.extend_from_slice(b"PK\x03\x04");
            u16le(&mut out, 20);
            u16le(&mut out, flags);
            u16le(&mut out, method);
            u16le(&mut out, time);
            u16le(&mut out, date);
            u32le(&mut out, crc);
            u32le(&mut out, data.len() as u32);
            u32le(&mut out, size);
            u16le(&mut out, name.len() as u16);
            u16le(&mut out, 0);
            out.extend_from_slice(name);
            out.extend_from_slice(data);

            central.extend_from_slice(b"PK\x01\x02");
            u16le(&mut central, 0x031e);
            u16le(&mut central, 20);
            u16le(&mut central, flags);
            u16le(&mut central, method);
            u16le(&mut central, time);
            u16le(&mut central, date);
            u32le(&mut central, crc);
            u32le(&mut central, data.len() as u32);
            u32le(&mut central, size);
            u16le(&mut central, name.len() as u16);
            u16le(&mut central, 0);
            u16le(&mut central, 0);
            u16le(&mut central, 0);
            u16le(&mut central, 0);
            let dir = if name.ends_with(b"/") { 0x10 } else { 0 };
            u32le(&mut central, (mode << 16) | dir);
            u32le(&mut central, offset);
            central.extend_from_slice(name);
            count += 1;
        };
    for e in entries {
        let mode = if e.name.ends_with(b"/") {
            0o040755
        } else {
            e.mode
        };
        add(
            e.name,
            e.data,
            e.utf8,
            mode,
            0,
            crc32(e.data),
            e.data.len() as u32,
        );
    }
    if let Some((name, data, crc, size)) = deflated {
        add(name.as_bytes(), data, true, 0o100644, 8, crc, size);
    }
    let start = out.len() as u32;
    out.extend_from_slice(&central);
    out.extend_from_slice(b"PK\x05\x06");
    u16le(&mut out, 0);
    u16le(&mut out, 0);
    u16le(&mut out, count);
    u16le(&mut out, count);
    u32le(&mut out, central.len() as u32);
    u32le(&mut out, start);
    u16le(&mut out, 0);
    out
}

/// The zip most tests use.
fn sample(s: &Scratch, name: &str) -> PathBuf {
    let bytes = zip(&[
        z("docs/", ""),
        z("docs/a.txt", "alpha\n"),
        z("docs/sub/b.txt", "beta\n"),
        z("top.txt", "top\n"),
        Z {
            name: b"caf\x82.txt",
            data: b"cafe\n",
            utf8: false,
            mode: 0o100644,
        },
        z("x\x1b[31m.txt", "esc\n"),
        z("../evil.txt", "evil\n"),
        Z {
            mode: 0o120777,
            ..z("link", "top.txt")
        },
    ]);
    s.write(name, &bytes)
}

/// Parses every stdout line of a `--json` run: each must be one JSON object.
fn json_lines(r: &Run) -> Vec<serde_json::Value> {
    let t = r.text();
    assert!(!t.is_empty(), "no output; stderr: {}", r.err);
    t.lines()
        .enumerate()
        .map(|(i, l)| {
            let v: serde_json::Value = serde_json::from_str(l)
                .unwrap_or_else(|e| panic!("line {i} isn't JSON ({e}): {l:?}"));
            assert!(v.is_object(), "line {i} isn't an object: {l:?}");
            v
        })
        .collect()
}

fn read(p: impl AsRef<Path>) -> String {
    std::fs::read_to_string(p.as_ref()).unwrap_or_else(|e| panic!("{}: {e}", p.as_ref().display()))
}

// ---- list ----

#[test]
fn list_shows_a_table_in_display_form() {
    let s = scratch!("list");
    let a = sample(&s, "sample.zip");
    let r = s.run(&["list", "--encoding", "cp437", a.to_str().unwrap()], None);
    r.assert_ok();
    r.assert_clean();
    let t = r.text();
    assert!(t.starts_with("T "), "{t}");
    for want in [
        "d",
        "docs/",
        "docs/a.txt",
        "docs/sub/b.txt",
        "top.txt",
        "café.txt",
        // The control characters of a name are shown, never sent.
        "x\\x1B[31m.txt",
        "link -> top.txt",
        "2024-03-",
    ] {
        assert!(t.contains(want), "missing {want:?} in:\n{t}");
    }
    // The escaping path is refused, with its reason on the next line.
    let evil = t.lines().position(|l| l.contains("../evil.txt")).expect(&t);
    let lines: Vec<&str> = t.lines().collect();
    assert!(lines[evil].contains('!'), "{}", lines[evil]);
    assert!(lines[evil + 1].trim_start().starts_with("! "), "{t}");
    assert!(t.lines().last().unwrap().contains("refused"), "{t}");
}

#[test]
fn list_json_is_one_object_per_line_with_a_summary() {
    let s = scratch!("listjson");
    let a = sample(&s, "sample.zip");
    let r = s.run(
        &["list", "--json", "--encoding", "cp437", a.to_str().unwrap()],
        None,
    );
    r.assert_ok();
    r.assert_clean();
    let t = r.text();
    let lines: Vec<&str> = t.lines().collect();
    for l in &lines {
        assert!(l.starts_with('{') && l.ends_with('}'), "{l}");
        assert!(l.chars().all(|c| !c.is_control()), "raw control in {l:?}");
    }
    let find = |needle: &str| {
        *lines
            .iter()
            .find(|l| l.contains(needle))
            .unwrap_or_else(|| panic!("no line with {needle}:\n{t}"))
    };
    let a_txt = find("\"path\":\"docs/a.txt\"");
    for want in [
        "\"display\":\"docs/a.txt\"",
        "\"kind\":\"file\"",
        "\"size\":6",
        "\"encrypted\":false",
        "\"link\":null",
        "\"refused\":null",
    ] {
        assert!(a_txt.contains(want), "{a_txt}");
    }
    assert!(!a_txt.contains("raw_hex"), "{a_txt}");
    assert!(find("\"path\":\"docs\",").contains("\"kind\":\"dir\""));
    // A name that isn't UTF-8 carries its bytes as hex.
    let cafe = find("raw_hex");
    assert!(cafe.contains("\"raw_hex\":\"636166822e747874\""), "{cafe}");
    assert!(cafe.contains("\"path\":\"café.txt\""), "{cafe}");
    // Controls are escaped in the path and shown as text in the display.
    let esc = find("\\u001b[31m.txt");
    assert!(esc.contains("\"display\":\"x\\\\x1B[31m.txt\""), "{esc}");
    assert!(find("\"kind\":\"symlink\"").contains("\"link\":\"top.txt\""));
    assert!(find("\"refused\":\"").contains("evil"), "{t}");
    let last = lines.last().unwrap();
    assert!(last.starts_with("{\"summary\":{"), "{last}");
    assert!(last.contains("\"format\":\"zip\""), "{last}");
    // Every line really parses, and says what the text checks above say.
    let v = json_lines(&r);
    assert_eq!(v.len(), lines.len());
    let (summary, entries) = v.split_last().unwrap();
    assert_eq!(summary["summary"]["format"], "zip");
    assert!(entries.iter().all(|e| e.get("summary").is_none()));
    let a_txt = entries.iter().find(|e| e["path"] == "docs/a.txt").unwrap();
    assert_eq!(a_txt["size"], 6);
    assert_eq!(a_txt["kind"], "file");
    let cafe = entries.iter().find(|e| e.get("raw_hex").is_some()).unwrap();
    assert_eq!(cafe["path"], "café.txt");
    let esc = entries
        .iter()
        .find(|e| e["display"] == "x\\x1B[31m.txt")
        .unwrap();
    assert_eq!(esc["path"], "x\u{1b}[31m.txt");
}

#[test]
fn list_of_an_encrypted_zip_names_it_encrypted() {
    let s = scratch!("listaes");
    let a = s.fixture("aes256-secret.zip");
    let r = s.run(&["list", "--json", a.to_str().unwrap()], None);
    r.assert_ok();
    let t = r.text();
    assert!(t.contains("\"path\":\"f.txt\""), "{t}");
    assert!(t.contains("\"encrypted\":true"), "{t}");
    let v = json_lines(&r);
    assert!(
        v.iter()
            .any(|e| e["path"] == "f.txt" && e["encrypted"] == true)
    );
}

// ---- info ----

#[test]
fn info_describes_the_archive() {
    let s = scratch!("info");
    let a = sample(&s, "sample.zip");
    let r = s.run(&["info", a.to_str().unwrap()], None);
    r.assert_ok();
    let t = r.text();
    for want in [
        "Format:     zip",
        "Encrypted:  no",
        "Volumes:    1",
        "Items:",
    ] {
        assert!(t.contains(want), "{t}");
    }
    let r = s.run(&["info", "--json", a.to_str().unwrap()], None);
    r.assert_ok();
    let t = r.text();
    assert_eq!(t.lines().count(), 1, "{t}");
    for want in [
        "\"format\":\"zip\"",
        "\"entries\":8",
        "\"encrypted\":false",
        "\"volumes\":1",
        "\"comment\":null",
    ] {
        assert!(t.contains(want), "{t}");
    }
    let v = json_lines(&r);
    assert_eq!(v.len(), 1);
    assert_eq!(v[0]["format"], "zip");
    assert_eq!(v[0]["entries"], 8);
    assert_eq!(v[0]["comment"], serde_json::Value::Null);
    let aes = s.fixture("aes256-secret.zip");
    let r = s.run(&["info", aes.to_str().unwrap()], None);
    r.assert_ok();
    assert!(r.text().contains("Encrypted:  yes"), "{}", r.text());
}

// ---- test ----

#[test]
fn test_passes_a_good_archive() {
    let s = scratch!("test");
    let a = sample(&s, "sample.zip");
    let r = s.run(&["test", a.to_str().unwrap()], None);
    r.assert_ok();
    assert!(r.text().contains("No errors found."), "{}", r.text());
    let r = s.run(&["test", "--json", a.to_str().unwrap()], None);
    r.assert_ok();
    assert!(
        r.text().contains("{\"summary\":{\"ok\":true"),
        "{}",
        r.text()
    );
    let v = json_lines(&r);
    assert_eq!(v.last().unwrap()["summary"]["ok"], true);
}

#[test]
fn test_fails_a_corrupt_archive() {
    let s = scratch!("testbad");
    let mut bytes = std::fs::read(sample(&s, "sample.zip")).unwrap();
    // Flip a data byte inside the first stored file: the CRC no longer fits.
    let at = bytes.windows(6).position(|w| w == b"alpha\n").unwrap();
    bytes[at] ^= 0xff;
    let a = s.write("bad.zip", &bytes);
    let r = s.run(&["test", a.to_str().unwrap()], None);
    assert_eq!(r.code, 1, "{}\n{}", r.text(), r.err);
    assert!(r.err.contains("Left out item"), "{}", r.err);
    assert!(r.err.contains("has errors"), "{}", r.err);
    assert!(!r.text().contains("No errors"), "{}", r.text());
    r.assert_clean();
    let r = s.run(&["test", "--json", a.to_str().unwrap()], None);
    assert_eq!(r.code, 1);
    assert!(r.text().contains("{\"skipped\":{"), "{}", r.text());
    assert!(r.text().contains("\"ok\":false"), "{}", r.text());
    let v = json_lines(&r);
    assert!(v.iter().any(|e| e.get("skipped").is_some()));
    assert_eq!(v.last().unwrap()["summary"]["ok"], false);
}

#[test]
fn passwords_come_from_a_descriptor() {
    let s = scratch!("pw");
    let a = s.fixture("aes256-secret.zip");
    let a = a.to_str().unwrap();
    let r = s.run(&["test", "--password-fd", "3", a], Some("secret"));
    r.assert_ok();
    // None given and no terminal.
    let r = s.run(&["test", a], None);
    assert_eq!(r.code, 3, "{}", r.err);
    assert_eq!(
        r.err.trim(),
        "telamon-archive-cli: This archive needs a password: run in a terminal or use --password-fd."
    );
    // A wrong one.
    let r = s.run(&["test", "--password-fd", "3", a], Some("wrong"));
    assert_eq!(r.code, 3, "{}", r.err);
    assert!(r.err.contains("didn't work"), "{}", r.err);
    assert!(!r.err.contains("wrong") || r.err.contains("didn't work"));
    // A descriptor that isn't open is a usage mistake.
    let r = s.run(&["test", "--password-fd", "77", a], None);
    assert_eq!(r.code, 2, "{}", r.err);
}

#[test]
fn a_password_is_never_logged() {
    let s = scratch!("pwlog");
    let a = s.fixture("zipcrypto-secret.zip");
    let r = s.run(
        &["-v", "test", "--password-fd", "3", a.to_str().unwrap()],
        Some("secret"),
    );
    r.assert_ok();
    // (The archive's own name has "secret" in it.)
    assert!(
        !r.err.replace("zipcrypto-secret.zip", "").contains("secret"),
        "{}",
        r.err
    );
    assert!(!r.text().contains("secret"));
    let r = s.run(
        &["-v", "test", "--password-fd", "3", a.to_str().unwrap()],
        Some("hunter2"),
    );
    assert_eq!(r.code, 3);
    assert!(!r.err.contains("hunter2"), "{}", r.err);
}

// ---- extract ----

#[test]
fn extract_goes_to_a_folder_named_like_the_archive() {
    let s = scratch!("extract");
    let a = sample(&s, "sample.zip");
    let r = s.run(&["extract", a.to_str().unwrap()], None);
    r.assert_ok();
    r.assert_clean();
    let out = s.path("sample");
    assert!(
        r.text().trim() == format!("Extracted to {}", out.display()),
        "{}",
        r.text()
    );
    assert_eq!(read(out.join("docs/a.txt")), "alpha\n");
    assert_eq!(read(out.join("docs/sub/b.txt")), "beta\n");
    assert_eq!(read(out.join("top.txt")), "top\n");
    assert_eq!(
        std::fs::read_link(out.join("link")).unwrap(),
        Path::new("top.txt")
    );
    // The path that climbed out was not written, and was said to be skipped.
    assert!(!s.path("evil.txt").exists());
    assert!(r.err.contains("../evil.txt"), "{}", r.err);
    // No staging folder or job record is left.
    assert!(
        s.ls(&s.root).iter().all(|n| !n.starts_with(".telamon")),
        "{:?}",
        s.ls(&s.root)
    );
    let jobs = s.ls(&s.path("state/telamon-archive/jobs"));
    assert!(jobs.is_empty(), "{jobs:?}");
}

#[test]
fn extract_to_and_name_choose_the_folder() {
    let s = scratch!("extractto");
    let a = sample(&s, "sample.zip");
    let dest = s.dest();
    let r = s.run(
        &[
            "extract",
            "--to",
            dest.to_str().unwrap(),
            a.to_str().unwrap(),
        ],
        None,
    );
    r.assert_ok();
    assert_eq!(read(dest.join("sample/top.txt")), "top\n");
    assert!(!s.path("sample").exists());
    let r = s.run(
        &[
            "extract",
            "--to",
            dest.to_str().unwrap(),
            "--name",
            "Mine",
            a.to_str().unwrap(),
        ],
        None,
    );
    r.assert_ok();
    assert_eq!(read(dest.join("Mine/top.txt")), "top\n");
    // A name with a slash can't climb out: refused before any work.
    for bad in ["../b", "a/b", "..", "."] {
        let r = s.run(
            &[
                "extract",
                "--to",
                dest.to_str().unwrap(),
                "--name",
                bad,
                a.to_str().unwrap(),
            ],
            None,
        );
        assert_eq!(r.code, 2, "{bad}: {}", r.err);
        assert!(r.err.contains("--name"), "{bad}: {}", r.err);
    }
    assert!(!s.path("b").exists());
    assert_eq!(s.ls(&dest).len(), 2, "{:?}", s.ls(&dest));
    assert!(!s.ls(&s.root).contains(&"b".to_string()));
}

#[test]
fn extract_here_moves_a_lone_folder_out_and_numbers_a_clash() {
    let s = scratch!("here");
    let a = s.write(
        "pack.zip",
        &zip(&[
            z("only/", ""),
            z("only/x.txt", "x\n"),
            z("only/y.txt", "y\n"),
        ]),
    );
    let dest = s.dest();
    let args = [
        "extract",
        "--here",
        "--to",
        dest.to_str().unwrap(),
        a.to_str().unwrap(),
    ];
    let r = s.run(&args, None);
    r.assert_ok();
    assert_eq!(s.ls(&dest), ["only"]);
    assert_eq!(read(dest.join("only/x.txt")), "x\n");
    // Again, with no terminal to ask: Keep Both.
    let r = s.run(&args, None);
    r.assert_ok();
    assert_eq!(s.ls(&dest), ["only", "only (2)"], "{}", r.err);
    assert!(r.text().contains("only (2)"), "{}", r.text());
    // --on-clash skip leaves things as they are and says so.
    let r = s.run(
        &[&args[..1], &["--on-clash", "skip"], &args[1..]].concat(),
        None,
    );
    r.assert_ok();
    assert_eq!(s.ls(&dest), ["only", "only (2)"]);
    assert!(r.err.contains("Skip"), "{}", r.err);
    // --on-clash replace puts the new one in place; the old goes to the Trash.
    std::fs::write(dest.join("only/x.txt"), "changed\n").unwrap();
    let r = s.run(
        &[&args[..1], &["--on-clash", "replace"], &args[1..]].concat(),
        None,
    );
    r.assert_ok();
    assert_eq!(read(dest.join("only/x.txt")), "x\n");
    assert_eq!(s.ls(&dest), ["only", "only (2)"]);
}

#[test]
fn extract_here_wraps_many_items_in_a_folder() {
    let s = scratch!("herewrap");
    let a = sample(&s, "sample.zip");
    let dest = s.dest();
    let r = s.run(
        &[
            "extract",
            "--here",
            "--to",
            dest.to_str().unwrap(),
            a.to_str().unwrap(),
        ],
        None,
    );
    r.assert_ok();
    assert_eq!(s.ls(&dest), ["sample"]);
}

#[test]
fn extract_takes_only_the_entries_asked_for() {
    let s = scratch!("select");
    let a = sample(&s, "sample.zip");
    let dest = s.dest();
    let d = dest.to_str().unwrap();
    let r = s.run(
        &[
            "extract",
            "--to",
            d,
            a.to_str().unwrap(),
            "docs/sub",
            "top.txt",
        ],
        None,
    );
    r.assert_ok();
    let out = dest.join("sample");
    assert_eq!(read(out.join("docs/sub/b.txt")), "beta\n");
    assert_eq!(read(out.join("top.txt")), "top\n");
    assert!(!out.join("docs/a.txt").exists());
    assert!(!out.join("link").exists());
    // A name that isn't in the archive fails before anything is written.
    let before = s.ls(&dest);
    let r = s.run(
        &[
            "extract",
            "--to",
            d,
            "--name",
            "Other",
            a.to_str().unwrap(),
            "nope.txt",
        ],
        None,
    );
    assert_eq!(r.code, 1, "{}", r.err);
    assert!(r.err.contains("nope.txt"), "{}", r.err);
    assert_eq!(s.ls(&dest), before);
}

#[test]
fn extract_json_reports_where_it_went() {
    let s = scratch!("extractjson");
    let a = sample(&s, "sample.zip");
    let dest = s.dest();
    let r = s.run(
        &[
            "extract",
            "--json",
            "--to",
            dest.to_str().unwrap(),
            a.to_str().unwrap(),
        ],
        None,
    );
    r.assert_ok();
    r.assert_clean();
    let t = r.text();
    let last = t.lines().last().unwrap();
    let want = format!("\"path\":{:?}", dest.join("sample").to_str().unwrap());
    assert!(last.starts_with("{\"summary\":{"), "{t}");
    assert!(last.contains(&want), "{last}\nwanted {want}");
    assert!(last.contains("\"left_out\":false"), "{last}");
    assert!(t.contains("{\"skipped\":{"), "{t}");
    let v = json_lines(&r);
    let summary = &v.last().unwrap()["summary"];
    assert_eq!(summary["path"], dest.join("sample").to_str().unwrap());
    assert_eq!(summary["left_out"], false);
    assert!(v.iter().any(|e| e.get("skipped").is_some()));
}

#[test]
fn extract_an_encrypted_zip_with_a_descriptor() {
    let s = scratch!("extractpw");
    let a = s.fixture("aes256-secret.zip");
    let dest = s.dest();
    let d = dest.to_str().unwrap();
    let r = s.run(
        &[
            "extract",
            "--to",
            d,
            "--password-fd",
            "3",
            a.to_str().unwrap(),
        ],
        Some("secret"),
    );
    r.assert_ok();
    assert_eq!(read(dest.join("aes256-secret/f.txt")), "secret text\n");
    // Wrong or missing: exit 3 and nothing left behind.
    let other = s.path("other");
    std::fs::create_dir(&other).unwrap();
    let o = other.to_str().unwrap();
    let r = s.run(
        &[
            "extract",
            "--to",
            o,
            "--password-fd",
            "3",
            a.to_str().unwrap(),
        ],
        Some("nope"),
    );
    assert_eq!(r.code, 3, "{}", r.err);
    assert!(s.ls(&other).is_empty(), "{:?}", s.ls(&other));
    let r = s.run(&["extract", "--to", o, a.to_str().unwrap()], None);
    assert_eq!(r.code, 3, "{}", r.err);
    assert!(s.ls(&other).is_empty(), "{:?}", s.ls(&other));
}

#[test]
fn extract_into_a_missing_folder_fails_in_words() {
    let s = scratch!("nodest");
    let a = sample(&s, "sample.zip");
    let gone = s.path("gone");
    let r = s.run(
        &[
            "extract",
            "--to",
            gone.to_str().unwrap(),
            a.to_str().unwrap(),
        ],
        None,
    );
    assert_eq!(r.code, 1, "{}", r.err);
    assert!(r.err.starts_with("telamon-archive-cli: "), "{}", r.err);
}

/// A zip holding 257 MiB of zeros, deflated to about 250 KiB: past 100 times
/// its own size once 256 MiB are written, which the limits ask about.
fn bomb(s: &Scratch) -> Option<PathBuf> {
    const SIZE: u64 = 257 * 1024 * 1024;
    let gz = Command::new("sh")
        .arg("-c")
        .arg(format!("head -c {SIZE} /dev/zero | gzip -9n"))
        .output()
        .ok()?;
    if !gz.status.success() || gz.stdout.len() < 18 {
        return None;
    }
    let g = gz.stdout;
    // A gzip file: a 10-byte header, the raw deflate stream, then the CRC-32
    // and the size.
    let deflate = &g[10..g.len() - 8];
    let crc = u32::from_le_bytes(g[g.len() - 8..g.len() - 4].try_into().unwrap());
    let bytes = zip_with(&[], Some(("zeros.bin", deflate, crc, SIZE as u32)));
    Some(s.write("bomb.zip", &bytes))
}

#[test]
fn limits_stop_extraction_unless_allowed() {
    let s = scratch!("limits");
    let Some(a) = bomb(&s) else {
        eprintln!("SKIPPED: gzip isn't available");
        return;
    };
    let dest = s.dest();
    let d = dest.to_str().unwrap();
    let r = s.run(&["extract", "--to", d, a.to_str().unwrap()], None);
    assert_eq!(r.code, 4, "{}", r.err);
    assert!(r.err.contains("--allow-large"), "{}", r.err);
    assert!(s.ls(&dest).is_empty(), "{:?}", s.ls(&dest));
    let r = s.run(
        &["extract", "--to", d, "--allow-large", a.to_str().unwrap()],
        None,
    );
    r.assert_ok();
    let len = std::fs::metadata(dest.join("bomb/zeros.bin"))
        .unwrap()
        .len();
    assert_eq!(len, 257 * 1024 * 1024);
}

// ---- failures and usage ----

#[test]
fn a_missing_archive_fails_with_exit_1() {
    let s = scratch!("missing");
    let gone = s.path("gone.zip");
    for cmd in ["list", "info", "test", "extract"] {
        let r = s.run(&[cmd, gone.to_str().unwrap()], None);
        assert_eq!(r.code, 1, "{cmd}: {}", r.err);
        assert!(r.err.contains("isn't there"), "{cmd}: {}", r.err);
        assert!(r.out.is_empty());
    }
}

#[test]
fn something_that_is_no_archive_fails_with_exit_1() {
    let s = scratch!("noarchive");
    let a = s.write("text.zip", b"this is not an archive at all\n");
    let r = s.run(&["list", a.to_str().unwrap()], None);
    assert_eq!(r.code, 1, "{}", r.err);
    assert!(r.out.is_empty());
}

#[test]
fn bad_usage_is_exit_2() {
    let s = scratch!("usage");
    let a = sample(&s, "sample.zip");
    let a = a.to_str().unwrap();
    for args in [
        vec![],
        vec!["frobnicate"],
        vec!["list"],
        vec!["list", "--bogus", a],
        vec!["list", "--here", a],
        vec!["extract", "--here", "--name", "x", a],
        vec!["extract", "--on-clash", "maybe", a],
        vec!["list", "--encoding", "klingon", a],
        vec!["test", "--password-fd", "x", a],
    ] {
        let r = s.run(&args, None);
        assert_eq!(r.code, 2, "{args:?}: {}", r.err);
        assert!(
            r.err.starts_with("telamon-archive-cli: "),
            "{args:?}: {}",
            r.err
        );
        assert!(r.out.is_empty(), "{args:?}");
    }
}

#[test]
fn create_is_not_available_yet() {
    let s = scratch!("create");
    let r = s.run(&["create", "x.zip", "file"], None);
    assert_eq!(r.code, 2);
    assert_eq!(
        r.err.trim(),
        "telamon-archive-cli: create isn't available yet"
    );
}

#[test]
fn help_and_version_work() {
    let s = scratch!("help");
    let r = s.run(&["--help"], None);
    r.assert_ok();
    for want in [
        "list",
        "extract",
        "--password-fd",
        "--allow-large",
        "-v",
        "Exit codes",
    ] {
        assert!(r.text().contains(want), "{want}");
    }
    let r = s.run(&["--version"], None);
    r.assert_ok();
    assert!(r.text().starts_with("telamon-archive-cli "), "{}", r.text());
}

#[test]
fn nothing_is_logged_without_dash_v() {
    let s = scratch!("quiet");
    let a = sample(&s, "sample.zip");
    let r = s.run(&["list", a.to_str().unwrap()], None);
    r.assert_ok();
    assert!(r.err.is_empty(), "{}", r.err);
    let r = s.run(&["-v", "list", a.to_str().unwrap()], None);
    r.assert_ok();
    assert!(
        r.err.contains("[debug]") || r.err.contains("[info]") || r.err.contains("[warn]"),
        "{}",
        r.err
    );
}

#[test]
fn a_non_utf8_archive_path_works() {
    use std::os::unix::ffi::OsStrExt;
    let s = scratch!("osstr");
    let bytes = std::fs::read(sample(&s, "sample.zip")).unwrap();
    let mut name = b"odd\xff".to_vec();
    name.extend_from_slice(b".zip");
    let path = s.root.join(std::ffi::OsStr::from_bytes(&name));
    std::fs::write(&path, bytes).unwrap();
    let r = s.run_os(vec!["list".into(), path.into_os_string()], None);
    r.assert_ok();
    let dest = s.dest();
    let r = s.run_os(
        vec![
            "extract".into(),
            "--to".into(),
            dest.clone().into_os_string(),
            s.root
                .join(std::ffi::OsStr::from_bytes(&name))
                .into_os_string(),
        ],
        None,
    );
    r.assert_ok();
    r.assert_clean();
    assert_eq!(s.ls(&dest).len(), 1, "{:?}", s.ls(&dest));
}

// ---- hardening ----

#[test]
fn a_worker_option_is_a_path_after_the_archive() {
    // A glob such as `extract a.zip *` must never reach an option.
    let s = scratch!("globopt");
    let a = sample(&s, "sample.zip");
    let r = s.run(
        &["extract", a.to_str().unwrap(), "--worker=/bin/true"],
        None,
    );
    assert_eq!(r.code, 1, "{}", r.err);
    assert!(r.err.contains("--worker=/bin/true"), "{}", r.err);
}

#[test]
fn a_file_named_like_a_flag_is_a_path_after_double_dash() {
    let s = scratch!("dashfile");
    let sample = sample(&s, "sample.zip");
    std::fs::copy(&sample, s.path("--allow-large")).unwrap();
    let go = |args: &[&str]| {
        s.run_full(
            args.iter().map(|a| (*a).into()).collect(),
            None,
            Some(&s.root),
        )
    };
    // As an option it is one (and `list` has no such option).
    let r = go(&["list", "--allow-large"]);
    assert_eq!(r.code, 2, "{}", r.err);
    // After `--` it is the archive.
    let r = go(&["list", "--", "--allow-large"]);
    r.assert_ok();
    assert!(r.text().contains("top.txt"), "{}", r.text());
    let dest = s.dest();
    let r = go(&[
        "extract",
        "--to",
        dest.to_str().unwrap(),
        "--",
        "--allow-large",
        "top.txt",
    ]);
    r.assert_ok();
    assert_eq!(read(dest.join("--allow-large/top.txt")), "top\n");
    // After the archive it is an item to extract, not a flag.
    let r = go(&["extract", "sample.zip", "--allow-large"]);
    assert_eq!(r.code, 1, "{}", r.err);
    assert!(
        r.err.contains("no item called \"--allow-large\""),
        "{}",
        r.err
    );
}

#[test]
fn no_core_dump_and_no_attaching_while_it_runs() {
    use std::os::unix::fs::MetadataExt;
    let s = scratch!("dump");
    let a = s.fixture("aes256-secret.zip");
    // It waits for a password that never comes, on a pipe held open here.
    let mut fds = [0; 2];
    // SAFETY: pipe2 fills two descriptors.
    assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
    // SAFETY: new descriptors we own.
    let (r, _w) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
    let rfd = r.as_raw_fd();
    let mut cmd = s.base(vec![
        "test".into(),
        "--password-fd".into(),
        "3".into(),
        a.into_os_string(),
    ]);
    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // SAFETY: only dup2 in the child.
    unsafe {
        cmd.pre_exec(move || {
            if libc::dup2(rfd, 3) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = cmd.spawn().unwrap();
    let proc = format!("/proc/{}", child.id());
    let mut ok = false;
    for _ in 0..600 {
        let limits = std::fs::read_to_string(format!("{proc}/limits")).unwrap_or_default();
        let core = limits.lines().find(|l| l.starts_with("Max core file size"));
        // A process that isn't dumpable owns its /proc files as root.
        if core.is_some_and(|l| l.split_whitespace().nth(4) == Some("0"))
            && std::fs::metadata(format!("{proc}/limits")).is_ok_and(|m| m.uid() == 0)
        {
            ok = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let _ = child.kill();
    let _ = child.wait();
    assert!(ok, "core limit and dumpable were not both off");
}

/// A pseudo-terminal: the CLI gets the slave as its controlling terminal.
struct Pty {
    master: OwnedFd,
    slave: OwnedFd,
}

impl Pty {
    fn new() -> Pty {
        let (mut m, mut sl) = (0, 0);
        // SAFETY: openpty fills two descriptors; the optional arguments are null.
        let rc = unsafe {
            libc::openpty(
                &mut m,
                &mut sl,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
            )
        };
        assert_eq!(rc, 0, "openpty failed");
        // The master stays ours: a child holding it would keep the terminal
        // from hanging up when this closes it.
        // SAFETY: fcntl on a descriptor we own.
        unsafe { libc::fcntl(m, libc::F_SETFD, libc::FD_CLOEXEC) };
        // SAFETY: new descriptors we own.
        unsafe {
            Pty {
                master: OwnedFd::from_raw_fd(m),
                slave: OwnedFd::from_raw_fd(sl),
            }
        }
    }

    fn echo(&self) -> bool {
        // SAFETY: tcgetattr fills a termios we own.
        let mut t: libc::termios = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { libc::tcgetattr(self.slave.as_raw_fd(), &mut t) },
            0
        );
        t.c_lflag & libc::ECHO != 0
    }

    /// Reads from the master until `needle` shows or 30 seconds pass (it
    /// returns as soon as the needle is there).
    fn wait_for(&self, needle: &str) -> String {
        self.read_for(needle, 600)
    }

    /// What shows on the master in `ms` milliseconds, to check that something
    /// does not appear.
    fn quiet_for(&self, ms: u64, needle: &str) -> String {
        self.read_for(needle, ms.div_ceil(50) as usize)
    }

    fn read_for(&self, needle: &str, polls: usize) -> String {
        let mut seen = Vec::new();
        for _ in 0..polls {
            let mut fds = libc::pollfd {
                fd: self.master.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: one live pollfd.
            if unsafe { libc::poll(&mut fds, 1, 50) } > 0 {
                let mut buf = [0u8; 256];
                // SAFETY: reads into a live buffer.
                let n =
                    unsafe { libc::read(self.master.as_raw_fd(), buf.as_mut_ptr().cast(), 256) };
                if n > 0 {
                    seen.extend_from_slice(&buf[..n as usize]);
                }
            }
            if String::from_utf8_lossy(&seen).contains(needle) {
                break;
            }
        }
        String::from_utf8_lossy(&seen).into_owned()
    }

    fn type_byte(&self, b: u8) {
        // SAFETY: writes one byte from a live local.
        unsafe { libc::write(self.master.as_raw_fd(), (&raw const b).cast(), 1) };
    }
}

/// Starts `test ARCHIVE` on a pty at its password prompt.
fn at_the_prompt(s: &Scratch, pty: &Pty) -> std::process::Child {
    let a = s.fixture("aes256-secret.zip");
    let mut cmd = s.base(vec!["test".into(), a.into_os_string()]);
    let slave = pty.slave.as_raw_fd();
    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // SAFETY: setsid and ioctl only, in the child.
    unsafe {
        cmd.pre_exec(move || {
            libc::setsid();
            if libc::ioctl(slave, libc::TIOCSCTTY, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let child = cmd.spawn().unwrap();
    let seen = pty.wait_for("Password: ");
    assert!(seen.contains("Password: "), "no prompt: {seen:?}");
    assert!(!pty.echo(), "echo should be off at the prompt");
    child
}

/// The exit code, waiting up to 30 seconds (it returns as soon as the process
/// is gone); `None` if it had to be killed.
fn wait_code(child: &mut std::process::Child) -> Option<i32> {
    for _ in 0..600 {
        if let Some(st) = child.try_wait().unwrap() {
            return st.code();
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let _ = child.kill();
    let _ = child.wait();
    None
}

#[test]
fn ctrl_backslash_at_the_prompt_cancels_and_restores_echo() {
    let s = scratch!("quit");
    let pty = Pty::new();
    let mut child = at_the_prompt(&s, &pty);
    pty.type_byte(0x1c); // Ctrl-\ : SIGQUIT to the foreground group
    assert_eq!(wait_code(&mut child), Some(130));
    assert!(pty.echo(), "echo was left off");
}

#[test]
fn ctrl_c_and_a_hangup_at_the_prompt_cancel_and_restore_echo() {
    let s = scratch!("intr");
    let pty = Pty::new();
    let mut child = at_the_prompt(&s, &pty);
    pty.type_byte(0x03);
    assert_eq!(wait_code(&mut child), Some(130));
    assert!(pty.echo(), "echo was left off");
}

#[test]
fn a_real_sighup_at_the_prompt_cancels_and_restores_echo() {
    let s = scratch!("sighup");
    let pty = Pty::new();
    let mut child = at_the_prompt(&s, &pty);
    kill(&child, libc::SIGHUP);
    assert_eq!(wait_code(&mut child), Some(130));
    assert!(pty.echo(), "echo was left off");
}

#[test]
fn the_terminal_hanging_up_at_the_prompt_exits_130() {
    let s = scratch!("hangup");
    let pty = Pty::new();
    let mut child = at_the_prompt(&s, &pty);
    // Closing the master hangs the terminal up: SIGHUP to the session, and
    // the read fails.
    let Pty { master, slave } = pty;
    drop(master);
    assert_eq!(wait_code(&mut child), Some(130));
    drop(slave);
}

#[test]
fn ctrl_z_at_the_prompt_doesnt_stop_it_with_echo_off() {
    let s = scratch!("stop");
    let pty = Pty::new();
    let mut child = at_the_prompt(&s, &pty);
    pty.type_byte(0x1a); // Ctrl-Z
    std::thread::sleep(std::time::Duration::from_millis(300));
    let mut status = 0;
    // SAFETY: waitpid on our own child, with a live status.
    let got = unsafe {
        libc::waitpid(
            child.id() as i32,
            &mut status,
            libc::WNOHANG | libc::WUNTRACED,
        )
    };
    assert_eq!(got, 0, "the process stopped or ended (status {status})");
    assert!(!pty.echo());
    pty.type_byte(0x1c);
    assert_eq!(wait_code(&mut child), Some(130));
    assert!(pty.echo());
}

#[test]
fn input_typed_before_a_cancel_is_thrown_away() {
    let s = scratch!("flush");
    let pty = Pty::new();
    let mut child = at_the_prompt(&s, &pty);
    for b in b"typed-ahead" {
        pty.type_byte(*b);
    }
    std::thread::sleep(std::time::Duration::from_millis(200));
    pty.type_byte(0x1c);
    assert_eq!(wait_code(&mut child), Some(130));
    // Nothing is left in the terminal's input for the shell to read.
    let mut n: libc::c_int = 0;
    // SAFETY: FIONREAD writes one int.
    unsafe { libc::ioctl(pty.slave.as_raw_fd(), libc::FIONREAD, &mut n) };
    assert_eq!(n, 0, "{n} bytes of input were left");
}

#[test]
fn password_fd_0_with_piped_stdin_never_turns_interactive() {
    use std::io::Write;
    let s = scratch!("fd0");
    let pty = Pty::new();
    let a = s.fixture("aes256-secret.zip");
    let mut cmd = s.base(vec![
        "test".into(),
        "--password-fd".into(),
        "0".into(),
        a.into_os_string(),
    ]);
    let slave = pty.slave.as_raw_fd();
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    // SAFETY: setsid and ioctl only, in the child.
    unsafe {
        cmd.pre_exec(move || {
            libc::setsid();
            if libc::ioctl(slave, libc::TIOCSCTTY, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = cmd.spawn().unwrap();
    // A wrong password: with a terminal in reach, the bug asked again there.
    child.stdin.take().unwrap().write_all(b"wrong\n").unwrap();
    let out = child.wait_with_output().unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(3), "{err}");
    assert!(err.contains("didn't work"), "{err}");
    let seen = pty.quiet_for(500, "Password");
    assert!(!seen.contains("Password"), "a prompt appeared: {seen:?}");
}

/// A shell script as the worker. The client starts it with no arguments and
/// an empty environment; descriptor 4 is open only for an extraction.
fn fake_worker(s: &Scratch, name: &str, body: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let p = s.write(name, format!("#!/bin/sh\n{body}\n").as_bytes());
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).unwrap();
    p
}

/// Waits (30 s at most; it returns as soon as the file is there) for `p`.
fn wait_for_file(p: &Path) {
    for _ in 0..1500 {
        if p.exists() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    panic!("{} never appeared", p.display());
}

fn kill(child: &std::process::Child, sig: libc::c_int) {
    // SAFETY: signals our own, still unreaped, child.
    unsafe { libc::kill(child.id() as i32, sig) };
}

/// Starts `list` against a worker that ignores every signal and never
/// answers, once it is running (it touches a marker; by then the CLI has long
/// blocked its signals).
fn start_stuck(s: &Scratch) -> std::process::Child {
    let marker = s.path("started");
    let fake = fake_worker(
        s,
        "stuck-worker.sh",
        &format!(
            "trap '' TERM INT HUP QUIT\n: > '{}'\nexec sleep 60",
            marker.display()
        ),
    );
    let a = sample(s, "sample.zip");
    let mut cmd = s.base_with(&fake, vec!["list".into(), a.into_os_string()]);
    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let child = cmd.spawn().unwrap();
    wait_for_file(&marker);
    child
}

#[test]
fn a_signal_cancels_a_job_whose_worker_ignores_it() {
    // The first signal cancels, and the client kills the worker for good:
    // the job ends at once although the worker would sleep a minute.
    let s = scratch!("stuck");
    let mut child = start_stuck(&s);
    kill(&child, libc::SIGTERM);
    let t = std::time::Instant::now();
    assert_eq!(wait_code(&mut child), Some(130));
    assert!(t.elapsed() < std::time::Duration::from_secs(5));
}

#[test]
fn two_different_signals_in_a_row_exit_130_promptly() {
    // Both are pending together, so the signal thread takes the second one
    // with the first already counted: the leave-at-once path. (That the
    // decision is right is unit-tested in sig.rs; the exit code alone can't
    // tell this path from a first signal's, so this checks it ends cleanly.)
    let s = scratch!("twosig");
    let mut child = start_stuck(&s);
    kill(&child, libc::SIGTERM);
    kill(&child, libc::SIGHUP);
    let t = std::time::Instant::now();
    assert_eq!(wait_code(&mut child), Some(130));
    assert!(t.elapsed() < std::time::Duration::from_secs(5));
}

#[test]
fn ctrl_c_mid_extract_with_a_running_worker_leaves_nothing() {
    let s = scratch!("midextract");
    let marker = s.path("extracting");
    // Lists with the real worker; an extraction (descriptor 4 is open) hangs.
    let fake = fake_worker(
        &s,
        "slow-worker.sh",
        &format!(
            "if [ -e /proc/self/fd/4 ]; then : > '{}'; exec sleep 60; fi\nexec '{}'",
            marker.display(),
            s.worker.display()
        ),
    );
    let a = sample(&s, "sample.zip");
    let dest = s.dest();
    let mut cmd = s.base_with(
        &fake,
        vec![
            "extract".into(),
            "--to".into(),
            dest.clone().into_os_string(),
            a.into_os_string(),
        ],
    );
    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child = cmd.spawn().unwrap();
    wait_for_file(&marker);
    // The staging folder is there while the worker runs.
    assert_eq!(s.ls(&dest).len(), 1, "{:?}", s.ls(&dest));
    kill(&child, libc::SIGINT);
    assert_eq!(wait_code(&mut child), Some(130));
    assert!(s.ls(&dest).is_empty(), "left behind: {:?}", s.ls(&dest));
}

#[test]
fn a_signal_after_the_files_are_in_place_doesnt_turn_it_into_a_cancel() {
    let s = scratch!("lateint");
    let a = sample(&s, "sample.zip");
    let dest = s.dest();
    // A stdout pipe that is full: the result line has to wait for a reader.
    let mut fds = [0; 2];
    // SAFETY: pipe2 fills two descriptors.
    assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
    // SAFETY: both are new descriptors we own.
    let (r, w) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
    // SAFETY: fcntl on descriptors we own; the writes are from a live buffer.
    unsafe {
        let fl = libc::fcntl(w.as_raw_fd(), libc::F_GETFL);
        libc::fcntl(w.as_raw_fd(), libc::F_SETFL, fl | libc::O_NONBLOCK);
        let junk = [b'.'; 4096];
        while libc::write(w.as_raw_fd(), junk.as_ptr().cast(), junk.len()) > 0 {}
        libc::fcntl(w.as_raw_fd(), libc::F_SETFL, fl);
        let fl = libc::fcntl(r.as_raw_fd(), libc::F_GETFL);
        libc::fcntl(r.as_raw_fd(), libc::F_SETFL, fl | libc::O_NONBLOCK);
    }
    let mut cmd = s.base(vec![
        "extract".into(),
        "--to".into(),
        dest.clone().into_os_string(),
        a.into_os_string(),
    ]);
    cmd.stdin(Stdio::null())
        .stdout(Stdio::from(w))
        .stderr(Stdio::null());
    let mut child = cmd.spawn().unwrap();
    wait_for_file(&dest.join("sample"));
    kill(&child, libc::SIGTERM);
    std::thread::sleep(std::time::Duration::from_millis(300));
    let early = child.try_wait().unwrap();
    assert!(
        early.is_none(),
        "the signal ended a finished job: {early:?}"
    );
    // A reader comes: the line is written and the run is a success.
    let mut buf = [0u8; 4096];
    // SAFETY: reads into a live buffer.
    while unsafe { libc::read(r.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) } > 0 {}
    assert_eq!(wait_code(&mut child), Some(0));
    assert_eq!(read(dest.join("sample/top.txt")), "top\n");
}

// ---- standard streams that fail ----

/// A pipe whose reader is gone: every write to the other end is EPIPE.
fn closed_pipe() -> OwnedFd {
    let mut fds = [0; 2];
    // SAFETY: pipe2 fills two descriptors.
    assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
    // SAFETY: new descriptors we own; the reader is closed right away.
    unsafe {
        drop(OwnedFd::from_raw_fd(fds[0]));
        OwnedFd::from_raw_fd(fds[1])
    }
}

fn dev_full() -> std::fs::File {
    std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/full")
        .unwrap()
}

/// Runs with no terminal and the given streams (stdin is /dev/null): the
/// exit code, and what reached the streams that were pipes.
fn run_streams(
    s: &Scratch,
    args: &[&str],
    stdout: Stdio,
    stderr: Stdio,
) -> (Option<i32>, String, String) {
    let mut cmd = s.base(args.iter().map(|a| a.to_string().into()).collect());
    cmd.stdin(Stdio::null()).stdout(stdout).stderr(stderr);
    // SAFETY: setsid only, in the child: no terminal to prompt on.
    unsafe {
        cmd.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    let out = cmd.spawn().unwrap().wait_with_output().unwrap();
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn list_into_a_closed_pipe_exits_1_without_a_word() {
    let s = scratch!("epipe");
    let a = sample(&s, "sample.zip");
    let (code, _, err) = run_streams(
        &s,
        &["list", a.to_str().unwrap()],
        Stdio::from(closed_pipe()),
        Stdio::piped(),
    );
    assert_eq!(code, Some(1), "{err}");
    assert!(err.is_empty(), "{err}");
}

#[test]
fn list_into_a_full_disk_exits_1_in_words_and_never_panics() {
    let s = scratch!("devfull");
    let a = sample(&s, "sample.zip");
    for json in [false, true] {
        let mut args = vec!["list"];
        if json {
            args.push("--json");
        }
        args.push(a.to_str().unwrap());
        let (code, _, err) = run_streams(&s, &args, Stdio::from(dev_full()), Stdio::piped());
        assert_eq!(code, Some(1), "{err}");
        assert!(err.contains("couldn't be written"), "{err}");
        assert!(!err.contains("Something went wrong"), "{err}");
        assert!(!err.contains("panicked"), "{err}");
    }
}

#[test]
fn a_closed_or_full_stderr_never_changes_the_exit_code() {
    let s = scratch!("badstderr");
    let aes = s.fixture("aes256-secret.zip");
    let aes = aes.to_str().unwrap();
    // Needs a password: exit 3, the sentence nowhere to go.
    let (code, ..) = run_streams(
        &s,
        &["test", aes],
        Stdio::null(),
        Stdio::from(closed_pipe()),
    );
    assert_eq!(code, Some(3));
    let (code, ..) = run_streams(&s, &["test", aes], Stdio::null(), Stdio::from(dev_full()));
    assert_eq!(code, Some(3));
    // Bad usage: exit 2. A missing archive: exit 1. A limit: exit 4.
    let (code, ..) = run_streams(&s, &["bogus"], Stdio::null(), Stdio::from(dev_full()));
    assert_eq!(code, Some(2));
    let (code, ..) = run_streams(
        &s,
        &["list", "/nonexistent/x.zip"],
        Stdio::null(),
        Stdio::from(closed_pipe()),
    );
    assert_eq!(code, Some(1));
    if let Some(b) = bomb(&s) {
        let dest = s.dest();
        let (code, ..) = run_streams(
            &s,
            &[
                "extract",
                "--to",
                dest.to_str().unwrap(),
                b.to_str().unwrap(),
            ],
            Stdio::null(),
            Stdio::from(dev_full()),
        );
        assert_eq!(code, Some(4));
    }
}

#[test]
fn a_finished_extraction_is_a_success_whatever_its_output_does() {
    let s = scratch!("lostoutput");
    let a = sample(&s, "sample.zip");
    let dest = s.dest();
    let args = [
        "extract",
        "--to",
        dest.to_str().unwrap(),
        a.to_str().unwrap(),
    ];
    // stderr can't take the notes: the result line is still printed.
    let (code, out, _) = run_streams(&s, &args, Stdio::piped(), Stdio::from(closed_pipe()));
    assert_eq!(code, Some(0));
    assert!(out.contains("Extracted to"), "{out}");
    assert_eq!(read(dest.join("sample/top.txt")), "top\n");
    // stdout can't take the line: the files are in place, so exit 0 and a
    // warning that says where they went.
    let (code, _, err) = run_streams(&s, &args, Stdio::from(dev_full()), Stdio::piped());
    assert_eq!(code, Some(0), "{err}");
    assert!(err.contains("the files were extracted to"), "{err}");
    assert!(!err.contains("panicked"), "{err}");
    let (code, _, err) = run_streams(&s, &args, Stdio::from(closed_pipe()), Stdio::piped());
    assert_eq!(code, Some(0), "{err}");
}

// ---- passwords on a descriptor ----

/// Gives the child `fd` as descriptor 3.
fn pass_as_3(cmd: &mut Command, fd: &OwnedFd) {
    let raw = fd.as_raw_fd();
    // SAFETY: only dup2 and fcntl in the child.
    unsafe {
        cmd.pre_exec(move || {
            if raw == 3 {
                libc::fcntl(3, libc::F_SETFD, 0);
            } else if libc::dup2(raw, 3) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

#[test]
fn an_empty_password_descriptor_is_exit_3_not_a_usage_error() {
    let s = scratch!("fdeof");
    let a = s.fixture("aes256-secret.zip");
    let null = OwnedFd::from(std::fs::File::open("/dev/null").unwrap());
    let mut cmd = s.base(vec![
        "test".into(),
        "--password-fd".into(),
        "3".into(),
        a.into_os_string(),
    ]);
    cmd.stdin(Stdio::null()).stdout(Stdio::null());
    pass_as_3(&mut cmd, &null);
    let out = cmd.output().unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(3), "{err}");
    assert!(
        err.contains("No password was sent on descriptor 3."),
        "{err}"
    );
}

#[test]
fn a_password_descriptor_that_stays_silent_times_out_with_exit_3() {
    // The 30 s wait is shortened by a knob that exists only with dev-worker.
    let s = scratch!("fdwait");
    let a = s.fixture("aes256-secret.zip");
    let mut fds = [0; 2];
    // SAFETY: pipe2 fills two descriptors.
    assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
    // SAFETY: new descriptors we own; the writer stays open and silent.
    let (r, _w) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
    let mut cmd = s.base(vec![
        "test".into(),
        "--password-fd".into(),
        "3".into(),
        a.into_os_string(),
    ]);
    cmd.env("TELAMON_ARCHIVE_TEST_FD_WAIT_MS", "300")
        .stdin(Stdio::null())
        .stdout(Stdio::null());
    pass_as_3(&mut cmd, &r);
    let t = std::time::Instant::now();
    let out = cmd.output().unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(3), "{err}");
    assert!(err.contains("No password arrived on descriptor 3"), "{err}");
    assert!(t.elapsed() < std::time::Duration::from_secs(10));
}

// ---- the -v log ----

#[test]
fn dash_v_logs_the_phases_and_never_a_password() {
    let s = scratch!("vlog");
    let a = s.fixture("aes256-secret.zip");
    let dest = s.dest();
    let r = s.run(
        &[
            "-v",
            "extract",
            "--password-fd",
            "3",
            "--to",
            dest.to_str().unwrap(),
            a.to_str().unwrap(),
        ],
        Some("secret"),
    );
    r.assert_ok();
    for want in [
        "command: extract",
        "opening ",
        "listed: format zip, 1 entries",
        "password: from a descriptor, asked for 1 time(s)",
        "extracting into ",
        "finished in ",
        "exit code 0",
    ] {
        assert!(r.err.contains(want), "no {want:?} in:\n{}", r.err);
    }
    assert!(
        !r.err.replace("aes256-secret", "").contains("secret"),
        "{}",
        r.err
    );
}

// ---- terminals ----

/// Starts the CLI with the pty as stdin and controlling terminal (so it may
/// ask questions), its output thrown away: the questions show on the pty.
fn on_pty(s: &Scratch, pty: &Pty, args: Vec<std::ffi::OsString>) -> std::process::Child {
    let mut cmd = s.base(args);
    let slave = pty.slave.as_raw_fd();
    cmd.stdin(Stdio::from(pty.slave.try_clone().unwrap()))
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // SAFETY: setsid and ioctl only, in the child.
    unsafe {
        cmd.pre_exec(move || {
            libc::setsid();
            if libc::ioctl(slave, libc::TIOCSCTTY, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    cmd.spawn().unwrap()
}

/// `extract --here` of `only/x.txt` into a folder that already holds `only`.
fn clash_setup(s: &Scratch) -> Vec<std::ffi::OsString> {
    let a = s.write("pack.zip", &zip(&[z("only/", ""), z("only/x.txt", "x\n")]));
    std::fs::create_dir(s.dest().join("only")).unwrap();
    vec![
        "extract".into(),
        "--here".into(),
        "--to".into(),
        s.dest().into_os_string(),
        a.into_os_string(),
    ]
}

#[test]
fn ctrl_c_at_the_clash_prompt_cancels_and_places_nothing() {
    let s = scratch!("clashint");
    let pty = Pty::new();
    let mut child = on_pty(&s, &pty, clash_setup(&s));
    let seen = pty.wait_for("[k] ");
    assert!(seen.contains("already here"), "no prompt: {seen:?}");
    pty.type_byte(0x03);
    assert_eq!(wait_code(&mut child), Some(130));
    // No "only (2)", and no staging folder.
    assert_eq!(s.ls(&s.dest()), ["only"]);
    assert!(s.ls(&s.dest().join("only")).is_empty());
}

#[test]
fn answering_the_clash_prompt_is_honoured() {
    let s = scratch!("clashans");
    let args = clash_setup(&s);
    let pty = Pty::new();
    let mut child = on_pty(&s, &pty, args.clone());
    pty.wait_for("[k] ");
    for b in b"k\n" {
        pty.type_byte(*b);
    }
    assert_eq!(wait_code(&mut child), Some(0));
    assert_eq!(s.ls(&s.dest()), ["only", "only (2)"]);
    let mut child = on_pty(&s, &pty, args);
    pty.wait_for("[k] ");
    for b in b"s\n" {
        pty.type_byte(*b);
    }
    assert_eq!(wait_code(&mut child), Some(0));
    assert_eq!(s.ls(&s.dest()), ["only", "only (2)"]);
}

#[test]
fn ctrl_c_at_the_limit_prompt_cancels_with_exit_130() {
    let s = scratch!("limitint");
    let Some(a) = bomb(&s) else {
        eprintln!("SKIPPED: gzip isn't available");
        return;
    };
    let pty = Pty::new();
    let mut child = on_pty(
        &s,
        &pty,
        vec![
            "extract".into(),
            "--to".into(),
            s.dest().into_os_string(),
            a.into_os_string(),
        ],
    );
    let seen = pty.wait_for("[y/N] ");
    assert!(seen.contains("[y/N]"), "no prompt: {seen:?}");
    pty.type_byte(0x03);
    assert_eq!(wait_code(&mut child), Some(130));
    assert!(s.ls(&s.dest()).is_empty(), "{:?}", s.ls(&s.dest()));
}

#[test]
fn two_quick_signals_at_the_prompt_still_restore_echo() {
    let s = scratch!("twice");
    let pty = Pty::new();
    let mut child = at_the_prompt(&s, &pty);
    pty.type_byte(0x1c);
    pty.type_byte(0x1c);
    assert_eq!(wait_code(&mut child), Some(130));
    assert!(pty.echo(), "echo was left off");
}

// ---- a listing that breaks part way ----

/// A tar of `a`, `b` and `c` whose third header is ruined.
fn broken_tar(s: &Scratch) -> Option<PathBuf> {
    std::fs::create_dir_all(s.path("src")).unwrap();
    for n in ["a", "b", "c"] {
        std::fs::write(s.path("src").join(n), n).unwrap();
    }
    let a = s.path("broken.tar");
    let ok = Command::new("tar")
        .arg("-cf")
        .arg(&a)
        .args(["-C"])
        .arg(s.path("src"))
        .args(["a", "b", "c"])
        .status()
        .ok()?;
    if !ok.success() {
        return None;
    }
    let mut bytes = std::fs::read(&a).unwrap();
    bytes[2048..2148].fill(0xff);
    std::fs::write(&a, &bytes).unwrap();
    Some(a)
}

#[test]
fn a_broken_listing_prints_what_was_read_then_fails_with_the_reason() {
    let s = scratch!("brokenlist");
    let Some(a) = broken_tar(&s) else {
        eprintln!("SKIPPED: tar isn't available");
        return;
    };
    let a = a.to_str().unwrap();
    let r = s.run(&["list", a], None);
    assert_eq!(r.code, 1, "{}\n{}", r.text(), r.err);
    let t = r.text();
    assert!(t.lines().any(|l| l.ends_with(" a")), "{t}");
    assert!(t.lines().any(|l| l.ends_with(" b")), "{t}");
    assert!(!t.lines().any(|l| l.ends_with(" c")), "{t}");
    assert!(r.err.starts_with("telamon-archive-cli: "), "{}", r.err);
    assert!(
        r.err.trim().len() > "telamon-archive-cli:".len(),
        "{}",
        r.err
    );
    r.assert_clean();
    let r = s.run(&["list", "--json", a], None);
    assert_eq!(r.code, 1, "{}", r.err);
    let v = json_lines(&r);
    let last = &v.last().unwrap()["summary"];
    assert!(last["broken"].is_string(), "{last}");
    assert!(v.iter().any(|e| e["path"] == "b"));
    // A whole listing says null.
    let ok = sample(&s, "sample.zip");
    let r = s.run(&["list", "--json", ok.to_str().unwrap()], None);
    r.assert_ok();
    let v = json_lines(&r);
    assert!(v.last().unwrap()["summary"]["broken"].is_null());
    // Extracting half a listing writes nothing.
    let dest = s.dest();
    let r = s.run(&["extract", "--to", dest.to_str().unwrap(), a], None);
    assert_eq!(r.code, 1, "{}", r.err);
    assert!(s.ls(&dest).is_empty(), "{:?}", s.ls(&dest));
}
