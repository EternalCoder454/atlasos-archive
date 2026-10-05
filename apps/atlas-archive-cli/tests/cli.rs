//! The CLI binary against the real worker. Archives are made here (a small
//! zip writer, and `gzip` for the one bomb), or taken from the engine's
//! fixtures. Everything lives under `ATLAS_ARCHIVE_TEST_DIR`, never /tmp.

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const CLI: &str = env!("CARGO_BIN_EXE_atlas-archive-cli");

/// The worker built next to the CLI (`cargo build -p atlas-archive-worker`).
fn worker() -> Option<PathBuf> {
    let w = Path::new(CLI).parent()?.join("atlas-archive-worker");
    w.exists().then_some(w)
}

/// Skips the test, saying why, when the worker isn't built.
macro_rules! scratch {
    ($tag:expr) => {{
        match Scratch::new($tag) {
            Some(s) => s,
            None => {
                eprintln!(
                    "SKIPPED: build the worker first: cargo build -p atlas-archive-worker \
                     (same target dir as this test)"
                );
                return;
            }
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
        let base = std::env::var_os("ATLAS_ARCHIVE_TEST_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| Path::new(CLI).parent().unwrap().join("../test-scratch"));
        let root = base.join(format!("atlas-cli-{tag}-{}", std::process::id()));
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
            .join("../../crates/atlas-archive-engine/tests/data")
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
        let mut cmd = Command::new(CLI);
        cmd.arg("--worker")
            .arg(&self.worker)
            .args(args)
            .env("HOME", self.path("home"))
            .env("XDG_STATE_HOME", self.path("state"))
            .env("XDG_DATA_HOME", self.path("data"))
            .env("XDG_CACHE_HOME", self.path("cache"))
            .env("XDG_CONFIG_HOME", self.path("config"))
            .env_remove("DISPLAY")
            .env_remove("WAYLAND_DISPLAY")
            .stdin(Stdio::null());
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

fn read(p: impl AsRef<Path>) -> String {
    std::fs::read_to_string(p.as_ref()).unwrap_or_else(|e| panic!("{}: {e}", p.as_ref().display()))
}

// ---- list ----

#[test]
fn list_shows_a_table_in_display_form() {
    let s = scratch!("list");
    let a = sample(&s, "sample.zip");
    let r = s.run(&["list", a.to_str().unwrap(), "--encoding", "cp437"], None);
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
        &["list", a.to_str().unwrap(), "--json", "--encoding", "cp437"],
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
}

#[test]
fn list_of_an_encrypted_zip_names_it_encrypted() {
    let s = scratch!("listaes");
    let a = s.fixture("aes256-secret.zip");
    let r = s.run(&["list", a.to_str().unwrap(), "--json"], None);
    r.assert_ok();
    let t = r.text();
    assert!(t.contains("\"path\":\"f.txt\""), "{t}");
    assert!(t.contains("\"encrypted\":true"), "{t}");
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
    let r = s.run(&["info", a.to_str().unwrap(), "--json"], None);
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
    let r = s.run(&["test", a.to_str().unwrap(), "--json"], None);
    r.assert_ok();
    assert!(
        r.text().contains("{\"summary\":{\"ok\":true"),
        "{}",
        r.text()
    );
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
    let r = s.run(&["test", a.to_str().unwrap(), "--json"], None);
    assert_eq!(r.code, 1);
    assert!(r.text().contains("{\"skipped\":{"), "{}", r.text());
    assert!(r.text().contains("\"ok\":false"), "{}", r.text());
}

#[test]
fn passwords_come_from_a_descriptor() {
    let s = scratch!("pw");
    let a = s.fixture("aes256-secret.zip");
    let a = a.to_str().unwrap();
    let r = s.run(&["test", a, "--password-fd", "3"], Some("secret"));
    r.assert_ok();
    // None given and no terminal.
    let r = s.run(&["test", a], None);
    assert_eq!(r.code, 3, "{}", r.err);
    assert_eq!(
        r.err.trim(),
        "atlas-archive-cli: This archive needs a password: run in a terminal or use --password-fd."
    );
    // A wrong one.
    let r = s.run(&["test", a, "--password-fd", "3"], Some("wrong"));
    assert_eq!(r.code, 3, "{}", r.err);
    assert!(r.err.contains("didn't work"), "{}", r.err);
    assert!(!r.err.contains("wrong") || r.err.contains("didn't work"));
    // A descriptor that isn't open is a usage mistake.
    let r = s.run(&["test", a, "--password-fd", "77"], None);
    assert_eq!(r.code, 2, "{}", r.err);
}

#[test]
fn a_password_is_never_logged() {
    let s = scratch!("pwlog");
    let a = s.fixture("zipcrypto-secret.zip");
    let r = s.run(
        &["-v", "test", a.to_str().unwrap(), "--password-fd", "3"],
        Some("secret"),
    );
    r.assert_ok();
    assert!(!r.err.contains("secret"), "{}", r.err);
    assert!(!r.text().contains("secret"));
    let r = s.run(
        &["-v", "test", a.to_str().unwrap(), "--password-fd", "3"],
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
        s.ls(&s.root).iter().all(|n| !n.starts_with(".atlas")),
        "{:?}",
        s.ls(&s.root)
    );
    let jobs = s.ls(&s.path("state/atlas-archive/jobs"));
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
            a.to_str().unwrap(),
            "--to",
            dest.to_str().unwrap(),
        ],
        None,
    );
    r.assert_ok();
    assert_eq!(read(dest.join("sample/top.txt")), "top\n");
    assert!(!s.path("sample").exists());
    let r = s.run(
        &[
            "extract",
            a.to_str().unwrap(),
            "--to",
            dest.to_str().unwrap(),
            "--name",
            "Mine",
        ],
        None,
    );
    r.assert_ok();
    assert_eq!(read(dest.join("Mine/top.txt")), "top\n");
    // A name with a slash can't climb out: it is cleaned to one folder name.
    let r = s.run(
        &[
            "extract",
            a.to_str().unwrap(),
            "--to",
            dest.to_str().unwrap(),
            "--name",
            "../b",
        ],
        None,
    );
    r.assert_ok();
    assert!(!s.path("b").exists());
    assert_eq!(s.ls(&dest).len(), 3, "{:?}", s.ls(&dest));
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
        a.to_str().unwrap(),
        "--here",
        "--to",
        dest.to_str().unwrap(),
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
    let r = s.run(&[args.as_slice(), &["--on-clash", "skip"]].concat(), None);
    r.assert_ok();
    assert_eq!(s.ls(&dest), ["only", "only (2)"]);
    assert!(r.err.contains("Skip"), "{}", r.err);
    // --on-clash replace puts the new one in place; the old goes to the Trash.
    std::fs::write(dest.join("only/x.txt"), "changed\n").unwrap();
    let r = s.run(
        &[args.as_slice(), &["--on-clash", "replace"]].concat(),
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
            a.to_str().unwrap(),
            "--here",
            "--to",
            dest.to_str().unwrap(),
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
            a.to_str().unwrap(),
            "docs/sub",
            "top.txt",
            "--to",
            d,
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
            a.to_str().unwrap(),
            "nope.txt",
            "--to",
            d,
            "--name",
            "Other",
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
            a.to_str().unwrap(),
            "--json",
            "--to",
            dest.to_str().unwrap(),
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
            a.to_str().unwrap(),
            "--to",
            d,
            "--password-fd",
            "3",
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
            a.to_str().unwrap(),
            "--to",
            o,
            "--password-fd",
            "3",
        ],
        Some("nope"),
    );
    assert_eq!(r.code, 3, "{}", r.err);
    assert!(s.ls(&other).is_empty(), "{:?}", s.ls(&other));
    let r = s.run(&["extract", a.to_str().unwrap(), "--to", o], None);
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
            a.to_str().unwrap(),
            "--to",
            gone.to_str().unwrap(),
        ],
        None,
    );
    assert_eq!(r.code, 1, "{}", r.err);
    assert!(r.err.starts_with("atlas-archive-cli: "), "{}", r.err);
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
    let r = s.run(&["extract", a.to_str().unwrap(), "--to", d], None);
    assert_eq!(r.code, 4, "{}", r.err);
    assert!(r.err.contains("--allow-large"), "{}", r.err);
    assert!(s.ls(&dest).is_empty(), "{:?}", s.ls(&dest));
    let r = s.run(
        &["extract", a.to_str().unwrap(), "--to", d, "--allow-large"],
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
        vec!["list", a, "--bogus"],
        vec!["list", a, "--here"],
        vec!["extract", a, "--here", "--name", "x"],
        vec!["extract", a, "--on-clash", "maybe"],
        vec!["list", a, "--encoding", "klingon"],
        vec!["test", a, "--password-fd", "x"],
    ] {
        let r = s.run(&args, None);
        assert_eq!(r.code, 2, "{args:?}: {}", r.err);
        assert!(
            r.err.starts_with("atlas-archive-cli: "),
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
        "atlas-archive-cli: create isn't available yet"
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
    assert!(r.text().starts_with("atlas-archive-cli "), "{}", r.text());
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
            s.root
                .join(std::ffi::OsStr::from_bytes(&name))
                .into_os_string(),
            "--to".into(),
            dest.clone().into_os_string(),
        ],
        None,
    );
    r.assert_ok();
    r.assert_clean();
    assert_eq!(s.ls(&dest).len(), 1, "{:?}", s.ls(&dest));
}
