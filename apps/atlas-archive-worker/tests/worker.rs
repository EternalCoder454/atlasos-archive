//! Runs the real worker binary over its pipes, sandbox and all.

use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use atlas_archive_core::proto::{self, Reply, Request};
use zeroize::Zeroizing;

fn scratch(tag: &str) -> PathBuf {
    // On disk, in the cargo target dir, never in tmpfs.
    let base = std::env::var_os("ATLAS_ARCHIVE_TEST_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            std::env::current_exe()
                .unwrap()
                .parent()
                .unwrap()
                .join("../test-scratch")
        });
    let p = base.join(format!("atlas-worker-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    p
}

/// Puts each `(from, to)` in place in the child, without close-on-exec.
/// Every source is first copied above 100, so one placement can't overwrite
/// a source still to come (`from` may be another pair's `to`); the worker
/// closes the copies.
fn place(pairs: &[(RawFd, RawFd)]) -> std::io::Result<()> {
    let mut high = [(0, 0); 4];
    // SAFETY: async-signal-safe calls between fork and exec.
    unsafe {
        for (i, &(from, to)) in pairs.iter().enumerate() {
            let fd = libc::fcntl(from, libc::F_DUPFD_CLOEXEC, 100);
            if fd < 0 {
                return Err(std::io::Error::last_os_error());
            }
            high[i] = (fd, to);
        }
        for &(fd, to) in &high[..pairs.len()] {
            if libc::dup2(fd, to) < 0 {
                return Err(std::io::Error::last_os_error());
            }
        }
    }
    Ok(())
}

/// Runs one job: sends `requests`, answers no limit questions, and returns
/// every reply and the exit code.
fn run(archive: Option<&Path>, staging: Option<&Path>, requests: &[Request]) -> (Vec<Reply>, i32) {
    let archive = archive.map(|p| File::open(p).unwrap());
    let staging = staging.map(|p| File::open(p).unwrap());
    let (a, s) = (
        archive.as_ref().map(|f| f.as_raw_fd()),
        staging.as_ref().map(|f| f.as_raw_fd()),
    );
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_atlas-archive-worker"));
    cmd.env_clear()
        .env("LANG", "C.UTF-8")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        // Never the test's own stderr: that can be a terminal, which the
        // worker refuses.
        .stderr(Stdio::piped());
    // SAFETY: `place` only makes async-signal-safe calls.
    unsafe {
        cmd.pre_exec(move || match (a, s) {
            (Some(a), Some(s)) => place(&[(a, 3), (s, 4)]),
            (Some(a), None) => place(&[(a, 3)]),
            (None, Some(s)) => place(&[(s, 4)]),
            (None, None) => Ok(()),
        });
    }
    let mut child = cmd.spawn().unwrap();
    // Drained, so a worker that logs a lot never blocks on it.
    let mut log = child.stderr.take().unwrap();
    let log = std::thread::spawn(move || {
        let mut text = String::new();
        let _ = log.read_to_string(&mut text);
        text
    });
    let mut input = child.stdin.take().unwrap();
    for r in requests {
        proto::write_frame(&mut input, &r.encode()).unwrap();
    }
    // With no job asked for, the worker waits for one until the pipe closes.
    let mut input = (!requests.is_empty()).then_some(input);
    let mut output = child.stdout.take().unwrap();
    let mut replies = Vec::new();
    while let Some(frame) = proto::read_frame(&mut output).unwrap() {
        let reply = Reply::decode(&frame).unwrap();
        if let (Reply::Limit(_), Some(input)) = (&reply, input.as_mut()) {
            proto::write_frame(input, &Request::GoOn(false).encode()).unwrap();
        }
        replies.push(reply);
    }
    drop(input);
    let status = child.wait().unwrap();
    let log = log.join().unwrap();
    if !log.is_empty() {
        eprintln!("worker log: {log}");
    }
    (replies, status.code().unwrap_or(-1))
}

fn tar(dir: &Path) -> PathBuf {
    std::fs::create_dir_all(dir.join("src/top/sub")).unwrap();
    std::fs::write(dir.join("src/top/sub/f.txt"), b"content").unwrap();
    let out = dir.join("a.tar.gz");
    let ok = Command::new("tar")
        .arg("-czf")
        .arg(&out)
        .args(["-C", "src", "top"])
        .current_dir(dir)
        .status()
        .unwrap();
    assert!(ok.success());
    out
}

fn extract_request() -> Request {
    Request::Extract {
        encoding: "UTF-8".into(),
        entries: None,
        raw_name: "data".into(),
    }
}

#[test]
fn lists_and_extracts() {
    let d = scratch("basic");
    let a = tar(&d);
    let (replies, code) = run(Some(&a), None, &[Request::List]);
    assert_eq!(code, 0, "{replies:?}");
    assert!(
        matches!(replies.last(), Some(Reply::Listed { entries: 3 })),
        "{replies:?}"
    );
    assert!(
        replies
            .iter()
            .any(|r| matches!(r, Reply::Format(f) if f.name == "tar.gz"))
    );

    let staging = d.join("staging");
    std::fs::create_dir(&staging).unwrap();
    let (replies, code) = run(Some(&a), Some(&staging), &[extract_request()]);
    assert_eq!(code, 0);
    assert_eq!(
        replies.last(),
        Some(&Reply::Done {
            written: vec![b"top".to_vec()]
        }),
        "{replies:?}"
    );
    assert_eq!(
        std::fs::read(staging.join("top/sub/f.txt")).unwrap(),
        b"content"
    );
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn passwords_come_over_the_pipe() {
    let d = scratch("password");
    let a = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../crates/atlas-archive-engine/tests/data/aes256-secret.zip");
    let staging = d.join("staging");
    std::fs::create_dir(&staging).unwrap();
    let (replies, _) = run(Some(&a), Some(&staging), &[extract_request()]);
    assert_eq!(replies.last(), Some(&Reply::NeedPassword { wrong: false }));
    std::fs::remove_dir_all(&staging).unwrap();
    std::fs::create_dir(&staging).unwrap();
    let password = Request::Password(Zeroizing::new(b"secret".to_vec()));
    let (replies, code) = run(Some(&a), Some(&staging), &[password, extract_request()]);
    assert_eq!(code, 0);
    assert!(
        matches!(replies.last(), Some(Reply::Done { .. })),
        "{replies:?}"
    );
    assert_eq!(
        std::fs::read(staging.join("f.txt")).unwrap(),
        b"secret text\n"
    );
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn missing_pieces_fail_in_words() {
    let d = scratch("missing");
    let a = tar(&d);
    let (replies, code) = run(None, None, &[Request::List]);
    assert_eq!(code, 0);
    assert!(
        matches!(replies.last(), Some(Reply::Failed { reason }) if reason.contains("No archive"))
    );
    let (replies, _) = run(Some(&a), None, &[extract_request()]);
    assert!(
        matches!(replies.last(), Some(Reply::Failed { reason }) if reason.contains("No folder"))
    );
    // A folder is no archive.
    let (replies, _) = run(Some(&d), None, &[Request::List]);
    assert!(
        matches!(replies.last(), Some(Reply::Failed { reason }) if reason.contains("regular file"))
    );
    let (replies, _) = run(Some(&a), Some(&d), &[Request::GoOn(true)]);
    assert!(
        matches!(replies.last(), Some(Reply::Failed { reason }) if reason.contains("out of turn"))
    );
    // No request at all: the client went away.
    let (replies, code) = run(Some(&a), None, &[]);
    assert!(replies.is_empty());
    assert_eq!(code, 0);
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn arguments_are_refused() {
    let out = Command::new(env!("CARGO_BIN_EXE_atlas-archive-worker"))
        .arg("--help")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn leaked_descriptors_are_closed() {
    // A descriptor the client forgot (here: 7) must not reach the parser;
    // the worker still works.
    let d = scratch("leak");
    let a = tar(&d);
    let leak = File::open(&a).unwrap();
    let l = leak.as_raw_fd();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_atlas-archive-worker"));
    let archive = File::open(&a).unwrap();
    let ar = archive.as_raw_fd();
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    // SAFETY: async-signal-safe calls only.
    unsafe {
        cmd.pre_exec(move || place(&[(ar, 3), (l, 7)]));
    }
    let mut child = cmd.spawn().unwrap();
    // The worker closes it first thing, then (PR_SET_DUMPABLE 0) hides its
    // /proc entries from us: either sight means it is closed.
    let fd_dir = format!("/proc/{}/fd", child.id());
    let has_7 = || match std::fs::read_dir(&fd_dir) {
        Ok(dir) => dir.filter_map(|e| e.ok()).any(|e| e.file_name() == "7"),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => false,
        Err(e) => panic!("{e}"),
    };
    let start = std::time::Instant::now();
    while has_7() {
        assert!(start.elapsed().as_secs() < 10, "descriptor 7 still open");
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let mut input = child.stdin.take().unwrap();
    proto::write_frame(&mut input, &Request::List.encode()).unwrap();
    input.flush().unwrap();
    drop(input);
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    drop(leak);
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn a_terminal_is_refused() {
    // A pty as the worker's stderr: it says so on the reply pipe and exits
    // with 2 before reading a request.
    let (mut master, mut slave) = (-1, -1);
    // SAFETY: valid out-pointers; null name, termios and window size.
    let r = unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
        )
    };
    assert_eq!(r, 0, "openpty: {}", std::io::Error::last_os_error());
    // SAFETY: two new descriptors, owned from here.
    let (master, slave) = unsafe { (OwnedFd::from_raw_fd(master), OwnedFd::from_raw_fd(slave)) };
    let mut child = Command::new(env!("CARGO_BIN_EXE_atlas-archive-worker"))
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::from(slave))
        .spawn()
        .unwrap();
    let mut output = child.stdout.take().unwrap();
    let frame = proto::read_frame(&mut output).unwrap().expect("a reply");
    let reply = Reply::decode(&frame).unwrap();
    assert!(
        matches!(&reply, Reply::Failed { reason } if reason.contains("terminal")),
        "{reply:?}"
    );
    drop(child.stdin.take());
    assert_eq!(child.wait().unwrap().code(), Some(2));
    drop(master);
}
