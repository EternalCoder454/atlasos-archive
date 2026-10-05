//! Starting a worker with exactly its descriptors, and talking to it
//! without ever blocking on it (docs/DESIGN.md, "The sandbox").

use std::fs::File;
use std::io::{self, Read};
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use super::sys::{self, bfd};
use crate::proto::{MAX_FRAME, ProtoError, Reply};

/// The worker's descriptors (docs/DESIGN.md): the archive and the staging folder.
const ARCHIVE_FD: RawFd = 3;
const STAGING_FD: RawFd = 4;
/// Where the parent keeps its copies until the child places them: above
/// everything std or the caller can have opened as 0 to 4.
const HIGH_FD: RawFd = 100;
/// The longest log line kept, and the most lines per worker.
const LOG_LINE_MAX: usize = 512;
const LOG_LINES_MAX: usize = 200;

/// Stops a running job from any thread. Cheap to clone; every clone is the
/// same handle.
#[derive(Clone, Debug)]
pub struct Cancel {
    inner: Arc<CancelInner>,
}

#[derive(Debug)]
struct CancelInner {
    flag: AtomicBool,
    /// Wakes the job thread out of `poll`; without one (no descriptors left)
    /// the job notices within `SLICE`.
    event: Option<OwnedFd>,
}

/// How long a wait goes without looking at the flag, when it has no eventfd.
const SLICE: Duration = Duration::from_millis(100);

impl Cancel {
    pub fn new() -> Cancel {
        // SAFETY: eventfd takes no pointers; the result is a new descriptor.
        let fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
        let event = if fd >= 0 {
            // SAFETY: a new descriptor we own.
            Some(unsafe { OwnedFd::from_raw_fd(fd) })
        } else {
            log::warn!("No eventfd for cancelling: {}", io::Error::last_os_error());
            None
        };
        Cancel {
            inner: Arc::new(CancelInner {
                flag: AtomicBool::new(false),
                event,
            }),
        }
    }

    /// Asks the job to stop: its worker is killed and nothing is left behind.
    pub fn cancel(&self) {
        self.inner.flag.store(true, Ordering::SeqCst);
        if let Some(fd) = &self.inner.event {
            let one = 1u64.to_ne_bytes();
            // SAFETY: writes 8 bytes from a live buffer; a full counter
            // (EAGAIN) means it is readable already.
            unsafe { libc::write(fd.as_raw_fd(), one.as_ptr().cast(), one.len()) };
        }
    }

    pub fn is_cancelled(&self) -> bool {
        self.inner.flag.load(Ordering::SeqCst)
    }

    fn fd(&self) -> Option<RawFd> {
        self.inner.event.as_ref().map(AsRawFd::as_raw_fd)
    }
}

impl Default for Cancel {
    fn default() -> Cancel {
        Cancel::new()
    }
}

/// Why a conversation with the worker stopped.
#[derive(Debug)]
pub enum Stop {
    /// Nothing came for the whole timeout.
    Timeout,
    Cancelled,
    /// The worker closed its replies.
    Eof,
    /// A frame that isn't one.
    Proto(ProtoError),
    Io(io::Error),
}

enum Ready {
    Yes,
    Cancelled,
    TimedOut,
}

/// Waits until `fd` has `events`, the job is cancelled or `deadline` passes.
fn wait(fd: RawFd, events: i16, cancel: &Cancel, deadline: Instant) -> io::Result<Ready> {
    loop {
        if cancel.is_cancelled() {
            return Ok(Ready::Cancelled);
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(Ready::TimedOut);
        }
        let slice = if cancel.fd().is_some() {
            remaining
        } else {
            remaining.min(SLICE)
        };
        let mut fds = [
            libc::pollfd {
                fd,
                events,
                revents: 0,
            },
            libc::pollfd {
                fd: cancel.fd().unwrap_or(-1),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        // Rounded up: waking a hair early only costs one more turn.
        let ms = slice.as_millis().min(i32::MAX as u128) as i32 + 1;
        // SAFETY: two valid pollfd structs; a negative fd is ignored.
        let r = unsafe { libc::poll(fds.as_mut_ptr(), 2, ms) };
        if r < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        if fds[1].revents != 0 {
            return Ok(Ready::Cancelled);
        }
        if fds[0].revents != 0 {
            return Ok(Ready::Yes);
        }
    }
}

/// A running worker. It is killed and reaped by `finish` or, failing that,
/// when this is dropped.
pub struct Running {
    child: Child,
    input: Option<OwnedFd>,
    output: OwnedFd,
    buf: Vec<u8>,
    start: usize,
    reaped: bool,
    timeout: Duration,
}

/// Opens the archive for a worker: read-only, never blocking on a pipe, and
/// a regular file (the worker checks too; this is the first answer).
pub fn open_archive(path: &Path) -> io::Result<File> {
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    let m = f.metadata()?;
    if !m.is_file() {
        let what = if m.is_dir() {
            "a folder"
        } else if m.file_type().is_fifo() || m.file_type().is_socket() {
            "a pipe or socket"
        } else {
            "a device"
        };
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("This is {what}, not an archive file."),
        ));
    }
    Ok(f)
}

/// Starts `exe` with the archive on 3 and, when given, the staging folder on 4.
pub fn spawn(
    exe: &Path,
    timeout: Duration,
    archive: &File,
    staging: Option<&OwnedFd>,
) -> io::Result<Running> {
    // Copies above the target range first: the pipes std makes for 0 to 2 can
    // be any numbers, and placing one descriptor must never overwrite another
    // still to come.
    let a = sys::dup_above(archive.as_fd(), HIGH_FD)?;
    let s = staging
        .map(|s| sys::dup_above(s.as_fd(), HIGH_FD))
        .transpose()?;
    let (a_raw, s_raw) = (a.as_raw_fd(), s.as_ref().map(AsRawFd::as_raw_fd));

    let mut cmd = Command::new(exe);
    cmd.env_clear()
        .env("LANG", "C.UTF-8")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // Its own group, so a kill reaches 7z and unrar too.
        .process_group(0);
    // SAFETY: the closure makes only async-signal-safe calls (dup2, close,
    // prctl) and touches no memory it didn't get before the fork.
    unsafe {
        cmd.pre_exec(move || {
            // The worker dies with the thread that started it.
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL as libc::c_ulong) < 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::dup2(a_raw, ARCHIVE_FD) < 0 {
                return Err(io::Error::last_os_error());
            }
            match s_raw {
                Some(s) => {
                    if libc::dup2(s, STAGING_FD) < 0 {
                        return Err(io::Error::last_os_error());
                    }
                }
                None => {
                    // Nothing else may pose as a staging folder.
                    libc::close(STAGING_FD);
                }
            }
            Ok(())
        });
    }
    let mut child = cmd.spawn()?;
    drop((a, s));

    let (Some(stdin), Some(stdout), Some(stderr)) =
        (child.stdin.take(), child.stdout.take(), child.stderr.take())
    else {
        let _ = child.kill();
        let _ = child.wait();
        return Err(io::Error::other("the worker's pipes are missing"));
    };
    let (input, output) = (OwnedFd::from(stdin), OwnedFd::from(stdout));
    let mut running = Running {
        child,
        input: None,
        output,
        buf: Vec::new(),
        start: 0,
        reaped: false,
        timeout,
    };
    // Our ends only: a worker that doesn't read or write must never block us.
    sys::set_nonblocking(bfd(&input))?;
    sys::set_nonblocking(bfd(&running.output))?;
    running.input = Some(input);
    // The pipe must be drained or the worker would block on it; no thread
    // means no worker.
    std::thread::Builder::new()
        .name("archive-worker-log".into())
        .spawn(move || drain_log(stderr))?;
    Ok(running)
}

/// Copies the worker's stderr into the log: capped lines, capped count, no
/// control characters. Never request frames; the worker doesn't log those.
fn drain_log(mut err: impl Read) {
    let mut line: Vec<u8> = Vec::new();
    let mut lines = 0usize;
    let mut chunk = [0u8; 4096];
    let flush = |line: &mut Vec<u8>, lines: &mut usize| {
        if line.is_empty() {
            return;
        }
        *lines += 1;
        if *lines <= LOG_LINES_MAX {
            let text: String = String::from_utf8_lossy(line)
                .chars()
                .map(|c| if c.is_control() { '?' } else { c })
                .collect();
            log::warn!("atlas-archive-worker: {text}");
        } else if *lines == LOG_LINES_MAX + 1 {
            log::warn!("atlas-archive-worker: more output was dropped");
        }
        line.clear();
    };
    loop {
        match err.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                for &b in &chunk[..n] {
                    if b == b'\n' {
                        flush(&mut line, &mut lines);
                    } else if line.len() < LOG_LINE_MAX {
                        line.push(b);
                    }
                }
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
    flush(&mut line, &mut lines);
}

impl Running {
    /// Sends one frame. The frame (a password may be in it) is wiped after.
    /// A worker that has already gone is not an error here: its replies, or
    /// their end, say what happened.
    pub fn send(&mut self, payload: &[u8], cancel: &Cancel) -> Result<(), Stop> {
        if payload.len() > MAX_FRAME {
            return Err(Stop::Proto(ProtoError::TooLarge));
        }
        let mut frame = Zeroizing::new(Vec::with_capacity(4 + payload.len()));
        frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        frame.extend_from_slice(payload);
        let deadline = Instant::now() + self.timeout;
        let mut at = 0;
        while at < frame.len() {
            let Some(input) = &self.input else {
                return Ok(());
            };
            let fd = input.as_raw_fd();
            // SAFETY: writes from the live, in-bounds rest of `frame`.
            let n = unsafe { libc::write(fd, frame[at..].as_ptr().cast(), frame.len() - at) };
            if n >= 0 {
                at += n as usize;
                continue;
            }
            let e = io::Error::last_os_error();
            match e.kind() {
                io::ErrorKind::Interrupted => {}
                io::ErrorKind::WouldBlock => {
                    match wait(fd, libc::POLLOUT, cancel, deadline).map_err(Stop::Io)? {
                        Ready::Yes => {}
                        Ready::Cancelled => return Err(Stop::Cancelled),
                        Ready::TimedOut => return Err(Stop::Timeout),
                    }
                }
                io::ErrorKind::BrokenPipe => {
                    log::debug!("The worker closed its request pipe.");
                    self.input = None;
                    return Ok(());
                }
                _ => return Err(Stop::Io(e)),
            }
        }
        Ok(())
    }

    /// The next reply, and the length of its frame. The timeout covers this
    /// call alone, so it restarts with every frame, and doesn't run while the
    /// caller is away answering a question.
    pub fn recv(&mut self, cancel: &Cancel) -> Result<(Reply, usize), Stop> {
        let deadline = Instant::now() + self.timeout;
        loop {
            let avail = &self.buf[self.start..];
            if avail.len() >= 4 {
                let len = u32::from_le_bytes([avail[0], avail[1], avail[2], avail[3]]) as usize;
                if len > MAX_FRAME {
                    return Err(Stop::Proto(ProtoError::TooLarge));
                }
                if avail.len() >= 4 + len {
                    let reply = Reply::decode(&avail[4..4 + len]).map_err(Stop::Proto)?;
                    self.start += 4 + len;
                    return Ok((reply, len));
                }
            }
            match wait(self.output.as_raw_fd(), libc::POLLIN, cancel, deadline).map_err(Stop::Io)? {
                Ready::Yes => {}
                Ready::Cancelled => return Err(Stop::Cancelled),
                Ready::TimedOut => return Err(Stop::Timeout),
            }
            if self.start > 0 {
                self.buf.drain(..self.start);
                self.start = 0;
            }
            let mut chunk = [0u8; 64 * 1024];
            // SAFETY: reads into a live buffer of the length passed.
            let n = unsafe {
                libc::read(
                    self.output.as_raw_fd(),
                    chunk.as_mut_ptr().cast(),
                    chunk.len(),
                )
            };
            if n == 0 {
                return Err(if self.buf.is_empty() {
                    Stop::Eof
                } else {
                    // Ended inside a frame.
                    Stop::Proto(ProtoError::Truncated)
                });
            }
            if n < 0 {
                let e = io::Error::last_os_error();
                match e.kind() {
                    io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock => continue,
                    _ => return Err(Stop::Io(e)),
                }
            }
            self.buf.extend_from_slice(&chunk[..n as usize]);
        }
    }

    /// Kills the worker and everything in its group, then reaps it. The kill
    /// goes out before the reap, while the number still names our child: it
    /// can't have been reused. Nothing else may look at the staging folder
    /// before this returns.
    pub fn finish(&mut self) -> io::Result<ExitStatus> {
        if !self.reaped {
            let pid = self.child.id() as libc::pid_t;
            // SAFETY: the child is not reaped (only `wait` below does that),
            // so `pid` is still its pid and its group's id.
            unsafe { libc::kill(-pid, libc::SIGKILL) };
            // The group may be gone while the child is not (setpgid failed).
            let _ = self.child.kill();
            self.reaped = true;
        }
        self.child.wait()
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        if !self.reaped
            && let Err(e) = self.finish()
        {
            log::warn!("The archive reader couldn't be reaped: {e}");
        }
    }
}

/// What to tell the user when the worker ended without a final reply.
pub fn died(status: &io::Result<ExitStatus>) -> String {
    match status {
        Ok(s) => match (s.signal(), s.code()) {
            // Our own kill: it was still running when its replies ended.
            (Some(libc::SIGKILL), _) | (None, Some(0)) => {
                "The archive reader stopped unexpectedly.".into()
            }
            (Some(sig), _) => format!("The archive reader crashed (signal {sig})."),
            (None, Some(code)) => {
                format!("The archive reader stopped unexpectedly (exit code {code}).")
            }
            (None, None) => "The archive reader stopped unexpectedly.".into(),
        },
        Err(_) => "The archive reader stopped unexpectedly.".into(),
    }
}
