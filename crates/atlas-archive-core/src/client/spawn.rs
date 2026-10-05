//! Starting a worker with exactly its descriptors, and talking to it
//! without ever blocking on it (docs/DESIGN.md, "The sandbox").

use std::fs::File;
use std::io::{self, Read};
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd, RawFd};
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
/// How long the wait for a killed worker may take before its drive is
/// called unresponsive (a process in uninterruptible I/O on a dead mount
/// doesn't die at SIGKILL until the I/O returns).
const KILL_WAIT: Duration = Duration::from_secs(10);

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
    /// `None` once reaped, or handed to a reaper thread.
    child: Option<Child>,
    pid: libc::pid_t,
    /// A handle on the child that can't name a later process; `None` where
    /// the kernel has no `pidfd_open` (before Linux 5.3).
    pidfd: Option<OwnedFd>,
    killed: bool,
    input: Option<OwnedFd>,
    output: OwnedFd,
    buf: Vec<u8>,
    start: usize,
    timeout: Duration,
}

/// Opens the archive for a worker: first with `O_PATH`, which never blocks
/// and never reads, to learn what it is, then for reading, and only if it is a
/// regular file and the same one. This can still block on a dead network or
/// removable mount: call it off the UI thread.
pub fn open_archive(path: &Path) -> io::Result<File> {
    use std::os::unix::ffi::OsStrExt;
    let c = sys::cstr(path.as_os_str().as_bytes())?;
    let open = |p: &std::ffi::CStr, flags: i32| -> io::Result<OwnedFd> {
        sys::retry(|| {
            // SAFETY: a C string; a new descriptor we own.
            let fd = unsafe { libc::open(p.as_ptr(), flags) };
            if fd < 0 {
                Err(io::Error::last_os_error())
            } else {
                // SAFETY: a new descriptor returned by a successful call.
                Ok(unsafe { OwnedFd::from_raw_fd(fd) })
            }
        })
    };
    let probe = open(&c, libc::O_PATH | libc::O_CLOEXEC)?;
    let first = sys::fstat(bfd(&probe))?;
    let kind = first.st_mode & libc::S_IFMT;
    if kind != libc::S_IFREG {
        let what = match kind {
            libc::S_IFDIR => "a folder",
            libc::S_IFIFO | libc::S_IFSOCK => "a pipe or socket",
            _ => "a device",
        };
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("This is {what}, not an archive file."),
        ));
    }
    let flags = libc::O_RDONLY | libc::O_NOCTTY | libc::O_CLOEXEC;
    // Through the probe descriptor, the very file just looked at; by path
    // (and then compared) only when /proc isn't there.
    let via_proc = sys::cstr(format!("/proc/self/fd/{}", probe.as_raw_fd()).as_bytes())?;
    let fd = match open(&via_proc, flags) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => open(&c, flags)?,
        r => r?,
    };
    let second = sys::fstat(bfd(&fd))?;
    if second.st_mode & libc::S_IFMT != libc::S_IFREG || !sys::same_file(&first, &second) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "The archive changed while it was being opened.",
        ));
    }
    Ok(File::from(fd))
}

/// Starts `exe` with the archive on 3 and, when given, the staging folder on 4.
///
/// The worker gets `PR_SET_PDEATHSIG`: it dies with the *thread* that started
/// it, so the calling thread must live until the job returns. A program that
/// ignores `SIGCHLD` (`SIG_IGN`) can't wait for its children: that is refused.
pub fn spawn(
    exe: &Path,
    timeout: Duration,
    archive: &File,
    staging: Option<&OwnedFd>,
) -> io::Result<Running> {
    // SAFETY: sigaction with a null new action only reads the current one.
    let ignored = unsafe {
        let mut old: libc::sigaction = std::mem::zeroed();
        libc::sigaction(libc::SIGCHLD, std::ptr::null(), &mut old) == 0
            && old.sa_sigaction == libc::SIG_IGN
    };
    if ignored {
        return Err(io::Error::other(
            "SIGCHLD is ignored by this program, so the archive reader can't be waited for",
        ));
    }
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
        .current_dir("/")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // Its own group, so a kill reaches 7z and unrar too.
        .process_group(0);
    // SAFETY: the closure makes only async-signal-safe calls (signal,
    // sigprocmask, prctl, dup2, close, fcntl, syscall) and touches no memory
    // it didn't get before the fork.
    unsafe {
        cmd.pre_exec(move || {
            // Nothing the parent ignored or blocked may reach the worker.
            for sig in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGPIPE] {
                libc::signal(sig, libc::SIG_DFL);
            }
            let mut empty: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut empty);
            libc::sigprocmask(libc::SIG_SETMASK, &empty, std::ptr::null_mut());
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
            // Everything above 4 is closed at exec, whatever the parent left
            // open without close-on-exec. (Marked, not closed now: std's pipe
            // that reports a failed exec must live until then.)
            let first_extra: libc::c_uint = 5;
            let r = libc::syscall(
                libc::SYS_close_range,
                first_extra,
                libc::c_uint::MAX,
                libc::CLOSE_RANGE_CLOEXEC,
            );
            if r < 0 {
                // Before Linux 5.11: mark them one by one.
                for fd in first_extra as libc::c_int..4096 {
                    libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
                }
            }
            Ok(())
        });
    }
    let mut child = cmd.spawn()?;
    drop((a, s));
    let pid = child.id() as libc::pid_t;
    // Right away: the child is not reaped (only we reap it), so the number
    // can't have been reused yet.
    // SAFETY: pidfd_open takes no pointers; the result is a new descriptor.
    let pidfd = unsafe {
        let r = libc::syscall(libc::SYS_pidfd_open, pid, 0);
        (r >= 0).then(|| OwnedFd::from_raw_fd(r as libc::c_int))
    };

    let (Some(stdin), Some(stdout), Some(stderr)) =
        (child.stdin.take(), child.stdout.take(), child.stderr.take())
    else {
        let _ = child.kill();
        let _ = child.wait();
        return Err(io::Error::other("the worker's pipes are missing"));
    };
    let (input, output) = (OwnedFd::from(stdin), OwnedFd::from(stdout));
    let mut running = Running {
        child: Some(child),
        pid,
        pidfd,
        killed: false,
        input: None,
        output,
        buf: Vec::new(),
        start: 0,
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
/// control or format characters. Never request frames; the worker doesn't log those.
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
            let text = sys::sanitize(&String::from_utf8_lossy(line), usize::MAX, '?');
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

/// `write` that can't raise SIGPIPE. The GUI's C++ `main` leaves SIGPIPE at
/// its default, and a plain write to a pipe whose reader is gone would kill
/// the process. This blocks SIGPIPE on this thread for the call, and on EPIPE
/// takes the signal that call made (thread-directed, so it is pending on this
/// thread alone) before the old mask returns. No process-wide state changes.
fn write_no_sigpipe(fd: RawFd, buf: &[u8]) -> io::Result<usize> {
    // SAFETY: sigset operations on local, zeroed sets; the mask is restored
    // before returning; write reads from a live buffer of the length passed.
    unsafe {
        let mut pipe: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut pipe);
        libc::sigaddset(&mut pipe, libc::SIGPIPE);
        let mut old: libc::sigset_t = std::mem::zeroed();
        let rc = libc::pthread_sigmask(libc::SIG_BLOCK, &pipe, &mut old);
        if rc != 0 {
            return Err(io::Error::from_raw_os_error(rc));
        }
        let was_blocked = libc::sigismember(&old, libc::SIGPIPE) == 1;
        let n = libc::write(fd, buf.as_ptr().cast(), buf.len());
        let err = (n < 0).then(io::Error::last_os_error);
        if !was_blocked && err.as_ref().and_then(|e| e.raw_os_error()) == Some(libc::EPIPE) {
            let zero = libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            loop {
                let r = libc::sigtimedwait(&pipe, std::ptr::null_mut(), &zero);
                if r < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                break;
            }
        }
        libc::pthread_sigmask(libc::SIG_SETMASK, &old, std::ptr::null_mut());
        match err {
            Some(e) => Err(e),
            None => Ok(n as usize),
        }
    }
}

impl Running {
    /// How long a reply may go without the job advancing.
    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Sends one frame. The frame (a password may be in it) is wiped after.
    /// A worker that has already gone is not an error here: its replies, or
    /// their end, say what happened. Never raises SIGPIPE.
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
            match write_no_sigpipe(fd, &frame[at..]) {
                Ok(n) => at += n,
                Err(e) => match e.kind() {
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
                },
            }
        }
        Ok(())
    }

    /// The next reply, and the length of its frame, or `None` when `tick`
    /// passed first (the caller looks at the staging folder and asks again).
    /// Waits no longer than `deadline`; it is the caller's to move, and the
    /// time the caller spends away isn't counted.
    pub fn recv(
        &mut self,
        cancel: &Cancel,
        deadline: Instant,
        tick: Option<Duration>,
    ) -> Result<Option<(Reply, usize)>, Stop> {
        let wake = tick.map(|t| Instant::now() + t);
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
                    return Ok(Some((reply, len)));
                }
            }
            let until = wake.map_or(deadline, |w| w.min(deadline));
            match wait(self.output.as_raw_fd(), libc::POLLIN, cancel, until).map_err(Stop::Io)? {
                Ready::Yes => {}
                Ready::Cancelled => return Err(Stop::Cancelled),
                Ready::TimedOut if Instant::now() >= deadline => return Err(Stop::Timeout),
                Ready::TimedOut => return Ok(None),
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

    /// Kills the worker and everything in its group, then reaps it, waiting
    /// at most `KILL_WAIT`. The kill goes out before the reap, while the
    /// number still names our child (and the pidfd names it for good), so it
    /// can't have been reused. Nothing else may look at the staging folder
    /// before this returns `Ok`.
    ///
    /// On `ErrorKind::TimedOut` the worker is stuck in the kernel (a dead
    /// mount): it stays a zombie-to-be, reaped by a detached thread whenever
    /// it ends, and the caller must leave the staging folder alone.
    pub fn finish(&mut self) -> io::Result<ExitStatus> {
        if !self.killed {
            self.killed = true;
            // SAFETY: the child is not reaped (only the code below does
            // that), so `pid` is still its pid and its group's id.
            unsafe { libc::kill(-self.pid, libc::SIGKILL) };
            let sent = self.pidfd.as_ref().is_some_and(|p| {
                // SAFETY: a valid pidfd; no siginfo, no flags.
                unsafe {
                    libc::syscall(
                        libc::SYS_pidfd_send_signal,
                        p.as_raw_fd(),
                        libc::SIGKILL,
                        std::ptr::null::<libc::siginfo_t>(),
                        0,
                    ) == 0
                }
            });
            // The group may be gone while the child is not (setpgid failed).
            if !sent && let Some(c) = self.child.as_mut() {
                let _ = c.kill();
            }
        }
        let Some(child) = self.child.as_mut() else {
            return Err(io::Error::other("the archive reader was already reaped"));
        };
        let deadline = Instant::now() + KILL_WAIT;
        loop {
            if let Some(status) = child.try_wait()? {
                self.child = None;
                return Ok(status);
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            match &self.pidfd {
                Some(p) => {
                    let mut fds = [libc::pollfd {
                        fd: p.as_raw_fd(),
                        events: libc::POLLIN,
                        revents: 0,
                    }];
                    let ms = remaining.as_millis().min(i32::MAX as u128) as i32 + 1;
                    // SAFETY: one valid pollfd; EINTR just loops.
                    unsafe { libc::poll(fds.as_mut_ptr(), 1, ms) };
                }
                None => std::thread::sleep(remaining.min(Duration::from_millis(10))),
            }
        }
        // Still not gone. Hand the zombie-to-be to a thread that waits for it.
        if let Some(mut child) = self.child.take() {
            let spawned = std::thread::Builder::new()
                .name("archive-worker-reaper".into())
                .spawn(move || {
                    let _ = child.wait();
                });
            if let Err(e) = spawned {
                log::warn!("No thread to reap a stuck archive reader: {e}");
            }
        }
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "The archive's drive isn't responding.",
        ))
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        if self.child.is_some()
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
