//! Starting a worker with exactly its descriptors, and talking to it
//! without ever blocking on it (docs/DESIGN.md, "The sandbox").

use std::fs::File;
use std::io::{self, Read};
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
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
/// The least a copy may be numbered, when `RLIMIT_NOFILE` leaves no room for
/// `HIGH_FD`: it only has to be above the targets, 3 and 4. The child's own
/// 0 to 2 are placed by dup2 over whatever is there, and the copies are close-on-exec.
const LOW_FD: RawFd = 5;
/// The longest log line kept, and the most lines per worker.
const LOG_LINE_MAX: usize = 512;
const LOG_LINES_MAX: usize = 200;
/// How long the wait for a killed worker may take before its drive is
/// called unresponsive (a process in uninterruptible I/O on a dead mount
/// doesn't die at SIGKILL until the I/O returns).
const KILL_WAIT: Duration = Duration::from_secs(10);
/// How long a SIGSTOP may take to show. Generous: a write held in the
/// kernel's writeback throttling on a slow USB stick returns to user mode
/// (and stops) only when its I/O allows.
const STOP_WAIT: Duration = Duration::from_secs(3);
/// The most workers that may be stuck in the kernel at once, process-wide,
/// each with a reaper thread and a log thread. Past it no job starts.
const MAX_STUCK: usize = 8;
/// Reaper threads that have not yet seen their worker end.
static REAPERS: AtomicUsize = AtomicUsize::new(0);
/// Stuck workers no reaper thread could be started for, tried again by
/// `check_capacity`; they count as stuck until they end.
static ORPHANS: Mutex<Vec<Child>> = Mutex::new(Vec::new());

/// The words for `check_capacity` failing; the client maps `ResourceBusy` to them.
pub const TOO_MANY_STUCK: &str = "Too many archive jobs are stuck on drives that don't respond.";

/// `Err(ResourceBusy)` when `MAX_STUCK` workers are still stuck on dead drives
/// (their drives came back, or not, since): a new job could only join them.
pub fn check_capacity() -> io::Result<()> {
    let orphans = {
        let mut o = ORPHANS.lock().unwrap_or_else(|p| p.into_inner());
        // A wait that errors means the child is gone for us as well.
        o.retain_mut(|c| matches!(c.try_wait(), Ok(None)));
        o.len()
    };
    if REAPERS.load(Ordering::SeqCst) + orphans >= MAX_STUCK {
        return Err(io::Error::new(io::ErrorKind::ResourceBusy, TOO_MANY_STUCK));
    }
    Ok(())
}

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
    /// The pidfd said the worker is gone (`ESRCH`): it may have been reaped
    /// by the kernel already, so its number may name something else now and
    /// nothing more is sent by number.
    gone: bool,
    killed: bool,
    input: Option<OwnedFd>,
    output: OwnedFd,
    buf: Vec<u8>,
    /// One read buffer for the whole job, not one per read.
    chunk: Vec<u8>,
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
            && (old.sa_sigaction == libc::SIG_IGN || old.sa_flags & libc::SA_NOCLDWAIT != 0)
    };
    if ignored {
        return Err(io::Error::other(
            "SIGCHLD is ignored (or children are not kept for waiting) by this program, so the archive reader can't be waited for",
        ));
    }
    check_capacity()?;
    // Copies above the target range first: the pipes std makes for 0 to 2 can
    // be any numbers, and placing one descriptor must never overwrite another
    // still to come.
    let a = dup_high(archive.as_fd())?;
    let s = staging.map(|s| dup_high(s.as_fd())).transpose()?;
    let (a_raw, s_raw) = (a.as_raw_fd(), s.as_ref().map(AsRawFd::as_raw_fd));

    // std's pipe that reports a failed exec takes the lowest free number in
    // the child. Were that 3 or 4, the `dup2` below would close it and a failed
    // exec would go unreported (the worker would just be gone, and the user
    // told it stopped). Two throwaway copies take the lowest free numbers from
    // 3 up for the duration of the spawn, so the pipe lands above 4. Best
    // effort: with no descriptor to spare, the spawn goes on without them.
    let holds = [
        sys::dup_above(archive.as_fd(), 3).ok(),
        sys::dup_above(archive.as_fd(), 3).ok(),
    ];
    // SAFETY: getpid takes no arguments and cannot fail.
    let parent = unsafe { libc::getpid() };
    let mut cmd = Command::new(exe);
    cmd.env_clear()
        .env("LANG", "C.UTF-8")
        .current_dir("/")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // Its own group, so a kill reaches 7z and unrar too.
        .process_group(0);
    // The user's own time zone, for the local times DOS-era entries store; it
    // is the user's environment, not archive input, but is still bounded.
    let tz = std::env::var("TZ").ok().filter(|t| tz_is_usable(t));
    if let Some(tz) = &tz {
        cmd.env("TZ", tz);
    }
    // SAFETY: the closure makes only async-signal-safe calls (signal,
    // sigprocmask, prctl, dup2, close, fcntl, syscall) and touches no memory
    // it didn't get before the fork.
    unsafe {
        cmd.pre_exec(move || {
            // Nothing the parent ignored or blocked may reach the worker.
            // (SIGKILL and SIGSTOP refuse with EINVAL, which is fine.)
            for sig in 1..=64 {
                libc::signal(sig, libc::SIG_DFL);
            }
            let mut empty: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut empty);
            libc::sigprocmask(libc::SIG_SETMASK, &empty, std::ptr::null_mut());
            // The worker dies with the thread that started it.
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL as libc::c_ulong) < 0 {
                return Err(io::Error::last_os_error());
            }
            // If the whole process ended between the fork and the prctl, the
            // signal guards nothing and the parent is already someone else.
            // (getppid is the parent's process id, not its thread's: a thread
            // that alone ended is not caught here, and the signal covers it
            // from the prctl on.)
            if libc::getppid() != parent {
                return Err(io::Error::from_raw_os_error(libc::ESRCH));
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
            // that reports a failed exec must live until then. It is numbered
            // above 4 because of the holds in `spawn`, bar a thread of the
            // program freeing a low descriptor at that very moment.)
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
    let spawned = cmd.spawn();
    drop((a, s, holds));
    let mut child = spawned?;
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
        gone: false,
        killed: false,
        input: None,
        output,
        buf: Vec::new(),
        chunk: vec![0u8; 64 * 1024],
        start: 0,
        timeout,
    };
    // Our ends only: a worker that doesn't read or write must never block us.
    sys::set_nonblocking(bfd(&input))?;
    sys::set_nonblocking(bfd(&running.output))?;
    running.input = Some(input);
    // The pipe must be drained or the worker would block on it; no thread
    // means no worker (`running` is killed and reaped as it drops).
    std::thread::Builder::new()
        .name("archive-worker-log".into())
        .spawn(move || drain_log(stderr))?;
    Ok(running)
}

/// A copy of `fd` numbered `HIGH_FD` or more, or at least `LOW_FD` when the
/// descriptor limit is too low for that.
fn dup_high(fd: std::os::fd::BorrowedFd<'_>) -> io::Result<OwnedFd> {
    match sys::dup_above(fd, HIGH_FD) {
        Err(e) if matches!(e.raw_os_error(), Some(libc::EINVAL | libc::EMFILE)) => {
            sys::dup_above(fd, LOW_FD)
        }
        r => r,
    }
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
            log::warn!("telamon-archive-worker: {text}");
        } else if *lines == LOG_LINES_MAX + 1 {
            log::warn!("telamon-archive-worker: more output was dropped");
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
    /// Sends `sig` to the worker itself: through the pidfd with no flags, which
    /// names this process and can't be redirected; by `kill(pid)` only where
    /// there is no pidfd (or it refuses) and the child is still unreaped, so
    /// the number is still its own. `true`: the signal went out.
    fn signal_worker(&mut self, sig: libc::c_int) -> bool {
        if self.gone {
            return false;
        }
        if let Some(p) = &self.pidfd {
            // SAFETY: a valid pidfd; no siginfo; no flags.
            let r = unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    p.as_raw_fd(),
                    sig,
                    std::ptr::null::<libc::siginfo_t>(),
                    0 as libc::c_uint,
                )
            };
            if r == 0 {
                return true;
            }
            if io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
                // Already gone, and maybe auto-reaped (SIGCHLD ignored): the
                // number may be reused, so no `kill` and no group signal.
                self.gone = true;
                return false;
            }
        }
        // SAFETY: kill takes no pointers; an unreaped child keeps its number.
        self.child.is_some() && unsafe { libc::kill(self.pid, sig) } == 0
    }

    /// Sends `sig` to the group the client made for the worker (its number is
    /// the worker's pid), so 7z and unrar are reached too. By `kill(-pid)`,
    /// never by the pidfd's group flag: that signals whatever group the worker
    /// is in at send time, and a hostile worker can move itself into the
    /// client's own group. Only while the child is unreaped: it pins the
    /// number, so it can't have been reused. `true`: the signal went out.
    fn signal_group(&self, sig: libc::c_int) -> bool {
        if self.gone {
            return false;
        }
        // SAFETY: kill takes no pointers; see above for why the number is ours.
        self.child.is_some() && unsafe { libc::kill(-self.pid, sig) } == 0
    }

    /// The worker first, then its group; `true` if either signal went out.
    /// Both always: the worker may have left the group, and the group may
    /// hold more than the worker.
    fn signal_both(&mut self, sig: libc::c_int) -> bool {
        let single = self.signal_worker(sig);
        let group = self.signal_group(sig);
        single || group
    }

    /// Stops the worker and its group (SIGSTOP) so that nothing writes while
    /// the user is asked a question. `false`: it could not be stopped. A
    /// stopped worker still dies at `finish` or when the thread ends.
    pub fn pause(&mut self) -> bool {
        let ok = self.signal_both(libc::SIGSTOP) && self.wait_stopped();
        if !ok {
            log::warn!("The archive reader couldn't be stopped for a question.");
        }
        ok
    }

    /// SIGSTOP is asynchronous: waits (at most `STOP_WAIT`) until the worker
    /// has really stopped, so nothing is written while the space is checked.
    /// Through the pidfd (`waitid` with `P_PIDFD`, which never reaps), else
    /// by number while the child is unreaped and the pidfd isn't readable.
    fn wait_stopped(&mut self) -> bool {
        let deadline = Instant::now() + STOP_WAIT;
        loop {
            match self.stopped_now() {
                Some(true) => return true,
                Some(false) => {}
                None => return false,
            }
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// `Some(stopped)`, or `None` when it can't be told (the worker is gone).
    fn stopped_now(&mut self) -> Option<bool> {
        if self.gone {
            return None;
        }
        const P_PIDFD: libc::c_long = 3;
        let opts = libc::WSTOPPED | libc::WNOHANG | libc::WNOWAIT | libc::WEXITED;
        let mut err = libc::EINVAL;
        if let Some(p) = &self.pidfd {
            // SAFETY: siginfo_t is plain data; all zeros is a valid value.
            let mut si: libc::siginfo_t = unsafe { std::mem::zeroed() };
            // SAFETY: a valid pidfd and siginfo; WNOWAIT never reaps.
            let r = unsafe {
                libc::syscall(
                    libc::SYS_waitid,
                    P_PIDFD,
                    p.as_raw_fd() as libc::c_long,
                    &mut si as *mut libc::siginfo_t,
                    opts,
                    std::ptr::null::<libc::rusage>(),
                )
            };
            if r == 0 {
                // SAFETY: filled by the successful call.
                return match (unsafe { si.si_pid() } != 0).then_some(si.si_code) {
                    Some(libc::CLD_STOPPED | libc::CLD_TRAPPED) => Some(true),
                    // Exited or killed: it can't be stopped.
                    Some(_) => None,
                    None => Some(false),
                };
            }
            err = io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EIO);
        }
        if err == libc::ESRCH {
            self.gone = true;
            return None;
        }
        // No pidfd waitid (an old kernel, or the kernel reaps for us): the
        // state letter in /proc, while the number is still ours.
        if self.child.is_none() && self.pidfd.is_none() {
            return None;
        }
        if let Some(p) = &self.pidfd {
            let mut fds = [libc::pollfd {
                fd: p.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            }];
            // SAFETY: one valid pollfd; no wait.
            if unsafe { libc::poll(fds.as_mut_ptr(), 1, 0) } > 0 {
                return None;
            }
        }
        let stat = std::fs::read_to_string(format!("/proc/{}/stat", self.pid)).ok()?;
        let state = stat.rsplit_once(')')?.1.trim_start().chars().next()?;
        Some(matches!(state, 'T' | 't'))
    }

    /// Lets a worker stopped by `pause` go on (SIGCONT).
    pub fn resume(&mut self) {
        if !self.signal_both(libc::SIGCONT) {
            log::warn!("The archive reader couldn't be continued.");
        }
    }

    /// How long a reply may go without the job advancing.
    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Sends one frame. The frame (a password may be in it) is wiped after.
    /// A worker that has already gone is not an error here: its replies, or
    /// their end, say what happened. Never raises SIGPIPE.
    pub fn send(&mut self, payload: &[u8], cancel: &Cancel) -> Result<(), Stop> {
        if payload.len() > MAX_FRAME {
            // Our own request, not the worker's reply: never blamed on it.
            return Err(Stop::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "the request is over one frame",
            )));
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
            // SAFETY: reads into a live buffer of the length passed.
            let n = unsafe {
                libc::read(
                    self.output.as_raw_fd(),
                    self.chunk.as_mut_ptr().cast(),
                    self.chunk.len(),
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
            self.buf.extend_from_slice(&self.chunk[..n as usize]);
        }
    }

    /// Whether the pidfd says the worker has ended, waiting until `deadline`.
    /// `false` with no pidfd or when it hasn't ended in time.
    fn gone_by_pidfd(&self, deadline: Instant) -> bool {
        let Some(p) = &self.pidfd else {
            return false;
        };
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let mut fds = [libc::pollfd {
                fd: p.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            }];
            let ms = remaining.as_millis().min(i32::MAX as u128) as i32 + 1;
            // SAFETY: one valid pollfd.
            let r = unsafe { libc::poll(fds.as_mut_ptr(), 1, ms) };
            if r > 0 {
                return fds[0].revents & (libc::POLLIN | libc::POLLHUP) != 0;
            }
            if r < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                return false;
            }
            if remaining.is_zero() {
                return false;
            }
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
            // The child is not reaped (only the code below does that), so
            // `pid` is still its pid and its group's id, and the pidfd names
            // it for good. SIGKILL ends a stopped worker too.
            // Not when the pidfd said it is gone: the number may be reused.
            if !self.signal_both(libc::SIGKILL)
                && !self.gone
                && let Some(c) = self.child.as_mut()
            {
                let _ = c.kill();
            }
        }
        let Some(child) = self.child.as_mut() else {
            return Err(io::Error::other("the archive reader was already reaped"));
        };
        let deadline = Instant::now() + KILL_WAIT;
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    self.child = None;
                    return Ok(status);
                }
                Ok(None) => {}
                Err(e) => {
                    // The host set SIGCHLD to be ignored since the spawn, so
                    // the kernel reaps the worker itself and `wait` can't
                    // say. The pidfd still tells when it is gone.
                    log::warn!("The archive reader's end can't be waited for: {e}");
                    if self.gone_by_pidfd(deadline) {
                        self.child = None;
                        return Err(io::Error::other(
                            "the archive reader ended, but not how (SIGCHLD is ignored)",
                        ));
                    }
                    break;
                }
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
                    let started = Instant::now();
                    let r = unsafe { libc::poll(fds.as_mut_ptr(), 1, ms) };
                    // Readable yet not reaped: don't spin on it.
                    if r > 0 && started.elapsed() < Duration::from_millis(10) {
                        std::thread::sleep(
                            deadline
                                .saturating_duration_since(Instant::now())
                                .min(Duration::from_millis(10)),
                        );
                    }
                }
                None => std::thread::sleep(remaining.min(Duration::from_millis(10))),
            }
        }
        // Still not gone. Hand the zombie-to-be to a thread that waits for it.
        // (`check_capacity` keeps the number of these down.)
        if let Some(child) = self.child.take() {
            let slot = Arc::new(Mutex::new(Some(child)));
            let theirs = Arc::clone(&slot);
            REAPERS.fetch_add(1, Ordering::SeqCst);
            let spawned = std::thread::Builder::new()
                .name("archive-worker-reaper".into())
                .spawn(move || {
                    let child = theirs.lock().unwrap_or_else(|p| p.into_inner()).take();
                    if let Some(mut child) = child {
                        let _ = child.wait();
                    }
                    REAPERS.fetch_sub(1, Ordering::SeqCst);
                });
            if let Err(e) = spawned {
                log::warn!("No thread to reap a stuck archive reader: {e}");
                REAPERS.fetch_sub(1, Ordering::SeqCst);
                // Keep the child: `check_capacity` looks at it again later.
                let child = slot.lock().unwrap_or_else(|p| p.into_inner()).take();
                if let Some(child) = child {
                    ORPHANS
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .push(child);
                }
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

/// A `TZ` worth passing on: a zoneinfo name or a POSIX TZ string, at most 256
/// bytes. One leading ':' is fine; a path (a leading '/'), a '..' component
/// and any character outside `[A-Za-z0-9_+-/,.:<>]` are not: the worker would
/// read whatever file it names.
fn tz_is_usable(tz: &str) -> bool {
    let name = tz.strip_prefix(':').unwrap_or(tz);
    !name.is_empty()
        && tz.len() <= 256
        && !name.starts_with('/')
        && !name.split('/').any(|c| c == "..")
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_+-/,.:<>".contains(&b))
}

/// What to tell the user when the worker ended without a final reply.
pub fn died(status: &io::Result<ExitStatus>) -> String {
    match status {
        Ok(s) => match (s.signal(), s.code()) {
            // Our own kill: it was still running when its replies ended.
            (Some(libc::SIGKILL), _) | (None, Some(0)) => {
                "The archive reader stopped unexpectedly.".into()
            }
            // The code or signal goes to the log (the caller has the status).
            (Some(libc::SIGSYS), _) => {
                "The archive reader broke one of its safety rules and was stopped.".into()
            }
            (Some(_), _) => "The archive reader crashed.".into(),
            // The worker's own refusal to start (its sandbox or pipes).
            (None, Some(2)) => {
                "The archive reader couldn't be set up safely, so it didn't run.".into()
            }
            (None, Some(_)) => "The archive reader stopped unexpectedly.".into(),
            (None, None) => "The archive reader stopped unexpectedly.".into(),
        },
        Err(_) => "The archive reader stopped unexpectedly.".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_sane_time_zone_is_passed_on() {
        assert!(tz_is_usable("Europe/Berlin"));
        assert!(tz_is_usable("EST5EDT,M3.2.0,M11.1.0"));
        assert!(!tz_is_usable(""));
        assert!(!tz_is_usable(&"x".repeat(257)));
        assert!(tz_is_usable(&"x".repeat(256)));
        assert!(!tz_is_usable("a\0b"));
        assert!(tz_is_usable(":Europe/Berlin"));
        assert!(tz_is_usable("<+03>-3"));
        assert!(!tz_is_usable("/etc/passwd"));
        assert!(!tz_is_usable(":/etc/passwd"));
        assert!(!tz_is_usable("../../etc/passwd"));
        assert!(!tz_is_usable("Europe/../../x"));
        assert!(!tz_is_usable("a b"));
        assert!(!tz_is_usable("a\nb"));
    }
}
