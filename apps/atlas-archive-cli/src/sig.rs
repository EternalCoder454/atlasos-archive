//! Ctrl-C, Ctrl-\, SIGTERM and SIGHUP: blocked in every thread, taken by one
//! thread with `sigwait`, which cancels the job through the client. Nothing
//! runs in a signal handler. A second signal, or one while no job is
//! running, ends the program at once (exit 130) with the terminal put back,
//! so a stuck job never ignores them. Ctrl-Z (SIGTSTP) is blocked and never
//! taken: the process can't be stopped with echo off at a password prompt.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use atlas_archive_core::client::Cancel;

pub struct Signals {
    interrupted: Arc<AtomicBool>,
    wake: Arc<OwnedFd>,
    busy: Arc<AtomicUsize>,
}

/// While it lives, a job is running that a first signal can cancel.
pub struct Busy(Arc<AtomicUsize>);

impl Drop for Busy {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// The signal thread's name: the panic hook knows it by this.
pub const THREAD: &str = "signals";

/// What the signal thread does with a signal it took.
#[derive(Debug, PartialEq, Eq)]
enum Action {
    /// Cancel the running job and keep waiting.
    Cancel,
    /// A second signal, or none to cancel: leave at once.
    Leave,
}

/// `flag` says a signal came before (it is set by this call); `busy` counts
/// the guards of running jobs.
fn decide(flag: &AtomicBool, busy: &AtomicUsize) -> Action {
    if flag.swap(true, Ordering::SeqCst) || busy.load(Ordering::SeqCst) == 0 {
        Action::Leave
    } else {
        Action::Cancel
    }
}

/// Ends the program with the cancelled code. Only async-signal-safe calls
/// besides the terminal restore, and no locks on stderr.
fn exit_now() -> ! {
    leave(b"\natlas-archive-cli: Cancelled.\n")
}

/// Ends the program with the cancelled code and `msg` on stderr.
pub fn leave(msg: &[u8]) -> ! {
    crate::term::restore_terminal();
    // SAFETY: writes from a live buffer; the result can't be used anyway.
    unsafe {
        libc::write(libc::STDERR_FILENO, msg.as_ptr().cast(), msg.len());
        libc::_exit(crate::error::EXIT_CANCELLED)
    }
}

fn set(signals: &[libc::c_int]) -> libc::sigset_t {
    // SAFETY: sigemptyset initialises the set; sigaddset takes valid numbers.
    unsafe {
        let mut s: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut s);
        for &n in signals {
            libc::sigaddset(&mut s, n);
        }
        s
    }
}

/// Blocks the signals in this thread, and so in every thread started after
/// it: call it first thing in `main`, before anything starts a thread.
pub fn block() -> io::Result<()> {
    // The terminal-control signals are blocked too, so a prompt in a
    // background job fails with an error instead of stopping the process.
    let all = set(&[
        libc::SIGINT,
        libc::SIGQUIT,
        libc::SIGTERM,
        libc::SIGHUP,
        libc::SIGTSTP,
        libc::SIGTTIN,
        libc::SIGTTOU,
    ]);
    // SAFETY: `all` is an initialised set; the old mask isn't wanted.
    let rc = unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &all, std::ptr::null_mut()) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(rc))
    }
}

/// Starts the thread that waits for the signals and cancels `cancel`.
pub fn watch(cancel: Cancel) -> io::Result<Signals> {
    // SAFETY: eventfd takes no pointers; the result is a new descriptor.
    let fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a new descriptor we own.
    let wake = Arc::new(unsafe { OwnedFd::from_raw_fd(fd) });
    let interrupted = Arc::new(AtomicBool::new(false));
    let busy = Arc::new(AtomicUsize::new(0));
    let (flag, wake_for_thread, busy_for_thread) = (
        Arc::clone(&interrupted),
        Arc::clone(&wake),
        Arc::clone(&busy),
    );
    let waited = set(&[libc::SIGINT, libc::SIGQUIT, libc::SIGTERM, libc::SIGHUP]);
    std::thread::Builder::new()
        .name(THREAD.into())
        .spawn(move || {
            loop {
                let mut got: libc::c_int = 0;
                // SAFETY: `waited` is an initialised set and `got` a live int.
                let rc = unsafe { libc::sigwait(&waited, &mut got) };
                if rc != 0 {
                    // EINTR can't happen here. Anything else means nothing
                    // can be waited for, and with the signals blocked the
                    // program could never be cancelled: end it, in words.
                    log::error!("sigwait failed: {}", io::Error::from_raw_os_error(rc));
                    leave(b"\natlas-archive-cli: Signals can't be waited for, so the program stops.\n");
                }
                if decide(&flag, &busy_for_thread) == Action::Leave {
                    exit_now();
                }
                log::info!("signal {got}: cancelling");
                cancel.cancel();
                let one = 1u64.to_ne_bytes();
                // SAFETY: writes 8 bytes from a live buffer; EAGAIN means it
                // is readable already.
                unsafe { libc::write(wake_for_thread.as_raw_fd(), one.as_ptr().cast(), 8) };
            }
        })?;
    Ok(Signals {
        interrupted,
        wake,
        busy,
    })
}

impl Signals {
    /// A descriptor that turns readable when a signal came.
    pub fn wake_fd(&self) -> RawFd {
        self.wake.as_raw_fd()
    }

    /// Marks a cancellable job as running until the guard drops.
    pub fn busy(&self) -> Busy {
        self.busy.fetch_add(1, Ordering::SeqCst);
        Busy(Arc::clone(&self.busy))
    }

    pub fn interrupted(&self) -> bool {
        self.interrupted.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_first_signal_cancels_a_running_job_and_the_second_leaves() {
        let (flag, busy) = (AtomicBool::new(false), AtomicUsize::new(1));
        assert_eq!(decide(&flag, &busy), Action::Cancel);
        assert!(flag.load(Ordering::SeqCst));
        assert_eq!(decide(&flag, &busy), Action::Leave);
        assert_eq!(decide(&flag, &busy), Action::Leave);
    }

    #[test]
    fn a_signal_with_no_job_running_leaves_at_once() {
        let (flag, busy) = (AtomicBool::new(false), AtomicUsize::new(0));
        assert_eq!(decide(&flag, &busy), Action::Leave);
    }

    #[test]
    fn the_guard_counts_nested_jobs() {
        let busy = Arc::new(AtomicUsize::new(0));
        busy.fetch_add(2, Ordering::SeqCst);
        drop(Busy(Arc::clone(&busy)));
        assert_eq!(busy.load(Ordering::SeqCst), 1);
        let flag = AtomicBool::new(false);
        assert_eq!(decide(&flag, &busy), Action::Cancel);
    }
}
