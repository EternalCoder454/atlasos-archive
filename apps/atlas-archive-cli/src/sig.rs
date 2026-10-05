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

/// Ends the program with the cancelled code. Only async-signal-safe calls
/// besides the terminal restore, and no locks on stderr.
fn exit_now() -> ! {
    crate::term::restore_terminal();
    let msg = b"\natlas-archive-cli: Cancelled.\n";
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
        .name("signals".into())
        .spawn(move || {
            loop {
                let mut got: libc::c_int = 0;
                // SAFETY: `waited` is an initialised set and `got` a live int.
                let rc = unsafe { libc::sigwait(&waited, &mut got) };
                if rc != 0 {
                    // EINTR can't happen here; anything else means nothing
                    // can be waited for, so stop rather than spin.
                    log::error!("sigwait failed: {}", io::Error::from_raw_os_error(rc));
                    return;
                }
                if flag.swap(true, Ordering::SeqCst) || busy_for_thread.load(Ordering::SeqCst) == 0
                {
                    // A second signal, or nothing to cancel: leave now.
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
