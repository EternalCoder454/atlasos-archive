//! Ctrl-C, SIGTERM and SIGHUP: blocked in every thread, taken by one thread
//! with `sigwait`, which cancels the job through the client. Nothing runs in
//! a signal handler.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use atlas_archive_core::client::Cancel;

pub struct Signals {
    interrupted: Arc<AtomicBool>,
    wake: Arc<OwnedFd>,
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
        libc::SIGTERM,
        libc::SIGHUP,
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
    let (flag, wake_for_thread) = (Arc::clone(&interrupted), Arc::clone(&wake));
    let waited = set(&[libc::SIGINT, libc::SIGTERM, libc::SIGHUP]);
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
                log::info!("signal {got}: cancelling");
                flag.store(true, Ordering::SeqCst);
                cancel.cancel();
                let one = 1u64.to_ne_bytes();
                // SAFETY: writes 8 bytes from a live buffer; EAGAIN means it
                // is readable already.
                unsafe { libc::write(wake_for_thread.as_raw_fd(), one.as_ptr().cast(), 8) };
            }
        })?;
    Ok(Signals { interrupted, wake })
}

impl Signals {
    /// A descriptor that turns readable when a signal came.
    pub fn wake_fd(&self) -> RawFd {
        self.wake.as_raw_fd()
    }

    pub fn interrupted(&self) -> bool {
        self.interrupted.load(Ordering::SeqCst)
    }
}
