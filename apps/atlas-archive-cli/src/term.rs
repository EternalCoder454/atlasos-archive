//! The terminal and descriptors: safe text for the screen, answers and
//! passwords read without ever blocking past a signal.

use std::ffi::OsStr;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;

use atlas_archive_core::name::{self, NameEncoding};
use zeroize::Zeroizing;

/// The longest password read, in bytes.
pub const MAX_PASSWORD: usize = 4096;
/// The longest answer to a question.
const MAX_ANSWER: usize = 64;

/// Free text from an archive or the worker, safe to print.
pub fn safe(text: &str) -> String {
    name::display_text(text)
}

/// A path or argument, safe to print: undecodable bytes show as `\xNN`.
pub fn safe_os(s: &OsStr) -> String {
    let mut pieces = Vec::new();
    name::decode(s.as_bytes(), NameEncoding::Utf8, |p| pieces.push(p));
    name::display(&pieces).0
}

pub fn is_tty(fd: RawFd) -> bool {
    // SAFETY: isatty takes only a descriptor number.
    unsafe { libc::isatty(fd) == 1 }
}

/// What reading a line gave.
#[derive(Debug, PartialEq, Eq)]
pub enum Line {
    /// The line, without its newline.
    Text(Zeroizing<Vec<u8>>),
    /// The stream ended before any byte.
    Eof,
    /// The wake descriptor fired (a signal came).
    Interrupted,
    TooLong,
}

fn poll2(a: RawFd, b: RawFd) -> io::Result<(bool, bool)> {
    let mut fds = [
        libc::pollfd {
            fd: a,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: b,
            events: libc::POLLIN,
            revents: 0,
        },
    ];
    loop {
        // SAFETY: `fds` is a live array of two pollfd structs.
        let n = unsafe { libc::poll(fds.as_mut_ptr(), 2, -1) };
        if n >= 0 {
            return Ok((fds[0].revents != 0, fds[1].revents != 0));
        }
        let e = io::Error::last_os_error();
        if e.kind() != io::ErrorKind::Interrupted {
            return Err(e);
        }
    }
}

/// Reads one line from `fd`, a byte at a time so nothing past the newline is
/// taken from a shared pipe, giving up when `wake` becomes readable. The
/// buffer is sized up front, so no reallocation leaves a copy behind.
pub fn read_line(fd: RawFd, wake: RawFd, max: usize) -> io::Result<Line> {
    let mut buf = Zeroizing::new(Vec::with_capacity(max + 1));
    loop {
        let (ready, woken) = poll2(fd, wake)?;
        if woken {
            return Ok(Line::Interrupted);
        }
        if !ready {
            continue;
        }
        let mut byte = 0u8;
        // SAFETY: reads at most one byte into a live local.
        let n = unsafe { libc::read(fd, (&raw mut byte).cast(), 1) };
        if n < 0 {
            let e = io::Error::last_os_error();
            match e.kind() {
                io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock => continue,
                _ => return Err(e),
            }
        }
        if n == 0 {
            return Ok(if buf.is_empty() {
                Line::Eof
            } else {
                Line::Text(buf)
            });
        }
        if byte == b'\n' {
            return Ok(Line::Text(buf));
        }
        if buf.len() >= max {
            return Ok(Line::TooLong);
        }
        buf.push(byte);
    }
}

/// The password on `--password-fd`: one line, the newline dropped, the
/// descriptor closed afterwards. The error is a sentence.
pub fn read_password_fd(fd: RawFd, wake: RawFd) -> Result<Option<Zeroizing<Vec<u8>>>, String> {
    // Our own descriptors (the eventfds) are never a password source.
    let target = std::fs::read_link(format!("/proc/self/fd/{fd}"))
        .map_err(|_| format!("Descriptor {fd} isn't open, so there is no password to read."))?;
    if target.as_os_str().as_bytes().starts_with(b"anon_inode:") {
        return Err(format!(
            "Descriptor {fd} isn't open, so there is no password to read."
        ));
    }
    if is_tty(fd) {
        return Err("--password-fd needs a pipe or a file, not a terminal.".into());
    }
    // SAFETY: the descriptor is open (checked above) and nothing else in
    // this process owns it; the OwnedFd closes it when this function ends.
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    match read_line(owned.as_raw_fd(), wake, MAX_PASSWORD) {
        Ok(Line::Text(p)) => Ok(Some(p)),
        Ok(Line::Eof) => Err(format!("No password was sent on descriptor {fd}.")),
        Ok(Line::TooLong) => Err("The password is too long.".into()),
        Ok(Line::Interrupted) => Ok(None),
        Err(e) => {
            log::warn!("reading descriptor {fd}: {e}");
            Err(format!(
                "The password couldn't be read from descriptor {fd}."
            ))
        }
    }
}

/// Echo off for as long as it lives; the terminal is put back on drop,
/// whatever way the code leaves.
struct EchoOff {
    fd: RawFd,
    saved: libc::termios,
}

impl EchoOff {
    fn new(fd: RawFd) -> io::Result<EchoOff> {
        // SAFETY: tcgetattr fills a termios we own; zeroed is a valid start.
        let mut saved: libc::termios = unsafe { std::mem::zeroed() };
        // SAFETY: `saved` is a live termios.
        if unsafe { libc::tcgetattr(fd, &mut saved) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let mut quiet = saved;
        quiet.c_lflag &= !(libc::ECHO | libc::ECHOE | libc::ECHOK | libc::ECHONL);
        // SAFETY: `quiet` is a live termios.
        if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &quiet) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(EchoOff { fd, saved })
    }
}

impl Drop for EchoOff {
    fn drop(&mut self) {
        // SAFETY: `saved` is the termios tcgetattr gave; the descriptor
        // outlives this guard (the Tty owns it).
        if unsafe { libc::tcsetattr(self.fd, libc::TCSANOW, &self.saved) } != 0 {
            log::warn!(
                "couldn't restore the terminal: {}",
                io::Error::last_os_error()
            );
        }
    }
}

/// The controlling terminal, `/dev/tty`.
pub struct Tty {
    file: File,
    wake: RawFd,
}

impl Tty {
    /// `None` when the process has no controlling terminal.
    pub fn open(wake: RawFd) -> Option<Tty> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOCTTY | libc::O_CLOEXEC)
            .open("/dev/tty")
            .ok()?;
        Some(Tty { file, wake })
    }

    /// Writes to the screen. A terminal that can't be written to has no one
    /// to tell, so errors end here.
    pub fn say(&self, text: &str) {
        let mut f = &self.file;
        let _ = f.write_all(text.as_bytes()).and_then(|()| f.flush());
    }

    /// Asks a question and returns the answer, lowercased; `None` at the end
    /// of input, a signal, or a failed read.
    pub fn ask(&self, prompt: &str) -> Option<String> {
        self.say(prompt);
        match read_line(self.file.as_raw_fd(), self.wake, MAX_ANSWER) {
            Ok(Line::Text(t)) => Some(String::from_utf8_lossy(&t).trim().to_lowercase()),
            Ok(Line::TooLong) => Some(String::new()),
            Ok(_) => {
                self.say("\n");
                None
            }
            Err(e) => {
                log::warn!("reading the terminal: {e}");
                None
            }
        }
    }

    /// Asks for a password with echo off. `Err` when it can't be hidden.
    pub fn password(&self, prompt: &str) -> io::Result<Line> {
        let _quiet = EchoOff::new(self.file.as_raw_fd())?;
        self.say(prompt);
        let line = read_line(self.file.as_raw_fd(), self.wake, MAX_PASSWORD);
        // Echo was off, so the Enter key showed nothing.
        self.say("\n");
        line
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn pipe() -> (OwnedFd, File) {
        let mut fds = [0; 2];
        // SAFETY: pipe2 fills two descriptors.
        assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
        // SAFETY: both are new descriptors we own.
        unsafe { (OwnedFd::from_raw_fd(fds[0]), File::from_raw_fd(fds[1])) }
    }

    fn eventfd() -> OwnedFd {
        // SAFETY: eventfd takes no pointers.
        let fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC) };
        assert!(fd >= 0);
        // SAFETY: a new descriptor.
        unsafe { OwnedFd::from_raw_fd(fd) }
    }

    #[test]
    fn safe_text_has_no_controls() {
        assert_eq!(safe("a\x1b[31mb"), "a\\x1B[31mb");
        assert_eq!(safe("evil\u{202e}gpj"), "evil<U+202E>gpj");
        let bad = OsStr::from_bytes(b"a\xffb\n");
        assert_eq!(safe_os(bad), "a\\xFFb\\x0A");
    }

    #[test]
    fn a_line_is_read_without_its_newline_and_nothing_more() {
        let wake = eventfd();
        let (r, mut w) = pipe();
        w.write_all(b"secret\nnext\n").unwrap();
        let first = read_line(r.as_raw_fd(), wake.as_raw_fd(), 100).unwrap();
        assert_eq!(first, Line::Text(Zeroizing::new(b"secret".to_vec())));
        let second = read_line(r.as_raw_fd(), wake.as_raw_fd(), 100).unwrap();
        assert_eq!(second, Line::Text(Zeroizing::new(b"next".to_vec())));
        drop(w);
        assert_eq!(
            read_line(r.as_raw_fd(), wake.as_raw_fd(), 100).unwrap(),
            Line::Eof
        );
    }

    #[test]
    fn an_unterminated_last_line_counts() {
        let wake = eventfd();
        let (r, mut w) = pipe();
        w.write_all(b"abc").unwrap();
        drop(w);
        assert_eq!(
            read_line(r.as_raw_fd(), wake.as_raw_fd(), 100).unwrap(),
            Line::Text(Zeroizing::new(b"abc".to_vec()))
        );
    }

    #[test]
    fn a_long_line_is_refused() {
        let wake = eventfd();
        let (r, mut w) = pipe();
        w.write_all(&[b'x'; 50]).unwrap();
        assert_eq!(
            read_line(r.as_raw_fd(), wake.as_raw_fd(), 10).unwrap(),
            Line::TooLong
        );
    }

    #[test]
    fn a_signal_wakes_a_blocked_read() {
        let wake = eventfd();
        let (r, _w) = pipe();
        let one = 1u64.to_ne_bytes();
        // SAFETY: writes 8 bytes from a live buffer.
        unsafe { libc::write(wake.as_raw_fd(), one.as_ptr().cast(), 8) };
        assert_eq!(
            read_line(r.as_raw_fd(), wake.as_raw_fd(), 10).unwrap(),
            Line::Interrupted
        );
    }

    #[test]
    fn password_fd_is_read_and_closed() {
        let wake = eventfd();
        let (r, mut w) = pipe();
        w.write_all(b"pass word\n").unwrap();
        let fd = r.as_raw_fd();
        std::mem::forget(r); // read_password_fd owns and closes it
        let p = read_password_fd(fd, wake.as_raw_fd()).unwrap().unwrap();
        assert_eq!(&p[..], b"pass word");
    }

    #[test]
    fn password_fd_errors_are_sentences() {
        let wake = eventfd();
        let e = read_password_fd(900, wake.as_raw_fd()).unwrap_err();
        assert!(e.contains("isn't open"), "{e}");
        // An eventfd is ours, not a password source.
        let other = eventfd();
        let e = read_password_fd(other.as_raw_fd(), wake.as_raw_fd()).unwrap_err();
        assert!(e.contains("isn't open"), "{e}");
        let (r, w) = pipe();
        drop(w);
        let fd = r.as_raw_fd();
        std::mem::forget(r);
        let e = read_password_fd(fd, wake.as_raw_fd()).unwrap_err();
        assert!(e.contains("No password"), "{e}");
    }
}
