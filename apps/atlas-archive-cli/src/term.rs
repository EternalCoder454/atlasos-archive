//! The terminal and descriptors: safe text for the screen, answers and
//! passwords read without ever blocking past a signal.

use std::ffi::OsStr;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use atlas_archive_core::name::{self, NameEncoding};
use zeroize::Zeroizing;

/// The longest password read, in bytes.
pub const MAX_PASSWORD: usize = 4096;
/// The most of an over-long line that is read and dropped before giving up.
const MAX_DISCARD: usize = 1 << 20;
/// The longest answer to a question.
const MAX_ANSWER: usize = 64;

/// The longest `--password-fd` waits for the line.
const FD_WAIT: Duration = Duration::from_secs(30);

/// Free text from an archive or the worker, safe to print on one line: a
/// newline shows as `\x0A`, so one reason can't forge a log or error line.
pub fn safe(text: &str) -> String {
    let chars: Vec<name::Piece> = text.chars().map(name::Piece::Char).collect();
    name::display(&chars).0
}

/// Free text that may run over several lines (an archive comment): the
/// newlines stay, every line is made safe.
pub fn safe_multiline(text: &str) -> String {
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
    /// The line was longer than allowed; the rest of it was read and dropped.
    TooLong,
    /// Nothing finished the line in time.
    TimedOut,
}

fn poll2(a: RawFd, b: RawFd, wait_ms: i32) -> io::Result<(bool, bool)> {
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
        let n = unsafe { libc::poll(fds.as_mut_ptr(), 2, wait_ms) };
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
/// buffer is sized up front, so no reallocation leaves a copy behind. A line
/// over `max` bytes is read to its end and dropped (`TooLong`), so the rest of
/// it isn't taken for the next answer. With `timeout`, `TimedOut` comes when
/// the whole line hasn't arrived by then.
pub fn read_line(
    fd: RawFd,
    wake: RawFd,
    max: usize,
    timeout: Option<Duration>,
) -> io::Result<Line> {
    let deadline = timeout.map(|t| Instant::now() + t);
    let mut buf = Zeroizing::new(Vec::with_capacity(max + 1));
    let mut too_long = false;
    let mut dropped = 0usize;
    loop {
        let wait_ms = match deadline {
            None => -1,
            Some(d) => {
                let left = d.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    return Ok(Line::TimedOut);
                }
                left.as_millis().clamp(1, 60_000) as i32
            }
        };
        let (ready, woken) = poll2(fd, wake, wait_ms)?;
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
            if too_long {
                return Ok(Line::TooLong);
            }
            return Ok(if buf.is_empty() {
                Line::Eof
            } else {
                Line::Text(buf)
            });
        }
        if byte == b'\n' {
            return Ok(if too_long {
                Line::TooLong
            } else {
                Line::Text(buf)
            });
        }
        if too_long {
            dropped += 1;
            if dropped >= MAX_DISCARD {
                return Ok(Line::TooLong);
            }
            continue;
        }
        if buf.len() >= max {
            too_long = true;
            continue;
        }
        buf.push(byte);
    }
}

/// Why `--password-fd` gave no password.
#[derive(Debug, PartialEq, Eq)]
pub struct FdError {
    /// Nothing arrived in time: the archive needs a password (exit 3), where
    /// anything else is a usage mistake.
    pub timed_out: bool,
    /// A sentence.
    pub message: String,
}

fn bad(message: String) -> FdError {
    FdError {
        timed_out: false,
        message,
    }
}

/// The password on `--password-fd`: one line, the newline dropped, the
/// descriptor closed afterwards, 30 seconds at most. When the descriptor is
/// 0 this takes the program's standard input.
pub fn read_password_fd(fd: RawFd, wake: RawFd) -> Result<Option<Zeroizing<Vec<u8>>>, FdError> {
    read_password_fd_within(fd, wake, FD_WAIT)
}

fn read_password_fd_within(
    fd: RawFd,
    wake: RawFd,
    wait: Duration,
) -> Result<Option<Zeroizing<Vec<u8>>>, FdError> {
    // Our own descriptors (the eventfds) are never a password source.
    let target = std::fs::read_link(format!("/proc/self/fd/{fd}")).map_err(|_| {
        bad(format!(
            "Descriptor {fd} isn't open, so there is no password to read."
        ))
    })?;
    if target.as_os_str().as_bytes().starts_with(b"anon_inode:") {
        return Err(bad(format!(
            "Descriptor {fd} isn't open, so there is no password to read."
        )));
    }
    if is_tty(fd) {
        return Err(bad(
            "--password-fd needs a pipe or a file, not a terminal.".into()
        ));
    }
    // Descriptors 0-2 are not closed afterwards: closing would let the next
    // open (the terminal) take the number, and a piped run would look
    // interactive. They get /dev/null instead.
    let owned = if fd <= 2 {
        None
    } else {
        // SAFETY: the descriptor is open (checked above) and nothing else in
        // this process owns it; the OwnedFd closes it when this ends.
        Some(unsafe { OwnedFd::from_raw_fd(fd) })
    };
    let result = read_line(fd, wake, MAX_PASSWORD, Some(wait));
    if owned.is_none() {
        silence(fd);
    }
    match result {
        Ok(Line::Text(p)) => Ok(Some(p)),
        Ok(Line::Eof) => Err(bad(format!("No password was sent on descriptor {fd}."))),
        Ok(Line::TooLong) => Err(bad("The password is too long.".into())),
        Ok(Line::TimedOut) => Err(FdError {
            timed_out: true,
            message: format!(
                "No password arrived on descriptor {fd} within {} seconds.",
                wait.as_secs().max(1)
            ),
        }),
        Ok(Line::Interrupted) => Ok(None),
        Err(e) => {
            log::warn!("reading descriptor {fd}: {e}");
            Err(bad(format!(
                "The password couldn't be read from descriptor {fd}."
            )))
        }
    }
}

/// Points a standard descriptor at /dev/null, so it stays taken but the
/// password source is gone.
fn silence(fd: RawFd) {
    match OpenOptions::new().read(true).write(true).open("/dev/null") {
        Ok(null) => {
            // SAFETY: both descriptors are open; dup2 replaces `fd`.
            if unsafe { libc::dup2(null.as_raw_fd(), fd) } < 0 {
                log::warn!("couldn't release descriptor {fd}");
            }
        }
        Err(e) => log::warn!("couldn't open /dev/null: {e}"),
    }
}

/// The terminal that has echo off, and how to put it back: read by the
/// signal thread and the panic hook, which leave without running drops.
static SAVED: Mutex<Option<(RawFd, libc::termios)>> = Mutex::new(None);

fn saved() -> std::sync::MutexGuard<'static, Option<(RawFd, libc::termios)>> {
    SAVED.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Puts back a terminal that has echo off, and throws away what was typed
/// meanwhile, so it isn't read by the shell. Safe to call at any time.
pub fn restore_terminal() {
    if let Some((fd, t)) = saved().take() {
        // SAFETY: `t` is the termios tcgetattr gave for `fd`, a descriptor
        // the prompt keeps open until it drops its guard.
        unsafe {
            libc::tcsetattr(fd, libc::TCSANOW, &t);
            libc::tcflush(fd, libc::TCIFLUSH);
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
        // Recorded first: a signal between the change and the record would
        // leave echo off.
        *self::saved() = Some((fd, saved));
        // SAFETY: `quiet` is a live termios.
        if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &quiet) } != 0 {
            let e = io::Error::last_os_error();
            self::saved().take();
            return Err(e);
        }
        Ok(EchoOff { fd, saved })
    }
}

impl Drop for EchoOff {
    fn drop(&mut self) {
        self::saved().take();
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
        match read_line(self.file.as_raw_fd(), self.wake, MAX_ANSWER, None) {
            Ok(Line::Text(t)) => Some(String::from_utf8_lossy(&t).trim().to_lowercase()),
            // The whole long line was read and dropped: no answer.
            Ok(Line::TooLong) => Some(String::new()),
            Ok(_) => {
                self.say("\n");
                self.flush_input();
                None
            }
            Err(e) => {
                log::warn!("reading the terminal: {e}");
                self.flush_input();
                None
            }
        }
    }

    /// Drops what was typed and not read yet, after a prompt that ended
    /// without an answer, so it doesn't reach the shell.
    fn flush_input(&self) {
        // SAFETY: tcflush takes a descriptor the Tty keeps open.
        unsafe { libc::tcflush(self.file.as_raw_fd(), libc::TCIFLUSH) };
    }

    /// Asks for a password with echo off. `Err` when it can't be hidden.
    pub fn password(&self, prompt: &str) -> io::Result<Line> {
        let _quiet = EchoOff::new(self.file.as_raw_fd())?;
        self.say(prompt);
        let line = read_line(self.file.as_raw_fd(), self.wake, MAX_PASSWORD, None);
        // Echo was off, so the Enter key showed nothing.
        self.say("\n");
        if !matches!(line, Ok(Line::Text(_))) {
            self.flush_input();
        }
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
        let first = read_line(r.as_raw_fd(), wake.as_raw_fd(), 100, None).unwrap();
        assert_eq!(first, Line::Text(Zeroizing::new(b"secret".to_vec())));
        let second = read_line(r.as_raw_fd(), wake.as_raw_fd(), 100, None).unwrap();
        assert_eq!(second, Line::Text(Zeroizing::new(b"next".to_vec())));
        drop(w);
        assert_eq!(
            read_line(r.as_raw_fd(), wake.as_raw_fd(), 100, None).unwrap(),
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
            read_line(r.as_raw_fd(), wake.as_raw_fd(), 100, None).unwrap(),
            Line::Text(Zeroizing::new(b"abc".to_vec()))
        );
    }

    #[test]
    fn a_long_line_is_dropped_through_its_newline() {
        let wake = eventfd();
        let (r, mut w) = pipe();
        w.write_all(&[b'x'; 50]).unwrap();
        w.write_all(b"\nnext\n").unwrap();
        let fd = r.as_raw_fd();
        assert_eq!(
            read_line(fd, wake.as_raw_fd(), 10, None).unwrap(),
            Line::TooLong
        );
        // Nothing of the long line is left to be taken for an answer.
        assert_eq!(
            read_line(fd, wake.as_raw_fd(), 10, None).unwrap(),
            Line::Text(Zeroizing::new(b"next".to_vec()))
        );
        // The same at the very limit and without a final newline.
        w.write_all(&[b'y'; 10]).unwrap();
        w.write_all(b"\n").unwrap();
        assert!(matches!(
            read_line(fd, wake.as_raw_fd(), 10, None).unwrap(),
            Line::Text(_)
        ));
        w.write_all(&[b'z'; 11]).unwrap();
        drop(w);
        assert_eq!(
            read_line(fd, wake.as_raw_fd(), 10, None).unwrap(),
            Line::TooLong
        );
    }

    #[test]
    fn a_silent_descriptor_times_out() {
        let wake = eventfd();
        let (r, _w) = pipe();
        let t = Instant::now();
        let got = read_line(
            r.as_raw_fd(),
            wake.as_raw_fd(),
            10,
            Some(Duration::from_millis(100)),
        )
        .unwrap();
        assert_eq!(got, Line::TimedOut);
        assert!(t.elapsed() < Duration::from_secs(5));
        let fd = r.as_raw_fd();
        std::mem::forget(r);
        let e =
            read_password_fd_within(fd, wake.as_raw_fd(), Duration::from_millis(100)).unwrap_err();
        assert!(e.timed_out, "{e:?}");
        assert!(e.message.contains("No password arrived"), "{e:?}");
    }

    #[test]
    fn an_endless_line_is_given_up_on() {
        let wake = eventfd();
        let (r, mut w) = pipe();
        let writer = std::thread::spawn(move || {
            // Ends with a broken pipe once the reader gives up.
            let _ = w.write_all(&vec![b'x'; MAX_DISCARD * 2]);
        });
        assert_eq!(
            read_line(
                r.as_raw_fd(),
                wake.as_raw_fd(),
                10,
                Some(Duration::from_secs(20))
            )
            .unwrap(),
            Line::TooLong
        );
        drop(r);
        writer.join().unwrap();
    }

    #[test]
    fn text_is_one_line_unless_asked() {
        assert_eq!(safe("a\nb\r\x1b[2J"), "a\\x0Ab\\x0D\\x1B[2J");
        assert_eq!(safe_multiline("a\nb\x1b"), "a\nb\\x1B");
    }

    #[test]
    fn a_signal_wakes_a_blocked_read() {
        let wake = eventfd();
        let (r, _w) = pipe();
        let one = 1u64.to_ne_bytes();
        // SAFETY: writes 8 bytes from a live buffer.
        unsafe { libc::write(wake.as_raw_fd(), one.as_ptr().cast(), 8) };
        assert_eq!(
            read_line(r.as_raw_fd(), wake.as_raw_fd(), 10, None).unwrap(),
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
        let e = read_password_fd(900, wake.as_raw_fd()).unwrap_err().message;
        assert!(e.contains("isn't open"), "{e}");
        // An eventfd is ours, not a password source.
        let other = eventfd();
        let e = read_password_fd(other.as_raw_fd(), wake.as_raw_fd())
            .unwrap_err()
            .message;
        assert!(e.contains("isn't open"), "{e}");
        let (r, w) = pipe();
        drop(w);
        let fd = r.as_raw_fd();
        std::mem::forget(r);
        let e = read_password_fd(fd, wake.as_raw_fd()).unwrap_err().message;
        assert!(e.contains("No password"), "{e}");
    }
}
