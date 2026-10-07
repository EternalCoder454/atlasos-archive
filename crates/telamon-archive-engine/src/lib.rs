//! Telamon Archive's engine: libarchive, the zip and 7z drivers, and the
//! extraction writer. It runs only in `telamon-archive-worker`, after the
//! sandbox is in place (docs/DESIGN.md, "The sandbox").
pub mod extract;
pub mod job;
pub mod libarchive;

/// One line on the log (fd 2), best effort: a broken log descriptor must
/// never stop a job, and `eprintln!` panics on one. Never a path, a name from
/// an archive or a password.
pub fn log_line(args: std::fmt::Arguments<'_>) {
    use std::io::Write;
    let mut line = format!("telamon-archive-worker: {args}");
    line.push('\n');
    // One write, so lines from one process don't interleave.
    let _ = std::io::stderr().write_all(line.as_bytes());
}

/// `log_line(format_args!(..))`.
#[macro_export]
macro_rules! log_line {
    ($($arg:tt)*) => {
        $crate::log_line(format_args!($($arg)*))
    };
}
