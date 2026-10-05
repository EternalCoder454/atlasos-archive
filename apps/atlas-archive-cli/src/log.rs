//! Logging to stderr, only with `-v`. Lines are made safe to print: they can
//! carry names from an archive. Nothing here ever sees a password.

use std::io::Write;

struct Stderr;

impl log::Log for Stderr {
    fn enabled(&self, _: &log::Metadata<'_>) -> bool {
        true
    }

    fn log(&self, record: &log::Record<'_>) {
        let text = crate::term::safe(&record.args().to_string());
        let _ = writeln!(
            std::io::stderr(),
            "atlas-archive-cli: [{}] {text}",
            record.level().as_str().to_lowercase()
        );
    }

    fn flush(&self) {}
}

/// Turns logging on (everything down to debug) when `verbose`; otherwise
/// the `log` macros do nothing.
pub fn init(verbose: bool) {
    if verbose && log::set_logger(&Stderr).is_ok() {
        log::set_max_level(log::LevelFilter::Debug);
    }
}
