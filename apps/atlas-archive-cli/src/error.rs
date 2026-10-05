//! How a run ends: the exit code and the sentence for stderr.

/// Why a command didn't finish. Each kind is an exit code.
#[derive(Debug, PartialEq, Eq)]
pub enum CliError {
    /// A usage mistake (exit 2).
    Usage(String),
    /// It failed (exit 1).
    Failed(String),
    /// The archive needs a password nobody can give (exit 3).
    NeedsPassword(String),
    /// A safety limit refused it (exit 4).
    LimitRefused(String),
    /// Ctrl-C or SIGTERM (exit 130).
    Cancelled,
    /// Standard output went away (`| head`): exit 1 with nothing to say.
    OutputClosed,
}

pub const EXIT_FAILED: i32 = 1;
pub const EXIT_USAGE: i32 = 2;
pub const EXIT_PASSWORD: i32 = 3;
pub const EXIT_LIMIT: i32 = 4;
pub const EXIT_CANCELLED: i32 = 130;

impl CliError {
    pub fn code(&self) -> i32 {
        match self {
            CliError::Failed(_) | CliError::OutputClosed => EXIT_FAILED,
            CliError::Usage(_) => EXIT_USAGE,
            CliError::NeedsPassword(_) => EXIT_PASSWORD,
            CliError::LimitRefused(_) => EXIT_LIMIT,
            CliError::Cancelled => EXIT_CANCELLED,
        }
    }

    /// The sentence for stderr, already safe to print. `None`: say nothing.
    pub fn message(&self) -> Option<&str> {
        match self {
            CliError::Usage(m)
            | CliError::Failed(m)
            | CliError::NeedsPassword(m)
            | CliError::LimitRefused(m) => Some(m),
            CliError::Cancelled => Some("Cancelled."),
            CliError::OutputClosed => None,
        }
    }
}

impl From<std::io::Error> for CliError {
    /// A failed write to standard output.
    fn from(e: std::io::Error) -> CliError {
        if e.kind() == std::io::ErrorKind::BrokenPipe {
            CliError::OutputClosed
        } else {
            log::warn!("writing output: {e}");
            CliError::Failed("The result couldn't be written.".into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_kind_has_its_code() {
        assert_eq!(CliError::Failed("x".into()).code(), 1);
        assert_eq!(CliError::Usage("x".into()).code(), 2);
        assert_eq!(CliError::NeedsPassword("x".into()).code(), 3);
        assert_eq!(CliError::LimitRefused("x".into()).code(), 4);
        assert_eq!(CliError::Cancelled.code(), 130);
        assert_eq!(CliError::OutputClosed.code(), 1);
    }

    #[test]
    fn only_a_closed_pipe_is_quiet() {
        let pipe = std::io::Error::from(std::io::ErrorKind::BrokenPipe);
        assert_eq!(CliError::from(pipe), CliError::OutputClosed);
        let full = std::io::Error::from_raw_os_error(libc::ENOSPC);
        assert!(CliError::from(full).message().is_some());
        assert_eq!(CliError::OutputClosed.message(), None);
    }
}
