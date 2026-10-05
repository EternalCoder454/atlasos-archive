//! `atlas-archive-cli`: Atlas Archive for scripts and the launcher
//! (docs/DESIGN.md, "CLI").
//!
//! The CLI never parses archive bytes: every job runs in the sandboxed
//! worker, through `atlas_archive_core::client` (used in `job` only).

mod args;
mod error;
mod job;
mod json;
mod log;
mod select;
mod show;
mod sig;
mod term;

use std::io::{self, BufWriter, Write};

use zeroize::Zeroizing;

use args::{Command, Common};
use error::CliError;
use job::Job;
use sig::Signals;

const HELP: &str = "\
Atlas Archive on the command line.

Usage:
  atlas-archive-cli list [--json] [--encoding LABEL] [--] ARCHIVE
  atlas-archive-cli extract [--to DIR] [--here] [--name NAME]
                    [--on-clash replace|skip|keep-both] [--allow-large]
                    [--] ARCHIVE [ENTRY...]
  atlas-archive-cli test [--json] [--] ARCHIVE
  atlas-archive-cli info [--json] [--] ARCHIVE
  atlas-archive-cli create            (not available yet)

Options come before ARCHIVE. ARCHIVE and everything after it are paths, even
when they start with a dash; -- ends the options early. Pass -- before
file names that aren't your own.

Commands:
  list     Show what is inside: size, date, name; refused items marked with !.
  extract  Unpack into <name>/ next to the archive. --to DIR picks the folder
           it goes in, --here unpacks without the extra folder when the
           archive has one item at the top, --name sets the folder's name.
           ENTRY paths (as list shows them) unpack only those items. When an
           item is already there, a terminal asks Replace, Skip or Keep Both;
           without one the answer is Keep Both unless --on-clash says.
  test     Read every item and check it, writing nothing.
  info     Show the format, item count, size, encryption, volumes, comment.

Options:
  --json               One JSON object per line, then a final {\"summary\":...}.
  --encoding LABEL     Read names with this encoding (UTF-8, IBM437, Shift_JIS,
                       GBK, windows-1252...), instead of detecting it.
  --password-fd N      Read the password from descriptor N: one line, then the
                       descriptor is closed, and waiting stops after 30
                       seconds (exit 3). With N = 0 this uses up standard
                       input. Without it a terminal is asked; a password is
                       never taken from an argument or the environment.
  --allow-large        Go past the size and ratio limits that guard against
                       archives built to fill a disk. Without a terminal
                       they stop the job; with one you are asked.
  -v                   Log to stderr (debug level). Without it nothing is
                       logged.
  -h, --help           Show this help.
  --version            Show the version.

Exit codes: 0 done, 1 failed, 2 bad usage, 3 needs a password, 4 a limit
refused it, 130 cancelled (Ctrl-C, Ctrl-\\ or SIGTERM; a second one stops at once).
";

fn main() {
    std::process::exit(run());
}

/// No core dump and no attaching to this process: a password may be in its
/// memory. Failing to ask for either is a failure to start.
fn harden() -> Result<(), io::Error> {
    let none = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `none` is a live rlimit; prctl takes plain integers.
    unsafe {
        if libc::setrlimit(libc::RLIMIT_CORE, &none) != 0 {
            return Err(io::Error::last_os_error());
        }
        if libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// A panic says one fixed sentence: the payload may hold archive text. With
/// `-v` its file and line are logged. The terminal is put back and the program ends with exit 1.
fn quiet_panics() {
    std::panic::set_hook(Box::new(|info| {
        term::restore_terminal();
        // Only the place, for a `-v` log: the payload may hold archive text.
        if let Some(at) = info.location() {
            ::log::error!("panic at {}:{}", at.file(), at.line());
        }
        let msg = b"atlas-archive-cli: Something went wrong inside the program.\n";
        // SAFETY: writes from a live buffer, then ends the process.
        unsafe {
            libc::write(libc::STDERR_FILENO, msg.as_ptr().cast(), msg.len());
            libc::_exit(error::EXIT_FAILED)
        }
    }));
}

fn run() -> i32 {
    quiet_panics();
    if let Err(e) = harden() {
        eprintln!("atlas-archive-cli: The program couldn't be locked down ({e}).");
        return error::EXIT_FAILED;
    }
    // Before anything starts a thread: Ctrl-C and SIGTERM are blocked here,
    // and so in every thread made later.
    if let Err(e) = sig::block() {
        eprintln!("atlas-archive-cli: Signals couldn't be set up ({e}).");
        return error::EXIT_FAILED;
    }
    let parsed = match args::parse(std::env::args_os().skip(1)) {
        Ok(p) => p,
        Err(args::Usage(m)) => {
            eprintln!("atlas-archive-cli: {m}");
            eprintln!("Try 'atlas-archive-cli --help'.");
            return error::EXIT_USAGE;
        }
    };
    match parsed.command {
        Command::Help => finish(io::stdout().write_all(HELP.as_bytes()).map_err(Into::into)),
        Command::Version => finish(
            writeln!(
                io::stdout(),
                "atlas-archive-cli {}",
                env!("CARGO_PKG_VERSION")
            )
            .map_err(Into::into),
        ),
        Command::Create => {
            eprintln!("atlas-archive-cli: create isn't available yet");
            error::EXIT_USAGE
        }
        command => {
            log::init(parsed.verbose);
            let cancel = job::Cancel::new();
            let sigs = match sig::watch(cancel.clone()) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("atlas-archive-cli: Signals couldn't be set up ({e}).");
                    return error::EXIT_FAILED;
                }
            };
            ::log::debug!("atlas-archive-cli {} started", env!("CARGO_PKG_VERSION"));
            // Only extraction leaves a staging folder behind; the sweep
            // runs with the signal thread already watching.
            if matches!(command, Command::Extract(_)) {
                job::clean_stale_jobs();
            }
            #[cfg(feature = "dev-worker")]
            let job = Job::with_worker(parsed.worker.as_deref(), cancel, &sigs);
            #[cfg(not(feature = "dev-worker"))]
            let job = Job::new(cancel, &sigs);
            finish(run_command(command, &job, &sigs))
        }
    }
}

/// Prints the failure, if there is one, and gives the exit code.
fn finish(result: Result<(), CliError>) -> i32 {
    match result {
        Ok(()) => 0,
        Err(e) => {
            if let Some(m) = e.message() {
                eprintln!("atlas-archive-cli: {m}");
            }
            e.code()
        }
    }
}

/// The password from `--password-fd`, read now so a bad descriptor is a
/// usage error before any work starts.
fn password(c: &Common, sigs: &Signals) -> Result<Option<Zeroizing<Vec<u8>>>, CliError> {
    let Some(fd) = c.password_fd else {
        return Ok(None);
    };
    let _busy = sigs.busy();
    match term::read_password_fd(fd, sigs.wake_fd()) {
        Ok(Some(p)) => Ok(Some(p)),
        Ok(None) => Err(CliError::Cancelled),
        Err(e) if e.timed_out => Err(CliError::NeedsPassword(e.message)),
        Err(e) => Err(CliError::Usage(e.message)),
    }
}

fn run_command(command: Command, job: &Job<'_>, sigs: &Signals) -> Result<(), CliError> {
    let stdout = io::stdout();
    let mut out = BufWriter::new(stdout.lock());
    match command {
        Command::List(c) => {
            let l = job.list(&c, password(&c, sigs)?, c.json)?;
            if c.json {
                show::list_json(&mut out, &l)?;
            } else {
                show::list_text(&mut out, &l)?;
            }
        }
        Command::Info(c) => {
            let l = job.list(&c, password(&c, sigs)?, false)?;
            if c.json {
                show::info_json(&mut out, &l)?;
            } else {
                show::info_text(&mut out, &l)?;
            }
        }
        Command::Test(c) => {
            let t = job.test(&c, password(&c, sigs)?)?;
            if c.json {
                show::test_json(&mut out, &t)?;
            } else {
                show::test_text(&mut out, &mut io::stderr().lock(), &t)?;
            }
            if !t.ok() {
                // What couldn't be read is a fault in the archive.
                out.flush()?;
                return Err(CliError::Failed(
                    "Some items couldn't be read, so this archive has errors.".into(),
                ));
            }
        }
        Command::Extract(a) => {
            let x = job.extract(&a, password(&a.common, sigs)?)?;
            if a.common.json {
                show::extract_json(&mut out, &x)?;
            } else {
                show::extract_text(&mut out, &mut io::stderr().lock(), &x)?;
            }
        }
        Command::Help | Command::Version | Command::Create => {}
    }
    out.flush()?;
    Ok(())
}
