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

use std::fmt::Display;
use std::io::{self, BufWriter, Write};
use std::time::Instant;

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

/// Says `msg` on stderr, best effort: a failed write there (a closed pipe,
/// a full disk, a hung-up terminal) must never change the exit code, and
/// `eprintln!` would panic on one.
fn say(msg: impl Display) {
    // One write, so lines from two threads never interleave.
    let _ = io::stderr().write_all(format!("atlas-archive-cli: {msg}\n").as_bytes());
}

/// A panic says one fixed sentence: the payload may hold archive text. With
/// `-v` its file and line are logged. The terminal is put back and the
/// program ends, with exit 1 when the main thread panicked and 130 when the
/// signal thread did (without it nothing could cancel the run). A panic in
/// any other thread (the detached stale-staging sweep, the client's helpers)
/// ends only that thread: it is logged and the run goes on.
fn quiet_panics() {
    std::panic::set_hook(Box::new(|info| {
        // Only the place, for a `-v` log: the payload may hold archive text.
        if let Some(at) = info.location() {
            ::log::error!("panic at {}:{}", at.file(), at.line());
        }
        let thread = std::thread::current();
        let (code, msg): (i32, &[u8]) = match thread.name() {
            Some("main") => (
                error::EXIT_FAILED,
                b"atlas-archive-cli: Something went wrong inside the program.\n",
            ),
            Some(sig::THREAD) => (
                error::EXIT_CANCELLED,
                b"atlas-archive-cli: Something went wrong inside the program.\n",
            ),
            _ => return,
        };
        term::restore_terminal();
        // SAFETY: writes from a live buffer, then ends the process.
        unsafe {
            libc::write(libc::STDERR_FILENO, msg.as_ptr().cast(), msg.len());
            libc::_exit(code)
        }
    }));
}

fn run() -> i32 {
    quiet_panics();
    if let Err(e) = harden() {
        say(format_args!("The program couldn't be locked down ({e})."));
        return error::EXIT_FAILED;
    }
    // Before anything starts a thread: Ctrl-C and SIGTERM are blocked here,
    // and so in every thread made later.
    if let Err(e) = sig::block() {
        say(format_args!("Signals couldn't be set up ({e})."));
        return error::EXIT_FAILED;
    }
    let parsed = match args::parse(std::env::args_os().skip(1)) {
        Ok(p) => p,
        Err(args::Usage(m)) => {
            say(&m);
            let _ = writeln!(io::stderr(), "Try 'atlas-archive-cli --help'.");
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
            say("create isn't available yet");
            error::EXIT_USAGE
        }
        command => {
            log::init(parsed.verbose);
            let cancel = job::Cancel::new();
            let sigs = match sig::watch(cancel.clone()) {
                Ok(s) => s,
                Err(e) => {
                    say(format_args!("Signals couldn't be set up ({e})."));
                    return error::EXIT_FAILED;
                }
            };
            let started = Instant::now();
            ::log::debug!("atlas-archive-cli {} started", env!("CARGO_PKG_VERSION"));
            log_command(&command);
            // Only extraction leaves a staging folder behind; the sweep
            // runs with the signal thread already watching.
            if matches!(command, Command::Extract(_)) {
                job::clean_stale_jobs();
            }
            #[cfg(feature = "dev-worker")]
            let job = Job::with_worker(parsed.worker.as_deref(), cancel, &sigs);
            #[cfg(not(feature = "dev-worker"))]
            let job = Job::new(cancel, &sigs);
            // Held until the exit code is known: once the files are in place a
            // signal must not turn a finished extraction into "Cancelled"
            // (exit 130). The first one is noted and ignored; a second still
            // leaves.
            let _done = matches!(command, Command::Extract(_)).then(|| sigs.busy());
            let code = finish(run_command(command, &job, &sigs));
            ::log::debug!(
                "finished in {:.2?} with exit code {code}",
                started.elapsed()
            );
            code
        }
    }
}

/// The command and its options for a `-v` log. Paths go through `term::safe`;
/// a password is never an option, only the descriptor's number is.
fn log_command(command: &Command) {
    let common = |name: &str, c: &Common| {
        ::log::debug!(
            "command: {name} {} (json {}, encoding {}, password descriptor {:?})",
            term::safe_os(&c.archive),
            c.json,
            c.encoding.map_or("detect", |e| e.label()),
            c.password_fd
        );
    };
    match command {
        Command::List(c) => common("list", c),
        Command::Info(c) => common("info", c),
        Command::Test(c) => common("test", c),
        Command::Extract(a) => {
            common("extract", &a.common);
            ::log::debug!(
                "extract options: to {:?}, here {}, name {:?}, {} entries, allow-large {}, on-clash {:?}",
                a.to.as_deref().map(term::safe_os),
                a.here,
                a.name.as_deref().map(term::safe),
                a.entries.len(),
                a.allow_large,
                a.on_clash
            );
        }
        Command::Help | Command::Version | Command::Create => {}
    }
}

/// Prints the failure, if there is one, and gives the exit code.
fn finish(result: Result<(), CliError>) -> i32 {
    match result {
        Ok(()) => 0,
        Err(e) => {
            if let Some(m) = e.message() {
                say(m);
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
        Err(e) if e.no_password => Err(CliError::NeedsPassword(e.message)),
        Err(e) => Err(CliError::Usage(e.message)),
    }
}

/// A listing that broke part way was printed as far as it went: the reason
/// goes to stderr and the exit code says it failed.
fn broken(out: &mut impl Write, l: &job::Loaded) -> Result<(), CliError> {
    match &l.broken {
        None => Ok(()),
        Some(why) => {
            // What was printed is best effort; the reason is the result.
            let _ = out.flush();
            Err(CliError::Failed(why.clone()))
        }
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
            broken(&mut out, &l)?;
        }
        Command::Info(c) => {
            let l = job.list(&c, password(&c, sigs)?, false)?;
            if c.json {
                show::info_json(&mut out, &l)?;
            } else {
                show::info_text(&mut out, &l)?;
            }
            broken(&mut out, &l)?;
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
            let wrote = if a.common.json {
                show::extract_json(&mut out, &x)
            } else {
                show::extract_text(&mut out, &mut io::stderr().lock(), &x)
            }
            .and_then(|()| out.flush());
            return match wrote {
                Err(e) if x.left_out => Err(e.into()),
                // The files are in place: the output is lost, the job isn't.
                Err(e) => {
                    say(format_args!(
                        "The result couldn't be written ({e}), but the files were extracted to {}.",
                        term::safe_os(x.path.as_os_str())
                    ));
                    Ok(())
                }
                Ok(()) => Ok(()),
            };
        }
        Command::Help | Command::Version | Command::Create => {}
    }
    out.flush()?;
    Ok(())
}
