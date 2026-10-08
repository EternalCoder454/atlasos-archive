//! The sandboxed worker (docs/DESIGN.md, "The sandbox"). The GUI and the CLI
//! start one per operation, with these descriptors and nothing else open:
//! 0 requests, 1 replies, 2 the log, 3 the archive, 4 the staging folder
//! (extraction only). It takes no arguments, does one job, and exits.
//!
//! Requests: an optional `Password`, then one of `List`, `Test` or
//! `Extract` (during which `GoOn` answers a `Limit`). The last reply is
//! always `Listed`, `Done`, `NeedPassword` or `Failed`; anything else means
//! the worker died, and the client says so.
//!
//! A job that makes an archive (`Create`) has no archive on 3. It gets the
//! staging folder on 4 and the folders its sources are in on 5 and up
//! (`proto::ROOT_FD`). Its one request names those sources; the client wrote
//! it (it is no archive byte), so it is read before the sandbox goes up, to
//! give Landlock a read rule for each source and nothing else.

mod sandbox;
mod seccomp;

use std::collections::HashSet;
use std::fs::File;
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::process::ExitCode;

use telamon_archive_core::compress::{CompressFormat, Level};
use telamon_archive_core::limits::Limits;
use telamon_archive_core::name::NameEncoding;
use telamon_archive_core::proto::{MAX_ROOTS, ROOT_FD, Reply, Request, Source};
use telamon_archive_engine::create::{self, CreateJob};
use telamon_archive_engine::extract::read_umask;
use telamon_archive_engine::job::{self, Conn, ExtractJob, Pipes};
use telamon_archive_engine::log_line;
use zeroize::Zeroizing;

const REQUESTS: RawFd = 0;
const REPLIES: RawFd = 1;
const ARCHIVE: RawFd = 3;
const STAGING: RawFd = 4;

/// Takes the inherited descriptor `fd`, if it is open.
fn take(fd: RawFd) -> Option<OwnedFd> {
    // SAFETY: F_GETFD/F_SETFD take no pointers. Descriptors 0-4 are this
    // process's by the contract above and owned by nothing else in it.
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFD);
        if flags < 0 {
            return None;
        }
        libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC);
        Some(OwnedFd::from_raw_fd(fd))
    }
}

/// The source folders of a Create job: the open descriptors from `ROOT_FD`
/// up, as far as they run without a gap.
fn take_roots() -> Vec<OwnedFd> {
    let mut roots = Vec::new();
    for fd in ROOT_FD..ROOT_FD + MAX_ROOTS as RawFd {
        match take(fd) {
            Some(r) => roots.push(r),
            None => break,
        }
    }
    roots
}

fn is_tty(fd: RawFd) -> bool {
    // SAFETY: isatty only inspects the descriptor.
    unsafe { libc::isatty(fd) == 1 }
}

fn kind_of(fd: &OwnedFd) -> Option<libc::mode_t> {
    let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: fstat fills `st` on success.
    if unsafe { libc::fstat(fd.as_raw_fd(), st.as_mut_ptr()) } != 0 {
        return None;
    }
    // SAFETY: initialised by the successful call.
    Some(unsafe { st.assume_init() }.st_mode & libc::S_IFMT)
}

fn main() -> ExitCode {
    if std::env::args_os().len() > 1 {
        // The log is fd 2 and may be anything: `log_line!` never panics.
        log_line!("Telamon Archive starts this program itself; it takes no arguments.");
        return ExitCode::from(2);
    }
    // Before anything else: nothing inherited past the contract stays open.
    let roots_open = (ROOT_FD..ROOT_FD + MAX_ROOTS as RawFd)
        .take_while(|&fd| {
            // SAFETY: F_GETFD takes no pointer.
            unsafe { libc::fcntl(fd, libc::F_GETFD) >= 0 }
        })
        .count();
    sandbox::close_others(ROOT_FD + roots_open as RawFd);
    let roots = take_roots();
    let (Some(requests), Some(replies)) = (take(REQUESTS), take(REPLIES)) else {
        log_line!("no request or reply pipe");
        return ExitCode::from(2);
    };
    let mut conn = Pipes {
        input: File::from(requests),
        output: File::from(replies),
    };
    // A terminal on any standard descriptor could be fed input (TIOCSTI and
    // its kin) after the worker is gone: the client never gives one. fd 2 is
    // the log, so say so on the reply pipe, unless that is one itself.
    if [0, 1, 2].into_iter().any(is_tty) {
        let reason = "The worker was started with a terminal as one of its standard streams.";
        // The reply first: the log may be the thing that is broken.
        if !is_tty(REPLIES) {
            let _ = conn.send(&Reply::Failed {
                reason: reason.into(),
            });
        }
        log_line!("{reason}");
        return ExitCode::from(2);
    }
    let archive = take(ARCHIVE);
    // Only a folder: a rule for anything else would give Landlock rights
    // it can't apply.
    let staging = take(STAGING).filter(|s| kind_of(s) == Some(libc::S_IFDIR));
    // A Create job: its request, now, and what the sandbox may read.
    let mut create_job = None;
    let mut reads = Vec::new();
    if !roots.is_empty() {
        match first_create(&mut conn, &roots) {
            Ok(job) => {
                reads = job.reads(&roots);
                create_job = Some(job);
            }
            Err(reason) => {
                let _ = conn.send(&Reply::Failed {
                    reason: reason.clone(),
                });
                log_line!("{reason}");
                return ExitCode::from(2);
            }
        }
    }
    let read_rules: Vec<(BorrowedFd<'_>, bool)> =
        reads.iter().map(|r| (r.0.as_fd(), r.1)).collect();
    if let Err(reason) = sandbox::enter(staging.as_ref().map(AsFd::as_fd), &read_rules) {
        let _ = conn.send(&Reply::Failed {
            reason: reason.clone(),
        });
        log_line!("{reason}");
        return ExitCode::from(2);
    }
    let ran = match create_job {
        Some(job) => run_create(&mut conn, job, roots, staging),
        None => run(&mut conn, archive, staging),
    };
    match ran {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            // A broken pipe or a bad frame: the client has gone or is not
            // speaking the protocol. Never the content of a frame.
            log_line!("{e}");
            ExitCode::FAILURE
        }
    }
}

/// A Create request, checked.
struct Creating {
    format: CompressFormat,
    level: Level,
    out_name: String,
    sources: Vec<Source>,
}

impl Creating {
    /// What the sandbox may read: each source folder or file, by an `O_PATH`
    /// descriptor made now, and whether it is a folder. Links and the rest are
    /// read by `readlinkat` and `fstatat`, which Landlock doesn't gate.
    fn reads(&self, roots: &[OwnedFd]) -> Vec<(OwnedFd, bool)> {
        let mut out = Vec::new();
        for s in &self.sources {
            let Some(root) = roots.get(s.root as usize) else {
                continue;
            };
            let Ok(name) = std::ffi::CString::new(s.name.clone()) else {
                continue;
            };
            // SAFETY: a valid folder descriptor and C string.
            let fd = unsafe {
                libc::openat(
                    root.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                continue;
            }
            // SAFETY: a new descriptor we own.
            let fd = unsafe { OwnedFd::from_raw_fd(fd) };
            match kind_of(&fd) {
                Some(libc::S_IFDIR) => out.push((fd, true)),
                Some(libc::S_IFREG) => out.push((fd, false)),
                _ => {}
            }
        }
        out
    }
}

/// Reads the one request of a Create job and checks it against what was
/// passed. Before the sandbox: the client wrote it.
fn first_create(conn: &mut impl Conn, roots: &[OwnedFd]) -> Result<Creating, String> {
    let bad = || "The request to make an archive wasn't valid.".to_string();
    let Some(Request::Create {
        format,
        level,
        out_name,
        sources,
    }) = conn.recv().map_err(|_| bad())?
    else {
        return Err(bad());
    };
    let (Some(format), Some(level)) = (CompressFormat::from_label(&format), Level::from_tag(level))
    else {
        return Err(bad());
    };
    if sources.is_empty()
        || sources
            .iter()
            .any(|s| s.root as usize >= roots.len() || !create::good_name(&s.name))
        || !create::good_name(out_name.as_bytes())
    {
        return Err(bad());
    }
    Ok(Creating {
        format,
        level,
        out_name,
        sources,
    })
}

fn run_create(
    conn: &mut impl Conn,
    job: Creating,
    roots: Vec<OwnedFd>,
    staging: Option<OwnedFd>,
) -> io::Result<()> {
    let Some(staging) = staging else {
        return fail(conn, "No folder was given to make the archive in.");
    };
    create::create(
        conn,
        CreateJob {
            roots,
            sources: job.sources,
            staging,
            out_name: job.out_name,
            format: job.format,
            level: job.level,
        },
    )
}

fn fail(conn: &mut impl Conn, reason: &str) -> io::Result<()> {
    conn.send(&Reply::Failed {
        reason: reason.into(),
    })
}

fn run(conn: &mut impl Conn, archive: Option<OwnedFd>, staging: Option<OwnedFd>) -> io::Result<()> {
    let mut password: Option<Zeroizing<Vec<u8>>> = None;
    let request = loop {
        match conn.recv()? {
            Some(Request::Password(p)) => password = Some(p),
            Some(r) => break r,
            // The client went away before asking for anything.
            None => return Ok(()),
        }
    };
    let Some(archive) = archive else {
        return fail(conn, "No archive was given to open.");
    };
    if kind_of(&archive) != Some(libc::S_IFREG) {
        return fail(conn, "The archive isn't a regular file.");
    }
    // Read-only, so not even a compromised parser can change the user's
    // archive.
    // SAFETY: F_GETFL takes no pointer.
    if unsafe { libc::fcntl(archive.as_raw_fd(), libc::F_GETFL) } & libc::O_ACCMODE
        != libc::O_RDONLY
    {
        return fail(conn, "The archive wasn't opened read-only.");
    }
    match request {
        Request::List => job::list_with(
            conn,
            archive.as_fd(),
            password.as_deref().map(Vec::as_slice),
        ),
        Request::Test => job::test(
            conn,
            archive.as_fd(),
            password.as_deref().map(Vec::as_slice),
        ),
        Request::Extract {
            encoding,
            entries,
            raw_name,
        } => {
            let Some(staging) = staging else {
                return fail(conn, "No folder was given to extract into.");
            };
            let Some(encoding) = NameEncoding::from_label(&encoding) else {
                return fail(conn, "The name encoding isn't one Telamon Archive knows.");
            };
            // Without the free space, the one limit that can't be gone past
            // would be off: refuse rather than run unlimited.
            let Some(free) = job::free_space(staging.as_fd()) else {
                return fail(
                    conn,
                    "Telamon Archive couldn't tell how much space is free on the drive.",
                );
            };
            let limits = Limits::new(Some(free));
            job::extract(
                conn,
                ExtractJob {
                    archive: archive.as_fd(),
                    staging,
                    umask: read_umask(),
                    encoding,
                    entries: entries.map(HashSet::from_iter),
                    limits,
                    raw_name,
                    password,
                },
            )
        }
        Request::Password(_) | Request::GoOn(_) | Request::Create { .. } => {
            fail(conn, "The request came out of turn.")
        }
    }
}
