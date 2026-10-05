//! The sandboxed worker (docs/DESIGN.md, "The sandbox"). The GUI and the CLI
//! start one per operation, with these descriptors and nothing else open:
//! 0 requests, 1 replies, 2 the log, 3 the archive, 4 the staging folder
//! (extraction only). It takes no arguments, does one job, and exits.
//!
//! Requests: an optional `Password`, then one of `List`, `Test` or
//! `Extract` (during which `GoOn` answers a `Limit`). The last reply is
//! always `Listed`, `Done`, `NeedPassword` or `Failed`; anything else means
//! the worker died, and the client says so.

mod sandbox;

use std::collections::HashSet;
use std::fs::File;
use std::io;
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::process::ExitCode;

use atlas_archive_core::limits::Limits;
use atlas_archive_core::name::NameEncoding;
use atlas_archive_core::proto::{Reply, Request};
use atlas_archive_engine::extract::read_umask;
use atlas_archive_engine::job::{self, Conn, ExtractJob, Pipes};
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
        eprintln!(
            "atlas-archive-worker: Atlas Archive starts this program itself; it takes no arguments."
        );
        return ExitCode::from(2);
    }
    // Before anything else: nothing inherited past the contract stays open.
    sandbox::close_others(STAGING + 1);
    let (Some(requests), Some(replies)) = (take(REQUESTS), take(REPLIES)) else {
        eprintln!("atlas-archive-worker: no request or reply pipe");
        return ExitCode::from(2);
    };
    let mut conn = Pipes {
        input: File::from(requests),
        output: File::from(replies),
    };
    let archive = take(ARCHIVE);
    // Only a folder: a rule for anything else would give Landlock rights
    // it can't apply.
    let staging = take(STAGING).filter(|s| kind_of(s) == Some(libc::S_IFDIR));
    if let Err(reason) = sandbox::enter(staging.as_ref().map(AsFd::as_fd)) {
        eprintln!("atlas-archive-worker: {reason}");
        let _ = conn.send(&Reply::Failed { reason });
        return ExitCode::from(2);
    }
    match run(&mut conn, archive, staging) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            // A broken pipe or a bad frame: the client has gone or is not
            // speaking the protocol. Never the content of a frame.
            eprintln!("atlas-archive-worker: {e}");
            ExitCode::FAILURE
        }
    }
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
    match request {
        Request::List => job::list(conn, archive.as_fd()),
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
                return fail(conn, "The name encoding isn't one Atlas Archive knows.");
            };
            let limits = Limits::new(job::free_space(staging.as_fd()));
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
        Request::Password(_) | Request::GoOn(_) => fail(conn, "The request came out of turn."),
    }
}
