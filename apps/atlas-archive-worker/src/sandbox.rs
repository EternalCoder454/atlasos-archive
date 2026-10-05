//! Entering the sandbox, before the worker reads a byte of the archive
//! (docs/DESIGN.md, "The sandbox").

use std::ffi::c_uint;
use std::os::fd::{BorrowedFd, RawFd};

use landlock::{
    ABI, Access, AccessFs, AccessNet, PathBeneath, PathFd, Ruleset, RulesetAttr,
    RulesetCreatedAttr, RulesetStatus, Scope,
};

/// The newest Landlock ABI this code was written and tested against; older
/// kernels get what they support (best effort), newer ones no more.
const ABI_TESTED: ABI = ABI::V9;

/// Address space: the largest 7z dictionary is 1.5 GiB.
const MAX_ADDRESS_SPACE: u64 = 4 << 30;
const MAX_FILES: u64 = 256;

/// Closes every descriptor from `from` up, so nothing the client leaked
/// reaches the parsers.
pub fn close_others(from: RawFd) {
    // SAFETY: close_range takes no pointers; descriptors at or above `from`
    // are not owned by anything in this process yet.
    let r = unsafe {
        libc::syscall(
            libc::SYS_close_range,
            from as c_uint,
            c_uint::MAX,
            0 as c_uint,
        )
    };
    if r != 0 {
        // Kernels before 5.9.
        for fd in from..1024 {
            // SAFETY: as above.
            unsafe { libc::close(fd) };
        }
    }
}

fn os_error(what: &str) -> String {
    format!("{what}: {}", std::io::Error::last_os_error())
}

fn limit(resource: libc::__rlimit_resource_t, value: u64) -> Result<(), String> {
    let lim = libc::rlimit {
        rlim_cur: value,
        rlim_max: value,
    };
    // SAFETY: a valid rlimit struct.
    if unsafe { libc::setrlimit(resource, &lim) } != 0 {
        return Err(os_error("Couldn't set a resource limit"));
    }
    Ok(())
}

/// Locks the process down: no new privileges, no core dumps, resource
/// limits, the C.UTF-8 locale, and Landlock (read `/usr`; write only below
/// `staging`; no network, no signals or abstract sockets outside).
pub fn enter(staging: Option<BorrowedFd<'_>>) -> Result<(), String> {
    // SAFETY: plain prctl calls with integer arguments.
    unsafe {
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            return Err(os_error("Couldn't drop privileges"));
        }
        if libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) != 0 {
            return Err(os_error("Couldn't turn off core dumps"));
        }
    }
    limit(libc::RLIMIT_CORE, 0)?;
    limit(libc::RLIMIT_NOFILE, MAX_FILES)?;
    limit(libc::RLIMIT_AS, MAX_ADDRESS_SPACE)?;
    // libarchive converts names it knows to be UTF-16 or UTF-8 into the
    // locale's charset; C.UTF-8 keeps them UTF-8 (built into glibc).
    // SAFETY: a static C string.
    if unsafe { libc::setlocale(libc::LC_ALL, c"C.UTF-8".as_ptr()) }.is_null() {
        return Err("The C.UTF-8 locale is missing.".into());
    }
    landlock(staging)
}

fn landlock(staging: Option<BorrowedFd<'_>>) -> Result<(), String> {
    let abi = ABI_TESTED;
    let fail = |e: landlock::RulesetError| format!("Couldn't set up the sandbox: {e}");
    // What extraction does in staging; never devices, FIFOs, sockets or
    // running anything.
    let write = AccessFs::ReadFile
        | AccessFs::ReadDir
        | AccessFs::WriteFile
        | AccessFs::Truncate
        | AccessFs::MakeReg
        | AccessFs::MakeDir
        | AccessFs::MakeSym
        | AccessFs::RemoveFile
        | AccessFs::RemoveDir
        | AccessFs::Refer;
    let usr = PathFd::new("/usr").map_err(|e| format!("Couldn't set up the sandbox: {e}"))?;
    let mut ruleset = Ruleset::default()
        .handle_access(AccessFs::from_all(abi))
        .and_then(|r| r.handle_access(AccessNet::from_all(abi)))
        .and_then(|r| r.scope(Scope::from_all(abi)))
        .and_then(|r| r.create())
        .and_then(|r| r.add_rule(PathBeneath::new(usr, AccessFs::from_read(abi))))
        .map_err(fail)?;
    if let Some(dir) = staging {
        ruleset = ruleset
            .add_rule(PathBeneath::new(dir, write))
            .map_err(fail)?;
    }
    let status = ruleset.restrict_self().map_err(fail)?;
    match status.ruleset {
        RulesetStatus::FullyEnforced => Ok(()),
        RulesetStatus::PartiallyEnforced => {
            eprintln!("atlas-archive-worker: this kernel supports only part of the sandbox; using that part");
            Ok(())
        }
        RulesetStatus::NotEnforced if cfg!(feature = "unsandboxed") => {
            eprintln!("atlas-archive-worker: running WITHOUT a sandbox (test build)");
            Ok(())
        }
        RulesetStatus::NotEnforced => Err(
            "Atlas Archive can't open archives safely here: this system's kernel has Landlock turned off.".into(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd;
    use std::path::PathBuf;
    use std::process::Command;

    const CHILD: &str = "ATLAS_ARCHIVE_SANDBOX_CHILD";

    fn scratch() -> PathBuf {
        let base = std::env::var_os("ATLAS_ARCHIVE_TEST_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        base.join(format!("atlas-sandbox-{}", std::process::id()))
    }

    /// Runs in a child process (see `the_sandbox_holds`): sandboxes itself,
    /// then tries what a compromised parser would.
    #[test]
    fn sandboxed_child() {
        let Some(dir) = std::env::var_os(CHILD).map(PathBuf::from) else {
            return;
        };
        let staging = std::fs::File::open(dir.join("staging")).unwrap();
        enter(Some(staging.as_fd())).unwrap();
        // Inside staging: allowed.
        std::fs::write(dir.join("staging/ok"), b"ok").unwrap();
        std::os::unix::fs::symlink("ok", dir.join("staging/link")).unwrap();
        // Beside it, and anywhere else: refused.
        let denied =
            |r: std::io::Result<()>| matches!(r, Err(e) if e.raw_os_error() == Some(libc::EACCES));
        assert!(
            denied(std::fs::write(dir.join("outside"), b"x")),
            "write beside staging"
        );
        assert!(
            denied(std::fs::read(dir.join("secret")).map(drop)),
            "read beside staging"
        );
        assert!(denied(std::fs::read_dir("/etc").map(drop)), "list /etc");
        let p = std::ffi::CString::new(
            dir.join("staging/fifo")
                .into_os_string()
                .into_encoded_bytes(),
        )
        .unwrap();
        // SAFETY: as above.
        assert_eq!(
            unsafe { libc::mkfifo(p.as_ptr(), 0o600) },
            -1,
            "no FIFOs even in staging"
        );
        assert!(std::fs::read_dir("/usr").is_ok(), "read /usr");
        // SAFETY: plain call.
        assert_eq!(
            unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) },
            1
        );
        assert!(std::net::TcpStream::connect("127.0.0.1:9").is_err());
    }

    #[test]
    fn the_sandbox_holds() {
        if std::env::var_os(CHILD).is_some() {
            return;
        }
        let dir = scratch();
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("staging")).unwrap();
        std::fs::write(dir.join("secret"), b"s").unwrap();
        let out = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "sandbox::tests::sandboxed_child",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD, &dir)
            .output()
            .unwrap();
        let log = String::from_utf8_lossy(&out.stderr).into_owned()
            + &String::from_utf8_lossy(&out.stdout);
        if !cfg!(feature = "unsandboxed") {
            assert!(out.status.success(), "{log}");
            assert!(log.contains("1 passed"), "{log}");
        }
        assert!(!dir.join("outside").exists());
        assert_eq!(
            std::fs::read(dir.join("staging/ok")).ok().as_deref(),
            Some(&b"ok"[..])
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
