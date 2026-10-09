//! Entering the sandbox, before the worker reads a byte of the archive
//! (docs/DESIGN.md, "The sandbox").

use std::ffi::c_uint;
use std::os::fd::{BorrowedFd, OwnedFd, RawFd};

use landlock::{
    ABI, Access, AccessFs, AccessNet, CompatLevel, Compatible, PathBeneath, PathFd, Ruleset,
    RulesetAttr, RulesetCreatedAttr, RulesetStatus, Scope,
};

/// The newest Landlock ABI this code was written and tested against; older
/// kernels get what they support (best effort), newer ones no more.
const ABI_TESTED: ABI = ABI::V9;
/// What the worker won't run without: the file system rights, TCP and the
/// scopes (no signals or abstract sockets outside). Newer rights (unix
/// socket paths) are best effort; the seccomp filter denies sockets anyway.
const ABI_REQUIRED: ABI = ABI::V6;
/// `ABI_REQUIRED` as the number users and the kernel docs call it.
const ABI_REQUIRED_NUMBER: u32 = 6;

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

unsafe extern "C" {
    /// glibc's; the libc crate doesn't bind it.
    fn tzset();
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
/// limits, the C.UTF-8 locale, Landlock (read `/usr` and `reads`; write only below
/// `staging`; run nothing; no network, no signals or abstract sockets
/// outside), then the system call filter (`seccomp`).
pub fn enter(
    staging: Option<BorrowedFd<'_>>,
    reads: impl IntoIterator<Item = (OwnedFd, bool)>,
) -> Result<(), String> {
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
    // glibc reads /etc/localtime on the first local-time conversion
    // (libarchive's zip DOS times, iso9660 and cab dates); Landlock allows
    // /usr only, so it is read now, while it can be.
    // SAFETY: tzset takes no arguments; the worker is single-threaded here.
    unsafe { tzset() };
    landlock(staging, reads)?;
    crate::seccomp::install()
}

fn landlock(
    staging: Option<BorrowedFd<'_>>,
    reads: impl IntoIterator<Item = (OwnedFd, bool)>,
) -> Result<(), String> {
    let abi = ABI_TESTED;
    let fail = |e: landlock::RulesetError| format!("Couldn't set up the sandbox: {e}");
    // A kernel without Landlock, or with too old a Landlock, fails while the
    // ruleset is made: say so in plain words and keep the crate's text for
    // the log.
    let unsupported = |e: landlock::RulesetError| {
        telamon_archive_engine::log_line!("Landlock isn't available: {e}");
        format!(
            "This system's kernel doesn't offer the sandbox Telamon Archive needs (Landlock ABI {ABI_REQUIRED_NUMBER}), so it won't open archives."
        )
    };
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
    // A test build may run on a kernel without Landlock; a real one refuses
    // a kernel short of the required rights.
    let required = if cfg!(feature = "unsandboxed") {
        CompatLevel::BestEffort
    } else {
        CompatLevel::HardRequirement
    };
    let ruleset = Ruleset::default()
        .set_compatibility(required)
        .handle_access(AccessFs::from_all(ABI_REQUIRED))
        .and_then(|r| r.handle_access(AccessNet::from_all(ABI_REQUIRED)))
        .and_then(|r| r.scope(Scope::from_all(ABI_REQUIRED)))
        .map(|r| r.set_compatibility(CompatLevel::BestEffort))
        .and_then(|r| r.handle_access(AccessFs::from_all(abi)))
        .and_then(|r| r.handle_access(AccessNet::from_all(abi)))
        .and_then(|r| r.scope(Scope::from_all(abi)))
        .and_then(|r| r.create())
        .map_err(unsupported)?;
    // Reading, never running: the worker starts no program.
    let mut ruleset = ruleset
        .add_rule(PathBeneath::new(
            usr,
            AccessFs::from_read(abi) & !AccessFs::Execute,
        ))
        .map_err(fail)?;
    if let Some(dir) = staging {
        ruleset = ruleset
            .add_rule(PathBeneath::new(dir, write))
            .map_err(fail)?;
    }
    // The sources of a Create job: each file or folder it was given, read
    // only (never run, never changed).
    for (fd, is_dir) in reads {
        let access = if is_dir {
            AccessFs::from_read(abi) & !AccessFs::Execute
        } else {
            AccessFs::ReadFile.into()
        };
        ruleset = ruleset
            .add_rule(PathBeneath::new(&fd, access))
            .map_err(fail)?;
    }
    let status = ruleset.restrict_self().map_err(fail)?;
    match status.ruleset {
        RulesetStatus::FullyEnforced => Ok(()),
        // Everything required is in force (or creating the ruleset failed).
        RulesetStatus::PartiallyEnforced => Ok(()),
        RulesetStatus::NotEnforced if cfg!(feature = "unsandboxed") => {
            telamon_archive_engine::log_line!("running WITHOUT a sandbox (test build)");
            Ok(())
        }
        RulesetStatus::NotEnforced => Err(
            "Telamon Archive can't open archives safely here: this system's kernel has Landlock turned off.".into(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::process::Command;

    const CHILD: &str = "TELAMON_ARCHIVE_SANDBOX_CHILD";

    fn scratch() -> PathBuf {
        // On disk, in the cargo target dir, never in tmpfs.
        let base = std::env::var_os("TELAMON_ARCHIVE_TEST_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                std::env::current_exe()
                    .unwrap()
                    .parent()
                    .unwrap()
                    .join("../test-scratch")
            });
        base.join(format!("telamon-sandbox-{}", std::process::id()))
    }

    /// Runs in a child process (see `the_sandbox_holds`): sandboxes itself,
    /// then tries what a compromised parser would.
    #[test]
    fn sandboxed_child() {
        let Some(dir) = std::env::var_os(CHILD).map(PathBuf::from) else {
            return;
        };
        let staging = std::fs::File::open(dir.join("staging")).unwrap();
        // A terminal to inject input into, opened before the sandbox closes
        // /dev/pts.
        let (mut master, mut slave) = (-1, -1);
        // SAFETY: valid out-pointers; null name, termios and window size.
        let pty = unsafe {
            libc::openpty(
                &mut master,
                &mut slave,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
            )
        };
        assert_eq!(pty, 0, "openpty");
        // The sources of a Create job: one folder, one file.
        let src_dir = std::fs::File::open(dir.join("src-dir")).unwrap();
        let src_file = std::fs::File::open(dir.join("src-file")).unwrap();
        enter(
            Some(staging.as_fd()),
            [
                (src_dir.try_clone().unwrap().into(), true),
                (src_file.try_clone().unwrap().into(), false),
            ],
        )
        .unwrap();
        assert_eq!(std::fs::read(dir.join("src-dir/in.txt")).unwrap(), b"in");
        assert_eq!(std::fs::read(dir.join("src-file")).unwrap(), b"file");
        assert!(std::fs::read_dir(dir.join("src-dir")).is_ok());
        let denied0 =
            |r: std::io::Result<()>| matches!(r, Err(e) if e.raw_os_error() == Some(libc::EACCES));
        assert!(
            denied0(std::fs::read(dir.join("sibling")).map(drop)),
            "read a sibling"
        );
        assert!(
            denied0(std::fs::write(dir.join("src-dir/in.txt"), b"x")),
            "write a source"
        );
        assert!(
            denied0(std::fs::write(dir.join("src-dir/new"), b"x")),
            "add to a source"
        );
        assert!(
            denied0(std::fs::write(dir.join("src-file"), b"x")),
            "write a source file"
        );
        assert!(
            denied0(std::fs::remove_file(dir.join("src-dir/in.txt"))),
            "remove from a source"
        );
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
        // The system call filter: no sockets of any family, no processes,
        // no extended attributes; threads still work.
        let eperm =
            |r: i64| r == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM);
        // SAFETY: plain calls; a descriptor that comes back is leaked.
        unsafe {
            assert!(
                eperm(libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0).into()),
                "UDP"
            );
            assert!(
                eperm(libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0).into()),
                "unix"
            );
            assert!(
                eperm(libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, 0).into()),
                "netlink"
            );
            let pid = libc::fork();
            if pid == 0 {
                libc::_exit(0);
            }
            assert!(eperm(pid.into()), "fork");
        }
        assert!(
            std::process::Command::new("/usr/bin/true")
                .status()
                .is_err(),
            "run a program"
        );
        assert_eq!(std::thread::spawn(|| 7).join().unwrap(), 7, "threads");
        // Same-user processes and terminals stay out of reach.
        // SAFETY: plain calls; null or valid pointers of the right size.
        unsafe {
            assert!(
                eperm(libc::shmget(libc::IPC_PRIVATE, 4096, 0o600).into()),
                "shmget"
            );
            assert!(
                eperm(libc::msgget(libc::IPC_PRIVATE, 0o600).into()),
                "msgget"
            );
            assert!(
                eperm(libc::semget(libc::IPC_PRIVATE, 1, 0o600).into()),
                "semget"
            );
            let mut old = std::mem::MaybeUninit::<libc::rlimit>::uninit();
            assert!(
                eperm(
                    libc::prlimit(
                        // 0 when the parent is outside our PID namespace,
                        // which would ask about ourselves.
                        libc::getppid().max(1),
                        libc::RLIMIT_NOFILE,
                        std::ptr::null(),
                        old.as_mut_ptr()
                    )
                    .into()
                ),
                "prlimit64 on the parent"
            );
            // Its own limits (what glibc's setrlimit does) still work.
            assert_eq!(
                libc::prlimit(0, libc::RLIMIT_NOFILE, std::ptr::null(), old.as_mut_ptr()),
                0,
                "prlimit64 on itself"
            );
            assert!(
                eperm(libc::setpriority(libc::PRIO_PROCESS, 0, 0).into()),
                "setpriority"
            );
            let c = b'x';
            assert!(
                eperm(libc::ioctl(slave, libc::TIOCSTI, &c as *const u8).into()),
                "TIOCSTI"
            );
            assert!(
                eperm(libc::ioctl(slave, 0x5000_940E_u32 as _, std::ptr::null::<u8>()).into()),
                "btrfs subvolume create"
            );
            assert_eq!(libc::ioctl(slave, libc::TCGETS, std::ptr::null::<u8>()), -1);
            assert_ne!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::EPERM),
                "other terminal calls aren't denied by the filter"
            );
        }
        let ok =
            std::ffi::CString::new(dir.join("staging/ok").into_os_string().into_encoded_bytes())
                .unwrap();
        // SAFETY: C strings and a buffer of the given length.
        let r =
            unsafe { libc::setxattr(ok.as_ptr(), c"user.x".as_ptr(), b"1".as_ptr().cast(), 1, 0) };
        assert!(eperm(r.into()), "xattr");
        // Landlock does not rule the mode, owner, times or extended attributes
        // of files that exist: the filter must. `sibling` is the user's own
        // file outside staging, as any file of the user's would be.
        let sib = std::ffi::CString::new(dir.join("sibling").into_os_string().into_encoded_bytes())
            .unwrap();
        let ts = [libc::timespec {
            tv_sec: 1,
            tv_nsec: 0,
        }; 2];
        // SAFETY: C strings, valid pointers and plain integers.
        unsafe {
            let uid = libc::getuid();
            let gid = libc::getgid();
            assert!(
                eperm(libc::chmod(sib.as_ptr(), 0o777).into()),
                "chmod by path"
            );
            assert!(
                eperm(libc::fchmodat(libc::AT_FDCWD, sib.as_ptr(), 0o777, 0).into()),
                "fchmodat"
            );
            assert!(
                eperm(libc::syscall(452, libc::AT_FDCWD, sib.as_ptr(), 0o777, 0)),
                "fchmodat2"
            );
            assert!(eperm(libc::chown(sib.as_ptr(), uid, gid).into()), "chown");
            assert!(eperm(libc::lchown(sib.as_ptr(), uid, gid).into()), "lchown");
            assert!(
                eperm(libc::fchownat(libc::AT_FDCWD, sib.as_ptr(), uid, gid, 0).into()),
                "fchownat"
            );
            assert!(
                eperm(libc::utimensat(libc::AT_FDCWD, sib.as_ptr(), ts.as_ptr(), 0).into()),
                "utimensat by path"
            );
            assert!(
                eperm(libc::utimes(sib.as_ptr(), std::ptr::null()).into()),
                "utimes"
            );
            assert!(
                eperm(libc::removexattr(sib.as_ptr(), c"user.x".as_ptr()).into()),
                "removexattr"
            );
            assert!(
                eperm(libc::lremovexattr(sib.as_ptr(), c"user.x".as_ptr()).into()),
                "lremovexattr"
            );
            // What extraction does still works, through a descriptor it opened
            // below staging: fchmod and futimens.
            let fd = libc::open(ok.as_ptr(), libc::O_RDWR | libc::O_NOFOLLOW);
            assert!(fd >= 0, "open a staged file");
            assert_eq!(libc::fchmod(fd, 0o600), 0, "fchmod on a staged file");
            assert_eq!(
                libc::futimens(fd, ts.as_ptr()),
                0,
                "futimens on a staged file"
            );
            libc::close(fd);
            // Calls that reach other processes, namespaces and the kernel's
            // larger surfaces stay out of reach (each denied by number, so the
            // check does not depend on libc's wrappers).
            for (name, nr, args) in [
                ("ptrace", libc::SYS_ptrace, [0u64, 0, 0, 0]),
                (
                    "unshare",
                    libc::SYS_unshare,
                    [libc::CLONE_NEWNS as u64, 0, 0, 0],
                ),
                ("setns", libc::SYS_setns, [0, 0, 0, 0]),
                ("io_uring_setup", libc::SYS_io_uring_setup, [1, 0, 0, 0]),
                ("bpf", libc::SYS_bpf, [0, 0, 0, 0]),
                ("perf_event_open", libc::SYS_perf_event_open, [0, 0, 0, 0]),
                ("keyctl", libc::SYS_keyctl, [0, 0, 0, 0]),
                ("userfaultfd", libc::SYS_userfaultfd, [0, 0, 0, 0]),
                ("mount", libc::SYS_mount, [0, 0, 0, 0]),
                ("open_tree", libc::SYS_open_tree, [0, 0, 0, 0]),
                ("fsopen", libc::SYS_fsopen, [0, 0, 0, 0]),
                ("pidfd_open", libc::SYS_pidfd_open, [1, 0, 0, 0]),
                ("process_vm_readv", libc::SYS_process_vm_readv, [1, 0, 0, 0]),
                ("kcmp", libc::SYS_kcmp, [0, 0, 0, 0]),
                (
                    "name_to_handle_at",
                    libc::SYS_name_to_handle_at,
                    [0, 0, 0, 0],
                ),
                ("quotactl_fd", 443, [0, 0, 0, 0]),
                ("lsm_set_self_attr", 460, [0, 0, 0, 0]),
                ("open_tree_attr", 467, [0, 0, 0, 0]),
                ("file_setattr", 469, [0, 0, 0, 0]),
                ("fanotify_init", libc::SYS_fanotify_init, [0, 0, 0, 0]),
                // fork by clone: no CLONE_THREAD
                (
                    "clone without CLONE_THREAD",
                    libc::SYS_clone,
                    [libc::SIGCHLD as u64, 0, 0, 0],
                ),
            ] {
                assert!(
                    eperm(libc::syscall(nr, args[0], args[1], args[2], args[3])),
                    "{name}"
                );
            }
        }
        assert_eq!(
            std::fs::metadata(dir.join("sibling"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            std::fs::metadata(dir.join("secret"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            "the sibling's mode did not change"
        );
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
        std::fs::create_dir_all(dir.join("src-dir")).unwrap();
        std::fs::write(dir.join("src-dir/in.txt"), b"in").unwrap();
        std::fs::write(dir.join("src-file"), b"file").unwrap();
        std::fs::write(dir.join("sibling"), b"sib").unwrap();
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
