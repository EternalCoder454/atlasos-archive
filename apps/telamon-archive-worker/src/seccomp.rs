//! The worker's system call filter (docs/DESIGN.md, "The sandbox"): what
//! Landlock doesn't cover. A compromised parser can't start a process (one
//! that outlived the worker would keep its rights on staging while the
//! client audits and moves it), open a socket of any kind (Landlock only
//! rules TCP), set extended attributes or ACLs, or reach the kernel's
//! larger attack surfaces (io_uring, BPF, perf, keyrings, namespaces). Nor
//! can it reach another process of the same user: no System V or POSIX
//! message queues and shared memory, no limits, priorities or scheduling of
//! another process (only the caller's own, pid 0), no terminal injection
//! (`TIOCSTI` and its kin), no btrfs subvolume creation (a new subvolume in
//! staging is a tree the audit's `RENAME_NOREPLACE` and `unlinkat` can't
//! handle). Nor can it change its process group or session: the client
//! signals the worker's group by number, and that must stay the group the
//! client made.
//!
//! A deny list: everything else the parsers, the allocator and threads need
//! stays allowed. Denied calls fail with EPERM (`clone3` with ENOSYS, so
//! glibc falls back to `clone`, whose flags the filter can read); a call
//! from another architecture's table kills the process.

use std::io;

// BPF_LD | BPF_W | BPF_ABS, BPF_JMP | BPF_JEQ | BPF_K, BPF_JMP | BPF_JSET |
// BPF_K, BPF_RET | BPF_K.
const LD_W_ABS: u16 = 0x20;
const JMP_JEQ_K: u16 = 0x15;
const JMP_JSET_K: u16 = 0x45;
const RET_K: u16 = 0x06;

/// `struct seccomp_data` offsets: the call, the architecture, the low half
/// of the first argument (little-endian).
const NR: u32 = 0;
const ARCH: u32 = 4;
const ARG0_LOW: u32 = 16;
const ARG0_HIGH: u32 = 20;
const ARG1_LOW: u32 = 24;
const ARG1_HIGH: u32 = 28;

/// What a classic BPF program may hold.
const BPF_MAXINSNS: usize = 4096;

/// `ioctl` commands that reach beyond the worker: terminal input injection,
/// and the btrfs calls that make a subvolume or snapshot (`_IOW(0x94, n,
/// struct btrfs_ioctl_vol_args[_v2])`, 4096 bytes: n is 14, 1, 23 and 24).
const DENIED_IOCTLS: [u32; 9] = [
    0x5412,      // TIOCSTI
    0x541C,      // TIOCLINUX
    0x541D,      // TIOCCONS
    0x540E,      // TIOCSCTTY
    0x5423,      // TIOCSETD
    0x5000_940E, // BTRFS_IOC_SUBVOL_CREATE
    0x5000_9401, // BTRFS_IOC_SNAP_CREATE
    0x5000_9417, // BTRFS_IOC_SNAP_CREATE_V2
    0x5000_9418, // BTRFS_IOC_SUBVOL_CREATE_V2
];

#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH: u32 = 0xC000_003E;
#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH: u32 = 0xC000_00B7;

/// x32 calls on x86_64 carry this bit; never ours.
#[cfg(target_arch = "x86_64")]
const X32_SYSCALL_BIT: u32 = 0x4000_0000;

/// Newer than the libc crate's tables; the same number on every
/// architecture (the shared table from 424 on).
const SYS_SETXATTRAT: i64 = 463;
/// Missing from the libc crate's tables.
#[cfg(target_arch = "x86_64")]
const SYS_IO_PGETEVENTS: i64 = 333;
#[cfg(target_arch = "aarch64")]
const SYS_IO_PGETEVENTS: i64 = 292;
/// `removexattrat` and `fchmodat2`, newer than the libc crate's tables (the
/// shared table, the same number on every architecture).
const SYS_REMOVEXATTRAT: i64 = 466;
const SYS_FCHMODAT2: i64 = 452;
const SYS_QUOTACTL_FD: i64 = 443;
const SYS_LSM_GET_SELF_ATTR: i64 = 459;
const SYS_LSM_SET_SELF_ATTR: i64 = 460;
const SYS_LSM_LIST_MODULES: i64 = 461;
const SYS_OPEN_TREE_ATTR: i64 = 467;
const SYS_FILE_GETATTR: i64 = 468;
const SYS_FILE_SETATTR: i64 = 469;
const SYS_LISTNS: i64 = 470;
const SYS_STATMOUNT: i64 = 457;
const SYS_LISTMOUNT: i64 = 458;

fn denied() -> Vec<i64> {
    let mut calls = vec![
        // Processes: none may outlive the worker.
        libc::SYS_execve,
        libc::SYS_execveat,
        libc::SYS_unshare,
        libc::SYS_setns,
        libc::SYS_ptrace,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        libc::SYS_pidfd_open,
        libc::SYS_pidfd_getfd,
        // Landlock's signal scope covers it; denied anyway, with
        // process_mrelease (reaping another process's memory).
        libc::SYS_pidfd_send_signal,
        libc::SYS_process_mrelease,
        libc::SYS_process_madvise,
        // Network, of every family.
        libc::SYS_socket,
        libc::SYS_socketpair,
        // Extended attributes and ACLs.
        libc::SYS_setxattr,
        libc::SYS_lsetxattr,
        libc::SYS_fsetxattr,
        SYS_SETXATTRAT,
        libc::SYS_removexattr,
        libc::SYS_lremovexattr,
        libc::SYS_fremovexattr,
        SYS_REMOVEXATTRAT,
        // Landlock rules who may open, create, rename and remove, but not who
        // may change the mode, owner or times of a file that exists: a
        // compromised parser could `chmod` or `chown` any file of the user's
        // by its path. The worker changes modes only with `fchmod` on a
        // descriptor it opened below staging, so every call that takes a path
        // is denied (`utimensat` below is allowed only without one: that is
        // `futimens`).
        libc::SYS_fchownat,
        libc::SYS_fchown,
        libc::SYS_fchmodat,
        SYS_FCHMODAT2,
        // Kernel surfaces no parser needs.
        libc::SYS_io_uring_setup,
        libc::SYS_io_uring_enter,
        libc::SYS_io_uring_register,
        libc::SYS_bpf,
        libc::SYS_perf_event_open,
        libc::SYS_keyctl,
        libc::SYS_add_key,
        libc::SYS_request_key,
        libc::SYS_userfaultfd,
        libc::SYS_name_to_handle_at,
        libc::SYS_open_by_handle_at,
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_pivot_root,
        libc::SYS_chroot,
        libc::SYS_open_tree,
        libc::SYS_move_mount,
        libc::SYS_fsopen,
        libc::SYS_fsconfig,
        libc::SYS_fsmount,
        libc::SYS_fspick,
        libc::SYS_mount_setattr,
        libc::SYS_init_module,
        libc::SYS_finit_module,
        libc::SYS_delete_module,
        libc::SYS_kexec_load,
        libc::SYS_kexec_file_load,
        libc::SYS_reboot,
        libc::SYS_swapon,
        libc::SYS_swapoff,
        libc::SYS_acct,
        libc::SYS_quotactl,
        libc::SYS_kcmp,
        libc::SYS_syslog,
        libc::SYS_personality,
        libc::SYS_io_setup,
        libc::SYS_io_submit,
        libc::SYS_io_getevents,
        libc::SYS_io_cancel,
        libc::SYS_io_destroy,
        SYS_IO_PGETEVENTS,
        SYS_STATMOUNT,
        SYS_LISTMOUNT,
        // Newer siblings of calls denied above, and calls into the security
        // modules (a chosen SELinux label for new files): nothing here needs
        // them, and a kernel that has them should not hand them to a parser.
        SYS_QUOTACTL_FD,
        SYS_LSM_GET_SELF_ATTR,
        SYS_LSM_SET_SELF_ATTR,
        SYS_LSM_LIST_MODULES,
        SYS_OPEN_TREE_ATTR,
        SYS_FILE_GETATTR,
        SYS_FILE_SETATTR,
        SYS_LISTNS,
        libc::SYS_fanotify_init,
        libc::SYS_fanotify_mark,
        // Another process of the same user, by shared memory, message
        // queues or semaphores: nothing the parsers need.
        libc::SYS_shmget,
        libc::SYS_shmat,
        libc::SYS_shmdt,
        libc::SYS_shmctl,
        libc::SYS_msgget,
        libc::SYS_msgsnd,
        libc::SYS_msgrcv,
        libc::SYS_msgctl,
        libc::SYS_semget,
        libc::SYS_semop,
        libc::SYS_semtimedop,
        libc::SYS_semctl,
        libc::SYS_mq_open,
        libc::SYS_mq_unlink,
        libc::SYS_mq_timedsend,
        libc::SYS_mq_timedreceive,
        libc::SYS_mq_notify,
        libc::SYS_mq_getsetattr,
        // Process groups and sessions: the client made the worker's group
        // before the exec and signals it by number. A worker that joined
        // another group (the client's own) would have the client's stop and
        // kill signals land there. glibc's `setpgrp` is `setpgid(0, 0)`, and
        // neither architecture has a `setpgrp` call of its own.
        libc::SYS_setpgid,
        libc::SYS_setsid,
        // Priorities: the caller's own are the system's to keep.
        libc::SYS_setpriority,
        libc::SYS_ioprio_set,
        // Moving another process's pages between NUMA nodes.
        libc::SYS_migrate_pages,
        libc::SYS_move_pages,
    ];
    #[cfg(target_arch = "x86_64")]
    calls.extend([
        libc::SYS_fork,
        libc::SYS_vfork,
        libc::SYS_modify_ldt,
        libc::SYS_chmod,
        libc::SYS_chown,
        libc::SYS_lchown,
        libc::SYS_utime,
        libc::SYS_utimes,
        libc::SYS_futimesat,
    ]);
    calls
}

/// Calls that act on a process by its first argument, and so only on the
/// caller's own (pid 0). glibc's `setrlimit` is `prlimit64(0, ...)`. glibc
/// names a new thread by its tid when a pthread attribute sets affinity or
/// scheduling, so such a `pthread_create` would fail here: nothing in the
/// worker does that, and the 7z/unrar profile gets its own filter.
fn own_process_only() -> [i64; 5] {
    [
        libc::SYS_prlimit64,
        libc::SYS_sched_setscheduler,
        libc::SYS_sched_setparam,
        libc::SYS_sched_setattr,
        libc::SYS_sched_setaffinity,
    ]
}

fn stmt(code: u16, k: u32) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

fn jump(code: u16, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}

fn errno(e: i32) -> u32 {
    libc::SECCOMP_RET_ERRNO | e as u32
}

/// Allows call `nr` only when its first argument (both halves) is 0, else
/// EPERM; any other call goes on to the next check. 8 instructions.
fn allow_only_pid_zero(p: &mut Vec<libc::sock_filter>, nr: i64) {
    allow_only_zero_arg(p, nr, ARG0_LOW, ARG0_HIGH);
}

/// The same for an argument at other offsets: `utimensat` with no path
/// (`futimens`) is allowed, one with a path is not.
fn allow_only_zero_arg(p: &mut Vec<libc::sock_filter>, nr: i64, low: u32, high: u32) {
    p.extend([
        jump(JMP_JEQ_K, nr as u32, 0, 6),
        stmt(LD_W_ABS, low),
        jump(JMP_JEQ_K, 0, 0, 3),
        stmt(LD_W_ABS, high),
        jump(JMP_JEQ_K, 0, 0, 1),
        stmt(RET_K, libc::SECCOMP_RET_ALLOW),
        stmt(RET_K, errno(libc::EPERM)),
        stmt(LD_W_ABS, NR),
    ]);
}

/// `ioctl` fails with EPERM for each of `DENIED_IOCTLS` (the request is the
/// low half of the second argument); other requests go on.
fn deny_ioctls(p: &mut Vec<libc::sock_filter>) {
    let n = DENIED_IOCTLS.len();
    p.push(jump(
        JMP_JEQ_K,
        libc::SYS_ioctl as u32,
        0,
        (2 * n + 1) as u8,
    ));
    p.push(stmt(LD_W_ABS, ARG1_LOW));
    for cmd in DENIED_IOCTLS {
        p.push(jump(JMP_JEQ_K, cmd, 0, 1));
        p.push(stmt(RET_K, errno(libc::EPERM)));
    }
    p.push(stmt(LD_W_ABS, NR));
}

/// The filter program.
fn program() -> Vec<libc::sock_filter> {
    let mut p = vec![
        stmt(LD_W_ABS, ARCH),
        jump(JMP_JEQ_K, AUDIT_ARCH, 1, 0),
        stmt(RET_K, libc::SECCOMP_RET_KILL_PROCESS),
        stmt(LD_W_ABS, NR),
    ];
    #[cfg(target_arch = "x86_64")]
    p.extend([
        jump(JMP_JSET_K, X32_SYSCALL_BIT, 0, 1),
        stmt(RET_K, libc::SECCOMP_RET_KILL_PROCESS),
    ]);
    for nr in denied() {
        p.push(jump(JMP_JEQ_K, nr as u32, 0, 1));
        p.push(stmt(RET_K, errno(libc::EPERM)));
    }
    for nr in own_process_only() {
        allow_only_pid_zero(&mut p, nr);
    }
    allow_only_zero_arg(&mut p, libc::SYS_utimensat, ARG1_LOW, ARG1_HIGH);
    deny_ioctls(&mut p);
    p.push(jump(JMP_JEQ_K, libc::SYS_clone3 as u32, 0, 1));
    p.push(stmt(RET_K, errno(libc::ENOSYS)));
    // clone: threads only.
    p.extend([
        jump(JMP_JEQ_K, libc::SYS_clone as u32, 0, 3),
        stmt(LD_W_ABS, ARG0_LOW),
        jump(JMP_JSET_K, libc::CLONE_THREAD as u32, 1, 0),
        stmt(RET_K, errno(libc::EPERM)),
        stmt(RET_K, libc::SECCOMP_RET_ALLOW),
    ]);
    p
}

/// Installs the filter on every thread. Needs `PR_SET_NO_NEW_PRIVS`.
pub fn install() -> Result<(), String> {
    let mut filter = program();
    if filter.len() >= BPF_MAXINSNS {
        return Err("The sandbox's system call filter is too long.".into());
    }
    let prog = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_mut_ptr(),
    };
    // SAFETY: a valid program that outlives the call (the kernel copies it).
    let r = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER,
            libc::SECCOMP_FILTER_FLAG_TSYNC,
            &prog as *const libc::sock_fprog,
        )
    };
    if r != 0 {
        return Err(format!(
            "Couldn't set up the sandbox's system call filter: {}",
            io::Error::last_os_error()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_program_fits_and_jumps_stay_inside() {
        let p = program();
        assert!(p.len() < BPF_MAXINSNS, "{}", p.len());
        for (i, f) in p.iter().enumerate() {
            if f.code == JMP_JEQ_K || f.code == JMP_JSET_K {
                let end = i + 1 + f.jt.max(f.jf) as usize;
                assert!(end < p.len(), "jump out of the program at {i}");
            }
        }
        // The last instruction ends the program.
        assert_eq!(p.last().map(|f| f.code), Some(RET_K));
    }

    #[test]
    fn the_worker_cannot_change_its_group_or_session() {
        // In a child, so the filter is not put on the test process.
        // SAFETY: the child makes only prctl, setpgid, setsid, write and _exit
        // after the fork (the filter's own allocation is ordinary Rust, which
        // is fine after a fork: glibc's allocator survives it).
        unsafe {
            let pid = libc::fork();
            assert!(pid >= 0);
            if pid == 0 {
                let mut code = 0;
                if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 || install().is_err() {
                    code = 10;
                } else {
                    let r = libc::setpgid(0, 0);
                    if r != -1 || *libc::__errno_location() != libc::EPERM {
                        code = 11;
                    }
                    let r = libc::setsid();
                    if r != -1 || *libc::__errno_location() != libc::EPERM {
                        code = 12;
                    }
                    // Not a blanket ban: asking is fine.
                    if libc::getpgid(0) < 0 {
                        code = 13;
                    }
                }
                libc::_exit(code);
            }
            let mut status = 0;
            assert_eq!(libc::waitpid(pid, &mut status, 0), pid);
            assert!(
                libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
                "child status {status:#x}"
            );
        }
    }
}
