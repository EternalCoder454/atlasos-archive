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
//! handle).
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
        libc::SYS_process_madvise,
        // Network, of every family.
        libc::SYS_socket,
        libc::SYS_socketpair,
        // Extended attributes and ACLs.
        libc::SYS_setxattr,
        libc::SYS_lsetxattr,
        libc::SYS_fsetxattr,
        SYS_SETXATTRAT,
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
        // Priorities: the caller's own are the system's to keep.
        libc::SYS_setpriority,
        libc::SYS_ioprio_set,
        // Moving another process's pages between NUMA nodes.
        libc::SYS_migrate_pages,
        libc::SYS_move_pages,
    ];
    #[cfg(target_arch = "x86_64")]
    calls.extend([libc::SYS_fork, libc::SYS_vfork, libc::SYS_modify_ldt]);
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
    p.extend([
        jump(JMP_JEQ_K, nr as u32, 0, 6),
        stmt(LD_W_ABS, ARG0_LOW),
        jump(JMP_JEQ_K, 0, 0, 3),
        stmt(LD_W_ABS, ARG0_HIGH),
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
}
