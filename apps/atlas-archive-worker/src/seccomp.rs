//! The worker's system call filter (docs/DESIGN.md, "The sandbox"): what
//! Landlock doesn't cover. A compromised parser can't start a process (one
//! that outlived the worker would keep its rights on staging while the
//! client audits and moves it), open a socket of any kind (Landlock only
//! rules TCP), set extended attributes or ACLs, or reach the kernel's
//! larger attack surfaces (io_uring, BPF, perf, keyrings, namespaces).
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
    ];
    #[cfg(target_arch = "x86_64")]
    calls.extend([libc::SYS_fork, libc::SYS_vfork]);
    calls
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
