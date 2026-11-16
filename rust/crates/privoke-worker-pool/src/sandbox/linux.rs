//! Linux sandbox: `PR_SET_PDEATHSIG`, rlimits and a seccomp filter that denies the network.
//!
//! Everything runs in `pre_exec`, between `fork` and `exec`, so it uses raw system calls only and allocates nothing:
//! the seccomp program is built before the fork. `PR_SET_PDEATHSIG` fires when the *thread* that forked the worker
//! exits, so the pool must spawn from a thread that lives as long as the pool (a Tokio worker thread does).
//!
//! The pdeathsig covers the workers the pool starts. A worker's own children are only covered if the worker sets
//! pdeathsig on them too, because the setting is cleared across `fork`.

#![allow(unsafe_code)]

use std::io;
use std::os::unix::process::CommandExt as _;

use tokio::process::{Child, Command};

use super::SandboxPolicy;

#[derive(Debug)]
pub(super) struct Guard;

/// One classic-BPF instruction, as the kernel's `struct sock_filter`.
type Insn = libc::sock_filter;

const BPF_LD_W_ABS: u16 = 0x20; // BPF_LD | BPF_W | BPF_ABS
const BPF_JEQ_K: u16 = 0x15; // BPF_JMP | BPF_JEQ | BPF_K
#[cfg(target_arch = "x86_64")]
const BPF_JGE_K: u16 = 0x35; // BPF_JMP | BPF_JGE | BPF_K
const BPF_RET_K: u16 = 0x06; // BPF_RET | BPF_K

const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
const SECCOMP_MODE_FILTER: libc::c_ulong = 2;

/// `offsetof(struct seccomp_data, nr)` and `offsetof(struct seccomp_data, arch)`.
const DATA_NR: u32 = 0;
const DATA_ARCH: u32 = 4;

#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH: u32 = 0xC000_003E;
#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH: u32 = 0xC000_00B7;

/// The syscalls that reach the network. `socketpair` stays allowed: it is local to the process tree and has no peer
/// outside it. `io_uring` is denied because it can issue socket operations without these syscalls.
fn denied_syscalls() -> [libc::c_long; 12] {
    [
        libc::SYS_socket,
        libc::SYS_connect,
        libc::SYS_bind,
        libc::SYS_listen,
        libc::SYS_accept,
        libc::SYS_accept4,
        libc::SYS_sendto,
        libc::SYS_sendmsg,
        libc::SYS_sendmmsg,
        libc::SYS_io_uring_setup,
        libc::SYS_io_uring_enter,
        libc::SYS_io_uring_register,
    ]
}

fn stmt(code: u16, k: u32) -> Insn {
    Insn { code, jt: 0, jf: 0, k }
}

fn jump(code: u16, k: u32, jt: u8, jf: u8) -> Insn {
    Insn { code, jt, jf, k }
}

/// Builds the filter: any other architecture is killed (so the 32-bit entry points cannot bypass the list), x32 calls
/// are refused, and each denied syscall returns `EPERM`.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn seccomp_program() -> io::Result<Vec<Insn>> {
    let deny = SECCOMP_RET_ERRNO | libc::EPERM as u32;
    let mut program = vec![
        stmt(BPF_LD_W_ABS, DATA_ARCH),
        jump(BPF_JEQ_K, AUDIT_ARCH, 1, 0),
        stmt(BPF_RET_K, SECCOMP_RET_KILL_PROCESS),
        stmt(BPF_LD_W_ABS, DATA_NR),
    ];
    #[cfg(target_arch = "x86_64")]
    {
        // x32 syscalls share the architecture and set bit 30 of the number.
        program.push(jump(BPF_JGE_K, 0x4000_0000, 0, 1));
        program.push(stmt(BPF_RET_K, deny));
    }
    for nr in denied_syscalls() {
        let nr = u32::try_from(nr).map_err(|_| io::Error::other("syscall number out of range"))?;
        program.push(jump(BPF_JEQ_K, nr, 0, 1));
        program.push(stmt(BPF_RET_K, deny));
    }
    program.push(stmt(BPF_RET_K, SECCOMP_RET_ALLOW));
    Ok(program)
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
fn seccomp_program() -> io::Result<Vec<Insn>> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "network denial has no seccomp filter for this architecture"))
}

#[cfg(target_env = "gnu")]
type Resource = libc::__rlimit_resource_t;
#[cfg(not(target_env = "gnu"))]
type Resource = libc::c_int;

fn set_rlimit(resource: Resource, value: u64) -> io::Result<()> {
    let limit = libc::rlimit { rlim_cur: value as libc::rlim_t, rlim_max: value as libc::rlim_t };
    // SAFETY: `limit` is a valid rlimit that outlives the call.
    if unsafe { libc::setrlimit(resource, &limit) } == 0 { Ok(()) } else { Err(io::Error::last_os_error()) }
}

pub(super) fn prepare(command: &mut Command, policy: &SandboxPolicy) -> io::Result<()> {
    let mut filter = if policy.deny_network { Some(seccomp_program()?) } else { None };
    let kill_with_parent = policy.kill_with_parent;
    let memory = policy.memory_limit_bytes;
    let processes = policy.max_processes.map(u64::from);
    // SAFETY: getpid has no preconditions.
    let parent = unsafe { libc::getpid() };
    let std_command = command.as_std_mut();
    // SAFETY: the closure calls only async-signal-safe functions (prctl, getppid, setrlimit) and allocates nothing; the
    // filter vector was built before the fork and is only read.
    unsafe {
        std_command.pre_exec(move || {
            if kill_with_parent {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL as libc::c_ulong, 0, 0, 0) != 0 {
                    return Err(io::Error::last_os_error());
                }
                // The parent may have died between fork and prctl; the signal would never come.
                if libc::getppid() != parent {
                    return Err(io::Error::from_raw_os_error(libc::ESRCH));
                }
            }
            set_rlimit(libc::RLIMIT_CORE, 0)?;
            if let Some(bytes) = memory {
                set_rlimit(libc::RLIMIT_AS, bytes)?;
            }
            if let Some(count) = processes {
                set_rlimit(libc::RLIMIT_NPROC, count)?;
            }
            if let Some(program) = filter.as_mut() {
                if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                    return Err(io::Error::last_os_error());
                }
                let mut fprog = libc::sock_fprog { len: program.len() as libc::c_ushort, filter: program.as_mut_ptr() };
                if libc::prctl(libc::PR_SET_SECCOMP, SECCOMP_MODE_FILTER, std::ptr::addr_of_mut!(fprog)) != 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    Ok(())
}

pub(super) fn attach(_child: &Child, _policy: &SandboxPolicy) -> io::Result<Guard> {
    Ok(Guard)
}
