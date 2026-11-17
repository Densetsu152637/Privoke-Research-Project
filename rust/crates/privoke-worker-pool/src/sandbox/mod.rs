//! The operating-system sandbox around each worker process.
//!
//! | Control | Windows | Linux |
//! | --- | --- | --- |
//! | Dies with the parent | Job Object with kill-on-close | `PR_SET_PDEATHSIG` (SIGKILL) |
//! | Memory limit | Job memory limit | `RLIMIT_AS` |
//! | Process limit | Job active-process limit (counts the worker) | `RLIMIT_NPROC` (a per-user ceiling) |
//! | No core dumps | - | `RLIMIT_CORE` 0 |
//! | Network denied | **Not provided** | seccomp filter on `socket`, `connect`, `bind`, `listen`, `accept`, `send*`, `io_uring` |
//! | Clean environment, explicit `PYTHONHOME` | yes | yes |
//!
//! Windows has no network denial here: the Job Object gives lifetime and resource limits only. The worker's own
//! self-check (it refuses to start when it can open a socket in sandboxed mode) and the absence of network code are
//! the controls there. [`network_denial_enforced`] says which case applies, and a policy that asks for network denial
//! on Windows logs a warning instead of claiming it.
//!
//! Every control that is asked for and cannot be installed fails the spawn, so a worker never runs less confined than
//! its policy says.

use std::ffi::OsString;
use std::io;
use std::path::PathBuf;

use tokio::process::{Child, Command};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
use linux as imp;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
use windows as imp;

#[cfg(not(any(target_os = "linux", windows)))]
mod other;
#[cfg(not(any(target_os = "linux", windows)))]
use other as imp;

/// What to confine a worker with.
#[derive(Clone, Debug)]
pub struct SandboxPolicy {
    /// Kill the worker when the parent dies, however the parent dies. Default true.
    pub kill_with_parent: bool,
    /// Memory ceiling in bytes. On Windows it covers the worker and its descendants together (committed memory); on
    /// Linux it limits each process's address space. A worker over it fails its allocation and dies.
    pub memory_limit_bytes: Option<u64>,
    /// Process ceiling. On Windows it is the number of live processes in the worker's job, the worker included, so 1
    /// forbids children. On Linux it is `RLIMIT_NPROC`, the ceiling for the whole real user, so choose it above the
    /// user's current count plus the worker's needs.
    pub max_processes: Option<u32>,
    /// Deny every network operation. Enforced on Linux only; see [`network_denial_enforced`].
    pub deny_network: bool,
    /// Start from an empty environment instead of the parent's. Only [`SandboxPolicy::inherit_env`], the platform
    /// baseline (`SystemRoot` on Windows), `python_home` and the pool's explicit variables reach the worker.
    pub clean_env: bool,
    /// Names of parent variables to pass through when `clean_env` is on.
    pub inherit_env: Vec<OsString>,
    /// Sets `PYTHONHOME` (and `PYTHONNOUSERSITE=1`) so an embedded interpreter never searches the host.
    pub python_home: Option<PathBuf>,
}

impl Default for SandboxPolicy {
    /// Lifetime control only: the worker dies with the parent, and nothing else changes.
    fn default() -> Self {
        Self {
            kill_with_parent: true,
            memory_limit_bytes: None,
            max_processes: None,
            deny_network: false,
            clean_env: false,
            inherit_env: Vec::new(),
            python_home: None,
        }
    }
}

impl SandboxPolicy {
    /// The full policy for a worker that needs no network: dies with the parent, clean environment, an explicit
    /// `PYTHONHOME`, network denied where the platform can. Add memory and process limits as the worker needs.
    pub fn strict(python_home: impl Into<PathBuf>) -> Self {
        Self { deny_network: true, clean_env: true, python_home: Some(python_home.into()), ..Self::default() }
    }

    pub(crate) fn validate(&self) -> Result<(), String> {
        if self.memory_limit_bytes == Some(0) {
            return Err("memory_limit_bytes must be positive".into());
        }
        if self.max_processes == Some(0) {
            return Err("max_processes must be positive".into());
        }
        Ok(())
    }

    /// Whether a Windows job (or the unsupported-platform check) is needed. Linux uses per-process controls instead.
    #[cfg_attr(target_os = "linux", allow(dead_code))]
    fn wants_job(&self) -> bool {
        self.kill_with_parent || self.memory_limit_bytes.is_some() || self.max_processes.is_some()
    }
}

/// True where [`SandboxPolicy::deny_network`] is enforced by the operating system (Linux). It is false on Windows,
/// which has lifetime and resource limits only.
pub const fn network_denial_enforced() -> bool {
    cfg!(target_os = "linux")
}

/// Variables a clean environment still needs to run a program at all.
fn baseline_env() -> &'static [&'static str] {
    if cfg!(windows) { &["SystemRoot"] } else { &[] }
}

/// Sets the environment, then lets the platform arrange the process-creation hooks. The pool applies its explicit
/// variables afterwards, so they win.
pub(crate) fn prepare(command: &mut Command, policy: &SandboxPolicy) -> io::Result<()> {
    if policy.deny_network && !network_denial_enforced() {
        tracing::warn!("network denial is not available on this platform; the worker's own self-check is the control");
    }
    if policy.clean_env {
        command.env_clear();
        for name in baseline_env().iter().map(OsString::from).chain(policy.inherit_env.iter().cloned()) {
            if let Some(value) = std::env::var_os(&name) {
                command.env(name, value);
            }
        }
    } else if policy.python_home.is_some() {
        // A host interpreter's search path must not leak into the worker's.
        for name in ["PYTHONPATH", "PYTHONSTARTUP", "PYTHONUSERBASE", "PYTHONEXECUTABLE", "PYTHONINSPECT"] {
            command.env_remove(name);
        }
    }
    if let Some(home) = &policy.python_home {
        command.env("PYTHONHOME", home).env("PYTHONNOUSERSITE", "1");
    }
    imp::prepare(command, policy)
}

/// What keeps a running worker confined. Dropping it releases the operating-system object (on Windows, closing the
/// job kills anything still in it).
#[derive(Debug)]
pub(crate) struct Guard {
    _inner: imp::Guard,
}

/// Puts the freshly spawned worker under the policy. On error the caller kills the child.
pub(crate) fn attach(child: &Child, policy: &SandboxPolicy) -> io::Result<Guard> {
    Ok(Guard { _inner: imp::attach(child, policy)? })
}
