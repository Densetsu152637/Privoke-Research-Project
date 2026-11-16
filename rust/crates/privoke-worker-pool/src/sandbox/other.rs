//! Platforms without a sandbox implementation. Anything beyond the environment policy fails the spawn.

use std::io;

use tokio::process::{Child, Command};

use super::SandboxPolicy;

#[derive(Debug)]
pub(super) struct Guard;

fn unsupported() -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, "the worker sandbox is not implemented for this platform")
}

pub(super) fn prepare(_command: &mut Command, policy: &SandboxPolicy) -> io::Result<()> {
    if policy.kill_with_parent || policy.wants_job() || policy.deny_network {
        return Err(unsupported());
    }
    Ok(())
}

pub(super) fn attach(_child: &Child, _policy: &SandboxPolicy) -> io::Result<Guard> {
    Ok(Guard)
}
