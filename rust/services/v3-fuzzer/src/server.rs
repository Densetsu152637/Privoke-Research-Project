//! The listener: one mutual-TLS port on the internal network, built from the same fail-closed [`privoke_transport`]
//! configuration as the other Rust services.
//!
//! * The two cycle RPCs: registered `publisher` services (the parameter-update scheduler) and `trainer` services (an operator).
//! * `Health`: `publisher`, `trainer` and `runtime` services (the container probe).
//!
//! There is no plaintext listener (the Python server allowed one on loopback): a peer that presents no certificate fails at the
//! handshake, and a certificate that the CA signed but the registry does not list for one of these roles is
//! `PERMISSION_DENIED` before any cycle, row or work directory exists.

use std::net::SocketAddr;
use std::time::Duration;

use privoke_contracts::proto::experimental_v3::v3_fuzzer_service_server::V3FuzzerServiceServer;
use privoke_transport::startup::CloudTransport;
use privoke_transport::{AuthLayer, LimiterKey, Limits, Policy, Role, SecureListener, secure_server};
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::backend::MESSAGE_LIMIT;
use crate::error::{Error, Result};
use crate::service::V3Handler;

const RUN: &str = "/privoke.experimental.v3.V3FuzzerService/RunTrainingCycle";
const RUN_UNDERLYING: &str = "/privoke.experimental.v3.V3FuzzerService/RunUnderlyingTrainingCycle";
const HEALTH: &str = "/privoke.experimental.v3.V3FuzzerService/Health";

/// Which roles may call which RPC.
pub fn policy() -> Policy {
    let cycle = [Role::Publisher, Role::Trainer];
    Policy::new().allow(RUN, &cycle, LimiterKey::Identity).allow(RUN_UNDERLYING, &cycle, LimiterKey::Identity).allow(
        HEALTH,
        &[Role::Publisher, Role::Trainer, Role::Runtime],
        LimiterKey::Identity,
    )
}

/// The limits of the listener: the nginx defaults, except that one RPC is one whole fit, so the per-RPC deadline and the age after
/// which a connection is drained follow `request_timeout`, and messages are bounded as the Python server bounded them.
pub fn limits_for(request_timeout: Duration) -> Limits {
    let defaults = Limits::default();
    Limits {
        request_timeout,
        max_message_bytes: MESSAGE_LIMIT,
        max_connection_age: request_timeout + defaults.max_connection_age_grace + Duration::from_secs(30),
        ..defaults
    }
}

/// A running server; dropping the handle does not stop it, [`shutdown`](Self::shutdown) does.
#[derive(Debug)]
pub struct ServerHandle {
    /// The bound address.
    pub addr: SocketAddr,
    shutdown: watch::Sender<bool>,
    task: JoinHandle<Result<()>>,
}

impl ServerHandle {
    /// Stop accepting, drain and wait.
    pub async fn shutdown(self) -> Result<()> {
        let _ = self.shutdown.send(true);
        self.task.await.map_err(|error| Error(error.to_string()))?
    }

    /// Wait until the listener stops by itself (an error) without requesting shutdown.
    pub async fn wait(&mut self) -> Result<()> {
        (&mut self.task).await.map_err(|error| Error(error.to_string()))?
    }
}

/// Bind the listener over the validated transport and start serving.
pub async fn start(
    listen: SocketAddr,
    handler: V3Handler,
    transport: CloudTransport,
    limits: Limits,
    poll: Duration,
) -> Result<ServerHandle> {
    let tls_watcher = transport.tls.spawn_watcher(poll);
    let registry_watcher = transport.registry.spawn_watcher(poll);
    let shared_registry = transport.registry.registry();

    let listener = SecureListener::bind(listen, transport.tls.clone(), limits.clone()).await.map_err(|error| Error(error.to_string()))?;
    let addr = listener.local_addr().map_err(|error| Error(error.to_string()))?;
    let auth = AuthLayer::new(policy(), shared_registry, limits.rate);
    let (shutdown, receiver) = watch::channel(false);

    let service = V3FuzzerServiceServer::new(handler)
        .max_decoding_message_size(limits.max_message_bytes)
        .max_encoding_message_size(limits.max_message_bytes);
    let server = secure_server(&limits, auth.clone()).add_service(service);
    let signal = stop_signal(receiver.clone());
    let task = tokio::spawn(async move {
        let _keep_alive = (tls_watcher, registry_watcher, transport);
        let sweeper = tokio::spawn(sweep(auth, receiver));
        let outcome =
            server.serve_with_incoming_shutdown(listener.incoming(), signal).await.map_err(|error| Error(format!("listener: {error}")));
        sweeper.abort();
        outcome
    });
    Ok(ServerHandle { addr, shutdown, task })
}

async fn sweep(auth: AuthLayer, mut stop: watch::Receiver<bool>) {
    let mut tick = tokio::time::interval(Duration::from_secs(60));
    loop {
        tokio::select! {
            _ = tick.tick() => auth.retain_recent(),
            _ = stop.wait_for(|stop| *stop) => return,
        }
    }
}

async fn stop_signal(mut receiver: watch::Receiver<bool>) {
    let _ = receiver.wait_for(|stop| *stop).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_three_rpcs_are_served_and_health_is_open_to_probes() {
        let served = policy();
        let mut paths: Vec<&str> = served.paths().collect();
        paths.sort_unstable();
        assert_eq!(paths, vec![HEALTH, RUN, RUN_UNDERLYING]);
    }

    #[test]
    fn a_cycle_may_run_for_the_whole_request_timeout() {
        let limits = limits_for(Duration::from_secs(7800));
        assert_eq!(limits.request_timeout, Duration::from_secs(7800));
        assert_eq!(limits.max_message_bytes, MESSAGE_LIMIT);
        assert!(limits.max_connection_age > limits.request_timeout);
    }
}
