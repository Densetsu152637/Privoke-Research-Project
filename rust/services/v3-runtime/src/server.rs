//! The listener: one mutual-TLS port on the internal network, built from the same fail-closed [`privoke_transport`]
//! configuration as the other Rust services. Both gRPC services of `runtime_server.py` share it.
//!
//! * `AnalyzePrompt`, and the four `PrivokeRuntimeService` RPCs this runtime does not serve (so that each answers
//!   `UNIMPLEMENTED` with its gap instead of a generic status): registered `publisher`, `trainer` and `runtime` services.
//! * `FitCandidate` and `GetFitStatus`: registered `publisher` services (the V3 fuzzer, the parameter-update scheduler) and
//!   `trainer` services (an operator).
//! * `Health` of both services: `publisher`, `trainer` and `runtime` services (the container probe).
//!
//! There is no plaintext listener (the Python server allowed one on loopback): a peer that presents no certificate fails at the
//! handshake, and a certificate that the CA signed but the registry does not list for one of these roles is
//! `PERMISSION_DENIED` before any request is handled.

use std::net::SocketAddr;
use std::time::Duration;

use privoke_contracts::proto::experimental_v3::training_service_server::TrainingServiceServer;
use privoke_contracts::proto::v1::privoke_runtime_service_server::PrivokeRuntimeServiceServer;
use privoke_transport::startup::CloudTransport;
use privoke_transport::{AuthLayer, LimiterKey, Limits, Policy, Role, SecureListener, secure_server};
use privoke_v3_fuzzer::backend::MESSAGE_LIMIT;
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::error::{Error, Result};
use crate::service::V3RuntimeHandler;

const ANALYZE: &str = "/privoke.v1.PrivokeRuntimeService/AnalyzePrompt";
const SEMANTIC_GRADIENTS: &str = "/privoke.v1.PrivokeRuntimeService/ComputeSemanticGradients";
const UNDERLYING_GRADIENTS: &str = "/privoke.v1.PrivokeRuntimeService/ComputeUnderlyingModelGradients";
const PRESENCE: &str = "/privoke.v1.PrivokeRuntimeService/DetectAnnotationPresence";
const PRESENCE_GRADIENTS: &str = "/privoke.v1.PrivokeRuntimeService/ComputePresenceGradients";
const RUNTIME_HEALTH: &str = "/privoke.v1.PrivokeRuntimeService/Health";
const FIT: &str = "/privoke.experimental.v3.TrainingService/FitCandidate";
const FIT_STATUS: &str = "/privoke.experimental.v3.TrainingService/GetFitStatus";
const TRAINING_HEALTH: &str = "/privoke.experimental.v3.TrainingService/Health";

/// Which roles may call which RPC.
pub fn policy() -> Policy {
    let analysis = [Role::Publisher, Role::Trainer, Role::Runtime];
    let training = [Role::Publisher, Role::Trainer];
    let mut policy = Policy::new();
    for path in [ANALYZE, SEMANTIC_GRADIENTS, UNDERLYING_GRADIENTS, PRESENCE, PRESENCE_GRADIENTS, RUNTIME_HEALTH, TRAINING_HEALTH] {
        policy = policy.allow(path, &analysis, LimiterKey::Identity);
    }
    policy.allow(FIT, &training, LimiterKey::Identity).allow(FIT_STATUS, &training, LimiterKey::Identity)
}

/// The limits of the listener: the nginx defaults, except that one RPC may be one whole fit, so the per-RPC deadline and the age
/// after which a connection is drained follow `request_timeout`, and messages are bounded as the Python server bounded them.
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
    handler: V3RuntimeHandler,
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

    let analysis = PrivokeRuntimeServiceServer::new(handler.clone())
        .max_decoding_message_size(limits.max_message_bytes)
        .max_encoding_message_size(limits.max_message_bytes);
    let training = TrainingServiceServer::new(handler)
        .max_decoding_message_size(limits.max_message_bytes)
        .max_encoding_message_size(limits.max_message_bytes);
    let server = secure_server(&limits, auth.clone()).add_service(analysis).add_service(training);
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
    fn exactly_the_nine_rpcs_of_the_two_services_are_routed() {
        let served = policy();
        let mut paths: Vec<&str> = served.paths().collect();
        paths.sort_unstable();
        let mut expected = vec![
            ANALYZE,
            SEMANTIC_GRADIENTS,
            UNDERLYING_GRADIENTS,
            PRESENCE,
            PRESENCE_GRADIENTS,
            RUNTIME_HEALTH,
            FIT,
            FIT_STATUS,
            TRAINING_HEALTH,
        ];
        expected.sort_unstable();
        assert_eq!(paths, expected);
    }

    #[test]
    fn a_fit_may_run_for_the_whole_request_timeout() {
        let limits = limits_for(Duration::from_secs(7800));
        assert_eq!(limits.request_timeout, Duration::from_secs(7800));
        assert_eq!(limits.max_message_bytes, MESSAGE_LIMIT);
        assert!(limits.max_connection_age > limits.request_timeout);
    }
}
