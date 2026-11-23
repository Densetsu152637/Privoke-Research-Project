//! The listener: one mutual-TLS port on the internal network, built from the same fail-closed
//! [`privoke_transport`] configuration as the other Rust services.
//!
//! * `SubmitParameterUpdate`: removed in stage V3-R8b (`UNIMPLEMENTED`, not in the policy).
//! * `GetParameterUpdateStatus`: `publisher` and `trainer` services.
//! * `Health`: `publisher`, `trainer` and `runtime` services (the container probe and the operator).
//! * `CheckpointService` (when a V3 store is configured, stage V3-R1): `CommitCandidate` for `publisher` and `trainer` services
//!   only; `StageCheckpoint`, `ResolveCurrent`, `FetchBlob`, `GetCommitStatus` and `Health` also for `runtime` services (the V3
//!   runtime stages the candidates it fits and never commits them). `RollbackModel` (an operator action that signs a new
//!   publication of an earlier version): `publisher` services only.
//!
//! An RPC the policy does not list, including `GetModelParameters` and the other services' methods, is `UNIMPLEMENTED`
//! here. An installation or reporter certificate that the CA signed is `PERMISSION_DENIED`. There is no plaintext
//! listener: a peer that presents no certificate fails at the handshake.

use std::net::SocketAddr;
use std::time::Duration;

use privoke_contracts::proto::experimental_v3::checkpoint_service_server::CheckpointServiceServer;
use privoke_contracts::proto::v1::param_update_service_server::ParamUpdateServiceServer;
use privoke_transport::startup::CloudTransport;
use privoke_transport::{AuthLayer, LimiterKey, Limits, Policy, Role, SecureListener, secure_server};
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::error::{Error, Result};
use crate::service::ParamUpdateHandler;
use crate::v3_store::CheckpointHandler;
use crate::v3_store::service::MESSAGE_LIMIT as CHECKPOINT_MESSAGE_LIMIT;

const STATUS: &str = "/privoke.v1.ParamUpdateService/GetParameterUpdateStatus";
const HEALTH: &str = "/privoke.v1.ParamUpdateService/Health";
const CHECKPOINT_RESOLVE: &str = "/privoke.experimental.v3.CheckpointService/ResolveCurrent";
const CHECKPOINT_FETCH: &str = "/privoke.experimental.v3.CheckpointService/FetchBlob";
const CHECKPOINT_STAGE: &str = "/privoke.experimental.v3.CheckpointService/StageCheckpoint";
const CHECKPOINT_COMMIT: &str = "/privoke.experimental.v3.CheckpointService/CommitCandidate";
const CHECKPOINT_STATUS: &str = "/privoke.experimental.v3.CheckpointService/GetCommitStatus";
const CHECKPOINT_ROLLBACK: &str = "/privoke.experimental.v3.CheckpointService/RollbackModel";
const CHECKPOINT_HEALTH: &str = "/privoke.experimental.v3.CheckpointService/Health";

/// Which roles may call which RPC.
pub fn policy() -> Policy {
    Policy::new()
        .allow(STATUS, &[Role::Publisher, Role::Trainer], LimiterKey::Identity)
        .allow(HEALTH, &[Role::Publisher, Role::Trainer, Role::Runtime], LimiterKey::Identity)
        .allow(CHECKPOINT_RESOLVE, &[Role::Publisher, Role::Trainer, Role::Runtime], LimiterKey::Identity)
        .allow(CHECKPOINT_FETCH, &[Role::Publisher, Role::Trainer, Role::Runtime], LimiterKey::Identity)
        .allow(CHECKPOINT_STAGE, &[Role::Publisher, Role::Trainer, Role::Runtime], LimiterKey::Identity)
        .allow(CHECKPOINT_COMMIT, &[Role::Publisher, Role::Trainer], LimiterKey::Identity)
        .allow(CHECKPOINT_ROLLBACK, &[Role::Publisher], LimiterKey::Identity)
        .allow(CHECKPOINT_STATUS, &[Role::Publisher, Role::Trainer, Role::Runtime], LimiterKey::Identity)
        .allow(CHECKPOINT_HEALTH, &[Role::Publisher, Role::Trainer, Role::Runtime], LimiterKey::Identity)
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

/// Bind the listener over the validated transport and start serving the update service.
pub async fn start(
    listen: SocketAddr,
    handler: ParamUpdateHandler,
    transport: CloudTransport,
    limits: Limits,
    poll: Duration,
) -> Result<ServerHandle> {
    start_with_checkpoint(listen, handler, None, transport, limits, poll).await
}

/// [`start`], and the V3 `CheckpointService` on the same listener when `checkpoint` is given.
pub async fn start_with_checkpoint(
    listen: SocketAddr,
    handler: ParamUpdateHandler,
    checkpoint: Option<CheckpointHandler>,
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

    let service = ParamUpdateServiceServer::new(handler).max_decoding_message_size(limits.max_message_bytes);
    let router = secure_server(&limits, auth.clone()).add_service(service);
    // A checkpoint chunk is 1 MiB, which is the default message bound of the update service: the V3 service has its own.
    let server = match checkpoint {
        Some(handler) => router.add_service(CheckpointServiceServer::new(handler).max_decoding_message_size(CHECKPOINT_MESSAGE_LIMIT)),
        None => router,
    };
    let signal = stop_signal(receiver.clone());
    let task = tokio::spawn(async move {
        let _keep_alive = (tls_watcher, registry_watcher);
        // Drop idle limiter buckets so a scan of many identities cannot grow memory without bound.
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
