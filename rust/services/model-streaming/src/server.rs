//! The two listeners.
//!
//! * **Public** (`consumer` role): `Health`, `StreamModelParameters`, `GetModelPackage`, `StreamModelAsset`. Exposing
//!   the last two is the G8 behaviour change: the nginx ingress routed only three RPCs.
//! * **Internal** (`publisher`, `trainer`, `runtime` roles): `GetModelParameters` and `Health`.
//!
//! Both are mutual-TLS listeners built from the same fail-closed [`privoke_transport`] configuration; an RPC that a
//! listener's policy does not list is `UNIMPLEMENTED` there, so `GetModelParameters` on the public listener and every
//! consumer RPC on the internal one are unreachable.

use std::net::SocketAddr;
use std::time::Duration;

use privoke_contracts::proto::v1::model_streaming_service_server::ModelStreamingServiceServer;
use privoke_transport::startup::CloudTransport;
use privoke_transport::{AuthLayer, LimiterKey, Limits, Policy, Role, SecureListener, secure_server};
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::error::{Error, Result};
use crate::service::ModelService;

const HEALTH: &str = "/privoke.v1.ModelStreamingService/Health";
const STREAM_PARAMETERS: &str = "/privoke.v1.ModelStreamingService/StreamModelParameters";
const GET_PACKAGE: &str = "/privoke.v1.ModelStreamingService/GetModelPackage";
const STREAM_ASSET: &str = "/privoke.v1.ModelStreamingService/StreamModelAsset";
const GET_PARAMETERS: &str = "/privoke.v1.ModelStreamingService/GetModelParameters";

/// The consumer-facing policy of the public listener.
pub fn public_policy() -> Policy {
    [HEALTH, STREAM_PARAMETERS, GET_PACKAGE, STREAM_ASSET]
        .into_iter()
        .fold(Policy::new(), |policy, path| policy.allow(path, &[Role::Consumer], LimiterKey::Identity))
}

/// The service-facing policy of the internal listener.
pub fn internal_policy() -> Policy {
    [HEALTH, GET_PARAMETERS]
        .into_iter()
        .fold(Policy::new(), |policy, path| policy.allow(path, &[Role::Publisher, Role::Trainer, Role::Runtime], LimiterKey::Identity))
}

/// Where to listen.
#[derive(Debug, Clone, Copy)]
pub struct Listen {
    /// Public listener address.
    pub public: SocketAddr,
    /// Internal listener address.
    pub internal: SocketAddr,
}

/// A running server; dropping the handle does not stop it, `shutdown` does.
#[derive(Debug)]
pub struct ServerHandle {
    /// The bound public address.
    pub public_addr: SocketAddr,
    /// The bound internal address.
    pub internal_addr: SocketAddr,
    shutdown: watch::Sender<bool>,
    task: JoinHandle<Result<()>>,
}

impl ServerHandle {
    /// Stop accepting, drain, and wait for both listeners.
    pub async fn shutdown(self) -> Result<()> {
        let _ = self.shutdown.send(true);
        self.task.await.map_err(|error| Error(error.to_string()))?
    }

    /// Wait until the listeners stop by themselves (an error) without requesting shutdown.
    pub async fn wait(&mut self) -> Result<()> {
        (&mut self.task).await.map_err(|error| Error(error.to_string()))?
    }
}

/// Bind both listeners over the validated transport and start serving.
pub async fn start(
    listen: Listen,
    service: ModelService,
    transport: CloudTransport,
    limits: Limits,
    poll: Duration,
) -> Result<ServerHandle> {
    let tls_watcher = transport.tls.spawn_watcher(poll);
    let registry_watcher = transport.registry.spawn_watcher(poll);
    let shared_registry = transport.registry.registry();

    let public_listener =
        SecureListener::bind(listen.public, transport.tls.clone(), limits.clone()).await.map_err(|error| Error(error.to_string()))?;
    let internal_listener =
        SecureListener::bind(listen.internal, transport.tls.clone(), limits.clone()).await.map_err(|error| Error(error.to_string()))?;
    let public_addr = public_listener.local_addr().map_err(|error| Error(error.to_string()))?;
    let internal_addr = internal_listener.local_addr().map_err(|error| Error(error.to_string()))?;

    let public_auth = AuthLayer::new(public_policy(), shared_registry.clone(), limits.rate);
    let internal_auth = AuthLayer::new(internal_policy(), shared_registry, limits.rate);
    let (shutdown, receiver) = watch::channel(false);

    let public_service = ModelStreamingServiceServer::new(service.clone()).max_decoding_message_size(limits.max_message_bytes);
    let internal_service = ModelStreamingServiceServer::new(service).max_decoding_message_size(limits.max_message_bytes);
    let public_server = secure_server(&limits, public_auth).add_service(public_service);
    let internal_server = secure_server(&limits, internal_auth).add_service(internal_service);

    let public_signal = signal(receiver.clone());
    let internal_signal = signal(receiver);
    let task = tokio::spawn(async move {
        let _keep_alive = (tls_watcher, registry_watcher);
        let public = public_server.serve_with_incoming_shutdown(public_listener.incoming(), public_signal);
        let internal = internal_server.serve_with_incoming_shutdown(internal_listener.incoming(), internal_signal);
        tokio::try_join!(async { public.await.map_err(|error| Error(format!("public listener: {error}"))) }, async {
            internal.await.map_err(|error| Error(format!("internal listener: {error}")))
        },)?;
        Ok(())
    });
    Ok(ServerHandle { public_addr, internal_addr, shutdown, task })
}

async fn signal(mut receiver: watch::Receiver<bool>) {
    let _ = receiver.wait_for(|stop| *stop).await;
}
