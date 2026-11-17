//! The two listeners.
//!
//! * **Public** (`reporter` role): `RecordTelemetry` and `Health`, rate-limited by source IP because every reporter
//!   shares one certificate (a certificate key would put all clients in one bucket).
//! * **Internal** (`publisher`, `trainer`, `runtime` roles): `GetTelemetrySummary` and `Health`, rate-limited by the
//!   service identity.
//!
//! Both are mutual-TLS listeners built from the same fail-closed [`privoke_transport`] configuration. An RPC that a
//! listener's policy does not list is `UNIMPLEMENTED` there, so the summary is unreachable with the reporter
//! credential, which is on every installation.

use std::net::SocketAddr;
use std::time::Duration;

use privoke_contracts::proto::v1::telemetry_service_server::TelemetryServiceServer;
use privoke_transport::startup::CloudTransport;
use privoke_transport::{AuthLayer, LimiterKey, Limits, Policy, Role, SecureListener, secure_server};
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::error::{Error, Result};
use crate::service::TelemetryCollector;

const RECORD: &str = "/privoke.v1.TelemetryService/RecordTelemetry";
const SUMMARY: &str = "/privoke.v1.TelemetryService/GetTelemetrySummary";
const HEALTH: &str = "/privoke.v1.TelemetryService/Health";

/// The reporter-facing policy of the public listener: limiter keyed by source IP.
pub fn public_policy() -> Policy {
    [RECORD, HEALTH].into_iter().fold(Policy::new(), |policy, path| policy.allow(path, &[Role::Reporter], LimiterKey::SourceIp))
}

/// The service-facing policy of the internal listener.
pub fn internal_policy() -> Policy {
    [SUMMARY, HEALTH]
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
    service: TelemetryCollector,
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

    let public_service = TelemetryServiceServer::new(service.clone()).max_decoding_message_size(limits.max_message_bytes);
    let internal_service = TelemetryServiceServer::new(service).max_decoding_message_size(limits.max_message_bytes);
    let public_server = secure_server(&limits, public_auth.clone()).add_service(public_service);
    let internal_server = secure_server(&limits, internal_auth.clone()).add_service(internal_service);

    let public_signal = signal(receiver.clone());
    let internal_signal = signal(receiver.clone());
    let task = tokio::spawn(async move {
        let _keep_alive = (tls_watcher, registry_watcher);
        // Drop idle limiter buckets so a scan of many source addresses cannot grow memory without bound.
        let sweeper = tokio::spawn(sweep(public_auth, internal_auth, receiver));
        let public = public_server.serve_with_incoming_shutdown(public_listener.incoming(), public_signal);
        let internal = internal_server.serve_with_incoming_shutdown(internal_listener.incoming(), internal_signal);
        let outcome = tokio::try_join!(async { public.await.map_err(|error| Error(format!("public listener: {error}"))) }, async {
            internal.await.map_err(|error| Error(format!("internal listener: {error}")))
        },);
        sweeper.abort();
        outcome.map(|_| ())
    });
    Ok(ServerHandle { public_addr, internal_addr, shutdown, task })
}

async fn sweep(public: AuthLayer, internal: AuthLayer, mut stop: watch::Receiver<bool>) {
    let mut tick = tokio::time::interval(Duration::from_secs(60));
    loop {
        tokio::select! {
            _ = tick.tick() => {
                public.retain_recent();
                internal.retain_recent();
            }
            _ = stop.wait_for(|stop| *stop) => return,
        }
    }
}

async fn signal(mut receiver: watch::Receiver<bool>) {
    let _ = receiver.wait_for(|stop| *stop).await;
}
