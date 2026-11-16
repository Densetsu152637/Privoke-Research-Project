//! `PrivokeRuntimeControlService` on the loopback interface. The port of the Python control service in `main.py`.
//!
//! Three RPCs: `SetRuntimeEnabled`, `Status` and `ModelStreamingHealth`. The listener is plaintext and loopback-only
//! (the workstation boundary kept by GAP-LOOPBACK-PLAINTEXT-POLICY): any local process can reach it, as it could the
//! Python control port. It carries no identity, so it is never given the cloud `AuthLayer`. It is not part of the
//! target design: W4 moves the extension to native messaging and removes the listener from workstation installs.
//! Until then it serves the Python bridge, which stays as the oracle.

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use privoke_contracts::proto::v1::model_streaming_service_client::ModelStreamingServiceClient;
use privoke_contracts::proto::v1::privoke_runtime_control_service_server::{
    PrivokeRuntimeControlService, PrivokeRuntimeControlServiceServer,
};
use privoke_contracts::proto::v1::{
    HealthRequest, RuntimeControlStatus, RuntimeHealthRequest, RuntimeHealthResponse, SetRuntimeEnabledRequest,
};
use privoke_transport::listener::loopback::LoopbackListener;
use tonic::{Request, Response, Status};

use crate::channel::ModelEndpoint;
use crate::process::{RuntimeProcessSupervisor, RuntimeStatus, SupervisorError};

/// The service name reported when the server does not name itself.
pub const MODEL_STREAMING_SERVICE: &str = "model-streaming-service";

/// A boxed future, so the health check is object-safe.
pub type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;

/// The model-streaming health check, replaceable in tests. It is only called when `ModelStreamingHealth` is, never
/// when the service is built.
pub trait ModelHealth: Send + Sync + 'static {
    /// `(service, status)`.
    fn check(&self) -> BoxFuture<(String, String)>;
}

/// The real check: one `Health` call to the configured model-streaming target. Any failure (no target, no
/// credential, refused connection, handshake failure, timeout, error status) is `NOT_SERVING`.
#[derive(Debug)]
pub struct EndpointHealth {
    supervisor: Arc<RuntimeProcessSupervisor>,
    timeout: Duration,
}

impl EndpointHealth {
    /// A check using the supervisor's live environment (which changes with the stack choice).
    pub fn new(supervisor: Arc<RuntimeProcessSupervisor>, timeout: Duration) -> Self {
        Self { supervisor, timeout }
    }
}

impl ModelHealth for EndpointHealth {
    fn check(&self) -> BoxFuture<(String, String)> {
        let supervisor = Arc::clone(&self.supervisor);
        let timeout = self.timeout;
        Box::pin(async move {
            let environment = tokio::task::spawn_blocking(move || supervisor.environment()).await.ok().and_then(Result::ok);
            let Some(environment) = environment else { return not_serving() };
            match ModelEndpoint::from_environment(&environment) {
                Ok(endpoint) => model_streaming_health(&endpoint, timeout).await,
                Err(_) => not_serving(),
            }
        })
    }
}

fn not_serving() -> (String, String) {
    (MODEL_STREAMING_SERVICE.to_string(), "NOT_SERVING".to_string())
}

/// `_model_streaming_health`: `(service, status)`, with `NOT_SERVING` for every failure.
pub async fn model_streaming_health(endpoint: &ModelEndpoint, timeout: Duration) -> (String, String) {
    let call = async {
        let channel = endpoint.connect(timeout).await.ok()?;
        let mut request = Request::new(HealthRequest {});
        request.set_timeout(timeout);
        let response = ModelStreamingServiceClient::new(channel).health(request).await.ok()?.into_inner();
        Some((
            if response.service.is_empty() { MODEL_STREAMING_SERVICE.to_string() } else { response.service },
            if response.status.is_empty() { "UNKNOWN".to_string() } else { response.status },
        ))
    };
    tokio::time::timeout(timeout, call).await.ok().flatten().unwrap_or_else(not_serving)
}

/// The control service.
#[derive(Clone)]
pub struct ControlService {
    supervisor: Arc<RuntimeProcessSupervisor>,
    health: Arc<dyn ModelHealth>,
}

impl std::fmt::Debug for ControlService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("ControlService").finish_non_exhaustive()
    }
}

impl ControlService {
    /// Build the service. Nothing is called until an RPC arrives.
    pub fn new(supervisor: Arc<RuntimeProcessSupervisor>, health: Arc<dyn ModelHealth>) -> Self {
        Self { supervisor, health }
    }

    /// The tonic server wrapper, with a small message limit (requests are a few bytes).
    pub fn into_server(self) -> PrivokeRuntimeControlServiceServer<Self> {
        PrivokeRuntimeControlServiceServer::new(self).max_decoding_message_size(64 * 1024)
    }
}

fn response(status: RuntimeStatus) -> RuntimeControlStatus {
    RuntimeControlStatus {
        enabled: status.enabled,
        status: status.status.to_string(),
        message: status.message,
        process_id: status.process_id,
    }
}

fn fail(error: SupervisorError) -> Status {
    match error {
        SupervisorError::Config(message) => Status::invalid_argument(message),
        other => Status::internal(other.to_string()),
    }
}

async fn blocking<T: Send + 'static>(
    supervisor: &Arc<RuntimeProcessSupervisor>,
    work: impl FnOnce(&RuntimeProcessSupervisor) -> Result<T, SupervisorError> + Send + 'static,
) -> Result<T, Status> {
    let supervisor = Arc::clone(supervisor);
    tokio::task::spawn_blocking(move || work(&supervisor)).await.map_err(|error| Status::internal(error.to_string()))?.map_err(fail)
}

#[tonic::async_trait]
impl PrivokeRuntimeControlService for ControlService {
    async fn set_runtime_enabled(&self, request: Request<SetRuntimeEnabledRequest>) -> Result<Response<RuntimeControlStatus>, Status> {
        let request = request.into_inner();
        let (enabled, use_local) = (request.enabled, request.use_local_stack);
        let status = blocking(&self.supervisor, move |supervisor| supervisor.set_enabled(enabled, use_local)).await?;
        Ok(Response::new(response(status)))
    }

    async fn status(&self, _request: Request<RuntimeHealthRequest>) -> Result<Response<RuntimeControlStatus>, Status> {
        let status = blocking(&self.supervisor, RuntimeProcessSupervisor::status).await?;
        Ok(Response::new(response(status)))
    }

    async fn model_streaming_health(&self, _request: Request<RuntimeHealthRequest>) -> Result<Response<RuntimeHealthResponse>, Status> {
        let (service, status) = self.health.check().await;
        Ok(Response::new(RuntimeHealthResponse { service, status }))
    }
}

/// Serve the control service on a loopback address until `shutdown` completes. Returns the bound address through
/// `bound` before serving, so a caller that asked for port 0 learns the port.
pub async fn serve_loopback(
    address: SocketAddr,
    service: ControlService,
    bound: tokio::sync::oneshot::Sender<SocketAddr>,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<(), crate::Error> {
    let listener = LoopbackListener::bind(address).await.map_err(|error| crate::Error::Bind(error.to_string()))?;
    let local = listener.local_addr().map_err(|error| crate::Error::Bind(error.to_string()))?;
    let _ = bound.send(local);
    tonic::transport::Server::builder()
        .add_service(service.into_server())
        .serve_with_incoming_shutdown(listener.incoming(), shutdown)
        .await
        .map_err(|error| crate::Error::Serve(error.to_string()))
}
