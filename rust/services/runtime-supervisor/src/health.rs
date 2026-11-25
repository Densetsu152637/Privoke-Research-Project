//! The model-streaming health check behind `ModelStreamingHealth`: one `Health` call to the configured target.
//!
//! Any failure (no target, no credential, refused connection, handshake failure, timeout, error status) is
//! `NOT_SERVING`. The extension reads this to decide whether the semantic layer can run.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use privoke_contracts::proto::v1::HealthRequest;
use privoke_contracts::proto::v1::model_streaming_service_client::ModelStreamingServiceClient;
use tonic::Request;

use crate::channel::ModelEndpoint;
use crate::runtime::RuntimeController;

/// The service name reported when the server does not name itself.
pub const MODEL_STREAMING_SERVICE: &str = "model-streaming-service";

/// A boxed future, so the health check is object-safe.
pub type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;

/// The model-streaming health check, replaceable in tests. It is only called when `ModelStreamingHealth` is.
pub trait ModelHealth: Send + Sync + 'static {
    /// `(service, status)`.
    fn check(&self) -> BoxFuture<(String, String)>;
}

/// The real check, using the controller's live environment (which changes with the stack choice).
#[derive(Debug)]
pub struct EndpointHealth {
    runtime: Arc<RuntimeController>,
    timeout: Duration,
}

impl EndpointHealth {
    /// A check against whatever target the runtime's environment names now.
    pub fn new(runtime: Arc<RuntimeController>, timeout: Duration) -> Self {
        Self { runtime, timeout }
    }
}

impl ModelHealth for EndpointHealth {
    fn check(&self) -> BoxFuture<(String, String)> {
        let environment = self.runtime.environment();
        let timeout = self.timeout;
        Box::pin(async move {
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
