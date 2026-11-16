//! The `ModelStreamingService` implementation. Port of `streaming_server.go` and the RPC halves of `standard_v3.go`.
//!
//! The `*_core` methods hold the behaviour and run on a blocking thread (they read files); the trait methods add the
//! caller binding that the Go service could not have: a request that names a `consumer_id` is refused unless it is the
//! caller's own certificate identity.

use std::pin::Pin;
use std::sync::Arc;

use privoke_contracts::proto::v1::model_streaming_service_server::ModelStreamingService;
use privoke_contracts::proto::v1::{
    HealthRequest, HealthResponse, ModelAssetChunk, ModelAssetRequest, ModelPackageResponse, ModelParameterChunk, ModelParametersRequest,
    ModelParametersResponse,
};
use privoke_transport::{Identity, Principal};
use tokio_stream::Stream;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};

use crate::artifact::{validate_configured_identifier, validate_identifier};
use crate::catalog::{Catalog, LATEST_MODEL_ALIAS};
use crate::releases::{is_allowlisted_asset, is_standard_v3, standard_pin};
use crate::response::{SERVICE_NAME, parameter_chunks, parameter_response};
use crate::scratch::is_scratch_model_id;
use crate::util::log;

type BoxedStream<T> = Pin<Box<dyn Stream<Item = Result<T, Status>> + Send + 'static>>;

/// The service.
#[derive(Debug, Clone)]
pub struct ModelService {
    catalog: Arc<Catalog>,
}

fn invalid(error: impl std::fmt::Display) -> Status {
    Status::invalid_argument(error.to_string())
}

impl ModelService {
    /// Serve `catalog`.
    pub fn new(catalog: Arc<Catalog>) -> Self {
        Self { catalog }
    }

    /// The catalog.
    pub fn catalog(&self) -> &Catalog {
        &self.catalog
    }

    /// `validateRequest`: identifier shape, and the stricter scratch consumer contract.
    pub fn validate_request(&self, request: &ModelParametersRequest) -> Result<(), Status> {
        validate_identifier("consumer_id", &request.consumer_id, false).map_err(invalid)?;
        validate_identifier("model_id", &request.model_id, false).map_err(invalid)?;
        if is_scratch_model_id(&request.model_id) {
            let consumer = &request.consumer_id;
            if consumer.is_empty() || consumer.len() > 128 {
                return Err(Status::invalid_argument("scratch consumer_id must contain 1 to 128 ASCII bytes"));
            }
            if !consumer.is_ascii() {
                return Err(Status::invalid_argument("scratch consumer_id must be ASCII"));
            }
        }
        Ok(())
    }

    /// `GetModelParameters`.
    pub fn get_model_parameters_core(&self, request: &ModelParametersRequest) -> Result<ModelParametersResponse, Status> {
        self.validate_request(request)?;
        let id = if request.model_id.is_empty() || request.model_id == LATEST_MODEL_ALIAS {
            self.catalog.latest_model_id()
        } else {
            request.model_id.as_str()
        };
        if is_standard_v3(id) {
            return Err(Status::failed_precondition("V3 models require the binary package RPCs; legacy float tensor limits are unchanged"));
        }
        let artifact = match self.catalog.load_model(&request.model_id) {
            Ok(artifact) => artifact,
            Err(error) => {
                if !self.catalog.contains(&request.model_id) {
                    return Err(Status::not_found(error.0));
                }
                log(format_args!("model artifact load failed: {error}"));
                return Err(Status::unavailable("model artifact is unavailable"));
            }
        };
        log(format_args!(
            "parameter request consumer={:?} model={:?} version={:?}",
            request.consumer_id, artifact.artifact.model_id, artifact.artifact.version
        ));
        Ok(parameter_response(&artifact, &request.consumer_id))
    }

    /// `GetModelPackage`.
    pub fn get_model_package_core(&self, request: &ModelParametersRequest) -> Result<ModelPackageResponse, Status> {
        self.validate_request(request)?;
        let id = if request.model_id.is_empty() || request.model_id == LATEST_MODEL_ALIAS {
            self.catalog.latest_model_id()
        } else {
            request.model_id.as_str()
        };
        if !is_standard_v3(id) {
            let artifact = self.catalog.load_model(id).map_err(|_| Status::not_found("model is unavailable"))?;
            return Ok(ModelPackageResponse {
                model_id: artifact.artifact.model_id.clone(),
                architecture: artifact.artifact.architecture.clone(),
                ..ModelPackageResponse::default()
            });
        }
        let Some(releases) = &self.catalog.releases else {
            return Err(Status::failed_precondition("standard V3 packages are unavailable"));
        };
        releases.manifest(id).map_err(|_| Status::unavailable("standard V3 manifest is unavailable"))
    }

    /// The part of `StreamModelAsset` that decides whether a stream starts at all.
    pub fn check_asset_request(&self, request: &ModelAssetRequest) -> Result<(), Status> {
        self.validate_request(&ModelParametersRequest { consumer_id: request.consumer_id.clone(), model_id: request.model_id.clone() })?;
        if !is_standard_v3(&request.model_id)
            || Some(request.manifest_sha256.as_str()) != standard_pin(&request.model_id)
            || self.catalog.releases.is_none()
        {
            return Err(Status::invalid_argument("explicit standard model and manifest pin required"));
        }
        if !is_allowlisted_asset(&request.asset_name) {
            return Err(Status::invalid_argument("asset is not allowlisted"));
        }
        Ok(())
    }

    /// `Health`.
    pub fn health_core(&self) -> HealthResponse {
        let status = if self.catalog.validate().is_ok() { "SERVING" } else { "NOT_SERVING" };
        HealthResponse { service: SERVICE_NAME.to_string(), status: status.to_string() }
    }
}

/// Bind the request's claimed identity to the certificate. Installations may name only themselves (or nothing);
/// service principals use `consumer_id` as a free log label. A request that reaches a handler without an
/// authenticated principal is refused.
fn bind_caller<T>(request: &Request<T>, claimed: &str) -> Result<(), Status> {
    let Some(principal) = request.extensions().get::<Principal>() else {
        return Err(Status::unauthenticated("no authenticated principal"));
    };
    match principal.identity {
        Identity::Installation(_) => principal.check_claim(claimed),
        Identity::Service(_) | Identity::Reporter => Ok(()),
    }
}

fn join_failure(error: tokio::task::JoinError) -> Status {
    log(format_args!("request task failed: {error}"));
    Status::internal("internal error")
}

#[tonic::async_trait]
impl ModelStreamingService for ModelService {
    async fn get_model_parameters(&self, request: Request<ModelParametersRequest>) -> Result<Response<ModelParametersResponse>, Status> {
        bind_caller(&request, &request.get_ref().consumer_id)?;
        let service = self.clone();
        let message = request.into_inner();
        let response = tokio::task::spawn_blocking(move || service.get_model_parameters_core(&message)).await.map_err(join_failure)??;
        Ok(Response::new(response))
    }

    type StreamModelParametersStream = BoxedStream<ModelParameterChunk>;

    async fn stream_model_parameters(
        &self,
        request: Request<ModelParametersRequest>,
    ) -> Result<Response<Self::StreamModelParametersStream>, Status> {
        bind_caller(&request, &request.get_ref().consumer_id)?;
        let service = self.clone();
        let message = request.into_inner();
        let response = tokio::task::spawn_blocking(move || service.get_model_parameters_core(&message)).await.map_err(join_failure)??;
        let chunks = parameter_chunks(&response);
        Ok(Response::new(Box::pin(tokio_stream::iter(chunks.into_iter().map(Ok)))))
    }

    async fn health(&self, request: Request<HealthRequest>) -> Result<Response<HealthResponse>, Status> {
        bind_caller(&request, "")?;
        let service = self.clone();
        let response = tokio::task::spawn_blocking(move || service.health_core()).await.map_err(join_failure)?;
        Ok(Response::new(response))
    }

    async fn get_model_package(&self, request: Request<ModelParametersRequest>) -> Result<Response<ModelPackageResponse>, Status> {
        bind_caller(&request, &request.get_ref().consumer_id)?;
        let service = self.clone();
        let message = request.into_inner();
        let response = tokio::task::spawn_blocking(move || service.get_model_package_core(&message)).await.map_err(join_failure)??;
        Ok(Response::new(response))
    }

    type StreamModelAssetStream = ReceiverStream<Result<ModelAssetChunk, Status>>;

    async fn stream_model_asset(&self, request: Request<ModelAssetRequest>) -> Result<Response<Self::StreamModelAssetStream>, Status> {
        bind_caller(&request, &request.get_ref().consumer_id)?;
        let message = request.into_inner();
        self.check_asset_request(&message)?;
        let (sender, receiver) = tokio::sync::mpsc::channel(2);
        let catalog = self.catalog.clone();
        tokio::task::spawn_blocking(move || {
            let Some(releases) = &catalog.releases else { return };
            let outcome = releases.stream_asset(&message.model_id, &message.manifest_sha256, &message.asset_name, |chunk| {
                sender.blocking_send(Ok(chunk)).is_ok()
            });
            if let Err(status) = outcome {
                let _ = sender.blocking_send(Err(status));
            }
        });
        Ok(Response::new(ReceiverStream::new(receiver)))
    }
}

/// Re-exported for the configuration check that mirrors `validateConfiguredIdentifier`.
pub fn validate_latest_id(id: &str) -> Result<(), crate::artifact::IdentifierError> {
    validate_configured_identifier("MODEL_LATEST_ID", id)
}
