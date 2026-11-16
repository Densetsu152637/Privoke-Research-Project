//! The gRPC service: `PrivokeRuntimeService`, for the fuzzer only.
//!
//! Two layers decide who may call and what. The transport policy ([`policy`]) lists exactly the six runtime RPCs for
//! the service roles; every other path, including every publisher RPC, is `UNIMPLEMENTED` before this code runs, and
//! installations and the reporter are `PERMISSION_DENIED`. This service then admits only the service names it was
//! configured with (default `fuzzer`): another registered service gets `PERMISSION_DENIED`.
//!
//! Every layer-bearing request must name exactly the semantic layer. The fuzzer's assertion that only the semantic layer
//! ran therefore holds through the service, and a request for regex, NER or the whole pipeline is
//! `INVALID_ARGUMENT` before it reaches a worker.

use std::sync::Arc;

use privoke_contracts::proto::v1::{
    AnalyzePromptRequest, ComputePresenceGradientsRequest, ComputeSemanticGradientsRequest, DetectAnnotationPresenceRequest,
    DetectionLayer, RuntimeHealthResponse,
};
use privoke_transport::{Identity, LimiterKey, Policy, Principal, Role};
use privoke_worker_pool::{PoolError, WorkerPool};
use prost::Message as _;
use tonic::{Request, Response, Status};

use crate::frames::{self, Method};
use crate::models::{ModelCache, SyncError};
use crate::protocol::{WorkerProtocol, decode_answer, split_reported};
use crate::util::log;

/// The service name `Health` reports.
pub const SERVICE_NAME: &str = "privoke-analysis-service";

/// The invocation metadata key the training RPCs read (`training_admission_metadata`).
pub const ADMISSION_HEADER: &str = "x-privoke-training-admission-v1";

const ANALYZE: &str = "/privoke.v1.PrivokeRuntimeService/AnalyzePrompt";
const PRESENCE: &str = "/privoke.v1.PrivokeRuntimeService/DetectAnnotationPresence";
const SEMANTIC_GRADIENTS: &str = "/privoke.v1.PrivokeRuntimeService/ComputeSemanticGradients";
const UNDERLYING_GRADIENTS: &str = "/privoke.v1.PrivokeRuntimeService/ComputeUnderlyingModelGradients";
const PRESENCE_GRADIENTS: &str = "/privoke.v1.PrivokeRuntimeService/ComputePresenceGradients";
const HEALTH: &str = "/privoke.v1.PrivokeRuntimeService/Health";

/// The transport policy: the analysis, presence, gradient and health RPCs for registered services, and nothing else.
///
/// Installations (`consumer`) and the reporter are not in any rule, so they are `PERMISSION_DENIED`. A path outside
/// the list (any publisher RPC, the control service) is `UNIMPLEMENTED`.
pub fn policy() -> Policy {
    [ANALYZE, PRESENCE, SEMANTIC_GRADIENTS, UNDERLYING_GRADIENTS, PRESENCE_GRADIENTS, HEALTH]
        .into_iter()
        .fold(Policy::new(), |policy, path| policy.allow(path, &[Role::Publisher, Role::Trainer, Role::Runtime], LimiterKey::Identity))
}

/// The six RPCs of the runtime service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rpc {
    /// `AnalyzePrompt`.
    Analyze,
    /// `DetectAnnotationPresence`.
    Presence,
    /// `ComputeSemanticGradients`.
    SemanticGradients,
    /// `ComputeUnderlyingModelGradients`.
    UnderlyingGradients,
    /// `ComputePresenceGradients`.
    PresenceGradients,
    /// `Health`.
    Health,
}

impl Rpc {
    /// The RPC a gRPC path names.
    pub fn from_path(path: &str) -> Option<Self> {
        Some(match path {
            ANALYZE => Self::Analyze,
            PRESENCE => Self::Presence,
            SEMANTIC_GRADIENTS => Self::SemanticGradients,
            UNDERLYING_GRADIENTS => Self::UnderlyingGradients,
            PRESENCE_GRADIENTS => Self::PresenceGradients,
            HEALTH => Self::Health,
            _ => return None,
        })
    }

    fn method(self) -> Option<Method> {
        Some(match self {
            Self::Analyze => Method::AnalyzePrompt,
            Self::Presence => Method::DetectAnnotationPresence,
            Self::SemanticGradients => Method::ComputeSemanticGradients,
            Self::UnderlyingGradients => Method::ComputeUnderlyingModelGradients,
            Self::PresenceGradients => Method::ComputePresenceGradients,
            Self::Health => return None,
        })
    }
}

struct Inner {
    pool: WorkerPool<WorkerProtocol>,
    cache: Arc<ModelCache>,
    allowed: Vec<String>,
    health: Vec<String>,
}

/// The service. Clones share the pool and the cache.
#[derive(Clone)]
pub struct AnalysisService {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for AnalysisService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("AnalysisService").field("allowed", &self.inner.allowed).finish_non_exhaustive()
    }
}

/// The layers and model ids a request names, read from its bytes. The bytes themselves are not changed.
fn inspect(rpc: Rpc, bytes: &[u8]) -> Result<(Vec<i32>, Vec<String>), Status> {
    let invalid = |error: prost::DecodeError| Status::invalid_argument(format!("the request is not a valid message: {error}"));
    Ok(match rpc {
        Rpc::Analyze => {
            let message = AnalyzePromptRequest::decode(bytes).map_err(invalid)?;
            let mut models = vec![message.semantic_model_id];
            if let Some(gate) = message.semantic_presence_gate {
                models.push(gate.model_id);
            }
            (message.layers, models)
        }
        Rpc::Presence => {
            let message = DetectAnnotationPresenceRequest::decode(bytes).map_err(invalid)?;
            (message.layers, vec![message.model_id])
        }
        Rpc::SemanticGradients | Rpc::UnderlyingGradients => {
            let message = ComputeSemanticGradientsRequest::decode(bytes).map_err(invalid)?;
            (message.layers, vec![message.model_id])
        }
        Rpc::PresenceGradients => {
            let message = ComputePresenceGradientsRequest::decode(bytes).map_err(invalid)?;
            (message.layers, vec![message.model_id])
        }
        Rpc::Health => (Vec::new(), Vec::new()),
    })
}

impl AnalysisService {
    /// Serve `pool`, keeping `cache` current for it, to the named service identities.
    ///
    /// `health_only` names service identities that may call `Health` and nothing else (the container's own probe).
    pub fn new(pool: WorkerPool<WorkerProtocol>, cache: Arc<ModelCache>, allowed: Vec<String>, health_only: Vec<String>) -> Self {
        Self { inner: Arc::new(Inner { pool, cache, allowed, health: health_only }) }
    }

    /// Whether a worker is ready.
    pub fn is_ready(&self) -> bool {
        self.inner.pool.is_ready()
    }

    fn authorise<T>(&self, request: &Request<T>, include_health: bool) -> Result<(), Status> {
        let principal = request.extensions().get::<Principal>().ok_or_else(|| Status::unauthenticated("no authenticated caller"))?;
        match &principal.identity {
            Identity::Service(name)
                if self.inner.allowed.iter().any(|allowed| allowed == name)
                    || (include_health && self.inner.health.iter().any(|allowed| allowed == name)) =>
            {
                Ok(())
            }
            _ => Err(Status::permission_denied("only the fuzzer service may call the analysis service")),
        }
    }

    /// Serves one call. The response is the worker's own byte string.
    pub async fn handle(&self, rpc: Rpc, request: Request<Vec<u8>>) -> Result<Response<Vec<u8>>, Status> {
        self.authorise(&request, rpc == Rpc::Health)?;
        let Some(method) = rpc.method() else {
            let status = if self.is_ready() { "SERVING" } else { "NOT_SERVING" };
            let health = RuntimeHealthResponse { service: SERVICE_NAME.to_string(), status: status.to_string() };
            return Ok(Response::new(health.encode_to_vec()));
        };
        let (layers, models) = inspect(rpc, request.get_ref())?;
        if layers != [DetectionLayer::Semantic as i32] {
            return Err(Status::invalid_argument(
                "the analysis service serves the semantic layer only; send layers=[DETECTION_LAYER_SEMANTIC]",
            ));
        }
        // Every value of the admission header travels (a duplicate is the worker's to reject, as on the gRPC path).
        let mut metadata = Vec::new();
        for value in request.metadata().get_all(ADMISSION_HEADER) {
            let text = value.to_str().map_err(|_| Status::invalid_argument("the training admission header is not ASCII"))?;
            metadata.push((ADMISSION_HEADER.to_string(), text.to_string()));
        }
        for requested in &models {
            match self.inner.cache.ensure(requested).await {
                Ok(_) | Err(SyncError::NotFound(_) | SyncError::Unsupported(_)) => {}
                Err(error @ SyncError::Refused { .. }) => return Err(Status::failed_precondition(error.to_string())),
                Err(error @ SyncError::Unavailable { .. }) => return Err(Status::unavailable(error.to_string())),
            }
        }
        let id = self.inner.pool.next_id();
        let frame = frames::encode_request(method, id, 0, &metadata, request.get_ref()).map_err(Status::invalid_argument)?;
        let answer = self.inner.pool.submit(id, frame).await.map_err(pool_status)?;
        Ok(Response::new(decode_answer(&answer).map_err(Status::internal)?))
    }
}

/// How a pool failure reaches the caller. The worker's own message is not forwarded for faults of the worker.
fn pool_status(error: PoolError) -> Status {
    match error {
        PoolError::ResourceExhausted { .. } => Status::resource_exhausted("the analysis queue is full"),
        PoolError::NotReady(_) => Status::unavailable("no analysis worker is ready"),
        PoolError::WorkerFailed(reason) => {
            log(format_args!("worker failed while serving a request: {reason}"));
            Status::unavailable("the analysis worker failed while serving this request")
        }
        PoolError::DeadlineExceeded(limit) => Status::deadline_exceeded(format!("the request missed its {limit:?} deadline")),
        PoolError::WorkerReported(text) => {
            let (code, message) = split_reported(&text);
            frames::status_for_worker_code(code, message)
        }
        PoolError::Shutdown => Status::unavailable("the analysis service is shutting down"),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn the_policy_lists_exactly_the_six_runtime_rpcs() {
        let policy = policy();
        let mut paths: Vec<&str> = policy.paths().collect();
        paths.sort_unstable();
        assert_eq!(paths.len(), 6);
        assert!(paths.iter().all(|path| path.starts_with("/privoke.v1.PrivokeRuntimeService/")));
    }

    #[test]
    fn worker_codes_map_to_client_visible_statuses() {
        assert_eq!(pool_status(PoolError::WorkerReported("INVALID_LAYERS\u{1f}m".into())).code(), tonic::Code::InvalidArgument);
        assert_eq!(pool_status(PoolError::WorkerReported("DEADLINE_EXCEEDED\u{1f}m".into())).code(), tonic::Code::DeadlineExceeded);
        assert_eq!(pool_status(PoolError::WorkerReported("UNKNOWN_METHOD\u{1f}m".into())).code(), tonic::Code::Internal);
        assert_eq!(pool_status(PoolError::ResourceExhausted { capacity: 1 }).code(), tonic::Code::ResourceExhausted);
        assert_eq!(pool_status(PoolError::NotReady("x".into())).code(), tonic::Code::Unavailable);
    }
}
