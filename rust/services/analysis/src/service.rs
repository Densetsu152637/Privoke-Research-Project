//! The gRPC service: `PrivokeRuntimeService`, for the fuzzer only.
//!
//! Two layers decide who may call and what. The transport policy ([`policy`]) lists exactly the three runtime RPCs for
//! the service roles; every other path, including every publisher RPC, is `UNIMPLEMENTED` before this code runs, and
//! installations and the reporter are `PERMISSION_DENIED`. This service then admits only the service names it was
//! configured with (default `fuzzer`): another registered service gets `PERMISSION_DENIED`.
//!
//! The three gradient RPCs (`ComputeSemanticGradients`, `ComputeUnderlyingModelGradients`, `ComputePresenceGradients`) are not
//! served (stage V3-R8a of `docs/plans/v3-routine-training.md`, goals G5 and U4): V1 models are served for detection but not
//! trained. They are outside the policy and outside [`Rpc`], so the transport and the router both answer `UNIMPLEMENTED`
//! before any model is fetched or any worker is chosen, and there is no Python fallback.
//!
//! Every layer-bearing request must name exactly the semantic layer. The fuzzer's assertion that only the semantic layer
//! ran therefore holds through the service, and a request for regex, NER or the whole pipeline is
//! `INVALID_ARGUMENT` before it reaches a worker.
//!
//! With the Rust analysis worker configured (`ANALYSIS_RUST_WORKER`) the service holds a second pool and routes each
//! call per request with `privoke_supervisor::routing`: the model-reading calls the Rust worker serves go to it, and
//! [`routing::call_routed`] sends a call it declines before executing anything (`UNSUPPORTED_LAYERS`) once to the Python
//! worker. Any other failure is the call's result; nothing is retried on the other engine.

use std::sync::Arc;

use privoke_contracts::proto::v1::{AnalyzePromptRequest, DetectAnnotationPresenceRequest, DetectionLayer, RuntimeHealthResponse};
use privoke_supervisor::routing::{self, Attempt, Capabilities, Engine};
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

const ANALYZE: &str = "/privoke.v1.PrivokeRuntimeService/AnalyzePrompt";
const PRESENCE: &str = "/privoke.v1.PrivokeRuntimeService/DetectAnnotationPresence";
const HEALTH: &str = "/privoke.v1.PrivokeRuntimeService/Health";

/// The transport policy: the analysis, presence and health RPCs for registered services, and nothing else.
///
/// Installations (`consumer`) and the reporter are not in any rule, so they are `PERMISSION_DENIED`. A path outside
/// the list (any publisher RPC, the control service, and the three removed gradient RPCs) is `UNIMPLEMENTED`.
pub fn policy() -> Policy {
    [ANALYZE, PRESENCE, HEALTH]
        .into_iter()
        .fold(Policy::new(), |policy, path| policy.allow(path, &[Role::Publisher, Role::Trainer, Role::Runtime], LimiterKey::Identity))
}

/// The three RPCs of the runtime service this service still answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rpc {
    /// `AnalyzePrompt`.
    Analyze,
    /// `DetectAnnotationPresence`.
    Presence,
    /// `Health`.
    Health,
}

impl Rpc {
    /// The RPC a gRPC path names.
    pub fn from_path(path: &str) -> Option<Self> {
        Some(match path {
            ANALYZE => Self::Analyze,
            PRESENCE => Self::Presence,
            HEALTH => Self::Health,
            _ => return None,
        })
    }

    fn method(self) -> Option<Method> {
        Some(match self {
            Self::Analyze => Method::AnalyzePrompt,
            Self::Presence => Method::DetectAnnotationPresence,
            Self::Health => return None,
        })
    }
}

struct Inner {
    pool: WorkerPool<WorkerProtocol>,
    /// The Rust analysis worker, when it is configured.
    rust: Option<WorkerPool<WorkerProtocol>>,
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

/// What a request names, read from its bytes (which are not changed), and the worker that serves it.
#[derive(Debug, PartialEq, Eq)]
struct Inspected {
    layers: Vec<i32>,
    models: Vec<String>,
    engine: Engine,
}

/// The layers and model ids a request names, and the engine that serves it, read from its bytes.
fn inspect(rpc: Rpc, bytes: &[u8], rust: Option<Capabilities>) -> Result<Inspected, Status> {
    let invalid = |error: prost::DecodeError| Status::invalid_argument(format!("the request is not a valid message: {error}"));
    Ok(match rpc {
        Rpc::Analyze => {
            let message = AnalyzePromptRequest::decode(bytes).map_err(invalid)?;
            let engine = routing::route_analysis(rust, &message);
            let mut models = vec![message.semantic_model_id];
            if let Some(gate) = message.semantic_presence_gate {
                models.push(gate.model_id);
            }
            Inspected { layers: message.layers, models, engine }
        }
        Rpc::Presence => {
            let message = DetectAnnotationPresenceRequest::decode(bytes).map_err(invalid)?;
            let engine = routing::route_presence(rust, &message);
            Inspected { layers: message.layers, models: vec![message.model_id], engine }
        }
        Rpc::Health => Inspected { layers: Vec::new(), models: Vec::new(), engine: Engine::Python },
    })
}

/// A pool failure as the router sees it: a worker's refusal of a layer selection before it executed anything may be sent to
/// the other engine; every other failure is final (`UNSUPPORTED_ROUTE` included: it belonged to the removed gradient RPCs).
fn attempt(error: PoolError) -> Attempt<PoolError> {
    let refused = matches!(&error, PoolError::WorkerReported(text) if routing::is_refusal(split_reported(text).0));
    if refused { Attempt::Refused(error) } else { Attempt::Failed(error) }
}

impl AnalysisService {
    /// Serve `pool`, keeping `cache` current for it, to the named service identities.
    ///
    /// `health_only` names service identities that may call `Health` and nothing else (the container's own probe).
    ///
    /// `rust` is the pool of the Rust analysis worker when one is configured; the Python pool serves every call it does
    /// not claim.
    pub fn new(
        pool: WorkerPool<WorkerProtocol>,
        rust: Option<WorkerPool<WorkerProtocol>>,
        cache: Arc<ModelCache>,
        allowed: Vec<String>,
        health_only: Vec<String>,
    ) -> Self {
        Self { inner: Arc::new(Inner { pool, rust, cache, allowed, health: health_only }) }
    }

    /// Whether every worker the service holds is ready.
    pub fn is_ready(&self) -> bool {
        self.inner.pool.is_ready() && self.inner.rust.as_ref().is_none_or(WorkerPool::is_ready)
    }

    /// What the Rust worker serves here, `None` without one. Regex and NER are in the claim but never reach it: this
    /// service admits the semantic layer only.
    fn rust_capabilities(&self) -> Option<Capabilities> {
        self.inner.rust.as_ref().map(|_| Capabilities::RUST.with_semantic())
    }

    /// One attempt on one engine.
    async fn call_worker(
        &self,
        engine: Engine,
        method: Method,
        metadata: &[(String, String)],
        payload: &[u8],
    ) -> Result<String, Attempt<PoolError>> {
        let pool = match engine {
            Engine::Python => &self.inner.pool,
            Engine::Rust => self
                .inner
                .rust
                .as_ref()
                .ok_or_else(|| Attempt::Failed(PoolError::NotReady("no Rust analysis worker is configured".into())))?,
        };
        let id = pool.next_id();
        let frame =
            frames::encode_request(method, id, 0, metadata, payload).map_err(|reason| Attempt::Failed(PoolError::WorkerFailed(reason)))?;
        pool.submit(id, frame).await.map_err(attempt)
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
        let Inspected { layers, models, engine } = inspect(rpc, request.get_ref(), self.rust_capabilities())?;
        if layers != [DetectionLayer::Semantic as i32] {
            return Err(Status::invalid_argument(
                "the analysis service serves the semantic layer only; send layers=[DETECTION_LAYER_SEMANTIC]",
            ));
        }
        // No call carries metadata any more: the training admission header belonged to the removed gradient RPCs.
        let metadata: Vec<(String, String)> = Vec::new();
        for requested in &models {
            match self.inner.cache.ensure(requested).await {
                Ok(_) | Err(SyncError::NotFound(_) | SyncError::Unsupported(_)) => {}
                Err(error @ SyncError::Refused { .. }) => return Err(Status::failed_precondition(error.to_string())),
                Err(error @ SyncError::Unavailable { .. }) => return Err(Status::unavailable(error.to_string())),
            }
        }
        // Checked here so that the caller's mistake is named; an attempt differs only by the request id.
        frames::encode_request(method, 0, 0, &metadata, request.get_ref()).map_err(Status::invalid_argument)?;
        let payload = request.get_ref().as_slice();
        let metadata = metadata.as_slice();
        let answer =
            routing::call_routed(engine, |engine| self.call_worker(engine, method, metadata, payload)).await.map_err(pool_status)?;
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
    fn the_policy_lists_exactly_the_three_runtime_rpcs_and_no_gradient_rpc() {
        let policy = policy();
        let mut paths: Vec<&str> = policy.paths().collect();
        paths.sort_unstable();
        assert_eq!(paths.len(), 3);
        for removed in ["ComputeSemanticGradients", "ComputeUnderlyingModelGradients", "ComputePresenceGradients"] {
            let path = format!("/privoke.v1.PrivokeRuntimeService/{removed}");
            assert!(!paths.contains(&path.as_str()), "{removed}");
            assert_eq!(Rpc::from_path(&path), None, "{removed}");
        }
        assert!(paths.iter().all(|path| path.starts_with("/privoke.v1.PrivokeRuntimeService/")));
    }

    fn semantic_layers() -> Vec<i32> {
        vec![DetectionLayer::Semantic as i32]
    }

    fn engine(rpc: Rpc, bytes: &[u8], rust: Option<Capabilities>) -> Engine {
        inspect(rpc, bytes, rust).unwrap().engine
    }

    fn rust() -> Option<Capabilities> {
        Some(Capabilities::RUST.with_semantic())
    }

    #[test]
    fn without_a_rust_worker_everything_is_the_python_workers() {
        let analyze = AnalyzePromptRequest { layers: semantic_layers(), ..AnalyzePromptRequest::default() }.encode_to_vec();
        let presence = DetectAnnotationPresenceRequest { layers: semantic_layers(), ..Default::default() }.encode_to_vec();
        assert_eq!(engine(Rpc::Analyze, &analyze, None), Engine::Python);
        assert_eq!(engine(Rpc::Presence, &presence, None), Engine::Python);
    }

    #[test]
    fn the_semantic_calls_the_rust_worker_serves_go_to_it() {
        let analyze =
            AnalyzePromptRequest { layers: semantic_layers(), semantic_model_id: "privoke-balanced".into(), ..Default::default() };
        let inspected = inspect(Rpc::Analyze, &analyze.encode_to_vec(), rust()).unwrap();
        assert_eq!(inspected, Inspected { layers: semantic_layers(), models: vec!["privoke-balanced".into()], engine: Engine::Rust });

        let presence =
            DetectAnnotationPresenceRequest { layers: semantic_layers(), model_id: "privoke-sparse".into(), ..Default::default() };
        assert_eq!(engine(Rpc::Presence, &presence.encode_to_vec(), rust()), Engine::Rust);
        let scratch = DetectAnnotationPresenceRequest {
            layers: semantic_layers(),
            model_id: "privoke-scratch-presence-a".into(),
            ..Default::default()
        };
        assert_eq!(engine(Rpc::Presence, &scratch.encode_to_vec(), rust()), Engine::Python);
    }

    #[test]
    fn a_scratch_presence_gate_stays_with_python() {
        use privoke_contracts::proto::v1::SemanticPresenceGate;
        let gate = SemanticPresenceGate { model_id: "privoke-scratch-presence-a".into(), ..Default::default() };
        let analyze = AnalyzePromptRequest { layers: semantic_layers(), semantic_presence_gate: Some(gate), ..Default::default() };
        let inspected = inspect(Rpc::Analyze, &analyze.encode_to_vec(), rust()).unwrap();
        assert_eq!(inspected.engine, Engine::Python);
        assert_eq!(inspected.models.len(), 2);
    }

    #[test]
    fn a_message_that_does_not_decode_is_invalid_argument_whatever_the_workers() {
        let status = inspect(Rpc::Analyze, &[0xff, 0xff, 0xff], rust()).unwrap_err();
        assert_eq!(status.code(), tonic::Code::InvalidArgument);
    }

    #[test]
    fn only_a_refusal_before_execution_is_sent_to_the_other_engine() {
        let reported = |code: &str| PoolError::WorkerReported(format!("{code}\u{1f}m"));
        assert!(matches!(attempt(reported("UNSUPPORTED_LAYERS")), Attempt::Refused(_)));
        for failure in [
            reported("UNSUPPORTED_ROUTE"),
            reported("INTERNAL"),
            reported("INVALID_LAYERS"),
            PoolError::Shutdown,
            PoolError::WorkerFailed("died".into()),
        ] {
            assert!(matches!(attempt(failure), Attempt::Failed(_)));
        }
    }

    /// Runs `call_routed` with a Rust attempt that fails with `rust_says` and a Python attempt that answers; returns the
    /// engines tried and the result.
    async fn route_with(rust_says: PoolError) -> (Vec<Engine>, Result<String, PoolError>) {
        let tried = std::sync::Mutex::new(Vec::new());
        let pending = std::sync::Mutex::new(Some(rust_says));
        let result = routing::call_routed(Engine::Rust, |engine| {
            tried.lock().unwrap().push(engine);
            let rust_says = pending.lock().unwrap().take();
            async move {
                match engine {
                    Engine::Rust => Err(attempt(rust_says.expect("the Rust engine is tried once"))),
                    Engine::Python => Ok("python".to_string()),
                }
            }
        })
        .await;
        (tried.into_inner().unwrap(), result)
    }

    #[tokio::test]
    async fn a_refused_call_runs_once_on_python_and_a_failed_one_does_not() {
        let refusal = PoolError::WorkerReported("UNSUPPORTED_LAYERS\u{1f}a layer selection the Rust worker does not serve".into());
        let (tried, result) = route_with(refusal).await;
        assert_eq!(tried, [Engine::Rust, Engine::Python]);
        assert_eq!(result.unwrap(), "python");

        let (tried, result) = route_with(PoolError::WorkerFailed("the Rust worker died".into())).await;
        assert_eq!(tried, [Engine::Rust], "a failure is never retried on Python");
        assert!(result.is_err());
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
