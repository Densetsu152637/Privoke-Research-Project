//! The engine and the gRPC shells of `RuntimeServer` (`runtime_server.py`).
//!
//! [`Runtime`] holds what the two services share: the durable `fits` table, the checkpoint client and the capabilities that
//! `Health` reports (the Python `preflight`). [`V3RuntimeHandler`] implements `TrainingService` and `PrivokeRuntimeService`
//! over it.
//!
//! The capabilities describe this implementation, not the Python one: the Python map named the exact versions of torch,
//! transformers and the rest of the admitted environment, none of which exists here.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use privoke_contracts::proto::experimental_v3 as v3;
use privoke_contracts::proto::experimental_v3::training_service_server::TrainingService;
use privoke_contracts::proto::v1::privoke_runtime_service_server::PrivokeRuntimeService;
use privoke_contracts::proto::v1::{
    AnalyzePromptRequest, AnalyzePromptResponse, ComputePresenceGradientsRequest, ComputePresenceGradientsResponse,
    ComputeSemanticGradientsRequest, ComputeSemanticGradientsResponse, DetectAnnotationPresenceRequest, DetectAnnotationPresenceResponse,
    RuntimeHealthRequest, RuntimeHealthResponse,
};
use privoke_v3_fuzzer::source::Closure;
use tonic::{Request, Response, Status};

use crate::ROLE;
use crate::assets::{Admission, Loaded};
use crate::checkpoint::Checkpoint;
use crate::error::{Error, Result, invalid};
use crate::fit::ScheduleSources;
use crate::state::FitStore;

/// What an engine is built from.
#[derive(Debug)]
pub struct RuntimeParts {
    /// The state directory: `fits.sqlite`, `assets/` and one work directory per fit.
    pub directory: PathBuf,
    /// Threads of the matrix kernels.
    pub threads: usize,
    /// The source of the `source_closure` capability.
    pub closure: Closure,
    /// How strictly snapshot manifests are admitted (the binary always uses [`Admission::Pinned`]).
    pub admission: Admission,
    /// The pinned sources of the frozen schedules, and the checkout whose Python files the evidence commits to.
    pub schedules: ScheduleSources,
}

/// The version of the tokenizer crate the Python `tokenizers` wheel is the binding of (`privoke-semantic` pins it).
const TOKENIZERS: &str = "0.22.2";

/// The capabilities that `Health` reports and a fit's evidence records (the Python `preflight`).
pub fn capabilities(threads: usize, source_closure: &str) -> BTreeMap<String, String> {
    [
        ("implementation", "privoke-v3-runtime"),
        ("backend", "privoke-semantic reference (float32 weights, float64 activations)"),
        ("tokenizers", TOKENIZERS),
        ("device", "cpu"),
    ]
    .iter()
    .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
    .chain([("threads".to_string(), threads.to_string()), ("source_closure".to_string(), source_closure.to_string())])
    .collect()
}

/// The V3 runtime engine.
pub struct Runtime {
    pub(crate) checkpoint: Arc<dyn Checkpoint>,
    pub(crate) capabilities: BTreeMap<String, String>,
    pub(crate) directory: PathBuf,
    pub(crate) threads: usize,
    pub(crate) admission: Admission,
    pub(crate) schedules: ScheduleSources,
    /// The last snapshot analysed. Its lock is also the serialisation of analyses and fits (the Python `RLock`).
    pub(crate) cache: tokio::sync::Mutex<Option<(String, Arc<Loaded>)>>,
    store: Mutex<FitStore>,
}

impl std::fmt::Debug for Runtime {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("Runtime").field("directory", &self.directory).field("threads", &self.threads).finish_non_exhaustive()
    }
}

impl Runtime {
    /// `RuntimeServer.__init__`: open the state and require the checkpoint service to report ready.
    pub async fn new(parts: RuntimeParts, checkpoint: Arc<dyn Checkpoint>) -> Result<Self> {
        let source_closure = parts.closure.identity()?;
        std::fs::create_dir_all(&parts.directory)?;
        let store = FitStore::open(&parts.directory)?;
        let ready =
            checkpoint.health().await.map_err(|status| Error(format!("checkpoint health: {:?}: {}", status.code(), status.message())))?;
        if !ready.ready {
            return invalid("Checkpoint server not ready.");
        }
        Ok(Self {
            checkpoint,
            capabilities: capabilities(parts.threads, &source_closure),
            directory: parts.directory,
            threads: parts.threads,
            admission: parts.admission,
            schedules: parts.schedules,
            cache: tokio::sync::Mutex::new(None),
            store: Mutex::new(store),
        })
    }

    /// The `fits` table (a short lock: status queries never wait for a running fit).
    pub fn store(&self) -> MutexGuard<'_, FitStore> {
        self.store.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// `Health`: ready, the role and the capabilities.
    pub fn health(&self) -> v3::HealthResponse {
        v3::HealthResponse { ready: true, role: ROLE.to_string(), capabilities: self.capabilities.clone() }
    }

    /// `GetFitStatus`: the row of the identity, or `unknown`.
    pub fn fit_status(&self, request_id: &str) -> Result<v3::Receipt> {
        let row = self.store().status(request_id)?;
        let (status, candidate, reason) = row.unwrap_or_else(|| ("unknown".to_string(), String::new(), String::new()));
        Ok(v3::Receipt { status, request_id: request_id.to_string(), candidate, reason, ..Default::default() })
    }
}

/// Flags the fit as abandoned when the RPC that started it ends.
struct StopOnDrop(Arc<AtomicBool>);

impl Drop for StopOnDrop {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

/// The two gRPC services over one [`Runtime`].
#[derive(Debug, Clone)]
pub struct V3RuntimeHandler {
    runtime: Arc<Runtime>,
}

impl V3RuntimeHandler {
    /// A handler over `runtime`.
    pub fn new(runtime: Arc<Runtime>) -> Self {
        Self { runtime }
    }
}

fn unserved(rpc: &str) -> Status {
    Status::unimplemented(format!(
        "{rpc} is not served by the V3 runtime: it serves PrivokeRuntimeService.AnalyzePrompt (V3 semantic inference), \
         TrainingService.FitCandidate, GetFitStatus and Health."
    ))
}

#[tonic::async_trait]
impl TrainingService for V3RuntimeHandler {
    async fn fit_candidate(&self, request: Request<v3::FitRequest>) -> std::result::Result<Response<v3::FitResponse>, Status> {
        // The fit runs in its own task: when the caller gives up (deadline, cancellation) this future is dropped, `active`
        // goes false, and the fit stops at its next step and records `failed`, as the Python fit did on `is_active()`.
        let active = Arc::new(AtomicBool::new(true));
        let _caller = StopOnDrop(Arc::clone(&active));
        let runtime = Arc::clone(&self.runtime);
        let request = request.into_inner();
        let task = tokio::spawn(async move { runtime.fit_candidate(request, active).await });
        task.await.map_err(|error| Status::unknown(error.to_string()))?.map(Response::new)
    }

    async fn get_fit_status(&self, request: Request<v3::StatusRequest>) -> std::result::Result<Response<v3::Receipt>, Status> {
        let receipt = self.runtime.fit_status(&request.into_inner().request_id).map_err(|error| Status::unknown(error.0))?;
        Ok(Response::new(receipt))
    }

    async fn health(&self, _request: Request<v3::HealthRequest>) -> std::result::Result<Response<v3::HealthResponse>, Status> {
        Ok(Response::new(self.runtime.health()))
    }
}

#[tonic::async_trait]
impl PrivokeRuntimeService for V3RuntimeHandler {
    async fn analyze_prompt(
        &self,
        _request: Request<AnalyzePromptRequest>,
    ) -> std::result::Result<Response<AnalyzePromptResponse>, Status> {
        Err(Status::unimplemented("AnalyzePrompt (V3 inference) is not ported yet (stage 22, checkpoint 2)."))
    }

    async fn compute_semantic_gradients(
        &self,
        _request: Request<ComputeSemanticGradientsRequest>,
    ) -> std::result::Result<Response<ComputeSemanticGradientsResponse>, Status> {
        Err(unserved("ComputeSemanticGradients"))
    }

    async fn compute_underlying_model_gradients(
        &self,
        _request: Request<ComputeSemanticGradientsRequest>,
    ) -> std::result::Result<Response<ComputeSemanticGradientsResponse>, Status> {
        Err(unserved("ComputeUnderlyingModelGradients"))
    }

    async fn detect_annotation_presence(
        &self,
        _request: Request<DetectAnnotationPresenceRequest>,
    ) -> std::result::Result<Response<DetectAnnotationPresenceResponse>, Status> {
        Err(unserved("DetectAnnotationPresence"))
    }

    async fn compute_presence_gradients(
        &self,
        _request: Request<ComputePresenceGradientsRequest>,
    ) -> std::result::Result<Response<ComputePresenceGradientsResponse>, Status> {
        Err(unserved("ComputePresenceGradients"))
    }

    /// The Python server registered its `TrainingService.Health` for this path too, whose response message is another type, so
    /// the call could never succeed there. It answers `UNIMPLEMENTED` here and names the working probe.
    async fn health(&self, _request: Request<RuntimeHealthRequest>) -> std::result::Result<Response<RuntimeHealthResponse>, Status> {
        Err(Status::unimplemented(
            "PrivokeRuntimeService.Health is not served by the V3 runtime: probe privoke.experimental.v3.TrainingService/Health.",
        ))
    }
}
