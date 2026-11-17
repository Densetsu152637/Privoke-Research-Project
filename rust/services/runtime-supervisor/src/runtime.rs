//! The runtime the controller owns: one pool of sandboxed W1 workers that is started and stopped on request.
//!
//! This replaces the Python `RuntimeProcessSupervisor` and the loopback control service. There is no child that
//! listens on a port: the worker is reached over pipes only, and it dies with the controller (the pool's sandbox), so
//! closing the browser, which ends the native-messaging session, ends the worker too.
//!
//! Analysis fails closed. Every error here becomes an error reply; nothing is ever turned into an allow decision.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use privoke_contracts::proto::v1::AnalyzePromptRequest;
use privoke_worker_pool::{PoolError, WorkerPool};
use prost::Message;
use tokio::sync::watch;

use crate::config::{Environment, boolean};
use crate::routing::{self, Capabilities, Engine, Rpc};
use crate::worker::{self, MAX_ANALYZE_REQUEST_BYTES, Method, WorkerProtocol, WorkerSettings};

/// What the control methods report, mirroring `RuntimeControlStatus`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeStatus {
    /// True while a worker is ready.
    pub enabled: bool,
    /// `RUNNING` or `STOPPED`.
    pub status: &'static str,
    /// Why the status is what it is.
    pub message: String,
    /// The worker's process id, 0 when stopped.
    pub process_id: u32,
}

/// A failed call, with a gRPC-style status code the extension surfaces as the error text.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct CallError {
    /// `INVALID_ARGUMENT`, `UNAVAILABLE`, `DEADLINE_EXCEEDED`, `RESOURCE_EXHAUSTED`, `FAILED_PRECONDITION` or
    /// `INTERNAL`.
    pub code: &'static str,
    /// What went wrong.
    pub message: String,
}

impl CallError {
    /// A new error.
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self { code, message: message.into() }
    }
}

struct Generation {
    pool: WorkerPool<WorkerProtocol>,
    /// Flips to true when this generation is being stopped, so waiting requests give their handle back at once.
    cancel: watch::Sender<bool>,
}

/// The runtime. Cheap to share: all methods take `&self`.
#[derive(Debug)]
pub struct RuntimeController {
    settings: WorkerSettings,
    /// The Rust analysis worker (stage 17), when `PRIVOKE_RUNTIME_ANALYSIS_ENGINE=rust`. The Python worker above is
    /// always started: it serves everything the Rust worker does not (see `routing`).
    rust_settings: Option<WorkerSettings>,
    environment: Mutex<Environment>,
    current: Mutex<Option<Arc<Generation>>>,
    rust_current: Mutex<Option<Arc<Generation>>>,
    message: Mutex<String>,
    /// Serialises start and stop, as the Python supervisor's lock did.
    lifecycle: tokio::sync::Mutex<()>,
}

/// Why a pool did not start.
enum StartFailure {
    /// The pool could not be created.
    Create(CallError),
    /// The worker did not become ready in time, or failed to start.
    NotReady(PoolError),
}

impl std::fmt::Debug for Generation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("Generation").finish_non_exhaustive()
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// `PRIVOKE_USE_LOCAL_STACK` as Python's `_boolean`: unset is false, anything outside the fixed words is an error.
pub fn use_local_stack(environment: &Environment) -> Result<bool, CallError> {
    boolean(environment, "PRIVOKE_USE_LOCAL_STACK", false)
        .map_err(|_| CallError::new("INVALID_ARGUMENT", "PRIVOKE_USE_LOCAL_STACK must be a boolean."))
}

impl RuntimeController {
    /// A controller that has started nothing yet.
    pub fn new(settings: WorkerSettings, environment: Environment) -> Self {
        Self {
            settings,
            rust_settings: None,
            environment: Mutex::new(environment),
            current: Mutex::new(None),
            rust_current: Mutex::new(None),
            message: Mutex::new("Client runtime has not been started.".into()),
            lifecycle: tokio::sync::Mutex::new(()),
        }
    }

    /// Adds the Rust analysis worker: calls it serves go to it, everything else to the Python worker.
    #[must_use]
    pub fn with_rust_worker(mut self, settings: WorkerSettings) -> Self {
        self.rust_settings = Some(settings);
        self
    }

    /// What the Rust worker serves, `None` when none is configured.
    fn rust_capabilities(&self) -> Option<Capabilities> {
        self.rust_settings.as_ref().map(|_| Capabilities::RUST)
    }

    /// The live environment: it changes with the stack choice, and the model-streaming health check reads it.
    pub fn environment(&self) -> Environment {
        lock(&self.environment).clone()
    }

    fn set_message(&self, text: impl Into<String>) {
        *lock(&self.message) = text.into();
    }

    /// The current status. Never blocks on a start in progress.
    pub fn status(&self) -> RuntimeStatus {
        let generation = lock(&self.current).clone();
        let rust_ready = self.rust_settings.is_none() || lock(&self.rust_current).as_ref().is_some_and(|rust| rust.pool.is_ready());
        if let Some(generation) = generation {
            if generation.pool.is_ready() && rust_ready {
                let process_id = generation.pool.worker_pids().first().copied().unwrap_or(0);
                return RuntimeStatus { enabled: true, status: "RUNNING", message: lock(&self.message).clone(), process_id };
            }
            return RuntimeStatus {
                enabled: false,
                status: "STOPPED",
                message: "Client runtime is not ready: the worker is starting or restarting.".into(),
                process_id: 0,
            };
        }
        RuntimeStatus { enabled: false, status: "STOPPED", message: lock(&self.message).clone(), process_id: 0 }
    }

    /// Start or stop the runtime. A change of `use_local` stops it first and records the choice.
    pub async fn set_enabled(&self, enabled: bool, use_local: Option<bool>) -> Result<RuntimeStatus, CallError> {
        let _serialised = self.lifecycle.lock().await;
        if let Some(wanted) = use_local
            && wanted != use_local_stack(&lock(&self.environment))?
        {
            self.stop().await;
            lock(&self.environment).insert("PRIVOKE_USE_LOCAL_STACK".into(), wanted.to_string());
        }
        if enabled {
            self.start().await
        } else {
            self.stop().await;
            self.set_message("Client runtime stopped.");
            Ok(self.status())
        }
    }

    async fn start(&self) -> Result<RuntimeStatus, CallError> {
        let mut started = self.start_generation(&self.current, &self.settings).await;
        if let (Ok(()), Some(rust)) = (&started, &self.rust_settings) {
            started = self.start_generation(&self.rust_current, rust).await;
        }
        match started {
            Ok(()) => {
                self.set_message("Client runtime started.");
                Ok(self.status())
            }
            // The pool could not be created at all: the caller learns why.
            Err(StartFailure::Create(error)) => Err(error),
            Err(StartFailure::NotReady(error)) => {
                self.stop().await;
                self.set_message(format!("Client runtime failed to start: {error}"));
                Ok(self.status())
            }
        }
    }

    /// Starts the pool in `slot` unless it exists, and waits until its worker is ready.
    async fn start_generation(&self, slot: &Mutex<Option<Arc<Generation>>>, settings: &WorkerSettings) -> Result<(), StartFailure> {
        let existing = lock(slot).clone();
        let generation = match existing {
            Some(generation) => generation,
            None => {
                let pool = WorkerPool::start(WorkerProtocol, settings.pool_config()).map_err(|error| {
                    StartFailure::Create(CallError::new("INTERNAL", format!("Client runtime failed to start: {error}")))
                })?;
                let generation = Arc::new(Generation { pool, cancel: watch::channel(false).0 });
                *lock(slot) = Some(Arc::clone(&generation));
                generation
            }
        };
        generation.pool.wait_ready(settings.start_timeout).await.map_err(StartFailure::NotReady)
    }

    /// Stop the pools and wait until their workers are gone. Callers hold the lifecycle lock.
    async fn stop(&self) {
        let python = lock(&self.current).take();
        let rust = lock(&self.rust_current).take();
        for generation in [python, rust].into_iter().flatten() {
            Self::stop_generation(generation).await;
        }
    }

    async fn stop_generation(generation: Arc<Generation>) {
        generation.cancel.send_replace(true);
        let mut generation = generation;
        // In-flight requests drop their handles as soon as they see the cancel; wait for the last one.
        for _ in 0..200 {
            match Arc::try_unwrap(generation) {
                Ok(owned) => {
                    // A worker stuck in a request would hold a graceful shutdown for the request deadline; past this
                    // bound the pool is dropped, which aborts its supervisors and kills the worker.
                    if tokio::time::timeout(Duration::from_secs(3), owned.pool.shutdown()).await.is_err() {
                        tracing::warn!("the worker pool did not stop in time and was dropped");
                    }
                    return;
                }
                Err(shared) => {
                    generation = shared;
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }
        }
        // A request that never lets go is abandoned: dropping the last handle kills the workers (the pool's `Drop`).
        tracing::warn!("a request outlived the runtime stop; its worker is killed when it ends");
    }

    /// Stops the runtime for good. The session calls it on every exit path.
    pub async fn shutdown(&self) {
        let _serialised = self.lifecycle.lock().await;
        self.stop().await;
    }

    /// One `AnalyzePrompt`: the protobuf request in, the base64 protobuf response out. The worker rejects an empty or
    /// runtime layer list, so a request can never select the full pipeline by omission.
    pub async fn analyze(&self, request: &[u8]) -> Result<String, CallError> {
        if request.len() > MAX_ANALYZE_REQUEST_BYTES {
            return Err(CallError::new("RESOURCE_EXHAUSTED", "The analysis request is too large."));
        }
        // The layer selection decides the worker. A request that does not decode goes to the Python worker, which
        // answers it with `INVALID_PAYLOAD` as it always has.
        let layers = AnalyzePromptRequest::decode(request).map(|message| message.layers).unwrap_or_default();
        let slot = match routing::route(self.rust_capabilities(), Rpc::AnalyzePrompt, &layers) {
            Engine::Rust => &self.rust_current,
            Engine::Python => &self.current,
        };
        let generation =
            lock(slot).clone().ok_or_else(|| CallError::new("FAILED_PRECONDITION", "The PriVoke client runtime is not running."))?;
        let id = generation.pool.next_id();
        let frame =
            worker::encode_request(Method::AnalyzePrompt, id, 0, request).map_err(|message| CallError::new("INVALID_ARGUMENT", message))?;
        let mut cancelled = generation.cancel.subscribe();
        let outcome = tokio::select! {
            result = generation.pool.submit(id, frame) => result,
            _ = cancelled.wait_for(|stopped| *stopped) => return Err(CallError::new("UNAVAILABLE", "The PriVoke client runtime was stopped.")),
        };
        outcome.map_err(pool_error)
    }
}

/// How a pool failure reads to the extension. All of them are failures; none is a decision.
fn pool_error(error: PoolError) -> CallError {
    match error {
        PoolError::ResourceExhausted { .. } => CallError::new("RESOURCE_EXHAUSTED", error.to_string()),
        PoolError::NotReady(_) | PoolError::WorkerFailed(_) | PoolError::Shutdown => CallError::new("UNAVAILABLE", error.to_string()),
        PoolError::DeadlineExceeded(_) => CallError::new("DEADLINE_EXCEEDED", error.to_string()),
        PoolError::WorkerReported(text) => {
            let (code, message) = worker::split_reported(&text);
            let mapped = match code {
                "INVALID_PAYLOAD" | "INVALID_LAYERS" | "INVALID_METADATA" | "INVALID_FLAGS" | "UNKNOWN_METHOD" => "INVALID_ARGUMENT",
                "FRAME_TOO_LARGE" | "RESPONSE_TOO_LARGE" => "RESOURCE_EXHAUSTED",
                "DEADLINE_EXCEEDED" => "DEADLINE_EXCEEDED",
                _ => "INTERNAL",
            };
            CallError::new(mapped, format!("{code}: {message}"))
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn worker_codes_map_to_status_codes() {
        let reported = |code: &str| pool_error(PoolError::WorkerReported(format!("{code}\u{1f}text"))).code;
        assert_eq!(reported("INVALID_LAYERS"), "INVALID_ARGUMENT");
        assert_eq!(reported("RESPONSE_TOO_LARGE"), "RESOURCE_EXHAUSTED");
        assert_eq!(reported("DEADLINE_EXCEEDED"), "DEADLINE_EXCEEDED");
        assert_eq!(reported("INTERNAL"), "INTERNAL");
        assert_eq!(pool_error(PoolError::Shutdown).code, "UNAVAILABLE");
        assert_eq!(pool_error(PoolError::DeadlineExceeded(Duration::from_secs(1))).code, "DEADLINE_EXCEEDED");
    }

    #[test]
    fn a_malformed_stack_setting_is_invalid_argument() {
        let mut environment = Environment::new();
        assert_eq!(use_local_stack(&environment), Ok(false));
        environment.insert("PRIVOKE_USE_LOCAL_STACK".into(), "sometimes".into());
        assert_eq!(use_local_stack(&environment).unwrap_err().code, "INVALID_ARGUMENT");
    }
}
