//! The in-process spaCy backend (stage 11b): one dedicated interpreter thread that owns the GIL and the loaded model,
//! reached through a bounded channel.
//!
//! No child process is created. Isolation comes from the runtime worker boundary: the W2 pool wraps the whole runtime
//! worker, so if the interpreter crashes, that worker dies and the pool restarts it, without retrying the request that
//! was in flight. Throughput scales by adding runtime workers, not interpreters.
//!
//! This module has no Python dependency. The interpreter thread runs any [`Engine`]; the PyO3 engine is behind the
//! `in-process` feature (see `python.rs`), and the tests drive a Python-free engine through the same thread, channel,
//! readiness, queue and deadline logic.
//!
//! Guarantees as seen by a caller (the same names as [`crate::SpacyPool`]):
//!
//! * **Bounded queue.** At most `queue_capacity` requests wait. The next one gets `ResourceExhausted`.
//! * **Readiness gating.** While the model loads, or after it was refused, a request gets `Unavailable` at once.
//! * **Deadline.** One deadline covers the queue and the interpreter. A thread cannot be killed, so a request that
//!   misses it returns `Unavailable` while the interpreter finishes (or never finishes) it; the W2 pool's own deadline
//!   then replaces the whole runtime worker. A request abandoned while it still waits in the queue is skipped.
//! * **No retry.** A request runs once, on the one interpreter.
//! * **Bundle refusal.** A bundle that differs from `bundle.lock.txt` is final: the backend never becomes ready.

use std::any::Any;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{OnceCell, mpsc, oneshot, watch};

use crate::error::{ConfigError, SpacyError};
use crate::pool::{BRIDGE_DEADLINE, check_text};
#[cfg(feature = "test-hooks")]
use crate::protocol::Request;
use crate::protocol::{Analysis, RawAnalysis, Selection, WorkerInfo};

/// The spaCy model the bundle ships.
pub const DEFAULT_MODEL: &str = "en_core_web_sm";

/// What the interpreter thread runs. All methods are called on that one thread, in order.
pub trait Engine: Send + 'static {
    /// Runs spaCy: the JSON text of the `analyze` result, or the reason the engine reports (a Python exception).
    fn analyze(&mut self, selection: Selection, text: &str) -> Result<String, String>;
    /// The lemma-index word list as a JSON array.
    fn lemma_index(&mut self) -> Result<String, String>;
    /// Test hook: crashes the interpreter, which takes the whole process with it. Returning is a failure of the hook.
    #[cfg(feature = "test-hooks")]
    fn crash(&mut self) -> Result<String, String>;
    /// Test hook: prints on stdout from Python and from C-level `write(1, ...)`, then answers `null`.
    #[cfg(feature = "test-hooks")]
    fn test_print(&mut self) -> Result<String, String>;
}

/// Why an engine could not start.
#[derive(Debug)]
pub enum StartFailure {
    /// The bundle differs from its lock, or is not isolated from the host Python. Final.
    Refused(String),
    /// Anything else (a missing model, an import error). The runtime worker cannot serve spaCy either.
    Failed(String),
}

/// Settings of the in-process backend.
#[derive(Clone, Debug)]
pub struct InProcessConfig {
    /// The bundle directory (`python311.dll` or `libpython`, `python311._pth`, `Lib/site-packages`, `bundle.lock.txt`).
    /// The host executable must sit in it: CPython finds its `_pth` file next to its library, and the isolation check
    /// refuses a process that sees anything outside the bundle. Default: the directory of the current executable.
    pub bundle: PathBuf,
    /// The model to load. Default [`DEFAULT_MODEL`].
    pub model: String,
    /// How many requests may wait for the interpreter. Default 64.
    pub queue_capacity: usize,
    /// One deadline for queueing plus serving. Must be below [`BRIDGE_DEADLINE`]. Default 25 s.
    pub request_deadline: Duration,
    /// Longest accepted text, in characters. Default 20 000, the runtime's `PRIVOKE_MAX_PROMPT_CHARS` default.
    pub max_text_chars: usize,
}

impl InProcessConfig {
    /// The defaults for a given bundle directory.
    pub fn new(bundle: impl Into<PathBuf>) -> Self {
        Self {
            bundle: bundle.into(),
            model: DEFAULT_MODEL.to_string(),
            queue_capacity: 64,
            request_deadline: Duration::from_secs(25),
            max_text_chars: 20_000,
        }
    }

    pub(crate) fn validate(&self) -> Result<(), ConfigError> {
        let invalid = |m: &str| Err(ConfigError::Invalid(m.to_string()));
        if self.queue_capacity == 0 {
            return invalid("queue_capacity must be at least 1");
        }
        if self.request_deadline.is_zero() || self.request_deadline >= BRIDGE_DEADLINE {
            return invalid("request_deadline must be positive and below the bridge's 30 s");
        }
        if self.max_text_chars == 0 {
            return invalid("max_text_chars must be at least 1");
        }
        Ok(())
    }
}

impl Default for InProcessConfig {
    /// The bundle is the directory of the running executable, where the runtime worker is installed.
    fn default() -> Self {
        let bundle = std::env::current_exe().ok().and_then(|exe| exe.parent().map(PathBuf::from)).unwrap_or_default();
        Self::new(bundle)
    }
}

#[derive(Clone, Debug)]
enum State {
    Loading,
    Ready(Arc<WorkerInfo>),
    Refused(String),
    Failed(String),
}

/// The engine's answer: the result text, or the error it reports (the interpreter is still usable).
type Reply = Result<String, String>;

/// What starting an engine produces: the engine and the announcement of the loaded model.
pub type Started = Result<(Box<dyn Engine>, WorkerInfo), StartFailure>;

enum Job {
    Analyze {
        selection: Selection,
        text: String,
        reply: oneshot::Sender<Reply>,
    },
    LemmaIndex {
        reply: oneshot::Sender<Reply>,
    },
    #[cfg(feature = "test-hooks")]
    Crash {
        reply: oneshot::Sender<Reply>,
    },
    #[cfg(feature = "test-hooks")]
    Print {
        reply: oneshot::Sender<Reply>,
    },
}

impl Job {
    fn abandoned(&self) -> bool {
        match self {
            Self::Analyze { reply, .. } | Self::LemmaIndex { reply } => reply.is_closed(),
            #[cfg(feature = "test-hooks")]
            Self::Crash { reply } | Self::Print { reply } => reply.is_closed(),
        }
    }
}

/// Ends the thread's story: whatever the state was, nothing will answer any more.
struct ExitGuard(Arc<watch::Sender<State>>);

impl Drop for ExitGuard {
    fn drop(&mut self) {
        self.0.send_modify(|state| {
            if matches!(state, State::Loading | State::Ready(_)) {
                *state = State::Failed("the interpreter thread ended".to_string());
            }
        });
    }
}

fn panic_message(payload: &(dyn Any + Send)) -> String {
    payload
        .downcast_ref::<&str>()
        .map(|s| (*s).to_string())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "the interpreter thread panicked".to_string())
}

fn interpreter_thread<F>(factory: F, mut jobs: mpsc::Receiver<Job>, state: Arc<watch::Sender<State>>)
where
    F: FnOnce() -> Started,
{
    let _guard = ExitGuard(state.clone());
    let started = match catch_unwind(AssertUnwindSafe(factory)) {
        Ok(started) => started,
        Err(payload) => Err(StartFailure::Failed(panic_message(payload.as_ref()))),
    };
    let (mut engine, info) = match started {
        Ok(started) => started,
        Err(StartFailure::Refused(reason)) => {
            tracing::error!(%reason, "the spaCy bundle was refused");
            state.send_replace(State::Refused(reason));
            return;
        }
        Err(StartFailure::Failed(reason)) => {
            tracing::error!(%reason, "spaCy could not start in process");
            state.send_replace(State::Failed(reason));
            return;
        }
    };
    state.send_replace(State::Ready(Arc::new(info)));
    while let Some(job) = jobs.blocking_recv() {
        if job.abandoned() {
            continue; // the caller already gave up (deadline); do not spend the interpreter on it
        }
        let outcome = catch_unwind(AssertUnwindSafe(|| match job {
            Job::Analyze { selection, text, reply } => (reply, engine.analyze(selection, &text)),
            Job::LemmaIndex { reply } => (reply, engine.lemma_index()),
            #[cfg(feature = "test-hooks")]
            Job::Crash { reply } => (reply, engine.crash()),
            #[cfg(feature = "test-hooks")]
            Job::Print { reply } => (reply, engine.test_print()),
        }));
        match outcome {
            Ok((reply, result)) => {
                let _ = reply.send(result);
            }
            Err(payload) => {
                // The interpreter's state is unknown after a panic; stop serving. The reply sender was dropped by the
                // unwind, which the waiting caller sees as a failed worker.
                let reason = panic_message(payload.as_ref());
                tracing::error!(%reason, "the spaCy interpreter thread panicked");
                state.send_replace(State::Failed(reason));
                return;
            }
        }
    }
}

/// The in-process spaCy backend. Dropping it lets the interpreter thread finish its current request and exit.
#[derive(Debug)]
pub struct InProcess {
    jobs: mpsc::Sender<Job>,
    state: watch::Receiver<State>,
    queue_capacity: usize,
    request_deadline: Duration,
    max_text_chars: usize,
    lemma: OnceCell<Arc<Vec<String>>>,
}

impl InProcess {
    /// Starts the interpreter thread, which checks the bundle against `bundle.lock.txt` and loads the model in the
    /// background. Returns at once; [`InProcess::wait_ready`] waits for the model.
    ///
    /// Needs the `in-process` feature (CPython linked through PyO3). Without it this fails with
    /// [`ConfigError::Invalid`] rather than silently starting a worker process.
    pub fn start(cfg: &InProcessConfig) -> Result<Self, ConfigError> {
        #[cfg(feature = "in-process")]
        {
            let (bundle, model) = (cfg.bundle.clone(), cfg.model.clone());
            Self::start_with(cfg, move || crate::python::load(&bundle, &model))
        }
        #[cfg(not(feature = "in-process"))]
        {
            cfg.validate()?;
            Err(ConfigError::Invalid("this build has no in-process spaCy: enable the `in-process` feature of privoke-spacy".to_string()))
        }
    }

    /// Starts the interpreter thread with a caller-supplied engine. The factory runs on the interpreter thread, so an
    /// engine that must not move between threads can be created there. `cfg.bundle` and `cfg.model` are not used.
    pub fn start_with<F>(cfg: &InProcessConfig, factory: F) -> Result<Self, ConfigError>
    where
        F: FnOnce() -> Started + Send + 'static,
    {
        cfg.validate()?;
        let (jobs, rx) = mpsc::channel(cfg.queue_capacity);
        let (state_tx, state) = watch::channel(State::Loading);
        let state_tx = Arc::new(state_tx);
        std::thread::Builder::new()
            .name("privoke-spacy-interpreter".to_string())
            // CPython's recursion limit assumes a generous stack; the default thread stack is smaller on Windows.
            .stack_size(8 * 1024 * 1024)
            .spawn(move || interpreter_thread(factory, rx, state_tx))
            .map_err(|e| ConfigError::Invalid(format!("cannot start the interpreter thread: {e}")))?;
        Ok(Self {
            jobs,
            state,
            queue_capacity: cfg.queue_capacity,
            request_deadline: cfg.request_deadline,
            max_text_chars: cfg.max_text_chars,
            lemma: OnceCell::new(),
        })
    }

    /// True once the model has loaded and the interpreter thread is alive.
    pub fn is_ready(&self) -> bool {
        matches!(*self.state.borrow(), State::Ready(_))
    }

    /// The announcement of the loaded model (spaCy, model and Python versions, lock hash).
    pub fn worker_info(&self) -> Option<WorkerInfo> {
        match &*self.state.borrow() {
            State::Ready(info) => Some((**info).clone()),
            _ => None,
        }
    }

    /// Waits until the model is loaded. Fails at once if the bundle was refused or the interpreter could not start, and
    /// when `within` elapses.
    pub async fn wait_ready(&self, within: Duration) -> Result<(), SpacyError> {
        let mut state = self.state.clone();
        let settled = tokio::time::timeout(within, state.wait_for(|s| !matches!(s, State::Loading))).await;
        match settled {
            Err(_) => Err(SpacyError::NotReady(format!("spaCy did not finish loading within {within:?}"))),
            Ok(Err(_)) => Err(SpacyError::WorkerFailed("the interpreter thread ended".to_string())),
            Ok(Ok(settled)) => match &*settled {
                State::Ready(_) => Ok(()),
                other => Err(Self::unavailable(other)),
            },
        }
    }

    fn unavailable(state: &State) -> SpacyError {
        match state {
            State::Loading => SpacyError::NotReady("spaCy is still loading".to_string()),
            State::Refused(reason) => SpacyError::NotReady(format!("the bundle was refused: {reason}")),
            State::Failed(reason) => SpacyError::WorkerFailed(reason.clone()),
            State::Ready(_) => SpacyError::Shutdown,
        }
    }

    async fn call(&self, make: impl FnOnce(oneshot::Sender<Reply>) -> Job) -> Result<String, SpacyError> {
        let current = self.state.borrow().clone();
        if !matches!(current, State::Ready(_)) {
            return Err(Self::unavailable(&current));
        }
        let (reply, answer) = oneshot::channel();
        self.jobs.try_send(make(reply)).map_err(|e| match e {
            mpsc::error::TrySendError::Full(_) => SpacyError::ResourceExhausted { capacity: self.queue_capacity },
            mpsc::error::TrySendError::Closed(_) => SpacyError::WorkerFailed("the interpreter thread ended".to_string()),
        })?;
        match tokio::time::timeout(self.request_deadline, answer).await {
            Err(_) => Err(SpacyError::DeadlineExceeded(self.request_deadline)),
            Ok(Err(_)) => {
                let state = self.state.borrow().clone();
                Err(match state {
                    State::Failed(reason) => SpacyError::WorkerFailed(reason),
                    _ => SpacyError::WorkerFailed("the interpreter thread ended".to_string()),
                })
            }
            Ok(Ok(Ok(body))) => Ok(body),
            Ok(Ok(Err(message))) => Err(SpacyError::WorkerReported(message)),
        }
    }

    /// Runs spaCy on `text` and returns the exact result bytes.
    pub async fn analyze_raw(&self, text: &str, selection: Selection) -> Result<RawAnalysis, SpacyError> {
        check_text(text, self.max_text_chars)?;
        let body = self.call(|reply| Job::Analyze { selection, text: text.to_string(), reply }).await?;
        Ok(RawAnalysis::new(body))
    }

    /// Runs spaCy on `text` and decodes the result, converting offsets to UTF-8 bytes and UTF-16 units.
    pub async fn analyze(&self, text: &str, selection: Selection) -> Result<Analysis, SpacyError> {
        self.analyze_raw(text, selection).await?.decode(text)
    }

    /// The model's lemma-index word list, fetched from the interpreter once and then cached.
    pub async fn lemma_index(&self) -> Result<Arc<Vec<String>>, SpacyError> {
        self.lemma
            .get_or_try_init(|| async {
                let body = self.call(|reply| Job::LemmaIndex { reply }).await?;
                let words: Vec<String> =
                    serde_json::from_str(&body).map_err(|e| SpacyError::Protocol(format!("malformed lemma index: {e}")))?;
                Ok(Arc::new(words))
            })
            .await
            .cloned()
    }

    /// Runs one of the worker protocol's test requests (the runtime host forwards them). Test builds only.
    #[cfg(feature = "test-hooks")]
    #[doc(hidden)]
    pub async fn run_test_request(&self, request: &Request<'_>) -> Result<String, SpacyError> {
        match request {
            Request::TestCrash { .. } => self.call(|reply| Job::Crash { reply }).await,
            Request::TestPrint { .. } => self.call(|reply| Job::Print { reply }).await,
            other => Err(SpacyError::InvalidArgument(format!("{other:?} is not an interpreter test request"))),
        }
    }
}
