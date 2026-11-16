//! The spaCy worker pool: `privoke-worker-pool`'s supervised pool with the spaCy protocol on top.
//!
//! Process supervision, the readiness gate, the bounded queue, deadlines, the no-retry rule, crash-loop backoff and the
//! OS sandbox live in `privoke-worker-pool` (stage W2) and have their tests there. What stays here is spaCy-specific:
//! the ready and answer frames, the text limits, the lemma-index cache and the decode of `analyze` results. The
//! guarantees as seen by a caller:
//!
//! * **Bounded queue.** At most `queue_capacity` requests wait. The next one gets `ResourceExhausted`.
//! * **Readiness gating.** While no worker is ready (loading, restarting, or refused) a request gets `Unavailable` at
//!   once instead of waiting on a dead pool.
//! * **Deadlines.** A request has one deadline covering the queue and the worker. A worker that exceeds it is killed
//!   and restarted, and the request gets `Unavailable`. The deadline must stay below the bridge's 30 s.
//! * **No retry of poisoned input.** A request is handed to one worker and never re-queued.
//! * **Crash-loop backoff.** Restarts wait 100 ms, 200 ms, ... up to 30 s. The count resets only after a worker
//!   completes a request.
//! * **Bundle refusal.** A `fatal` frame (the bundle check failed) stops the slot for good; the pool never becomes
//!   ready and [`SpacyPool::wait_ready`] returns the reason.

use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use privoke_worker_pool::{Hello, PoolError, Protocol, Reply, WorkerPool};
use tokio::sync::OnceCell;

pub use privoke_worker_pool::{Backoff, SandboxPolicy};

use crate::error::{ConfigError, SpacyError};
use crate::protocol::{Analysis, Envelope, RawAnalysis, Request, Selection, WorkerInfo};

/// The text rules both backends apply before a request is queued: not empty, and at most `max` characters.
pub(crate) fn check_text(text: &str, max: usize) -> Result<(), SpacyError> {
    if text.is_empty() {
        return Err(SpacyError::InvalidArgument("text must not be empty".into()));
    }
    if text.chars().nth(max).is_some() {
        return Err(SpacyError::InvalidArgument(format!("text may contain at most {max} characters")));
    }
    Ok(())
}

/// The bridge's deadline. A request deadline must be below it.
pub const BRIDGE_DEADLINE: Duration = Duration::from_secs(30);

/// Pool settings.
#[derive(Clone, Debug)]
pub struct PoolConfig {
    /// The worker executable (`privoke-spacy-worker`, normally inside the bundle).
    pub command: PathBuf,
    /// Arguments for every worker.
    pub args: Vec<OsString>,
    /// Extra environment for every worker.
    pub envs: Vec<(OsString, OsString)>,
    /// Number of worker processes. Default 1, the workstation setting.
    pub workers: usize,
    /// How many requests may wait for a free worker. Default 64.
    pub queue_capacity: usize,
    /// One deadline for queueing plus serving. Must be below [`BRIDGE_DEADLINE`]. Default 25 s.
    pub request_deadline: Duration,
    /// How long a new worker may take to load spaCy and send its ready frame. Default 120 s.
    pub startup_timeout: Duration,
    /// Longest accepted text, in characters. Default 20 000, the runtime's `PRIVOKE_MAX_PROMPT_CHARS` default.
    pub max_text_chars: usize,
    /// Restart backoff.
    pub backoff: Backoff,
    /// The OS sandbox around each worker. The default only ties the worker's life to the parent's; use
    /// [`SandboxPolicy::strict`] and limits for a production bundle.
    pub sandbox: SandboxPolicy,
}

impl PoolConfig {
    /// A configuration with the defaults for the given worker executable.
    pub fn new(command: impl Into<PathBuf>) -> Self {
        Self {
            command: command.into(),
            args: Vec::new(),
            envs: Vec::new(),
            workers: 1,
            queue_capacity: 64,
            request_deadline: Duration::from_secs(25),
            startup_timeout: Duration::from_secs(120),
            max_text_chars: 20_000,
            backoff: Backoff::default(),
            sandbox: SandboxPolicy::default(),
        }
    }

    fn validate(&self) -> Result<(), ConfigError> {
        let invalid = |m: &str| Err(ConfigError::Invalid(m.to_string()));
        if self.workers == 0 {
            return invalid("workers must be at least 1");
        }
        if self.queue_capacity == 0 {
            return invalid("queue_capacity must be at least 1");
        }
        if self.request_deadline.is_zero() || self.request_deadline >= BRIDGE_DEADLINE {
            return invalid("request_deadline must be positive and below the bridge's 30 s");
        }
        if self.max_text_chars == 0 {
            return invalid("max_text_chars must be at least 1");
        }
        if self.backoff.initial.is_zero() || self.backoff.max < self.backoff.initial {
            return invalid("backoff needs a positive initial delay and a cap of at least that");
        }
        Ok(())
    }

    fn pool_config(&self) -> privoke_worker_pool::PoolConfig {
        let mut cfg = privoke_worker_pool::PoolConfig::new(&self.command);
        cfg.name = "spacy".into();
        cfg.args.clone_from(&self.args);
        cfg.envs.clone_from(&self.envs);
        cfg.workers = self.workers;
        cfg.queue_capacity = self.queue_capacity;
        cfg.request_deadline = self.request_deadline;
        cfg.startup_timeout = self.startup_timeout;
        cfg.backoff = self.backoff;
        cfg.sandbox = self.sandbox.clone();
        cfg
    }
}

/// The spaCy protocol over the pool's frames.
#[derive(Clone, Copy, Debug)]
struct SpacyProtocol;

impl Protocol for SpacyProtocol {
    type Info = WorkerInfo;

    fn parse_hello(&self, frame: &[u8]) -> Result<Hello<WorkerInfo>, String> {
        let info: WorkerInfo = serde_json::from_slice(frame).map_err(|e| format!("malformed ready frame: {e}"))?;
        match info.kind.as_str() {
            "fatal" => Ok(Hello::Fatal(info.reason.unwrap_or_else(|| "no reason given".into()))),
            "ready" => Ok(Hello::Ready(info)),
            other => Err(format!("unexpected first frame of type {other:?}")),
        }
    }

    fn parse_reply(&self, frame: &[u8], request_id: u64) -> Reply {
        let envelope: Envelope<'_> = match serde_json::from_slice(frame) {
            Ok(envelope) => envelope,
            Err(e) => return Reply::Violation(format!("malformed response frame: {e}")),
        };
        if envelope.id != request_id {
            return Reply::Violation(format!("response id {} does not match request id {request_id}", envelope.id));
        }
        if !envelope.ok {
            return Reply::Reported(envelope.error.unwrap_or_else(|| "unspecified error".into()));
        }
        match envelope.result {
            Some(raw) => Reply::Answer(raw.get().to_string()),
            None => Reply::Violation("a successful response has no result".into()),
        }
    }
}

impl From<PoolError> for SpacyError {
    fn from(error: PoolError) -> Self {
        match error {
            PoolError::ResourceExhausted { capacity } => Self::ResourceExhausted { capacity },
            // The pool does not know it is running a spaCy bundle; the caller's wording does.
            PoolError::NotReady(reason) => Self::NotReady(reason.replacen("the worker was refused", "the bundle was refused", 1)),
            PoolError::WorkerFailed(reason) => Self::WorkerFailed(reason),
            PoolError::DeadlineExceeded(deadline) => Self::DeadlineExceeded(deadline),
            PoolError::WorkerReported(message) => Self::WorkerReported(message),
            PoolError::Shutdown => Self::Shutdown,
        }
    }
}

impl From<privoke_worker_pool::ConfigError> for ConfigError {
    fn from(error: privoke_worker_pool::ConfigError) -> Self {
        match error {
            privoke_worker_pool::ConfigError::Invalid(message) => Self::Invalid(message),
            privoke_worker_pool::ConfigError::NoRuntime => Self::NoRuntime,
        }
    }
}

/// A supervised pool of spaCy worker processes. Dropping it kills the workers.
#[derive(Debug)]
pub struct SpacyPool {
    pool: WorkerPool<SpacyProtocol>,
    max_text_chars: usize,
    lemma: OnceCell<Arc<Vec<String>>>,
}

impl SpacyPool {
    /// Validates the configuration and starts one supervisor per worker. Returns immediately; the workers load spaCy in
    /// the background and [`SpacyPool::wait_ready`] waits for the first one. Must run inside a Tokio runtime.
    pub fn start(cfg: PoolConfig) -> Result<Self, ConfigError> {
        cfg.validate()?;
        let pool = WorkerPool::start(SpacyProtocol, cfg.pool_config())?;
        Ok(Self { pool, max_text_chars: cfg.max_text_chars, lemma: OnceCell::new() })
    }

    /// True while at least one worker has loaded spaCy and is alive.
    pub fn is_ready(&self) -> bool {
        self.pool.is_ready()
    }

    /// The number of ready workers.
    pub fn ready_workers(&self) -> usize {
        self.pool.ready_workers()
    }

    /// The first ready worker's announcement (spaCy, model and Python versions, lock hash).
    pub fn worker_info(&self) -> Option<WorkerInfo> {
        self.pool.info()
    }

    /// How many worker processes have been started, counting restarts.
    pub fn starts(&self) -> u64 {
        self.pool.starts()
    }

    /// The operating-system ids of the running worker processes, for diagnostics and for tests that kill one.
    pub fn worker_pids(&self) -> Vec<u32> {
        self.pool.worker_pids()
    }

    /// Waits until a worker is ready. Fails at once if the bundle was refused, and when `within` elapses.
    pub async fn wait_ready(&self, within: Duration) -> Result<(), SpacyError> {
        Ok(self.pool.wait_ready(within).await?)
    }

    /// Runs spaCy on `text` and returns the exact result bytes.
    pub async fn analyze_raw(&self, text: &str, selection: Selection) -> Result<RawAnalysis, SpacyError> {
        check_text(text, self.max_text_chars)?;
        let id = self.pool.next_id();
        let body = self.submit(id, Request::Analyze { id, selection, text }.encode()?).await?;
        Ok(RawAnalysis::new(body))
    }

    /// Runs spaCy on `text` and decodes the result, converting offsets to UTF-8 bytes and UTF-16 units.
    pub async fn analyze(&self, text: &str, selection: Selection) -> Result<Analysis, SpacyError> {
        self.analyze_raw(text, selection).await?.decode(text)
    }

    /// The model's lemma-index word list, fetched from a worker once and then cached.
    pub async fn lemma_index(&self) -> Result<Arc<Vec<String>>, SpacyError> {
        self.lemma
            .get_or_try_init(|| async {
                let id = self.pool.next_id();
                let body = self.submit(id, Request::LemmaIndex { id }.encode()?).await?;
                let words: Vec<String> =
                    serde_json::from_str(&body).map_err(|e| SpacyError::Protocol(format!("malformed lemma index: {e}")))?;
                Ok(Arc::new(words))
            })
            .await
            .cloned()
    }

    /// Sends an arbitrary encoded request. For tests of the worker's own hooks.
    #[doc(hidden)]
    pub async fn submit_request(&self, build: impl FnOnce(u64) -> Request<'static>) -> Result<String, SpacyError> {
        let id = self.pool.next_id();
        self.submit(id, build(id).encode()?).await
    }

    /// Stops the supervisors and kills the workers.
    pub async fn shutdown(self) {
        self.pool.shutdown().await;
    }

    async fn submit(&self, id: u64, payload: Vec<u8>) -> Result<String, SpacyError> {
        Ok(self.pool.submit(id, payload).await?)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_from_100ms_to_a_30s_cap() {
        let b = Backoff::default();
        let delays: Vec<u64> = (1..=11).map(|n| b.delay(n).as_millis() as u64).collect();
        assert_eq!(delays, [100, 200, 400, 800, 1_600, 3_200, 6_400, 12_800, 25_600, 30_000, 30_000]);
        assert_eq!(b.delay(u32::MAX), Duration::from_secs(30));
        assert_eq!(b.delay(0), Duration::from_millis(100));
    }

    #[test]
    fn deadline_must_stay_below_the_bridge() {
        let mut cfg = PoolConfig::new("x");
        assert!(cfg.validate().is_ok());
        cfg.request_deadline = BRIDGE_DEADLINE;
        assert!(cfg.validate().is_err());
        cfg.request_deadline = Duration::from_secs(1);
        cfg.workers = 0;
        assert!(cfg.validate().is_err());
    }
}
