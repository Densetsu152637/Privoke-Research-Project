//! The supervised worker pool.
//!
//! One supervisor task owns each worker slot. It starts the worker process under the sandbox, waits for the first frame
//! (the worker has finished loading by then), takes requests from the shared bounded queue, and replaces the process
//! whenever it exits, crashes, answers out of protocol or misses a deadline.
//!
//! Guarantees, each with a test:
//!
//! * **Bounded queue.** At most `queue_capacity` requests wait. The next one gets `ResourceExhausted`.
//! * **Readiness gating.** While no worker is ready (loading, restarting, or refused) a request gets `NotReady` at once
//!   instead of waiting on a dead pool.
//! * **Deadlines.** A request has one deadline covering the queue and the worker. A worker that exceeds it is killed
//!   and restarted, and the request gets `DeadlineExceeded`.
//! * **No retry of poisoned input.** A request is handed to one worker and never re-queued. If that worker dies, the
//!   request fails, so a crashing document cannot take down the other workers in turn.
//! * **Crash-loop backoff.** Restarts wait `initial`, `2 * initial`, ... up to `max`. The count resets only after a
//!   worker completes a request.
//! * **Refusal.** A `Fatal` hello stops the slot for good; the pool never becomes ready and [`WorkerPool::wait_ready`]
//!   returns the reason.
//!
//! The frame pipe is the worker's stdin and stdout. A worker moves its frame writer off its standard output and points
//! that at standard error before it loads anything (see [`crate::worker_side`]), so stray output cannot corrupt a
//! frame; the pool drains standard error into the log.

use std::collections::{BTreeMap, VecDeque};
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::sync::{Notify, oneshot, watch};
use tokio::task::JoinHandle;
use tokio::time::{Instant, sleep, timeout, timeout_at};

use crate::error::{ConfigError, PoolError};
use crate::frame::{read_frame, write_frame};
use crate::protocol::{Hello, Protocol, Reply};
use crate::sandbox::{self, Guard, SandboxPolicy};

/// Exponential restart backoff.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Backoff {
    /// The delay after the first failure.
    pub initial: Duration,
    /// The cap.
    pub max: Duration,
}

impl Default for Backoff {
    fn default() -> Self {
        Self { initial: Duration::from_millis(100), max: Duration::from_secs(30) }
    }
}

impl Backoff {
    /// The delay before restart number `failures` in a row (1 is the first): `initial * 2^(failures - 1)`, capped.
    pub fn delay(&self, failures: u32) -> Duration {
        let shift = failures.saturating_sub(1).min(32);
        self.initial.saturating_mul(1u32 << shift.min(31)).min(self.max)
    }
}

/// Pool settings.
#[derive(Clone, Debug)]
pub struct PoolConfig {
    /// A short name for log lines.
    pub name: String,
    /// The worker executable.
    pub command: PathBuf,
    /// Arguments for every worker.
    pub args: Vec<OsString>,
    /// Extra environment for every worker, applied after the sandbox's environment policy.
    pub envs: Vec<(OsString, OsString)>,
    /// Number of worker processes. Default 1.
    pub workers: usize,
    /// How many requests may wait for a free worker. Default 64.
    pub queue_capacity: usize,
    /// One deadline for queueing plus serving. Default 25 s.
    pub request_deadline: Duration,
    /// How long a new worker may take to send its first frame. Default 120 s.
    pub startup_timeout: Duration,
    /// Restart backoff.
    pub backoff: Backoff,
    /// The operating-system sandbox around each worker.
    pub sandbox: SandboxPolicy,
}

impl PoolConfig {
    /// A configuration with the defaults for the given worker executable.
    pub fn new(command: impl Into<PathBuf>) -> Self {
        Self {
            name: "worker".into(),
            command: command.into(),
            args: Vec::new(),
            envs: Vec::new(),
            workers: 1,
            queue_capacity: 64,
            request_deadline: Duration::from_secs(25),
            startup_timeout: Duration::from_secs(120),
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
        if self.request_deadline.is_zero() {
            return invalid("request_deadline must be positive");
        }
        if self.backoff.initial.is_zero() || self.backoff.max < self.backoff.initial {
            return invalid("backoff needs a positive initial delay and a cap of at least that");
        }
        self.sandbox.validate().map_err(ConfigError::Invalid)
    }
}

struct Status<I> {
    ready: usize,
    fatal: Option<String>,
    info: Option<I>,
}

struct Job {
    id: u64,
    payload: Vec<u8>,
    deadline: Instant,
    reply: oneshot::Sender<Result<String, PoolError>>,
}

struct Shared<P: Protocol> {
    protocol: P,
    cfg: PoolConfig,
    queue: Mutex<VecDeque<Job>>,
    wake: Notify,
    status: watch::Sender<Status<P::Info>>,
    shutdown: watch::Sender<bool>,
    next_id: AtomicU64,
    starts: AtomicU64,
    pids: Mutex<BTreeMap<usize, u32>>,
}

/// A supervised pool of worker processes. Dropping it kills the workers.
pub struct WorkerPool<P: Protocol> {
    shared: Arc<Shared<P>>,
    tasks: Vec<JoinHandle<()>>,
}

impl<P: Protocol> std::fmt::Debug for WorkerPool<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WorkerPool").field("name", &self.shared.cfg.name).field("workers", &self.shared.cfg.workers).finish()
    }
}

impl<P: Protocol> WorkerPool<P> {
    /// Validates the configuration and starts one supervisor per worker. Returns immediately; the workers load in the
    /// background and [`WorkerPool::wait_ready`] waits for the first one. Must run inside a Tokio runtime.
    pub fn start(protocol: P, cfg: PoolConfig) -> Result<Self, ConfigError> {
        cfg.validate()?;
        tokio::runtime::Handle::try_current().map_err(|_| ConfigError::NoRuntime)?;
        let workers = cfg.workers;
        let shared = Arc::new(Shared {
            protocol,
            cfg,
            queue: Mutex::new(VecDeque::new()),
            wake: Notify::new(),
            status: watch::channel(Status { ready: 0, fatal: None, info: None }).0,
            shutdown: watch::channel(false).0,
            next_id: AtomicU64::new(1),
            starts: AtomicU64::new(0),
            pids: Mutex::new(BTreeMap::new()),
        });
        let tasks = (0..workers).map(|slot| tokio::spawn(supervise(shared.clone(), slot))).collect();
        Ok(Self { shared, tasks })
    }

    /// True while at least one worker has announced itself and is alive.
    pub fn is_ready(&self) -> bool {
        self.shared.status.borrow().ready > 0
    }

    /// The number of ready workers.
    pub fn ready_workers(&self) -> usize {
        self.shared.status.borrow().ready
    }

    /// The first ready worker's announcement.
    pub fn info(&self) -> Option<P::Info> {
        self.shared.status.borrow().info.clone()
    }

    /// How many worker processes have been started, counting restarts.
    pub fn starts(&self) -> u64 {
        self.shared.starts.load(Ordering::SeqCst)
    }

    /// The operating-system ids of the running worker processes, for diagnostics and for tests that kill one.
    pub fn worker_pids(&self) -> Vec<u32> {
        self.shared.pids.lock().unwrap_or_else(PoisonError::into_inner).values().copied().collect()
    }

    /// A fresh request id.
    pub fn next_id(&self) -> u64 {
        self.shared.next_id.fetch_add(1, Ordering::SeqCst)
    }

    /// Waits until a worker is ready. Fails at once if a worker was refused, and when `within` elapses.
    pub async fn wait_ready(&self, within: Duration) -> Result<(), PoolError> {
        let mut rx = self.shared.status.subscribe();
        let wait = async {
            loop {
                {
                    let status = rx.borrow_and_update();
                    if let Some(reason) = &status.fatal {
                        return Err(PoolError::NotReady(format!("the worker was refused: {reason}")));
                    }
                    if status.ready > 0 {
                        return Ok(());
                    }
                }
                if rx.changed().await.is_err() {
                    return Err(PoolError::Shutdown);
                }
            }
        };
        timeout(within, wait).await.unwrap_or_else(|_| Err(PoolError::NotReady(format!("no worker became ready within {within:?}"))))
    }

    /// Queues one encoded request (its id must come from [`WorkerPool::next_id`]) and returns the result text.
    pub async fn submit(&self, id: u64, payload: Vec<u8>) -> Result<String, PoolError> {
        if *self.shared.shutdown.borrow() {
            return Err(PoolError::Shutdown);
        }
        {
            let status = self.shared.status.borrow();
            if let Some(reason) = &status.fatal {
                return Err(PoolError::NotReady(format!("the worker was refused: {reason}")));
            }
            if status.ready == 0 {
                return Err(PoolError::NotReady("no worker has finished loading".into()));
            }
        }
        let deadline = Instant::now() + self.shared.cfg.request_deadline;
        let (reply, answer) = oneshot::channel();
        {
            let mut queue = self.shared.queue.lock().unwrap_or_else(PoisonError::into_inner);
            if queue.len() >= self.shared.cfg.queue_capacity {
                return Err(PoolError::ResourceExhausted { capacity: self.shared.cfg.queue_capacity });
            }
            queue.push_back(Job { id, payload, deadline, reply });
        }
        self.shared.wake.notify_one();
        match timeout_at(deadline, answer).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(PoolError::WorkerFailed("the worker dropped the request".into())),
            Err(_) => Err(PoolError::DeadlineExceeded(self.shared.cfg.request_deadline)),
        }
    }

    /// Stops the supervisors and kills the workers.
    pub async fn shutdown(mut self) {
        self.shared.shutdown.send_replace(true);
        for task in self.tasks.drain(..) {
            let _ = task.await;
        }
    }
}

impl<P: Protocol> Drop for WorkerPool<P> {
    fn drop(&mut self) {
        self.shared.shutdown.send_replace(true);
        for task in &self.tasks {
            task.abort();
        }
    }
}

struct Running {
    child: Child,
    stdin: ChildStdin,
    stdout: ChildStdout,
    /// Released after the child is killed; on Windows closing it kills anything left in the worker's job.
    _confinement: Guard,
}

enum Outcome {
    /// The pool is shutting down.
    Shutdown,
    /// The worker exited, crashed, broke the protocol or missed a deadline.
    Failed(String),
    /// The worker was refused; do not restart.
    Fatal,
}

async fn supervise<P: Protocol>(shared: Arc<Shared<P>>, slot: usize) {
    let mut shutdown = shared.shutdown.subscribe();
    let mut failures: u32 = 0;
    loop {
        if *shutdown.borrow() {
            return;
        }
        shared.starts.fetch_add(1, Ordering::SeqCst);
        let outcome = match spawn(&shared.cfg, slot) {
            Ok(mut running) => {
                if let Some(pid) = running.child.id() {
                    shared.pids.lock().unwrap_or_else(PoisonError::into_inner).insert(slot, pid);
                }
                let outcome = run_worker(&shared, slot, &mut running, &mut shutdown, &mut failures).await;
                let _ = running.child.kill().await;
                shared.pids.lock().unwrap_or_else(PoisonError::into_inner).remove(&slot);
                outcome
            }
            Err(e) => Outcome::Failed(format!("cannot start {}: {e}", shared.cfg.command.display())),
        };
        match outcome {
            Outcome::Shutdown | Outcome::Fatal => return,
            Outcome::Failed(reason) => {
                failures = failures.saturating_add(1);
                let delay = shared.cfg.backoff.delay(failures);
                tracing::warn!(pool = %shared.cfg.name, slot, failures, ?delay, "worker stopped: {reason}");
                tokio::select! {
                    () = sleep(delay) => {}
                    _ = shutdown.changed() => return,
                }
            }
        }
    }
}

fn spawn(cfg: &PoolConfig, slot: usize) -> std::io::Result<Running> {
    let mut command = Command::new(&cfg.command);
    command.args(&cfg.args);
    sandbox::prepare(&mut command, &cfg.sandbox)?;
    command
        .envs(cfg.envs.iter().map(|(k, v)| (k, v)))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = command.spawn()?;
    let confinement = match sandbox::attach(&child, &cfg.sandbox) {
        Ok(guard) => guard,
        Err(e) => {
            // Fail closed: a worker that could not be confined must not run.
            let _ = child.start_kill();
            return Err(e);
        }
    };
    let missing = || std::io::Error::other("the worker's pipes are missing");
    let stdin = child.stdin.take().ok_or_else(missing)?;
    let stdout = child.stdout.take().ok_or_else(missing)?;
    if let Some(stderr) = child.stderr.take() {
        let pool = cfg.name.clone();
        tokio::spawn(async move {
            let mut lines = BufReader::new(stderr).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                tracing::debug!(target: "privoke_worker_pool::worker", pool = %pool, slot, "{line}");
            }
        });
    }
    Ok(Running { child, stdin, stdout, _confinement: confinement })
}

async fn run_worker<P: Protocol>(
    shared: &Shared<P>,
    slot: usize,
    running: &mut Running,
    shutdown: &mut watch::Receiver<bool>,
    failures: &mut u32,
) -> Outcome {
    // Handshake: the worker is not ready until it says so.
    let hello = tokio::select! {
        r = timeout(shared.cfg.startup_timeout, read_frame(&mut running.stdout)) => r,
        _ = shutdown.changed() => return Outcome::Shutdown,
    };
    let frame = match hello {
        Err(_) => return Outcome::Failed(format!("no ready frame within {:?}", shared.cfg.startup_timeout)),
        Ok(Err(e)) => return Outcome::Failed(format!("no ready frame: {e}")),
        Ok(Ok(frame)) => frame,
    };
    let info = match shared.protocol.parse_hello(&frame) {
        Ok(Hello::Ready(info)) => info,
        Ok(Hello::Fatal(reason)) => {
            tracing::error!(pool = %shared.cfg.name, slot, "worker refused: {reason}");
            shared.status.send_modify(|s| s.fatal = Some(reason));
            return Outcome::Fatal;
        }
        Err(reason) => return Outcome::Failed(reason),
    };
    shared.status.send_modify(|s| {
        s.ready += 1;
        s.info.get_or_insert(info);
    });
    let outcome = serve(shared, running, shutdown, failures).await;
    shared.status.send_modify(|s| s.ready = s.ready.saturating_sub(1));
    outcome
}

async fn serve<P: Protocol>(
    shared: &Shared<P>,
    running: &mut Running,
    shutdown: &mut watch::Receiver<bool>,
    failures: &mut u32,
) -> Outcome {
    loop {
        let job = loop {
            let next = shared.queue.lock().unwrap_or_else(PoisonError::into_inner).pop_front();
            if let Some(job) = next {
                break job;
            }
            tokio::select! {
                () = shared.wake.notified() => {}
                status = running.child.wait() => {
                    return Outcome::Failed(format!("the worker exited while idle: {status:?}"));
                }
                _ = shutdown.changed() => return Outcome::Shutdown,
            }
        };
        if job.reply.is_closed() {
            continue;
        }
        if Instant::now() >= job.deadline {
            let _ = job.reply.send(Err(PoolError::DeadlineExceeded(shared.cfg.request_deadline)));
            continue;
        }
        match exchange(&shared.protocol, running, &job, shared.cfg.request_deadline).await {
            Exchange::Answer(result) => {
                *failures = 0;
                let _ = job.reply.send(result);
            }
            Exchange::Failed(err, reason) => {
                // The request is answered with its own error and is never handed to another worker.
                let _ = job.reply.send(Err(err));
                return Outcome::Failed(reason);
            }
        }
    }
}

enum Exchange {
    Answer(Result<String, PoolError>),
    Failed(PoolError, String),
}

async fn exchange<P: Protocol>(protocol: &P, running: &mut Running, job: &Job, configured: Duration) -> Exchange {
    let failed = |reason: String| Exchange::Failed(PoolError::WorkerFailed(reason.clone()), reason);
    let io = async {
        write_frame(&mut running.stdin, &job.payload).await?;
        read_frame(&mut running.stdout).await
    };
    let frame = match timeout_at(job.deadline, io).await {
        Err(_) => return Exchange::Failed(PoolError::DeadlineExceeded(configured), "the request missed its deadline".into()),
        Ok(Err(e)) => return failed(format!("pipe error: {e}")),
        Ok(Ok(frame)) => frame,
    };
    match protocol.parse_reply(&frame, job.id) {
        Reply::Answer(result) => Exchange::Answer(Ok(result)),
        Reply::Reported(error) => Exchange::Answer(Err(PoolError::WorkerReported(error))),
        Reply::Violation(reason) => failed(reason),
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
    fn validation_rejects_unusable_settings() {
        let ok = PoolConfig::new("x");
        assert!(ok.validate().is_ok());
        let mut bad = ok.clone();
        bad.workers = 0;
        assert!(bad.validate().is_err());
        let mut bad = ok.clone();
        bad.queue_capacity = 0;
        assert!(bad.validate().is_err());
        let mut bad = ok.clone();
        bad.request_deadline = Duration::ZERO;
        assert!(bad.validate().is_err());
        let mut bad = ok.clone();
        bad.sandbox.memory_limit_bytes = Some(0);
        assert!(bad.validate().is_err());
        let mut bad = ok;
        bad.sandbox.max_processes = Some(0);
        assert!(bad.validate().is_err());
    }
}
