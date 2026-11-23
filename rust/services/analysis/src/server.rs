//! Wiring: the validated transport, the model cache, the worker pool and the mutual-TLS listener.
//!
//! Start-up is fail-closed and ordered. The transport (certificates, CRL, registry) is validated before anything is
//! bound. The start-up models are fetched and checked next. Only then is the worker started, and the listener binds
//! after the worker announced READY, so a reachable service always has a loaded worker behind it.

use std::ffi::OsString;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use privoke_transport::startup::CloudTransport;
use privoke_transport::{AuthLayer, Limits, RateLimit, SecureListener, secure_server};
use privoke_worker_pool::{PoolConfig, SandboxPolicy, WorkerPool};
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::config::{AnalysisConfig, RustWorkerSettings, WorkerSettings};
use crate::error::{Error, Result};
use crate::models::ModelCache;
use crate::protocol::WorkerProtocol;
use crate::raw::RuntimeServer;
use crate::service::{AnalysisService, policy};
use crate::util::log;

/// Largest request: the W1 gradient request limit (4 MiB) plus the protobuf envelope.
pub const MAX_REQUEST_BYTES: usize = 4 * 1024 * 1024 + 64 * 1024;

/// The limits of this listener. Only the fuzzer calls it, so the request rate is far above the model service's, and a
/// request may run as long as the pool allows.
pub fn limits(worker: &WorkerSettings) -> Limits {
    Limits {
        request_timeout: worker.request_deadline + Duration::from_secs(30),
        max_message_bytes: MAX_REQUEST_BYTES,
        max_connections: 64,
        max_connections_per_ip: 32,
        max_connection_age: Duration::from_secs(3600),
        rate: RateLimit { per_second: 500, burst: 1000 },
        ..Limits::default()
    }
}

/// The pool configuration for the Python worker behind the shim.
pub fn pool_config(config: &AnalysisConfig) -> PoolConfig {
    let worker = &config.worker;
    let mut pool = PoolConfig::new(&worker.python);
    pool.name = "analysis".into();
    let mut args: Vec<OsString> = vec![
        worker.shim.clone().into(),
        "--runtime-root".into(),
        worker.runtime_root.clone().into(),
        "--".into(),
        "--model-root".into(),
        config.cache_dir.clone().into(),
        "--latest-model-id".into(),
        config.default_model_id.clone().into(),
        // Semantic only: the regex and NER layers are never exercised by this service, so they are not warmed.
        "--warm-layers=".into(),
    ];
    for model in &config.warm_models {
        args.push("--warm-semantic-model".into());
        args.push(model.into());
    }
    pool.args = args;
    let mut envs: Vec<(&str, String)> = vec![
        ("PYTHONDONTWRITEBYTECODE", "1".into()),
        ("PYTHONUNBUFFERED", "1".into()),
        ("PYTHONNOUSERSITE", "1".into()),
        ("PYTHONIOENCODING", "utf-8".into()),
        ("PRIVOKE_LLM_CHOICE", "streamed".into()),
        ("PRIVOKE_MODEL_DEVICE", "cpu".into()),
        ("MODEL_ID", "latest".into()),
        ("MODEL_STREAMING_CACHE_TTL_SECONDS", "1".into()),
        ("TELEMETRY_ENABLED", "false".into()),
        ("HF_HUB_OFFLINE", "1".into()),
        ("TRANSFORMERS_OFFLINE", "1".into()),
        ("OMP_NUM_THREADS", "1".into()),
    ];
    if worker.require_sandbox {
        envs.push(("PRIVOKE_WORKER_SANDBOX", "1".into()));
    }
    pool.envs = envs.into_iter().map(|(key, value)| (OsString::from(key), OsString::from(value))).collect();
    apply_limits(&mut pool, worker);
    pool
}

/// The pool sizes, deadlines and sandbox the two workers share.
fn apply_limits(pool: &mut PoolConfig, worker: &WorkerSettings) {
    pool.workers = worker.workers;
    pool.queue_capacity = worker.queue;
    pool.request_deadline = worker.request_deadline;
    pool.startup_timeout = worker.startup_timeout;
    let mut sandbox = SandboxPolicy { deny_network: true, clean_env: true, ..SandboxPolicy::default() };
    sandbox.inherit_env = ["PATH", "VIRTUAL_ENV", "HOME", "TMPDIR", "TMP", "TEMP", "LANG", "LC_ALL", "LD_LIBRARY_PATH"]
        .into_iter()
        .map(OsString::from)
        .collect();
    sandbox.memory_limit_bytes = worker.memory_limit_bytes;
    sandbox.max_processes = worker.max_processes;
    pool.sandbox = sandbox;
}

/// The pool configuration for the Rust analysis worker (`privoke-runtime-worker`), under the same sandbox, limits and
/// deadlines as the Python worker. It serves the semantic layer and presence from its read-only model
/// root, which is by default this service's own cache (the `<id>.snapshot.pb` files it replaces atomically). Regex and
/// NER are never exercised by this service, so they are not warmed. The start-up models are warmed only when the root is
/// the cache, which `start` has filled by then; another root is the operator's, and a model missing there is that
/// request's error rather than a start-up failure.
pub fn rust_pool_config(config: &AnalysisConfig, rust: &RustWorkerSettings) -> PoolConfig {
    let mut pool = PoolConfig::new(&rust.command);
    pool.name = "analysis-rust".into();
    let mut args: Vec<OsString> = vec![
        "--model-root".into(),
        rust.model_root.clone().into(),
        "--latest-model-id".into(),
        config.default_model_id.clone().into(),
        "--warm-layers".into(),
        OsString::new(),
    ];
    if rust.model_root == config.cache_dir {
        for model in &config.warm_models {
            args.extend(["--warm-semantic-model".into(), model.into()]);
        }
    }
    if let Some(bundle) = &rust.bundle {
        args.extend(["--bundle".into(), bundle.clone().into()]);
    }
    if let Some(directory) = &rust.pretrained_context_dir {
        args.extend(["--pretrained-context-dir".into(), directory.clone().into()]);
    }
    pool.args = args;
    let mut envs: Vec<(&str, String)> = vec![("OMP_NUM_THREADS", "1".into())];
    if config.worker.require_sandbox {
        envs.push(("PRIVOKE_WORKER_SANDBOX", "1".into()));
    }
    pool.envs = envs.into_iter().map(|(key, value)| (OsString::from(key), OsString::from(value))).collect();
    apply_limits(&mut pool, &config.worker);
    pool
}

/// A running server. Dropping the handle does not stop it; `shutdown` does.
#[derive(Debug)]
pub struct ServerHandle {
    /// The bound address.
    pub addr: SocketAddr,
    /// The service, for readiness checks.
    pub service: AnalysisService,
    shutdown: watch::Sender<bool>,
    task: JoinHandle<Result<()>>,
}

impl ServerHandle {
    /// Stop accepting, drain, and stop the workers.
    pub async fn shutdown(self) -> Result<()> {
        let _ = self.shutdown.send(true);
        self.task.await.map_err(|error| Error(error.to_string()))?
    }

    /// Waits until the listener stops by itself (an error) without requesting shutdown.
    pub async fn wait(&mut self) -> Result<()> {
        (&mut self.task).await.map_err(|error| Error(error.to_string()))?
    }
}

/// Starts the service: models, worker, then the listener.
pub async fn start(config: &AnalysisConfig, bind: SocketAddr, transport: CloudTransport, poll: Duration) -> Result<ServerHandle> {
    let cache = Arc::new(ModelCache::new(
        &config.cache_dir,
        config.models.clone(),
        config.model_ttl,
        config.pins.clone(),
        config.default_model_id.clone(),
    ));
    cache.warm(&config.warm_models, config.worker.startup_timeout).await.map_err(|error| Error(format!("start-up models: {error}")))?;

    let pool = WorkerPool::start(WorkerProtocol, pool_config(config)).map_err(|error| Error(error.to_string()))?;
    pool.wait_ready(config.worker.startup_timeout).await.map_err(|error| Error(format!("worker: {error}")))?;
    if let Some(info) = pool.info() {
        log(format_args!("worker ready: {}", info.ready_json));
    }
    let rust_pool = match &config.rust_worker {
        Some(rust) => {
            let pool = WorkerPool::start(WorkerProtocol, rust_pool_config(config, rust)).map_err(|error| Error(error.to_string()))?;
            pool.wait_ready(config.worker.startup_timeout).await.map_err(|error| Error(format!("rust worker: {error}")))?;
            if let Some(info) = pool.info() {
                log(format_args!("rust worker ready: {}", info.ready_json));
            }
            Some(pool)
        }
        None => None,
    };
    let service = AnalysisService::new(pool, rust_pool, cache, config.allowed_services.clone(), config.health_services.clone());

    let limits = limits(&config.worker);
    let tls_watcher = transport.tls.spawn_watcher(poll);
    let registry_watcher = transport.registry.spawn_watcher(poll);
    let auth = AuthLayer::new(policy(), transport.registry.registry(), limits.rate);
    let listener = SecureListener::bind(bind, transport.tls.clone(), limits.clone()).await.map_err(|error| Error(error.to_string()))?;
    let addr = listener.local_addr().map_err(|error| Error(error.to_string()))?;
    let server = secure_server(&limits, auth).add_service(RuntimeServer::new(service.clone(), MAX_REQUEST_BYTES));
    let (shutdown, mut receiver) = watch::channel(false);
    let kept = service.clone();
    let task = tokio::spawn(async move {
        let _keep_alive = (tls_watcher, registry_watcher, kept);
        let stop = async move {
            let _ = receiver.wait_for(|stop| *stop).await;
        };
        server.serve_with_incoming_shutdown(listener.incoming(), stop).await.map_err(|error| Error(format!("listener: {error}")))
    });
    Ok(ServerHandle { addr, service, shutdown, task })
}
