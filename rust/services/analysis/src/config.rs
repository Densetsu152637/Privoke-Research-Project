//! Process configuration from the environment.
//!
//! The service has no plaintext mode and no default for any credential path: it refuses to start without them.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

use crate::error::{Error, Result};
use crate::fail;

/// Default listener port: the port the fuzzer already uses for `PRIVOKE_RUNTIME_TARGET` (`client-runtime:50054`).
pub const DEFAULT_PORT: u16 = 50054;
/// The model the empty id and the alias `latest` resolve to. Legacy float artifacts only: V3 packages are not served.
pub const DEFAULT_MODEL_ID: &str = "privoke-balanced";
/// The only service identity admitted by default.
pub const DEFAULT_ALLOWED_SERVICE: &str = "fuzzer";

/// How the model-streaming service is reached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelSource {
    /// `host:port` of the internal listener (`GetModelParameters`, registered services only).
    pub target: String,
    /// CA bundle that signed the model-streaming server certificate.
    pub server_ca: PathBuf,
    /// The service certificate this service presents (a `runtime` registration, never `publisher`).
    pub client_cert: PathBuf,
    /// Its private key.
    pub client_key: PathBuf,
    /// The name the model-streaming server certificate carries.
    pub server_name: String,
}

/// How the worker is started.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerSettings {
    /// The interpreter, normally the virtual environment's `python`.
    pub python: PathBuf,
    /// `worker_shim.py`.
    pub shim: PathBuf,
    /// `extension/client-runtime`, the directory that holds `src/worker_main.py`.
    pub runtime_root: PathBuf,
    /// Worker processes. Each loads its own copy of the models.
    pub workers: usize,
    /// Requests that may wait for a free worker.
    pub queue: usize,
    /// One deadline for queueing plus serving; the longest gradient deadline plus a grace period.
    pub request_deadline: Duration,
    /// How long a worker may take to load before it announces READY.
    pub startup_timeout: Duration,
    /// Run the worker's socket self-check (`PRIVOKE_WORKER_SANDBOX=1`). Off only where the OS cannot deny sockets
    /// (a Windows development host); the container is the quarantine.
    pub require_sandbox: bool,
    /// Per-process address-space ceiling. Unset by default: torch maps large address ranges, and the container's
    /// cgroup memory limit is the control.
    pub memory_limit_bytes: Option<u64>,
    /// `RLIMIT_NPROC`. Unset by default: the container's pids limit is the control.
    pub max_processes: Option<u32>,
}

/// The optional Rust analysis worker (`privoke-runtime-worker`, stage 17). When it is configured the service holds a
/// second pool of it and sends each call to the worker that serves it (`privoke_supervisor::routing`); the Python worker
/// stays the answer for everything the Rust worker declines. Absent, nothing changes.
///
/// The Rust worker reads the `<id>.snapshot.pb` files this service keeps for the Python worker (and plain
/// `<root>/<model_id>.json` artifacts), so by default its model root is this service's own cache and a model that a
/// training cycle publishes reaches both pools through the one file the service replaces atomically.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RustWorkerSettings {
    /// The `privoke-runtime-worker` executable (`ANALYSIS_RUST_WORKER`).
    pub command: PathBuf,
    /// Its read-only model root (`ANALYSIS_RUST_MODEL_ROOT`); the service's own `cache_dir` unless set.
    pub model_root: PathBuf,
    /// The spaCy bundle directory, when it is not beside the executable (`ANALYSIS_RUST_BUNDLE`).
    pub bundle: Option<PathBuf>,
    /// The pretrained contextual encoder assets (`ANALYSIS_RUST_PRETRAINED_CONTEXT_DIR`).
    pub pretrained_context_dir: Option<PathBuf>,
}

/// Everything the service reads from its environment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnalysisConfig {
    /// Interface the listener binds.
    pub bind: IpAddr,
    /// Listener port.
    pub port: u16,
    /// Service names (the `urn:privoke:service:<name>` of the certificate) that may call. Default `fuzzer`.
    pub allowed_services: Vec<String>,
    /// Service names that may call `Health` only (the container's own probe identity). Default none.
    pub health_services: Vec<String>,
    /// Model-streaming access.
    pub models: ModelSource,
    /// Where fetched models are written and the worker reads them (a named volume).
    pub cache_dir: PathBuf,
    /// What the empty id and `latest` mean.
    pub default_model_id: String,
    /// Models fetched and loaded before the service reports ready.
    pub warm_models: Vec<String>,
    /// How long a fetched model is trusted before the next request checks model-streaming again.
    pub model_ttl: Duration,
    /// `model_id=artifact_checksum` pins for immutable models.
    pub pins: BTreeMap<String, String>,
    /// The worker.
    pub worker: WorkerSettings,
    /// The Rust analysis worker, when `ANALYSIS_RUST_WORKER` is set.
    pub rust_worker: Option<RustWorkerSettings>,
}

/// `[A-Za-z0-9][A-Za-z0-9._+-]{0,127}`, the worker's model id rule.
pub fn is_model_id(text: &str) -> bool {
    let bytes = text.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 128
        && bytes[0].is_ascii_alphanumeric()
        && bytes.iter().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'+' | b'-'))
}

fn text(get: &impl Fn(&str) -> Option<String>, key: &str, fallback: &str) -> String {
    get(key).filter(|value| !value.is_empty()).unwrap_or_else(|| fallback.to_string())
}

fn required(get: &impl Fn(&str) -> Option<String>, key: &str) -> Result<String> {
    get(key).filter(|value| !value.is_empty()).ok_or_else(|| Error(format!("{key} is required")))
}

fn number<T: std::str::FromStr>(get: &impl Fn(&str) -> Option<String>, key: &str, fallback: T) -> Result<T> {
    match get(key).filter(|value| !value.is_empty()) {
        None => Ok(fallback),
        Some(value) => value.parse().map_err(|_| Error(format!("{key} must be a number"))),
    }
}

fn flag(get: &impl Fn(&str) -> Option<String>, key: &str, fallback: bool) -> Result<bool> {
    match get(key).filter(|value| !value.is_empty()).as_deref() {
        None => Ok(fallback),
        Some("1" | "true" | "yes" | "on") => Ok(true),
        Some("0" | "false" | "no" | "off") => Ok(false),
        Some(_) => Err(Error(format!("{key} must be a boolean"))),
    }
}

fn list(value: &str) -> Vec<String> {
    value.split(',').map(str::trim).filter(|item| !item.is_empty()).map(str::to_string).collect()
}

impl AnalysisConfig {
    /// Reads variables through `get`, so tests do not touch the process environment.
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Self> {
        let target = required(&get, "MODEL_STREAMING_TARGET")?;
        let server_name = match get("ANALYSIS_MODEL_SERVER_NAME").filter(|value| !value.is_empty()) {
            Some(name) => name,
            None => target.rsplit_once(':').map_or(target.clone(), |(host, _)| host.to_string()),
        };
        let default_model_id = text(&get, "ANALYSIS_DEFAULT_MODEL_ID", DEFAULT_MODEL_ID);
        let warm_models = match get("ANALYSIS_WARM_MODELS") {
            Some(value) => list(&value),
            None => vec![default_model_id.clone()],
        };
        let mut pins = BTreeMap::new();
        for entry in list(&text(&get, "ANALYSIS_MODEL_PINS", "")) {
            let Some((id, checksum)) = entry.split_once('=') else { fail!("ANALYSIS_MODEL_PINS entries are model_id=sha256") };
            if !is_model_id(id) || checksum.len() != 64 || !checksum.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                fail!("ANALYSIS_MODEL_PINS entry {entry:?} is not model_id=64 hex digits");
            }
            pins.insert(id.to_string(), checksum.to_ascii_lowercase());
        }
        let cache_dir: PathBuf = text(&get, "ANALYSIS_CACHE_DIR", "/var/cache/privoke-models").into();
        let rust_worker = match get("ANALYSIS_RUST_WORKER").filter(|value| !value.is_empty()) {
            Some(command) => Some(RustWorkerSettings {
                command: command.into(),
                model_root: get("ANALYSIS_RUST_MODEL_ROOT")
                    .filter(|value| !value.is_empty())
                    .map_or_else(|| cache_dir.clone(), PathBuf::from),
                bundle: get("ANALYSIS_RUST_BUNDLE").filter(|value| !value.is_empty()).map(PathBuf::from),
                pretrained_context_dir: get("ANALYSIS_RUST_PRETRAINED_CONTEXT_DIR").filter(|value| !value.is_empty()).map(PathBuf::from),
            }),
            None => {
                for key in ["ANALYSIS_RUST_MODEL_ROOT", "ANALYSIS_RUST_BUNDLE", "ANALYSIS_RUST_PRETRAINED_CONTEXT_DIR"] {
                    if get(key).is_some_and(|value| !value.is_empty()) {
                        fail!("{key} is set without ANALYSIS_RUST_WORKER");
                    }
                }
                None
            }
        };
        let config = Self {
            bind: text(&get, "ANALYSIS_BIND", "0.0.0.0")
                .parse()
                .map_err(|error| Error(format!("ANALYSIS_BIND must be an IP address: {error}")))?,
            port: number(&get, "ANALYSIS_PORT", DEFAULT_PORT)?,
            allowed_services: match get("ANALYSIS_ALLOWED_SERVICES").filter(|value| !value.is_empty()) {
                Some(value) => list(&value),
                None => vec![DEFAULT_ALLOWED_SERVICE.to_string()],
            },
            health_services: list(&text(&get, "ANALYSIS_HEALTH_SERVICES", "")),
            models: ModelSource {
                target,
                server_ca: required(&get, "ANALYSIS_MODEL_SERVER_CA")?.into(),
                client_cert: required(&get, "ANALYSIS_MODEL_CLIENT_CERT")?.into(),
                client_key: required(&get, "ANALYSIS_MODEL_CLIENT_KEY")?.into(),
                server_name,
            },
            cache_dir,
            default_model_id,
            warm_models,
            model_ttl: Duration::from_millis(number(&get, "ANALYSIS_MODEL_TTL_MS", 1000)?),
            pins,
            worker: WorkerSettings {
                python: text(&get, "ANALYSIS_WORKER_PYTHON", "python").into(),
                shim: text(&get, "ANALYSIS_WORKER_SHIM", "/opt/privoke-analysis/worker_shim.py").into(),
                runtime_root: text(&get, "ANALYSIS_RUNTIME_ROOT", "/workspace/extension/client-runtime").into(),
                workers: number(&get, "ANALYSIS_WORKERS", 1)?,
                queue: number(&get, "ANALYSIS_QUEUE", 64)?,
                request_deadline: Duration::from_secs(number(&get, "ANALYSIS_REQUEST_DEADLINE_SECS", 330)?),
                startup_timeout: Duration::from_secs(number(&get, "ANALYSIS_STARTUP_TIMEOUT_SECS", 300)?),
                require_sandbox: flag(&get, "ANALYSIS_REQUIRE_SANDBOX", true)?,
                memory_limit_bytes: get("ANALYSIS_WORKER_MEMORY_BYTES")
                    .filter(|value| !value.is_empty())
                    .map(|value| value.parse())
                    .transpose()
                    .map_err(|_| Error("ANALYSIS_WORKER_MEMORY_BYTES must be a number".into()))?,
                max_processes: get("ANALYSIS_WORKER_MAX_PROCESSES")
                    .filter(|value| !value.is_empty())
                    .map(|value| value.parse())
                    .transpose()
                    .map_err(|_| Error("ANALYSIS_WORKER_MAX_PROCESSES must be a number".into()))?,
            },
            rust_worker,
        };
        config.validate()?;
        Ok(config)
    }

    /// Reads the process environment.
    pub fn from_env() -> Result<Self> {
        Self::from_lookup(|key| std::env::var(key).ok())
    }

    /// Checks the values that would otherwise fail late or open a gap.
    pub fn validate(&self) -> Result<()> {
        if self.port == 0 {
            fail!("ANALYSIS_PORT must be between 1 and 65535");
        }
        if self.allowed_services.is_empty() {
            fail!("ANALYSIS_ALLOWED_SERVICES must name at least one service");
        }
        for name in self.allowed_services.iter().chain(&self.health_services) {
            let bytes = name.as_bytes();
            let valid = !bytes.is_empty()
                && bytes.len() <= 63
                && bytes[0].is_ascii_lowercase()
                && bytes.iter().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-');
            if !valid {
                fail!("service name {name:?} is not valid");
            }
        }
        for id in std::iter::once(&self.default_model_id).chain(&self.warm_models) {
            if !is_model_id(id) {
                fail!("{id:?} is not a valid model id");
            }
        }
        if self.worker.workers == 0 || self.worker.queue == 0 {
            fail!("ANALYSIS_WORKERS and ANALYSIS_QUEUE must be at least 1");
        }
        if self.worker.request_deadline.is_zero() {
            fail!("ANALYSIS_REQUEST_DEADLINE_SECS must be positive");
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn base() -> BTreeMap<&'static str, String> {
        BTreeMap::from([
            ("MODEL_STREAMING_TARGET", "model-streaming:50051".to_string()),
            ("ANALYSIS_MODEL_SERVER_CA", "/c/ca.pem".to_string()),
            ("ANALYSIS_MODEL_CLIENT_CERT", "/c/a.crt".to_string()),
            ("ANALYSIS_MODEL_CLIENT_KEY", "/c/a.key".to_string()),
        ])
    }

    fn load(values: &BTreeMap<&'static str, String>) -> Result<AnalysisConfig> {
        AnalysisConfig::from_lookup(|key| values.get(key).cloned())
    }

    #[test]
    fn defaults_admit_only_the_fuzzer_and_warm_the_default_model() {
        let config = load(&base()).unwrap();
        assert_eq!(config.allowed_services, ["fuzzer"]);
        assert_eq!(config.port, 50054);
        assert_eq!(config.warm_models, ["privoke-balanced"]);
        assert_eq!(config.models.server_name, "model-streaming");
        assert!(config.worker.require_sandbox);
    }

    #[test]
    fn every_credential_is_required() {
        for key in ["MODEL_STREAMING_TARGET", "ANALYSIS_MODEL_SERVER_CA", "ANALYSIS_MODEL_CLIENT_CERT", "ANALYSIS_MODEL_CLIENT_KEY"] {
            let mut values = base();
            values.remove(key);
            assert!(load(&values).is_err(), "{key}");
        }
    }

    #[test]
    fn bad_values_are_refused() {
        for (key, value) in [
            ("ANALYSIS_ALLOWED_SERVICES", "Fuzzer"),
            ("ANALYSIS_DEFAULT_MODEL_ID", "../escape"),
            ("ANALYSIS_PORT", "0"),
            ("ANALYSIS_WORKERS", "0"),
            ("ANALYSIS_MODEL_PINS", "privoke-balanced=abc"),
            ("ANALYSIS_REQUIRE_SANDBOX", "maybe"),
        ] {
            let mut values = base();
            values.insert(key, value.to_string());
            assert!(load(&values).is_err(), "{key}={value}");
        }
    }

    #[test]
    fn the_rust_worker_is_off_by_default_and_reads_the_services_cache_unless_told_otherwise() {
        assert_eq!(load(&base()).unwrap().rust_worker, None);

        let mut values = base();
        values.insert("ANALYSIS_RUST_WORKER", "/opt/privoke/privoke-runtime-worker".to_string());
        let config = load(&values).unwrap();
        let rust = config.rust_worker.unwrap();
        assert_eq!(rust.command, PathBuf::from("/opt/privoke/privoke-runtime-worker"));
        assert_eq!(rust.model_root, config.cache_dir, "the service's own store by default");
        assert_eq!((rust.bundle, rust.pretrained_context_dir), (None, None));

        values.insert("ANALYSIS_CACHE_DIR", "/cache".to_string());
        assert_eq!(load(&values).unwrap().rust_worker.unwrap().model_root, PathBuf::from("/cache"));
        values.insert("ANALYSIS_RUST_MODEL_ROOT", "/models".to_string());
        assert_eq!(load(&values).unwrap().rust_worker.unwrap().model_root, PathBuf::from("/models"));

        for key in ["ANALYSIS_RUST_MODEL_ROOT", "ANALYSIS_RUST_BUNDLE", "ANALYSIS_RUST_PRETRAINED_CONTEXT_DIR"] {
            let mut orphan = base();
            orphan.insert(key, "/x".to_string());
            assert!(load(&orphan).is_err(), "{key} without the worker");
        }
    }

    #[test]
    fn model_ids_follow_the_worker_rule() {
        assert!(is_model_id("privoke-balanced"));
        assert!(!is_model_id(""));
        assert!(!is_model_id("-x"));
        assert!(!is_model_id("a/b"));
        assert!(!is_model_id(&"a".repeat(129)));
    }
}
