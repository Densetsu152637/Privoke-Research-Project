//! The W1 inference worker behind the W2 pool: the frame codec, the pool [`Protocol`], and how the worker is started.
//!
//! The pool talks to its child on stdin and stdout with `u32` little-endian length frames. The Python worker
//! (`extension/client-runtime/src/worker_main.py`) speaks its own 20-byte-header frames on two dedicated pipe
//! descriptors. `python/worker_shim.py` runs the unchanged worker in-process and pumps frames between the two framings;
//! each pool frame carries exactly one W1 frame. The shim also lets the worker find the model packages under the
//! controller's own cache layout (`<cache>/<model_id>/<pin>/`), read-only.
//!
//! The worker never opens a socket and reads models only from the paths given here. Where the operating system can deny
//! the network (Linux) the pool's sandbox does and the worker self-checks it; on Windows only the self-check's
//! absence is documented and no denial is claimed.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use privoke_worker_pool::{Hello, PoolConfig, Protocol, Reply, SandboxPolicy, network_denial_enforced};
use serde::Deserialize;

use crate::config::{Environment, boolean, cache_root, positive_int, positive_seconds};
use crate::routing::Selection;

/// Header size of a W1 frame.
pub const HEADER_LEN: usize = 20;
/// The W1 protocol version.
pub const VERSION: u8 = 1;
/// The most an `AnalyzePrompt` request may carry (the worker's own limit).
pub const MAX_ANALYZE_REQUEST_BYTES: usize = 262_144;

/// Separates a worker error code from its message inside a `Reported` string.
const SEPARATOR: char = '\u{1f}';

/// Frame kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    /// Controller to worker.
    Request = 1,
    /// Worker answer.
    Response = 2,
    /// Worker error.
    Error = 3,
    /// First frame of a worker.
    Ready = 4,
}

/// The methods the controller uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Method {
    /// `AnalyzePrompt`.
    AnalyzePrompt = 1,
    /// `Health`.
    Health = 3,
}

/// A decoded header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// The kind byte, undecoded.
    pub kind: u8,
    /// The method tag.
    pub method: u8,
    /// The request id.
    pub request_id: u64,
}

/// A request frame. `deadline_ms` 0 selects the worker's default for the method.
pub fn encode_request(method: Method, request_id: u64, deadline_ms: u32, payload: &[u8]) -> Result<Vec<u8>, String> {
    let length = u32::try_from(payload.len()).map_err(|_| "request payload is too large".to_string())?;
    let mut frame = Vec::with_capacity(HEADER_LEN + payload.len());
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(&[VERSION, Kind::Request as u8, method as u8, 0]);
    frame.extend_from_slice(&request_id.to_be_bytes());
    frame.extend_from_slice(&deadline_ms.to_be_bytes());
    frame.extend_from_slice(payload);
    Ok(frame)
}

/// A response, error or ready frame, as the worker (or a stand-in) writes it.
pub fn encode_frame(kind: Kind, method: u8, request_id: u64, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(HEADER_LEN + payload.len());
    frame.extend_from_slice(&u32::try_from(payload.len()).unwrap_or(u32::MAX).to_be_bytes());
    frame.extend_from_slice(&[VERSION, kind as u8, method, 0]);
    frame.extend_from_slice(&request_id.to_be_bytes());
    frame.extend_from_slice(&[0, 0, 0, 0]);
    frame.extend_from_slice(payload);
    frame
}

/// Splits a whole frame into its header and payload, checking the length field against the frame.
pub fn decode(frame: &[u8]) -> Result<(Header, &[u8]), String> {
    if frame.len() < HEADER_LEN {
        return Err(format!("frame of {} bytes is shorter than the {HEADER_LEN}-byte header", frame.len()));
    }
    let declared = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]) as usize;
    if declared != frame.len() - HEADER_LEN {
        return Err(format!("frame declares {declared} payload bytes but carries {}", frame.len() - HEADER_LEN));
    }
    if frame[4] != VERSION {
        return Err(format!("unsupported frame version {}", frame[4]));
    }
    let mut id = [0u8; 8];
    id.copy_from_slice(&frame[8..16]);
    Ok((Header { kind: frame[5], method: frame[6], request_id: u64::from_be_bytes(id) }, &frame[HEADER_LEN..]))
}

/// What the worker announced in its READY frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerInfo {
    /// The READY frame's JSON payload (`protocol_version`, `pid`, `sandbox_self_check`, `telemetry`, `loaded`, ...).
    pub ready_json: String,
}

#[derive(Deserialize)]
struct ErrorBody {
    #[serde(default)]
    code: String,
    #[serde(default)]
    message: String,
}

fn error_fields(payload: &[u8]) -> (String, String) {
    match serde_json::from_slice::<ErrorBody>(payload) {
        Ok(body) => (body.code, body.message),
        Err(_) => (String::new(), String::from_utf8_lossy(payload).into_owned()),
    }
}

/// Splits a `Reported` string back into the worker's code and message.
pub fn split_reported(text: &str) -> (&str, &str) {
    text.split_once(SEPARATOR).unwrap_or(("INTERNAL", text))
}

/// The W1 protocol over the pool's frames. A pool answer is the response payload as standard base64, which is also
/// what the native-messaging reply carries.
#[derive(Debug, Clone, Copy, Default)]
pub struct WorkerProtocol;

impl Protocol for WorkerProtocol {
    type Info = WorkerInfo;

    fn parse_hello(&self, frame: &[u8]) -> Result<Hello<WorkerInfo>, String> {
        let (header, payload) = decode(frame)?;
        match header.kind {
            kind if kind == Kind::Ready as u8 => Ok(Hello::Ready(WorkerInfo { ready_json: String::from_utf8_lossy(payload).into_owned() })),
            // SANDBOX_VIOLATION and STARTUP_FAILED end the worker with a non-restartable exit code.
            kind if kind == Kind::Error as u8 => {
                let (code, message) = error_fields(payload);
                Ok(Hello::Fatal(format!("{code}: {message}")))
            }
            other => Err(format!("unexpected first frame of kind {other}")),
        }
    }

    fn parse_reply(&self, frame: &[u8], request_id: u64) -> Reply {
        let (header, payload) = match decode(frame) {
            Ok(decoded) => decoded,
            Err(reason) => return Reply::Violation(reason),
        };
        if header.kind == Kind::Response as u8 && header.request_id == request_id {
            return Reply::Answer(STANDARD.encode(payload));
        }
        if header.kind == Kind::Error as u8 && (header.request_id == request_id || header.request_id == 0) {
            let (code, message) = error_fields(payload);
            return Reply::Reported(format!("{code}{SEPARATOR}{message}"));
        }
        Reply::Violation(format!("unexpected frame: kind {}, request id {} (waiting for {request_id})", header.kind, header.request_id))
    }
}

/// Everything needed to start the worker pool.
#[derive(Debug, Clone)]
pub struct WorkerSettings {
    /// The program the pool starts.
    pub command: PathBuf,
    /// Its arguments.
    pub args: Vec<OsString>,
    /// Environment passed to the worker after the sandbox's clean-environment policy.
    pub envs: Vec<(OsString, OsString)>,
    /// How long the worker may take to load and announce itself.
    pub start_timeout: Duration,
    /// One deadline for queueing and serving an analysis. Longer than the worker's own 25 s, shorter than the
    /// extension's 30 s.
    pub request_deadline: Duration,
    /// Committed-memory ceiling for the worker and its children, `None` for no limit.
    pub memory_limit_bytes: Option<u64>,
    /// Live-process ceiling (on Windows the venv launcher and the interpreter are two).
    pub max_processes: u32,
    /// For the Rust worker: whether it is given model roots, and so serves the semantic layer.
    pub serves_semantic: bool,
}

/// The variables a worker may inherit. Everything else, including credentials and the telemetry and TLS settings, stays
/// in the controller.
const WORKER_ENVIRONMENT: [&str; 26] = [
    "TEMP",
    "TMP",
    "TMPDIR",
    "LOCALAPPDATA",
    "APPDATA",
    "USERPROFILE",
    "HOME",
    "XDG_CACHE_HOME",
    "XDG_STATE_HOME",
    "PRIVOKE_MODEL_DEVICE",
    "PRIVOKE_LLM_CHOICE",
    "OMP_NUM_THREADS",
    "MKL_NUM_THREADS",
    // The frozen window and component release of the window training route (read by both workers).
    "PRIVOKE_WINDOW_PATH",
    "PRIVOKE_WINDOW_MANIFEST_SHA256",
    "PRIVOKE_COMPONENT_BANK_PATH",
    "PRIVOKE_COMPONENT_REFERENCE_PATH",
    "PRIVOKE_COMPONENT_MANIFEST_PATH",
    "PRIVOKE_COMPONENT_TEACHER_PATH",
    "PRIVOKE_COMPONENT_MANIFEST_SHA256",
    "PRIVOKE_COMPONENT_TEACHER_SHA256",
    // The ORIGINAL retention release of the retention training route (read by both workers).
    "PRIVOKE_RETENTION_BANK_PATH",
    "PRIVOKE_RETENTION_REFERENCE_PATH",
    "PRIVOKE_RETENTION_MANIFEST_PATH",
    "PRIVOKE_RETENTION_TEACHER_PATH",
    "PRIVOKE_RETENTION_MANIFEST_SHA256",
];

impl WorkerSettings {
    /// The worker for the installed tree under `repository_root`, configured from `environment`.
    pub fn from_environment(environment: &Environment, repository_root: &Path) -> Result<Self, String> {
        let runtime_root = repository_root.join("extension").join("client-runtime");
        let python = runtime_python(&runtime_root, environment);
        let shim =
            environment.get("PRIVOKE_WORKER_SHIM").map(|v| v.trim()).filter(|v| !v.is_empty()).map(PathBuf::from).unwrap_or_else(|| {
                repository_root.join("rust").join("services").join("runtime-supervisor").join("python").join("worker_shim.py")
            });

        let mut args: Vec<OsString> = vec![shim.into(), "--runtime-root".into(), runtime_root.into(), "--".into()];
        let cache = cache_root(environment);
        if cache.is_dir() {
            args.extend(["--model-root".into(), cache.into()]);
        }
        if let Some(latest) = environment.get("PRIVOKE_LATEST_MODEL_ID").map(|v| v.trim()).filter(|v| !v.is_empty()) {
            args.extend(["--latest-model-id".into(), latest.into()]);
        }
        if let Some(layers) = environment.get("PRIVOKE_WORKER_WARM_LAYERS") {
            args.extend(["--warm-layers".into(), layers.trim().into()]);
        }
        for model in environment.get("PRIVOKE_WORKER_WARM_MODELS").map(String::as_str).unwrap_or_default().split(',') {
            if !model.trim().is_empty() {
                args.extend(["--warm-semantic-model".into(), model.trim().into()]);
            }
        }

        let mut envs: Vec<(OsString, OsString)> = WORKER_ENVIRONMENT
            .iter()
            .filter_map(|name| environment.get(*name).map(|value| (OsString::from(*name), OsString::from(value))))
            .collect();
        if network_denial_enforced() {
            // The OS layer denies sockets here, so the worker's own check is meaningful and is switched on.
            envs.push(("PRIVOKE_WORKER_SANDBOX".into(), "1".into()));
        }

        let memory_mb = positive_int_or_zero(environment, "PRIVOKE_WORKER_MEMORY_MB", 6144)?;
        Ok(Self {
            command: python,
            args,
            envs,
            start_timeout: positive_seconds(environment, "PRIVOKE_RUNTIME_START_TIMEOUT_SECONDS", 30.0)?,
            request_deadline: positive_seconds(environment, "PRIVOKE_RUNTIME_REQUEST_TIMEOUT_SECONDS", 27.0)?,
            memory_limit_bytes: (memory_mb > 0).then(|| memory_mb.saturating_mul(1024 * 1024)),
            max_processes: u32::try_from(positive_int(environment, "PRIVOKE_WORKER_MAX_PROCESSES", 8)?)
                .map_err(|_| "PRIVOKE_WORKER_MAX_PROCESSES is too large.".to_string())?,
            serves_semantic: false,
        })
    }

    /// The Rust analysis worker (`privoke-runtime-worker`, stage 17), configured like the Python worker (the same
    /// environment allow-list, limits and deadlines). `None` unless `PRIVOKE_RUNTIME_ANALYSIS_ENGINE=rust`; the Python
    /// worker is always started, because it serves everything the Rust worker does not (see `routing`).
    ///
    /// The binary is `PRIVOKE_RUNTIME_RUST_WORKER`, else the file `privoke-runtime-worker` beside this executable. It is
    /// installed in the spaCy bundle directory, where CPython finds its `_pth` file, so the bundle needs no setting.
    pub fn rust_from_environment(environment: &Environment, repository_root: &Path) -> Result<Option<Self>, String> {
        let selection = Selection::parse(environment.get("PRIVOKE_RUNTIME_ANALYSIS_ENGINE").map(String::as_str))?;
        if selection != Selection::Rust {
            return Ok(None);
        }
        let command = rust_worker_path(environment)?;
        let mut settings = Self::from_environment(environment, repository_root)?;
        settings.command = command;
        // The same read-only roots, alias and warm-up the Python worker gets; the Rust worker reads the controller's cache
        // layout (`<cache>/<model_id>/<pin>/`) directly.
        let mut args: Vec<OsString> = Vec::new();
        let cache = cache_root(environment);
        if cache.is_dir() {
            args.extend(["--model-root".into(), cache.into()]);
            settings.serves_semantic = true;
        }
        if let Some(latest) = environment.get("PRIVOKE_LATEST_MODEL_ID").map(|v| v.trim()).filter(|v| !v.is_empty()) {
            args.extend(["--latest-model-id".into(), latest.into()]);
        }
        // The frozen backbone and tokenizer of the pretrained contextual encoder, read-only (the Python runtime's
        // `PRIVOKE_PRETRAINED_CONTEXT_DIR`). The worker verifies both files against their pins before it parses them.
        if settings.serves_semantic
            && let Some(directory) = environment.get("PRIVOKE_PRETRAINED_CONTEXT_DIR").map(|v| v.trim()).filter(|v| !v.is_empty())
        {
            args.extend(["--pretrained-context-dir".into(), directory.into()]);
        }
        args.extend([
            "--warm-layers".into(),
            environment.get("PRIVOKE_WORKER_WARM_LAYERS").map_or("regex,ner", |layers| layers.trim()).into(),
        ]);
        if settings.serves_semantic {
            for model in environment.get("PRIVOKE_WORKER_WARM_MODELS").map(String::as_str).unwrap_or_default().split(',') {
                if !model.trim().is_empty() {
                    args.extend(["--warm-semantic-model".into(), model.trim().into()]);
                }
            }
        }
        settings.args = args;
        Ok(Some(settings))
    }

    /// The pool configuration: one sandboxed worker, a short queue, and the worker's own deadlines underneath.
    pub fn pool_config(&self) -> PoolConfig {
        let mut config = PoolConfig::new(&self.command);
        config.name = "runtime-worker".into();
        config.args.clone_from(&self.args);
        config.envs.clone_from(&self.envs);
        config.workers = 1;
        config.queue_capacity = 16;
        config.request_deadline = self.request_deadline;
        config.startup_timeout = self.start_timeout;
        config.sandbox = SandboxPolicy {
            kill_with_parent: true,
            memory_limit_bytes: self.memory_limit_bytes,
            max_processes: Some(self.max_processes),
            deny_network: true,
            clean_env: true,
            inherit_env: Vec::new(),
            python_home: None,
        };
        config
    }
}

fn positive_int_or_zero(environment: &Environment, name: &str, default: u64) -> Result<u64, String> {
    match environment.get(name).map(|v| v.trim()) {
        None => Ok(default),
        Some("0") => Ok(0),
        Some(_) => positive_int(environment, name, default),
    }
}

/// `PRIVOKE_RUNTIME_PYTHON`, else the client runtime's virtual environment, else the system interpreter.
pub fn runtime_python(runtime_root: &Path, environment: &Environment) -> PathBuf {
    if let Some(configured) = environment.get("PRIVOKE_RUNTIME_PYTHON").map(|v| v.trim()).filter(|v| !v.is_empty()) {
        return PathBuf::from(configured);
    }
    for relative in [".venv/Scripts/python.exe", ".venv/bin/python"] {
        let candidate = runtime_root.join(relative);
        if candidate.is_file() {
            return candidate;
        }
    }
    PathBuf::from(if cfg!(windows) { "python" } else { "python3" })
}

/// `PRIVOKE_RUNTIME_RUST_WORKER`, else `privoke-runtime-worker` next to the running executable.
pub fn rust_worker_path(environment: &Environment) -> Result<PathBuf, String> {
    let name = if cfg!(windows) { "privoke-runtime-worker.exe" } else { "privoke-runtime-worker" };
    let candidate = match environment.get("PRIVOKE_RUNTIME_RUST_WORKER").map(|v| v.trim()).filter(|v| !v.is_empty()) {
        Some(configured) => PathBuf::from(configured),
        None => std::env::current_exe()
            .ok()
            .and_then(|exe| exe.parent().map(|directory| directory.join(name)))
            .ok_or_else(|| "The Rust analysis worker cannot be located: set PRIVOKE_RUNTIME_RUST_WORKER.".to_string())?,
    };
    if candidate.is_file() {
        Ok(candidate)
    } else {
        Err(format!("The Rust analysis worker {} does not exist (PRIVOKE_RUNTIME_ANALYSIS_ENGINE=rust).", candidate.display()))
    }
}

/// `PRIVOKE_RUNTIME_START_ENABLED`: whether the runtime starts without the extension asking. Default false for the
/// controller: the extension enables it.
pub fn start_enabled(environment: &Environment) -> Result<bool, String> {
    boolean(environment, "PRIVOKE_RUNTIME_START_ENABLED", false)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn request_header_is_twenty_big_endian_bytes() {
        let frame = encode_request(Method::AnalyzePrompt, 0x0102_0304_0506_0708, 7, b"abc").unwrap();
        assert_eq!(&frame[..20], &[0, 0, 0, 3, 1, 1, 1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 7]);
        assert_eq!(&frame[20..], b"abc");
        let (header, payload) = decode(&frame).unwrap();
        assert_eq!((header.kind, header.method, header.request_id), (1, 1, 0x0102_0304_0506_0708));
        assert_eq!(payload, b"abc");
    }

    #[test]
    fn length_mismatch_and_short_frames_are_refused() {
        let mut frame = encode_request(Method::Health, 1, 0, b"").unwrap();
        frame.push(0);
        assert!(decode(&frame).is_err());
        assert!(decode(&[0; 5]).is_err());
    }

    #[test]
    fn replies_are_matched_by_request_id_and_errors_keep_their_code() {
        let protocol = WorkerProtocol;
        let answer = encode_frame(Kind::Response, 1, 9, b"\x01\x02");
        assert!(matches!(protocol.parse_reply(&answer, 9), Reply::Answer(text) if text == "AQI="));
        assert!(matches!(protocol.parse_reply(&answer, 10), Reply::Violation(_)));
        let error = encode_frame(Kind::Error, 1, 9, br#"{"code": "INVALID_LAYERS", "message": "no layers"}"#);
        match protocol.parse_reply(&error, 9) {
            Reply::Reported(text) => assert_eq!(split_reported(&text), ("INVALID_LAYERS", "no layers")),
            other => panic!("{other:?}"),
        }
        assert!(matches!(protocol.parse_reply(b"short", 1), Reply::Violation(_)));
    }

    #[test]
    fn a_startup_error_is_fatal_and_ready_is_ready() {
        let protocol = WorkerProtocol;
        let ready = encode_frame(Kind::Ready, 0, 0, b"{}");
        assert!(matches!(protocol.parse_hello(&ready), Ok(Hello::Ready(_))));
        let refused = encode_frame(Kind::Error, 0, 0, br#"{"code": "STARTUP_FAILED", "message": "no torch"}"#);
        assert!(matches!(protocol.parse_hello(&refused), Ok(Hello::Fatal(text)) if text == "STARTUP_FAILED: no torch"));
        assert!(protocol.parse_hello(&encode_frame(Kind::Response, 0, 0, b"")).is_err());
    }

    #[test]
    fn only_named_variables_reach_the_worker() {
        let mut environment = Environment::new();
        for name in ["TEMP", "PRIVOKE_TLS_KEY_FILE", "OPENAI_API_KEY", "PRIVOKE_MODEL_DEVICE"] {
            environment.insert(name.into(), "x".into());
        }
        let settings = WorkerSettings::from_environment(&environment, Path::new("/repo")).unwrap();
        let names: Vec<_> = settings.envs.iter().map(|(name, _)| name.to_string_lossy().into_owned()).collect();
        assert!(names.contains(&"TEMP".to_string()) && names.contains(&"PRIVOKE_MODEL_DEVICE".to_string()));
        assert!(!names.iter().any(|name| name.contains("TLS") || name.contains("OPENAI")), "{names:?}");
        let config = settings.pool_config();
        assert!(config.sandbox.clean_env && config.sandbox.kill_with_parent);
        assert_eq!(config.sandbox.memory_limit_bytes, Some(6144 * 1024 * 1024));
        assert_eq!(config.workers, 1);
    }

    #[test]
    fn the_rust_worker_is_configured_only_when_selected_and_present() {
        let mut environment = Environment::new();
        assert!(WorkerSettings::rust_from_environment(&environment, Path::new("/repo")).unwrap().is_none());
        environment.insert("PRIVOKE_RUNTIME_ANALYSIS_ENGINE".into(), "rust".into());
        environment.insert("PRIVOKE_RUNTIME_RUST_WORKER".into(), "/definitely/not/here".into());
        assert!(WorkerSettings::rust_from_environment(&environment, Path::new("/repo")).unwrap_err().contains("does not exist"));
        let directory = std::env::temp_dir().join(format!("privoke-rust-worker-test-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let binary = directory.join("worker");
        std::fs::write(&binary, b"").unwrap();
        environment.insert("PRIVOKE_RUNTIME_RUST_WORKER".into(), binary.to_string_lossy().into_owned());
        let settings = WorkerSettings::rust_from_environment(&environment, Path::new("/repo")).unwrap().unwrap();
        std::fs::remove_dir_all(&directory).unwrap();
        assert_eq!(settings.command, binary);
        // No model cache directory exists here, so the worker is given none and serves no semantic layer.
        assert_eq!(settings.args, vec![OsString::from("--warm-layers"), OsString::from("regex,ner")]);
        assert!(!settings.serves_semantic);
        assert_eq!(settings.memory_limit_bytes, Some(6144 * 1024 * 1024));
        environment.insert("PRIVOKE_RUNTIME_ANALYSIS_ENGINE".into(), "both".into());
        assert!(WorkerSettings::rust_from_environment(&environment, Path::new("/repo")).is_err());
    }

    #[test]
    fn a_memory_limit_of_zero_means_none() {
        let mut environment = Environment::new();
        environment.insert("PRIVOKE_WORKER_MEMORY_MB".into(), "0".into());
        assert_eq!(WorkerSettings::from_environment(&environment, Path::new("/repo")).unwrap().memory_limit_bytes, None);
        environment.insert("PRIVOKE_WORKER_MEMORY_MB".into(), "x".into());
        assert!(WorkerSettings::from_environment(&environment, Path::new("/repo")).is_err());
    }
}
