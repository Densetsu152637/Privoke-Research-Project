//! The training-cycle scheduler (`fuzzer_requests.py`): the process that asks the Python fuzzer, over mutual TLS, to run
//! a head training cycle and then a full-encoder cycle, and survives restarts, lost acknowledgements and rejections.
//!
//! Each cycle is journalled ([`crate::journal`]) before its first request with fixed request ids and a fixed seed, so a
//! retry or a restart sends the same request and the fuzzer's own receipts answer it exactly once. The encoder stage
//! asks for the head stage's published version as its base. A rejection that the fuzzer states definitively
//! (`FAILED_PRECONDITION`, `INVALID_ARGUMENT`, `ALREADY_EXISTS`, or an unacceptable response) ends the stage; anything else
//! is retried up to `max_attempts` and then left pending for the next interval.
//!
//! The Python scheduler's bounded study controls (a fixed cycle count, stage observers and extra request metadata) are
//! not ported: they exist for evaluation scripts, which keep calling the Python implementation.

use std::collections::BTreeMap;
use std::future::Future;
use std::path::PathBuf;
use std::time::Duration;

use privoke_contracts::proto::v1::fuzzer_service_client::FuzzerServiceClient;
use privoke_contracts::proto::v1::{FuzzerTrainingRequest, FuzzerTrainingResponse};
use privoke_transport::ClientTlsConfig;
use privoke_transport::client::connect;
use prost::Message;
use tonic::Code;

use crate::error::{Error, Result};
use crate::journal::{Cycle, Journal, Stage, StageRecord};
use crate::pyfmt::py_int;
use crate::util::{hex, log, unix_seconds_f64};
use crate::validate::validate_text;

/// What the scheduler is configured with (`FuzzerRequestConfig` in Python).
#[derive(Debug, Clone, PartialEq)]
pub struct FuzzerRequestConfig {
    /// The fuzzer's `host:port` (`FUZZER_TARGET`).
    pub target: String,
    /// Prompts per request; zero disables the scheduler (`FUZZER_PROMPT_COUNT`).
    pub prompt_count: i64,
    /// The model (`MODEL_ID`).
    pub model_id: String,
    /// This service's source id in the fuzzer requests (`PARAM_UPDATE_SOURCE_ID`).
    pub source_id: String,
    /// Deadline of one request in seconds (`FUZZER_REQUEST_TIMEOUT_SECONDS`).
    pub timeout_seconds: f64,
    /// Seconds between cycles; zero or less runs one cycle (`FUZZER_REQUEST_INTERVAL_SECONDS`).
    pub interval_seconds: f64,
    /// Seconds before the first cycle (`FUZZER_REQUEST_INITIAL_DELAY_SECONDS`).
    pub initial_delay_seconds: f64,
    /// Seconds between attempts (`FUZZER_REQUEST_RETRY_SECONDS`).
    pub retry_seconds: f64,
    /// Attempts per stage (`FUZZER_REQUEST_MAX_ATTEMPTS`).
    pub max_attempts: i64,
    /// The base seed (`FUZZER_REQUEST_SEED`).
    pub seed: i64,
    /// `deterministic_v1` or `seeded_family_v1` (`FUZZER_CURRICULUM_SAMPLER_POLICY`).
    pub curriculum_sampler_policy: String,
    /// The sampler seed (`FUZZER_CURRICULUM_SAMPLER_SEED`).
    pub curriculum_sampler_seed: i64,
    /// Whether the full-encoder stage runs after the head stage (`FUZZER_TRAIN_UNDERLYING`).
    pub train_underlying: bool,
    /// The journal (`FUZZER_CYCLE_STATE_PATH`).
    pub state_path: PathBuf,
}

impl FuzzerRequestConfig {
    /// A configuration with the Python defaults for everything but the model and source ids.
    pub fn defaults() -> Self {
        Self {
            target: "privoke-fuzzer:50053".to_string(),
            prompt_count: 32,
            model_id: "privoke-baseline".to_string(),
            source_id: "param-update-service".to_string(),
            timeout_seconds: 30.0,
            interval_seconds: 3600.0,
            initial_delay_seconds: 2.0,
            retry_seconds: 2.0,
            max_attempts: 3,
            seed: 1337,
            curriculum_sampler_policy: "deterministic_v1".to_string(),
            curriculum_sampler_seed: 0,
            train_underlying: true,
            state_path: PathBuf::from("/data/training-cycles.sqlite3"),
        }
    }

    /// Read variables through `get`.
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Self> {
        let defaults = Self::defaults();
        let text = |key: &str, fallback: &str| {
            get(key).filter(|value| !value.is_empty()).map_or_else(|| fallback.to_string(), |value| value.trim().to_string())
        };
        let integer = |key: &str, fallback: i64| -> Result<i64> {
            match get(key).filter(|value| !value.is_empty()) {
                None => Ok(fallback),
                Some(value) => {
                    py_int(&value).and_then(|number| i64::try_from(number).ok()).ok_or_else(|| Error(format!("{key} must be an integer.")))
                }
            }
        };
        let number = |key: &str, fallback: f64| -> Result<f64> {
            match get(key).filter(|value| !value.is_empty()) {
                None => Ok(fallback),
                Some(value) => value.trim().parse::<f64>().map_err(|_| Error(format!("{key} must be a number."))),
            }
        };
        let underlying = match text("FUZZER_TRAIN_UNDERLYING", "true").to_ascii_lowercase().as_str() {
            "true" => true,
            "false" => false,
            _ => return Err(Error("FUZZER_TRAIN_UNDERLYING must be true or false.".to_string())),
        };
        let config = Self {
            target: text("FUZZER_TARGET", &defaults.target),
            prompt_count: integer("FUZZER_PROMPT_COUNT", defaults.prompt_count)?,
            model_id: text("MODEL_ID", &defaults.model_id),
            source_id: text("PARAM_UPDATE_SOURCE_ID", &defaults.source_id),
            timeout_seconds: number("FUZZER_REQUEST_TIMEOUT_SECONDS", defaults.timeout_seconds)?,
            interval_seconds: number("FUZZER_REQUEST_INTERVAL_SECONDS", defaults.interval_seconds)?,
            initial_delay_seconds: number("FUZZER_REQUEST_INITIAL_DELAY_SECONDS", defaults.initial_delay_seconds)?,
            retry_seconds: number("FUZZER_REQUEST_RETRY_SECONDS", defaults.retry_seconds)?,
            max_attempts: integer("FUZZER_REQUEST_MAX_ATTEMPTS", defaults.max_attempts)?,
            seed: integer("FUZZER_REQUEST_SEED", defaults.seed)?,
            curriculum_sampler_policy: text("FUZZER_CURRICULUM_SAMPLER_POLICY", &defaults.curriculum_sampler_policy),
            curriculum_sampler_seed: integer("FUZZER_CURRICULUM_SAMPLER_SEED", defaults.curriculum_sampler_seed)?,
            train_underlying: underlying,
            state_path: PathBuf::from(text("FUZZER_CYCLE_STATE_PATH", &defaults.state_path.to_string_lossy())),
        };
        config.validate()?;
        Ok(config)
    }

    /// Read the process environment.
    pub fn from_env() -> Result<Self> {
        Self::from_lookup(|key| std::env::var(key).ok())
    }

    /// The Python `validate`.
    pub fn validate(&self) -> Result<()> {
        if self.state_path.as_os_str().is_empty() {
            return Err(Error("Automatic training requires a boolean stage selection and durable state path.".to_string()));
        }
        let text =
            |value: &str, field: &str, limit: usize| validate_text(value, field, true, limit).map_err(|failure| Error(failure.to_string()));
        text(&self.target, "FUZZER_TARGET", 256)?;
        text(&self.model_id, "MODEL_ID", 128)?;
        text(&self.source_id, "PARAM_UPDATE_SOURCE_ID", 128)?;
        if !(0..=i64::from(u32::MAX)).contains(&self.prompt_count) {
            return Err(Error("FUZZER_PROMPT_COUNT must not be negative.".to_string()));
        }
        if self.max_attempts <= 0 {
            return Err(Error("FUZZER_REQUEST_MAX_ATTEMPTS must be positive.".to_string()));
        }
        if !(0..=i64::from(u32::MAX)).contains(&self.seed) {
            return Err(Error("FUZZER_REQUEST_SEED must fit an unsigned 32-bit integer.".to_string()));
        }
        if self.curriculum_sampler_policy != "deterministic_v1" && self.curriculum_sampler_policy != "seeded_family_v1" {
            return Err(Error("Unknown FUZZER_CURRICULUM_SAMPLER_POLICY.".to_string()));
        }
        if !(0..=i64::from(u32::MAX)).contains(&self.curriculum_sampler_seed) {
            return Err(Error("FUZZER_CURRICULUM_SAMPLER_SEED must fit an unsigned 32-bit integer.".to_string()));
        }
        if self.curriculum_sampler_policy == "deterministic_v1" && self.curriculum_sampler_seed != 0 {
            return Err(Error("deterministic_v1 requires FUZZER_CURRICULUM_SAMPLER_SEED=0.".to_string()));
        }
        for (name, value, allow_zero) in [
            ("FUZZER_REQUEST_TIMEOUT_SECONDS", self.timeout_seconds, false),
            ("FUZZER_REQUEST_INTERVAL_SECONDS", self.interval_seconds, true),
            ("FUZZER_REQUEST_INITIAL_DELAY_SECONDS", self.initial_delay_seconds, true),
            ("FUZZER_REQUEST_RETRY_SECONDS", self.retry_seconds, true),
        ] {
            if !value.is_finite() || value < 0.0 || (!allow_zero && value == 0.0) {
                let requirement = if allow_zero { "non-negative" } else { "positive" };
                return Err(Error(format!("{name} must be finite and {requirement}.")));
            }
        }
        Ok(())
    }

    /// The host part of the target, for the server name the fuzzer's certificate must carry.
    pub fn target_host(&self) -> &str {
        match self.target.rsplit_once(':') {
            Some((host, _)) => host.trim_start_matches('[').trim_end_matches(']'),
            None => &self.target,
        }
    }
}

/// `build_training_request`.
pub fn build_training_request(
    config: &FuzzerRequestConfig,
    request_id: &str,
    expected_base_version: Option<&str>,
) -> FuzzerTrainingRequest {
    let mut metadata: BTreeMap<String, String> = BTreeMap::new();
    metadata.insert("initiator".to_string(), "param-update-service".to_string());
    if config.train_underlying {
        metadata.insert("require_full_capability".to_string(), "true".to_string());
    }
    if let Some(base) = expected_base_version.filter(|base| !base.is_empty()) {
        metadata.insert("expected_base_version".to_string(), base.to_string());
    }
    if config.curriculum_sampler_policy != "deterministic_v1" {
        metadata.insert("curriculum_sampler_policy".to_string(), config.curriculum_sampler_policy.clone());
        metadata.insert("curriculum_sampler_seed".to_string(), config.curriculum_sampler_seed.to_string());
    }
    FuzzerTrainingRequest {
        request_id: request_id.to_string(),
        source_id: config.source_id.clone(),
        model_id: config.model_id.clone(),
        prompt_count: u32::try_from(config.prompt_count).unwrap_or_default(),
        seed: u32::try_from(config.seed).unwrap_or_default(),
        metadata,
    }
}

/// Why a request to the fuzzer failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallError {
    /// The gRPC status code when the fuzzer answered; `None` for a failure to connect.
    pub code: Option<Code>,
    /// The text.
    pub message: String,
}

impl CallError {
    /// A definite protocol rejection by the fuzzer, as opposed to an uncertain transport outcome.
    pub fn terminal(&self) -> bool {
        matches!(self.code, Some(Code::FailedPrecondition | Code::InvalidArgument | Code::AlreadyExists))
    }
}

impl std::fmt::Display for CallError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.code {
            Some(code) => write!(formatter, "{code:?}: {}", self.message),
            None => formatter.write_str(&self.message),
        }
    }
}

/// The fuzzer, as the scheduler sees it.
pub trait FuzzerCaller {
    /// Send one training request for `stage` and wait at most `timeout`.
    fn call(
        &self,
        stage: Stage,
        request: FuzzerTrainingRequest,
        timeout: Duration,
    ) -> impl Future<Output = std::result::Result<FuzzerTrainingResponse, CallError>> + Send;
}

/// The mutual-TLS client of the Python fuzzer.
#[derive(Debug, Clone)]
pub struct GrpcFuzzer {
    target: String,
    tls: ClientTlsConfig,
}

impl GrpcFuzzer {
    /// A client for `target` that presents the service identity in `tls` and trusts only its server CA.
    pub fn new(target: impl Into<String>, tls: ClientTlsConfig) -> Self {
        Self { target: target.into(), tls }
    }
}

impl FuzzerCaller for GrpcFuzzer {
    async fn call(
        &self,
        stage: Stage,
        request: FuzzerTrainingRequest,
        timeout: Duration,
    ) -> std::result::Result<FuzzerTrainingResponse, CallError> {
        let exchange = async {
            let channel = connect(&self.target, &self.tls).await.map_err(|error| CallError { code: None, message: error.to_string() })?;
            let mut client = FuzzerServiceClient::new(channel);
            let mut wrapped = tonic::Request::new(request);
            wrapped.set_timeout(timeout);
            let outcome = match stage {
                Stage::Heads => client.run_training_cycle(wrapped).await,
                Stage::FullEncoder => client.run_underlying_training_cycle(wrapped).await,
            };
            outcome
                .map(tonic::Response::into_inner)
                .map_err(|status| CallError { code: Some(status.code()), message: status.message().to_string() })
        };
        match tokio::time::timeout(timeout, exchange).await {
            Ok(result) => result,
            Err(_) => Err(CallError { code: Some(Code::DeadlineExceeded), message: "request to the fuzzer timed out".to_string() }),
        }
    }
}

/// The scheduler's mutual-TLS client identity: this service's own certificate (`PRIVOKE_TLS_CERT_FILE` and
/// `PRIVOKE_TLS_KEY_FILE`, issued as a registered service) and the CA that signed the fuzzer's server certificate
/// (`PRIVOKE_TLS_CA_FILE`). The fuzzer's certificate must carry the target's host name, or `FUZZER_TLS_SERVER_NAME`. A
/// missing or empty file is an error, so a deployment without credentials fails at startup instead of sending plaintext.
pub fn client_tls_from_lookup(config: &FuzzerRequestConfig, get: impl Fn(&str) -> Option<String>) -> Result<ClientTlsConfig> {
    let file = |variable: &str| -> Result<PathBuf> {
        let path = get(variable)
            .filter(|value| !value.trim().is_empty())
            .map(PathBuf::from)
            .ok_or_else(|| Error(format!("{variable} is required for the scheduler.")))?;
        match std::fs::metadata(&path) {
            Ok(metadata) if metadata.is_file() && metadata.len() > 0 => Ok(path),
            _ => Err(Error(format!("{variable} {} is not a non-empty file.", path.display()))),
        }
    };
    let server_name =
        get("FUZZER_TLS_SERVER_NAME").filter(|value| !value.trim().is_empty()).unwrap_or_else(|| config.target_host().to_string());
    Ok(ClientTlsConfig {
        server_ca: file("PRIVOKE_TLS_CA_FILE")?,
        identity: Some((file("PRIVOKE_TLS_CERT_FILE")?, file("PRIVOKE_TLS_KEY_FILE")?)),
        server_name,
    })
}

fn pause(seconds: f64) -> tokio::time::Sleep {
    tokio::time::sleep(Duration::try_from_secs_f64(seconds.max(0.0)).unwrap_or(Duration::ZERO))
}

/// The training-cycle loop. Returns when `prompt_count` is zero, when a one-shot (`interval_seconds <= 0`) cycle has
/// ended or a completed one-shot cycle with these settings already exists, and with an error when the journal fails or
/// a pending cycle belongs to different settings. Otherwise it runs until its task is aborted.
pub async fn run<C: FuzzerCaller>(config: &FuzzerRequestConfig, caller: &C) -> Result<()> {
    if config.prompt_count <= 0 {
        return Ok(());
    }
    if config.initial_delay_seconds > 0.0 {
        pause(config.initial_delay_seconds).await;
    }
    let mut journal = Journal::open(&config.state_path)?;
    loop {
        let Some(mut cycle) = journal.reserve(config, unix_seconds_f64())? else { return Ok(()) };
        if cycle.state != "pending" {
            let remaining = cycle.finished_at.unwrap_or(0.0) + config.interval_seconds - unix_seconds_f64();
            if remaining > 0.0 {
                pause(remaining).await;
            }
            continue;
        }
        for stage in Stage::sequence(config.train_underlying) {
            if !run_stage(config, caller, &mut journal, &mut cycle, stage).await? {
                break;
            }
        }
        if cycle.all_accepted() {
            cycle.state = "complete".to_string();
            cycle.finished_at = Some(unix_seconds_f64());
            journal.save(&cycle)?;
        }
        if config.interval_seconds <= 0.0 {
            return Ok(());
        }
        // Transient exhaustion remains pending and resumes with identical stage ids; a terminal safety rejection
        // starts a fresh independent cycle.
        pause(config.interval_seconds).await;
    }
}

/// Run one stage of `cycle`. `Ok(true)` when it is accepted (now or before), `Ok(false)` when the cycle must stop here.
async fn run_stage<C: FuzzerCaller>(
    config: &FuzzerRequestConfig,
    caller: &C,
    journal: &mut Journal,
    cycle: &mut Cycle,
    stage: Stage,
) -> Result<bool> {
    let mut state = cycle.stage(stage).cloned().ok_or_else(|| Error(format!("cycle {} has no {} stage", cycle.cycle_id, stage.name())))?;
    if state.state == "accepted" {
        return Ok(true);
    }
    let expected_base =
        if stage == Stage::FullEncoder { cycle.stage(Stage::Heads).and_then(|heads| heads.applied_version.clone()) } else { None };
    let mut stage_config = config.clone();
    stage_config.seed = cycle.seed;
    let request = build_training_request(&stage_config, &state.request_id, expected_base.as_deref());
    let serialized = hex(&request.encode_to_vec());
    if let Some(existing) = &state.request_protobuf_hex
        && *existing != serialized
    {
        return Err(Error("Pending automatic request bytes changed".to_string()));
    }
    state.request_protobuf_hex = Some(serialized);
    cycle.set_stage(stage, state.clone());
    journal.save(cycle)?;
    let timeout = Duration::try_from_secs_f64(config.timeout_seconds).unwrap_or(Duration::from_secs(30));
    for attempt in 0..config.max_attempts {
        state.physical_attempts += 1;
        cycle.set_stage(stage, state.clone());
        journal.save(cycle)?;
        match caller.call(stage, request.clone(), timeout).await {
            Ok(response) => match accept(config, &response, expected_base.as_deref()) {
                Ok(()) => {
                    state.state = "accepted".to_string();
                    state.base_version = Some(response.base_version.clone());
                    state.applied_version = Some(response.applied_version.clone());
                    state.response_protobuf_hex = Some(hex(&response.encode_to_vec()));
                    cycle.set_stage(stage, state.clone());
                    journal.save(cycle)?;
                    return Ok(true);
                }
                Err(message) => {
                    reject(cycle, journal, stage, &mut state, &message)?;
                    return Ok(false);
                }
            },
            Err(error) => {
                let text = error.to_string();
                if error.terminal() {
                    reject(cycle, journal, stage, &mut state, &text)?;
                    return Ok(false);
                }
                state.last_error = Some(text.clone());
                state.attempt_errors.push(text.clone());
                cycle.set_stage(stage, state.clone());
                journal.save(cycle)?;
                log(format_args!("automatic training cycle={} stage={} state={}: {text}", cycle.cycle_id, stage.name(), cycle.state));
                if attempt + 1 == config.max_attempts {
                    return Ok(false);
                }
                pause(config.retry_seconds).await;
            }
        }
    }
    Ok(false)
}

/// The response checks of the Python loop; the text of a failure is the `StageRejected` message.
fn accept(config: &FuzzerRequestConfig, response: &FuzzerTrainingResponse, expected_base: Option<&str>) -> std::result::Result<(), String> {
    if !response.accepted || response.model_id != config.model_id || response.applied_version.is_empty() {
        return Err("Fuzzer rejected the training stage or returned a mismatched publication.".to_string());
    }
    if let Some(base) = expected_base.filter(|base| !base.is_empty())
        && response.base_version != base
    {
        return Err("Underlying stage did not use the acknowledged head publication base.".to_string());
    }
    Ok(())
}

fn reject(cycle: &mut Cycle, journal: &mut Journal, stage: Stage, state: &mut StageRecord, message: &str) -> Result<()> {
    state.last_error = Some(message.to_string());
    state.attempt_errors.push(message.to_string());
    state.state = "rejected".to_string();
    cycle.set_stage(stage, state.clone());
    cycle.state = if cycle.stages.iter().any(|(_, record)| record.state == "accepted") { "partial" } else { "rejected" }.to_string();
    cycle.finished_at = Some(unix_seconds_f64());
    journal.save(cycle)?;
    log(format_args!("automatic training cycle={} stage={} state={}: {message}", cycle.cycle_id, stage.name(), cycle.state));
    Ok(())
}
