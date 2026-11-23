//! The routine-training scheduler (stage V3-R6 of the routine-training plan): the process that asks the V3 fuzzer, over mutual TLS,
//! for one HEADS fit and then one FULL_ENCODER fit of each of the three V3 tiers, round after round, and survives restarts, lost
//! fits and refusals. It replaces the V1 scheduler (`fuzzer_requests.py`); no V1 `FuzzerService` call remains.
//!
//! The scheduler is the **single allocator** of `(request_id, seed, expected_base, sampler, scope, source_commitment)`
//! ([`crate::journal`]):
//!
//! * `expected_base` is what the store authority serves for the model when the request is allocated;
//! * the `source_commitment` is the *routine commitment* of the sampler, the seed and the frozen policy
//!   ([`Commitments`]). The scheduler computes it from its own copy of the pinned sources and the policy, not from anything the
//!   fuzzer says, because the commit happens **inside** the fuzzer's call, before any response exists, and the guard gate
//!   ([`crate::v3_guard::GuardGate`]) must already find the allocation then. The fuzzer's own `routine_commitment` in its response
//!   is compared with it afterwards;
//! * the allocation is journalled durably before the fuzzer is called.
//!
//! Restart rule (G3): for an allocation still in flight the scheduler asks the store (`GetCommitStatus`) what became of the request
//! before it asks the fuzzer again. A recorded receipt settles the allocation. Otherwise the same identity is re-sent (the fuzzer
//! resumes a fit whose commit request it holds and answers `FAILED_PRECONDITION` when the fit was lost); a lost fit is replaced
//! by a new allocation with a new request id and seed.

use std::collections::BTreeMap;
use std::future::Future;
use std::path::PathBuf;
use std::time::Duration;

use privoke_contracts::digest::sha256_hex;
use privoke_contracts::proto::experimental_v3::v3_fuzzer_service_client::V3FuzzerServiceClient;
use privoke_contracts::proto::v1::{FuzzerTrainingRequest, FuzzerTrainingResponse};
use privoke_curriculum::v3::{
    AU3_SAMPLER, AU3_SOURCE_FILES, BC01_SAMPLER, BC01_SOURCE_FILES, INPUTS, python_source_hashes, routine_commitment,
};
use privoke_curriculum::value;
use privoke_transport::ClientTlsConfig;
use privoke_transport::client::connect;
use tonic::Code;

use crate::error::{Error, Result};
use crate::journal::{AllocationRow, Cycle, Journal, Stage, TIERS, model_of};
use crate::pyfmt::py_int;
use crate::util::{log, unix_seconds_f64};
use crate::v3_store::{CheckpointStore, PinnedSources};
use crate::validate::validate_text;

/// What the scheduler is configured with.
#[derive(Debug, Clone, PartialEq)]
pub struct FuzzerRequestConfig {
    /// The V3 fuzzer's `host:port` (`FUZZER_TARGET`).
    pub target: String,
    /// Prompts per request; zero disables the scheduler (`FUZZER_PROMPT_COUNT`).
    pub prompt_count: i64,
    /// This service's source id in the fuzzer requests (`PARAM_UPDATE_SOURCE_ID`).
    pub source_id: String,
    /// Deadline of one request in seconds (`FUZZER_REQUEST_TIMEOUT_SECONDS`): a quality-tier FULL fit takes up to 25 minutes.
    pub timeout_seconds: f64,
    /// Seconds between rounds; zero or less runs one round (`FUZZER_REQUEST_INTERVAL_SECONDS`).
    pub interval_seconds: f64,
    /// Seconds before the first round (`FUZZER_REQUEST_INITIAL_DELAY_SECONDS`).
    pub initial_delay_seconds: f64,
    /// Seconds between attempts (`FUZZER_REQUEST_RETRY_SECONDS`).
    pub retry_seconds: f64,
    /// Attempts per stage per round (`FUZZER_REQUEST_MAX_ATTEMPTS`).
    pub max_attempts: i64,
    /// The base seed of the rounds (`FUZZER_REQUEST_SEED`).
    pub seed: i64,
    /// The journal (`FUZZER_CYCLE_STATE_PATH`).
    pub state_path: PathBuf,
    /// The frozen policy file of the fuzzer (`V3_POLICY_FILE`), whose digest the fuzzer requires in every routine request.
    pub policy_file: PathBuf,
}

impl FuzzerRequestConfig {
    /// A configuration with the defaults.
    pub fn defaults() -> Self {
        Self {
            target: "v3-fuzzer:50053".to_string(),
            prompt_count: 32,
            source_id: "param-update-service".to_string(),
            timeout_seconds: 3600.0,
            interval_seconds: 10_800.0,
            initial_delay_seconds: 2.0,
            retry_seconds: 30.0,
            max_attempts: 3,
            seed: 1337,
            state_path: PathBuf::from("/data/training-cycles.sqlite3"),
            policy_file: PathBuf::from("/config/v3-policy.json"),
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
        let config = Self {
            target: text("FUZZER_TARGET", &defaults.target),
            prompt_count: integer("FUZZER_PROMPT_COUNT", defaults.prompt_count)?,
            source_id: text("PARAM_UPDATE_SOURCE_ID", &defaults.source_id),
            timeout_seconds: number("FUZZER_REQUEST_TIMEOUT_SECONDS", defaults.timeout_seconds)?,
            interval_seconds: number("FUZZER_REQUEST_INTERVAL_SECONDS", defaults.interval_seconds)?,
            initial_delay_seconds: number("FUZZER_REQUEST_INITIAL_DELAY_SECONDS", defaults.initial_delay_seconds)?,
            retry_seconds: number("FUZZER_REQUEST_RETRY_SECONDS", defaults.retry_seconds)?,
            max_attempts: integer("FUZZER_REQUEST_MAX_ATTEMPTS", defaults.max_attempts)?,
            seed: integer("FUZZER_REQUEST_SEED", defaults.seed)?,
            state_path: PathBuf::from(text("FUZZER_CYCLE_STATE_PATH", &defaults.state_path.to_string_lossy())),
            policy_file: PathBuf::from(text("V3_POLICY_FILE", &defaults.policy_file.to_string_lossy())),
        };
        config.validate()?;
        Ok(config)
    }

    /// Read the process environment.
    pub fn from_env() -> Result<Self> {
        Self::from_lookup(|key| std::env::var(key).ok())
    }

    /// Bounds of the settings.
    pub fn validate(&self) -> Result<()> {
        if self.state_path.as_os_str().is_empty() {
            return Err(Error("Automatic training requires a durable state path.".to_string()));
        }
        let text =
            |value: &str, field: &str, limit: usize| validate_text(value, field, true, limit).map_err(|failure| Error(failure.to_string()));
        text(&self.target, "FUZZER_TARGET", 256)?;
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

/// What the store recorded of a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitStatus {
    /// `applied` or `rejected`.
    pub status: String,
    /// The candidate of the request.
    pub candidate: String,
    /// The refusal's reason (empty for an applied request).
    pub reason: String,
}

/// The store authority, as the scheduler reads it (in process: the scheduler runs beside the checkpoint store).
pub trait StoreView: Send + Sync {
    /// The manifest the model serves now.
    fn resolve(&self, model_id: &str) -> Result<String>;
    /// The recorded outcome of a request, or `None` when the store has no receipt for it.
    fn commit_status(&self, request_id: &str) -> Result<Option<CommitStatus>>;
}

impl StoreView for CheckpointStore {
    fn resolve(&self, model_id: &str) -> Result<String> {
        CheckpointStore::resolve(self, model_id).map_err(|error| Error(format!("store authority: {error}")))
    }

    fn commit_status(&self, request_id: &str) -> Result<Option<CommitStatus>> {
        let receipt = self.status(request_id).map_err(|error| Error(format!("store authority: {error}")))?;
        Ok(matches!(receipt.status.as_str(), "applied" | "rejected").then(|| CommitStatus {
            status: receipt.status,
            candidate: receipt.candidate,
            reason: receipt.reason,
        }))
    }
}

/// The routine commitment of a sampler and a seed, and the digest of the frozen policy every request must name.
pub trait Commitments: Send + Sync {
    /// `policy_sha256` of the requests.
    fn policy_sha256(&self) -> String;
    /// The routine commitment of `sampler` at `seed`.
    fn commitment(&self, sampler: &str, seed: u32) -> Result<String>;
}

/// The commitments over the pinned sources of this process: the BC01 inputs and the audience release the store validates
/// against, the digests of the Python files the schedules pin (under the same checkout the fuzzer reads), and the policy file.
#[derive(Debug, Clone)]
pub struct PinnedCommitments {
    policy_sha256: String,
    parts: BTreeMap<String, (serde_json::Value, serde_json::Value)>,
}

fn json_of(document: &value::Value) -> Result<serde_json::Value> {
    let bytes = value::canonical_bytes(document).map_err(|error| Error(error.to_string()))?;
    serde_json::from_slice(&bytes).map_err(|error| Error(error.to_string()))
}

impl PinnedCommitments {
    /// Pin the commitments: `policy` is the bytes of the frozen policy file, `source_root` the checkout the fuzzer hashes.
    pub fn new(sources: &PinnedSources, source_root: &std::path::Path, policy: &[u8]) -> Result<Self> {
        let failure = |error: &dyn std::fmt::Display| Error(format!("routine commitments: {error}"));
        let release = sources.audience_release().map_err(|error| failure(&error))?;
        let bc01_inputs = value::object(INPUTS.iter().map(|(key, _, sha)| (*key, value::string(sha))).collect());
        let au3_inputs = value::object(vec![("audience_manifest", value::string(&release.sha256))]);
        let bc01_hashes = python_source_hashes(source_root, &BC01_SOURCE_FILES).map_err(|error| failure(&error))?;
        let au3_hashes = python_source_hashes(source_root, &AU3_SOURCE_FILES).map_err(|error| failure(&error))?;
        let mut parts = BTreeMap::new();
        parts.insert(BC01_SAMPLER.to_string(), (json_of(&bc01_inputs)?, json_of(&bc01_hashes)?));
        parts.insert(AU3_SAMPLER.to_string(), (json_of(&au3_inputs)?, json_of(&au3_hashes)?));
        Ok(Self { policy_sha256: sha256_hex(policy), parts })
    }
}

impl Commitments for PinnedCommitments {
    fn policy_sha256(&self) -> String {
        self.policy_sha256.clone()
    }

    fn commitment(&self, sampler: &str, seed: u32) -> Result<String> {
        let (inputs, hashes) = self.parts.get(sampler).ok_or_else(|| Error(format!("No frozen release is named {sampler}.")))?;
        let parse = |document: &serde_json::Value| {
            privoke_curriculum::value::parse_bytes(document.to_string().as_bytes()).map_err(|error| Error(error.to_string()))
        };
        routine_commitment(sampler, &parse(inputs)?, &parse(hashes)?, &self.policy_sha256, u64::from(seed))
            .map_err(|error| Error(format!("routine commitment: {error}")))
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
    /// The fuzzer states that it does not know the outcome of this identity (its fit was lost).
    pub fn outcome_unknown(&self) -> bool {
        self.code == Some(Code::FailedPrecondition)
    }

    /// A definite protocol rejection other than a lost fit.
    pub fn refused(&self) -> bool {
        matches!(self.code, Some(Code::InvalidArgument | Code::AlreadyExists))
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
    /// Send one routine request for `stage` and wait at most `timeout`.
    fn call(
        &self,
        stage: Stage,
        request: FuzzerTrainingRequest,
        timeout: Duration,
    ) -> impl Future<Output = std::result::Result<FuzzerTrainingResponse, CallError>> + Send;
}

/// The mutual-TLS client of the V3 fuzzer.
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
            let mut client = V3FuzzerServiceClient::new(channel);
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

/// The seed of one allocation: derived from the round's seed, the model, the stage and the attempt, so that a replacement of a lost
/// fit never reuses a seed.
pub fn allocation_seed(cycle_seed: u32, model_id: &str, stage: Stage, attempt: i64) -> u32 {
    let digest = sha256_hex(format!("{cycle_seed}|{model_id}|{}|{attempt}", stage.name()).as_bytes());
    u32::from_str_radix(&digest[..8], 16).unwrap_or(1).max(1)
}

/// The request of an allocation: everything the fuzzer needs and nothing it chooses.
pub fn build_request(config: &FuzzerRequestConfig, row: &AllocationRow, policy_sha256: &str) -> FuzzerTrainingRequest {
    let metadata: BTreeMap<String, String> =
        [("expected_base", row.expected_base.clone()), ("policy_sha256", policy_sha256.to_string()), ("sampler", row.sampler.clone())]
            .into_iter()
            .map(|(key, value)| (key.to_string(), value))
            .collect();
    FuzzerTrainingRequest {
        request_id: row.request_id.clone(),
        source_id: config.source_id.clone(),
        model_id: row.model_id.clone(),
        prompt_count: u32::try_from(config.prompt_count).unwrap_or_default(),
        seed: row.seed,
        metadata,
    }
}

/// The routine-training loop. Returns when `prompt_count` is zero, when a one-shot (`interval_seconds <= 0`) round has ended, and
/// with an error when the journal or the store authority fails. Otherwise it runs until its task is aborted.
pub async fn run<C: FuzzerCaller, S: StoreView>(
    config: &FuzzerRequestConfig,
    caller: &C,
    store: &S,
    commitments: &dyn Commitments,
) -> Result<()> {
    if config.prompt_count <= 0 {
        return Ok(());
    }
    if config.initial_delay_seconds > 0.0 {
        pause(config.initial_delay_seconds).await;
    }
    let mut journal = Journal::open(&config.state_path)?;
    let samplers = [BC01_SAMPLER, AU3_SAMPLER];
    let base_seed = u32::try_from(config.seed).unwrap_or(1337);
    loop {
        let Some(cycle) = journal.reserve(base_seed, &samplers, config.interval_seconds, unix_seconds_f64())? else { return Ok(()) };
        if cycle.state != "pending" {
            let remaining = cycle.finished_at.unwrap_or(0.0) + config.interval_seconds - unix_seconds_f64();
            if remaining > 0.0 {
                pause(remaining).await;
            }
            continue;
        }
        let mut settled = true;
        for tier in TIERS {
            for stage in [Stage::Heads, Stage::FullEncoder] {
                settled &= run_stage(config, caller, store, commitments, &mut journal, &cycle, &model_of(tier), stage).await?;
            }
        }
        if settled {
            journal.finish(&cycle, unix_seconds_f64())?;
            log(format_args!("routine training round={} sampler={} complete", cycle.sequence, cycle.sampler));
        }
        if config.interval_seconds <= 0.0 {
            return Ok(());
        }
        // A stage left in flight resumes with its identity in the next pass.
        pause(config.interval_seconds).await;
    }
}

/// Settle `row` from a receipt the store holds.
fn settle_from(journal: &mut Journal, row: &AllocationRow, status: &CommitStatus) -> Result<()> {
    let state = if status.status == "applied" { "accepted" } else { "rejected" };
    journal.settle(&row.request_id, state, Some(&status.candidate), (!status.reason.is_empty()).then_some(status.reason.as_str()))
}

/// One tier and stage of a round. `Ok(true)` when it is settled (accepted or refused, now or before), `Ok(false)` when it stays in
/// flight for the next pass.
#[allow(clippy::too_many_arguments)]
async fn run_stage<C: FuzzerCaller, S: StoreView>(
    config: &FuzzerRequestConfig,
    caller: &C,
    store: &S,
    commitments: &dyn Commitments,
    journal: &mut Journal,
    cycle: &Cycle,
    model_id: &str,
    stage: Stage,
) -> Result<bool> {
    let policy = commitments.policy_sha256();
    let timeout = Duration::try_from_secs_f64(config.timeout_seconds).unwrap_or(Duration::from_secs(3600));
    let history = journal.allocations(cycle.sequence)?;
    let mut latest = history.iter().rev().find(|row| row.model_id == model_id && row.stage == stage).cloned();
    if let Some(row) = &latest
        && matches!(row.state.as_str(), "accepted" | "rejected")
    {
        return Ok(true);
    }
    let mut resumed = latest.is_some();
    for attempt in 0..config.max_attempts {
        // Allocate (or resume the allocation in flight).
        let row = match latest.take().filter(|row| row.state == "allocated") {
            Some(row) => row,
            None => {
                let next = journal
                    .allocations(cycle.sequence)?
                    .iter()
                    .filter(|row| row.model_id == model_id && row.stage == stage)
                    .map(|row| row.attempt + 1)
                    .max()
                    .unwrap_or(0);
                let seed = allocation_seed(cycle.seed, model_id, stage, next);
                let row = AllocationRow {
                    request_id: format!(
                        "v3r-c{}-{}-{}-a{next}-{}",
                        cycle.sequence,
                        model_id.trim_start_matches("privoke-v3-"),
                        stage.name(),
                        &uuid::Uuid::new_v4().simple().to_string()[..8]
                    ),
                    cycle: cycle.sequence,
                    model_id: model_id.to_string(),
                    stage,
                    attempt: next,
                    sampler: cycle.sampler.clone(),
                    seed,
                    expected_base: store.resolve(model_id)?,
                    source_commitment: commitments.commitment(&cycle.sampler, seed)?,
                    state: "allocated".to_string(),
                    candidate: None,
                    reason: None,
                };
                journal.allocate(&row)?;
                resumed = false;
                row
            }
        };
        // What became of an earlier send of this identity is the store's to say before anyone is asked again.
        if (resumed || attempt > 0)
            && let Some(status) = store.commit_status(&row.request_id)?
        {
            settle_from(journal, &row, &status)?;
            return Ok(true);
        }
        resumed = false;
        let request = build_request(config, &row, &policy);
        match caller.call(stage, request, timeout).await {
            Ok(response) => {
                if response.accepted && !response.applied_version.is_empty() && response.base_version == row.expected_base {
                    if response.metadata.get("routine_commitment") != Some(&row.source_commitment) {
                        log(format_args!(
                            "routine training request={:?}: the fuzzer's routine commitment differs from the allocation (the store applied the candidate)",
                            row.request_id
                        ));
                    }
                    journal.settle(&row.request_id, "accepted", Some(&response.applied_version), None)?;
                } else {
                    let reason = if response.accepted { "mismatched response".to_string() } else { response.message.clone() };
                    journal.settle(&row.request_id, "rejected", None, Some(&reason))?;
                }
                return Ok(true);
            }
            Err(error) if error.outcome_unknown() => {
                // The fuzzer lost this fit. The store may still hold a receipt (a commit whose answer was lost).
                match store.commit_status(&row.request_id)? {
                    Some(status) => {
                        settle_from(journal, &row, &status)?;
                        return Ok(true);
                    }
                    None => {
                        journal.settle(&row.request_id, "lost", None, Some(&error.to_string()))?;
                        log(format_args!("routine training request={:?} lost ({error}); allocating a new request", row.request_id));
                    }
                }
            }
            Err(error) if error.refused() => {
                journal.settle(&row.request_id, "rejected", None, Some(&error.to_string()))?;
                return Ok(true);
            }
            Err(error) => {
                log(format_args!("routine training request={:?} stage={}: {error}", row.request_id, stage.name()));
                latest = Some(row);
                if attempt + 1 < config.max_attempts {
                    pause(config.retry_seconds).await;
                }
            }
        }
    }
    Ok(false)
}
