//! `fuzzer_service.py`: the orchestration of one bounded training cycle.
//!
//! A cycle admits a request, reserves its identity, asks the parameter-update service for a receipt (a replay is answered
//! from it), draws the examples (the stage 20 samplers, in process), has the runtime compute gradients and the guard
//! metrics, applies the publication guard, retains the complete record and submits the update. A step that fails answers
//! the gRPC status the Python service answered with.
//!
//! A policy-admitted FULL Adam cycle (RUST-S21F) sends the admission header with the gradient request, reserves and retains the
//! physical attempt, admits the 64-step trace, selects the candidate TRAIN metric through the retained attempt, states the exact
//! gate and publishes the projected metadata bound to the retained cycle (`full_adam_evidence`, `attempts`, `policy_response`).
//!
//! Not ported, and refused with `UNIMPLEMENTED` and the name of the gap instead of running a different cycle:
//! backtracking and TRAIN diagnostics admission, the window cycle, the audience, rehearsal and benign samplers (and with them a
//! complete ORIGINAL retention cycle, which requires the benign sampler) and the presence cycle.

use std::collections::BTreeMap;
use std::sync::Arc;

use privoke_contracts::proto::v1::{FuzzerTrainingRequest, FuzzerTrainingResponse, ParameterUpdateStatusRequest};
use privoke_curriculum::curriculum::{ReserveOptions, load_curriculum, request_fingerprint, reserve_batch, sampler_settings};
use privoke_curriculum::generator::{PartitionSources, contextual_sampling_audit, generate_training_partition};
use privoke_curriculum::taxonomy::{self, TaxonomyDataset};
use privoke_curriculum::trainer::{merge_publication_metadata, prepare_trainer_examples};
use privoke_curriculum::types::BatchTrainingConfig;
use privoke_curriculum::value::{self, Value};
use privoke_curriculum::{Example, anchor, audience, benign, train_window};
use tokio::sync::Semaphore;
use tonic::{Code, Status};

use crate::attempts::{
    Failure, Recorded, persist_backtracking_admission, persist_backtracking_attempt, persist_policy_attempt, persist_reservation_rejection,
    reserve_physical_attempt,
};
use crate::config::{FuzzerConfig, Scope};
use crate::error::Error;
use crate::evidence::{persist_cycle_evidence, recover_cycle_evidence_ack, reserve_training_request};
use crate::policy::{Expectations, training_admission_header};
use crate::runtime::{BatchUpdate, CallOptions, RuntimeBackend, gradient_request, update_from_response, validate_response};
use crate::state::SqliteState;
use crate::updates::{PublicationContext, UpdateBackend, publication_request};
use crate::validate::CONTEXTUAL_SAMPLING_STRATEGY_KEY;

const TAXONOMY_STRATEGY: &str = "taxonomy_coverage_v1";
const RUNTIME_UNAVAILABLE: &str = "Client runtime training evaluation is unavailable.";

/// `TrainingCycle`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrainingCycle {
    /// The prompt count the caller asked for.
    pub requested_prompt_count: u32,
    /// The count after the service's cap.
    pub prompt_count: i64,
    /// The model the cycle trains.
    pub model_id: String,
    /// The cycle seed.
    pub seed: u64,
}

/// `_resolve_cycle`.
pub fn resolve_cycle(request: &FuzzerTrainingRequest, config: &FuzzerConfig) -> TrainingCycle {
    let requested = i64::from(request.prompt_count);
    let prompt_count = requested.min(config.max_prompt_count);
    if prompt_count < requested {
        log(format_args!("capped training prompt count requested={requested} max={}", config.max_prompt_count));
    }
    TrainingCycle {
        requested_prompt_count: request.prompt_count,
        prompt_count,
        model_id: if request.model_id.is_empty() { config.model_id.clone() } else { request.model_id.clone() },
        seed: if request.seed == 0 { config.seed } else { u64::from(request.seed) },
    }
}

/// The status of a failed evidence write: a contract failure is `FAILED_PRECONDITION`, a disk failure `UNAVAILABLE`.
fn failure_status(failure: &Failure) -> Status {
    match failure {
        Failure::Value(message) => Status::failed_precondition(message.clone()),
        Failure::Os(_, message) => {
            log(format_args!("client runtime semantic training failed: {message}"));
            Status::unavailable(RUNTIME_UNAVAILABLE)
        }
    }
}

/// An exception the Python handler does not catch: the caller sees `UNKNOWN` with the exception text.
fn unhandled(error: impl std::fmt::Display) -> Status {
    Status::unknown(format!("Exception calling application: {error}"))
}

/// What the caller asked the runtime to admit: the resolved expectations and the header that carries them.
struct Policy<'a> {
    expectations: &'a Expectations,
    header: Option<&'a str>,
}

/// `full_adam.CONFIG["eta"]` and `["delta_cap"]`: the fixed rate and cap of a FULL Adam fit.
const FULL_ADAM_ETA: f64 = 0.003;
const FULL_ADAM_DELTA_CAP: f64 = 0.05;

/// `str(float)`.
fn py_float_text(number: f64) -> String {
    privoke_contracts::pyfloat::repr(number).unwrap_or_default()
}

fn log(message: std::fmt::Arguments<'_>) {
    eprintln!("{message}");
}

/// A `ValueError` of the cycle: `FAILED_PRECONDITION` with its message.
fn precondition(error: impl std::fmt::Display) -> Status {
    Status::failed_precondition(error.to_string())
}

/// The named gap: the path is not ported, and says so.
fn gap(feature: &str) -> Status {
    Status::unimplemented(format!("{feature} is not ported to the Rust fuzzer (stage 21 gap)."))
}

/// `_training_request_fingerprint`.
pub fn plain_fingerprint(request: &FuzzerTrainingRequest) -> String {
    value::sha256(&crate::pywire::fuzzer_request_bytes(request))
}

fn settings_fingerprint(request: &FuzzerTrainingRequest, settings: &Value) -> Result<String, Error> {
    let document = Value::Array(vec![value::string(&hex(&crate::pywire::fuzzer_request_bytes(request))), settings.clone()]);
    Ok(value::sha256(value::dumps_compact(&document)?.as_bytes()))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// `asdict(BatchTrainingConfig)`.
fn config_value(config: &BatchTrainingConfig) -> Value {
    value::object(vec![
        ("learning_rate", Value::Float(config.learning_rate)),
        ("max_gradient", Value::Float(config.max_gradient)),
        ("new_example_weight", Value::Float(config.new_example_weight)),
        ("golden_example_weight", Value::Float(config.golden_example_weight)),
        ("transformations_per_example", value::int(config.transformations_per_example)),
        ("seed", value::uint(config.seed)),
    ])
}

/// `validate_training_update` without a window policy: the publication guard.
pub fn validate_training_update(update: &BatchUpdate, minimum_exact_match_rate: f64) -> Result<(), Error> {
    if !minimum_exact_match_rate.is_finite() || !(0.0..=1.0).contains(&minimum_exact_match_rate) {
        return Err(Error("Minimum exact match rate must be finite and within [0, 1].".to_string()));
    }
    let metrics = &update.metrics;
    for name in [
        "exact_match_rate",
        "heldout_exact_match_rate",
        "candidate_heldout_exact_match_rate",
        "heldout_sensitive_recall",
        "candidate_heldout_sensitive_recall",
        "heldout_clean_specificity",
        "candidate_heldout_clean_specificity",
        "candidate_heldout_safety_regression_rate",
    ] {
        let Some(number) = metrics.get(name) else { return Err(Error(format!("Training update did not report {name}."))) };
        if !number.is_finite() || !(0.0..=1.0).contains(number) {
            return Err(Error(format!("Training update {name} must be finite and within [0, 1].")));
        }
    }
    for name in ["heldout_sensitive_examples", "heldout_clean_examples"] {
        let number = metrics.get(name).copied().unwrap_or(0.0);
        if !number.is_finite() || number < 1.0 || number != number.trunc() {
            return Err(Error("Held-out evaluation needs both clean and sensitive examples.".to_string()));
        }
    }
    crate::retention::require_no_violations(&update.metadata)?;
    let selected = crate::full_adam_evidence::eligibility_metric(update)?;
    let Some(exact) = metrics.get(selected).copied() else {
        return Err(Error("Training update did not report exact_match_rate.".to_string()));
    };
    let metric = |name: &str| metrics.get(name).copied().unwrap_or(f64::NAN);
    if exact <= minimum_exact_match_rate {
        return Err(Error(format!(
            "Training update exact_match_rate {exact:.4} must be greater than the minimum {minimum_exact_match_rate:.4}."
        )));
    }
    if metric("candidate_heldout_sensitive_recall") < metric("heldout_sensitive_recall")
        || metric("candidate_heldout_clean_specificity") < metric("heldout_clean_specificity")
        || metric("candidate_heldout_exact_match_rate") < metric("heldout_exact_match_rate")
        || metric("candidate_heldout_safety_regression_rate") > 0.0
    {
        return Err(Error("Candidate model is worse on the held-out evaluation set.".to_string()));
    }
    Ok(())
}

/// `build_training_response`.
pub fn build_training_response(
    ack: &privoke_contracts::proto::v1::ParameterUpdateAck,
    update: &BatchUpdate,
    prompts_generated: usize,
) -> Result<FuzzerTrainingResponse, Error> {
    let metadata = merge_publication_metadata(&update.metadata, &update.metrics, &BTreeMap::new())?;
    Ok(FuzzerTrainingResponse {
        accepted: ack.accepted,
        model_id: ack.model_id.clone(),
        base_version: update.base_version.clone(),
        applied_version: ack.applied_version.clone(),
        prompts_generated: u32::try_from(prompts_generated).unwrap_or(u32::MAX),
        message: ack.message.clone(),
        metadata: metadata.into_iter().collect(),
    })
}

/// The cycle engine: the configuration, the two backends and the concurrency bound.
pub struct Engine {
    config: FuzzerConfig,
    runtime: Arc<dyn RuntimeBackend>,
    updates: Arc<dyn UpdateBackend>,
    slots: Semaphore,
}

impl std::fmt::Debug for Engine {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("Engine").field("config", &self.config).finish_non_exhaustive()
    }
}

/// What the sampling step produced.
struct Sampled {
    examples: Vec<Example>,
    heldout: Vec<Example>,
    replay: Vec<Example>,
    audit: BTreeMap<String, String>,
}

impl Engine {
    /// An engine over the two backends.
    pub fn new(config: FuzzerConfig, runtime: Arc<dyn RuntimeBackend>, updates: Arc<dyn UpdateBackend>) -> Self {
        let slots = Semaphore::new(config.max_concurrent_cycles);
        Self { config, runtime, updates, slots }
    }

    /// The configuration.
    pub fn config(&self) -> &FuzzerConfig {
        &self.config
    }

    /// `RunTrainingCycle` and `RunUnderlyingTrainingCycle`: validate, take a slot, run.
    pub async fn run_training_cycle(&self, request: FuzzerTrainingRequest, scope: Scope) -> Result<FuzzerTrainingResponse, Status> {
        crate::validate::validate_training_request(&request, &self.config.model_id).map_err(|error| Status::invalid_argument(error.0))?;
        let Ok(_permit) = self.slots.try_acquire() else {
            return Err(Status::resource_exhausted("The maximum number of concurrent training cycles is already running."));
        };
        self.cycle(request, scope).await
    }

    /// `RunPresenceTrainingCycle`: validated like Python, then refused as a gap.
    pub async fn run_presence_cycle(&self, request: FuzzerTrainingRequest) -> Result<FuzzerTrainingResponse, Status> {
        crate::validate::validate_presence_training_request(&request, &self.config.presence_model_id)
            .map_err(|error| Status::invalid_argument(error.0))?;
        Err(gap("The presence training cycle (the presence gradient RPC and its guard)"))
    }

    async fn cycle(&self, request: FuzzerTrainingRequest, scope: Scope) -> Result<FuzzerTrainingResponse, Status> {
        let request = if scope == Scope::FullEncoder { scoped(request) } else { request };
        let strategy_key = request.metadata.get(CONTEXTUAL_SAMPLING_STRATEGY_KEY).map(String::as_str);
        if request.metadata.get("expected_contextual_training_optimizer").map(String::as_str)
            == Some("full_projected_adam64_window_checkpoint_v1")
            || strategy_key == Some(train_window::SAMPLER)
        {
            return Err(gap("The window training cycle"));
        }
        let cycle = resolve_cycle(&request, &self.config);
        let expectations = crate::policy::training_policy_expectations(&request.metadata).map_err(precondition)?;
        let retention_mode =
            expectations.get("expected_optimizer").is_some_and(|name| crate::full_adam::RETENTION_POLICIES.contains(&name));
        let batch_config = self.config.batch_training_config(cycle.seed, scope);
        if expectations.contains("expected_optimizer") && expectations.get("expected_training_scope") != Some(scope.name()) {
            return Err(precondition("FULL Adam request header scope differs before reservation."));
        }
        if expectations.contains("expected_optimizer")
            && scope == Scope::FullEncoder
            && (batch_config.learning_rate != FULL_ADAM_ETA || batch_config.max_gradient != FULL_ADAM_DELTA_CAP)
        {
            return Err(precondition("FULL Adam fixed rate/cap must match before reservation or receipt recovery."));
        }
        if expectations.contains("expected_backtracking_policy") && scope != Scope::FullEncoder {
            return Err(precondition("Backtracking admission is FULL-only."));
        }
        if !expectations.is_empty() && self.config.dump_dir.is_none() {
            return Err(precondition("Training policy admission requires durable PRIVOKE_FUZZER_DUMP_DIR."));
        }
        if expectations.contains("expected_backtracking_policy") {
            return Err(gap("Backtracking admission (the physical backtracking route, its trace and the known-rejection admission)"));
        }
        if expectations.get("expected_diagnostics_policy").is_some() {
            return Err(gap("TRAIN diagnostics admission (the diagnostics validator and the compact publication)"));
        }
        let strategy: Option<String> = match strategy_key.unwrap_or(&self.config.contextual_sampling_strategy) {
            text if text == audience::LEGACY => None,
            text => Some(text.to_string()),
        };
        if strategy.as_deref() == Some(audience::STRATEGY) {
            return Err(gap("Audience coverage sampling (the pinned AU3 release and its implementation closure)"));
        }
        if retention_mode && strategy.as_deref() != Some(benign::STRATEGY) {
            return Err(precondition("ORIGINAL retention requires the unchanged BC01 main composition."));
        }
        if strategy.as_deref() != Some(anchor::STRATEGY)
            && [anchor::BANK_KEY, anchor::MANIFEST_KEY].iter().any(|key| request.metadata.contains_key(*key))
        {
            return Err(precondition("Orphan rehearsal pins require the explicit rehearsal strategy."));
        }
        if strategy.as_deref() != Some(benign::STRATEGY)
            && [benign::POOL_KEY, benign::MANIFEST_KEY, benign::PROOF_KEY].iter().any(|key| request.metadata.contains_key(*key))
        {
            return Err(precondition("Orphan benign pins require the explicit benign strategy."));
        }
        if matches!(strategy.as_deref(), Some(anchor::STRATEGY | benign::STRATEGY)) {
            return Err(gap(
                "Rehearsal and benign coverage sampling (they require the authenticated FULL Adam policy admission and the FULL Adam gate)",
            ));
        }
        let mut taxonomy_dataset: Option<TaxonomyDataset> = None;
        let mut fingerprint: Option<String> = None;
        if strategy.as_deref() == Some(TAXONOMY_STRATEGY) {
            if self.config.curriculum_manifest_path.is_some() {
                return Err(precondition("Taxonomy coverage cannot override a fixed curriculum."));
            }
            if self.config.dump_dir.is_none() {
                return Err(precondition("Taxonomy coverage requires durable PRIVOKE_FUZZER_DUMP_DIR."));
            }
            if cycle.prompt_count != 32 || self.config.heldout_prompt_count != 16 || batch_config.transformations_per_example != 1 {
                return Err(precondition("Taxonomy coverage requires 32 originals, 16 guard rows and one transformation."));
            }
            let dataset = taxonomy::load_dataset(self.config.prompt_dataset_path.as_deref()).map_err(precondition)?;
            if request.metadata.get("taxonomy_dataset_sha256").is_some_and(|expected| expected != &dataset.sha256) {
                return Err(precondition("Requested taxonomy dataset hash differs from the server release."));
            }
            let settings = value::object(vec![
                ("training", config_value(&batch_config)),
                ("scope", value::string(scope.name())),
                ("model_id", value::string(&cycle.model_id)),
                ("prompt_count", value::int(cycle.prompt_count)),
                ("seed", value::uint(cycle.seed)),
                ("heldout_count", value::int(self.config.heldout_prompt_count)),
                ("minimum_exact_match_rate", Value::Float(self.config.minimum_exact_match_rate)),
                ("dataset_sha256", value::string(&dataset.sha256)),
                ("policy", taxonomy::policy_contract()),
            ]);
            fingerprint = Some(settings_fingerprint(&request, &settings).map_err(precondition)?);
            taxonomy_dataset = Some(dataset);
        }
        let curriculum = match &self.config.curriculum_manifest_path {
            Some(path) => Some(load_curriculum(path).map_err(precondition)?),
            None => None,
        };
        if let Some(curriculum) = &curriculum {
            sampler_settings(&request.metadata).map_err(precondition)?;
            for (key, actual) in [("curriculum_id", &curriculum.curriculum_id), ("curriculum_manifest_sha256", &curriculum.manifest_sha256)]
            {
                if request.metadata.get(key).is_some_and(|expected| expected != actual) {
                    return Err(precondition(format!("Requested {key} differs from the server curriculum.")));
                }
            }
            let mut pairs = vec![
                ("training", config_value(&batch_config)),
                ("prompt_count", value::int(cycle.prompt_count)),
                ("model_id", value::string(&cycle.model_id)),
                ("replay_fraction", Value::Float(self.config.curriculum_replay_fraction)),
                ("minimum_exact_match_rate", Value::Float(self.config.minimum_exact_match_rate)),
                ("heldout_count", value::int(self.config.heldout_prompt_count)),
            ];
            if scope == Scope::FullEncoder {
                pairs.push(("training_scope", value::string(scope.name())));
            }
            fingerprint = Some(request_fingerprint(&request, curriculum, &value::object(pairs)).map_err(precondition)?);
        }
        let require_full = request.metadata.get("require_full_capability").map(String::as_str) == Some("true");
        let header = training_admission_header(&expectations).map_err(precondition)?;
        if !expectations.is_empty() || scope == Scope::FullEncoder || require_full || taxonomy_dataset.is_some() {
            if curriculum.is_none() && taxonomy_dataset.is_none() {
                fingerprint = Some(self.generic_fingerprint(&request, &batch_config, &cycle, scope, &expectations).map_err(precondition)?);
            }
            if let Some(header) = &header {
                let document = Value::Array(vec![
                    value::string(fingerprint.as_deref().unwrap_or_default()),
                    crate::attempts::invocation_value(header),
                ]);
                let wrapped = value::dumps_compact(&document).map_err(precondition)?;
                fingerprint = Some(value::sha256(wrapped.as_bytes()));
            }
            let reserved = fingerprint.as_deref().unwrap_or_default();
            reserve_training_request(self.config.dump_dir.as_deref(), &request, scope.name(), reserved).map_err(precondition)?;
        }
        let lookup = fingerprint.clone().unwrap_or_else(|| plain_fingerprint(&request));
        if let Some(replayed) = self.previous_update(&request, &cycle, scope, &lookup).await? {
            return Ok(replayed);
        }
        log(format_args!(
            "{} id={:?} source={:?} model={:?} prompts={}",
            if request.metadata.get("initiator").map(String::as_str) == Some("param-update-service") {
                "starting automatic training run"
            } else {
                "received training request"
            },
            request.request_id,
            request.source_id,
            cycle.model_id,
            cycle.prompt_count
        ));
        let sampled = self.sample(
            &request,
            &cycle,
            strategy.as_deref(),
            curriculum.as_ref(),
            taxonomy_dataset.as_ref(),
            fingerprint.as_deref(),
            &batch_config,
        )?;
        let policy = Policy { expectations: &expectations, header: header.as_deref() };
        let mut update =
            self.train(&request, &cycle, scope, &sampled, &batch_config, require_full, taxonomy_dataset.as_ref(), &policy).await?;
        if !sampled.audit.is_empty() {
            update.metadata.extend(sampled.audit.clone());
        }
        if crate::full_adam_evidence::is_full_adam_family(update.metadata.get("executed_contextual_training_optimizer").map(String::as_str))
        {
            // Python lets a failure here escape the handler: the caller sees `UNKNOWN` with the exception text.
            let gate = crate::full_adam_evidence::gate_text(&update, self.config.minimum_exact_match_rate).map_err(unhandled)?;
            update.metadata.insert(crate::full_adam_evidence::GATE_KEY.to_string(), gate);
        }
        if let Some(expected) = request.metadata.get("expected_base_version").filter(|expected| !expected.is_empty())
            && &update.base_version != expected
        {
            return Err(precondition("Underlying stage base differs from the prior committed head stage."));
        }
        if request.metadata.get("study_gate_diagnostics").map(String::as_str) == Some("v1") {
            crate::gate_diagnostics::write_gate_diagnostics(&request, &update, &self.config).map_err(precondition)?;
        }
        let dump = self.config.dump_dir.as_deref();
        if let Err(error) = validate_training_update(&update, self.config.minimum_exact_match_rate) {
            persist_cycle_evidence(dump, &request, &update, scope.name(), false, None).map_err(precondition)?;
            log(format_args!("rejecting training update: {error}"));
            return Err(precondition(error));
        }
        let generated = sampled.examples.len() + sampled.replay.len();
        persist_cycle_evidence(dump, &request, &update, scope.name(), true, None).map_err(precondition)?;
        let ack = self.submit(&request, &cycle, &update, generated, fingerprint.as_deref()).await?;
        if !ack.accepted || ack.model_id != update.model_id || ack.applied_version.is_empty() {
            return Err(precondition("Parameter updater did not acknowledge the selected model publication."));
        }
        if let Err(error) = persist_cycle_evidence(dump, &request, &update, scope.name(), true, Some(&ack)) {
            // Prepared evidence and the durable updater receipt remain available for recovery; a missing acknowledgement
            // must never trigger republication.
            log(format_args!("Committed training acknowledgement evidence persistence failed: {error}"));
        }
        log(format_args!(
            "completed training request id={:?} accepted={} version={:?} prompts={}",
            request.request_id,
            ack.accepted,
            ack.applied_version,
            sampled.examples.len()
        ));
        build_training_response(&ack, &update, generated).map_err(precondition)
    }

    /// The settings of a dual cycle without a curriculum or a policy, and the request's fingerprint over them.
    fn generic_fingerprint(
        &self,
        request: &FuzzerTrainingRequest,
        batch_config: &BatchTrainingConfig,
        cycle: &TrainingCycle,
        scope: Scope,
        expectations: &Expectations,
    ) -> Result<String, Error> {
        let dataset = match &self.config.prompt_dataset_path {
            Some(path) => value::sha256(&std::fs::read(path)?),
            None => "bundled_synthetic_generator_v1".to_string(),
        };
        let mut pairs = vec![
            ("training", config_value(batch_config)),
            ("scope", value::string(scope.name())),
            ("prompt_count", value::int(cycle.prompt_count)),
            ("heldout_count", value::int(self.config.heldout_prompt_count)),
            ("minimum_exact_match_rate", Value::Float(self.config.minimum_exact_match_rate)),
            ("dataset_sha256", value::string(&dataset)),
        ];
        if !expectations.is_empty() {
            pairs.push(("model_id", value::string(&cycle.model_id)));
            pairs.push(("seed", value::uint(cycle.seed)));
            pairs.push(("policy_admission", value::string("artifact_policy_v1")));
            pairs.push(("expectations", expectations.to_value()));
            pairs.push(("semantic_execution_contract", value::string("training_base_heldout_candidate_heldout_v1")));
        }
        settings_fingerprint(request, &value::object(pairs))
    }

    async fn previous_update(
        &self,
        request: &FuzzerTrainingRequest,
        cycle: &TrainingCycle,
        scope: Scope,
        fingerprint: &str,
    ) -> Result<Option<FuzzerTrainingResponse>, Status> {
        let lookup = ParameterUpdateStatusRequest {
            source_id: self.config.fuzzer_id.clone(),
            request_id: request.request_id.clone(),
            request_source_id: request.source_id.clone(),
            model_id: cycle.model_id.clone(),
            request_fingerprint: fingerprint.to_string(),
        };
        let status = match self.updates.status(lookup).await {
            Ok(status) => status,
            Err(status) if status.code() == Code::AlreadyExists => {
                return Err(Status::already_exists("request_id belongs to a different training request."));
            }
            Err(_) => return Err(Status::unavailable("Parameter update receipts are unavailable.")),
        };
        if !status.found {
            return Ok(None);
        }
        recover_cycle_evidence_ack(self.config.dump_dir.as_deref(), request, scope.name(), &status).map_err(precondition)?;
        let ack = status.ack.clone().unwrap_or_default();
        Ok(Some(FuzzerTrainingResponse {
            accepted: ack.accepted,
            model_id: ack.model_id,
            base_version: status.base_version,
            applied_version: ack.applied_version,
            prompts_generated: status.prompts_generated,
            message: ack.message,
            metadata: BTreeMap::from([("replayed".to_string(), "true".to_string())]).into_iter().collect(),
        }))
    }

    #[allow(clippy::too_many_arguments)]
    fn sample(
        &self,
        request: &FuzzerTrainingRequest,
        cycle: &TrainingCycle,
        strategy: Option<&str>,
        curriculum: Option<&privoke_curriculum::curriculum::Curriculum>,
        taxonomy_dataset: Option<&TaxonomyDataset>,
        fingerprint: Option<&str>,
        batch_config: &BatchTrainingConfig,
    ) -> Result<Sampled, Status> {
        if let Some(curriculum) = curriculum {
            if strategy.is_some() {
                return Err(precondition("Contextual sampling strategy cannot override the fixed curriculum."));
            }
            let path = self
                .config
                .curriculum_state_path
                .as_deref()
                .ok_or_else(|| precondition("Curriculum training requires a durable FUZZ_CURRICULUM_STATE_PATH."))?;
            let mut state = SqliteState::begin(path).map_err(precondition)?;
            let options = ReserveOptions {
                replay_fraction: self.config.curriculum_replay_fraction,
                fingerprint,
                model_id: Some(cycle.model_id.as_str()),
            };
            let batch = reserve_batch(curriculum, &mut state, request, cycle.prompt_count, options);
            state.finish(batch.is_ok()).map_err(precondition)?;
            let mut batch = batch.map_err(precondition)?;
            batch.audit.insert("curriculum_replay_weight".to_string(), py_float_text(batch_config.golden_example_weight));
            return Ok(Sampled { examples: batch.examples, heldout: batch.heldout, replay: batch.replay, audit: batch.audit });
        }
        let sources = PartitionSources {
            dataset_path: self.config.prompt_dataset_path.as_deref(),
            sampling_strategy: strategy,
            taxonomy_dataset,
            ..PartitionSources::default()
        };
        let (examples, heldout) = generate_training_partition(cycle.prompt_count, self.config.heldout_prompt_count, cycle.seed, &sources)
            .map_err(precondition)?;
        let audit = match (strategy, taxonomy_dataset) {
            (None, _) => BTreeMap::new(),
            (Some(_), Some(dataset)) => taxonomy::audit_originals(dataset, &examples, &heldout).map_err(precondition)?,
            (Some(_), None) => contextual_sampling_audit(&examples).map_err(precondition)?,
        };
        Ok(Sampled { examples, heldout, replay: Vec::new(), audit })
    }

    /// `_train`: prepare the examples, have the runtime compute, admit the response.
    #[allow(clippy::too_many_arguments)]
    async fn train(
        &self,
        request: &FuzzerTrainingRequest,
        cycle: &TrainingCycle,
        scope: Scope,
        sampled: &Sampled,
        batch_config: &BatchTrainingConfig,
        require_full_capability: bool,
        taxonomy_dataset: Option<&TaxonomyDataset>,
        policy: &Policy<'_>,
    ) -> Result<BatchUpdate, Status> {
        let trainer_examples =
            prepare_trainer_examples(&sampled.examples, &sampled.replay, &sampled.heldout, batch_config).map_err(precondition)?;
        let expanded_audit = match taxonomy_dataset {
            Some(dataset) => {
                if !sampled.replay.is_empty() {
                    return Err(precondition("Taxonomy coverage requires its dataset snapshot and no extra replay rows."));
                }
                taxonomy::audit_expanded(dataset, &sampled.examples, &trainer_examples, &sampled.heldout, batch_config)
                    .map_err(precondition)?
            }
            None => BTreeMap::new(),
        };
        let wire = gradient_request(
            &trainer_examples,
            &sampled.heldout,
            &cycle.model_id,
            &request.request_id,
            batch_config.learning_rate,
            batch_config.max_gradient,
        )
        .map_err(precondition)?;
        let dump = self.config.dump_dir.as_deref();
        let expectations = policy.expectations;
        let header = policy.header;
        let optimizer = expectations.contains("expected_optimizer");
        if optimizer
            && (expectations.get("expected_training_scope") != Some(scope.name())
                || (scope == Scope::FullEncoder
                    && (batch_config.learning_rate != FULL_ADAM_ETA || batch_config.max_gradient != FULL_ADAM_DELTA_CAP)))
        {
            return Err(precondition("FULL Adam scope/rate/cap differs before runtime compute."));
        }
        if expectations.contains("expected_backtracking_policy") && scope != Scope::FullEncoder {
            return Err(precondition("Backtracking admission is FULL-only."));
        }
        if !expectations.is_empty() && dump.is_none() {
            return Err(precondition("Training policy admission requires durable PRIVOKE_FUZZER_DUMP_DIR."));
        }
        if optimizer && let Err(failure) = reserve_physical_attempt(&wire, header.unwrap_or_default(), dump) {
            if matches!(failure, Failure::Os(..)) {
                let _ = persist_reservation_rejection(&wire, header.unwrap_or_default(), dump, &failure);
            }
            return Err(failure_status(&failure));
        }
        let options = CallOptions { header: header.map(str::to_string), long_deadline: optimizer && scope == Scope::FullEncoder };
        let response = match self.runtime.compute_gradients(scope, wire.clone(), options).await {
            Ok(response) => response,
            Err(status) => {
                log(format_args!("client runtime semantic training failed: {status}"));
                let message = status.to_string();
                let recorded = Recorded { type_name: "_InactiveRpcError", message: &message };
                if let Some(header) = header {
                    if let Ok(attempt) =
                        persist_backtracking_attempt(dump, &wire, None, scope.name(), expectations, header, Some(&recorded))
                    {
                        let _ = persist_backtracking_admission(&attempt, None, "unadmitted", Some(&recorded));
                    }
                } else if !expectations.is_empty() {
                    let _ = persist_policy_attempt(dump, &wire, None, scope.name(), expectations, Some(&recorded));
                }
                return Err(Status::unavailable(RUNTIME_UNAVAILABLE));
            }
        };
        let attempt = match header {
            Some(header) => Some(
                persist_backtracking_attempt(dump, &wire, Some(&response), scope.name(), expectations, header, None)
                    .map_err(|failure| failure_status(&failure))?,
            ),
            None => None,
        };
        if let Err(error) = validate_response(&wire, &response, scope, batch_config.max_gradient, require_full_capability, expectations) {
            log(format_args!("client runtime semantic training failed: {error}"));
            let recorded = Recorded { type_name: "RuntimeAnalysisError", message: &error.0 };
            if let Some(attempt) = &attempt {
                let _ = persist_backtracking_admission(attempt, Some(&response), "unadmitted", Some(&recorded));
            } else if !expectations.is_empty() {
                let _ = persist_policy_attempt(dump, &wire, Some(&response), scope.name(), expectations, Some(&recorded));
            }
            return Err(Status::unavailable(RUNTIME_UNAVAILABLE));
        }
        if let Some(attempt) = &attempt {
            persist_backtracking_admission(attempt, Some(&response), "accepted", None).map_err(|failure| failure_status(&failure))?;
        } else if !expectations.is_empty() {
            persist_policy_attempt(dump, &wire, Some(&response), scope.name(), expectations, None)
                .map_err(|failure| failure_status(&failure))?;
        }
        let mut update = match update_from_response(&wire, &response, scope) {
            Ok(update) => update,
            Err(error) => {
                log(format_args!("client runtime semantic training failed: {error}"));
                return Err(Status::unavailable(RUNTIME_UNAVAILABLE));
            }
        };
        if let (Some(attempt), Some(header), Value::Object(map)) = (&attempt, header, &mut update.execution_evidence) {
            map.insert("invocation_metadata".to_string(), crate::attempts::invocation_value(header));
            map.insert("physical_attempt".to_string(), value::string(&attempt.display().to_string()));
        }
        update.metadata.extend(expanded_audit);
        update.metrics.insert("new_examples".to_string(), sampled.examples.len() as f64);
        update.metrics.insert("golden_examples".to_string(), sampled.replay.len() as f64);
        update.metadata.insert("transformations_per_example".to_string(), batch_config.transformations_per_example.to_string());
        Ok(update)
    }

    /// `_submit_update`.
    async fn submit(
        &self,
        request: &FuzzerTrainingRequest,
        cycle: &TrainingCycle,
        update: &BatchUpdate,
        generated: usize,
        fingerprint: Option<&str>,
    ) -> Result<privoke_contracts::proto::v1::ParameterUpdateAck, Status> {
        let plain;
        let fingerprint = match fingerprint {
            Some(text) => text,
            None => {
                plain = plain_fingerprint(request);
                plain.as_str()
            }
        };
        let pipeline = if update.metadata.get("training_scope").map(String::as_str) == Some("full_encoder") {
            "client_runtime_underlying_gradients"
        } else {
            "client_runtime_semantic_gradients"
        };
        let context = PublicationContext {
            request_id: &request.request_id,
            request_source_id: &request.source_id,
            requested_prompt_count: cycle.requested_prompt_count,
            generated_prompt_count: generated,
            pipeline,
            fingerprint,
        };
        let message = publication_request(&self.config.fuzzer_id, update, &context.metadata(), self.config.dump_dir.as_deref())
            .map_err(|_| precondition("Training publication evidence or metadata is invalid."))?;
        match self.updates.submit(message).await {
            Ok(ack) => Ok(ack),
            Err(status) => {
                log(format_args!("parameter update submission failed code={:?}", status.code()));
                if matches!(status.code(), Code::InvalidArgument | Code::FailedPrecondition | Code::AlreadyExists) {
                    return Err(Status::new(status.code(), "Parameter update service rejected the training stage."));
                }
                Err(Status::unavailable("Parameter update service is unavailable."))
            }
        }
    }
}

/// The FULL scope's receipt and reservation namespace: a distinct, derived source identity.
fn scoped(request: FuzzerTrainingRequest) -> FuzzerTrainingRequest {
    let mut scoped = request.clone();
    scoped.metadata.insert("original_request_source_id".to_string(), request.source_id.clone());
    scoped.source_id = value::sha256(format!("underlying-v1:{}", request.source_id).as_bytes());
    scoped
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn update(metrics: &[(&str, f64)]) -> BatchUpdate {
        BatchUpdate {
            model_id: "m".into(),
            base_version: "v".into(),
            gradients: Vec::new(),
            shapes: BTreeMap::new(),
            metrics: metrics.iter().map(|(key, number)| ((*key).to_string(), *number)).collect(),
            metadata: BTreeMap::new(),
            execution_evidence: Value::Null,
        }
    }

    fn passing() -> Vec<(&'static str, f64)> {
        vec![
            ("exact_match_rate", 0.5),
            ("heldout_exact_match_rate", 0.5),
            ("candidate_heldout_exact_match_rate", 0.5),
            ("heldout_sensitive_recall", 0.5),
            ("candidate_heldout_sensitive_recall", 0.5),
            ("heldout_clean_specificity", 0.5),
            ("candidate_heldout_clean_specificity", 0.5),
            ("candidate_heldout_safety_regression_rate", 0.0),
            ("heldout_sensitive_examples", 8.0),
            ("heldout_clean_examples", 8.0),
        ]
    }

    #[test]
    fn the_guard_accepts_a_non_regressing_candidate() {
        validate_training_update(&update(&passing()), 0.0).unwrap();
    }

    #[test]
    fn the_guard_refuses_in_the_python_order_with_its_messages() {
        let mut worse = passing();
        worse[5] = ("heldout_clean_specificity", 0.75);
        assert_eq!(
            validate_training_update(&update(&worse), 0.0).unwrap_err().0,
            "Candidate model is worse on the held-out evaluation set."
        );
        assert_eq!(
            validate_training_update(&update(&passing()), 0.5).unwrap_err().0,
            "Training update exact_match_rate 0.5000 must be greater than the minimum 0.5000."
        );
        let mut missing = passing();
        missing.remove(0);
        assert_eq!(validate_training_update(&update(&missing), 0.0).unwrap_err().0, "Training update did not report exact_match_rate.");
        let mut range = passing();
        range[0] = ("exact_match_rate", 1.5);
        assert_eq!(
            validate_training_update(&update(&range), 0.0).unwrap_err().0,
            "Training update exact_match_rate must be finite and within [0, 1]."
        );
        let mut counts = passing();
        counts[8] = ("heldout_sensitive_examples", 0.0);
        assert_eq!(
            validate_training_update(&update(&counts), 0.0).unwrap_err().0,
            "Held-out evaluation needs both clean and sensitive examples."
        );
        assert_eq!(
            validate_training_update(&update(&passing()), 2.0).unwrap_err().0,
            "Minimum exact match rate must be finite and within [0, 1]."
        );
        let mut eligibility = update(&passing());
        eligibility.metadata.insert("full_projected_adam_trace_v1".into(), "x".into());
        assert_eq!(
            validate_training_update(&eligibility, 0.0).unwrap_err().0,
            "Candidate eligibility evidence requires its explicit artifact optimizer."
        );
    }

    #[test]
    fn the_full_scope_has_its_own_identity_namespace() {
        let request = FuzzerTrainingRequest { request_id: "r".into(), source_id: "s".into(), ..FuzzerTrainingRequest::default() };
        let full = scoped(request.clone());
        assert_eq!(full.metadata["original_request_source_id"], "s");
        assert_eq!(full.source_id, value::sha256(b"underlying-v1:s"));
        assert_ne!(full.source_id, request.source_id);
    }

    #[test]
    fn the_cycle_resolves_cap_model_and_seed() {
        let config =
            FuzzerConfig::from_lookup(|name| (name == "FUZZ_CONTEXTUAL_SAMPLING_STRATEGY").then(|| "legacy_random_v1".to_string()))
                .unwrap();
        let request = FuzzerTrainingRequest { prompt_count: 1000, model_id: String::new(), seed: 0, ..FuzzerTrainingRequest::default() };
        let cycle = resolve_cycle(&request, &config);
        assert_eq!((cycle.requested_prompt_count, cycle.prompt_count, cycle.seed), (1000, 256, 1337));
        assert_eq!(cycle.model_id, "privoke-baseline");
    }
}
