//! `training/window_cycle.py`: the operative frozen-window cycle (RUST-S21H), including the terminal no-update receipts.
//!
//! A window request carries the exact window policy admission (`expected_contextual_training_optimizer` of the window policy,
//! the window and component manifest pins) and the window sampler. Everything is reconstructed before the reservation and the
//! receipt lookup: the pinned window, the authenticated component release, the authenticated taxonomy and benign snapshots and
//! the frozen source selection. The runtime computes the 64 Adam steps and the checkpoint selection; the fuzzer retains the
//! window and component bytes, reserves and retains the physical attempt, re-derives the whole trace ([`crate::window`]) and
//! either publishes the selected checkpoint or retains a terminal no-update receipt (`window-outcomes/<identity>.json`) that
//! answers a repeated request without another fit.
//!
//! Every `ValueError`, `OSError`, `KeyError` or `TypeError` of the cycle is `FAILED_PRECONDITION` with its text, as in Python;
//! a failed runtime or updater call is `UNAVAILABLE` and an unknown physical outcome is never replayed.

use std::collections::BTreeMap;
use std::path::PathBuf;

use base64::Engine as _;
use privoke_contracts::proto::v1::{
    ComputeSemanticGradientsRequest, FuzzerTrainingRequest, FuzzerTrainingResponse, RuntimeClassification, RuntimeTrainingExample,
};
use privoke_curriculum::value::{self, Value};
use privoke_curriculum::{Example, benign, taxonomy, train_window};
use privoke_training::window::Window;
use prost::Message;
use tonic::Status;

use crate::attempts::{
    Failure, Recorded, persist_backtracking_admission, persist_backtracking_attempt, persist_reservation_rejection,
    reserve_physical_attempt, write_attempt,
};
use crate::config::Scope;
use crate::cycle::{Engine, TrainingCycle, build_training_response, config_value, precondition, resolve_cycle, settings_fingerprint};
use crate::error::{Error, Result, invalid};
use crate::evidence::{cycle_identity, persist_cycle_evidence, reserve_training_request, write_atomic};
use crate::policy::{Expectations, training_admission_header};
use crate::runtime::{BatchUpdate, CallOptions, SEMANTIC_LAYER};
use crate::validate::CONTEXTUAL_SAMPLING_STRATEGY_KEY;
use crate::window::{Components, Pins, TRACE_KEY};

const UNAVAILABLE: &str = "Window runtime/updater unavailable; unknown physical outcomes are never replayed.";

/// What the checks before the reservation produced.
enum Prepared {
    /// A repeated request whose terminal no-update receipt exists.
    Known(FuzzerTrainingResponse),
    /// The authenticated inputs of a cycle that must run.
    Ready(Box<Ready>),
}

struct Ready {
    window: Window,
    window_value: Value,
    components: Components,
    admission: Expectations,
    fingerprint: String,
    outcome_path: PathBuf,
}

fn failure(error: Failure) -> Status {
    precondition(error.message())
}

fn response(model_id: &str, base_version: &str, message: &str, metadata: &[(&str, &str)]) -> FuzzerTrainingResponse {
    FuzzerTrainingResponse {
        accepted: true,
        model_id: model_id.to_string(),
        base_version: base_version.to_string(),
        applied_version: base_version.to_string(),
        prompts_generated: 256,
        message: message.to_string(),
        metadata: metadata.iter().map(|(key, text)| ((*key).to_string(), (*text).to_string())).collect(),
    }
}

impl Engine {
    /// `window_cycle.run(service, request, context, training_scope=)`.
    pub(crate) async fn window_cycle(
        &self,
        request: FuzzerTrainingRequest,
        scope: Scope,
    ) -> std::result::Result<FuzzerTrainingResponse, Status> {
        let ready = match self.window_prepare(&request, scope).map_err(precondition)? {
            Prepared::Known(known) => return Ok(known),
            Prepared::Ready(ready) => *ready,
        };
        let cycle = resolve_cycle(&request, &self.config);
        if let Some(mut replayed) = self.previous_update(&request, &cycle, scope, &ready.fingerprint).await? {
            replayed.metadata.insert("window_outcome".to_string(), "selected".to_string());
            return Ok(replayed);
        }
        let (examples, guard) = train_window::examples(&ready.window_value).map_err(precondition)?;
        let update = self.window_compute(&request, &cycle, &ready, &examples, &guard).await?;
        let pins = Pins::of(&self.config);
        let trace = crate::window::validate_update(&update, &pins).map_err(precondition)?;
        let exact = update
            .metrics
            .get("candidate_train_exact_match_rate")
            .copied()
            .ok_or_else(|| precondition("'candidate_train_exact_match_rate'"))?;
        let no_update = trace.status == "no_update" || exact <= self.config.minimum_exact_match_rate;
        let dump = self.config.dump_dir.as_deref();
        persist_cycle_evidence(dump, &request, &update, "full_encoder", !no_update, None).map_err(precondition)?;
        if no_update {
            let reason = if trace.status == "no_update" { trace.reason.clone() } else { "minimum_train_exact_gate".to_string() };
            if let Some(parent) = ready.outcome_path.parent() {
                std::fs::create_dir_all(parent).map_err(precondition)?;
            }
            let trace_text = update.metadata.get(TRACE_KEY).ok_or_else(|| precondition(format!("'{TRACE_KEY}'")))?;
            let receipt = value::object(vec![
                ("schema", value::int(1)),
                ("fingerprint", value::string(&ready.fingerprint)),
                ("base_version", value::string(&update.base_version)),
                ("reason", value::string(&reason)),
                ("trace_sha256", value::string(&value::sha256(trace_text.as_bytes()))),
            ]);
            write_atomic(&ready.outcome_path, &receipt).map_err(precondition)?;
            return Ok(response(
                &update.model_id,
                &update.base_version,
                "No update; immutable BASE retained.",
                &[("window_outcome", "no_update"), ("reason", &reason)],
            ));
        }
        crate::window::validate_publishable(&update, &pins, self.config.minimum_exact_match_rate).map_err(precondition)?;
        let ack = self.submit(&request, &cycle, &update, 256, Some(ready.fingerprint.as_str())).await?;
        if !ack.accepted || ack.model_id != update.model_id || ack.applied_version.is_empty() {
            return Err(precondition("Updater did not acknowledge selected checkpoint publication."));
        }
        persist_cycle_evidence(dump, &request, &update, "full_encoder", true, Some(&ack)).map_err(precondition)?;
        build_training_response(&ack, &update, 256).map_err(precondition)
    }

    /// The reconstruction of every input before the reservation and the replay lookup.
    fn window_prepare(&self, request: &FuzzerTrainingRequest, scope: Scope) -> Result<Prepared> {
        let config = &self.config;
        let strategy = request.metadata.get(CONTEXTUAL_SAMPLING_STRATEGY_KEY).map(String::as_str);
        if scope != Scope::FullEncoder || strategy != Some(train_window::SAMPLER) {
            return invalid("Window sampler/optimizer requires explicit underlying FULL endpoint.");
        }
        let excluded = ["expected_contextual_training_backtracking_policy", "expected_contextual_training_diagnostics_policy"]
            .iter()
            .any(|key| request.metadata.get(*key).is_some_and(|text| !text.is_empty()));
        let admission = match crate::policy::window_expectations(&request.metadata)? {
            Some(admission) if !excluded => admission,
            _ => return invalid("Window cycle requires exclusive explicit schema5 policy admission."),
        };
        let payload = crate::window::read_pinned(config.window_path.as_deref(), config.window_manifest_sha256.as_deref())?;
        let pin = config.window_manifest_sha256.as_deref().unwrap_or_default();
        let window = Window::parse(&payload, pin).map_err(|error| Error(error.to_string()))?;
        let window_value = value::parse_bytes(&payload)?;
        let components = crate::window::load_components(
            [
                config.component_bank_path.as_deref(),
                config.component_reference_path.as_deref(),
                config.component_manifest_path.as_deref(),
                config.component_teacher_path.as_deref(),
            ],
            &request.model_id,
            config.component_manifest_sha256.as_deref(),
            config.component_teacher_sha256.as_deref(),
        )?;
        if admission.get("expected_window_manifest_sha256") != config.window_manifest_sha256.as_deref()
            || admission.get("expected_component_manifest_sha256") != config.component_manifest_sha256.as_deref()
            || request.seed.to_string() != window.seed
            || i64::from(request.prompt_count) != crate::window::WINDOW_PROMPTS
            || config.heldout_prompt_count != 16
            || config.curriculum_manifest_path.is_some()
        {
            return invalid("Window cycle request differs from frozen seed/256originals/pins/exclusive snapshots.");
        }
        let dataset = taxonomy::load_dataset(config.prompt_dataset_path.as_deref())?;
        let (Some(pool), Some(manifest), Some(proof)) =
            (config.benign_pool_path.as_deref(), config.benign_manifest_path.as_deref(), config.benign_exclusion_proof_path.as_deref())
        else {
            return invalid("Benign coverage requires explicit pool, manifest and exclusion-proof paths.");
        };
        let release = benign::load_release(pool, manifest, proof, &dataset)?;
        train_window::validate_sources(&window_value, &dataset, &release)?;
        let seed = window.seed.parse::<u64>().map_err(|_| Error("Window seed differs.".to_string()))?;
        let training = config.batch_training_config(seed, Scope::FullEncoder);
        if training.learning_rate != 0.003
            || training.max_gradient != 0.05
            || training.transformations_per_example != 1
            || training.new_example_weight != 1.0
        {
            return invalid("Window service settings differ from prepared Adam/source contract.");
        }
        let Some(dump) = config.dump_dir.as_deref() else {
            return invalid("Window service requires durable evidence and no-update receipts.");
        };
        let settings = value::object(vec![
            ("training", config_value(&training)),
            ("window_sha256", value::string(pin)),
            ("component_sha256", value::string(&components.release.sha256)),
            ("admission", admission.to_value()),
            ("minimum_exact_match_rate", Value::Float(config.minimum_exact_match_rate)),
        ]);
        let fingerprint = settings_fingerprint(request, &settings)?;
        reserve_training_request(Some(dump), request, scope.name(), &fingerprint)?;
        let outcome_path = dump.join("window-outcomes").join(format!("{}.json", cycle_identity(request, scope.name())?));
        if outcome_path.exists() {
            let outcome = value::parse_bytes(&std::fs::read(&outcome_path)?)?;
            let text =
                |key: &str| value::get(&outcome, key).and_then(value::as_str).map(str::to_string).ok_or_else(|| Error(format!("'{key}'")));
            if text("fingerprint")? != fingerprint {
                return invalid("Known no-update receipt belongs to different effective settings.");
            }
            let (base, reason) = (text("base_version")?, text("reason")?);
            return Ok(Prepared::Known(response(
                &request.model_id,
                &base,
                "Known no_update; immutable BASE retained.",
                &[("window_outcome", "no_update"), ("replayed", "true"), ("reason", &reason)],
            )));
        }
        Ok(Prepared::Ready(Box::new(Ready { window, window_value, components, admission, fingerprint, outcome_path })))
    }

    /// `window_evidence.compute` behind `train_parameter_batch`: the physical window request, its retained attempt and the admitted
    /// response as an update.
    async fn window_compute(
        &self,
        request: &FuzzerTrainingRequest,
        _cycle: &TrainingCycle,
        ready: &Ready,
        examples: &[Example],
        guard: &[Example],
    ) -> std::result::Result<BatchUpdate, Status> {
        let config = &self.config;
        let training = config.batch_training_config(ready.window.seed.parse::<u64>().unwrap_or_default(), Scope::FullEncoder);
        crate::window::validate_request(&ready.window, examples, guard).map_err(precondition)?;
        if ready.components.model_id != request.model_id {
            return Err(precondition("Component reference teacher/bank/profile differs."));
        }
        if config.component_teacher_sha256.as_deref() != Some(ready.components.teacher_sha256.as_str()) {
            return Err(precondition("Fuzzer component teacher SHA differs from independently configured accepted pin."));
        }
        if config.window_manifest_sha256.as_deref() != Some(ready.window.sha256.as_str())
            || training.learning_rate != 0.003
            || training.max_gradient != 0.05
            || ready.admission.get("expected_component_manifest_sha256") != Some(ready.components.release.sha256.as_str())
            || ready.admission.get("expected_window_manifest_sha256") != config.window_manifest_sha256.as_deref()
        {
            return Err(precondition("Window client effective settings/pins differ before reservation."));
        }
        let Some(dump) = config.dump_dir.as_deref() else {
            return Err(precondition("Window compute requires durable evidence directory."));
        };
        let inputs = crate::window::persist_inputs(&ready.window_value, &ready.components, dump).map_err(failure)?;
        let wire_row = |row: &Example| RuntimeTrainingExample {
            text: row.text.clone(),
            has_target: true,
            weight: row.weight,
            target: Some(RuntimeClassification { packed: u32::from(row.target.map_or(0, |target| target.pack())), ..Default::default() }),
        };
        let wire = ComputeSemanticGradientsRequest {
            request_id: request.request_id.clone(),
            model_id: request.model_id.clone(),
            layers: vec![SEMANTIC_LAYER],
            examples: examples.iter().map(wire_row).collect(),
            heldout_examples: guard.iter().map(wire_row).collect(),
            learning_rate: training.learning_rate,
            max_gradient: training.max_gradient,
        };
        let header = training_admission_header(&ready.admission)
            .map_err(precondition)?
            .ok_or_else(|| precondition("Window admission has no header."))?;
        if let Err(error) = reserve_physical_attempt(&wire, &header, Some(dump)) {
            if matches!(error, Failure::Os(..)) {
                let _ = persist_reservation_rejection(&wire, &header, Some(dump), &error);
            }
            return Err(failure(error));
        }
        let options = CallOptions { header: Some(header.clone()), long_deadline: true, deadline_floor: true };
        let response = match self.runtime.compute_gradients(Scope::FullEncoder, wire.clone(), options).await {
            Ok(response) => response,
            Err(status) => {
                let message = status.to_string();
                let recorded = Recorded { type_name: "_InactiveRpcError", message: &message };
                if let Ok(attempt) =
                    persist_backtracking_attempt(Some(dump), &wire, None, "full_encoder", &ready.admission, &header, Some(&recorded))
                {
                    let _ = persist_backtracking_admission(&attempt, None, "unadmitted", Some(&recorded));
                }
                return Err(Status::unavailable(UNAVAILABLE));
            }
        };
        let attempt = persist_backtracking_attempt(Some(dump), &wire, Some(&response), "full_encoder", &ready.admission, &header, None)
            .map_err(failure)?;
        let trace = match crate::window::validate_response(&wire, &response, &ready.admission, &ready.window, &ready.components.release) {
            Ok(trace) => trace,
            Err(error) => {
                let recorded = Recorded { type_name: "ValueError", message: &error.0 };
                let _ = persist_backtracking_admission(&attempt, Some(&response), "unadmitted", Some(&recorded));
                return Err(precondition(error));
            }
        };
        // The admission writer assumes nonempty gradients; a known BASE/no-update outcome is a distinct terminal receipt.
        let parent = attempt.parent().and_then(std::path::Path::parent).ok_or_else(|| precondition("The attempt has no parent."))?;
        let receipt = value::object(vec![
            ("schema", value::int(1)),
            ("physical_attempt", value::string(&attempt.display().to_string())),
            ("status", value::string(&trace.status)),
            ("trace_sha256", value::string(&value::sha256(trace.raw.as_bytes()))),
        ]);
        write_attempt(&parent.join("window-admission"), &receipt).map_err(failure)?;
        let encoder = base64::engine::general_purpose::STANDARD;
        let evidence = value::object(vec![
            ("rpc", value::string("ComputeUnderlyingModelGradients")),
            ("request_layers", Value::Array(vec![value::int(4)])),
            ("request_protobuf_base64", value::string(&encoder.encode(wire.encode_to_vec()))),
            ("response_protobuf_base64", value::string(&encoder.encode(crate::pywire::compute_response_bytes(&response)))),
            ("invocation_metadata", crate::attempts::invocation_value(&header)),
            ("physical_attempt", value::string(&attempt.display().to_string())),
            ("window_inputs", inputs),
        ]);
        Ok(BatchUpdate {
            model_id: response.model_id.clone(),
            base_version: response.base_version.clone(),
            gradients: response
                .gradients
                .iter()
                .map(|parameter| (parameter.name.clone(), parameter.values.iter().map(|number| f64::from(*number)).collect()))
                .collect(),
            shapes: response.gradients.iter().map(|parameter| (parameter.name.clone(), parameter.shape.clone())).collect(),
            metrics: response.metrics.iter().map(|(key, number)| (key.clone(), *number)).collect::<BTreeMap<_, _>>(),
            metadata: response.metadata.iter().map(|(key, text)| (key.clone(), text.clone())).collect(),
            execution_evidence: evidence,
        })
    }
}
