//! `RunPresenceTrainingCycle` (RUST-S21H item 3): `fuzzer_service._run_presence_training_cycle`, `training/presence.py`,
//! `runtime_client.compute_presence_gradients` and its response admission, `validate_presence_training_update` and the presence
//! branch of `persist_cycle_evidence`.
//!
//! The cycle draws a presence partition (disjoint normalised texts and source groups, both strata), sends explicit binary labels to the
//! runtime over `ComputePresenceGradients` with the explicit `[SEMANTIC]` layer list, retains the physical attempt under
//! `presence-runtime/<request sha256>/attempts/`, admits the three actual executions, applies the presence guard and publishes.
//! There is no reservation: a repeated request is answered from the updater's receipt.

use std::collections::{BTreeMap, BTreeSet};

use base64::Engine as _;
use privoke_contracts::proto::v1::{
    ComputePresenceGradientsRequest, ComputePresenceGradientsResponse, FuzzerTrainingRequest, FuzzerTrainingResponse,
    PresenceTrainingExample,
};
use privoke_curriculum::presence::{PresenceExample, generate_presence_training_partition};
use privoke_curriculum::text::training_text_key;
use privoke_curriculum::value::{self, Value};
use prost::Message;
use tonic::Status;

use crate::attempts::write_attempt;
use crate::cycle::{Engine, TrainingCycle, build_training_response, log, precondition, resolve_cycle};
use crate::error::{Error, Result, invalid};
use crate::evidence::{cycle_identity, write_atomic};
use crate::runtime::{BatchUpdate, SEMANTIC_LAYER};
use crate::updates::{PublicationContext, publication_request};

const UNAVAILABLE: &str = "Client runtime presence training evaluation is unavailable.";
const ABSENT: i32 = 1;
const PRESENT: i32 = 2;

/// `grpc.StatusCode.name` of a code.
fn code_name(code: tonic::Code) -> String {
    let debug = format!("{code:?}");
    let mut out = String::new();
    for (index, character) in debug.chars().enumerate() {
        if character.is_uppercase() && index > 0 {
            out.push('_');
        }
        out.push(character.to_ascii_uppercase());
    }
    out
}

/// `_presence_training_request_fingerprint`.
pub fn presence_fingerprint(request: &FuzzerTrainingRequest) -> String {
    let mut payload = b"RunPresenceTrainingCycle:annotation_presence:v1\0".to_vec();
    payload.extend(crate::pywire::fuzzer_request_bytes(request));
    value::sha256(&payload)
}

fn hex_sha(bytes: &[u8]) -> String {
    value::sha256(bytes)
}

fn encode(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// `_presence_execution_evidence(request, response)`.
fn evidence(request: &ComputePresenceGradientsRequest, response: &ComputePresenceGradientsResponse) -> Value {
    let executions = response
        .executions
        .iter()
        .map(|run| {
            value::object(vec![
                ("phase", value::string(&run.phase)),
                ("layer", value::int(i64::from(run.layer))),
                ("status", value::string(&run.status)),
                ("examples", value::int(i64::from(run.examples))),
                ("error", value::string(&run.error)),
            ])
        })
        .collect();
    value::object(vec![
        ("rpc", value::string("ComputePresenceGradients")),
        ("request_layers", Value::Array(request.layers.iter().map(|layer| value::int(i64::from(*layer))).collect())),
        ("request_protobuf_base64", value::string(&encode(&request.encode_to_vec()))),
        ("response_protobuf_base64", value::string(&encode(&crate::pywire::presence_response_bytes(response)))),
        ("executions", Value::Array(executions)),
    ])
}

/// `validate_presence_training_response(request, response)`: all three actual binary-task computations.
fn validate_runtime_response(request: &ComputePresenceGradientsRequest, response: &ComputePresenceGradientsResponse) -> Result<()> {
    if request.layers != [SEMANTIC_LAYER] {
        return invalid("Presence training requires explicit semantic-only layers.");
    }
    if !response.error.is_empty()
        || response.request_id != request.request_id
        || response.model_id != request.model_id
        || response.base_version.is_empty()
    {
        return invalid("Presence training response identity or error is invalid.");
    }
    let phases = [
        ("training", request.examples.len()),
        ("base_heldout", request.heldout_examples.len()),
        ("candidate_heldout", request.heldout_examples.len()),
    ];
    if phases.iter().any(|(_, count)| *count == 0) || response.executions.len() != phases.len() {
        return invalid("Presence training requires three nonempty actual semantic executions.");
    }
    for (run, (phase, count)) in response.executions.iter().zip(phases) {
        if run.phase != phase
            || run.examples as usize != count
            || run.layer != SEMANTIC_LAYER
            || run.status != "ok"
            || !run.error.is_empty()
        {
            return invalid("Presence training execution evidence is invalid.");
        }
    }
    Ok(())
}

/// `persist_presence_runtime_attempt(request, response, evidence, status=, error=)`.
fn persist_runtime_attempt(
    dump: Option<&std::path::Path>,
    request: &ComputePresenceGradientsRequest,
    response: &ComputePresenceGradientsResponse,
    evidence: &Value,
    status: &str,
    error: &str,
) -> Result<()> {
    let Some(dump) = dump else { return Ok(()) };
    let raw = request.encode_to_vec();
    let digest = hex_sha(&raw);
    let record = value::object(vec![
        ("schema_version", value::int(1)),
        ("request_id", value::string(&request.request_id)),
        ("model_id", value::string(&request.model_id)),
        ("base_version", value::string(&response.base_version)),
        ("request_protobuf_sha256", value::string(&digest)),
        ("base_parameter_fingerprint", value::string(response.metadata.get("base_parameter_fingerprint").map_or("", String::as_str))),
        ("compute_status", value::string(status)),
        ("validation_error", value::string(error)),
        ("execution_evidence", evidence.clone()),
    ]);
    write_attempt(&dump.join("presence-runtime").join(digest), &record).map_err(|failure| Error(failure.message().to_string()))?;
    Ok(())
}

fn wire(rows: &[PresenceExample]) -> Vec<PresenceTrainingExample> {
    rows.iter()
        .map(|row| PresenceTrainingExample {
            text: row.text.clone(),
            target: if row.sensitive { PRESENT } else { ABSENT },
            weight: row.weight,
            group_id: row.group_id.clone(),
        })
        .collect()
}

/// `str(float)` of a non-finite metric, which the retained record keeps as text.
fn metric_value(number: f64) -> Value {
    if number.is_finite() {
        Value::Float(number)
    } else if number.is_nan() {
        value::string("nan")
    } else if number > 0.0 {
        value::string("inf")
    } else {
        value::string("-inf")
    }
}

/// `persist_cycle_evidence(request, update, "presence", ...)`: the complete record, also kept as an immutable attempt.
fn persist_evidence(
    dump: Option<&std::path::Path>,
    request: &FuzzerTrainingRequest,
    update: &BatchUpdate,
    gate_passed: bool,
    ack: Option<&privoke_contracts::proto::v1::ParameterUpdateAck>,
    minimum: f64,
    error: &str,
) -> Result<()> {
    let Some(dump) = dump else { return Ok(()) };
    let parent = dump.join("training-cycles").join(cycle_identity(request, "presence")?);
    std::fs::create_dir_all(&parent)?;
    let base = update.metadata.get("base_parameter_fingerprint").ok_or_else(|| Error("'base_parameter_fingerprint'".to_string()))?;
    let metrics = Value::Object(update.metrics.iter().map(|(key, number)| (key.clone(), metric_value(*number))).collect());
    let wire_text = value::get(&update.execution_evidence, "request_protobuf_base64").and_then(value::as_str).unwrap_or_default();
    let decoded = base64::engine::general_purpose::STANDARD.decode(wire_text).map_err(|error| Error(error.to_string()))?;
    let original = request.metadata.get("original_request_source_id").unwrap_or(&request.source_id);
    let mut pairs = vec![
        ("schema_version", value::int(1)),
        ("training_stage", value::string("presence")),
        ("request_id", value::string(&request.request_id)),
        ("source_id", value::string(&request.source_id)),
        ("original_source_id", value::string(original)),
        ("model_id", value::string(&update.model_id)),
        ("base_version", value::string(&update.base_version)),
        ("metadata", value::from_string_map(&update.metadata)),
        ("metrics", metrics.clone()),
        ("execution_evidence", update.execution_evidence.clone()),
        ("gate_passed", Value::Bool(gate_passed)),
        (
            "gate_diagnostics",
            value::object(vec![("minimum_exact_match_rate", Value::Float(minimum)), ("metrics", metrics), ("error", value::string(error))]),
        ),
        ("request_protobuf_sha256", value::string(&hex_sha(&decoded))),
        ("compute_status", value::string("execution_validated")),
    ];
    if let Some(ack) = ack {
        pairs.push((
            "ack",
            value::object(vec![
                ("accepted", Value::Bool(ack.accepted)),
                ("model_id", value::string(&ack.model_id)),
                ("applied_version", value::string(&ack.applied_version)),
                ("message", value::string(&ack.message)),
            ]),
        ));
    }
    let record = value::object(pairs);
    write_attempt(&parent, &record).map_err(|failure| Error(failure.message().to_string()))?;
    write_atomic(&parent.join(format!("{base}.json")), &record)
}

/// `_require_integral_correct_count`.
fn integral(rate: f64, count: f64, label: &str) -> Result<f64> {
    let correct = rate * count;
    let nearest = correct.round_ties_even();
    if (correct - nearest).abs() > 1e-8 {
        return invalid(format!("Presence {label} rate is inconsistent with its example count."));
    }
    Ok(nearest)
}

fn rates(metrics: &BTreeMap<String, f64>, prefix: &str, total: &str, present: &str, absent: &str) -> Result<()> {
    let at = |key: &str| metrics.get(key).copied().ok_or_else(|| Error(format!("'{key}'")));
    let (total, present, absent) = (at(total)?, at(present)?, at(absent)?);
    let recall = format!("{prefix}_present_recall");
    let specificity = format!("{prefix}_absent_specificity");
    let exact = format!("{prefix}_exact_match_rate");
    let present_correct = integral(at(&recall)?, present, &recall)?;
    let absent_correct = integral(at(&specificity)?, absent, &specificity)?;
    let exact_correct = integral(at(&exact)?, total, &exact)?;
    if ((present_correct + absent_correct) - exact_correct).abs() > 1e-8 {
        return invalid(format!("Presence {exact} does not agree with its stratum rates."));
    }
    Ok(())
}

/// `validate_presence_training_update`.
pub fn validate_update(update: &BatchUpdate, minimum: f64, expected_examples: usize, expected_heldout: usize) -> Result<()> {
    if !minimum.is_finite() || !(0.0..=1.0).contains(&minimum) {
        return invalid("Minimum exact match rate must be finite and within [0, 1].");
    }
    let metrics = &update.metrics;
    for name in [
        "examples",
        "heldout_examples",
        "heldout_present_examples",
        "heldout_absent_examples",
        "candidate_heldout_examples",
        "candidate_heldout_present_examples",
        "candidate_heldout_absent_examples",
    ] {
        if !metrics.get(name).is_some_and(|number| number.is_finite() && *number >= 1.0 && *number == number.trunc()) {
            return invalid("Presence held-out evaluation needs positive integral counts in both strata.");
        }
    }
    if metrics["examples"] != expected_examples as f64 {
        return invalid("Presence training example count does not match the submitted batch.");
    }
    if metrics["heldout_examples"] != expected_heldout as f64 {
        return invalid("Presence held-out count does not match the submitted batch.");
    }
    for suffix in ["examples", "present_examples", "absent_examples"] {
        if metrics[&format!("candidate_heldout_{suffix}")] != metrics[&format!("heldout_{suffix}")] {
            return invalid("Presence candidate held-out counts do not match the baseline counts.");
        }
    }
    if metrics["heldout_examples"] != metrics["heldout_present_examples"] + metrics["heldout_absent_examples"] {
        return invalid("Presence held-out example counts are inconsistent.");
    }
    match metrics.get("average_loss") {
        Some(loss) if loss.is_finite() && *loss >= 0.0 => {}
        _ => return invalid("Presence training average_loss must be finite and non-negative."),
    }
    for name in [
        "exact_match_rate",
        "heldout_exact_match_rate",
        "candidate_heldout_exact_match_rate",
        "heldout_present_recall",
        "candidate_heldout_present_recall",
        "heldout_absent_specificity",
        "candidate_heldout_absent_specificity",
    ] {
        let Some(number) = metrics.get(name) else { return invalid(format!("Presence training update did not report {name}.")) };
        if !number.is_finite() || !(0.0..=1.0).contains(number) {
            return invalid(format!("Presence training update {name} must be finite and within [0, 1]."));
        }
    }
    integral(metrics["exact_match_rate"], metrics["examples"], "training exact match")?;
    rates(metrics, "heldout", "heldout_examples", "heldout_present_examples", "heldout_absent_examples")?;
    rates(
        metrics,
        "candidate_heldout",
        "candidate_heldout_examples",
        "candidate_heldout_present_examples",
        "candidate_heldout_absent_examples",
    )?;
    if metrics["exact_match_rate"] <= minimum {
        return invalid("Presence training exact_match_rate must be greater than the configured minimum.");
    }
    if metrics["candidate_heldout_exact_match_rate"] < metrics["heldout_exact_match_rate"]
        || metrics["candidate_heldout_present_recall"] < metrics["heldout_present_recall"]
        || metrics["candidate_heldout_absent_specificity"] < metrics["heldout_absent_specificity"]
    {
        return invalid("Candidate presence model is worse on the held-out evaluation set.");
    }
    Ok(())
}

/// `train_presence_batch`'s checks of the examples.
fn check_examples(examples: &[PresenceExample], heldout: &[PresenceExample]) -> Result<()> {
    if examples.is_empty() {
        return invalid("At least one presence training example is required.");
    }
    if examples.len() + heldout.len() > 1024 {
        return invalid("Presence training plus held-out examples must not exceed 1024.");
    }
    if examples.iter().chain(heldout).any(|row| row.group_id.is_empty()) {
        return invalid("Presence examples need source group IDs.");
    }
    let groups = |rows: &[PresenceExample]| rows.iter().map(|row| row.group_id.clone()).collect::<BTreeSet<_>>();
    if groups(examples).intersection(&groups(heldout)).next().is_some() {
        return invalid("Presence training and held-out source groups overlap.");
    }
    let texts = |rows: &[PresenceExample]| rows.iter().map(|row| training_text_key(&row.text)).collect::<BTreeSet<_>>();
    if texts(examples).intersection(&texts(heldout)).next().is_some() {
        return invalid("Presence training and held-out normalized texts overlap.");
    }
    Ok(())
}

impl Engine {
    /// `RunPresenceTrainingCycle`: validate, take a slot, run.
    pub async fn run_presence_cycle(&self, request: FuzzerTrainingRequest) -> std::result::Result<FuzzerTrainingResponse, Status> {
        crate::validate::validate_presence_training_request(&request, &self.config.presence_model_id)
            .map_err(|error| Status::invalid_argument(error.0))?;
        let Ok(_permit) = self.slots.try_acquire() else {
            return Err(Status::resource_exhausted("The maximum number of concurrent training cycles is already running."));
        };
        self.presence_cycle(request).await
    }

    async fn presence_cycle(&self, request: FuzzerTrainingRequest) -> std::result::Result<FuzzerTrainingResponse, Status> {
        let config = &self.config;
        let base = resolve_cycle(&request, config);
        let cycle = TrainingCycle { model_id: request.model_id.clone(), ..base };
        let fingerprint = presence_fingerprint(&request);
        if let Some(replayed) = self.previous_stage(&request, &cycle, "presence", &fingerprint).await? {
            return Ok(replayed);
        }
        let dataset = config
            .presence_dataset_path
            .as_deref()
            .ok_or_else(|| precondition("A prepared presence curriculum dataset path is required."))?;
        let (examples, heldout) =
            generate_presence_training_partition(cycle.prompt_count, config.heldout_prompt_count, cycle.seed, dataset)
                .map_err(precondition)?;
        if examples.len() as i64 != cycle.prompt_count || heldout.len() as i64 != config.heldout_prompt_count {
            return Err(precondition("Presence sampler returned counts that do not match the requested partition."));
        }
        let update = self.train_presence(&request, &cycle, &examples, &heldout).await?;
        let dump = config.dump_dir.as_deref();
        let minimum = config.minimum_exact_match_rate;
        if let Err(error) = validate_update(&update, minimum, examples.len(), heldout.len()) {
            persist_evidence(dump, &request, &update, false, None, minimum, &error.0).map_err(precondition)?;
            log(format_args!("rejecting presence training update: {error}"));
            return Err(precondition(error));
        }
        persist_evidence(dump, &request, &update, true, None, minimum, "").map_err(precondition)?;
        let context = PublicationContext {
            request_id: &request.request_id,
            request_source_id: &request.source_id,
            requested_prompt_count: cycle.requested_prompt_count,
            generated_prompt_count: examples.len(),
            pipeline: "client_runtime_presence_gradients",
            fingerprint: &fingerprint,
        };
        let mut extra = context.metadata();
        extra.insert("task".to_string(), "annotation_presence".to_string());
        let message = publication_request(&config.fuzzer_id, &update, &extra, dump, &crate::window::Pins::default())
            .map_err(|error| Status::unknown(format!("Exception calling application: {error}")))?;
        let ack = match self.updates.submit(message).await {
            Ok(ack) => ack,
            Err(status) => {
                log(format_args!("presence parameter update submission failed code={:?}", status.code()));
                return Err(Status::unavailable("Parameter update service is unavailable."));
            }
        };
        persist_evidence(dump, &request, &update, true, Some(&ack), minimum, "")
            .map_err(|error| Status::unknown(format!("Exception calling application: {error}")))?;
        build_training_response(&ack, &update, examples.len()).map_err(precondition)
    }

    /// `_train_presence` over `train_presence_batch` and `compute_presence_gradients`.
    async fn train_presence(
        &self,
        request: &FuzzerTrainingRequest,
        cycle: &TrainingCycle,
        examples: &[PresenceExample],
        heldout: &[PresenceExample],
    ) -> std::result::Result<BatchUpdate, Status> {
        let config = &self.config;
        check_examples(examples, heldout).map_err(precondition)?;
        let wire_request = ComputePresenceGradientsRequest {
            request_id: request.request_id.clone(),
            model_id: cycle.model_id.clone(),
            layers: vec![SEMANTIC_LAYER],
            examples: wire(examples),
            heldout_examples: wire(heldout),
            learning_rate: config.training_learning_rate,
            max_gradient: config.training_max_gradient,
        };
        let dump = config.dump_dir.as_deref();
        let response = match self.runtime.compute_presence_gradients(wire_request.clone()).await {
            Ok(response) => response,
            Err(status) => {
                log(format_args!("client runtime presence training failed: {status}"));
                let empty = ComputePresenceGradientsResponse::default();
                let _ = persist_runtime_attempt(
                    dump,
                    &wire_request,
                    &empty,
                    &evidence(&wire_request, &empty),
                    "unknown",
                    &code_name(status.code()),
                );
                return Err(Status::unavailable(UNAVAILABLE));
            }
        };
        let proof = evidence(&wire_request, &response);
        if let Err(error) = validate_runtime_response(&wire_request, &response) {
            let _ = persist_runtime_attempt(dump, &wire_request, &response, &proof, "rejected", &error.0);
            log(format_args!("client runtime presence training failed: {error}"));
            return Err(Status::unavailable(UNAVAILABLE));
        }
        persist_runtime_attempt(dump, &wire_request, &response, &proof, "execution_validated", "").map_err(|error| {
            log(format_args!("client runtime presence training failed: {error}"));
            Status::unavailable(UNAVAILABLE)
        })?;
        let mut gradients: Vec<(String, Vec<f64>)> = Vec::new();
        let mut shapes: BTreeMap<String, Vec<u32>> = BTreeMap::new();
        for parameter in &response.gradients {
            if gradients.iter().any(|(name, _)| name == &parameter.name) {
                return Err(Status::unavailable(UNAVAILABLE));
            }
            gradients.push((parameter.name.clone(), parameter.values.iter().map(|number| f64::from(*number)).collect()));
            shapes.insert(parameter.name.clone(), parameter.shape.clone());
        }
        if response.model_id != cycle.model_id
            || response.base_version.is_empty()
            || gradients.is_empty()
            || gradients.iter().any(|(name, _)| !name.starts_with("head.presence."))
        {
            return Err(Status::unavailable(UNAVAILABLE));
        }
        let mut metadata: BTreeMap<String, String> = response.metadata.iter().map(|(key, text)| (key.clone(), text.clone())).collect();
        metadata.insert("training_pipeline".to_string(), "client_runtime_presence_gradients".to_string());
        metadata.insert("task".to_string(), "annotation_presence".to_string());
        Ok(BatchUpdate {
            model_id: response.model_id.clone(),
            base_version: response.base_version.clone(),
            gradients,
            shapes,
            metrics: response.metrics.iter().map(|(key, number)| (key.clone(), *number)).collect(),
            metadata,
            execution_evidence: proof,
        })
    }
}
