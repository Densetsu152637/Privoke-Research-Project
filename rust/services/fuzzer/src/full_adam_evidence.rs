//! `training/full_adam_evidence.py`: the opt-in candidate eligibility of a FULL Adam update and the evidence that binds it.
//!
//! [`validate_candidate_route`] re-reads the immutable physical attempt of the runtime call and checks, independently of
//! the cycle's own variables, that the raw request and response, the admission header, the executed phases and the 64-step
//! trace agree with the update. A route that passes selects the candidate TRAIN exact metric ([`eligibility_metric`]), and
//! [`gate_summary`] states the exact guard. [`publication_metadata`] projects the metadata a published update carries and
//! binds it to the retained complete cycle by hash.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use base64::Engine as _;
use privoke_contracts::fingerprint::parameter_fingerprint;
use privoke_contracts::proto::v1::{
    ComputeSemanticGradientsRequest, ComputeSemanticGradientsResponse, DetectionLayer, RuntimeTrainingExample,
};
use privoke_curriculum::value::{self, Value};
use privoke_training::admission::CONFIG_CANONICAL;
use prost::Message;

use crate::error::{Error, Result, invalid};
use crate::full_adam::{
    ELIGIBILITY, ELIGIBILITY_KEY, EXECUTED_KEY, OPTIMIZER_KEY, RETENTION_POLICIES, SUMMARY_KEY, TRACE_KEY, validate_trace,
};
use crate::policy::{ADMISSION_HEADER, FULL_ADAM_POLICY, RETENTION_ELIGIBILITY, parse_training_admission_header};
use crate::runtime::BatchUpdate;

/// `GATE_KEY`.
pub const GATE_KEY: &str = "full_adam_gate_v1";
/// `WEIGHT_KEY`.
pub const WEIGHT_KEY: &str = "full_adam_weight_audit_v1";
/// `WEIGHT_FIELDS`.
pub const WEIGHT_FIELDS: [&str; 9] = [
    "training_clean_examples",
    "training_sensitive_examples",
    "raw_clean_weight",
    "raw_sensitive_weight",
    "raw_total_weight",
    "effective_clean_weight",
    "effective_sensitive_weight",
    "clean_objective_mass",
    "sensitive_objective_mass",
];
/// `TAXONOMY_KEY`.
pub const TAXONOMY_KEY: &str = "full_adam_taxonomy_audit_v1";
/// `TAXONOMY_FIELDS`.
pub const TAXONOMY_FIELDS: [&str; 14] = [
    "sampling_training_rows",
    "sampling_training_unique_texts",
    "sampling_training_groups",
    "sampling_guard_rows",
    "sampling_guard_groups",
    "sampling_sensitivity_counts",
    "sampling_sensitive_visibility_counts",
    "sampling_category_counts",
    "sampling_training_ids_sha256",
    "sampling_training_groups_sha256",
    "sampling_guard_groups_sha256",
    "sampling_expanded_rows",
    "sampling_expanded_unique_texts",
    "sampling_expanded_ids_sha256",
];
const CANDIDATE_METRIC: &str = "candidate_train_exact_match_rate";
const RETENTION_TRACE_KEY: &str = "original_train_retention_trace_v1";
const RETENTION_SUMMARY_KEY: &str = "original_train_retention_summary_v1";
const RETENTION_MANIFEST_KEY: &str = "original_train_retention_manifest_sha256";
const SEMANTIC_LAYER: i32 = DetectionLayer::Semantic as i32;

fn canonical(document: &Value) -> Result<String> {
    Ok(value::dumps_compact(document)?)
}

fn is_retention(optimizer: Option<&str>) -> bool {
    optimizer.is_some_and(|name| RETENTION_POLICIES.contains(&name))
}

/// Whether an update's optimizer is one of the FULL Adam family (`{"full_projected_adam64_v1"} | retention.POLICIES`).
pub fn is_full_adam_family(optimizer: Option<&str>) -> bool {
    optimizer == Some(FULL_ADAM_POLICY) || is_retention(optimizer)
}

fn evidence_text<'a>(evidence: &'a Value, key: &str) -> Result<&'a str> {
    value::get(evidence, key).and_then(value::as_str).ok_or_else(|| Error(format!("'{key}'")))
}

fn evidence_field<'a>(evidence: &'a Value, key: &str) -> Result<&'a Value> {
    value::get(evidence, key).ok_or_else(|| Error(format!("'{key}'")))
}

fn decode(text: &str) -> Result<Vec<u8>> {
    base64::engine::general_purpose::STANDARD.decode(text).map_err(|error| Error(error.to_string()))
}

/// The fingerprint of the tensors an update transports (`parameter_fingerprint(update.gradients, update.parameter_shapes)`).
pub fn update_delta_fingerprint(update: &BatchUpdate) -> Result<String> {
    let values: BTreeMap<String, Vec<f64>> = update.gradients.iter().cloned().collect();
    let shapes: BTreeMap<String, Vec<u64>> =
        update.shapes.iter().map(|(name, shape)| (name.clone(), shape.iter().map(|size| u64::from(*size)).collect())).collect();
    parameter_fingerprint(&values, Some(&shapes)).map_err(|error| Error(error.to_string()))
}

/// `validate_candidate_route(update)`: whether the update opted into candidate eligibility, with every binding verified.
/// Metrics alone can never opt a legacy or HEAD update into it.
pub fn validate_candidate_route(update: &BatchUpdate) -> Result<bool> {
    let meta = &update.metadata;
    let optimizer = meta.get(OPTIMIZER_KEY).map(String::as_str);
    let retention_mode = is_retention(optimizer);
    if !(optimizer == Some(FULL_ADAM_POLICY) || retention_mode) {
        if [ELIGIBILITY_KEY, EXECUTED_KEY, TRACE_KEY, SUMMARY_KEY, RETENTION_TRACE_KEY, RETENTION_SUMMARY_KEY]
            .iter()
            .any(|key| meta.contains_key(*key))
        {
            return invalid("Candidate eligibility evidence requires its explicit artifact optimizer.");
        }
        return Ok(false);
    }
    let evidence = &update.execution_evidence;
    let physical = evidence_text(evidence, "physical_attempt")?;
    let record = value::parse_bytes(&std::fs::read(physical)?)?;
    let request_text = evidence_text(evidence, "request_protobuf_base64")?;
    let response_text = evidence_text(evidence, "response_protobuf_base64")?;
    let raw_request = decode(request_text)?;
    let raw_response = decode(response_text)?;
    let header = value::get(evidence, "invocation_metadata");
    if value::get(&record, "request_protobuf_base64").and_then(value::as_str) != Some(request_text)
        || value::get(&record, "response_protobuf_base64").and_then(value::as_str) != Some(response_text)
        || value::get(&record, "invocation_metadata") != header
        || value::get(&record, "request_protobuf_sha256").and_then(value::as_str) != Some(value::sha256(&raw_request).as_str())
    {
        return invalid("FULL Adam immutable attempt differs from admitted raw evidence/header.");
    }
    let request = ComputeSemanticGradientsRequest::decode(raw_request.as_slice()).map_err(|error| Error(error.to_string()))?;
    let response = ComputeSemanticGradientsResponse::decode(raw_response.as_slice()).map_err(|error| Error(error.to_string()))?;
    let admission = admission_of(header)?;
    let gradients: BTreeMap<&str, Vec<f64>> = response
        .gradients
        .iter()
        .map(|parameter| (parameter.name.as_str(), parameter.values.iter().map(|number| f64::from(*number)).collect()))
        .collect();
    let transported: BTreeMap<&str, &Vec<f64>> = update.gradients.iter().map(|(name, values)| (name.as_str(), values)).collect();
    let shapes: BTreeMap<&str, Vec<u32>> =
        response.gradients.iter().map(|parameter| (parameter.name.as_str(), parameter.shape.clone())).collect();
    let transported_shapes: BTreeMap<&str, &Vec<u32>> = update.shapes.iter().map(|(name, shape)| (name.as_str(), shape)).collect();
    let admitted = admission.as_ref();
    let differs = admitted.is_none_or(|admission| {
        admission.get("expected_optimizer") != optimizer
            || admission.get("expected_candidate_eligibility") != Some(if retention_mode { RETENTION_ELIGIBILITY } else { ELIGIBILITY })
            || admission.get("expected_optimizer_config") != Some(CONFIG_CANONICAL)
            || admission.get("expected_training_scope") != meta.get("training_scope").map(String::as_str)
    }) || request.layers != [SEMANTIC_LAYER]
        || request.request_id != response.request_id
        || request.model_id != response.model_id
        || response.model_id != update.model_id
        || response.base_version != update.base_version
        || !response.error.is_empty()
        || response.metadata.iter().any(|(key, text)| meta.get(key) != Some(text))
        || response.metrics.iter().any(|(key, number)| update.metrics.get(key) != Some(number))
        || gradients.len() != transported.len()
        || gradients.iter().any(|(name, values)| transported.get(name).is_none_or(|other| *other != values))
        || shapes.len() != transported_shapes.len()
        || shapes.iter().any(|(name, shape)| transported_shapes.get(name).is_none_or(|other| *other != shape));
    if differs {
        return invalid("FULL Adam raw response/request/policy/delta binding differs.");
    }
    let scope = meta.get("training_scope").ok_or_else(|| Error("'training_scope'".to_string()))?;
    let rpc = if scope == "full_encoder" { "ComputeUnderlyingModelGradients" } else { "ComputeSemanticGradients" };
    if value::get(evidence, "rpc").and_then(value::as_str) != Some(rpc) {
        return invalid("FULL Adam scope differs from executed RPC.");
    }
    let mut phases = vec![
        ("training", request.examples.len()),
        ("base_heldout", request.heldout_examples.len()),
        ("candidate_heldout", request.heldout_examples.len()),
    ];
    if retention_mode {
        phases.extend(crate::retention::execution_phases(meta)?);
        if admitted.and_then(|admission| admission.get("expected_retention_manifest_sha256"))
            != meta.get(RETENTION_MANIFEST_KEY).map(String::as_str)
        {
            return invalid("Retention raw admission manifest differs.");
        }
        let snapshot = crate::retention::retained_release(evidence_field(evidence, "retention_release")?, &update.model_id)?;
        crate::retention::validate_source_bindings(meta, &snapshot.release)?;
    }
    if response.executions.len() != phases.len()
        || response.executions.iter().zip(phases).any(|(execution, (phase, count))| {
            execution.phase != phase
                || execution.examples as usize != count
                || execution.status != "ok"
                || !execution.error.is_empty()
                || execution.layer != SEMANTIC_LAYER
        })
    {
        return invalid("FULL Adam actual semantic phases differ.");
    }
    let candidate = meta.get("updated_parameter_fingerprint").ok_or_else(|| Error("'updated_parameter_fingerprint'".to_string()))?;
    validate_trace(meta, scope, request.examples.len(), candidate, &update_delta_fingerprint(update)?)?;
    if scope == "heads" {
        return Ok(false);
    }
    let rows = request.examples.len() as f64;
    let exact = update.metrics.get(CANDIDATE_METRIC).copied();
    if !exact.is_some_and(|number| (0.0..=1.0).contains(&number) && (number * rows - (number * rows).round_ties_even()).abs() <= 1e-7) {
        return invalid("FULL Adam candidate TRAIN exact metric/count differs.");
    }
    Ok(true)
}

/// `parse_training_admission_metadata(header or ())`: the expectations the single admission header encodes.
fn admission_of(header: Option<&Value>) -> Result<Option<crate::policy::Expectations>> {
    let pairs: Vec<&Value> = header.and_then(value::as_array).map(|rows| rows.iter().collect()).unwrap_or_default();
    let mut raws: Vec<&str> = Vec::new();
    for pair in pairs {
        if let Some([name, raw]) = value::as_array(pair).map(Vec::as_slice)
            && value::as_str(name) == Some(ADMISSION_HEADER)
            && let Some(text) = value::as_str(raw)
        {
            raws.push(text);
        }
    }
    match raws.as_slice() {
        [] => Ok(None),
        [raw] => Ok(Some(parse_training_admission_header(raw)?)),
        _ => invalid("Duplicate backtracking admission header."),
    }
}

/// `eligibility_metric(update)`.
pub fn eligibility_metric(update: &BatchUpdate) -> Result<&'static str> {
    Ok(if validate_candidate_route(update)? { CANDIDATE_METRIC } else { "exact_match_rate" })
}

/// `gate_summary(update, minimum)`: the authenticated metric choice and the exact strict guard contract, with no prompt data.
pub fn gate_summary(update: &BatchUpdate, minimum: f64) -> Result<Value> {
    if !minimum.is_finite() || !(0.0..=1.0).contains(&minimum) {
        return invalid("Minimum exact match rate must be finite and within [0, 1].");
    }
    let metric = eligibility_metric(update)?;
    let retained = is_retention(update.metadata.get(OPTIMIZER_KEY).map(String::as_str));
    let policy = if retained {
        RETENTION_ELIGIBILITY
    } else if metric == CANDIDATE_METRIC {
        ELIGIBILITY
    } else {
        "base_train_exact_v1"
    };
    let mut pairs = vec![
        ("schema", value::int(if retained { 2 } else { 1 })),
        ("policy", value::string(policy)),
        ("selected_metric", value::string(metric)),
        ("minimum_exact_match_rate", Value::Float(minimum)),
        ("training_predicate", value::string(">")),
        (
            "heldout_predicates",
            value::object(vec![
                ("exact", value::string(">=base")),
                ("sensitive_recall", value::string(">=base")),
                ("clean_specificity", value::string(">=base")),
                ("safety_regression", value::string("<=0")),
                ("sensitive_examples", value::string(">=1_integer")),
                ("clean_examples", value::string(">=1_integer")),
            ]),
        ),
    ];
    if retained {
        let manifest = update.metadata.get(RETENTION_MANIFEST_KEY).ok_or_else(|| Error(format!("'{RETENTION_MANIFEST_KEY}'")))?;
        pairs.push((
            "original_train_per_row_predicates",
            value::strings(&["sensitive", "severity>=min(gold,original)", "action>=min(gold,original)"]),
        ));
        pairs.push(("allowed_violations", value::int(0)));
        pairs.push(("manifest_sha256", value::string(manifest)));
    }
    Ok(value::object(pairs))
}

/// `canonical(gate_summary(update, minimum))`: the text a cycle stores under [`GATE_KEY`].
pub fn gate_text(update: &BatchUpdate, minimum: f64) -> Result<String> {
    canonical(&gate_summary(update, minimum)?)
}

fn string_map_value(map: &BTreeMap<String, String>) -> Value {
    value::from_string_map(map)
}

/// The retained complete record of a cycle, as the cycle persisted it.
fn retained_record(update: &BatchUpdate, extra: &BTreeMap<String, String>, directory: &Path) -> Result<Value> {
    let source = extra.get("request_source_id").ok_or_else(|| Error("'request_source_id'".to_string()))?;
    let request_id = extra.get("request_id").ok_or_else(|| Error("'request_id'".to_string()))?;
    let identity = value::sha256(canonical(&value::strings(&["full_encoder", source.as_str(), request_id.as_str()]))?.as_bytes());
    let base = update.metadata.get("base_parameter_fingerprint").ok_or_else(|| Error("'base_parameter_fingerprint'".to_string()))?;
    let path = directory.join("training-cycles").join(identity).join(format!("{base}.json"));
    Ok(value::parse_bytes(&std::fs::read(path)?)?)
}

/// `publication_metadata(update, metadata, extra, directory)`: the metadata a FULL Adam update publishes. The trace stays in the
/// retained evidence; the weight audit and the sampling audit are packed into one string each, and the retained cycle is
/// bound by `training_evidence_sha256`.
pub fn publication_metadata(
    update: &BatchUpdate,
    metadata: BTreeMap<String, String>,
    extra: &BTreeMap<String, String>,
    directory: Option<&Path>,
) -> Result<BTreeMap<String, String>> {
    if !validate_candidate_route(update)? {
        return Ok(metadata);
    }
    let Some(directory) = directory else {
        return invalid("FULL Adam publication requires durable complete cycle evidence.");
    };
    let retained = retained_record(update, extra, directory)?;
    let evidence = &update.execution_evidence;
    let request_text = evidence_text(evidence, "request_protobuf_base64")?;
    let request = ComputeSemanticGradientsRequest::decode(decode(request_text)?.as_slice()).map_err(|error| Error(error.to_string()))?;
    let gate = update.metadata.get(GATE_KEY).ok_or_else(|| Error(format!("'{GATE_KEY}'")))?;
    let summary = value::parse_bytes(gate.as_bytes())?;
    let minimum = value::get(&summary, "minimum_exact_match_rate")
        .and_then(value::as_number)
        .ok_or_else(|| Error("'minimum_exact_match_rate'".to_string()))?;
    if gate != &gate_text(update, minimum)? {
        return invalid("FULL Adam retained gate policy/config differs.");
    }
    crate::cycle::validate_training_update(update, minimum)?;
    let metrics = Value::Object(update.metrics.iter().map(|(key, number)| (key.clone(), Value::Float(*number))).collect());
    let field = |name: &str| value::get(&retained, name);
    if field("metadata") != Some(&string_map_value(&update.metadata))
        || field("metrics") != Some(&metrics)
        || field("execution_evidence") != Some(evidence)
        || field("gate_passed") != Some(&Value::Bool(true))
        || field("request_id").and_then(value::as_str) != Some(extra.get("request_id").map_or("", String::as_str))
        || request.request_id != extra.get("request_id").map_or("", String::as_str)
        || field("source_id").and_then(value::as_str) != Some(extra.get("request_source_id").map_or("", String::as_str))
        || field("model_id").and_then(value::as_str) != Some(update.model_id.as_str())
        || field("base_version").and_then(value::as_str) != Some(update.base_version.as_str())
        || field("training_stage").and_then(value::as_str) != Some("full_encoder")
        || update.metadata.iter().any(|(key, text)| metadata.get(key) != Some(text))
    {
        return invalid("FULL Adam publication differs from retained cycle/gate/identity.");
    }
    let mut projected = metadata;
    let retention_mode = is_retention(projected.get(OPTIMIZER_KEY).map(String::as_str));
    projected.remove(if retention_mode { RETENTION_TRACE_KEY } else { TRACE_KEY });
    // The exact outgoing string values are preserved; nothing is reformatted.
    let mut weights: BTreeMap<String, String> = BTreeMap::new();
    for key in WEIGHT_FIELDS {
        let text = projected.get(key).ok_or_else(|| Error(format!("'{key}'")))?;
        let metric = update.metrics.get(key).ok_or_else(|| Error(format!("'{key}'")))?;
        if text != &pyfloat_text(*metric)? {
            return invalid("FULL Adam weight audit differs from retained metrics.");
        }
        weights.insert(key.to_string(), text.clone());
    }
    for key in WEIGHT_FIELDS {
        projected.remove(key);
    }
    projected.insert(
        WEIGHT_KEY.to_string(),
        canonical(&value::object(vec![("schema", value::int(1)), ("fields", string_map_value(&weights))]))?,
    );
    match projected.get("contextual_sampling_strategy").map(String::as_str) {
        Some("taxonomy_benign_coverage_v1") => {
            let (path, sha256) = retained_audit_reference(evidence, "benign_audit")?;
            privoke_curriculum::benign::validate_retained_audit(Path::new(&path), &sha256, &projected)?;
            projected = project_audit(projected, &request, &BENIGN)?;
        }
        Some("taxonomy_anchor_rehearsal_v1") => {
            let (path, sha256) = retained_audit_reference(evidence, "rehearsal_audit")?;
            privoke_curriculum::anchor::validate_retained_audit(Path::new(&path), &sha256, &projected)?;
            projected = project_audit(projected, &request, &REHEARSAL)?;
        }
        Some("taxonomy_coverage_v1") => {
            if projected.contains_key(TAXONOMY_KEY) {
                return invalid("FULL Adam taxonomy summary must not overwrite an existing key.");
            }
            let sampled: BTreeSet<&str> = projected.keys().filter(|key| key.starts_with("sampling_")).map(String::as_str).collect();
            if sampled != TAXONOMY_FIELDS.iter().copied().collect::<BTreeSet<_>>() {
                return invalid("FULL Adam taxonomy audit requires its complete exact field allowlist.");
            }
            let dataset = projected.get("taxonomy_dataset_sha256").map_or("", String::as_str);
            if dataset.len() != 64 || !dataset.bytes().all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f')) {
                return invalid("FULL Adam taxonomy audit requires its visible dataset identity.");
            }
            let mut fields: BTreeMap<String, String> = BTreeMap::new();
            for key in TAXONOMY_FIELDS {
                if let Some(text) = projected.remove(key) {
                    fields.insert(key.to_string(), text);
                }
            }
            projected.insert(
                TAXONOMY_KEY.to_string(),
                canonical(&value::object(vec![("schema", value::int(1)), ("fields", string_map_value(&fields))]))?,
            );
        }
        _ => {}
    }
    let bound = value::object(
        ["metadata", "metrics", "execution_evidence", "gate_passed", "request_id", "source_id", "model_id", "base_version"]
            .iter()
            .map(|key| (*key, field(key).cloned().unwrap_or(Value::Null)))
            .collect(),
    );
    projected.insert("training_evidence_sha256".to_string(), value::sha256(canonical(&bound)?.as_bytes()));
    if projected.len() > 64 || projected.values().any(|text| text.len() > 2048) {
        return invalid("FULL Adam publication exceeds unchanged64-entry/2048-byte limits.");
    }
    Ok(projected)
}

/// The packed audit of a sampling strategy: the keys, the extra fields beyond the taxonomy ones, the pins and the messages.
struct AuditShape {
    key: &'static str,
    extra: &'static [&'static str],
    dataset: &'static str,
    pins: &'static [&'static str],
    guard_wire: bool,
    differs: &'static str,
    schema: &'static str,
    lossless: &'static str,
}

/// `BENIGN_KEY`, `BENIGN_FIELDS` and `project_benign_audit`: bind the exact source and the ordered TRAIN and guard wire commitments.
const BENIGN: AuditShape = AuditShape {
    key: "full_adam_benign_audit_v1",
    extra: &[
        "sampling_ordinary_benign_rows",
        "sampling_fiction_rows",
        "sampling_original_order_sha256",
        "sampling_seed",
        "sampling_expanded_wire_sha256",
        "sampling_guard_wire_sha256",
    ],
    dataset: privoke_curriculum::benign::DATASET_SHA256,
    pins: &[privoke_curriculum::benign::POOL_KEY, privoke_curriculum::benign::MANIFEST_KEY, privoke_curriculum::benign::PROOF_KEY],
    guard_wire: true,
    differs: "FULL Adam benign audit/pins/actual ordered TRAIN/guard wire differs.",
    schema: "FULL Adam benign summary schema differs.",
    lossless: "FULL Adam benign summary is not lossless.",
};

/// `REHEARSAL_KEY`, `REHEARSAL_FIELDS` and `project_rehearsal_audit`.
const REHEARSAL: AuditShape = AuditShape {
    key: "full_adam_rehearsal_audit_v1",
    extra: &[
        "sampling_table_version",
        "sampling_anchor_rows",
        "sampling_complement_rows",
        "sampling_anchor_clean_rows",
        "sampling_anchor_sensitive_rows",
        "sampling_original_order_sha256",
        "sampling_seed",
        "sampling_expanded_wire_sha256",
    ],
    dataset: privoke_curriculum::anchor::DATASET_SHA256,
    pins: &[privoke_curriculum::anchor::BANK_KEY, privoke_curriculum::anchor::MANIFEST_KEY],
    guard_wire: false,
    differs: "FULL Adam rehearsal audit/pins/actual wire commitment differs.",
    schema: "FULL Adam rehearsal summary schema differs.",
    lossless: "FULL Adam rehearsal publication summary is not lossless.",
};

/// `wire_commitment(rows)` over the actual protobuf rows: the ordered text, target flag, weight and named target.
fn wire_commitment(rows: &[RuntimeTrainingExample]) -> Result<String> {
    let items: Vec<Value> = rows
        .iter()
        .map(|row| {
            let target = row.target.clone().unwrap_or_default();
            value::object(vec![
                ("text", value::string(&row.text)),
                ("has_target", Value::Bool(row.has_target)),
                ("weight", Value::Float(row.weight)),
                (
                    "target",
                    value::object(vec![
                        ("packed", value::int(i64::from(target.packed))),
                        ("sensitivity", value::string(&target.sensitivity)),
                        ("visibility", value::string(&target.visibility)),
                        ("categories", value::strings(&target.categories)),
                    ]),
                ),
            ])
        })
        .collect();
    Ok(privoke_curriculum::anchor::digest(&Value::Array(items))?)
}

/// `evidence[name]` of a retained sampling audit: its path and checksum.
fn retained_audit_reference(evidence: &Value, name: &str) -> Result<(String, String)> {
    let reference = evidence_field(evidence, name)?;
    let text = |key: &str| value::get(reference, key).and_then(value::as_str).map(str::to_string).ok_or_else(|| Error(format!("'{key}'")));
    Ok((text("path")?, text("sha256")?))
}

fn is_hex64(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

/// `project_benign_audit` and `project_rehearsal_audit`: pack the exact outgoing strings under one key and independently restore
/// them before publication.
fn project_audit(
    metadata: BTreeMap<String, String>,
    request: &ComputeSemanticGradientsRequest,
    shape: &AuditShape,
) -> Result<BTreeMap<String, String>> {
    let fields: BTreeSet<&str> = TAXONOMY_FIELDS.iter().chain(shape.extra).copied().collect();
    let sampled: BTreeSet<&str> = metadata.keys().filter(|key| key.starts_with("sampling_")).map(String::as_str).collect();
    let pinned = shape.pins.iter().all(|key| metadata.get(*key).is_some_and(|text| is_hex64(text.as_str())));
    let expanded_wire = wire_commitment(&request.examples)?;
    let guard_wire_ok = !shape.guard_wire
        || metadata.get("sampling_guard_wire_sha256").map(String::as_str) == Some(wire_commitment(&request.heldout_examples)?.as_str());
    if metadata.contains_key(shape.key)
        || sampled != fields
        || metadata.get("taxonomy_dataset_sha256").map(String::as_str) != Some(shape.dataset)
        || !pinned
        || request.examples.len() != 64
        || request.heldout_examples.len() != 16
        || metadata.get("sampling_expanded_wire_sha256").map(String::as_str) != Some(expanded_wire.as_str())
        || !guard_wire_ok
    {
        return invalid(shape.differs);
    }
    let mut projected = metadata.clone();
    let mut packed: BTreeMap<String, String> = BTreeMap::new();
    for key in &fields {
        if let Some(text) = projected.remove(*key) {
            packed.insert((*key).to_string(), text);
        }
    }
    let text = canonical(&value::object(vec![("schema", value::int(1)), ("fields", string_map_value(&packed))]))?;
    projected.insert(shape.key.to_string(), text.clone());
    let mut restored = projected.clone();
    restored.remove(shape.key);
    let document = value::parse_bytes(text.as_bytes())?;
    let restored_fields = value::get(&document, "fields").and_then(value::string_map);
    let schema_ok = value::as_object(&document).is_some_and(|map| map.len() == 2)
        && value::get(&document, "schema") == Some(&value::int(1))
        && restored_fields.as_ref().is_some_and(|map| map.keys().map(String::as_str).collect::<BTreeSet<_>>() == fields);
    if !schema_ok {
        return invalid(shape.schema);
    }
    restored.extend(restored_fields.unwrap_or_default());
    if restored != metadata {
        return invalid(shape.lossless);
    }
    Ok(projected)
}

fn pyfloat_text(number: f64) -> Result<String> {
    privoke_contracts::pyfloat::repr(number).map_err(|error| Error(error.to_string()))
}
