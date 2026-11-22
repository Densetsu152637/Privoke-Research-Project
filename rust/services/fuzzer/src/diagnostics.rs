//! The TRAIN diagnostics and the FULL backtracking evidence a runtime reports with its gradients, and their admission:
//! `contextual_training.validate_training_diagnostics`, `validate_backtracking_trace` and `runtime_client.validate_backtracking_response`.
//!
//! The evidence is a handful of bounded JSON strings in the response metadata (the prompt-free TRAIN diagnostics record, the
//! backtracking trace header and its five trials). Each validator accepts exactly the documents the Python one accepts.
//! Python reports a refusal with a specific message; every path of [`validate_backtracking_response`] ends in the single
//! `RuntimeAnalysisError` of the caller, so the messages here only help a reader.
//!
//! JSON that holds `NaN` or an infinity (which `json.loads` accepts and the validators then refuse at the first finite check) is
//! refused by the parser instead: the same verdict, since the only positions that skip the finite check are the nulls of an
//! `invalid_numeric` trial.

use privoke_contracts::json::{self, Duplicates, ParseOptions, Value};
use privoke_contracts::proto::v1::{ComputeSemanticGradientsRequest, ComputeSemanticGradientsResponse, DetectionLayer};
use privoke_curriculum::classification::Classification;
use privoke_curriculum::value;
use privoke_training::objective::fsum;

use crate::error::{Error, Result, invalid};
use crate::policy::{Expectations, PROCESS_OBJECTIVES, SUM_MARGIN};
use crate::runtime::{FULL_ENCODER_STRATEGY, exact_labels, full_encoder_tensor_shapes};

/// `DIAGNOSTICS_POLICY_KEY`.
pub const DIAGNOSTICS_POLICY_KEY: &str = "contextual_training_diagnostics_policy";
/// `DIAGNOSTICS_KEY`.
pub const DIAGNOSTICS_KEY: &str = "contextual_training_diagnostics";
/// `TRAIN_DIAGNOSTICS_POLICY`.
pub const TRAIN_DIAGNOSTICS_POLICY: &str = "train_before_candidate_v1";
/// `EXECUTED_OBJECTIVE_KEY`.
pub const EXECUTED_OBJECTIVE_KEY: &str = "executed_contextual_training_objective";
/// `BACKTRACKING_KEY`.
pub const BACKTRACKING_KEY: &str = "contextual_training_backtracking_policy";
/// `BACKTRACKING_POLICY`.
pub const BACKTRACKING_POLICY: &str = "full_train_backtracking_v1";
/// `BACKTRACKING_PREPARATION_KEY`.
pub const BACKTRACKING_PREPARATION_KEY: &str = "contextual_training_backtracking_preparation";
/// `BACKTRACKING_TRACE_KEY`.
pub const BACKTRACKING_TRACE_KEY: &str = "contextual_training_backtracking_trace";
/// `BACKTRACKING_TRIALS_KEY`.
pub const BACKTRACKING_TRIALS_KEY: &str = "contextual_training_backtracking_trials";
/// `BACKTRACKING_REJECTION`: the typed error of a known one-fit rejection.
pub const BACKTRACKING_REJECTION: &str = "TRAIN_BACKTRACKING_NO_IMPROVEMENT_V1";
/// `BACKTRACKING_SCALES`.
const BACKTRACKING_SCALES: [f64; 5] = [1.0, 0.25, 0.0625, 0.015_625, 0.003_906_25];
/// `BACKTRACKING_DECREASE`.
const BACKTRACKING_DECREASE: f64 = 0.000_02;
const LOSS_COLUMNS: [&str; 4] = ["sensitivity_ce", "visibility_ce", "category_sum_bce", "objective"];
const SUM_MARGIN_LOSS_COLUMNS: [&str; 5] = ["sensitivity_ce", "visibility_ce", "category_sum_bce", "decision_margin_bce", "objective"];
const ACCURACY_COLUMNS: [&str; 6] =
    ["exact", "sensitivity_exact", "visibility_exact", "category_set_exact", "clean_specificity", "sensitive_recall"];
const UPDATE_COLUMNS: [&str; 4] = ["coordinates", "strictly_clipped", "raw_abs_max", "transported_abs_max"];
static NULL: Value = Value::Null;
const SEMANTIC_LAYER: i32 = DetectionLayer::Semantic as i32;
const RETENTION_OBJECTIVES: [&str; 2] =
    ["class_balanced_contextual_sum_margin_original_gate_v1", "class_balanced_contextual_sum_margin_original_hinge_v1"];

fn is_hex64(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

/// `training_loss_contract(objective)`: the schema and the loss columns of an objective.
fn loss_contract(objective: Option<&str>) -> Result<(i64, &'static [&'static str])> {
    let Some(objective) = objective.filter(|name| PROCESS_OBJECTIVES.contains(name)) else {
        return invalid("Unsupported TRAIN process objective.");
    };
    Ok(if objective == SUM_MARGIN || RETENTION_OBJECTIVES.contains(&objective) {
        (2, &SUM_MARGIN_LOSS_COLUMNS[..])
    } else {
        (1, &LOSS_COLUMNS[..])
    })
}

/// `_bounded_training_json(raw)`: at most 2048 bytes, no repeated field.
fn bounded_json(raw: Option<&str>, budget: &str) -> Result<Value> {
    let Some(raw) = raw.filter(|text| text.len() <= 2048) else { return invalid(budget) };
    json::parse_with(raw, ParseOptions { duplicates: Duplicates::Reject, ..ParseOptions::default() })
        .map_err(|error| Error(error.to_string()))
}

/// An `int` (a boolean is not).
fn int_of(item: &Value) -> Option<i64> {
    match item {
        Value::Int(digits) => digits.parse().ok(),
        _ => None,
    }
}

/// `type(x) in (int, float)`.
fn number_of(item: &Value) -> Option<f64> {
    match item {
        Value::Int(digits) => digits.parse().ok(),
        Value::Float(number) => Some(*number),
        _ => None,
    }
}

/// `type(x) in (int, float) and math.isfinite(x) and x >= 0`.
fn finite_non_negative(item: &Value) -> bool {
    number_of(item).is_some_and(|number| number.is_finite() && number >= 0.0)
}

fn is_sha(item: &Value) -> bool {
    value::as_str(item).is_some_and(is_hex64)
}

/// `math.isclose(a, b, rel_tol=1e-10, abs_tol=1e-10)` for finite numbers.
fn is_close(left: f64, right: f64) -> bool {
    let tolerance = (1e-10 * left.abs().max(right.abs())).max(1e-10);
    (left - right).abs() <= tolerance
}

/// Python's `==` on parsed JSON: an `int` equals the `float` of the same value.
fn same(left: &Value, right: &Value) -> bool {
    match (left, right) {
        (Value::Int(a), Value::Int(b)) => a == b,
        (Value::Array(a), Value::Array(b)) => a.len() == b.len() && a.iter().zip(b).all(|(x, y)| same(x, y)),
        (Value::Object(a), Value::Object(b)) => a.len() == b.len() && a.iter().all(|(key, x)| b.get(key).is_some_and(|y| same(x, y))),
        (Value::Int(_) | Value::Float(_), Value::Int(_) | Value::Float(_)) => number_of(left) == number_of(right),
        _ => left == right,
    }
}

fn strings_equal(item: &Value, expected: &[&str]) -> bool {
    value::as_array(item)
        .is_some_and(|rows| rows.len() == expected.len() && rows.iter().zip(expected).all(|(row, name)| value::as_str(row) == Some(*name)))
}

/// A finite non-negative number list whose last entry is the `math.fsum` of the others (`isclose` within 1e-10).
fn reconciled(row: &Value, columns: usize) -> bool {
    let Some(items) = value::as_array(row) else { return false };
    if items.len() != columns || !items.iter().all(finite_non_negative) {
        return false;
    }
    let numbers: Vec<f64> = items.iter().filter_map(number_of).collect();
    let (last, rest) = numbers.split_last().map_or((0.0, &[][..]), |(last, rest)| (*last, rest));
    is_close(fsum(rest.iter().copied()), last)
}

/// `validate_training_diagnostics(raw, objective=..., examples=..., base_fingerprint=..., candidate_fingerprint=...)`: admit a
/// bounded prompt-free semantic TRAIN record for the exact transported state.
pub fn validate_training_diagnostics(
    raw: Option<&str>,
    objective: Option<&str>,
    examples: usize,
    base_fingerprint: &str,
    candidate_fingerprint: &str,
) -> Result<Value> {
    let record = bounded_json(raw, "TRAIN diagnostics exceed their byte budget or are missing.")?;
    let (schema, loss_columns) = loss_contract(objective)?;
    let names = [
        "schema",
        "objective",
        "fingerprints",
        "phases",
        "counts",
        "loss_columns",
        "loss",
        "accuracy_columns",
        "accuracy",
        "update_columns",
        "update",
    ];
    let keys_match =
        value::as_object(&record).is_some_and(|map| map.len() == names.len() && names.iter().all(|name| map.contains_key(*name)));
    if !keys_match || value::get(&record, "schema").and_then(int_of) != Some(schema) {
        return invalid("Unknown TRAIN diagnostics schema.");
    }
    let field = |name: &str| value::get(&record, name).unwrap_or(&NULL);
    let count = i64::try_from(examples).unwrap_or(i64::MAX);
    let phases = Value::Array(vec![
        Value::Array(vec![value::string("base_training"), value::string("semantic"), value::string("ok"), value::int(count)]),
        Value::Array(vec![value::string("candidate_training"), value::string("semantic"), value::string("ok"), value::int(count)]),
    ]);
    if value::as_str(field("objective")) != objective
        || !same(field("fingerprints"), &value::strings(&[base_fingerprint, candidate_fingerprint]))
        || !same(field("phases"), &phases)
    {
        return invalid("TRAIN diagnostic policy, identity or semantic execution differs.");
    }
    let counts: Option<Vec<i64>> = value::as_array(field("counts")).and_then(|items| items.iter().map(int_of).collect());
    match counts.as_deref() {
        Some([total, clean, sensitive]) if *total > 0 && *clean > 0 && *sensitive > 0 && *total == count && clean + sensitive == count => {}
        _ => return invalid("TRAIN diagnostic strata counts are invalid."),
    }
    for (key, columns) in [("loss", loss_columns), ("accuracy", &ACCURACY_COLUMNS[..])] {
        let rows = value::as_array(field(key));
        if !strings_equal(field(format!("{key}_columns").as_str()), columns) || rows.is_none_or(|rows| rows.len() != 2) {
            return invalid("TRAIN diagnostic columns are invalid.");
        }
        for row in rows.into_iter().flatten() {
            let ok = value::as_array(row).is_some_and(|items| {
                items.len() == columns.len()
                    && items.iter().all(finite_non_negative)
                    && (key != "accuracy" || items.iter().filter_map(number_of).all(|number| number <= 1.0))
            });
            if !ok {
                return invalid("TRAIN diagnostic values are invalid.");
            }
            if key == "loss" && !reconciled(row, columns.len()) {
                return invalid("TRAIN diagnostic objective does not reconcile.");
            }
        }
    }
    let update = value::as_array(field("update"));
    let update_ok = strings_equal(field("update_columns"), &UPDATE_COLUMNS)
        && update.is_some_and(|items| {
            items.len() == 4
                && items[..2].iter().all(|item| int_of(item).is_some_and(|number| number >= 0))
                && int_of(&items[0])
                    .is_some_and(|coordinates| coordinates > 0 && int_of(&items[1]).is_some_and(|clipped| clipped <= coordinates))
                && items[2..].iter().all(finite_non_negative)
        });
    if !update_ok {
        return invalid("TRAIN diagnostic update summary is invalid.");
    }
    Ok(record)
}

/// `runtime_client.validate_training_policy_response`'s TRAIN diagnostics branch, with the response's own identities and the
/// sensitive and clean counts of the actual request rows.
pub fn validate_response_diagnostics(request: &ComputeSemanticGradientsRequest, response: &ComputeSemanticGradientsResponse) -> Result<()> {
    let metadata = &response.metadata;
    let get = |key: &str| metadata.get(key).map(String::as_str).ok_or_else(|| Error(format!("'{key}'")));
    let record = validate_training_diagnostics(
        metadata.get(DIAGNOSTICS_KEY).map(String::as_str),
        metadata.get(EXECUTED_OBJECTIVE_KEY).map(String::as_str),
        request.examples.len(),
        get("base_parameter_fingerprint")?,
        get("updated_parameter_fingerprint")?,
    )?;
    let mut sensitive = 0_i64;
    for item in &request.examples {
        let target = item.target.as_ref().filter(|_| item.has_target);
        let packed = target.map(|target| u16::try_from(target.packed)).transpose().map_err(|error| Error(error.to_string()))?;
        let Some(packed) = packed else { return invalid("TRAIN diagnostic actual target counts differ.") };
        sensitive += i64::from(Classification(packed).is_sensitive());
    }
    let total = i64::try_from(request.examples.len()).unwrap_or(i64::MAX);
    let expected = Value::Array(vec![value::int(total), value::int(total - sensitive), value::int(sensitive)]);
    if !same(value::get(&record, "counts").unwrap_or(&NULL), &expected) {
        return invalid("TRAIN diagnostic actual target counts differ.");
    }
    Ok(())
}

/// The validated trace: its header and its trials.
struct Trace {
    header: Value,
    trials: Vec<Value>,
}

/// `validate_backtracking_trace(metadata, examples=..., requested_rate=..., rejected=...)`: compact bounded trials, without
/// accepting non-finite arithmetic.
fn validate_backtracking_trace(
    metadata: &std::collections::BTreeMap<String, String>,
    examples: usize,
    requested_rate: f64,
    rejected: bool,
) -> Result<Trace> {
    let header = bounded_json(metadata.get(BACKTRACKING_TRACE_KEY).map(String::as_str), "Training policy JSON exceeds its byte budget.")?;
    let trials = bounded_json(metadata.get(BACKTRACKING_TRIALS_KEY).map(String::as_str), "Training policy JSON exceeds its byte budget.")?;
    let objective = metadata.get(EXECUTED_OBJECTIVE_KEY).map(String::as_str);
    let (schema, columns) = loss_contract(objective)?;
    let mut keys = vec!["schema", "policy", "objective", "base", "raw", "selected", "gradient_fits"];
    if schema == 2 {
        keys.push("loss_columns");
    }
    let schema_error = || invalid::<Trace>("Invalid backtracking trace schema.");
    let header_keys_match =
        value::as_object(&header).is_some_and(|map| map.len() == keys.len() && keys.iter().all(|key| map.contains_key(*key)));
    let field = |name: &str| value::get(&header, name).unwrap_or(&NULL);
    let trial_rows = value::as_array(&trials);
    if !header_keys_match
        || int_of(field("schema")) != Some(schema)
        || (schema == 2 && !strings_equal(field("loss_columns"), columns))
        || value::as_str(field("policy")) != Some(BACKTRACKING_POLICY)
        || int_of(field("gradient_fits")) != Some(1)
        || value::as_str(field("objective")) != objective
        || !trial_rows.is_some_and(|rows| (1..=5).contains(&rows.len()))
    {
        return schema_error();
    }
    let trial_rows = trial_rows.cloned().unwrap_or_default();
    let (base, raw) = (field("base"), field("raw"));
    let audit_error = || invalid::<Trace>("Invalid backtracking base/raw-gradient audit.");
    let (Some(base_items), Some(raw_items)) = (value::as_array(base), value::as_array(raw)) else { return audit_error() };
    if base_items.len() != 2 || raw_items.len() != 5 {
        return audit_error();
    }
    let base_losses = &base_items[1];
    let base_ok = is_sha(&base_items[0])
        && value::as_str(&base_items[0]) == metadata.get("base_parameter_fingerprint").map(String::as_str)
        && reconciled(base_losses, columns.len());
    let raw_ok = is_sha(&raw_items[0])
        && is_sha(&raw_items[1])
        && value::as_str(&raw_items[1]) == metadata.get("trained_parameter_inventory_fingerprint").map(String::as_str)
        && int_of(&raw_items[2]).is_some_and(|coordinates| coordinates > 0)
        && raw_items[3..].iter().all(finite_non_negative);
    if !base_ok || !raw_ok {
        return audit_error();
    }
    let raw_coordinates = int_of(&raw_items[2]).unwrap_or(0);
    let base_objective = value::as_array(base_losses).and_then(|items| items.last()).and_then(number_of).unwrap_or(f64::NAN);
    let examples = i64::try_from(examples).unwrap_or(i64::MAX);
    let mut improving: Vec<usize> = Vec::new();
    for (index, row) in trial_rows.iter().enumerate() {
        let Some(items) = value::as_array(row).filter(|items| items.len() == 11) else {
            return invalid("Invalid backtracking trial rate/shape.");
        };
        let rate = number_of(&items[0]);
        if !rate.is_some_and(|rate| rate.is_finite() && rate > 0.0 && rate == requested_rate * BACKTRACKING_SCALES[index]) {
            return invalid("Invalid backtracking trial rate/shape.");
        }
        let status = value::as_str(&items[7]);
        let completed = int_of(&items[8]);
        let attempted = int_of(&items[10]);
        if !matches!(status, Some("ok" | "invalid_numeric"))
            || !completed.is_some_and(|rows| rows == 0 || rows == examples)
            || !matches!(items[9], Value::Bool(_))
            || !attempted.is_some_and(|rows| rows == 0 || rows == examples)
            || completed > attempted
        {
            return invalid("Invalid backtracking trial execution.");
        }
        if status == Some("invalid_numeric") {
            let bad = !matches!(items[1], Value::Null)
                || (!matches!(items[2], Value::Null) && !int_of(&items[2]).is_some_and(|clipped| (0..=raw_coordinates).contains(&clipped)))
                || items[3..5].iter().any(|item| !matches!(item, Value::Null) && !finite_non_negative(item))
                || items[5..7].iter().any(|item| !matches!(item, Value::Null) && !is_sha(item));
            if bad {
                return invalid("Invalid numeric trial must have null loss.");
            }
            continue;
        }
        if !reconciled(&items[1], columns.len())
            || !int_of(&items[2]).is_some_and(|clipped| (0..=raw_coordinates).contains(&clipped))
            || !items[3..5].iter().all(finite_non_negative)
            || !items[5..7].iter().all(is_sha)
            || completed != Some(examples)
        {
            return invalid("Invalid backtracking trial values.");
        }
        let candidate_objective = value::as_array(&items[1]).and_then(|losses| losses.last()).and_then(number_of).unwrap_or(f64::NAN);
        if base_objective - candidate_objective > BACKTRACKING_DECREASE && matches!(items[9], Value::Bool(true)) {
            improving.push(index);
        }
    }
    let selected = field("selected");
    if rejected {
        if !matches!(selected, Value::Null) || !improving.is_empty() || trial_rows.len() != 5 {
            return invalid("No-improvement rejection contradicts trial evidence.");
        }
    } else {
        let chosen = int_of(selected).and_then(|index| usize::try_from(index).ok());
        let ok = chosen.is_some_and(|index| {
            let trial = value::as_array(&trial_rows[index.min(trial_rows.len() - 1)]).cloned().unwrap_or_default();
            improving == [index]
                && index == trial_rows.len() - 1
                && metadata.get("effective_learning_rate").map(String::as_str) == Some(number_text(trial.first()).as_str())
                && metadata.get("updated_parameter_fingerprint").map(String::as_str) == trial.get(6).and_then(value::as_str)
        });
        if !ok {
            return invalid("Selected backtracking trial differs from first improvement.");
        }
    }
    Ok(Trace { header, trials: trial_rows })
}

/// `str(x)` of a parsed JSON number.
fn number_text(item: Option<&Value>) -> String {
    match item {
        Some(Value::Int(digits)) => digits.clone(),
        Some(Value::Float(number)) => privoke_contracts::pyfloat::repr(*number).unwrap_or_default(),
        _ => String::new(),
    }
}

/// `runtime_client.validate_backtracking_response(request, response, expectations, rejected=...)`: every failure is the
/// caller's `RuntimeAnalysisError`.
pub fn validate_backtracking_response(
    request: &ComputeSemanticGradientsRequest,
    response: &ComputeSemanticGradientsResponse,
    expectations: &Expectations,
    rejected: bool,
) -> Result<()> {
    backtracking_evidence(request, response, expectations, rejected)
        .map_err(|_| Error("Runtime backtracking evidence failed admission.".to_string()))
}

fn backtracking_evidence(
    request: &ComputeSemanticGradientsRequest,
    response: &ComputeSemanticGradientsResponse,
    expectations: &Expectations,
    rejected: bool,
) -> Result<()> {
    let meta = &response.metadata;
    let text = |key: &str| meta.get(key).map(String::as_str);
    let required = |key: &str| text(key).ok_or_else(|| Error(format!("'{key}'")));
    let rate_text = privoke_contracts::pyfloat::repr(request.learning_rate).map_err(|error| Error(error.to_string()))?;
    if response.request_id != request.request_id
        || response.model_id != request.model_id
        || response.base_version.is_empty()
        || request.layers != [SEMANTIC_LAYER]
        || text(BACKTRACKING_KEY) != expectations.get("expected_backtracking_policy")
        || text(BACKTRACKING_KEY) != Some(BACKTRACKING_POLICY)
        || text(BACKTRACKING_PREPARATION_KEY) != expectations.get("expected_backtracking_preparation_sha256")
        || text(EXECUTED_OBJECTIVE_KEY) != expectations.get("expected_objective")
        || text(DIAGNOSTICS_POLICY_KEY) != expectations.get("expected_diagnostics_policy")
        || text("training_scope") != Some("full_encoder")
        || text("learning_rate") != Some(rate_text.as_str())
    {
        return invalid("Backtracking response policy/rate identity differs.");
    }
    let config = json::parse(required("model_config")?).map_err(|error| Error(error.to_string()))?;
    let shapes = full_encoder_tensor_shapes(&config)?;
    if text("strategy") != Some(FULL_ENCODER_STRATEGY)
        || text("artifact_training_strategy") != Some(FULL_ENCODER_STRATEGY)
        || text("underlying_training_available") != Some("true")
        || ["artifact_checksum", "base_parameter_fingerprint"].iter().any(|key| !text(key).is_some_and(is_hex64))
        || response.metrics.values().any(|number| !number.is_finite())
    {
        return invalid("Backtracking response capability/base/numeric identity differs.");
    }
    if ["sensitivity", "visibility", "category"].iter().any(|task| !exact_labels(&config, task)) {
        return invalid("Backtracking classification label inventory differs.");
    }
    let declared = json::parse(required("trained_parameter_names")?).map_err(|error| Error(error.to_string()))?;
    let expected_names = Value::Array(shapes.keys().map(|name| Value::String(name.clone())).collect());
    let empty: std::collections::BTreeMap<String, Vec<f64>> = shapes.keys().map(|name| (name.clone(), Vec::new())).collect();
    let inventory =
        privoke_contracts::fingerprint::parameter_fingerprint(&empty, Some(&shapes)).map_err(|error| Error(error.to_string()))?;
    if declared != expected_names || required("trained_parameter_inventory_fingerprint")? != inventory {
        return invalid("Backtracking raw gradient inventory differs.");
    }
    let Trace { header, trials } = validate_backtracking_trace(meta, request.examples.len(), request.learning_rate, rejected)?;
    let coordinates: u64 = shapes.values().map(|shape| shape.iter().product::<u64>()).sum();
    let raw = value::get(&header, "raw").and_then(value::as_array).ok_or_else(|| Error("'raw'".to_string()))?;
    if int_of(&raw[2]).and_then(|number| u64::try_from(number).ok()) != Some(coordinates) {
        return invalid("Backtracking raw coordinate count differs.");
    }
    let rows: Vec<&Vec<Value>> = trials.iter().filter_map(value::as_array).collect();
    let sum = |index: usize| rows.iter().filter_map(|row| int_of(&row[index])).sum::<i64>() as f64;
    let metric = |name: &str| response.metrics.get(name).copied();
    if metric("gradient_fits") != Some(1.0)
        || metric("backtracking_trials") != Some(rows.len() as f64)
        || metric("backtracking_semantic_examples") != Some(sum(8))
        || metric("backtracking_forward_attempts")
            != Some(rows.iter().filter(|row| int_of(&row[10]).is_some_and(|attempted| attempted > 0)).count() as f64)
        || metric("backtracking_attempted_semantic_examples") != Some(sum(10))
    {
        return invalid("Backtracking physical/trial accounting differs.");
    }
    if rejected {
        let execution_ok = response.executions.len() == 1
            && response.executions.first().is_some_and(|execution| {
                execution.phase == "training"
                    && execution.layer == SEMANTIC_LAYER
                    && execution.status == "ok"
                    && execution.error.is_empty()
                    && execution.examples as usize == request.examples.len()
            });
        if response.error != BACKTRACKING_REJECTION
            || !response.gradients.is_empty()
            || !execution_ok
            || response.metrics.keys().any(|key| key.starts_with("heldout_") || key.starts_with("candidate_heldout_"))
            || meta.contains_key("updated_parameter_fingerprint")
            || meta.contains_key("effective_learning_rate")
            || meta.contains_key(DIAGNOSTICS_KEY)
        {
            return invalid("Known rejection falsely claims a selected step or guard.");
        }
        return Ok(());
    }
    let selected = value::get(&header, "selected")
        .and_then(int_of)
        .and_then(|index| usize::try_from(index).ok())
        .ok_or_else(|| Error("'selected'".to_string()))?;
    let trial = rows.get(selected).ok_or_else(|| Error("trial".to_string()))?;
    let delta: std::collections::BTreeMap<String, Vec<f64>> = response
        .gradients
        .iter()
        .map(|parameter| (parameter.name.clone(), parameter.values.iter().map(|number| f64::from(*number)).collect()))
        .collect();
    let fingerprint =
        privoke_contracts::fingerprint::parameter_fingerprint(&delta, Some(&shapes)).map_err(|error| Error(error.to_string()))?;
    if value::as_str(&trial[5]) != Some(fingerprint.as_str()) {
        return invalid("Selected transported delta differs from trace.");
    }
    let diagnostic = json::parse(required(DIAGNOSTICS_KEY)?).map_err(|error| Error(error.to_string()))?;
    let base_losses = value::get(&header, "base").and_then(value::as_array).map(|items| items[1].clone()).unwrap_or(Value::Null);
    let expected_loss = Value::Array(vec![base_losses, trial[1].clone()]);
    if !same(value::get(&diagnostic, "loss").unwrap_or(&NULL), &expected_loss) {
        return invalid("Selected TRAIN diagnostics differ from trial losses.");
    }
    Ok(())
}
