//! `validate_publication` of `privoke_model.window_training`: the updater's boundary for the opt-in frozen TRAIN
//! window and checkpoint policy. A window-policy artifact accepts only a complete, exactly bound, selected-checkpoint
//! publication; any other artifact accepts only a request that does not claim the policy.
//!
//! The text of every refusal is the Python one. `==` on JSON numbers is Python's loose numeric equality (`1 == 1.0`,
//! `0 == False`); `type(x) is int` is strict.

use std::collections::BTreeMap;

use privoke_contracts::canonical::{self, Variant};
use privoke_contracts::fingerprint::parameter_fingerprint;
use privoke_contracts::json::{self, Value};
use privoke_contracts::proto::v1::ParameterUpdateRequest;
use privoke_model_streaming::artifact::ModelArtifact;
use privoke_model_streaming::contextual::{
    CANDIDATE_ELIGIBILITY_KEY, CLASS_BALANCED_SUM_DECISION_MARGIN_OBJECTIVE, COMPONENT_MANIFEST_KEY, FULL_ADAM_CONFIG_KEY,
    FULL_ENCODER_STRATEGY, OBJECTIVE_KEY, OPTIMIZER_KEY, RETENTION_MANIFEST_KEY, STRATEGY_KEY, WINDOW_ADAM, WINDOW_CONFIG,
    WINDOW_CONFIG_KEY, WINDOW_ELIGIBILITY, WINDOW_MANIFEST_KEY,
};

use crate::error::Failure;
use crate::pyfmt::{float32, round8};

/// The metadata key that carries the compact selected-checkpoint summary.
pub const SUMMARY_KEY: &str = "train_window_summary_v1";
const SUMMARY_FIELDS: [&str; 19] = [
    "schema",
    "policy",
    "trace_sha256",
    "window",
    "references",
    "base",
    "terminal",
    "selected",
    "selected_step",
    "delta",
    "published",
    "status",
    "reason",
    "main_rows",
    "auxiliary_rows",
    "checkpoint_rows",
    "violations",
    "guard_passed",
    "sensitive_progress",
];
const CHECKPOINTS: [i64; 8] = [8, 16, 24, 32, 40, 48, 56, 64];

fn is_sha256(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

fn is_sha256_value(value: Option<&Value>) -> bool {
    matches!(value, Some(Value::String(text)) if is_sha256(text))
}

/// Python `value == number` for a JSON value.
fn loosely_equals(value: Option<&Value>, number: i64) -> bool {
    match value {
        Some(Value::Int(digits)) => digits.parse::<i64>().is_ok_and(|parsed| parsed == number),
        Some(Value::Float(float)) => *float == number as f64,
        Some(Value::Bool(flag)) => i64::from(*flag) == number,
        _ => false,
    }
}

/// `type(value) is int`.
fn strict_int(value: Option<&Value>) -> Option<i64> {
    match value {
        Some(Value::Int(digits)) => digits.parse::<i64>().ok(),
        _ => None,
    }
}

fn text_equals(value: Option<&Value>, expected: &str) -> bool {
    matches!(value, Some(Value::String(text)) if text == expected)
}

/// `validate_policy`: whether the metadata activates the window policy, refusing orphan or mixed policy keys.
pub fn validate_policy(metadata: &BTreeMap<String, String>) -> Result<bool, Failure> {
    let get = |key: &str| metadata.get(key).map(String::as_str);
    if get(OPTIMIZER_KEY) != Some(WINDOW_ADAM) {
        if [WINDOW_CONFIG_KEY, WINDOW_MANIFEST_KEY, COMPONENT_MANIFEST_KEY].iter().any(|key| metadata.contains_key(*key)) {
            return Err(Failure::invalid("Orphan window/checkpoint artifact policy."));
        }
        return Ok(false);
    }
    let pins_ok = [WINDOW_MANIFEST_KEY, COMPONENT_MANIFEST_KEY].iter().all(|key| get(key).is_some_and(is_sha256));
    let mixed =
        ["contextual_training_backtracking_policy", "contextual_training_diagnostics_policy", FULL_ADAM_CONFIG_KEY, RETENTION_MANIFEST_KEY]
            .iter()
            .any(|key| metadata.contains_key(*key));
    if get(STRATEGY_KEY) != Some(FULL_ENCODER_STRATEGY)
        || get(OBJECTIVE_KEY) != Some(CLASS_BALANCED_SUM_DECISION_MARGIN_OBJECTIVE)
        || get(CANDIDATE_ELIGIBILITY_KEY) != Some(WINDOW_ELIGIBILITY)
        || get(WINDOW_CONFIG_KEY) != Some(WINDOW_CONFIG)
        || !pins_ok
        || mixed
    {
        return Err(Failure::invalid("Window policy requires exact exclusive FULL optimizer/objective/config/pins."));
    }
    Ok(true)
}

fn summary_invalid() -> Failure {
    Failure::invalid("Invalid selected-versus-terminal checkpoint publication evidence.")
}

/// `validate_publication(request, artifact)`.
pub fn validate_publication(request: &ParameterUpdateRequest, artifact: &ModelArtifact) -> Result<(), Failure> {
    if !validate_policy(artifact.metadata())? {
        if request.metadata.get(OPTIMIZER_KEY).map(String::as_str) == Some(WINDOW_ADAM) {
            return Err(Failure::invalid("Window publication requires its actual prepared artifact policy."));
        }
        return Ok(());
    }
    validate_policy(&request.metadata)?;
    for key in [WINDOW_CONFIG_KEY, WINDOW_MANIFEST_KEY, COMPONENT_MANIFEST_KEY] {
        if request.metadata.get(key) != artifact.metadata().get(key) {
            return Err(Failure::invalid("Selected publication differs from prepared artifact source/config pins."));
        }
    }
    let raw = match request.metadata.get(SUMMARY_KEY) {
        Some(raw) if raw.len() <= 2048 => raw,
        _ => return Err(Failure::invalid("Missing compact selected checkpoint publication summary.")),
    };
    let summary_value = json::parse(raw).map_err(|error| Failure::invalid(error.to_string()))?;
    let canonical_text = canonical::to_string(&summary_value, Variant::Ascii).map_err(|error| Failure::invalid(error.to_string()))?;
    let Value::Object(summary) = &summary_value else { return Err(summary_invalid()) };
    let keys_match = summary.len() == SUMMARY_FIELDS.len() && SUMMARY_FIELDS.iter().all(|field| summary.contains_key(*field));
    if raw != &canonical_text || !keys_match {
        return Err(summary_invalid());
    }
    let field = |name: &str| summary.get(name);
    let window_pin = artifact.metadata().get(WINDOW_MANIFEST_KEY).map(String::as_str).unwrap_or_default();
    let reference_pin = artifact.metadata().get(COMPONENT_MANIFEST_KEY).map(String::as_str).unwrap_or_default();
    let auxiliary = strict_int(field("auxiliary_rows"));
    let selected_step_ok = strict_int(field("selected_step")).is_some_and(|step| CHECKPOINTS.contains(&step));
    let auxiliary_ok = auxiliary.is_some_and(|rows| rows % 64 == 0 && (20 * 64..=200 * 64).contains(&rows));
    let checkpoint_rows_ok = auxiliary.is_some_and(|rows| loosely_equals(field("checkpoint_rows"), 9 * (512 + rows / 64)));
    let hashes_ok = ["trace_sha256", "base", "terminal", "selected", "delta", "published"].iter().all(|name| is_sha256_value(field(name)));
    if !loosely_equals(field("schema"), 1)
        || !text_equals(field("policy"), WINDOW_ADAM)
        || !text_equals(field("status"), "selected")
        || !text_equals(field("reason"), "guard_passed")
        || !matches!(field("guard_passed"), Some(Value::Bool(true)))
        || !matches!(field("sensitive_progress"), Some(Value::Bool(true)))
        || !loosely_equals(field("violations"), 0)
        || !text_equals(field("window"), window_pin)
        || !text_equals(field("references"), reference_pin)
        || !selected_step_ok
        || !loosely_equals(field("main_rows"), 4096)
        || !auxiliary_ok
        || !checkpoint_rows_ok
        || field("published") != field("selected")
        || !hashes_ok
        || !is_sha256(request.metadata.get("training_evidence_sha256").map(String::as_str).unwrap_or_default())
    {
        return Err(summary_invalid());
    }

    let parameters = &artifact.parameters;
    let shapes: BTreeMap<String, Vec<u64>> = parameters
        .iter()
        .map(|(name, tensor)| (name.clone(), tensor.shape.iter().map(|dimension| u64::from(*dimension)).collect()))
        .collect();
    let gradients: BTreeMap<String, Vec<f64>> = request
        .gradients
        .iter()
        .map(|gradient| (gradient.name.clone(), gradient.values.iter().map(|value| f64::from(*value)).collect()))
        .collect();
    if gradients.len() != request.gradients.len() || !gradients.keys().eq(parameters.keys()) {
        return Err(Failure::invalid("Window publication requires exact complete FULL tensor inventory."));
    }
    let fingerprint = |values: &BTreeMap<String, Vec<f64>>| -> Result<String, Failure> {
        parameter_fingerprint(values, Some(&shapes)).map_err(|error| Failure::invalid(error.to_string()))
    };
    if !text_equals(field("delta"), &fingerprint(&gradients)?) {
        return Err(Failure::invalid("Published delta differs from selected transported checkpoint."));
    }
    let claims_selected = request.metadata.get("updated_parameter_fingerprint").map(String::as_str);
    let claims_base = request.metadata.get("base_parameter_fingerprint").map(String::as_str);
    if !claims_selected.is_some_and(|claim| text_equals(field("selected"), claim))
        || !claims_base.is_some_and(|claim| text_equals(field("base"), claim))
    {
        return Err(Failure::invalid("Publication state identity differs from selected summary."));
    }
    // An identical committed payload is checked by the updater's receipt path; stale uncommitted requests still fail
    // the apply step's version check.
    if artifact.version == request.base_version {
        let mut base: BTreeMap<String, Vec<f64>> = BTreeMap::new();
        let mut updated: BTreeMap<String, Vec<f64>> = BTreeMap::new();
        for (name, tensor) in parameters {
            let delta =
                gradients.get(name).ok_or_else(|| Failure::invalid("Window publication requires exact complete FULL tensor inventory."))?;
            if delta.len() != tensor.values.len() {
                return Err(Failure::invalid("Parameter and delta lengths must match."));
            }
            let mut base_values = Vec::with_capacity(tensor.values.len());
            let mut updated_values = Vec::with_capacity(tensor.values.len());
            for (value, change) in tensor.values.iter().zip(delta) {
                let stored = float32(*value).map_err(Failure::Invalid)?;
                let moved = round8(stored + float32(*change).map_err(Failure::Invalid)?);
                base_values.push(stored);
                updated_values.push(float32(moved).map_err(Failure::Invalid)?);
            }
            base.insert(name.clone(), base_values);
            updated.insert(name.clone(), updated_values);
        }
        if !text_equals(field("base"), &fingerprint(&base)?)
            || !text_equals(field("selected"), &fingerprint(&updated)?)
            || request.metadata.get("artifact_checksum") != Some(&artifact.checksum)
        {
            return Err(Failure::invalid("Actual updater BASE/transported selected state differs from admitted runtime identity."));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn metadata(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs.iter().map(|(key, value)| ((*key).to_string(), (*value).to_string())).collect()
    }

    #[test]
    fn a_plain_artifact_does_not_activate_the_policy_and_orphans_are_refused() {
        assert!(!validate_policy(&metadata(&[])).unwrap());
        let hash = "a".repeat(64);
        assert!(validate_policy(&metadata(&[(WINDOW_MANIFEST_KEY, hash.as_str())])).unwrap_err().message().contains("Orphan"));
    }

    #[test]
    fn an_active_policy_needs_the_exact_exclusive_configuration() {
        let hash = "b".repeat(64);
        let complete = [
            (OPTIMIZER_KEY, WINDOW_ADAM),
            (STRATEGY_KEY, FULL_ENCODER_STRATEGY),
            (OBJECTIVE_KEY, CLASS_BALANCED_SUM_DECISION_MARGIN_OBJECTIVE),
            (CANDIDATE_ELIGIBILITY_KEY, WINDOW_ELIGIBILITY),
            (WINDOW_CONFIG_KEY, WINDOW_CONFIG),
            (WINDOW_MANIFEST_KEY, hash.as_str()),
            (COMPONENT_MANIFEST_KEY, hash.as_str()),
        ];
        assert!(validate_policy(&metadata(&complete)).unwrap());
        let mut mixed = metadata(&complete);
        mixed.insert(FULL_ADAM_CONFIG_KEY.into(), "{}".into());
        assert!(validate_policy(&mixed).is_err());
        let mut wrong_pin = metadata(&complete);
        wrong_pin.insert(WINDOW_MANIFEST_KEY.into(), "short".into());
        assert!(validate_policy(&wrong_pin).is_err());
    }

    #[test]
    fn json_equality_is_python_loose_where_python_is() {
        assert!(loosely_equals(Some(&Value::Int("0".into())), 0));
        assert!(loosely_equals(Some(&Value::Float(0.0)), 0));
        assert!(loosely_equals(Some(&Value::Bool(false)), 0));
        assert!(!loosely_equals(Some(&Value::String("0".into())), 0));
        assert_eq!(strict_int(Some(&Value::Float(1.0))), None);
        assert_eq!(strict_int(Some(&Value::Bool(true))), None);
        assert_eq!(strict_int(Some(&Value::Int("64".into()))), Some(64));
    }
}
