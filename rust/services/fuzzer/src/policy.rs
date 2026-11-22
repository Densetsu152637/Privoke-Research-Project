//! The caller's training-policy admission, as the fuzzer resolves it before any reservation or gradient call:
//! `contextual_training.training_policy_expectations` with `full_adam.expectations`, `window_training.expectations` and
//! `sensitive_retention.expectations`, and `training_admission_metadata`, which turns the expectations into the pre-gradient
//! admission header (`x-privoke-training-admission-v1`) that the runtime compares with the artifact it serves.
//!
//! The expectations are pure functions of the request metadata. The artifact policy and the runtime's own admission live in
//! [`privoke_training::admission`]; the constants of that module (the canonical FULL Adam and window configurations) are reused.

use std::collections::BTreeMap;

use privoke_contracts::canonical::{self, Variant};
use privoke_contracts::json::Value;
use privoke_training::admission::{CONFIG_CANONICAL, WINDOW_CONFIG_CANONICAL};

use crate::error::{Error, Result, invalid};

/// `x-privoke-training-admission-v1`.
pub const ADMISSION_HEADER: &str = "x-privoke-training-admission-v1";
const LEGACY_OBJECTIVE: &str = "legacy_sum_category";
const CLASS_BALANCED: &str = "class_balanced_contextual_v1";
/// `full_adam.OBJECTIVE`: the SUM-category decision-margin objective.
pub const SUM_MARGIN: &str = "class_balanced_contextual_sum_category_decision_margin_v1";
const RETENTION_GATE_OBJECTIVE: &str = "class_balanced_contextual_sum_margin_original_gate_v1";
const RETENTION_HINGE_OBJECTIVE: &str = "class_balanced_contextual_sum_margin_original_hinge_v1";
pub(crate) const PROCESS_OBJECTIVES: [&str; 5] =
    [LEGACY_OBJECTIVE, CLASS_BALANCED, SUM_MARGIN, RETENTION_GATE_OBJECTIVE, RETENTION_HINGE_OBJECTIVE];
const TRAIN_DIAGNOSTICS_POLICY: &str = "train_before_candidate_v1";
const BACKTRACKING_POLICY: &str = "full_train_backtracking_v1";
/// `full_adam.POLICY`.
pub const FULL_ADAM_POLICY: &str = "full_projected_adam64_v1";
pub(crate) const FULL_ADAM_ELIGIBILITY: &str = "candidate_train_exact_eligibility_v1";
/// `window_training.POLICY`.
pub const WINDOW_POLICY: &str = "full_projected_adam64_window_checkpoint_v1";
const WINDOW_ELIGIBILITY: &str = "candidate_window_exact_component_retention_v1";
const RETENTION_GATE_POLICY: &str = "full_projected_adam64_original_train_gate_v1";
const RETENTION_HINGE_POLICY: &str = "full_projected_adam64_original_train_hinge_v1";
pub(crate) const RETENTION_ELIGIBILITY: &str = "candidate_train_exact_original_target_capped_v1";

/// The request metadata.
pub type Metadata = BTreeMap<String, String>;

/// `training_policy_expectations(metadata)`: expectation name to value, where a value may be an explicit `None`
/// (`expected_diagnostics_policy` is `None` when a policy says that no diagnostics are expected).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Expectations(pub BTreeMap<String, Option<String>>);

impl Expectations {
    /// Whether the caller asked for no policy admission at all (`policy_expectations` is falsy).
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// `expectations.get(key)` for a present, non-null value.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).and_then(|value| value.as_deref())
    }

    /// `key in expectations`.
    pub fn contains(&self, key: &str) -> bool {
        self.0.contains_key(key)
    }

    pub(crate) fn set(&mut self, key: &str, value: Option<&str>) {
        self.0.insert(key.to_string(), value.map(str::to_string));
    }
}

fn is_sha256(value: Option<&String>) -> bool {
    value.is_some_and(|text| text.len() == 64 && text.bytes().all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f')))
}

fn get<'a>(metadata: &'a Metadata, key: &str) -> Option<&'a str> {
    metadata.get(key).map(String::as_str)
}

/// `window_training.expectations`.
fn window_expectations(metadata: &Metadata) -> Result<Option<Expectations>> {
    if get(metadata, "expected_contextual_training_optimizer") != Some(WINDOW_POLICY) {
        if ["train_window_manifest_sha256", "original_train_component_manifest_sha256", "train_window_config_v1"]
            .iter()
            .any(|key| metadata.contains_key(&format!("expected_{key}")))
        {
            return invalid("Orphan window/checkpoint request pin.");
        }
        return Ok(None);
    }
    if get(metadata, "expected_contextual_training_objective") != Some(SUM_MARGIN)
        || get(metadata, "expected_contextual_candidate_eligibility") != Some(WINDOW_ELIGIBILITY)
        || get(metadata, "expected_contextual_training_scope") != Some("full_encoder")
        || get(metadata, "expected_train_window_config_v1") != Some(WINDOW_CONFIG_CANONICAL)
        || !["expected_train_window_manifest_sha256", "expected_original_train_component_manifest_sha256"]
            .iter()
            .all(|key| is_sha256(metadata.get(*key)))
    {
        return invalid("Window admission requires exact FULL policy/config and independent release pins.");
    }
    let mut result = Expectations::default();
    result.set("expected_objective", Some(SUM_MARGIN));
    result.set("expected_diagnostics_policy", None);
    result.set("expected_optimizer", Some(WINDOW_POLICY));
    result.set("expected_candidate_eligibility", Some(WINDOW_ELIGIBILITY));
    result.set("expected_optimizer_config", Some(WINDOW_CONFIG_CANONICAL));
    result.set("expected_training_scope", Some("full_encoder"));
    result.set("expected_window_manifest_sha256", get(metadata, "expected_train_window_manifest_sha256"));
    result.set("expected_component_manifest_sha256", get(metadata, "expected_original_train_component_manifest_sha256"));
    Ok(Some(result))
}

pub(crate) fn retention_objective(policy: &str) -> Option<&'static str> {
    match policy {
        RETENTION_GATE_POLICY => Some(RETENTION_GATE_OBJECTIVE),
        RETENTION_HINGE_POLICY => Some(RETENTION_HINGE_OBJECTIVE),
        _ => None,
    }
}

/// `sensitive_retention.expectations`.
pub(crate) fn retention_expectations(metadata: &Metadata) -> Result<Option<Expectations>> {
    let policy = get(metadata, "expected_contextual_training_optimizer");
    let Some(objective) = policy.and_then(retention_objective) else {
        if metadata.contains_key("expected_original_train_retention_manifest_sha256") {
            return invalid("Orphan ORIGINAL retention request pin.");
        }
        return Ok(None);
    };
    let pin = metadata.get("expected_original_train_retention_manifest_sha256");
    if get(metadata, "expected_contextual_training_objective") != Some(objective)
        || get(metadata, "expected_contextual_candidate_eligibility") != Some(RETENTION_ELIGIBILITY)
        || get(metadata, "expected_full_projected_adam_config_v1") != Some(CONFIG_CANONICAL)
        || get(metadata, "expected_contextual_training_scope") != Some("full_encoder")
        || !is_sha256(pin)
        || metadata.contains_key("expected_contextual_training_diagnostics_policy")
        || metadata.contains_key("expected_contextual_training_backtracking_policy")
    {
        return invalid("Retention admission requires exact FULL policy/config/objective and immutable manifest pin.");
    }
    let mut result = Expectations::default();
    result.set("expected_optimizer", policy);
    result.set("expected_candidate_eligibility", Some(RETENTION_ELIGIBILITY));
    result.set("expected_optimizer_config", Some(CONFIG_CANONICAL));
    result.set("expected_training_scope", Some("full_encoder"));
    result.set("expected_retention_manifest_sha256", pin.map(String::as_str));
    Ok(Some(result))
}

/// `full_adam.expectations`: the window and retention contracts first, then the plain FULL Adam one.
pub(crate) fn full_adam_expectations(metadata: &Metadata) -> Result<Expectations> {
    if let Some(window) = window_expectations(metadata)? {
        return Ok(window);
    }
    if let Some(retention) = retention_expectations(metadata)? {
        return Ok(retention);
    }
    let optimizer = get(metadata, "expected_contextual_training_optimizer");
    let eligibility = get(metadata, "expected_contextual_candidate_eligibility");
    let config = get(metadata, "expected_full_projected_adam_config_v1");
    let scope = get(metadata, "expected_contextual_training_scope");
    if optimizer.is_none() && eligibility.is_none() && config.is_none() && scope.is_none() {
        return Ok(Expectations::default());
    }
    if optimizer != Some(FULL_ADAM_POLICY)
        || eligibility != Some(FULL_ADAM_ELIGIBILITY)
        || config != Some(CONFIG_CANONICAL)
        || !matches!(scope, Some("heads" | "full_encoder"))
        || get(metadata, "expected_contextual_training_objective") != Some(SUM_MARGIN)
        || metadata.contains_key("expected_contextual_training_diagnostics_policy")
        || metadata.contains_key("expected_contextual_training_backtracking_policy")
    {
        return invalid("FULL Adam admission requires exact optimizer, eligibility, config and objective.");
    }
    let mut result = Expectations::default();
    result.set("expected_optimizer", Some(FULL_ADAM_POLICY));
    result.set("expected_candidate_eligibility", Some(FULL_ADAM_ELIGIBILITY));
    result.set("expected_optimizer_config", Some(CONFIG_CANONICAL));
    result.set("expected_training_scope", scope);
    Ok(result)
}

/// `contextual_training.training_policy_expectations(metadata)`.
pub fn training_policy_expectations(metadata: &Metadata) -> Result<Expectations> {
    let objective = get(metadata, "expected_contextual_training_objective");
    let diagnostics = get(metadata, "expected_contextual_training_diagnostics_policy");
    if objective.is_some() && !objective.is_some_and(|name| PROCESS_OBJECTIVES.contains(&name)) {
        return invalid("Unsupported expected contextual training objective.");
    }
    if diagnostics.is_some_and(|policy| policy != TRAIN_DIAGNOSTICS_POLICY) {
        return invalid("Unsupported expected contextual training diagnostics policy.");
    }
    let mut result = Expectations::default();
    if let Some(objective) = objective {
        result.set("expected_objective", Some(objective));
    }
    if let Some(diagnostics) = diagnostics {
        result.set("expected_diagnostics_policy", Some(diagnostics));
    }
    if matches!(objective, Some(SUM_MARGIN | RETENTION_GATE_OBJECTIVE | RETENTION_HINGE_OBJECTIVE)) {
        result.set("expected_diagnostics_policy", diagnostics);
    }
    let policy = get(metadata, "expected_contextual_training_backtracking_policy");
    let preparation = metadata.get("expected_contextual_training_backtracking_preparation_sha256");
    if policy.is_some() || preparation.is_some() {
        if policy != Some(BACKTRACKING_POLICY)
            || !is_sha256(preparation)
            || !objective.is_some_and(|name| PROCESS_OBJECTIVES.contains(&name))
            || diagnostics != Some(TRAIN_DIAGNOSTICS_POLICY)
        {
            return invalid("Backtracking admission requires its policy, preparation hash, objective and diagnostics.");
        }
        result.set("expected_backtracking_policy", policy);
        result.set("expected_backtracking_preparation_sha256", preparation.map(String::as_str));
    }
    result.0.extend(full_adam_expectations(metadata)?.0);
    Ok(result)
}

fn json_value(value: &Option<String>) -> Value {
    value.as_ref().map_or(Value::Null, |text| Value::String(text.clone()))
}

/// `training_admission_metadata(expectations)`: the header value the runtime receives, or `None` when the expectations carry
/// nothing to admit. The record's schema (1 backtracking, 2 objective-only, 3 FULL Adam, 4 ORIGINAL retention, 5 window) is the
/// first key of the Python record; the JSON is `json.dumps(record, sort_keys=True, separators=(",", ":"))` (ASCII).
pub fn training_admission_header(expectations: &Expectations) -> Result<Option<String>> {
    let optimizer = expectations.get("expected_optimizer");
    let mut record: BTreeMap<String, Value> = BTreeMap::new();
    let schema: i64 = if optimizer == Some(WINDOW_POLICY) {
        5
    } else if optimizer.is_some() {
        if optimizer.and_then(retention_objective).is_some() { 4 } else { 3 }
    } else if !expectations.contains("expected_backtracking_policy") {
        if expectations.get("expected_objective") != Some(SUM_MARGIN) {
            return Ok(None);
        }
        record.insert("expected_objective".to_string(), Value::String(SUM_MARGIN.to_string()));
        record.insert(
            "expected_diagnostics_policy".to_string(),
            json_value(expectations.0.get("expected_diagnostics_policy").unwrap_or(&None)),
        );
        2
    } else {
        1
    };
    if schema != 2 {
        for (key, value) in &expectations.0 {
            record.insert(key.clone(), json_value(value));
        }
    }
    record.insert("schema".to_string(), Value::Int(schema.to_string()));
    let bytes = canonical::to_bytes(&Value::Object(record), Variant::Ascii).map_err(|error| Error(error.to_string()))?;
    String::from_utf8(bytes).map(Some).map_err(|error| Error(error.to_string()))
}

/// The exact expectations of an authenticated plain FULL Adam request, as the rehearsal and benign admissions require them
/// (`{expected_objective, expected_diagnostics_policy: None, expected_optimizer, expected_candidate_eligibility,
/// expected_optimizer_config, expected_training_scope}`), or, for `retention`, the ORIGINAL retention variant of the policy.
pub(crate) fn exact_full_adam(retention: Option<(&str, &str)>) -> Expectations {
    let mut required = Expectations::default();
    match retention {
        None => {
            required.set("expected_objective", Some(SUM_MARGIN));
            required.set("expected_optimizer", Some(FULL_ADAM_POLICY));
            required.set("expected_candidate_eligibility", Some(FULL_ADAM_ELIGIBILITY));
        }
        Some((policy, pin)) => {
            required.set("expected_objective", retention_objective(policy));
            required.set("expected_optimizer", Some(policy));
            required.set("expected_candidate_eligibility", Some(RETENTION_ELIGIBILITY));
            required.set("expected_retention_manifest_sha256", Some(pin));
        }
    }
    required.set("expected_diagnostics_policy", None);
    required.set("expected_optimizer_config", Some(CONFIG_CANONICAL));
    required.set("expected_training_scope", Some("full_encoder"));
    required
}

impl Expectations {
    /// The expectations as the JSON object Python records (`None` is `null`).
    pub fn to_value(&self) -> Value {
        Value::Object(self.0.iter().map(|(key, value)| (key.clone(), json_value(value))).collect())
    }
}

/// `parse_training_admission_metadata` for the header value: the expectations the record encodes, checked against the
/// contracts they name. Schemas 3 (FULL Adam) and 4 (ORIGINAL retention) are the ones an optimizer admission uses; the
/// objective-only and backtracking schemas carry no optimizer and are validated by their own cycles.
pub fn parse_training_admission_header(raw: &str) -> Result<Expectations> {
    if raw.len() > 2048 {
        return invalid("Training policy JSON exceeds its byte budget.");
    }
    let record = privoke_contracts::json::parse(raw).map_err(|error| Error(error.to_string()))?;
    let object = match &record {
        Value::Object(map) => Some(map),
        _ => None,
    };
    let schema = object.and_then(|map| map.get("schema")).and_then(|value| match value {
        Value::Int(digits) => digits.parse::<i64>().ok(),
        _ => None,
    });
    let text = |key: &str| -> Option<String> {
        match object.and_then(|map| map.get(key)) {
            Some(Value::String(text)) => Some(text.clone()),
            _ => None,
        }
    };
    let key_set =
        |names: &[&str]| -> bool { object.is_some_and(|map| map.len() == names.len() && names.iter().all(|name| map.contains_key(*name))) };
    let base_names = [
        "schema",
        "expected_objective",
        "expected_diagnostics_policy",
        "expected_optimizer",
        "expected_candidate_eligibility",
        "expected_optimizer_config",
        "expected_training_scope",
    ];
    let mut metadata = Metadata::new();
    let mut put = |key: &str, value: Option<String>| {
        if let Some(value) = value {
            metadata.insert(key.to_string(), value);
        }
    };
    match schema {
        Some(3) => {
            if !key_set(&base_names) {
                return invalid("Unsupported FULL Adam admission contract.");
            }
            put("expected_contextual_training_optimizer", text("expected_optimizer"));
            put("expected_contextual_candidate_eligibility", text("expected_candidate_eligibility"));
            put("expected_full_projected_adam_config_v1", text("expected_optimizer_config"));
            put("expected_contextual_training_scope", text("expected_training_scope"));
            put("expected_contextual_training_objective", text("expected_objective"));
            put("expected_contextual_training_diagnostics_policy", text("expected_diagnostics_policy"));
            let mut result = Expectations::default();
            result.set("expected_objective", text("expected_objective").as_deref());
            result.set("expected_diagnostics_policy", None);
            result.0.extend(full_adam_expectations(&metadata)?.0);
            Ok(result)
        }
        Some(4) => {
            let mut names = base_names.to_vec();
            names.push("expected_retention_manifest_sha256");
            if !key_set(&names)
                || text("expected_diagnostics_policy").is_some()
                || !matches!(object.and_then(|map| map.get("expected_diagnostics_policy")), Some(Value::Null))
            {
                return invalid("Unsupported ORIGINAL TRAIN retention admission contract.");
            }
            put("expected_contextual_training_optimizer", text("expected_optimizer"));
            put("expected_contextual_candidate_eligibility", text("expected_candidate_eligibility"));
            put("expected_full_projected_adam_config_v1", text("expected_optimizer_config"));
            put("expected_contextual_training_scope", text("expected_training_scope"));
            put("expected_contextual_training_objective", text("expected_objective"));
            put("expected_original_train_retention_manifest_sha256", text("expected_retention_manifest_sha256"));
            let Some(checked) = retention_expectations(&metadata)? else {
                return invalid("Retention schema4 requires a retention optimizer.");
            };
            let mut result = Expectations::default();
            result.set("expected_objective", text("expected_objective").as_deref());
            result.set("expected_diagnostics_policy", None);
            result.0.extend(checked.0);
            Ok(result)
        }
        _ => invalid("Unsupported backtracking admission contract."),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn metadata(pairs: &[(&str, &str)]) -> Metadata {
        pairs.iter().map(|(key, value)| ((*key).to_string(), (*value).to_string())).collect()
    }

    #[test]
    fn no_expectation_means_no_policy_admission() {
        let result = training_policy_expectations(&metadata(&[("initiator", "x")])).unwrap();
        assert!(result.is_empty());
        assert_eq!(training_admission_header(&result).unwrap(), None);
    }

    #[test]
    fn the_exact_full_adam_request_is_admitted_with_a_schema_3_header() {
        let request = metadata(&[
            ("expected_contextual_training_objective", SUM_MARGIN),
            ("expected_contextual_training_optimizer", FULL_ADAM_POLICY),
            ("expected_contextual_candidate_eligibility", FULL_ADAM_ELIGIBILITY),
            ("expected_full_projected_adam_config_v1", CONFIG_CANONICAL),
            ("expected_contextual_training_scope", "full_encoder"),
        ]);
        let result = training_policy_expectations(&request).unwrap();
        assert_eq!(result.get("expected_optimizer"), Some(FULL_ADAM_POLICY));
        assert!(result.contains("expected_diagnostics_policy") && result.get("expected_diagnostics_policy").is_none());
        let header = training_admission_header(&result).unwrap().unwrap();
        assert!(header.starts_with("{\"expected_candidate_eligibility\""));
        assert!(header.ends_with("\"schema\":3}"));
    }

    #[test]
    fn invalid_requests_are_refused_with_the_python_messages() {
        let objective = metadata(&[("expected_contextual_training_objective", "other")]);
        assert_eq!(training_policy_expectations(&objective).unwrap_err().0, "Unsupported expected contextual training objective.");
        let diagnostics = metadata(&[("expected_contextual_training_diagnostics_policy", "x")]);
        assert_eq!(
            training_policy_expectations(&diagnostics).unwrap_err().0,
            "Unsupported expected contextual training diagnostics policy."
        );
        let orphan = metadata(&[("expected_train_window_config_v1", "{}")]);
        assert_eq!(training_policy_expectations(&orphan).unwrap_err().0, "Orphan window/checkpoint request pin.");
        let half = metadata(&[("expected_contextual_training_optimizer", FULL_ADAM_POLICY)]);
        assert_eq!(
            training_policy_expectations(&half).unwrap_err().0,
            "FULL Adam admission requires exact optimizer, eligibility, config and objective."
        );
    }
}
