//! Artifact policy and pre-gradient admission of the Tiny gradient envelope (`privoke_model/full_adam.py`,
//! `window_training.py`, `sensitive_retention.py` and the checks at the top of `training._compute_training_gradients`).
//!
//! Ported: the FULL Adam, window and ORIGINAL-retention policy and admission checks (the window and retention training
//! loops are not, so an artifact that passes them is [`Admitted::Elsewhere`]), the backtracking policy, and the
//! comparison of the request's objective, diagnostics and backtracking admission with the artifact that serves it.
//! [`admit`] returns the route (objective, local-SGD optimizer, diagnostics, backtracking) the artifact selects.

use std::collections::BTreeMap;

use privoke_contracts::digest::sha256_hex;
use privoke_contracts::json::{Duplicates, ParseOptions, Value, parse_with};

use crate::adam::{OBJECTIVE, POLICY};
use crate::error::TrainingError;

/// `contextual_training_optimizer`.
pub const OPTIMIZER_KEY: &str = "contextual_training_optimizer";
/// `contextual_training_objective`.
pub const OBJECTIVE_KEY: &str = "contextual_training_objective";
/// `contextual_training_diagnostics_policy`.
pub const DIAGNOSTICS_POLICY_KEY: &str = "contextual_training_diagnostics_policy";
/// The one diagnostics policy.
pub const TRAIN_DIAGNOSTICS_POLICY: &str = "train_before_candidate_v1";
/// `contextual_training_backtracking_policy`.
pub const BACKTRACKING_KEY: &str = "contextual_training_backtracking_policy";
/// The one backtracking policy.
pub const BACKTRACKING_POLICY: &str = "full_train_backtracking_v1";
/// `contextual_training_backtracking_preparation`.
pub const BACKTRACKING_PREPARATION_KEY: &str = "contextual_training_backtracking_preparation";
/// The objective of an artifact that names none.
pub const LEGACY_OBJECTIVE: &str = "legacy_sum_category";
/// The objectives of the Tiny routes that this crate serves.
pub const SERVED_OBJECTIVES: [&str; 4] = [
    "class_balanced_contextual_v1",
    "class_balanced_contextual_mean_category_v1",
    "class_balanced_contextual_decision_margin_v1",
    OBJECTIVE,
];
const MEAN_OBJECTIVES: [&str; 2] = ["class_balanced_contextual_mean_category_v1", "class_balanced_contextual_decision_margin_v1"];
const STRATEGY_KEY: &str = "contextual_training_strategy";
const ELIGIBILITY: &str = "candidate_train_exact_eligibility_v1";
const ELIGIBILITY_KEY: &str = "contextual_candidate_eligibility";
const CONFIG_KEY: &str = "full_projected_adam_config_v1";
const STRATEGY: &str = "contextual_full_encoder_sgd_v1";

const WINDOW_POLICY: &str = "full_projected_adam64_window_checkpoint_v1";
/// `window_training.ELIGIBILITY`.
pub const WINDOW_ELIGIBILITY: &str = "candidate_window_exact_component_retention_v1";
const WINDOW_CONFIG_KEY: &str = "train_window_config_v1";
const WINDOW_KEY: &str = "train_window_manifest_sha256";
const REFERENCE_KEY: &str = "original_train_component_manifest_sha256";
/// `canonical(window_training.CONFIG)`.
pub const WINDOW_CONFIG_CANONICAL: &str = "{\"adam\":{\"beta1\":0.9,\"beta2\":0.999,\"cpu_threads\":1,\"delta_cap\":0.05,\"device\":\"cpu\",\"epsilon\":1e-08,\"eta\":0.003,\"gradient_denominator\":1,\"margin_coefficient\":1,\"microbatch_size\":32,\"moment_dtype\":\"float64\",\"steps\":64},\"auxiliary_coefficient\":1,\"block_rows\":64,\"blocks\":8,\"candidate_seeds\":64,\"checkpoints\":[8,16,24,32,40,48,56,64],\"component_order\":[\"sensitivity\",\"severity\",\"category\",\"visibility\",\"action\"],\"epochs\":8,\"epsilon\":1e-06,\"main_normalization\":\"eight_times_block_over_frozen_window_weight_v1\",\"margin_cap\":1.0,\"normalization\":\"category_bits_then_components_then_rows_v1\",\"selector\":\"transported_train_component_rank_v1\"}";

const RETENTION_GATE_POLICY: &str = "full_projected_adam64_original_train_gate_v1";
const RETENTION_HINGE_POLICY: &str = "full_projected_adam64_original_train_hinge_v1";
const RETENTION_GATE_OBJECTIVE: &str = "class_balanced_contextual_sum_margin_original_gate_v1";
const RETENTION_HINGE_OBJECTIVE: &str = "class_balanced_contextual_sum_margin_original_hinge_v1";
const RETENTION_ELIGIBILITY: &str = "candidate_train_exact_original_target_capped_v1";
const RETENTION_MANIFEST_KEY: &str = "original_train_retention_manifest_sha256";

/// `canonical(CONFIG)`: sorted keys, compact separators, Python float `repr`.
pub const CONFIG_CANONICAL: &str = "{\"beta1\":0.9,\"beta2\":0.999,\"cpu_threads\":1,\"delta_cap\":0.05,\"device\":\"cpu\",\"epsilon\":1e-08,\"eta\":0.003,\"gradient_denominator\":1,\"margin_coefficient\":1,\"microbatch_size\":32,\"moment_dtype\":\"float64\",\"steps\":64}";

/// Artifact fields, as strings.
pub type Fields = BTreeMap<String, String>;

/// The pre-gradient admission record of a request: every key it carries, with `None` for a JSON `null`.
pub type Header = BTreeMap<String, Option<String>>;

fn invalid(message: &str) -> TrainingError {
    TrainingError::invalid(message)
}

fn is(metadata: &Fields, key: &str, expected: &str) -> bool {
    metadata.get(key).map(String::as_str) == Some(expected)
}

fn is_sha256(value: Option<&String>) -> bool {
    value.is_some_and(|text| text.len() == 64 && text.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
}

/// `admission.get(key)`: the value, or `None` when the key is absent or null.
fn entry<'a>(admission: Option<&'a Header>, key: &str) -> Option<&'a str> {
    admission.and_then(|header| header.get(key)).and_then(|value| value.as_deref())
}

fn retention_objective(policy: &str) -> Option<&'static str> {
    match policy {
        RETENTION_GATE_POLICY => Some(RETENTION_GATE_OBJECTIVE),
        RETENTION_HINGE_POLICY => Some(RETENTION_HINGE_OBJECTIVE),
        _ => None,
    }
}

/// `window_training.validate_policy`.
fn window_policy(metadata: &Fields) -> Result<bool, TrainingError> {
    if !is(metadata, OPTIMIZER_KEY, WINDOW_POLICY) {
        if [WINDOW_CONFIG_KEY, WINDOW_KEY, REFERENCE_KEY].iter().any(|key| metadata.contains_key(*key)) {
            return Err(invalid("Orphan window/checkpoint artifact policy."));
        }
        return Ok(false);
    }
    let exact = is(metadata, STRATEGY_KEY, STRATEGY)
        && is(metadata, OBJECTIVE_KEY, OBJECTIVE)
        && is(metadata, ELIGIBILITY_KEY, WINDOW_ELIGIBILITY)
        && is(metadata, WINDOW_CONFIG_KEY, WINDOW_CONFIG_CANONICAL)
        && is_sha256(metadata.get(WINDOW_KEY))
        && is_sha256(metadata.get(REFERENCE_KEY))
        && ![BACKTRACKING_KEY, DIAGNOSTICS_POLICY_KEY, CONFIG_KEY, RETENTION_MANIFEST_KEY].iter().any(|key| metadata.contains_key(*key));
    if exact { Ok(true) } else { Err(invalid("Window policy requires exact exclusive FULL optimizer/objective/config/pins.")) }
}

/// `sensitive_retention.validate_policy`.
fn retention_policy(metadata: &Fields) -> Result<bool, TrainingError> {
    let policy = metadata.get(OPTIMIZER_KEY).map(String::as_str).filter(|policy| retention_objective(policy).is_some());
    let Some(policy) = policy else {
        if metadata.contains_key(RETENTION_MANIFEST_KEY) {
            return Err(invalid("Orphan ORIGINAL retention artifact pin."));
        }
        return Ok(false);
    };
    let exact = is(metadata, STRATEGY_KEY, STRATEGY)
        && retention_objective(policy).is_some_and(|objective| is(metadata, OBJECTIVE_KEY, objective))
        && is(metadata, ELIGIBILITY_KEY, RETENTION_ELIGIBILITY)
        && is(metadata, CONFIG_KEY, CONFIG_CANONICAL)
        && is_sha256(metadata.get(RETENTION_MANIFEST_KEY))
        && ![BACKTRACKING_KEY, BACKTRACKING_PREPARATION_KEY, DIAGNOSTICS_POLICY_KEY].iter().any(|key| metadata.contains_key(*key));
    if exact { Ok(true) } else { Err(invalid("Retention requires its exact versioned optimizer/objective/config/admission/manifest.")) }
}

/// `full_adam.validate_policy`: whether the artifact activates FULL Adam, window or ORIGINAL-retention training.
pub fn validate_policy(metadata: &Fields) -> Result<bool, TrainingError> {
    let optimizer = metadata.get(OPTIMIZER_KEY).map(String::as_str);
    if optimizer == Some(WINDOW_POLICY) {
        return window_policy(metadata);
    }
    window_policy(metadata)?;
    if optimizer.and_then(retention_objective).is_some() {
        return retention_policy(metadata);
    }
    retention_policy(metadata)?;
    if optimizer != Some(POLICY) {
        if metadata.contains_key(ELIGIBILITY_KEY) || metadata.contains_key(CONFIG_KEY) {
            return Err(invalid("FULL Adam configuration/eligibility requires its optimizer."));
        }
        return Ok(false);
    }
    let exact = is(metadata, STRATEGY_KEY, STRATEGY)
        && is(metadata, OBJECTIVE_KEY, OBJECTIVE)
        && is(metadata, ELIGIBILITY_KEY, ELIGIBILITY)
        && is(metadata, CONFIG_KEY, CONFIG_CANONICAL)
        && ![BACKTRACKING_KEY, BACKTRACKING_PREPARATION_KEY, DIAGNOSTICS_POLICY_KEY].iter().any(|key| metadata.contains_key(*key));
    if exact { Ok(true) } else { Err(invalid("FULL Adam requires its exact FULL, SUM-margin, fixed config and eligibility contract.")) }
}

/// The optimizer policy that an artifact declares and its admission accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Policy {
    /// No FULL Adam, window or retention policy.
    Inactive,
    /// FULL Adam.
    FullAdam,
    /// The frozen window with checkpoint selection.
    Window,
    /// ORIGINAL retention (gate or hinge).
    Retention,
}

fn expected_window_header(metadata: &Fields) -> Header {
    let pin = |key: &str| metadata.get(key).cloned();
    Header::from([
        ("expected_objective".to_string(), Some(OBJECTIVE.to_string())),
        ("expected_diagnostics_policy".to_string(), None),
        ("expected_optimizer".to_string(), Some(WINDOW_POLICY.to_string())),
        ("expected_candidate_eligibility".to_string(), Some(WINDOW_ELIGIBILITY.to_string())),
        ("expected_optimizer_config".to_string(), Some(WINDOW_CONFIG_CANONICAL.to_string())),
        ("expected_training_scope".to_string(), Some("full_encoder".to_string())),
        ("expected_window_manifest_sha256".to_string(), pin(WINDOW_KEY)),
        ("expected_component_manifest_sha256".to_string(), pin(REFERENCE_KEY)),
    ])
}

/// `full_adam.validate_admission` over a header with optional values, including the window and retention dispatch.
pub fn policy_admission(admission: Option<&Header>, metadata: &Fields) -> Result<Policy, TrainingError> {
    let optimizer = metadata.get(OPTIMIZER_KEY).map(String::as_str);
    if optimizer == Some(WINDOW_POLICY) {
        if !window_policy(metadata)? || admission.is_none() {
            return Err(invalid("Window artifact requires explicit matching pre-gradient admission."));
        }
        if admission != Some(&expected_window_header(metadata)) {
            return Err(invalid("Window artifact differs from admitted effective settings."));
        }
        return Ok(Policy::Window);
    }
    if let Some(policy) = optimizer.filter(|policy| retention_objective(policy).is_some()) {
        if !retention_policy(metadata)? {
            return Err(invalid("Retention admission requires its actual artifact policy."));
        }
        let matches = admission.is_some()
            && entry(admission, "expected_optimizer") == Some(policy)
            && entry(admission, "expected_objective") == retention_objective(policy)
            && entry(admission, "expected_candidate_eligibility") == Some(RETENTION_ELIGIBILITY)
            && entry(admission, "expected_optimizer_config") == Some(CONFIG_CANONICAL)
            && entry(admission, "expected_training_scope") == Some("full_encoder")
            && entry(admission, "expected_retention_manifest_sha256") == metadata.get(RETENTION_MANIFEST_KEY).map(String::as_str);
        if !matches {
            return Err(invalid("Retention artifact differs from pre-gradient admission."));
        }
        return Ok(Policy::Retention);
    }
    let active = validate_policy(metadata)?;
    let expected =
        [("expected_optimizer", POLICY), ("expected_candidate_eligibility", ELIGIBILITY), ("expected_optimizer_config", CONFIG_CANONICAL)];
    if active {
        if admission.is_none() || !expected.iter().all(|(key, value)| entry(admission, key) == Some(*value)) {
            return Err(invalid("FULL Adam artifact requires matching explicit pre-gradient admission."));
        }
        Ok(Policy::FullAdam)
    } else {
        if admission.is_some_and(|header| expected.iter().any(|(key, _)| header.contains_key(*key))) {
            return Err(invalid("FULL Adam admission differs from actual artifact."));
        }
        Ok(Policy::Inactive)
    }
}

/// `validate_admission` for a header whose values are all present: whether the artifact activates FULL Adam (or the window
/// or retention policy, which dispatch through the same check).
pub fn validate_admission(admission: Option<&Fields>, metadata: &Fields) -> Result<bool, TrainingError> {
    let header: Option<Header> = admission.map(|fields| fields.iter().map(|(key, value)| (key.clone(), Some(value.clone()))).collect());
    Ok(policy_admission(header.as_ref(), metadata)? != Policy::Inactive)
}

/// `contextual_training.validate_backtracking_policy`: the SHA-256 of the artifact's preparation record when it declares
/// the backtracking policy.
pub fn validate_backtracking_policy(metadata: &Fields) -> Result<Option<String>, TrainingError> {
    if !metadata.contains_key(BACKTRACKING_KEY) {
        if metadata.contains_key(BACKTRACKING_PREPARATION_KEY) {
            return Err(invalid("Backtracking preparation requires its policy."));
        }
        return Ok(None);
    }
    let objective = metadata.get(OBJECTIVE_KEY).map(String::as_str);
    if !is(metadata, BACKTRACKING_KEY, BACKTRACKING_POLICY)
        || !is(metadata, STRATEGY_KEY, STRATEGY)
        || !matches!(objective, None | Some("class_balanced_contextual_v1" | OBJECTIVE))
        || !is(metadata, DIAGNOSTICS_POLICY_KEY, TRAIN_DIAGNOSTICS_POLICY)
        || metadata.contains_key(OPTIMIZER_KEY)
    {
        return Err(invalid("Backtracking requires FULL summed BCE, diagnostics and absent optimizer."));
    }
    let preparation = metadata.get(BACKTRACKING_PREPARATION_KEY).filter(|text| text.len() <= 2048);
    let record = preparation
        .and_then(|text| parse_with(text, ParseOptions { duplicates: Duplicates::Reject, ..ParseOptions::default() }).ok())
        .and_then(|value| if let Value::Object(entries) = value { Some(entries) } else { None });
    let keys = ["schema", "baseline_checksum", "baseline_fingerprint", "protocol_sha256", "source_sha256"];
    let valid = record.as_ref().is_some_and(|entries| {
        entries.len() == keys.len()
            && keys.iter().all(|key| entries.contains_key(*key))
            && matches!(entries.get("schema"), Some(Value::Int(schema)) if schema == "1")
            && keys[1..].iter().all(|key| matches!(entries.get(*key), Some(Value::String(text)) if is_sha256(Some(text))))
    });
    match (valid, preparation) {
        (true, Some(text)) => Ok(Some(sha256_hex(text.as_bytes()))),
        _ => Err(invalid("Backtracking preparation is invalid.")),
    }
}

/// The route an artifact and its admission select on the Tiny gradient envelope.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Route {
    /// The artifact's `contextual_training_objective`, if any.
    pub objective: Option<String>,
    /// The explicit local-SGD optimizer (`local_sgd_1_v1`, `local_sgd_4_v1`), if any.
    pub optimizer: Option<String>,
    /// The TRAIN diagnostics policy is declared.
    pub diagnostics: bool,
    /// The backtracking route: the SHA-256 of the preparation record (full-encoder scope only).
    pub backtracking: Option<String>,
}

/// The outcome of [`admit`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Admitted {
    /// A route this crate computes.
    Route(Route),
    /// A route another worker serves: the policy checks passed, but its training loop is not ported.
    Elsewhere(&'static str),
}

/// The checks of `_compute_training_gradients` that read the artifact's metadata and the request's admission, in
/// Python's order: policy admission (FULL Adam, window, retention), the backtracking policy, the objective, diagnostics
/// and backtracking admission against the artifact, and the contract of the optimizer and diagnostics metadata.
pub fn admit(admission: Option<&Header>, metadata: &Fields, full_encoder: bool) -> Result<Admitted, TrainingError> {
    match policy_admission(admission, metadata)? {
        Policy::Inactive => {}
        Policy::FullAdam => return Ok(Admitted::Elsewhere("the FULL Adam fit is served by the Python worker")),
        Policy::Window => return Ok(Admitted::Elsewhere("the window checkpoint training is served by the Python worker")),
        Policy::Retention => return Ok(Admitted::Elsewhere("the ORIGINAL retention training is served by the Python worker")),
    }
    let preparation = validate_backtracking_policy(metadata)?;
    let backtracking = if full_encoder { preparation.clone() } else { None };
    let objective = metadata.get(OBJECTIVE_KEY).map(String::as_str);
    if objective.is_some_and(|name| !SERVED_OBJECTIVES.contains(&name)) {
        return Ok(Admitted::Elsewhere("the artifact declares an objective this worker does not serve"));
    }
    if let Some(header) = admission {
        let get = |key: &str| entry(Some(header), key);
        if get("expected_objective") != Some(objective.unwrap_or(LEGACY_OBJECTIVE))
            || get("expected_diagnostics_policy") != metadata.get(DIAGNOSTICS_POLICY_KEY).map(String::as_str)
        {
            return Err(invalid("Actual artifact differs from pre-gradient objective admission."));
        }
        let declared = backtracking.is_some() || header.contains_key("expected_backtracking_policy");
        if declared
            && (backtracking.is_none()
                || get("expected_backtracking_policy") != Some(BACKTRACKING_POLICY)
                || get("expected_backtracking_preparation_sha256") != preparation.as_deref())
        {
            return Err(invalid("Actual artifact differs from pre-gradient backtracking admission."));
        }
    } else if backtracking.is_some() {
        return Err(invalid("FULL backtracking requires explicit matching pre-gradient admission."));
    } else if objective == Some(OBJECTIVE) {
        return Err(invalid("Summed-category decision-margin training requires explicit objective admission."));
    }
    // `validate_contextual_training_contract`: the metadata of the optimizer and diagnostics.
    if metadata.get(DIAGNOSTICS_POLICY_KEY).is_some_and(|policy| policy != TRAIN_DIAGNOSTICS_POLICY) {
        return Err(invalid("Unsupported contextual training diagnostics policy."));
    }
    let optimizer = metadata.get(OPTIMIZER_KEY).map(String::as_str);
    if objective == Some(OBJECTIVE) && optimizer.is_some() {
        return Err(invalid("Summed-category decision-margin training requires absent optimizer metadata."));
    }
    if optimizer.is_some_and(|name| !matches!(name, "local_sgd_1_v1" | "local_sgd_4_v1")) {
        return Err(invalid("Unsupported contextual training optimizer."));
    }
    let diagnostics = metadata.contains_key(DIAGNOSTICS_POLICY_KEY);
    if diagnostics && (optimizer.is_some() || objective.is_some_and(|name| MEAN_OBJECTIVES.contains(&name))) {
        return Err(invalid("TRAIN process diagnostics require one legacy update with summed category BCE."));
    }
    Ok(Admitted::Route(Route {
        objective: objective.map(str::to_string),
        optimizer: optimizer.map(str::to_string),
        diagnostics,
        backtracking,
    }))
}
