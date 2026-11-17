//! FULL Adam artifact policy and pre-gradient admission (`privoke_model/full_adam.py::validate_policy` and
//! `validate_admission`). The window and ORIGINAL-retention policies dispatch to their own contracts, which are not
//! ported: such an artifact is reported as unsupported instead of being admitted.

use std::collections::BTreeMap;

use crate::adam::POLICY;
use crate::error::TrainingError;

/// `contextual_training_optimizer`.
pub const OPTIMIZER_KEY: &str = "contextual_training_optimizer";
const ELIGIBILITY: &str = "candidate_train_exact_eligibility_v1";
const ELIGIBILITY_KEY: &str = "contextual_candidate_eligibility";
const CONFIG_KEY: &str = "full_projected_adam_config_v1";
const STRATEGY: &str = "contextual_full_encoder_sgd_v1";

/// `canonical(CONFIG)`: sorted keys, compact separators, Python float `repr`.
pub const CONFIG_CANONICAL: &str = "{\"beta1\":0.9,\"beta2\":0.999,\"cpu_threads\":1,\"delta_cap\":0.05,\"device\":\"cpu\",\"epsilon\":1e-08,\"eta\":0.003,\"gradient_denominator\":1,\"margin_coefficient\":1,\"microbatch_size\":32,\"moment_dtype\":\"float64\",\"steps\":64}";

/// Artifact or admission fields, as strings.
pub type Fields = BTreeMap<String, String>;

fn unsupported() -> TrainingError {
    TrainingError::invalid("Window and ORIGINAL-retention optimizer policies are not supported by this port.")
}

/// `validate_policy`: whether the artifact activates FULL Adam.
pub fn validate_policy(metadata: &Fields) -> Result<bool, TrainingError> {
    match metadata.get(OPTIMIZER_KEY).map(String::as_str) {
        Some(POLICY) => {}
        Some(other) if other.contains("window") || other.contains("retention") => return Err(unsupported()),
        _ => {
            if metadata.contains_key(ELIGIBILITY_KEY) || metadata.contains_key(CONFIG_KEY) {
                return Err(TrainingError::invalid("FULL Adam configuration/eligibility requires its optimizer."));
            }
            return Ok(false);
        }
    }
    let exact = metadata.get("contextual_training_strategy").map(String::as_str) == Some(STRATEGY)
        && metadata.get("contextual_training_objective").map(String::as_str) == Some(crate::adam::OBJECTIVE)
        && metadata.get(ELIGIBILITY_KEY).map(String::as_str) == Some(ELIGIBILITY)
        && metadata.get(CONFIG_KEY).map(String::as_str) == Some(CONFIG_CANONICAL)
        && ![
            "contextual_training_backtracking_policy",
            "contextual_training_backtracking_preparation",
            "contextual_training_diagnostics_policy",
        ]
        .iter()
        .any(|key| metadata.contains_key(*key));
    if exact {
        Ok(true)
    } else {
        Err(TrainingError::invalid("FULL Adam requires its exact FULL, SUM-margin, fixed config and eligibility contract."))
    }
}

/// `validate_admission`: the pre-gradient header must match the actual artifact.
pub fn validate_admission(admission: Option<&Fields>, metadata: &Fields) -> Result<bool, TrainingError> {
    let active = validate_policy(metadata)?;
    let expected =
        [("expected_optimizer", POLICY), ("expected_candidate_eligibility", ELIGIBILITY), ("expected_optimizer_config", CONFIG_CANONICAL)];
    if active {
        match admission {
            Some(header) if expected.iter().all(|(key, value)| header.get(*key).map(String::as_str) == Some(*value)) => {}
            _ => return Err(TrainingError::invalid("FULL Adam artifact requires matching explicit pre-gradient admission.")),
        }
    } else if admission.is_some_and(|header| expected.iter().any(|(key, _)| header.contains_key(*key))) {
        return Err(TrainingError::invalid("FULL Adam admission differs from actual artifact."));
    }
    Ok(active)
}
