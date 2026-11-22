//! `runtime_client.validate_training_policy_response`: the admission of the policy evidence a runtime reports with its
//! gradients (the executed objective, the TRAIN diagnostics, the optimizer identity and the 64-step trace) against what the
//! caller asked for. Every failure is Python's `RuntimeAnalysisError`.
//!
//! The TRAIN diagnostics and the backtracking evidence are admitted by [`crate::diagnostics`] (RUST-S21G item 3).

use std::collections::BTreeMap;

use privoke_contracts::fingerprint::parameter_fingerprint;
use privoke_contracts::proto::v1::{ComputeSemanticGradientsRequest, ComputeSemanticGradientsResponse};

use crate::error::{Error, Result};
use crate::full_adam::{CONFIG_KEY, ELIGIBILITY, validate_trace};
use crate::policy::{Expectations, FULL_ADAM_POLICY, PROCESS_OBJECTIVES, RETENTION_ELIGIBILITY, SUM_MARGIN};

const EXECUTED_OBJECTIVE_KEY: &str = "executed_contextual_training_objective";
const DIAGNOSTICS_POLICY_KEY: &str = "contextual_training_diagnostics_policy";
const DIAGNOSTICS_KEY: &str = "contextual_training_diagnostics";
const RETENTION_MANIFEST_KEY: &str = "original_train_retention_manifest_sha256";

fn reject<T>(message: &str) -> Result<T> {
    Err(Error(message.to_string()))
}

/// `parameter_fingerprint` of the tensors a response carries: the delta the trace binds.
pub fn response_delta_fingerprint(response: &ComputeSemanticGradientsResponse) -> Result<String> {
    let values: BTreeMap<String, Vec<f64>> = response
        .gradients
        .iter()
        .map(|parameter| (parameter.name.clone(), parameter.values.iter().map(|value| f64::from(*value)).collect()))
        .collect();
    let shapes: BTreeMap<String, Vec<u64>> = response
        .gradients
        .iter()
        .map(|parameter| (parameter.name.clone(), parameter.shape.iter().map(|size| u64::from(*size)).collect()))
        .collect();
    parameter_fingerprint(&values, Some(&shapes)).map_err(|error| Error(error.to_string()))
}

/// `validate_training_policy_response(request, response, **expectations)`.
pub fn validate_training_policy_response(
    request: &ComputeSemanticGradientsRequest,
    response: &ComputeSemanticGradientsResponse,
    expectations: &Expectations,
) -> Result<()> {
    let metadata = &response.metadata;
    let expected_objective = expectations.get("expected_objective");
    let actual = metadata.get(EXECUTED_OBJECTIVE_KEY).map(String::as_str);
    if !actual.is_some_and(|name| PROCESS_OBJECTIVES.contains(&name)) || expected_objective.is_some_and(|name| Some(name) != actual) {
        return reject("Runtime executed a different or missing objective policy.");
    }
    let diagnostics = expectations.get("expected_diagnostics_policy");
    if expected_objective == Some(SUM_MARGIN)
        && diagnostics.is_none()
        && (metadata.contains_key(DIAGNOSTICS_POLICY_KEY) || metadata.contains_key(DIAGNOSTICS_KEY))
    {
        return reject("Runtime unexpectedly enabled TRAIN diagnostics.");
    }
    if let Some(diagnostics) = diagnostics {
        if metadata.get(DIAGNOSTICS_POLICY_KEY).map(String::as_str) != Some(diagnostics) {
            return reject("Runtime executed a different or missing TRAIN diagnostic policy.");
        }
        if crate::diagnostics::validate_response_diagnostics(request, response).is_err() {
            return reject("Runtime TRAIN diagnostics failed admission.");
        }
    }
    if expectations.get("expected_backtracking_policy").is_some() {
        crate::diagnostics::validate_backtracking_response(request, response, expectations, false)?;
    }
    let Some(optimizer) = expectations.get("expected_optimizer") else { return Ok(()) };
    let retention = crate::full_adam::RETENTION_POLICIES.contains(&optimizer);
    if !(optimizer == FULL_ADAM_POLICY || retention)
        || expectations.get("expected_candidate_eligibility") != Some(if retention { RETENTION_ELIGIBILITY } else { ELIGIBILITY })
        || metadata.get(CONFIG_KEY).map(String::as_str) != expectations.get("expected_optimizer_config")
        || metadata.get("training_scope").map(String::as_str) != expectations.get("expected_training_scope")
    {
        return reject("Runtime FULL Adam policy identity differs.");
    }
    if retention && metadata.get(RETENTION_MANIFEST_KEY).map(String::as_str) != expectations.get("expected_retention_manifest_sha256") {
        return reject("Runtime ORIGINAL retention manifest differs.");
    }
    let trace = trace_admission(request, response);
    if trace.is_err() {
        return reject("Runtime FULL Adam trace failed admission.");
    }
    Ok(())
}

/// `validate_trace` over the response's own identities and tensors.
fn trace_admission(request: &ComputeSemanticGradientsRequest, response: &ComputeSemanticGradientsResponse) -> Result<()> {
    let metadata = &response.metadata;
    let scope = metadata.get("training_scope").ok_or_else(|| Error("'training_scope'".to_string()))?;
    let candidate = metadata.get("updated_parameter_fingerprint").ok_or_else(|| Error("'updated_parameter_fingerprint'".to_string()))?;
    validate_trace(metadata, scope, request.examples.len(), candidate, &response_delta_fingerprint(response)?)?;
    Ok(())
}
