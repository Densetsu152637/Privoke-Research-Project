//! Validation of incoming updates (`validation.py` and the text rules of `privoke_service.validation`).
//!
//! Every message is the Python text, because the stage 0 corpus records them. `repr` of a name is
//! [`repr_str`](crate::pyfmt::repr_str).

use std::collections::BTreeSet;

use privoke_contracts::proto::v1::{Parameter, ParameterUpdateRequest};
use privoke_model_streaming::artifact::ModelArtifact;
use privoke_model_streaming::contextual::{FULL_ENCODER_STRATEGY, STRATEGY_KEY};

use crate::error::Failure;
use crate::pyfmt::{py_int, repr_str};
use crate::window;

/// Most gradients in one update.
pub const MAX_GRADIENTS: usize = 256;
/// Largest tensor of an update against a legacy artifact.
pub const MAX_GRADIENT_VALUES: usize = 4_096;
/// Largest tensor of an update against a full-encoder artifact.
pub const FULL_ENCODER_MAX_TENSOR_VALUES: usize = 24_576;
/// Most values in one update.
pub const MAX_UPDATE_VALUES: usize = 65_536;
/// Most metadata entries.
pub const MAX_METADATA_ENTRIES: usize = 64;

/// `validate_text`: bounded text before storage or interpolation into logs. Limits count characters.
pub fn validate_text(value: &str, field: &str, required: bool, limit: usize) -> Result<(), Failure> {
    if required && value.is_empty() {
        return Err(Failure::invalid(format!("{field} is required.")));
    }
    if value.chars().count() > limit {
        return Err(Failure::invalid(format!("{field} exceeds {limit} characters.")));
    }
    if value.chars().any(|character| u32::from(character) < 32 || u32::from(character) == 127) {
        return Err(Failure::invalid(format!("{field} must not contain control characters.")));
    }
    Ok(())
}

/// `validate_parameter_update`. With an artifact, the checks that need it run first (model identity, per-tensor bound
/// of the artifact's strategy, shapes, window publication evidence), then the gradient and metadata checks.
pub fn validate_parameter_update(
    request: &ParameterUpdateRequest,
    expected_model_id: &str,
    max_abs_gradient: f64,
    artifact: Option<&ModelArtifact>,
) -> Result<(), Failure> {
    validate_text(&request.source_id, "source_id", true, 128)?;
    validate_text(&request.model_id, "model_id", true, 128)?;
    validate_text(&request.base_version, "base_version", true, 128)?;
    if request.model_id != expected_model_id {
        return Err(Failure::invalid(format!("model_id must be {}.", repr_str(expected_model_id))));
    }
    if request.gradients.is_empty() {
        return Err(Failure::invalid("At least one gradient is required."));
    }
    if request.gradients.len() > MAX_GRADIENTS {
        return Err(Failure::invalid(format!("A parameter update may contain at most {MAX_GRADIENTS} gradients.")));
    }

    let mut maximum = MAX_GRADIENT_VALUES;
    if let Some(artifact) = artifact {
        if artifact.model_id != request.model_id {
            return Err(Failure::invalid("Parameter update does not match the validated artifact model ID."));
        }
        if artifact.metadata().get(STRATEGY_KEY).map(String::as_str) == Some(FULL_ENCODER_STRATEGY) {
            maximum = FULL_ENCODER_MAX_TENSOR_VALUES;
        }
        validate_gradient_shapes_against_artifact(request, artifact)?;
        window::validate_publication(request, artifact)?;
    }
    validate_gradients(&request.gradients, max_abs_gradient, maximum)?;
    validate_metadata(request)?;
    Ok(())
}

fn validate_gradients(gradients: &[Parameter], max_abs_gradient: f64, maximum: usize) -> Result<(), Failure> {
    let mut names: BTreeSet<&str> = BTreeSet::new();
    let mut total_values = 0usize;
    for gradient in gradients {
        validate_text(&gradient.name, "gradient name", true, 256)?;
        if !names.insert(gradient.name.as_str()) {
            return Err(Failure::invalid(format!("Duplicate gradient name: {}.", repr_str(&gradient.name))));
        }
        validate_gradient_shape(gradient, maximum)?;
        validate_gradient_values(gradient, max_abs_gradient)?;
        total_values += gradient.values.len();
    }
    if total_values > MAX_UPDATE_VALUES {
        return Err(Failure::invalid(format!("A parameter update may contain at most {MAX_UPDATE_VALUES} values.")));
    }
    Ok(())
}

fn validate_gradient_shape(gradient: &Parameter, maximum: usize) -> Result<(), Failure> {
    let name = repr_str(&gradient.name);
    if gradient.values.is_empty() {
        return Err(Failure::invalid(format!("Gradient {name} has no values.")));
    }
    if gradient.values.len() > maximum {
        return Err(Failure::invalid(format!("Gradient {name} exceeds {maximum} values.")));
    }
    if gradient.shape.is_empty() {
        return Err(Failure::invalid(format!("Gradient {name} has no shape.")));
    }
    if gradient.shape.contains(&0) {
        return Err(Failure::invalid(format!("Gradient {name} has an invalid shape.")));
    }
    let expected = gradient.shape.iter().fold(1u128, |product, dimension| product.saturating_mul(u128::from(*dimension)));
    if expected != gradient.values.len() as u128 {
        return Err(Failure::invalid(format!("Gradient {name} shape does not match its values.")));
    }
    Ok(())
}

fn validate_gradient_values(gradient: &Parameter, max_abs_gradient: f64) -> Result<(), Failure> {
    if gradient.values.iter().any(|value| !value.is_finite() || f64::from(*value).abs() > max_abs_gradient) {
        return Err(Failure::invalid(format!("Gradient {} contains a non-finite or out-of-range value.", repr_str(&gradient.name))));
    }
    Ok(())
}

fn validate_metadata(request: &ParameterUpdateRequest) -> Result<(), Failure> {
    let metadata = &request.metadata;
    if metadata.len() > MAX_METADATA_ENTRIES {
        return Err(Failure::invalid(format!("metadata may contain at most {MAX_METADATA_ENTRIES} entries.")));
    }
    for (key, value) in metadata {
        validate_text(key, "metadata key", true, 128)?;
        validate_text(value, "metadata value", false, 2_048)?;
    }
    if let Some(text) = metadata.get("generated_prompt_count") {
        let Some(count) = py_int(text) else {
            return Err(Failure::invalid("generated_prompt_count must be an integer."));
        };
        if !(0..=1_024).contains(&count) {
            return Err(Failure::invalid("generated_prompt_count must be between 0 and 1024."));
        }
    }
    Ok(())
}

/// `validate_gradient_shapes_against_artifact`: a tensor the artifact holds must be sent with exactly its shape.
/// A name the artifact does not hold is left to the apply step, which reports it as unknown.
pub fn validate_gradient_shapes_against_artifact(request: &ParameterUpdateRequest, artifact: &ModelArtifact) -> Result<(), Failure> {
    for gradient in &request.gradients {
        let Some(tensor) = artifact.parameters.get(&gradient.name) else { continue };
        if gradient.shape != tensor.shape {
            return Err(Failure::invalid(format!("Parameter shape mismatch for {}.", repr_str(&gradient.name))));
        }
    }
    Ok(())
}

/// The Euclidean norm of every gradient value (float32 values widened to f64, summed in request order).
pub fn update_l2(request: &ParameterUpdateRequest) -> f64 {
    request
        .gradients
        .iter()
        .flat_map(|gradient| gradient.values.iter())
        .map(|value| f64::from(*value) * f64::from(*value))
        .sum::<f64>()
        .sqrt()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn request() -> ParameterUpdateRequest {
        ParameterUpdateRequest {
            source_id: "test-fuzzer".into(),
            model_id: "privoke-baseline".into(),
            base_version: "v1".into(),
            gradients: vec![Parameter { name: "head.sensitivity.bias".into(), values: vec![0.0, 0.0, 0.0, 0.01], shape: vec![4] }],
            metadata: [("request_id".to_string(), "test-1".to_string())].into_iter().collect(),
        }
    }

    fn rejected(mutate: impl FnOnce(&mut ParameterUpdateRequest)) -> String {
        let mut value = request();
        mutate(&mut value);
        validate_parameter_update(&value, "privoke-baseline", 1.0, None).unwrap_err().message().to_string()
    }

    #[test]
    fn accepts_a_bounded_update() {
        validate_parameter_update(&request(), "privoke-baseline", 1.0, None).unwrap();
    }

    #[test]
    fn rejects_the_python_cases_with_the_python_messages() {
        assert!(rejected(|r| r.gradients[0].values[0] = f32::NAN).contains("non-finite"));
        assert_eq!(rejected(|r| r.model_id = "other-model".into()), "model_id must be 'privoke-baseline'.");
        assert!(rejected(|r| r.gradients[0].shape = vec![2]).contains("shape"));
        assert!(rejected(|r| r.gradients[0].shape.clear()).contains("no shape"));
        assert!(rejected(|r| r.source_id = "attacker\nforged-log".into()).contains("control"));
        assert_eq!(rejected(|r| r.source_id.clear()), "source_id is required.");
        assert_eq!(rejected(|r| r.gradients.clear()), "At least one gradient is required.");
        assert!(rejected(|r| r.gradients[0].values[1] = 1.0000001).contains("out-of-range"));
        assert_eq!(
            rejected(|r| {
                r.metadata.insert("generated_prompt_count".into(), "1025".into());
            }),
            "generated_prompt_count must be between 0 and 1024."
        );
        assert_eq!(
            rejected(|r| {
                r.metadata.insert("generated_prompt_count".into(), "many".into());
            }),
            "generated_prompt_count must be an integer."
        );
    }

    #[test]
    fn per_tensor_and_total_limits() {
        let big = |count: usize, name: &str| Parameter {
            name: name.into(),
            values: vec![0.0; count],
            shape: vec![u32::try_from(count).unwrap()],
        };
        assert!(rejected(|r| r.gradients = vec![big(4_097, "a")]).contains("exceeds 4096 values"));
        assert!(rejected(|r| r.gradients = (0..257).map(|i| big(1, &format!("g{i}"))).collect()).contains("at most 256 gradients"));
        assert!(rejected(|r| r.gradients = (0..17).map(|i| big(4_000, &format!("g{i}"))).collect()).contains("at most 65536 values"));
        let mut metadata_heavy = request();
        for index in 0..65 {
            metadata_heavy.metadata.insert(format!("k{index}"), "v".into());
        }
        assert!(
            validate_parameter_update(&metadata_heavy, "privoke-baseline", 1.0, None).unwrap_err().message().contains("at most 64 entries")
        );
    }

    #[test]
    fn the_norm_is_the_euclidean_norm() {
        let mut value = request();
        value.gradients[0].values = vec![3.0, 4.0, 0.0, 0.0];
        assert!((update_l2(&value) - 5.0).abs() < 1e-12);
    }
}
