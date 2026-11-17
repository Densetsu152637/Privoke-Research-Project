//! `privoke_service.validate_text` and the request validators of `fuzzer_service.py`.

use privoke_contracts::proto::v1::FuzzerTrainingRequest;
use privoke_curriculum::generator::validate_contextual_sampling_strategy;
use privoke_curriculum::train_window;

use crate::error::{Result, invalid};

/// The metadata key that selects a contextual sampling strategy.
pub const CONTEXTUAL_SAMPLING_STRATEGY_KEY: &str = "contextual_sampling_strategy";

/// `validate_text`: bounded text without control characters (the limit counts code points, as Python's `len`).
pub fn validate_text(value: &str, name: &str, required: bool, limit: usize) -> Result<()> {
    if required && value.is_empty() {
        return invalid(format!("{name} is required."));
    }
    if value.chars().count() > limit {
        return invalid(format!("{name} exceeds {limit} characters."));
    }
    if value.chars().any(|character| u32::from(character) < 32 || u32::from(character) == 127) {
        return invalid(format!("{name} must not contain control characters."));
    }
    Ok(())
}

fn validate_metadata(request: &FuzzerTrainingRequest) -> Result<()> {
    if request.metadata.len() > 64 {
        return invalid("metadata may contain at most 64 entries.");
    }
    for (key, value) in &request.metadata {
        validate_text(key, "metadata key", true, 128)?;
        validate_text(value, "metadata value", false, 2_048)?;
    }
    Ok(())
}

/// `validate_training_request`. A window sampling request passes here: the cycle refuses it as a named gap.
pub fn validate_training_request(request: &FuzzerTrainingRequest, expected_model_id: &str) -> Result<()> {
    validate_text(&request.request_id, "request_id", true, 128)?;
    validate_text(&request.source_id, "source_id", true, 128)?;
    validate_text(&request.model_id, "model_id", false, 128)?;
    if !request.model_id.is_empty() && request.model_id != expected_model_id {
        return invalid(format!("model_id must be '{expected_model_id}'."));
    }
    if request.prompt_count == 0 {
        return invalid("prompt_count must be greater than zero.");
    }
    validate_metadata(request)?;
    if let Some(strategy) = request.metadata.get(CONTEXTUAL_SAMPLING_STRATEGY_KEY)
        && strategy != train_window::SAMPLER
    {
        validate_contextual_sampling_strategy(strategy, i64::from(request.prompt_count))?;
    }
    Ok(())
}

/// `validate_presence_training_request`.
pub fn validate_presence_training_request(request: &FuzzerTrainingRequest, expected_model_id: &str) -> Result<()> {
    validate_text(&request.request_id, "request_id", true, 128)?;
    validate_text(&request.source_id, "source_id", true, 128)?;
    validate_text(&request.model_id, "model_id", true, 128)?;
    if request.model_id != expected_model_id {
        return invalid(format!("model_id must be '{expected_model_id}'."));
    }
    if request.prompt_count < 2 {
        return invalid("Presence prompt_count must be at least two to train both binary classes.");
    }
    validate_metadata(request)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn request() -> FuzzerTrainingRequest {
        FuzzerTrainingRequest {
            request_id: "r".into(),
            source_id: "s".into(),
            model_id: "m".into(),
            prompt_count: 8,
            ..FuzzerTrainingRequest::default()
        }
    }

    #[test]
    fn text_limits_and_control_characters() {
        assert!(validate_text("", "x", true, 4).is_err());
        assert!(validate_text("abcde", "x", false, 4).is_err());
        assert!(validate_text("a\u{7f}", "x", false, 4).is_err());
        assert!(validate_text("a\nb", "x", false, 4).is_err());
        assert!(validate_text("\u{e9}\u{e9}\u{e9}\u{e9}", "x", false, 4).is_ok());
    }

    #[test]
    fn a_request_is_checked_in_the_python_order() {
        assert!(validate_training_request(&request(), "m").is_ok());
        assert_eq!(validate_training_request(&request(), "other").unwrap_err().0, "model_id must be 'other'.");
        let mut zero = request();
        zero.prompt_count = 0;
        assert_eq!(validate_training_request(&zero, "m").unwrap_err().0, "prompt_count must be greater than zero.");
        let mut many = request();
        for index in 0..65 {
            many.metadata.insert(format!("k{index}"), String::new());
        }
        assert_eq!(validate_training_request(&many, "m").unwrap_err().0, "metadata may contain at most 64 entries.");
    }

    #[test]
    fn presence_requests_need_two_prompts_and_a_model() {
        let mut one = request();
        one.prompt_count = 1;
        assert!(validate_presence_training_request(&one, "m").is_err());
        one.prompt_count = 2;
        assert!(validate_presence_training_request(&one, "m").is_ok());
        one.model_id.clear();
        assert_eq!(validate_presence_training_request(&one, "m").unwrap_err().0, "model_id is required.");
    }
}
