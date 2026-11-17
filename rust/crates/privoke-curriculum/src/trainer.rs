//! The pure half of `training/trainer.py` and `training/parameter_updates.py`: what the fuzzer prepares before and
//! after the runtime computes gradients.
//!
//! Model execution and the gRPC submission stay with the fuzzer service (stage 21). Here are the seeded augmentation
//! stream, the request validation, and the publication metadata assembly with its compact audit.

use std::collections::{BTreeMap, BTreeSet};

use privoke_contracts::pyfloat;

use crate::error::{Result, invalid};
use crate::pyrandom::Random;
use crate::text::{random_pii_transform, training_text_key};
use crate::types::{BatchTrainingConfig, Example};
use crate::value::{self, Value};

/// Largest expanded training batch plus held-out guard the trainer accepts.
pub const MAX_EXPANDED_EXAMPLES: usize = 1024;

/// `iter_training_examples`: each new example, its seeded invariance transforms, then the golden rows.
pub fn iter_training_examples(new_examples: &[Example], golden_examples: &[Example], config: &BatchTrainingConfig) -> Result<Vec<Example>> {
    let mut rng = Random::new(config.seed);
    let mut out = Vec::with_capacity(new_examples.len() * 2 + golden_examples.len());
    for example in new_examples {
        let weight = example.weight * config.new_example_weight;
        out.push(example.with_text_and_weight(example.text.clone(), weight));
        for _ in 0..config.transformations_per_example.max(0) {
            out.push(example.with_text_and_weight(random_pii_transform(&example.text, &mut rng)?, weight));
        }
    }
    for example in golden_examples {
        out.push(example.with_text_and_weight(example.text.clone(), example.weight * config.golden_example_weight));
    }
    Ok(out)
}

/// `_validate_config`.
pub fn validate_config(config: &BatchTrainingConfig) -> Result<()> {
    if !(0..=1023).contains(&config.transformations_per_example) {
        return invalid("transformations_per_example must be an integer between 0 and 1023.");
    }
    if !config.learning_rate.is_finite() || config.learning_rate <= 0.0 {
        return invalid("learning_rate must be finite and greater than zero.");
    }
    if !config.max_gradient.is_finite() || config.max_gradient <= 0.0 {
        return invalid("max_gradient must be finite and greater than zero.");
    }
    Ok(())
}

/// `_validate_examples`.
pub fn validate_examples(examples: &[Example]) -> Result<()> {
    if examples.is_empty() {
        return invalid("At least one training example is required.");
    }
    if examples.iter().any(|example| !example.weight.is_finite() || example.weight <= 0.0) {
        return invalid("Training example weights must be finite and positive.");
    }
    Ok(())
}

/// The checks and expansion `train_parameter_batch` runs before any runtime call: configuration, the 1024 bound,
/// the expanded stream, weights, and disjointness from the held-out normalised texts.
pub fn prepare_trainer_examples(
    new_examples: &[Example],
    golden_examples: &[Example],
    heldout_examples: &[Example],
    config: &BatchTrainingConfig,
) -> Result<Vec<Example>> {
    validate_config(config)?;
    let expanded_count = new_examples.len() * (config.transformations_per_example as usize + 1);
    if expanded_count + golden_examples.len() + heldout_examples.len() > MAX_EXPANDED_EXAMPLES {
        return invalid("Expanded training plus held-out examples must not exceed 1024.");
    }
    let expanded = iter_training_examples(new_examples, golden_examples, config)?;
    validate_examples(&expanded)?;
    let heldout: BTreeSet<String> = heldout_examples.iter().map(|example| training_text_key(&example.text)).collect();
    if expanded.iter().any(|example| heldout.contains(&training_text_key(&example.text))) {
        return invalid("Held-out examples overlap transformed training texts.");
    }
    Ok(expanded)
}

/// Metadata and metrics an update carries, merged as `emit_training_update` does: metadata, then `str(metric)` for
/// every metric, then the caller's extra metadata.
pub fn merge_publication_metadata(
    metadata: &BTreeMap<String, String>,
    metrics: &BTreeMap<String, f64>,
    extra: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>> {
    let mut merged = metadata.clone();
    for (key, number) in metrics {
        let text = pyfloat::repr(*number).map_err(|_| crate::error::Error::Invalid("non-finite metric".to_string()))?;
        merged.insert(key.clone(), text);
    }
    for (key, text) in extra {
        merged.insert(key.clone(), text.clone());
    }
    Ok(merged)
}

const WEIGHT_KEYS: [&str; 10] = [
    "training_clean_examples",
    "training_sensitive_examples",
    "raw_clean_weight",
    "raw_sensitive_weight",
    "raw_total_weight",
    "effective_clean_weight",
    "effective_sensitive_weight",
    "clean_objective_mass",
    "sensitive_objective_mass",
    "objective_strata",
];

/// The compact publication of `emit_training_update` for `train_before_candidate_v1`: sampling and weight fields move
/// into one `training_audit_v1` JSON string, and the retained complete evidence is bound by its SHA-256.
///
/// `bound_evidence` is the retained record's `{metadata, metrics, execution_evidence}` object.
pub fn compact_training_publication(metadata: &BTreeMap<String, String>, bound_evidence: &Value) -> Result<BTreeMap<String, String>> {
    let audit: BTreeMap<String, Value> = metadata
        .iter()
        .filter(|(key, _)| key.starts_with("sampling_") || WEIGHT_KEYS.contains(&key.as_str()))
        .map(|(key, text)| (key.clone(), value::string(text)))
        .collect();
    // `json.dumps({"schema": 1, "fields": audit}, ...)` keeps insertion order: `schema` first, then the sorted fields.
    let compact = format!("{{\"schema\":1,\"fields\":{}}}", value::dumps_compact(&Value::Object(audit.clone()))?);
    if compact.len() > 2048 {
        return invalid("Compact training audit exceeds publication byte budget.");
    }
    let mut out: BTreeMap<String, String> =
        metadata.iter().filter(|(key, _)| !audit.contains_key(*key)).map(|(key, text)| (key.clone(), text.clone())).collect();
    out.insert("training_audit_v1".to_string(), compact);
    out.insert("training_evidence_sha256".to_string(), value::sha256(value::dumps_compact(bound_evidence)?.as_bytes()));
    Ok(out)
}

/// The opt-in publication limits: at most 64 entries of at most 2048 UTF-8 bytes each.
pub fn check_publication_limits(metadata: &BTreeMap<String, String>) -> Result<()> {
    if metadata.len() > 64 || metadata.values().any(|text| text.len() > 2048) {
        return invalid("Opt-in training publication metadata exceeds its unchanged limits.");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classification::Classification;

    fn example(text: &str) -> Example {
        Example::new(text, Classification(28), 1.0, BTreeMap::new())
    }

    #[test]
    fn stream_has_original_then_transform_per_example() {
        let config = BatchTrainingConfig::default();
        let expanded = iter_training_examples(&[example("a"), example("b")], &[example("g")], &config).unwrap_or_default();
        assert_eq!(expanded.len(), 5);
        assert_eq!(expanded[0].text, "a");
        assert!((expanded[4].weight - 0.35).abs() < f64::EPSILON);
    }

    #[test]
    fn config_bounds_are_enforced() {
        let config = BatchTrainingConfig { transformations_per_example: 1024, ..BatchTrainingConfig::default() };
        assert!(validate_config(&config).is_err());
    }
}
