//! The sparse annotation-presence model (`privoke_model/presence.py`, additive to the stage 14 scope, which did not port
//! it): inference only. `compute_presence_gradients` (the V1 presence training) was removed in stage V3-R8a; presence
//! training is retired (decision U4) while the presence gate keeps serving detection.
//!
//! The model is a TF-IDF logistic head: word 1-2-gram and character 3-5-gram counts over `training_text_key`, a
//! sublinear tf, the immutable IDF, one L2 norm per branch, and a trainable coefficient vector plus bias. Arithmetic is
//! float64 over float32 parameters with `math.fsum` reductions, so the Rust result follows Python up to libm
//! differences in `ln`, `exp` and `sqrt`.

use std::collections::{BTreeMap, HashMap};

use privoke_rules::pyunicode;
use serde_json::Value;

use crate::error::TrainingError;
use crate::pycompat::{fsum, training_text_key};

const BIAS: &str = "head.presence.bias";
const WEIGHT_PREFIX: &str = "head.presence.weight.";

fn invalid(message: &str) -> TrainingError {
    TrainingError::invalid(message)
}

/// The immutable-vocabulary presence model.
#[derive(Debug, Clone)]
pub struct PresenceModel {
    threshold: f64,
    /// Profile name.
    pub profile: String,
    vocabularies: [HashMap<String, usize>; 2],
    sizes: [usize; 2],
    /// Parameters by name (float32-exact values).
    pub parameters: BTreeMap<String, Vec<f64>>,
    /// Shapes by name.
    pub shapes: BTreeMap<String, Vec<u64>>,
    coefficients: Vec<f64>,
}

impl PresenceModel {
    /// Build from an artifact (`config`, `parameters`).
    pub fn from_artifact(artifact: &Value) -> Result<Self, TrainingError> {
        let config = artifact.get("config").ok_or_else(|| invalid("Presence config has missing or unknown fields."))?;
        let entries = artifact
            .get("parameters")
            .and_then(Value::as_object)
            .ok_or_else(|| invalid("Artifact config and parameters must be objects."))?;
        let mut parameters = BTreeMap::new();
        let mut shapes = BTreeMap::new();
        for (name, tensor) in entries {
            let values: Vec<f64> = tensor
                .get("values")
                .and_then(Value::as_array)
                .and_then(|v| v.iter().map(|x| x.as_f64().map(|x| f64::from(x as f32))).collect())
                .ok_or_else(|| invalid("Presence tensor has invalid values."))?;
            let shape: Vec<u64> = tensor
                .get("shape")
                .and_then(Value::as_array)
                .and_then(|v| v.iter().map(Value::as_u64).collect())
                .ok_or_else(|| invalid("Presence tensor has the wrong shape."))?;
            if shape != [values.len() as u64] || values.iter().any(|v| !v.is_finite()) {
                return Err(invalid("Presence tensor has the wrong shape or value."));
            }
            parameters.insert(name.clone(), values);
            shapes.insert(name.clone(), shape);
        }
        Self::build(config, parameters, shapes)
    }

    fn build(config: &Value, parameters: BTreeMap<String, Vec<f64>>, shapes: BTreeMap<String, Vec<u64>>) -> Result<Self, TrainingError> {
        let threshold = config
            .get("threshold")
            .and_then(Value::as_f64)
            .filter(|t| (0.0..=1.0).contains(t))
            .ok_or_else(|| invalid("Presence threshold must be finite and in [0, 1]."))?;
        let profile = config.get("profile").and_then(Value::as_str).ok_or_else(|| invalid("Unsupported presence profile."))?.to_string();
        let mut vocabularies: [HashMap<String, usize>; 2] = [HashMap::new(), HashMap::new()];
        let mut sizes = [0usize; 2];
        for (slot, branch) in ["word", "char"].into_iter().enumerate() {
            let features = config
                .get("branches")
                .and_then(|b| b.get(branch))
                .and_then(|b| b.get("features"))
                .and_then(Value::as_array)
                .filter(|f| !f.is_empty())
                .ok_or_else(|| invalid("Presence vocabulary is empty or exceeds its profile bound."))?;
            for (index, feature) in features.iter().enumerate() {
                let text = feature
                    .as_str()
                    .filter(|t| !t.is_empty())
                    .ok_or_else(|| invalid("Presence vocabulary must contain unique nonempty Unicode strings."))?;
                if vocabularies[slot].insert(text.to_string(), index).is_some() {
                    return Err(invalid("Presence vocabulary must contain unique nonempty Unicode strings."));
                }
            }
            sizes[slot] = features.len();
            let idf =
                parameters.get(&format!("features.{branch}.idf")).ok_or_else(|| invalid("Presence tensor manifest is incomplete."))?;
            if idf.len() != sizes[slot] || idf.iter().any(|v| *v <= 0.0) {
                return Err(invalid("Presence IDF values must be positive finite float32 values."));
            }
        }
        let weights: Vec<&String> = parameters.keys().filter(|n| n.starts_with(WEIGHT_PREFIX)).collect();
        let coefficients: Vec<f64> = weights.iter().flat_map(|n| parameters[*n].iter().copied()).collect();
        if coefficients.len() != sizes[0] + sizes[1] || parameters.get(BIAS).is_none_or(|b| b.len() != 1) {
            return Err(invalid("Presence tensor manifest is incomplete or contains unknown tensors."));
        }
        Ok(Self { threshold, profile, vocabularies, sizes, parameters, shapes, coefficients })
    }

    /// The model's decision threshold (`SparsePresenceModel.threshold`): a text is `PRESENT` at or above it.
    pub fn threshold(&self) -> f64 {
        self.threshold
    }

    /// `features(text)`: sparse L2-normalised TF-IDF per branch, indexed word columns first.
    pub fn features(&self, text: &str) -> BTreeMap<usize, f64> {
        let key = training_text_key(text);
        let chars: Vec<char> = key.chars().collect();
        let mut tokens: Vec<String> = Vec::new();
        let mut run = String::new();
        let mut length = 0;
        for &c in &chars {
            if pyunicode::is_word(c) {
                run.push(c);
                length += 1;
            } else {
                if length >= 2 {
                    tokens.push(std::mem::take(&mut run));
                }
                run.clear();
                length = 0;
            }
        }
        if length >= 2 {
            tokens.push(run);
        }
        let mut counts: [BTreeMap<String, usize>; 2] = [BTreeMap::new(), BTreeMap::new()];
        for token in &tokens {
            *counts[0].entry(token.clone()).or_default() += 1;
        }
        for pair in tokens.windows(2) {
            *counts[0].entry(format!("{} {}", pair[0], pair[1])).or_default() += 1;
        }
        for size in 3..=5 {
            for window in chars.windows(size) {
                *counts[1].entry(window.iter().collect()).or_default() += 1;
            }
        }
        let mut result = BTreeMap::new();
        let mut offset = 0;
        for (slot, branch) in ["word", "char"].into_iter().enumerate() {
            let idf = &self.parameters[&format!("features.{branch}.idf")];
            let values: BTreeMap<usize, f64> = counts[slot]
                .iter()
                .filter_map(|(feature, count)| {
                    self.vocabularies[slot].get(feature).map(|index| (*index, (1.0 + (*count as f64).ln()) * idf[*index]))
                })
                .collect();
            let norm = fsum(values.values().map(|v| v * v)).sqrt();
            if norm != 0.0 {
                for (index, value) in &values {
                    result.insert(offset + index, value / norm);
                }
            }
            offset += self.sizes[slot];
        }
        result
    }

    /// `predict_probability(text)`.
    pub fn predict_probability(&self, text: &str) -> f64 {
        let features = self.features(text);
        let logit = fsum(features.iter().map(|(i, v)| self.coefficients[*i] * v)) + self.parameters[BIAS][0];
        if logit >= 0.0 {
            1.0 / (1.0 + (-logit).exp())
        } else {
            let e = logit.exp();
            e / (1.0 + e)
        }
    }
}
