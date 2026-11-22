//! `ComputePresenceGradients`: the sparse annotation-presence model (`privoke_model/presence.py`, additive to the
//! stage 14 scope, which did not port it) and `presence_training.compute_presence_gradients`.
//!
//! The model is a TF-IDF logistic head: word 1-2-gram and character 3-5-gram counts over `training_text_key`, a
//! sublinear tf, the immutable IDF, one L2 norm per branch, and a trainable coefficient vector plus bias. Arithmetic is
//! float64 over float32 parameters with `math.fsum` reductions, so the Rust result follows Python up to libm
//! differences in `ln`, `exp` and `sqrt`.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use privoke_contracts::fingerprint::parameter_fingerprint;
use privoke_rules::pyunicode;
use serde_json::Value;

use crate::error::TrainingError;
use crate::objective::fsum;
use crate::rpc::training_text_key;

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

    /// The same vocabulary with other parameters (float32-exact values).
    pub fn with_parameters(&self, parameters: BTreeMap<String, Vec<f64>>) -> Result<Self, TrainingError> {
        let weights: Vec<&String> = parameters.keys().filter(|n| n.starts_with(WEIGHT_PREFIX)).collect();
        let coefficients: Vec<f64> = weights.iter().flat_map(|n| parameters[*n].iter().copied()).collect();
        if parameters.keys().ne(self.parameters.keys()) || coefficients.len() != self.coefficients.len() {
            return Err(invalid("Presence tensor manifest is incomplete or contains unknown tensors."));
        }
        Ok(Self { parameters, coefficients, ..self.clone() })
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

    /// `presence_head_deltas(text, target)`: unscaled BCE ascent deltas per trainable tensor.
    pub fn presence_head_deltas(&self, text: &str, target: bool) -> BTreeMap<String, Vec<f64>> {
        let residual = f64::from(u8::from(target)) - self.predict_probability(text);
        let features = self.features(text);
        let mut deltas = BTreeMap::new();
        let mut offset = 0;
        for (name, values) in self.parameters.iter().filter(|(n, _)| n.starts_with(WEIGHT_PREFIX)) {
            deltas
                .insert(name.clone(), (0..values.len()).map(|j| residual * features.get(&(offset + j)).copied().unwrap_or(0.0)).collect());
            offset += values.len();
        }
        deltas.insert(BIAS.to_string(), vec![residual]);
        deltas
    }
}

/// A presence training row.
#[derive(Debug, Clone, PartialEq)]
pub struct PresenceExample {
    /// Prompt text.
    pub text: String,
    /// Whether an annotation is present.
    pub target: bool,
    /// Positive finite weight.
    pub weight: f64,
    /// Group identifier (held-out groups must be disjoint).
    pub group_id: String,
}

/// The snapshot a presence computation reads.
#[derive(Debug, Clone)]
pub struct PresenceSnapshot {
    /// Artifact JSON (`config`, `parameters`).
    pub artifact: Value,
    /// Model version, `release[+train.N]`.
    pub version: String,
}

/// One presence request.
#[derive(Debug, Clone)]
pub struct PresenceRequest {
    /// Training rows.
    pub examples: Vec<PresenceExample>,
    /// Held-out rows (required).
    pub heldout: Vec<PresenceExample>,
    /// Learning rate.
    pub learning_rate: f64,
    /// Bound of one transported coordinate.
    pub max_gradient: f64,
}

/// The response of a presence computation.
#[derive(Debug, Clone)]
pub struct PresenceBatch {
    /// Transported update per trainable tensor.
    pub gradients: BTreeMap<String, Vec<f32>>,
    /// Response metrics.
    pub metrics: BTreeMap<String, f64>,
    /// `(phase, rows)`.
    pub executions: Vec<(String, usize)>,
    /// Release and fingerprint metadata (a subset of the Python metadata).
    pub metadata: BTreeMap<String, String>,
    /// The candidate parameters.
    pub candidate: BTreeMap<String, Vec<f32>>,
}

fn blank(text: &str) -> bool {
    text.chars().all(pyunicode::is_space)
}

fn validate(examples: &[PresenceExample], name: &str) -> Result<(), TrainingError> {
    let mut keys = Vec::new();
    for item in examples {
        if blank(&item.text) {
            return Err(TrainingError::invalid(format!("{name} example text is required.")));
        }
        if blank(&item.group_id) {
            return Err(TrainingError::invalid(format!("{name} group_id is required.")));
        }
        if !item.weight.is_finite() || item.weight <= 0.0 {
            return Err(TrainingError::invalid(format!("{name} weights must be finite and positive.")));
        }
        let key = training_text_key(&item.text);
        if key.is_empty() {
            return Err(TrainingError::invalid(format!("{name} text is empty after normalization.")));
        }
        keys.push(key);
    }
    if keys.iter().collect::<BTreeSet<_>>().len() != keys.len() {
        return Err(TrainingError::invalid(format!("{name} texts must be distinct after normalization.")));
    }
    if examples.iter().map(|e| e.target).collect::<BTreeSet<_>>().len() != 2 {
        return Err(TrainingError::invalid(format!("{name} examples require both binary labels.")));
    }
    Ok(())
}

fn cross_entropy(target: bool, probability: f64) -> f64 {
    let p = probability.clamp(1e-15, 1.0 - 1e-15);
    -(if target { p } else { 1.0 - p }).ln()
}

fn heldout_metrics(model: &PresenceModel, examples: &[PresenceExample]) -> Result<BTreeMap<String, f64>, TrainingError> {
    let total_weight = fsum(examples.iter().map(|e| e.weight));
    if !total_weight.is_finite() || total_weight <= 0.0 {
        return Err(invalid("Held-out weights must have a finite positive total."));
    }
    let (mut loss, mut correct, mut present, mut present_correct, mut absent, mut absent_correct) =
        (0.0, 0usize, 0usize, 0usize, 0usize, 0usize);
    for item in examples {
        let probability = model.predict_probability(&item.text);
        let predicted = probability >= model.threshold;
        loss += cross_entropy(item.target, probability) * item.weight;
        correct += usize::from(predicted == item.target);
        if item.target {
            present += 1;
            present_correct += usize::from(predicted);
        } else {
            absent += 1;
            absent_correct += usize::from(!predicted);
        }
    }
    let n = examples.len() as f64;
    Ok(BTreeMap::from([
        ("heldout_examples".to_string(), n),
        ("heldout_present_examples".to_string(), present as f64),
        ("heldout_absent_examples".to_string(), absent as f64),
        ("heldout_average_loss".to_string(), loss / total_weight),
        ("heldout_exact_match_rate".to_string(), correct as f64 / n),
        ("heldout_present_recall".to_string(), present_correct as f64 / present as f64),
        ("heldout_absent_specificity".to_string(), absent_correct as f64 / absent as f64),
    ]))
}

fn round8(x: f64) -> f64 {
    format!("{x:.8}").parse().unwrap_or(x)
}

fn fingerprint(values: &BTreeMap<String, Vec<f64>>, shapes: &BTreeMap<String, Vec<u64>>) -> Result<String, TrainingError> {
    Ok(parameter_fingerprint(values, Some(shapes))?)
}

/// `compute_presence_gradients`.
pub fn compute_presence_gradients(snapshot: &PresenceSnapshot, request: &PresenceRequest) -> Result<PresenceBatch, TrainingError> {
    if request.examples.is_empty() {
        return Err(invalid("At least one training example is required."));
    }
    if !request.learning_rate.is_finite() || request.learning_rate <= 0.0 {
        return Err(invalid("learning_rate must be finite and greater than zero."));
    }
    if !request.max_gradient.is_finite() || request.max_gradient <= 0.0 {
        return Err(invalid("max_gradient must be finite and greater than zero."));
    }
    validate(&request.examples, "Training")?;
    if request.heldout.is_empty() {
        return Err(invalid("Presence training requires nonempty held-out examples."));
    }
    validate(&request.heldout, "Held-out")?;
    let training_keys: BTreeSet<String> = request.examples.iter().map(|e| training_text_key(&e.text)).collect();
    if request.heldout.iter().any(|e| training_keys.contains(&training_text_key(&e.text))) {
        return Err(invalid("Held-out texts must be separate from training texts."));
    }
    let groups: BTreeSet<&str> = request.examples.iter().map(|e| e.group_id.as_str()).collect();
    if request.heldout.iter().any(|e| groups.contains(e.group_id.as_str())) {
        return Err(invalid("Held-out groups must be separate from training groups."));
    }
    let model = PresenceModel::from_artifact(&snapshot.artifact)?;
    let trainable: BTreeSet<&String> = model.parameters.keys().filter(|n| n.starts_with("head.presence.")).collect();
    let mut sums: BTreeMap<String, Vec<f64>> = trainable.iter().map(|n| ((*n).clone(), vec![0.0; model.parameters[*n].len()])).collect();
    let total_weight = fsum(request.examples.iter().map(|e| e.weight));
    if !total_weight.is_finite() || total_weight <= 0.0 {
        return Err(invalid("Training weights must have a finite positive total."));
    }
    let (mut total_loss, mut exact) = (0.0, 0usize);
    for item in &request.examples {
        let probability = model.predict_probability(&item.text);
        total_loss += cross_entropy(item.target, probability) * item.weight;
        exact += usize::from((probability >= model.threshold) == item.target);
        for (name, values) in model.presence_head_deltas(&item.text, item.target) {
            let slot = sums.get_mut(&name).ok_or_else(|| invalid("Presence head returned an unexpected delta manifest."))?;
            for (sum, value) in slot.iter_mut().zip(&values) {
                if !value.is_finite() {
                    return Err(invalid("Presence gradient contains a non-finite value."));
                }
                *sum += value * item.weight;
            }
        }
    }
    if !total_loss.is_finite() {
        return Err(invalid("Training loss must remain finite."));
    }
    let bound = request.max_gradient;
    let gradients: BTreeMap<String, Vec<f32>> = sums
        .iter()
        .map(|(n, v)| (n.clone(), v.iter().map(|x| (x / total_weight * request.learning_rate).clamp(-bound, bound) as f32).collect()))
        .collect();
    let mut candidate_values: BTreeMap<String, Vec<f64>> = BTreeMap::new();
    let mut candidate: BTreeMap<String, Vec<f32>> = BTreeMap::new();
    for (name, values) in &model.parameters {
        let updated: Vec<f32> = match gradients.get(name) {
            Some(g) => values.iter().zip(g).map(|(b, d)| round8(*b + f64::from(*d)) as f32).collect(),
            None => values.iter().map(|v| *v as f32).collect(),
        };
        candidate_values.insert(name.clone(), updated.iter().map(|v| f64::from(*v)).collect());
        candidate.insert(name.clone(), updated);
    }
    let candidate_model = model.with_parameters(candidate_values.clone())?;
    let mut metrics = BTreeMap::from([
        ("examples".to_string(), request.examples.len() as f64),
        ("average_loss".to_string(), total_loss / total_weight),
        ("exact_match_rate".to_string(), exact as f64 / request.examples.len() as f64),
        ("total_weight".to_string(), total_weight),
    ]);
    metrics.extend(heldout_metrics(&model, &request.heldout)?);
    for (key, value) in heldout_metrics(&candidate_model, &request.heldout)? {
        metrics.insert(format!("candidate_{key}"), value);
    }
    let (release, separator, revision) = match snapshot.version.split_once("+train.") {
        Some((release, revision)) => (release, true, revision),
        None => (snapshot.version.as_str(), false, ""),
    };
    if release.is_empty() || (separator && (revision.is_empty() || !revision.chars().all(pyunicode::is_decimal))) {
        return Err(invalid("Presence model version has an invalid training revision suffix."));
    }
    let delta_values: BTreeMap<String, Vec<f64>> =
        gradients.iter().map(|(n, v)| (n.clone(), v.iter().map(|x| f64::from(*x)).collect())).collect();
    let delta_shapes: BTreeMap<String, Vec<u64>> = gradients.keys().map(|n| (n.clone(), model.shapes[n].clone())).collect();
    let candidate_fingerprint = fingerprint(&candidate_values, &model.shapes)?;
    let metadata = BTreeMap::from([
        ("release_version".to_string(), release.to_string()),
        ("training_revision".to_string(), if separator { revision.trim_start_matches('0').to_string() } else { "0".to_string() }),
        ("profile".to_string(), model.profile.clone()),
        ("base_parameter_fingerprint".to_string(), fingerprint(&model.parameters, &model.shapes)?),
        ("updated_parameter_fingerprint".to_string(), candidate_fingerprint.clone()),
        ("candidate_parameter_fingerprint".to_string(), candidate_fingerprint),
        ("publication_delta_fingerprint".to_string(), fingerprint(&delta_values, &delta_shapes)?),
    ]);
    let metadata = {
        let mut m = metadata;
        if m["training_revision"].is_empty() {
            m.insert("training_revision".to_string(), "0".to_string());
        }
        m
    };
    Ok(PresenceBatch {
        gradients,
        metrics,
        executions: vec![
            ("training".to_string(), request.examples.len()),
            ("base_heldout".to_string(), request.heldout.len()),
            ("candidate_heldout".to_string(), request.heldout.len()),
        ],
        metadata,
        candidate,
    })
}
