//! The legacy Tiny transformer (`model.py::TinyTransformerModel`, `transformer_encoder.py`, `task_readout.py`) and the
//! streamed-model wrapper that turns its prediction into a finding (`streamed_model.py::classify`).
//!
//! The CPU path of the Python runtime is the NumPy one; this port follows it: hashed word tokens, learned positions,
//! post-norm blocks without affine layer norm and with the tanh GELU, and either the mean/first pooling
//! (`legacy_pool_v1`) or the residual task-query readout (`residual_task_query_v1`).

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use privoke_rules::classification::Classification;
use privoke_rules::pyunicode;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::error::SemanticError;
use crate::labels::{
    CATEGORY, Prediction, SENSITIVITY, VISIBILITY, argmax, category_bit, is_empty_classification, reported_confidence, sensitivity_value,
    visibility_value,
};
use crate::layer::{Finding, SemanticClassifier};
use crate::math::{Dense, attention, gelu_tanh, layer_norm_plain, softmax_f32, softmax_in_place};

/// Architecture of the legacy readout.
pub const LEGACY_ARCHITECTURE: &str = "privoke_tiny_transformer_v1";
/// Architecture of the task-query readout.
pub const TASK_QUERY_ARCHITECTURE: &str = "privoke_tiny_transformer_v2";
/// `readout` of the task-query architecture.
pub const TASK_QUERY_READOUT: &str = "residual_task_query_v1";
/// Layer-norm epsilon of the Tiny blocks.
const EPS: f64 = 1e-5;
/// Task order of the readout and the heads.
const TASKS: [&str; 3] = ["sensitivity", "visibility", "category"];

/// How the pooled feature of each task is read out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Readout {
    /// `legacy_pool_v1`: half the first state plus half the mean, for every task.
    LegacyPool,
    /// `residual_task_query_v1`: the pooled feature plus a learned-query attention residual per task.
    TaskQuery,
}

/// The `model_config` of a Tiny artifact.
#[derive(Debug, Clone, PartialEq)]
pub struct TinyConfig {
    /// Vocabulary (hash buckets).
    pub vocab_size: usize,
    /// Hidden width.
    pub hidden_size: usize,
    /// Feed-forward width.
    pub intermediate_size: usize,
    /// Context, including the start token.
    pub max_tokens: usize,
    /// Encoder blocks.
    pub num_layers: usize,
    /// Attention heads.
    pub num_attention_heads: usize,
    /// Probability at or above which a category is reported.
    pub category_threshold: f64,
    /// Readout.
    pub readout: Readout,
    /// Sensitivity labels in head order.
    pub sensitivity_labels: Vec<String>,
    /// Visibility labels in head order.
    pub visibility_labels: Vec<String>,
    /// Category labels in head order.
    pub category_labels: Vec<String>,
}

#[derive(Debug, Clone)]
struct Block {
    query: Dense,
    key: Dense,
    value: Dense,
    output: Dense,
    ffn_input: Dense,
    ffn_output: Dense,
}

/// Prediction of the Tiny model for one text.
#[derive(Debug, Clone, PartialEq)]
pub struct TinyPrediction {
    /// Hashed token ids, start token first.
    pub ids: Vec<usize>,
    /// `0.5 * first + 0.5 * mean`.
    pub pooled: Vec<f32>,
    /// Logits per task, in `sensitivity`, `visibility`, `category` order.
    pub logits: [Vec<f32>; 3],
    /// Sensitivity probabilities.
    pub sensitivity_probabilities: Vec<f32>,
    /// Visibility probabilities.
    pub visibility_probabilities: Vec<f32>,
    /// Category probabilities.
    pub category_probabilities: Vec<f32>,
    /// The decision.
    pub decision: Prediction,
}

/// A Tiny model with the identity the streamed wrapper reports.
#[derive(Debug, Clone)]
pub struct TinyModel {
    config: TinyConfig,
    model_id: String,
    version: String,
    token_embedding: Vec<f32>,
    position_embedding: Vec<f32>,
    blocks: Vec<Block>,
    heads: [Dense; 3],
    queries: Option<[Vec<f32>; 3]>,
    threads: usize,
}

fn invalid(message: impl Into<String>) -> SemanticError {
    SemanticError::artifact(message.into())
}

fn integer(config: &Map<String, Value>, name: &str, default: Option<usize>) -> Result<usize, SemanticError> {
    match config.get(name) {
        None => default.ok_or_else(|| invalid(format!("Invalid transformer config: {name} is missing."))),
        Some(value) => value
            .as_u64()
            .and_then(|value| usize::try_from(value).ok())
            .filter(|value| *value > 0 && *value <= 1 << 24)
            .ok_or_else(|| invalid(format!("{name} must be a positive integer."))),
    }
}

fn labels(config: &Map<String, Value>, name: &str, inventory: &[&str]) -> Result<Vec<String>, SemanticError> {
    let bad = || invalid(format!("{name} must contain every supported label exactly once."));
    let values = config.get(name).and_then(Value::as_array).ok_or_else(bad)?;
    let labels: Vec<String> = values.iter().map(|value| value.as_str().map(str::to_string)).collect::<Option<_>>().ok_or_else(bad)?;
    let distinct: BTreeSet<&str> = labels.iter().map(String::as_str).collect();
    if labels.len() != inventory.len() || distinct != inventory.iter().copied().collect::<BTreeSet<&str>>() {
        return Err(bad());
    }
    Ok(labels)
}

impl TinyConfig {
    /// `ModelConfig.from_mapping` with `validate_readout_identity`; `architecture` is the artifact's.
    pub fn from_json(config: &Value, architecture: &str) -> Result<Self, SemanticError> {
        let config = config.as_object().ok_or_else(|| invalid("model_config must be a JSON object."))?;
        let readout = match config.get("readout") {
            None => Readout::LegacyPool,
            Some(Value::String(name)) if name == "legacy_pool_v1" => Readout::LegacyPool,
            Some(Value::String(name)) if name == TASK_QUERY_READOUT => Readout::TaskQuery,
            Some(_) => return Err(invalid("Unsupported Tiny readout.")),
        };
        let expected = if readout == Readout::TaskQuery { TASK_QUERY_ARCHITECTURE } else { LEGACY_ARCHITECTURE };
        if architecture != expected {
            return Err(invalid("Tiny architecture and readout configuration disagree."));
        }
        let threshold = match config.get("category_threshold") {
            None => 0.5,
            Some(value) => value
                .as_f64()
                .filter(|t| *t > 0.0 && *t < 1.0)
                .ok_or_else(|| invalid("category_threshold must be between zero and one."))?,
        };
        let sensitivity: Vec<&str> = SENSITIVITY.iter().map(|(name, _)| *name).collect();
        let visibility: Vec<&str> = VISIBILITY.iter().map(|(name, _)| *name).collect();
        let category: Vec<&str> = CATEGORY.iter().map(|(name, _)| *name).collect();
        let parsed = Self {
            vocab_size: integer(config, "vocab_size", None)?,
            hidden_size: integer(config, "hidden_size", None)?,
            intermediate_size: integer(config, "intermediate_size", None)?,
            max_tokens: integer(config, "max_tokens", None)?,
            num_layers: integer(config, "num_layers", Some(1))?,
            num_attention_heads: integer(config, "num_attention_heads", Some(1))?,
            category_threshold: threshold,
            readout,
            sensitivity_labels: labels(config, "sensitivity_labels", &sensitivity)?,
            visibility_labels: labels(config, "visibility_labels", &visibility)?,
            category_labels: labels(config, "category_labels", &category)?,
        };
        if parsed.vocab_size < 2 {
            return Err(invalid("vocab_size must include padding and at least one token."));
        }
        if !parsed.hidden_size.is_multiple_of(parsed.num_attention_heads) {
            return Err(invalid("hidden_size must be divisible by num_attention_heads."));
        }
        if parsed.max_tokens > 512 {
            return Err(invalid("Transformer context must not exceed 512 tokens."));
        }
        Ok(parsed)
    }
}

fn layer_prefix(config: &TinyConfig, index: usize) -> String {
    // Schema-v1 artifacts used unprefixed names for their sole encoder block.
    if config.num_layers == 1 { String::new() } else { format!("layers.{index}.") }
}

struct Tensors {
    values: BTreeMap<String, (Vec<usize>, Vec<f32>)>,
}

impl Tensors {
    fn parse(parameters: &Value) -> Result<Self, SemanticError> {
        let entries = parameters.as_object().ok_or_else(|| invalid("Artifact config and parameters must be objects."))?;
        let mut values = BTreeMap::new();
        for (name, tensor) in entries {
            let tensor = tensor.as_object().ok_or_else(|| invalid("Invalid artifact parameter entry."))?;
            let shape: Vec<usize> = tensor
                .get("shape")
                .and_then(Value::as_array)
                .and_then(|dims| dims.iter().map(|d| d.as_u64().and_then(|d| usize::try_from(d).ok())).collect())
                .ok_or_else(|| invalid("Invalid artifact parameter entry."))?;
            let raw = tensor.get("values").and_then(Value::as_array).ok_or_else(|| invalid("Invalid artifact parameter entry."))?;
            let data: Vec<f32> = raw
                .iter()
                .map(|v| v.as_f64().map(|v| v as f32))
                .collect::<Option<_>>()
                .ok_or_else(|| invalid("Invalid artifact parameter entry."))?;
            let count = shape.iter().try_fold(1usize, |acc, dim| acc.checked_mul(*dim));
            if count != Some(data.len()) {
                return Err(invalid(format!("Tensor {name:?} does not hold the values of its shape.")));
            }
            if data.iter().any(|v| !v.is_finite()) {
                return Err(invalid(format!("Tensor {name:?} is not finite.")));
            }
            values.insert(name.clone(), (shape, data));
        }
        Ok(Self { values })
    }

    fn take(&mut self, name: &str, shape: &[usize]) -> Result<Vec<f32>, SemanticError> {
        let (actual, data) = self.values.remove(name).ok_or_else(|| invalid(format!("Model is missing tensor {name:?}.")))?;
        if actual != shape {
            return Err(invalid(format!("Tensor {name:?} has shape {actual:?}, expected {shape:?}.")));
        }
        Ok(data)
    }
}

/// One `[input][output]` weight of a block, with its bias when the architecture has one (otherwise zeros).
fn block_dense(
    tensors: &mut Tensors,
    prefix: &str,
    name: &str,
    (input, output): (usize, usize),
    has_bias: bool,
) -> Result<Dense, SemanticError> {
    let weight = tensors.take(&format!("{prefix}{name}.weight"), &[input, output])?;
    let bias = if has_bias { tensors.take(&format!("{prefix}{name}.bias"), &[output])? } else { vec![0.0; output] };
    Dense::from_input_major(&weight, bias, input, output)
}

impl TinyModel {
    /// Build from an artifact JSON object: `architecture`, `config`, `parameters` and the identity fields
    /// `model_id` and `version` (the streamed wrapper's reasoning text).
    pub fn from_artifact(artifact: &Value) -> Result<Self, SemanticError> {
        let architecture = artifact.get("architecture").and_then(Value::as_str).unwrap_or(LEGACY_ARCHITECTURE);
        let config = TinyConfig::from_json(artifact.get("config").unwrap_or(&Value::Null), architecture)?;
        let mut tensors = Tensors::parse(artifact.get("parameters").unwrap_or(&Value::Null))?;
        let hidden = config.hidden_size;
        let token_embedding = tensors.take("token_embedding", &[config.vocab_size, hidden])?;
        let position_embedding = tensors.take("position_embedding", &[config.max_tokens, hidden])?;
        let widths = [config.sensitivity_labels.len(), config.visibility_labels.len(), config.category_labels.len()];
        let mut heads = Vec::with_capacity(3);
        for (task, width) in TASKS.iter().zip(widths) {
            let weight = tensors.take(&format!("head.{task}.weight"), &[hidden, width])?;
            let bias = tensors.take(&format!("head.{task}.bias"), &[width])?;
            heads.push(Dense::from_input_major(&weight, bias, hidden, width)?);
        }
        let queries = if config.readout == Readout::TaskQuery {
            let mut queries = Vec::with_capacity(3);
            for task in TASKS {
                queries.push(tensors.take(&format!("readout.{task}.query"), &[hidden])?);
            }
            Some(<[Vec<f32>; 3]>::try_from(queries).map_err(|_| invalid("Task-query readout needs three queries."))?)
        } else {
            None
        };
        let mut blocks = Vec::with_capacity(config.num_layers);
        for index in 0..config.num_layers {
            let prefix = layer_prefix(&config, index);
            blocks.push(Block {
                query: block_dense(&mut tensors, &prefix, "attention.query", (hidden, hidden), false)?,
                key: block_dense(&mut tensors, &prefix, "attention.key", (hidden, hidden), false)?,
                value: block_dense(&mut tensors, &prefix, "attention.value", (hidden, hidden), false)?,
                output: block_dense(&mut tensors, &prefix, "attention.output", (hidden, hidden), true)?,
                ffn_input: block_dense(&mut tensors, &prefix, "ffn.input", (hidden, config.intermediate_size), true)?,
                ffn_output: block_dense(&mut tensors, &prefix, "ffn.output", (config.intermediate_size, hidden), true)?,
            });
        }
        if !tensors.values.is_empty() {
            return Err(invalid("Tiny tensor manifest has unknown tensors."));
        }
        let heads = <[Dense; 3]>::try_from(heads).map_err(|_| invalid("Tiny model needs three heads."))?;
        let text = |name: &str| artifact.get(name).and_then(Value::as_str).unwrap_or("").to_string();
        Ok(Self {
            config,
            model_id: text("model_id"),
            version: text("version"),
            token_embedding,
            position_embedding,
            blocks,
            heads,
            queries,
            threads: 1,
        })
    }

    /// Read an artifact JSON file (`models/privoke-*.json`).
    pub fn from_file(path: &Path) -> Result<Self, SemanticError> {
        let bytes = std::fs::read(path).map_err(|source| SemanticError::Io { path: path.display().to_string(), source })?;
        let value: Value = serde_json::from_slice(&bytes).map_err(|error| invalid(format!("Artifact is not JSON: {error}")))?;
        Self::from_artifact(&value)
    }

    /// Set the number of threads of the matrix kernels.
    #[must_use]
    pub fn with_threads(mut self, threads: usize) -> Self {
        self.threads = threads.max(1);
        self
    }

    /// The configuration.
    pub fn config(&self) -> &TinyConfig {
        &self.config
    }

    /// Hashed word tokens: the start token `0`, then `1 + (SHA-256 prefix mod (vocab - 1))` for each regex token of the
    /// lower-cased text, at most `max_tokens - 1` of them (`transformer_encoder.token_ids`).
    pub fn token_ids(&self, text: &str) -> Vec<usize> {
        let lowered: Vec<char> = pyunicode::lower(text).chars().collect();
        let mut ids = vec![0usize];
        let buckets = (self.config.vocab_size - 1) as u64;
        for token in word_tokens(&lowered, self.config.max_tokens - 1) {
            let digest = Sha256::digest(token.as_bytes());
            let prefix = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]);
            ids.push(1 + (u64::from(prefix) % buckets) as usize);
        }
        ids
    }

    /// `predict(text)`.
    pub fn predict(&self, text: &str) -> TinyPrediction {
        let ids = self.token_ids(text);
        let hidden_states = self.encode(&ids);
        let hidden = self.config.hidden_size;
        let n = ids.len();
        let mean: Vec<f32> = (0..hidden)
            .map(|j| (hidden_states.iter().skip(j).step_by(hidden).map(|v| f64::from(*v)).sum::<f64>() / n as f64) as f32)
            .collect();
        let pooled: Vec<f32> = hidden_states[..hidden].iter().zip(&mean).map(|(first, mean)| *first * 0.5 + *mean * 0.5).collect();
        let mut logits: Vec<Vec<f32>> = Vec::with_capacity(3);
        for (index, head) in self.heads.iter().enumerate() {
            let features = match &self.queries {
                None => pooled.clone(),
                Some(queries) => self.task_feature(&hidden_states, &queries[index], &pooled, &mean),
            };
            logits.push(head.apply(&features, 1, 1));
        }
        let (sensitivity, visibility, category) = (softmax_f32(&logits[0]), softmax_f32(&logits[1]), numpy_sigmoid(&logits[2]));
        let sensitivity_name = &self.config.sensitivity_labels[argmax(&sensitivity)];
        let visibility_name = &self.config.visibility_labels[argmax(&visibility)];
        let mut mask = 0u16;
        let mut names = Vec::new();
        for (name, probability) in self.config.category_labels.iter().zip(&category) {
            if f64::from(*probability) >= self.config.category_threshold {
                mask |= category_bit(name).unwrap_or(0);
                names.push(name.clone());
            }
        }
        let raw = sensitivity.iter().chain(&category).copied().fold(f32::NEG_INFINITY, f32::max);
        let raw = if raw.is_finite() { f64::from(raw) } else { 0.0 };
        let decision = Prediction {
            classification: Classification::new(
                sensitivity_value(sensitivity_name).unwrap_or(SENSITIVITY[0].1),
                visibility_value(visibility_name).unwrap_or(VISIBILITY[0].1),
                mask,
            ),
            sensitivity: sensitivity_name.clone(),
            visibility: visibility_name.clone(),
            categories: names,
            confidence_raw: raw,
            confidence: reported_confidence(raw),
        };
        let [first, second, third] = <[Vec<f32>; 3]>::try_from(logits).unwrap_or_default();
        TinyPrediction {
            ids,
            pooled,
            logits: [first, second, third],
            sensitivity_probabilities: sensitivity,
            visibility_probabilities: visibility,
            category_probabilities: category,
            decision,
        }
    }

    fn encode(&self, ids: &[usize]) -> Vec<f32> {
        let hidden = self.config.hidden_size;
        let n = ids.len();
        let mut x = vec![0f32; n * hidden];
        for (position, (row, id)) in x.chunks_mut(hidden).zip(ids).enumerate() {
            let token = &self.token_embedding[id * hidden..(id + 1) * hidden];
            let place = &self.position_embedding[position * hidden..(position + 1) * hidden];
            for ((slot, t), p) in row.iter_mut().zip(token).zip(place) {
                *slot = *t + *p;
            }
        }
        let heads = self.config.num_attention_heads;
        for block in &self.blocks {
            let q = block.query.apply(&x, n, self.threads);
            let k = block.key.apply(&x, n, self.threads);
            let v = block.value.apply(&x, n, self.threads);
            let context = attention(&q, &k, &v, n, heads, hidden / heads);
            let mut attended = block.output.apply(&context, n, self.threads);
            for (slot, residual) in attended.iter_mut().zip(&x) {
                *slot += *residual;
            }
            layer_norm_plain(&mut attended, hidden, EPS);
            let mut inner = block.ffn_input.apply(&attended, n, self.threads);
            for value in &mut inner {
                *value = gelu_tanh(*value);
            }
            let mut out = block.ffn_output.apply(&inner, n, self.threads);
            for (slot, residual) in out.iter_mut().zip(&attended) {
                *slot += *residual;
            }
            layer_norm_plain(&mut out, hidden, EPS);
            x = out;
        }
        x
    }

    /// `pooled + (alpha @ hidden - mean)` with `alpha = softmax(hidden @ query / sqrt(hidden))`.
    fn task_feature(&self, states: &[f32], query: &[f32], pooled: &[f32], mean: &[f32]) -> Vec<f32> {
        let hidden = self.config.hidden_size;
        let scale = (hidden as f64).sqrt();
        let mut alpha: Vec<f64> =
            states.chunks(hidden).map(|row| f64::from((crate::math::dot(row, query) as f32) / scale as f32)).collect();
        softmax_in_place(&mut alpha);
        let mut attended = vec![0f64; hidden];
        for (weight, row) in alpha.iter().zip(states.chunks(hidden)) {
            for (slot, value) in attended.iter_mut().zip(row) {
                *slot += weight * f64::from(*value);
            }
        }
        pooled.iter().zip(attended).zip(mean).map(|((pooled, attended), mean)| *pooled + (attended as f32 - *mean)).collect()
    }
}

/// `1 / (1 + exp(-clip(x, -30, 30)))`, rounded to float32 (the NumPy `_sigmoid`).
fn numpy_sigmoid(logits: &[f32]) -> Vec<f32> {
    logits.iter().map(|v| (1.0 / (1.0 + (-f64::from(v.clamp(-30.0, 30.0))).exp())) as f32).collect()
}

/// `re.findall(r"[A-Za-z]+(?:'[A-Za-z]+)?|\d+|[^\w\s]", text)[:limit]` over code points, with Python's Unicode classes.
fn word_tokens(chars: &[char], limit: usize) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut index = 0;
    while index < chars.len() && tokens.len() < limit {
        let c = chars[index];
        let end = if c.is_ascii_alphabetic() {
            let mut end = index;
            while end < chars.len() && chars[end].is_ascii_alphabetic() {
                end += 1;
            }
            if end + 1 < chars.len() && chars[end] == '\'' && chars[end + 1].is_ascii_alphabetic() {
                end += 1;
                while end < chars.len() && chars[end].is_ascii_alphabetic() {
                    end += 1;
                }
            }
            end
        } else if pyunicode::is_decimal(c) {
            let mut end = index;
            while end < chars.len() && pyunicode::is_decimal(chars[end]) {
                end += 1;
            }
            end
        } else if !pyunicode::is_word(c) && !pyunicode::is_space(c) {
            index + 1
        } else {
            index += 1;
            continue;
        };
        tokens.push(chars[index..end].iter().collect());
        index = end;
    }
    tokens
}

impl SemanticClassifier for TinyModel {
    /// `StreamedTransformerPrivacyModel.classify`.
    fn classify(&self, text: &str) -> Result<Vec<Finding>, SemanticError> {
        let prediction = self.predict(text).decision;
        let classification = prediction.classification;
        let visibility = visibility_value(&prediction.visibility).unwrap_or(0);
        if is_empty_classification(classification.sensitivity(), classification.categories(), visibility) {
            return Ok(Vec::new());
        }
        Ok(vec![Finding {
            classification,
            confidence: prediction.confidence,
            reasoning: format!(
                "Streamed transformer {} {} predicted {}/{}.",
                self.model_id, self.version, prediction.sensitivity, prediction.visibility
            ),
            span: if text.is_empty() { None } else { Some((0, text.chars().count())) },
            section: text.to_string(),
        }])
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn tokens(text: &str) -> Vec<String> {
        let chars: Vec<char> = pyunicode::lower(text).chars().collect();
        word_tokens(&chars, usize::MAX)
    }

    #[test]
    fn regex_tokens_follow_python() {
        // re.findall of the token pattern over the lower-cased text; "_" and non-ASCII letters match no alternative.
        let expected = ["don't", "stop", ",", "it's", "42", "!", "x", "y", "caf"];
        assert_eq!(tokens("Don't stop, it's 42! x_y caf\u{e9} \u{4e2d}"), expected.iter().map(|t| t.to_string()).collect::<Vec<_>>());
        assert_eq!(tokens("a'b' 'c 1\u{661}2"), vec!["a'b", "'", "'", "c", "1\u{661}2"]);
        assert!(tokens("").is_empty());
    }

    #[test]
    fn the_token_limit_stops_the_scan() {
        let chars: Vec<char> = "a b c d e".chars().collect();
        assert_eq!(word_tokens(&chars, 2), vec!["a", "b"]);
        assert!(word_tokens(&chars, 0).is_empty());
    }
}
