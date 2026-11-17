//! The native BERT encoder with pooler (`transformers.BertModel(..., add_pooling_layer=True)` in inference mode).

use std::collections::BTreeMap;

use serde_json::Value;

use crate::error::SemanticError;
use crate::math::{Dense, attention, gelu_erf, layer_norm_affine};
use crate::safetensors::Tensor;

/// The fields of a BERT `config.json` the encoder reads.
#[derive(Debug, Clone, PartialEq)]
pub struct BertConfig {
    /// Hidden width.
    pub hidden_size: usize,
    /// Encoder layers.
    pub num_hidden_layers: usize,
    /// Attention heads.
    pub num_attention_heads: usize,
    /// Feed-forward width.
    pub intermediate_size: usize,
    /// Positions the position embedding holds.
    pub max_position_embeddings: usize,
    /// Vocabulary size.
    pub vocab_size: usize,
    /// Token-type rows.
    pub type_vocab_size: usize,
    /// Layer-norm epsilon.
    pub layer_norm_eps: f64,
}

fn dimension(config: &Value, key: &str) -> Result<usize, SemanticError> {
    config
        .get(key)
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .filter(|value| *value > 0 && *value <= 1 << 24)
        .ok_or_else(|| SemanticError::artifact(format!("config.json: {key} must be a positive integer.")))
}

impl BertConfig {
    /// Parse and validate `config.json`.
    ///
    /// Only the stock configuration the pinned releases use is accepted: absolute positions, the exact GELU.
    pub fn from_json(text: &str) -> Result<Self, SemanticError> {
        let config: Value =
            serde_json::from_str(text).map_err(|error| SemanticError::artifact(format!("config.json is not JSON: {error}")))?;
        if let Some(kind) = config.get("model_type")
            && kind != "bert"
        {
            return Err(SemanticError::artifact("config.json: model_type must be bert."));
        }
        if let Some(act) = config.get("hidden_act")
            && act != "gelu"
        {
            return Err(SemanticError::artifact("config.json: only the exact gelu activation is supported."));
        }
        if let Some(kind) = config.get("position_embedding_type")
            && kind != "absolute"
        {
            return Err(SemanticError::artifact("config.json: only absolute position embeddings are supported."));
        }
        let eps = match config.get("layer_norm_eps") {
            None => 1e-12,
            Some(value) => value
                .as_f64()
                .filter(|eps| eps.is_finite() && *eps >= 0.0)
                .ok_or_else(|| SemanticError::artifact("config.json: layer_norm_eps is invalid."))?,
        };
        let parsed = Self {
            hidden_size: dimension(&config, "hidden_size")?,
            num_hidden_layers: dimension(&config, "num_hidden_layers")?,
            num_attention_heads: dimension(&config, "num_attention_heads")?,
            intermediate_size: dimension(&config, "intermediate_size")?,
            max_position_embeddings: dimension(&config, "max_position_embeddings")?,
            vocab_size: dimension(&config, "vocab_size")?,
            type_vocab_size: if config.get("type_vocab_size").is_some() { dimension(&config, "type_vocab_size")? } else { 2 },
            layer_norm_eps: eps,
        };
        if !parsed.hidden_size.is_multiple_of(parsed.num_attention_heads) {
            return Err(SemanticError::artifact("config.json: hidden_size must be divisible by num_attention_heads."));
        }
        Ok(parsed)
    }
}

#[derive(Debug, Clone)]
struct Norm {
    gamma: Vec<f32>,
    beta: Vec<f32>,
}

#[derive(Debug, Clone)]
struct Layer {
    query: Dense,
    key: Dense,
    value: Dense,
    attention_output: Dense,
    attention_norm: Norm,
    intermediate: Dense,
    output: Dense,
    output_norm: Norm,
}

/// The encoder: embeddings, layers and the pooler.
#[derive(Debug, Clone)]
pub struct Encoder {
    config: BertConfig,
    word: Vec<f32>,
    position: Vec<f32>,
    token_type: Vec<f32>,
    embedding_norm: Norm,
    layers: Vec<Layer>,
    pooler: Dense,
}

/// Take a tensor of a given shape out of `tensors`.
pub(crate) fn take(tensors: &mut BTreeMap<String, Tensor>, name: &str, shape: &[usize]) -> Result<Vec<f32>, SemanticError> {
    let tensor = tensors
        .remove(name)
        .ok_or_else(|| SemanticError::artifact(format!("Checkpoint includes unsupported or missing model keys: {name} is missing.")))?;
    if tensor.shape != shape {
        return Err(SemanticError::artifact(format!("Checkpoint tensor {name} has shape {:?}, expected {shape:?}.", tensor.shape)));
    }
    Ok(tensor.data)
}

fn dense(tensors: &mut BTreeMap<String, Tensor>, prefix: &str, input: usize, output: usize) -> Result<Dense, SemanticError> {
    let weight = take(tensors, &format!("{prefix}.weight"), &[output, input])?;
    let bias = take(tensors, &format!("{prefix}.bias"), &[output])?;
    Dense::new(weight, bias, input, output)
}

fn norm(tensors: &mut BTreeMap<String, Tensor>, prefix: &str, width: usize) -> Result<Norm, SemanticError> {
    Ok(Norm { gamma: take(tensors, &format!("{prefix}.weight"), &[width])?, beta: take(tensors, &format!("{prefix}.bias"), &[width])? })
}

impl Encoder {
    /// Build the encoder from the tensors whose names start with `encoder.` (the prefix is part of `prefix`),
    /// removing them from `tensors`.
    pub fn from_tensors(config: BertConfig, tensors: &mut BTreeMap<String, Tensor>, prefix: &str) -> Result<Self, SemanticError> {
        let hidden = config.hidden_size;
        let word = take(tensors, &format!("{prefix}embeddings.word_embeddings.weight"), &[config.vocab_size, hidden])?;
        let position = take(tensors, &format!("{prefix}embeddings.position_embeddings.weight"), &[config.max_position_embeddings, hidden])?;
        let token_type = take(tensors, &format!("{prefix}embeddings.token_type_embeddings.weight"), &[config.type_vocab_size, hidden])?;
        let embedding_norm = norm(tensors, &format!("{prefix}embeddings.LayerNorm"), hidden)?;
        let mut layers = Vec::with_capacity(config.num_hidden_layers);
        for index in 0..config.num_hidden_layers {
            let base = format!("{prefix}encoder.layer.{index}");
            layers.push(Layer {
                query: dense(tensors, &format!("{base}.attention.self.query"), hidden, hidden)?,
                key: dense(tensors, &format!("{base}.attention.self.key"), hidden, hidden)?,
                value: dense(tensors, &format!("{base}.attention.self.value"), hidden, hidden)?,
                attention_output: dense(tensors, &format!("{base}.attention.output.dense"), hidden, hidden)?,
                attention_norm: norm(tensors, &format!("{base}.attention.output.LayerNorm"), hidden)?,
                intermediate: dense(tensors, &format!("{base}.intermediate.dense"), hidden, config.intermediate_size)?,
                output: dense(tensors, &format!("{base}.output.dense"), config.intermediate_size, hidden)?,
                output_norm: norm(tensors, &format!("{base}.output.LayerNorm"), hidden)?,
            });
        }
        let pooler = dense(tensors, &format!("{prefix}pooler.dense"), hidden, hidden)?;
        Ok(Self { config, word, position, token_type, embedding_norm, layers, pooler })
    }

    /// The configuration.
    pub fn config(&self) -> &BertConfig {
        &self.config
    }

    /// `pooler_output` for one sequence of token ids (no padding, all-zero token types): `tanh(W h[0] + b)`.
    pub fn pooled(&self, ids: &[u32], threads: usize) -> Result<Vec<f32>, SemanticError> {
        let hidden = self.config.hidden_size;
        let n = ids.len();
        if n == 0 || n > self.config.max_position_embeddings {
            return Err(SemanticError::Input(format!(
                "Token sequence of length {n} is outside the model's {} positions.",
                self.config.max_position_embeddings
            )));
        }
        let mut x = vec![0f64; n * hidden];
        let token_type = &self.token_type[..hidden];
        for (position, (row, id)) in x.chunks_mut(hidden).zip(ids).enumerate() {
            let id = usize::try_from(*id).unwrap_or(usize::MAX);
            if id >= self.config.vocab_size {
                return Err(SemanticError::Input(format!("Token id {id} is outside the vocabulary of {} tokens.", self.config.vocab_size)));
            }
            let word = &self.word[id * hidden..(id + 1) * hidden];
            let place = &self.position[position * hidden..(position + 1) * hidden];
            for (((slot, w), t), p) in row.iter_mut().zip(word).zip(token_type).zip(place) {
                // BertEmbeddings: (inputs_embeds + token_type_embeddings) + position_embeddings.
                *slot = f64::from(*w) + f64::from(*t) + f64::from(*p);
            }
        }
        layer_norm_affine(&mut x, hidden, &self.embedding_norm.gamma, &self.embedding_norm.beta, self.config.layer_norm_eps);
        let heads = self.config.num_attention_heads;
        for layer in &self.layers {
            x = self.layer_forward(layer, &x, n, heads, threads);
        }
        let first = self.pooler.apply(&x[..hidden], 1, 1);
        Ok(first.into_iter().map(|value| value.tanh() as f32).collect())
    }

    fn layer_forward(&self, layer: &Layer, x: &[f64], n: usize, heads: usize, threads: usize) -> Vec<f64> {
        let hidden = self.config.hidden_size;
        let eps = self.config.layer_norm_eps;
        let q = layer.query.apply(x, n, threads);
        let k = layer.key.apply(x, n, threads);
        let v = layer.value.apply(x, n, threads);
        let context = attention(&q, &k, &v, n, heads, hidden / heads);
        let mut y = layer.attention_output.apply(&context, n, threads);
        for (slot, residual) in y.iter_mut().zip(x) {
            *slot += *residual;
        }
        layer_norm_affine(&mut y, hidden, &layer.attention_norm.gamma, &layer.attention_norm.beta, eps);
        let mut inner = layer.intermediate.apply(&y, n, threads);
        for value in &mut inner {
            *value = gelu_erf(*value);
        }
        let mut z = layer.output.apply(&inner, n, threads);
        for (slot, residual) in z.iter_mut().zip(&y) {
            *slot += *residual;
        }
        layer_norm_affine(&mut z, hidden, &layer.output_norm.gamma, &layer.output_norm.beta, eps);
        z
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    const CONFIG: &str = r#"{"hidden_act":"gelu","hidden_size":8,"intermediate_size":16,"layer_norm_eps":1e-12,"max_position_embeddings":32,
        "model_type":"bert","num_attention_heads":2,"num_hidden_layers":1,"type_vocab_size":2,"vocab_size":10}"#;

    #[test]
    fn parses_the_stock_configuration() {
        let config = BertConfig::from_json(CONFIG).unwrap();
        assert_eq!(config.hidden_size, 8);
        assert_eq!(config.layer_norm_eps, 1e-12);
        assert_eq!(config.type_vocab_size, 2);
    }

    #[test]
    fn refuses_unsupported_configurations() {
        for (from, to) in [
            ("\"gelu\"", "\"relu\""),
            ("\"bert\"", "\"roberta\""),
            ("\"num_attention_heads\":2", "\"num_attention_heads\":3"),
            ("\"vocab_size\":10", "\"vocab_size\":0"),
            ("\"layer_norm_eps\":1e-12", "\"layer_norm_eps\":-1"),
        ] {
            assert!(BertConfig::from_json(&CONFIG.replace(from, to)).is_err(), "{to}");
        }
        assert!(BertConfig::from_json(&CONFIG.replace("\"bert\"", "\"bert\",\"position_embedding_type\":\"relative_key\"")).is_err());
        assert!(BertConfig::from_json("[]").is_err());
    }

    #[test]
    fn missing_and_misshapen_tensors_are_refused() {
        let mut tensors = BTreeMap::new();
        tensors.insert("x".to_string(), Tensor { shape: vec![2], data: vec![1.0, 2.0], sha256: String::new() });
        assert!(take(&mut tensors, "y", &[2]).is_err());
        let mut other = tensors.clone();
        assert!(take(&mut other, "x", &[3]).is_err());
        assert_eq!(take(&mut tensors, "x", &[2]).unwrap(), vec![1.0, 2.0]);
        assert!(tensors.is_empty());
    }
}
