//! The pretrained contextual encoder (`privoke-pretrained-context-minilm`): a frozen MiniLM backbone and three offline
//! linear heads (`src/pretrained_context.py::FrozenPretrainedEncoder` and `PretrainedContextModel`).
//!
//! * [`ContextEncoder`] reads the backbone from the pinned `model.onnx` ([`crate::onnx`]) and the tokenizer from the
//!   pinned `tokenizer.json`, tokenises the (already normalised) text without truncation or padding, runs the
//!   [`crate::bert`] encoder in float64, takes the mean of the last hidden states over all tokens, L2-normalises it, and
//!   rounds to float32 once: the 384 features.
//! * [`ContextModel`] adds the three heads (`features @ W + b`, `W` stored `[384][labels]`) and the decision rules of
//!   the Python model: softmax argmax for the sensitivity and visibility, sigmoid and the category threshold.
//!
//! Python runs the backbone in float32 onnxruntime, so the features agree to about 1e-6, not bit for bit; the stage 14
//! tolerances apply. This port is verified against a numpy float32 reference of the same graph on synthetic weights
//! (`tests/context_golden.rs`). Against onnxruntime 1.23.2 on the real pinned file the features agree within 1e-6
//! (`tests/context_onnx_real.rs`, env-gated local evidence: 31 texts, maximum difference 1.99e-7).

use std::path::Path;

use privoke_contracts::digest::sha256_hex;
use privoke_rules::classification::Classification;
use tokenizers::Tokenizer;

use crate::bert::{BertConfig, Encoder};
use crate::error::SemanticError;
use crate::labels::{CATEGORY, HEAD_WIDTHS, Prediction, SENSITIVITY, VISIBILITY, argmax, reported_confidence};
use crate::math::{Dense, sigmoid_f32, softmax_f32};
use crate::onnx;

/// `PRETRAINED_CONTEXT_MODEL_ID`.
pub const MODEL_ID: &str = "privoke-pretrained-context-minilm";
/// `PRETRAINED_CONTEXT_ARCHITECTURE`.
pub const ARCHITECTURE: &str = "privoke_pretrained_context_v1";
/// SHA-256 of the pinned `model.onnx` (`BACKBONE_SHA256`).
pub const BACKBONE_SHA256: &str = "6fd5d72fe4589f189f8ebc006442dbb529bb7ce38f8082112682524616046452";
/// SHA-256 of the pinned `tokenizer.json` (`TOKENIZER_SHA256`).
pub const TOKENIZER_SHA256: &str = "be50c3628f2bf5bb5e3a7f17b1f74611b2561a3a27eeab05e5aa30f411572037";
/// Width of the pooled features and of every head's input.
pub const HIDDEN_SIZE: usize = 384;
/// The context lengths the contract admits, special tokens included.
pub const SUPPORTED_MAX_TOKENS: [usize; 2] = [256, 512];
/// Largest `tokenizer.json` read.
const MAX_TOKENIZER_BYTES: usize = 2 * 1024 * 1024;
/// Threads of the matrix kernels (one, as the onnxruntime session of the Python runtime).
const THREADS: usize = 1;

/// The configuration of the pinned backbone, `sentence-transformers/all-MiniLM-L6-v2`.
pub fn minilm_config() -> BertConfig {
    BertConfig {
        hidden_size: HIDDEN_SIZE,
        num_hidden_layers: 6,
        num_attention_heads: 12,
        intermediate_size: 1536,
        max_position_embeddings: 512,
        vocab_size: 30522,
        type_vocab_size: 2,
        layer_norm_eps: 1e-12,
    }
}

/// The frozen backbone with its tokenizer.
#[derive(Debug)]
pub struct ContextEncoder {
    encoder: Encoder,
    tokenizer: Tokenizer,
    max_tokens: usize,
}

fn read_regular(directory: &Path, name: &str, maximum: usize) -> Result<Vec<u8>, SemanticError> {
    let path = directory.join(name);
    let described = path.display().to_string();
    let invalid = || SemanticError::Artifact("Pretrained encoder asset must be a regular local file.".to_string());
    let metadata = std::fs::symlink_metadata(&path).map_err(|source| SemanticError::Io { path: described.clone(), source })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(invalid());
    }
    let bytes = std::fs::read(&path).map_err(|source| SemanticError::Io { path: described, source })?;
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(SemanticError::Artifact("Pretrained encoder asset size or SHA-256 does not match.".to_string()));
    }
    Ok(bytes)
}

fn digest_mismatch() -> SemanticError {
    SemanticError::Artifact("Pretrained encoder asset size or SHA-256 does not match.".to_string())
}

impl ContextEncoder {
    /// The pinned backbone from a directory that holds `model.onnx` and `tokenizer.json`
    /// (`PRIVOKE_PRETRAINED_CONTEXT_DIR`): both are verified against their pins before they are parsed.
    pub fn load_directory(directory: &Path, max_tokens: usize) -> Result<Self, SemanticError> {
        Self::load_directory_admitted_by(directory, max_tokens, BACKBONE_SHA256, TOKENIZER_SHA256, &minilm_config())
    }

    /// As [`ContextEncoder::load_directory`], admitting the two files by the given SHA-256 values and reading the
    /// backbone with the given configuration (the pinned ones for the product; a small synthetic backbone in tests).
    pub fn load_directory_admitted_by(
        directory: &Path,
        max_tokens: usize,
        model_sha256: &str,
        tokenizer_sha256: &str,
        config: &BertConfig,
    ) -> Result<Self, SemanticError> {
        let model = read_regular(directory, "model.onnx", onnx::MAX_ONNX_BYTES)?;
        let tokenizer = read_regular(directory, "tokenizer.json", MAX_TOKENIZER_BYTES)?;
        if sha256_hex(&model) != model_sha256 || sha256_hex(&tokenizer) != tokenizer_sha256 {
            return Err(digest_mismatch());
        }
        Self::from_bytes(&model, &tokenizer, max_tokens, config.clone())
    }

    /// The encoder from already admitted bytes. The caller has verified them.
    pub fn from_bytes(onnx_bytes: &[u8], tokenizer_json: &[u8], max_tokens: usize, config: BertConfig) -> Result<Self, SemanticError> {
        let mut tensors = onnx::encoder_tensors(onnx_bytes, config.num_hidden_layers)?;
        let encoder = Encoder::from_tensors_without_pooler(config, &mut tensors, "")?;
        if !tensors.is_empty() {
            return Err(SemanticError::artifact("Pretrained contextual export holds tensors the encoder does not use."));
        }
        let mut tokenizer = Tokenizer::from_bytes(tokenizer_json).map_err(|error| SemanticError::Tokenizer(error.to_string()))?;
        // `no_truncation()` and `no_padding()`: an overlength prompt is an error, never silently cut.
        tokenizer.with_truncation(None).map_err(|error| SemanticError::Tokenizer(error.to_string()))?;
        tokenizer.with_padding(None);
        Ok(Self { encoder, tokenizer, max_tokens })
    }

    /// Admitted context length, special tokens included.
    pub fn max_tokens(&self) -> usize {
        self.max_tokens
    }

    /// `encode_normalized`: the features of text the pipeline has already normalised.
    pub fn encode_normalized(&self, text: &str) -> Result<Vec<f32>, SemanticError> {
        let encoding = self.tokenizer.encode(text, true).map_err(|error| SemanticError::Tokenizer(error.to_string()))?;
        let ids = encoding.get_ids();
        let length = ids.len();
        if !(2..=self.max_tokens).contains(&length) {
            return Err(SemanticError::Input(format!(
                "Pretrained contextual input exceeds its {}-token context including special tokens.",
                self.max_tokens
            )));
        }
        let hidden = self.encoder.config().hidden_size;
        let states = self.encoder.hidden_states(ids, THREADS)?;
        if states.iter().any(|value| !value.is_finite()) {
            return Err(SemanticError::Input("Pretrained encoder output shape, dtype or values are invalid.".to_string()));
        }
        let mut pooled = vec![0f64; hidden];
        for row in states.chunks_exact(hidden) {
            for (slot, value) in pooled.iter_mut().zip(row) {
                *slot += *value;
            }
        }
        for slot in &mut pooled {
            *slot /= length as f64;
        }
        let norm = pooled.iter().map(|value| value * value).sum::<f64>().sqrt();
        if !norm.is_finite() || norm <= 0.0 {
            return Err(SemanticError::Input("Pretrained encoder produced an invalid pooled norm.".to_string()));
        }
        let features: Vec<f32> = pooled.iter().map(|value| (value / norm) as f32).collect();
        if features.iter().any(|value| !value.is_finite()) {
            return Err(SemanticError::Input("Pretrained encoder features must be finite.".to_string()));
        }
        Ok(features)
    }
}

/// The result of one prediction: the decision and what the Python `ModelPrediction` carries besides it.
#[derive(Debug, Clone, PartialEq)]
pub struct ContextPrediction {
    /// The decision (classification, labels, confidence).
    pub prediction: Prediction,
    /// The sigmoid of the category head, in label order.
    pub category_probabilities: Vec<f32>,
    /// The softmax of the sensitivity head.
    pub sensitivity_probabilities: Vec<f32>,
    /// The softmax of the visibility head.
    pub visibility_probabilities: Vec<f32>,
    /// The 384 pooled features.
    pub pooled: Vec<f32>,
}

/// The encoder with its three heads.
#[derive(Debug)]
pub struct ContextModel {
    encoder: ContextEncoder,
    sensitivity: Dense,
    visibility: Dense,
    category: Dense,
    threshold: f32,
}

impl ContextModel {
    /// A model over an encoder and the six head tensors, each `[HIDDEN_SIZE][labels]` weight and `[labels]` bias, with
    /// the category threshold of the artifact's config. The threshold is compared in float32, as numpy does.
    pub fn new(encoder: ContextEncoder, weights: [&[f32]; 3], biases: [&[f32]; 3], category_threshold: f64) -> Result<Self, SemanticError> {
        let head = |index: usize| Dense::from_input_major(weights[index], biases[index].to_vec(), HIDDEN_SIZE, HEAD_WIDTHS[index]);
        if encoder.encoder.config().hidden_size != HIDDEN_SIZE {
            return Err(SemanticError::artifact("Pretrained contextual encoder hidden size does not match its heads."));
        }
        Ok(Self { sensitivity: head(0)?, visibility: head(1)?, category: head(2)?, encoder, threshold: category_threshold as f32 })
    }

    /// The encoder.
    pub fn encoder(&self) -> &ContextEncoder {
        &self.encoder
    }

    /// `PretrainedContextModel.predict`.
    pub fn predict(&self, text: &str) -> Result<ContextPrediction, SemanticError> {
        let pooled = self.encoder.encode_normalized(text)?;
        let logits = [self.sensitivity.apply_to_f32(&pooled), self.visibility.apply_to_f32(&pooled), self.category.apply_to_f32(&pooled)];
        if logits.iter().flatten().any(|value| !value.is_finite()) {
            return Err(SemanticError::Input("Pretrained contextual heads produced non-finite logits.".to_string()));
        }
        let sensitivity = softmax_f32(&logits[0]);
        let visibility = softmax_f32(&logits[1]);
        let categories = sigmoid_f32(&logits[2]);
        let (sensitivity_label, sensitivity_value) = SENSITIVITY[argmax(&sensitivity)];
        let (visibility_label, visibility_value) = VISIBILITY[argmax(&visibility)];
        let mut mask = 0u16;
        let mut names = Vec::new();
        for ((name, bit), probability) in CATEGORY.iter().zip(&categories) {
            if *probability >= self.threshold {
                mask |= bit;
                names.push((*name).to_string());
            }
        }
        // `ModelPrediction.confidence`: the largest of the sensitivity and category probabilities.
        let raw = sensitivity.iter().chain(&categories).copied().fold(f32::NEG_INFINITY, f32::max);
        let prediction = Prediction {
            classification: Classification::new(sensitivity_value, visibility_value, mask),
            sensitivity: sensitivity_label.to_string(),
            visibility: visibility_label.to_string(),
            categories: names,
            confidence_raw: f64::from(raw),
            confidence: reported_confidence(f64::from(raw)),
        };
        Ok(ContextPrediction {
            prediction,
            category_probabilities: categories,
            sensitivity_probabilities: sensitivity,
            visibility_probabilities: visibility,
            pooled,
        })
    }
}
