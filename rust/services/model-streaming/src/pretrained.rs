//! The experimental pretrained contextual model: a frozen MiniLM backbone with six head tensors. It is servable by
//! explicit ID only and can never be the `latest` model. Port of `pretrained_context.go`.

use crate::artifact::ModelArtifact;
use crate::error::{Error, Result};
use crate::fail;
use crate::jsonx;

/// The architecture string.
pub const ARCHITECTURE: &str = "privoke_pretrained_context_v1";
/// The only admitted model ID.
pub const MODEL_ID: &str = "privoke-pretrained-context-minilm";
const BACKBONE_HASH: &str = "6fd5d72fe4589f189f8ebc006442dbb529bb7ce38f8082112682524616046452";
const TOKENIZER_HASH: &str = "be50c3628f2bf5bb5e3a7f17b1f74611b2561a3a27eeab05e5aa30f411572037";

const SENSITIVITY: [&str; 4] = ["S0", "S1", "S2", "S3"];
const VISIBILITY: [&str; 6] = ["P0", "P1", "P2", "P3", "P4", "PU"];
const CATEGORY: [&str; 10] =
    ["HEALTH", "POLITICS", "RELIGION", "CRIMINAL", "FINANCIAL", "SEXUAL", "CHILD", "LOCATION", "IDENTITY", "THIRD_PARTY"];

/// `^[A-Za-z0-9][A-Za-z0-9.+_-]{0,127}$`.
pub fn is_valid_version(version: &str) -> bool {
    let bytes = version.as_bytes();
    if bytes.is_empty() || bytes.len() > 128 || !bytes[0].is_ascii_alphanumeric() {
        return false;
    }
    bytes[1..].iter().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'+' | b'_' | b'-'))
}

fn labels_equal(actual: &[String], expected: &[&str]) -> bool {
    actual.len() == expected.len() && actual.iter().zip(expected).all(|(left, right)| left == right)
}

/// `validatePretrainedContextArtifact`.
pub fn validate_pretrained_context_artifact(artifact: &ModelArtifact) -> Result<()> {
    if artifact.architecture != ARCHITECTURE || artifact.model_id != MODEL_ID {
        fail!("pretrained contextual architecture/model ID mismatch");
    }
    if !is_valid_version(&artifact.version) {
        fail!("pretrained contextual version is invalid");
    }
    let value = jsonx::parse(&artifact.config)?;
    jsonx::exact_fields(
        Some(&value),
        &[
            "task",
            "backbone_model_id",
            "backbone_revision",
            "backbone_sha256",
            "tokenizer_sha256",
            "hidden_size",
            "max_tokens",
            "pooling",
            "normalization",
            "category_semantics",
            "arithmetic",
            "sensitivity_labels",
            "visibility_labels",
            "category_labels",
            "category_threshold",
        ],
    )?;
    let fields = jsonx::object_of(&artifact.config)?;
    let decode = || -> Result<_> {
        Ok((
            jsonx::string(fields.get("task"))?,
            jsonx::string(fields.get("backbone_model_id"))?,
            jsonx::string(fields.get("backbone_revision"))?,
            jsonx::string(fields.get("backbone_sha256"))?,
            jsonx::string(fields.get("tokenizer_sha256"))?,
            jsonx::int64(fields.get("hidden_size"))?,
            jsonx::int64(fields.get("max_tokens"))?,
            jsonx::string(fields.get("pooling"))?,
            jsonx::string(fields.get("normalization"))?,
            jsonx::string(fields.get("category_semantics"))?,
            jsonx::string(fields.get("arithmetic"))?,
            jsonx::string_list(fields.get("sensitivity_labels"))?,
            jsonx::string_list(fields.get("visibility_labels"))?,
            jsonx::string_list(fields.get("category_labels"))?,
            jsonx::float64(fields.get("category_threshold"))?,
        ))
    };
    let (
        task,
        backbone_id,
        revision,
        backbone_sha,
        tokenizer_sha,
        hidden,
        max_tokens,
        pooling,
        normalization,
        semantics,
        arithmetic,
        sensitivity,
        visibility,
        category,
        threshold,
    ) = decode().map_err(|error| Error(format!("invalid pretrained contextual config: {error}")))?;
    if task != "contextual_privacy"
        || backbone_id != "sentence-transformers/all-MiniLM-L6-v2"
        || revision != "1110a243fdf4706b3f48f1d95db1a4f5529b4d41"
        || backbone_sha != BACKBONE_HASH
        || tokenizer_sha != TOKENIZER_HASH
        || hidden != 384
        || (max_tokens != 256 && max_tokens != 512)
        || pooling != "masked_mean_l2_v1"
        || normalization != "detector_normalize_text_v1"
        || semantics != "asserted_personal_disclosure_v1"
        || arithmetic != "float32_onnx_numpy_heads_v1"
    {
        fail!("pretrained contextual encoder contract mismatch");
    }
    if !labels_equal(&sensitivity, &SENSITIVITY) || !labels_equal(&visibility, &VISIBILITY) || !labels_equal(&category, &CATEGORY) {
        fail!("pretrained contextual label order mismatch");
    }
    if !threshold.is_finite() || threshold <= 0.0 || threshold >= 1.0 {
        fail!("pretrained contextual category threshold is invalid");
    }
    if artifact.parameters.len() != 6 {
        fail!("pretrained contextual model requires exactly six head tensors");
    }
    for (task, labels) in [("sensitivity", SENSITIVITY.len()), ("visibility", VISIBILITY.len()), ("category", CATEGORY.len())] {
        for part in ["weight", "bias"] {
            let shape = if part == "weight" { vec![384u32, labels as u32] } else { vec![labels as u32] };
            let Some(tensor) = artifact.parameters.get(&format!("head.{task}.{part}")) else {
                fail!("pretrained contextual head shape/scope mismatch")
            };
            if tensor.shape != shape || tensor.trainable {
                fail!("pretrained contextual head shape/scope mismatch");
            }
            if tensor.values.iter().any(|value| (*value as f32).is_infinite() || value.is_nan()) {
                fail!("pretrained contextual head is outside finite float32 range");
            }
        }
    }
    if artifact.metadata.is_none() {
        fail!("pretrained contextual metadata must be an object");
    }
    Ok(())
}
