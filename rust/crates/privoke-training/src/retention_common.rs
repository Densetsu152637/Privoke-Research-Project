//! What the ORIGINAL TRAIN retention shares between the V1 loops and the V3 gate: the approved bank's pin, the strict
//! eligibility boundary, the float32 union margin, the sensitivity predicate and the teacher tensor reader.
//!
//! These items used to live in [`crate::retention`] (V1 loops) and [`crate::window`] (V1 window); they moved here, unchanged in
//! behaviour, so that the V3 retention ([`crate::retention_v3`], [`crate::reference`]) does not depend on a V1 training module and
//! stage V3-R8b can delete those. The V1 modules re-use them from here.

use std::collections::BTreeMap;

use privoke_semantic::TinyPrediction;
use privoke_semantic::tiny::TinyConfig;
use serde_json::Value;

use crate::error::TrainingError;

/// The sha256 of the approved ORIGINAL TRAIN bank (`sensitive_retention.BANK_SHA256`).
pub const BANK_SHA256: &str = "c9b0b64133e6474487c1d3fe2ac9410c720b19a1f1571469dc8c3483f4e4a41a";
/// The strict eligibility boundary of a reference row, as the reference files record it.
pub const BOUNDARY: &str = "{\"version\":\"original_sensitive_strict_margin_gap_v1\",\"epsilon\":1e-6,\"gold_non_s0\":true,\"decoded_sensitive\":true,\"packed_exact\":false,\"teacher_at_least_gold\":false,\"required_groups\":20}";
/// The strict margin and gap threshold of [`BOUNDARY`].
pub const EPSILON: f64 = 1e-6;
/// The three fixed ORIGINAL teacher artifacts (profile, sha256 of the artifact bytes) a retention reference is pinned to.
pub(crate) const TEACHERS: [(&str, &str); 3] = [
    ("quality", "50657f82e52bb2df56e0ce57c3124a7d7b97a9d9ea338e5eac3c42552fb40733"),
    ("balanced", "4e991e8f1c3e6211e824613fa8eee2fdc6f0cec6ec9a5e817dbf1c17802cf8a1"),
    ("efficient", "a23e986915225373663ed7a017d13fa82aac8c3a266ff5a3f4943b129d92e4ef"),
];
/// The category bits of a packed classification.
pub(crate) const CATEGORY_MASK: u16 = 0x7FE0;

pub(crate) type Values = BTreeMap<String, Vec<f64>>;
pub(crate) type Shapes = BTreeMap<String, Vec<u64>>;

fn invalid(message: &str) -> TrainingError {
    TrainingError::invalid(message)
}

/// The severity bits of a packed classification.
pub(crate) fn sensitivity_bits(packed: u16) -> u16 {
    packed & 0b11
}

/// Whether a packed classification is sensitive: a severity above S0 or any category.
pub(crate) fn is_sensitive(packed: u16) -> bool {
    sensitivity_bits(packed) != 0 || packed & CATEGORY_MASK != 0
}

/// The union margin in float32 (`margin_and_gap`): the largest of the non-S0 severity logits minus the S0 logit and the
/// category logits minus `offset` (the logit of the category threshold). Every logit and the margin must be finite.
pub fn union_margin_f32(sensitivity: &[f32], s0: usize, category: &[f32], offset: f32) -> Result<f64, TrainingError> {
    if s0 >= sensitivity.len() {
        return Err(invalid("ORIGINAL retention logits/margins must be finite."));
    }
    let mut best = f32::NEG_INFINITY;
    for (index, value) in sensitivity.iter().enumerate() {
        if index != s0 {
            best = best.max(*value - sensitivity[s0]);
        }
    }
    for value in category {
        best = best.max(value - offset);
    }
    if !best.is_finite() || sensitivity.iter().any(|v| !v.is_finite()) {
        return Err(invalid("ORIGINAL retention logits/margins must be finite."));
    }
    Ok(f64::from(best))
}

/// The union margin of a served V1 prediction in float32 (`margin_and_gap`).
pub(crate) fn safety_margin(config: &TinyConfig, prediction: &TinyPrediction) -> Result<f64, TrainingError> {
    let s0 = config
        .sensitivity_labels
        .iter()
        .position(|label| label == "S0")
        .ok_or_else(|| invalid("ORIGINAL retention logits/margins must be finite."))?;
    let offset = (config.category_threshold.ln() - (-config.category_threshold).ln_1p()) as f32;
    union_margin_f32(&prediction.logits[0], s0, &prediction.logits[2], offset)
}

pub(crate) fn teacher_tensors(artifact: &Value) -> Result<(Values, Shapes), TrainingError> {
    let bad = || invalid("Component ORIGINAL teacher differs from independently configured accepted raw-file SHA.");
    let entries = artifact["parameters"].as_object().ok_or_else(bad)?;
    let (mut values, mut shapes) = (Values::new(), Shapes::new());
    for (name, tensor) in entries {
        let data = tensor["values"].as_array().ok_or_else(bad)?;
        values.insert(
            name.clone(),
            data.iter().map(|v| v.as_f64().map(|x| f64::from(x as f32))).collect::<Option<Vec<f64>>>().ok_or_else(bad)?,
        );
        let shape = tensor["shape"].as_array().ok_or_else(bad)?;
        shapes.insert(name.clone(), shape.iter().filter_map(Value::as_u64).collect());
    }
    Ok((values, shapes))
}
