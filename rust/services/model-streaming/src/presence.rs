//! Sparse presence ("privoke-presence-*") artifact validation. Port of `validatePresenceArtifact`.

use std::collections::{BTreeMap, BTreeSet};

use privoke_contracts::json::Value;
use unicode_properties::{GeneralCategoryGroup, UnicodeGeneralCategory};

use crate::artifact::{self, MAX_PRESENCE_CONFIG_BYTES, ModelArtifact, PRESENCE_BLOCK_SIZE};
use crate::error::{Error, Result};
use crate::fail;
use crate::jsonx::{self, Object};

/// The branch fields Go's `presenceConfig` decodes.
#[derive(Debug, Default)]
struct Branch {
    analyzer: String,
    ngram_range: Vec<i64>,
    max_features: i64,
    features: Vec<String>,
    sublinear_tf: bool,
    use_idf: bool,
    smooth_idf: bool,
    norm: String,
    lowercase: bool,
    token_pattern: String,
}

fn decode_branch(value: &Value) -> Result<Branch> {
    static EMPTY: Object = Object::new();
    let fields = match value {
        Value::Object(map) => map,
        Value::Null => &EMPTY,
        _ => fail!("presence branch is not an object"),
    };
    Ok(Branch {
        analyzer: jsonx::string(fields.get("analyzer"))?,
        ngram_range: jsonx::int_list(fields.get("ngram_range"))?,
        max_features: jsonx::int64(fields.get("max_features"))?,
        features: jsonx::string_list(fields.get("features"))?,
        sublinear_tf: jsonx::boolean(fields.get("sublinear_tf"))?,
        use_idf: jsonx::boolean(fields.get("use_idf"))?,
        smooth_idf: jsonx::boolean(fields.get("smooth_idf"))?,
        norm: jsonx::string(fields.get("norm"))?,
        lowercase: jsonx::boolean(fields.get("lowercase"))?,
        token_pattern: jsonx::string(fields.get("token_pattern"))?,
    })
}

/// `validatePresenceArtifact`.
pub fn validate_presence_artifact(model: &ModelArtifact) -> Result<()> {
    if !jsonx::valid_json_unicode(model.config.as_bytes()) {
        fail!("presence config contains invalid Unicode");
    }
    let config_value = jsonx::parse(&model.config)?;
    jsonx::exact_fields(
        Some(&config_value),
        &["task", "profile", "threshold", "normalization", "column_order", "coefficient_block_size", "branches"],
    )?;
    let fields = jsonx::object_of(&model.config).map_err(|error| Error(format!("invalid presence config: {error}")))?;
    let decode = || -> Result<_> {
        Ok((
            jsonx::string(fields.get("task"))?,
            jsonx::string(fields.get("profile"))?,
            jsonx::float64(fields.get("threshold"))?,
            jsonx::string(fields.get("normalization"))?,
            jsonx::string_list(fields.get("column_order"))?,
            jsonx::int64(fields.get("coefficient_block_size"))?,
        ))
    };
    let (task, profile, threshold, normalization, column_order, block_size) =
        decode().map_err(|error| Error(format!("invalid presence config: {error}")))?;
    let branches_value = fields.get("branches");
    let mut branches: BTreeMap<String, Branch> = BTreeMap::new();
    match branches_value {
        Some(Value::Object(map)) => {
            for (name, value) in map {
                branches.insert(name.clone(), decode_branch(value).map_err(|error| Error(format!("invalid presence config: {error}")))?);
            }
        }
        _ => fail!("invalid presence config: branches is not an object"),
    }
    // Canonicalize the decoded configuration before applying the config bound.
    let canonical = artifact::canonical_text(&config_value)?;
    if canonical.len() > MAX_PRESENCE_CONFIG_BYTES {
        fail!("presence config exceeds 2 MiB");
    }
    let limit = match profile.as_str() {
        "efficient" => 2000,
        "balanced" => 8000,
        "quality" => 16000,
        _ => fail!("presence profile/model ID mismatch"),
    };
    if model.model_id != format!("privoke-presence-{profile}") {
        fail!("presence profile/model ID mismatch");
    }
    if task != "annotation_presence" || normalization != "training_text_key_v1" {
        fail!("unsupported presence task or normalization");
    }
    if !threshold.is_finite() || !(0.0..=1.0).contains(&threshold) {
        fail!("invalid presence threshold");
    }
    if column_order.len() != 2 || column_order[0] != "word" || column_order[1] != "char" || block_size != PRESENCE_BLOCK_SIZE as i64 {
        fail!("invalid presence column order/block size");
    }
    jsonx::exact_fields(branches_value, &["word", "char"])?;
    let raw_branches = match branches_value {
        Some(Value::Object(map)) => map,
        _ => fail!("branches is not an object"),
    };
    let mut expected_shapes: BTreeMap<String, usize> = BTreeMap::new();
    let mut total = 0usize;
    for name in ["word", "char"] {
        let mut names =
            vec!["analyzer", "ngram_range", "max_features", "features", "sublinear_tf", "use_idf", "smooth_idf", "norm", "lowercase"];
        if name == "word" {
            names.push("token_pattern");
        }
        jsonx::exact_fields(raw_branches.get(name), &names)?;
        let default = Branch::default();
        let branch = branches.get(name).unwrap_or(&default);
        let (lower, upper) = if name == "char" { (3, 5) } else { (1, 2) };
        if branch.analyzer != name
            || branch.ngram_range.len() != 2
            || branch.ngram_range[0] != lower
            || branch.ngram_range[1] != upper
            || branch.max_features != limit
        {
            fail!("invalid presence {name} analyzer/profile");
        }
        if name == "word" && branch.token_pattern != r"(?u)\b\w\w+\b" {
            fail!("unsupported presence word token pattern");
        }
        if !branch.sublinear_tf || !branch.use_idf || !branch.smooth_idf || branch.norm != "l2" || branch.lowercase {
            fail!("invalid presence TF-IDF settings");
        }
        if branch.features.is_empty() || branch.features.len() as i64 > limit {
            fail!("presence vocabulary exceeds profile bound or is empty");
        }
        let mut seen = BTreeSet::new();
        for feature in &branch.features {
            if feature.is_empty() || !seen.insert(feature.as_str()) {
                fail!("presence vocabulary must contain unique Unicode strings");
            }
            if name == "word" && !valid_word_feature(feature) {
                fail!("presence word vocabulary violates token rule");
            }
            let size = feature.chars().count();
            if name == "char" && !(3..=5).contains(&size) {
                fail!("presence character n-gram has invalid length");
            }
        }
        expected_shapes.insert(format!("features.{name}.idf"), branch.features.len());
        total += branch.features.len();
    }
    let mut offset = 0;
    while offset < total {
        expected_shapes
            .insert(format!("head.presence.weight.{:03}", offset / PRESENCE_BLOCK_SIZE), PRESENCE_BLOCK_SIZE.min(total - offset));
        offset += PRESENCE_BLOCK_SIZE;
    }
    expected_shapes.insert("head.presence.bias".into(), 1);
    if model.parameters.len() != expected_shapes.len() {
        fail!("presence tensor manifest has missing or unknown tensors");
    }
    for (name, size) in &expected_shapes {
        let Some(tensor) = model.parameters.get(name) else { fail!("presence tensor {name:?} has invalid shape") };
        if tensor.shape.len() != 1 || tensor.shape[0] as usize != *size || tensor.values.len() != *size {
            fail!("presence tensor {name:?} has invalid shape");
        }
        if tensor.trainable != name.starts_with("head.presence.") {
            fail!("only presence head tensors may be trainable");
        }
        for value in &tensor.values {
            let converted = *value as f32;
            if converted.is_infinite() || converted.is_nan() || (name.starts_with("features.") && converted <= 0.0) {
                fail!("presence tensor {name:?} contains invalid float32 values");
            }
        }
    }
    Ok(())
}

/// `validPresenceWordFeature`: one or two space-separated tokens of two or more letters, numbers or underscores
/// (Unicode categories L and N, as Go's `unicode.IsLetter` and `unicode.IsNumber`).
pub fn valid_word_feature(feature: &str) -> bool {
    let tokens: Vec<&str> = feature.split(' ').collect();
    if tokens.is_empty() || tokens.len() > 2 {
        return false;
    }
    tokens.iter().all(|token| {
        token.chars().count() >= 2 && token.chars().all(|character| character == '_' || is_letter(character) || is_number(character))
    })
}

fn is_letter(character: char) -> bool {
    character.general_category_group() == GeneralCategoryGroup::Letter
}

fn is_number(character: char) -> bool {
    character.general_category_group() == GeneralCategoryGroup::Number
}
