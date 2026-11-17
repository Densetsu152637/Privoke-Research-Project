//! `apply_parameter_update` of `privoke_model.artifact`: compare-and-swap on the base version, then the arithmetic.
//!
//! Each value becomes `round(float32(stored) + float32(delta), 8)`, evaluated in doubles exactly as Python does, and
//! the version, revision counters and provenance metadata advance. The result is a JSON tree; the caller attaches the
//! receipt and the drift record, seals the checksum and publishes it.

use std::collections::BTreeMap;

use privoke_contracts::json::Value;
use privoke_contracts::proto::v1::ParameterUpdateRequest;
use privoke_model_streaming::{pretrained, scratch};

use crate::artifact_io::Loaded;
use crate::error::Failure;
use crate::pyfmt::{float32, py_int, repr_str, round8};

/// `release_version` of an artifact: the metadata value, or the version without its `+train.` suffix.
pub fn release_anchor(loaded: &Loaded, base_version: &str) -> String {
    match loaded.typed.metadata().get("release_version").filter(|value| !value.is_empty()) {
        Some(release) => release.clone(),
        None => base_version.split("+train.").next().unwrap_or_default().to_string(),
    }
}

/// The artifact after the update, without a receipt or a refreshed checksum, and the version it carries.
#[derive(Debug, Clone)]
pub struct Applied {
    /// The edited document. Its checksum is stale until the caller seals it.
    pub root: Value,
    /// `<release>+train.<revision>`.
    pub applied_version: String,
}

/// `apply_parameter_update(payload, base_version=..., deltas=..., source_id=...)`. `now` is the value of
/// `int(time.time())`, read by the caller at the point Python reads it (after every check that can fail).
pub fn apply_parameter_update(loaded: &Loaded, request: &ParameterUpdateRequest, now: impl FnOnce() -> i64) -> Result<Applied, Failure> {
    let typed = &loaded.typed;
    if typed.architecture == scratch::SCRATCH_PRESENCE_ARCHITECTURE {
        return Err(Failure::invalid("Scratch artifacts only allow offline release fitting."));
    }
    if typed.architecture == pretrained::ARCHITECTURE {
        return Err(Failure::invalid("Pretrained contextual artifacts only allow offline release fitting."));
    }
    let base_version = request.base_version.as_str();
    if typed.version != base_version {
        return Err(Failure::Precondition(format!(
            "Stale base_version {}; current version is {}.",
            repr_str(base_version),
            repr_str(&typed.version)
        )));
    }
    if request.gradients.is_empty() {
        return Err(Failure::invalid("At least one parameter delta is required."));
    }
    let mut names: Vec<&str> = request.gradients.iter().map(|gradient| gradient.name.as_str()).collect();
    names.sort_unstable();
    names.dedup();
    if let Some(unknown) = names.iter().find(|name| !typed.parameters.contains_key(**name)) {
        return Err(Failure::invalid(format!("Unknown parameter: {}.", repr_str(unknown))));
    }
    if let Some(frozen) = names.iter().find(|name| !typed.parameters.get(**name).is_some_and(|tensor| tensor.trainable)) {
        return Err(Failure::invalid(format!("Parameter is not trainable: {}.", repr_str(frozen))));
    }

    let mut updated_values: BTreeMap<String, Vec<f64>> = BTreeMap::new();
    for gradient in &request.gradients {
        let Some(tensor) = typed.parameters.get(&gradient.name) else { continue };
        if gradient.values.len() != tensor.values.len() {
            return Err(Failure::invalid(format!("Parameter shape mismatch for {}.", repr_str(&gradient.name))));
        }
        let mut values = Vec::with_capacity(tensor.values.len());
        for (stored, delta) in tensor.values.iter().zip(&gradient.values) {
            let sum = float32(*stored).map_err(Failure::Invalid)? + float32(f64::from(*delta)).map_err(Failure::Invalid)?;
            values.push(round8(sum));
        }
        updated_values.insert(gradient.name.clone(), values);
    }

    let revision_text = typed.metadata().get("training_revision").map_or("0", String::as_str);
    let Some(current_revision) = py_int(revision_text) else {
        return Err(Failure::invalid("training_revision must be an integer."));
    };
    let revision = current_revision + 1;
    if revision <= 0 {
        return Err(Failure::invalid("training_revision must not be negative."));
    }
    let release_version = release_anchor(loaded, base_version);
    let applied_version = format!("{release_version}+train.{revision}");

    let Value::Object(mut root) = loaded.root.clone() else {
        return Err(Failure::invalid("Model artifact must be a JSON object."));
    };
    if let Some(Value::Object(parameters)) = root.get_mut("parameters") {
        for (name, values) in updated_values {
            if let Some(Value::Object(tensor)) = parameters.get_mut(&name) {
                tensor.insert("values".to_string(), Value::Array(values.into_iter().map(Value::Float).collect()));
            }
        }
    }
    let metadata = root.entry("metadata".to_string()).or_insert_with(|| Value::Object(BTreeMap::new()));
    if !matches!(metadata, Value::Object(_)) {
        *metadata = Value::Object(BTreeMap::new());
    }
    if let Value::Object(map) = metadata {
        map.insert("release_version".to_string(), Value::String(release_version));
        map.insert("training_revision".to_string(), Value::String(revision.to_string()));
        map.insert("last_update_source".to_string(), Value::String(request.source_id.clone()));
    }
    root.insert("version".to_string(), Value::String(applied_version.clone()));
    root.insert("generated_at_unix".to_string(), Value::Int(now().to_string()));
    Ok(Applied { root: Value::Object(root), applied_version })
}
