//! Idempotent preparation of the selected mutable Tiny model before serving it (`bootstrap.py` and
//! `prepare_full_encoder_artifact`).
//!
//! The receipt transaction is also the cross-process model writer lock. The artifact is reloaded after every
//! checkpoint boundary before its bytes are inspected or replaced, learned weights are never reseeded, and a context
//! that is already large enough is never shrunk. The preparation is a pure function of the input artifact, the target
//! context and the clock reading, so it reproduces the Python service's bytes.

use std::collections::BTreeMap;
use std::path::Path;

use privoke_contracts::digest::sha256_hex;
use privoke_contracts::json::Value;
use privoke_model_streaming::artifact::{EXPECTED_ARCHITECTURE, TASK_QUERY_ARCHITECTURE};
use privoke_model_streaming::contextual::{FULL_ENCODER_STRATEGY, STRATEGY_KEY, contextual_trainable_names};

use crate::artifact_io::{self, Loaded};
use crate::engine::{Clock, Hook};
use crate::error::Failure;
use crate::pyfmt::float32;
use crate::receipts::{RECEIPT_METADATA_KEY, ReceiptStore};

/// The commit that implements the versioned preparation algorithm (`bootstrap.PREPARATION_CODE_REVISION`).
pub const PREPARATION_CODE_REVISION: &str = "d19ec2e09fcf052af408387b36f4ff033d17913a";

fn config_object(root: &Value) -> Option<&BTreeMap<String, Value>> {
    match root {
        Value::Object(map) => match map.get("config") {
            Some(Value::Object(config)) => Some(config),
            _ => None,
        },
        _ => None,
    }
}

fn config_int(root: &Value, name: &str) -> Option<i64> {
    match config_object(root)?.get(name) {
        Some(Value::Int(digits)) => digits.parse::<i64>().ok(),
        _ => None,
    }
}

fn valid_release_version(version: &str) -> bool {
    let bytes = version.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 128
        && bytes[0].is_ascii_alphanumeric()
        && bytes.iter().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'+' | b'_' | b'-'))
}

/// `prepare_full_encoder_artifact(artifact, version=..., generated_at_unix=..., source_revision=..., max_tokens=...)`.
///
/// `base` must not carry a recovery receipt. The result is sealed with its checksum and not yet validated; the caller
/// publishes it through [`artifact_io::write_atomic`], which validates.
pub fn prepare_full_encoder_artifact(
    base: &Loaded,
    version: &str,
    generated_at_unix: i64,
    source_revision: &str,
    max_tokens: i64,
) -> Result<Value, Failure> {
    let typed = &base.typed;
    if typed.metadata().contains_key(RECEIPT_METADATA_KEY) {
        return Err(Failure::invalid("Checkpoint and clear the recovery receipt before preparing a new release."));
    }
    if !valid_release_version(version) || version == typed.version {
        return Err(Failure::invalid("Full encoder preparation requires a distinct valid release version."));
    }
    if generated_at_unix <= 0 {
        return Err(Failure::invalid("Full encoder preparation requires a positive timestamp."));
    }
    if source_revision.len() != 40 || !source_revision.bytes().all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f')) {
        return Err(Failure::invalid("Full encoder preparation requires an exact source commit."));
    }
    if typed.architecture != EXPECTED_ARCHITECTURE && typed.architecture != TASK_QUERY_ARCHITECTURE {
        return Err(Failure::invalid("Contextual adaptation requires a contextual transformer."));
    }
    let (trainable, _layers) =
        contextual_trainable_names(&typed.config, FULL_ENCODER_STRATEGY).map_err(|error| Failure::invalid(error.to_string()))?;
    let previous_context =
        config_int(&base.root, "max_tokens").ok_or_else(|| Failure::invalid("Model config has no integer max_tokens."))?;
    if !(previous_context..=512).contains(&max_tokens) {
        return Err(Failure::invalid("Context extension must be an integer between the source context and 512."));
    }
    let hidden = config_int(&base.root, "hidden_size").ok_or_else(|| Failure::invalid("Model config has no integer hidden_size."))?;

    let Value::Object(mut root) = base.root.clone() else {
        return Err(Failure::invalid("Model artifact must be a JSON object."));
    };
    if let Some(Value::Object(parameters)) = root.get_mut("parameters") {
        for (name, tensor) in parameters.iter_mut() {
            if let Value::Object(fields) = tensor {
                fields.insert("trainable".to_string(), Value::Bool(trainable.contains(name)));
            }
        }
    }
    artifact_io::metadata_mut(&mut root).insert(STRATEGY_KEY.to_string(), Value::String(FULL_ENCODER_STRATEGY.to_string()));

    if max_tokens != previous_context {
        let columns = u64::try_from(hidden).map_err(|_| Failure::invalid("Model config has an invalid hidden_size."))?;
        let Some(Value::Object(parameters)) = root.get_mut("parameters") else {
            return Err(Failure::invalid("Model artifact has no parameters."));
        };
        let Some(Value::Object(position)) = parameters.get_mut("position_embedding") else {
            return Err(Failure::invalid("Model artifact has no position_embedding."));
        };
        let Some(Value::Array(values)) = position.get_mut("values") else {
            return Err(Failure::invalid("position_embedding has no values."));
        };
        // Independent hash draws avoid a framework RNG or version dependency. Each new coordinate maps a 32-bit
        // integer to [-.03, .03] and then rounds to float32.
        for row in previous_context..max_tokens {
            for column in 0..columns {
                let digest = sha256_hex(format!("privoke_position_sha256_v1:{row}:{column}").as_bytes());
                let number = u32::from_str_radix(&digest[..8], 16).map_err(|error| Failure::invalid(error.to_string()))?;
                let draw = (f64::from(number) / 4_294_967_295.0 * 2.0 - 1.0) * 0.03;
                values.push(Value::Float(float32(draw).map_err(Failure::Invalid)?));
            }
        }
        position.insert("shape".to_string(), Value::Array(vec![Value::Int(max_tokens.to_string()), Value::Int(hidden.to_string())]));
        if let Some(Value::Object(config)) = root.get_mut("config") {
            config.insert("max_tokens".to_string(), Value::Int(max_tokens.to_string()));
        }
    }

    root.insert("version".to_string(), Value::String(version.to_string()));
    root.insert("generated_at_unix".to_string(), Value::Int(generated_at_unix.to_string()));
    let initialization = if max_tokens != previous_context { "sha256_coordinate_uniform_float32_v1" } else { "unchanged" };
    let metadata = artifact_io::metadata_mut(&mut root);
    for (key, value) in [
        ("release_version", version.to_string()),
        ("training_revision", "0".to_string()),
        ("preparation_source_revision", source_revision.to_string()),
        ("preparation_base_version", typed.version.clone()),
        ("preparation_base_checksum", typed.checksum.clone()),
        ("preparation_old_max_tokens", previous_context.to_string()),
        ("preparation_max_tokens", max_tokens.to_string()),
        ("preparation_position_initialization", initialization.to_string()),
        ("preparation_purpose", "explicit_full_tiny_encoder_training_no_quality_promotion".to_string()),
    ] {
        metadata.insert(key.to_string(), Value::String(value));
    }
    let mut prepared = Value::Object(root);
    artifact_io::seal(&mut prepared)?;
    Ok(prepared)
}

/// `bootstrap_model`: migrate the current learned weights to a full-encoder release with at least `max_tokens` of
/// context, checkpointing the receipts first. Returns the artifact that is current afterwards.
pub fn bootstrap_model(
    model_path: &Path,
    audit_path: &Path,
    model_id: &str,
    max_tokens: i64,
    clock: &Clock,
    hook: &Hook,
) -> Result<Loaded, Failure> {
    if !(1..=512).contains(&max_tokens) {
        return Err(Failure::invalid("Bootstrap context must be an integer from 1 through 512."));
    }
    if let Some(parent) = audit_path.parent().filter(|parent| !parent.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }
    let injected = |phase: &str| hook(phase, "").map_err(|message| Failure::persistence(format!("{phase}: {message}")));
    let mut store = ReceiptStore::begin(audit_path)?;
    let outcome = bootstrap_locked(&mut store, model_path, model_id, max_tokens, clock, &injected);
    match outcome {
        Ok(loaded) => {
            store.commit()?;
            Ok(loaded)
        }
        Err(failure) => {
            store.rollback();
            Err(failure)
        }
    }
}

fn bootstrap_locked(
    store: &mut ReceiptStore,
    model_path: &Path,
    model_id: &str,
    max_tokens: i64,
    clock: &Clock,
    injected: &dyn Fn(&str) -> Result<(), Failure>,
) -> Result<Loaded, Failure> {
    let mismatch = || Failure::invalid("Bootstrap selected model ID does not match the mutable artifact.");
    let mut loaded = artifact_io::load(model_path)?;
    if loaded.typed.model_id != model_id {
        return Err(mismatch());
    }
    while store.recover(&loaded.typed)? {
        store.checkpoint()?;
        injected("after_checkpoint")?;
        loaded = artifact_io::load(model_path)?;
        if loaded.typed.model_id != model_id {
            return Err(Failure::invalid("Bootstrap selected model ID changed across the receipt checkpoint."));
        }
    }
    if loaded.typed.model_id != model_id {
        return Err(mismatch());
    }
    let context = config_int(&loaded.root, "max_tokens").ok_or_else(|| Failure::invalid("Model config has no integer max_tokens."))?;
    if loaded.typed.metadata().get(STRATEGY_KEY).map(String::as_str) == Some(FULL_ENCODER_STRATEGY) && context >= max_tokens {
        return Ok(loaded);
    }
    // recover() may report an already-durable receipt as not missing. All history is now committed; only the private
    // preparation copy loses its marker.
    injected("before_prepare")?;
    let original_checksum = loaded.typed.checksum.clone();
    let mut clean = loaded.clone();
    if let Value::Object(root) = &mut clean.root
        && let Some(Value::Object(metadata)) = root.get_mut("metadata")
    {
        metadata.remove(RECEIPT_METADATA_KEY);
    }
    artifact_io::seal(&mut clean.root)?;
    let clean = artifact_io::decode(artifact_io::render(&clean.root)?.as_bytes())?;
    let target = max_tokens.max(context);
    let version = format!("v0.4.0-full-ctx{target}-{}", &original_checksum[..12]);
    let mut prepared = prepare_full_encoder_artifact(&clean, &version, clock(), PREPARATION_CODE_REVISION, target)?;
    if let Value::Object(root) = &mut prepared {
        artifact_io::metadata_mut(root).insert("preparation_base_checksum".to_string(), Value::String(original_checksum));
    }
    artifact_io::seal(&mut prepared)?;
    injected("before_publish")?;
    artifact_io::write_atomic(model_path, &prepared)?;
    injected("after_publish")?;
    artifact_io::load(model_path)
}
