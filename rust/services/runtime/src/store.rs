//! Read-only model artifacts for the presence and gradient RPCs.
//!
//! The Python worker reads `<root>/<model_id>.json` through `worker_main.LocalModelProvider` and `artifact.load_artifact`;
//! this is the same read for the Rust worker. The front end has fetched the model and checked its pin, and the worker
//! only reads: it has no network. The checks of `validate_artifact` that do not depend on the architecture are made here
//! with Python's messages (schema, identity, tensor shapes and values, the size budgets and the checksum over the
//! canonical content). The architecture contracts (presence config and tensors, the Tiny contextual training contract)
//! are checked by the model code that uses the artifact.
//!
//! What this reader does not serve is a [`LoadError::Declined`]: the call is handed to the Python worker (a pinned V3
//! package at the same name, an artifact whose metadata holds a value that is not a string). A [`LoadError::Message`] is
//! the text the Python worker puts in the response's `error`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use privoke_contracts::digest::{artifact_checksum_of_artifact, sha256_hex};
use privoke_contracts::json as strict_json;
use serde_json::Value;

/// `MAX_ARTIFACT_BYTES`.
pub const MAX_ARTIFACT_BYTES: usize = 8 * 1024 * 1024;
/// `MAX_PARAMETER_VALUES`.
pub const MAX_PARAMETER_VALUES: usize = 65_536;
/// The architectures `validate_artifact` accepts for the artifacts this worker reads.
const KNOWN_ARCHITECTURES: [&str; 3] = ["privoke_tiny_transformer_v1", "privoke_tiny_transformer_v2", PRESENCE_ARCHITECTURE];
/// The architecture of the sparse annotation-presence artifact.
pub const PRESENCE_ARCHITECTURE: &str = "privoke_sparse_presence_v1";
/// The text of the provider for artifacts that no W1 worker serves.
const NOT_SERVED: &str = "Scratch-presence and pretrained-context artifacts are not served by the W1 worker.";
const PRETRAINED_CONTEXT_MODEL_ID: &str = "privoke-pretrained-context-minilm";

/// Why an artifact could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoadError {
    /// The text the Python worker reports for the same failure.
    Message(String),
    /// A model this reader does not serve; the Python worker answers the call.
    Declined(String),
}

fn message(text: impl Into<String>) -> LoadError {
    LoadError::Message(text.into())
}

/// An artifact as the worker's provider snapshots it.
#[derive(Debug, Clone)]
pub struct Artifact {
    /// The parsed JSON.
    pub value: Value,
    /// `model_id`.
    pub model_id: String,
    /// `version`.
    pub version: String,
    /// `architecture`.
    pub architecture: String,
    /// `checksum`.
    pub checksum: String,
    /// SHA-256 of the file's bytes (`artifact_file_checksum`).
    pub file_sha256: String,
    /// The snapshot metadata: the artifact's own metadata (strings only) plus `architecture`, `model_config` (the raw
    /// source text of `config`), `artifact_checksum`, `artifact_file_checksum` and `trainable_parameters`, and for a
    /// presence artifact `task`, `profile`, `text_normalization` and `arithmetic`.
    pub metadata: BTreeMap<String, String>,
    /// Parameters rounded to float32 (as doubles), by name.
    pub parameters: BTreeMap<String, Vec<f64>>,
    /// Shapes by name.
    pub shapes: BTreeMap<String, Vec<u64>>,
}

/// Model ids the file system never sees as paths (`MODEL_ID_PATTERN`).
pub fn valid_model_id(model_id: &str) -> bool {
    let mut chars = model_id.chars();
    let Some(first) = chars.next() else { return false };
    model_id.chars().count() <= 128
        && first.is_ascii_alphanumeric()
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+' | '-'))
}

/// The roots a worker reads models from.
#[derive(Debug, Clone)]
pub struct ArtifactStore {
    roots: Vec<PathBuf>,
    latest: Option<String>,
}

impl ArtifactStore {
    /// A store over directories. `latest` is what the alias `latest` resolves to.
    pub fn new(roots: Vec<PathBuf>, latest: Option<String>) -> Self {
        Self { roots, latest }
    }

    /// The roots.
    pub fn roots(&self) -> &[PathBuf] {
        &self.roots
    }

    fn locate(&self, model_id: &str) -> Result<PathBuf, LoadError> {
        for root in &self.roots {
            if root.join(model_id).join("manifest.json").is_file() {
                return Err(LoadError::Declined(format!("{model_id} is a pinned V3 package")));
            }
            let artifact = root.join(format!("{model_id}.json"));
            if artifact.is_file() {
                return Ok(artifact);
            }
        }
        Err(message(format!("Model {model_id} is not available in the worker model roots.")))
    }

    /// The bytes of the artifact for a model id (`latest` resolved), with the resolved id.
    pub fn read_bytes(&self, requested: &str) -> Result<(String, Vec<u8>), LoadError> {
        let model_id = if requested == "latest" {
            self.latest.clone().ok_or_else(|| message("latest is not resolvable in the worker; name the model explicitly."))?
        } else {
            requested.to_string()
        };
        if !valid_model_id(&model_id) {
            return Err(message("model_id is not a valid model identifier."));
        }
        let path = self.locate(&model_id)?;
        let bytes = std::fs::read(&path).map_err(|error| message(format!("{}: {error}", path.display())))?;
        Ok((model_id, bytes))
    }

    /// Reads and validates the artifact for a model id.
    pub fn read(&self, requested: &str) -> Result<Artifact, LoadError> {
        let (model_id, bytes) = self.read_bytes(requested)?;
        Artifact::parse(&model_id, &bytes)
    }
}

fn repr(value: Option<&Value>) -> String {
    match value {
        None | Some(Value::Null) => "None".to_string(),
        Some(Value::Bool(true)) => "True".to_string(),
        Some(Value::Bool(false)) => "False".to_string(),
        Some(Value::String(text)) => format!("'{text}'"),
        Some(other) => other.to_string(),
    }
}

fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(flag) => *flag,
        Value::Number(number) => number.as_f64() != Some(0.0),
        Value::String(text) => !text.is_empty(),
        Value::Array(items) => !items.is_empty(),
        Value::Object(items) => !items.is_empty(),
    }
}

fn skip(bytes: &[u8], mut index: usize, accept: impl Fn(u8) -> bool) -> usize {
    while index < bytes.len() && accept(bytes[index]) {
        index += 1;
    }
    index
}

/// The index after the closing quote of the string that starts at `index`.
fn string_end(bytes: &[u8], index: usize) -> Result<usize, String> {
    if bytes.get(index) != Some(&b'"') {
        return Err("Artifact config is malformed.".to_string());
    }
    let mut position = index + 1;
    while position < bytes.len() {
        match bytes[position] {
            b'\\' => position += 2,
            b'"' => return Ok(position + 1),
            _ => position += 1,
        }
    }
    Err("Artifact config is malformed.".to_string())
}

/// The index after the value that starts at `index`.
fn value_end(bytes: &[u8], index: usize) -> Result<usize, String> {
    match bytes.get(index) {
        None => Err("Artifact config is malformed.".to_string()),
        Some(b'"') => string_end(bytes, index),
        Some(b'{' | b'[') => {
            let (mut depth, mut position) = (0usize, index);
            while position < bytes.len() {
                match bytes[position] {
                    b'"' => {
                        position = string_end(bytes, position)?;
                        continue;
                    }
                    b'{' | b'[' => depth += 1,
                    b'}' | b']' => {
                        depth -= 1;
                        if depth == 0 {
                            return Ok(position + 1);
                        }
                    }
                    _ => {}
                }
                position += 1;
            }
            Err("Artifact config is malformed.".to_string())
        }
        Some(_) => Ok(skip(bytes, index, |b| !matches!(b, b',' | b'}' | b']' | b' ' | b'\t' | b'\r' | b'\n'))),
    }
}

/// `_raw_config_text`: the exact source text of the top-level `config` value, as the Go service streams it.
pub fn raw_config_text(text: &str) -> Result<String, String> {
    let bytes = text.as_bytes();
    let mut index = text.find('{').ok_or_else(|| "Artifact has no config.".to_string())? + 1;
    loop {
        index = skip(bytes, index, |b| matches!(b, b' ' | b'\t' | b'\r' | b'\n' | b','));
        if index >= bytes.len() || bytes[index] == b'}' {
            return Err("Artifact has no config.".to_string());
        }
        let key_end = string_end(bytes, index)?;
        let key: String = serde_json::from_str(&text[index..key_end]).map_err(|error| error.to_string())?;
        index = skip(bytes, key_end, |b| matches!(b, b' ' | b'\t' | b'\r' | b'\n' | b':'));
        let start = index;
        index = value_end(bytes, index)?;
        if key == "config" {
            return Ok(text[start..index].to_string());
        }
    }
}

fn validate_text_field(value: &Value, name: &str) -> Result<String, LoadError> {
    let text = value.as_str().filter(|text| !text.is_empty() && text.chars().count() <= 128);
    let Some(text) = text else { return Err(message(format!("{name} must contain 1 to 128 characters."))) };
    if text.chars().any(|c| (c as u32) < 32 || c as u32 == 127) {
        return Err(message(format!("{name} contains control characters.")));
    }
    Ok(text.to_string())
}

impl Artifact {
    /// `load_artifact` and the provider's snapshot, for the bytes of the file of `model_id`.
    pub fn parse(model_id: &str, bytes: &[u8]) -> Result<Self, LoadError> {
        if bytes.len() > MAX_ARTIFACT_BYTES {
            return Err(message("Model artifact exceeds 8 MiB."));
        }
        let text = std::str::from_utf8(bytes).map_err(|error| message(format!("Could not load model artifact: {error}")))?;
        let value: Value = serde_json::from_str(text).map_err(|error| message(format!("Could not load model artifact: {error}")))?;
        let object = value.as_object().ok_or_else(|| message("Model artifact must be a JSON object."))?;
        if object.get("schema_version").and_then(Value::as_u64) != Some(1) {
            return Err(message(format!("Unsupported model schema: {}.", repr(object.get("schema_version")))));
        }
        let architecture = object.get("architecture").and_then(Value::as_str).unwrap_or_default().to_string();
        if !KNOWN_ARCHITECTURES.contains(&architecture.as_str()) {
            let named = object.get("architecture");
            let scratch = named.and_then(Value::as_str).is_some_and(|name| name.contains("scratch") || name.contains("pretrained_context"));
            if scratch || object.get("model_id").and_then(Value::as_str) == Some(PRETRAINED_CONTEXT_MODEL_ID) {
                return Err(message(NOT_SERVED));
            }
            return Err(message(format!("Unsupported model architecture: {}.", repr(named))));
        }
        let artifact_id = validate_text_field(object.get("model_id").unwrap_or(&Value::Null), "model_id")?;
        let version = validate_text_field(object.get("version").unwrap_or(&Value::Null), "version")?;
        let config = object.get("config").filter(|config| config.is_object());
        if config.is_none() {
            return Err(message("Model config must be a JSON object."));
        }
        let tensors = object
            .get("parameters")
            .and_then(Value::as_object)
            .filter(|tensors| !tensors.is_empty())
            .ok_or_else(|| message("Model artifact must contain parameters."))?;
        let mut total = 0usize;
        for (name, tensor) in tensors {
            if name.is_empty() || name.chars().count() > 256 {
                return Err(message("Parameter names must contain 1 to 256 characters."));
            }
            let Some(tensor) = tensor.as_object() else { return Err(message(format!("Parameter '{name}' must be an object."))) };
            let shape: Option<Vec<u64>> = tensor
                .get("shape")
                .and_then(Value::as_array)
                .filter(|shape| !shape.is_empty())
                .and_then(|shape| shape.iter().map(|size| size.as_u64().filter(|size| *size > 0)).collect());
            let Some(shape) = shape else { return Err(message(format!("Parameter '{name}' has an invalid shape."))) };
            let values = tensor.get("values").and_then(Value::as_array).filter(|values| !values.is_empty());
            let Some(values) = values else { return Err(message(format!("Parameter '{name}' has no values."))) };
            let expected = shape.iter().try_fold(1u64, |product, size| product.checked_mul(*size));
            if expected != Some(values.len() as u64) {
                return Err(message(format!(
                    "Parameter '{name}' shape requires {} values, got {}.",
                    expected.map_or_else(|| "too many".to_string(), |count| count.to_string()),
                    values.len()
                )));
            }
            if !values.iter().all(Value::is_number) {
                return Err(message(format!("Parameter '{name}' contains a non-finite value.")));
            }
            total += values.len();
        }
        if total > MAX_PARAMETER_VALUES {
            return Err(message(format!("Model artifact exceeds {MAX_PARAMETER_VALUES} parameter values.")));
        }
        let checksum = object.get("checksum").and_then(Value::as_str).filter(|checksum| checksum.chars().count() == 64);
        let Some(checksum) = checksum else { return Err(message("Model artifact has no valid checksum.")) };
        let strict = strict_json::parse(text).map_err(|error| message(format!("Could not load model artifact: {error}")))?;
        let expected = artifact_checksum_of_artifact(&strict).map_err(|_| message("Model artifact contains a non-finite value."))?;
        if expected != checksum {
            return Err(message("Model artifact checksum does not match its contents."));
        }
        if artifact_id != model_id {
            return Err(message("Artifact model_id differs from its file name."));
        }
        if model_id.starts_with("privoke-scratch-presence-") || model_id == PRETRAINED_CONTEXT_MODEL_ID {
            return Err(message(NOT_SERVED));
        }

        let mut metadata = BTreeMap::new();
        match object.get("metadata") {
            None | Some(Value::Null) => {}
            Some(Value::Object(entries)) => {
                for (key, entry) in entries {
                    match entry {
                        Value::String(text) => {
                            metadata.insert(key.clone(), text.clone());
                        }
                        _ => return Err(LoadError::Declined(format!("the artifact metadata {key:?} is not a string"))),
                    }
                }
            }
            Some(_) => return Err(LoadError::Declined("the artifact metadata is not an object".to_string())),
        }
        let mut parameters = BTreeMap::new();
        let mut shapes = BTreeMap::new();
        let mut trainable = Vec::new();
        for (name, tensor) in tensors {
            let mut rounded = Vec::new();
            for entry in tensor.get("values").and_then(Value::as_array).into_iter().flatten() {
                let narrowed = entry.as_f64().unwrap_or(f64::NAN) as f32;
                if !narrowed.is_finite() {
                    return Err(message("Parameter is outside finite float32 range."));
                }
                rounded.push(f64::from(narrowed));
            }
            parameters.insert(name.clone(), rounded);
            shapes.insert(
                name.clone(),
                tensor.get("shape").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_u64).collect(),
            );
            let Some(flag) = tensor.get("trainable") else { return Err(message("'trainable'")) };
            if truthy(flag) {
                trainable.push(name.clone());
            }
        }
        let config_text = raw_config_text(text).map_err(message)?;
        metadata.insert("architecture".to_string(), architecture.clone());
        metadata.insert("model_config".to_string(), config_text);
        metadata.insert("artifact_checksum".to_string(), checksum.to_string());
        metadata.insert("artifact_file_checksum".to_string(), sha256_hex(bytes));
        metadata.insert("trainable_parameters".to_string(), trainable.join(","));
        if architecture == PRESENCE_ARCHITECTURE {
            let field = |name: &str| config.and_then(|config| config.get(name)).and_then(Value::as_str).map(str::to_string);
            let (Some(task), Some(profile), Some(normalization)) = (field("task"), field("profile"), field("normalization")) else {
                return Err(message("Presence config has missing or unknown fields."));
            };
            metadata.insert("task".to_string(), task);
            metadata.insert("profile".to_string(), profile);
            metadata.insert("text_normalization".to_string(), normalization);
            metadata.insert("arithmetic".to_string(), "float32_parameters_float64_features_fsum_v1".to_string());
        }
        Ok(Self {
            value,
            model_id: artifact_id,
            version,
            architecture,
            checksum: checksum.to_string(),
            file_sha256: sha256_hex(bytes),
            metadata,
            parameters,
            shapes,
        })
    }
}

/// The path of an artifact under a root, for tests and the golden generator.
pub fn artifact_path(root: &Path, model_id: &str) -> PathBuf {
    root.join(format!("{model_id}.json"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn the_raw_config_text_is_the_source_slice() {
        let text =
            "{\n \"architecture\": \"a\",\n \"config\": {\"b\": [1, 2.50, \"x}\"], \"c\": {\"d\": \"q\\\"\"}},\n \"version\": \"v\" }";
        assert_eq!(raw_config_text(text).unwrap(), "{\"b\": [1, 2.50, \"x}\"], \"c\": {\"d\": \"q\\\"\"}}");
        assert_eq!(raw_config_text("{\"config\": 7}").unwrap(), "7");
        assert!(raw_config_text("{\"a\": 1}").is_err());
        assert!(raw_config_text("{\"config\": {\"a\": ").is_err());
    }

    #[test]
    fn model_ids_are_file_names_only() {
        assert!(valid_model_id("privoke-presence-efficient"));
        assert!(valid_model_id("a.b_c+d-e"));
        assert!(!valid_model_id(""));
        assert!(!valid_model_id("../x"));
        assert!(!valid_model_id(".hidden"));
        assert!(!valid_model_id("a/b"));
        assert!(!valid_model_id(&"x".repeat(129)));
    }

    #[test]
    fn an_unknown_model_is_not_available_and_latest_needs_a_target() {
        let store = ArtifactStore::new(Vec::new(), None);
        assert_eq!(store.read("nope").unwrap_err(), message("Model nope is not available in the worker model roots."));
        assert_eq!(store.read("latest").unwrap_err(), message("latest is not resolvable in the worker; name the model explicitly."));
        assert_eq!(store.read("../x").unwrap_err(), message("model_id is not a valid model identifier."));
    }

    #[test]
    fn documents_that_are_not_artifacts_get_python_messages() {
        let parse = |text: &str| Artifact::parse("m", text.as_bytes()).unwrap_err();
        assert_eq!(parse("[]"), message("Model artifact must be a JSON object."));
        assert_eq!(parse("{\"schema_version\": 2}"), message("Unsupported model schema: 2."));
        assert_eq!(parse("{}"), message("Unsupported model schema: None."));
        assert_eq!(parse("{\"schema_version\": 1, \"architecture\": \"x\"}"), message("Unsupported model architecture: 'x'."));
        assert!(matches!(parse("{"), LoadError::Message(text) if text.starts_with("Could not load model artifact")));
    }
}
