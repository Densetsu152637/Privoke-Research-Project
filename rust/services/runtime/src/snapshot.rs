//! A model as the analysis service caches it: `<model_id>.snapshot.pb`, a serialized `ModelParametersResponse`.
//!
//! The quarantined analysis service (stage W3) fetches each model from model-streaming and keeps the response it checked.
//! The Python worker behind its shim reads that file and builds the streaming client's snapshot from it
//! (`worker_shim.py`, `SnapshotModelProvider._snapshot`): the identity, the float32 tensors with their shapes and the
//! response metadata, verbatim. This module reads the same file for the Rust worker, so a model that a training cycle
//! publishes reaches both pools through the one file the service already writes.
//!
//! The artifact file itself is not recoverable from a snapshot (its float64 values and its bytes are gone), so nothing is
//! rebuilt that the file's bytes would have to match: the snapshot's metadata is the metadata, as for the Python worker
//! (`artifact_checksum`, `artifact_file_checksum`, `model_config`, `trainable_parameters` and the rest are the ones model-
//! streaming computed from the file). What the model code reads as a JSON artifact (`config`, the tensors with their
//! `trainable` flags, `checksum`) is rebuilt from those fields, with the float32 values the Python worker also reads.
//! The checksum over the file's contents is not recomputed, as for the Tiny artifacts: the service that cached the
//! snapshot has checked it.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use privoke_contracts::proto::v1::ModelParametersResponse;
use prost::Message as _;
use serde_json::{Map, Number, Value};

/// File suffix of a cached snapshot (`analysis::models::SNAPSHOT_SUFFIX`).
pub const SUFFIX: &str = ".snapshot.pb";

/// The snapshot file of a model under a root.
pub fn path(root: &Path, model_id: &str) -> PathBuf {
    root.join(format!("{model_id}{SUFFIX}"))
}

/// The metadata keys of the response that describe the artifact file; the others are the artifact's own `metadata`.
const FILE_KEYS: [&str; 5] = ["architecture", "model_config", "artifact_checksum", "artifact_file_checksum", "trainable_parameters"];

/// A snapshot read for the Rust worker.
#[derive(Debug, Clone)]
pub struct Snapshot {
    /// The artifact as the JSON the model code reads: `schema_version`, `model_id`, `version`, `generated_at_unix`,
    /// `architecture`, `config`, `parameters` (shape, float32 values, `trainable`), `metadata` and `checksum`.
    pub value: Value,
    /// `model_id`.
    pub model_id: String,
    /// `version`.
    pub version: String,
    /// `metadata["architecture"]`.
    pub architecture: String,
    /// `metadata["artifact_checksum"]`, empty when absent.
    pub checksum: String,
    /// `metadata["artifact_file_checksum"]`, empty when absent.
    pub file_sha256: String,
    /// The response metadata, verbatim.
    pub metadata: BTreeMap<String, String>,
    /// The tensors as doubles holding float32 values, by name.
    pub parameters: BTreeMap<String, Vec<f64>>,
    /// The shapes by name.
    pub shapes: BTreeMap<String, Vec<u64>>,
}

/// Reads the bytes of `<model_id>.snapshot.pb`. The messages are the Python worker's where it has one.
pub fn decode(model_id: &str, bytes: &[u8]) -> Result<Snapshot, String> {
    let message = ModelParametersResponse::decode(bytes).map_err(|error| format!("Could not load model snapshot: {error}"))?;
    if message.model_id != model_id {
        return Err("Cached snapshot model_id differs from its file name.".to_string());
    }
    let metadata: BTreeMap<String, String> = message.metadata.iter().map(|(key, value)| (key.clone(), value.clone())).collect();
    let architecture = metadata.get("architecture").cloned().ok_or_else(|| "Streamed model snapshot has no architecture.".to_string())?;
    let config: Value = serde_json::from_str(metadata.get("model_config").map_or("", String::as_str))
        .map_err(|_| "Streamed model config is not valid JSON.".to_string())?;
    if !config.is_object() {
        return Err("Model config must be a JSON object.".to_string());
    }
    let trainable: Vec<&str> =
        metadata.get("trainable_parameters").map_or("", String::as_str).split(',').filter(|name| !name.is_empty()).collect();

    let mut tensors = Map::new();
    let mut parameters = BTreeMap::new();
    let mut shapes = BTreeMap::new();
    for item in &message.parameters {
        let shape: Vec<u64> = item.shape.iter().map(|size| u64::from(*size)).collect();
        let expected = shape.iter().try_fold(1u64, |product, size| product.checked_mul(*size));
        if shape.is_empty() || shape.contains(&0) || expected != Some(item.values.len() as u64) {
            return Err(format!("Parameter '{}' has an invalid shape.", item.name));
        }
        let mut values = Vec::with_capacity(item.values.len());
        let mut numbers = Vec::with_capacity(item.values.len());
        for value in &item.values {
            let wide = f64::from(*value);
            let Some(number) = Number::from_f64(wide) else { return Err("Parameter is outside finite float32 range.".to_string()) };
            values.push(wide);
            numbers.push(Value::Number(number));
        }
        let mut tensor = Map::new();
        tensor.insert("shape".to_string(), Value::Array(shape.iter().map(|size| Value::from(*size)).collect()));
        tensor.insert("values".to_string(), Value::Array(numbers));
        tensor.insert("trainable".to_string(), Value::Bool(trainable.contains(&item.name.as_str())));
        if tensors.insert(item.name.clone(), Value::Object(tensor)).is_some() {
            return Err(format!("Parameter '{}' is repeated.", item.name));
        }
        shapes.insert(item.name.clone(), shape);
        parameters.insert(item.name.clone(), values);
    }
    if tensors.is_empty() {
        return Err("Model artifact must contain parameters.".to_string());
    }

    let checksum = metadata.get("artifact_checksum").cloned().unwrap_or_default();
    let own: Map<String, Value> = metadata
        .iter()
        .filter(|(key, _)| !FILE_KEYS.contains(&key.as_str()))
        .map(|(key, value)| (key.clone(), Value::String(value.clone())))
        .collect();
    let mut object = Map::new();
    object.insert("schema_version".to_string(), Value::from(1));
    object.insert("model_id".to_string(), Value::String(message.model_id.clone()));
    object.insert("version".to_string(), Value::String(message.version.clone()));
    object.insert("generated_at_unix".to_string(), Value::from(message.generated_at_unix));
    object.insert("architecture".to_string(), Value::String(architecture.clone()));
    object.insert("config".to_string(), config);
    object.insert("parameters".to_string(), Value::Object(tensors));
    object.insert("metadata".to_string(), Value::Object(own));
    object.insert("checksum".to_string(), Value::String(checksum.clone()));
    Ok(Snapshot {
        value: Value::Object(object),
        model_id: message.model_id,
        version: message.version,
        architecture,
        checksum,
        file_sha256: metadata.get("artifact_file_checksum").cloned().unwrap_or_default(),
        metadata,
        parameters,
        shapes,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use privoke_contracts::proto::v1::Parameter;

    fn response(mutate: impl FnOnce(&mut ModelParametersResponse)) -> Vec<u8> {
        let mut message = ModelParametersResponse {
            model_id: "m".into(),
            version: "v1".into(),
            generated_at_unix: 7,
            parameters: vec![
                Parameter { name: "a".into(), values: vec![0.5, -1.25], shape: vec![2] },
                Parameter { name: "b".into(), values: vec![1.0, 2.0, 3.0, 4.0], shape: vec![2, 2] },
            ],
            metadata: [
                ("architecture", "privoke_tiny_transformer_v1"),
                ("model_config", r#"{"d_model": 4,  "x": [1, 2.50]}"#),
                ("artifact_checksum", "ab"),
                ("artifact_file_checksum", "cd"),
                ("trainable_parameters", "b"),
                ("served_by", "model-streaming-service"),
            ]
            .into_iter()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect(),
        };
        mutate(&mut message);
        message.encode_to_vec()
    }

    #[test]
    fn the_snapshot_is_read_as_the_python_worker_reads_it() {
        let snapshot = decode("m", &response(|_| {})).unwrap();
        assert_eq!(
            (snapshot.model_id.as_str(), snapshot.version.as_str(), snapshot.architecture.as_str()),
            ("m", "v1", "privoke_tiny_transformer_v1")
        );
        assert_eq!((snapshot.checksum.as_str(), snapshot.file_sha256.as_str()), ("ab", "cd"));
        assert_eq!(snapshot.parameters["a"], [0.5, -1.25]);
        assert_eq!(snapshot.shapes["b"], [2, 2]);
        // The metadata is the response's, verbatim, including keys of the service's own.
        assert_eq!(snapshot.metadata["served_by"], "model-streaming-service");
        assert_eq!(snapshot.metadata["model_config"], r#"{"d_model": 4,  "x": [1, 2.50]}"#);
        // The JSON the model code reads.
        assert_eq!(snapshot.value["config"]["d_model"], 4);
        assert_eq!(snapshot.value["parameters"]["b"]["trainable"], true);
        assert_eq!(snapshot.value["parameters"]["a"]["trainable"], false);
        assert_eq!(snapshot.value["parameters"]["b"]["values"][3], 4.0);
        assert_eq!(snapshot.value["metadata"], serde_json::json!({"served_by": "model-streaming-service"}));
        assert_eq!(snapshot.value["checksum"], "ab");
    }

    #[test]
    fn a_snapshot_that_does_not_hold_together_is_refused() {
        assert_eq!(decode("other", &response(|_| {})).unwrap_err(), "Cached snapshot model_id differs from its file name.");
        assert!(decode("m", b"\xff\xff").unwrap_err().starts_with("Could not load model snapshot"));
        type Damage = Box<dyn Fn(&mut ModelParametersResponse)>;
        let cases: [(&str, Damage); 5] = [
            ("no architecture", Box::new(|m| drop(m.metadata.remove("architecture")))),
            ("config", Box::new(|m| drop(m.metadata.insert("model_config".into(), "[1]".into())))),
            ("shape", Box::new(|m| m.parameters[0].shape = vec![3])),
            ("finite", Box::new(|m| m.parameters[0].values[0] = f32::NAN)),
            ("empty", Box::new(|m| m.parameters.clear())),
        ];
        for (name, mutate) in cases {
            assert!(decode("m", &response(mutate)).is_err(), "{name}");
        }
    }
}
