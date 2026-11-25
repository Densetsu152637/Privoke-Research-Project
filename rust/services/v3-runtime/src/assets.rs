//! `fetch`, `materialize` and `load` of `runtime_server.py`: the snapshot manifest and its three assets come from the checkpoint
//! service, are cached by digest under `<state>/assets/`, and are verified against the manifest before a model is built.
//!
//! * `fetch(stub, sha)`: the ordered, bounded, hash-checked reassembly of a blob stream.
//! * `materialize(sha)`: the cached file of a blob, fetched when absent, and its bytes re-hashed on every use
//!   (`Runtime cached asset bytes corrupted.`).
//! * `load(sha)`: the manifest is parsed canonically and validated (`validate_manifest`), the assets are materialized, and the
//!   model is built the way `PretrainedV3.load` builds it: every asset must hash to the manifest and the checkpoint's tensor
//!   inventory (names, shapes, dtypes, tensor hashes) must equal the manifest's.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use privoke_semantic::V3Model;
use privoke_semantic::safetensors::{self, Tensor};
use privoke_v3_fuzzer::backend::assemble_blob;
use privoke_v3_fuzzer::contract::{self, MAX_MANIFEST_BYTES, check_sha, digest};
use serde_json::Value;

use crate::pyerr::PyError;
use crate::service::Runtime;

/// How strictly a manifest is admitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    /// `validate_manifest`: the three admitted tiers with their pinned provenance, asset hashes and parameter counts. The
    /// only mode the service binary runs.
    Pinned,
    /// The structure of the manifest only (the key set, the schema and the architecture). For the synthetic packages of the
    /// tests, which are no admitted tier; nothing in the binary or the environment selects it.
    Structural,
}

/// A loaded snapshot.
#[derive(Debug)]
pub struct Loaded {
    /// The validated manifest.
    pub manifest: Value,
    /// The same manifest as the strict JSON value of the canonical writer (the candidate manifest of a fit starts from it).
    pub document: privoke_contracts::json::Value,
    /// The model.
    pub model: V3Model,
    /// The checkpoint tensors (`encoder.*` and `heads.*`), kept only for a fit, which starts from them.
    pub tensors: Option<BTreeMap<String, Tensor>>,
}

const MANIFEST_KEYS: [&str; 14] = [
    "schema",
    "architecture",
    "model_id",
    "tier",
    "parent",
    "original",
    "blob",
    "config",
    "vocab",
    "source",
    "tensors",
    "parameter_count",
    "scope",
    "evidence",
];

fn structural(manifest: &Value) -> Result<(), PyError> {
    let object = manifest
        .as_object()
        .filter(|object| object.len() == MANIFEST_KEYS.len() && MANIFEST_KEYS.iter().all(|key| object.contains_key(*key)));
    let valid = object.is_some_and(|object| object["schema"] == 1 && object["architecture"] == privoke_contracts::v3::ARCHITECTURE);
    if !valid {
        return Err(PyError::value("Unsupported v3 manifest schema."));
    }
    for key in ["blob", "config", "vocab"] {
        check_sha(manifest[key].as_str().unwrap_or_default())?;
    }
    Ok(())
}

/// `validate_manifest(parse(payload))`, in the chosen admission mode: the manifest as a strict JSON value and as a `serde_json` one.
pub fn admit(payload: &[u8], admission: Admission) -> Result<(privoke_contracts::json::Value, Value), PyError> {
    let document = contract::parse(payload, MAX_MANIFEST_BYTES)?;
    match admission {
        Admission::Pinned => {
            contract::validate_manifest(&document)?;
        }
        Admission::Structural => {}
    }
    let manifest = contract::to_serde(&document)?;
    if admission == Admission::Structural {
        structural(&manifest)?;
    }
    Ok((document, manifest))
}

/// `inventory(state) != manifest["tensors"]`.
pub fn check_inventory(tensors: &BTreeMap<String, Tensor>, declared: &Value) -> Result<(), PyError> {
    let mismatch = || PyError::value("Checkpoint inventory/hash mismatch.");
    let declared = declared.as_object().ok_or_else(mismatch)?;
    if declared.len() != tensors.len() {
        return Err(mismatch());
    }
    for (name, tensor) in tensors {
        let entry = declared.get(name).ok_or_else(mismatch)?;
        let shape: Option<Vec<usize>> = entry
            .get("shape")
            .and_then(Value::as_array)
            .and_then(|dims| dims.iter().map(|dim| dim.as_u64().and_then(|dim| usize::try_from(dim).ok())).collect());
        let same = entry.get("dtype").and_then(Value::as_str) == Some("F32")
            && shape.as_deref() == Some(tensor.shape.as_slice())
            && entry.get("sha256").and_then(Value::as_str) == Some(tensor.sha256.as_str());
        if !same {
            return Err(mismatch());
        }
    }
    Ok(())
}

fn write_new(path: &Path, payload: &[u8]) -> Result<(), PyError> {
    use std::io::Write;
    // Written beside the target and renamed, so that an interrupted write never leaves a partial cached asset behind.
    let name = path.file_name().map(|name| name.to_string_lossy().to_string()).unwrap_or_default();
    let temporary = path.with_file_name(format!("{name}.partial"));
    let mut handle = std::fs::OpenOptions::new().write(true).create(true).truncate(true).open(&temporary)?;
    handle.write_all(payload)?;
    handle.sync_all()?;
    drop(handle);
    std::fs::rename(&temporary, path)?;
    Ok(())
}

fn verified(path: &Path, sha: &str) -> Result<(), PyError> {
    if digest(&std::fs::read(path)?) != sha {
        return Err(PyError::value("Runtime cached asset bytes corrupted."));
    }
    Ok(())
}

impl Runtime {
    /// `fetch(stub, sha)`.
    pub(crate) async fn fetch(&self, sha: &str) -> Result<Vec<u8>, PyError> {
        check_sha(sha)?;
        let chunks = self.checkpoint.fetch_blob(sha).await.map_err(|status| PyError::rpc(&status))?;
        Ok(assemble_blob(&chunks, sha)?)
    }

    /// `materialize(sha)`: the path of the cached blob.
    pub(crate) async fn materialize(&self, sha: &str) -> Result<PathBuf, PyError> {
        check_sha(sha)?;
        let path = self.directory.join("assets").join(sha);
        std::fs::create_dir_all(self.directory.join("assets"))?;
        if !path.exists() {
            let payload = self.fetch(sha).await?;
            let target = path.clone();
            tokio::task::spawn_blocking(move || write_new(&target, &payload))
                .await
                .map_err(|error| PyError::value(error.to_string()))??;
        }
        let (target, expected) = (path.clone(), sha.to_string());
        tokio::task::spawn_blocking(move || verified(&target, &expected)).await.map_err(|error| PyError::value(error.to_string()))??;
        Ok(path)
    }

    /// `load(sha)`: the manifest and the model of a snapshot. `keep_tensors` keeps the checkpoint tensors for a fit.
    pub(crate) async fn load(&self, sha: &str, keep_tensors: bool) -> Result<Loaded, PyError> {
        let payload = self.fetch(sha).await?;
        let (document, manifest) = admit(&payload, self.admission)?;
        let text = |key: &str| manifest[key].as_str().unwrap_or_default().to_string();
        let blob = self.materialize(&text("blob")).await?;
        let config = self.materialize(&text("config")).await?;
        let vocab = self.materialize(&text("vocab")).await?;
        let threads = self.threads;
        let declared = manifest["tensors"].clone();
        let (blob_sha, config_sha, vocab_sha) = (text("blob"), text("config"), text("vocab"));
        let (model, tensors) = tokio::task::spawn_blocking(move || -> Result<_, PyError> {
            for (path, expected) in [(&blob, &blob_sha), (&config, &config_sha), (&vocab, &vocab_sha)] {
                if digest(&std::fs::read(path)?) != *expected {
                    return Err(PyError::value("Runtime asset bytes do not match admitted manifest."));
                }
            }
            let tensors = safetensors::parse(&std::fs::read(&blob)?)?;
            check_inventory(&tensors, &declared)?;
            let model = V3Model::from_files(&config, &blob, &vocab)?.with_threads(threads);
            Ok((model, tensors))
        })
        .await
        .map_err(|error| PyError::value(error.to_string()))??;
        Ok(Loaded { manifest, document, model, tensors: keep_tensors.then_some(tensors) })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn tensor(shape: &[usize], sha256: &str) -> Tensor {
        Tensor { shape: shape.to_vec(), data: Vec::new(), sha256: sha256.to_string() }
    }

    #[test]
    fn the_inventory_must_equal_the_manifests() {
        let sha = "a".repeat(64);
        let tensors = BTreeMap::from([("heads.sensitivity_bias".to_string(), tensor(&[4], &sha))]);
        let declared = serde_json::json!({"heads.sensitivity_bias": {"shape": [4], "dtype": "F32", "sha256": sha}});
        assert!(check_inventory(&tensors, &declared).is_ok());
        for changed in [
            serde_json::json!({"heads.sensitivity_bias": {"shape": [5], "dtype": "F32", "sha256": sha}}),
            serde_json::json!({"heads.sensitivity_bias": {"shape": [4], "dtype": "F16", "sha256": sha}}),
            serde_json::json!({"heads.sensitivity_bias": {"shape": [4], "dtype": "F32", "sha256": "b".repeat(64)}}),
            serde_json::json!({"heads.other": {"shape": [4], "dtype": "F32", "sha256": sha}}),
            serde_json::json!({}),
            serde_json::json!(7),
        ] {
            assert_eq!(check_inventory(&tensors, &changed).unwrap_err().to_string(), "ValueError: Checkpoint inventory/hash mismatch.");
        }
    }

    #[test]
    fn a_cached_asset_is_written_whole_and_rechecked() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("blob");
        write_new(&path, b"payload").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"payload");
        assert!(!directory.path().join("blob.partial").exists());
        assert!(verified(&path, &digest(b"payload")).is_ok());
        assert_eq!(verified(&path, &digest(b"other")).unwrap_err().to_string(), "ValueError: Runtime cached asset bytes corrupted.");
    }

    #[test]
    fn a_structural_manifest_needs_the_exact_key_set() {
        let sha = "c".repeat(64);
        let mut manifest = serde_json::json!({
            "schema": 1, "architecture": "privoke_pretrained_bert_v3", "model_id": "m", "tier": "t", "parent": "", "original": "",
            "blob": sha, "config": sha, "vocab": sha, "source": {}, "tensors": {}, "parameter_count": 1, "scope": "original", "evidence": ""
        });
        assert!(structural(&manifest).is_ok());
        manifest["extra"] = serde_json::json!(1);
        assert_eq!(structural(&manifest).unwrap_err().to_string(), "ValueError: Unsupported v3 manifest schema.");
    }
}
