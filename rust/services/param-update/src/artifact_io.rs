//! Reading and atomically publishing the model artifact (`privoke_model.artifact.load_artifact` and
//! `write_artifact_atomic`).
//!
//! The artifact is read twice over: as the typed, validated [`ModelArtifact`] of the stage 3 loader (every
//! per-architecture validator and the checksum), and as a JSON [`Value`] tree that the update edits and writes back in
//! the Python layout (`json.dump(indent=2, sort_keys=True)` and a final newline). Nothing is published that the
//! stage 3 loader would not accept.

use std::collections::BTreeMap;
use std::path::Path;

use privoke_contracts::digest::artifact_checksum_of_artifact;
use privoke_contracts::json::{self, Value};
use privoke_model_streaming::artifact::{ModelArtifact, load_model_artifact_bytes, read_bounded};

use crate::error::Failure;
use crate::pyfmt::{Layout, dumps};

/// A validated artifact in both forms.
#[derive(Debug, Clone)]
pub struct Loaded {
    /// The typed, validated artifact.
    pub typed: ModelArtifact,
    /// The same document as a JSON tree (duplicate keys resolved last-wins, as `json.loads`).
    pub root: Value,
}

/// `load_artifact`: a regular, non-symlink file of at most 8 MiB that passes validation.
pub fn load(path: &Path) -> Result<Loaded, Failure> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| Failure::invalid(format!("Could not load model artifact: {error}")))?;
    if metadata.file_type().is_symlink() {
        return Err(Failure::invalid("Model artifact must not be a symbolic link."));
    }
    let file = std::fs::File::open(path).map_err(|error| Failure::invalid(format!("Could not load model artifact: {error}")))?;
    let raw = read_bounded(file).map_err(|error| Failure::invalid(format!("Could not load model artifact: {error}")))?;
    decode(&raw)
}

/// Validate `raw` and decode it into both forms.
pub fn decode(raw: &[u8]) -> Result<Loaded, Failure> {
    let loaded = load_model_artifact_bytes(raw, "").map_err(|error| Failure::invalid(format!("Could not load model artifact: {error}")))?;
    let text = std::str::from_utf8(raw).map_err(|error| Failure::invalid(format!("Could not load model artifact: {error}")))?;
    let root = json::parse(text).map_err(|error| Failure::invalid(format!("Could not load model artifact: {error}")))?;
    Ok(Loaded { typed: loaded.artifact, root })
}

/// The artifact text as Python writes it: `json.dump(payload, handle, indent=2, sort_keys=True)` and one newline.
pub fn render(root: &Value) -> Result<String, Failure> {
    let mut text = dumps(root, Layout::Indented).map_err(|error| Failure::invalid(format!("Model artifact cannot be written: {error}")))?;
    text.push('\n');
    Ok(text)
}

/// The `metadata` object of an artifact document, created (or replaced, if it was not an object) on demand.
pub fn metadata_mut(root: &mut BTreeMap<String, Value>) -> &mut BTreeMap<String, Value> {
    let entry = root.entry("metadata".to_string()).or_insert_with(|| Value::Object(BTreeMap::new()));
    if !matches!(entry, Value::Object(_)) {
        *entry = Value::Object(BTreeMap::new());
    }
    match entry {
        Value::Object(map) => map,
        // The entry was just made an object.
        _ => unreachable!("metadata was normalised to an object"),
    }
}

/// Set `root["checksum"]` to the checksum of everything else.
pub fn seal(root: &mut Value) -> Result<(), Failure> {
    let checksum = artifact_checksum_of_artifact(root).map_err(|error| Failure::invalid(error.to_string()))?;
    if let Value::Object(map) = root {
        map.insert("checksum".to_string(), Value::String(checksum));
    }
    Ok(())
}

#[cfg(unix)]
fn set_mode(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644))
}

#[cfg(not(unix))]
fn set_mode(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn sync_directory(directory: &Path) -> std::io::Result<()> {
    std::fs::File::open(directory)?.sync_all()
}

#[cfg(not(unix))]
fn sync_directory(_directory: &Path) -> std::io::Result<()> {
    Ok(())
}

/// `write_artifact_atomic`: validate the final bytes, write them to a temporary file in the same directory, fsync it,
/// rename it over the artifact and fsync the directory. A reader sees the old file or the new one, never a mixture.
pub fn write_atomic(path: &Path, root: &Value) -> Result<(), Failure> {
    let text = render(root)?;
    // The loader is the validator: refuse to publish anything it would refuse to serve.
    decode(text.as_bytes())?;
    if std::fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
        return Err(Failure::invalid("Model artifact must not be a symbolic link."));
    }
    let directory = path.parent().filter(|parent| !parent.as_os_str().is_empty()).unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(directory)?;
    let name = path.file_name().map(|name| name.to_string_lossy().into_owned()).unwrap_or_default();
    let temporary = directory.join(format!(".{name}.{}.tmp", uuid::Uuid::new_v4().simple()));
    let outcome = publish(&temporary, path, directory, text.as_bytes());
    if temporary.exists() {
        let _ = std::fs::remove_file(&temporary);
    }
    outcome.map_err(Failure::persistence)
}

fn publish(temporary: &Path, target: &Path, directory: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    {
        let mut file = std::fs::OpenOptions::new().write(true).create_new(true).open(temporary)?;
        file.write_all(bytes)?;
        file.flush()?;
        file.sync_all()?;
    }
    set_mode(temporary)?;
    std::fs::rename(temporary, target)?;
    sync_directory(directory)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn a_missing_or_unreadable_artifact_is_a_load_failure() {
        let directory = tempfile::tempdir().unwrap();
        let error = load(&directory.path().join("absent.json")).unwrap_err();
        assert!(error.message().starts_with("Could not load model artifact"));
    }

    #[test]
    fn nothing_invalid_is_published() {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("model.json");
        let root = json::parse(r#"{"schema_version":1}"#).unwrap();
        assert!(write_atomic(&target, &root).is_err());
        assert!(!target.exists());
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0, "no temporary file is left behind");
    }
}
