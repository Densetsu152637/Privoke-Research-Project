//! A model cached as `<id>.snapshot.pb` (the analysis service's layout) is the same model to the Rust worker as the
//! artifact file it came from: the same identity, metadata, tensors, JSON for the training code, presence model and
//! semantic results. The snapshot is built the way model-streaming builds its response (`response_metadata`: the
//! artifact's metadata plus architecture, `model_config`, the two checksums and the trainable names; float32 tensors).
//! The analysis crate repeats the comparison with a snapshot that the real model-streaming service sent.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};

use privoke_contracts::proto::v1::{ModelParametersResponse, Parameter};
use privoke_runtime::presence::PresenceModels;
use privoke_runtime::semantic::SemanticLayer;
use privoke_runtime::snapshot;
use privoke_runtime::store::{Artifact, ArtifactStore};
use prost::Message as _;
use serde_json::Value;

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/worker_models")
}

fn snapshot_of(artifact: &Artifact) -> Vec<u8> {
    ModelParametersResponse {
        model_id: artifact.model_id.clone(),
        version: artifact.version.clone(),
        generated_at_unix: artifact.value["generated_at_unix"].as_i64().unwrap_or(0),
        parameters: artifact
            .parameters
            .iter()
            .map(|(name, values)| Parameter {
                name: name.clone(),
                values: values.iter().map(|value| *value as f32).collect(),
                shape: artifact.shapes[name].iter().map(|size| *size as u32).collect(),
            })
            .collect(),
        metadata: artifact.metadata.clone().into_iter().collect(),
    }
    .encode_to_vec()
}

/// Two roots with the same models: one with the files, one with their snapshots.
fn roots(directory: &Path) -> (tempfile::TempDir, tempfile::TempDir, Vec<String>) {
    let files = tempfile::tempdir().unwrap();
    let snapshots = tempfile::tempdir().unwrap();
    let mut ids = Vec::new();
    for entry in std::fs::read_dir(directory).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_none_or(|extension| extension != "json") {
            continue;
        }
        let id = path.file_stem().unwrap().to_string_lossy().into_owned();
        let bytes = std::fs::read(&path).unwrap();
        let Ok(artifact) = Artifact::parse(&id, &bytes) else { continue };
        std::fs::write(files.path().join(format!("{id}.json")), &bytes).unwrap();
        std::fs::write(snapshot::path(snapshots.path(), &id), snapshot_of(&artifact)).unwrap();
        ids.push(id);
    }
    ids.sort();
    (files, snapshots, ids)
}

fn narrowed(value: &Value) -> Vec<f32> {
    value.as_array().unwrap().iter().map(|number| number.as_f64().unwrap() as f32).collect()
}

#[test]
fn a_snapshot_reads_as_the_artifact_file_it_came_from() {
    let (files, snapshots, ids) = roots(&fixtures());
    assert!(ids.len() >= 8, "{ids:?}");
    let from_files = ArtifactStore::new(vec![files.path().to_path_buf()], None);
    let from_snapshots = ArtifactStore::new(vec![snapshots.path().to_path_buf()], None);
    for id in &ids {
        let (file, cached) = (from_files.read(id).unwrap(), from_snapshots.read(id).unwrap());
        assert_eq!(
            (&file.model_id, &file.version, &file.architecture, &file.checksum, &file.file_sha256),
            (&cached.model_id, &cached.version, &cached.architecture, &cached.checksum, &cached.file_sha256),
            "{id}"
        );
        assert_eq!(file.metadata, cached.metadata, "{id}: the metadata is the response's, which is what the file yields");
        assert_eq!((&file.parameters, &file.shapes), (&cached.parameters, &cached.shapes), "{id}");
        // The JSON the training and presence code read.
        assert_eq!(file.value["config"], cached.value["config"], "{id}");
        assert_eq!(file.value["checksum"], cached.value["checksum"], "{id}");
        let (file_tensors, cached_tensors) =
            (file.value["parameters"].as_object().unwrap(), cached.value["parameters"].as_object().unwrap());
        assert_eq!(file_tensors.keys().collect::<Vec<_>>(), cached_tensors.keys().collect::<Vec<_>>(), "{id}");
        for (name, tensor) in file_tensors {
            let other = &cached_tensors[name];
            assert_eq!(tensor["shape"], other["shape"], "{id} {name}");
            assert_eq!(narrowed(&tensor["values"]), narrowed(&other["values"]), "{id} {name}: float32 values");
            assert_eq!(tensor["trainable"], other["trainable"], "{id} {name}");
        }
    }
}

#[test]
fn the_semantic_layer_and_the_presence_models_cannot_tell_the_two_apart() {
    let (files, snapshots, ids) = roots(&fixtures());
    let semantic = |root: &Path| SemanticLayer::new(vec![root.to_path_buf()], None).unwrap();
    let (by_file, by_snapshot) = (semantic(files.path()), semantic(snapshots.path()));
    let presence = |root: &Path| PresenceModels::new(std::sync::Arc::new(ArtifactStore::new(vec![root.to_path_buf()], None)));
    let (presence_files, presence_snapshots) = (presence(files.path()), presence(snapshots.path()));
    let (mut tiny, mut gates) = (0, 0);
    for id in &ids {
        for text in ["My doctor prescribed medication for my diagnosis.", "Meet at noon on Friday.", ""] {
            let (left, right) = (by_file.run(text, Some(id.as_str())), by_snapshot.run(text, Some(id.as_str())));
            assert_eq!(left, right, "{id} on {text:?}");
        }
        if let (Ok(left), Ok(right)) = (by_file.fetch(id), by_snapshot.fetch(id)) {
            assert_eq!(format!("{left:?}"), format!("{right:?}"), "{id}");
            tiny += 1;
        }
        if let (Ok(left), Ok(right)) = (presence_files.fetch(id), presence_snapshots.fetch(id)) {
            assert_eq!(
                (&left.model_id, &left.version, &left.artifact_checksum, &left.parameter_fingerprint, left.threshold),
                (&right.model_id, &right.version, &right.artifact_checksum, &right.parameter_fingerprint, right.threshold),
                "{id}"
            );
            let text = "My doctor prescribed medication for my diagnosis.";
            assert_eq!(left.model.predict_probability(text).to_bits(), right.model.predict_probability(text).to_bits(), "{id}");
            gates += 1;
        }
    }
    assert!(tiny >= 1 && gates >= 1, "tiny {tiny}, presence {gates}");
}

#[test]
fn a_snapshot_is_read_before_a_file_and_a_damaged_one_is_an_error() {
    let (files, snapshots, ids) = roots(&fixtures());
    let id = ids.iter().find(|id| id.starts_with("synthetic-legacy")).unwrap();
    // Both layouts in one root: the snapshot is read, as the Python worker's shim reads it.
    let mixed = tempfile::tempdir().unwrap();
    std::fs::copy(files.path().join(format!("{id}.json")), mixed.path().join(format!("{id}.json"))).unwrap();
    let cached = snapshot::path(snapshots.path(), id);
    std::fs::copy(&cached, snapshot::path(mixed.path(), id)).unwrap();
    let store = ArtifactStore::new(vec![mixed.path().to_path_buf()], None);
    assert!(store.read_source(id).unwrap().2, "the snapshot, not the file");

    std::fs::write(snapshot::path(mixed.path(), id), b"\xff\xff not a message").unwrap();
    assert!(store.read(id).is_err());
    assert!(SemanticLayer::new(vec![mixed.path().to_path_buf()], None).unwrap().fetch(id).is_err());
}
