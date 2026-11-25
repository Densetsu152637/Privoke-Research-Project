//! The Rust worker reads the model cache this service writes. Each tracked legacy model is fetched from the real
//! model-streaming service over mutual TLS into the cache (`<id>.snapshot.pb`), and the Rust worker's readers are run over
//! that cache and over the artifact files the models were served from: the identity, the metadata (the cache adds the two
//! keys model-streaming itself writes), the tensors, the JSON the training code reads and the semantic results must be
//! the same. No Python is needed.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::collections::BTreeMap;
use std::time::Duration;

use common::Env;
use privoke_analysis::models::{ModelCache, snapshot_path};
use privoke_runtime::semantic::SemanticLayer;
use privoke_runtime::store::ArtifactStore;

const MODELS: [&str; 4] = ["privoke-baseline", "privoke-balanced", "privoke-efficient", "privoke-quality"];

#[tokio::test]
async fn the_rust_worker_reads_what_the_service_cached_as_it_reads_the_artifact_file() {
    let env = Env::new();
    let server = env.start_model_streaming().await;
    let analysis = env.service("analysis", "runtime");
    let config = env.analysis_config(server.internal_addr, &analysis, std::path::Path::new("python"));
    let cache = ModelCache::new(env.cache.path(), config.models, Duration::from_millis(50), BTreeMap::new(), "privoke-balanced");
    for id in MODELS {
        assert_eq!(cache.ensure(id).await.unwrap(), id);
        assert!(snapshot_path(env.cache.path(), id).is_file());
    }

    let cached = ArtifactStore::new(vec![env.cache.path().to_path_buf()], Some("privoke-balanced".into()));
    let files = ArtifactStore::new(vec![env.models.path().to_path_buf()], Some("privoke-balanced".into()));
    for id in MODELS {
        let (from_cache, from_file) = (cached.read(id).unwrap(), files.read(id).unwrap());
        assert_eq!(
            (&from_cache.model_id, &from_cache.version, &from_cache.architecture, &from_cache.checksum, &from_cache.file_sha256),
            (&from_file.model_id, &from_file.version, &from_file.architecture, &from_file.checksum, &from_file.file_sha256),
            "{id}"
        );
        // Everything the file yields is in the response's metadata, unchanged; the response adds what model-streaming writes.
        for (key, value) in &from_file.metadata {
            assert_eq!(from_cache.metadata.get(key), Some(value), "{id}: {key}");
        }
        let extra: Vec<&str> =
            from_cache.metadata.keys().filter(|key| !from_file.metadata.contains_key(*key)).map(String::as_str).collect();
        assert_eq!(extra, ["consumer_id", "served_by"], "{id}");
        assert_eq!((&from_cache.parameters, &from_cache.shapes), (&from_file.parameters, &from_file.shapes), "{id}");
        assert_eq!(from_cache.value["config"], from_file.value["config"], "{id}");
        assert_eq!(from_cache.value["checksum"], from_file.value["checksum"], "{id}");
        for (name, tensor) in from_file.value["parameters"].as_object().unwrap() {
            let other = &from_cache.value["parameters"][name];
            assert_eq!(tensor["shape"], other["shape"], "{id} {name}");
            assert_eq!(tensor["trainable"].as_bool(), other["trainable"].as_bool(), "{id} {name}");
            let narrow =
                |value: &serde_json::Value| -> Vec<f32> { value.as_array().unwrap().iter().map(|n| n.as_f64().unwrap() as f32).collect() };
            assert_eq!(narrow(&tensor["values"]), narrow(&other["values"]), "{id} {name}");
        }
    }

    let by_cache = SemanticLayer::new(vec![env.cache.path().to_path_buf()], Some("privoke-balanced".into())).unwrap();
    let by_file = SemanticLayer::new(vec![env.models.path().to_path_buf()], Some("privoke-balanced".into())).unwrap();
    for id in MODELS.into_iter().chain(["latest"]) {
        for text in ["My doctor prescribed medication for my diagnosis.", "Please call me at 555-0100 tomorrow.", "Nothing to see here."] {
            let (left, right) = (by_cache.run(text, Some(id)), by_file.run(text, Some(id)));
            assert_eq!(left.error, None, "{id}");
            assert_eq!(left, right, "{id} on {text:?}");
        }
    }
    server.shutdown().await.unwrap();
}
