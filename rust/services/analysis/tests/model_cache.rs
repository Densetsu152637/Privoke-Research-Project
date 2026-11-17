//! The model cache against the real model-streaming service over mutual TLS. No Python is needed.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::collections::BTreeMap;
use std::time::Duration;

use common::Env;
use privoke_analysis::models::{ModelCache, SyncError, snapshot_path};
use privoke_contracts::proto::v1::ModelParametersResponse;
use prost::Message as _;

async fn cache(env: &Env, server: &privoke_model_streaming::server::ServerHandle, pins: BTreeMap<String, String>) -> ModelCache {
    let analysis = env.service("analysis", "runtime");
    let config = env.analysis_config(server.internal_addr, &analysis, std::path::Path::new("python"));
    ModelCache::new(env.cache.path(), config.models, Duration::from_millis(50), pins, "privoke-balanced")
}

#[tokio::test]
async fn a_model_is_fetched_over_mutual_tls_checked_and_cached() {
    let env = Env::new();
    let server = env.start_model_streaming().await;
    let cache = cache(&env, &server, BTreeMap::new()).await;

    assert_eq!(cache.ensure("").await.unwrap(), "privoke-balanced", "the empty id is the default model");
    assert_eq!(cache.ensure("latest").await.unwrap(), "privoke-balanced");
    let cached =
        ModelParametersResponse::decode(std::fs::read(snapshot_path(env.cache.path(), "privoke-balanced")).unwrap().as_slice()).unwrap();
    assert_eq!(cached.model_id, "privoke-balanced");
    assert!(!cached.parameters.is_empty());
    assert_eq!(cached.metadata.get("served_by").map(String::as_str), Some("model-streaming-service"));

    assert!(matches!(cache.ensure("privoke-not-a-model").await, Err(SyncError::NotFound(_))));
    assert!(matches!(cache.ensure("../escape").await, Err(SyncError::Refused { .. })));
    assert!(!snapshot_path(env.cache.path(), "privoke-not-a-model").exists());
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn the_cache_follows_an_update_and_keeps_serving_when_model_streaming_is_gone() {
    let env = Env::new();
    let server = env.start_model_streaming().await;
    let cache = cache(&env, &server, BTreeMap::new()).await;
    cache.ensure("privoke-quality").await.unwrap();
    let path = snapshot_path(env.cache.path(), "privoke-quality");
    let first = std::fs::read(&path).unwrap();

    // Publish a new version of the artifact, as param-update would, and the cache picks it up after its ttl.
    let artifact_path = env.models.path().join("privoke-quality.json");
    let mut loaded = privoke_model_streaming::artifact::load_model_artifact(&artifact_path, "privoke-quality").unwrap().artifact;
    loaded.version = format!("{}-next", loaded.version);
    std::fs::write(&artifact_path, privoke_model_streaming::artifact::to_checked_bytes(&loaded).unwrap()).unwrap();
    tokio::time::sleep(Duration::from_millis(80)).await;
    cache.ensure("privoke-quality").await.unwrap();
    let second = std::fs::read(&path).unwrap();
    assert_ne!(first, second);
    assert!(ModelParametersResponse::decode(second.as_slice()).unwrap().version.ends_with("-next"));

    server.shutdown().await.unwrap();
    tokio::time::sleep(Duration::from_millis(80)).await;
    assert_eq!(cache.ensure("privoke-quality").await.unwrap(), "privoke-quality", "the cached snapshot stays in use");
    assert!(matches!(cache.ensure("privoke-efficient").await, Err(SyncError::Unavailable { .. })), "nothing cached, nothing served");
}

#[tokio::test]
async fn a_wrong_pin_refuses_the_model_and_caches_nothing() {
    let env = Env::new();
    let server = env.start_model_streaming().await;
    let pins = BTreeMap::from([("privoke-quality".to_string(), "0".repeat(64))]);
    let cache = cache(&env, &server, pins).await;
    assert!(matches!(cache.ensure("privoke-quality").await, Err(SyncError::Refused { .. })));
    assert!(!snapshot_path(env.cache.path(), "privoke-quality").exists());
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn an_unregistered_service_cannot_fetch_models() {
    let env = Env::new();
    let server = env.start_model_streaming().await;
    // Registered nowhere: a certificate from the right CA, but no registry entry.
    let analysis = env.service("analysis", "runtime");
    let mut config = env.analysis_config(server.internal_addr, &analysis, std::path::Path::new("python"));
    let issued_dir = env.path("svc-analysis");
    std::fs::write(env.registry(), "version = 1\n").unwrap();
    config.models.client_cert = issued_dir.join("service.crt");
    config.models.client_key = issued_dir.join("service.key");
    let cache = ModelCache::new(env.cache.path(), config.models, Duration::from_millis(50), BTreeMap::new(), "privoke-balanced");
    tokio::time::sleep(Duration::from_millis(400)).await; // the registry reloads on change
    assert!(matches!(cache.ensure("privoke-balanced").await, Err(SyncError::Unavailable { .. })));
    server.shutdown().await.unwrap();
}
