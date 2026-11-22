//! The legacy model fetch against the Python fetch (D11).
//!
//! `model_fetch_golden.json` (`rust/services/runtime-supervisor/tests/fixtures`, written by
//! `evaluation/generate_model_fetch_golden.py`) records what the unchanged Python client holds after it streams the
//! four tracked legacy models from a fake client, and which synthetic snapshots it refuses.
//!
//! The Python legacy fetch writes no cache; it keeps the snapshot in memory. What can be compared is therefore the
//! content: the snapshot this service caches for each tracked model (as served by the real Rust model-streaming
//! service) must hold the same tensors, bit for bit in float32, as the Python client holds. And every snapshot the
//! Python client refuses, that can be written as one unary `ModelParametersResponse`, must be refused by `validate`.
//! The refusals that exist only in a chunk stream (order, offsets, a snapshot that changes mid-stream) have no unary
//! form; model-streaming's own tests cover its stream, and the golden records Python's refusal of them.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::collections::BTreeMap;
use std::time::Duration;

use common::Env;
use privoke_analysis::models::{ModelCache, snapshot_path, validate};
use privoke_contracts::proto::v1::{ModelParametersResponse, Parameter};
use prost::Message as _;
use serde_json::Value;
use sha2::{Digest, Sha256};

const GOLDEN: &str = include_str!("../../runtime-supervisor/tests/fixtures/model_fetch_golden.json");

fn f32_digest(values: &[f32]) -> String {
    let mut digest = Sha256::new();
    for value in values {
        digest.update(value.to_le_bytes());
    }
    digest.finalize().iter().map(|byte| format!("{byte:02x}")).collect()
}

fn number(value: &Value) -> f32 {
    match value {
        Value::String(text) => match text.as_str() {
            "nan" => f32::NAN,
            "inf" => f32::INFINITY,
            "-inf" => f32::NEG_INFINITY,
            other => panic!("unknown number {other}"),
        },
        other => other.as_f64().unwrap() as f32,
    }
}

fn response_of(spec: &Value) -> ModelParametersResponse {
    ModelParametersResponse {
        model_id: spec["model_id"].as_str().unwrap().into(),
        version: spec["version"].as_str().unwrap().into(),
        generated_at_unix: spec["generated_at_unix"].as_i64().unwrap(),
        parameters: spec["tensors"]
            .as_array()
            .unwrap()
            .iter()
            .map(|tensor| Parameter {
                name: tensor["name"].as_str().unwrap().into(),
                values: tensor["values"].as_array().unwrap().iter().map(number).collect(),
                shape: tensor["shape"].as_array().unwrap().iter().map(|size| size.as_u64().unwrap() as u32).collect(),
            })
            .collect(),
        metadata: spec["metadata"].as_object().unwrap().iter().map(|(key, value)| (key.clone(), value.as_str().unwrap().into())).collect(),
    }
}

#[tokio::test]
async fn the_snapshot_cached_for_each_tracked_model_holds_the_tensors_the_python_client_holds() {
    let golden: Value = serde_json::from_str(GOLDEN).unwrap();
    assert!(golden["legacy"]["python_disk_cache"].as_str().unwrap().starts_with("none"));
    let env = Env::new();
    let server = env.start_model_streaming().await;
    let analysis = env.service("analysis", "runtime");
    let config = env.analysis_config(server.internal_addr, &analysis, std::path::Path::new("python"));
    let cache = ModelCache::new(env.cache.path(), config.models, Duration::from_millis(50), BTreeMap::new(), "privoke-balanced");

    let tracked = golden["legacy"]["tracked"].as_array().unwrap();
    assert_eq!(tracked.len(), 4);
    for model in tracked {
        let id = model["model_id"].as_str().unwrap();
        assert_eq!(cache.ensure(id).await.unwrap(), id);
        let snapshot = ModelParametersResponse::decode(std::fs::read(snapshot_path(env.cache.path(), id)).unwrap().as_slice()).unwrap();
        assert_eq!(snapshot.version, model["version"].as_str().unwrap(), "{id}: version");
        assert_eq!(snapshot.generated_at_unix, model["generated_at_unix"].as_i64().unwrap(), "{id}: timestamp");
        assert_eq!(snapshot.metadata["artifact_checksum"], model["artifact_checksum"].as_str().unwrap(), "{id}: artifact checksum");
        let expected = model["tensors"].as_array().unwrap();
        assert_eq!(snapshot.parameters.len(), expected.len(), "{id}: tensor count");
        let mut total = 0usize;
        for (held, wanted) in snapshot.parameters.iter().zip(expected) {
            assert_eq!(held.name, wanted["name"].as_str().unwrap(), "{id}: tensor order");
            let shape: Vec<u64> = held.shape.iter().map(|size| u64::from(*size)).collect();
            let wanted_shape: Vec<u64> = wanted["shape"].as_array().unwrap().iter().map(|size| size.as_u64().unwrap()).collect();
            assert_eq!(shape, wanted_shape, "{id}/{}: shape", held.name);
            assert_eq!(held.values.len() as u64, wanted["count"].as_u64().unwrap(), "{id}/{}: value count", held.name);
            assert_eq!(f32_digest(&held.values), wanted["f32_sha256"].as_str().unwrap(), "{id}/{}: float32 values", held.name);
            total += held.values.len();
        }
        assert_eq!(total as u64, model["parameter_count"].as_u64().unwrap(), "{id}: parameter count");
    }
    server.shutdown().await.unwrap();
    eprintln!("model fetch golden (legacy): 4 of 4 tracked models hold the Python client's float32 tensors");
}

#[test]
fn a_snapshot_the_python_client_refuses_is_refused_here_too() {
    let golden: Value = serde_json::from_str(GOLDEN).unwrap();
    let (mut compared, mut stream_only) = (0, 0);
    for case in golden["legacy"]["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let python_accepted = case["accepted"].as_bool().unwrap();
        match case["kind"].as_str().unwrap() {
            "unary" => {
                let spec = &case["spec"];
                let id = spec["model_id"].as_str().unwrap();
                let verdict = validate(&response_of(spec), id, None);
                assert_eq!(verdict.is_ok(), python_accepted, "{name}: Python accepted={python_accepted}, Rust {verdict:?}");
                compared += 1;
            }
            "stream_only" => {
                assert!(!python_accepted, "{name}: a stream property the Python client refuses");
                stream_only += 1;
            }
            other => panic!("unknown case kind {other}"),
        }
    }
    assert!(compared >= 10 && stream_only >= 5);
    eprintln!("model fetch golden (legacy): {compared} snapshot decisions agree with Python; {stream_only} stream-only refusals recorded");
}
