//! Parity of `AnalyzePrompt` with the Python `RuntimeServer` on the committed synthetic golden
//! (`evaluation/generate_v3_runtime_golden.py analyze-synthetic`): the 195 synthetic prompts over the synthetic V3 package of the
//! semantic crate, and the request shapes around them (empty text, over-length, visibility hints, wrong model, malformed pin,
//! requests the server aborts). Every request is semantic-only. The model is the stage 14 reference backend, so a confidence may
//! differ from Torch's by one rounding step at a boundary (counted and printed); every other field is identical.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::path::{Path, PathBuf};

use common::{Scripted, b64, replay, runtime_over, serve_package};
use privoke_contracts::proto::v1::AnalyzePromptRequest;
use privoke_semantic::V3Model;
use privoke_v3_runtime::assets::Admission;
use prost::Message;

fn package() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../crates/privoke-semantic/tests/fixtures/v3_synthetic")
}

fn golden() -> serde_json::Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/v3_runtime_analyze_golden.json");
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

#[tokio::test]
async fn the_synthetic_golden_replays_identically() {
    let golden = golden();
    let manifest = b64(golden["manifest"].as_str().unwrap());
    let scripted = Scripted::ready();
    let sha = serve_package(&scripted, &package(), "privoke-v3-efficient", &manifest);
    assert_eq!(sha, golden["meta"]["manifest_sha256"].as_str().unwrap(), "the manifest bytes are the oracle's");
    let state = tempfile::tempdir().unwrap();
    let runtime = runtime_over(&scripted, state.path(), Admission::Structural).await;
    let package = package();
    let model = V3Model::from_files(&package.join("config.json"), &package.join("model.safetensors"), &package.join("vocab.txt")).unwrap();
    let raw = |text: &str| model.predict(text).map(|prediction| prediction.confidence_raw).unwrap_or(0.0);
    let rows = golden["rows"].as_array().unwrap();
    assert!(rows.len() >= 200);
    let report = replay(&runtime, rows, &raw).await;
    report.assert_clean("AnalyzePrompt, synthetic V3 package");
    assert!(report.finding_rows > 20 && report.error_rows >= 5 && report.aborts == 5, "the golden covers findings, errors and aborts");
}

#[tokio::test]
async fn the_snapshot_is_cached_and_replaced_by_another_request() {
    let golden = golden();
    let manifest = b64(golden["manifest"].as_str().unwrap());
    let scripted = Scripted::ready();
    let sha = serve_package(&scripted, &package(), "privoke-v3-efficient", &manifest);
    let state = tempfile::tempdir().unwrap();
    let runtime = runtime_over(&scripted, state.path(), Admission::Structural).await;
    let rows = golden["rows"].as_array().unwrap();
    let request = |label: &str| {
        let row = rows.iter().find(|row| row["id"] == label).unwrap();
        AnalyzePromptRequest::decode(b64(row["request"].as_str().unwrap()).as_slice()).unwrap()
    };
    runtime.analyze_prompt(request("s000")).await.unwrap();
    runtime.analyze_prompt(request("s001")).await.unwrap();
    let calls = scripted.calls.lock().unwrap().clone();
    let manifest_fetches = calls.iter().filter(|call| **call == format!("fetch:{sha}")).count();
    assert_eq!(manifest_fetches, 1, "the second request reuses the cached snapshot: {calls:?}");
    assert_eq!(calls.iter().filter(|call| call.starts_with("resolve:")).count(), 2, "the current snapshot is resolved per request");
    // The assets are cached on disk by digest and re-verified.
    let assets: Vec<_> = std::fs::read_dir(state.path().join("assets")).unwrap().collect();
    assert_eq!(assets.len(), 3, "the three assets of the manifest are cached (the manifest itself is fetched, not cached)");
}

#[tokio::test]
async fn an_unreachable_snapshot_is_a_block_response_naming_the_rpc_error_and_never_a_status() {
    let scripted = Scripted::ready();
    let state = tempfile::tempdir().unwrap();
    let runtime = runtime_over(&scripted, state.path(), Admission::Structural).await;
    let request = AnalyzePromptRequest {
        text: "hello".to_string(),
        semantic_model_id: "privoke-v3-efficient".to_string(),
        layers: vec![4],
        request_id: "r".to_string(),
        ..Default::default()
    };
    let response = runtime.analyze_prompt(request).await.unwrap();
    assert_eq!(response.action, "BLOCK");
    assert!(!response.allowed);
    assert!(response.error.starts_with("_InactiveRpcError: "), "{}", response.error);
    assert_eq!(response.layers[0].status, "error");
    assert_eq!(response.classification.unwrap().visibility, "PU");
}
