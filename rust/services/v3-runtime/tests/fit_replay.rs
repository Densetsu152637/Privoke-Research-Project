//! Parity of `FitCandidate` with the Python `RuntimeServer` on the committed synthetic golden
//! (`evaluation/generate_v3_runtime_golden.py fit-synthetic`): the real frozen BC01 schedule over the committed pinned inputs, the
//! pilot policy (two AdamW steps over one block of 64 rows, a guard of 16), the synthetic V3 package, once per scope, and the
//! requests the server refuses. Every fit request is semantic-only. The comparison follows stage 19 (see `common/fit_support.rs`).
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use common::fit_support::{checkout, replay_golden};
use common::{Scripted, b64, serve_package};
use privoke_contracts::proto::experimental_v3 as v3;
use privoke_v3_fuzzer::source::Closure;
use privoke_v3_runtime::assets::Admission;
use privoke_v3_runtime::fit::ScheduleSources;
use privoke_v3_runtime::service::{Runtime, RuntimeParts};
use prost::Message;
use serde_json::Value;

fn package() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../crates/privoke-semantic/tests/fixtures/v3_synthetic")
}

fn golden() -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/v3_runtime_fit_golden.json");
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

#[tokio::test]
async fn the_synthetic_golden_replays_identically() {
    let root = tempfile::tempdir().unwrap();
    checkout(root.path());
    let counts = replay_golden(&golden(), &package(), "privoke-v3-efficient", Admission::Structural, root.path(), 4, &["full-2"]).await;
    assert_eq!(counts.fits, 2);
}

#[tokio::test]
async fn a_caller_that_gives_up_stops_the_fit_and_the_identity_is_recorded_failed() {
    let golden = golden();
    let manifest = b64(golden["base_manifest"].as_str().unwrap());
    let scripted = Scripted::ready();
    serve_package(&scripted, &package(), "privoke-v3-efficient", &manifest);
    let root = tempfile::tempdir().unwrap();
    checkout(root.path());
    let state = tempfile::tempdir().unwrap();
    let parts = RuntimeParts {
        directory: state.path().join("state"),
        threads: 2,
        closure: Closure::Fixed("replay".to_string()),
        admission: Admission::Structural,
        schedules: ScheduleSources { root: root.path().to_path_buf(), audience: None },
    };
    let runtime = Arc::new(Runtime::new(parts, scripted.clone()).await.unwrap());
    let case = &golden["cases"][0];
    let request = v3::FitRequest::decode(b64(case["request"].as_str().unwrap()).as_slice()).unwrap();
    let id = request.request_id.clone();
    let status = runtime.fit_candidate(request, Arc::new(AtomicBool::new(false))).await.unwrap_err();
    assert_eq!(status.message(), "ValueError: Fit cancelled; no publication attempted.");
    let receipt = runtime.fit_status(&id).unwrap();
    assert_eq!(receipt.status, "failed");
    assert_eq!(receipt.reason, "ValueError: Fit cancelled; no publication attempted.");
    assert!(scripted.staged.lock().unwrap().is_empty(), "nothing is staged for a cancelled fit");
}
