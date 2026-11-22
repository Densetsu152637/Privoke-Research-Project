//! The window route of the worker on the real, locally held release, against the golden of the unchanged Python
//! `window_training.compute` (`evaluation/generate_window_golden.py`). Skipped unless `PRIVOKE_WINDOW_GOLDEN` is set (the
//! golden and the release hold study data and stay out of Git and CI). `PRIVOKE_WINDOW_RELEASE` names the release directory
//! (default `/data/models/task_query_window_20261012/releases/host-v2/v1/42`).
//!
//! The request is the frozen window itself (512 rows, 16 guard rows) on the ORIGINAL balanced teacher prepared as a window
//! artifact (its checksum is recomputed over the added policy metadata), sent with the schema 5 header. The Rust gradients
//! drive the loop, so the comparison is the tolerance category: the outcome, the executions, the metrics and the trace
//! fields that do not hash computed values must equal Python's, and the metadata must carry the keys Python writes.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use privoke_contracts::canonical::{self, Variant};
use privoke_contracts::digest::artifact_checksum_of_artifact;
use privoke_contracts::json::{Value as Node, parse};
use privoke_contracts::proto::v1::{
    ComputeSemanticGradientsRequest, ComputeSemanticGradientsResponse, RuntimeClassification, RuntimeTrainingExample,
};
use privoke_runtime::frames::{Method, Request};
use privoke_runtime::store::ArtifactStore;
use privoke_runtime::training::{ADMISSION_HEADER, Trainer, WindowConfig};
use privoke_training::admission::{WINDOW_CONFIG_CANONICAL, WINDOW_ELIGIBILITY};
use prost::Message;
use serde_json::Value;

const OBJECTIVE: &str = "class_balanced_contextual_sum_category_decision_margin_v1";
const POLICY: &str = "full_projected_adam64_window_checkpoint_v1";
const STRATEGY: &str = "contextual_full_encoder_sgd_v1";

fn read(path: &PathBuf) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

/// The ORIGINAL teacher as a window artifact: the policy metadata added and the checksum recomputed.
fn prepared_artifact(teacher: &[u8], window_pin: &str, component_pin: &str) -> String {
    let mut artifact = parse(std::str::from_utf8(teacher).unwrap()).unwrap();
    let Node::Object(map) = &mut artifact else { panic!("the teacher is an object") };
    let metadata = map.entry("metadata".to_string()).or_insert_with(|| Node::Object(BTreeMap::new()));
    let Node::Object(entries) = metadata else { panic!("the metadata is an object") };
    for (key, value) in [
        ("contextual_training_strategy", STRATEGY),
        ("contextual_training_objective", OBJECTIVE),
        ("contextual_training_optimizer", POLICY),
        ("contextual_candidate_eligibility", WINDOW_ELIGIBILITY),
        ("train_window_config_v1", WINDOW_CONFIG_CANONICAL),
        ("train_window_manifest_sha256", window_pin),
        ("original_train_component_manifest_sha256", component_pin),
    ] {
        entries.insert(key.to_string(), Node::String(value.to_string()));
    }
    let checksum = artifact_checksum_of_artifact(&artifact).unwrap();
    if let Node::Object(map) = &mut artifact {
        map.insert("checksum".to_string(), Node::String(checksum));
    }
    canonical::to_string(&artifact, Variant::Utf8Go).unwrap()
}

fn row_message(row: &Value) -> RuntimeTrainingExample {
    RuntimeTrainingExample {
        text: row["text"].as_str().unwrap().to_string(),
        has_target: true,
        target: Some(RuntimeClassification { packed: u32::try_from(row["packed"].as_u64().unwrap()).unwrap(), ..Default::default() }),
        weight: row["weight"].as_f64().unwrap(),
    }
}

#[test]
fn the_worker_serves_the_window_loop_on_the_real_release() {
    let Some(golden) = std::env::var_os("PRIVOKE_WINDOW_GOLDEN").map(PathBuf::from) else {
        eprintln!("window worker release test skipped: PRIVOKE_WINDOW_GOLDEN is not set");
        return;
    };
    let release = std::env::var_os("PRIVOKE_WINDOW_RELEASE")
        .map_or_else(|| PathBuf::from("/data/models/task_query_window_20261012/releases/host-v2/v1/42"), PathBuf::from);
    let meta: Value = serde_json::from_slice(&read(&golden.join("meta.json"))).unwrap();
    let python_trace: Value = serde_json::from_slice(&read(&golden.join("trace.json"))).unwrap();
    let pin = |key: &str| meta["pins"][key].as_str().unwrap().to_string();
    let (window_pin, manifest_pin, teacher_pin) = (pin("window"), pin("manifest"), pin("teacher"));

    let models = tempfile::tempdir().unwrap();
    std::fs::write(
        models.path().join("privoke-balanced.json"),
        prepared_artifact(&read(&release.join("original.json")), &window_pin, &manifest_pin),
    )
    .unwrap();
    let configuration = WindowConfig {
        window_path: release.join("window.json"),
        window_sha256: window_pin.clone(),
        bank_path: release.join("bank.json"),
        reference_path: release.join("references-v2.json"),
        manifest_path: release.join("component-manifest-v2.json"),
        teacher_path: release.join("original.json"),
        manifest_sha256: manifest_pin.clone(),
        teacher_sha256: teacher_pin,
    };
    let trainer =
        Trainer::new(Arc::new(ArtifactStore::new(vec![models.path().to_path_buf()], None)), 1_000_000).with_window(Some(configuration));

    let window: Value = serde_json::from_slice(&read(&release.join("window.json"))).unwrap();
    let train: Vec<RuntimeTrainingExample> =
        window["blocks"].as_array().unwrap().iter().flat_map(|block| block["rows"].as_array().unwrap().iter()).map(row_message).collect();
    let guard: Vec<RuntimeTrainingExample> = window["guard"].as_array().unwrap().iter().map(row_message).collect();
    let message = ComputeSemanticGradientsRequest {
        request_id: "window-1".into(),
        model_id: "privoke-balanced".into(),
        examples: train,
        heldout_examples: guard,
        learning_rate: 0.003,
        max_gradient: 0.05,
        layers: vec![4],
    };
    let header = serde_json::json!({
        "schema": 5, "expected_objective": OBJECTIVE, "expected_diagnostics_policy": null, "expected_optimizer": POLICY,
        "expected_candidate_eligibility": WINDOW_ELIGIBILITY, "expected_optimizer_config": WINDOW_CONFIG_CANONICAL,
        "expected_training_scope": "full_encoder", "expected_window_manifest_sha256": window_pin,
        "expected_component_manifest_sha256": manifest_pin
    })
    .to_string();
    let request = Request {
        method: Method::ComputeUnderlyingModelGradients,
        request_id: 1,
        deadline_ms: 600_000,
        metadata: vec![(ADMISSION_HEADER.to_string(), header)],
        payload: message.encode_to_vec(),
    };
    let payload = trainer.handle(&request).expect("the window route is served by the Rust worker");
    let response = ComputeSemanticGradientsResponse::decode(payload.as_slice()).unwrap();
    assert_eq!(response.error, "", "the window route answered an error");

    // The metadata Python writes (`window_training.compute`).
    let expected_keys = [
        "contextual_training_optimizer",
        "executed_contextual_training_optimizer",
        "contextual_training_objective",
        "executed_contextual_training_objective",
        "contextual_training_strategy",
        "strategy",
        "artifact_training_strategy",
        "training_scope",
        "underlying_training_available",
        "contextual_candidate_eligibility",
        "train_window_config_v1",
        "train_window_manifest_sha256",
        "original_train_component_manifest_sha256",
        "train_window_trace_v1",
        "train_window_summary_v1",
        "window_outcome",
        "base_parameter_fingerprint",
        "updated_parameter_fingerprint",
        "artifact_checksum",
        "architecture",
        "model_config",
        "trained_parameter_names",
        "trained_parameter_inventory_fingerprint",
        "learning_rate",
        "max_gradient",
    ];
    let mut keys: Vec<&str> = response.metadata.keys().map(String::as_str).collect();
    keys.sort_unstable();
    let mut wanted = expected_keys.to_vec();
    wanted.sort_unstable();
    assert_eq!(keys, wanted, "the response metadata keys");
    let rust_trace: Value = serde_json::from_str(&response.metadata["train_window_trace_v1"]).unwrap();
    let outcome = (&rust_trace["status"], &rust_trace["reason"], &rust_trace["selected_step"]);
    eprintln!(
        "window worker: {}/{} at step {} (Python {}/{} at step {}); {} gradient tensors; {} executions",
        outcome.0,
        outcome.1,
        outcome.2,
        python_trace["status"],
        python_trace["reason"],
        python_trace["selected_step"],
        response.gradients.len(),
        response.executions.len()
    );
    let (mut counts_equal, mut originals_equal) = (0usize, 0usize);
    for (rust, python) in rust_trace["checkpoints"].as_array().unwrap().iter().zip(python_trace["checkpoints"].as_array().unwrap()) {
        counts_equal += usize::from(rust["counts"] == python["counts"]);
        originals_equal += usize::from(rust["violations"] == python["violations"]);
    }
    eprintln!(
        "window worker checkpoints (9, tolerance category): counts equal {counts_equal}, ORIGINAL violations equal {originals_equal}"
    );
    assert_eq!(outcome, (&python_trace["status"], &python_trace["reason"], &python_trace["selected_step"]), "the outcome");
    assert_eq!(response.metadata["window_outcome"], python_trace["status"].as_str().unwrap());
    assert_eq!(response.gradients.is_empty(), python_trace["status"] == "no_update", "the transported update");
    for key in ["window_sha256", "references_sha256", "base", "weights", "main", "auxiliary", "work", "config", "policy"] {
        assert_eq!(rust_trace[key], python_trace[key], "trace field {key}");
    }
    assert_eq!(response.metadata["base_parameter_fingerprint"], python_trace["base"].as_str().unwrap());
    assert_eq!(response.metadata["updated_parameter_fingerprint"], python_trace["published"].as_str().unwrap());
    let executions: Vec<(String, u64)> = response.executions.iter().map(|e| (e.phase.clone(), u64::from(e.examples))).collect();
    let python_executions: Vec<(String, u64)> =
        meta["executions"].as_array().unwrap().iter().map(|e| (e[0].as_str().unwrap().to_string(), e[1].as_u64().unwrap())).collect();
    assert_eq!(executions, python_executions, "the executed phases");
    assert!(response.executions.iter().all(|e| e.layer == 4 && e.status == "ok"), "every phase is the semantic layer");
    for (key, expected) in meta["metrics"].as_object().unwrap() {
        let (got, want) = (response.metrics[key], expected.as_f64().unwrap());
        assert!((got - want).abs() <= 1e-5 * want.abs().max(1.0), "metric {key}: {got} against {want}");
    }
    assert_eq!(response.metrics.len(), 5);
    let summary: Value = serde_json::from_str(&response.metadata["train_window_summary_v1"]).unwrap();
    let python_summary: Value = serde_json::from_str(meta["summary"].as_str().unwrap()).unwrap();
    for key in [
        "schema",
        "policy",
        "window",
        "references",
        "base",
        "selected_step",
        "status",
        "reason",
        "main_rows",
        "auxiliary_rows",
        "checkpoint_rows",
        "violations",
        "guard_passed",
        "sensitive_progress",
    ] {
        assert_eq!(summary[key], python_summary[key], "summary field {key}");
    }
}
