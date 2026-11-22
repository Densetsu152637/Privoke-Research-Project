//! The retention route of the worker on the real balanced release, against the golden of the unchanged Python route
//! (`evaluation/generate_retention_golden.py`). Skipped unless `PRIVOKE_RETENTION_GOLDEN` is set (the golden and the release
//! hold study data and stay out of Git and CI). `PRIVOKE_RETENTION_RELEASE` names the run directory
//! `evaluation/results/iterative_fuzzer_20261011` (default `/data/retention`).
//!
//! The request is the golden's 64 main and 16 guard rows on the ORIGINAL balanced teacher prepared as a retention artifact
//! (policy metadata added, checksum recomputed), sent with the schema 4 header, for each policy. The Rust gradients drive the
//! loop, so the comparison is the tolerance category: the metadata keys, the executed phases, the metric names, the audit of
//! the BASE (which does not depend on the fit) and the trace fields that hash no computed value must equal Python's.

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
use privoke_runtime::training::{ADMISSION_HEADER, RetentionConfig, Trainer};
use privoke_training::admission::CONFIG_CANONICAL;
use privoke_training::retention::{ELIGIBILITY, objective_of};
use prost::Message;
use serde_json::Value;

const STRATEGY: &str = "contextual_full_encoder_sgd_v1";

fn read(path: &PathBuf) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

fn prepared_artifact(teacher: &[u8], policy: &str, pin: &str) -> String {
    let mut artifact = parse(std::str::from_utf8(teacher).unwrap()).unwrap();
    let Node::Object(map) = &mut artifact else { panic!("the teacher is an object") };
    let metadata = map.entry("metadata".to_string()).or_insert_with(|| Node::Object(BTreeMap::new()));
    let Node::Object(entries) = metadata else { panic!("the metadata is an object") };
    for (key, value) in [
        ("contextual_training_strategy", STRATEGY),
        ("contextual_training_objective", objective_of(policy).unwrap()),
        ("contextual_training_optimizer", policy),
        ("contextual_candidate_eligibility", ELIGIBILITY),
        ("full_projected_adam_config_v1", CONFIG_CANONICAL),
        ("original_train_retention_manifest_sha256", pin),
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

fn relative(a: f64, b: f64) -> f64 {
    (a - b).abs() / b.abs().max(1.0)
}

#[test]
fn the_worker_serves_the_retention_loops_on_the_real_release() {
    let Some(golden) = std::env::var_os("PRIVOKE_RETENTION_GOLDEN").map(PathBuf::from) else {
        eprintln!("retention worker release test skipped: PRIVOKE_RETENTION_GOLDEN is not set");
        return;
    };
    let root = std::env::var_os("PRIVOKE_RETENTION_RELEASE").map_or_else(|| PathBuf::from("/data/retention"), PathBuf::from);
    let references = root.join("sensitive-retention-pilot/execution/references/balanced");
    let teacher = read(&root.join("block01/balanced/catalog/privoke-balanced.json"));
    let rows: Value = serde_json::from_slice(&read(&golden.join("rows.json"))).unwrap();
    let train: Vec<RuntimeTrainingExample> = rows["main"].as_array().unwrap().iter().map(row_message).collect();
    let guard: Vec<RuntimeTrainingExample> = rows["guard"].as_array().unwrap().iter().map(row_message).collect();
    for directory in ["gate", "hinge"] {
        let meta: Value = serde_json::from_slice(&read(&golden.join(directory).join("meta.json"))).unwrap();
        let python_trace: Value = serde_json::from_slice(&read(&golden.join(directory).join("trace.json"))).unwrap();
        let (policy, pin) = (meta["policy"].as_str().unwrap().to_string(), meta["pin"].as_str().unwrap().to_string());
        let models = tempfile::tempdir().unwrap();
        std::fs::write(models.path().join("privoke-balanced.json"), prepared_artifact(&teacher, &policy, &pin)).unwrap();
        let configuration = RetentionConfig {
            bank_path: root.join("train-sensitive-retention/approved-train-bank.json"),
            reference_path: references.join("references.json"),
            manifest_path: references.join("manifest.json"),
            teacher_path: root.join("block01/balanced/catalog/privoke-balanced.json"),
            manifest_sha256: pin.clone(),
        };
        let trainer = Trainer::new(Arc::new(ArtifactStore::new(vec![models.path().to_path_buf()], None)), 1_000_000)
            .with_retention(Some(configuration));
        let message = ComputeSemanticGradientsRequest {
            request_id: format!("retention-{directory}"),
            model_id: "privoke-balanced".into(),
            examples: train.clone(),
            heldout_examples: guard.clone(),
            learning_rate: 0.003,
            max_gradient: 0.05,
            layers: vec![4],
        };
        let header = serde_json::json!({
            "schema": 4, "expected_objective": objective_of(&policy).unwrap(), "expected_diagnostics_policy": null, "expected_optimizer": policy,
            "expected_candidate_eligibility": ELIGIBILITY, "expected_optimizer_config": CONFIG_CANONICAL,
            "expected_training_scope": "full_encoder", "expected_retention_manifest_sha256": pin
        })
        .to_string();
        let request = Request {
            method: Method::ComputeUnderlyingModelGradients,
            request_id: 1,
            deadline_ms: 600_000,
            metadata: vec![(ADMISSION_HEADER.to_string(), header)],
            payload: message.encode_to_vec(),
        };
        let payload = trainer.handle(&request).expect("the retention route is served by the Rust worker");
        let response = ComputeSemanticGradientsResponse::decode(payload.as_slice()).unwrap();
        assert_eq!(response.error, "", "{directory}: the retention route answered an error");

        let mut keys: Vec<&str> = response.metadata.keys().map(String::as_str).collect();
        keys.sort_unstable();
        let mut wanted: Vec<&str> = meta["metadata"].as_object().unwrap().keys().map(String::as_str).collect();
        wanted.push("original_train_retention_trace_v1");
        wanted.sort_unstable();
        assert_eq!(keys, wanted, "{directory}: the response metadata keys");
        let rust_trace: Value = serde_json::from_str(&response.metadata["original_train_retention_trace_v1"]).unwrap();
        for key in ["policy", "manifest_sha256", "base_safety"] {
            if key == "base_safety" {
                let (a, b) = (rust_trace[key].as_array().unwrap(), python_trace[key].as_array().unwrap());
                assert_eq!(a.len(), b.len());
                for (rust, python) in a.iter().zip(b) {
                    for field in [
                        "id",
                        "gold",
                        "original",
                        "candidate",
                        "gold_action",
                        "original_action",
                        "candidate_action",
                        "violation",
                        "original_confidence",
                        "candidate_confidence",
                    ] {
                        assert_eq!(rust[field], python[field], "{directory}: base audit {field}");
                    }
                    for field in ["original_margin", "candidate_margin", "hinge"] {
                        assert!(
                            relative(rust[field].as_f64().unwrap(), python[field].as_f64().unwrap()) <= 1e-5,
                            "{directory}: base audit {field}"
                        );
                    }
                }
            } else {
                assert_eq!(rust_trace[key], python_trace[key], "{directory}: trace {key}");
            }
        }
        for key in ["schema", "policy", "base", "config", "counts", "train"] {
            assert_eq!(rust_trace["adam"][key], python_trace["adam"][key], "{directory}: adam {key}");
        }
        assert_eq!(rust_trace["auxiliary"]["counts"], python_trace["auxiliary"]["counts"], "{directory}: auxiliary counts");
        assert_eq!(rust_trace["adam"]["steps"].as_array().unwrap().len(), 64);
        let executions: Vec<(String, u64)> = response.executions.iter().map(|e| (e.phase.clone(), u64::from(e.examples))).collect();
        let python_executions: Vec<(String, u64)> =
            meta["executions"].as_array().unwrap().iter().map(|e| (e[0].as_str().unwrap().to_string(), e[1].as_u64().unwrap())).collect();
        assert_eq!(executions, python_executions, "{directory}: the executed phases");
        assert!(response.executions.iter().all(|e| e.layer == 4 && e.status == "ok"), "every phase is the semantic layer");
        let python_metrics = meta["metrics"].as_object().unwrap();
        assert_eq!(response.metrics.len(), python_metrics.len(), "{directory}: metric names");
        for key in python_metrics.keys() {
            assert!(response.metrics.contains_key(key), "{directory}: metric {key} is missing");
        }
        for key in ["examples", "total_weight", "exact_match_rate", "base_train_objective_loss", "raw_total_weight", "heldout_examples"] {
            let (got, want) = (response.metrics[key], python_metrics[key].as_f64().unwrap());
            assert!(relative(got, want) <= 1e-5, "{directory}: metric {key}: {got} against {want}");
        }
        let (summary, python_summary): (Value, Value) = (
            serde_json::from_str(&response.metadata["original_train_retention_summary_v1"]).unwrap(),
            serde_json::from_str(meta["metadata"]["original_train_retention_summary_v1"].as_str().unwrap()).unwrap(),
        );
        assert_eq!(summary["eligible"], python_summary["eligible"]);
        eprintln!(
            "retention worker {directory}: served, 26 metadata keys, {} executions, {} gradient tensors; candidate exact {:.4} (Python {:.4}); violations {} (Python {})",
            response.executions.len(),
            response.gradients.len(),
            response.metrics["candidate_train_exact_match_rate"],
            python_metrics["candidate_train_exact_match_rate"].as_f64().unwrap(),
            summary["violations"],
            python_summary["violations"]
        );
    }
}
