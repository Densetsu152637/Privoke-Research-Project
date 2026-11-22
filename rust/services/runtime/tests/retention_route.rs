//! The schema 4 (ORIGINAL retention) route of the Rust worker, on the synthetic retention artifact: the route is reached for a
//! retention header, answers Python's texts for the request checks that precede the sidecars, reads the configured sidecars (a
//! synthetic release cannot pass the contract: the bank and the teacher are pinned to the real study data), and is declined to
//! Python when the worker has no retention configuration. The loops themselves run against the real release in
//! `retention_worker_release.rs`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;
use std::sync::Arc;

use privoke_contracts::proto::v1::{
    ComputeSemanticGradientsRequest, ComputeSemanticGradientsResponse, RuntimeClassification, RuntimeTrainingExample,
};
use privoke_runtime::frames::{FrameError, Method, Request, code};
use privoke_runtime::store::ArtifactStore;
use privoke_runtime::training::{ADMISSION_HEADER, RetentionConfig, Trainer};
use privoke_training::admission::CONFIG_CANONICAL;
use privoke_training::retention::{ELIGIBILITY, GATE_OBJECTIVE, GATE_POLICY};
use prost::Message;

const PIN: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

fn trainer(retention: Option<RetentionConfig>) -> Trainer {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/worker_models");
    Trainer::new(Arc::new(ArtifactStore::new(vec![root], None)), 10_000).with_retention(retention)
}

fn config(pin: &str) -> RetentionConfig {
    let missing = |name: &str| PathBuf::from(format!("/nonexistent/{name}"));
    RetentionConfig {
        bank_path: missing("bank.json"),
        reference_path: missing("references.json"),
        manifest_path: missing("manifest.json"),
        teacher_path: missing("teacher.json"),
        manifest_sha256: pin.to_string(),
    }
}

fn row(text: &str, packed: u32) -> RuntimeTrainingExample {
    RuntimeTrainingExample {
        text: text.into(),
        has_target: true,
        target: Some(RuntimeClassification { packed, ..Default::default() }),
        weight: 1.0,
    }
}

fn header() -> String {
    serde_json::json!({
        "schema": 4, "expected_objective": GATE_OBJECTIVE, "expected_diagnostics_policy": null, "expected_optimizer": GATE_POLICY,
        "expected_candidate_eligibility": ELIGIBILITY, "expected_optimizer_config": CONFIG_CANONICAL,
        "expected_training_scope": "full_encoder", "expected_retention_manifest_sha256": PIN
    })
    .to_string()
}

fn call(trainer: &Trainer, method: Method) -> Result<ComputeSemanticGradientsResponse, FrameError> {
    let message = ComputeSemanticGradientsRequest {
        request_id: "r1".into(),
        model_id: "synthetic-legacy-retention".into(),
        examples: vec![row("alpha beta", 0b10 | 0b00100), row("lunch report", 0b00100)],
        heldout_examples: vec![row("gamma delta", 0b00100)],
        learning_rate: 0.003,
        max_gradient: 0.05,
        layers: vec![4],
    };
    let request = Request {
        method,
        request_id: 1,
        deadline_ms: 1_000,
        metadata: vec![(ADMISSION_HEADER.to_string(), header())],
        payload: message.encode_to_vec(),
    };
    trainer.handle(&request).map(|payload| ComputeSemanticGradientsResponse::decode(payload.as_slice()).unwrap())
}

#[test]
fn the_retention_route_answers_pythons_texts_before_it_reads_the_sidecars() {
    let served = trainer(Some(config(PIN)));
    let heads = call(&served, Method::ComputeSemanticGradients).unwrap();
    assert_eq!(heads.error, "ORIGINAL retention is an opt-in FULL-only route.");
    assert!(heads.gradients.is_empty());
    let other_pin = trainer(Some(config(&"d".repeat(64))));
    let pins = call(&other_pin, Method::ComputeUnderlyingModelGradients).unwrap();
    assert_eq!(pins.error, "Runtime retention requires a distinct trusted configured accepted manifest SHA before model access.");
}

#[test]
fn the_retention_route_reads_the_configured_sidecars() {
    let answer = call(&trainer(Some(config(PIN))), Method::ComputeUnderlyingModelGradients).unwrap();
    assert!(answer.error.contains("/nonexistent/bank.json"), "{}", answer.error);
    assert!(answer.gradients.is_empty() && answer.metadata.is_empty());
}

#[test]
fn a_worker_without_a_retention_configuration_declines_to_python() {
    let declined = call(&trainer(None), Method::ComputeUnderlyingModelGradients).unwrap_err();
    assert_eq!(declined.code, code::UNSUPPORTED_ROUTE);
    assert!(declined.message.contains("Python worker"), "{}", declined.message);
}
