//! The schema 5 (window) route of the Rust worker, on the synthetic window artifact: the route is reached for a window
//! header, answers Python's texts for the request checks that precede the sidecars, reads the configured sidecars
//! (a synthetic window cannot pass the contract: the bank is pinned to the real study data), and is declined to Python when
//! the worker has no window configuration. The loop itself runs against the real release in `window_worker_release.rs`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;
use std::sync::Arc;

use privoke_contracts::proto::v1::{
    ComputeSemanticGradientsRequest, ComputeSemanticGradientsResponse, RuntimeClassification, RuntimeTrainingExample,
};
use privoke_runtime::frames::{FrameError, Method, Request, code};
use privoke_runtime::store::ArtifactStore;
use privoke_runtime::training::{ADMISSION_HEADER, Trainer, WindowConfig};
use privoke_training::admission::{WINDOW_CONFIG_CANONICAL, WINDOW_ELIGIBILITY};
use prost::Message;

const WINDOW_PIN: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const COMPONENT_PIN: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn trainer(window: Option<WindowConfig>) -> Trainer {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/worker_models");
    Trainer::new(Arc::new(ArtifactStore::new(vec![root], None)), 10_000).with_window(window)
}

fn config(window_pin: &str) -> WindowConfig {
    let missing = |name: &str| PathBuf::from(format!("/nonexistent/{name}"));
    WindowConfig {
        window_path: missing("window.json"),
        window_sha256: window_pin.to_string(),
        bank_path: missing("bank.json"),
        reference_path: missing("references.json"),
        manifest_path: missing("manifest.json"),
        teacher_path: missing("teacher.json"),
        manifest_sha256: COMPONENT_PIN.to_string(),
        teacher_sha256: COMPONENT_PIN.to_string(),
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
        "schema": 5, "expected_objective": "class_balanced_contextual_sum_category_decision_margin_v1",
        "expected_diagnostics_policy": null, "expected_optimizer": "full_projected_adam64_window_checkpoint_v1",
        "expected_candidate_eligibility": WINDOW_ELIGIBILITY, "expected_optimizer_config": WINDOW_CONFIG_CANONICAL,
        "expected_training_scope": "full_encoder", "expected_window_manifest_sha256": WINDOW_PIN,
        "expected_component_manifest_sha256": COMPONENT_PIN
    })
    .to_string()
}

fn call(trainer: &Trainer, method: Method, rate: f64, bound: f64) -> Result<ComputeSemanticGradientsResponse, FrameError> {
    let message = ComputeSemanticGradientsRequest {
        request_id: "w1".into(),
        model_id: "synthetic-legacy-window".into(),
        examples: vec![row("alpha beta", 0b10 | 0b00100), row("lunch report", 0b00100)],
        heldout_examples: vec![row("gamma delta", 0b00100)],
        learning_rate: rate,
        max_gradient: bound,
        layers: vec![4],
        ..Default::default()
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
fn the_window_route_answers_pythons_texts_before_it_reads_the_sidecars() {
    let served = trainer(Some(config(WINDOW_PIN)));
    let heads = call(&served, Method::ComputeSemanticGradients, 0.003, 0.05).unwrap();
    assert_eq!(heads.error, "Frozen window/checkpoint training is FULL-only.");
    assert!(heads.gradients.is_empty());
    let rate = call(&served, Method::ComputeUnderlyingModelGradients, 0.5, 0.05).unwrap();
    assert_eq!(rate.error, "Window optimizer requires explicit FULL scope/fixed rate/cap.");
    let bound = call(&served, Method::ComputeUnderlyingModelGradients, 0.003, 0.5).unwrap();
    assert_eq!(bound.error, "Window optimizer requires explicit FULL scope/fixed rate/cap.");
    let other_pin = trainer(Some(config(&"c".repeat(64))));
    let pins = call(&other_pin, Method::ComputeUnderlyingModelGradients, 0.003, 0.05).unwrap();
    assert_eq!(pins.error, "Request pins differ from trusted runtime window/component configuration.");
}

#[test]
fn the_window_route_reads_the_configured_sidecars() {
    let served = trainer(Some(config(WINDOW_PIN)));
    let answer = call(&served, Method::ComputeUnderlyingModelGradients, 0.003, 0.05).unwrap();
    assert!(answer.error.contains("/nonexistent/window.json"), "{}", answer.error);
    assert!(answer.gradients.is_empty() && answer.metadata.is_empty());
}

#[test]
fn a_worker_without_a_window_configuration_declines_to_python() {
    let declined = call(&trainer(None), Method::ComputeUnderlyingModelGradients, 0.003, 0.05).unwrap_err();
    assert_eq!(declined.code, code::UNSUPPORTED_ROUTE);
    assert!(declined.message.contains("Python worker"), "{}", declined.message);
}
