//! Shared by the V3 fit parity tests (the synthetic CI test and the gated real-package test).

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;

use privoke_semantic::safetensors::Tensor;
use privoke_training::v3_fit::{Fit, FitInput, Row};
use serde_json::Value;

use std::path::PathBuf;

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

pub fn rows(value: &Value) -> Vec<Row> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|row| Row { text: row["text"].as_str().unwrap().to_string(), packed: u16::try_from(row["packed"].as_u64().unwrap()).unwrap() })
        .collect()
}

pub fn golden() -> Value {
    serde_json::from_slice(&std::fs::read(fixtures().join("v3_fit/golden.json")).unwrap()).unwrap()
}

pub fn input(golden: &Value, scope: &str) -> FitInput {
    let evidence = &golden["scopes"][scope];
    FitInput {
        request_id: evidence["request_id"].as_str().unwrap().to_string(),
        model_id: golden["model_id"].as_str().unwrap().to_string(),
        base: evidence["base"].as_str().unwrap().to_string(),
        source_commitment: evidence["source_commitment"].as_str().unwrap().to_string(),
        full: scope == "full_encoder",
        train: rows(&golden["train"]),
        guard: rows(&golden["guard"]),
        train_wire_sha256: evidence["train_wire_sha256"].as_str().unwrap().to_string(),
        guard_wire_sha256: evidence["guard_wire_sha256"].as_str().unwrap().to_string(),
        policy: golden["policy"].clone(),
    }
}

pub fn relative(a: f64, b: f64) -> f64 {
    (a - b).abs() / b.abs().max(1.0)
}

/// Compare a fit with the product's evidence and exported candidate for one scope; `min_fraction` is the least share of
/// candidate values that must agree within 1e-6.
pub fn compare(scope: &str, python: &Value, result: &Fit, exported: &BTreeMap<String, Tensor>, min_fraction: f64) {
    let rust = &result.evidence;
    for key in ["counts", "block_counts", "phases", "scope", "layers", "policy", "trainable_count", "parameter_count", "tier"] {
        assert_eq!(rust[key], python[key], "{scope}: {key}");
    }
    // The changed tensors. The gradient of a key bias is exactly zero (softmax ignores a constant added to every score), so what
    // Torch's float32 backward leaves there is rounding noise, which AdamW's normalisation turns into a real step; the float64
    // backward leaves noise far below epsilon, which float32 storage rounds away. Those tensors may differ; nothing else may.
    let names = |value: &Value| -> Vec<String> {
        value["changed_tensors"].as_array().unwrap().iter().map(|n| n.as_str().unwrap().to_string()).collect()
    };
    let (rust_changed, python_changed) = (names(rust), names(python));
    let missing: Vec<&String> = python_changed.iter().filter(|name| !rust_changed.contains(name)).collect();
    assert!(rust_changed.iter().all(|name| python_changed.contains(name)), "{scope}: Rust changed a tensor Torch did not");
    assert!(missing.iter().all(|name| name.ends_with("attention.self.key.bias")), "{scope}: tensors only Torch changed: {missing:?}");
    assert_eq!(rust["changes"]["heads"], python["changes"]["heads"], "{scope}");
    assert_eq!(rust["changes"]["embeddings"], python["changes"]["embeddings"], "{scope}");
    assert_eq!(rust["changes"]["pooler"], python["changes"]["pooler"], "{scope}");
    assert_eq!(
        rust["changes"]["encoder"].as_u64().unwrap() + missing.len() as u64,
        python["changes"]["encoder"].as_u64().unwrap(),
        "{scope}"
    );
    for (key, tolerance) in [("losses", 1e-4)] {
        for (a, b) in rust[key].as_array().unwrap().iter().zip(python[key].as_array().unwrap()) {
            assert!(relative(a.as_f64().unwrap(), b.as_f64().unwrap()) < tolerance, "{scope}: {key} {a} against {b}");
        }
    }
    let (rust_trace, python_trace) = (rust["gradient_trace"].as_array().unwrap(), python["gradient_trace"].as_array().unwrap());
    for (a, b) in rust_trace.iter().zip(python_trace) {
        assert_eq!(a["step"], b["step"]);
        assert!(
            relative(a["norm_before_clip"].as_f64().unwrap(), b["norm_before_clip"].as_f64().unwrap()) < 1e-4,
            "{scope}: {a} against {b}"
        );
        let (x, y) = (a["encoder_nonzero_gradients"].as_f64().unwrap(), b["encoder_nonzero_gradients"].as_f64().unwrap());
        assert!((x - y).abs() <= 0.01 * y.max(1.0), "{scope}: encoder nonzero gradients {x} against {y}");
    }
    // The guard: the same predictions, actions and harms as the product.
    for guard in ["base_guard", "candidate_guard"] {
        for key in ["joint_correct", "action_correct", "examples"] {
            assert_eq!(rust[guard][key], python[guard][key], "{scope}: {guard} {key}");
        }
        for (a, b) in rust[guard]["rows"].as_array().unwrap().iter().zip(python[guard]["rows"].as_array().unwrap()) {
            for key in ["target", "prediction", "action", "target_action", "action_value", "target_action_value", "joint_correct"] {
                assert_eq!(a[key], b[key], "{scope}: {guard} {key}: {a} against {b}");
            }
            assert!(
                (a["confidence"].as_f64().unwrap() - b["confidence"].as_f64().unwrap()).abs() <= 1.1e-3,
                "{scope}: {guard}: {a} against {b}"
            );
        }
    }
    assert_eq!(rust["action_harms"], python["action_harms"], "{scope}");
    // The candidate against the product's exported candidate.
    assert_eq!(result.candidate.len(), exported.len());
    let (head_lr, encoder_lr) = (1e-3, 2e-5);
    let (mut values, mut within, mut worst, mut bitwise, mut identical_tensors) = (0usize, 0usize, 0f64, 0usize, 0usize);
    for (name, tensor) in &result.candidate {
        let reference = &exported[name];
        assert_eq!(tensor.shape, reference.shape, "{scope}: {name}");
        let bound = 2.0 * if name.starts_with("heads.") { head_lr } else { encoder_lr } * 1.01 + 1e-6;
        for (a, b) in tensor.data.iter().zip(&reference.data) {
            let error = f64::from((a - b).abs());
            assert!(error <= bound, "{scope}: {name}: {a} against {b}");
            values += 1;
            within += usize::from(error <= 1e-6);
            bitwise += usize::from(a.to_bits() == b.to_bits());
            worst = worst.max(error);
        }
        identical_tensors += usize::from(tensor.sha256 == reference.sha256);
    }
    eprintln!(
        "v3 fit {scope}: counts, blocks, phases and guards equal, {} key-bias tensors changed only by Torch's noise; losses {:?} against {:?}; candidate {values} values, {within} within 1e-6, {bitwise} bitwise, {identical_tensors} of {} tensors byte-identical, max abs error {worst:.3e}",
        missing.len(),
        rust["losses"],
        python["losses"],
        result.candidate.len()
    );
    assert!(within as f64 >= min_fraction * values as f64, "{scope}: only {within} of {values} candidate values within 1e-6");
}
