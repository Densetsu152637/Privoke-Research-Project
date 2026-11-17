//! `_compute_training_gradients` (single-update route) against the Python golden: transported update, response
//! metrics and the held-out guard outcome, semantic-only (no detector layer runs on either side).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::path::PathBuf;

use privoke_training::objective::{Example, Target};
use privoke_training::rpc::{Request, Snapshot, compute_gradients};
use serde_json::Value;

fn golden() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/tiny_training_golden.json");
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

fn rows(value: &Value) -> Vec<Example> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|row| Example {
            text: row["text"].as_str().unwrap().to_string(),
            target: Target {
                sensitivity: row["sensitivity"].as_str().unwrap().to_string(),
                visibility: row["visibility"].as_str().unwrap().to_string(),
                categories: row["categories"].as_array().unwrap().iter().map(|c| c.as_str().unwrap().to_string()).collect(),
            },
            weight: row["weight"].as_f64().unwrap(),
        })
        .collect()
}

fn bits(value: &Value) -> Vec<f32> {
    value.as_array().unwrap().iter().map(|v| f32::from_bits(u32::try_from(v.as_u64().unwrap()).unwrap())).collect()
}

/// Metrics that are exact counts or rates of decisions: any difference is a changed decision.
fn is_decision_metric(key: &str) -> bool {
    key.contains("heldout") || key.starts_with("exact_match") || key.starts_with("examples") || key.ends_with("_examples")
}

#[test]
fn single_update_route_matches_python() {
    let golden = golden();
    let (examples, heldout) = (rows(&golden["examples"]), rows(&golden["heldout"]));
    let cases = golden["rpc_cases"].as_array().unwrap();
    let (mut coordinates, mut within, mut bitwise, mut metrics_total, mut metrics_close) = (0usize, 0usize, 0usize, 0usize, 0usize);
    let (mut guard_equal, mut accept_equal, mut accepted, mut rejected) = (0usize, 0usize, 0usize, 0usize);
    let mut max_error = 0f64;
    for case in cases {
        let model = case["model"].as_str().unwrap();
        let label = format!("{model}/{}/{}", case["objective"].as_str().unwrap_or("legacy"), case["scope"].as_str().unwrap());
        let snapshot = Snapshot {
            artifact: golden["models"][model].clone(),
            full_capable: true,
            objective: case["objective"].as_str().map(str::to_string),
        };
        let request = Request {
            examples: examples.clone(),
            heldout: heldout.clone(),
            learning_rate: case["learning_rate"].as_f64().unwrap(),
            max_gradient: case["max_gradient"].as_f64().unwrap(),
            full_encoder: case["full_encoder"].as_bool().unwrap(),
        };
        let batch = compute_gradients(&snapshot, &request).unwrap();
        assert_eq!(batch.scope, case["scope"].as_str().unwrap(), "{label}");
        let python: BTreeMap<String, Vec<f32>> = case["gradients"].as_object().unwrap().iter().map(|(k, v)| (k.clone(), bits(v))).collect();
        assert_eq!(batch.gradients.keys().collect::<Vec<_>>(), python.keys().collect::<Vec<_>>(), "{label} inventory");
        for (name, expected) in &python {
            for (r, p) in batch.gradients[name].iter().zip(expected) {
                coordinates += 1;
                bitwise += usize::from(r.to_bits() == p.to_bits());
                let error = f64::from(*r - *p).abs();
                within += usize::from(error <= 1e-6);
                max_error = max_error.max(error);
            }
        }
        let expected_metrics = case["metrics"].as_object().unwrap();
        assert_eq!(
            batch.metrics.keys().map(String::as_str).collect::<Vec<_>>(),
            expected_metrics.keys().map(String::as_str).collect::<Vec<_>>(),
            "{label} metric names"
        );
        for (key, expected) in expected_metrics {
            let (actual, expected) = (batch.metrics[key], expected.as_f64().unwrap());
            metrics_total += 1;
            let close = if is_decision_metric(key) {
                (actual - expected).abs() < 1e-12
            } else {
                (actual - expected).abs() <= 1e-5 * expected.abs().max(1.0)
            };
            metrics_close += usize::from(close);
            assert!(close, "{label} {key}: {actual} vs {expected}");
        }
        let key = "candidate_heldout_safety_regression_rate";
        guard_equal += usize::from(batch.metrics[key] == expected_metrics[key].as_f64().unwrap());
        // The guard accepts a candidate only when it regresses no held-out row.
        let (rust_accept, python_accept) = (batch.metrics[key] == 0.0, expected_metrics[key].as_f64().unwrap() == 0.0);
        accept_equal += usize::from(rust_accept == python_accept);
        if python_accept {
            accepted += 1
        } else {
            rejected += 1
        }
        assert_eq!(
            batch.executions.iter().map(|(p, n)| (p.as_str(), *n)).collect::<Vec<_>>(),
            case["executions"]
                .as_array()
                .unwrap()
                .iter()
                .map(|e| (e[0].as_str().unwrap(), usize::try_from(e[1].as_u64().unwrap()).unwrap()))
                .collect::<Vec<_>>(),
            "{label} executions"
        );
    }
    println!(
        "rpc: {} cases; transported coordinates {coordinates}, within 1e-6 {within}, bitwise {bitwise}, max error {max_error:.3e}; metrics {metrics_close}/{metrics_total}; guard rate equal {guard_equal}, accept/reject equal {accept_equal} (accepted {accepted}, rejected {rejected})",
        cases.len()
    );
    assert_eq!(within, coordinates);
    assert_eq!(accept_equal, cases.len());
    assert_eq!(guard_equal, cases.len());
}
