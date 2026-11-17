//! `ComputePresenceGradients` (`presence_training.compute_presence_gradients`) and the FULL Adam admission checks
//! against the Python golden. Semantic-only: no detector layer runs on either side.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::path::PathBuf;

use privoke_training::admission::{CONFIG_CANONICAL, Fields, validate_admission};
use privoke_training::presence::{PresenceExample, PresenceModel, PresenceRequest, PresenceSnapshot, compute_presence_gradients};
use serde_json::Value;

fn golden() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/tiny_training_golden.json");
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

fn rows(value: &Value) -> Vec<PresenceExample> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|row| PresenceExample {
            text: row["text"].as_str().unwrap().to_string(),
            target: row["target"].as_bool().unwrap(),
            weight: row["weight"].as_f64().unwrap(),
            group_id: row["group_id"].as_str().unwrap().to_string(),
        })
        .collect()
}

#[test]
fn presence_gradients_match_python() {
    let golden = golden();
    let record = &golden["presence"];
    let snapshot = PresenceSnapshot { artifact: record["artifact"].clone(), version: record["version"].as_str().unwrap().to_string() };
    let request = PresenceRequest {
        examples: rows(&record["examples"]),
        heldout: rows(&record["heldout"]),
        learning_rate: record["learning_rate"].as_f64().unwrap(),
        max_gradient: record["max_gradient"].as_f64().unwrap(),
    };
    // Probabilities of every row first: the model itself, before the update.
    let model = PresenceModel::from_artifact(&snapshot.artifact).unwrap();
    let expected_probabilities = record["probabilities"].as_array().unwrap();
    let texts: Vec<&PresenceExample> = request.examples.iter().chain(&request.heldout).collect();
    let mut max_probability_error = 0f64;
    for (item, expected) in texts.iter().zip(expected_probabilities) {
        max_probability_error = max_probability_error.max((model.predict_probability(&item.text) - expected.as_f64().unwrap()).abs());
    }
    assert!(max_probability_error <= 1e-12, "probability error {max_probability_error:e}");

    let batch = compute_presence_gradients(&snapshot, &request).unwrap();
    let python: BTreeMap<String, Vec<f32>> = record["gradients"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(k, v)| {
            (k.clone(), v.as_array().unwrap().iter().map(|b| f32::from_bits(u32::try_from(b.as_u64().unwrap()).unwrap())).collect())
        })
        .collect();
    assert_eq!(batch.gradients.keys().collect::<Vec<_>>(), python.keys().collect::<Vec<_>>());
    let (mut coordinates, mut bitwise, mut max_error) = (0usize, 0usize, 0f64);
    for (name, expected) in &python {
        for (r, p) in batch.gradients[name].iter().zip(expected) {
            coordinates += 1;
            bitwise += usize::from(r.to_bits() == p.to_bits());
            max_error = max_error.max(f64::from(*r - *p).abs());
        }
    }
    let expected_metrics = record["metrics"].as_object().unwrap();
    assert_eq!(
        batch.metrics.keys().map(String::as_str).collect::<Vec<_>>(),
        expected_metrics.keys().map(String::as_str).collect::<Vec<_>>()
    );
    let mut metrics_equal = 0usize;
    for (key, expected) in expected_metrics {
        let (actual, expected) = (batch.metrics[key], expected.as_f64().unwrap());
        let tolerance = if key.contains("loss") { 1e-9 * expected.abs().max(1.0) } else { 0.0 };
        assert!((actual - expected).abs() <= tolerance, "{key}: {actual} vs {expected}");
        metrics_equal += usize::from(actual == expected);
    }
    let metadata = record["metadata"].as_object().unwrap();
    let mut fingerprints_equal = 0usize;
    for (key, expected) in metadata {
        let actual = &batch.metadata[key];
        if key.ends_with("fingerprint") {
            fingerprints_equal += usize::from(actual == expected.as_str().unwrap());
        } else {
            assert_eq!(actual, expected.as_str().unwrap(), "{key}");
        }
    }
    let executions: Vec<(String, usize)> = record["executions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| (e[0].as_str().unwrap().to_string(), usize::try_from(e[1].as_u64().unwrap()).unwrap()))
        .collect();
    assert_eq!(batch.executions, executions);
    eprintln!(
        "presence: {coordinates} coordinates, bitwise {bitwise}, max error {max_error:.3e}; probability max error {max_probability_error:.3e}; metrics bitwise-equal {metrics_equal}/{}; fingerprints equal {fingerprints_equal}/4",
        expected_metrics.len()
    );
    assert!(max_error <= 1e-6, "presence update error {max_error:e}");
    // The candidate fingerprints bind the exact float32 update: they are equal only for a bitwise-equal update.
    if bitwise == coordinates {
        assert_eq!(fingerprints_equal, 4);
    }
}

fn fields(value: &Value) -> Fields {
    value.as_object().unwrap().iter().map(|(k, v)| (k.clone(), v.as_str().unwrap().to_string())).collect()
}

#[test]
fn full_adam_admission_matches_python() {
    let golden = golden();
    let admission = &golden["admission"];
    assert_eq!(admission["config_canonical"].as_str().unwrap(), CONFIG_CANONICAL);
    let cases = admission["cases"].as_array().unwrap();
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let header = (!case["admission"].is_null()).then(|| fields(&case["admission"]));
        let outcome = validate_admission(header.as_ref(), &fields(&case["metadata"]));
        match (outcome, case["active"].as_bool(), case["error"].as_str()) {
            (Ok(active), Some(expected), None) => assert_eq!(active, expected, "{name}"),
            (Err(error), None, Some(expected)) => assert_eq!(error.to_string(), expected, "{name}"),
            (rust, active, error) => panic!("{name}: Rust {rust:?} vs Python active {active:?} error {error:?}"),
        }
    }
    eprintln!("admission: {} of {} cases identical", cases.len(), cases.len());
}
