//! The presence model's probabilities (the presence gate's inference; the gradients were removed in stage V3-R8a) and the
//! FULL Adam admission checks against the Python golden. Semantic-only: no detector layer runs on either side.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;

use privoke_training::admission::{CONFIG_CANONICAL, Fields, validate_admission};
use privoke_training::presence::PresenceModel;
use serde_json::Value;

fn golden() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/tiny_training_golden.json");
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

#[test]
fn presence_probabilities_match_python() {
    let golden = golden();
    let record = &golden["presence"];
    let model = PresenceModel::from_artifact(&record["artifact"]).unwrap();
    // The training rows, then the held-out rows: the model itself, which the presence gate serves for detection.
    let texts: Vec<&str> = ["examples", "heldout"]
        .into_iter()
        .flat_map(|key| record[key].as_array().unwrap())
        .map(|row| row["text"].as_str().unwrap())
        .collect();
    let expected = record["probabilities"].as_array().unwrap();
    assert_eq!(texts.len(), expected.len());
    let mut max_probability_error = 0f64;
    for (text, expected) in texts.iter().zip(expected) {
        max_probability_error = max_probability_error.max((model.predict_probability(text) - expected.as_f64().unwrap()).abs());
    }
    eprintln!("presence: {} probabilities, max error {max_probability_error:.3e}", texts.len());
    assert!(max_probability_error <= 1e-12, "probability error {max_probability_error:e}");
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
