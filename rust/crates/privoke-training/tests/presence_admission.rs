//! The presence model's probabilities against the Python golden (the presence gate's inference; the gradients were removed
//! in stage V3-R8a and the FULL Adam admission with the V1 modules in stage V3-R8b). Semantic-only: no detector layer runs.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;

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
