//! The caller's policy admission against the Python oracle (RUST-S21D): `tests/fixtures/policy_expectations_golden.json` is
//! written by `evaluation/generate_fuzzer_policy_golden.py` from `training_policy_expectations` and `training_admission_metadata`.
//! Every valid policy yields the same expectations and the same admission header, byte for byte, and every invalid request the
//! same message.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::path::Path;

use privoke_fuzzer::policy::{training_admission_header, training_policy_expectations};
use serde_json::Value;

#[test]
fn the_policy_admission_matches_the_python_oracle() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/policy_expectations_golden.json");
    let golden: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let (mut valid, mut invalid, mut headers) = (0, 0, 0);
    for case in golden["cases"].as_array().unwrap() {
        let label = case["label"].as_str().unwrap();
        let metadata: BTreeMap<String, String> =
            case["metadata"].as_object().unwrap().iter().map(|(key, value)| (key.clone(), value.as_str().unwrap().to_string())).collect();
        let outcome = training_policy_expectations(&metadata);
        if let Some(message) = case.get("error") {
            assert_eq!(outcome.unwrap_err().0, message.as_str().unwrap(), "{label}");
            invalid += 1;
            continue;
        }
        let expectations = outcome.unwrap_or_else(|error| panic!("{label}: {error}"));
        let expected: BTreeMap<String, Option<String>> = case["expectations"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(key, value)| (key.clone(), value.as_str().map(str::to_string)))
            .collect();
        assert_eq!(expectations.0, expected, "{label}: expectations");
        let header = training_admission_header(&expectations).unwrap();
        assert_eq!(header.as_deref(), case["header"].as_str(), "{label}: admission header");
        headers += usize::from(header.is_some());
        valid += 1;
    }
    eprintln!(
        "fuzzer policy admission: {valid} valid and {invalid} invalid requests, {headers} admission headers identical to the Python oracle"
    );
    assert_eq!((valid, invalid, headers), (12, 19, 9));
}
