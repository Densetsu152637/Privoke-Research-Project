//! The FULL Adam trace admission against the Python oracle (RUST-S21E): `tests/fixtures/full_adam_trace_golden.json` is written by
//! `evaluation/generate_full_adam_trace_golden.py` from `privoke_model.full_adam.validate_trace`, over one retained FULL fit and
//! mutations of it. Every verdict, and every error message, must be Python's.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::path::Path;

use privoke_fuzzer::full_adam::validate_trace;
use serde_json::Value;

#[test]
fn the_trace_admission_matches_the_python_oracle() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/full_adam_trace_golden.json");
    let golden: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let (mut admitted, mut refused) = (0, 0);
    for case in golden["cases"].as_array().unwrap() {
        let label = case["label"].as_str().unwrap();
        let metadata: BTreeMap<String, String> =
            case["metadata"].as_object().unwrap().iter().map(|(key, value)| (key.clone(), value.as_str().unwrap().to_string())).collect();
        let outcome = validate_trace(
            &metadata,
            case["scope"].as_str().unwrap(),
            usize::try_from(case["examples"].as_u64().unwrap()).unwrap(),
            case["candidate"].as_str().unwrap(),
            case["delta"].as_str().unwrap(),
        );
        match case.get("error") {
            Some(message) => {
                assert_eq!(outcome.unwrap_err().0, message.as_str().unwrap(), "{label}");
                refused += 1;
            }
            None => {
                let trace = outcome.unwrap_or_else(|error| panic!("{label}: {error}"));
                assert_eq!(trace.is_some(), case["result"] == "trace", "{label}");
                admitted += 1;
            }
        }
    }
    eprintln!("fuzzer FULL Adam trace admission: {admitted} admitted and {refused} refused cases identical to the Python oracle");
    assert_eq!((admitted, refused), (2, 24));
}
