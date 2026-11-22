//! The ORIGINAL retention evidence against the Python oracle (RUST-S21F item 2): `tests/fixtures/retention_trace_golden.json` is
//! written by `evaluation/generate_retention_trace_golden.py` from `sensitive_retention.validate_trace`, `execution_phases` and
//! `sensitive_retention_evidence.validate_source_bindings`, over two retained retention cycles (a gate-only and a hinge policy) and
//! mutations of them. Every verdict, and every error message, must be Python's.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::path::Path;

use privoke_fuzzer::retention::{execution_phases, validate_source_bindings, validate_trace};
use privoke_training::retention::{Reference, Release};
use serde_json::Value;

fn text_map(document: &Value) -> BTreeMap<String, String> {
    document.as_object().unwrap().iter().map(|(key, value)| (key.clone(), value.as_str().unwrap().to_string())).collect()
}

fn release(base: &Value) -> Release {
    let references = base["references"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| Reference {
            id: row["id"].as_str().unwrap().to_string(),
            text: String::new(),
            gold: u16::try_from(row["gold"].as_u64().unwrap()).unwrap(),
            original: u16::try_from(row["original"].as_u64().unwrap()).unwrap(),
            confidence: row["confidence"].as_f64().unwrap(),
            margin: row["margin"].as_f64().unwrap(),
        })
        .collect();
    Release {
        sha256: base["release_sha256"].as_str().unwrap().to_string(),
        teacher_fingerprint: String::new(),
        teacher_config: Value::Null,
        model_id: base["model_id"].as_str().unwrap().to_string(),
        references,
    }
}

#[test]
fn the_retention_evidence_matches_the_python_oracle() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/retention_trace_golden.json");
    let golden: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let bases = golden["bases"].as_array().unwrap();
    let (mut admitted, mut refused) = (0, 0);
    for case in golden["cases"].as_array().unwrap() {
        let label = case["label"].as_str().unwrap();
        let base = &bases[usize::try_from(case["base"].as_u64().unwrap()).unwrap()];
        let mut metadata = text_map(&base["metadata"]);
        metadata.extend(text_map(&case["set"]));
        for key in case["unset"].as_array().unwrap() {
            metadata.remove(key.as_str().unwrap());
        }
        let outcome: Result<String, String> = match case["kind"].as_str().unwrap() {
            "trace" => validate_trace(
                &metadata,
                case["scope"].as_str().unwrap(),
                usize::try_from(case["examples"].as_u64().unwrap()).unwrap(),
                case["candidate"].as_str().unwrap(),
                case["delta"].as_str().unwrap(),
            )
            .map(|trace| if trace.is_some() { "trace" } else { "none" }.to_string())
            .map_err(|error| error.0),
            "phases" => execution_phases(&metadata)
                .map(|phases| phases.iter().map(|(name, count)| format!("{name}:{count}")).collect::<Vec<_>>().join(","))
                .map_err(|error| error.0),
            _ => validate_source_bindings(&metadata, &release(base)).map(|()| "ok".to_string()).map_err(|error| error.0),
        };
        match case.get("error") {
            Some(message) => {
                assert_eq!(outcome.unwrap_err(), message.as_str().unwrap(), "{label}");
                refused += 1;
            }
            None => {
                let expected = match case["kind"].as_str().unwrap() {
                    "phases" => case["result"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|pair| format!("{}:{}", pair[0].as_str().unwrap(), pair[1]))
                        .collect::<Vec<_>>()
                        .join(","),
                    _ => case["result"].as_str().unwrap().to_string(),
                };
                assert_eq!(outcome.unwrap_or_else(|error| panic!("{label}: {error}")), expected, "{label}");
                admitted += 1;
            }
        }
    }
    eprintln!("fuzzer ORIGINAL retention evidence: {admitted} admitted and {refused} refused cases identical to the Python oracle");
    assert!(admitted >= 6 && refused >= 40);
}
