//! ORIGINAL reference preparation on the seeded Tiny golden model (no study data): the row invariants, the canonical payload
//! layout and the refusal of a bank that is not the approved one. The comparison with the real reference file of the balanced
//! release is `reference_release_parity.rs`, which needs the local release and is skipped when `PRIVOKE_RETENTION_RELEASE`
//! is unset.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;

use privoke_semantic::TinyModel;
use privoke_training::reference::{PreparedRow, payload, prepare_references, prepared_row};
use serde_json::{Value, json};

fn golden() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/tiny_training_golden.json");
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

#[test]
fn rows_follow_the_strict_policy() {
    let golden = golden();
    let model = TinyModel::from_artifact(&golden["models"]["legacy"]).unwrap();
    let mut eligible = 0;
    for (index, example) in golden["examples"].as_array().unwrap().iter().chain(golden["heldout"].as_array().unwrap()).enumerate() {
        let row = prepared_row(&model, &format!("row{index}"), example["text"].as_str().unwrap()).unwrap();
        assert!((0.0..=0.999).contains(&row.confidence));
        assert_eq!(format!("{:.3}", row.confidence).parse::<f64>().unwrap(), row.confidence, "confidence has three places");
        assert!(row.margin.is_finite() && row.sensitivity_gap >= 0.0);
        let sensitive = row.packed & 0b11 != 0 || row.packed & 0x7FE0 != 0;
        assert_eq!(row.eligible, sensitive && row.margin > 1e-6 && row.sensitivity_gap > 1e-6, "{row:?}");
        eligible += usize::from(row.eligible);
    }
    assert!(eligible > 0, "no eligible row at all");
}

#[test]
fn the_payload_is_canonical_python_json() {
    let teacher = json!({"profile": "balanced", "model_id": "privoke-balanced"});
    let rows = vec![
        PreparedRow { id: "b".into(), packed: 30, confidence: 0.522, margin: 0.4069713354110718, sensitivity_gap: 1e-7, eligible: false },
        PreparedRow { id: "a".into(), packed: 7, confidence: 0.999, margin: 100.0, sensitivity_gap: 2.5, eligible: true },
    ];
    let text = payload(&teacher, &rows).unwrap();
    assert!(text.ends_with("}\n") && text.matches('\n').count() == 1);
    assert!(text.starts_with("{\"bank_sha256\":\"c9b0b641"), "sorted keys: {text}");
    assert!(text.contains("\"sensitivity_gap\":1e-07"), "Python float layout: {text}");
    assert!(text.contains("\"margin\":100.0") && text.contains("\"margin\":0.4069713354110718"), "{text}");
    assert!(text.contains("\"epsilon\":1e-06"), "{text}");
    // The rows keep their order (Python's list), the keys inside a row are sorted.
    assert!(text.find("\"id\":\"b\"").unwrap() < text.find("\"id\":\"a\"").unwrap());
    let parsed: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(parsed["schema"], 1);
    assert_eq!(parsed["rows"].as_array().unwrap().len(), 2);
}

#[test]
fn a_bank_that_is_not_the_approved_one_is_refused() {
    let mut seen = 0;
    let error = prepare_references(b"[]", b"{}", "balanced", &mut |_| seen += 1).unwrap_err();
    assert_eq!(error.to_string(), "Retention bank differs from the independently approved200 TRAIN rows.");
    assert_eq!(seen, 0, "nothing is predicted before the bank and teacher are authenticated");
}
