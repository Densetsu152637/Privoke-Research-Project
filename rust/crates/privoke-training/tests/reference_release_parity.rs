//! ORIGINAL reference preparation against the real reference file of the balanced release, which is the product of the
//! unchanged Python `prepare_references` (200 bank rows through the real semantic dispatcher). Skipped unless
//! `PRIVOKE_RETENTION_RELEASE` names the run directory `evaluation/results/iterative_fuzzer_20261011` (the study data stays
//! out of Git and CI). No golden is generated: the committed release file is the Python output.
//!
//! Compared per row: the packed prediction, the rounded confidence and the eligibility exactly; the float32 margin and gap
//! within 1e-6 (relative to max(1, |v|)), with the bitwise count reported (the logits are float32 in numpy and float64
//! cast to float32 here); and the teacher identity. The payload bytes equal the file's only when every float is bitwise equal.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;

use privoke_training::reference::prepare_references;
use serde_json::Value;

fn read(path: &PathBuf) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

#[test]
fn the_prepared_references_match_the_balanced_release() {
    let Some(root) = std::env::var_os("PRIVOKE_RETENTION_RELEASE").map(PathBuf::from) else {
        eprintln!("reference release parity skipped: PRIVOKE_RETENTION_RELEASE is not set");
        return;
    };
    let bank = read(&root.join("train-sensitive-retention/approved-train-bank.json"));
    let teacher = read(&root.join("block01/balanced/catalog/privoke-balanced.json"));
    let file = read(&root.join("sensitive-retention-pilot/execution/references/balanced/references.json"));
    let (mut attempted, mut completed) = (0, 0);
    let (payload, identity) = prepare_references(&bank, &teacher, "balanced", &mut |record| match record["status"].as_str() {
        Some("attempted") => attempted += 1,
        Some("completed") => completed += 1,
        other => panic!("unexpected record status {other:?}"),
    })
    .expect("the references are prepared");
    let python: Value = serde_json::from_slice(&file).unwrap();
    let rust: Value = serde_json::from_str(&payload).unwrap();
    assert_eq!((attempted, completed), (200, 200), "one attempt and one completion per row");
    assert_eq!(rust["teacher"], python["teacher"], "the teacher identity");
    assert_eq!(identity, python["teacher"]);
    for key in ["schema", "bank_sha256", "boundary"] {
        assert_eq!(rust[key], python[key], "{key}");
    }
    let (rows, expected) = (rust["rows"].as_array().unwrap(), python["rows"].as_array().unwrap());
    assert_eq!(rows.len(), expected.len());
    let (mut exact, mut bitwise, mut within, mut max_error, mut eligible) = (0usize, 0usize, 0usize, 0f64, 0usize);
    let mut failures = Vec::new();
    for (rust_row, python_row) in rows.iter().zip(expected) {
        let same = ["id", "packed", "confidence", "eligible"].iter().all(|key| rust_row[*key] == python_row[*key]);
        exact += usize::from(same);
        if !same {
            failures.push(format!("{}: Rust {rust_row} against Python {python_row}", python_row["id"]));
        }
        eligible += usize::from(python_row["eligible"].as_bool().unwrap());
        for key in ["margin", "sensitivity_gap"] {
            let (a, b) = (rust_row[key].as_f64().unwrap(), python_row[key].as_f64().unwrap());
            let error = (a - b).abs() / b.abs().max(1.0);
            bitwise += usize::from(a.to_bits() == b.to_bits());
            within += usize::from(error <= 1e-6);
            max_error = max_error.max(error);
        }
    }
    eprintln!(
        "reference preparation: {} rows ({eligible} eligible), packed/confidence/eligibility equal {exact}; margins and gaps: {within} of {} within 1e-6, {bitwise} bitwise equal, max relative error {max_error:.3e}; payload byte-equal: {}",
        rows.len(),
        2 * rows.len(),
        payload.as_bytes() == file.as_slice()
    );
    assert!(failures.is_empty(), "{} rows differ, first: {:?}", failures.len(), failures.iter().take(5).collect::<Vec<_>>());
    assert_eq!(within, 2 * rows.len(), "margins and gaps within 1e-6");
}
