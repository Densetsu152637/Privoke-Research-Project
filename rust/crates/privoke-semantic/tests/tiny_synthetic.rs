//! Legacy Tiny inference against the Python runtime (NumPy CPU path), semantic-only golden from
//! `evaluation/generate_semantic_golden.py synthetic`:
//!
//! * two seeded synthetic artifacts, one per readout (`legacy_pool_v1` and `residual_task_query_v1`), and
//! * the four tracked legacy models (`models/privoke-*.json`) on the same synthetic prompts.

#![allow(clippy::unwrap_used, clippy::expect_used)]

#[macro_use]
mod common;

use common::{Report, check_tiny_row, fixtures, read_json, repo_root};
use privoke_contracts::digest::sha256_hex;
use privoke_semantic::TinyModel;
use privoke_semantic::tiny::Readout;

fn replay(model: &TinyModel, rows: &[serde_json::Value], label: &str) -> Report {
    let mut report = Report::default();
    for row in rows {
        check_tiny_row(model, row, &mut report);
    }
    report.assert_clean(label);
    report
}

#[test]
fn legacy_readout_matches_numpy() {
    let model = TinyModel::from_file(&fixtures().join("tiny_synthetic_legacy.json")).unwrap();
    assert_eq!(model.config().readout, Readout::LegacyPool);
    let golden = read_json(&fixtures().join("tiny_synthetic_legacy.golden.json"));
    assert_eq!(golden["meta"]["layers"], serde_json::json!(["semantic"]));
    let report = replay(&model, golden["rows"].as_array().unwrap(), "tiny legacy readout");
    assert!(report.finding_rows > 100);
}

#[test]
fn task_query_readout_matches_numpy() {
    let model = TinyModel::from_file(&fixtures().join("tiny_synthetic_task_query.json")).unwrap();
    assert_eq!(model.config().readout, Readout::TaskQuery);
    let golden = read_json(&fixtures().join("tiny_synthetic_task_query.golden.json"));
    let report = replay(&model, golden["rows"].as_array().unwrap(), "tiny task-query readout");
    assert!(report.finding_rows > 100);
}

#[test]
fn tracked_legacy_models_match_numpy() {
    let golden = read_json(&fixtures().join("tiny_tracked.golden.json"));
    let models = golden["models"].as_object().unwrap();
    assert_eq!(models.len(), 4);
    for (name, rows) in models {
        let path = repo_root().join("models").join(format!("{name}.json"));
        // Git checks text files out with CRLF on Windows; the golden hashes the LF form.
        let bytes: Vec<u8> = std::fs::read(&path).unwrap().into_iter().filter(|byte| *byte != 13).collect();
        assert_eq!(Some(sha256_hex(&bytes).as_str()), golden["meta"]["sha256"][name].as_str(), "{name} changed since the golden was made");
        let model = TinyModel::from_file(&path).unwrap();
        replay(&model, rows.as_array().unwrap(), &format!("tiny {name}"));
    }
}

#[test]
fn artifacts_with_the_wrong_architecture_or_tensors_are_refused() {
    let path = fixtures().join("tiny_synthetic_task_query.json");
    let artifact = read_json(&path);

    let mut wrong = artifact.clone();
    wrong["architecture"] = "privoke_tiny_transformer_v1".into();
    assert!(TinyModel::from_artifact(&wrong).is_err(), "readout and architecture must agree");

    let mut missing = artifact.clone();
    missing["parameters"].as_object_mut().unwrap().remove("readout.category.query");
    assert!(TinyModel::from_artifact(&missing).is_err());

    let mut extra = artifact.clone();
    extra["parameters"]["unexpected"] = serde_json::json!({"shape": [1], "values": [0.0]});
    assert!(TinyModel::from_artifact(&extra).is_err());

    let mut shape = artifact.clone();
    shape["parameters"]["token_embedding"]["shape"] = serde_json::json!([1, 1]);
    assert!(TinyModel::from_artifact(&shape).is_err());

    let mut labels = artifact.clone();
    labels["config"]["category_labels"] = serde_json::json!(["HEALTH"]);
    assert!(TinyModel::from_artifact(&labels).is_err());

    let mut threshold = artifact;
    threshold["config"]["category_threshold"] = serde_json::json!(1.0);
    assert!(TinyModel::from_artifact(&threshold).is_err());
}
