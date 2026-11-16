//! Parity with Python on the committed synthetic fixture, with the spaCy results Python saw replayed (no worker).
//!
//! The fixture is written by `evaluation/generate_ner_golden.py synthetic`: generic sentences, the NER layer's results
//! and post-filter decision log for every configuration (default, caseless, each robustness flag, all flags,
//! lower-cased input, no post-filter), and the pattern detector's results for its configurations.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::collections::HashSet;
use std::sync::Arc;

use base64::Engine as _;
use privoke_ner_layer::replay::ReplayAnalyzer;
use serde_json::Value;

fn fixture() -> Value {
    let encoded = include_str!("fixtures/synthetic_golden.b64");
    let bytes = base64::engine::general_purpose::STANDARD.decode(encoded.trim()).expect("fixture is base64");
    serde_json::from_slice(&bytes).expect("fixture is JSON")
}

#[tokio::test]
async fn synthetic_rows_match_python_in_every_configuration() {
    let fixture = fixture();
    let lexicon: Vec<String> =
        fixture["lexicon"].as_array().expect("lexicon").iter().map(|w| w.as_str().expect("word").to_owned()).collect();
    let lexicon_set: Arc<HashSet<String>> = Arc::new(lexicon.iter().cloned().collect());
    let rows = fixture["rows"].as_array().expect("rows");
    assert!(rows.len() >= 100);
    let mut layer_runs = 0;
    let mut pattern_runs = 0;
    let mut failures = Vec::new();
    for row in rows {
        let records = row["spacy"].as_array().expect("spacy records");
        let replay = ReplayAnalyzer::new(records, lexicon.clone()).expect("recorded analyses decode");
        let report = common::check_row(&replay, lexicon_set.clone(), "en_core_web_sm", row, false).await;
        layer_runs += report.layer.len();
        pattern_runs += report.pattern.len();
        for (name, same) in report.layer.iter().chain(report.pattern.iter()) {
            if !same {
                failures.push(format!("row {} {name}", row["id"]));
            }
        }
        failures.extend(report.diffs);
    }
    assert!(
        failures.is_empty(),
        "{} differences, first:\n{}",
        failures.len(),
        failures.iter().take(8).cloned().collect::<Vec<_>>().join("\n")
    );
    assert_eq!(layer_runs, rows.len() * common::LAYER_CONFIGS.len());
    assert_eq!(pattern_runs, rows.len() * common::PATTERN_CONFIGS.len());
}

#[test]
fn fixture_covers_every_postfilter_rule() {
    let fixture = fixture();
    let mut seen = HashSet::new();
    for row in fixture["rows"].as_array().expect("rows") {
        for config in row["layer"].as_object().expect("layers").values() {
            for decision in config["decisions"].as_array().expect("decisions") {
                seen.insert(decision["rule"].as_str().expect("rule").to_owned());
            }
        }
    }
    for rule in [
        "placeholder",
        "identifier",
        "structural",
        "short_acronym",
        "common_phrase",
        "person_linked",
        "place_org_linked",
        "person_corroborated",
        "relation_tied",
        "relation_anchored",
        "address_shape",
        "weak_person",
        "lone_place_org",
    ] {
        assert!(seen.contains(rule), "the synthetic fixture never decides by {rule}");
    }
}
