//! Parity of the Rust port with the Python regex layer.
//!
//! * `rule_inventory`: every shipped rule, in order, equals the Python registry.
//! * `synthetic_golden`: the committed synthetic corpus, all configurations.
//! * `recorded_sets_golden`: the recorded detector sets, when `PRIVOKE_RULES_GOLDEN_DIR` points
//!   at a directory written by `evaluation/generate_rules_golden.py sets` (ignored by Git).

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::io::{BufRead, BufReader};
use std::path::PathBuf;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use common::{Detectors, Tally, compare_row};
use privoke_rules::{Detector, RuleSetOptions};
use serde_json::Value;
use sha2::{Digest, Sha256};

fn fixture(name: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(name);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    // Fixtures with token-shaped text are stored base64-encoded.
    let text = match path.extension().is_some_and(|ext| ext == "b64") {
        true => String::from_utf8(BASE64.decode(text.trim()).expect("base64 fixture")).expect("utf-8 fixture"),
        false => text,
    };
    serde_json::from_str(&text).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

#[test]
fn rule_inventory() {
    let inventory = fixture("rule_inventory.json");
    let expected = inventory.as_array().expect("array");
    let detector = Detector::new(RuleSetOptions::default()).expect("detector");
    let rules = detector.rules();
    assert_eq!(rules.len(), expected.len(), "rule count");
    for (index, (rule, want)) in rules.iter().zip(expected).enumerate() {
        let definition = &rule.definition;
        let context = format!("rule {index} {}", definition.name);
        assert_eq!(want["name"].as_str(), Some(definition.name.as_str()), "{context}: name");
        assert_eq!(want["signal"].as_str(), Some(definition.signal.as_str()), "{context}: signal");
        assert_eq!(want["packed"].as_u64(), Some(u64::from(definition.classification.pack())), "{context}: classification");
        assert_eq!(want["validator"].as_bool(), Some(definition.validator.is_some()), "{context}: validator");
        let digest: String = Sha256::digest(definition.pattern.as_bytes()).iter().map(|byte| format!("{byte:02x}")).collect();
        assert_eq!(want["pattern_sha256"].as_str(), Some(digest.as_str()), "{context}: pattern text");
        if let Some(pattern) = want["pattern"].as_str() {
            assert_eq!(pattern, definition.pattern, "{context}: pattern");
        }
        let downgrades = want["downgrades"].as_array().expect("downgrades");
        assert_eq!(downgrades.len(), definition.downgrades.len(), "{context}: downgrade count");
        for (got, want) in definition.downgrades.iter().zip(downgrades) {
            assert_eq!(want["name"].as_str(), Some(got.name), "{context}: downgrade name");
            assert_eq!(want["signal"].as_str(), Some(got.signal), "{context}: downgrade signal");
            assert_eq!(want["packed"].as_u64(), Some(u64::from(got.classification.pack())), "{context}: downgrade classification");
            assert_eq!(want["confidence"].as_f64(), Some(got.confidence), "{context}: downgrade confidence");
            assert_eq!(want["accept"].as_bool(), Some(got.accept.is_some()), "{context}: downgrade accept");
        }
    }
}

#[test]
fn no_rule_matches_the_empty_string() {
    let detector = Detector::new(RuleSetOptions::default()).expect("detector");
    for rule in detector.rules() {
        let hay = privoke_rules::pyre::Haystack::new("");
        assert!(rule.regex.search(&hay).expect("search").is_none(), "{} matches the empty text", rule.definition.name);
    }
}

#[test]
fn synthetic_golden() {
    let golden = fixture("synthetic_golden.b64");
    let rows = golden["rows"].as_array().expect("rows");
    let mut detectors = Detectors::default();
    let (mut norm, mut layer) = (Tally::default(), Tally::default());
    for row in rows {
        compare_row(row, &mut detectors, &mut norm, &mut layer);
    }
    assert!(
        norm.differences.is_empty(),
        "normalisation differences ({} of {}):\n{}",
        norm.differences.len(),
        norm.compared,
        norm.differences.join("\n")
    );
    assert!(
        layer.differences.is_empty(),
        "layer differences ({} of {}):\n{}",
        layer.differences.len(),
        layer.compared,
        layer.differences.join("\n")
    );
    assert!(norm.compared >= rows.len() * 7 && layer.compared >= rows.len() * 9);
}

#[test]
fn recorded_sets_golden() {
    let Some(dir) = std::env::var_os("PRIVOKE_RULES_GOLDEN_DIR") else {
        eprintln!("PRIVOKE_RULES_GOLDEN_DIR is not set: recorded-set parity not run");
        return;
    };
    let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)
        .expect("golden dir")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "jsonl") && path.file_name().is_some_and(|n| n != "unicode_sweep.jsonl"))
        .collect();
    files.sort();
    let mut detectors = Detectors::default();
    let mut failures = Vec::new();
    for file in files {
        let reader = BufReader::new(std::fs::File::open(&file).expect("open golden"));
        let (mut norm, mut layer) = (Tally::default(), Tally::default());
        for line in reader.lines().map_while(Result::ok).filter(|line| !line.trim().is_empty()) {
            let row: Value = serde_json::from_str(&line).expect("golden row");
            compare_row(&row, &mut detectors, &mut norm, &mut layer);
        }
        eprintln!(
            "{}: normalisation {}/{} identical, layer {}/{} identical",
            file.file_stem().and_then(|s| s.to_str()).unwrap_or("?"),
            norm.identical,
            norm.compared,
            layer.identical,
            layer.compared
        );
        if norm.identical != norm.compared || layer.identical != layer.compared {
            failures.push(format!("{}:\n{}\n{}", file.display(), norm.differences.join("\n"), layer.differences.join("\n")));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
