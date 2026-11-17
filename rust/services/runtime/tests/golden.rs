//! Byte parity of the serialised `AnalyzePromptResponse` with the Python `PrivokeRuntimeService`, for explicit regex and
//! NER selections, replaying the spaCy results Python saw (no interpreter).
//!
//! The fixture is written by `evaluation/generate_runtime_golden.py write`: for every request, the Python servicer's
//! response serialised deterministically with the wall-clock fields cleared. The same bytes come out of
//! `handle_frame` here, through the W1 frame codec. Selections that name the semantic layer are not in the fixture
//! (the Rust worker does not serve them), so these results are detector ablations or product-pipeline rows and never
//! LLM-only evidence.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use privoke_ner_layer::EntityNerDetector;
use privoke_ner_layer::replay::ReplayAnalyzer;
use privoke_rules::{Detector, RuleSetOptions};
use privoke_runtime::frames::{self, HEADER_LEN, Kind};
use privoke_runtime::{Pipeline, PipelineOptions, Service, ServiceOptions};
use serde_json::Value;
use sha2::{Digest, Sha256};

fn fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/runtime_golden.json")).expect("the fixture is JSON")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn sha256_hex(data: &[u8]) -> String {
    hex(&Sha256::digest(data))
}

fn decode(value: &Value) -> Vec<u8> {
    STANDARD.decode(value.as_str().expect("base64 text")).expect("valid base64")
}

async fn service(fixture: &Value, options: ServiceOptions) -> Service<ReplayAnalyzer> {
    let lexicon: Vec<String> =
        fixture["lexicon"].as_array().expect("lexicon").iter().map(|w| w.as_str().expect("word").to_owned()).collect();
    let records = fixture["spacy"].as_array().expect("spaCy records");
    let replay = ReplayAnalyzer::new(records, lexicon).expect("recorded analyses decode");
    let ner = EntityNerDetector::new(replay, "en_core_web_sm").await.expect("the lexicon loads");
    let regex = Detector::new(RuleSetOptions::from_lookup(&|_| None)).expect("the rules compile");
    Service::new(Pipeline::new(regex, ner, PipelineOptions::default()), options)
}

fn request_frame(id: u64, payload: &[u8]) -> Vec<u8> {
    frames::encode_frame(Kind::Request, 1, id, payload)
}

#[tokio::test(flavor = "current_thread")]
async fn every_recorded_response_is_byte_identical() {
    let fixture = fixture();
    let service = service(&fixture, ServiceOptions { clear_elapsed: true, ..ServiceOptions::default() }).await;
    let cases = fixture["cases"].as_array().expect("cases");
    assert!(cases.len() >= 200, "{} cases", cases.len());
    let mut per_scope: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    let mut failures = Vec::new();
    let mut capture_checked = 0;
    for (index, case) in cases.iter().enumerate() {
        let id = case["id"].as_str().expect("id");
        let answer = service.handle_frame(&request_frame(index as u64 + 1, &decode(&case["request"]))).await;
        let entry = per_scope.entry(case["scope"].as_str().expect("scope").to_owned()).or_default();
        entry.0 += 1;
        if answer[5] != Kind::Response as u8 {
            failures.push(format!("{id}: error frame {}", String::from_utf8_lossy(&answer[HEADER_LEN..])));
            continue;
        }
        let payload = &answer[HEADER_LEN..];
        let expected = decode(&case["response"]);
        if payload == expected.as_slice() {
            entry.1 += 1;
        } else {
            failures.push(format!(
                "{id}: {} bytes against {} recorded\n  got      {}\n  expected {}",
                payload.len(),
                expected.len(),
                hex(payload),
                hex(&expected)
            ));
        }
        if let Some(digest) = case.get("capture_sha256").and_then(Value::as_str) {
            capture_checked += 1;
            assert_eq!(sha256_hex(payload), digest, "{id} differs from the W1 capture of the Python worker");
        }
    }
    for (scope, (total, identical)) in &per_scope {
        eprintln!("runtime golden: {scope}: {identical} of {total} responses byte-identical");
    }
    eprintln!("runtime golden: {capture_checked} responses equal the W1 capture digests");
    assert!(
        failures.is_empty(),
        "{} differences, first:\n{}",
        failures.len(),
        failures.iter().take(3).cloned().collect::<Vec<_>>().join("\n")
    );
    assert!(capture_checked >= 60, "{capture_checked} capture digests");
}

#[tokio::test(flavor = "current_thread")]
async fn the_measured_elapsed_time_is_the_only_difference() {
    let fixture = fixture();
    let cleared = service(&fixture, ServiceOptions { clear_elapsed: true, ..ServiceOptions::default() }).await;
    let measured = service(&fixture, ServiceOptions::default()).await;
    let case = fixture["cases"].as_array().expect("cases").iter().find(|c| c["id"] == "person-organisation/regex+ner").expect("case");
    let request = request_frame(9, &decode(&case["request"]));
    let (a, b) = (cleared.handle_frame(&request).await, measured.handle_frame(&request).await);
    assert!(b.len() > a.len(), "the measured response carries elapsed_ms twice");
}

#[test]
fn the_float_rule_and_the_byte_equal_selections_are_declared() {
    let declared = include_str!("../../../../tests/conformance/normalization.toml");
    let section = declared.split("[analysis_runtime]").nth(1).expect("the analysis_runtime section exists");
    for line in [
        "float_decimal_places = 6",
        "float_absolute_tolerance = 1e-5",
        r#"cleared_fields = ["elapsed_ms", "metadata.elapsed_ms"]"#,
        r#"byte_equal_selections = ["regex", "ner", "regex+ner"]"#,
        r#"llm_only_selections = ["semantic"]"#,
    ] {
        assert!(section.contains(line), "normalization.toml does not declare {line}");
    }
}
