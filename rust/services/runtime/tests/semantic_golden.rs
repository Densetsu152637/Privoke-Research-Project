//! The semantic layer of the Rust worker against the Python `PrivokeRuntimeService`, on the four tracked legacy models.
//!
//! `evaluation/generate_runtime_golden.py semantic` runs the unchanged Python servicer on 135 requests with explicit
//! layer selections. The `llm_only` rows select exactly `DETECTION_LAYER_SEMANTIC` and the generator asserted that the
//! returned execution is that one layer; here the Rust response must show the same. The `product_pipeline` rows add the
//! regex and NER layers (spaCy replayed) and are reported apart, never as LLM-only evidence.
//!
//! Semantic responses are compared by the rule of `tests/conformance/normalization.toml` (`[analysis_runtime]`): every
//! decision field and every text exactly, floats (confidence, category probabilities) after rounding to 6 decimal
//! places or within an absolute 1e-5, the 4-decimal category probabilities within one unit of their last digit.
//! Responses that happen to be byte-identical are counted too.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::path::PathBuf;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use privoke_contracts::proto::v1::{AnalyzePromptResponse, RuntimeDetectionResult};
use privoke_ner_layer::EntityNerDetector;
use privoke_ner_layer::replay::ReplayAnalyzer;
use privoke_rules::{Detector, RuleSetOptions};
use privoke_runtime::frames::{self, HEADER_LEN, Kind};
use privoke_runtime::semantic::SemanticLayer;
use privoke_runtime::{Pipeline, PipelineOptions, Service, ServiceOptions};
use prost::Message;
use serde_json::Value;

fn fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/runtime_semantic_golden.json")).expect("the fixture is JSON")
}

fn decode(value: &Value) -> Vec<u8> {
    STANDARD.decode(value.as_str().expect("base64 text")).expect("valid base64")
}

fn models() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../models")
}

fn close(a: f64, b: f64) -> bool {
    let round = |v: f64| format!("{v:.6}");
    (a - b).abs() <= 1e-5 || round(a) == round(b)
}

fn metadata_matches(a: &BTreeMap<String, String>, b: &BTreeMap<String, String>) -> Result<(), String> {
    if a.keys().ne(b.keys()) {
        return Err(format!("metadata keys differ: {:?} against {:?}", a.keys().collect::<Vec<_>>(), b.keys().collect::<Vec<_>>()));
    }
    for (key, left) in a {
        let right = &b[key];
        if key == "category_probabilities" {
            let (l, r): (Value, Value) = (serde_json::from_str(left).unwrap(), serde_json::from_str(right).unwrap());
            let (l, r) = (l.as_object().unwrap(), r.as_object().unwrap());
            if l.keys().ne(r.keys()) {
                return Err("category_probabilities labels differ".to_string());
            }
            for (label, value) in l {
                let (x, y) = (value.as_f64().unwrap(), r[label].as_f64().unwrap());
                if (x - y).abs() > 1.0e-4 + 1.0e-9 {
                    return Err(format!("category probability {label}: {x} against {y}"));
                }
            }
        } else if left != right {
            return Err(format!("metadata {key}: {left:?} against {right:?}"));
        }
    }
    Ok(())
}

fn result_matches(a: &RuntimeDetectionResult, b: &RuntimeDetectionResult) -> Result<(), String> {
    if a.classification != b.classification || a.action != b.action {
        return Err(format!("decision differs: {:?}/{} against {:?}/{}", a.classification, a.action, b.classification, b.action));
    }
    if (&a.section_of_text, a.span_start, a.span_end, a.has_span, a.has_confidence, &a.reasoning)
        != (&b.section_of_text, b.span_start, b.span_end, b.has_span, b.has_confidence, &b.reasoning)
    {
        return Err(format!("finding differs: {:?} against {:?}", a.reasoning, b.reasoning));
    }
    if !close(a.confidence, b.confidence) {
        return Err(format!("confidence {} against {}", a.confidence, b.confidence));
    }
    metadata_matches(&a.metadata, &b.metadata)
}

fn response_matches(a: &AnalyzePromptResponse, b: &AnalyzePromptResponse) -> Result<(), String> {
    let exact = |name: &str, x: &dyn std::fmt::Debug, y: &dyn std::fmt::Debug, same: bool| {
        if same { Ok(()) } else { Err(format!("{name}: {x:?} against {y:?}")) }
    };
    exact("request_id", &a.request_id, &b.request_id, a.request_id == b.request_id)?;
    exact("action", &a.action, &b.action, a.action == b.action)?;
    exact("allowed", &a.allowed, &b.allowed, a.allowed == b.allowed)?;
    exact("masked_text", &a.masked_text, &b.masked_text, a.masked_text == b.masked_text)?;
    exact("classification", &a.classification, &b.classification, a.classification == b.classification)?;
    exact("reason", &a.reason, &b.reason, a.reason == b.reason)?;
    exact("error", &a.error, &b.error, a.error == b.error)?;
    match (&a.evidence, &b.evidence) {
        (Some(x), Some(y)) => result_matches(x, y).map_err(|e| format!("evidence: {e}"))?,
        (None, None) => {}
        _ => return Err("evidence present on one side only".to_string()),
    }
    metadata_matches(&a.metadata, &b.metadata).map_err(|e| format!("response {e}"))?;
    if a.layers.len() != b.layers.len() {
        return Err("layer count differs".to_string());
    }
    for (x, y) in a.layers.iter().zip(&b.layers) {
        if (x.layer, &x.status, &x.error, x.results.len()) != (y.layer, &y.status, &y.error, y.results.len()) {
            return Err(format!("layer execution {:?}/{} against {:?}/{}", x.layer, x.status, y.layer, y.status));
        }
        for (p, q) in x.results.iter().zip(&y.results) {
            result_matches(p, q).map_err(|e| format!("layer {}: {e}", x.layer))?;
        }
    }
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn semantic_selections_match_python_on_the_tracked_models() {
    let fixture = fixture();
    let lexicon: Vec<String> = fixture["lexicon"].as_array().unwrap().iter().map(|w| w.as_str().unwrap().to_owned()).collect();
    let replay = ReplayAnalyzer::new(fixture["spacy"].as_array().unwrap(), lexicon).unwrap();
    let ner = EntityNerDetector::new(replay, "en_core_web_sm").await.unwrap();
    let regex = Detector::new(RuleSetOptions::from_lookup(&|_| None)).unwrap();
    let semantic = SemanticLayer::new(vec![models()], None).unwrap();
    let pipeline = Pipeline::new(regex, ner, PipelineOptions::default()).with_semantic(semantic);
    let service = Service::new(pipeline, ServiceOptions { clear_elapsed: true, ..ServiceOptions::default() });

    let cases = fixture["cases"].as_array().unwrap();
    assert!(cases.len() >= 130, "{} cases", cases.len());
    let mut counts: BTreeMap<String, [usize; 3]> = BTreeMap::new();
    let mut failures = Vec::new();
    for (index, case) in cases.iter().enumerate() {
        let id = case["id"].as_str().unwrap();
        let answer = service.handle_frame(&frames::encode_frame(Kind::Request, 1, index as u64 + 1, &decode(&case["request"]))).await;
        let entry = counts.entry(case["scope"].as_str().unwrap().to_owned()).or_default();
        entry[0] += 1;
        if answer[5] != Kind::Response as u8 {
            failures.push(format!("{id}: error frame {}", String::from_utf8_lossy(&answer[HEADER_LEN..])));
            continue;
        }
        let payload = &answer[HEADER_LEN..];
        let expected = decode(&case["response"]);
        let (got, want) = (AnalyzePromptResponse::decode(payload).unwrap(), AnalyzePromptResponse::decode(expected.as_slice()).unwrap());
        if case["scope"] == "llm_only" && got.error.is_empty() {
            let executed: Vec<(i32, &str)> = got.layers.iter().map(|l| (l.layer, l.status.as_str())).collect();
            assert_eq!(executed, vec![(4, "ok")], "{id}: an LLM-only row must execute exactly the semantic layer");
        }
        match response_matches(&got, &want) {
            Ok(()) => {
                entry[1] += 1;
                if payload == expected.as_slice() {
                    entry[2] += 1;
                }
            }
            Err(reason) => failures.push(format!("{id}: {reason}")),
        }
    }
    for (scope, [total, matched, identical]) in &counts {
        eprintln!("runtime semantic golden: {scope}: {matched} of {total} within the declared rule, {identical} byte-identical");
    }
    assert!(
        failures.is_empty(),
        "{} differences, first:\n{}",
        failures.len(),
        failures.iter().take(5).cloned().collect::<Vec<_>>().join("\n")
    );
}

#[tokio::test(flavor = "current_thread")]
async fn without_model_roots_or_with_a_gate_the_semantic_layer_is_refused_for_routing() {
    let fixture = fixture();
    let ner = EntityNerDetector::new(ReplayAnalyzer::new(&[], Vec::new()).unwrap(), "en_core_web_sm").await.unwrap();
    let regex = Detector::new(RuleSetOptions::from_lookup(&|_| None)).unwrap();
    let service = Service::new(Pipeline::new(regex, ner, PipelineOptions::default()), ServiceOptions::default());
    let case = &fixture["cases"].as_array().unwrap()[0];
    let answer = service.handle_frame(&frames::encode_frame(Kind::Request, 1, 1, &decode(&case["request"]))).await;
    assert_eq!(answer[5], Kind::Error as u8);
    assert!(String::from_utf8_lossy(&answer[HEADER_LEN..]).contains("UNSUPPORTED_LAYERS"));
}
