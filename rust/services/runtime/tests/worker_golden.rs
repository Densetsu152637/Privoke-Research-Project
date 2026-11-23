//! `DetectAnnotationPresence` and the presence-gated `AnalyzePrompt` of the Rust worker against the Python worker, over W1
//! frames. The gradient rows of the fixture (methods 4, 5 and 6) are the frozen Python oracle: the worker refuses them.
//!
//! `evaluation/generate_runtime_worker_golden.py write` hands the unchanged Python `worker_main.Dispatcher` the frames
//! recorded in `fixtures/worker_golden.json` (models read from `fixtures/worker_models/` and the tracked legacy models
//! of `models/`, read only) and records the payload or the frame error code it answers. Here the same frames go through
//! `Service::handle_frame`. Every request names its layers explicitly and non-empty: the presence and gradient rows
//! select exactly the semantic layer (LLM only); the gate rows labelled `product_pipeline` add the regex layer and are
//! reported apart.
//!
//! The comparison is the declared rule of `tests/conformance/normalization.toml`: decisions, texts, identities and error
//! messages exactly; probabilities and confidences within 1e-5 (after rounding to 6 decimal places); gradient tensors
//! within an absolute 1e-6; metrics exactly when they count or rate decisions and within 1e-5 (relative) otherwise;
//! metadata strings exactly, except float values (1e-5 relative) and the fingerprints that hash the updated floats, which
//! can differ only when a coordinate is not bitwise equal. Responses that carry no model float must be byte-identical.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use privoke_contracts::proto::v1::{
    AnalyzePromptResponse, DetectAnnotationPresenceResponse, RuntimeDetectionResult, SemanticPresenceGateTrace,
};
use privoke_ner_layer::EntityNerDetector;
use privoke_ner_layer::replay::ReplayAnalyzer;
use privoke_rules::{Detector, RuleSetOptions};
use privoke_runtime::frames::{self, HEADER_LEN, Kind, code};
use privoke_runtime::presence::PresenceModels;
use privoke_runtime::semantic::SemanticLayer;
use privoke_runtime::store::ArtifactStore;
use privoke_runtime::{Pipeline, PipelineOptions, Service, ServiceOptions};
use prost::Message;
use serde_json::Value;

fn fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/worker_golden.json")).expect("the fixture is JSON")
}

fn decode(value: &Value) -> Vec<u8> {
    STANDARD.decode(value.as_str().expect("base64 text")).expect("valid base64")
}

fn roots() -> Vec<PathBuf> {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    vec![manifest.join("tests/fixtures/worker_models"), manifest.join("../../../models")]
}

async fn service() -> Service<ReplayAnalyzer> {
    let ner = EntityNerDetector::new(ReplayAnalyzer::new(&[], Vec::new()).unwrap(), "en_core_web_sm").await.unwrap();
    let regex = Detector::new(RuleSetOptions::from_lookup(&|_| None)).unwrap();
    let store = Arc::new(ArtifactStore::new(roots(), None));
    let pipeline = Pipeline::new(regex, ner, PipelineOptions::default())
        .with_semantic(SemanticLayer::new(roots(), None).unwrap())
        .with_presence(PresenceModels::new(store));
    Service::new(pipeline, ServiceOptions { clear_elapsed: true, ..ServiceOptions::default() })
}

/// The request frame of a recorded case: the metadata block (the training admission header) when the case has one.
fn request_frame(case: &Value, id: u64) -> Vec<u8> {
    let method = u8::try_from(case["method"].as_u64().unwrap()).unwrap();
    let payload = decode(&case["request"]);
    let metadata: Vec<(String, String)> = case["metadata"]
        .as_array()
        .unwrap()
        .iter()
        .map(|pair| (pair[0].as_str().unwrap().to_owned(), pair[1].as_str().unwrap().to_owned()))
        .collect();
    if metadata.is_empty() {
        return frames::encode_frame(Kind::Request, method, id, &payload);
    }
    let pairs: Vec<(&str, &str)> = metadata.iter().map(|(key, value)| (key.as_str(), value.as_str())).collect();
    let mut body = frames::encode_metadata(&pairs);
    body.extend_from_slice(&payload);
    let mut frame = frames::encode_frame(Kind::Request, method, id, &body);
    frame[7] = 1;
    frame
}

fn error_code(answer: &[u8]) -> String {
    assert_eq!(answer[5], Kind::Error as u8, "an error frame was expected, got {}", String::from_utf8_lossy(&answer[HEADER_LEN..]));
    let body: Value = serde_json::from_slice(&answer[HEADER_LEN..]).expect("the error body is JSON");
    body["code"].as_str().expect("a code").to_owned()
}

/// Confidences and probabilities: equal after rounding to 6 decimal places, or within an absolute 1e-5.
fn close(a: f64, b: f64) -> bool {
    (a - b).abs() <= 1e-5 || format!("{a:.6}") == format!("{b:.6}")
}

fn optional_close(name: &str, a: Option<f64>, b: Option<f64>) -> Result<(), String> {
    match (a, b) {
        (None, None) => Ok(()),
        (Some(x), Some(y)) if close(x, y) => Ok(()),
        _ => Err(format!("{name}: {a:?} against {b:?}")),
    }
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

fn trace_matches(a: &SemanticPresenceGateTrace, b: &SemanticPresenceGateTrace) -> Result<(), String> {
    let left = (
        a.status,
        &a.model_id,
        &a.model_version,
        &a.artifact_checksum,
        &a.parameter_fingerprint,
        a.predicted_label,
        &a.error,
        &a.contextual_model_id,
        &a.contextual_model_version,
        &a.contextual_artifact_checksum,
        &a.contextual_parameter_fingerprint,
    );
    let right = (
        b.status,
        &b.model_id,
        &b.model_version,
        &b.artifact_checksum,
        &b.parameter_fingerprint,
        b.predicted_label,
        &b.error,
        &b.contextual_model_id,
        &b.contextual_model_version,
        &b.contextual_artifact_checksum,
        &b.contextual_parameter_fingerprint,
    );
    if left != right {
        return Err(format!("gate trace identity differs: {left:?} against {right:?}"));
    }
    optional_close("gate probability", a.probability, b.probability)?;
    optional_close("gate model_threshold", a.model_threshold, b.model_threshold)?;
    optional_close("gate decision_threshold", a.decision_threshold, b.decision_threshold)?;
    if a.semantic_results.len() != b.semantic_results.len() {
        return Err("gate semantic result count differs".to_string());
    }
    for (x, y) in a.semantic_results.iter().zip(&b.semantic_results) {
        result_matches(x, y).map_err(|reason| format!("gate semantic result: {reason}"))?;
    }
    Ok(())
}

fn analysis_matches(a: &AnalyzePromptResponse, b: &AnalyzePromptResponse) -> Result<(), String> {
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
        match (&x.semantic_presence_gate, &y.semantic_presence_gate) {
            (Some(p), Some(q)) => trace_matches(p, q).map_err(|e| format!("layer {}: {e}", x.layer))?,
            (None, None) => {}
            _ => return Err(format!("layer {}: a gate trace on one side only", x.layer)),
        }
    }
    Ok(())
}

fn presence_matches(a: &DetectAnnotationPresenceResponse, b: &DetectAnnotationPresenceResponse) -> Result<(), String> {
    let left = (
        &a.request_id,
        &a.model_id,
        &a.model_version,
        a.predicted_label,
        &a.artifact_checksum,
        &a.parameter_fingerprint,
        &a.error,
        &a.executions,
    );
    let right = (
        &b.request_id,
        &b.model_id,
        &b.model_version,
        b.predicted_label,
        &b.artifact_checksum,
        &b.parameter_fingerprint,
        &b.error,
        &b.executions,
    );
    if left != right {
        return Err(format!("presence response differs: {left:?} against {right:?}"));
    }
    if !close(a.probability, b.probability) || !close(a.threshold, b.threshold) {
        return Err(format!("probability {} against {}, threshold {} against {}", a.probability, b.probability, a.threshold, b.threshold));
    }
    Ok(())
}

#[derive(Default)]
struct Counts {
    total: usize,
    matched: usize,
    identical: usize,
}

#[tokio::test(flavor = "current_thread")]
async fn every_recorded_answer_matches_the_python_worker() {
    let fixture = fixture();
    let service = service().await;
    let cases = fixture["cases"].as_array().unwrap();
    assert!(cases.len() >= 150, "{} cases", cases.len());
    let mut counts: BTreeMap<String, Counts> = BTreeMap::new();
    let mut failures = Vec::new();
    for (index, case) in cases.iter().enumerate() {
        let id = case["id"].as_str().unwrap();
        let method = case["method"].as_u64().unwrap();
        let answer = service.handle_frame(&request_frame(case, index as u64 + 1)).await;
        let entry = counts.entry(format!("{}/{}", case["scope"].as_str().unwrap(), method)).or_default();
        entry.total += 1;
        if [4, 5, 6].contains(&method) {
            // The gradient methods were removed (stages V3-R8a and V3-R8b, decision U4): the Python rows stay as the frozen
            // oracle, and the worker refuses every one of them without reading the request or any model.
            let got = error_code(&answer);
            if got == code::UNKNOWN_METHOD {
                entry.matched += 1;
                entry.identical += 1;
            } else {
                failures.push(format!("{id}: a gradient method answered {got}, expected {}", code::UNKNOWN_METHOD));
            }
            continue;
        }
        if let Some(expected) = case.get("error_code") {
            // A frame the worker refuses: the same code, and nothing was run.
            let got = error_code(&answer);
            if got == expected.as_str().unwrap() {
                entry.matched += 1;
                entry.identical += 1;
            } else {
                failures.push(format!("{id}: error frame {got}, expected {expected}"));
            }
            continue;
        }
        if answer[5] != Kind::Response as u8 {
            failures.push(format!("{id}: error frame {}", String::from_utf8_lossy(&answer[HEADER_LEN..])));
            continue;
        }
        let payload = &answer[HEADER_LEN..];
        let expected = decode(&case["response"]);
        let outcome: Result<(), String> = match method {
            1 => {
                let (got, want) =
                    (AnalyzePromptResponse::decode(payload).unwrap(), AnalyzePromptResponse::decode(expected.as_slice()).unwrap());
                if case["scope"] == "llm_only" && got.error.is_empty() {
                    let executed: Vec<(i32, &str)> = got.layers.iter().map(|l| (l.layer, l.status.as_str())).collect();
                    assert_eq!(executed, vec![(4, "ok")], "{id}: an LLM-only row must execute exactly the semantic layer");
                }
                analysis_matches(&got, &want)
            }
            2 => presence_matches(
                &DetectAnnotationPresenceResponse::decode(payload).unwrap(),
                &DetectAnnotationPresenceResponse::decode(expected.as_slice()).unwrap(),
            ),
            other => panic!("{id}: method {other}"),
        };
        match outcome {
            Ok(()) => {
                entry.matched += 1;
                entry.identical += usize::from(payload == expected.as_slice());
                // A response that carries no model float is byte-identical: every refusal is.
                let carries_floats = method == 1 && !AnalyzePromptResponse::decode(payload).unwrap().layers.is_empty();
                if case["scope"] == "validation" && !carries_floats && payload != expected.as_slice() {
                    failures.push(format!("{id}: a validation response is not byte-identical"));
                }
            }
            Err(reason) => failures.push(format!("{id}: {reason}")),
        }
    }
    for (scope, counts) in &counts {
        eprintln!(
            "worker golden: {scope}: {} of {} within the declared rule, {} byte-identical",
            counts.matched, counts.total, counts.identical
        );
    }
    assert!(
        failures.is_empty(),
        "{} differences, first:\n{}",
        failures.len(),
        failures.iter().take(8).cloned().collect::<Vec<_>>().join("\n")
    );
}

fn frame_of(method: u8, metadata: &[(&str, &str)], payload: &[u8], request_id: u64) -> Vec<u8> {
    if metadata.is_empty() {
        return frames::encode_frame(Kind::Request, method, request_id, payload);
    }
    let mut body = frames::encode_metadata(metadata);
    body.extend_from_slice(payload);
    let mut frame = frames::encode_frame(Kind::Request, method, request_id, &body);
    frame[7] = 1;
    frame
}

#[tokio::test(flavor = "current_thread")]
async fn a_worker_without_model_roots_refuses_what_reads_a_model_before_anything_runs() {
    let fixture = fixture();
    let ner = EntityNerDetector::new(ReplayAnalyzer::new(&[], Vec::new()).unwrap(), "en_core_web_sm").await.unwrap();
    let regex = Detector::new(RuleSetOptions::from_lookup(&|_| None)).unwrap();
    let service = Service::new(Pipeline::new(regex, ner, PipelineOptions::default()), ServiceOptions::default());
    for (index, case) in fixture["cases"].as_array().unwrap().iter().enumerate() {
        let method = case["method"].as_u64().unwrap();
        if case.get("error_code").is_some() || method != 2 {
            continue;
        }
        let answer = service.handle_frame(&request_frame(case, index as u64 + 1)).await;
        assert_eq!(error_code(&answer), code::UNSUPPORTED_ROUTE, "{}", case["id"]);
    }
    let gated = fixture["cases"].as_array().unwrap().iter().find(|case| case["id"].as_str().unwrap().starts_with("gate/")).unwrap();
    assert_eq!(error_code(&service.handle_frame(&request_frame(gated, 7)).await), code::UNSUPPORTED_LAYERS);
}

#[tokio::test(flavor = "current_thread")]
async fn an_empty_layer_selection_never_reaches_a_model() {
    use privoke_contracts::proto::v1::{ComputePresenceGradientsRequest, ComputeSemanticGradientsRequest, DetectAnnotationPresenceRequest};
    let service = service().await;
    let presence = DetectAnnotationPresenceRequest {
        request_id: "r".into(),
        text: "my passport".into(),
        model_id: "privoke-presence-efficient".into(),
        layers: Vec::new(),
    };
    let answer = service.handle_frame(&frame_of(2, &[], &presence.encode_to_vec(), 1)).await;
    assert_eq!(error_code(&answer), code::INVALID_LAYERS);
    // The gradient methods are removed: an unknown method, whatever the layers, and no model is read.
    for method in [4u8, 5] {
        let request =
            ComputeSemanticGradientsRequest { request_id: "r".into(), model_id: "synthetic-legacy-mean".into(), ..Default::default() };
        let answer = service.handle_frame(&frame_of(method, &[], &request.encode_to_vec(), 2)).await;
        assert_eq!(error_code(&answer), code::UNKNOWN_METHOD);
    }
    let request =
        ComputePresenceGradientsRequest { request_id: "r".into(), model_id: "privoke-presence-efficient".into(), ..Default::default() };
    assert_eq!(error_code(&service.handle_frame(&frame_of(6, &[], &request.encode_to_vec(), 3)).await), code::UNKNOWN_METHOD);
}
