//! `DetectAnnotationPresence`, the presence-gated `AnalyzePrompt` and the three gradient RPCs of the Rust worker against the
//! Python worker, over W1 frames.
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
    AnalyzePromptResponse, ComputeSemanticGradientsResponse, DetectAnnotationPresenceResponse, RuntimeDetectionResult,
    SemanticPresenceGateTrace,
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

fn routes_fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/worker_routes_golden.json")).expect("the fixture is JSON")
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
        .with_presence(PresenceModels::new(Arc::clone(&store)));
    Service::new(pipeline, ServiceOptions { clear_elapsed: true, ..ServiceOptions::default() }).with_training(store)
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

/// Metrics that count or rate decisions: any difference is a changed decision.
fn is_decision_metric(key: &str) -> bool {
    key.contains("examples")
        || key.contains("exact_match")
        || key.contains("recall")
        || key.contains("specificity")
        || key.contains("regression_rate")
        || key.contains("clean_examples")
}

/// The metadata keys that carry a JSON trace (`[worker_gradients] json_metadata_keys`).
const JSON_METADATA: [&str; 4] = [
    "contextual_optimizer_trace",
    "contextual_training_diagnostics",
    "contextual_training_backtracking_trace",
    "contextual_training_backtracking_trials",
];

#[derive(Default)]
struct GradientTally {
    coordinates: usize,
    within: usize,
    bitwise: usize,
    max_error: f64,
    metrics: usize,
    metrics_close: usize,
    fingerprints_equal: usize,
    fingerprints: usize,
    traces: usize,
    traces_identical: usize,
    trace_numbers: usize,
    trace_max_relative: f64,
    trace_hashes: usize,
    trace_hashes_equal: usize,
}

fn is_hash(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Structural comparison of two JSON traces under the declared rule.
fn json_close(path: &str, got: &Value, want: &Value, tally: &mut GradientTally) -> Result<(), String> {
    match (got, want) {
        (Value::Number(a), Value::Number(b)) => {
            if a.is_i64() != b.is_i64() {
                return Err(format!("{path}: {a} against {b} (an integer against a float)"));
            }
            if a.is_i64() {
                return if a == b { Ok(()) } else { Err(format!("{path}: {a} against {b}")) };
            }
            let (x, y) = (a.as_f64().unwrap(), b.as_f64().unwrap());
            let relative = (x - y).abs() / y.abs().max(1.0);
            tally.trace_numbers += 1;
            tally.trace_max_relative = tally.trace_max_relative.max(relative);
            if relative <= 1e-5 { Ok(()) } else { Err(format!("{path}: {x} against {y}, relative error {relative:e}")) }
        }
        (Value::String(a), Value::String(b)) if is_hash(a) && is_hash(b) => {
            tally.trace_hashes += 1;
            tally.trace_hashes_equal += usize::from(a == b);
            let value_independent = path.ends_with("fingerprints[0]") || path.ends_with(".base[0]") || path.ends_with(".raw[1]");
            if value_independent && a != b { Err(format!("{path}: {a} against {b}")) } else { Ok(()) }
        }
        (Value::Array(a), Value::Array(b)) => {
            if a.len() != b.len() {
                return Err(format!("{path}: {} items against {}", a.len(), b.len()));
            }
            for (index, (x, y)) in a.iter().zip(b).enumerate() {
                json_close(&format!("{path}[{index}]"), x, y, tally)?;
            }
            Ok(())
        }
        (Value::Object(a), Value::Object(b)) => {
            if a.keys().ne(b.keys()) {
                return Err(format!("{path}: keys {:?} against {:?}", a.keys().collect::<Vec<_>>(), b.keys().collect::<Vec<_>>()));
            }
            for (key, x) in a {
                json_close(&format!("{path}.{key}"), x, &b[key], tally)?;
            }
            Ok(())
        }
        _ if got == want => Ok(()),
        _ => Err(format!("{path}: {got} against {want}")),
    }
}

/// The shared shape of the two gradient responses.
struct Gradients<'a> {
    request_id: &'a str,
    model_id: &'a str,
    base_version: &'a str,
    error: &'a str,
    gradients: Vec<(&'a str, Vec<f32>, &'a [u32])>,
    metrics: &'a BTreeMap<String, f64>,
    metadata: &'a BTreeMap<String, String>,
    executions: Vec<(String, i32, String, u32, String)>,
}

fn semantic_parts(response: &ComputeSemanticGradientsResponse) -> Gradients<'_> {
    Gradients {
        request_id: &response.request_id,
        model_id: &response.model_id,
        base_version: &response.base_version,
        error: &response.error,
        gradients: response.gradients.iter().map(|g| (g.name.as_str(), g.values.clone(), g.shape.as_slice())).collect(),
        metrics: &response.metrics,
        metadata: &response.metadata,
        executions: response.executions.iter().map(|e| (e.phase.clone(), e.layer, e.status.clone(), e.examples, e.error.clone())).collect(),
    }
}

fn gradients_match(got: &Gradients<'_>, want: &Gradients<'_>, tally: &mut GradientTally) -> Result<(), String> {
    let identity = (got.request_id, got.model_id, got.base_version, got.error);
    if identity != (want.request_id, want.model_id, want.base_version, want.error) {
        return Err(format!(
            "identity or error differs: {identity:?} against {:?}",
            (want.request_id, want.model_id, want.base_version, want.error)
        ));
    }
    if got.executions != want.executions {
        return Err(format!("executions differ: {:?} against {:?}", got.executions, want.executions));
    }
    let names = |parts: &Gradients<'_>| -> Vec<(String, Vec<u32>)> {
        let mut names: Vec<(String, Vec<u32>)> =
            parts.gradients.iter().map(|(name, _, shape)| ((*name).to_owned(), shape.to_vec())).collect();
        names.sort();
        names
    };
    if names(got) != names(want) {
        return Err("the transported tensors (names and shapes) differ".to_string());
    }
    let mut all_bitwise = true;
    for (name, values, _) in &got.gradients {
        let (_, expected, _) = want.gradients.iter().find(|(other, _, _)| other == name).expect("the inventory matches");
        if values.len() != expected.len() {
            return Err(format!("{name}: {} values against {}", values.len(), expected.len()));
        }
        for (r, p) in values.iter().zip(expected) {
            let error = f64::from(*r - *p).abs();
            tally.coordinates += 1;
            tally.within += usize::from(error <= 1e-6);
            tally.bitwise += usize::from(r.to_bits() == p.to_bits());
            all_bitwise &= r.to_bits() == p.to_bits();
            tally.max_error = tally.max_error.max(error);
            if error > 1e-6 {
                return Err(format!("{name}: {r} against {p}, error {error:e}"));
            }
        }
    }
    if got.metrics.keys().collect::<std::collections::BTreeSet<_>>() != want.metrics.keys().collect::<std::collections::BTreeSet<_>>() {
        return Err(format!(
            "metric names differ: {:?} against {:?}",
            got.metrics.keys().collect::<std::collections::BTreeSet<_>>(),
            want.metrics.keys().collect::<std::collections::BTreeSet<_>>()
        ));
    }
    for (key, actual) in got.metrics {
        let expected = want.metrics[key];
        let same = if is_decision_metric(key) {
            (actual - expected).abs() < 1e-12
        } else {
            (actual - expected).abs() <= 1e-5 * expected.abs().max(1.0)
        };
        tally.metrics += 1;
        tally.metrics_close += usize::from(same);
        if !same {
            return Err(format!("metric {key}: {actual} against {expected}"));
        }
    }
    let got_keys: std::collections::BTreeSet<_> = got.metadata.keys().collect();
    let want_keys: std::collections::BTreeSet<_> = want.metadata.keys().collect();
    if got_keys != want_keys {
        return Err(format!("metadata keys differ: {got_keys:?} against {want_keys:?}"));
    }
    for (key, actual) in got.metadata {
        let expected = &want.metadata[key];
        let hashes_updated_floats =
            matches!(key.as_str(), "updated_parameter_fingerprint" | "candidate_parameter_fingerprint" | "publication_delta_fingerprint");
        if hashes_updated_floats {
            tally.fingerprints += 1;
            tally.fingerprints_equal += usize::from(actual == expected);
            if actual != expected && all_bitwise {
                return Err(format!("{key} differs although every coordinate is bitwise equal: {actual} against {expected}"));
            }
            continue;
        }
        if JSON_METADATA.contains(&key.as_str()) {
            let (left, right): (Value, Value) = (serde_json::from_str(actual).unwrap(), serde_json::from_str(expected).unwrap());
            tally.traces += 1;
            tally.traces_identical += usize::from(actual == expected);
            json_close("$", &left, &right, tally).map_err(|reason| format!("metadata {key}: {reason}"))?;
            continue;
        }
        if actual == expected {
            continue;
        }
        match (actual.parse::<f64>(), expected.parse::<f64>()) {
            (Ok(x), Ok(y)) if (x - y).abs() <= 1e-5 * y.abs().max(1.0) => {}
            _ => return Err(format!("metadata {key}: {actual:?} against {expected:?}")),
        }
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
    let mut tally = GradientTally::default();
    let mut failures = Vec::new();
    for (index, case) in cases.iter().enumerate() {
        let id = case["id"].as_str().unwrap();
        let method = case["method"].as_u64().unwrap();
        let answer = service.handle_frame(&request_frame(case, index as u64 + 1)).await;
        let entry = counts.entry(format!("{}/{}", case["scope"].as_str().unwrap(), method)).or_default();
        entry.total += 1;
        if method == 6 {
            // `ComputePresenceGradients` was removed (stage V3-R8a, decision U4): the Python rows stay as the frozen oracle,
            // and the worker refuses every one of them without reading the request or any model.
            let got = error_code(&answer);
            if got == code::UNKNOWN_METHOD {
                entry.matched += 1;
                entry.identical += 1;
            } else {
                failures.push(format!("{id}: presence gradients answered {got}, expected {}", code::UNKNOWN_METHOD));
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
            4 | 5 => {
                let (got, want) = (
                    ComputeSemanticGradientsResponse::decode(payload).unwrap(),
                    ComputeSemanticGradientsResponse::decode(expected.as_slice()).unwrap(),
                );
                gradients_match(&semantic_parts(&got), &semantic_parts(&want), &mut tally)
            }
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
    eprintln!(
        "worker golden gradients: {} transported coordinates, {} within 1e-6, {} bitwise equal, max error {:.3e}; {} of {} metrics within the rule; {} of {} value-dependent fingerprints equal",
        tally.coordinates,
        tally.within,
        tally.bitwise,
        tally.max_error,
        tally.metrics_close,
        tally.metrics,
        tally.fingerprints_equal,
        tally.fingerprints
    );
    assert!(tally.coordinates > 5_000, "{} coordinates", tally.coordinates);
    assert!(
        failures.is_empty(),
        "{} differences, first:\n{}",
        failures.len(),
        failures.iter().take(8).cloned().collect::<Vec<_>>().join("\n")
    );
}

/// Stage 19 item 2c: the local-SGD, TRAIN diagnostics and FULL backtracking routes, and the policy and admission
/// refusals, against the unchanged Python worker over W1 frames. The refusals are byte-identical responses.
#[tokio::test(flavor = "current_thread")]
async fn the_route_answers_match_the_python_worker() {
    let fixture = routes_fixture();
    let service = service().await;
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 18, "{} cases", cases.len());
    let mut counts: BTreeMap<String, Counts> = BTreeMap::new();
    let mut tally = GradientTally::default();
    let mut failures = Vec::new();
    for (index, case) in cases.iter().enumerate() {
        let id = case["id"].as_str().unwrap();
        let scope = case["scope"].as_str().unwrap();
        let answer = service.handle_frame(&request_frame(case, index as u64 + 1)).await;
        let entry = counts.entry(format!("{scope}/{}", case["method"].as_u64().unwrap())).or_default();
        entry.total += 1;
        if answer[5] != Kind::Response as u8 {
            failures.push(format!("{id}: error frame {}", String::from_utf8_lossy(&answer[HEADER_LEN..])));
            continue;
        }
        let payload = &answer[HEADER_LEN..];
        let expected = decode(&case["response"]);
        let (got, want) = (
            ComputeSemanticGradientsResponse::decode(payload).unwrap(),
            ComputeSemanticGradientsResponse::decode(expected.as_slice()).unwrap(),
        );
        if scope != "validation" {
            // LLM only: every phase of the run executed exactly the semantic layer.
            assert!(got.executions.iter().all(|e| e.layer == 4 && e.status == "ok"), "{id}: {:?}", got.executions);
            if id.ends_with("/rejected") {
                assert_eq!(got.error, "TRAIN_BACKTRACKING_NO_IMPROVEMENT_V1", "{id}");
                assert!(got.gradients.is_empty(), "{id}: a rejection transports no tensor");
            }
        }
        match gradients_match(&semantic_parts(&got), &semantic_parts(&want), &mut tally) {
            Ok(()) => {
                entry.matched += 1;
                entry.identical += usize::from(payload == expected.as_slice());
                if scope == "validation" && payload != expected.as_slice() {
                    failures.push(format!("{id}: a refusal is not byte-identical"));
                }
            }
            Err(reason) => failures.push(format!("{id}: {reason}")),
        }
    }
    for (scope, counts) in &counts {
        eprintln!(
            "worker routes: {scope}: {} of {} within the declared rule, {} byte-identical",
            counts.matched, counts.total, counts.identical
        );
    }
    eprintln!(
        "worker routes gradients: {} transported coordinates, {} within 1e-6, {} bitwise equal, max error {:.3e}; {} of {} metrics within the rule; {} of {} value-dependent fingerprints equal; {} trace strings ({} byte-identical), {} numbers within 1e-5 (max relative {:.3e}), {} of {} value-dependent trace fingerprints equal",
        tally.coordinates,
        tally.within,
        tally.bitwise,
        tally.max_error,
        tally.metrics_close,
        tally.metrics,
        tally.fingerprints_equal,
        tally.fingerprints,
        tally.traces,
        tally.traces_identical,
        tally.trace_numbers,
        tally.trace_max_relative,
        tally.trace_hashes_equal,
        tally.trace_hashes
    );
    assert!(tally.coordinates > 1_000, "{} coordinates", tally.coordinates);
    assert!(tally.traces >= 12, "{} traces", tally.traces);
    assert!(
        failures.is_empty(),
        "{} differences, first:\n{}",
        failures.len(),
        failures.iter().take(8).cloned().collect::<Vec<_>>().join("\n")
    );
}

/// Frames for the shapes this worker does not serve, built from a recorded request.
fn recorded(fixture: &Value, id: &str) -> Value {
    fixture["cases"].as_array().unwrap().iter().find(|case| case["id"] == id).unwrap_or_else(|| panic!("no case {id}")).clone()
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
async fn shapes_the_worker_does_not_serve_are_refused_before_anything_runs() {
    use privoke_contracts::proto::v1::ComputeSemanticGradientsRequest;
    let fixture = fixture();
    let service = service().await;
    let base =
        ComputeSemanticGradientsRequest::decode(decode(&recorded(&fixture, "synthetic-legacy-mean/heads")["request"]).as_slice()).unwrap();
    let with_model = |model: &str| {
        let mut request = base.clone();
        request.model_id = model.to_string();
        request.encode_to_vec()
    };
    let schema3 = "{\"schema\": 3, \"expected_objective\": \"x\"}";
    let sum_header = "{\"schema\": 2, \"expected_objective\": \"class_balanced_contextual_sum_category_decision_margin_v1\", \"expected_diagnostics_policy\": null}";
    let mut untargeted = base.clone();
    untargeted.examples[0].has_target = false;
    type Refused<'a> = (&'a str, u8, Vec<(&'a str, &'a str)>, Vec<u8>);
    let cases: Vec<Refused<'_>> = vec![
        ("an artifact that is not full-capable", 4, vec![], with_model("synthetic-legacy-heads")),
        ("the same on the full-encoder scope", 5, vec![], with_model("synthetic-legacy-heads")),
        ("a header of another schema", 5, vec![("x-privoke-training-admission-v1", schema3)], with_model("synthetic-legacy-mean")),
        ("a header that is not JSON", 4, vec![("x-privoke-training-admission-v1", "{")], with_model("synthetic-legacy-mean")),
        (
            "a repeated header",
            4,
            vec![("x-privoke-training-admission-v1", sum_header), ("x-privoke-training-admission-v1", sum_header)],
            with_model("synthetic-legacy-sum"),
        ),
        ("a row without an explicit target", 4, vec![], untargeted.encode_to_vec()),
        (
            "a FULL Adam artifact with its own admission",
            5,
            vec![("x-privoke-training-admission-v1", schema3)],
            with_model("synthetic-legacy-adam"),
        ),
    ];
    for (index, (note, method, metadata, payload)) in cases.iter().enumerate() {
        let answer = service.handle_frame(&frame_of(*method, metadata, payload, index as u64 + 1)).await;
        assert_eq!(error_code(&answer), code::UNSUPPORTED_ROUTE, "{note}");
        assert!(String::from_utf8_lossy(&answer[HEADER_LEN..]).contains("Python worker"), "{note}");
    }
    // The shapes that are served keep working in the same service afterwards.
    let served = service.handle_frame(&frame_of(4, &[], &with_model("synthetic-legacy-mean"), 99)).await;
    assert_eq!(served[5], Kind::Response as u8);
}

#[tokio::test(flavor = "current_thread")]
async fn a_worker_without_model_roots_refuses_what_reads_a_model_before_anything_runs() {
    let fixture = fixture();
    let ner = EntityNerDetector::new(ReplayAnalyzer::new(&[], Vec::new()).unwrap(), "en_core_web_sm").await.unwrap();
    let regex = Detector::new(RuleSetOptions::from_lookup(&|_| None)).unwrap();
    let service = Service::new(Pipeline::new(regex, ner, PipelineOptions::default()), ServiceOptions::default());
    for (index, case) in fixture["cases"].as_array().unwrap().iter().enumerate() {
        let method = case["method"].as_u64().unwrap();
        if case.get("error_code").is_some() || ![2, 4, 5, 6].contains(&method) {
            continue;
        }
        let answer = service.handle_frame(&request_frame(case, index as u64 + 1)).await;
        assert_eq!(error_code(&answer), code::UNSUPPORTED_ROUTE, "{}", case["id"]);
    }
    let gated = fixture["cases"].as_array().unwrap().iter().find(|case| case["id"].as_str().unwrap().starts_with("gate/")).unwrap();
    assert_eq!(error_code(&service.handle_frame(&request_frame(gated, 7)).await), code::UNSUPPORTED_LAYERS);
}

#[test]
fn the_gradient_and_presence_rules_are_declared() {
    let declared = include_str!("../../../../tests/conformance/normalization.toml");
    let section = declared.split("[worker_gradients]").nth(1).expect("the worker_gradients section exists");
    for line in [
        "gradient_tensor_absolute_tolerance = 1e-6",
        "metric_decisions_exact = true",
        "metric_relative_tolerance = 1e-5",
        "metadata_float_relative_tolerance = 1e-5",
        "json_metadata_float_relative_tolerance = 1e-5",
        r#"json_metadata_keys = ["contextual_optimizer_trace", "contextual_training_diagnostics", "contextual_training_backtracking_trace", "contextual_training_backtracking_trials"]"#,
        r#"value_dependent_fingerprints = ["updated_parameter_fingerprint", "candidate_parameter_fingerprint", "publication_delta_fingerprint"]"#,
        "presence_float_places = 6",
        "presence_float_absolute_tolerance = 1e-5",
        "refusals_byte_equal = true",
    ] {
        assert!(section.contains(line), "normalization.toml does not declare {line}");
    }
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
    for method in [4u8, 5] {
        let request =
            ComputeSemanticGradientsRequest { request_id: "r".into(), model_id: "synthetic-legacy-mean".into(), ..Default::default() };
        let answer = service.handle_frame(&frame_of(method, &[], &request.encode_to_vec(), 2)).await;
        assert_eq!(error_code(&answer), code::INVALID_LAYERS);
    }
    let request =
        ComputePresenceGradientsRequest { request_id: "r".into(), model_id: "privoke-presence-efficient".into(), ..Default::default() };
    // Presence gradients are removed: refused as an unknown method, whatever the layers.
    assert_eq!(error_code(&service.handle_frame(&frame_of(6, &[], &request.encode_to_vec(), 3)).await), code::UNKNOWN_METHOD);
}
