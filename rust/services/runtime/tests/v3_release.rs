//! The Rust worker's semantic layer on the pinned standard V3 releases against the unchanged Python W1 worker
//! (RUST-S17H). Gated, local evidence: the golden holds prompt text and the releases are not committed, so the test runs
//! only when both of these are set (CI has neither and prints why):
//!
//! * `PRIVOKE_RUNTIME_V3_GOLDEN`: the directory written by `evaluation/generate_runtime_v3_golden.py real` (one file per
//!   tier and set, git-ignored under `tests/local/v3`);
//! * `PRIVOKE_V3_RELEASES`: `models/standard-releases` (`privoke-v3-<tier>/` with `manifest.json` and the assets); it is
//!   the worker's model root, so the loader admits each manifest against the real pins.
//!
//! Every row is an LLM-only request: `layers=[SEMANTIC]` with the release named, and the test asserts that the executed
//! layers are exactly the semantic layer. Nothing here is a product-pipeline row. The rule is the one declared for the
//! pinned releases (`normalization.toml`): decisions, texts, errors and every identity field exactly; the confidence within
//! an absolute 1.5e-5 (the V3 logit tolerance: a torch float32 logit is not closer to the Rust one than to the exact
//! value), or equal after rounding to 6 places; `category_probabilities` within one unit of their fourth decimal. The
//! response carries the confidence rounded to three decimals, so a row whose two confidences differ by exactly one step is
//! accepted only if the Rust unrounded confidence (recomputed with `V3Model` on the normalised text) lies within the
//! declared tolerance of a rounding boundary; such rows are counted and listed apart, the stage 14 and stage 22 rule.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::path::PathBuf;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use privoke_contracts::proto::v1::{AnalyzePromptResponse, RuntimeDetectionResult};
use privoke_ner_layer::EntityNerDetector;
use privoke_ner_layer::replay::ReplayAnalyzer;
use privoke_rules::preprocessing::normalize_text;
use privoke_rules::{Detector, RuleSetOptions};
use privoke_runtime::frames::{self, HEADER_LEN, Kind};
use privoke_runtime::semantic::SemanticLayer;
use privoke_runtime::{Pipeline, PipelineOptions, Service, ServiceOptions};
use privoke_semantic::V3Model;
use prost::Message;
use serde_json::Value;

const V3_CONFIDENCE_TOLERANCE: f64 = 1.5e-5;

fn env_dir(name: &str) -> Option<PathBuf> {
    std::env::var_os(name).map(PathBuf::from).filter(|path| path.is_dir())
}

fn decode(value: &Value) -> Vec<u8> {
    STANDARD.decode(value.as_str().expect("base64 text")).expect("valid base64")
}

fn close(a: f64, b: f64) -> bool {
    (a - b).abs() <= V3_CONFIDENCE_TOLERANCE || format!("{a:.6}") == format!("{b:.6}")
}

#[derive(Default)]
struct Stats {
    rows: usize,
    answered: usize,
    identical: usize,
    above_1e5: usize,
    max_confidence_difference: f64,
    /// Whether a one-step difference of the rounded confidence is admitted for the row being compared.
    boundary_allowed: bool,
    /// Rows accepted only by the rounding-boundary rule.
    boundary_rows: usize,
}

/// The distance of an unrounded confidence from the nearest three-decimal rounding boundary.
fn boundary_distance(raw: f64) -> f64 {
    (((raw * 1000.0).fract()).abs() - 0.5).abs() / 1000.0
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

fn result_matches(a: &RuntimeDetectionResult, b: &RuntimeDetectionResult, stats: &mut Stats) -> Result<(), String> {
    if a.classification != b.classification || a.action != b.action {
        return Err(format!("decision differs: {:?}/{} against {:?}/{}", a.classification, a.action, b.classification, b.action));
    }
    if (&a.section_of_text, a.span_start, a.span_end, a.has_span, a.has_confidence, &a.reasoning)
        != (&b.section_of_text, b.span_start, b.span_end, b.has_span, b.has_confidence, &b.reasoning)
    {
        return Err(format!("finding differs: {:?} against {:?}", a.reasoning, b.reasoning));
    }
    let difference = (a.confidence - b.confidence).abs();
    stats.max_confidence_difference = stats.max_confidence_difference.max(difference);
    stats.above_1e5 += usize::from(difference > 1e-5);
    if !close(a.confidence, b.confidence) {
        let one_step = ((a.confidence - b.confidence).abs() - 1e-3).abs() < 1e-9;
        if !(stats.boundary_allowed && one_step) {
            return Err(format!("confidence {} against {}", a.confidence, b.confidence));
        }
        stats.boundary_rows += 1;
    }
    metadata_matches(&a.metadata, &b.metadata)
}

fn response_matches(a: &AnalyzePromptResponse, b: &AnalyzePromptResponse, stats: &mut Stats) -> Result<(), String> {
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
        (Some(x), Some(y)) => result_matches(x, y, stats).map_err(|e| format!("evidence: {e}"))?,
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
            result_matches(p, q, stats).map_err(|e| format!("layer {}: {e}", x.layer))?;
        }
    }
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn the_pinned_v3_releases_match_python_on_the_recorded_sets_llm_only() {
    let (Some(golden), Some(releases)) = (env_dir("PRIVOKE_RUNTIME_V3_GOLDEN"), env_dir("PRIVOKE_V3_RELEASES")) else {
        eprintln!("PENDING: set PRIVOKE_RUNTIME_V3_GOLDEN and PRIVOKE_V3_RELEASES to compare the pinned V3 releases (not run in CI)");
        return;
    };
    let ner = EntityNerDetector::new(ReplayAnalyzer::new(&[], Vec::new()).unwrap(), "en_core_web_sm").await.unwrap();
    let regex = Detector::new(RuleSetOptions::from_lookup(&|_| None)).unwrap();
    let semantic = SemanticLayer::new(vec![releases.clone()], None).unwrap();
    let service = Service::new(
        Pipeline::new(regex, ner, PipelineOptions::default()).with_semantic(semantic),
        ServiceOptions { clear_elapsed: true, ..ServiceOptions::default() },
    );

    let mut files: Vec<PathBuf> = std::fs::read_dir(&golden).unwrap().map(|entry| entry.unwrap().path()).collect();
    files.sort();
    let mut per_tier: BTreeMap<String, Stats> = BTreeMap::new();
    let mut failures = Vec::new();
    let mut id = 0u64;
    for path in files.iter().filter(|path| path.extension().is_some_and(|extension| extension == "json")) {
        let document: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        assert_eq!(document["meta"]["layers"], serde_json::json!(["semantic"]));
        let tier = document["meta"]["tier"].as_str().unwrap().to_string();
        let group = document["meta"]["set"].as_str().unwrap().to_string();
        let stats = per_tier.entry(tier.clone()).or_default();
        for row in document["rows"].as_array().unwrap() {
            id += 1;
            let label = format!("{tier} {group} {}", row["id"].as_str().unwrap());
            stats.rows += 1;
            let answer = service.handle_frame(&frames::encode_frame(Kind::Request, 1, id, &decode(&row["request"]))).await;
            if row.get("response").is_none() {
                // The Python worker refused the frame; the Rust worker must refuse it too.
                if answer[5] == Kind::Error as u8 {
                    stats.answered += 1;
                } else {
                    failures.push(format!("{label}: Python refused the frame, Rust answered"));
                }
                continue;
            }
            if answer[5] != Kind::Response as u8 {
                failures.push(format!("{label}: error frame {}", String::from_utf8_lossy(&answer[HEADER_LEN..])));
                continue;
            }
            let payload = &answer[HEADER_LEN..];
            let expected = decode(&row["response"]);
            let (got, want) =
                (AnalyzePromptResponse::decode(payload).unwrap(), AnalyzePromptResponse::decode(expected.as_slice()).unwrap());
            if got.error.is_empty() {
                let executed: Vec<(i32, &str)> = got.layers.iter().map(|l| (l.layer, l.status.as_str())).collect();
                assert_eq!(executed, vec![(4, "ok")], "{label}: an LLM-only row must execute exactly the semantic layer");
            }
            let mut verdict = response_matches(&got, &want, stats);
            if verdict.as_ref().is_err_and(|reason| reason.contains("confidence")) {
                // Retry under the rounding-boundary rule, if the unrounded Rust confidence is near a boundary.
                let model_id = format!("privoke-v3-{tier}");
                let model = V3Model::load_release(&releases.join(&model_id), &model_id).unwrap();
                let text = normalize_text(row["text"].as_str().unwrap()).unwrap();
                let raw = model.predict(&text).map(|prediction| prediction.confidence_raw).unwrap_or(0.0);
                let distance = boundary_distance(raw);
                eprintln!("boundary candidate {label}: raw confidence {raw}, distance from a rounding boundary {distance:.3e}");
                stats.boundary_allowed = distance <= V3_CONFIDENCE_TOLERANCE;
                verdict = response_matches(&got, &want, stats);
                stats.boundary_allowed = false;
            }
            match verdict {
                Ok(()) => {
                    stats.answered += 1;
                    stats.identical += usize::from(payload == expected.as_slice());
                }
                Err(reason) => failures.push(format!("{label}: {reason}")),
            }
        }
    }
    assert!(!per_tier.is_empty(), "the golden directory held no rows");
    let (mut rows, mut answered, mut identical) = (0, 0, 0);
    for (tier, stats) in &per_tier {
        eprintln!(
            "runtime V3 golden (LLM-only) privoke-v3-{tier}: {} of {} within the declared rule, {} byte-identical, {} only by the rounding-boundary rule, max confidence difference {:.3e}, {} above 1e-5",
            stats.answered, stats.rows, stats.identical, stats.boundary_rows, stats.max_confidence_difference, stats.above_1e5
        );
        rows += stats.rows;
        answered += stats.answered;
        identical += stats.identical;
    }
    eprintln!("runtime V3 golden (LLM-only), all tiers: {answered} of {rows} within the declared rule, {identical} byte-identical");
    assert!(
        failures.is_empty(),
        "{} differences, first:\n{}",
        failures.len(),
        failures.iter().take(8).cloned().collect::<Vec<_>>().join("\n")
    );
}
