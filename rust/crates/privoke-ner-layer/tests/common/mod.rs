//! Shared by the replay test and the `parity` example: runs Rust over a golden row and compares everything.

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashSet;
use std::sync::Arc;

use privoke_ner_layer::analyzer::SpacyBackend;
use privoke_ner_layer::detector::{EntityNerDetector, NerOptions};
use privoke_ner_layer::layer::{LayerHit, LayerOptions, LayerOutcome, analyse_ner_layer};
use privoke_ner_layer::pattern::{PatternEntityDetector, PatternOptions, PatternOutput, PatternResult, Seed};
use privoke_ner_layer::postfilter::Decision;
use privoke_ner_layer::replay::CachedAnalyzer;
use privoke_rules::preprocessing::RobustnessOptions;
use serde_json::{Value, json};

/// The NER-layer settings of `LAYER_CONFIGS` in `evaluation/generate_ner_golden.py`:
/// `(case_preserving, strip_format, digits, email, caseless_gate, postfilter)`.
type LayerFlags = (bool, bool, bool, bool, bool, bool);
type PatternFlags = (bool, bool, bool, bool, bool);

pub const LAYER_CONFIGS: [(&str, LayerFlags); 9] = [
    ("default", (true, false, false, false, false, true)),
    ("caseless", (true, false, false, false, true, true)),
    ("format", (true, true, false, false, false, true)),
    ("digits", (true, false, true, false, false, true)),
    ("email", (true, false, false, true, false, true)),
    ("all-flags", (true, true, true, true, false, true)),
    ("caseless-all-flags", (true, true, true, true, true, true)),
    ("lowercase", (false, false, false, false, false, true)),
    ("no-postfilter", (true, false, false, false, false, false)),
];

/// `PATTERN_CONFIGS`: `(use_cues, use_shape, use_recurrence, use_gazetteer, hybrid)`.
pub const PATTERN_CONFIGS: [(&str, PatternFlags); 6] = [
    ("default", (true, true, true, false, false)),
    ("gazetteer", (true, true, true, true, false)),
    ("cues", (true, false, false, false, false)),
    ("shape", (false, true, false, false, false)),
    ("no-recurrence", (true, true, false, false, false)),
    ("hybrid", (true, true, true, false, true)),
];

pub fn layer_options(name: &str) -> LayerOptions {
    let &(_, (case_preserving, strip, digits, email, caseless, postfilter)) =
        LAYER_CONFIGS.iter().find(|(n, _)| *n == name).unwrap_or_else(|| panic!("unknown layer configuration {name}"));
    LayerOptions {
        case_preserving,
        robustness: Some(RobustnessOptions { strip_format_chars: strip, canonicalise_digits: digits, canonicalise_email_words: email }),
        ner: NerOptions { caseless_gate: caseless, postfilter },
    }
}

pub fn pattern_options(name: &str) -> (PatternOptions, bool) {
    let &(_, (use_cues, use_shape, use_recurrence, use_gazetteer, hybrid)) =
        PATTERN_CONFIGS.iter().find(|(n, _)| *n == name).unwrap_or_else(|| panic!("unknown pattern configuration {name}"));
    (PatternOptions { use_cues, use_shape, use_recurrence, use_gazetteer }, hybrid)
}

fn hit_json(hit: &LayerHit) -> Value {
    let mut metadata = json!({"label": hit.label, "entity_type": hit.entity_type, "model": hit.model});
    if let Some(rule) = &hit.postfilter_rule {
        metadata["postfilter_rule"] = json!(rule);
    }
    json!({
        "span": hit.span.map(|(a, b)| json!([a, b])).unwrap_or(Value::Null),
        "text": hit.text,
        "packed": hit.classification.pack(),
        "confidence": hit.confidence,
        "reasoning": hit.reasoning,
        "metadata": metadata,
    })
}

fn decision_json(d: &Decision) -> Value {
    let c = &d.candidate;
    json!({
        "rule": d.rule, "stage": d.stage.as_str(), "keep": d.keep, "sensitivity": d.sensitivity.map(|s| s as u8),
        "label": c.label, "start": c.start, "end": c.end, "text": c.text,
        "strong_cue": c.strong_cue, "multi_token": c.multi_token, "relation_cue": c.relation_cue, "geo_or_org_cue": c.geo_or_org_cue,
    })
}

fn pattern_result_json(r: &PatternResult) -> Value {
    json!({
        "span": [r.span.0, r.span.1], "text": r.text, "packed": r.classification.pack(), "confidence": r.confidence,
        "reasoning": r.reasoning,
        "metadata": {"label": r.label, "entity_type": r.entity_type, "model": "pattern-entity-detector", "mechanism": r.mechanism, "cue": r.cue},
    })
}

/// Rust's answer for one NER-layer configuration, in the golden shape.
pub async fn layer_value<A: SpacyBackend>(detector: &EntityNerDetector<A>, text: &str, name: &str) -> Value {
    match analyse_ner_layer(detector, text, &layer_options(name)).await {
        Ok(LayerOutcome::Ok(hits, extraction)) => json!({
            "results": hits.iter().map(hit_json).collect::<Vec<_>>(),
            "decisions": extraction.decisions.iter().map(decision_json).collect::<Vec<_>>(),
        }),
        Ok(LayerOutcome::Error(message)) => json!({"error": message, "decisions": []}),
        Err(error) => json!({"rust_error": error.to_string()}),
    }
}

/// Rust's answer for one pattern-detector configuration, in the golden shape.
pub fn pattern_value(text: &str, name: &str, seeds_json: &[Value]) -> Value {
    let (options, hybrid) = pattern_options(name);
    let detector = PatternEntityDetector::new(options);
    let seeds: Vec<Seed> = seeds_json
        .iter()
        .map(|s| Seed {
            span: s["span"].as_array().map(|a| (a[0].as_u64().unwrap_or(0) as usize, a[1].as_u64().unwrap_or(0) as usize)),
            label: s["metadata"]["label"].as_str().map(str::to_owned),
        })
        .collect();
    let outputs = if hybrid { detector.augment_entities(text, &seeds) } else { detector.extract_entities(text) };
    match outputs {
        Ok(outputs) => json!({
            "results": outputs
                .iter()
                .map(|o| match o {
                    PatternOutput::Found(r) => pattern_result_json(r),
                    PatternOutput::Seed(i) => seeds_json[*i].clone(),
                })
                .collect::<Vec<_>>()
        }),
        Err(error) => json!({"error": error.to_string()}),
    }
}

/// Per-configuration verdicts for one row.
#[derive(Default)]
pub struct RowReport {
    pub layer: Vec<(String, bool)>,
    pub pattern: Vec<(String, bool)>,
    pub diffs: Vec<String>,
}

fn shorten(value: &Value) -> String {
    let text = value.to_string();
    if text.len() > 700 { format!("{}...", text.chars().take(700).collect::<String>()) } else { text }
}

/// Runs every configuration recorded in `row` through Rust and compares with Python.
pub async fn check_row<A: SpacyBackend>(
    inner: &A,
    lexicon: Arc<HashSet<String>>,
    model: &str,
    row: &Value,
    skip_pattern: bool,
) -> RowReport {
    let text = row["text"].as_str().expect("row text");
    let id = row["id"].to_string();
    let cached = CachedAnalyzer::new(inner);
    let detector = EntityNerDetector::with_lexicon(cached, model, lexicon);
    let mut report = RowReport::default();
    if let Some(layers) = row["layer"].as_object() {
        for (name, expected) in layers {
            let actual = layer_value(&detector, text, name).await;
            let same = actual == *expected;
            if !same && report.diffs.len() < 4 {
                report.diffs.push(format!(
                    "row {id} layer {name}: text {text:?}\n  python: {}\n  rust:   {}",
                    shorten(expected),
                    shorten(&actual)
                ));
            }
            report.layer.push((name.clone(), same));
        }
    }
    if let (false, Some(patterns)) = (skip_pattern, row["pattern"].as_object()) {
        let seeds = row["seeds"].as_array().cloned();
        for (name, expected) in patterns {
            let Some(seeds) = &seeds else {
                continue;
            };
            let actual = pattern_value(text, name, seeds);
            let same = actual == *expected;
            if !same && report.diffs.len() < 4 {
                report.diffs.push(format!(
                    "row {id} pattern {name}: text {text:?}
  python: {}
  rust:   {}",
                    shorten(expected),
                    shorten(&actual)
                ));
            }
            report.pattern.push((name.clone(), same));
        }
    }
    report
}
