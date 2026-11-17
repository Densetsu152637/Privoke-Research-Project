//! Parity of the GLiNER backend with Python on a recorded set, without the model weights (stage 15).
//!
//! `evaluation/generate_gliner_golden.py` records, per text, the spans the Python GLiNER model returned for each
//! window, the spaCy analyses the post-filter read, and the detector's results with the post-filter on and off. This
//! test replays the model and spaCy and compares the Rust detector's results with the recorded ones. The golden
//! directory is ignored by Git; point `PRIVOKE_GLINER_GOLDEN` at it. Without it the test prints why it is pending and
//! passes, so CI reports it as pending, not verified.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashMap;
use std::path::PathBuf;

use privoke_ner_layer::NerError;
use privoke_ner_layer::detector::NerOptions;
use privoke_ner_layer::gliner::{Found, GlinerDetector, GlinerHit, GlinerModel, GlinerOptions, LabelPreset};
use privoke_ner_layer::replay::ReplayAnalyzer;
use serde_json::{Value, json};

#[derive(Debug)]
struct Recorded(HashMap<String, Vec<Found>>);

impl GlinerModel for Recorded {
    fn predict_entities(&self, window: &str, _labels: &[&str], _threshold: f32) -> Result<Vec<Found>, NerError> {
        self.0.get(window).cloned().ok_or_else(|| NerError::SpacyBackend(format!("no recorded model call for window {window:?}")))
    }
}

fn recorded_model(row: &Value) -> Recorded {
    let mut calls = HashMap::new();
    for call in row["windows"].as_array().expect("windows") {
        let found = call["found"]
            .as_array()
            .expect("found")
            .iter()
            .map(|f| Found {
                start: f["start"].as_u64().expect("start") as usize,
                end: f["end"].as_u64().expect("end") as usize,
                label: f["label"].as_str().expect("label").to_owned(),
                score: f["score"].as_f64().expect("score") as f32,
            })
            .collect();
        calls.insert(call["window"].as_str().expect("window").to_owned(), found);
    }
    Recorded(calls)
}

fn hit_json(hit: &GlinerHit) -> Value {
    let r = &hit.result;
    let mut metadata = json!({"label": r.label, "entity_type": r.entity_type, "model": r.model, "backend": "gliner"});
    if let Some(rule) = &r.postfilter_rule {
        metadata["postfilter_rule"] = json!(rule);
    }
    if let Some(score) = hit.score {
        metadata["score"] = json!(score);
    }
    json!({"span": [r.span.0, r.span.1], "text": r.text, "packed": r.classification.pack(), "confidence": r.confidence,
           "reasoning": r.reasoning, "metadata": metadata})
}

/// Compares numbers by value (the recorded JSON may write `0.8` or `0.80`).
fn same(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => x.as_f64() == y.as_f64(),
        (Value::Array(x), Value::Array(y)) => x.len() == y.len() && x.iter().zip(y).all(|(p, q)| same(p, q)),
        (Value::Object(x), Value::Object(y)) => x.len() == y.len() && x.iter().all(|(k, v)| y.get(k).is_some_and(|w| same(v, w))),
        _ => a == b,
    }
}

#[tokio::test]
async fn recorded_rows_match_python() {
    let Some(dir) = std::env::var_os("PRIVOKE_GLINER_GOLDEN").map(PathBuf::from) else {
        println!(
            "PENDING: PRIVOKE_GLINER_GOLDEN is not set; the GLiNER golden (needs the gliner package and the checkpoint) is not available here, so recorded-set parity is not verified"
        );
        return;
    };
    let summary: Value = serde_json::from_slice(&std::fs::read(dir.join("summary.json")).unwrap()).unwrap();
    let lexicon: Vec<String> = serde_json::from_slice(&std::fs::read(dir.join("lexicon.json")).unwrap()).unwrap();
    let options = GlinerOptions {
        threshold: summary["threshold"].as_f64().unwrap(),
        preset: LabelPreset::parse(summary["preset"].as_str().unwrap()).unwrap(),
    };
    let model_name = summary["model"].as_str().unwrap().to_owned();
    let (mut rows, mut failures) = (0usize, Vec::new());
    for set in summary["sets"].as_object().unwrap().keys() {
        let text = std::fs::read_to_string(dir.join(format!("{set}.jsonl"))).unwrap();
        for line in text.lines().filter(|l| !l.trim().is_empty()) {
            let row: Value = serde_json::from_str(line).unwrap();
            if row.get("error").is_some() {
                continue;
            }
            let replay = ReplayAnalyzer::new(row["spacy"].as_array().unwrap(), lexicon.clone()).unwrap();
            let detector = GlinerDetector::new(replay, recorded_model(&row), &model_name, options);
            let input = row["text"].as_str().unwrap();
            for (key, postfilter) in [("pf1", true), ("pf0", false)] {
                let got = detector.extract_entities(input, &NerOptions { caseless_gate: false, postfilter }).await.unwrap();
                let got: Value = Value::Array(got.results.iter().map(hit_json).collect());
                if !same(&got, &row[key]) {
                    failures.push(format!("{set} row {} {key}: got {got} want {}", row["id"], row[key]));
                }
            }
            rows += 1;
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {rows} rows differ, first:\n{}",
        failures.len(),
        failures.iter().take(5).cloned().collect::<Vec<_>>().join("\n")
    );
    println!("compared {rows} recorded rows, identical spans and results");
}
