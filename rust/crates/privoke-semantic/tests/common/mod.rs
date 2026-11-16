//! Shared by the parity tests: replays a golden row (made by `evaluation/generate_semantic_golden.py`) through Rust and
//! compares tokens, logits, decisions and the semantic layer's result. LLM-only: no regex or NER layer is involved.

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;

/// Print a line straight to stderr. `println!` is captured by the test harness and hidden for a passing test; the
/// measurements and the reasons for a skip must reach the CI log.
macro_rules! say {
    ($($arg:tt)*) => {{
        use std::io::Write;
        let _ = writeln!(std::io::stderr(), $($arg)*);
    }};
}

use privoke_semantic::layer::{LayerOutcome, SemanticClassifier, analyse_semantic_layer};
use privoke_semantic::{Prediction, TinyModel, V3Model};
use serde_json::Value;

/// The stage's logit tolerance: an absolute 1e-5 against torch (V3) and NumPy (Tiny) on CPU float32.
pub const LOGIT_TOLERANCE: f64 = 1e-5;

pub fn crate_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

pub fn fixtures() -> PathBuf {
    crate_dir().join("tests").join("fixtures")
}

pub fn repo_root() -> PathBuf {
    crate_dir().join("..").join("..").join("..")
}

pub fn read_json(path: &std::path::Path) -> Value {
    let bytes = std::fs::read(path).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    serde_json::from_slice(&bytes).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

/// What a replay measured.
#[derive(Debug, Default)]
pub struct Report {
    pub rows: usize,
    pub error_rows: usize,
    pub finding_rows: usize,
    pub max_logit_diff: f64,
    pub max_pooled_diff: f64,
    pub max_confidence_diff: f64,
    pub boundary_confidences: usize,
    pub failures: Vec<String>,
}

impl Report {
    fn fail(&mut self, id: &str, message: String) {
        self.failures.push(format!("{id}: {message}"));
    }

    /// Print the measurements and fail with the first mismatches.
    pub fn assert_clean(&self, label: &str) {
        say!(
            "{label}: {} rows ({} error rows, {} with findings), max logit diff {:.3e}, max pooled diff {:.3e}, max raw confidence diff {:.3e}, {} rounding-boundary confidences, {} failures",
            self.rows,
            self.error_rows,
            self.finding_rows,
            self.max_logit_diff,
            self.max_pooled_diff,
            self.max_confidence_diff,
            self.boundary_confidences,
            self.failures.len()
        );
        assert!(
            self.failures.is_empty(),
            "{label}: {} failures; first: {:#?}",
            self.failures.len(),
            &self.failures[..self.failures.len().min(8)]
        );
    }
}

fn floats(value: &Value) -> Vec<f64> {
    value.as_array().unwrap().iter().map(|v| v.as_f64().unwrap()).collect()
}

fn compare_vectors(report: &mut Report, id: &str, name: &str, mine: &[f32], golden: &Value, maximum: fn(&mut Report) -> &mut f64) {
    let golden = floats(golden);
    if mine.len() != golden.len() {
        report.fail(id, format!("{name} has {} values, golden {}", mine.len(), golden.len()));
        return;
    }
    for (a, b) in mine.iter().zip(&golden) {
        let diff = (f64::from(*a) - b).abs();
        let slot = maximum(report);
        if diff > *slot {
            *slot = diff;
        }
        if diff > LOGIT_TOLERANCE || !diff.is_finite() {
            report.fail(id, format!("{name} differs by {diff:e} (rust {a}, golden {b})"));
            return;
        }
    }
}

fn logit_slot(report: &mut Report) -> &mut f64 {
    &mut report.max_logit_diff
}

fn pooled_slot(report: &mut Report) -> &mut f64 {
    &mut report.max_pooled_diff
}

/// Compare two reported (3-decimal) confidences. They must be equal, except that a one-step rounding difference is
/// accepted (and counted) when the unrounded values agree within 1e-5 and lie within 2e-5 of a rounding boundary.
fn check_confidence(report: &mut Report, id: &str, mine: f64, golden: f64, raws: Option<(f64, f64)>) {
    if mine == golden {
        return;
    }
    if let Some((mine_raw, golden_raw)) = raws {
        let scaled = golden_raw.clamp(0.0, 0.999) * 1000.0;
        let to_boundary = ((scaled - scaled.floor()) - 0.5).abs() / 1000.0;
        if (mine_raw - golden_raw).abs() <= LOGIT_TOLERANCE && to_boundary <= 2.0 * LOGIT_TOLERANCE {
            report.boundary_confidences += 1;
            return;
        }
    }
    report.fail(id, format!("confidence {mine} != {golden} (raw {raws:?})"));
}

fn check_decision(report: &mut Report, id: &str, mine: &Prediction, golden: &Value) {
    let text = |key: &str| golden[key].as_str().unwrap().to_string();
    if mine.sensitivity != text("sensitivity") || mine.visibility != text("visibility") {
        report.fail(id, format!("decision {}/{} != {}/{}", mine.sensitivity, mine.visibility, text("sensitivity"), text("visibility")));
    }
    let categories: Vec<String> = golden["categories"].as_array().unwrap().iter().map(|v| v.as_str().unwrap().to_string()).collect();
    if mine.categories != categories {
        report.fail(id, format!("categories {:?} != {categories:?}", mine.categories));
    }
    if let Some(packed) = golden.get("packed").and_then(Value::as_u64)
        && u64::from(mine.classification.pack()) != packed
    {
        report.fail(id, format!("packed classification {} != {packed}", mine.classification.pack()));
    }
    let golden_raw = golden["confidence_raw"].as_f64().unwrap();
    let diff = (mine.confidence_raw - golden_raw).abs();
    if diff > report.max_confidence_diff {
        report.max_confidence_diff = diff;
    }
    if diff > LOGIT_TOLERANCE {
        report.fail(id, format!("raw confidence differs by {diff:e}"));
    }
    if let Some(confidence) = golden.get("confidence").and_then(Value::as_f64) {
        check_confidence(report, id, mine.confidence, confidence, Some((mine.confidence_raw, golden_raw)));
    }
}

fn check_layer(report: &mut Report, id: &str, model: &impl SemanticClassifier, text: &str, golden: &Value, raws: Option<(f64, f64)>) {
    let status = golden["status"].as_str().unwrap();
    match (analyse_semantic_layer(model, text), status) {
        (LayerOutcome::Error(message), "error") => {
            report.error_rows += 1;
            if Some(message.as_str()) != golden["error"].as_str() {
                report.fail(id, format!("layer error {message:?} != {:?}", golden["error"]));
            }
        }
        (LayerOutcome::Ok(hits), "ok") => {
            let expected = golden["results"].as_array().unwrap();
            if hits.len() != expected.len() {
                report.fail(id, format!("{} findings, golden {}", hits.len(), expected.len()));
                return;
            }
            report.finding_rows += usize::from(!hits.is_empty());
            for (hit, golden) in hits.iter().zip(expected) {
                let span = golden["span"].as_array().map(|pair| (pair[0].as_u64().unwrap() as usize, pair[1].as_u64().unwrap() as usize));
                if hit.span != span {
                    report.fail(id, format!("span {:?} != {span:?}", hit.span));
                }
                if Some(hit.text.as_str()) != golden["text"].as_str() {
                    report.fail(id, "finding text differs".to_string());
                }
                if u64::from(hit.classification.pack()) != golden["packed"].as_u64().unwrap() {
                    report.fail(id, format!("finding classification {} != {}", hit.classification.pack(), golden["packed"]));
                }
                if Some(hit.reasoning.as_str()) != golden["reasoning"].as_str() {
                    report.fail(id, format!("reasoning {:?} != {}", hit.reasoning, golden["reasoning"]));
                }
                check_confidence(report, id, hit.confidence, golden["confidence"].as_f64().unwrap(), raws);
            }
        }
        (outcome, status) => report.fail(id, format!("layer outcome {outcome:?} but golden status {status}")),
    }
}

/// Replay one V3 golden row.
pub fn check_v3_row(model: &V3Model, row: &Value, report: &mut Report) {
    let id = row["id"].as_str().unwrap().to_string();
    let text = row["text"].as_str().unwrap();
    let mut raws = None;
    report.rows += 1;
    if let Some(error) = row.get("error").and_then(Value::as_str) {
        match model.tokenize(text) {
            Err(mine) if mine.to_string() == error => {}
            other => report.fail(&id, format!("expected the error {error:?}, got {other:?}")),
        }
    } else {
        let ids: Vec<u32> = row["ids"].as_array().unwrap().iter().map(|v| v.as_u64().unwrap() as u32).collect();
        match model.tokenize(text) {
            Ok(mine) if mine == ids => match model.logits_for_ids(&ids) {
                Ok(logits) => {
                    compare_vectors(report, &id, "pooled", &logits.pooled, &row["pooled"], pooled_slot);
                    compare_vectors(report, &id, "sensitivity logits", &logits.sensitivity, &row["logits"]["sensitivity"], logit_slot);
                    compare_vectors(report, &id, "visibility logits", &logits.visibility, &row["logits"]["visibility"], logit_slot);
                    compare_vectors(report, &id, "category logits", &logits.category, &row["logits"]["category"], logit_slot);
                    match model.predict(text) {
                        Ok(prediction) => {
                            raws = row["decision"]["confidence_raw"].as_f64().map(|golden| (prediction.confidence_raw, golden));
                            check_decision(report, &id, &prediction, &row["decision"]);
                        }
                        Err(error) => report.fail(&id, format!("predict failed: {error}")),
                    }
                }
                Err(error) => report.fail(&id, format!("logits failed: {error}")),
            },
            Ok(mine) => report.fail(&id, format!("token ids {mine:?} != {ids:?}")),
            Err(error) => report.fail(&id, format!("tokenize failed: {error}")),
        }
    }
    check_layer(report, &id, model, text, &row["layer"], raws);
}

/// Replay one Tiny golden row.
pub fn check_tiny_row(model: &TinyModel, row: &Value, report: &mut Report) {
    let id = row["id"].as_str().unwrap().to_string();
    let text = row["text"].as_str().unwrap();
    report.rows += 1;
    let prediction = model.predict(text);
    let decision = &row["decision"];
    let ids: Vec<usize> = row["ids"].as_array().unwrap().iter().map(|v| v.as_u64().unwrap() as usize).collect();
    if prediction.ids != ids {
        report.fail(&id, format!("token ids {:?} != {ids:?}", prediction.ids));
    } else {
        compare_vectors(report, &id, "pooled", &prediction.pooled, &row["pooled"], pooled_slot);
        for (index, task) in ["sensitivity", "visibility", "category"].iter().enumerate() {
            compare_vectors(report, &id, &format!("{task} logits"), &prediction.logits[index], &row["logits"][*task], logit_slot);
        }
        let golden = serde_json::json!({
            "sensitivity": decision["sensitivity"], "visibility": decision["visibility"], "categories": decision["categories"],
            "confidence_raw": decision["confidence_raw"],
        });
        check_decision(report, &id, &prediction.decision, &golden);
    }
    let raws = decision["confidence_raw"].as_f64().map(|golden| (prediction.decision.confidence_raw, golden));
    check_layer(report, &id, model, text, &row["layer"], raws);
}
