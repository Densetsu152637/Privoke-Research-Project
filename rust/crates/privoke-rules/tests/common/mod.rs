//! Shared comparison of Rust output with the Python golden rows (used by the integration
//! tests and by the `parity` example).

#![allow(dead_code)]

use std::collections::HashMap;

use privoke_rules::{
    Detector, LayerOptions, LayerOutcome, RobustnessOptions, RuleSetOptions, analyse_regex_layer, normalize_with_offsets,
    preprocessing::NormalizeError,
};
use serde_json::Value;

/// `NORM_CONFIGS` of `evaluation/generate_rules_golden.py`.
pub fn norm_config(name: &str) -> (bool, RobustnessOptions) {
    let (lowercase, format, digits, email) = match name {
        "lower" => (true, false, false, false),
        "case" => (false, false, false, false),
        "case+format" => (false, true, false, false),
        "case+digits" => (false, false, true, false),
        "case+email" => (false, false, false, true),
        "case+all" => (false, true, true, true),
        "lower+all" => (true, true, true, true),
        other => panic!("unknown normalisation config {other}"),
    };
    (lowercase, RobustnessOptions { strip_format_chars: format, canonicalise_digits: digits, canonicalise_email_words: email })
}

/// `LAYER_CONFIGS` of `evaluation/generate_rules_golden.py`.
pub fn layer_config(name: &str) -> (LayerOptions, RuleSetOptions) {
    let (case_preserving, format, digits, email, presidio, gitleaks) = match name {
        "default" => (true, false, false, false, true, true),
        "lowercase" => (false, false, false, false, true, true),
        "format" => (true, true, false, false, true, true),
        "digits" => (true, false, true, false, true, true),
        "email" => (true, false, false, true, true, true),
        "all-flags" => (true, true, true, true, true, true),
        "no-presidio" => (true, false, false, false, false, true),
        "no-gitleaks" => (true, false, false, false, true, false),
        "no-external" => (true, false, false, false, false, false),
        other => panic!("unknown layer config {other}"),
    };
    let robustness = RobustnessOptions { strip_format_chars: format, canonicalise_digits: digits, canonicalise_email_words: email };
    (LayerOptions { case_preserving, robustness: Some(robustness) }, RuleSetOptions { presidio, gitleaks })
}

/// One detector per rule-set selection.
#[derive(Default)]
pub struct Detectors(HashMap<(bool, bool), Detector>);

impl Detectors {
    pub fn get(&mut self, options: RuleSetOptions) -> &Detector {
        self.0
            .entry((options.presidio, options.gitleaks))
            .or_insert_with(|| Detector::new(options).unwrap_or_else(|error| panic!("detector: {error}")))
    }
}

/// Counts for one comparison family.
#[derive(Default, Clone, Debug)]
pub struct Tally {
    pub compared: usize,
    pub identical: usize,
    pub differences: Vec<String>,
}

impl Tally {
    pub fn record(&mut self, difference: Option<String>) {
        self.compared += 1;
        match difference {
            None => self.identical += 1,
            Some(text) => {
                if self.differences.len() < 20 {
                    self.differences.push(text);
                }
            }
        }
    }
}

fn decode_runs(value: &Value) -> Vec<(usize, usize)> {
    let mut origins = Vec::new();
    for run in value.as_array().expect("runs array") {
        let run = run.as_array().expect("run");
        let (start, end, count) =
            (run[0].as_u64().unwrap_or(0) as usize, run[1].as_u64().unwrap_or(0) as usize, run[2].as_u64().unwrap_or(0));
        origins.extend(std::iter::repeat_n((start, end), count as usize));
    }
    origins
}

/// Compare a normalisation; `None` when identical.
pub fn compare_norm(id: &str, name: &str, text: &str, golden: &Value) -> Option<String> {
    let (lowercase, options) = norm_config(name);
    let actual = normalize_with_offsets(text, lowercase, Some(options));
    if let Some(expected) = golden.get("error").and_then(Value::as_str) {
        return match actual {
            Err(error @ NormalizeError::UnknownDigitWord(_)) if error.to_string() == expected => None,
            other => Some(format!("{id} {name}: expected error {expected:?}, got {:?}", other.map(|n| n.text().to_owned()))),
        };
    }
    let expected_text = golden["text"].as_str().unwrap_or_default();
    let expected_origins = decode_runs(&golden["runs"]);
    match actual {
        Err(error) => Some(format!("{id} {name}: unexpected error {error}")),
        Ok(actual) if actual.text() == expected_text && actual.origins() == expected_origins.as_slice() => None,
        Ok(actual) if actual.text() != expected_text => Some(format!("{id} {name}: text {:?} != {:?}", actual.text(), expected_text)),
        Ok(actual) => Some(format!("{id} {name}: origins differ (lens {} vs {})", actual.origins().len(), expected_origins.len())),
    }
}

/// Compare a regex-layer run; `None` when identical.
pub fn compare_layer(id: &str, name: &str, text: &str, golden: &Value, detectors: &mut Detectors) -> Option<String> {
    let (options, rules) = layer_config(name);
    let detector = detectors.get(rules);
    let actual = match analyse_regex_layer(detector, text, &options) {
        Ok(outcome) => outcome,
        Err(error) => return Some(format!("{id} {name}: detector failed: {error}")),
    };
    if let Some(expected) = golden.get("error").and_then(Value::as_str) {
        return match actual {
            LayerOutcome::Error(message) if message == expected => None,
            other => Some(format!("{id} {name}: expected error {expected:?}, got {other:?}")),
        };
    }
    let LayerOutcome::Ok(hits) = actual else { return Some(format!("{id} {name}: unexpected error outcome")) };
    let expected = golden.as_array().expect("hit array");
    if hits.len() != expected.len() {
        let names: Vec<&str> = hits.iter().map(|hit| hit.rule_name.as_str()).collect();
        let want: Vec<&str> = expected.iter().filter_map(|hit| hit["rule"].as_str()).collect();
        return Some(format!("{id} {name}: {} hits vs {} expected: {names:?} vs {want:?}", hits.len(), expected.len()));
    }
    for (index, (hit, want)) in hits.iter().zip(expected).enumerate() {
        let span = hit.span.map(|(a, b)| vec![a as u64, b as u64]);
        let want_span: Option<Vec<u64>> = want["span"].as_array().map(|items| items.iter().filter_map(Value::as_u64).collect());
        let same = want["rule"].as_str() == Some(hit.rule_name.as_str())
            && want["text"].as_str() == Some(hit.text.as_str())
            && want["packed"].as_u64() == Some(u64::from(hit.classification.pack()))
            && want["confidence"].as_f64() == Some(hit.confidence)
            && span == want_span;
        if !same {
            return Some(format!("{id} {name}: hit {index} {hit:?} != {want}"));
        }
    }
    None
}

/// Compare every configuration of one golden row.
pub fn compare_row(row: &Value, detectors: &mut Detectors, norm: &mut Tally, layer: &mut Tally) {
    let id = row["id"].as_str().unwrap_or("?");
    let text = row["text"].as_str().unwrap_or_default();
    if let Some(configs) = row["norm"].as_object() {
        for (name, golden) in configs {
            norm.record(compare_norm(id, name, text, golden));
        }
    }
    if let Some(configs) = row["layer"].as_object() {
        for (name, golden) in configs {
            layer.record(compare_layer(id, name, text, golden, detectors));
        }
    }
}
