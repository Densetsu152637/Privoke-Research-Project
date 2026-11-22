//! The local-SGD, backtracking and TRAIN-diagnostics routes of `_compute_training_gradients`, and the artifact policy and
//! admission refusals that choose them, against the Python golden (`generate_training_golden.py routes`): transported
//! update, response metrics, the held-out guard outcome, the response error and the route metadata strings.
//! Semantic-only: no detector layer runs on either side.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::path::PathBuf;

use privoke_training::admission::{Admitted, Fields, Header, admit};
use privoke_training::objective::{Example, Target};
use privoke_training::rpc::{Request, Snapshot, compute_gradients};
use serde_json::Value;

/// Metadata that carries JSON: compared structurally (numbers within a relative 1e-5, integers and text exactly).
const JSON_KEYS: [&str; 4] = [
    "contextual_optimizer_trace",
    "contextual_training_diagnostics",
    "contextual_training_backtracking_trace",
    "contextual_training_backtracking_trials",
];
/// Every metadata key the routes add.
const ROUTE_KEYS: [&str; 8] = [
    "contextual_optimizer_trace",
    "contextual_training_diagnostics_policy",
    "contextual_training_diagnostics",
    "contextual_training_backtracking_policy",
    "contextual_training_backtracking_preparation",
    "contextual_training_backtracking_trace",
    "contextual_training_backtracking_trials",
    "effective_learning_rate",
];

fn golden() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/tiny_training_routes_golden.json");
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

fn rows(value: &Value) -> Vec<Example> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|row| Example {
            text: row["text"].as_str().unwrap().to_string(),
            target: Target {
                sensitivity: row["sensitivity"].as_str().unwrap().to_string(),
                visibility: row["visibility"].as_str().unwrap().to_string(),
                categories: row["categories"].as_array().unwrap().iter().map(|c| c.as_str().unwrap().to_string()).collect(),
            },
            weight: row["weight"].as_f64().unwrap(),
        })
        .collect()
}

fn bits(value: &Value) -> Vec<f32> {
    value.as_array().unwrap().iter().map(|v| f32::from_bits(u32::try_from(v.as_u64().unwrap()).unwrap())).collect()
}

fn fields(value: &Value) -> Fields {
    value.as_object().unwrap().iter().map(|(key, text)| (key.clone(), text.as_str().unwrap().to_string())).collect()
}

fn header(value: &Value) -> Option<Header> {
    value.as_object().map(|entries| entries.iter().map(|(key, text)| (key.clone(), text.as_str().map(str::to_string))).collect())
}

/// Metrics that are exact counts or rates of decisions: any difference is a changed decision.
fn is_decision_metric(key: &str) -> bool {
    key.contains("heldout") || key.starts_with("exact_match") || key.starts_with("examples") || key.ends_with("_examples")
}

fn is_hash(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[derive(Default)]
struct JsonTally {
    numbers: usize,
    max_relative: f64,
    hashes: usize,
    hashes_equal: usize,
}

/// Structural comparison of two trace records. The fingerprints of the base state and the inventory depend on no
/// computed value, so they must be equal; every other fingerprint hashes values that are within the tolerance only,
/// and is counted.
fn close(path: &str, got: &Value, want: &Value, tally: &mut JsonTally) -> Result<(), String> {
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
            tally.numbers += 1;
            tally.max_relative = tally.max_relative.max(relative);
            if relative <= 1e-5 { Ok(()) } else { Err(format!("{path}: {x} against {y}, relative error {relative:e}")) }
        }
        (Value::String(a), Value::String(b)) if is_hash(a) && is_hash(b) => {
            tally.hashes += 1;
            tally.hashes_equal += usize::from(a == b);
            let value_independent = path.ends_with("fingerprints[0]") || path.ends_with(".base[0]") || path.ends_with(".raw[1]");
            if value_independent && a != b { Err(format!("{path}: {a} against {b}")) } else { Ok(()) }
        }
        (Value::Array(a), Value::Array(b)) => {
            if a.len() != b.len() {
                return Err(format!("{path}: {} items against {}", a.len(), b.len()));
            }
            for (index, (x, y)) in a.iter().zip(b).enumerate() {
                close(&format!("{path}[{index}]"), x, y, tally)?;
            }
            Ok(())
        }
        (Value::Object(a), Value::Object(b)) => {
            if a.keys().ne(b.keys()) {
                return Err(format!("{path}: keys {:?} against {:?}", a.keys().collect::<Vec<_>>(), b.keys().collect::<Vec<_>>()));
            }
            for (key, x) in a {
                close(&format!("{path}.{key}"), x, &b[key], tally)?;
            }
            Ok(())
        }
        _ if got == want => Ok(()),
        _ => Err(format!("{path}: {got} against {want}")),
    }
}

#[derive(Default)]
struct Route {
    cases: usize,
    coordinates: usize,
    bitwise: usize,
    max_error: f64,
}

#[test]
fn routes_match_python() {
    let golden = golden();
    let (examples, heldout) = (rows(&golden["examples"]), rows(&golden["heldout"]));
    let cases = golden["cases"].as_array().unwrap();
    let mut routes: BTreeMap<String, Route> = BTreeMap::new();
    let mut json = JsonTally::default();
    let (mut served, mut refusals) = (0usize, 0usize);
    let (mut coordinates, mut within, mut bitwise, mut max_error) = (0usize, 0usize, 0usize, 0f64);
    let (mut metrics_total, mut metrics_close, mut guard_equal) = (0usize, 0usize, 0usize);
    let (mut accepted, mut rejected) = (0usize, 0usize);
    let (mut strings, mut strings_equal) = (0usize, 0usize);
    let mut selected: BTreeMap<String, usize> = BTreeMap::new();
    for case in cases {
        let label = case["label"].as_str().unwrap();
        let model = case["model"].as_str().unwrap();
        let metadata = fields(&case["metadata"]);
        let admission = header(&case["admission"]);
        let full_encoder = case["full_encoder"].as_bool().unwrap();
        let train: Vec<Example> = case["example_indices"]
            .as_array()
            .unwrap()
            .iter()
            .map(|index| examples[usize::try_from(index.as_u64().unwrap()).unwrap()].clone())
            .collect();
        let request = Request {
            examples: train,
            heldout: heldout.clone(),
            learning_rate: case["learning_rate"].as_f64().unwrap(),
            max_gradient: case["max_gradient"].as_f64().unwrap(),
            full_encoder,
        };
        let outcome = match admit(admission.as_ref(), &metadata, full_encoder) {
            Err(error) => Err(error.to_string()),
            Ok(Admitted::Elsewhere(reason)) => panic!("{label}: another worker serves it: {reason}"),
            Ok(Admitted::Route(route)) => {
                let snapshot = Snapshot {
                    artifact: golden["models"][model].clone(),
                    full_capable: true,
                    objective: route.objective,
                    optimizer: route.optimizer,
                    diagnostics: route.diagnostics,
                    backtracking: route.backtracking,
                };
                compute_gradients(&snapshot, &request).map_err(|error| error.to_string())
            }
        };
        if let Some(refusal) = case.get("refusal") {
            match outcome {
                Err(message) => assert_eq!(message, refusal.as_str().unwrap(), "{label}: the refusal text"),
                Ok(_) => panic!("{label}: the Rust computation served a request that Python refused with {refusal}"),
            }
            refusals += 1;
            continue;
        }
        let batch = outcome.unwrap_or_else(|message| panic!("{label}: refused with {message:?}"));
        served += 1;
        let route_name = label.split('/').nth(1).unwrap().to_string();
        assert_eq!(batch.scope, case["scope"].as_str().unwrap(), "{label}");
        assert_eq!(batch.error, case["error"].as_str().unwrap(), "{label}: the response error");
        let python: BTreeMap<String, Vec<f32>> = case["gradients"].as_object().unwrap().iter().map(|(k, v)| (k.clone(), bits(v))).collect();
        assert_eq!(batch.gradients.keys().collect::<Vec<_>>(), python.keys().collect::<Vec<_>>(), "{label} inventory");
        let (mut case_n, mut case_bits, mut case_max) = (0usize, 0usize, 0f64);
        for (name, expected) in &python {
            for (r, p) in batch.gradients[name].iter().zip(expected) {
                case_n += 1;
                case_bits += usize::from(r.to_bits() == p.to_bits());
                let error = f64::from(*r - *p).abs();
                within += usize::from(error <= 1e-6);
                case_max = case_max.max(error);
            }
        }
        coordinates += case_n;
        bitwise += case_bits;
        max_error = max_error.max(case_max);
        let entry = routes.entry(route_name).or_default();
        entry.cases += 1;
        entry.coordinates += case_n;
        entry.bitwise += case_bits;
        entry.max_error = entry.max_error.max(case_max);
        eprintln!("routes case {label}: {case_n} coordinates, bitwise {case_bits}, max error {case_max:.3e}");
        let expected_metrics = case["metrics"].as_object().unwrap();
        assert_eq!(
            batch.metrics.keys().map(String::as_str).collect::<Vec<_>>(),
            expected_metrics.keys().map(String::as_str).collect::<Vec<_>>(),
            "{label} metric names"
        );
        for (key, expected) in expected_metrics {
            let (actual, expected) = (batch.metrics[key], expected.as_f64().unwrap());
            metrics_total += 1;
            let ok = if is_decision_metric(key) {
                (actual - expected).abs() < 1e-12
            } else {
                (actual - expected).abs() <= 1e-5 * expected.abs().max(1.0)
            };
            metrics_close += usize::from(ok);
            assert!(ok, "{label} {key}: {actual} vs {expected}");
        }
        let key = "candidate_heldout_safety_regression_rate";
        match (batch.metrics.get(key), expected_metrics.get(key)) {
            (Some(rust), Some(python)) => {
                let python = python.as_f64().unwrap();
                guard_equal += usize::from(*rust == python);
                assert_eq!(*rust == 0.0, python == 0.0, "{label}: the guard outcome");
                if python == 0.0 {
                    accepted += 1;
                } else {
                    rejected += 1;
                }
            }
            (None, None) => {}
            other => panic!("{label}: the guard metric is present on one side only: {other:?}"),
        }
        assert_eq!(
            batch.executions.iter().map(|(p, n)| (p.as_str(), *n)).collect::<Vec<_>>(),
            case["executions"]
                .as_array()
                .unwrap()
                .iter()
                .map(|e| (e[0].as_str().unwrap(), usize::try_from(e[1].as_u64().unwrap()).unwrap()))
                .collect::<Vec<_>>(),
            "{label} executions"
        );
        let python_meta = case["metadata_out"].as_object().unwrap();
        assert_eq!(serde_json::to_string(&batch.inventory).unwrap(), python_meta["trained_parameter_names"].as_str().unwrap(), "{label}");
        for key in ROUTE_KEYS {
            assert_eq!(batch.metadata.contains_key(key), python_meta.contains_key(key), "{label}: metadata {key} on one side only");
        }
        for (key, value) in &batch.metadata {
            let want = python_meta[key].as_str().unwrap();
            strings += 1;
            strings_equal += usize::from(value == want);
            if JSON_KEYS.contains(&key.as_str()) {
                let (got, expected): (Value, Value) = (serde_json::from_str(value).unwrap(), serde_json::from_str(want).unwrap());
                close("$", &got, &expected, &mut json).unwrap_or_else(|reason| panic!("{label} {key}: {reason}"));
            } else {
                assert_eq!(value, want, "{label} {key}");
            }
        }
        if let Some(trace) = python_meta.get("contextual_training_backtracking_trace") {
            let trace: Value = serde_json::from_str(trace.as_str().unwrap()).unwrap();
            let outcome = match trace["selected"].as_u64() {
                None => "rejected".to_string(),
                Some(index) => format!("selected scale {index}"),
            };
            *selected.entry(outcome).or_default() += 1;
        }
    }
    for (name, route) in &routes {
        eprintln!(
            "routes {name}: {} cases, {} coordinates, {} bitwise, max error {:.3e}",
            route.cases, route.coordinates, route.bitwise, route.max_error
        );
    }
    eprintln!(
        "routes: {served} served cases and {refusals} refusals (identical texts); transported coordinates {coordinates}, within 1e-6 {within}, bitwise {bitwise}, max error {max_error:.3e}; metrics {metrics_close}/{metrics_total}; guard rate equal {guard_equal}, accept/reject equal {} of {} (accepted {accepted}, rejected {rejected}); backtracking {selected:?}; trace JSON: {} numbers within 1e-5 (max relative {:.3e}), {} of {} value-dependent fingerprints equal; {strings_equal} of {strings} route metadata strings byte-equal",
        accepted + rejected,
        accepted + rejected,
        json.numbers,
        json.max_relative,
        json.hashes_equal,
        json.hashes
    );
    assert_eq!(within, coordinates);
    assert!(served >= 40 && refusals >= 20, "{served} served, {refusals} refused");
    assert_eq!(selected.values().sum::<usize>(), 24, "{selected:?}");
}
