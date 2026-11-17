//! Tiny gradients and the FULL projected Adam against the Python golden (`evaluation/generate_training_golden.py`),
//! semantic-only: the Python side runs the training modules directly and never builds a detector layer list.
//!
//! Categories reported (printed with `--nocapture`): gradient coordinates bitwise equal to torch, and within 1e-6;
//! Adam steps whose fingerprints equal Python's when fed Python's recorded gradients; and the chained Rust fit.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::path::PathBuf;

use privoke_training::TinyNet;
use privoke_training::adam::{self, F32Map};
use privoke_training::objective::{Example, Objective, Target, class_balanced, supervised_deltas};
use serde_json::Value;

const GRADIENT_TOLERANCE: f64 = 1e-6;

fn golden() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/tiny_training_golden.json");
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

fn bits_to_f32(value: &Value) -> Vec<f32> {
    value.as_array().unwrap().iter().map(|v| f32::from_bits(u32::try_from(v.as_u64().unwrap()).unwrap())).collect()
}

fn tensor_map(value: &Value) -> BTreeMap<String, Vec<f32>> {
    value.as_object().unwrap().iter().map(|(k, v)| (k.clone(), bits_to_f32(v))).collect()
}

fn widen(map: BTreeMap<String, Vec<f32>>) -> BTreeMap<String, Vec<f64>> {
    map.into_iter().map(|(k, v)| (k, v.into_iter().map(f64::from).collect())).collect()
}

fn examples(golden: &Value) -> Vec<Example> {
    golden["examples"]
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

fn recorded_directions(steps: &[Value]) -> Vec<BTreeMap<String, Vec<f64>>> {
    steps.iter().map(|s| widen(tensor_map(&s["direction"]))).collect()
}

#[derive(Default)]
struct Compare {
    coordinates: usize,
    bitwise: usize,
    within: usize,
    max_error: f64,
}

impl Compare {
    fn add(&mut self, rust: &[f64], python: &[f32]) {
        assert_eq!(rust.len(), python.len());
        for (r, p) in rust.iter().zip(python) {
            self.coordinates += 1;
            if (*r as f32).to_bits() == p.to_bits() {
                self.bitwise += 1;
            }
            let error = (r - f64::from(*p)).abs();
            if error <= GRADIENT_TOLERANCE {
                self.within += 1;
            }
            self.max_error = self.max_error.max(error);
        }
    }
}

#[test]
fn class_balanced_weights_match_python() {
    let golden = golden();
    let rows = examples(&golden);
    let expected: Vec<f64> = golden["adam"]["weights"].as_array().unwrap().iter().map(|w| w.as_f64().unwrap()).collect();
    let balanced = class_balanced(&rows).unwrap();
    let actual: Vec<f64> = balanced.iter().map(|e| e.weight).collect();
    assert_eq!(actual, expected);
}

#[test]
fn gradients_of_every_objective_match_torch() {
    let golden = golden();
    let rows = examples(&golden);
    let balanced = class_balanced(&rows).unwrap();
    let mut total = Compare::default();
    for case in golden["gradient_cases"].as_array().unwrap() {
        let model = case["model"].as_str().unwrap();
        let name = case["objective_name"].as_str().unwrap();
        let net = TinyNet::from_artifact(&golden["models"][model]).unwrap();
        let objective = Objective::from_name(case["objective"].as_str()).unwrap();
        let used = if case["objective"].is_null() { &rows } else { &balanced };
        let weights: Vec<f64> = case["weights"].as_array().unwrap().iter().map(|w| w.as_f64().unwrap()).collect();
        assert_eq!(used.iter().map(|e| e.weight).collect::<Vec<_>>(), weights);
        let result = supervised_deltas(&net, used, objective).unwrap();
        let python = tensor_map(&case["deltas"]);
        assert_eq!(result.deltas.keys().collect::<Vec<_>>(), python.keys().collect::<Vec<_>>());
        let mut compare = Compare::default();
        for (tensor, expected) in &python {
            compare.add(&result.deltas[tensor], expected);
        }
        let loss = case["loss"].as_f64().unwrap();
        eprintln!(
            "{model}/{name}: {} coordinates, bitwise {}, within 1e-6 {}, max error {:.3e}, loss {:.9} (python {loss:.9})",
            compare.coordinates, compare.bitwise, compare.within, compare.max_error, result.loss
        );
        assert_eq!(compare.within, compare.coordinates, "{model}/{name} gradient");
        assert!((result.loss - loss).abs() <= 1e-5 * loss.abs().max(1.0), "{model}/{name} loss {} vs {loss}", result.loss);
        let python_totals = case["task_totals"].as_object().filter(|t| !t.is_empty());
        match (result.task_totals, python_totals) {
            (Some(totals), Some(python_totals)) => {
                let names = ["supervised_sensitivity_ce_loss", "supervised_visibility_ce_loss", "supervised_category_bce_loss"];
                for (value, key) in totals.iter().zip(names) {
                    let expected = python_totals[key].as_f64().unwrap();
                    assert!((value - expected).abs() <= 1e-5 * expected.abs().max(1.0), "{model}/{name} {key}");
                }
            }
            (None, None) => {}
            (rust, python) => panic!("task totals differ in presence for {model}/{name}: {rust:?} vs {python:?}"),
        }
        total.coordinates += compare.coordinates;
        total.bitwise += compare.bitwise;
        total.within += compare.within;
        total.max_error = total.max_error.max(compare.max_error);
    }
    eprintln!(
        "gradients: {} cases, {} coordinates, bitwise {}, within 1e-6 {}, max error {:.3e}",
        golden["gradient_cases"].as_array().unwrap().len(),
        total.coordinates,
        total.bitwise,
        total.within,
        total.max_error
    );
}

#[test]
fn adam_recurrence_with_recorded_gradients_is_exact() {
    let golden = golden();
    let record = &golden["adam"];
    let net = TinyNet::from_artifact(&golden["models"]["task_query"]).unwrap();
    let steps = record["steps"].as_array().unwrap();
    let recorded = recorded_directions(steps);
    let rows = golden["examples"].as_array().unwrap().len();
    let fit = adam::fit_with(&net, rows, 64, |_, step| {
        let index = usize::try_from(step).unwrap() - 1;
        Ok((recorded[index].clone(), steps[index]["loss"].as_f64().unwrap()))
    })
    .unwrap();
    assert_eq!(fit.base, record["base_fingerprint"].as_str().unwrap());
    let (mut before, mut after, mut delta, mut clipped) = (0, 0, 0, 0);
    for (rust, python) in fit.steps.iter().zip(steps) {
        before += usize::from(rust.before == python["before"].as_str().unwrap());
        after += usize::from(rust.after == python["after"].as_str().unwrap());
        delta += usize::from(rust.delta == python["delta"].as_str().unwrap());
        clipped += usize::from(rust.clipped as u64 == python["clipped"].as_u64().unwrap());
    }
    eprintln!("adam replay: {} steps; before {before}, after {after}, delta {delta}, clipped {clipped}", fit.steps.len());
    assert_eq!((fit.steps.len(), before, after, delta, clipped), (64, 64, 64, 64, 64));
    assert_eq!(fit.final_fingerprint, record["final_fingerprint"].as_str().unwrap());
    assert_eq!(fit.delta, record["delta_fingerprint"].as_str().unwrap());
    let candidate: F32Map = tensor_map(&record["candidate_bits"]);
    assert_eq!(fit.candidate, candidate);
    let counts = &record["counts"];
    let batches = rows.div_ceil(32) as u64;
    assert_eq!(fit.counts.directions, counts["directions_completed"].as_u64().unwrap());
    assert_eq!(fit.counts.microbatches, counts["microbatch_forward_completed"].as_u64().unwrap());
    assert_eq!(fit.counts.microbatches, counts["microbatch_backward_completed"].as_u64().unwrap());
    assert_eq!(fit.counts.block_forwards, counts["torch_block_forwards_completed"].as_u64().unwrap());
    assert_eq!(fit.counts.parameter_states, counts["train_parameter_states"].as_u64().unwrap());
    assert_eq!(batches * 64, fit.counts.microbatches);
}

#[test]
fn rust_gradients_follow_the_python_trajectory() {
    // At every recorded Python state the Rust gradient is compared with the recorded torch direction; the replay then
    // continues along Python's own trajectory.
    let golden = golden();
    let record = &golden["adam"];
    let balanced = class_balanced(&examples(&golden)).unwrap();
    let net = TinyNet::from_artifact(&golden["models"]["task_query"]).unwrap();
    let steps = record["steps"].as_array().unwrap();
    let recorded = recorded_directions(steps);
    let mut compare = Compare::default();
    let mut visited = 0;
    let replay = adam::fit_with(&net, balanced.len(), 64, |current, step| {
        let index = usize::try_from(step).unwrap() - 1;
        let result = supervised_deltas(current, &balanced, Objective::SumMargin)?;
        for (tensor, values) in &result.deltas {
            let python: Vec<f32> = recorded[index][tensor].iter().map(|v| *v as f32).collect();
            compare.add(values, &python);
        }
        visited += 1;
        Ok((recorded[index].clone(), steps[index]["loss"].as_f64().unwrap()))
    })
    .unwrap();
    assert_eq!(replay.final_fingerprint, record["final_fingerprint"].as_str().unwrap());
    eprintln!(
        "trajectory gradients: {visited} steps, {} coordinates, bitwise {}, within 1e-6 {}, max error {:.3e}",
        compare.coordinates, compare.bitwise, compare.within, compare.max_error
    );
    assert_eq!(visited, 64);
    assert_eq!(compare.within, compare.coordinates);
}

#[test]
fn chained_rust_fit_reports_its_deviation_from_python() {
    let golden = golden();
    let record = &golden["adam"];
    let balanced = class_balanced(&examples(&golden)).unwrap();
    let net = TinyNet::from_artifact(&golden["models"]["task_query"]).unwrap();
    let fit = adam::fit(&net, &balanced, 64).unwrap();
    let python = tensor_map(&record["candidate_bits"]);
    let (mut coordinates, mut bitwise, mut within, mut max_error) = (0usize, 0usize, 0usize, 0f64);
    for (tensor, expected) in &python {
        for (r, p) in fit.candidate[tensor].iter().zip(expected) {
            coordinates += 1;
            bitwise += usize::from(r.to_bits() == p.to_bits());
            let error = f64::from(*r - *p).abs();
            within += usize::from(error <= 1e-6);
            max_error = max_error.max(error);
        }
    }
    let identical = fit.final_fingerprint == record["final_fingerprint"].as_str().unwrap();
    eprintln!(
        "chained fit: {coordinates} candidate coordinates, bitwise {bitwise}, within 1e-6 {within}, max error {max_error:.3e}, fingerprint identical {identical}"
    );
    assert_eq!(fit.steps.len(), 64);
    assert_eq!(fit.counts.parameter_states, 65);
    // The gradients are not bitwise torch's, so this run is in the tolerance category: same inventory and shapes,
    // every coordinate within 1e-6.
    assert_eq!(within, coordinates);
}
