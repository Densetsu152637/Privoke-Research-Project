//! `clip_grad_norm_` and AdamW against `torch` in float64 (`generate_adamw_golden.py`, synthetic tensors, two learning-rate
//! groups): the norm before clipping, the clipped gradients and the parameters after every step, within 1e-12 relative to
//! max(1, |v|); the bitwise count is printed.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;

use privoke_training::adamw::{AdamW, clip_grad_norm};
use serde_json::Value;

fn floats(value: &Value) -> Vec<f64> {
    value.as_array().unwrap().iter().map(|v| v.as_f64().unwrap()).collect()
}

fn list(value: &Value) -> Vec<Vec<f64>> {
    value.as_array().unwrap().iter().map(floats).collect()
}

#[test]
fn the_optimizer_matches_torch() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/adamw_golden.json");
    let golden: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let (mut count, mut bitwise, mut worst) = (0usize, 0usize, 0f64);
    let mut compare = |label: &str, rust: &[f64], python: &[f64]| {
        assert_eq!(rust.len(), python.len(), "{label}");
        for (a, b) in rust.iter().zip(python) {
            let error = (a - b).abs() / b.abs().max(1.0);
            assert!(error < 1e-12, "{label}: {a} against {b}");
            count += 1;
            bitwise += usize::from(a.to_bits() == b.to_bits());
            worst = worst.max(error);
        }
    };
    for case in golden["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let betas = floats(&case["betas"]);
        let rates_of_group = floats(&case["rates"]);
        let mut rates = vec![0.0; 4];
        for (group, rate) in case["groups"].as_array().unwrap().iter().zip(&rates_of_group) {
            for index in group.as_array().unwrap() {
                rates[usize::try_from(index.as_u64().unwrap()).unwrap()] = *rate;
            }
        }
        let mut params = list(&case["initial"]);
        let mut optimizer =
            AdamW::new((betas[0], betas[1]), case["eps"].as_f64().unwrap(), &params.iter().map(Vec::len).collect::<Vec<_>>());
        for (index, step) in case["steps"].as_array().unwrap().iter().enumerate() {
            let mut grads = list(&step["grads"]);
            let norm = clip_grad_norm(&mut grads.iter_mut().collect::<Vec<_>>(), case["clip_norm"].as_f64().unwrap()).unwrap();
            compare(&format!("{name} step {index} norm"), &[norm], &[step["norm"].as_f64().unwrap()]);
            for (tensor, (rust, python)) in grads.iter().zip(list(&step["clipped"])).enumerate() {
                compare(&format!("{name} step {index} clipped {tensor}"), rust, &python);
            }
            let views: Vec<&[f64]> = grads.iter().map(Vec::as_slice).collect();
            optimizer.step(&mut params.iter_mut().collect::<Vec<_>>(), &views, &rates).unwrap();
            for (tensor, python) in list(&step["params"]).iter().enumerate() {
                compare(&format!("{name} step {index} param {tensor}"), &params[tensor], python);
            }
        }
        assert_eq!(optimizer.steps(), 8);
    }
    eprintln!("adamw and clip_grad_norm: {count} values within 1e-12, {bitwise} bitwise, max relative {worst:.3e}");
}
