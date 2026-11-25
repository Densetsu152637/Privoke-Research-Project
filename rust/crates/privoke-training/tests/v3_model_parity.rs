//! The V3 model forward and microbatch loss gradient against `generate_v3_model_golden.py`: `transformers.BertModel` (padded
//! batch, attention mask) with three affine heads in float64 on seeded synthetic float32 weights (no study data). The Rust
//! model is built from the same float32 tensors `Encoder::from_tensors` of `privoke-semantic` reads, and its pooled output is
//! also compared with that encoder's. Tolerance 1e-9 relative to max(1, |v|) (both float64); the bitwise count is printed.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::path::PathBuf;

use privoke_semantic::bert::{BertConfig, Encoder};
use privoke_semantic::safetensors::Tensor;
use privoke_training::v3_model::{Example, V3Params, microbatch, sequence_forward};
use serde_json::Value;

fn floats(value: &Value) -> Vec<f64> {
    value.as_array().unwrap().iter().map(|v| v.as_f64().unwrap()).collect()
}

fn golden() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/v3_model_golden.json");
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

fn tensors(case: &Value) -> BTreeMap<String, Tensor> {
    case["tensors"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(name, record)| {
            let shape = record["shape"].as_array().unwrap().iter().map(|d| usize::try_from(d.as_u64().unwrap()).unwrap()).collect();
            let data = floats(&record["data"]).into_iter().map(|v| v as f32).collect();
            (name.clone(), Tensor { shape, data, sha256: String::new() })
        })
        .collect()
}

fn examples(case: &Value) -> Vec<Example> {
    case["examples"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| Example {
            ids: row["ids"].as_array().unwrap().iter().map(|v| u32::try_from(v.as_u64().unwrap()).unwrap()).collect(),
            sensitivity: usize::try_from(row["sensitivity"].as_u64().unwrap()).unwrap(),
            visibility: usize::try_from(row["visibility"].as_u64().unwrap()).unwrap(),
            categories: floats(&row["categories"]),
        })
        .collect()
}

fn relative(a: f64, b: f64) -> f64 {
    (a - b).abs() / b.abs().max(1.0)
}

fn setup(case: &Value) -> (BertConfig, BTreeMap<String, Tensor>, V3Params, Vec<Example>) {
    let config = BertConfig::from_json(&case["config"].to_string()).unwrap();
    let map = tensors(case);
    let params = V3Params::from_tensors(&config, &map).unwrap();
    (config, map, params, examples(case))
}

#[test]
fn the_forward_and_loss_gradient_match_the_torch_golden() {
    let golden = golden();
    let (mut count, mut bitwise, mut worst) = (0usize, 0usize, 0f64);
    for case in golden["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let (config, map, params, rows) = setup(case);
        // The forward: pooled output and logits per row, against Python's padded batch and the semantic crate's encoder.
        let mut encoder_tensors: BTreeMap<String, Tensor> =
            map.iter().filter(|(k, _)| k.starts_with("encoder.")).map(|(k, v)| (k.clone(), v.clone())).collect();
        let encoder = Encoder::from_tensors(config, &mut encoder_tensors, "encoder.").unwrap();
        assert!(encoder_tensors.is_empty(), "{name}: the encoder consumed every encoder tensor");
        for (index, row) in rows.iter().enumerate() {
            let cache = sequence_forward(&params, &row.ids).unwrap();
            let python = floats(&case["pooled"][index]);
            for (a, b) in cache.pooled.iter().zip(&python) {
                assert!(relative(*a, *b) < 1e-9, "{name} row {index}: pooled {a} against {b}");
            }
            let native = encoder.pooled(&row.ids, 1).unwrap();
            for (a, b) in cache.pooled.iter().zip(&native) {
                assert!((a - f64::from(*b)).abs() < 1e-6, "{name} row {index}: pooled {a} against the semantic encoder's {b}");
            }
            for (task, key) in ["sensitivity", "visibility", "category"].iter().enumerate() {
                for (a, b) in cache.logits[task].iter().zip(floats(&case["logits"][*key][index])) {
                    assert!(relative(*a, b) < 1e-9, "{name} row {index} {key}: {a} against {b}");
                }
            }
        }
        // The loss and every parameter gradient of the microbatch.
        let mut grads = params.zeros_like();
        let loss = microbatch(&params, &rows, case["scale"].as_f64().unwrap(), &mut grads).unwrap();
        let expected = case["loss"].as_f64().unwrap();
        assert!(relative(loss, expected) < 1e-9, "{name}: loss {loss} against {expected}");
        let mut local = (0usize, 0usize, 0f64);
        for (parameter, values) in grads.named_mut() {
            let python = floats(&case["grads"][parameter.as_str()]);
            assert_eq!(values.len(), python.len(), "{name} {parameter}");
            let worst_here = values.iter().zip(&python).map(|(a, b)| relative(*a, *b)).fold(0f64, f64::max);
            assert!(worst_here < 1e-9, "{name} {parameter}: max relative error {worst_here:.3e}");
            local.0 += values.len();
            local.1 += values.iter().zip(&python).filter(|(a, b)| a.to_bits() == b.to_bits()).count();
            local.2 = local.2.max(worst_here);
        }
        eprintln!(
            "{name}: loss {loss} (Python {expected}); {} gradient values, {} bitwise, max relative error {:.3e}",
            local.0, local.1, local.2
        );
        count += local.0;
        bitwise += local.1;
        worst = worst.max(local.2);
    }
    eprintln!("v3 model gradient: {count} values, all within 1e-9, {bitwise} bitwise, max relative {worst:.3e}");
}

#[test]
fn microbatches_accumulate() {
    let golden = golden();
    let case = &golden["cases"][0];
    let (_, _, params, rows) = setup(case);
    let mut whole = params.zeros_like();
    let total = microbatch(&params, &rows, 64.0, &mut whole).unwrap();
    let mut split = params.zeros_like();
    let (left, right) = rows.split_at(1);
    let sum = microbatch(&params, left, 64.0, &mut split).unwrap() + microbatch(&params, right, 64.0, &mut split).unwrap();
    assert!(relative(total, sum) < 1e-12);
    for ((name, a), (_, b)) in whole.named_mut().into_iter().zip(split.named_mut()) {
        for (x, y) in a.iter().zip(b.iter()) {
            assert!(relative(*x, *y) < 1e-12, "{name}");
        }
    }
}

#[test]
fn the_gradient_agrees_with_finite_differences() {
    let golden = golden();
    let case = &golden["cases"][1];
    let (_, _, params, rows) = setup(case);
    let mut grads = params.zeros_like();
    microbatch(&params, &rows, 64.0, &mut grads).unwrap();
    let step = 1e-6;
    let mut worst: f64 = 0.0;
    let mut probe = params.clone();
    let names: Vec<String> = probe.named_mut().into_iter().map(|(name, _)| name).collect();
    for (slot, name) in names.iter().enumerate() {
        let analytic = grads.named_mut().remove(slot).1.clone();
        // A few coordinates of every tensor (the token-type table and unused embedding rows have zero gradient).
        for index in (0..analytic.len()).step_by(analytic.len().div_ceil(5)) {
            let value = |delta: f64| {
                let mut moved = params.clone();
                moved.named_mut().remove(slot).1[index] += delta;
                let mut sink = params.zeros_like();
                microbatch(&moved, &rows, 64.0, &mut sink).unwrap()
            };
            let numeric = (value(step) - value(-step)) / (2.0 * step);
            let error = (numeric - analytic[index]).abs() / analytic[index].abs().max(1.0);
            assert!(error < 1e-6, "{name}[{index}]: numeric {numeric} against analytic {}", analytic[index]);
            worst = worst.max(error);
        }
    }
    eprintln!("v3 model finite differences: max relative error {worst:.3e}");
}
