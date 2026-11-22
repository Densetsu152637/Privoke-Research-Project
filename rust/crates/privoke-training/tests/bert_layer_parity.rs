//! The BERT encoder-layer backward against `transformers.BertModel`'s own layers in float64 (`generate_bert_layer_golden.py`,
//! seeded synthetic weights, no study data): the stack output, the gradient of the input and of every layer parameter for the
//! loss `sum(w * output)`. Both sides are float64 and the sums differ only in order, so the tolerance is 1e-9 relative to
//! max(1, |v|); the bitwise count is printed. A central finite difference of the Rust forward then checks the Rust backward
//! independently of Torch.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;

use privoke_training::bert_backward::{Dense, LayerParams, Norm, layer_forward, stack_backward};
use serde_json::Value;

fn floats(value: &Value) -> Vec<f64> {
    value.as_array().unwrap().iter().map(|v| v.as_f64().unwrap()).collect()
}

fn dense(record: &Value, grad: bool) -> Dense {
    let suffix = if grad { "_grad" } else { "" };
    Dense { weight: floats(&record[format!("weight{suffix}")]), bias: floats(&record[format!("bias{suffix}")]) }
}

fn norm(record: &Value, grad: bool) -> Norm {
    let suffix = if grad { "_grad" } else { "" };
    Norm { gamma: floats(&record[format!("gamma{suffix}")]), beta: floats(&record[format!("beta{suffix}")]) }
}

fn params(record: &Value, grad: bool) -> LayerParams {
    LayerParams {
        query: dense(&record["query"], grad),
        key: dense(&record["key"], grad),
        value: dense(&record["value"], grad),
        attention_output: dense(&record["attention_output"], grad),
        attention_norm: norm(&record["attention_norm"], grad),
        intermediate: dense(&record["intermediate"], grad),
        output: dense(&record["output"], grad),
        output_norm: norm(&record["output_norm"], grad),
    }
}

fn parts(p: &LayerParams) -> Vec<(&'static str, &[f64])> {
    vec![
        ("query.weight", &p.query.weight),
        ("query.bias", &p.query.bias),
        ("key.weight", &p.key.weight),
        ("key.bias", &p.key.bias),
        ("value.weight", &p.value.weight),
        ("value.bias", &p.value.bias),
        ("attention_output.weight", &p.attention_output.weight),
        ("attention_output.bias", &p.attention_output.bias),
        ("attention_norm.gamma", &p.attention_norm.gamma),
        ("attention_norm.beta", &p.attention_norm.beta),
        ("intermediate.weight", &p.intermediate.weight),
        ("intermediate.bias", &p.intermediate.bias),
        ("output.weight", &p.output.weight),
        ("output.bias", &p.output.bias),
        ("output_norm.gamma", &p.output_norm.gamma),
        ("output_norm.beta", &p.output_norm.beta),
    ]
}

#[derive(Default)]
struct Tally {
    count: usize,
    bitwise: usize,
    within: usize,
    worst: f64,
}

impl Tally {
    fn add(&mut self, rust: &[f64], python: &[f64], tolerance: f64) {
        assert_eq!(rust.len(), python.len());
        for (a, b) in rust.iter().zip(python) {
            let error = (a - b).abs() / b.abs().max(1.0);
            self.count += 1;
            self.bitwise += usize::from(a.to_bits() == b.to_bits());
            self.within += usize::from(error <= tolerance);
            self.worst = self.worst.max(error);
        }
    }
}

fn golden() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/bert_layer_golden.json");
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

fn dims(case: &Value) -> (usize, usize, usize, f64) {
    let size = |key: &str| usize::try_from(case[key].as_u64().unwrap()).unwrap();
    (size("rows"), size("hidden"), size("heads"), case["eps"].as_f64().unwrap())
}

fn layer_records(case: &Value, grad: bool) -> Vec<LayerParams> {
    case["layer_params"].as_array().unwrap().iter().map(|record| params(record, grad)).collect()
}

#[test]
fn the_layer_stack_matches_the_torch_golden() {
    let golden = golden();
    let mut total = Tally::default();
    for case in golden["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let (n, hidden, heads, eps) = dims(case);
        let layers = layer_records(case, false);
        let expected = layer_records(case, true);
        let (output, dx, grads) = stack_backward(&layers, &floats(&case["x"]), n, hidden, heads, eps, &floats(&case["loss_weights"]));
        let mut local = Tally::default();
        local.add(&output, &floats(&case["output"]), 1e-9);
        local.add(&dx, &floats(&case["x_grad"]), 1e-9);
        for (index, (rust, python)) in grads.iter().zip(&expected).enumerate() {
            for ((label, a), (_, b)) in parts(rust).into_iter().zip(parts(python)) {
                let mut one = Tally::default();
                one.add(a, b, 1e-9);
                assert_eq!(one.within, one.count, "{name} layer {index} {label}: max relative error {:.3e}", one.worst);
                local.add(a, b, 1e-9);
            }
        }
        eprintln!(
            "{name}: {} values, {} within 1e-9, {} bitwise equal, max relative error {:.3e}",
            local.count, local.within, local.bitwise, local.worst
        );
        assert_eq!(local.within, local.count, "{name}");
        total.count += local.count;
        total.bitwise += local.bitwise;
        total.within += local.within;
        total.worst = total.worst.max(local.worst);
    }
    eprintln!(
        "bert layer backward: {} values, {} within 1e-9, {} bitwise, max relative {:.3e}",
        total.count, total.within, total.bitwise, total.worst
    );
}

/// The loss `sum(w * stack(x))` of the Rust forward.
fn loss(layers: &[LayerParams], x: &[f64], weights: &[f64], shape: (usize, usize, usize, f64)) -> f64 {
    let (n, hidden, heads, eps) = shape;
    let mut current = x.to_vec();
    for layer in layers {
        current = layer_forward(layer, &current, n, hidden, heads, eps).0;
    }
    current.iter().zip(weights).map(|(a, w)| a * w).sum()
}

type Field = fn(&mut LayerParams) -> &mut Vec<f64>;

#[test]
fn the_backward_agrees_with_finite_differences_of_the_forward() {
    let golden = golden();
    let case = &golden["cases"][1];
    let shape = dims(case);
    let (n, hidden, heads, eps) = shape;
    let layers = layer_records(case, false);
    let (x, weights) = (floats(&case["x"]), floats(&case["loss_weights"]));
    let (_, dx, grads) = stack_backward(&layers, &x, n, hidden, heads, eps, &weights);
    let step = 1e-6;
    let mut worst: f64 = 0.0;
    for index in (0..x.len()).step_by(7) {
        let (mut up, mut down) = (x.clone(), x.clone());
        up[index] += step;
        down[index] -= step;
        let numeric = (loss(&layers, &up, &weights, shape) - loss(&layers, &down, &weights, shape)) / (2.0 * step);
        worst = worst.max((numeric - dx[index]).abs() / dx[index].abs().max(1.0));
    }
    let probes: [(&str, Field); 6] = [
        ("query.weight", |p| &mut p.query.weight),
        ("value.bias", |p| &mut p.value.bias),
        ("attention_norm.gamma", |p| &mut p.attention_norm.gamma),
        ("intermediate.weight", |p| &mut p.intermediate.weight),
        ("output.bias", |p| &mut p.output.bias),
        ("output_norm.beta", |p| &mut p.output_norm.beta),
    ];
    for (label, field) in probes {
        let analytic = parts(&grads[0]).into_iter().find(|(name, _)| *name == label).unwrap().1.to_vec();
        for index in (0..analytic.len()).step_by(11) {
            let (mut up, mut down) = (layers.clone(), layers.clone());
            field(&mut up[0])[index] += step;
            field(&mut down[0])[index] -= step;
            let numeric = (loss(&up, &x, &weights, shape) - loss(&down, &x, &weights, shape)) / (2.0 * step);
            let error = (numeric - analytic[index]).abs() / analytic[index].abs().max(1.0);
            worst = worst.max(error);
            assert!(error < 1e-6, "{label}[{index}]: numeric {numeric} against analytic {}", analytic[index]);
        }
    }
    eprintln!("finite differences: max relative error {worst:.3e}");
    assert!(worst < 1e-6);
}
