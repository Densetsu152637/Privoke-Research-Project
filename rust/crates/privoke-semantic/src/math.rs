//! Numeric kernels of the reference backend: float32 storage, float64 accumulation.
//!
//! Every tensor is stored as `f32`, as in torch. Sums and transcendental functions are evaluated in `f64` and rounded to
//! `f32` once per operation, so each operation is within one float32 rounding of the exact value. torch's own float32
//! kernels are within a few float32 roundings of it as well, which is what the 1e-5 logit tolerance of the stage covers.

use std::thread;

use crate::error::SemanticError;

/// A dense layer `y = x W^T + b`, with the weight stored `[output][input]` (torch's `nn.Linear` layout).
#[derive(Debug, Clone)]
pub struct Dense {
    weight: Vec<f32>,
    bias: Vec<f32>,
    input: usize,
    output: usize,
}

impl Dense {
    /// Build a layer; the weight must hold `output * input` values and the bias `output`.
    pub fn new(weight: Vec<f32>, bias: Vec<f32>, input: usize, output: usize) -> Result<Self, SemanticError> {
        if input == 0 || output == 0 || weight.len() != input * output || bias.len() != output {
            return Err(SemanticError::artifact("Dense layer dimensions do not match its tensors."));
        }
        Ok(Self { weight, bias, input, output })
    }

    /// A layer from a weight stored `[input][output]` (`x @ W`), which is transposed here.
    pub fn from_input_major(weight: &[f32], bias: Vec<f32>, input: usize, output: usize) -> Result<Self, SemanticError> {
        if weight.len() != input * output {
            return Err(SemanticError::artifact("Dense layer dimensions do not match its tensors."));
        }
        let mut transposed = vec![0f32; weight.len()];
        for (row, values) in weight.chunks(output).enumerate() {
            for (column, value) in values.iter().enumerate() {
                transposed[column * input + row] = *value;
            }
        }
        Self::new(transposed, bias, input, output)
    }

    /// Input width.
    pub fn input(&self) -> usize {
        self.input
    }

    /// Output width.
    pub fn output(&self) -> usize {
        self.output
    }

    /// Apply the layer to `rows` rows of `x`, on up to `threads` threads.
    pub fn apply(&self, x: &[f32], rows: usize, threads: usize) -> Vec<f32> {
        let mut out = vec![0f32; rows * self.output];
        if rows == 0 || x.len() < rows * self.input {
            return out;
        }
        let threads = threads.clamp(1, rows);
        if threads == 1 {
            self.apply_rows(x, 0, &mut out);
            return out;
        }
        let per = rows.div_ceil(threads);
        thread::scope(|scope| {
            for (index, chunk) in out.chunks_mut(per * self.output).enumerate() {
                scope.spawn(move || self.apply_rows(x, index * per, chunk));
            }
        });
        out
    }

    fn apply_rows(&self, x: &[f32], first: usize, out: &mut [f32]) {
        for (offset, out_row) in out.chunks_mut(self.output).enumerate() {
            let start = (first + offset) * self.input;
            let row = &x[start..start + self.input];
            for ((slot, weights), bias) in out_row.iter_mut().zip(self.weight.chunks(self.input)).zip(&self.bias) {
                *slot = (dot(row, weights) + f64::from(*bias)) as f32;
            }
        }
    }
}

/// `sum(a[i] * b[i])` in `f64`, with four independent accumulators (a fixed summation order).
pub fn dot(a: &[f32], b: &[f32]) -> f64 {
    let mut acc = [0f64; 4];
    for (x, y) in a.chunks_exact(4).zip(b.chunks_exact(4)) {
        acc[0] += f64::from(x[0]) * f64::from(y[0]);
        acc[1] += f64::from(x[1]) * f64::from(y[1]);
        acc[2] += f64::from(x[2]) * f64::from(y[2]);
        acc[3] += f64::from(x[3]) * f64::from(y[3]);
    }
    let tail: f64 =
        a.chunks_exact(4).remainder().iter().zip(b.chunks_exact(4).remainder()).map(|(x, y)| f64::from(*x) * f64::from(*y)).sum();
    (acc[0] + acc[1]) + (acc[2] + acc[3]) + tail
}

/// `layer_norm` with an affine transform over every row of width `width`, biased variance, as torch computes it.
pub fn layer_norm_affine(x: &mut [f32], width: usize, gamma: &[f32], beta: &[f32], eps: f64) {
    for row in x.chunks_mut(width) {
        let (mean, inv) = moments(row, eps);
        for ((value, g), b) in row.iter_mut().zip(gamma).zip(beta) {
            *value = ((f64::from(*value) - mean) * inv * f64::from(*g) + f64::from(*b)) as f32;
        }
    }
}

/// `layer_norm` without an affine transform (the Tiny model's).
pub fn layer_norm_plain(x: &mut [f32], width: usize, eps: f64) {
    for row in x.chunks_mut(width) {
        let (mean, inv) = moments(row, eps);
        for value in row.iter_mut() {
            *value = ((f64::from(*value) - mean) * inv) as f32;
        }
    }
}

fn moments(row: &[f32], eps: f64) -> (f64, f64) {
    let count = row.len() as f64;
    let mean = row.iter().map(|v| f64::from(*v)).sum::<f64>() / count;
    let variance = row
        .iter()
        .map(|v| {
            let centred = f64::from(*v) - mean;
            centred * centred
        })
        .sum::<f64>()
        / count;
    (mean, 1.0 / (variance + eps).sqrt())
}

/// The error function, to float64 accuracy (relative error below 1e-15 on the range used).
///
/// `erf(x) = 2/sqrt(pi) * exp(-x^2) * sum_n 2^n x^(2n+1) / (2n+1)!!`; every term is positive, so there is no cancellation.
pub fn erf(x: f64) -> f64 {
    if x.is_nan() {
        return x;
    }
    let magnitude = x.abs();
    if magnitude >= 6.0 {
        return x.signum();
    }
    let square = magnitude * magnitude;
    let mut term = magnitude;
    let mut sum = magnitude;
    let mut n = 0u32;
    while term > sum * 1e-18 && n < 2000 {
        term *= 2.0 * square / f64::from(2 * n + 3);
        sum += term;
        n += 1;
    }
    let value = std::f64::consts::FRAC_2_SQRT_PI * (-square).exp() * sum;
    value.copysign(x)
}

/// torch's exact (`erf`) GELU, the activation of BERT.
pub fn gelu_erf(x: f32) -> f32 {
    let v = f64::from(x);
    (0.5 * v * (1.0 + erf(v * std::f64::consts::FRAC_1_SQRT_2))) as f32
}

/// The tanh approximation of GELU (`approximate="tanh"`), used by the Tiny model.
pub fn gelu_tanh(x: f32) -> f32 {
    let v = f64::from(x);
    let inner = (2.0 / std::f64::consts::PI).sqrt() * (v + 0.044715 * v * v * v);
    (0.5 * v * (1.0 + inner.tanh())) as f32
}

/// Softmax of `scores` in place (`f64`), shifted by the maximum.
pub fn softmax_in_place(scores: &mut [f64]) {
    let max = scores.iter().copied().fold(f64::NEG_INFINITY, f64::max);
    let mut sum = 0.0;
    for score in scores.iter_mut() {
        *score = (*score - max).exp();
        sum += *score;
    }
    for score in scores.iter_mut() {
        *score /= sum;
    }
}

/// Softmax of float32 logits, rounded to float32 (the probabilities torch returns).
pub fn softmax_f32(logits: &[f32]) -> Vec<f32> {
    let mut values: Vec<f64> = logits.iter().map(|v| f64::from(*v)).collect();
    softmax_in_place(&mut values);
    values.into_iter().map(|v| v as f32).collect()
}

/// Logistic function of float32 logits, rounded to float32.
pub fn sigmoid_f32(logits: &[f32]) -> Vec<f32> {
    logits.iter().map(|v| (1.0 / (1.0 + (-f64::from(*v)).exp())) as f32).collect()
}

/// Multi-head self-attention without a mask over one sequence: `softmax(Q K^T / sqrt(d)) V`.
///
/// `q`, `k` and `v` hold `n` rows of `heads * head_size` values; the result has the same shape.
pub fn attention(q: &[f32], k: &[f32], v: &[f32], n: usize, heads: usize, head_size: usize) -> Vec<f32> {
    let width = heads * head_size;
    let scale = (head_size as f64).sqrt();
    let mut out = vec![0f32; n * width];
    let mut scores = vec![0f64; n];
    let mut context = vec![0f64; head_size];
    for head in 0..heads {
        let offset = head * head_size;
        for row in 0..n {
            let query = &q[row * width + offset..row * width + offset + head_size];
            for (score, key_row) in scores.iter_mut().zip(k.chunks(width)) {
                *score = dot(query, &key_row[offset..offset + head_size]) / scale;
            }
            softmax_in_place(&mut scores);
            context.fill(0.0);
            for (probability, value_row) in scores.iter().zip(v.chunks(width)) {
                for (slot, value) in context.iter_mut().zip(&value_row[offset..offset + head_size]) {
                    *slot += probability * f64::from(*value);
                }
            }
            let target = &mut out[row * width + offset..row * width + offset + head_size];
            for (slot, value) in target.iter_mut().zip(&context) {
                *slot = *value as f32;
            }
        }
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn erf_matches_reference_values() {
        // Reference values of the error function (Abramowitz and Stegun, rounded to 16 digits).
        let cases = [
            (0.0, 0.0),
            (0.5, 0.520_499_877_813_046_5),
            (1.0, 0.842_700_792_949_714_9),
            (2.0, 0.995_322_265_018_952_7),
            (3.0, 0.999_977_909_503_001_4),
            (-1.0, -0.842_700_792_949_714_9),
        ];
        for (x, expected) in cases {
            assert!((erf(x) - expected).abs() < 1e-14, "erf({x}) = {} != {expected}", erf(x));
        }
        assert_eq!(erf(8.0), 1.0);
        assert_eq!(erf(-8.0), -1.0);
        assert!(erf(f64::NAN).is_nan());
        assert_eq!(erf(0.0).to_bits(), 0.0f64.to_bits());
    }

    #[test]
    fn gelu_is_zero_at_zero_and_identity_for_large_inputs() {
        assert_eq!(gelu_erf(0.0), 0.0);
        assert!((gelu_erf(10.0) - 10.0).abs() < 1e-6);
        assert!(gelu_erf(-10.0).abs() < 1e-6);
        assert!((gelu_erf(1.0) - 0.841_344_75).abs() < 1e-6);
        assert!((gelu_tanh(1.0) - 0.841_192).abs() < 1e-5);
    }

    #[test]
    fn dense_applies_weight_and_bias_on_any_thread_count() {
        // x = [[1, 2], [3, 4], [5, 6]]; W = [[1, 0], [0, 1], [1, 1]]; b = [0.5, 0, -1].
        let layer = Dense::new(vec![1.0, 0.0, 0.0, 1.0, 1.0, 1.0], vec![0.5, 0.0, -1.0], 2, 3).unwrap();
        let x = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0];
        let expected = vec![1.5, 2.0, 2.0, 3.5, 4.0, 6.0, 5.5, 6.0, 10.0];
        for threads in [1, 2, 3, 8] {
            assert_eq!(layer.apply(&x, 3, threads), expected, "threads {threads}");
        }
        let transposed = Dense::from_input_major(&[1.0, 0.0, 1.0, 0.0, 1.0, 1.0], vec![0.5, 0.0, -1.0], 2, 3).unwrap();
        assert_eq!(transposed.apply(&x, 3, 1), expected);
        assert!(Dense::new(vec![1.0], vec![0.0], 2, 3).is_err());
    }

    #[test]
    fn dot_covers_tails() {
        let a: Vec<f32> = (1..=7).map(|v| v as f32).collect();
        assert_eq!(dot(&a, &a), 140.0);
    }

    #[test]
    fn layer_norm_normalises_rows() {
        let mut x = vec![1.0f32, 2.0, 3.0, 4.0, 10.0, 10.0, 10.0, 10.0];
        layer_norm_plain(&mut x, 4, 1e-12);
        let mean: f32 = x[..4].iter().sum::<f32>() / 4.0;
        assert!(mean.abs() < 1e-6);
        assert!((x[0] + 1.341_640_8).abs() < 1e-6);
        assert_eq!(&x[4..], &[0.0, 0.0, 0.0, 0.0]);
        let mut y = vec![1.0f32, 2.0, 3.0, 4.0];
        layer_norm_affine(&mut y, 4, &[2.0; 4], &[1.0; 4], 1e-12);
        assert!((y[0] - (1.0 - 2.0 * 1.341_640_8)).abs() < 1e-5);
    }

    #[test]
    fn softmax_and_sigmoid() {
        let p = softmax_f32(&[0.0, 0.0, 0.0, 0.0]);
        assert!(p.iter().all(|v| (*v - 0.25).abs() < 1e-7));
        let s = sigmoid_f32(&[0.0, 100.0, -100.0]);
        assert_eq!(s[0], 0.5);
        assert_eq!(s[1], 1.0);
        assert!(s[2] < 1e-30);
    }

    #[test]
    fn attention_of_one_token_is_its_value() {
        let q = [0.3f32, -0.2, 0.9, 0.1];
        let k = [0.5f32, 0.5, -0.5, 0.25];
        let v = [1.0f32, 2.0, 3.0, 4.0];
        assert_eq!(attention(&q, &k, &v, 1, 2, 2), v.to_vec());
    }
}
