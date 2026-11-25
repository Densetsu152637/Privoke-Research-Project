//! Reverse-mode backward of the BERT encoder layer (V3 training, `extension/client-runtime/src/v3/training.py`, checkpoint 1).
//!
//! The V3 fit backpropagates through `transformers.BertModel`: a layer is multi-head self-attention, a residual and an
//! affine layer norm, an exact (erf) GELU feed-forward, a second residual and layer norm. The forward here mirrors
//! `privoke_semantic::bert::Encoder::layer_forward` (float64, no mask, no dropout) and records what the backward needs;
//! [`layer_backward`] returns the gradient of the layer input and of every layer parameter. Weights follow torch's
//! `nn.Linear` layout (`[output, input]`, `y = x W^T + b`). The embeddings, pooler, heads and the optimizer are later
//! checkpoints.

use privoke_semantic::math::erf;

/// A dense layer, `[output, input]` row-major.
#[derive(Debug, Clone, PartialEq)]
pub struct Dense {
    /// The weight, `output * input` values.
    pub weight: Vec<f64>,
    /// The bias, `output` values.
    pub bias: Vec<f64>,
}

/// An affine layer norm.
#[derive(Debug, Clone, PartialEq)]
pub struct Norm {
    /// The scale.
    pub gamma: Vec<f64>,
    /// The shift.
    pub beta: Vec<f64>,
}

/// The parameters of one encoder layer; also the shape of its gradient.
#[derive(Debug, Clone, PartialEq)]
pub struct LayerParams {
    /// `attention.self.query`.
    pub query: Dense,
    /// `attention.self.key`.
    pub key: Dense,
    /// `attention.self.value`.
    pub value: Dense,
    /// `attention.output.dense`.
    pub attention_output: Dense,
    /// `attention.output.LayerNorm`.
    pub attention_norm: Norm,
    /// `intermediate.dense`.
    pub intermediate: Dense,
    /// `output.dense`.
    pub output: Dense,
    /// `output.LayerNorm`.
    pub output_norm: Norm,
}

/// The suffixes of the sixteen layer tensors, in [`LayerParams::parts_mut`] order (the BERT state-dict names inside a layer).
pub const LAYER_SUFFIXES: [&str; 16] = [
    "attention.self.query.weight",
    "attention.self.query.bias",
    "attention.self.key.weight",
    "attention.self.key.bias",
    "attention.self.value.weight",
    "attention.self.value.bias",
    "attention.output.dense.weight",
    "attention.output.dense.bias",
    "attention.output.LayerNorm.weight",
    "attention.output.LayerNorm.bias",
    "intermediate.dense.weight",
    "intermediate.dense.bias",
    "output.dense.weight",
    "output.dense.bias",
    "output.LayerNorm.weight",
    "output.LayerNorm.bias",
];

impl LayerParams {
    /// The sixteen tensors in [`LAYER_SUFFIXES`] order.
    pub fn parts_mut(&mut self) -> [&mut Vec<f64>; 16] {
        [
            &mut self.query.weight,
            &mut self.query.bias,
            &mut self.key.weight,
            &mut self.key.bias,
            &mut self.value.weight,
            &mut self.value.bias,
            &mut self.attention_output.weight,
            &mut self.attention_output.bias,
            &mut self.attention_norm.gamma,
            &mut self.attention_norm.beta,
            &mut self.intermediate.weight,
            &mut self.intermediate.bias,
            &mut self.output.weight,
            &mut self.output.bias,
            &mut self.output_norm.gamma,
            &mut self.output_norm.beta,
        ]
    }

    /// The same layout filled with zeros.
    #[must_use]
    pub fn zeros_like(&self) -> Self {
        let mut zeros = self.clone();
        for part in zeros.parts_mut() {
            part.fill(0.0);
        }
        zeros
    }

    /// `self += other`.
    pub fn add_assign(&mut self, mut other: Self) {
        for (slot, value) in self.parts_mut().into_iter().zip(other.parts_mut()) {
            for (a, b) in slot.iter_mut().zip(value.iter()) {
                *a += b;
            }
        }
    }
}

/// What the forward pass keeps for the backward.
#[derive(Debug, Clone)]
pub struct LayerCache {
    n: usize,
    heads: usize,
    hidden: usize,
    inner: usize,
    x: Vec<f64>,
    q: Vec<f64>,
    k: Vec<f64>,
    v: Vec<f64>,
    probs: Vec<f64>,
    context: Vec<f64>,
    xhat1: Vec<f64>,
    inv1: Vec<f64>,
    y1: Vec<f64>,
    pre_activation: Vec<f64>,
    activated: Vec<f64>,
    xhat2: Vec<f64>,
    inv2: Vec<f64>,
}

/// `y = x W^T + b` over `rows` rows.
pub(crate) fn linear(x: &[f64], rows: usize, dense: &Dense, input: usize, output: usize) -> Vec<f64> {
    let mut out = vec![0.0; rows * output];
    for (row, dst) in x.chunks(input).zip(out.chunks_mut(output)).take(rows) {
        for (slot, (weights, bias)) in dst.iter_mut().zip(dense.weight.chunks(input).zip(&dense.bias)) {
            *slot = row.iter().zip(weights).map(|(a, b)| a * b).sum::<f64>() + bias;
        }
    }
    out
}

/// The gradient of [`linear`]: `(dx, dense gradient)`.
pub(crate) fn linear_back(dy: &[f64], x: &[f64], rows: usize, dense: &Dense, input: usize, output: usize) -> (Vec<f64>, Dense) {
    let mut dx = vec![0.0; rows * input];
    let mut dw = vec![0.0; output * input];
    let mut db = vec![0.0; output];
    for ((dy_row, x_row), dx_row) in dy.chunks(output).zip(x.chunks(input)).zip(dx.chunks_mut(input)).take(rows) {
        for (o, (grad, weights)) in dy_row.iter().zip(dense.weight.chunks(input)).enumerate() {
            db[o] += grad;
            for ((slot, w), (acc, xv)) in dx_row.iter_mut().zip(weights).zip(dw[o * input..(o + 1) * input].iter_mut().zip(x_row)) {
                *slot += grad * w;
                *acc += grad * xv;
            }
        }
    }
    (dx, Dense { weight: dw, bias: db })
}

/// The affine layer norm: the output, the normalised rows and `1 / sigma` per row.
pub(crate) fn norm_forward(x: &[f64], width: usize, norm: &Norm, eps: f64) -> (Vec<f64>, Vec<f64>, Vec<f64>) {
    let mut out = vec![0.0; x.len()];
    let mut xhat = vec![0.0; x.len()];
    let mut inv = Vec::with_capacity(x.len() / width);
    for ((row, hat), dst) in x.chunks(width).zip(xhat.chunks_mut(width)).zip(out.chunks_mut(width)) {
        let count = width as f64;
        let mean = row.iter().sum::<f64>() / count;
        let variance = row.iter().map(|v| (v - mean) * (v - mean)).sum::<f64>() / count;
        let scale = 1.0 / (variance + eps).sqrt();
        for (((h, o), v), (g, b)) in hat.iter_mut().zip(dst.iter_mut()).zip(row).zip(norm.gamma.iter().zip(&norm.beta)) {
            *h = (v - mean) * scale;
            *o = *h * g + b;
        }
        inv.push(scale);
    }
    (out, xhat, inv)
}

/// The gradient of [`norm_forward`]: `(dx, gamma and beta gradients)`.
pub(crate) fn norm_back(dy: &[f64], xhat: &[f64], inv: &[f64], width: usize, norm: &Norm) -> (Vec<f64>, Norm) {
    let mut dx = vec![0.0; dy.len()];
    let mut dgamma = vec![0.0; width];
    let mut dbeta = vec![0.0; width];
    let count = width as f64;
    for (((dy_row, hat), dst), scale) in dy.chunks(width).zip(xhat.chunks(width)).zip(dx.chunks_mut(width)).zip(inv) {
        let dxhat: Vec<f64> = dy_row.iter().zip(&norm.gamma).map(|(d, g)| d * g).collect();
        let mean_dxhat = dxhat.iter().sum::<f64>() / count;
        let mean_dxhat_xhat = dxhat.iter().zip(hat).map(|(d, h)| d * h).sum::<f64>() / count;
        for (i, slot) in dst.iter_mut().enumerate() {
            *slot = scale * (dxhat[i] - mean_dxhat - hat[i] * mean_dxhat_xhat);
            dgamma[i] += dy_row[i] * hat[i];
            dbeta[i] += dy_row[i];
        }
    }
    (dx, Norm { gamma: dgamma, beta: dbeta })
}

/// `1 / sqrt(2 * pi)`.
const INV_SQRT_TAU: f64 = 0.398_942_280_401_432_7;

/// The exact GELU, `x * Phi(x)`.
fn gelu(x: f64) -> f64 {
    0.5 * x * (1.0 + erf(x * std::f64::consts::FRAC_1_SQRT_2))
}

/// The derivative of the exact GELU, `Phi(x) + x * phi(x)`.
fn gelu_grad(x: f64) -> f64 {
    0.5 * (1.0 + erf(x * std::f64::consts::FRAC_1_SQRT_2)) + x * INV_SQRT_TAU * (-0.5 * x * x).exp()
}

/// The attention probabilities and context of every head: `probs[(head * n + row) * n + column]`.
fn attention_forward(q: &[f64], k: &[f64], v: &[f64], n: usize, heads: usize, head_size: usize) -> (Vec<f64>, Vec<f64>) {
    let width = heads * head_size;
    let scale = (head_size as f64).sqrt();
    let mut probs = vec![0.0; heads * n * n];
    let mut context = vec![0.0; n * width];
    for head in 0..heads {
        let offset = head * head_size;
        for row in 0..n {
            let query = &q[row * width + offset..row * width + offset + head_size];
            let scores = &mut probs[(head * n + row) * n..(head * n + row + 1) * n];
            for (score, key_row) in scores.iter_mut().zip(k.chunks(width)) {
                *score = query.iter().zip(&key_row[offset..offset + head_size]).map(|(a, b)| a * b).sum::<f64>() / scale;
            }
            let max = scores.iter().copied().fold(f64::NEG_INFINITY, f64::max);
            let mut sum = 0.0;
            for score in scores.iter_mut() {
                *score = (*score - max).exp();
                sum += *score;
            }
            for score in scores.iter_mut() {
                *score /= sum;
            }
            let out = &mut context[row * width + offset..row * width + offset + head_size];
            for (probability, value_row) in scores.iter().zip(v.chunks(width)) {
                for (slot, value) in out.iter_mut().zip(&value_row[offset..offset + head_size]) {
                    *slot += probability * value;
                }
            }
        }
    }
    (probs, context)
}

/// The gradient of [`attention_forward`] with respect to `q`, `k` and `v`.
fn attention_back(
    dcontext: &[f64],
    (q, k, v): (&[f64], &[f64], &[f64]),
    probs: &[f64],
    (n, heads, head_size): (usize, usize, usize),
) -> (Vec<f64>, Vec<f64>, Vec<f64>) {
    let width = heads * head_size;
    let scale = (head_size as f64).sqrt();
    let (mut dq, mut dk, mut dv) = (vec![0.0; n * width], vec![0.0; n * width], vec![0.0; n * width]);
    let mut dprobs = vec![0.0; n];
    for head in 0..heads {
        let offset = head * head_size;
        for row in 0..n {
            let p = &probs[(head * n + row) * n..(head * n + row + 1) * n];
            let dctx = &dcontext[row * width + offset..row * width + offset + head_size];
            for (column, slot) in dprobs.iter_mut().enumerate() {
                let value_row = &v[column * width + offset..column * width + offset + head_size];
                *slot = dctx.iter().zip(value_row).map(|(a, b)| a * b).sum();
                for (acc, g) in dv[column * width + offset..column * width + offset + head_size].iter_mut().zip(dctx) {
                    *acc += p[column] * g;
                }
            }
            let weighted: f64 = dprobs.iter().zip(p).map(|(d, pr)| d * pr).sum();
            let query = &q[row * width + offset..row * width + offset + head_size];
            for (column, (probability, dprobability)) in p.iter().zip(&dprobs).enumerate() {
                let dscore = probability * (dprobability - weighted) / scale;
                let key_row = &k[column * width + offset..column * width + offset + head_size];
                for (slot, key) in dq[row * width + offset..row * width + offset + head_size].iter_mut().zip(key_row) {
                    *slot += dscore * key;
                }
                for (slot, q_value) in dk[column * width + offset..column * width + offset + head_size].iter_mut().zip(query) {
                    *slot += dscore * q_value;
                }
            }
        }
    }
    (dq, dk, dv)
}

/// One layer forward over `n` rows of `hidden` values, with `heads` attention heads and the layer-norm `eps`.
pub fn layer_forward(params: &LayerParams, x: &[f64], n: usize, hidden: usize, heads: usize, eps: f64) -> (Vec<f64>, LayerCache) {
    let inner = params.intermediate.bias.len();
    let head_size = hidden / heads;
    let q = linear(x, n, &params.query, hidden, hidden);
    let k = linear(x, n, &params.key, hidden, hidden);
    let v = linear(x, n, &params.value, hidden, hidden);
    let (probs, context) = attention_forward(&q, &k, &v, n, heads, head_size);
    let mut attended = linear(&context, n, &params.attention_output, hidden, hidden);
    for (slot, residual) in attended.iter_mut().zip(x) {
        *slot += residual;
    }
    let (y1, xhat1, inv1) = norm_forward(&attended, hidden, &params.attention_norm, eps);
    let pre_activation = linear(&y1, n, &params.intermediate, hidden, inner);
    let activated: Vec<f64> = pre_activation.iter().map(|u| gelu(*u)).collect();
    let mut projected = linear(&activated, n, &params.output, inner, hidden);
    for (slot, residual) in projected.iter_mut().zip(&y1) {
        *slot += residual;
    }
    let (out, xhat2, inv2) = norm_forward(&projected, hidden, &params.output_norm, eps);
    let cache = LayerCache {
        n,
        heads,
        hidden,
        inner,
        x: x.to_vec(),
        q,
        k,
        v,
        probs,
        context,
        xhat1,
        inv1,
        y1,
        pre_activation,
        activated,
        xhat2,
        inv2,
    };
    (out, cache)
}

/// The backward of one layer: the gradient of its input and of every parameter, given the gradient of its output.
pub fn layer_backward(params: &LayerParams, cache: &LayerCache, dy: &[f64]) -> (Vec<f64>, LayerParams) {
    let (n, hidden, inner, heads) = (cache.n, cache.hidden, cache.inner, cache.heads);
    let head_size = hidden / heads;
    // Second residual and layer norm.
    let (dprojected, output_norm) = norm_back(dy, &cache.xhat2, &cache.inv2, hidden, &params.output_norm);
    let (dactivated, output) = linear_back(&dprojected, &cache.activated, n, &params.output, inner, hidden);
    let dpre: Vec<f64> = dactivated.iter().zip(&cache.pre_activation).map(|(d, u)| d * gelu_grad(*u)).collect();
    let (mut dy1, intermediate) = linear_back(&dpre, &cache.y1, n, &params.intermediate, hidden, inner);
    for (slot, residual) in dy1.iter_mut().zip(&dprojected) {
        *slot += residual;
    }
    // First residual and layer norm.
    let (dattended, attention_norm) = norm_back(&dy1, &cache.xhat1, &cache.inv1, hidden, &params.attention_norm);
    let (dcontext, attention_output) = linear_back(&dattended, &cache.context, n, &params.attention_output, hidden, hidden);
    let (dq, dk, dv) = attention_back(&dcontext, (&cache.q, &cache.k, &cache.v), &cache.probs, (n, heads, head_size));
    let (dx_q, query) = linear_back(&dq, &cache.x, n, &params.query, hidden, hidden);
    let (dx_k, key) = linear_back(&dk, &cache.x, n, &params.key, hidden, hidden);
    let (dx_v, value) = linear_back(&dv, &cache.x, n, &params.value, hidden, hidden);
    let dx = dattended.iter().zip(&dx_q).zip(&dx_k).zip(&dx_v).map(|(((residual, a), b), c)| residual + a + b + c).collect();
    (dx, LayerParams { query, key, value, attention_output, attention_norm, intermediate, output, output_norm })
}

/// A stack of layers: the output and, for the gradient of the stack output, the gradient of the stack input and of every
/// layer (in layer order).
pub fn stack_backward(
    layers: &[LayerParams],
    x: &[f64],
    n: usize,
    hidden: usize,
    heads: usize,
    eps: f64,
    dy: &[f64],
) -> (Vec<f64>, Vec<f64>, Vec<LayerParams>) {
    let mut caches = Vec::with_capacity(layers.len());
    let mut current = x.to_vec();
    for layer in layers {
        let (next, cache) = layer_forward(layer, &current, n, hidden, heads, eps);
        caches.push(cache);
        current = next;
    }
    let mut grads = Vec::with_capacity(layers.len());
    let mut upstream = dy.to_vec();
    for (layer, cache) in layers.iter().zip(&caches).rev() {
        let (dx, grad) = layer_backward(layer, cache, &upstream);
        grads.push(grad);
        upstream = dx;
    }
    grads.reverse();
    (current, upstream, grads)
}
