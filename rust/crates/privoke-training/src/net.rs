//! The Tiny transformer with a reverse-mode backward pass.
//!
//! Forward (one text at a time; padding never reaches a real row in the Python batch, so rows are independent):
//! `x = token[ids] + position[:n]`, then per block post-norm attention (`q`, `k`, `v` without bias, multi-head,
//! scaled by `sqrt(head)`), `LN(x + attn)`, a tanh-GELU feed-forward, `LN(h + ffn)`; layer norms have no affine part
//! and `eps = 1e-5`. The readout is `legacy_pool_v1` (half first state, half mean) or `residual_task_query_v1`
//! (the pooled feature plus a learned-query attention residual per task). Names and layouts are those of
//! `model.py` and `task_readout.py`; weights are `[input][output]` row-major.

use std::collections::BTreeMap;

use privoke_semantic::TinyModel;
use privoke_semantic::tiny::{Readout, TinyConfig};
use serde_json::Value;

use crate::error::TrainingError;

const EPS: f64 = 1e-5;
/// Task order of the heads and the readout.
pub const TASKS: [&str; 3] = ["sensitivity", "visibility", "category"];

/// One named tensor: row-major float values (float32-exact for weights).
#[derive(Debug, Clone, PartialEq)]
pub struct Tensor {
    /// Dimensions.
    pub shape: Vec<usize>,
    /// Values.
    pub data: Vec<f64>,
}

/// Named tensors in lexicographic order, as `sorted(parameters)` in Python.
pub type Params = BTreeMap<String, Tensor>;

/// A Tiny model for training: configuration, parameters and the tokenizer of the serving model.
#[derive(Debug, Clone)]
pub struct TinyNet {
    /// Configuration.
    pub config: TinyConfig,
    /// Parameters.
    pub params: Params,
    model: TinyModel,
}

fn prefix(config: &TinyConfig, layer: usize) -> String {
    if config.num_layers == 1 { String::new() } else { format!("layers.{layer}.") }
}

/// Names and shapes the architecture requires (`TinyTransformerModel._required_tensors` and `_validate_shapes`).
pub fn expected_shapes(config: &TinyConfig) -> BTreeMap<String, Vec<usize>> {
    let (h, inner) = (config.hidden_size, config.intermediate_size);
    let mut shapes = BTreeMap::new();
    shapes.insert("token_embedding".to_string(), vec![config.vocab_size, h]);
    shapes.insert("position_embedding".to_string(), vec![config.max_tokens, h]);
    let widths = [config.sensitivity_labels.len(), config.visibility_labels.len(), config.category_labels.len()];
    for (task, width) in TASKS.iter().zip(widths) {
        shapes.insert(format!("head.{task}.weight"), vec![h, width]);
        shapes.insert(format!("head.{task}.bias"), vec![width]);
        if config.readout == Readout::TaskQuery {
            shapes.insert(format!("readout.{task}.query"), vec![h]);
        }
    }
    for layer in 0..config.num_layers {
        let p = prefix(config, layer);
        for (name, shape) in [
            ("attention.query.weight", vec![h, h]),
            ("attention.key.weight", vec![h, h]),
            ("attention.value.weight", vec![h, h]),
            ("attention.output.weight", vec![h, h]),
            ("attention.output.bias", vec![h]),
            ("ffn.input.weight", vec![h, inner]),
            ("ffn.input.bias", vec![inner]),
            ("ffn.output.weight", vec![inner, h]),
            ("ffn.output.bias", vec![h]),
        ] {
            shapes.insert(format!("{p}{name}"), shape);
        }
    }
    shapes
}

impl TinyNet {
    /// Build from an artifact JSON object (`config`, `parameters`, `architecture`), checking the inventory and shapes.
    pub fn from_artifact(artifact: &Value) -> Result<Self, TrainingError> {
        let model = TinyModel::from_artifact(artifact)?;
        let config = model.config().clone();
        let entries = artifact
            .get("parameters")
            .and_then(Value::as_object)
            .ok_or_else(|| TrainingError::invalid("Artifact config and parameters must be objects."))?;
        let mut params = Params::new();
        for (name, tensor) in entries {
            let bad = || TrainingError::invalid(format!("Invalid artifact parameter entry {name:?}."));
            let shape: Vec<usize> = tensor
                .get("shape")
                .and_then(Value::as_array)
                .and_then(|dims| dims.iter().map(|d| d.as_u64().and_then(|d| usize::try_from(d).ok())).collect())
                .ok_or_else(bad)?;
            let data: Vec<f64> = tensor
                .get("values")
                .and_then(Value::as_array)
                .and_then(|values| values.iter().map(|v| v.as_f64().map(|v| f64::from(v as f32))).collect())
                .ok_or_else(bad)?;
            params.insert(name.clone(), Tensor { shape, data });
        }
        Self::new(config, params, model)
    }

    /// Replace the parameters (same inventory), keeping the tokenizer.
    pub fn with_params(&self, params: Params) -> Result<Self, TrainingError> {
        Self::new(self.config.clone(), params, self.model.clone())
    }

    fn new(config: TinyConfig, params: Params, model: TinyModel) -> Result<Self, TrainingError> {
        let expected = expected_shapes(&config);
        if params.keys().ne(expected.keys()) {
            return Err(TrainingError::invalid("Tiny tensor manifest differs from the architecture."));
        }
        for (name, tensor) in &params {
            let shape = &expected[name];
            let count: usize = shape.iter().product();
            if &tensor.shape != shape || tensor.data.len() != count {
                return Err(TrainingError::invalid(format!("Tensor {name:?} has shape {:?}, expected {shape:?}.", tensor.shape)));
            }
            if tensor.data.iter().any(|v| !v.is_finite()) {
                return Err(TrainingError::invalid("Contextual training parameters must be finite."));
            }
        }
        Ok(Self { config, params, model })
    }

    /// Hashed word tokens of `text`, start token first.
    pub fn token_ids(&self, text: &str) -> Vec<usize> {
        self.model.token_ids(text)
    }

    fn p(&self, name: &str) -> &[f64] {
        // The inventory was checked in `new`; a missing name is a programming error and yields an empty slice, which
        // the kernels then reject by length instead of panicking.
        self.params.get(name).map_or(&[][..], |t| t.data.as_slice())
    }
}

struct LayerCache {
    input: Vec<f64>,
    q: Vec<f64>,
    k: Vec<f64>,
    v: Vec<f64>,
    probs: Vec<f64>,
    context: Vec<f64>,
    xhat1: Vec<f64>,
    inv1: Vec<f64>,
    h1: Vec<f64>,
    pre_gelu: Vec<f64>,
    activated: Vec<f64>,
    xhat2: Vec<f64>,
    inv2: Vec<f64>,
}

/// Activations of one forward pass, kept for the backward pass.
pub struct Forward {
    ids: Vec<usize>,
    layers: Vec<LayerCache>,
    hidden: Vec<f64>,
    features: [Vec<f64>; 3],
    alphas: [Vec<f64>; 3],
    /// Logits per task.
    pub logits: [Vec<f64>; 3],
}

fn matmul(x: &[f64], n: usize, w: &[f64], k: usize, m: usize) -> Vec<f64> {
    let mut out = vec![0.0; n * m];
    for i in 0..n {
        let row = &x[i * k..(i + 1) * k];
        let dst = &mut out[i * m..(i + 1) * m];
        for (p, xv) in row.iter().enumerate() {
            let wr = &w[p * m..(p + 1) * m];
            for (d, wv) in dst.iter_mut().zip(wr) {
                *d += xv * wv;
            }
        }
    }
    out
}

/// `a^T b` with `a: [n, k]`, `b: [n, m]` giving `[k, m]`.
fn matmul_tn(a: &[f64], n: usize, k: usize, b: &[f64], m: usize) -> Vec<f64> {
    let mut out = vec![0.0; k * m];
    for i in 0..n {
        for p in 0..k {
            let av = a[i * k + p];
            let dst = &mut out[p * m..(p + 1) * m];
            for (d, bv) in dst.iter_mut().zip(&b[i * m..(i + 1) * m]) {
                *d += av * bv;
            }
        }
    }
    out
}

/// `a w^T` with `a: [n, m]`, `w: [k, m]` giving `[n, k]`.
fn matmul_nt(a: &[f64], n: usize, m: usize, w: &[f64], k: usize) -> Vec<f64> {
    let mut out = vec![0.0; n * k];
    for i in 0..n {
        for p in 0..k {
            out[i * k + p] = a[i * m..(i + 1) * m].iter().zip(&w[p * m..(p + 1) * m]).map(|(x, y)| x * y).sum();
        }
    }
    out
}

fn add_bias(x: &mut [f64], bias: &[f64]) {
    for row in x.chunks_mut(bias.len()) {
        for (v, b) in row.iter_mut().zip(bias) {
            *v += b;
        }
    }
}

fn column_sums(x: &[f64], width: usize) -> Vec<f64> {
    let mut out = vec![0.0; width];
    for row in x.chunks(width) {
        for (o, v) in out.iter_mut().zip(row) {
            *o += v;
        }
    }
    out
}

/// Layer norm without affine part: returns the normalised rows, the normalised values and `1 / sigma` per row.
fn layer_norm(x: &[f64], width: usize) -> (Vec<f64>, Vec<f64>) {
    let mut xhat = vec![0.0; x.len()];
    let mut inv = Vec::with_capacity(x.len() / width);
    for (row, out) in x.chunks(width).zip(xhat.chunks_mut(width)) {
        let mean = row.iter().sum::<f64>() / width as f64;
        let var = row.iter().map(|v| (v - mean) * (v - mean)).sum::<f64>() / width as f64;
        let s = 1.0 / (var + EPS).sqrt();
        for (o, v) in out.iter_mut().zip(row) {
            *o = (v - mean) * s;
        }
        inv.push(s);
    }
    (xhat, inv)
}

fn layer_norm_back(dy: &[f64], xhat: &[f64], inv: &[f64], width: usize) -> Vec<f64> {
    let mut dx = vec![0.0; dy.len()];
    for (((dyr, xr), out), s) in dy.chunks(width).zip(xhat.chunks(width)).zip(dx.chunks_mut(width)).zip(inv) {
        let mean_dy = dyr.iter().sum::<f64>() / width as f64;
        let mean_dyx = dyr.iter().zip(xr).map(|(a, b)| a * b).sum::<f64>() / width as f64;
        for ((o, d), x) in out.iter_mut().zip(dyr).zip(xr) {
            *o = s * (d - mean_dy - x * mean_dyx);
        }
    }
    dx
}

const GELU_C: f64 = 0.797_884_560_802_865_4; // sqrt(2 / pi)

fn gelu(u: f64) -> f64 {
    0.5 * u * (1.0 + (GELU_C * (u + 0.044715 * u * u * u)).tanh())
}

fn gelu_grad(u: f64) -> f64 {
    let t = (GELU_C * (u + 0.044715 * u * u * u)).tanh();
    0.5 * (1.0 + t) + 0.5 * u * (1.0 - t * t) * GELU_C * (1.0 + 3.0 * 0.044715 * u * u)
}

fn softmax(values: &[f64]) -> Vec<f64> {
    let max = values.iter().copied().fold(f64::NEG_INFINITY, f64::max);
    let exp: Vec<f64> = values.iter().map(|v| (v - max).exp()).collect();
    let total: f64 = exp.iter().sum();
    exp.into_iter().map(|v| v / total).collect()
}

impl TinyNet {
    /// Forward pass over the token ids of one text.
    pub fn forward(&self, ids: &[usize]) -> Result<Forward, TrainingError> {
        let c = &self.config;
        let (h, n, heads) = (c.hidden_size, ids.len(), c.num_attention_heads);
        if n == 0 || n > c.max_tokens || ids.iter().any(|id| *id >= c.vocab_size) {
            return Err(TrainingError::invalid("Token ids exceed the Tiny model's vocabulary or context."));
        }
        let hd = h / heads;
        let scale = (hd as f64).sqrt();
        let (tok, pos) = (self.p("token_embedding"), self.p("position_embedding"));
        let mut x = vec![0.0; n * h];
        for (t, id) in ids.iter().enumerate() {
            for d in 0..h {
                x[t * h + d] = tok[id * h + d] + pos[t * h + d];
            }
        }
        let mut layers = Vec::with_capacity(c.num_layers);
        for layer in 0..c.num_layers {
            let pre = prefix(c, layer);
            let name = |suffix: &str| format!("{pre}{suffix}");
            let q = matmul(&x, n, self.p(&name("attention.query.weight")), h, h);
            let k = matmul(&x, n, self.p(&name("attention.key.weight")), h, h);
            let v = matmul(&x, n, self.p(&name("attention.value.weight")), h, h);
            let mut probs = vec![0.0; heads * n * n];
            let mut context = vec![0.0; n * h];
            for head in 0..heads {
                let off = head * hd;
                for i in 0..n {
                    let scores: Vec<f64> =
                        (0..n).map(|j| (0..hd).map(|d| q[i * h + off + d] * k[j * h + off + d]).sum::<f64>() / scale).collect();
                    let a = softmax(&scores);
                    for (j, aj) in a.iter().enumerate() {
                        probs[(head * n + i) * n + j] = *aj;
                        for d in 0..hd {
                            context[i * h + off + d] += aj * v[j * h + off + d];
                        }
                    }
                }
            }
            let mut attended = matmul(&context, n, self.p(&name("attention.output.weight")), h, h);
            add_bias(&mut attended, self.p(&name("attention.output.bias")));
            for (a, r) in attended.iter_mut().zip(&x) {
                *a += r;
            }
            // No affine part: the layer-norm output is the normalised row.
            let (h1, inv1) = layer_norm(&attended, h);
            let xhat1 = h1.clone();
            let inner = c.intermediate_size;
            let mut pre_gelu = matmul(&h1, n, self.p(&name("ffn.input.weight")), h, inner);
            add_bias(&mut pre_gelu, self.p(&name("ffn.input.bias")));
            let activated: Vec<f64> = pre_gelu.iter().map(|u| gelu(*u)).collect();
            let mut r2 = matmul(&activated, n, self.p(&name("ffn.output.weight")), inner, h);
            add_bias(&mut r2, self.p(&name("ffn.output.bias")));
            for (a, r) in r2.iter_mut().zip(&h1) {
                *a += r;
            }
            let (out, inv2) = layer_norm(&r2, h);
            layers.push(LayerCache { input: x, q, k, v, probs, context, xhat1, inv1, h1, pre_gelu, activated, xhat2: out.clone(), inv2 });
            x = out;
        }
        let hidden = x;
        let mean: Vec<f64> = (0..h).map(|d| (0..n).map(|t| hidden[t * h + d]).sum::<f64>() / n as f64).collect();
        let pooled: Vec<f64> = (0..h).map(|d| hidden[d] * 0.5 + mean[d] * 0.5).collect();
        let mut features: [Vec<f64>; 3] = Default::default();
        let mut alphas: [Vec<f64>; 3] = Default::default();
        let mut logits: [Vec<f64>; 3] = Default::default();
        for (index, task) in TASKS.iter().enumerate() {
            let mut feature = pooled.clone();
            if c.readout == Readout::TaskQuery {
                let query = self.p(&format!("readout.{task}.query"));
                let scores: Vec<f64> =
                    (0..n).map(|t| (0..h).map(|d| hidden[t * h + d] * query[d]).sum::<f64>() / (h as f64).sqrt()).collect();
                let alpha = softmax(&scores);
                for d in 0..h {
                    let attended: f64 = (0..n).map(|t| alpha[t] * hidden[t * h + d]).sum();
                    feature[d] += attended - mean[d];
                }
                alphas[index] = alpha;
            }
            let width = self.p(&format!("head.{task}.bias")).len();
            let mut out = matmul(&feature, 1, self.p(&format!("head.{task}.weight")), h, width);
            add_bias(&mut out, self.p(&format!("head.{task}.bias")));
            if out.iter().any(|v| !v.is_finite()) {
                return Err(TrainingError::invalid("Tiny readout produced non-finite states."));
            }
            features[index] = feature;
            logits[index] = out;
        }
        Ok(Forward { ids: ids.to_vec(), layers, hidden, features, alphas, logits })
    }

    /// Accumulate the gradient of a loss whose derivative with respect to the logits is `dlogits` into `grads`.
    pub fn backward(&self, fwd: &Forward, dlogits: &[Vec<f64>; 3], grads: &mut BTreeMap<String, Vec<f64>>) {
        let c = &self.config;
        let (h, n, heads) = (c.hidden_size, fwd.ids.len(), c.num_attention_heads);
        let hd = h / heads;
        let hidden = &fwd.hidden;
        let mut dpooled = vec![0.0; h];
        let mut dmean = vec![0.0; h];
        let mut dh = vec![0.0; n * h];
        for (index, task) in TASKS.iter().enumerate() {
            let dl = &dlogits[index];
            let width = dl.len();
            let feature = &fwd.features[index];
            add_into(grads, &format!("head.{task}.weight"), &matmul_tn(feature, 1, h, dl, width));
            add_into(grads, &format!("head.{task}.bias"), dl);
            let dfeature = matmul_nt(dl, 1, width, self.p(&format!("head.{task}.weight")), h);
            for d in 0..h {
                dpooled[d] += dfeature[d];
            }
            if c.readout == Readout::TaskQuery {
                let alpha = &fwd.alphas[index];
                let query = self.p(&format!("readout.{task}.query"));
                let scale = 1.0 / (h as f64).sqrt();
                for d in 0..h {
                    dmean[d] -= dfeature[d];
                }
                let dalpha: Vec<f64> = (0..n).map(|t| (0..h).map(|d| hidden[t * h + d] * dfeature[d]).sum()).collect();
                let dot: f64 = alpha.iter().zip(&dalpha).map(|(a, b)| a * b).sum();
                let mut dquery = vec![0.0; h];
                for t in 0..n {
                    let ds = alpha[t] * (dalpha[t] - dot);
                    for d in 0..h {
                        dh[t * h + d] += alpha[t] * dfeature[d] + ds * scale * query[d];
                        dquery[d] += ds * scale * hidden[t * h + d];
                    }
                }
                add_into(grads, &format!("readout.{task}.query"), &dquery);
            }
        }
        for d in 0..h {
            dh[d] += 0.5 * dpooled[d];
            dmean[d] += 0.5 * dpooled[d];
        }
        for t in 0..n {
            for d in 0..h {
                dh[t * h + d] += dmean[d] / n as f64;
            }
        }
        let inner = c.intermediate_size;
        for layer in (0..c.num_layers).rev() {
            let cache = &fwd.layers[layer];
            let pre = prefix(c, layer);
            let name = |suffix: &str| format!("{pre}{suffix}");
            let dr2 = layer_norm_back(&dh, &cache.xhat2, &cache.inv2, h);
            add_into(grads, &name("ffn.output.bias"), &column_sums(&dr2, h));
            add_into(grads, &name("ffn.output.weight"), &matmul_tn(&cache.activated, n, inner, &dr2, h));
            let dactivated = matmul_nt(&dr2, n, h, self.p(&name("ffn.output.weight")), inner);
            let du: Vec<f64> = dactivated.iter().zip(&cache.pre_gelu).map(|(g, u)| g * gelu_grad(*u)).collect();
            add_into(grads, &name("ffn.input.bias"), &column_sums(&du, inner));
            add_into(grads, &name("ffn.input.weight"), &matmul_tn(&cache.h1, n, h, &du, inner));
            let mut dh1 = matmul_nt(&du, n, inner, self.p(&name("ffn.input.weight")), h);
            for (a, b) in dh1.iter_mut().zip(&dr2) {
                *a += b;
            }
            let dr1 = layer_norm_back(&dh1, &cache.xhat1, &cache.inv1, h);
            let mut dx = dr1.clone();
            add_into(grads, &name("attention.output.bias"), &column_sums(&dr1, h));
            add_into(grads, &name("attention.output.weight"), &matmul_tn(&cache.context, n, h, &dr1, h));
            let dcontext = matmul_nt(&dr1, n, h, self.p(&name("attention.output.weight")), h);
            let scale = (hd as f64).sqrt();
            let mut dq = vec![0.0; n * h];
            let mut dk = vec![0.0; n * h];
            let mut dv = vec![0.0; n * h];
            for head in 0..heads {
                let off = head * hd;
                for i in 0..n {
                    let a = &cache.probs[(head * n + i) * n..(head * n + i + 1) * n];
                    let da: Vec<f64> =
                        (0..n).map(|j| (0..hd).map(|d| dcontext[i * h + off + d] * cache.v[j * h + off + d]).sum()).collect();
                    let dot: f64 = a.iter().zip(&da).map(|(x, y)| x * y).sum();
                    for j in 0..n {
                        let ds = a[j] * (da[j] - dot) / scale;
                        for d in 0..hd {
                            dq[i * h + off + d] += ds * cache.k[j * h + off + d];
                            dk[j * h + off + d] += ds * cache.q[i * h + off + d];
                            dv[j * h + off + d] += a[j] * dcontext[i * h + off + d];
                        }
                    }
                }
            }
            for (suffix, d) in [("query", &dq), ("key", &dk), ("value", &dv)] {
                let weight = name(&format!("attention.{suffix}.weight"));
                add_into(grads, &weight, &matmul_tn(&cache.input, n, h, d, h));
                let back = matmul_nt(d, n, h, self.p(&weight), h);
                for (a, b) in dx.iter_mut().zip(&back) {
                    *a += b;
                }
            }
            dh = dx;
        }
        for (t, id) in fwd.ids.iter().enumerate() {
            for d in 0..h {
                let g = dh[t * h + d];
                if let Some(slot) = grads.get_mut("token_embedding") {
                    slot[id * h + d] += g;
                }
                if let Some(slot) = grads.get_mut("position_embedding") {
                    slot[t * h + d] += g;
                }
            }
        }
    }

    /// Zero gradients for every tensor.
    pub fn zero_grads(&self) -> BTreeMap<String, Vec<f64>> {
        self.params.iter().map(|(name, t)| (name.clone(), vec![0.0; t.data.len()])).collect()
    }
}

fn add_into(grads: &mut BTreeMap<String, Vec<f64>>, name: &str, values: &[f64]) {
    if let Some(slot) = grads.get_mut(name) {
        for (a, b) in slot.iter_mut().zip(values) {
            *a += b;
        }
    }
}
