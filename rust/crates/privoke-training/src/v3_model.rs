//! The V3 model and its microbatch loss gradient (`extension/client-runtime/src/v3/model.py` and the loss of
//! `v3/training.py`, checkpoint 2).
//!
//! `PretrainedV3.forward` is `BertModel` (embeddings, layers, tanh pooler on the first row) followed by three affine heads on
//! the pooled output; the fit minimises, per microbatch of rows,
//! `(CE_sensitivity_sum + CE_visibility_sum + BCE_category_sum / 10) / 64`. [`V3Params`] holds every tensor in float64 (built
//! from the float32 checkpoint tensors `Encoder::from_tensors` consumes, same names), [`sequence_forward`] runs one
//! unpadded sequence (the padded Python batch gives the same values for the real positions, as `Encoder::pooled` does) and
//! [`microbatch`] adds the loss gradient of a microbatch into a gradient accumulator of the same layout. The optimizer and
//! the fit loop are later checkpoints; the word-embedding gradient is dense here.

use std::collections::BTreeMap;

use privoke_semantic::bert::BertConfig;
use privoke_semantic::labels::HEAD_WIDTHS;
use privoke_semantic::safetensors::Tensor;

use crate::bert_backward::{
    Dense, LAYER_SUFFIXES, LayerCache, LayerParams, Norm, layer_backward, layer_forward, linear, linear_back, norm_back, norm_forward,
};
use crate::error::TrainingError;

/// The head tasks, in `LABELS` order.
pub const TASKS: [&str; 3] = ["sensitivity", "visibility", "category"];

/// Embeddings: word, position and token-type tables (`[rows, hidden]`) and their layer norm.
#[derive(Debug, Clone, PartialEq)]
pub struct Embeddings {
    /// `[vocab, hidden]`.
    pub word: Vec<f64>,
    /// `[positions, hidden]`.
    pub position: Vec<f64>,
    /// `[token types, hidden]`; only row 0 is used (all-zero token types).
    pub token_type: Vec<f64>,
    /// `embeddings.LayerNorm`.
    pub norm: Norm,
}

/// Every parameter of the V3 model; also the layout of its gradient.
#[derive(Debug, Clone, PartialEq)]
pub struct V3Params {
    /// Hidden width.
    pub hidden: usize,
    /// Attention heads.
    pub heads: usize,
    /// Layer-norm epsilon.
    pub eps: f64,
    /// The embeddings.
    pub embeddings: Embeddings,
    /// The encoder layers.
    pub layers: Vec<LayerParams>,
    /// `pooler.dense`.
    pub pooler: Dense,
    /// The three task heads (`heads.<task>_weight` and `_bias`), `[labels, hidden]`.
    pub task_heads: [Dense; 3],
}

fn take(tensors: &BTreeMap<String, Tensor>, name: &str, shape: &[usize]) -> Result<Vec<f64>, TrainingError> {
    let tensor = tensors
        .get(name)
        .ok_or_else(|| TrainingError::invalid(format!("Checkpoint includes unsupported or missing model keys: {name}.")))?;
    if tensor.shape != shape {
        return Err(TrainingError::invalid(format!("Checkpoint tensor {name} has shape {:?}, expected {shape:?}.", tensor.shape)));
    }
    Ok(tensor.data.iter().map(|v| f64::from(*v)).collect())
}

fn dense(tensors: &BTreeMap<String, Tensor>, prefix: &str, input: usize, output: usize) -> Result<Dense, TrainingError> {
    Ok(Dense {
        weight: take(tensors, &format!("{prefix}.weight"), &[output, input])?,
        bias: take(tensors, &format!("{prefix}.bias"), &[output])?,
    })
}

fn norm(tensors: &BTreeMap<String, Tensor>, prefix: &str, width: usize) -> Result<Norm, TrainingError> {
    Ok(Norm { gamma: take(tensors, &format!("{prefix}.weight"), &[width])?, beta: take(tensors, &format!("{prefix}.bias"), &[width])? })
}

impl V3Params {
    /// Build the parameters from a checkpoint's tensors: the encoder under `encoder.` (the names `Encoder::from_tensors`
    /// reads, with a pooler) and the heads under `heads.`. Every name and shape is checked.
    pub fn from_tensors(config: &BertConfig, tensors: &BTreeMap<String, Tensor>) -> Result<Self, TrainingError> {
        let hidden = config.hidden_size;
        let embeddings = Embeddings {
            word: take(tensors, "encoder.embeddings.word_embeddings.weight", &[config.vocab_size, hidden])?,
            position: take(tensors, "encoder.embeddings.position_embeddings.weight", &[config.max_position_embeddings, hidden])?,
            token_type: take(tensors, "encoder.embeddings.token_type_embeddings.weight", &[config.type_vocab_size, hidden])?,
            norm: norm(tensors, "encoder.embeddings.LayerNorm", hidden)?,
        };
        let mut layers = Vec::with_capacity(config.num_hidden_layers);
        for index in 0..config.num_hidden_layers {
            let base = format!("encoder.encoder.layer.{index}");
            layers.push(LayerParams {
                query: dense(tensors, &format!("{base}.attention.self.query"), hidden, hidden)?,
                key: dense(tensors, &format!("{base}.attention.self.key"), hidden, hidden)?,
                value: dense(tensors, &format!("{base}.attention.self.value"), hidden, hidden)?,
                attention_output: dense(tensors, &format!("{base}.attention.output.dense"), hidden, hidden)?,
                attention_norm: norm(tensors, &format!("{base}.attention.output.LayerNorm"), hidden)?,
                intermediate: dense(tensors, &format!("{base}.intermediate.dense"), hidden, config.intermediate_size)?,
                output: dense(tensors, &format!("{base}.output.dense"), config.intermediate_size, hidden)?,
                output_norm: norm(tensors, &format!("{base}.output.LayerNorm"), hidden)?,
            });
        }
        let pooler = dense(tensors, "encoder.pooler.dense", hidden, hidden)?;
        let head = |task: &str, width: usize| -> Result<Dense, TrainingError> {
            Ok(Dense {
                weight: take(tensors, &format!("heads.{task}_weight"), &[width, hidden])?,
                bias: take(tensors, &format!("heads.{task}_bias"), &[width])?,
            })
        };
        let task_heads = [head(TASKS[0], HEAD_WIDTHS[0])?, head(TASKS[1], HEAD_WIDTHS[1])?, head(TASKS[2], HEAD_WIDTHS[2])?];
        let expected = 5 + 16 * config.num_hidden_layers + 2 + 6;
        if tensors.len() != expected {
            return Err(TrainingError::invalid("Checkpoint includes unsupported or missing model keys."));
        }
        Ok(Self { hidden, heads: config.num_attention_heads, eps: config.layer_norm_eps, embeddings, layers, pooler, task_heads })
    }

    /// Every tensor by its checkpoint name, in a fixed order (embeddings, layers, pooler, heads).
    pub fn named_mut(&mut self) -> Vec<(String, &mut Vec<f64>)> {
        let mut out: Vec<(String, &mut Vec<f64>)> = vec![
            ("encoder.embeddings.word_embeddings.weight".into(), &mut self.embeddings.word),
            ("encoder.embeddings.position_embeddings.weight".into(), &mut self.embeddings.position),
            ("encoder.embeddings.token_type_embeddings.weight".into(), &mut self.embeddings.token_type),
            ("encoder.embeddings.LayerNorm.weight".into(), &mut self.embeddings.norm.gamma),
            ("encoder.embeddings.LayerNorm.bias".into(), &mut self.embeddings.norm.beta),
        ];
        for (index, layer) in self.layers.iter_mut().enumerate() {
            for (suffix, part) in LAYER_SUFFIXES.iter().zip(layer.parts_mut()) {
                out.push((format!("encoder.encoder.layer.{index}.{suffix}"), part));
            }
        }
        out.push(("encoder.pooler.dense.weight".into(), &mut self.pooler.weight));
        out.push(("encoder.pooler.dense.bias".into(), &mut self.pooler.bias));
        for (task, head) in TASKS.iter().zip(self.task_heads.iter_mut()) {
            out.push((format!("heads.{task}_weight"), &mut head.weight));
            out.push((format!("heads.{task}_bias"), &mut head.bias));
        }
        out
    }

    /// The same layout filled with zeros (a gradient accumulator).
    #[must_use]
    pub fn zeros_like(&self) -> Self {
        let mut zeros = self.clone();
        for (_, part) in zeros.named_mut() {
            part.fill(0.0);
        }
        zeros
    }
}

/// One sequence's forward state: what [`sequence_backward`] needs.
#[derive(Debug, Clone)]
pub struct SequenceCache {
    ids: Vec<u32>,
    xhat: Vec<f64>,
    inv: Vec<f64>,
    layers: Vec<LayerCache>,
    first: Vec<f64>,
    /// `pooler_output`.
    pub pooled: Vec<f64>,
    /// The logits of the three heads.
    pub logits: [Vec<f64>; 3],
}

/// The forward of one unpadded token sequence through the embeddings, layers, pooler and heads.
pub fn sequence_forward(params: &V3Params, ids: &[u32]) -> Result<SequenceCache, TrainingError> {
    let hidden = params.hidden;
    let n = ids.len();
    let vocab = params.embeddings.word.len() / hidden;
    if n == 0 || n > params.embeddings.position.len() / hidden {
        return Err(TrainingError::invalid("Token sequence is outside the model's positions."));
    }
    let mut x = vec![0.0; n * hidden];
    for (position, (row, id)) in x.chunks_mut(hidden).zip(ids).enumerate() {
        let id = usize::try_from(*id).unwrap_or(usize::MAX);
        if id >= vocab {
            return Err(TrainingError::invalid("Token id is outside the vocabulary."));
        }
        let word = &params.embeddings.word[id * hidden..(id + 1) * hidden];
        let place = &params.embeddings.position[position * hidden..(position + 1) * hidden];
        for (((slot, w), t), p) in row.iter_mut().zip(word).zip(&params.embeddings.token_type[..hidden]).zip(place) {
            *slot = w + t + p;
        }
    }
    let (mut current, xhat, inv) = norm_forward(&x, hidden, &params.embeddings.norm, params.eps);
    let mut layers = Vec::with_capacity(params.layers.len());
    for layer in &params.layers {
        let (next, cache) = layer_forward(layer, &current, n, hidden, params.heads, params.eps);
        layers.push(cache);
        current = next;
    }
    let first = current[..hidden].to_vec();
    let pooled: Vec<f64> = linear(&first, 1, &params.pooler, hidden, hidden).into_iter().map(f64::tanh).collect();
    let logits = [0, 1, 2].map(|task| linear(&pooled, 1, &params.task_heads[task], hidden, HEAD_WIDTHS[task]));
    Ok(SequenceCache { ids: ids.to_vec(), xhat, inv, layers, first, pooled, logits })
}

/// One labelled row: the token ids and the three targets.
#[derive(Debug, Clone, PartialEq)]
pub struct Example {
    /// The unpadded token ids.
    pub ids: Vec<u32>,
    /// The sensitivity class index.
    pub sensitivity: usize,
    /// The visibility class index.
    pub visibility: usize,
    /// The ten category indicators (0 or 1).
    pub categories: Vec<f64>,
}

/// `logsumexp(x) - x[target]` and the gradient `softmax(x) - onehot(target)`.
fn cross_entropy(logits: &[f64], target: usize) -> (f64, Vec<f64>) {
    let max = logits.iter().copied().fold(f64::NEG_INFINITY, f64::max);
    let exp: Vec<f64> = logits.iter().map(|v| (v - max).exp()).collect();
    let sum: f64 = exp.iter().sum();
    let loss = max + sum.ln() - logits[target];
    let grad = exp.iter().enumerate().map(|(i, e)| e / sum - f64::from(u8::from(i == target))).collect();
    (loss, grad)
}

/// Binary cross entropy with logits, summed over the entries, and its gradient `sigmoid(x) - c`.
fn bce_with_logits(logits: &[f64], targets: &[f64]) -> (f64, Vec<f64>) {
    let mut loss = 0.0;
    let mut grad = Vec::with_capacity(logits.len());
    for (x, c) in logits.iter().zip(targets) {
        loss += x.max(0.0) - x * c + (-x.abs()).exp().ln_1p();
        grad.push(1.0 / (1.0 + (-x).exp()) - c);
    }
    (loss, grad)
}

/// The backward of one sequence given the gradient of its three logits, added into `grads`.
pub fn sequence_backward(params: &V3Params, cache: &SequenceCache, dlogits: &[Vec<f64>; 3], grads: &mut V3Params) {
    let hidden = params.hidden;
    let n = cache.ids.len();
    let mut dpooled = vec![0.0; hidden];
    for (((dlogit, head), head_grads), width) in dlogits.iter().zip(&params.task_heads).zip(grads.task_heads.iter_mut()).zip(HEAD_WIDTHS) {
        let (dx, grad) = linear_back(dlogit, &cache.pooled, 1, head, hidden, width);
        for (slot, value) in dpooled.iter_mut().zip(dx) {
            *slot += value;
        }
        add(&mut head_grads.weight, &grad.weight);
        add(&mut head_grads.bias, &grad.bias);
    }
    let dz: Vec<f64> = dpooled.iter().zip(&cache.pooled).map(|(d, p)| d * (1.0 - p * p)).collect();
    let (dfirst, pooler) = linear_back(&dz, &cache.first, 1, &params.pooler, hidden, hidden);
    add(&mut grads.pooler.weight, &pooler.weight);
    add(&mut grads.pooler.bias, &pooler.bias);
    let mut upstream = vec![0.0; n * hidden];
    upstream[..hidden].copy_from_slice(&dfirst);
    for ((layer, layer_cache), layer_grads) in params.layers.iter().zip(&cache.layers).zip(grads.layers.iter_mut()).rev() {
        let (dx, grad) = layer_backward(layer, layer_cache, &upstream);
        layer_grads.add_assign(grad);
        upstream = dx;
    }
    let (dsum, norm_grad) = norm_back(&upstream, &cache.xhat, &cache.inv, hidden, &params.embeddings.norm);
    add(&mut grads.embeddings.norm.gamma, &norm_grad.gamma);
    add(&mut grads.embeddings.norm.beta, &norm_grad.beta);
    for (position, (row, id)) in dsum.chunks(hidden).zip(&cache.ids).enumerate() {
        let id = usize::try_from(*id).unwrap_or(usize::MAX);
        add(&mut grads.embeddings.word[id * hidden..(id + 1) * hidden], row);
        add(&mut grads.embeddings.position[position * hidden..(position + 1) * hidden], row);
        add(&mut grads.embeddings.token_type[..hidden], row);
    }
}

fn add(slot: &mut [f64], values: &[f64]) {
    for (a, b) in slot.iter_mut().zip(values) {
        *a += b;
    }
}

/// The loss of one microbatch, `(CE_sensitivity_sum + CE_visibility_sum + BCE_category_sum / 10) / scale` (`scale` is the
/// 64 of a full training batch), with its gradient added into `grads`.
pub fn microbatch(params: &V3Params, examples: &[Example], scale: f64, grads: &mut V3Params) -> Result<f64, TrainingError> {
    let categories = HEAD_WIDTHS[2] as f64;
    let mut total = 0.0;
    for example in examples {
        if example.sensitivity >= HEAD_WIDTHS[0] || example.visibility >= HEAD_WIDTHS[1] || example.categories.len() != HEAD_WIDTHS[2] {
            return Err(TrainingError::invalid("Training target is outside the head labels."));
        }
        let cache = sequence_forward(params, &example.ids)?;
        let (loss_s, mut grad_s) = cross_entropy(&cache.logits[0], example.sensitivity);
        let (loss_v, mut grad_v) = cross_entropy(&cache.logits[1], example.visibility);
        let (loss_c, mut grad_c) = bce_with_logits(&cache.logits[2], &example.categories);
        total += loss_s + loss_v + loss_c / categories;
        grad_s.iter_mut().for_each(|g| *g /= scale);
        grad_v.iter_mut().for_each(|g| *g /= scale);
        grad_c.iter_mut().for_each(|g| *g /= categories * scale);
        sequence_backward(params, &cache, &[grad_s, grad_v, grad_c], grads);
    }
    Ok(total / scale)
}
