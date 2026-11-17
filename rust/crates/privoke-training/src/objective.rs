//! The supervised objectives of `supervised_training.supervised_last_block_deltas` and the class-balanced reweighting
//! of `training._class_balanced_examples`.

use std::collections::BTreeMap;

use crate::error::TrainingError;
use crate::net::TinyNet;

/// The contextual training objectives the Tiny paths use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Objective {
    /// `legacy_sum_category` (no objective key) and `class_balanced_contextual_v1`: sensitivity CE, visibility CE and
    /// the summed category BCE.
    Legacy,
    /// `class_balanced_contextual_mean_category_v1`: category BCE averaged over the labels.
    MeanCategory,
    /// `class_balanced_contextual_decision_margin_v1`: mean category BCE plus the union-margin loss.
    DecisionMargin,
    /// `class_balanced_contextual_sum_category_decision_margin_v1`: summed category BCE plus the union-margin loss.
    SumMargin,
}

impl Objective {
    /// The objective for a metadata value (`None` is the legacy objective).
    pub fn from_name(name: Option<&str>) -> Result<Self, TrainingError> {
        match name {
            None | Some("legacy_sum_category" | "class_balanced_contextual_v1") => Ok(Self::Legacy),
            Some("class_balanced_contextual_mean_category_v1") => Ok(Self::MeanCategory),
            Some("class_balanced_contextual_decision_margin_v1") => Ok(Self::DecisionMargin),
            Some("class_balanced_contextual_sum_category_decision_margin_v1") => Ok(Self::SumMargin),
            Some(_) => Err(TrainingError::invalid("Unsupported contextual training objective.")),
        }
    }

    pub fn mean_category(self) -> bool {
        matches!(self, Self::MeanCategory | Self::DecisionMargin)
    }

    pub fn decision_margin(self) -> bool {
        matches!(self, Self::DecisionMargin | Self::SumMargin)
    }
}

/// The explicit target of a row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    /// Sensitivity label name.
    pub sensitivity: String,
    /// Visibility label name.
    pub visibility: String,
    /// Category label names.
    pub categories: Vec<String>,
}

impl Target {
    /// `Classification.is_sensitive`.
    pub fn is_sensitive(&self) -> bool {
        self.sensitivity != "S0" || !self.categories.is_empty()
    }
}

/// A training row: normalised text, target and weight.
#[derive(Debug, Clone, PartialEq)]
pub struct Example {
    /// The (already normalised) prompt text.
    pub text: String,
    /// Target.
    pub target: Target,
    /// Positive finite weight.
    pub weight: f64,
}

/// Result of one gradient computation.
#[derive(Debug, Clone, PartialEq)]
pub struct Deltas {
    /// `-gradient` per tensor, row-major.
    pub deltas: BTreeMap<String, Vec<f64>>,
    /// The weighted objective loss.
    pub loss: f64,
    /// Weighted task components (`sensitivity`, `visibility`, `category`), filled for the mean and margin objectives.
    pub task_totals: Option<[f64; 3]>,
}

/// `math.fsum`: the exactly rounded sum (Shewchuk's partials).
pub fn fsum(values: impl IntoIterator<Item = f64>) -> f64 {
    let mut partials: Vec<f64> = Vec::new();
    for mut x in values {
        let mut kept = 0;
        for index in 0..partials.len() {
            let mut y = partials[index];
            if x.abs() < y.abs() {
                std::mem::swap(&mut x, &mut y);
            }
            let hi = x + y;
            let lo = y - (hi - x);
            if lo != 0.0 {
                partials[kept] = lo;
                kept += 1;
            }
            x = hi;
        }
        partials.truncate(kept);
        partials.push(x);
    }
    partials.iter().rev().fold(0.0, |acc, p| acc + p)
}

/// `_class_balanced_examples`: give each target class half of the total weight.
pub fn class_balanced(examples: &[Example]) -> Result<Vec<Example>, TrainingError> {
    if examples.is_empty() {
        return Err(TrainingError::invalid("Class-balanced training requires explicit contextual targets for every row."));
    }
    if examples.iter().any(|e| !e.weight.is_finite() || e.weight <= 0.0) {
        return Err(TrainingError::invalid("Class-balanced training weights must be finite and positive."));
    }
    let raw = |label: bool| fsum(examples.iter().filter(|e| e.target.is_sensitive() == label).map(|e| e.weight));
    let (clean, sensitive) = (raw(false), raw(true));
    let total = fsum([clean, sensitive]);
    if !(clean.is_finite() && sensitive.is_finite() && clean > 0.0 && sensitive > 0.0) {
        return Err(TrainingError::invalid("Class-balanced training requires both clean and sensitive target classes."));
    }
    if !total.is_finite() {
        return Err(TrainingError::invalid("Class-balanced total weight must remain finite."));
    }
    let adjusted: Vec<Example> = examples
        .iter()
        .map(|e| {
            let stratum = if e.target.is_sensitive() { sensitive } else { clean };
            Example { weight: total * (e.weight / stratum) * 0.5, ..e.clone() }
        })
        .collect();
    if adjusted.iter().any(|e| !e.weight.is_finite() || e.weight <= 0.0) {
        return Err(TrainingError::invalid("Class-balanced effective weights must remain finite and positive."));
    }
    Ok(adjusted)
}

fn softplus(x: f64) -> f64 {
    x.max(0.0) + (-x.abs()).exp().ln_1p()
}

fn sigmoid(x: f64) -> f64 {
    1.0 / (1.0 + (-x).exp())
}

fn label_index(labels: &[String], name: &str) -> Result<usize, TrainingError> {
    labels.iter().position(|l| l == name).ok_or_else(|| TrainingError::invalid(format!("Unknown classification label {name:?}.")))
}

/// Weighted gradient direction (`-gradient`) and loss of `examples` under `objective`, over every tensor.
///
/// All rows share one global weight denominator (the sum of the weights), as the Python microbatches do. A weight is
/// rounded to float32 after the division, as torch builds its weight tensor.
pub fn supervised_deltas(net: &TinyNet, examples: &[Example], objective: Objective) -> Result<Deltas, TrainingError> {
    if examples.is_empty() {
        return Err(TrainingError::invalid("Encoder adaptation requires explicit contextual targets for every row."));
    }
    if examples.iter().any(|e| !e.weight.is_finite() || e.weight <= 0.0) {
        return Err(TrainingError::invalid("Training weights must be finite and positive."));
    }
    let c = &net.config;
    if objective.decision_margin() {
        let s0 = c.sensitivity_labels.iter().filter(|l| *l == "S0").count();
        if s0 != 1 || c.sensitivity_labels.iter().all(|l| l == "S0") || !(c.category_threshold > 0.0 && c.category_threshold < 1.0) {
            return Err(TrainingError::invalid("Decision-margin training requires S0 and non-S0 sensitivity labels."));
        }
    }
    let total = fsum(examples.iter().map(|e| e.weight));
    if !total.is_finite() {
        return Err(TrainingError::invalid("Training total weight must remain finite."));
    }
    let mut grads = net.zero_grads();
    let mut loss = 0.0;
    let mut totals = [0.0; 3];
    let categories = c.category_labels.len() as f64;
    for example in examples {
        let weight = f64::from((example.weight / total) as f32);
        let ids = net.token_ids(&example.text);
        let fwd = net.forward(&ids)?;
        let [zs, zv, zc] = &fwd.logits;
        let sens = label_index(&c.sensitivity_labels, &example.target.sensitivity)?;
        let vis = label_index(&c.visibility_labels, &example.target.visibility)?;
        let mut y = vec![0.0; c.category_labels.len()];
        for name in &example.target.categories {
            y[label_index(&c.category_labels, name)?] = 1.0;
        }
        let mut dz: [Vec<f64>; 3] = [vec![0.0; zs.len()], vec![0.0; zv.len()], vec![0.0; zc.len()]];
        let mut components = [0.0; 3];
        for (slot, (z, index)) in [(zs, sens), (zv, vis)].into_iter().enumerate() {
            let max = z.iter().copied().fold(f64::NEG_INFINITY, f64::max);
            let lse = max + z.iter().map(|v| (v - max).exp()).sum::<f64>().ln();
            components[slot] = lse - z[index];
            for (j, v) in z.iter().enumerate() {
                dz[slot][j] = (v - lse).exp() - if j == index { 1.0 } else { 0.0 };
            }
        }
        let category_scale = if objective.mean_category() { 1.0 / categories } else { 1.0 };
        for (j, (z, target)) in zc.iter().zip(&y).enumerate() {
            components[2] += (softplus(*z) - target * z) * category_scale;
            dz[2][j] = (sigmoid(*z) - target) * category_scale;
        }
        let mut row = components.iter().sum::<f64>();
        if objective.decision_margin() {
            let s0 = label_index(&c.sensitivity_labels, "S0")?;
            let offset = c.category_threshold.ln() - (-c.category_threshold).ln_1p();
            // (slot, index) of every margin, in the order of the Python `torch.cat`.
            let mut margins: Vec<(f64, usize, usize)> = Vec::new();
            for (index, label) in c.sensitivity_labels.iter().enumerate() {
                if label != "S0" {
                    margins.push((zs[index] - zs[s0], 0, index));
                }
            }
            for (index, z) in zc.iter().enumerate() {
                margins.push((z - offset, 2, index));
            }
            if margins.iter().any(|m| !m.0.is_finite()) {
                return Err(TrainingError::invalid("Decision-margin differences must remain finite."));
            }
            let mut best = margins[0];
            for candidate in &margins[1..] {
                if candidate.0 > best.0 {
                    best = *candidate;
                }
            }
            let (margin, slot, index) = best;
            let (auxiliary, dmargin) =
                if example.target.is_sensitive() { (softplus(-margin), -sigmoid(-margin)) } else { (softplus(margin), sigmoid(margin)) };
            row += auxiliary;
            dz[slot][index] += dmargin;
            if slot == 0 {
                dz[0][s0] -= dmargin;
            }
        }
        if !row.is_finite() {
            return Err(TrainingError::invalid("Contextual supervised loss must be finite."));
        }
        loss += row * weight;
        for (running, component) in totals.iter_mut().zip(components) {
            *running += component * weight;
        }
        for part in &mut dz {
            for v in part.iter_mut() {
                *v *= weight;
            }
        }
        net.backward(&fwd, &dz, &mut grads);
    }
    let deltas: BTreeMap<String, Vec<f64>> = grads.into_iter().map(|(name, g)| (name, g.into_iter().map(|v| -v).collect())).collect();
    if deltas.values().flatten().any(|v| !v.is_finite()) {
        return Err(TrainingError::invalid("Contextual supervised gradients must exist and be finite."));
    }
    let task_totals = (objective.mean_category() || objective.decision_margin()).then_some(totals);
    Ok(Deltas { deltas, loss, task_totals })
}
