//! The FULL projected Adam of `full_adam_training.py` (policy `full_projected_adam64_v1`).
//!
//! Contract (binding, from `privoke_model.full_adam.CONFIG`): 64 fixed steps, `eta = 0.003`, `beta1 = 0.9`,
//! `beta2 = 0.999`, `epsilon = 1e-8`, float64 moments, gradient denominator 1, microbatches of 32, one CPU thread.
//! Every step recomputes the gradient from the candidate parameters of the previous step; the cumulative float32
//! delta from the immutable base is capped at the float32 value just inside 0.05, and the candidate is
//! `float32(round(float32(base) + float32(delta), 8))`.

use std::collections::BTreeMap;

use privoke_contracts::fingerprint::parameter_fingerprint;

use crate::error::TrainingError;
use crate::net::{Params, Tensor, TinyNet};
use crate::objective::{Example, Objective, supervised_deltas};

/// Name of the optimizer policy.
pub const POLICY: &str = "full_projected_adam64_v1";
/// The one objective of the FULL route.
pub const OBJECTIVE: &str = "class_balanced_contextual_sum_category_decision_margin_v1";
/// Fixed number of steps.
pub const STEPS: u32 = 64;
/// Step size.
pub const ETA: f64 = 0.003;
/// First-moment decay.
pub const BETA1: f64 = 0.9;
/// Second-moment decay.
pub const BETA2: f64 = 0.999;
/// Denominator offset.
pub const EPSILON: f64 = 1e-8;
/// Cumulative delta cap.
pub const DELTA_CAP: f64 = 0.05;
/// Rows per microbatch.
pub const MICROBATCH: usize = 32;

/// Float32 values of every tensor, by name.
pub type F32Map = BTreeMap<String, Vec<f32>>;

/// The delta cap as float32 rounded toward zero when the nearest float32 exceeds the real cap.
pub fn delta_cap() -> f32 {
    let cap = DELTA_CAP as f32;
    if f64::from(cap) > DELTA_CAP { f32::from_bits(cap.to_bits() - 1) } else { cap }
}

/// Persisted delta and float64 moments.
#[derive(Debug, Clone)]
pub struct AdamState {
    /// Cumulative float32 delta from the base.
    pub delta: F32Map,
    moment: BTreeMap<String, Vec<f64>>,
    variance: BTreeMap<String, Vec<f64>>,
}

impl AdamState {
    /// The first and second moments (float64), by tensor name.
    pub fn moments(&self) -> (&BTreeMap<String, Vec<f64>>, &BTreeMap<String, Vec<f64>>) {
        (&self.moment, &self.variance)
    }

    /// Zero delta and zero moments over the inventory of `base`.
    pub fn new(base: &F32Map) -> Self {
        let zeros = |n: usize| vec![0.0f64; n];
        Self {
            delta: base.iter().map(|(k, v)| (k.clone(), vec![0.0f32; v.len()])).collect(),
            moment: base.iter().map(|(k, v)| (k.clone(), zeros(v.len()))).collect(),
            variance: base.iter().map(|(k, v)| (k.clone(), zeros(v.len()))).collect(),
        }
    }
}

/// Result of one Adam step.
#[derive(Debug, Clone)]
pub struct StepOutcome {
    /// Cumulative delta as doubles (`float(v)` of the float32 delta).
    pub cumulative: BTreeMap<String, Vec<f64>>,
    /// The transported candidate (float32).
    pub candidate: F32Map,
    /// Coordinates whose raw cumulative delta exceeded the cap.
    pub clipped: usize,
}

/// `round(x, 8)` of Python: the correctly rounded decimal with eight places.
///
/// Rust formats the exact binary value with correct rounding; the two differ only on an exact decimal tie
/// (a dyadic value with nine decimals ending in 5), which a sum of two random float32 values does not produce in
/// practice.
fn round8(x: f64) -> f64 {
    format!("{x:.8}").parse().unwrap_or(x)
}

/// One `adam_step`: the negative globally normalised direction is accumulated into the persisted delta.
pub fn adam_step(
    base: &F32Map,
    state: &mut AdamState,
    direction: &BTreeMap<String, Vec<f64>>,
    step: u32,
) -> Result<StepOutcome, TrainingError> {
    if direction.keys().ne(base.keys()) {
        return Err(TrainingError::invalid("FULL Adam direction inventory differs from immutable base."));
    }
    let cap = f64::from(delta_cap());
    let correction1 = 1.0 - BETA1.powf(f64::from(step));
    let correction2 = 1.0 - BETA2.powf(f64::from(step));
    let mut clipped = 0usize;
    for (name, values) in base {
        let g = &direction[name];
        if g.len() != values.len() || g.iter().any(|v| !v.is_finite()) {
            return Err(TrainingError::invalid("FULL Adam gradients must have exact finite shapes."));
        }
        let (moment, variance, delta) = (state.moment.get_mut(name), state.variance.get_mut(name), state.delta.get_mut(name));
        let (Some(moment), Some(variance), Some(delta)) = (moment, variance, delta) else {
            return Err(TrainingError::invalid("FULL Adam state differs from its base inventory."));
        };
        for (i, gv) in g.iter().enumerate() {
            moment[i] = BETA1 * moment[i] + (1.0 - BETA1) * gv;
            variance[i] = BETA2 * variance[i] + (1.0 - BETA2) * gv * gv;
            let increment = ETA * (moment[i] / correction1) / ((variance[i] / correction2).sqrt() + EPSILON);
            let raw = f64::from(delta[i]) + increment;
            if !raw.is_finite() {
                return Err(TrainingError::invalid("FULL Adam moments/increments must remain finite."));
            }
            if raw.abs() > cap {
                clipped += 1;
            }
            delta[i] = raw.clamp(-cap, cap) as f32;
            if f64::from(delta[i]).abs() > DELTA_CAP {
                return Err(TrainingError::invalid("FULL Adam transported delta exceeds its fixed cap."));
            }
        }
    }
    let cumulative: BTreeMap<String, Vec<f64>> =
        state.delta.iter().map(|(n, v)| (n.clone(), v.iter().map(|x| f64::from(*x)).collect())).collect();
    let mut candidate = F32Map::new();
    for (name, values) in base {
        let delta = &state.delta[name];
        let transported: Vec<f32> = values.iter().zip(delta).map(|(b, d)| round8(f64::from(*b) + f64::from(*d)) as f32).collect();
        if transported.iter().any(|v| !v.is_finite()) {
            return Err(TrainingError::invalid("FULL Adam transported candidate must remain finite."));
        }
        candidate.insert(name.clone(), transported);
    }
    Ok(StepOutcome { cumulative, candidate, clipped })
}

/// One recorded step of a fit.
#[derive(Debug, Clone, PartialEq)]
pub struct FitStep {
    /// 1-based step.
    pub step: u32,
    /// Fingerprint of the parameters before the step.
    pub before: String,
    /// Fingerprint of the candidate after the step.
    pub after: String,
    /// Objective loss at the `before` parameters.
    pub loss: f64,
    /// Fingerprint of the cumulative delta.
    pub delta: String,
    /// Coordinates clipped at the cap.
    pub clipped: usize,
}

/// Counters of the trace, derived from the fixed schedule (the Python run counts observed block boundaries).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Counts {
    /// Directions computed.
    pub directions: u64,
    /// Microbatch forwards (equal to the backward passes).
    pub microbatches: u64,
    /// Encoder block forwards.
    pub block_forwards: u64,
    /// Parameter states, the base included.
    pub parameter_states: u64,
}

/// A completed fit.
#[derive(Debug, Clone)]
pub struct Fit {
    /// Cumulative delta as doubles.
    pub cumulative: BTreeMap<String, Vec<f64>>,
    /// The final candidate.
    pub candidate: F32Map,
    /// Fingerprint of the base.
    pub base: String,
    /// Fingerprint of the final candidate.
    pub final_fingerprint: String,
    /// Fingerprint of the final cumulative delta.
    pub delta: String,
    /// Every step.
    pub steps: Vec<FitStep>,
    /// Counters.
    pub counts: Counts,
}

fn fingerprint_f32(values: &F32Map, shapes: &BTreeMap<String, Vec<u64>>) -> Result<String, TrainingError> {
    let widened: BTreeMap<String, Vec<f64>> = values.iter().map(|(n, v)| (n.clone(), v.iter().map(|x| f64::from(*x)).collect())).collect();
    Ok(parameter_fingerprint(&widened, Some(shapes))?)
}

fn params_of(net: &TinyNet, values: &F32Map) -> Params {
    values
        .iter()
        .map(|(name, v)| {
            let shape = net.params.get(name).map(|t| t.shape.clone()).unwrap_or_default();
            (name.clone(), Tensor { shape, data: v.iter().map(|x| f64::from(*x)).collect() })
        })
        .collect()
}

/// The FULL fit with a pluggable gradient source (`direction(net, step) -> (direction, loss)`); the Rust gradient is
/// [`fit`], and a recorded Python gradient replays the Adam recurrence exactly.
pub fn fit_with<F>(net: &TinyNet, example_count: usize, steps: u32, mut direction: F) -> Result<Fit, TrainingError>
where
    F: FnMut(&TinyNet, u32) -> Result<(BTreeMap<String, Vec<f64>>, f64), TrainingError>,
{
    if example_count == 0 {
        return Err(TrainingError::invalid("At least one training example is required."));
    }
    let base: F32Map = net.params.iter().map(|(n, t)| (n.clone(), t.data.iter().map(|v| *v as f32).collect())).collect();
    let shapes: BTreeMap<String, Vec<u64>> =
        net.params.iter().map(|(n, t)| (n.clone(), t.shape.iter().map(|d| *d as u64).collect())).collect();
    let mut state = AdamState::new(&base);
    let base_fingerprint = fingerprint_f32(&base, &shapes)?;
    let mut current_net = net.clone();
    let mut current = base.clone();
    let mut recorded = Vec::new();
    let mut cumulative = BTreeMap::new();
    for step in 1..=steps {
        let (grad, loss) = direction(&current_net, step)?;
        if !loss.is_finite() || loss < 0.0 {
            return Err(TrainingError::invalid("FULL Adam helper loss must remain finite and nonnegative."));
        }
        let before = fingerprint_f32(&current, &shapes)?;
        let outcome = adam_step(&base, &mut state, &grad, step)?;
        let after = fingerprint_f32(&outcome.candidate, &shapes)?;
        let delta = parameter_fingerprint(&outcome.cumulative, Some(&shapes))?;
        recorded.push(FitStep { step, before, after, loss, delta, clipped: outcome.clipped });
        cumulative = outcome.cumulative;
        current_net = net.with_params(params_of(net, &outcome.candidate))?;
        current = outcome.candidate;
    }
    let batches = example_count.div_ceil(MICROBATCH) as u64;
    let layers = net.config.num_layers as u64;
    let steps64 = u64::from(steps);
    let delta = recorded.last().map(|s| s.delta.clone()).unwrap_or_default();
    Ok(Fit {
        cumulative,
        final_fingerprint: fingerprint_f32(&current, &shapes)?,
        candidate: current,
        base: base_fingerprint,
        delta,
        steps: recorded,
        counts: Counts {
            directions: steps64,
            microbatches: steps64 * batches,
            block_forwards: steps64 * batches * layers,
            parameter_states: steps64 + 1,
        },
    })
}

/// The FULL fit with the Rust gradient of the sum-margin objective over (class-balanced) `examples`.
pub fn fit(net: &TinyNet, examples: &[Example], steps: u32) -> Result<Fit, TrainingError> {
    fit_with(net, examples.len(), steps, |current, _| {
        let result = supervised_deltas(current, examples, Objective::SumMargin)?;
        Ok((result.deltas, result.loss))
    })
}
