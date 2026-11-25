//! `torch.optim.AdamW` (weight decay 0) and `torch.nn.utils.clip_grad_norm_` as the V3 fit uses them
//! (`extension/client-runtime/src/v3/training.py`, checkpoint 3).
//!
//! The optimizer holds one first and second moment per tensor and the shared step count; every tensor belongs to a group
//! with its own learning rate (heads and encoder). The arithmetic follows torch's single-tensor AdamW in the order torch
//! evaluates it (`lerp` for the first moment, `addcmul` for the second, bias corrections, `addcdiv`), here in float64.

use crate::error::TrainingError;

/// The `clip_grad_norm_` epsilon.
const CLIP_EPSILON: f64 = 1e-6;

/// The AdamW state over a fixed list of tensors.
#[derive(Debug, Clone)]
pub struct AdamW {
    beta1: f64,
    beta2: f64,
    eps: f64,
    step: i32,
    first: Vec<Vec<f64>>,
    second: Vec<Vec<f64>>,
}

impl AdamW {
    /// A fresh state for tensors of the given sizes.
    pub fn new(betas: (f64, f64), eps: f64, sizes: &[usize]) -> Self {
        Self {
            beta1: betas.0,
            beta2: betas.1,
            eps,
            step: 0,
            first: sizes.iter().map(|n| vec![0.0; *n]).collect(),
            second: sizes.iter().map(|n| vec![0.0; *n]).collect(),
        }
    }

    /// Steps taken.
    pub fn steps(&self) -> i32 {
        self.step
    }

    /// One optimizer step: `params[i]` moves along `grads[i]` with learning rate `rates[i]`.
    pub fn step(&mut self, params: &mut [&mut Vec<f64>], grads: &[&[f64]], rates: &[f64]) -> Result<(), TrainingError> {
        if params.len() != self.first.len() || grads.len() != params.len() || rates.len() != params.len() {
            return Err(TrainingError::invalid("Optimizer tensors differ from its state."));
        }
        self.step += 1;
        let bias1 = 1.0 - self.beta1.powi(self.step);
        let bias2 = 1.0 - self.beta2.powi(self.step);
        let bias2_sqrt = bias2.sqrt();
        for (((param, grad), rate), (first, second)) in
            params.iter_mut().zip(grads).zip(rates).zip(self.first.iter_mut().zip(self.second.iter_mut()))
        {
            if param.len() != grad.len() || first.len() != grad.len() {
                return Err(TrainingError::invalid("Optimizer tensor sizes differ."));
            }
            let step_size = rate / bias1;
            let weight = 1.0 - self.beta1;
            for (((p, g), m), v) in param.iter_mut().zip(*grad).zip(first.iter_mut()).zip(second.iter_mut()) {
                // `exp_avg.lerp_(grad, 1 - beta1)`: torch takes the branch on the weight.
                let delta = g - *m;
                *m = if weight < 0.5 { *m + weight * delta } else { g - delta * (1.0 - weight) };
                // `exp_avg_sq.mul_(beta2).addcmul_(grad, grad, value=1 - beta2)`.
                *v = *v * self.beta2 + (1.0 - self.beta2) * g * g;
                let denom = v.sqrt() / bias2_sqrt + self.eps;
                *p += -step_size * *m / denom;
            }
        }
        Ok(())
    }
}

/// `clip_grad_norm_(grads, max_norm, error_if_nonfinite=True)`: the 2-norm of the per-tensor 2-norms, then every gradient is
/// scaled by `min(max_norm / (norm + 1e-6), 1)`. Returns the norm before clipping.
pub fn clip_grad_norm(grads: &mut [&mut Vec<f64>], max_norm: f64) -> Result<f64, TrainingError> {
    let norms: Vec<f64> = grads.iter().map(|g| g.iter().map(|v| v * v).sum::<f64>().sqrt()).collect();
    let total = norms.iter().map(|n| n * n).sum::<f64>().sqrt();
    if !total.is_finite() {
        return Err(TrainingError::invalid("The total norm for gradients is non-finite, so it cannot be clipped."));
    }
    let coefficient = (max_norm / (total + CLIP_EPSILON)).min(1.0);
    for grad in grads.iter_mut() {
        for value in grad.iter_mut() {
            *value *= coefficient;
        }
    }
    Ok(total)
}
