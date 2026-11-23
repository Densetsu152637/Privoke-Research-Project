//! The V3 fit (`extension/client-runtime/src/v3/training.py`, `fit` and `assess`, and `validate_execution` of
//! `shared/python/privoke_model/v3_contract.py`; checkpoint 4).
//!
//! A frozen window of TRAIN rows and a guard of 16 rows are fitted with AdamW over microbatches of the V3 loss
//! ([`crate::v3_model`]): per step the 64 rows of the scheduled block are split into microbatches, their gradients accumulate,
//! `clip_grad_norm_` and one AdamW step follow ([`crate::adamw`]). The candidate is exported as float32 tensors, assessed on the
//! guard by the semantic crate's own model ([`privoke_semantic::V3Model::with_tensors`], the way the product reloads the serialized
//! candidate), and the evidence is reconciled by [`validate_execution`]. Parameters are rounded to float32 after every step, as the
//! product's float32 tensors are; the arithmetic itself is float64.
//!
//! Deviations from the Python run: `torch`/`device` identify this implementation, `cuda_peak_bytes` is 0, and the dense word
//! embedding gradient is kept (about 62 MB at the real vocabulary of the 256-wide tiers; every row has an Adam moment anyway).

use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

use privoke_contracts::digest::sha256_hex;
use privoke_contracts::v3 as contract;
use privoke_contracts::v3::action_value;
use privoke_rules::preprocessing::normalize_text;
use privoke_semantic::V3Model;
use privoke_semantic::labels::{CATEGORY, VISIBILITY};
use privoke_semantic::safetensors::Tensor;
use serde_json::{Map, Value, json};

use crate::adamw::{AdamW, clip_grad_norm};
use crate::error::TrainingError;
use crate::v3_model::{Example, V3Params, microbatch_with};

fn invalid(message: &str) -> TrainingError {
    TrainingError::invalid(message)
}

/// The frozen policy of `validate_policy`: the pilot variant has two steps over one block, otherwise `steps` is 64, 256 or 512.
/// The contract lives in [`privoke_contracts::v3`], shared with the V3 fuzzer and the param-update checkpoint store.
pub use privoke_contracts::v3::frozen_policy;

/// `validate_policy`.
pub fn validate_policy(policy: &Value, pilot: bool) -> Result<(), TrainingError> {
    contract::validate_policy(policy, pilot).map_err(|error| TrainingError::invalid(error.0))
}

const ACTIONS: [&str; 3] = ["ALLOW", "WARN", "BLOCK"];

/// One labelled row of the frozen window or guard.
#[derive(Debug, Clone, PartialEq)]
pub struct Row {
    /// The prompt text.
    pub text: String,
    /// The packed target classification.
    pub packed: u16,
}

/// Everything the fit takes besides the model: the request identity, the rows and the policy.
#[derive(Debug, Clone)]
pub struct FitInput {
    /// `request_id`.
    pub request_id: String,
    /// `model_id` (`privoke-v3-<tier>`).
    pub model_id: String,
    /// The base manifest identity.
    pub base: String,
    /// The source commitment.
    pub source_commitment: String,
    /// FULL_ENCODER (true) or HEADS (false).
    pub full: bool,
    /// The frozen TRAIN window, in order.
    pub train: Vec<Row>,
    /// The 16 guard rows.
    pub guard: Vec<Row>,
    /// SHA-256 of the concatenated deterministic wire encoding of the train rows (the caller owns the protobuf).
    pub train_wire_sha256: String,
    /// The same for the guard rows.
    pub guard_wire_sha256: String,
    /// The policy, as parsed from `policy_json`.
    pub policy: Value,
}

/// The result of a fit.
#[derive(Debug, Clone)]
pub struct Fit {
    /// The evidence record (before the serialized-candidate fields the service adds).
    pub evidence: Value,
    /// The candidate checkpoint tensors (`encoder.*` and `heads.*`, float32).
    pub candidate: BTreeMap<String, Tensor>,
}

fn example(model: &V3Model, row: &Row) -> Result<Example, TrainingError> {
    let packed = row.packed;
    if !contract::valid_packed(u64::from(packed)) {
        return Err(invalid("Named and packed training targets disagree."));
    }
    let visibility = VISIBILITY.iter().position(|(_, value)| packed & 0b11100 == *value).ok_or_else(|| invalid("Invalid visibility."))?;
    Ok(Example {
        ids: model.tokenize(&row.text)?,
        sensitivity: usize::from(packed & 0b11),
        visibility,
        categories: CATEGORY.iter().map(|(_, bit)| f64::from(u8::from(packed & bit != 0))).collect(),
    })
}

/// `assess`: the model's prediction and action for every guard row.
fn assess(model: &V3Model, rows: &[Row]) -> Result<Value, TrainingError> {
    let mut results = Vec::with_capacity(rows.len());
    for row in rows {
        let prediction = model.predict(&row.text)?;
        let packed = prediction.classification.pack();
        let actual = action_value(packed, Some(prediction.confidence));
        let desired = action_value(row.packed, Some(0.999));
        results.push(json!({
            "target": row.packed, "prediction": packed, "action": ACTIONS[usize::try_from(actual).unwrap_or(0)],
            "confidence": prediction.confidence, "target_action": ACTIONS[usize::try_from(desired).unwrap_or(0)],
            "action_value": actual, "target_action_value": desired, "joint_correct": packed == row.packed && actual == desired
        }));
    }
    let count = |key: &str| results.iter().filter(|row| row[key] == true).count();
    let joint = count("joint_correct");
    let action = results.iter().filter(|row| row["action"] == row["target_action"]).count();
    Ok(json!({"rows": results, "joint_correct": joint, "action_correct": action, "examples": rows.len()}))
}

fn tensor_bytes(values: &[f32]) -> Vec<u8> {
    values.iter().flat_map(|value| value.to_le_bytes()).collect()
}

/// `tensor_changes`: the changed tensor names and the counts per group ([`privoke_contracts::v3::tensor_changes`]).
fn tensor_changes(before: &BTreeMap<String, Tensor>, after: &BTreeMap<String, Tensor>, layers: usize) -> (Vec<String>, Value) {
    let digests = |tensors: &BTreeMap<String, Tensor>| -> BTreeMap<String, String> {
        tensors.iter().map(|(name, tensor)| (name.clone(), tensor.sha256.clone())).collect()
    };
    contract::tensor_changes(&digests(before), &digests(after), layers)
}

fn require_f64(policy: &Value, key: &str) -> Result<f64, TrainingError> {
    policy[key].as_f64().ok_or_else(|| invalid("Policy differs from the frozen v3 contract."))
}

fn require_usize(policy: &Value, key: &str) -> Result<usize, TrainingError> {
    policy[key].as_u64().and_then(|value| usize::try_from(value).ok()).ok_or_else(|| invalid("Policy differs from the frozen v3 contract."))
}

/// `fit`. `model` is the base model as loaded from the release (its tokenizer and base guard inference), `base` its checkpoint
/// tensors; `cancel` returning false aborts at the start of a step with Python's text.
pub fn fit(model: &V3Model, base: &BTreeMap<String, Tensor>, input: &FitInput, cancel: &dyn Fn() -> bool) -> Result<Fit, TrainingError> {
    let result = fit_unchecked(model, base, input, cancel)?;
    validate_execution(&result.evidence, false)?;
    Ok(result)
}

/// [`fit`] without the final [`validate_execution`], whose tier pins (parameter counts, layer counts) describe the admitted real
/// tiers: the synthetic packages of the tests are not one of them.
pub fn fit_unchecked(
    model: &V3Model,
    base: &BTreeMap<String, Tensor>,
    input: &FitInput,
    cancel: &dyn Fn() -> bool,
) -> Result<Fit, TrainingError> {
    let policy = &input.policy;
    validate_policy(policy, policy["steps"] == 2)?;
    let (steps, window, microbatch_rows) =
        (require_usize(policy, "steps")?, require_usize(policy, "window_batches")?, require_usize(policy, "microbatch")?);
    if input.train.len() != window * 64 || input.guard.len() != 16 {
        return Err(invalid("Frozen TRAIN window/guard counts differ."));
    }
    let normalised = |rows: &[Row]| -> Result<BTreeSet<String>, TrainingError> {
        rows.iter().map(|row| normalize_text(&row.text).map_err(|error| TrainingError::invalid(format!("{error:?}")))).collect()
    };
    if !normalised(&input.train)?.is_disjoint(&normalised(&input.guard)?) {
        return Err(invalid("TRAIN/guard normalized texts overlap."));
    }
    let train: Vec<Example> = input.train.iter().map(|row| example(model, row)).collect::<Result<_, _>>()?;
    for row in &input.guard {
        example(model, row)?;
    }
    let config = model.encoder().config().clone();
    let layers = config.num_hidden_layers;
    let mut params = V3Params::from_tensors(&config, base)?;
    let mut grads = params.zeros_like();
    let started = Instant::now();
    let base_guard = assess(model, &input.guard)?;
    let (head_rate, encoder_rate) = (require_f64(policy, "head_lr")?, require_f64(policy, "encoder_lr")?);
    let betas = (policy["betas"][0].as_f64().unwrap_or(0.9), policy["betas"][1].as_f64().unwrap_or(0.999));
    let trainable = |name: &str| input.full || name.starts_with("heads.");
    let rates: Vec<f64> = params
        .named_mut()
        .iter()
        .filter(|(name, _)| trainable(name))
        .map(|(name, _)| if name.starts_with("heads.") { head_rate } else { encoder_rate })
        .collect();
    let sizes: Vec<usize> = params.named_mut().iter().filter(|(name, _)| trainable(name)).map(|(_, values)| values.len()).collect();
    let mut optimizer = AdamW::new(betas, require_f64(policy, "eps")?, &sizes);
    let clip_norm = require_f64(policy, "clip_norm")?;
    let mut counts = Map::new();
    let (mut optimizer_steps, mut train_rows, mut forward, mut backward) = (0u64, 0u64, 0u64, 0u64);
    let (mut block_forward, mut block_backward) = (vec![0u64; layers], vec![0u64; layers]);
    let (mut losses, mut trace) = (Vec::new(), Vec::new());
    for step in 0..steps {
        if !cancel() {
            return Err(invalid("Fit cancelled; no publication attempted."));
        }
        for (_, values) in grads.named_mut() {
            values.fill(0.0);
        }
        let offset = (step % window) * 64;
        let rows = &train[offset..offset + 64];
        let mut total = 0.0;
        for begin in (0..64).step_by(microbatch_rows) {
            let selected = &rows[begin..begin + microbatch_rows];
            let loss = microbatch_with(&params, selected, 64.0, input.full, &mut grads)?;
            forward += 1;
            backward += 1;
            for slot in &mut block_forward {
                *slot += 1;
            }
            if input.full {
                for slot in &mut block_backward {
                    *slot += 1;
                }
            }
            if !loss.is_finite() {
                return Err(invalid("Nonfinite training loss."));
            }
            train_rows += selected.len() as u64;
            total += loss;
        }
        let mut gradient_refs: Vec<&mut Vec<f64>> = Vec::new();
        let mut encoder_nonzero = 0usize;
        for (name, values) in grads.named_mut() {
            if !trainable(&name) {
                continue;
            }
            if values.iter().any(|v| !v.is_finite()) {
                return Err(invalid("Missing/nonfinite trainable gradient."));
            }
            if !name.starts_with("heads.") {
                encoder_nonzero += values.iter().filter(|v| **v != 0.0).count();
            }
            gradient_refs.push(values);
        }
        let norm = clip_grad_norm(&mut gradient_refs, clip_norm)?;
        let views: Vec<&[f64]> = gradient_refs.iter().map(|values| values.as_slice()).collect();
        let mut parameter_refs: Vec<&mut Vec<f64>> =
            params.named_mut().into_iter().filter(|(name, _)| trainable(name)).map(|(_, values)| values).collect();
        optimizer.step(&mut parameter_refs, &views, &rates)?;
        // The product's parameters are float32 tensors.
        for values in &mut parameter_refs {
            for value in values.iter_mut() {
                *value = f64::from(*value as f32);
            }
        }
        optimizer_steps += 1;
        if params.named_mut().iter().any(|(_, values)| values.iter().any(|v| !v.is_finite())) {
            return Err(invalid("Nonfinite candidate parameter."));
        }
        losses.push(total);
        trace.push(json!({"step": step + 1, "encoder_nonzero_gradients": encoder_nonzero, "norm_before_clip": norm}));
    }
    // The candidate checkpoint (float32) and its inventory.
    let mut candidate = BTreeMap::new();
    let named = params.named_mut();
    let mut parameter_count = 0usize;
    for (name, values) in named {
        let data: Vec<f32> = values.iter().map(|v| *v as f32).collect();
        parameter_count += data.len();
        let shape = base.get(&name).ok_or_else(|| invalid("Checkpoint includes unsupported or missing model keys."))?.shape.clone();
        candidate.insert(name, Tensor { shape, sha256: sha256_hex(&tensor_bytes(&data)), data });
    }
    let trainable_count: usize = if input.full {
        parameter_count
    } else {
        candidate.iter().filter(|(n, _)| n.starts_with("heads.")).map(|(_, t)| t.data.len()).sum()
    };
    let candidate_model = model.with_tensors(candidate.clone())?;
    let candidate_guard = assess(&candidate_model, &input.guard)?;
    let (changed, changes) = tensor_changes(base, &candidate, layers);
    let harms = contract::harm_count(&base_guard["rows"], &candidate_guard["rows"]);
    counts.insert("optimizer_steps".into(), optimizer_steps.into());
    counts.insert("train_rows".into(), train_rows.into());
    counts.insert("microbatch_forward".into(), forward.into());
    counts.insert("microbatch_backward".into(), backward.into());
    counts.insert("encoder_block_forward".into(), block_forward.iter().sum::<u64>().into());
    counts.insert("encoder_block_backward".into(), block_backward.iter().sum::<u64>().into());
    let tier = input.model_id.strip_prefix("privoke-v3-").unwrap_or_default();
    let evidence = json!({
        "schema": 1, "model_id": input.model_id, "tier": tier, "request_id": input.request_id, "base": input.base,
        "scope": if input.full { "full_encoder" } else { "heads" }, "layers": [4], "source_commitment": input.source_commitment,
        "policy": policy, "train_wire_sha256": input.train_wire_sha256, "guard_wire_sha256": input.guard_wire_sha256,
        "phases": {
            "training": {"layer": 4, "status": "ok", "examples": train_rows},
            "base_heldout": {"layer": 4, "status": "ok", "examples": input.guard.len()},
            "candidate_heldout": {"layer": 4, "status": "ok", "examples": input.guard.len()}
        },
        "base_guard": base_guard, "candidate_guard": candidate_guard, "action_harms": harms, "changes": changes,
        "changed_tensors": changed, "counts": counts, "block_counts": {"forward": block_forward, "backward": block_backward},
        "losses": losses, "gradient_trace": trace, "parameter_count": parameter_count, "trainable_count": trainable_count,
        "device": "cpu", "torch": "privoke-training-rust", "seconds": started.elapsed().as_secs_f64(), "cuda_peak_bytes": 0
    });
    Ok(Fit { evidence, candidate })
}

/// `validate_execution`: the evidence must reconcile the actual work, every block and the guard arithmetic
/// ([`privoke_contracts::v3::validate_execution`]).
pub fn validate_execution(evidence: &Value, finalized: bool) -> Result<(), TrainingError> {
    contract::validate_execution(evidence, finalized).map_err(|error| TrainingError::invalid(error.0))
}

/// `publication_passes`: the candidate improves the joint count and harms no action.
pub fn publication_passes(evidence: &Value) -> Result<bool, TrainingError> {
    contract::publication_passes(evidence).map_err(|error| TrainingError::invalid(error.0))
}
