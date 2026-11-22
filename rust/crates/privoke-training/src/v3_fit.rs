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
use privoke_rules::preprocessing::normalize_text;
use privoke_semantic::V3Model;
use privoke_semantic::labels::{CATEGORY, VISIBILITY};
use privoke_semantic::safetensors::Tensor;
use serde_json::{Map, Value, json};

use crate::adamw::{AdamW, clip_grad_norm};
use crate::error::TrainingError;
use crate::v3_model::{Example, V3Params, microbatch_with};
use crate::window::action_value;

fn invalid(message: &str) -> TrainingError {
    TrainingError::invalid(message)
}

/// The admitted tiers: `(name, hidden size, layers, attention heads, parameters)`.
pub const TIERS: [(&str, usize, usize, usize, usize); 3] =
    [("efficient", 128, 4, 2, 4_785_044), ("balanced", 256, 2, 4, 9_596_180), ("quality", 256, 12, 4, 17_493_780)];

/// The frozen policy of `validate_policy`: the pilot variant has two steps over one block, otherwise `steps` is 64, 256 or 512.
pub fn frozen_policy(steps: i64, pilot: bool) -> Value {
    let (window_batches, epochs) = if pilot { (1, 2) } else { (8, steps / 8) };
    json!({
        "schema": 1, "optimizer": "adamw", "head_lr": 0.001, "encoder_lr": 0.00002, "betas": [0.9, 0.999], "eps": 1e-8,
        "weight_decay": 0.0, "clip_norm": 1.0, "microbatch": 4, "steps": steps, "window_batches": window_batches, "batch_rows": 64,
        "epochs": epochs, "guard_rows": 16, "dropout": false, "max_tokens": 512, "category_threshold": 0.5,
        "objective": "sensitivity_ce+visibility_ce+category_mean_bce", "checkpoint_selection": "final_only",
        "publication": "joint_improve_action_harm_zero_v1"
    })
}

/// `validate_policy`.
pub fn validate_policy(policy: &Value, pilot: bool) -> Result<(), TrainingError> {
    let steps = if pilot {
        2
    } else {
        match policy["steps"].as_i64() {
            Some(steps @ (64 | 256 | 512)) => steps,
            _ => return Err(invalid("Predeclared v3 work budget must be 64, 256 or 512 steps.")),
        }
    };
    if *policy != frozen_policy(steps, pilot) {
        return Err(invalid("Policy differs from the frozen v3 contract."));
    }
    Ok(())
}

const ACTIONS: [&str; 3] = ["ALLOW", "WARN", "BLOCK"];

/// Whether `packed` is a classification the contract can name (`Classification(packed).pack() == packed`, `to_dict()`).
fn valid_packed(packed: u64) -> bool {
    let Ok(packed) = u16::try_from(packed) else { return false };
    packed & 0x8000 == 0 && VISIBILITY.iter().any(|(_, value)| packed & 0b11100 == *value)
}

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
    if !valid_packed(u64::from(packed)) {
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

/// `tensor_changes`: the changed tensor names and the counts per group.
fn tensor_changes(before: &BTreeMap<String, Tensor>, after: &BTreeMap<String, Tensor>, layers: usize) -> (Vec<String>, Value) {
    let changed: Vec<String> =
        before.iter().filter(|(name, tensor)| after[*name].sha256 != tensor.sha256).map(|(name, _)| name.clone()).collect();
    let under = |prefix: &str| changed.iter().filter(|name| name.starts_with(prefix)).count();
    let blocks: Vec<usize> = (0..layers).map(|index| under(&format!("encoder.encoder.layer.{index}."))).collect();
    let counts = json!({
        "heads": under("heads."), "encoder": under("encoder."), "embeddings": under("encoder.embeddings."),
        "first_block": under("encoder.encoder.layer.0."), "last_block": under(&format!("encoder.encoder.layer.{}.", layers - 1)),
        "pooler": under("encoder.pooler."), "blocks": blocks
    });
    (changed, counts)
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
    let harms = harm_count(&base_guard["rows"], &candidate_guard["rows"]);
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

/// Rows where a candidate action is farther from the target than the base's, in either direction.
fn harm_count(base: &Value, candidate: &Value) -> usize {
    let value = |row: &Value, key: &str| row[key].as_i64().unwrap_or(0);
    base.as_array()
        .into_iter()
        .flatten()
        .zip(candidate.as_array().into_iter().flatten())
        .filter(|(a, b)| {
            let (a, b) = (*a, *b);
            [-1i64, 1].iter().any(|direction| {
                (direction * (value(b, "action_value") - value(b, "target_action_value"))).max(0)
                    > (direction * (value(a, "action_value") - value(a, "target_action_value"))).max(0)
            })
        })
        .count()
}

fn validate_guard(value: &Value, denominator: usize) -> Result<Vec<Value>, TrainingError> {
    let rows = value["rows"].as_array().cloned().unwrap_or_default();
    if value["examples"].as_u64() != Some(denominator as u64) || rows.len() != denominator {
        return Err(invalid("Guard row denominator differs from policy."));
    }
    for row in &rows {
        for key in ["target", "prediction"] {
            if !row[key].as_u64().is_some_and(valid_packed) {
                return Err(invalid("Invalid packed guard classification."));
            }
        }
        for key in ["action", "target_action"] {
            let name = row[key].as_str().unwrap_or_default();
            let position = ACTIONS.iter().position(|candidate| *candidate == name);
            if position.map(|p| p as i64) != row[format!("{key}_value")].as_i64() {
                return Err(invalid("Guard action name/value mismatch."));
            }
        }
        let confidence = row["confidence"]
            .as_f64()
            .filter(|c| c.is_finite() && (0.0..=1.0).contains(c))
            .ok_or_else(|| invalid("Actual guard confidence required."))?;
        for (packed, score, action) in [("prediction", confidence, "action"), ("target", 0.999, "target_action")] {
            let packed = u16::try_from(row[packed].as_u64().unwrap_or(0)).unwrap_or(0);
            if ACTIONS[usize::try_from(action_value(packed, Some(score))).unwrap_or(0)] != row[action].as_str().unwrap_or_default() {
                return Err(invalid("Guard action differs from production classification policy."));
            }
        }
        let joint = row["target"] == row["prediction"] && row["action"] == row["target_action"];
        if row["joint_correct"].as_bool() != Some(joint) {
            return Err(invalid("Guard joint correctness differs from rows."));
        }
    }
    let joint = rows.iter().filter(|row| row["joint_correct"] == true).count() as u64;
    if value["joint_correct"].as_u64() != Some(joint) {
        return Err(invalid("Guard joint count differs from rows."));
    }
    if value["action_correct"].as_u64() != Some(rows.iter().filter(|row| row["action"] == row["target_action"]).count() as u64) {
        return Err(invalid("Guard action count differs from rows."));
    }
    Ok(rows)
}

fn is_sha(value: &Value) -> bool {
    value.as_str().is_some_and(|text| text.len() == 64 && text.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
}

/// `validate_execution`: the evidence must reconcile the actual work, every block and the guard arithmetic.
pub fn validate_execution(evidence: &Value, finalized: bool) -> Result<(), TrainingError> {
    let scope = evidence["scope"].as_str().unwrap_or_default();
    if evidence["schema"] != 1 || evidence["layers"] != json!([4]) || !matches!(scope, "heads" | "full_encoder") {
        return Err(invalid("Actual explicit semantic-only training evidence required."));
    }
    let policy = &evidence["policy"];
    validate_policy(policy, policy["steps"] == 2)?;
    for key in ["base", "source_commitment", "train_wire_sha256", "guard_wire_sha256"] {
        if !is_sha(&evidence[key]) {
            return Err(invalid("Expected a lowercase SHA-256 identity."));
        }
    }
    if evidence["request_id"].as_str().is_none_or(str::is_empty) {
        return Err(invalid("Execution request identity required."));
    }
    let tier_name = evidence["tier"].as_str().unwrap_or_default();
    let Some((_, hidden, layers, _, parameters)) = TIERS.iter().find(|tier| tier.0 == tier_name) else {
        return Err(invalid("Execution model/tier identity required."));
    };
    if evidence["model_id"] != format!("privoke-v3-{tier_name}") {
        return Err(invalid("Execution model/tier identity required."));
    }
    if evidence["parameter_count"].as_u64() != Some(*parameters as u64) {
        return Err(invalid("Execution complete parameter count mismatch."));
    }
    let full = scope == "full_encoder";
    // The head width is 20 = 4 + 6 + 10 labels; the parameters are `20 * (hidden + 1)`.
    let expected_trainable = if full { *parameters } else { 20 * (hidden + 1) };
    if evidence["trainable_count"].as_u64() != Some(expected_trainable as u64) {
        return Err(invalid("Execution trainable parameter count mismatch."));
    }
    let (steps, rows, micro, guard_rows) = (
        policy["steps"].as_u64().unwrap_or(0),
        policy["batch_rows"].as_u64().unwrap_or(0),
        policy["microbatch"].as_u64().unwrap_or(1),
        policy["guard_rows"].as_u64().unwrap_or(0),
    );
    let microbatches = steps * rows / micro;
    let layer_count = *layers;
    let layers = layer_count as u64;
    let expected = json!({
        "optimizer_steps": steps, "train_rows": steps * rows, "microbatch_forward": microbatches, "microbatch_backward": microbatches,
        "encoder_block_forward": microbatches * layers, "encoder_block_backward": if full { microbatches * layers } else { 0 }
    });
    if evidence["counts"] != expected {
        return Err(invalid("Actual work counters differ from frozen policy."));
    }
    let blocks = json!({
        "forward": vec![microbatches; layer_count], "backward": vec![if full { microbatches } else { 0 }; layer_count]
    });
    if evidence["block_counts"] != blocks {
        return Err(invalid("Every encoder block must attest actual forward/backward work."));
    }
    let phases = &evidence["phases"];
    let expected_phases = [("training", steps * rows), ("base_heldout", guard_rows), ("candidate_heldout", guard_rows)];
    if phases.as_object().map(Map::len) != Some(3)
        || expected_phases.iter().any(|(name, n)| phases[*name] != json!({"layer": 4, "status": "ok", "examples": n}))
    {
        return Err(invalid("Successful exact-denominator semantic phases required."));
    }
    let changes = &evidence["changes"];
    let block_changes: Vec<u64> = changes["blocks"].as_array().map(|b| b.iter().filter_map(Value::as_u64).collect()).unwrap_or_default();
    if changes["heads"].as_u64().unwrap_or(0) == 0 || block_changes.len() as u64 != layers {
        return Err(invalid("Observed head and complete block changes required."));
    }
    if !full && (changes["encoder"] != 0 || block_changes.iter().any(|n| *n != 0)) {
        return Err(invalid("HEADS changed pretrained encoder."));
    }
    if full
        && (["encoder", "embeddings", "first_block", "last_block", "pooler"].iter().any(|key| changes[*key].as_u64().unwrap_or(0) == 0)
            || block_changes.contains(&0))
    {
        return Err(invalid("FULL requires changes in embeddings, every encoder block, and pooler."));
    }
    let losses = evidence["losses"].as_array().cloned().unwrap_or_default();
    if losses.len() as u64 != steps || losses.iter().any(|v| !v.as_f64().is_some_and(f64::is_finite)) {
        return Err(invalid("Finite per-step loss trace required."));
    }
    let trace = evidence["gradient_trace"].as_array().cloned().unwrap_or_default();
    if trace.len() as u64 != steps
        || trace
            .iter()
            .enumerate()
            .any(|(i, row)| row["step"].as_u64() != Some(i as u64 + 1) || !row["norm_before_clip"].as_f64().is_some_and(f64::is_finite))
    {
        return Err(invalid("Complete finite per-step gradient trace required."));
    }
    if full && !trace.iter().skip(1).any(|row| row["encoder_nonzero_gradients"].as_u64().unwrap_or(0) > 0) {
        return Err(invalid("FULL requires observed encoder gradients after the zero-head step."));
    }
    let before = validate_guard(&evidence["base_guard"], guard_rows as usize)?;
    let after = validate_guard(&evidence["candidate_guard"], guard_rows as usize)?;
    if before.iter().zip(&after).any(|(a, b)| a["target"] != b["target"] || a["target_action"] != b["target_action"]) {
        return Err(invalid("Base/candidate guard targets differ."));
    }
    if evidence["action_harms"].as_u64() != Some(harm_count(&json!(before), &json!(after)) as u64) {
        return Err(invalid("Action harm count differs from guard rows."));
    }
    if finalized {
        if !is_sha(&evidence["candidate_blob"]) {
            return Err(invalid("Expected a lowercase SHA-256 identity."));
        }
        if evidence["serialized_guard_parity"] != true {
            return Err(invalid("Serialized guard parity required."));
        }
    }
    Ok(())
}

/// `publication_passes`: the candidate improves the joint count and harms no action.
pub fn publication_passes(evidence: &Value) -> Result<bool, TrainingError> {
    validate_execution(evidence, true)?;
    Ok(evidence["candidate_guard"]["joint_correct"].as_u64() > evidence["base_guard"]["joint_correct"].as_u64()
        && evidence["action_harms"] == 0)
}
