//! The gradient RPC computation of `training._compute_training_gradients` (`ComputeSemanticGradients` for the head
//! scope, `ComputeUnderlyingModelGradients` for the full-encoder scope).
//!
//! Ported: request validation, canonical text normalisation, class balancing, the objectives of
//! [`crate::objective`], the transported update `float32(clamp(delta * learning_rate, +-cap))` with the inward float32
//! cap on full-capable artifacts, the candidate (`updated_parameter_values`), the held-out guard metrics (exact match,
//! sensitive recall, clean specificity and the safety-regression rate that decides accept or reject), the response
//! metrics, and the three routes of [`crate::routes`] (local SGD, backtracking and TRAIN diagnostics) with their
//! metadata strings. The artifact and admission checks that choose the route are [`crate::admission::admit`]. Not
//! ported: the FULL Adam fit (the fit itself is [`crate::adam`]), the window and retention training loops, and
//! `reject_overlength`.

use std::collections::{BTreeMap, BTreeSet};

use privoke_contracts::pyfloat;
use privoke_rules::preprocessing::normalize_text;
use privoke_rules::pyunicode;
use privoke_semantic::{TinyModel, TinyPrediction};
use serde_json::Value;

use crate::admission::{
    BACKTRACKING_KEY, BACKTRACKING_POLICY, BACKTRACKING_PREPARATION_KEY, DIAGNOSTICS_POLICY_KEY, LEGACY_OBJECTIVE, TRAIN_DIAGNOSTICS_POLICY,
};
use crate::error::TrainingError;
use crate::net::{Params, Tensor, TinyNet};
use crate::objective::{Example, Objective, class_balanced, fsum, supervised_deltas};
use crate::routes::{self, BACKTRACKING_REJECTION, Plan};

/// The served snapshot of a Tiny model, as the training endpoint sees it.
#[derive(Debug, Clone, Default)]
pub struct Snapshot {
    /// Artifact JSON object (`architecture`, `config`, `parameters`, `model_id`, `version`).
    pub artifact: Value,
    /// Whether the artifact declares the full-encoder strategy (`contextual_full_encoder_sgd_v1`).
    pub full_capable: bool,
    /// The artifact's `contextual_training_objective`, if any.
    pub objective: Option<String>,
    /// The artifact's explicit local-SGD optimizer (`local_sgd_1_v1`, `local_sgd_4_v1`), if any.
    pub optimizer: Option<String>,
    /// The artifact declares the TRAIN diagnostics policy.
    pub diagnostics: bool,
    /// The SHA-256 of the artifact's backtracking preparation record when it declares the policy (used on the
    /// full-encoder scope only).
    pub backtracking: Option<String>,
}

/// One gradient request.
#[derive(Debug, Clone)]
pub struct Request {
    /// Training rows (texts are normalised here).
    pub examples: Vec<Example>,
    /// Held-out rows for the guard (may be empty).
    pub heldout: Vec<Example>,
    /// Learning rate.
    pub learning_rate: f64,
    /// Bound of one transported coordinate.
    pub max_gradient: f64,
    /// `true` for `ComputeUnderlyingModelGradients` (all tensors), `false` for the head scope.
    pub full_encoder: bool,
}

/// The response of one computation.
#[derive(Debug, Clone)]
pub struct Batch {
    /// Transported (float32) update per trained tensor.
    pub gradients: BTreeMap<String, Vec<f32>>,
    /// Response metrics.
    pub metrics: BTreeMap<String, f64>,
    /// `(phase, rows)` of the executed work.
    pub executions: Vec<(String, usize)>,
    /// `training_scope`.
    pub scope: &'static str,
    /// The candidate parameters after the transported update (the base itself after a backtracking rejection).
    pub candidate: BTreeMap<String, Vec<f32>>,
    /// The response `error`: `TRAIN_BACKTRACKING_NO_IMPROVEMENT_V1` after a backtracking rejection, else empty.
    pub error: String,
    /// The tensors the update was computed over (`trained_parameter_names`); a rejection transports none of them.
    pub inventory: Vec<String>,
    /// The metadata this route adds: `contextual_optimizer_trace`, the backtracking policy, preparation, trace, trials and
    /// `effective_learning_rate`, the diagnostics policy and record.
    pub metadata: BTreeMap<String, String>,
}

fn invalid(message: &str) -> TrainingError {
    TrainingError::invalid(message)
}

/// `training_text_key` (`\d` is Unicode `Nd`, whitespace is Python's `str.isspace`): NFKC, lower case, `[at]` and `(at)` as `@`, digit-adjacent blanks removed, whitespace collapsed.
pub fn training_text_key(text: &str) -> String {
    let lowered = pyunicode::lower(&pyunicode::nfkc(text)).replace("[at]", "@").replace("(at)", "@");
    let chars: Vec<char> = lowered.chars().collect();
    let mut joined = String::new();
    let mut index = 0;
    while index < chars.len() {
        if chars[index] == ' ' || chars[index] == '\t' {
            let start = index;
            while index < chars.len() && (chars[index] == ' ' || chars[index] == '\t') {
                index += 1;
            }
            let digit_before = start > 0 && pyunicode::is_decimal(chars[start - 1]);
            let digit_after = index < chars.len() && pyunicode::is_decimal(chars[index]);
            if !(digit_before && digit_after) {
                joined.extend(&chars[start..index]);
            }
        } else {
            joined.push(chars[index]);
            index += 1;
        }
    }
    // `str.split()`: runs of Python whitespace (`str.isspace`) separate the words.
    joined.split(pyunicode::is_space).filter(|word| !word.is_empty()).collect::<Vec<_>>().join(" ")
}

fn sensitivity_value(name: &str) -> i64 {
    match name {
        "S1" => 1,
        "S2" => 2,
        "S3" => 3,
        _ => 0,
    }
}

fn visibility_rank(name: &str) -> i64 {
    match name {
        "P0" => 4,
        "P1" => 8,
        "P2" => 12,
        "P3" => 16,
        "P4" => 20,
        _ => 0,
    }
}

/// A classification: sensitivity, visibility and category names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Class {
    pub(crate) sensitivity: String,
    pub(crate) visibility: String,
    pub(crate) categories: BTreeSet<String>,
}

impl Class {
    pub(crate) fn of_target(target: &crate::objective::Target) -> Self {
        Self {
            sensitivity: target.sensitivity.clone(),
            visibility: target.visibility.clone(),
            categories: target.categories.iter().cloned().collect(),
        }
    }

    pub(crate) fn of_prediction(prediction: &TinyPrediction) -> Self {
        let d = &prediction.decision;
        Self { sensitivity: d.sensitivity.clone(), visibility: d.visibility.clone(), categories: d.categories.iter().cloned().collect() }
    }

    pub(crate) fn is_sensitive(&self) -> bool {
        self.sensitivity != "S0" || !self.categories.is_empty()
    }
}

/// `action_for_classification_result`: 0 allow, 1 warn, 2 block.
fn action(class: &Class, confidence: Option<f64>) -> i64 {
    let identifier = |c: &BTreeSet<String>| c.iter().filter(|n| *n == "IDENTITY" || *n == "LOCATION").count();
    if confidence.is_some_and(|c| c < 0.5) {
        return match class.sensitivity.as_str() {
            "S3" => 1,
            "S2" if identifier(&class.categories) > 0 => 1,
            _ => 0,
        };
    }
    if class.sensitivity == "S0" && class.categories.is_empty() {
        return 0;
    }
    match class.sensitivity.as_str() {
        "S3" => 2,
        "S2" => 1,
        _ => {
            let found = identifier(&class.categories);
            let restricted = class.visibility != "PU" && visibility_rank(&class.visibility) >= visibility_rank("P2");
            i64::from(found > 0 && (found > 1 || restricted))
        }
    }
}

fn classification_loss(target: &Class, predicted: &Class) -> f64 {
    let sensitivity = (sensitivity_value(&target.sensitivity) - sensitivity_value(&predicted.sensitivity)).abs() as f64 / 3.0;
    let visibility = (visibility_rank(&target.visibility) - visibility_rank(&predicted.visibility)).abs() as f64 / 20.0;
    let category = target.categories.symmetric_difference(&predicted.categories).count() as f64 / 10.0;
    sensitivity + 0.5 * visibility + 0.25 * category
}

pub(crate) fn artifact_with(artifact: &Value, params: &Params) -> Value {
    let mut value = artifact.clone();
    if let Some(Value::Object(entries)) = value.get_mut("parameters") {
        for (name, tensor) in params {
            if let Some(slot) = entries.get_mut(name).and_then(|t| t.get_mut("values")) {
                *slot = Value::Array(tensor.data.iter().map(|v| Value::from(*v)).collect());
            }
        }
    }
    value
}

pub(crate) fn params_from_f32(base: &Params, values: &BTreeMap<String, Vec<f32>>) -> Params {
    base.iter()
        .map(|(name, tensor)| {
            let data = values.get(name).map_or_else(|| tensor.data.clone(), |v| v.iter().map(|x| f64::from(*x)).collect());
            (name.clone(), Tensor { shape: tensor.shape.clone(), data })
        })
        .collect()
}

pub(crate) fn predictions(snapshot: &Snapshot, params: &Params, examples: &[Example]) -> Result<Vec<TinyPrediction>, TrainingError> {
    let model = TinyModel::from_artifact(&artifact_with(&snapshot.artifact, params))?;
    Ok(examples.iter().map(|e| model.predict(&e.text)).collect())
}

/// `_heldout_metrics`, with the safety-regression rate when a reference is given.
pub(crate) fn heldout_metrics(
    snapshot: &Snapshot,
    params: &Params,
    examples: &[Example],
    reference: Option<&Params>,
) -> Result<BTreeMap<String, f64>, TrainingError> {
    let mut metrics = BTreeMap::new();
    if examples.is_empty() {
        return Ok(metrics);
    }
    let predicted = predictions(snapshot, params, examples)?;
    let (mut exact, mut sensitive, mut sensitive_correct, mut clean, mut clean_correct) = (0usize, 0usize, 0usize, 0usize, 0usize);
    for (example, prediction) in examples.iter().zip(&predicted) {
        let target = Class::of_target(&example.target);
        let class = Class::of_prediction(prediction);
        exact += usize::from(target == class);
        if target.is_sensitive() {
            sensitive += 1;
            sensitive_correct += usize::from(class.is_sensitive());
        } else {
            clean += 1;
            clean_correct += usize::from(!class.is_sensitive());
        }
    }
    let total = sensitive + clean;
    let ratio = |n: usize, d: usize, empty: f64| if d == 0 { empty } else { n as f64 / d as f64 };
    metrics.insert("heldout_examples".into(), total as f64);
    metrics.insert("heldout_sensitive_examples".into(), sensitive as f64);
    metrics.insert("heldout_clean_examples".into(), clean as f64);
    metrics.insert("heldout_exact_match_rate".into(), ratio(exact, total, 0.0));
    metrics.insert("heldout_sensitive_recall".into(), ratio(sensitive_correct, sensitive, 1.0));
    metrics.insert("heldout_clean_specificity".into(), ratio(clean_correct, clean, 1.0));
    if let Some(reference) = reference {
        let before = predictions(snapshot, reference, examples)?;
        let mut regressions = 0usize;
        for ((example, base), after) in examples.iter().zip(&before).zip(&predicted) {
            let target = Class::of_target(&example.target);
            let (baseline, candidate) = (Class::of_prediction(base), Class::of_prediction(after));
            let (target_action, base_action) = (action(&target, None), action(&baseline, Some(base.decision.confidence)));
            let candidate_action = action(&candidate, Some(after.decision.confidence));
            let severity = |c: &Class| sensitivity_value(&c.sensitivity).min(sensitivity_value(&target.sensitivity));
            regressions += usize::from(
                severity(&candidate) < severity(&baseline) || candidate_action.min(target_action) < base_action.min(target_action),
            );
        }
        metrics.insert("heldout_safety_regression_rate".into(), ratio(regressions, examples.len(), 0.0));
    }
    Ok(metrics)
}

/// The largest float32 magnitude no greater than the configured real bound.
pub fn inward_float32_bound(bound: f64) -> f64 {
    let rounded = bound.min(f64::from(f32::MAX)) as f32;
    let rounded = if f64::from(rounded) > bound { f32::from_bits(rounded.to_bits() - 1) } else { rounded };
    f64::from(rounded)
}

pub(crate) fn round8(x: f64) -> f64 {
    format!("{x:.8}").parse().unwrap_or(x)
}

fn normalised(examples: &[Example]) -> Result<Vec<Example>, TrainingError> {
    examples
        .iter()
        .map(|e| {
            let text = normalize_text(&e.text).map_err(|error| TrainingError::invalid(format!("{error:?}")))?;
            Ok(Example { text, ..e.clone() })
        })
        .collect()
}

/// One bounded update with held-out guard metrics.
pub fn compute_gradients(snapshot: &Snapshot, request: &Request) -> Result<Batch, TrainingError> {
    if request.examples.is_empty() {
        return Err(invalid("At least one training example is required."));
    }
    if !request.learning_rate.is_finite() || request.learning_rate <= 0.0 {
        return Err(invalid("learning_rate must be finite and greater than zero."));
    }
    if !request.max_gradient.is_finite() || request.max_gradient <= 0.0 {
        return Err(invalid("max_gradient must be finite and greater than zero."));
    }
    if request.examples.iter().any(|e| !e.weight.is_finite() || e.weight <= 0.0) {
        return Err(invalid("Training example weights must be finite and positive."));
    }
    if request.full_encoder && !snapshot.full_capable {
        return Err(invalid("Underlying training requires the full Tiny encoder artifact strategy."));
    }
    let raw = normalised(&request.examples)?;
    let heldout = normalised(&request.heldout)?;
    if !heldout.is_empty() {
        let training_keys: BTreeSet<String> = raw.iter().map(|e| training_text_key(&e.text)).collect();
        let keys: Vec<String> = heldout.iter().map(|e| training_text_key(&e.text)).collect();
        if keys.iter().any(String::is_empty) || keys.iter().collect::<BTreeSet<_>>().len() != keys.len() {
            return Err(invalid("Held-out examples must contain distinct non-empty texts."));
        }
        if keys.iter().any(|k| training_keys.contains(k)) {
            return Err(invalid("Held-out examples must be separate from training texts."));
        }
        if heldout.iter().any(|e| !e.weight.is_finite() || e.weight <= 0.0) {
            return Err(invalid("Held-out example weights must be finite and positive."));
        }
        let sensitive: BTreeSet<bool> = heldout.iter().map(|e| e.target.is_sensitive()).collect();
        if sensitive.len() != 2 {
            return Err(invalid("Held-out evaluation needs both clean and sensitive labels."));
        }
    }
    let name = snapshot.objective.as_deref();
    let objective = Objective::from_name(name)?;
    if snapshot.diagnostics {
        if snapshot.optimizer.is_some() || objective.mean_category() {
            return Err(invalid("TRAIN process diagnostics require one legacy update with summed category BCE."));
        }
        if raw.iter().all(|e| e.target.is_sensitive()) || raw.iter().all(|e| !e.target.is_sensitive()) {
            return Err(invalid("TRAIN diagnostics require both clean and sensitive targets."));
        }
    }
    let balanced = !matches!(name, None | Some("legacy_sum_category"));
    let net = TinyNet::from_artifact(&snapshot.artifact)?;
    let mean = objective.mean_category();
    let mut audit = BTreeMap::new();
    let examples = if balanced {
        let adjusted = class_balanced(&raw)?;
        let sum = |rows: &[Example], label: bool| fsum(rows.iter().filter(|e| e.target.is_sensitive() == label).map(|e| e.weight));
        let (raw_clean, raw_sensitive) = (sum(&raw, false), sum(&raw, true));
        let (clean, sensitive) = (sum(&adjusted, false), sum(&adjusted, true));
        let total = fsum([raw_clean, raw_sensitive]);
        audit.insert("training_clean_examples".to_string(), raw.iter().filter(|e| !e.target.is_sensitive()).count() as f64);
        audit.insert("training_sensitive_examples".to_string(), raw.iter().filter(|e| e.target.is_sensitive()).count() as f64);
        audit.insert("raw_clean_weight".to_string(), raw_clean);
        audit.insert("raw_sensitive_weight".to_string(), raw_sensitive);
        audit.insert("raw_total_weight".to_string(), total);
        audit.insert("effective_clean_weight".to_string(), clean);
        audit.insert("effective_sensitive_weight".to_string(), sensitive);
        audit.insert("clean_objective_mass".to_string(), clean / total);
        audit.insert("sensitive_objective_mass".to_string(), sensitive / total);
        adjusted
    } else {
        raw
    };
    // Loss, exact match and weight totals of the served model on the training rows.
    let base_predictions = predictions(snapshot, &net.params, &examples)?;
    let mut total_weight = if mean { fsum(examples.iter().map(|e| e.weight)) } else { 0.0 };
    let (mut total_loss, mut exact) = (0.0, 0usize);
    for (example, prediction) in examples.iter().zip(&base_predictions) {
        let (target, predicted) = (Class::of_target(&example.target), Class::of_prediction(prediction));
        exact += usize::from(target == predicted);
        let accumulation = if mean { example.weight / total_weight } else { example.weight };
        total_loss += classification_loss(&target, &predicted) * accumulation;
        if !mean {
            total_weight += example.weight;
        }
    }
    if balanced && !mean {
        total_weight = fsum(examples.iter().map(|e| e.weight));
    }
    let result = supervised_deltas(&net, &examples, objective)?;
    let trainable: BTreeSet<String> =
        net.params.keys().filter(|n| request.full_encoder || n.starts_with("head.") || n.starts_with("readout.")).cloned().collect();
    let cap = if snapshot.full_capable { inward_float32_bound(request.max_gradient) } else { request.max_gradient };
    let direction: BTreeMap<String, Vec<f64>> =
        result.deltas.iter().filter(|(n, _)| trainable.contains(*n)).map(|(n, d)| (n.clone(), d.clone())).collect();
    let plan = Plan {
        examples: &examples,
        objective,
        objective_name: name.unwrap_or(LEGACY_OBJECTIVE),
        rate: request.learning_rate,
        bound: request.max_gradient,
    };
    let mut route_metadata: BTreeMap<String, String> = BTreeMap::new();
    let mut route_metrics: BTreeMap<String, f64> = BTreeMap::new();
    let mut effective_rate = request.learning_rate;
    let mut error = String::new();
    let preparation = snapshot.backtracking.as_ref().filter(|_| request.full_encoder);
    let gradients: BTreeMap<String, Vec<f32>> = if let Some(preparation) = preparation {
        let baseline = routes::local_training_losses(&net, &examples, objective)?;
        let found = routes::backtracking(&net, &plan, &direction, &baseline)?;
        route_metadata.insert(BACKTRACKING_KEY.to_string(), BACKTRACKING_POLICY.to_string());
        route_metadata.insert(BACKTRACKING_PREPARATION_KEY.to_string(), preparation.clone());
        route_metadata.insert("contextual_training_backtracking_trace".to_string(), found.trace.clone());
        route_metadata.insert("contextual_training_backtracking_trials".to_string(), found.trials.clone());
        match found.effective_rate {
            Some(rate) => {
                effective_rate = rate;
                let text = pyfloat::repr(rate).map_err(|_| invalid("Parameter must be finite."))?;
                route_metadata.insert("effective_learning_rate".to_string(), text);
            }
            None => error = BACKTRACKING_REJECTION.to_string(),
        }
        route_metrics.insert("gradient_fits".to_string(), 1.0);
        route_metrics.insert("backtracking_trials".to_string(), found.trial_count as f64);
        route_metrics.insert("backtracking_semantic_examples".to_string(), found.semantic_examples as f64);
        route_metrics.insert("backtracking_forward_attempts".to_string(), found.forward_attempts as f64);
        route_metrics.insert("backtracking_attempted_semantic_examples".to_string(), found.attempted_examples as f64);
        found.delta
    } else if let Some(optimizer) = snapshot.optimizer.as_deref() {
        let local = routes::local_sgd(&net, &plan, &trainable, optimizer, &direction)?;
        route_metadata.insert("contextual_optimizer_trace".to_string(), local.trace);
        local.accumulated
    } else {
        direction
            .iter()
            .map(|(n, d)| (n.clone(), d.iter().map(|v| (v * request.learning_rate).clamp(-cap, cap) as f32).collect()))
            .collect()
    };
    let rejected = !error.is_empty();
    let base_f32: BTreeMap<String, Vec<f32>> =
        net.params.iter().map(|(n, t)| (n.clone(), t.data.iter().map(|v| *v as f32).collect())).collect();
    let candidate: BTreeMap<String, Vec<f32>> = base_f32
        .iter()
        .map(|(n, values)| {
            let updated = match gradients.get(n) {
                Some(g) => values.iter().zip(g).map(|(b, d)| round8(f64::from(*b) + f64::from(*d)) as f32).collect(),
                None => values.clone(),
            };
            (n.clone(), updated)
        })
        .collect();
    if candidate.values().flatten().any(|v| !v.is_finite()) {
        return Err(invalid("Parameter must be finite."));
    }
    let outputs: BTreeSet<&String> = net.params.keys().filter(|n| n.starts_with("head.") || n.starts_with("readout.")).collect();
    if request.full_encoder && !rejected && !candidate.iter().any(|(n, v)| !outputs.contains(n) && *v != base_f32[n]) {
        return Err(invalid("Underlying training produced no transported encoder weight update."));
    }
    let candidate_params = params_from_f32(&net.params, &candidate);
    let mut metrics = BTreeMap::new();
    metrics.insert("examples".to_string(), examples.len() as f64);
    metrics.insert("average_loss".to_string(), if mean { total_loss } else { total_loss / total_weight });
    metrics.insert("exact_match_rate".to_string(), exact as f64 / examples.len() as f64);
    metrics.insert("total_weight".to_string(), total_weight);
    if !rejected {
        metrics.extend(heldout_metrics(snapshot, &net.params, &heldout, None)?);
        if !heldout.is_empty() {
            for (key, value) in heldout_metrics(snapshot, &candidate_params, &heldout, Some(&net.params))? {
                metrics.insert(format!("candidate_{key}"), value);
            }
        }
    }
    metrics.extend(audit);
    metrics.extend(route_metrics);
    if let Some(totals) = result.task_totals.filter(|_| mean || request.full_encoder) {
        for (key, value) in
            ["supervised_sensitivity_ce_loss", "supervised_visibility_ce_loss", "supervised_category_bce_loss"].into_iter().zip(totals)
        {
            metrics.insert(key.to_string(), value);
        }
    }
    if mean || request.full_encoder {
        metrics.insert("supervised_objective_loss".to_string(), result.loss);
    }
    if snapshot.diagnostics {
        route_metadata.insert(DIAGNOSTICS_POLICY_KEY.to_string(), TRAIN_DIAGNOSTICS_POLICY.to_string());
        if !rejected {
            let unclipped: Vec<f64> = direction.values().flatten().map(|v| v * effective_rate).collect();
            let record = routes::diagnostics(snapshot, &plan, &net, &candidate, &unclipped, &gradients, cap)?;
            route_metadata.insert("contextual_training_diagnostics".to_string(), record);
        }
    }
    let mut executions = vec![("training".to_string(), examples.len())];
    if !heldout.is_empty() && !rejected {
        executions.push(("base_heldout".to_string(), heldout.len()));
        executions.push(("candidate_heldout".to_string(), heldout.len()));
    }
    Ok(Batch {
        gradients,
        metrics,
        executions,
        scope: if request.full_encoder { "full_encoder" } else { "heads" },
        candidate,
        error,
        inventory: direction.keys().cloned().collect(),
        metadata: route_metadata,
    })
}
