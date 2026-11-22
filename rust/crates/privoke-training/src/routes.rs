//! The local-SGD, backtracking and TRAIN-diagnostics routes of `training._compute_training_gradients`.
//!
//! * `_local_sgd_updates`: one or four projected steps from one immutable base; every next direction is recomputed at
//!   the transported state `float32(round(float32(base) + float32(delta), 8))`, and the bounded trace records each
//!   state's true task losses and fingerprints.
//! * `_backtracking_trials`: one original direction scaled by 1, 1/4, 1/16, 1/64 and 1/256 of the requested rate; the
//!   first scale whose transported candidate lowers the TRAIN objective by more than `2e-5` and changes an encoder
//!   tensor is the update, and no such scale is the rejection `TRAIN_BACKTRACKING_NO_IMPROVEMENT_V1`.
//! * `_training_diagnostics`: the passive scoring of the base and candidate TRAIN states.
//!
//! The losses are the true weighted cross-entropy and binary cross-entropy of the logits, in float64 over the stage 14
//! reference forward pass (Python evaluates the float32 logits of torch). Trace strings carry the Python bytes for every
//! number that does not depend on rounding; the fingerprints and float values that do are tolerance quantities, like
//! the gradients they derive from.

use std::collections::{BTreeMap, BTreeSet};

use privoke_contracts::fingerprint::parameter_fingerprint;

use crate::adam::F32Map;
use crate::admission::BACKTRACKING_POLICY;
use crate::error::TrainingError;
use crate::net::{Params, TinyNet};
use crate::objective::{Example, Objective, Target, fsum, supervised_deltas};
use crate::rpc::{Class, Snapshot, inward_float32_bound, params_from_f32, predictions, round8};
use crate::trace::Json;

type Values = BTreeMap<String, Vec<f64>>;
type Shapes = BTreeMap<String, Vec<u64>>;

/// The error text of a backtracking run that found no improving scale.
pub const BACKTRACKING_REJECTION: &str = "TRAIN_BACKTRACKING_NO_IMPROVEMENT_V1";
/// The scales of the requested rate that backtracking tries, in order.
pub const BACKTRACKING_SCALES: [f64; 5] = [1.0, 0.25, 0.0625, 0.015625, 0.00390625];
/// The objective decrease that a backtracking trial must exceed.
pub const BACKTRACKING_DECREASE: f64 = 0.00002;
/// The byte budget of every trace and diagnostics record.
const TRACE_BYTES: usize = 2048;
const SUM_MARGIN: &str = "class_balanced_contextual_sum_category_decision_margin_v1";
const LOCAL_COLUMNS: &[&str] = &["sensitivity_ce", "visibility_ce", "category_bce", "objective"];
const LOCAL_MARGIN_COLUMNS: &[&str] = &["sensitivity_ce", "visibility_ce", "category_bce", "decision_margin_bce", "objective"];
const PROCESS_COLUMNS: &[&str] = &["sensitivity_ce", "visibility_ce", "category_sum_bce", "objective"];
const PROCESS_MARGIN_COLUMNS: &[&str] = &["sensitivity_ce", "visibility_ce", "category_sum_bce", "decision_margin_bce", "objective"];

fn invalid(message: &str) -> TrainingError {
    TrainingError::invalid(message)
}

fn values_of(params: &Params) -> Values {
    params.iter().map(|(name, tensor)| (name.clone(), tensor.data.clone())).collect()
}

fn shapes_of(params: &Params) -> Shapes {
    params
        .iter()
        .map(|(name, tensor)| (name.clone(), tensor.shape.iter().map(|size| u64::try_from(*size).unwrap_or(u64::MAX)).collect()))
        .collect()
}

fn widen(values: &F32Map) -> Values {
    values.iter().map(|(name, list)| (name.clone(), list.iter().map(|value| f64::from(*value)).collect())).collect()
}

fn fingerprint(values: &Values, shapes: Option<&Shapes>) -> Result<String, TrainingError> {
    Ok(parameter_fingerprint(values, shapes)?)
}

/// `_transport_local_parameters`: the float32 candidate `float32(round(float32(base) + float32(delta), 8))`.
fn transport(base: &Params, delta: &F32Map) -> F32Map {
    base.iter()
        .map(|(name, tensor)| {
            let values: Vec<f32> = match delta.get(name) {
                Some(update) => tensor
                    .data
                    .iter()
                    .zip(update)
                    .map(|(before, step)| round8(f64::from(*before as f32) + f64::from(*step)) as f32)
                    .collect(),
                None => tensor.data.iter().map(|value| *value as f32).collect(),
            };
            (name.clone(), values)
        })
        .collect()
}

fn is_output(name: &str) -> bool {
    name.starts_with("head.") || name.starts_with("readout.")
}

fn largest(values: impl IntoIterator<Item = f64>) -> f64 {
    values.into_iter().fold(0.0, |best, value| best.max(value.abs()))
}

fn label_index(labels: &[String], name: &str) -> Result<usize, TrainingError> {
    labels.iter().position(|label| label == name).ok_or_else(|| TrainingError::invalid(format!("Unknown classification label {name:?}.")))
}

/// `_mean_category_loss_components`: the true cross-entropy of the sensitivity and visibility heads and the mean binary
/// cross-entropy of the category head.
fn task_losses(net: &TinyNet, logits: &[Vec<f64>; 3], target: &Target) -> Result<[f64; 3], TrainingError> {
    let config = &net.config;
    let cross_entropy = |values: &[f64], index: usize| {
        let maximum = values.iter().copied().fold(f64::NEG_INFINITY, f64::max);
        maximum - values[index] + fsum(values.iter().map(|value| (value - maximum).exp())).ln()
    };
    let sensitivity = cross_entropy(&logits[0], label_index(&config.sensitivity_labels, &target.sensitivity)?);
    let visibility = cross_entropy(&logits[1], label_index(&config.visibility_labels, &target.visibility)?);
    let category = fsum(logits[2].iter().zip(&config.category_labels).map(|(value, label)| {
        let present = if target.categories.contains(label) { 1.0 } else { 0.0 };
        value.max(0.0) - present * value + (-value.abs()).exp().ln_1p()
    })) / config.category_labels.len() as f64;
    let components = [sensitivity, visibility, category];
    if components.iter().any(|value| !value.is_finite() || *value < 0.0) {
        return Err(invalid("Contextual supervised task losses must be finite and nonnegative."));
    }
    Ok(components)
}

/// The loss of `_decision_margin_loss_and_head_deltas`: the union margin (the largest of the non-S0 severity logits minus
/// the S0 logit and the category logits minus the threshold logit) under a target-conditional softplus.
fn decision_margin_loss(net: &TinyNet, logits: &[Vec<f64>; 3], target: &Target) -> Result<f64, TrainingError> {
    let config = &net.config;
    let s0 = label_index(&config.sensitivity_labels, "S0")?;
    let offset = config.category_threshold.ln() - (-config.category_threshold).ln_1p();
    let mut margins: Vec<f64> = Vec::new();
    for (index, label) in config.sensitivity_labels.iter().enumerate() {
        if label != "S0" {
            margins.push(logits[0][index] - logits[0][s0]);
        }
    }
    margins.extend(logits[2].iter().map(|value| value - offset));
    if margins.iter().any(|value| !value.is_finite()) {
        return Err(invalid("Decision-margin differences must remain finite."));
    }
    let margin = margins.iter().copied().fold(f64::NEG_INFINITY, f64::max);
    let signed = if target.is_sensitive() { -margin } else { margin };
    Ok(signed.max(0.0) + (-margin.abs()).exp().ln_1p())
}

/// The fixed inputs of a route: the (class-balanced) rows, the objective and the request's rate and bound.
#[derive(Debug, Clone, Copy)]
pub struct Plan<'a> {
    /// The training rows after normalisation and class balancing.
    pub examples: &'a [Example],
    /// The objective.
    pub objective: Objective,
    /// The artifact's objective name (`legacy_sum_category` when it names none).
    pub objective_name: &'a str,
    /// The requested learning rate.
    pub rate: f64,
    /// The requested bound of one transported coordinate.
    pub bound: f64,
}

/// `_local_training_losses`: the weighted task losses (sensitivity, visibility, category, the decision margin when the
/// objective has one) and their sum at this exact state.
pub fn local_training_losses(net: &TinyNet, examples: &[Example], objective: Objective) -> Result<Vec<f64>, TrainingError> {
    let total = fsum(examples.iter().map(|example| example.weight));
    if !total.is_finite() || total <= 0.0 {
        return Err(invalid("Local SGD total weight must remain finite and positive."));
    }
    let count = net.config.category_labels.len() as f64;
    let mut losses = [0.0f64; 4];
    for example in examples {
        let forward = net.forward(&net.token_ids(&example.text))?;
        let mut values = task_losses(net, &forward.logits, &example.target)?;
        if !objective.mean_category() {
            values[2] *= count;
        }
        let share = example.weight / total;
        for (slot, value) in values.iter().enumerate() {
            losses[slot] += value * share;
        }
        if objective.decision_margin() {
            losses[3] += decision_margin_loss(net, &forward.logits, &example.target)? * share;
        }
    }
    let mut result = vec![losses[0], losses[1], losses[2]];
    if objective.decision_margin() {
        result.push(losses[3]);
    }
    let total_loss = fsum(result.iter().copied());
    result.push(total_loss);
    if result.iter().any(|value| !value.is_finite() || *value < 0.0) {
        return Err(invalid("Local SGD task losses must remain finite and nonnegative."));
    }
    Ok(result)
}

/// The steps of a local-SGD optimizer name.
pub fn local_steps(optimizer: &str) -> Result<usize, TrainingError> {
    match optimizer {
        "local_sgd_1_v1" => Ok(1),
        "local_sgd_4_v1" => Ok(4),
        _ => Err(invalid("Unsupported contextual training optimizer.")),
    }
}

/// The result of a local-SGD run.
#[derive(Debug, Clone)]
pub struct LocalSgd {
    /// The accumulated transported update per trained tensor.
    pub accumulated: F32Map,
    /// `contextual_optimizer_trace`.
    pub trace: String,
}

fn checked(trace: String, message: &str) -> Result<String, TrainingError> {
    if trace.len() > TRACE_BYTES { Err(invalid(message)) } else { Ok(trace) }
}

/// `_local_sgd_updates`: projected local SGD relative to one immutable publication base. `initial` is the normalised
/// direction (the negative gradient divided by the global weight) of the base state.
pub fn local_sgd(
    net: &TinyNet,
    plan: &Plan<'_>,
    names: &BTreeSet<String>,
    optimizer: &str,
    initial: &Values,
) -> Result<LocalSgd, TrainingError> {
    let steps = local_steps(optimizer)?;
    let cap = inward_float32_bound(plan.bound);
    let shapes = shapes_of(&net.params);
    let mut accumulated: F32Map =
        names.iter().map(|name| (name.clone(), vec![0.0f32; net.params.get(name).map_or(0, |tensor| tensor.data.len())])).collect();
    let mut local = net.clone();
    let mut direction = initial.clone();
    let mut losses: Vec<Vec<f64>> = Vec::new();
    let mut updates: Vec<(f64, f64, usize, f64)> = Vec::new();
    let mut fingerprints = vec![fingerprint(&values_of(&net.params), Some(&shapes))?];
    for step in 0..steps {
        losses.push(local_training_losses(&local, plan.examples, plan.objective)?);
        if step > 0 {
            let fresh = supervised_deltas(&local, plan.examples, plan.objective)?;
            direction = fresh.deltas.into_iter().filter(|(name, _)| names.contains(name)).collect();
        }
        if direction.keys().ne(names.iter()) {
            return Err(invalid("Local SGD direction manifest is inconsistent."));
        }
        let (mut raw_max, mut clipped, mut squares) = (0.0f64, 0usize, Vec::new());
        let mut updated = F32Map::new();
        for name in names {
            let (Some(values), Some(prior)) = (direction.get(name), accumulated.get(name)) else {
                return Err(invalid("Local SGD direction manifest is inconsistent."));
            };
            if values.len() != prior.len() {
                return Err(invalid("Local SGD direction shape is inconsistent."));
            }
            let mut next = Vec::with_capacity(values.len());
            for (before, value) in prior.iter().zip(values) {
                let increment = value * plan.rate;
                let raw = if step == 0 { increment } else { f64::from(*before) + increment };
                if !(value.is_finite() && increment.is_finite() && raw.is_finite()) {
                    return Err(invalid("Local SGD gradients and accumulators must remain finite."));
                }
                squares.push(value * value);
                raw_max = raw_max.max(raw.abs());
                clipped += usize::from(raw.abs() > cap);
                let transported = raw.clamp(-cap, cap) as f32;
                if f64::from(transported).abs() > plan.bound {
                    return Err(invalid("Local SGD transport exceeds the configured delta bound."));
                }
                next.push(transported);
            }
            updated.insert(name.clone(), next);
        }
        let norm = fsum(squares.iter().copied()).sqrt();
        if !norm.is_finite() {
            return Err(invalid("Local SGD gradient norm must remain finite."));
        }
        accumulated = updated;
        updates.push((norm, raw_max, clipped, largest(accumulated.values().flatten().map(|value| f64::from(*value)))));
        let candidate = transport(&net.params, &accumulated);
        fingerprints.push(fingerprint(&widen(&candidate), Some(&shapes))?);
        local = net.with_params(params_from_f32(&net.params, &candidate))?;
    }
    losses.push(local_training_losses(&local, plan.examples, plan.objective)?);
    let margin = plan.objective == Objective::DecisionMargin;
    let columns = if margin { LOCAL_MARGIN_COLUMNS } else { LOCAL_COLUMNS };
    let mut entries = vec![
        ("optimizer", Json::text(optimizer)),
        ("steps", Json::count(steps)),
        ("objective", Json::text(plan.objective_name)),
        ("rate", Json::Float(plan.rate)),
        ("max_gradient", Json::Float(plan.bound)),
        ("transport_cap", Json::Float(cap)),
        ("category_normalization", Json::text(if plan.objective.mean_category() { "mean_per_label" } else { "sum_labels" })),
        ("category_count", Json::count(net.config.category_labels.len())),
        ("loss_columns", Json::strings(columns)),
    ];
    if margin {
        entries.push(("decision_margin_coefficient", Json::Float(1.0)));
        entries.push(("decision_margin_rule", Json::text("max_non_s0_or_category_logit_v1")));
    }
    entries.push(("loss", Json::Array(losses.iter().map(|row| Json::floats(row)).collect())));
    entries.push(("state_parameter_fingerprints", Json::Array(fingerprints.iter().map(|text| Json::text(text.as_str())).collect())));
    entries.push(("update_columns", Json::strings(&["gradient_l2", "raw_delta_max", "clipped_coordinates", "transport_delta_max"])));
    entries.push((
        "updates",
        Json::Array(
            updates
                .iter()
                .map(|(norm, raw_max, clipped, transported)| {
                    Json::Array(vec![Json::Float(*norm), Json::Float(*raw_max), Json::count(*clipped), Json::Float(*transported)])
                })
                .collect(),
        ),
    ));
    let trace = checked(Json::object(entries).dump()?, "Local SGD optimizer trace exceeds its metadata byte budget.")?;
    Ok(LocalSgd { accumulated, trace })
}

/// `training_loss_contract`: the trace schema and the loss columns of a TRAIN process objective.
fn loss_contract(objective_name: &str) -> Result<(i64, &'static [&'static str]), TrainingError> {
    match objective_name {
        "legacy_sum_category" | "class_balanced_contextual_v1" => Ok((1, PROCESS_COLUMNS)),
        SUM_MARGIN => Ok((2, PROCESS_MARGIN_COLUMNS)),
        _ => Err(invalid("Unsupported TRAIN process objective.")),
    }
}

/// One backtracking trial: `[rate, losses, clipped, raw max, transported max, delta fingerprint, candidate fingerprint,
/// status, completed rows, encoder changed, attempted rows]`.
#[derive(Debug, Clone)]
struct Row {
    rate: f64,
    losses: Option<Vec<f64>>,
    clipped: Option<usize>,
    raw_max: Option<f64>,
    transport_max: Option<f64>,
    delta_fingerprint: Option<String>,
    candidate_fingerprint: Option<String>,
    status: &'static str,
    completed: usize,
    changed: bool,
    attempted: usize,
}

impl Row {
    fn invalid(rate: f64) -> Self {
        Self {
            rate,
            losses: None,
            clipped: None,
            raw_max: None,
            transport_max: None,
            delta_fingerprint: None,
            candidate_fingerprint: None,
            status: "invalid_numeric",
            completed: 0,
            changed: false,
            attempted: 0,
        }
    }

    fn json(&self) -> Json {
        let float = |value: Option<f64>| value.map_or(Json::Null, Json::Float);
        let text = |value: &Option<String>| value.as_ref().map_or(Json::Null, |text| Json::text(text.as_str()));
        Json::Array(vec![
            Json::Float(self.rate),
            self.losses.as_ref().map_or(Json::Null, |losses| Json::floats(losses)),
            self.clipped.map_or(Json::Null, Json::count),
            float(self.raw_max),
            float(self.transport_max),
            text(&self.delta_fingerprint),
            text(&self.candidate_fingerprint),
            Json::text(self.status),
            Json::count(self.completed),
            Json::Bool(self.changed),
            Json::count(self.attempted),
        ])
    }
}

/// The semantic forward pass and task losses of one candidate state; `None` is an invalid numeric trial.
fn trial_losses(net: &TinyNet, plan: &Plan<'_>, candidate: &F32Map, row: &mut Row) -> Option<Vec<f64>> {
    let model = net.with_params(params_from_f32(&net.params, candidate)).ok()?;
    row.attempted = plan.examples.len();
    for example in plan.examples {
        model.forward(&model.token_ids(&example.text)).ok()?;
    }
    row.completed = plan.examples.len();
    local_training_losses(&model, plan.examples, plan.objective).ok()
}

/// The result of a backtracking run.
#[derive(Debug, Clone)]
pub struct Backtracking {
    /// The selected transported update (empty when no scale improved).
    pub delta: F32Map,
    /// The selected rate, or `None` for the rejection.
    pub effective_rate: Option<f64>,
    /// `contextual_training_backtracking_trace`.
    pub trace: String,
    /// `contextual_training_backtracking_trials`.
    pub trials: String,
    /// The number of trials that ran.
    pub trial_count: usize,
    /// The sum of the completed semantic rows.
    pub semantic_examples: usize,
    /// The number of trials that attempted a forward pass.
    pub forward_attempts: usize,
    /// The sum of the attempted semantic rows.
    pub attempted_examples: usize,
}

/// `_backtracking_trials`: one immutable original direction (`raw`, normalised), each trial reconstructed before clipping.
/// `baseline` is the TRAIN objective vector of the base state.
pub fn backtracking(net: &TinyNet, plan: &Plan<'_>, raw: &Values, baseline: &[f64]) -> Result<Backtracking, TrainingError> {
    let cap = inward_float32_bound(plan.bound);
    let normalized: Vec<f64> = raw.values().flatten().copied().collect();
    if normalized.iter().any(|value| !value.is_finite()) {
        return Err(invalid("Backtracking original direction must remain finite."));
    }
    let (schema, columns) = loss_contract(plan.objective_name)?;
    let shapes = shapes_of(&net.params);
    let base_fingerprint = fingerprint(&values_of(&net.params), None)?;
    let raw_fingerprint = fingerprint(raw, Some(&shapes))?;
    let inventory: Values = raw.keys().map(|name| (name.clone(), Vec::new())).collect();
    let inventory_shapes: Shapes = raw.keys().filter_map(|name| shapes.get(name).map(|shape| (name.clone(), shape.clone()))).collect();
    let inventory_fingerprint = fingerprint(&inventory, Some(&inventory_shapes))?;
    let norm = fsum(normalized.iter().map(|value| value * value)).sqrt();
    let mut rows: Vec<Row> = Vec::new();
    let mut selected: Option<usize> = None;
    let mut selected_delta = F32Map::new();
    let mut selected_rate = None;
    for (index, scale) in BACKTRACKING_SCALES.iter().enumerate() {
        let rate = plan.rate * scale;
        let mut row = Row::invalid(rate);
        let scaled: Vec<f64> = normalized.iter().map(|value| value * rate).collect();
        let mut chosen: Option<F32Map> = None;
        if scaled.iter().all(|value| value.is_finite()) {
            let delta: F32Map = raw
                .iter()
                .map(|(name, values)| (name.clone(), values.iter().map(|value| (value * rate).clamp(-cap, cap) as f32).collect()))
                .collect();
            row.clipped = Some(scaled.iter().filter(|value| value.abs() > cap).count());
            row.raw_max = Some(largest(scaled.iter().copied()));
            row.transport_max = Some(largest(delta.values().flatten().map(|value| f64::from(*value))));
            row.delta_fingerprint = Some(fingerprint(&widen(&delta), Some(&shapes))?);
            let candidate = transport(&net.params, &delta);
            if candidate.values().flatten().all(|value| value.is_finite()) {
                row.candidate_fingerprint = Some(fingerprint(&widen(&candidate), None)?);
                row.changed = candidate.iter().any(|(name, values)| {
                    !is_output(name)
                        && net
                            .params
                            .get(name)
                            .is_some_and(|tensor| tensor.data.iter().zip(values).any(|(base, now)| (*base as f32) != *now))
                });
                if let Some(losses) = trial_losses(net, plan, &candidate, &mut row) {
                    row.status = "ok";
                    let decrease = baseline.last().copied().unwrap_or(f64::NAN) - losses.last().copied().unwrap_or(f64::NAN);
                    if decrease > BACKTRACKING_DECREASE && row.changed {
                        selected = Some(index);
                        selected_rate = Some(rate);
                        chosen = Some(delta);
                    }
                    row.losses = Some(losses);
                }
            }
        }
        if let Some(delta) = chosen {
            selected_delta = delta;
        }
        rows.push(row);
        if selected.is_some() {
            break;
        }
    }
    let mut header = vec![
        ("schema", Json::Int(schema)),
        ("policy", Json::text(BACKTRACKING_POLICY)),
        ("objective", Json::text(plan.objective_name)),
        ("base", Json::Array(vec![Json::text(base_fingerprint), Json::floats(baseline)])),
        (
            "raw",
            Json::Array(vec![
                Json::text(raw_fingerprint),
                Json::text(inventory_fingerprint),
                Json::count(normalized.len()),
                Json::Float(norm),
                Json::Float(largest(normalized.iter().copied())),
            ]),
        ),
        ("selected", selected.map_or(Json::Null, Json::count)),
        ("gradient_fits", Json::Int(1)),
    ];
    if schema == 2 {
        header.push(("loss_columns", Json::strings(columns)));
    }
    let budget = "Training policy JSON exceeds its byte budget.";
    let trace = checked(Json::object(header).dump()?, budget)?;
    let trials = checked(Json::Array(rows.iter().map(Row::json).collect()).dump()?, budget)?;
    Ok(Backtracking {
        delta: selected_delta,
        effective_rate: selected_rate,
        trace,
        trials,
        trial_count: rows.len(),
        semantic_examples: rows.iter().map(|row| row.completed).sum(),
        forward_attempts: rows.iter().filter(|row| row.attempted > 0).count(),
        attempted_examples: rows.iter().map(|row| row.attempted).sum(),
    })
}

/// `_training_diagnostics`: the passive scoring of the base and the transported candidate on the TRAIN rows. `raw` is the
/// unclipped update `direction * rate` of every trained coordinate, `scaled` the transported one and `cap` the inward
/// float32 bound.
pub fn diagnostics(
    snapshot: &Snapshot,
    plan: &Plan<'_>,
    net: &TinyNet,
    candidate: &F32Map,
    raw: &[f64],
    scaled: &F32Map,
    cap: f64,
) -> Result<String, TrainingError> {
    let examples = plan.examples;
    let clean = examples.iter().filter(|example| !example.target.is_sensitive()).count();
    let sensitive = examples.len() - clean;
    if clean == 0 || sensitive == 0 {
        return Err(invalid("TRAIN diagnostics require both clean and sensitive targets."));
    }
    if raw.iter().any(|value| !value.is_finite()) {
        return Err(invalid("TRAIN diagnostic raw deltas must remain finite."));
    }
    let (schema, columns) = loss_contract(plan.objective_name)?;
    let candidate_params = params_from_f32(&net.params, candidate);
    let candidate_net = net.with_params(candidate_params.clone())?;
    let mut losses: Vec<Json> = Vec::new();
    let mut accuracy: Vec<Json> = Vec::new();
    for (model, params) in [(net, &net.params), (&candidate_net, &candidate_params)] {
        losses.push(Json::floats(&local_training_losses(model, examples, plan.objective)?));
        let predicted = predictions(snapshot, params, examples)?;
        let mut hits = [0usize; 6];
        for (example, prediction) in examples.iter().zip(&predicted) {
            let (target, class) = (Class::of_target(&example.target), Class::of_prediction(prediction));
            hits[0] += usize::from(target == class);
            hits[1] += usize::from(target.sensitivity == class.sensitivity);
            hits[2] += usize::from(target.visibility == class.visibility);
            hits[3] += usize::from(target.categories == class.categories);
            hits[4] += usize::from(!target.is_sensitive() && !class.is_sensitive());
            hits[5] += usize::from(target.is_sensitive() && class.is_sensitive());
        }
        let rows = examples.len() as f64;
        let denominators = [rows, rows, rows, rows, clean as f64, sensitive as f64];
        let rates: Vec<f64> = hits.iter().zip(denominators).map(|(hit, denominator)| *hit as f64 / denominator).collect();
        accuracy.push(Json::floats(&rates));
    }
    let fingerprints = vec![fingerprint(&values_of(&net.params), None)?, fingerprint(&widen(candidate), None)?];
    let phase = |name: &str| Json::Array(vec![Json::text(name), Json::text("semantic"), Json::text("ok"), Json::count(examples.len())]);
    let record = Json::object(vec![
        ("schema", Json::Int(schema)),
        ("objective", Json::text(plan.objective_name)),
        ("fingerprints", Json::Array(fingerprints.iter().map(|text| Json::text(text.as_str())).collect())),
        ("phases", Json::Array(vec![phase("base_training"), phase("candidate_training")])),
        ("counts", Json::Array(vec![Json::count(examples.len()), Json::count(clean), Json::count(sensitive)])),
        ("loss_columns", Json::strings(columns)),
        ("loss", Json::Array(losses)),
        (
            "accuracy_columns",
            Json::strings(&[
                "exact",
                "sensitivity_exact",
                "visibility_exact",
                "category_set_exact",
                "clean_specificity",
                "sensitive_recall",
            ]),
        ),
        ("accuracy", Json::Array(accuracy)),
        ("update_columns", Json::strings(&["coordinates", "strictly_clipped", "raw_abs_max", "transported_abs_max"])),
        (
            "update",
            Json::Array(vec![
                Json::count(raw.len()),
                Json::count(raw.iter().filter(|value| value.abs() > cap).count()),
                Json::Float(largest(raw.iter().copied())),
                Json::Float(largest(scaled.values().flatten().map(|value| f64::from(*value)))),
            ]),
        ),
    ]);
    checked(record.dump()?, "TRAIN diagnostics exceed their byte budget or are missing.")
}
