//! The ORIGINAL TRAIN retention loops: `LLM/privoke/sensitive_retention_training.py` and the retention hinge of
//! `supervised_training.py` over `privoke_model/sensitive_retention.py` (policies `..._original_train_gate_v1` and
//! `..._original_train_hinge_v1`).
//!
//! Both policies are the fixed FULL Adam fit (64 steps, the summed-margin objective over the 64 class-balanced rows) with the
//! target-capped safety audit of the eligible ORIGINAL TRAIN rows before and after. The gate policy only audits; the
//! hinge policy adds, at every step, the independently normalised hinge direction of the eligible rows,
//! `mean(relu(original_margin - candidate_margin))`, to the main direction.
//!
//! Ported: the release ([`Release::load`]: bank, ordered references, ORIGINAL teacher identity and the manifest the
//! contract derives, all under their pins), the hinge direction ([`hinge_deltas`]), the fit with its audit trace, the safety
//! rows, the retained trace and summary and the response metadata ([`run`]). Not ported: `validate_trace` and the other
//! self-consistency validators, cancellation, and the held-out example validation of `_validate_heldout_examples`. The
//! directions come from a pluggable source ([`compute_directions`] is the Rust gradient), so recorded Python directions replay
//! the recurrence exactly.

use std::collections::{BTreeMap, BTreeSet};

use privoke_contracts::canonical::{self, Variant};
use privoke_contracts::digest::sha256_hex;
use privoke_contracts::fingerprint::parameter_fingerprint;
use privoke_contracts::json::{Value as Node, parse as parse_node};
use privoke_rules::preprocessing::normalize_text;
use privoke_semantic::tiny::TinyConfig;
use privoke_semantic::{TinyModel, TinyPrediction};
use serde_json::Value;

use crate::adam::{AdamState, F32Map, adam_step};
use crate::admission::CONFIG_CANONICAL as CONFIG_CANONICAL_TEXT;
use crate::error::TrainingError;
use crate::net::TinyNet;
use crate::objective::{Example, Objective, class_balanced, fsum, supervised_deltas_with};
use crate::retention_common::{BANK_SHA256, BOUNDARY, EPSILON, is_sensitive, safety_margin, sensitivity_bits, teacher_tensors};
use crate::routes::local_training_losses;
use crate::rpc::{Snapshot, artifact_with, heldout_metrics};
use crate::window::{action_value, array_identity, fingerprint, node_int, node_object, node_text, packed_of_target, params_of, shapes_of};

/// The gate policy: the audit only.
pub const GATE_POLICY: &str = "full_projected_adam64_original_train_gate_v1";
/// The hinge policy: the audit and the ORIGINAL-margin hinge direction.
pub const HINGE_POLICY: &str = "full_projected_adam64_original_train_hinge_v1";
/// `contextual_training_objective` of the gate policy.
pub const GATE_OBJECTIVE: &str = "class_balanced_contextual_sum_margin_original_gate_v1";
/// `contextual_training_objective` of the hinge policy.
pub const HINGE_OBJECTIVE: &str = "class_balanced_contextual_sum_margin_original_hinge_v1";
/// `ELIGIBILITY`.
pub const ELIGIBILITY: &str = "candidate_train_exact_original_target_capped_v1";
/// The fixed fit's policy name (`full_adam.POLICY`).
const ADAM_POLICY: &str = crate::adam::POLICY;
const DATASET_SHA256: &str = "3b777f328a8e08140ee964facbd559c694673336b4c5655320befdd84aef66e0";
const LEGACY_SHA256: &str = "04db8a469aa5c430f9333829da015f01b4377eb5268c58c1451c63b0a51dcced";
const LABEL_REVIEW_SHA256: &str = "7ddca38130b65c167945f8c0f822caee3012b25787000edfbf311f6d89a0a7fe";
pub(crate) const TEACHERS: [(&str, &str); 3] = [
    ("quality", "50657f82e52bb2df56e0ce57c3124a7d7b97a9d9ea338e5eac3c42552fb40733"),
    ("balanced", "4e991e8f1c3e6211e824613fa8eee2fdc6f0cec6ec9a5e817dbf1c17802cf8a1"),
    ("efficient", "a23e986915225373663ed7a017d13fa82aac8c3a266ff5a3f4943b129d92e4ef"),
];
const NORMALIZATION: &str = "{\"main\":\"unchanged_class_balanced_weight_mean\",\"auxiliary\":\"unweighted_eligible_mean\",\"coefficient\":1,\"gradient_denominator\":1,\"microbatch_size\":32}";
const STRATEGY: &str = "contextual_full_encoder_sgd_v1";

type Values = BTreeMap<String, Vec<f64>>;

fn invalid(message: &str) -> TrainingError {
    TrainingError::invalid(message)
}

fn is_sha256(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// The objective name of a retention policy.
pub fn objective_of(policy: &str) -> Option<&'static str> {
    match policy {
        GATE_POLICY => Some(GATE_OBJECTIVE),
        HINGE_POLICY => Some(HINGE_OBJECTIVE),
        _ => None,
    }
}

/// An eligible ORIGINAL TRAIN reference: the bank row and the teacher's frozen output.
#[derive(Debug, Clone, PartialEq)]
pub struct Reference {
    /// The bank id.
    pub id: String,
    /// The bank text, normalised for the serving model.
    pub text: String,
    /// The gold packed classification.
    pub gold: u16,
    /// The ORIGINAL packed prediction.
    pub original: u16,
    /// The ORIGINAL confidence.
    pub confidence: f64,
    /// The ORIGINAL union margin (strictly positive for an eligible row).
    pub margin: f64,
}

/// An authenticated retention release.
#[derive(Debug, Clone)]
pub struct Release {
    /// The sha256 of the manifest bytes (the request pin).
    pub sha256: String,
    /// The fingerprint of the ORIGINAL teacher's float32 parameters.
    pub teacher_fingerprint: String,
    /// The ORIGINAL teacher configuration.
    pub teacher_config: Value,
    /// The ORIGINAL teacher's model id (`privoke-<profile>`).
    pub model_id: String,
    /// The eligible references, in bank order.
    pub references: Vec<Reference>,
}

impl Release {
    /// `load_release` and `validate_trusted_release`: the manifest must hash to `trusted_sha256`, the bank to the approved
    /// bank, the teacher to the fixed ORIGINAL artifact of its profile; the references must follow the bank, name the
    /// teacher, obey the strict margin and gap policy and cover 20 groups; and the manifest must be the one the contract
    /// derives from them.
    pub fn load(bank: &[u8], references: &[u8], manifest: &[u8], teacher: &[u8], trusted_sha256: &str) -> Result<Self, TrainingError> {
        if !is_sha256(trusted_sha256) || sha256_hex(manifest) != trusted_sha256 {
            return Err(invalid("Retention requires a distinct trusted configured accepted manifest SHA, matching the request."));
        }
        let differs = || invalid("Retention manifest/reference/bank/teacher snapshot differs.");
        let manifest_value: Value = serde_json::from_slice(manifest).map_err(|_| differs())?;
        let profile = manifest_value["teacher"]["profile"].as_str().ok_or_else(differs)?;
        let pinned = TEACHERS.iter().find(|(name, _)| *name == profile).map(|(_, sha)| *sha);
        if pinned != Some(sha256_hex(teacher).as_str()) {
            return Err(invalid("Retention teacher differs from the fixed ORIGINAL artifact bytes."));
        }
        let artifact: Value = serde_json::from_slice(teacher).map_err(|_| differs())?;
        if artifact["model_id"] != format!("privoke-{profile}") {
            return Err(invalid("Retention teacher profile differs."));
        }
        let (parameters, shapes) = teacher_tensors(&artifact)?;
        let inventory: Values = parameters.keys().map(|name| (name.clone(), Vec::new())).collect();
        let parameter_fingerprint_text = parameter_fingerprint(&parameters, Some(&shapes))?;
        let identity = serde_json::json!({
            "profile": profile, "file_sha256": pinned, "checksum": artifact["checksum"], "model_id": artifact["model_id"],
            "version": artifact["version"], "config": artifact["config"], "parameter_fingerprint": parameter_fingerprint_text,
            "inventory_fingerprint": parameter_fingerprint(&inventory, Some(&shapes))?,
        });
        // The bank.
        if sha256_hex(bank) != BANK_SHA256 {
            return Err(invalid("Retention bank differs from the independently approved200 TRAIN rows."));
        }
        let bank_rows: Vec<Value> = serde_json::from_slice(bank).map_err(|_| differs())?;
        let ids: Vec<&str> = bank_rows.iter().filter_map(|row| row["id"].as_str()).collect();
        if bank_rows.len() != 200 || ids.len() != 200 || ids.windows(2).any(|pair| pair[0] > pair[1]) {
            return Err(invalid("Retention bank differs from the independently approved200 TRAIN rows."));
        }
        let positive = |row: &Value| row["packed_classification"].as_u64().is_some_and(|packed| packed & 0b11 != 0);
        if bank_rows
            .iter()
            .any(|row| row["metadata"]["taxonomy_partition"] != "train" || row["metadata"]["split"] != "train" || !positive(row))
        {
            return Err(invalid("Retention bank requires approved positive permanent TRAIN only."));
        }
        let bank_groups: BTreeSet<String> = bank_rows.iter().map(|row| row["metadata"]["group_id"].to_string()).collect();
        if bank_groups.len() != 20 {
            return Err(invalid("Retention bank must cover exactly20 approved groups."));
        }
        // The references.
        let refs: Value = serde_json::from_slice(references).map_err(|_| differs())?;
        let boundary: Value = serde_json::from_str(BOUNDARY).map_err(|_| differs())?;
        let reference_error = || invalid("Retention references differ from original teacher/bank/boundary policy.");
        let rows = refs["rows"].as_array().ok_or_else(reference_error)?;
        let keys: BTreeSet<&str> = refs.as_object().map(|o| o.keys().map(String::as_str).collect()).unwrap_or_default();
        if keys != BTreeSet::from(["schema", "teacher", "bank_sha256", "boundary", "rows"])
            || refs["schema"] != 1
            || refs["teacher"] != identity
            || refs["bank_sha256"] != BANK_SHA256
            || refs["boundary"] != boundary
            || rows.len() != bank_rows.len()
        {
            return Err(reference_error());
        }
        let (mut groups, mut eligible_ids, mut eligible) = (BTreeSet::new(), Vec::new(), Vec::new());
        for (row, source) in rows.iter().zip(&bank_rows) {
            let malformed = || invalid("Malformed ordered ORIGINAL TRAIN reference.");
            let row_keys: BTreeSet<&str> = row.as_object().map(|o| o.keys().map(String::as_str).collect()).unwrap_or_default();
            let packed = row["packed"].as_u64().and_then(|n| u16::try_from(n).ok());
            let numbers = ["confidence", "margin", "sensitivity_gap"].map(|key| row[key].as_f64().filter(|v| v.is_finite()));
            let (Some(packed), [Some(confidence), Some(margin), Some(gap)], Some(flag)) = (packed, numbers, row["eligible"].as_bool())
            else {
                return Err(malformed());
            };
            let rounded = format!("{confidence:.3}").parse::<f64>().unwrap_or(f64::NAN);
            if row_keys != BTreeSet::from(["id", "packed", "confidence", "margin", "sensitivity_gap", "eligible"])
                || row["id"] != source["id"]
                || !(0.0..=0.999).contains(&confidence)
                || confidence != rounded
                || gap < 0.0
            {
                return Err(malformed());
            }
            let eligible_row = is_sensitive(packed) && margin > EPSILON && gap > EPSILON;
            if flag != eligible_row {
                return Err(invalid("Retention eligibility mask differs from the fixed strict policy."));
            }
            if eligible_row {
                groups.insert(source["metadata"]["group_id"].to_string());
                eligible_ids.push(source["id"].clone());
                let text = source["text"].as_str().ok_or_else(malformed)?;
                eligible.push(Reference {
                    id: source["id"].as_str().unwrap_or_default().to_string(),
                    text: normalize_text(text).map_err(|error| TrainingError::invalid(format!("{error:?}")))?,
                    gold: source["packed_classification"].as_u64().and_then(|n| u16::try_from(n).ok()).ok_or_else(malformed)?,
                    original: packed,
                    confidence,
                    margin,
                });
            }
        }
        if groups.len() != 20 {
            return Err(invalid("Retention requires eligible ORIGINAL coverage in every20 TRAIN group; no backfill."));
        }
        let expected = serde_json::json!({
            "schema": 1, "kind": "original_train_retention_v1", "dataset_sha256": DATASET_SHA256, "legacy_snapshot_sha256": LEGACY_SHA256,
            "bank_sha256": BANK_SHA256, "label_review_sha256": LABEL_REVIEW_SHA256, "references_sha256": sha256_hex(references),
            "teacher": identity, "boundary": boundary,
            "normalization": serde_json::from_str::<Value>(NORMALIZATION).map_err(|_| differs())?,
            "eligible_ids": eligible_ids, "fit_release": false
        });
        if manifest_value != expected {
            return Err(differs());
        }
        Ok(Self {
            sha256: trusted_sha256.to_string(),
            teacher_fingerprint: parameter_fingerprint_text,
            teacher_config: artifact["config"].clone(),
            model_id: format!("privoke-{profile}"),
            references: eligible,
        })
    }
}

/// The union margin of one row: the largest of the non-S0 severity logits minus the S0 logit and the category logits
/// minus the threshold logit, and where it came from (the first maximum wins).
struct Winner {
    margin: f64,
    /// `Some(label)` for a severity alternative, `None` for a category.
    severity: Option<usize>,
    category: usize,
    s0: usize,
}

fn union_margin(config: &TinyConfig, sensitivity: &[f64], category: &[f64]) -> Result<Winner, TrainingError> {
    let s0 = config
        .sensitivity_labels
        .iter()
        .position(|label| label == "S0")
        .ok_or_else(|| invalid("Decision-margin training requires S0 and non-S0 sensitivity labels."))?;
    let offset = config.category_threshold.ln() - (-config.category_threshold).ln_1p();
    let mut best: Option<Winner> = None;
    let mut consider = |margin: f64, severity: Option<usize>, category: usize| {
        if best.as_ref().is_none_or(|current| margin > current.margin) {
            best = Some(Winner { margin, severity, category, s0 });
        }
    };
    for (index, label) in config.sensitivity_labels.iter().enumerate() {
        if label != "S0" {
            consider(sensitivity[index] - sensitivity[s0], Some(index), 0);
        }
    }
    for (index, value) in category.iter().enumerate() {
        consider(value - offset, None, index);
    }
    let winner = best.ok_or_else(|| invalid("Decision-margin differences must remain finite."))?;
    if !winner.margin.is_finite() {
        return Err(invalid("Decision-margin differences must remain finite."));
    }
    Ok(winner)
}

/// The diagnostics of one hinge direction.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct HingeDiagnostics {
    /// Rows whose hinge exceeds `1e-4 + 1e-4 * |reference|`.
    pub active_rows: usize,
    /// The largest hinge.
    pub maximum_hinge: f64,
    /// The largest `|reference - current| / (1e-5 + 1e-5 * |reference|)`.
    pub maximum_scaled_original_difference: f64,
}

/// The independently normalised hinge direction (the negative gradient over every tensor) of the eligible references,
/// `sum(relu(original_margin - margin)) / rows`, its loss and its diagnostics.
pub fn hinge_deltas(net: &TinyNet, references: &[Reference]) -> Result<(Values, f64, HingeDiagnostics), TrainingError> {
    if references.is_empty() || references.iter().any(|r| !r.margin.is_finite()) {
        return Err(invalid("Retention hinge requires independent unit-weight rows and fixed finite ORIGINAL margins."));
    }
    let total = references.len() as f64;
    let mut grads = net.zero_grads();
    let mut loss = 0.0;
    let mut diagnostics = HingeDiagnostics { active_rows: 0, maximum_hinge: 0.0, maximum_scaled_original_difference: 0.0 };
    for reference in references {
        let forward = net.forward(&net.token_ids(&reference.text))?;
        let winner = union_margin(&net.config, &forward.logits[0], &forward.logits[2])?;
        let hinge = (reference.margin - winner.margin).max(0.0);
        loss += hinge / total;
        let mut dz: [Vec<f64>; 3] =
            [vec![0.0; forward.logits[0].len()], vec![0.0; forward.logits[1].len()], vec![0.0; forward.logits[2].len()]];
        if hinge > 0.0 {
            match winner.severity {
                Some(index) => {
                    dz[0][index] -= 1.0 / total;
                    dz[0][winner.s0] += 1.0 / total;
                }
                None => dz[2][winner.category] -= 1.0 / total,
            }
        }
        net.backward(&forward, &dz, &mut grads);
        diagnostics.active_rows += usize::from(hinge > 1e-4 + 1e-4 * reference.margin.abs());
        diagnostics.maximum_hinge = diagnostics.maximum_hinge.max(hinge);
        diagnostics.maximum_scaled_original_difference = diagnostics
            .maximum_scaled_original_difference
            .max((reference.margin - winner.margin).abs() / (1e-5 + 1e-5 * reference.margin.abs()));
    }
    let deltas: Values = grads.into_iter().map(|(name, g)| (name, g.into_iter().map(|v| -v).collect())).collect();
    if deltas.values().flatten().any(|v| !v.is_finite()) || !loss.is_finite() {
        return Err(invalid("Contextual supervised gradients must exist and be finite."));
    }
    Ok((deltas, loss, diagnostics))
}

/// The inputs of one step's directions.
#[derive(Debug)]
pub struct Step<'a> {
    /// The 1-based step.
    pub index: usize,
    /// The model at the current transported state.
    pub net: &'a TinyNet,
    /// The 64 class-balanced main rows.
    pub rows: &'a [Example],
    /// The eligible references.
    pub references: &'a [Reference],
    /// Whether the policy adds the hinge direction.
    pub hinge: bool,
}

/// The hinge part of a step's directions.
#[derive(Debug, Clone)]
pub struct Auxiliary {
    /// The hinge direction.
    pub direction: Values,
    /// The hinge loss.
    pub loss: f64,
    /// The diagnostics.
    pub diagnostics: HingeDiagnostics,
}

/// The two directions of a step.
#[derive(Debug, Clone)]
pub struct Directions {
    /// The main sum-margin direction.
    pub main: Values,
    /// The main loss.
    pub main_loss: f64,
    /// The hinge direction (the hinge policy only).
    pub auxiliary: Option<Auxiliary>,
}

/// The Rust gradient of both directions.
pub fn compute_directions(step: &Step<'_>) -> Result<Directions, TrainingError> {
    let main = supervised_deltas_with(step.net, step.rows, Objective::SumMargin, None)?;
    let auxiliary = if step.hinge {
        let (direction, loss, diagnostics) = hinge_deltas(step.net, step.references)?;
        Some(Auxiliary { direction, loss, diagnostics })
    } else {
        None
    };
    Ok(Directions { main: main.deltas, main_loss: main.loss, auxiliary })
}

/// One audited eligible row.
#[derive(Debug, Clone, PartialEq)]
pub struct Safety {
    /// The bank id.
    pub id: String,
    /// Gold, ORIGINAL and candidate packed classifications.
    pub packed: [u16; 3],
    /// ORIGINAL and candidate confidences.
    pub confidence: [f64; 2],
    /// Gold, ORIGINAL and candidate actions.
    pub actions: [i64; 3],
    /// The target-capped violation.
    pub violation: bool,
    /// ORIGINAL and candidate union margins.
    pub margin: [f64; 2],
    /// `max(0, original - candidate)`.
    pub hinge: f64,
}

fn safety_rows(config: &TinyConfig, references: &[Reference], predictions: &[TinyPrediction]) -> Result<Vec<Safety>, TrainingError> {
    if predictions.len() != references.len() {
        return Err(invalid("Retention safety execution returned incomplete rows."));
    }
    references
        .iter()
        .zip(predictions)
        .map(|(reference, prediction)| {
            let candidate = prediction.decision.classification.pack();
            let confidence = prediction.decision.confidence.clamp(0.0, 0.999);
            let actions = [
                action_value(reference.gold, None),
                action_value(reference.original, Some(reference.confidence)),
                action_value(candidate, Some(confidence)),
            ];
            let regression = sensitivity_bits(candidate).min(sensitivity_bits(reference.gold))
                < sensitivity_bits(reference.original).min(sensitivity_bits(reference.gold))
                || actions[2].min(actions[0]) < actions[1].min(actions[0]);
            let margin = safety_margin(config, prediction)?;
            Ok(Safety {
                id: reference.id.clone(),
                packed: [reference.gold, reference.original, candidate],
                confidence: [reference.confidence, confidence],
                actions,
                violation: !is_sensitive(candidate) || regression,
                margin: [reference.margin, margin],
                hinge: (reference.margin - margin).max(0.0),
            })
        })
        .collect()
}

fn safety_node(rows: &[Safety]) -> Node {
    Node::Array(
        rows.iter()
            .map(|row| {
                node_object(vec![
                    ("id", node_text(&row.id)),
                    ("gold", node_int(usize::from(row.packed[0]))),
                    ("original", node_int(usize::from(row.packed[1]))),
                    ("candidate", node_int(usize::from(row.packed[2]))),
                    ("original_confidence", Node::Float(row.confidence[0])),
                    ("candidate_confidence", Node::Float(row.confidence[1])),
                    ("gold_action", Node::Int(row.actions[0].to_string())),
                    ("original_action", Node::Int(row.actions[1].to_string())),
                    ("candidate_action", Node::Int(row.actions[2].to_string())),
                    ("violation", Node::Bool(row.violation)),
                    ("original_margin", Node::Float(row.margin[0])),
                    ("candidate_margin", Node::Float(row.margin[1])),
                    ("hinge", Node::Float(row.hinge)),
                ])
            })
            .collect(),
    )
}

fn predictions_of(artifact: &Value, params: &crate::net::Params, texts: &[String]) -> Result<Vec<TinyPrediction>, TrainingError> {
    let model = TinyModel::from_artifact(&artifact_with(artifact, params))?;
    Ok(texts.iter().map(|text| model.predict(text)).collect())
}

fn packed_of(prediction: &TinyPrediction) -> u16 {
    prediction.decision.classification.pack()
}

fn phase(rows: usize, layers: usize) -> Node {
    node_object(vec![
        ("rows_attempted", node_int(rows)),
        ("rows_completed", node_int(rows)),
        ("blocks_attempted", node_int(rows * layers)),
        ("blocks_completed", node_int(rows * layers)),
    ])
}

fn count_node(pairs: &[(&str, usize)]) -> Node {
    node_object(pairs.iter().map(|(key, value)| (*key, node_int(*value))).collect())
}

/// The result of a retention run.
#[derive(Debug, Clone)]
pub struct Outcome {
    /// The transported update (the cumulative float32 delta of every tensor).
    pub gradients: F32Map,
    /// The candidate parameters.
    pub candidate: F32Map,
    /// The metadata the loop writes (the worker adds the artifact identity, configuration and cache key).
    pub metadata: BTreeMap<String, String>,
    /// The response metrics.
    pub metrics: BTreeMap<String, f64>,
    /// `(phase, rows)` of the executed work.
    pub executions: Vec<(String, usize)>,
    /// The retained trace, canonical JSON.
    pub trace: String,
    /// The audit of the base and the candidate.
    pub base_safety: Vec<Safety>,
    /// The audit of the candidate.
    pub safety: Vec<Safety>,
    /// The base and final identities of the steps: `(gradient, moments)`.
    pub identities: Vec<(String, String)>,
}

fn weight_audit(raw: &[Example], adjusted: &[Example]) -> BTreeMap<String, f64> {
    let sum = |rows: &[Example], label: bool| fsum(rows.iter().filter(|e| e.target.is_sensitive() == label).map(|e| e.weight));
    let (raw_clean, raw_sensitive) = (sum(raw, false), sum(raw, true));
    let (clean, sensitive) = (sum(adjusted, false), sum(adjusted, true));
    let total = fsum([raw_clean, raw_sensitive]);
    let clean_rows = raw.iter().filter(|e| !e.target.is_sensitive()).count() as f64;
    BTreeMap::from([
        ("training_clean_examples".to_string(), clean_rows),
        ("training_sensitive_examples".to_string(), raw.len() as f64 - clean_rows),
        ("raw_clean_weight".to_string(), raw_clean),
        ("raw_sensitive_weight".to_string(), raw_sensitive),
        ("raw_total_weight".to_string(), total),
        ("effective_clean_weight".to_string(), clean),
        ("effective_sensitive_weight".to_string(), sensitive),
        ("clean_objective_mass".to_string(), clean / total),
        ("sensitive_objective_mass".to_string(), sensitive / total),
    ])
}

fn normalised(rows: &[Example]) -> Result<Vec<Example>, TrainingError> {
    rows.iter()
        .map(|row| {
            let text = normalize_text(&row.text).map_err(|error| TrainingError::invalid(format!("{error:?}")))?;
            Ok(Example { text, ..row.clone() })
        })
        .collect()
}

/// The retention fit: the fixed 64-step FULL Adam over the 64 main rows (with the hinge direction under the hinge policy),
/// the audit of the eligible rows before and after, and the held-out guard metrics of the 16 guard rows.
pub fn run(
    artifact: &Value,
    release: &Release,
    policy: &str,
    examples: &[Example],
    heldout: &[Example],
    source: &mut dyn FnMut(&Step<'_>) -> Result<Directions, TrainingError>,
) -> Result<Outcome, TrainingError> {
    let objective_name = objective_of(policy).ok_or_else(|| invalid("Unsupported retention optimizer."))?;
    let hinge = policy == HINGE_POLICY;
    let net = TinyNet::from_artifact(artifact)?;
    if artifact["config"] != release.teacher_config {
        return Err(invalid("Retention CURRENT config/main64/guard16 differs from fixed reference contract."));
    }
    if examples.len() != 64 || heldout.len() != 16 {
        return Err(invalid("Retention CURRENT config/main64/guard16 differs from fixed reference contract."));
    }
    let raw = normalised(examples)?;
    let heldout = normalised(heldout)?;
    let balanced = class_balanced(&raw)?;
    let audit = weight_audit(&raw, &balanced);
    let layers = net.config.num_layers;
    let shapes = shapes_of(&net.params);
    let base: F32Map = net.params.iter().map(|(name, tensor)| (name.clone(), tensor.data.iter().map(|v| *v as f32).collect())).collect();
    let snapshot = Snapshot { artifact: artifact.clone(), full_capable: true, ..Snapshot::default() };
    let texts: Vec<String> = balanced.iter().map(|e| e.text.clone()).collect();
    let reference_texts: Vec<String> = release.references.iter().map(|r| r.text.clone()).collect();
    // The untouched BASE: its predictions, its objective and its audit.
    let base_predictions = predictions_of(artifact, &net.params, &texts)?;
    let exact = |predictions: &[TinyPrediction]| -> f64 {
        balanced.iter().zip(predictions).filter(|(e, p)| packed_of_target(&e.target) == packed_of(p)).count() as f64 / balanced.len() as f64
    };
    let base_exact = exact(&base_predictions);
    let base_safety = safety_rows(&net.config, &release.references, &predictions_of(artifact, &net.params, &reference_texts)?)?;
    // The fit.
    let base_fingerprint = fingerprint(&base, &shapes)?;
    let (mut state, mut current_net, mut current) = (AdamState::new(&base), net.clone(), base.clone());
    let (mut steps, mut auxiliary_steps, mut identities) = (Vec::new(), Vec::new(), Vec::new());
    let mut cumulative = Values::new();
    for index in 1..=64usize {
        let directions = source(&Step { index, net: &current_net, rows: &balanced, references: &release.references, hinge })?;
        let mut loss = directions.main_loss;
        let mut direction = directions.main.clone();
        if let Some(extra) = &directions.auxiliary {
            let norm = |values: &Values| fsum(values.values().flatten().map(|v| v * v)).sqrt();
            let dot = fsum(directions.main.iter().flat_map(|(name, a)| a.iter().zip(&extra.direction[name]).map(|(x, y)| x * y)));
            let parity = (fingerprint(&current, &shapes)? == release.teacher_fingerprint)
                .then_some(extra.diagnostics.maximum_scaled_original_difference);
            auxiliary_steps.push(node_object(vec![
                ("step", node_int(index)),
                ("main_loss", Node::Float(directions.main_loss)),
                ("auxiliary_loss", Node::Float(extra.loss)),
                ("main_gradient_norm", Node::Float(norm(&directions.main))),
                ("auxiliary_gradient_norm", Node::Float(norm(&extra.direction))),
                ("gradient_dot", Node::Float(dot)),
                ("active_rows", node_int(extra.diagnostics.active_rows)),
                ("maximum_hinge", Node::Float(extra.diagnostics.maximum_hinge)),
                ("original_state_parity_scaled_error", parity.map_or(Node::Null, Node::Float)),
            ]));
            for (name, values) in &mut direction {
                for (value, add) in values.iter_mut().zip(&extra.direction[name]) {
                    *value += add;
                }
            }
            loss += extra.loss;
        }
        if !loss.is_finite() || loss < 0.0 {
            return Err(invalid("FULL Adam helper loss must remain finite and nonnegative."));
        }
        let before = fingerprint(&current, &shapes)?;
        let outcome = adam_step(&base, &mut state, &direction, u32::try_from(index).unwrap_or(u32::MAX))?;
        let after = fingerprint(&outcome.candidate, &shapes)?;
        let (moment, variance) = state.moments();
        let mut moments = Values::new();
        for name in base.keys() {
            moments.insert(format!("{name}:m"), moment[name].clone());
            moments.insert(format!("{name}:v"), variance[name].clone());
        }
        let (gradient_id, moments_id) = (array_identity(&direction), array_identity(&moments));
        steps.push(node_object(vec![
            ("step", node_int(index)),
            ("before", node_text(&before)),
            ("after", node_text(&after)),
            ("loss", Node::Float(loss)),
            ("gradient", node_text(&gradient_id)),
            ("moments", node_text(&moments_id)),
            ("delta", node_text(&parameter_fingerprint(&outcome.cumulative, Some(&shapes))?)),
            ("clipped", node_int(outcome.clipped)),
        ]));
        identities.push((gradient_id, moments_id));
        cumulative = outcome.cumulative;
        current_net = net.with_params(params_of(&net, &outcome.candidate))?;
        current = outcome.candidate;
    }
    let outputs = |name: &String| name.starts_with("head.") || name.starts_with("readout.");
    if !current.iter().any(|(name, values)| !outputs(name) && *values != base[name]) {
        return Err(invalid("FULL Adam produced no transported encoder change."));
    }
    let final_fingerprint = fingerprint(&current, &shapes)?;
    let delta_fingerprint = parameter_fingerprint(&cumulative, Some(&shapes))?;
    let batches = balanced.len().div_ceil(32);
    let counts = count_node(&[
        ("directions_attempted", 64),
        ("directions_completed", 64),
        ("microbatch_forward_attempted", 64 * batches),
        ("microbatch_forward_completed", 64 * batches),
        ("microbatch_backward_started", 64 * batches),
        ("microbatch_backward_completed", 64 * batches),
        ("torch_block_forwards_attempted", 64 * batches * layers),
        ("torch_block_forwards_completed", 64 * batches * layers),
        ("train_parameter_states", 65),
    ]);
    let config = parse_node(CONFIG_CANONICAL_TEXT).map_err(|_| invalid("Invalid FULL Adam configuration."))?;
    let adam_trace = node_object(vec![
        ("schema", node_int(1)),
        ("policy", node_text(ADAM_POLICY)),
        ("config", config),
        ("base", node_text(&base_fingerprint)),
        ("final", node_text(&final_fingerprint)),
        ("delta", node_text(&delta_fingerprint)),
        ("steps", Node::Array(steps)),
        ("counts", counts),
        ("train", node_int(balanced.len())),
    ]);
    // The candidate: its predictions, objective, held-out guard and audit.
    let candidate_params = params_of(&net, &current);
    let candidate_net = net.with_params(candidate_params.clone())?;
    let candidate_predictions = predictions_of(artifact, &candidate_params, &texts)?;
    let candidate_exact = exact(&candidate_predictions);
    let base_loss = local_training_losses(&net, &balanced, Objective::SumMargin)?.last().copied().unwrap_or(f64::NAN);
    let final_loss = local_training_losses(&candidate_net, &balanced, Objective::SumMargin)?.last().copied().unwrap_or(f64::NAN);
    let mut metrics = BTreeMap::from([
        ("examples".to_string(), balanced.len() as f64),
        ("exact_match_rate".to_string(), base_exact),
        ("candidate_train_exact_match_rate".to_string(), candidate_exact),
        ("base_train_objective_loss".to_string(), base_loss),
        ("candidate_train_objective_loss".to_string(), final_loss),
        ("total_weight".to_string(), fsum(balanced.iter().map(|e| e.weight))),
    ]);
    metrics.extend(heldout_metrics(&snapshot, &net.params, &heldout, None)?);
    for (key, value) in heldout_metrics(&snapshot, &candidate_params, &heldout, Some(&net.params))? {
        metrics.insert(format!("candidate_{key}"), value);
    }
    metrics.extend(audit);
    let safety = safety_rows(&net.config, &release.references, &predictions_of(artifact, &candidate_params, &reference_texts)?)?;
    let count = release.references.len();
    let auxiliary = if hinge {
        node_object(vec![
            (
                "counts",
                count_node(&[
                    ("directions_attempted", 64),
                    ("directions_completed", 64),
                    ("rows_attempted", 64 * count),
                    ("rows_completed", 64 * count),
                    ("microbatch_forward_attempted", 64 * count.div_ceil(32)),
                    ("microbatch_forward_completed", 64 * count.div_ceil(32)),
                    ("microbatch_backward_started", 64 * count.div_ceil(32)),
                    ("microbatch_backward_completed", 64 * count.div_ceil(32)),
                    ("torch_block_forwards_attempted", 64 * count.div_ceil(32) * layers),
                    ("torch_block_forwards_completed", 64 * count.div_ceil(32) * layers),
                ]),
            ),
            ("steps", Node::Array(auxiliary_steps)),
        ])
    } else {
        node_object(vec![("counts", Node::Object(BTreeMap::new())), ("steps", Node::Array(Vec::new()))])
    };
    let counts_for_summary = match &auxiliary {
        Node::Object(entries) => entries.get("counts").cloned().unwrap_or(Node::Null),
        _ => Node::Null,
    };
    let trace = node_object(vec![
        ("schema", node_int(1)),
        ("policy", node_text(policy)),
        ("manifest_sha256", node_text(&release.sha256)),
        ("adam", adam_trace),
        ("auxiliary", auxiliary),
        ("base_safety", safety_node(&base_safety)),
        ("safety", safety_node(&safety)),
    ]);
    let raw_trace = canonical::to_string(&trace, Variant::Ascii)?;
    let summary = node_object(vec![
        ("schema", node_int(1)),
        ("policy", node_text(policy)),
        ("manifest_sha256", node_text(&release.sha256)),
        ("trace_sha256", node_text(&sha256_hex(raw_trace.as_bytes()))),
        ("base", node_text(&base_fingerprint)),
        ("final", node_text(&final_fingerprint)),
        ("delta", node_text(&delta_fingerprint)),
        ("eligible", node_int(safety.len())),
        ("violations", node_int(safety.iter().filter(|row| row.violation).count())),
        ("auxiliary", counts_for_summary),
    ]);
    // The numpy work the Python run observed, derived from the fixed schedule.
    let mut phases = BTreeMap::new();
    for (name, rows) in [
        ("base_train", balanced.len()),
        ("base_original_train_safety", count),
        ("candidate_train", balanced.len()),
        ("base_heldout", heldout.len()),
        ("candidate_heldout", heldout.len()),
        ("reference_heldout", heldout.len()),
        ("original_train_safety", count),
    ] {
        phases.insert(name.to_string(), phase(rows, layers));
    }
    let work = node_object(vec![
        ("schema", node_int(1)),
        ("device", node_text("cpu")),
        ("backend", node_text("numpy")),
        ("phases", Node::Object(phases)),
        ("partial_counts_are_observed_lower_bounds", Node::Bool(true)),
        ("internal_completion_work_unknown", Node::Bool(false)),
        ("capability_backwards", node_int(1)),
        ("objective_attempted", node_int(2)),
        ("objective_completed", node_int(2)),
    ]);
    let inventory: Values = base.keys().map(|name| (name.clone(), Vec::new())).collect();
    let names: Vec<&String> = base.keys().collect();
    let entries: [(&str, String); 20] = [
        ("contextual_training_optimizer", policy.to_string()),
        ("executed_contextual_training_optimizer", policy.to_string()),
        ("executed_contextual_training_objective", objective_name.to_string()),
        ("contextual_training_objective", objective_name.to_string()),
        ("contextual_training_strategy", STRATEGY.to_string()),
        ("contextual_candidate_eligibility", ELIGIBILITY.to_string()),
        ("full_projected_adam_config_v1", CONFIG_CANONICAL_TEXT.to_string()),
        ("original_train_retention_trace_v1", raw_trace.clone()),
        ("original_train_retention_summary_v1", canonical::to_string(&summary, Variant::Ascii)?),
        ("original_train_retention_manifest_sha256", release.sha256.clone()),
        ("strategy", STRATEGY.to_string()),
        ("artifact_training_strategy", STRATEGY.to_string()),
        ("underlying_training_available", "true".to_string()),
        ("training_scope", "full_encoder".to_string()),
        ("trained_parameter_names", serde_json::to_string(&names).map_err(|error| TrainingError::invalid(error.to_string()))?),
        ("trained_parameter_inventory_fingerprint", parameter_fingerprint(&inventory, Some(&shapes))?),
        ("base_parameter_fingerprint", base_fingerprint),
        ("updated_parameter_fingerprint", fingerprint(&current, &shapes)?),
        ("learning_rate", "0.003".to_string()),
        ("max_gradient", "0.05".to_string()),
    ];
    let mut metadata: BTreeMap<String, String> = entries.into_iter().map(|(key, value)| (key.to_string(), value)).collect();
    metadata.insert("text_preprocessing".to_string(), "canonical_detector_normalize_text".to_string());
    metadata.insert("full_adam_numpy_work_v1".to_string(), canonical::to_string(&work, Variant::Ascii)?);
    let mut executions = vec![
        ("training".to_string(), balanced.len()),
        ("base_heldout".to_string(), heldout.len()),
        ("candidate_heldout".to_string(), heldout.len()),
    ];
    if hinge {
        executions.push(("original_train_hinge".to_string(), 64 * count));
    }
    executions.push(("base_original_train_safety".to_string(), count));
    executions.push(("original_train_safety".to_string(), count));
    let gradients: F32Map = cumulative.iter().map(|(name, values)| (name.clone(), values.iter().map(|v| *v as f32).collect())).collect();
    Ok(Outcome { gradients, candidate: current, metadata, metrics, executions, trace: raw_trace, base_safety, safety, identities })
}
