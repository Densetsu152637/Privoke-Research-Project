//! The frozen TRAIN window with exact checkpoint selection: `LLM/privoke/window_training.py` over
//! `privoke_model/window_training.py` (policy `full_projected_adam64_window_checkpoint_v1`).
//!
//! Ported: the window contract ([`Window::parse`]: sources, eight 64-row blocks, sixteen guard rows, the all-20 family
//! and separation checks, the multiplicity accounting), the block schedule ([`schedule`], sha256-derived permutations),
//! the component release ([`Release::load`]: pins, bank, task-logit references, ORIGINAL teacher identity, manifest),
//! the component hinge ([`component_deltas`], the retention auxiliary of the supervised gradient), the checkpoint
//! scoring, eligibility, progress and ranking ([`select`]), the unchanged held-out guard, and the retained trace and
//! summary (canonical JSON, with the float64 gradient and moment identities of `array_identity`).
//!
//! Not ported: the self-consistency validators of the trace (`validate_trace`, `validate_guard`, `validate_publication`)
//! and the numpy recomputation of the references (`decoded_logits`, `component_specs` against the file): a release is
//! authenticated by its sha256 pins, and the references are used as the pinned file gives them. Cancellation and the
//! worker wiring are not ported either.
//!
//! The directions come from a pluggable source ([`compute_directions`] is the Rust gradient), so a recorded Python
//! direction replays the Adam recurrence, the checkpoints and the selection exactly, as for the FULL fit.

use std::collections::{BTreeMap, BTreeSet};

use privoke_contracts::canonical::{self, Variant};
use privoke_contracts::digest::sha256_hex;
use privoke_contracts::fingerprint::parameter_fingerprint;
use privoke_contracts::json::{Value as Node, parse as parse_node};
use privoke_rules::preprocessing::normalize_text;
use privoke_semantic::TinyModel;
use serde_json::Value;

use crate::adam::{AdamState, F32Map, adam_step};
use crate::error::TrainingError;
use crate::net::{Params, Tensor, TinyNet};
use crate::objective::{Example, Objective, Target, class_balanced, fsum, supervised_deltas_with};
use crate::routes::local_training_losses;
use crate::rpc::{artifact_with, training_text_key};

/// The optimizer policy.
pub const POLICY: &str = "full_projected_adam64_window_checkpoint_v1";
/// The sampler of the frozen window.
pub const SAMPLER: &str = "taxonomy_benign_train_window_v1";
/// The components of the ORIGINAL retention, in the order of the contract.
pub const COMPONENTS: [&str; 5] = ["sensitivity", "severity", "category", "visibility", "action"];
/// The checkpoint steps.
pub const CHECKPOINTS: [usize; 8] = [8, 16, 24, 32, 40, 48, 56, 64];
/// The sha256 of the approved ORIGINAL TRAIN bank (`sensitive_retention.BANK_SHA256`).
pub const BANK_SHA256: &str = "c9b0b64133e6474487c1d3fe2ac9410c720b19a1f1571469dc8c3483f4e4a41a";
const WINDOW_CONFIG: &str = crate::admission::WINDOW_CONFIG_CANONICAL;
const CATEGORY_MASK: u16 = 0x7FE0;
const VISIBILITY_MASK: u16 = 0b1_1100;
const PU: u16 = 0b1_1100;
const IDENTIFIERS: u16 = 0b001_0000_0000_0000 | 0b010_0000_0000_0000;
const VISIBILITIES: [(&str, u16); 6] =
    [("P0", 0b00100), ("P1", 0b01000), ("P2", 0b01100), ("P3", 0b10000), ("P4", 0b10100), ("PU", 0b11100)];
const CATEGORIES: [(&str, u16); 10] = [
    ("HEALTH", 0b000_0000_0010_0000),
    ("POLITICS", 0b000_0000_0100_0000),
    ("RELIGION", 0b000_0000_1000_0000),
    ("CRIMINAL", 0b000_0001_0000_0000),
    ("FINANCIAL", 0b000_0010_0000_0000),
    ("SEXUAL", 0b000_0100_0000_0000),
    ("CHILD", 0b000_1000_0000_0000),
    ("LOCATION", 0b001_0000_0000_0000),
    ("IDENTITY", 0b010_0000_0000_0000),
    ("THIRD_PARTY", 0b100_0000_0000_0000),
];

type Values = BTreeMap<String, Vec<f64>>;
type Shapes = BTreeMap<String, Vec<u64>>;

fn invalid(message: &str) -> TrainingError {
    TrainingError::invalid(message)
}

fn is_sha256(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// A frozen source row.
#[derive(Debug, Clone, PartialEq)]
pub struct Row {
    /// The prompt text as frozen (the request normalises it).
    pub text: String,
    /// The packed gold classification.
    pub packed: u16,
    /// The raw weight.
    pub weight: f64,
    /// The source id.
    pub id: String,
    /// The family group.
    pub group: String,
    /// `family_kind == "taxonomy"`.
    pub taxonomy: bool,
}

/// The frozen TRAIN window.
#[derive(Debug, Clone)]
pub struct Window {
    /// The window seed, as the decimal digits of the JSON integer.
    pub seed: String,
    /// Eight blocks of 64 rows.
    pub blocks: Vec<Vec<Row>>,
    /// The sixteen guard rows.
    pub guard: Vec<Row>,
    /// The sha256 of the file bytes (the window pin).
    pub sha256: String,
}

fn text_of<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str).filter(|text| !text.is_empty())
}

fn parse_row(value: &Value) -> Result<(Row, String), TrainingError> {
    let malformed = || invalid("Malformed frozen source row.");
    let object = value.as_object().ok_or_else(malformed)?;
    let keys: BTreeSet<&str> = object.keys().map(String::as_str).collect();
    if keys != BTreeSet::from(["text", "packed", "weight", "id", "group", "partition", "family_kind"]) {
        return Err(malformed());
    }
    let packed = value["packed"].as_u64().and_then(|n| u16::try_from(n).ok()).ok_or_else(malformed)?;
    let weight = value["weight"].as_f64().filter(|w| w.is_finite() && *w > 0.0).ok_or_else(malformed)?;
    let (text, id, group) = (text_of(value, "text"), text_of(value, "id"), text_of(value, "group"));
    let (Some(text), Some(id), Some(group)) = (text, id, group) else { return Err(malformed()) };
    let taxonomy = match value["family_kind"].as_str() {
        Some("taxonomy") => true,
        Some("benign") => false,
        _ => return Err(malformed()),
    };
    if !VISIBILITIES.iter().any(|(_, bits)| *bits == packed & VISIBILITY_MASK) {
        return Err(malformed());
    }
    let partition = value["partition"].as_str().unwrap_or_default().to_string();
    Ok((Row { text: text.to_string(), packed, weight, id: id.to_string(), group: group.to_string(), taxonomy }, partition))
}

impl Window {
    /// `read_pinned` and `validate_window`: the file bytes must hash to `pin` (the canonical-bytes check of Python is
    /// implied by the pin) and satisfy the frozen window contract.
    pub fn parse(payload: &[u8], pin: &str) -> Result<Self, TrainingError> {
        if !is_sha256(pin) || sha256_hex(payload) != pin || payload.len() > 4 * 1024 * 1024 {
            return Err(invalid("Canonical immutable release differs from trusted pin."));
        }
        let value: Value = serde_json::from_slice(payload).map_err(|_| invalid("Invalid frozen TRAIN window contract."))?;
        let contract = || invalid("Invalid frozen TRAIN window contract.");
        let object = value.as_object().ok_or_else(contract)?;
        let keys: BTreeSet<&str> = object.keys().map(String::as_str).collect();
        let config: Value = serde_json::from_str(WINDOW_CONFIG).map_err(|_| contract())?;
        let sources_ok = value["sources"].as_object().is_some_and(|sources| {
            sources.keys().map(String::as_str).collect::<BTreeSet<_>>() == BTreeSet::from(["taxonomy", "benign", "pool", "proof"])
                && sources.values().all(|digest| digest.as_str().is_some_and(is_sha256))
        });
        let blocks = value["blocks"].as_array().ok_or_else(contract)?;
        let guard = value["guard"].as_array().ok_or_else(contract)?;
        if keys != BTreeSet::from(["schema", "sampler", "seed", "config", "sources", "blocks", "guard", "provenance"])
            || value["schema"] != 1
            || value["sampler"] != SAMPLER
            || (!value["seed"].is_i64() && !value["seed"].is_u64())
            || value["config"] != config
            || blocks.len() != 8
            || guard.len() != 16
            || !sources_ok
        {
            return Err(contract());
        }
        let (mut groups, mut guard_groups, mut ids, mut texts) = (BTreeSet::new(), BTreeSet::new(), Vec::new(), Vec::new());
        let mut parsed_blocks = Vec::new();
        for block in blocks {
            let rows = block["rows"].as_array().filter(|rows| rows.len() == 64 && block.as_object().is_some_and(|o| o.len() == 2));
            let (Some(rows), true) = (rows, block["seed"].is_i64() || block["seed"].is_u64()) else {
                return Err(invalid("Invalid frozen TRAIN block."));
            };
            let mut parsed = Vec::new();
            for row in rows {
                let (row, partition) = parse_row(row)?;
                if partition != "train" {
                    return Err(invalid("Window may access permanent TRAIN only."));
                }
                if row.taxonomy {
                    groups.insert(row.group.clone());
                }
                ids.push(row.id.clone());
                texts.push(training_text_key(&row.text));
                parsed.push(row);
            }
            parsed_blocks.push(parsed);
        }
        let mut parsed_guard = Vec::new();
        for row in guard {
            let (row, partition) = parse_row(row)?;
            if partition != "guard" {
                return Err(invalid("Guard must retain permanent guard membership."));
            }
            guard_groups.insert(row.group.clone());
            parsed_guard.push(row);
        }
        let train_texts: BTreeSet<&String> = texts.iter().collect();
        let guard_texts: BTreeSet<String> = parsed_guard.iter().map(|row| training_text_key(&row.text)).collect();
        if groups.len() != 20 || groups.intersection(&guard_groups).next().is_some() || train_texts.iter().any(|t| guard_texts.contains(*t))
        {
            return Err(invalid("Window requires all20 TRAIN families and separate guard groups/texts."));
        }
        let unique_ids = ids.iter().collect::<BTreeSet<_>>().len();
        let actual = serde_json::json!({
            "wire_rows": 512, "unique_source_ids": unique_ids, "unique_texts": train_texts.len(), "taxonomy_families": 20,
            "repeated_source_presentations": 512 - unique_ids, "fit_release": false
        });
        if value["provenance"] != actual {
            return Err(invalid("Window source multiplicity accounting differs."));
        }
        Ok(Self { seed: value["seed"].to_string(), blocks: parsed_blocks, guard: parsed_guard, sha256: pin.to_string() })
    }

    /// `flat_rows`: the 512 rows in block order.
    pub fn rows(&self) -> Vec<&Row> {
        self.blocks.iter().flatten().collect()
    }
}

/// `derived_seed`: eight bytes of the sha256 of the canonical `[sampler, seed, purpose, index]`.
pub fn derived_seed(seed: &str, purpose: &str, index: usize) -> u64 {
    let text = format!("[\"{SAMPLER}\",{seed},\"{purpose}\",{index}]");
    let digest = sha256_hex(text.as_bytes());
    u64::from_str_radix(&digest[..16], 16).unwrap_or(0)
}

/// `schedule`: eight permutations of the eight blocks, one per epoch.
pub fn schedule(seed: &str) -> Vec<usize> {
    let mut order = Vec::with_capacity(64);
    for epoch in 0..8 {
        let mut blocks: Vec<usize> = (0..8).collect();
        blocks.sort_by_key(|block| (derived_seed(seed, "epoch", epoch * 8 + block), *block));
        order.extend(blocks);
    }
    order
}

/// A frozen component margin of one ORIGINAL TRAIN reference.
#[derive(Debug, Clone, PartialEq)]
pub struct Entry {
    /// The head: 0 sensitivity, 1 visibility, 2 category.
    pub slot: usize,
    /// The capped target margin.
    pub target: f64,
    /// Category entries: the label index.
    pub index: usize,
    /// Category entries: the sign.
    pub sign: f64,
    /// Category entries: the threshold logit.
    pub offset: f64,
    /// Margin entries: the positive labels.
    pub positive: Vec<usize>,
    /// Margin entries: the negative labels.
    pub negative: Vec<usize>,
}

/// An eligible ORIGINAL TRAIN reference: the bank row and its frozen task-logit reference.
#[derive(Debug, Clone, PartialEq)]
pub struct Reference {
    /// The bank text, normalised for the serving model.
    pub text: String,
    /// The gold packed classification.
    pub gold: u16,
    /// The ORIGINAL prediction.
    pub original: u16,
    /// The ORIGINAL confidence.
    pub confidence: f64,
    /// The component entries, grouped by component.
    pub components: Vec<Vec<Entry>>,
}

/// An authenticated component release (the eligible references only).
#[derive(Debug, Clone)]
pub struct Release {
    /// The sha256 of the manifest bytes (the reference pin).
    pub sha256: String,
    /// The ORIGINAL teacher configuration.
    pub teacher_config: Value,
    /// The references with at least one component, in bank order.
    pub references: Vec<Reference>,
}

fn parse_entry(value: &Value) -> Result<Entry, TrainingError> {
    let bad = || invalid("Malformed authenticated task-logit reference.");
    let slot = match value["task"].as_str() {
        Some("sensitivity") => 0,
        Some("visibility") => 1,
        Some("category") => 2,
        _ => return Err(bad()),
    };
    let target = value["target"].as_f64().ok_or_else(bad)?;
    let list = |key: &str| -> Result<Vec<usize>, TrainingError> {
        value[key]
            .as_array()
            .map(|items| items.iter().filter_map(|n| n.as_u64().and_then(|n| usize::try_from(n).ok())).collect())
            .ok_or_else(bad)
    };
    if slot == 2 {
        let index = value["index"].as_u64().and_then(|n| usize::try_from(n).ok()).ok_or_else(bad)?;
        Ok(Entry {
            slot,
            target,
            index,
            sign: value["sign"].as_f64().ok_or_else(bad)?,
            offset: value["offset"].as_f64().ok_or_else(bad)?,
            positive: Vec::new(),
            negative: Vec::new(),
        })
    } else {
        Ok(Entry { slot, target, index: 0, sign: 0.0, offset: 0.0, positive: list("positive")?, negative: list("negative")? })
    }
}

impl Release {
    /// `load_components` and `validate_component_release` over the four sidecars: the manifest must hash to
    /// `trusted_sha256`, the ORIGINAL teacher to `teacher_sha256`, the bank to [`BANK_SHA256`], the references must be the
    /// bank's rows in order, name the authenticated teacher identity, and cover exactly 20 families, and the manifest
    /// must be the one the contract derives.
    pub fn load(
        bank: &[u8],
        references: &[u8],
        manifest: &[u8],
        teacher: &[u8],
        trusted_sha256: &str,
        teacher_sha256: &str,
    ) -> Result<Self, TrainingError> {
        if !is_sha256(trusted_sha256) || sha256_hex(manifest) != trusted_sha256 {
            return Err(invalid("Component release differs from distinct trusted configured pin."));
        }
        if !is_sha256(teacher_sha256) || sha256_hex(teacher) != teacher_sha256 {
            return Err(invalid("Component ORIGINAL teacher differs from independently configured accepted raw-file SHA."));
        }
        let differs = || invalid("Component reference teacher/bank/profile differs.");
        if sha256_hex(bank) != BANK_SHA256 {
            return Err(invalid("Retention bank differs from the independently approved200 TRAIN rows."));
        }
        let bank_rows: Vec<Value> = serde_json::from_slice(bank).map_err(|_| differs())?;
        let refs: Value = serde_json::from_slice(references).map_err(|_| differs())?;
        let manifest_value: Value = serde_json::from_slice(manifest).map_err(|_| differs())?;
        let artifact: Value = serde_json::from_slice(teacher).map_err(|_| differs())?;
        let profile = manifest_value["teacher"]["profile"].as_str().ok_or_else(differs)?;
        if artifact["model_id"] != format!("privoke-{profile}") {
            return Err(invalid("Component ORIGINAL teacher profile differs."));
        }
        let (parameters, shapes) = teacher_tensors(&artifact)?;
        let inventory: Values = parameters.keys().map(|name| (name.clone(), Vec::new())).collect();
        let identity = serde_json::json!({
            "profile": profile, "file_sha256": teacher_sha256, "checksum": artifact["checksum"], "model_id": artifact["model_id"],
            "version": artifact["version"], "config": artifact["config"],
            "parameter_fingerprint": parameter_fingerprint(&parameters, Some(&shapes))?,
            "inventory_fingerprint": parameter_fingerprint(&inventory, Some(&shapes))?,
        });
        let rows = refs["rows"].as_array().ok_or_else(differs)?;
        if refs.as_object().is_none_or(|o| {
            o.keys().map(String::as_str).collect::<BTreeSet<_>>() != BTreeSet::from(["schema", "teacher", "bank_sha256", "rows"])
        }) || refs["schema"] != 2
            || refs["teacher"] != identity
            || refs["bank_sha256"] != BANK_SHA256
            || rows.len() != bank_rows.len()
        {
            return Err(differs());
        }
        let (mut eligible, mut groups) = (Vec::new(), BTreeSet::new());
        for (source, row) in bank_rows.iter().zip(rows) {
            if row["id"] != source["id"] || row["gold"] != source["packed_classification"] {
                return Err(invalid("Malformed authenticated task-logit reference."));
            }
            let components = row["components"].as_object().ok_or_else(differs)?;
            if components.is_empty() {
                continue;
            }
            let gold = row["gold"].as_u64().and_then(|n| u16::try_from(n).ok()).ok_or_else(differs)?;
            let original = row["original"].as_u64().and_then(|n| u16::try_from(n).ok()).ok_or_else(differs)?;
            let text = source["text"].as_str().ok_or_else(differs)?;
            let grouped = components
                .values()
                .map(|entries| {
                    entries
                        .as_array()
                        .ok_or_else(differs)
                        .and_then(|items| items.iter().map(parse_entry).collect::<Result<Vec<Entry>, TrainingError>>())
                })
                .collect::<Result<Vec<Vec<Entry>>, _>>()?;
            groups.insert(source["metadata"]["group_id"].to_string());
            eligible.push(Reference {
                text: normalize_text(text).map_err(|error| TrainingError::invalid(format!("{error:?}")))?,
                gold,
                original,
                confidence: row["confidence"].as_f64().ok_or_else(differs)?,
                components: grouped,
            });
        }
        let expected = serde_json::json!({
            "schema": 2, "kind": "original_train_component_retention_v2", "teacher": identity, "bank_sha256": BANK_SHA256,
            "references_sha256": sha256_hex(references), "epsilon": 1e-6, "margin_cap": 1.0,
            "normalization": "category_bits_then_components_then_rows_v1", "coefficient": 1, "fit_release": false
        });
        if manifest_value != expected || groups.len() != 20 {
            return Err(invalid("Component manifest/eligible20-family coverage differs."));
        }
        Ok(Self { sha256: trusted_sha256.to_string(), teacher_config: artifact["config"].clone(), references: eligible })
    }
}

fn teacher_tensors(artifact: &Value) -> Result<(Values, Shapes), TrainingError> {
    let bad = || invalid("Component ORIGINAL teacher differs from independently configured accepted raw-file SHA.");
    let entries = artifact["parameters"].as_object().ok_or_else(bad)?;
    let (mut values, mut shapes) = (Values::new(), Shapes::new());
    for (name, tensor) in entries {
        let data = tensor["values"].as_array().ok_or_else(bad)?;
        values.insert(
            name.clone(),
            data.iter().map(|v| v.as_f64().map(|x| f64::from(x as f32))).collect::<Option<Vec<f64>>>().ok_or_else(bad)?,
        );
        let shape = tensor["shape"].as_array().ok_or_else(bad)?;
        shapes.insert(name.clone(), shape.iter().filter_map(Value::as_u64).collect());
    }
    Ok((values, shapes))
}

fn names_of(packed: u16) -> Target {
    let sensitivity = ["S0", "S1", "S2", "S3"][usize::from(packed & 0b11)].to_string();
    let visibility = VISIBILITIES.iter().find(|(_, bits)| *bits == packed & VISIBILITY_MASK).map_or("P0", |(name, _)| *name).to_string();
    let categories = CATEGORIES.iter().filter(|(_, bit)| packed & bit != 0).map(|(name, _)| (*name).to_string()).collect();
    Target { sensitivity, visibility, categories }
}

/// The training example of a frozen row (text normalised, as the serving layer does).
pub fn example_of(row: &Row) -> Result<Example, TrainingError> {
    let text = normalize_text(&row.text).map_err(|error| TrainingError::invalid(format!("{error:?}")))?;
    Ok(Example { text, target: names_of(row.packed), weight: row.weight })
}

/// `component_hinge` summed over the eligible references and divided by their number: the direction (the negative
/// gradient over every tensor) and the loss of the retention auxiliary. Each reference averages its entries within a
/// component, then its components; the margin of a category entry is `sign * (logit - offset)`, any other the largest
/// positive logit minus the largest negative one.
pub fn component_deltas(net: &TinyNet, references: &[Reference]) -> Result<(Values, f64), TrainingError> {
    if references.is_empty() {
        return Err(invalid("Component auxiliary requires one nonempty frozen specification per eligible row."));
    }
    let total = references.len() as f64;
    let mut grads = net.zero_grads();
    let mut loss = 0.0;
    for reference in references {
        let forward = net.forward(&net.token_ids(&reference.text))?;
        let mut dz: [Vec<f64>; 3] =
            [vec![0.0; forward.logits[0].len()], vec![0.0; forward.logits[1].len()], vec![0.0; forward.logits[2].len()]];
        let components = reference.components.len() as f64;
        let mut row_loss = 0.0;
        for entries in &reference.components {
            let share = 1.0 / (entries.len() as f64 * components);
            for entry in entries {
                let logits = &forward.logits[entry.slot];
                if entry.slot == 2 {
                    let margin = entry.sign * (logits[entry.index] - entry.offset);
                    let hinge = entry.target - margin;
                    row_loss += hinge.max(0.0) * share;
                    if hinge > 0.0 {
                        dz[2][entry.index] -= entry.sign * share / total;
                    }
                } else {
                    let best = |labels: &[usize]| -> Result<usize, TrainingError> {
                        let mut winner = *labels.first().ok_or_else(|| invalid("Component margin has an empty label set."))?;
                        for label in labels {
                            if logits[*label] > logits[winner] {
                                winner = *label;
                            }
                        }
                        Ok(winner)
                    };
                    let (up, down) = (best(&entry.positive)?, best(&entry.negative)?);
                    let hinge = entry.target - (logits[up] - logits[down]);
                    row_loss += hinge.max(0.0) * share;
                    if hinge > 0.0 {
                        dz[entry.slot][up] -= share / total;
                        dz[entry.slot][down] += share / total;
                    }
                }
            }
        }
        if !row_loss.is_finite() {
            return Err(invalid("Contextual supervised loss must be finite."));
        }
        loss += row_loss / total;
        net.backward(&forward, &dz, &mut grads);
    }
    let deltas: Values = grads.into_iter().map(|(name, g)| (name, g.into_iter().map(|v| -v).collect())).collect();
    if deltas.values().flatten().any(|v| !v.is_finite()) {
        return Err(invalid("Contextual supervised gradients must exist and be finite."));
    }
    Ok((deltas, loss))
}

fn sensitivity_bits(packed: u16) -> u16 {
    packed & 0b11
}

fn is_sensitive(packed: u16) -> bool {
    sensitivity_bits(packed) != 0 || packed & CATEGORY_MASK != 0
}

/// `action_value`: the production action as 0 allow, 1 warn, 2 block.
pub fn action_value(packed: u16, confidence: Option<f64>) -> i64 {
    let severity = i64::from(sensitivity_bits(packed));
    let identifiers = (packed & IDENTIFIERS).count_ones();
    if confidence.is_some_and(|value| value < 0.5) {
        return i64::from(severity == 3 || (severity == 2 && identifiers > 0));
    }
    if severity >= 2 {
        return severity - 1;
    }
    let visibility = packed & VISIBILITY_MASK;
    let private = visibility != PU && visibility >= 0b01100;
    i64::from(identifiers > 0 && (identifiers > 1 || private))
}

/// `component_predicates`: which components of the ORIGINAL retention a candidate prediction keeps.
pub fn component_predicates(gold: u16, original: u16, original_confidence: f64, candidate: u16, candidate_confidence: f64) -> [bool; 5] {
    let category_kept =
        CATEGORIES.iter().all(|(_, bit)| (original & bit != 0) != (gold & bit != 0) || ((candidate & bit != 0) == (gold & bit != 0)));
    [
        is_sensitive(candidate),
        sensitivity_bits(candidate) >= sensitivity_bits(gold).min(sensitivity_bits(original)),
        category_kept,
        original & VISIBILITY_MASK != gold & VISIBILITY_MASK || candidate & VISIBILITY_MASK == gold & VISIBILITY_MASK,
        action_value(candidate, Some(candidate_confidence))
            >= action_value(gold, None).min(action_value(original, Some(original_confidence))),
    ]
}

/// `checkpoint_counts`: the joint and per-component exact counts of the clean and sensitive rows.
pub fn checkpoint_counts(targets: &[u16], predictions: &[(u16, f64)]) -> Result<BTreeMap<String, i64>, TrainingError> {
    if targets.len() != predictions.len() {
        return Err(invalid("Checkpoint row membership differs."));
    }
    let mut counts: BTreeMap<String, i64> = ["all_joint", "clean_joint", "sensitive_joint", "clean_specificity", "sensitive_recall"]
        .into_iter()
        .map(|key| (key.to_string(), 0))
        .collect();
    for prefix in ["clean_", "sensitive_"] {
        for component in COMPONENTS {
            counts.insert(format!("{prefix}{component}"), 0);
        }
    }
    for (gold, (candidate, confidence)) in targets.iter().zip(predictions) {
        let prefix = if is_sensitive(*gold) { "sensitive_" } else { "clean_" };
        let correct = [
            is_sensitive(*candidate) == is_sensitive(*gold),
            sensitivity_bits(*candidate) == sensitivity_bits(*gold),
            candidate & CATEGORY_MASK == gold & CATEGORY_MASK,
            candidate & VISIBILITY_MASK == gold & VISIBILITY_MASK,
            action_value(*candidate, Some(*confidence)) == action_value(*gold, None),
        ];
        for (component, ok) in COMPONENTS.iter().zip(correct) {
            *counts.entry(format!("{prefix}{component}")).or_default() += i64::from(ok);
        }
        let joint = i64::from(correct.iter().all(|ok| *ok));
        *counts.entry(format!("{prefix}joint")).or_default() += joint;
        *counts.entry("all_joint".to_string()).or_default() += joint;
        let recall_key = if is_sensitive(*gold) { "sensitive_recall" } else { "clean_specificity" };
        *counts.entry(recall_key.to_string()).or_default() += i64::from(correct[0]);
    }
    Ok(counts)
}

/// One scored state: step 0 is the base, then every checkpoint.
#[derive(Debug, Clone)]
pub struct Checkpoint {
    /// The step.
    pub step: usize,
    /// The parameter fingerprint of the state.
    pub fingerprint: String,
    /// The joint and component counts on the window.
    pub counts: BTreeMap<String, i64>,
    /// The sum-margin objective on the (class-balanced) window.
    pub loss: f64,
    /// `[packed, confidence]` of every window row.
    pub predictions: Vec<(u16, f64)>,
    /// The same on the eligible ORIGINAL references.
    pub original_predictions: Vec<(u16, f64)>,
    /// References with any violated component.
    pub violations: usize,
    /// Violations per component, in [`COMPONENTS`] order.
    pub component_violations: [usize; 5],
}

/// `eligible`: no ORIGINAL violation and no count below the base.
pub fn eligible(checkpoint: &Checkpoint, baseline: &Checkpoint) -> bool {
    checkpoint.violations == 0 && baseline.counts.iter().all(|(key, base)| checkpoint.counts.get(key).is_some_and(|count| count >= base))
}

/// `progress`: a sensitive count rose above the base.
pub fn progress(checkpoint: &Checkpoint, baseline: &Checkpoint) -> bool {
    std::iter::once("sensitive_joint".to_string())
        .chain(COMPONENTS.iter().map(|component| format!("sensitive_{component}")))
        .any(|key| checkpoint.counts[&key] > baseline.counts[&key])
}

/// `rank`: the sensitive joint, the sensitive components, the all-row joint, then the lower loss and the earlier step.
pub fn rank(checkpoint: &Checkpoint) -> Vec<f64> {
    let counts = &checkpoint.counts;
    let mut key = vec![counts["sensitive_joint"] as f64];
    key.extend(COMPONENTS.iter().map(|component| counts[&format!("sensitive_{component}")] as f64));
    key.push(counts["all_joint"] as f64);
    key.push(-checkpoint.loss);
    key.push(-(checkpoint.step as f64));
    key
}

/// `select`: the best eligible checkpoint with sensitive progress, or the base.
pub fn select(checkpoints: &[Checkpoint]) -> &Checkpoint {
    let baseline = &checkpoints[0];
    let mut best = baseline;
    for candidate in &checkpoints[1..] {
        if eligible(candidate, baseline)
            && progress(candidate, baseline)
            && rank(candidate).partial_cmp(&rank(best)) == Some(std::cmp::Ordering::Greater)
        {
            best = candidate;
        }
    }
    best
}

/// The inputs of one Adam step's directions.
#[derive(Debug)]
pub struct Step<'a> {
    /// The 1-based step.
    pub index: usize,
    /// The window block of this step.
    pub block: usize,
    /// The model at the current transported state.
    pub net: &'a TinyNet,
    /// The 64 (class-balanced) rows of the block.
    pub rows: &'a [Example],
    /// The explicit main denominator: an eighth of the frozen window weight.
    pub denominator: f64,
    /// The eligible ORIGINAL references.
    pub references: &'a [Reference],
}

/// The two directions of a step and their losses.
#[derive(Debug, Clone)]
pub struct Directions {
    /// The main sum-margin direction of the block.
    pub main: Values,
    /// The main loss.
    pub main_loss: f64,
    /// The component-hinge direction.
    pub auxiliary: Values,
    /// The component-hinge loss.
    pub auxiliary_loss: f64,
}

/// The Rust gradient of both directions.
pub fn compute_directions(step: &Step<'_>) -> Result<Directions, TrainingError> {
    let main = supervised_deltas_with(step.net, step.rows, Objective::SumMargin, Some(step.denominator))?;
    let (auxiliary, auxiliary_loss) = component_deltas(step.net, step.references)?;
    Ok(Directions { main: main.deltas, main_loss: main.loss, auxiliary, auxiliary_loss })
}

/// The result of a window run.
#[derive(Debug, Clone)]
pub struct Outcome {
    /// `selected` or `no_update`.
    pub status: &'static str,
    /// `guard_passed`, `guard_failed`, `base_selected` or `no_transported_encoder_change`.
    pub reason: &'static str,
    /// The transported update of the selected checkpoint (empty for `no_update`).
    pub gradients: F32Map,
    /// The published candidate (the base for `no_update`).
    pub candidate: F32Map,
    /// The retained trace, canonical JSON (`train_window_trace_v1`).
    pub trace: String,
    /// The compact summary, canonical JSON (`train_window_summary_v1`).
    pub summary: String,
    /// Every scored state.
    pub checkpoints: Vec<Checkpoint>,
    /// The selected step (0 for the base).
    pub selected_step: usize,
    /// Per step: the identities of the combined direction and of the moments.
    pub identities: Vec<(String, String)>,
    /// The response metrics.
    pub metrics: BTreeMap<String, f64>,
}

fn node_object(entries: Vec<(&str, Node)>) -> Node {
    Node::Object(entries.into_iter().map(|(key, value)| (key.to_string(), value)).collect())
}

fn node_int(value: usize) -> Node {
    Node::Int(value.to_string())
}

fn node_text(value: &str) -> Node {
    Node::String(value.to_string())
}

fn node_floats(values: &[f64]) -> Node {
    Node::Array(values.iter().map(|value| Node::Float(*value)).collect())
}

fn node_rows(rows: &[(u16, f64)]) -> Node {
    Node::Array(
        rows.iter().map(|(packed, confidence)| Node::Array(vec![node_int(usize::from(*packed)), Node::Float(*confidence)])).collect(),
    )
}

/// `array_identity`: the sha256 of every array's name, a zero byte and its float64 little-endian bytes, by name.
pub fn array_identity(arrays: &Values) -> String {
    let mut bytes = Vec::new();
    for (name, values) in arrays {
        bytes.extend_from_slice(name.as_bytes());
        bytes.push(0);
        for value in values {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
    }
    sha256_hex(&bytes)
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

fn params_of(net: &TinyNet, values: &F32Map) -> Params {
    values
        .iter()
        .map(|(name, list)| {
            let shape = net.params.get(name).map(|tensor| tensor.shape.clone()).unwrap_or_default();
            (name.clone(), Tensor { shape, data: list.iter().map(|value| f64::from(*value)).collect() })
        })
        .collect()
}

fn fingerprint(values: &F32Map, shapes: &Shapes) -> Result<String, TrainingError> {
    Ok(parameter_fingerprint(&widen(values), Some(shapes))?)
}

fn predict(artifact: &Value, params: &Params, texts: &[String]) -> Result<Vec<(u16, f64)>, TrainingError> {
    let model = TinyModel::from_artifact(&artifact_with(artifact, params))?;
    Ok(texts
        .iter()
        .map(|text| {
            let decision = model.predict(text).decision;
            (decision.classification.pack(), decision.confidence.clamp(0.0, 0.999))
        })
        .collect())
}

struct Scorer<'a> {
    artifact: &'a Value,
    shapes: &'a Shapes,
    texts: Vec<String>,
    targets: Vec<u16>,
    examples: &'a [Example],
    references: &'a [Reference],
}

impl Scorer<'_> {
    /// `_score`: the window predictions, objective and counts, and the ORIGINAL predicates, of one state.
    fn score(&self, step: usize, net: &TinyNet, current: &F32Map) -> Result<Checkpoint, TrainingError> {
        let predictions = predict(self.artifact, &net.params, &self.texts)?;
        let loss = local_training_losses(net, self.examples, Objective::SumMargin)?.last().copied().unwrap_or(f64::NAN);
        let reference_texts: Vec<String> = self.references.iter().map(|reference| reference.text.clone()).collect();
        let original_predictions = predict(self.artifact, &net.params, &reference_texts)?;
        let mut component_violations = [0usize; 5];
        let mut violations = 0;
        for (reference, (candidate, confidence)) in self.references.iter().zip(&original_predictions) {
            let predicates = component_predicates(reference.gold, reference.original, reference.confidence, *candidate, *confidence);
            violations += usize::from(!predicates.iter().all(|ok| *ok));
            for (slot, ok) in predicates.iter().enumerate() {
                component_violations[slot] += usize::from(!ok);
            }
        }
        Ok(Checkpoint {
            step,
            fingerprint: fingerprint(current, self.shapes)?,
            counts: checkpoint_counts(&self.targets, &predictions)?,
            loss,
            predictions,
            original_predictions,
            violations,
            component_violations,
        })
    }
}

fn counts_node(counts: &BTreeMap<String, i64>) -> Node {
    Node::Object(counts.iter().map(|(key, value)| (key.clone(), Node::Int(value.to_string()))).collect())
}

fn checkpoint_node(checkpoint: &Checkpoint) -> Node {
    node_object(vec![
        ("step", node_int(checkpoint.step)),
        ("fingerprint", node_text(&checkpoint.fingerprint)),
        ("counts", counts_node(&checkpoint.counts)),
        ("loss", Node::Float(checkpoint.loss)),
        ("predictions", node_rows(&checkpoint.predictions)),
        ("original_predictions", node_rows(&checkpoint.original_predictions)),
        ("violations", node_int(checkpoint.violations)),
        (
            "component_violations",
            Node::Object(
                COMPONENTS
                    .iter()
                    .zip(checkpoint.component_violations)
                    .map(|(name, count)| ((*name).to_string(), node_int(count)))
                    .collect(),
            ),
        ),
    ])
}

struct Guard {
    node: Node,
    passed: bool,
}

/// `_guard`: the base and candidate on the sixteen unchanged guard rows.
fn guard(artifact: &Value, base: &Params, candidate: &Params, rows: &[Row]) -> Result<Guard, TrainingError> {
    let texts: Vec<String> = rows
        .iter()
        .map(|row| normalize_text(&row.text).map_err(|error| TrainingError::invalid(format!("{error:?}"))))
        .collect::<Result<_, _>>()?;
    let targets: Vec<u16> = rows.iter().map(|row| row.packed).collect();
    if !targets.iter().any(|t| is_sensitive(*t)) || targets.iter().all(|t| is_sensitive(*t)) {
        return Err(invalid("Unchanged guard requires both clean and sensitive rows."));
    }
    let before = predict(artifact, base, &texts)?;
    let after = predict(artifact, candidate, &texts)?;
    let counts = |predictions: &[(u16, f64)]| -> [usize; 3] {
        let (mut exact, mut recall, mut specificity) = (0, 0, 0);
        for (target, (packed, _)) in targets.iter().zip(predictions) {
            exact += usize::from(target == packed);
            if is_sensitive(*target) {
                recall += usize::from(is_sensitive(*packed));
            } else {
                specificity += usize::from(!is_sensitive(*packed));
            }
        }
        [exact, recall, specificity]
    };
    let (base_counts, candidate_counts) = (counts(&before), counts(&after));
    let mut regressions = 0usize;
    for ((target, (b, bc)), (a, ac)) in targets.iter().zip(&before).zip(&after) {
        let severity = sensitivity_bits(*a) < sensitivity_bits(*target).min(sensitivity_bits(*b));
        let action = action_value(*a, Some(*ac)) < action_value(*target, None).min(action_value(*b, Some(*bc)));
        regressions += usize::from(severity || action);
    }
    let rate = regressions as f64 / targets.len() as f64;
    let passed = base_counts.iter().zip(&candidate_counts).all(|(b, a)| a >= b) && rate == 0.0;
    let named = |values: [usize; 3]| {
        node_object(vec![("exact", node_int(values[0])), ("recall", node_int(values[1])), ("specificity", node_int(values[2]))])
    };
    Ok(Guard {
        node: node_object(vec![
            ("before", node_rows(&before)),
            ("after", node_rows(&after)),
            ("base_counts", named(base_counts)),
            ("candidate_counts", named(candidate_counts)),
            ("regression_rate", Node::Float(rate)),
            ("passed", Node::Bool(passed)),
        ]),
        passed,
    })
}

fn work_counts(directions: usize, rows: usize, layers: usize) -> Node {
    let batches = directions * rows.div_ceil(32);
    node_object(vec![
        ("directions_attempted", node_int(directions)),
        ("directions_completed", node_int(directions)),
        ("rows_attempted", node_int(directions * rows)),
        ("rows_completed", node_int(directions * rows)),
        ("microbatch_forward_attempted", node_int(batches)),
        ("microbatch_forward_completed", node_int(batches)),
        ("microbatch_backward_started", node_int(batches)),
        ("microbatch_backward_completed", node_int(batches)),
        ("torch_block_forwards_attempted", node_int(batches * layers)),
        ("torch_block_forwards_completed", node_int(batches * layers)),
    ])
}

fn phase(rows: usize, layers: usize) -> Node {
    node_object(vec![
        ("rows_attempted", node_int(rows)),
        ("rows_completed", node_int(rows)),
        ("blocks_attempted", node_int(rows * layers)),
        ("blocks_completed", node_int(rows * layers)),
    ])
}

/// The class-balance audit of `_class_balanced_examples`, as the trace's `weights`.
fn weight_audit(raw: &[Example], adjusted: &[Example]) -> Node {
    let sum = |rows: &[Example], label: bool| fsum(rows.iter().filter(|e| e.target.is_sensitive() == label).map(|e| e.weight));
    let (raw_clean, raw_sensitive) = (sum(raw, false), sum(raw, true));
    let (clean, sensitive) = (sum(adjusted, false), sum(adjusted, true));
    let total = fsum([raw_clean, raw_sensitive]);
    let clean_rows = raw.iter().filter(|e| !e.target.is_sensitive()).count() as f64;
    node_object(vec![
        ("training_clean_examples", Node::Float(clean_rows)),
        ("training_sensitive_examples", Node::Float(raw.len() as f64 - clean_rows)),
        ("raw_clean_weight", Node::Float(raw_clean)),
        ("raw_sensitive_weight", Node::Float(raw_sensitive)),
        ("raw_total_weight", Node::Float(total)),
        ("effective_clean_weight", Node::Float(clean)),
        ("effective_sensitive_weight", Node::Float(sensitive)),
        ("clean_objective_mass", Node::Float(clean / total)),
        ("sensitive_objective_mass", Node::Float(sensitive / total)),
    ])
}

/// The window loop: 64 Adam steps over the scheduled blocks, nine scored states, the TRAIN-only selection, and the
/// unchanged guard of the selected candidate. `artifact` is the base model; `source` yields each step's directions
/// ([`compute_directions`] for the Rust gradient).
pub fn run(
    artifact: &Value,
    window: &Window,
    release: &Release,
    source: &mut dyn FnMut(&Step<'_>) -> Result<Directions, TrainingError>,
) -> Result<Outcome, TrainingError> {
    let net = TinyNet::from_artifact(artifact)?;
    if artifact["config"] != release.teacher_config {
        return Err(invalid("CURRENT complete config/readout differs from authenticated ORIGINAL reference."));
    }
    let layers = net.config.num_layers;
    let raw: Vec<Example> = window.rows().into_iter().map(example_of).collect::<Result<_, _>>()?;
    let examples = class_balanced(&raw)?;
    let audit = weight_audit(&raw, &examples);
    let denominator = fsum(examples.iter().map(|e| e.weight)) / 8.0;
    let shapes = shapes_of(&net.params);
    let base: F32Map = net.params.iter().map(|(name, tensor)| (name.clone(), tensor.data.iter().map(|v| *v as f32).collect())).collect();
    let names: BTreeSet<String> = net.params.keys().cloned().collect();
    let scorer = Scorer {
        artifact,
        shapes: &shapes,
        texts: examples.iter().map(|e| e.text.clone()).collect(),
        targets: window.rows().iter().map(|row| row.packed).collect(),
        examples: &examples,
        references: &release.references,
    };
    let base_fingerprint = fingerprint(&base, &shapes)?;
    let mut checkpoints = vec![scorer.score(0, &net, &base)?];
    let (mut state, mut current_net, mut current) = (AdamState::new(&base), net.clone(), base.clone());
    let (mut steps, mut identities, mut saved) = (Vec::new(), Vec::new(), BTreeMap::new());
    for (index, block) in schedule(&window.seed).into_iter().enumerate() {
        let index = index + 1;
        let rows = &examples[block * 64..(block + 1) * 64];
        let directions = source(&Step { index, block, net: &current_net, rows, denominator, references: &release.references })?;
        let combined: Values = names
            .iter()
            .map(|name| {
                let (main, auxiliary) = (&directions.main[name], &directions.auxiliary[name]);
                (name.clone(), main.iter().zip(auxiliary).map(|(a, b)| a + b).collect())
            })
            .collect();
        let before = fingerprint(&current, &shapes)?;
        let outcome = adam_step(&base, &mut state, &combined, u32::try_from(index).unwrap_or(u32::MAX))?;
        let after = fingerprint(&outcome.candidate, &shapes)?;
        let (moment, variance) = state.moments();
        let mut moments = Values::new();
        for name in &names {
            moments.insert(format!("{name}:m"), moment[name].clone());
            moments.insert(format!("{name}:v"), variance[name].clone());
        }
        let (gradient_id, moments_id) = (array_identity(&combined), array_identity(&moments));
        let delta_id = parameter_fingerprint(&outcome.cumulative, Some(&shapes))?;
        steps.push(node_object(vec![
            ("step", node_int(index)),
            ("block", node_int(block)),
            ("before", node_text(&before)),
            ("after", node_text(&after)),
            ("main_loss", Node::Float(directions.main_loss)),
            ("auxiliary_loss", Node::Float(directions.auxiliary_loss)),
            ("clipped", node_int(outcome.clipped)),
            ("gradient", node_text(&gradient_id)),
            ("moments", node_text(&moments_id)),
            ("delta", node_text(&delta_id)),
        ]));
        identities.push((gradient_id, moments_id));
        let cumulative = outcome.cumulative;
        current_net = net.with_params(params_of(&net, &outcome.candidate))?;
        current = outcome.candidate;
        if CHECKPOINTS.contains(&index) {
            checkpoints.push(scorer.score(index, &current_net, &current)?);
            saved.insert(index, (cumulative.clone(), current.clone()));
        }
    }
    let terminal = fingerprint(&current, &shapes)?;
    let selected = select(&checkpoints).clone();
    let (mut status, mut reason) = ("no_update", "base_selected");
    let (mut gradients, mut candidate) = (F32Map::new(), base.clone());
    let mut guard_node = Node::Null;
    let mut guard_run = false;
    if selected.step != 0 {
        let (delta, state_params) = saved.get(&selected.step).cloned().ok_or_else(|| invalid("The selected checkpoint was not saved."))?;
        let encoder_changed = names
            .iter()
            .filter(|name| !name.starts_with("head.") && !name.starts_with("readout."))
            .any(|name| state_params[name] != base[name]);
        if encoder_changed {
            let verdict = guard(artifact, &net.params, &params_of(&net, &state_params), &window.guard)?;
            guard_run = true;
            guard_node = verdict.node;
            (status, reason) = if verdict.passed { ("selected", "guard_passed") } else { ("no_update", "guard_failed") };
        } else {
            reason = "no_transported_encoder_change";
        }
        if status == "selected" {
            gradients = delta.iter().map(|(name, values)| (name.clone(), values.iter().map(|v| *v as f32).collect())).collect();
            candidate = state_params;
        }
    }
    let selected_delta =
        if selected.step == 0 { Node::Null } else { node_text(&parameter_fingerprint(&saved[&selected.step].0, Some(&shapes))?) };
    let published = fingerprint(&candidate, &shapes)?;
    let mut phases = BTreeMap::new();
    for step in std::iter::once(0).chain(CHECKPOINTS) {
        phases.insert(format!("checkpoint_{step}_window"), phase(512, layers));
        phases.insert(format!("checkpoint_{step}_original_train"), phase(release.references.len(), layers));
    }
    if guard_run {
        phases.insert("base_heldout".to_string(), phase(16, layers));
        phases.insert("candidate_heldout".to_string(), phase(16, layers));
    }
    let config = parse_node(WINDOW_CONFIG).map_err(|_| invalid("Invalid frozen TRAIN window contract."))?;
    let trace = node_object(vec![
        ("schema", node_int(1)),
        ("policy", node_text(POLICY)),
        ("config", config),
        ("window_sha256", node_text(&window.sha256)),
        ("references_sha256", node_text(&release.sha256)),
        ("base", node_text(&base_fingerprint)),
        ("steps", Node::Array(steps)),
        ("checkpoints", Node::Array(checkpoints.iter().map(checkpoint_node).collect())),
        (
            "work",
            node_object(vec![
                ("schema", node_int(1)),
                ("backend", node_text("numpy_cpu_float32")),
                ("phases", Node::Object(phases.into_iter().collect())),
                ("objective_attempted", node_int(9)),
                ("objective_completed", node_int(9)),
            ]),
        ),
        ("main", work_counts(64, 64, layers)),
        ("auxiliary", work_counts(64, release.references.len(), layers)),
        ("guard", guard_node),
        ("weights", audit),
        ("terminal", node_text(&terminal)),
        ("selected_step", node_int(selected.step)),
        ("selected", node_text(&selected.fingerprint)),
        ("status", node_text(status)),
        ("reason", node_text(reason)),
        ("published", node_text(&published)),
        ("selected_delta", selected_delta.clone()),
    ]);
    let raw_trace = canonical::to_string(&trace, Variant::Ascii)?;
    let main_rows = 64 * 64;
    let checkpoint_rows = 9 * (512 + release.references.len());
    let summary = node_object(vec![
        ("schema", node_int(1)),
        ("policy", node_text(POLICY)),
        ("trace_sha256", node_text(&sha256_hex(raw_trace.as_bytes()))),
        ("window", node_text(&window.sha256)),
        ("references", node_text(&release.sha256)),
        ("base", node_text(&base_fingerprint)),
        ("terminal", node_text(&terminal)),
        ("selected", node_text(&selected.fingerprint)),
        ("selected_step", node_int(selected.step)),
        ("delta", selected_delta),
        ("published", node_text(&published)),
        ("status", node_text(status)),
        ("reason", node_text(reason)),
        ("main_rows", node_int(main_rows)),
        ("auxiliary_rows", node_int(64 * release.references.len())),
        ("checkpoint_rows", node_int(checkpoint_rows)),
        ("violations", node_int(selected.violations)),
        ("guard_passed", Node::Bool(guard_run && status == "selected")),
        ("sensitive_progress", Node::Bool(progress(&selected, &checkpoints[0]))),
    ]);
    let rows = window.rows();
    let exact = |checkpoint: &Checkpoint| {
        rows.iter().zip(&checkpoint.predictions).filter(|(row, (packed, _))| row.packed == *packed).count() as f64 / rows.len() as f64
    };
    let metrics = BTreeMap::from([
        ("examples".to_string(), 512.0),
        ("candidate_train_exact_match_rate".to_string(), exact(&selected)),
        ("exact_match_rate".to_string(), exact(&checkpoints[0])),
        ("candidate_train_objective_loss".to_string(), selected.loss),
        ("base_train_objective_loss".to_string(), checkpoints[0].loss),
    ]);
    Ok(Outcome {
        status,
        reason,
        gradients,
        candidate,
        trace: raw_trace,
        summary: canonical::to_string(&summary, Variant::Ascii)?,
        selected_step: selected.step,
        checkpoints,
        identities,
        metrics,
    })
}
