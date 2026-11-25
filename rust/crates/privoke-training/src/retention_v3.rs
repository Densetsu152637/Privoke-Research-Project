//! The V3 ORIGINAL TRAIN retention (stage V3-R9 of the routine-training plan, decision U3).
//!
//! A routine candidate must keep what the pinned standard release of its tier already gets right on the approved ORIGINAL
//! TRAIN bank ([`BANK_SHA256`], 200 positive rows in 20 groups). The V1 retention (deleted in stage V3-R8b) audited a Tiny fit; this
//! module is the same idea for the three V3 heads, and it never trains: it freezes a teacher into a *reference release* and
//! judges candidates against it.
//!
//! # The reference release
//!
//! One release per tier, built from the pinned standard release (the routine root), never from the untrained `initials/`:
//!
//! * `references.json`: one row per bank row, in bank order: the teacher's packed prediction, its rounded confidence, the union
//!   margin and the sensitivity gap of its float32 logits, and the strict eligibility (a sensitive prediction with margin and
//!   gap above `1e-6`; the same boundary as V1). Canonical JSON (sorted keys, Python float layout, one LF).
//! * `manifest.json`: the identity of the teacher (the pinned release's manifest, ORIGINAL, checkpoint, config and vocabulary
//!   digests), the bank pin, the digest of `references.json`, the eligible ids and the rule. The SHA-256 of this file is the
//!   release's pin ([`RELEASE_PINS`]).
//!
//! The bank holds prompt text and is never part of a release: it is a separately mounted file that must hash to
//! [`BANK_SHA256`]. A release is authenticated by its manifest pin; [`RetentionRelease::load`] then re-derives everything the
//! manifest says from the bank and the references.
//!
//! # The rule
//!
//! For every eligible row with gold target `g`, teacher prediction `t` (confidence `c_t`) and candidate prediction `k` (confidence
//! `c_k`), the candidate *regresses* on the row when
//!
//! * it no longer predicts anything sensitive, or
//! * its severity drops below what the teacher kept: `min(sev(k), sev(g)) < min(sev(t), sev(g))`, or
//! * its served action falls below what the teacher's was, capped at the target's:
//!   `min(act(k, c_k), act(g)) < min(act(t, c_t), act(g))`.
//!
//! Capping at the target means a candidate may become *more* protective than the gold (and than the teacher) and is never
//! penalised for it. A candidate passes when it regresses on no more rows than the release allows (`max_violations`: in the
//! production releases 5% of the eligible rows, see [`production_allowance`]). The
//! candidate is always compared with the teacher, never with its parent, so retention is cumulative over every routine cycle
//! since the pinned release.
//!
//! Everything here is LLM-only: it runs the semantic model alone, never a detector layer.

use std::collections::BTreeSet;
use std::path::Path;

use privoke_contracts::digest::sha256_hex;
use privoke_contracts::v3::{TIERS, Tier, action_value, admitted_manifest};
use privoke_rules::classification::Classification;
use privoke_semantic::labels::{CATEGORY, SENSITIVITY, VISIBILITY, argmax, reported_confidence};
use privoke_semantic::math::{sigmoid_f32, softmax_f32};
use privoke_semantic::{V3Logits, V3Model};
use serde_json::{Value, json};

use crate::error::TrainingError;
use crate::reference::{APPROVED_BANK, BankSpec, PreparedRow, canonical_json, parse_bank, payload_of, row_of, sensitivity_gap};
use crate::retention_common::{BOUNDARY, EPSILON, is_sensitive, sensitivity_bits, union_margin_f32};

/// `schema` of both files of a V3 reference release.
pub const SCHEMA: u64 = 3;
/// `kind` of the manifest of a V3 reference release.
pub const KIND: &str = "v3_original_train_retention_v1";
/// The version of the rule above, as the manifest records it.
pub const RULE_VERSION: &str = "v3_target_capped_original_train_v1";
/// The tolerance of the production releases: one regressed row in this many eligible rows (5%), rounded down. A strict zero
/// is not usable: of the six routine calibration candidates of the efficient tier (V3-R5, standard-release base, three
/// cycles of HEADS and FULL) every one regressed on 1 to 4 of its 155 eligible rows, on a handful of fragile rows, while a
/// candidate that really forgot (every eligible row) regresses on all of them.
pub const PRODUCTION_TOLERANCE_DENOMINATOR: usize = 20;

/// The most regressed rows a production release allows for `eligible` eligible rows.
pub const fn production_allowance(eligible: usize) -> usize {
    eligible / PRODUCTION_TOLERANCE_DENOMINATOR
}
/// The probability at which a category is present.
const CATEGORY_THRESHOLD: f64 = 0.5;

fn invalid(message: impl Into<String>) -> TrainingError {
    TrainingError::invalid(message)
}

/// The pins of the production reference release of each tier: the SHA-256 of its `manifest.json` (which names the digest of
/// `references.json`). Rebuild them with the generator (`privoke-v3-retention-reference`) from the pinned standard releases and
/// the approved bank.
pub const RELEASE_PINS: [(&str, &str); 3] = [
    ("efficient", "72ca6cc073bdf5f75e07c5dd7070c0a6fe42f273f9374e6ea9fe75c63a3caf5a"),
    ("balanced", "c43862591e8caa505312ebbe5a307f4d673e08be20c331ec1855777f97bf0b3c"),
    ("quality", "d2472f6ea6281542063cce8fac37b01497ceec1e0d81a398d3cc2b3927cf47ec"),
];

/// What a reference release must be, independently of the files that claim to be one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReleaseSpec<'a> {
    /// `privoke-v3-<tier>`.
    pub model_id: &'a str,
    /// The pinned standard release the references were taken from (the compiled tier pin).
    pub teacher_manifest_sha256: &'a str,
    /// The SHA-256 of the release's `manifest.json`.
    pub manifest_sha256: &'a str,
    /// The approved bank.
    pub bank: BankSpec<'a>,
}

fn model_id_of(tier: &Tier) -> &'static str {
    match tier.name {
        "efficient" => "privoke-v3-efficient",
        "balanced" => "privoke-v3-balanced",
        _ => "privoke-v3-quality",
    }
}

/// The production spec of a tier (`efficient`, `balanced` or `quality`): the compiled standard release as the teacher, the
/// approved bank, and the release pin of [`RELEASE_PINS`].
pub fn production_spec(tier: &str) -> Option<ReleaseSpec<'static>> {
    let compiled: &Tier = TIERS.iter().find(|candidate| candidate.name == tier)?;
    let pin = RELEASE_PINS.iter().find(|(name, _)| *name == tier)?.1;
    Some(ReleaseSpec {
        model_id: model_id_of(compiled),
        teacher_manifest_sha256: compiled.manifest_pin,
        manifest_sha256: pin,
        bank: APPROVED_BANK,
    })
}

/// The production spec of a model id (`privoke-v3-<tier>`).
pub fn production_spec_of_model(model_id: &str) -> Option<ReleaseSpec<'static>> {
    TIERS.iter().map(|tier| tier.name).find(|name| format!("privoke-v3-{name}") == model_id).and_then(production_spec)
}

/// The tolerance a release carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rule {
    /// The most rows a passing candidate may regress on.
    pub max_violations: usize,
}

/// An eligible reference: the bank row and the teacher's frozen output.
#[derive(Debug, Clone, PartialEq)]
pub struct Reference {
    /// The bank id.
    pub id: String,
    /// The bank text (the model normalises and tokenises it itself).
    pub text: String,
    /// The gold packed classification.
    pub gold: u16,
    /// The teacher's packed prediction.
    pub original: u16,
    /// The teacher's rounded confidence.
    pub confidence: f64,
    /// The teacher's union margin (strictly positive for an eligible row).
    pub margin: f64,
}

/// An authenticated V3 reference release.
#[derive(Debug, Clone)]
pub struct RetentionRelease {
    /// The SHA-256 of `manifest.json` (the release pin).
    pub sha256: String,
    /// `privoke-v3-<tier>`.
    pub model_id: String,
    /// The teacher identity both files carry.
    pub teacher: Value,
    /// The rule of the release.
    pub rule: Rule,
    /// The eligible references, in bank order.
    pub references: Vec<Reference>,
}

fn is_sha256(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

impl RetentionRelease {
    /// Authenticate a release: `manifest` must hash to the pin of `spec`, `bank` to the bank pin, and the references must be
    /// exactly what the manifest says they are: the bank's rows in order, the teacher the spec names, the strict eligibility
    /// recomputed from each row's own numbers, every group covered, and the manifest the one this contract derives from them.
    pub fn load(bank: &[u8], references: &[u8], manifest: &[u8], spec: &ReleaseSpec<'_>) -> Result<Self, TrainingError> {
        if !is_sha256(spec.manifest_sha256) || sha256_hex(manifest) != spec.manifest_sha256 {
            return Err(invalid("Retention release manifest differs from its pin."));
        }
        let differs = || invalid("Retention manifest/reference/bank/teacher snapshot differs.");
        let bank_rows = parse_bank(bank, &spec.bank)?;
        let manifest_value: Value = serde_json::from_slice(manifest).map_err(|_| differs())?;
        let refs: Value = serde_json::from_slice(references).map_err(|_| differs())?;
        let teacher = manifest_value["teacher"].clone();
        if teacher["model_id"] != spec.model_id || teacher["manifest_sha256"] != spec.teacher_manifest_sha256 {
            return Err(invalid("Retention teacher is not the pinned standard release of this model."));
        }
        let boundary: Value = serde_json::from_str(BOUNDARY).map_err(|_| differs())?;
        let reference_error = || invalid("Retention references differ from original teacher/bank/boundary policy.");
        let rows = refs["rows"].as_array().ok_or_else(reference_error)?;
        let keys: BTreeSet<&str> = refs.as_object().map(|object| object.keys().map(String::as_str).collect()).unwrap_or_default();
        if keys != BTreeSet::from(["schema", "teacher", "bank_sha256", "boundary", "rows"])
            || refs["schema"] != SCHEMA
            || refs["teacher"] != teacher
            || refs["bank_sha256"] != spec.bank.sha256
            || refs["boundary"] != boundary
            || rows.len() != bank_rows.len()
        {
            return Err(reference_error());
        }
        let (mut groups, mut eligible_ids, mut eligible) = (BTreeSet::new(), Vec::new(), Vec::new());
        for (row, source) in rows.iter().zip(&bank_rows) {
            let malformed = || invalid("Malformed ordered ORIGINAL TRAIN reference.");
            let row_keys: BTreeSet<&str> = row.as_object().map(|object| object.keys().map(String::as_str).collect()).unwrap_or_default();
            let packed = row["packed"].as_u64().and_then(|n| u16::try_from(n).ok());
            let numbers = ["confidence", "margin", "sensitivity_gap"].map(|key| row[key].as_f64().filter(|value| value.is_finite()));
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
                eligible.push(Reference {
                    id: source["id"].as_str().unwrap_or_default().to_string(),
                    text: source["text"].as_str().ok_or_else(malformed)?.to_string(),
                    gold: source["packed_classification"].as_u64().and_then(|n| u16::try_from(n).ok()).ok_or_else(malformed)?,
                    original: packed,
                    confidence,
                    margin,
                });
            }
        }
        if groups.len() != spec.bank.groups {
            return Err(invalid("Retention requires eligible ORIGINAL coverage in every TRAIN group; no backfill."));
        }
        let max_violations = manifest_value["rule"]["max_violations"].as_u64().and_then(|n| usize::try_from(n).ok()).ok_or_else(differs)?;
        let expected = manifest_record(spec.bank.sha256, &teacher, &sha256_hex(references), &eligible_ids, max_violations);
        if manifest_value != expected {
            return Err(differs());
        }
        Ok(Self {
            sha256: spec.manifest_sha256.to_string(),
            model_id: spec.model_id.to_string(),
            teacher,
            rule: Rule { max_violations },
            references: eligible,
        })
    }

    /// Judge `model` (a candidate, loaded through [`V3Model::with_tensors`] or from files) against the references.
    pub fn assess(&self, model: &V3Model) -> Result<Report, TrainingError> {
        self.assess_with(|text| predict(model, text))
    }

    /// [`assess`](Self::assess) over any predictor (the packed prediction, the rounded confidence and the union margin of a text):
    /// the seam the rule is tested through without a model.
    pub fn assess_with(&self, mut predictor: impl FnMut(&str) -> Result<Prediction, TrainingError>) -> Result<Report, TrainingError> {
        let rows = self
            .references
            .iter()
            .map(|reference| Ok(judge(reference, &predictor(&reference.text)?)))
            .collect::<Result<Vec<RowReport>, TrainingError>>()?;
        let violations = rows.iter().filter(|row| row.violation).count();
        Ok(Report { rows, violations, rule: self.rule })
    }
}

/// One prediction as the retention reads it.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Prediction {
    /// The packed classification.
    pub packed: u16,
    /// The reported confidence (clamped, rounded to three places).
    pub confidence: f64,
    /// The union margin of the float32 logits.
    pub margin: f64,
}

/// The prediction and union margin of one text from a single forward pass: the packed classification, confidence and decision
/// rule of `V3Model::predict` (checked equal in the tests) and the margin of the same logits.
pub fn predict(model: &V3Model, text: &str) -> Result<Prediction, TrainingError> {
    let logits = model.logits(text)?;
    prediction_of(&logits).map(|(prediction, _gap)| prediction)
}

/// The prediction of one set of head logits, and the gap between the two largest sensitivity logits.
pub fn prediction_of(logits: &V3Logits) -> Result<(Prediction, f64), TrainingError> {
    let sensitivity = softmax_f32(&logits.sensitivity);
    let visibility = softmax_f32(&logits.visibility);
    let categories = sigmoid_f32(&logits.category);
    let (_, severity) = SENSITIVITY[argmax(&sensitivity)];
    let (_, visible) = VISIBILITY[argmax(&visibility)];
    let mut mask = 0u16;
    for ((_, bit), probability) in CATEGORY.iter().zip(&categories) {
        if *probability >= 0.5 {
            mask |= bit;
        }
    }
    let raw = sensitivity.iter().chain(&categories).copied().fold(f32::NEG_INFINITY, f32::max);
    let offset = (CATEGORY_THRESHOLD.ln() - (-CATEGORY_THRESHOLD).ln_1p()) as f32;
    let margin = union_margin_f32(&logits.sensitivity, 0, &logits.category, offset)?;
    let gap = sensitivity_gap(&logits.sensitivity)?;
    let packed = Classification::new(severity, visible, mask).pack();
    Ok((Prediction { packed, confidence: reported_confidence(f64::from(raw)), margin }, gap))
}

/// The row of one eligible reference under a candidate's prediction.
fn judge(reference: &Reference, candidate: &Prediction) -> RowReport {
    let actions = [
        action_value(reference.gold, None),
        action_value(reference.original, Some(reference.confidence)),
        action_value(candidate.packed, Some(candidate.confidence)),
    ];
    let regression = sensitivity_bits(candidate.packed).min(sensitivity_bits(reference.gold))
        < sensitivity_bits(reference.original).min(sensitivity_bits(reference.gold))
        || actions[2].min(actions[0]) < actions[1].min(actions[0]);
    RowReport {
        id: reference.id.clone(),
        packed: [reference.gold, reference.original, candidate.packed],
        actions,
        violation: !is_sensitive(candidate.packed) || regression,
        margin: [reference.margin, candidate.margin],
    }
}

/// One audited eligible row.
#[derive(Debug, Clone, PartialEq)]
pub struct RowReport {
    /// The bank id.
    pub id: String,
    /// Gold, teacher and candidate packed classifications.
    pub packed: [u16; 3],
    /// Gold, teacher and candidate actions (0 allow, 1 warn, 2 block).
    pub actions: [i64; 3],
    /// Whether the candidate regressed on the row.
    pub violation: bool,
    /// Teacher and candidate union margins.
    pub margin: [f64; 2],
}

/// The verdict of one candidate.
#[derive(Debug, Clone, PartialEq)]
pub struct Report {
    /// Every eligible row.
    pub rows: Vec<RowReport>,
    /// The rows the candidate regressed on.
    pub violations: usize,
    /// The rule of the release it was judged by.
    pub rule: Rule,
}

impl Report {
    /// Whether the candidate retains: at most `max_violations` regressed rows.
    pub fn passes(&self) -> bool {
        self.violations <= self.rule.max_violations
    }
}

fn manifest_record(bank_sha256: &str, teacher: &Value, references_sha256: &str, eligible_ids: &[Value], max_violations: usize) -> Value {
    json!({
        "schema": SCHEMA, "kind": KIND, "bank_sha256": bank_sha256,
        "boundary": serde_json::from_str::<Value>(BOUNDARY).unwrap_or(Value::Null),
        "teacher": teacher, "references_sha256": references_sha256, "eligible_ids": eligible_ids,
        "rule": {"version": RULE_VERSION, "max_violations": max_violations}, "fit_release": false
    })
}

/// The two files of a built reference release and the rows behind them.
#[derive(Debug, Clone)]
pub struct BuiltRelease {
    /// `references.json`.
    pub references: String,
    /// `manifest.json`.
    pub manifest: String,
    /// One prepared row per bank row.
    pub rows: Vec<PreparedRow>,
}

impl BuiltRelease {
    /// The SHA-256 of `manifest.json`: the pin of this release.
    pub fn manifest_sha256(&self) -> String {
        sha256_hex(self.manifest.as_bytes())
    }

    /// The SHA-256 of `references.json`.
    pub fn references_sha256(&self) -> String {
        sha256_hex(self.references.as_bytes())
    }
}

/// Freeze `model` into a reference release over the bank: one forward pass per bank row, with the teacher identity the files
/// carry and the tolerance `allowance` gives for the number of eligible rows. `observer` receives each row as it is prepared.
pub fn build_release(
    bank: &[u8],
    bank_spec: &BankSpec<'_>,
    model: &V3Model,
    teacher: &Value,
    allowance: &dyn Fn(usize) -> usize,
    observer: &mut dyn FnMut(&PreparedRow),
) -> Result<BuiltRelease, TrainingError> {
    let bank_rows = parse_bank(bank, bank_spec)?;
    let mut rows = Vec::with_capacity(bank_rows.len());
    for source in &bank_rows {
        let (id, text) = (source["id"].as_str().unwrap_or_default(), source["text"].as_str().unwrap_or_default());
        let logits = model.logits(text)?;
        let (prediction, gap) = prediction_of(&logits)?;
        let row = row_of(id, prediction.packed, prediction.confidence, prediction.margin, gap);
        observer(&row);
        rows.push(row);
    }
    let references = payload_of(SCHEMA, bank_spec.sha256, teacher, &rows)?;
    let eligible_ids: Vec<Value> = rows.iter().filter(|row| row.eligible).map(|row| Value::String(row.id.clone())).collect();
    let max_violations = allowance(eligible_ids.len());
    let manifest =
        canonical_json(&manifest_record(bank_spec.sha256, teacher, &sha256_hex(references.as_bytes()), &eligible_ids, max_violations))?;
    Ok(BuiltRelease { references, manifest, rows })
}

/// The identity of the teacher of a standard release: the compiled tier pin and the digests its manifest names.
pub fn standard_teacher(tier: &str, manifest: &[u8]) -> Result<Value, TrainingError> {
    let compiled = TIERS.iter().find(|candidate| candidate.name == tier).ok_or_else(|| invalid("No such V3 tier."))?;
    let admitted = admitted_manifest(manifest, Some(model_id_of(compiled))).map_err(|error| invalid(error.to_string()))?;
    Ok(json!({
        "model_id": admitted.model_id, "tier": admitted.tier, "scope": admitted.scope,
        "manifest_sha256": sha256_hex(manifest), "original_sha256": compiled.release_original,
        "blob_sha256": admitted.blob, "config_sha256": admitted.config, "vocab_sha256": admitted.vocab
    }))
}

/// Build the production reference release of `tier` from its standard release directory (`manifest.json`, `config.json`,
/// `vocab.txt`, `model.safetensors`, all checked against the compiled pin as the product loads them) and the approved bank.
pub fn build_production_release(
    tier: &str,
    release_dir: &Path,
    bank: &[u8],
    observer: &mut dyn FnMut(&PreparedRow),
) -> Result<BuiltRelease, TrainingError> {
    let spec = production_spec(tier).ok_or_else(|| invalid("No such V3 tier."))?;
    let manifest = std::fs::read(release_dir.join("manifest.json")).map_err(|error| invalid(error.to_string()))?;
    let teacher = standard_teacher(tier, &manifest)?;
    let model = V3Model::load_release(release_dir, spec.model_id)?;
    build_release(bank, &APPROVED_BANK, &model, &teacher, &production_allowance, observer)
}
