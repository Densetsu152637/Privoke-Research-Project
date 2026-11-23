//! ORIGINAL TRAIN reference preparation: `LLM/privoke/reference_preparation.py` (`prepare_references`), and the teacher-neutral
//! parts the V3 retention references share ([`parse_bank`], [`row_of`], [`sensitivity_gap`], [`payload_of`]; the V3 teacher is
//! [`crate::retention_v3`]).
//!
//! One semantic prediction of the authenticated ORIGINAL teacher per approved bank row, recorded as the row of the frozen
//! reference file: the packed prediction, its rounded confidence, the union margin and the sensitivity gap in float32, and the
//! strict eligibility (sensitive prediction, margin and gap above `1e-6`). The canonical payload is the reference file the
//! retention release pins.
//!
//! The Python run dispatches each row through the runtime's `AnalyzePrompt` with the sole semantic layer and observes the
//! prediction that dispatch makes; here the same teacher model predicts the normalised text directly (the semantic layer
//! alone: no detector layer is involved), so the dispatcher's identity assertions have no counterpart. The final
//! `validate_references` of Python re-checks the rows just built and is not repeated.

use std::collections::BTreeSet;

use privoke_contracts::canonical::{self, Variant};
use privoke_contracts::digest::sha256_hex;
use privoke_contracts::fingerprint::parameter_fingerprint;
use privoke_contracts::json::parse as parse_node;
use privoke_rules::preprocessing::normalize_text;
use privoke_semantic::TinyModel;
use serde_json::{Value, json};

use crate::error::TrainingError;
use crate::retention::TEACHERS;
use crate::retention_common::{BANK_SHA256, BOUNDARY, EPSILON, is_sensitive, safety_margin, teacher_tensors};

fn invalid(message: &str) -> TrainingError {
    TrainingError::invalid(message)
}

/// One prepared reference row.
#[derive(Debug, Clone, PartialEq)]
pub struct PreparedRow {
    /// The bank id.
    pub id: String,
    /// The packed ORIGINAL prediction.
    pub packed: u16,
    /// The ORIGINAL confidence, clamped and rounded to three places.
    pub confidence: f64,
    /// The union margin of the float32 logits.
    pub margin: f64,
    /// The gap between the two largest sensitivity logits.
    pub sensitivity_gap: f64,
    /// Whether the row is eligible under the strict policy.
    pub eligible: bool,
}

impl PreparedRow {
    /// The row as the reference file writes it.
    pub fn to_json(&self) -> Value {
        json!({
            "id": self.id, "packed": self.packed, "confidence": self.confidence, "margin": self.margin,
            "sensitivity_gap": self.sensitivity_gap, "eligible": self.eligible
        })
    }
}

/// The two largest sensitivity logits' gap (`margin_and_gap`), in float32.
pub fn sensitivity_gap(logits: &[f32]) -> Result<f64, TrainingError> {
    let mut ordered = logits.to_vec();
    ordered.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    match ordered.as_slice() {
        [.., second, top] => Ok(f64::from(top - second)),
        _ => Err(invalid("ORIGINAL retention logits/margins must be finite.")),
    }
}

/// The reference row of a teacher prediction: its packed classification, raw confidence, union margin and sensitivity gap. The
/// confidence is clamped to `[0, 0.999]` here; the row is eligible under the strict policy (sensitive, margin and gap above
/// [`EPSILON`]).
pub fn row_of(id: &str, packed: u16, confidence: f64, margin: f64, gap: f64) -> PreparedRow {
    PreparedRow {
        id: id.to_string(),
        packed,
        confidence: confidence.clamp(0.0, 0.999),
        margin,
        sensitivity_gap: gap,
        eligible: is_sensitive(packed) && margin > EPSILON && gap > EPSILON,
    }
}

/// One row: the teacher's prediction on the normalised text, its margin and gap, and its eligibility
/// (`margin_and_gap` and the row of `prepare_references`).
pub fn prepared_row(model: &TinyModel, id: &str, text: &str) -> Result<PreparedRow, TrainingError> {
    let normalized = normalize_text(text).map_err(|error| TrainingError::invalid(format!("{error:?}")))?;
    let prediction = model.predict(&normalized);
    let margin = safety_margin(model.config(), &prediction)?;
    let gap = sensitivity_gap(&prediction.logits[0])?;
    Ok(row_of(id, prediction.decision.classification.pack(), prediction.decision.confidence, margin, gap))
}

/// The canonical reference payload (`canonical_bytes` of the schema 1 record: sorted keys, one LF).
pub fn payload(teacher: &Value, rows: &[PreparedRow]) -> Result<String, TrainingError> {
    payload_of(1, BANK_SHA256, teacher, rows)
}

/// The canonical reference payload of any schema and bank pin.
pub fn payload_of(schema: u64, bank_sha256: &str, teacher: &Value, rows: &[PreparedRow]) -> Result<String, TrainingError> {
    let boundary: Value = serde_json::from_str(BOUNDARY).map_err(|error| TrainingError::invalid(error.to_string()))?;
    let record = json!({
        "schema": schema, "teacher": teacher, "bank_sha256": bank_sha256, "boundary": boundary,
        "rows": rows.iter().map(PreparedRow::to_json).collect::<Vec<_>>()
    });
    canonical_json(&record)
}

/// The canonical text of a record (sorted keys, Python float layout, one LF).
pub fn canonical_json(record: &Value) -> Result<String, TrainingError> {
    // `serde_json` writes shortest round-trip floats; the contract writer then lays them out as Python does.
    let node = parse_node(&record.to_string()).map_err(|error| TrainingError::invalid(error.to_string()))?;
    Ok(canonical::to_string(&node, Variant::Utf8Lf)?)
}

/// What an approved retention bank must be: its pin, its row count and the number of groups the rows cover.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BankSpec<'a> {
    /// The sha256 of the bank file.
    pub sha256: &'a str,
    /// The rows of the bank.
    pub rows: usize,
    /// The groups the rows cover.
    pub groups: usize,
}

/// The independently approved ORIGINAL TRAIN bank (`BANK_SHA256`): 200 rows over 20 groups.
pub const APPROVED_BANK: BankSpec<'static> = BankSpec { sha256: BANK_SHA256, rows: 200, groups: 20 };

/// The rows of a bank that is the approved one: it hashes to the pin, holds the rows in ascending id order, only approved
/// positive TRAIN rows, and covers the groups. The messages are those of the Python validator.
pub fn parse_bank(bank: &[u8], spec: &BankSpec<'_>) -> Result<Vec<Value>, TrainingError> {
    let differs = || invalid("Retention bank differs from the independently approved200 TRAIN rows.");
    if sha256_hex(bank) != spec.sha256 {
        return Err(differs());
    }
    let bank_rows: Vec<Value> = serde_json::from_slice(bank).map_err(|_| differs())?;
    let ids: Vec<&str> = bank_rows.iter().filter_map(|row| row["id"].as_str()).collect();
    if bank_rows.len() != spec.rows || ids.len() != spec.rows || ids.windows(2).any(|pair| pair[0] > pair[1]) {
        return Err(differs());
    }
    let positive = |row: &Value| row["packed_classification"].as_u64().is_some_and(|packed| packed & 0b11 != 0);
    if bank_rows.iter().any(|row| row["metadata"]["taxonomy_partition"] != "train" || row["metadata"]["split"] != "train" || !positive(row))
    {
        return Err(invalid("Retention bank requires approved positive permanent TRAIN only."));
    }
    if bank_rows.iter().map(|row| row["metadata"]["group_id"].to_string()).collect::<BTreeSet<_>>().len() != spec.groups {
        return Err(invalid("Retention bank must cover exactly20 approved groups."));
    }
    Ok(bank_rows)
}

/// `prepare_references`: validates the bank and the teacher under their pins, predicts every bank row once and returns the
/// canonical payload and the teacher identity. `observer` receives the durable record of each row before and after its
/// prediction, as the Python `output` callback does.
pub fn prepare_references(
    bank: &[u8],
    teacher: &[u8],
    profile: &str,
    observer: &mut dyn FnMut(&Value),
) -> Result<(String, Value), TrainingError> {
    let bank_rows = parse_bank(bank, &APPROVED_BANK)?;
    let pinned = TEACHERS.iter().find(|(name, _)| *name == profile).map(|(_, sha)| *sha);
    if pinned != Some(sha256_hex(teacher).as_str()) {
        return Err(invalid("Retention teacher differs from the fixed ORIGINAL artifact bytes."));
    }
    let artifact: Value =
        serde_json::from_slice(teacher).map_err(|_| invalid("Retention teacher differs from the fixed ORIGINAL artifact bytes."))?;
    if artifact["model_id"] != format!("privoke-{profile}") {
        return Err(invalid("Retention teacher profile differs."));
    }
    let (parameters, shapes) = teacher_tensors(&artifact)?;
    let inventory: std::collections::BTreeMap<String, Vec<f64>> = parameters.keys().map(|name| (name.clone(), Vec::new())).collect();
    let identity = json!({
        "profile": profile, "file_sha256": pinned, "checksum": artifact["checksum"], "model_id": artifact["model_id"],
        "version": artifact["version"], "config": artifact["config"],
        "parameter_fingerprint": parameter_fingerprint(&parameters, Some(&shapes))?,
        "inventory_fingerprint": parameter_fingerprint(&inventory, Some(&shapes))?,
    });
    let model = TinyModel::from_artifact(&artifact)?;
    let mut rows = Vec::with_capacity(bank_rows.len());
    for source in &bank_rows {
        let (id, text) = (source["id"].as_str().unwrap_or_default(), source["text"].as_str().unwrap_or_default());
        observer(&json!({"id": id, "status": "attempted", "layers": [4]}));
        let row = prepared_row(&model, id, text)?;
        observer(&json!({
            "id": id, "status": "completed", "layers": [4], "reference": row.to_json(),
            "execution": {"layer": 4, "status": "ok"}, "teacher": identity
        }));
        rows.push(row);
    }
    Ok((payload(&identity, &rows)?, identity))
}
