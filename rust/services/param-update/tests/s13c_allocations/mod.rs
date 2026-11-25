//! The allocation format of stage 13c (`S13C_ALLOCATIONS`), defined once and read strictly. Both 13c tests use it: the CI matrix
//! (`s13c_update_attacks.rs`) and the `s13c_journal_seed` helper of the real-weight and container legs
//! (`s13c_update_attacks_real.rs`); every 13d Python allocation writer emits it.
#![allow(dead_code)]

use std::collections::BTreeSet;

use privoke_curriculum::v3::{AU3_SAMPLER, BC01_SAMPLER};
use privoke_model_streaming::releases::STANDARD_IDS;
use privoke_param_update::journal::{AllocationRow, Stage};
use serde_json::Value as Json;

/// The fields of one allocation: the `v3_allocations` columns without `candidate` and `reason`, which are written only when a request
/// is settled.
pub const ALLOCATION_KEYS: [&str; 10] =
    ["request_id", "cycle", "model_id", "stage", "attempt", "sampler", "seed", "expected_base", "source_commitment", "state"];

/// 64 lowercase hexadecimal characters.
pub fn is_sha(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

/// `S13C_ALLOCATIONS`: a JSON array of objects that mirror the `v3_allocations` columns. Unknown and missing fields are refused.
pub fn parse_allocations(text: &str) -> Result<Vec<AllocationRow>, String> {
    let items: Vec<Json> = serde_json::from_str(text).map_err(|error| format!("not a JSON array: {error}"))?;
    let mut rows = Vec::new();
    for (index, item) in items.iter().enumerate() {
        let Some(map) = item.as_object() else { return Err(format!("item {index} is not an object")) };
        let keys: BTreeSet<&str> = map.keys().map(String::as_str).collect();
        if keys != ALLOCATION_KEYS.iter().copied().collect::<BTreeSet<_>>() {
            return Err(format!("item {index} has unknown or missing fields"));
        }
        let string = |key: &str| item[key].as_str().map(str::to_string).ok_or_else(|| format!("item {index}: {key} is not a string"));
        let integer =
            |key: &str| item[key].as_i64().filter(|number| *number >= 0).ok_or_else(|| format!("item {index}: {key} is not a count"));
        let request_id = string("request_id")?;
        if request_id.is_empty() || request_id.chars().count() > 200 {
            return Err(format!("item {index}: request_id is not bounded"));
        }
        let model_id = string("model_id")?;
        if !STANDARD_IDS.contains(&model_id.as_str()) {
            return Err(format!("item {index}: model_id is not a V3 tier"));
        }
        let stage = Stage::of(&string("stage")?).ok_or_else(|| format!("item {index}: stage is not heads or full_encoder"))?;
        let sampler = string("sampler")?;
        if ![AU3_SAMPLER, BC01_SAMPLER].contains(&sampler.as_str()) {
            return Err(format!("item {index}: sampler is not a frozen release"));
        }
        let seed = u32::try_from(integer("seed")?).map_err(|_| format!("item {index}: seed exceeds 32 bits"))?;
        let (expected_base, source_commitment) = (string("expected_base")?, string("source_commitment")?);
        if !is_sha(&expected_base) || !is_sha(&source_commitment) {
            return Err(format!("item {index}: a digest is not 64 lowercase hexadecimal characters"));
        }
        if string("state")? != "allocated" {
            return Err(format!("item {index}: state must be allocated"));
        }
        rows.push(AllocationRow {
            request_id,
            cycle: integer("cycle")?,
            model_id,
            stage,
            attempt: integer("attempt")?,
            sampler,
            seed,
            expected_base,
            source_commitment,
            state: "allocated".to_string(),
            candidate: None,
            reason: None,
        });
    }
    Ok(rows)
}

/// One allocation in the format, from a journal row (its `candidate` and `reason` are dropped).
pub fn allocation_json(row: &AllocationRow) -> Json {
    serde_json::json!({
        "request_id": row.request_id, "cycle": row.cycle, "model_id": row.model_id, "stage": row.stage.name(), "attempt": row.attempt,
        "sampler": row.sampler, "seed": row.seed, "expected_base": row.expected_base, "source_commitment": row.source_commitment,
        "state": "allocated"
    })
}
