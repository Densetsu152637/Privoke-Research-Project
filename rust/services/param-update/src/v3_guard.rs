//! The recomputed guard (stage V3-R2 of the routine-training plan).
//!
//! The trainer's evidence says the candidate beat the guard; that is a claim, not a control. Param-update judges the candidate
//! itself, before the commit transaction:
//!
//! 1. the scheduler's allocation of the request (`seed`, `source_commitment`, `expected_base`) is looked up ([`Allocations`]):
//!    a request the scheduler never allocated is refused;
//! 2. the 16 guard rows are rebuilt from the frozen BC01 or AU3 release with
//!    [`privoke_curriculum::v3::routine_guard_rows`], the one definition of the selection, never from rows the trainer
//!    supplied; the guard targets of the evidence must be exactly those rows' targets;
//! 3. the Rust V3 encoder scores the guard with the base model and with the candidate (loaded through
//!    [`V3Model::with_tensors`], not through a pinned-manifest loader), and the candidate must improve the joint count without
//!    harming any action: the rule of `publication_passes`, over rows param-update chose and predictions param-update computed.
//!
//! A failure is a `rejected` receipt with a reason; the checks run in `prepare`, before the transaction, for the one candidate
//! of the request (nothing is cached across requests).

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};

use privoke_contracts::json::Value;
use privoke_contracts::v3::{action_value, harm_count};
use privoke_curriculum::Example;
use privoke_curriculum::v3::{AU3_SAMPLER, RoutineRelease, routine_guard_rows};
use privoke_semantic::V3Model;
use privoke_semantic::safetensors::{self, Tensor};
use serde_json::json;

use crate::v3_store::{Candidate, CheckpointStore, CommitObserver, PinnedSources, StoreError};

/// The commit named a request the scheduler never allocated.
pub const REQUEST_NOT_ALLOCATED: &str = "request_not_allocated";
/// The allocation's expected base is not the commit's.
pub const ALLOCATION_MISMATCH: &str = "allocation_mismatch";
/// The evidence commits to another source than the one the scheduler allocated.
pub const COMMITMENT_MISMATCH: &str = "commitment_mismatch";
/// The evidence guard rows are not the rows param-update rebuilt.
pub const GUARD_ROWS_DIFFER: &str = "guard_rows_differ";
/// The recomputed guard does not show the candidate better than its base.
pub const GUARD_RECOMPUTED: &str = "guard_recomputed";

/// What the scheduler allocated to one request before it called the fuzzer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Allocation {
    /// The routine seed.
    pub seed: u64,
    /// The commitment the guard selection is bound to.
    pub source_commitment: String,
    /// The base version the fit was allocated on.
    pub expected_base: String,
}

/// The scheduler's journal of allocations, as the guard gate reads it (stage V3-R6 implements it over `journal.rs`).
pub trait Allocations: Send + Sync + std::fmt::Debug {
    /// The allocation of `request_id` for `model_id`, if the scheduler made one.
    fn allocation(&self, request_id: &str, model_id: &str) -> Option<Allocation>;
}

/// An in-memory allocation table, for tests and the scheduler's first wiring.
#[derive(Debug, Default)]
pub struct StaticAllocations {
    table: Mutex<BTreeMap<(String, String), Allocation>>,
}

impl StaticAllocations {
    /// Record an allocation.
    pub fn allocate(&self, request_id: &str, model_id: &str, allocation: Allocation) {
        self.table.lock().unwrap_or_else(PoisonError::into_inner).insert((request_id.to_string(), model_id.to_string()), allocation);
    }
}

impl Allocations for StaticAllocations {
    fn allocation(&self, request_id: &str, model_id: &str) -> Option<Allocation> {
        self.table.lock().unwrap_or_else(PoisonError::into_inner).get(&(request_id.to_string(), model_id.to_string())).cloned()
    }
}

fn text(document: &Value, key: &str) -> String {
    match document {
        Value::Object(map) => match map.get(key) {
            Some(Value::String(text)) => text.clone(),
            _ => String::new(),
        },
        _ => String::new(),
    }
}

fn semantic(error: impl std::fmt::Display) -> StoreError {
    StoreError::Invalid(format!("Guard recomputation failed: {error}"))
}

/// The guard result of one model: the joint-correct count, the predictions and the per-row action values.
#[derive(Debug, Clone, PartialEq)]
pub struct Assessment {
    /// Rows whose packed prediction and action are the target's.
    pub joint: usize,
    /// The packed prediction of every row.
    pub predictions: Vec<u16>,
    rows: Vec<serde_json::Value>,
}

fn assess(model: &V3Model, rows: &[Example]) -> Result<Assessment, StoreError> {
    let mut results = Vec::with_capacity(rows.len());
    let mut predictions = Vec::with_capacity(rows.len());
    let mut joint = 0usize;
    for row in rows {
        let target = row.packed().ok_or_else(|| StoreError::Invalid("A guard row has no target.".to_string()))?;
        let prediction = model.predict(&row.text).map_err(semantic)?;
        let packed = prediction.classification.pack();
        let actual = action_value(packed, Some(prediction.confidence));
        let desired = action_value(target, Some(0.999));
        joint += usize::from(packed == target && actual == desired);
        predictions.push(packed);
        results.push(json!({"action_value": actual, "target_action_value": desired}));
    }
    Ok(Assessment { joint, predictions, rows: results })
}

/// `publication_passes` over recomputed guards: the candidate improves the joint count and harms no action.
pub fn passes(base: &Assessment, candidate: &Assessment) -> bool {
    candidate.joint > base.joint && harm_count(&json!(base.rows), &json!(candidate.rows)) == 0
}

/// Score `rows` with the base checkpoint and with a candidate loaded over it through [`V3Model::with_tensors`].
pub fn score(
    config: &Path,
    vocab: &Path,
    base_checkpoint: &Path,
    candidate: BTreeMap<String, Tensor>,
    rows: &[Example],
) -> Result<(Assessment, Assessment), StoreError> {
    let base = V3Model::from_files(config, base_checkpoint, vocab).map_err(semantic)?;
    let candidate = base.with_tensors(candidate).map_err(semantic)?;
    Ok((assess(&base, rows)?, assess(&candidate, rows)?))
}

/// The guard gate: a [`CommitObserver`] whose `prepare` recomputes the guard of a candidate.
#[derive(Debug)]
pub struct GuardGate {
    sources: Arc<PinnedSources>,
    allocations: Arc<dyn Allocations>,
}

impl GuardGate {
    /// A gate over the frozen releases and the scheduler's allocations.
    pub fn new(sources: Arc<PinnedSources>, allocations: Arc<dyn Allocations>) -> Self {
        Self { sources, allocations }
    }

    /// The guard rows of an allocation for a sampler.
    pub fn rows(&self, sampler: &str, allocation: &Allocation) -> Result<Vec<Example>, StoreError> {
        let rows = if sampler == AU3_SAMPLER {
            let release = self.sources.audience_release()?;
            routine_guard_rows(RoutineRelease::Au3(&release), allocation.seed, &allocation.source_commitment)?
        } else {
            let sources = self.sources.bc01_sources()?;
            routine_guard_rows(RoutineRelease::Bc01(&sources), allocation.seed, &allocation.source_commitment)?
        };
        Ok(rows)
    }

    /// Whether the candidate beats its base on `rows`, both scored here.
    pub fn recompute(store: &CheckpointStore, manifest: &Value, rows: &[Example]) -> Result<bool, StoreError> {
        let parent = store.manifest(&text(manifest, "parent"))?;
        let blobs = store.directory().join("blobs");
        let candidate = safetensors::parse(&store.read(&text(manifest, "blob"))?).map_err(semantic)?;
        let (base, candidate) = score(
            &blobs.join(text(manifest, "config")),
            &blobs.join(text(manifest, "vocab")),
            &blobs.join(text(&parent, "blob")),
            candidate,
            rows,
        )?;
        Ok(passes(&base, &candidate))
    }
}

impl CommitObserver for GuardGate {
    fn prepare(&self, candidate: &Candidate<'_>) -> Result<Option<String>, StoreError> {
        let Some(evidence) = candidate.evidence else { return Ok(None) };
        let Some(allocation) = self.allocations.allocation(candidate.request_id, candidate.model_id) else {
            return Ok(Some(REQUEST_NOT_ALLOCATED.to_string()));
        };
        if allocation.expected_base != candidate.expected_base {
            return Ok(Some(ALLOCATION_MISMATCH.to_string()));
        }
        if evidence["source_commitment"].as_str() != Some(allocation.source_commitment.as_str()) {
            return Ok(Some(COMMITMENT_MISMATCH.to_string()));
        }
        let sampler = evidence["source"]["sampler"].as_str().unwrap_or_default();
        let rows = self.rows(sampler, &allocation)?;
        // The rows of the evidence (the texts of its source record and the targets its guard scored) are the rebuilt rows.
        let reported_texts: Vec<Option<&str>> = evidence["source"]["guard_sidecar"]
            .as_array()
            .map_or_else(Vec::new, |items| items.iter().map(|item| item["text"].as_str()).collect());
        let wanted_texts: Vec<Option<&str>> = rows.iter().map(|row| Some(row.text.as_str())).collect();
        if reported_texts != wanted_texts {
            return Ok(Some(GUARD_ROWS_DIFFER.to_string()));
        }
        let targets: Vec<Option<u64>> = rows.iter().map(|row| row.packed().map(u64::from)).collect();
        for key in ["base_guard", "candidate_guard"] {
            let reported: Vec<Option<u64>> =
                evidence[key]["rows"].as_array().map_or_else(Vec::new, |items| items.iter().map(|item| item["target"].as_u64()).collect());
            if reported != targets {
                return Ok(Some(GUARD_ROWS_DIFFER.to_string()));
            }
        }
        if Self::recompute(candidate.store, candidate.manifest, &rows)? { Ok(None) } else { Ok(Some(GUARD_RECOMPUTED.to_string())) }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn assessment(joint: usize, actions: &[(i64, i64)]) -> Assessment {
        Assessment {
            joint,
            predictions: Vec::new(),
            rows: actions.iter().map(|(actual, desired)| json!({"action_value": actual, "target_action_value": desired})).collect(),
        }
    }

    #[test]
    fn a_candidate_passes_only_with_a_higher_joint_count_and_no_action_harm() {
        let base = assessment(3, &[(0, 0), (1, 2)]);
        assert!(passes(&base, &assessment(4, &[(0, 0), (2, 2)])));
        assert!(!passes(&base, &assessment(3, &[(0, 0), (2, 2)])), "no improvement");
        assert!(!passes(&base, &assessment(5, &[(1, 0), (2, 2)])), "an action moved away from its target");
    }

    #[test]
    fn the_allocation_table_answers_by_request_and_model() {
        let table = StaticAllocations::default();
        let allocation = Allocation { seed: 7, source_commitment: "c".repeat(64), expected_base: "b".repeat(64) };
        table.allocate("r1", "privoke-v3-efficient", allocation.clone());
        assert_eq!(table.allocation("r1", "privoke-v3-efficient"), Some(allocation));
        assert_eq!(table.allocation("r1", "privoke-v3-balanced"), None);
        assert_eq!(table.allocation("r2", "privoke-v3-efficient"), None);
    }
}
