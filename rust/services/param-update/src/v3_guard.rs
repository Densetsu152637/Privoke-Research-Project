//! The recomputed guard (stage V3-R2 of the routine-training plan).
//!
//! The trainer's evidence says the candidate beat the guard; that is a claim, not a control. Param-update judges the candidate
//! itself, before the commit transaction:
//!
//! 1. the scheduler's allocation of the request (`sampler`, `scope`, `seed`, `source_commitment`, `expected_base`) is looked up
//!    ([`Allocations`]): a request the scheduler never allocated is refused, and so is evidence that names another release or
//!    scope than the allocation (the release is the scheduler's choice, never the trainer's);
//! 2. the 16 guard rows are rebuilt from the frozen BC01 or AU3 release with
//!    [`privoke_curriculum::v3::routine_guard_rows`], the one definition of the selection, never from rows the trainer
//!    supplied; the guard targets of the evidence must be exactly those rows' targets;
//! 3. the Rust V3 encoder scores the guard with the base model and with the candidate (loaded through
//!    [`V3Model::with_tensors`], not through a pinned-manifest loader) from hash-checked copies of the store's bytes, and the
//!    candidate must improve the joint count without harming any action: the rule of `publication_passes`, over rows
//!    param-update chose and predictions param-update computed. The scoring is behind [`GuardScorer`] so that a test can drive
//!    every branch of the gate without a real-tier checkpoint.
//!
//! A failure is a `rejected` receipt with a reason; the checks run in `prepare`, before the transaction, for the one candidate
//! of the request (nothing is cached across requests).

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};

use privoke_contracts::json::Value;
use privoke_contracts::v3::{action_value, harm_count};
use privoke_curriculum::Example;
use privoke_curriculum::v3::{AU3_SAMPLER, BC01_SAMPLER, RoutineRelease, routine_guard_rows};
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

/// What the scheduler allocated to one request before it called the fuzzer. The release and the scope are the scheduler's
/// too: the evidence never chooses them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Allocation {
    /// The frozen release the guard is selected from: `existing_taxonomy_benign_common_frozen_stream_v1` (BC01) or
    /// `audience_common_frozen_stream_v1` (AU3).
    pub sampler: String,
    /// The scope of the fit (`heads` or `full_encoder`).
    pub scope: String,
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

/// How a candidate is scored against the guard rows: `true` when it beats its base without harming an action.
pub trait GuardScorer: Send + Sync + std::fmt::Debug {
    /// Score the admitted `manifest` (its parent is the base) on `rows`.
    fn passes(&self, store: &CheckpointStore, manifest: &Value, rows: &[Example]) -> Result<bool, StoreError>;
}

/// The Rust V3 encoder over the store's own bytes.
#[derive(Debug, Default, Clone, Copy)]
pub struct V3Scorer;

/// The name prefix of the scratch directories of a scoring (swept when a store is opened).
pub const SCRATCH_PREFIX: &str = "guard-";

/// A scratch directory under the store that is removed when it goes out of scope.
struct Scratch(std::path::PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Score `rows` with the model of `base_blob` and with the candidate of `candidate_blob` loaded over it, both built from the
/// store's hash-checked bytes (`config` and `vocab` are the candidate's). The model is loaded from verified copies in a scratch
/// directory, not from paths another process could have changed since.
pub fn score_blobs(
    store: &CheckpointStore,
    config: &str,
    vocab: &str,
    base_blob: &str,
    candidate_blob: &str,
    rows: &[Example],
) -> Result<(Assessment, Assessment), StoreError> {
    let scratch = Scratch(store.directory().join(format!("{SCRATCH_PREFIX}{}", uuid::Uuid::new_v4().simple())));
    std::fs::create_dir_all(&scratch.0)?;
    let (config_file, vocab_file, checkpoint) =
        (scratch.0.join("config.json"), scratch.0.join("vocab.txt"), scratch.0.join("base.safetensors"));
    std::fs::write(&config_file, store.read(config)?)?;
    std::fs::write(&vocab_file, store.read(vocab)?)?;
    std::fs::write(&checkpoint, store.read(base_blob)?)?;
    let candidate = safetensors::parse(&store.read(candidate_blob)?).map_err(semantic)?;
    score(&config_file, &vocab_file, &checkpoint, candidate, rows)
}

/// The four blobs a candidate is scored from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardInputs {
    /// The candidate's `config.json`.
    pub config: String,
    /// The candidate's `vocab.txt`.
    pub vocab: String,
    /// The checkpoint of the candidate's **parent**: the base the guard is scored against.
    pub base_blob: String,
    /// The candidate's own checkpoint.
    pub candidate_blob: String,
}

/// Which blobs score `manifest`: the base is its parent's checkpoint, never its own.
pub fn guard_inputs(store: &CheckpointStore, manifest: &Value) -> Result<GuardInputs, StoreError> {
    let parent = store.manifest(&text(manifest, "parent"))?;
    Ok(GuardInputs {
        config: text(manifest, "config"),
        vocab: text(manifest, "vocab"),
        base_blob: text(&parent, "blob"),
        candidate_blob: text(manifest, "blob"),
    })
}

impl GuardScorer for V3Scorer {
    fn passes(&self, store: &CheckpointStore, manifest: &Value, rows: &[Example]) -> Result<bool, StoreError> {
        let inputs = guard_inputs(store, manifest)?;
        let (base, candidate) = score_blobs(store, &inputs.config, &inputs.vocab, &inputs.base_blob, &inputs.candidate_blob, rows)?;
        Ok(passes(&base, &candidate))
    }
}

/// The guard gate: a [`CommitObserver`] whose `prepare` recomputes the guard of a candidate.
#[derive(Debug)]
pub struct GuardGate {
    sources: Arc<PinnedSources>,
    allocations: Arc<dyn Allocations>,
    scorer: Arc<dyn GuardScorer>,
}

impl GuardGate {
    /// A gate over the frozen releases and the scheduler's allocations, scoring with the Rust V3 encoder.
    pub fn new(sources: Arc<PinnedSources>, allocations: Arc<dyn Allocations>) -> Self {
        Self { sources, allocations, scorer: Arc::new(V3Scorer) }
    }

    /// The same gate with another scorer.
    #[must_use]
    pub fn with_scorer(mut self, scorer: Arc<dyn GuardScorer>) -> Self {
        self.scorer = scorer;
        self
    }

    /// The guard rows of an allocation, from the release the allocation names.
    pub fn rows(&self, allocation: &Allocation) -> Result<Vec<Example>, StoreError> {
        match allocation.sampler.as_str() {
            AU3_SAMPLER => {
                let release = self.sources.audience_release()?;
                Ok(routine_guard_rows(RoutineRelease::Au3(&release), allocation.seed, &allocation.source_commitment)?)
            }
            BC01_SAMPLER => {
                let sources = self.sources.bc01_sources()?;
                Ok(routine_guard_rows(RoutineRelease::Bc01(&sources), allocation.seed, &allocation.source_commitment)?)
            }
            other => Err(StoreError::Invalid(format!("No frozen release is named {other}."))),
        }
    }
}

impl CommitObserver for GuardGate {
    fn prepare(&self, candidate: &Candidate<'_>) -> Result<Option<String>, StoreError> {
        let Some(evidence) = candidate.evidence else { return Ok(None) };
        let Some(allocation) = self.allocations.allocation(candidate.request_id, candidate.model_id) else {
            return Ok(Some(REQUEST_NOT_ALLOCATED.to_string()));
        };
        // The scheduler chose the base, the release, the scope and the seed; the evidence must agree with every one of them.
        let named = [AU3_SAMPLER, BC01_SAMPLER].contains(&allocation.sampler.as_str());
        if allocation.expected_base != candidate.expected_base
            || !named
            || evidence["source"]["sampler"].as_str() != Some(allocation.sampler.as_str())
            || evidence["scope"].as_str() != Some(allocation.scope.as_str())
            || text(candidate.manifest, "scope") != allocation.scope
        {
            return Ok(Some(ALLOCATION_MISMATCH.to_string()));
        }
        if evidence["source_commitment"].as_str() != Some(allocation.source_commitment.as_str()) {
            return Ok(Some(COMMITMENT_MISMATCH.to_string()));
        }
        let rows = self.rows(&allocation)?;
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
        if self.scorer.passes(candidate.store, candidate.manifest, &rows)? { Ok(None) } else { Ok(Some(GUARD_RECOMPUTED.to_string())) }
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
        let allocation = Allocation {
            sampler: BC01_SAMPLER.to_string(),
            scope: "heads".to_string(),
            seed: 7,
            source_commitment: "c".repeat(64),
            expected_base: "b".repeat(64),
        };
        table.allocate("r1", "privoke-v3-efficient", allocation.clone());
        assert_eq!(table.allocation("r1", "privoke-v3-efficient"), Some(allocation));
        assert_eq!(table.allocation("r1", "privoke-v3-balanced"), None);
        assert_eq!(table.allocation("r2", "privoke-v3-efficient"), None);
    }
}
