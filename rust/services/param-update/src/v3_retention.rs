//! The V3 retention gate (stage V3-R9 of the routine-training plan, decision U3).
//!
//! A routine candidate must keep what the pinned standard release of its tier gets right on the approved ORIGINAL TRAIN bank
//! (the rule is [`privoke_training::retention_v3`]). Scoring the 200 bank rows with a tier's encoder takes from seconds
//! (efficient) to minutes (quality), so it must not run where it could stall anything else:
//!
//! 1. **Before the transaction.** The check runs in [`CommitObserver::prepare`], after admission and the cheaper gates and
//!    before the `BEGIN IMMEDIATE` of the compare-and-swap. Neither admission nor `prepare` holds the store's SQLite connection or
//!    any other lock, so a quality-tier check leaves every other call (other tiers' commits, status, resolve, rollback) free to
//!    complete; only the final compare-and-swap, which is short, takes the connection.
//! 2. **Bound to the candidate.** The verdict is recorded under `(model, candidate manifest SHA, request id)`; the candidate is
//!    scored from the store's hash-checked bytes (the parent's checkpoint as the shell, the candidate's tensors loaded over it
//!    with `V3Model::with_tensors`), never from a path another process could have changed.
//! 3. **The commit only checks that result.** [`CommitObserver::before_swap`], inside the transaction, looks the verdict up and
//!    refuses (rolls the transaction back) when there is none for this exact candidate or it did not pass. It runs no model.
//!
//! A candidate that regresses is a `rejected` receipt with [`RETENTION_REGRESSED`]; nothing is signed or published. A rollback is
//! exempt (it returns to a version that passed once). A commit whose base is already stale skips the check: the transaction will
//! reject it as `stale_base` whatever the verdict. A tier with no reference release is an error, not a pass.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};

use privoke_contracts::json::Value;
use privoke_semantic::V3Model;
use privoke_semantic::safetensors;
use privoke_training::retention_v3::{RetentionRelease, production_spec};
use rusqlite::Connection;

use crate::util::log;
use crate::v3_guard::{Scratch, guard_inputs};
use crate::v3_store::{Candidate, CheckpointStore, CommitObserver, StoreError, Swap};

/// The reason of a `rejected` receipt for a candidate that regressed on the retention bank.
pub const RETENTION_REGRESSED: &str = "retention_regressed";

/// The tiers, in the order of the reference releases.
const TIERS: [&str; 3] = ["efficient", "balanced", "quality"];

/// The threads of the matrix kernels of one retention scoring (the paper's Torch setting).
pub const DEFAULT_THREADS: usize = 4;

fn invalid(message: impl Into<String>) -> StoreError {
    StoreError::Invalid(message.into())
}

fn semantic(error: impl std::fmt::Display) -> StoreError {
    StoreError::Invalid(format!("Retention assessment failed: {error}"))
}

/// What one scoring found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Verdict {
    /// The eligible rows the candidate was judged on.
    pub eligible: usize,
    /// The rows it regressed on.
    pub violations: usize,
    /// The rows the release tolerates.
    pub max_violations: usize,
}

impl Verdict {
    /// Whether the candidate retains.
    pub fn passes(&self) -> bool {
        self.violations <= self.max_violations
    }
}

/// How a candidate is judged against a reference release.
pub trait RetentionScorer: Send + Sync + std::fmt::Debug {
    /// Judge the admitted `manifest` (its parent is the shell the candidate is loaded over) against `release`.
    fn assess(&self, store: &CheckpointStore, manifest: &Value, release: &RetentionRelease) -> Result<Verdict, StoreError>;
}

/// The Rust V3 encoder over the store's own bytes.
#[derive(Debug, Clone, Copy)]
pub struct V3RetentionScorer {
    threads: usize,
}

impl Default for V3RetentionScorer {
    fn default() -> Self {
        Self { threads: DEFAULT_THREADS }
    }
}

impl V3RetentionScorer {
    /// A scorer whose matrix kernels use `threads` threads.
    #[must_use]
    pub fn with_threads(mut self, threads: usize) -> Self {
        self.threads = threads.max(1);
        self
    }
}

/// Judge `candidate_blob` (a checkpoint of the store) loaded over `shell_blob` with the config and vocabulary named, against
/// `release`. Both are read from the store's hash-checked bytes into a scratch directory.
pub fn assess_blobs(
    store: &CheckpointStore,
    release: &RetentionRelease,
    config: &str,
    vocab: &str,
    shell_blob: &str,
    candidate_blob: &str,
    threads: usize,
) -> Result<Verdict, StoreError> {
    let scratch = Scratch::create(store)?;
    let (config_file, vocab_file, checkpoint) =
        (scratch.0.join("config.json"), scratch.0.join("vocab.txt"), scratch.0.join("shell.safetensors"));
    std::fs::write(&config_file, store.read(config)?)?;
    std::fs::write(&vocab_file, store.read(vocab)?)?;
    std::fs::write(&checkpoint, store.read(shell_blob)?)?;
    let tensors = safetensors::parse(&store.read(candidate_blob)?).map_err(semantic)?;
    let shell = V3Model::from_files(&config_file, &checkpoint, &vocab_file).map_err(semantic)?.with_threads(threads);
    let candidate = shell.with_tensors(tensors).map_err(semantic)?;
    drop(shell);
    let report = release.assess(&candidate).map_err(semantic)?;
    Ok(Verdict { eligible: report.rows.len(), violations: report.violations, max_violations: report.rule.max_violations })
}

impl RetentionScorer for V3RetentionScorer {
    fn assess(&self, store: &CheckpointStore, manifest: &Value, release: &RetentionRelease) -> Result<Verdict, StoreError> {
        let inputs = guard_inputs(store, manifest)?;
        assess_blobs(store, release, &inputs.config, &inputs.vocab, &inputs.base_blob, &inputs.candidate_blob, self.threads)
    }
}

/// The reference releases the gate judges by, one per model.
#[derive(Debug, Clone, Default)]
pub struct RetentionReleases {
    by_model: BTreeMap<String, Arc<RetentionRelease>>,
}

impl RetentionReleases {
    /// Releases from already authenticated parts (tests, and [`load`](Self::load)).
    pub fn from_releases(releases: impl IntoIterator<Item = RetentionRelease>) -> Self {
        Self { by_model: releases.into_iter().map(|release| (release.model_id.clone(), Arc::new(release))).collect() }
    }

    /// The production releases: `<root>/<tier>/{references,manifest}.json` for every tier, authenticated against the compiled
    /// pins and the approved bank at `bank`. A missing or differing file is an error: nothing is gated by a release that was not
    /// authenticated, and a tier without one is not served.
    pub fn load(root: &Path, bank: &Path) -> Result<Self, StoreError> {
        let bank_bytes = std::fs::read(bank)?;
        let mut releases = Vec::new();
        for tier in TIERS {
            let spec = production_spec(tier).ok_or_else(|| invalid(format!("No retention pin for tier {tier}.")))?;
            let read = |name: &str| std::fs::read(root.join(tier).join(name));
            let release = RetentionRelease::load(&bank_bytes, &read("references.json")?, &read("manifest.json")?, &spec)
                .map_err(|error| invalid(format!("Retention release of {tier}: {error}")))?;
            releases.push(release);
        }
        Ok(Self::from_releases(releases))
    }

    /// The release of a model.
    pub fn get(&self, model_id: &str) -> Option<&Arc<RetentionRelease>> {
        self.by_model.get(model_id)
    }
}

type VerdictKey = (String, String, String);

/// The retention gate: a [`CommitObserver`] whose `prepare` judges the candidate and whose `before_swap` only checks that result.
#[derive(Debug)]
pub struct RetentionGate {
    releases: RetentionReleases,
    scorer: Arc<dyn RetentionScorer>,
    /// The verdicts of the candidates between their `prepare` and the end of their commit, keyed by model, candidate manifest and
    /// request.
    verdicts: Mutex<BTreeMap<VerdictKey, Verdict>>,
}

impl RetentionGate {
    /// A gate over `releases`, scoring with the Rust V3 encoder.
    pub fn new(releases: RetentionReleases) -> Self {
        Self { releases, scorer: Arc::new(V3RetentionScorer::default()), verdicts: Mutex::new(BTreeMap::new()) }
    }

    /// The same gate with another scorer.
    #[must_use]
    pub fn with_scorer(mut self, scorer: Arc<dyn RetentionScorer>) -> Self {
        self.scorer = scorer;
        self
    }

    fn key(model_id: &str, manifest_sha: &str, request_id: &str) -> VerdictKey {
        (model_id.to_string(), manifest_sha.to_string(), request_id.to_string())
    }

    fn verdicts(&self) -> std::sync::MutexGuard<'_, BTreeMap<VerdictKey, Verdict>> {
        self.verdicts.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The recorded verdict of a candidate, if its `prepare` has run and its commit has not ended.
    pub fn verdict(&self, model_id: &str, manifest_sha: &str, request_id: &str) -> Option<Verdict> {
        self.verdicts().get(&Self::key(model_id, manifest_sha, request_id)).copied()
    }
}

impl CommitObserver for RetentionGate {
    fn prepare(&self, candidate: &Candidate<'_>) -> Result<Option<String>, StoreError> {
        // A rollback returns to a version that passed (or to the pinned release, the teacher itself).
        if candidate.evidence.is_none() {
            return Ok(None);
        }
        // A stale base is a `stale_base` receipt whatever the verdict; the expensive scoring is not spent on it. (Should the base
        // become current again before the transaction, `before_swap` finds no verdict and refuses.)
        if candidate.store.resolve(candidate.model_id)? != candidate.expected_base {
            return Ok(None);
        }
        let release = self
            .releases
            .get(candidate.model_id)
            .ok_or_else(|| invalid(format!("No retention release is configured for {}.", candidate.model_id)))?;
        let verdict = self.scorer.assess(candidate.store, candidate.manifest, release)?;
        log(format_args!(
            "V3 retention model={:?} candidate={} request={:?} eligible={} violations={} allowed={} release={}",
            candidate.model_id,
            candidate.manifest_sha,
            candidate.request_id,
            verdict.eligible,
            verdict.violations,
            verdict.max_violations,
            release.sha256
        ));
        self.verdicts().insert(Self::key(candidate.model_id, candidate.manifest_sha, candidate.request_id), verdict);
        Ok((!verdict.passes()).then(|| RETENTION_REGRESSED.to_string()))
    }

    fn before_swap(&self, swap: &Swap<'_>, _transaction: &Connection) -> Result<(), StoreError> {
        if swap.rollback {
            return Ok(());
        }
        match self.verdict(swap.model_id, swap.candidate, swap.request_id) {
            Some(verdict) if verdict.passes() => Ok(()),
            _ => Err(invalid("Retention has not passed for this candidate.")),
        }
    }

    fn after_commit(&self, swap: &Swap<'_>) -> Result<(), StoreError> {
        self.verdicts().remove(&Self::key(swap.model_id, swap.candidate, swap.request_id));
        Ok(())
    }

    fn abandon(&self, model_id: &str, manifest_sha: &str, request_id: &str) {
        self.verdicts().remove(&Self::key(model_id, manifest_sha, request_id));
    }
}
