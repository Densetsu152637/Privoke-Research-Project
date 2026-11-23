//! The scheduler on real weights (stage V3-R6): the real `scheduler::run` allocates and journals a HEADS and a FULL_ENCODER request
//! per tier; the fuzzer's routine engine, the real V3 runtime (`FitCandidate`, pinned admission) and the real param-update store run
//! in process behind it, with the full chain `main.rs` installs: pinned bootstrap, drift gate, guard gate over the journal, retention
//! gate over the real reference releases and the approved bank, and the signing publisher. Local only: without
//! `PRIVOKE_V3_SCHED_PACKAGES` it prints why it skipped and passes (CI has no weights).
//!
//! ```text
//! PRIVOKE_V3_SCHED_PACKAGES   the standard releases: privoke-v3-<tier>/{manifest,config,vocab,model.safetensors}
//! PRIVOKE_V3_SCHED_ORIGINALS  the ORIGINAL packages: <tier>/{manifest,config,vocab,model.safetensors}
//! PRIVOKE_V3_SCHED_RETENTION  the reference releases: <tier>/{references,manifest}.json for every tier
//! PRIVOKE_V3_SCHED_BANK       the approved ORIGINAL TRAIN bank
//! PRIVOKE_V3_SCHED_TIERS      comma list (default efficient)
//! PRIVOKE_V3_SCHED_STEPS      the frozen budget, 64 (default), 256 or 512
//! PRIVOKE_V3_SCHED_THREADS    the runtime's CPU threads (default 8)
//! ```
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use common::{Inputs, fixtures};
use privoke_contracts::proto::experimental_v3 as v3;
use privoke_contracts::proto::v1::{FuzzerTrainingRequest, FuzzerTrainingResponse};
use privoke_curriculum::audience::BUNDLED_MANIFEST_SHA256;
use privoke_curriculum::v3::{AU3_SOURCE_FILES, BC01_SOURCE_FILES, INPUTS, Policy};
use privoke_param_update::journal::{Journal, JournalAllocations, Stage};
use privoke_param_update::scheduler::{CallError, FuzzerCaller, FuzzerRequestConfig, PinnedCommitments, run};
use privoke_param_update::v3_guard::GuardGate;
use privoke_param_update::v3_policy::{DriftBounds, DriftGate};
use privoke_param_update::v3_publish::{Publisher, no_crash};
use privoke_param_update::v3_retention::{RetentionGate, RetentionReleases};
use privoke_param_update::v3_store::{AudienceSource, ChainObserver, CheckpointStore, CommitObserver, PinnedSources};
use privoke_v3_fuzzer::backend::{CheckpointBackend, FitBackend, blob_chunks};
use privoke_v3_fuzzer::contract::canonical;
use privoke_v3_fuzzer::cycle::{Engine, EngineParts};
use privoke_v3_fuzzer::source::{Closure, Sampler, python_source_hashes};
use privoke_v3_runtime::assets::Admission;
use privoke_v3_runtime::checkpoint::Checkpoint;
use privoke_v3_runtime::evidence::EVIDENCE_SOURCES;
use privoke_v3_runtime::fit::ScheduleSources;
use privoke_v3_runtime::service::{Runtime, RuntimeParts};
use tonic::Status;

fn say(text: &str) {
    use std::io::Write;
    let _ = writeln!(std::io::stderr(), "{text}");
}

fn status_of(error: privoke_param_update::v3_store::StoreError) -> Status {
    privoke_param_update::v3_store::service::status_of(error)
}

/// The checkpoint service of the run: the real param-update store.
struct StoreService(Arc<CheckpointStore>);

#[tonic::async_trait]
impl Checkpoint for StoreService {
    async fn resolve_current(&self, model_id: &str) -> Result<v3::Ref, Status> {
        self.0.resolve(model_id).map(|sha256| v3::Ref { sha256 }).map_err(status_of)
    }

    async fn fetch_blob(&self, sha256: &str) -> Result<Vec<v3::Chunk>, Status> {
        self.0.read(sha256).map(|payload| blob_chunks(&payload)).map_err(status_of)
    }

    async fn stage_checkpoint(&self, chunks: Vec<v3::Chunk>) -> Result<v3::Ref, Status> {
        let payload: Vec<u8> = chunks.iter().flat_map(|chunk| chunk.data.iter().copied()).collect();
        let manifest = chunks.first().map(|chunk| chunk.manifest_json.clone()).unwrap_or_default();
        self.0.stage(&payload, &manifest).map(|sha256| v3::Ref { sha256 }).map_err(status_of)
    }

    async fn health(&self) -> Result<v3::HealthResponse, Status> {
        Ok(v3::HealthResponse { ready: true, role: "checkpoint".to_string(), capabilities: BTreeMap::new() })
    }
}

#[tonic::async_trait]
impl CheckpointBackend for StoreService {
    async fn resolve_current(&self, model_id: &str) -> Result<v3::Ref, Status> {
        Checkpoint::resolve_current(self, model_id).await
    }

    async fn fetch_blob(&self, sha256: &str) -> Result<Vec<v3::Chunk>, Status> {
        Checkpoint::fetch_blob(self, sha256).await
    }

    async fn commit_candidate(&self, commit: v3::Commit) -> Result<v3::Receipt, Status> {
        let store = self.0.clone();
        tokio::task::spawn_blocking(move || store.commit(&commit).map_err(status_of)).await.unwrap()
    }

    async fn commit_status(&self, request_id: &str) -> Result<v3::Receipt, Status> {
        self.0.status(request_id).map_err(status_of)
    }

    async fn health(&self) -> Result<v3::HealthResponse, Status> {
        Ok(v3::HealthResponse { ready: true, role: "checkpoint".to_string(), capabilities: BTreeMap::new() })
    }
}

/// The real runtime as the fuzzer's fit backend.
struct LocalFit(Arc<Runtime>);

#[tonic::async_trait]
impl FitBackend for LocalFit {
    async fn fit_candidate(&self, request: v3::FitRequest, _timeout: Duration) -> Result<v3::FitResponse, Status> {
        self.0.fit_candidate(request, Arc::new(AtomicBool::new(true))).await
    }

    async fn fit_status(&self, request_id: &str) -> Result<v3::Receipt, Status> {
        self.0.fit_status(request_id).map_err(|error| Status::unknown(error.0))
    }

    async fn health(&self) -> Result<v3::HealthResponse, Status> {
        Ok(self.0.health())
    }
}

/// The fuzzer, in process: the scheduler's request goes straight to the engine.
struct InProcess(Arc<Engine>);

impl FuzzerCaller for InProcess {
    async fn call(&self, stage: Stage, request: FuzzerTrainingRequest, _timeout: Duration) -> Result<FuzzerTrainingResponse, CallError> {
        let scope = if stage == Stage::Heads { v3::Scope::Heads } else { v3::Scope::FullEncoder };
        self.0.run(request, scope).await.map_err(|status| CallError { code: Some(status.code()), message: status.message().to_string() })
    }
}

fn copy_checkout(root: &Path) {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    for relative in EVIDENCE_SOURCES.iter().copied().chain(BC01_SOURCE_FILES).chain(AU3_SOURCE_FILES) {
        let target = root.join(relative);
        std::fs::create_dir_all(target.parent().unwrap()).unwrap();
        std::fs::copy(repo.join(relative), target).unwrap();
    }
    for (_, relative, _) in INPUTS {
        let target = root.join(relative);
        std::fs::create_dir_all(target.parent().unwrap()).unwrap();
        std::fs::copy(fixtures().join("bc01").join(Path::new(relative).file_name().unwrap()), target).unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_scheduler_runs_a_real_round_through_the_full_chain() {
    let (Some(packages), Some(originals), Some(retention), Some(bank)) = (
        std::env::var_os("PRIVOKE_V3_SCHED_PACKAGES").map(PathBuf::from),
        std::env::var_os("PRIVOKE_V3_SCHED_ORIGINALS").map(PathBuf::from),
        std::env::var_os("PRIVOKE_V3_SCHED_RETENTION").map(PathBuf::from),
        std::env::var_os("PRIVOKE_V3_SCHED_BANK").map(PathBuf::from),
    ) else {
        say("PENDING: set PRIVOKE_V3_SCHED_PACKAGES, _ORIGINALS, _RETENTION and _BANK to run the real round (not run in CI)");
        return;
    };
    let env = |name: &str, default: &str| std::env::var(name).unwrap_or_else(|_| default.to_string());
    let steps: u32 = env("PRIVOKE_V3_SCHED_STEPS", "64").parse().unwrap();
    let threads: usize = env("PRIVOKE_V3_SCHED_THREADS", "8").parse().unwrap();
    let tiers: Vec<String> = env("PRIVOKE_V3_SCHED_TIERS", "efficient").split(',').map(str::to_string).collect();
    let root = tempfile::tempdir().unwrap();
    copy_checkout(root.path());
    let audience = (fixtures().join("au3/audience-v3-manifest-v1.json"), BUNDLED_MANIFEST_SHA256.to_string());
    let policy = Policy { steps };
    let policy_bytes = canonical(&policy.to_value()).unwrap();
    let inputs = Inputs::load();
    let schedules = |sampler| inputs.schedules(sampler, python_source_hashes(root.path(), sampler).unwrap());
    let param_update = Path::new(env!("CARGO_MANIFEST_DIR")).join("../param-update");

    for tier in &tiers {
        let model = format!("privoke-v3-{tier}");
        let state = tempfile::tempdir().unwrap();
        let journal = state.path().join("cycles.sqlite3");
        Journal::open(&journal).unwrap();
        let pinned = Arc::new(PinnedSources::new(
            INPUTS.iter().map(|(key, relative, _)| (*key, root.path().join(relative))).collect(),
            AudienceSource::Trusted { path: audience.0.clone(), sha256: audience.1.clone() },
        ));
        let bounds = DriftBounds::load(&param_update.join("config/v3-drift-bounds.toml")).unwrap();
        let releases = RetentionReleases::load(&retention, &bank).unwrap();
        let publisher = Arc::new(Publisher::new(state.path().join("published"), "v3r6-real", [9u8; 32], no_crash()).unwrap());
        // The chain of `main.rs`: drift, guard over the journal, retention, then the publisher.
        let observers: Vec<Arc<dyn CommitObserver>> = vec![
            Arc::new(DriftGate::new(bounds)),
            Arc::new(GuardGate::new(pinned.clone(), Arc::new(JournalAllocations::new(&journal)))),
            Arc::new(RetentionGate::new(releases)),
            publisher.clone(),
        ];
        let store = Arc::new(
            CheckpointStore::open(state.path().join("store"), pinned.clone())
                .unwrap()
                .with_observer(Arc::new(ChainObserver::new(observers))),
        );
        store.bootstrap_pinned(&originals.join(tier), &packages.join(&model)).unwrap();
        let service = Arc::new(StoreService(store.clone()));
        let runtime = Arc::new(
            Runtime::new(
                RuntimeParts {
                    directory: state.path().join("runtime"),
                    threads,
                    closure: Closure::Fixed("scheduler-real".to_string()),
                    admission: Admission::Pinned,
                    schedules: ScheduleSources { root: root.path().to_path_buf(), audience: Some(audience.clone()) },
                },
                service.clone(),
            )
            .await
            .unwrap(),
        );
        let parts = EngineParts {
            policy: policy.to_value(),
            schedules: schedules(Sampler::Bc01),
            directory: state.path().join("fuzzer"),
            fit_timeout: Duration::from_secs(7200),
            closure: Closure::Fixed("scheduler-real".to_string()),
        };
        let engine = Engine::new(parts, Arc::new(LocalFit(runtime)), service.clone()).await.unwrap();
        let engine = Arc::new(engine.with_routine(vec![schedules(Sampler::Bc01), schedules(Sampler::Au3)]).unwrap());
        let commitments = PinnedCommitments::new(&pinned, root.path(), &policy_bytes).unwrap();
        let config = FuzzerRequestConfig {
            target: "in-process".to_string(),
            prompt_count: (policy.window_batches() * 32) as i64,
            source_id: "scheduler-real".to_string(),
            timeout_seconds: 7200.0,
            interval_seconds: 0.0,
            initial_delay_seconds: 0.0,
            retry_seconds: 0.0,
            max_attempts: 1,
            seed: 20_261_124,
            state_path: journal.clone(),
            policy_file: PathBuf::from("unused"),
            tiers: vec![tier.clone()],
        };
        let before = store.resolve(&model).unwrap();
        say(&format!("SCHED {tier}: pinned release is current: {before}"));
        let started = std::time::Instant::now();
        run(&config, &InProcess(engine), store.as_ref(), &commitments).await.unwrap();
        say(&format!("SCHED {tier}: round took {:.1} s", started.elapsed().as_secs_f64()));
        let rows = Journal::open(&journal).unwrap().allocations(0).unwrap();
        assert_eq!(rows.len(), 2, "HEADS and FULL_ENCODER");
        for row in &rows {
            let receipt = store.status(&row.request_id).unwrap();
            say(&format!(
                "SCHED {tier}: {} request={} seed={} base={} journal={} receipt=({} reason={:?}) candidate={}",
                row.stage.name(),
                row.request_id,
                row.seed,
                row.expected_base,
                row.state,
                receipt.status,
                receipt.reason,
                receipt.candidate
            ));
            assert!(matches!(row.state.as_str(), "accepted" | "rejected"), "{row:?}");
            assert_eq!(receipt.status, if row.state == "accepted" { "applied" } else { "rejected" });
        }
        for row in store.publications(&model).unwrap() {
            say(&format!("SCHED {tier}: published sequence={} manifest={} key={}", row.sequence, row.manifest, row.key_id));
        }
        say(&format!("SCHED {tier}: serving {}", store.resolve(&model).unwrap()));
    }
}
