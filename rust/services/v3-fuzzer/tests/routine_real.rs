//! The routine cycle on real weights (stage V3-R5): the fuzzer's routine engine, the real V3 runtime (`FitCandidate`, pinned
//! admission) and the real param-update checkpoint store, in process. Per tier, `PRIVOKE_V3_ROUTINE_CYCLES` routine cycles, each
//! HEADS and then FULL_ENCODER, with a scheduler-allocated seed per cycle and `[SEMANTIC]` only.
//!
//! It measures what stage V3-R5 needs: the wall seconds of every fit and cycle (the U5 threshold), and the L2 distance of every
//! candidate from its base (per update) and from the pinned ORIGINAL (cumulative), for the drift-bound calibration. Every candidate
//! and a `routine-calibration-<tier>.json` record are kept under `PRIVOKE_V3_ROUTINE_OUT`. Local only: without
//! `PRIVOKE_V3_ROUTINE_PACKAGES` it prints why it skipped and passes (CI has no weights).
//!
//! ```text
//! PRIVOKE_V3_ROUTINE_PACKAGES   a directory with one standard-release package per tier: privoke-v3-<tier>/{manifest,config,vocab,model.safetensors}
//! PRIVOKE_V3_ROUTINE_OUT        where the candidates and the records go (required)
//! PRIVOKE_V3_ROUTINE_TIERS      comma list (default efficient,balanced,quality)
//! PRIVOKE_V3_ROUTINE_CYCLES     routine cycles per tier (default 3)
//! PRIVOKE_V3_ROUTINE_STEPS      the frozen budget, 64 (default), 256 or 512
//! PRIVOKE_V3_ROUTINE_THREADS    the runtime's CPU threads (default 8)
//! PRIVOKE_V3_ROUTINE_SEED       the first scheduler seed (default 20261124)
//! ```
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

use common::{Inputs, fixtures};
use privoke_contracts::proto::experimental_v3 as v3;
use privoke_contracts::proto::v1::FuzzerTrainingRequest;
use privoke_curriculum::audience::BUNDLED_MANIFEST_SHA256;
use privoke_curriculum::v3::{BC01_SOURCE_FILES, INPUTS, Policy};
use privoke_param_update::v3_store::{AudienceSource, CheckpointStore, PinnedSources};
use privoke_semantic::safetensors::{Tensor, parse};
use privoke_v3_fuzzer::backend::{CheckpointBackend, FitBackend, blob_chunks};
use privoke_v3_fuzzer::contract::{canonical, digest};
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

/// The real store as the runtime's and the fuzzer's checkpoint service.
struct StoreService(Arc<CheckpointStore>);

fn status_of(error: privoke_param_update::v3_store::StoreError) -> Status {
    privoke_param_update::v3_store::service::status_of(error)
}

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
        self.0.commit(&commit).map_err(status_of)
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

/// L2 of `candidate - reference` over the heads tensors, the other tensors, and all of them.
fn l2(reference: &BTreeMap<String, Tensor>, candidate: &BTreeMap<String, Tensor>) -> serde_json::Value {
    let (mut heads, mut encoder) = (0f64, 0f64);
    let (mut changed_heads, mut changed_encoder) = (0usize, 0usize);
    for (name, tensor) in candidate {
        let base = &reference[name];
        let squares: f64 = tensor.data.iter().zip(&base.data).map(|(a, b)| f64::from(a - b).powi(2)).sum();
        let moved = tensor.sha256 != base.sha256;
        if name.starts_with("heads.") {
            heads += squares;
            changed_heads += usize::from(moved);
        } else {
            encoder += squares;
            changed_encoder += usize::from(moved);
        }
    }
    serde_json::json!({
        "l2_total": (heads + encoder).sqrt(), "l2_heads_tensors": heads.sqrt(), "l2_encoder_tensors": encoder.sqrt(),
        "changed_heads_tensors": changed_heads, "changed_encoder_tensors": changed_encoder
    })
}

fn weights_of(store: &CheckpointStore, manifest_sha: &str) -> (Vec<u8>, BTreeMap<String, Tensor>) {
    let manifest: serde_json::Value = serde_json::from_slice(&store.read(manifest_sha).unwrap()).unwrap();
    let bytes = store.read(manifest["blob"].as_str().unwrap()).unwrap();
    let tensors = parse(&bytes).unwrap();
    (bytes, tensors)
}

fn copy_checkout(root: &Path) {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    for relative in EVIDENCE_SOURCES.iter().copied().chain(BC01_SOURCE_FILES) {
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

#[tokio::test]
async fn routine_cycles_on_real_weights_are_timed_and_their_drift_measured() {
    let (Some(packages), Some(out)) =
        (std::env::var_os("PRIVOKE_V3_ROUTINE_PACKAGES").map(PathBuf::from), std::env::var_os("PRIVOKE_V3_ROUTINE_OUT").map(PathBuf::from))
    else {
        say("PENDING: set PRIVOKE_V3_ROUTINE_PACKAGES and PRIVOKE_V3_ROUTINE_OUT to run real-weight routine cycles (not run in CI)");
        return;
    };
    let env = |name: &str, default: &str| std::env::var(name).unwrap_or_else(|_| default.to_string());
    let cycles: u32 = env("PRIVOKE_V3_ROUTINE_CYCLES", "3").parse().unwrap();
    let steps: u32 = env("PRIVOKE_V3_ROUTINE_STEPS", "64").parse().unwrap();
    let threads: usize = env("PRIVOKE_V3_ROUTINE_THREADS", "8").parse().unwrap();
    let mut seed: u32 = env("PRIVOKE_V3_ROUTINE_SEED", "20261124").parse().unwrap();
    let tiers: Vec<String> = env("PRIVOKE_V3_ROUTINE_TIERS", "efficient,balanced,quality").split(',').map(str::to_string).collect();
    std::fs::create_dir_all(&out).unwrap();

    let root = tempfile::tempdir().unwrap();
    copy_checkout(root.path());
    let audience = (fixtures().join("au3/audience-v3-manifest-v1.json"), BUNDLED_MANIFEST_SHA256.to_string());
    let policy = Policy { steps };
    let policy_bytes = canonical(&policy.to_value()).unwrap();
    let policy_sha = digest(&policy_bytes);
    let inputs = Inputs::load();
    let schedules = |sampler| inputs.schedules(sampler, python_source_hashes(root.path(), sampler).unwrap());

    for tier in &tiers {
        let model = format!("privoke-v3-{tier}");
        let package = packages.join(&model);
        let state = tempfile::tempdir().unwrap();
        let pinned = PinnedSources::new(
            INPUTS.iter().map(|(key, relative, _)| (*key, root.path().join(relative))).collect(),
            AudienceSource::Trusted { path: audience.0.clone(), sha256: audience.1.clone() },
        );
        let store = Arc::new(CheckpointStore::open(state.path().join("store"), Arc::new(pinned)).unwrap());
        store.bootstrap(&package).unwrap();
        let service = Arc::new(StoreService(store.clone()));
        let runtime_parts = RuntimeParts {
            directory: state.path().join("runtime"),
            threads,
            closure: Closure::Fixed("routine-real".to_string()),
            admission: Admission::Pinned,
            schedules: ScheduleSources { root: root.path().to_path_buf(), audience: Some(audience.clone()) },
        };
        let runtime = Arc::new(Runtime::new(runtime_parts, service.clone()).await.unwrap());
        let parts = EngineParts {
            policy: policy.to_value(),
            schedules: schedules(Sampler::Bc01),
            directory: state.path().join("fuzzer"),
            fit_timeout: Duration::from_secs(7200),
            closure: Closure::Fixed("routine-real".to_string()),
        };
        let engine = Engine::new(parts, Arc::new(LocalFit(runtime)), service.clone()).await.unwrap();
        let engine = engine.with_routine(vec![schedules(Sampler::Bc01), schedules(Sampler::Au3)]).unwrap();

        let original = CheckpointBackend::resolve_current(service.as_ref(), &model).await.unwrap().sha256;
        let (_, original_tensors) = weights_of(&store, &original);
        let mut records = Vec::new();
        let mut round_seconds = 0f64;
        for cycle in 0..cycles {
            let sampler = if cycle % 2 == 0 { Sampler::Bc01 } else { Sampler::Au3 };
            let cycle_started = Instant::now();
            for (stage, scope) in [("heads", v3::Scope::Heads), ("full", v3::Scope::FullEncoder)] {
                seed += 1;
                // The scheduler of this test: allocate the identity, the seed and the base from the store, journal, call.
                let base = CheckpointBackend::resolve_current(service.as_ref(), &model).await.unwrap().sha256;
                let id = format!("routine-{tier}-c{cycle}-{stage}-{seed}");
                let request = FuzzerTrainingRequest {
                    request_id: id.clone(),
                    source_id: String::new(),
                    model_id: model.clone(),
                    prompt_count: (policy.window_batches() * 32) as u32,
                    seed,
                    metadata: [
                        ("expected_base", base.clone()),
                        ("policy_sha256", policy_sha.clone()),
                        ("sampler", sampler.name().to_string()),
                    ]
                    .into_iter()
                    .map(|(key, item)| (key.to_string(), item))
                    .collect(),
                };
                let started = Instant::now();
                let response = engine.run(request, scope).await.unwrap_or_else(|status| panic!("{id}: {status:?}"));
                let seconds = started.elapsed().as_secs_f64();
                // Executed layer: the evidence the runtime recorded names the semantic layer alone.
                let evidence: serde_json::Value =
                    serde_json::from_slice(&std::fs::read(engine.work_directory(&id).join("evidence.json")).unwrap()).unwrap();
                assert_eq!(evidence["layers"], serde_json::json!([4]), "{id}: the executed layer");
                assert_eq!(evidence["phases"]["training"]["layer"], 4);
                let fit_request = v3::FitRequest::decode_from(&std::fs::read(engine.work_directory(&id).join("fit-request.pb")).unwrap());
                assert_eq!(fit_request.layers, vec![4], "{id}: sent [SEMANTIC] only");

                let candidate_manifest = response.metadata["candidate_manifest"].clone();
                let (_, base_tensors) = weights_of(&store, &base);
                let (candidate_bytes, candidate_tensors) = weights_of(&store, &candidate_manifest);
                let guard = |key: &str| (evidence[key]["joint_correct"].clone(), evidence[key]["examples"].clone());
                let mut record = l2(&base_tensors, &candidate_tensors);
                let cumulative = l2(&original_tensors, &candidate_tensors);
                record["cumulative_l2_total"] = cumulative["l2_total"].clone();
                record["cumulative_l2_heads_tensors"] = cumulative["l2_heads_tensors"].clone();
                record["cumulative_l2_encoder_tensors"] = cumulative["l2_encoder_tensors"].clone();
                record["model_id"] = model.clone().into();
                record["cycle"] = cycle.into();
                record["scope"] = stage.into();
                record["sampler"] = sampler.name().into();
                record["scheduler_seed"] = seed.into();
                record["schedule_seed"] = response.metadata["schedule_seed"].clone().into();
                record["routine_commitment"] = response.metadata["routine_commitment"].clone().into();
                record["source_commitment"] = response.metadata["source_commitment"].clone().into();
                record["seconds"] = seconds.into();
                record["steps"] = steps.into();
                record["threads"] = threads.into();
                record["publication_status"] = response.metadata["publication_status"].clone().into();
                record["receipt"] = response.message.clone().into();
                record["guard_passed"] = response.metadata["guard_passed"].clone().into();
                record["base_guard_joint_correct_of_examples"] = serde_json::json!(guard("base_guard"));
                record["candidate_guard_joint_correct_of_examples"] = serde_json::json!(guard("candidate_guard"));
                record["layers"] = evidence["layers"].clone();
                record["base_manifest_sha256"] = base.clone().into();
                record["candidate_manifest_sha256"] = candidate_manifest.clone().into();
                record["candidate_weights_sha256"] = digest(&candidate_bytes).into();
                record["evidence_sha256"] = response.metadata["evidence_sha256"].clone().into();
                record["request_id"] = id.clone().into();
                say(&format!("ROUTINE {record}"));
                std::fs::write(out.join(format!("{model}-c{cycle}-{stage}.safetensors")), &candidate_bytes).unwrap();
                records.push(record);
            }
            let cycle_seconds = cycle_started.elapsed().as_secs_f64();
            round_seconds += cycle_seconds;
            say(&format!("ROUTINE CYCLE {model} cycle {cycle} (HEADS then FULL) {cycle_seconds:.1} s"));
        }
        let document = serde_json::json!({
            "model_id": model, "original_manifest_sha256": original, "cycles": cycles, "steps": steps, "threads": threads,
            "total_seconds": round_seconds, "fits": records
        });
        std::fs::write(out.join(format!("routine-calibration-{tier}.json")), serde_json::to_vec_pretty(&document).unwrap()).unwrap();
    }
}

trait DecodeFrom {
    fn decode_from(bytes: &[u8]) -> Self;
}

impl DecodeFrom for v3::FitRequest {
    fn decode_from(bytes: &[u8]) -> Self {
        prost::Message::decode(bytes).unwrap()
    }
}
