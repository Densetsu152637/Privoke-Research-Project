//! The routine mode of the V3 fuzzer (stage V3-R5): both samplers, a scheduler-allocated seed per cycle, the commitments computed and
//! recorded by the fuzzer, the guard rows from `routine_guard_rows`, and a restart rule that neither stalls a tier nor lets a request
//! identity carry two contents.
//!
//! The runtime and the checkpoint service are `common::fakes::World`: it checks each fit request as the real runtime does
//! (`[SEMANTIC]` only, the canonical source commitment, the frozen schedule validators) and admits each commit through the
//! param-update store's own `validate_source_evidence`, so a routine source record must satisfy both. The real-weight version of the
//! same cycle is `routine_real.rs` (local only).
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use common::fakes::World;
use common::{Env, Inputs};
use privoke_contracts::proto::experimental_v3 as v3;
use privoke_contracts::proto::experimental_v3::HealthRequest;
use privoke_contracts::proto::experimental_v3::v3_fuzzer_service_client::V3FuzzerServiceClient;
use privoke_contracts::proto::v1::{FuzzerTrainingRequest, FuzzerTrainingResponse};
use privoke_curriculum::v3::{self as curriculum, Policy, routine_guard_rows, routine_guard_seed};
use privoke_curriculum::value;
use privoke_transport::client::connect;
use privoke_v3_fuzzer::contract::{canonical, digest};
use privoke_v3_fuzzer::cycle::{Engine, EngineParts, Mode};
use privoke_v3_fuzzer::server::{self, limits_for};
use privoke_v3_fuzzer::service::V3Handler;
use privoke_v3_fuzzer::source::{Closure, Sampler, Schedules, python_source_hashes, routine_commitment_of_source};
use tonic::{Code, Request};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

fn policy_sha() -> String {
    digest(&canonical(&Policy::PILOT.to_value()).unwrap())
}

fn schedules(inputs: &Inputs, sampler: Sampler) -> Schedules {
    inputs.schedules(sampler, python_source_hashes(&repo_root(), sampler).unwrap())
}

async fn routine_engine(world: &Arc<World>, state: &Path) -> Engine {
    let parts = EngineParts {
        policy: Policy::PILOT.to_value(),
        schedules: schedules(world.inputs(), Sampler::Bc01),
        directory: state.to_path_buf(),
        fit_timeout: Duration::from_secs(60),
        closure: Closure::Fixed("routine-test".to_string()),
    };
    let engine = Engine::new(parts, world.clone(), world.clone()).await.unwrap();
    engine.with_routine(vec![schedules(world.inputs(), Sampler::Bc01), schedules(world.inputs(), Sampler::Au3)]).unwrap()
}

/// What the scheduler allocates and journals before it calls: the identity, the seed, the base and the sampler.
fn allocate(id: &str, model: &str, seed: u32, base: &str, sampler: Sampler) -> FuzzerTrainingRequest {
    let metadata: BTreeMap<String, String> =
        [("expected_base", base.to_string()), ("policy_sha256", policy_sha()), ("sampler", sampler.name().to_string())]
            .into_iter()
            .map(|(key, item)| (key.to_string(), item))
            .collect();
    FuzzerTrainingRequest {
        request_id: id.to_string(),
        source_id: String::new(),
        model_id: model.to_string(),
        prompt_count: 32,
        seed,
        metadata,
    }
}

fn with_timeout<T>(message: T) -> Request<T> {
    let mut request = Request::new(message);
    request.set_timeout(Duration::from_secs(120));
    request
}

#[tokio::test]
async fn a_routine_cycle_records_the_commitments_and_selects_the_guard_through_the_shared_function() {
    let world = Arc::new(World::new());
    let base = world.bootstrap("efficient");
    let state = tempfile::tempdir().unwrap();
    let engine = routine_engine(&world, &state.path().join("state")).await;
    assert_eq!(engine.mode(), Mode::Routine);
    assert_eq!(engine.health().unwrap().capabilities["mode"], "routine");

    for (index, sampler) in [Sampler::Bc01, Sampler::Au3].into_iter().enumerate() {
        let seed = 7001 + index as u32;
        let id = format!("routine-{index}");
        let request = allocate(&id, "privoke-v3-efficient", seed, &world.current("privoke-v3-efficient"), sampler);
        let response = engine.run(request.clone(), v3::Scope::Heads).await.unwrap();
        assert!(response.accepted, "{response:?}");
        assert_eq!(response.metadata["mode"], "routine");
        assert_eq!(response.metadata["seed"], seed.to_string());

        let fit = world.fits.lock().unwrap().last().unwrap().clone();
        assert_eq!(fit.layers, vec![4], "the fit request selects exactly the semantic layer");
        let source = value::parse_bytes(&fit.source_json).unwrap();
        // The commitment is the fuzzer's, recomputable from the evidence's source record and the journalled seed alone.
        let commitment = routine_commitment_of_source(&source, &policy_sha(), u64::from(seed)).unwrap();
        assert_eq!(response.metadata["routine_commitment"], commitment);
        assert_eq!(commitment, schedules(world.inputs(), sampler).routine_commitment(&policy_sha(), u64::from(seed)).unwrap());
        assert_eq!(response.metadata["source_commitment"], digest(&fit.source_json));
        assert_eq!(fit.source_commitment, digest(&fit.source_json));
        // The schedule seed is derived from the scheduler's seed and the commitment, and recorded.
        let schedule_seed = routine_guard_seed(u64::from(seed), &commitment).unwrap();
        assert_eq!(response.metadata["schedule_seed"], schedule_seed.to_string());
        assert_eq!(value::i64_at(&source, "seed").unwrap() as u64, schedule_seed);
        // A verifier holding only the evidence and the journalled seed recomputes the same commitment (policy digest included).
        let kept: serde_json::Value =
            serde_json::from_slice(&std::fs::read(engine.work_directory(&id).join("evidence.json")).unwrap()).unwrap();
        let evidence_source = value::parse_bytes(kept["source"].to_string().as_bytes()).unwrap();
        let evidence_policy = value::parse_bytes(kept["policy"].to_string().as_bytes()).unwrap();
        assert_eq!(
            routine_commitment_of_source(&evidence_source, &value::digest_of(&evidence_policy).unwrap(), u64::from(seed)).unwrap(),
            commitment
        );
        assert_eq!(kept["source"]["seed"].as_u64(), Some(schedule_seed));
        // The guard rows are the shared function's rows.
        let release = schedules(world.inputs(), sampler);
        let rows: Vec<_> = routine_guard_rows(release.guard_release(), u64::from(seed), &commitment)
            .unwrap()
            .iter()
            .map(curriculum::wire)
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(fit.guard, rows);
        assert_eq!(fit.train.len(), 64);
        let record = std::fs::read(engine.work_directory(&id).join("routine.json")).unwrap();
        let record = value::parse_bytes(&record).unwrap();
        assert_eq!(value::str_at(&record, "routine_commitment").unwrap(), commitment);
        assert_eq!(value::str_at(&record, "source_commitment").unwrap(), digest(&fit.source_json));
        assert_eq!(value::str_at(&record, "expected_base").unwrap(), request.metadata["expected_base"]);
    }
    assert_ne!(world.current("privoke-v3-efficient"), base, "both candidates were applied through the store's admission");
}

#[tokio::test]
async fn a_fresh_seed_gives_fresh_training_rows_and_for_bc01_a_fresh_guard() {
    let world = Arc::new(World::new());
    world.bootstrap("efficient");
    let state = tempfile::tempdir().unwrap();
    let engine = routine_engine(&world, &state.path().join("state")).await;
    for (sampler, fixed_guard) in [(Sampler::Bc01, false), (Sampler::Au3, true)] {
        let mut seen = Vec::new();
        for seed in [11u32, 12] {
            let base = world.current("privoke-v3-efficient");
            let request = allocate(&format!("{}-{seed}", sampler.name()), "privoke-v3-efficient", seed, &base, sampler);
            engine.run(request, v3::Scope::Heads).await.unwrap();
            let fit = world.fits.lock().unwrap().last().unwrap().clone();
            seen.push((fit.train, fit.guard));
        }
        assert_ne!(seen[0].0, seen[1].0, "{}: the training rows change with the seed", sampler.name());
        assert_eq!(seen[0].1 == seen[1].1, fixed_guard, "{}: BC01 reselects its guard, AU3's is the release's", sampler.name());
    }
}

#[tokio::test]
async fn a_routine_request_must_name_a_sampler_and_the_frozen_policy() {
    let world = Arc::new(World::new());
    let base = world.bootstrap("efficient");
    let state = tempfile::tempdir().unwrap();
    let engine = routine_engine(&world, &state.path().join("state")).await;
    let mut unnamed = allocate("a", "privoke-v3-efficient", 1, &base, Sampler::Bc01);
    unnamed.metadata.remove("sampler");
    assert_eq!(engine.run(unnamed, v3::Scope::Heads).await.unwrap_err().code(), Code::InvalidArgument);
    let mut wrong = allocate("b", "privoke-v3-efficient", 1, &base, Sampler::Bc01);
    wrong.metadata.insert("policy_sha256".to_string(), "0".repeat(64));
    assert_eq!(engine.run(wrong, v3::Scope::Heads).await.unwrap_err().code(), Code::Unknown);
    let mut foreign = allocate("c", "privoke-v3-efficient", 1, &base, Sampler::Bc01);
    foreign.metadata.insert("source_commitment".to_string(), "1".repeat(64));
    assert_eq!(engine.run(foreign, v3::Scope::Heads).await.unwrap_err().code(), Code::Unknown);
    assert_eq!(world.fit_count.load(Ordering::SeqCst), 0, "nothing reached the runtime");
}

/// A fuzzer process that died after the fit and before the commit: the commit never reached the store.
async fn crash_after_the_fit(world: &Arc<World>, state: &Path, request: &FuzzerTrainingRequest) -> String {
    let engine = routine_engine(world, state).await;
    world.lose_commits.store(true, Ordering::SeqCst);
    let status = engine.run(request.clone(), v3::Scope::Heads).await.unwrap_err();
    assert_eq!(status.code(), Code::Unknown);
    assert_eq!(status.message(), "Commit outcome unknown; stop without replay.");
    world.lose_commits.store(false, Ordering::SeqCst);
    world.current("privoke-v3-efficient")
}

#[tokio::test]
async fn a_crash_after_the_fit_is_resumed_by_its_own_identity_without_refitting() {
    let world = Arc::new(World::new());
    let base = world.bootstrap("efficient");
    let state = tempfile::tempdir().unwrap();
    let request = allocate("cycle-1", "privoke-v3-efficient", 21, &base, Sampler::Bc01);
    assert_eq!(crash_after_the_fit(&world, &state.path().join("state"), &request).await, base, "nothing was committed");
    assert_eq!(world.fit_count.load(Ordering::SeqCst), 1);

    // The process restarts. The scheduler asks the store about the journalled identity: the store never saw it.
    let engine = routine_engine(&world, &state.path().join("state")).await;
    assert_eq!(engine.rows().await.unwrap().iter().filter(|row| row.2.is_none()).count(), 1, "the row survived with no response");
    let store_view = privoke_v3_fuzzer::backend::CheckpointBackend::commit_status(world.as_ref(), "cycle-1").await.unwrap();
    assert_eq!(store_view.status, "unknown");
    // Re-asking with the same identity and the same content resumes: the recorded commit is re-sent, the fit is not replayed.
    let response = engine.run(request.clone(), v3::Scope::Heads).await.unwrap();
    assert!(response.accepted, "{response:?}");
    assert_eq!(world.fit_count.load(Ordering::SeqCst), 1, "never a second physical fit");
    assert_eq!(world.commits_seen.lock().unwrap().len(), 1);
    assert_eq!(world.receipt_of("cycle-1").unwrap().status, "applied");
    assert_eq!(engine.run(request, v3::Scope::Heads).await.unwrap(), response, "a stored response answers the identity");
}

#[tokio::test]
async fn a_lost_fit_is_answered_by_a_new_identity_and_no_identity_carries_two_contents() {
    let world = Arc::new(World::new());
    let base = world.bootstrap("balanced");
    let model = "privoke-v3-balanced";
    let state = tempfile::tempdir().unwrap();
    let lost = allocate("cycle-1", model, 31, &base, Sampler::Au3);
    {
        let engine = routine_engine(&world, &state.path().join("state")).await;
        world.lose_commits.store(true, Ordering::SeqCst);
        assert!(engine.run(lost.clone(), v3::Scope::Heads).await.is_err());
        world.lose_commits.store(false, Ordering::SeqCst);
    }
    // A restart that lost the work directory: the fuzzer cannot resume, and says so.
    std::fs::remove_file(state.path().join("state").join(digest(b"cycle-1")).join("commit-request.pb")).unwrap();
    let engine = routine_engine(&world, &state.path().join("state")).await;
    assert_eq!(engine.run(lost.clone(), v3::Scope::Heads).await.unwrap_err().code(), Code::FailedPrecondition);
    // The scheduler's rule: the store reports the journalled identity unknown, so it allocates a new identity and a new seed.
    let status = privoke_v3_fuzzer::backend::CheckpointBackend::commit_status(world.as_ref(), "cycle-1").await.unwrap();
    assert_eq!(status.status, "unknown");
    let retry = allocate("cycle-1b", model, 32, &world.current(model), Sampler::Au3);
    let response = engine.run(retry, v3::Scope::Heads).await.unwrap();
    assert!(response.accepted, "the tier is not stalled: {response:?}");
    assert_ne!(world.current(model), base);
    // Re-using the old identity with the new content is refused before any work, here and at the store.
    let mut reused = lost.clone();
    reused.seed = 32;
    assert_eq!(engine.run(reused, v3::Scope::Heads).await.unwrap_err().code(), Code::AlreadyExists);
    let committed = world.commits_seen.lock().unwrap()[0].clone();
    let conflicting = v3::Commit { evidence: digest(b"another"), ..committed };
    let backend = world.as_ref();
    assert_eq!(
        privoke_v3_fuzzer::backend::CheckpointBackend::commit_candidate(backend, conflicting).await.unwrap_err().code(),
        Code::AlreadyExists,
        "the store refuses a request-id content conflict"
    );
}

#[tokio::test]
async fn a_late_resume_of_a_stale_cycle_is_a_rejection_not_a_conflict() {
    let world = Arc::new(World::new());
    let base = world.bootstrap("efficient");
    let state = tempfile::tempdir().unwrap();
    let request = allocate("old", "privoke-v3-efficient", 41, &base, Sampler::Bc01);
    crash_after_the_fit(&world, &state.path().join("state"), &request).await;
    let engine = routine_engine(&world, &state.path().join("state")).await;
    let newer = allocate("new", "privoke-v3-efficient", 42, &base, Sampler::Bc01);
    assert!(engine.run(newer, v3::Scope::Heads).await.unwrap().accepted);
    let late = engine.run(request, v3::Scope::Heads).await.unwrap();
    assert!(!late.accepted);
    assert!(late.message.contains("stale_base"), "{}", late.message);
}

/// The scheduler of this test: HEADS, then FULL_ENCODER on the version HEADS published, for each tier, through the real mutual-TLS
/// listener of the fuzzer.
#[tokio::test]
async fn a_routine_heads_then_full_cycle_runs_for_every_tier_through_the_mutual_tls_listener() {
    let world = Arc::new(World::new());
    let tiers = ["efficient", "balanced", "quality"];
    let originals: Vec<String> = tiers.iter().map(|tier| world.bootstrap(tier)).collect();
    let env = Env::new();
    let state = tempfile::tempdir().unwrap();
    let engine = Arc::new(routine_engine(&world, &state.path().join("state")).await);
    let transport = env.tls_args().into_config().unwrap();
    let handler = V3Handler::new(engine.clone());
    let handle =
        server::start("127.0.0.1:0".parse().unwrap(), handler, transport, limits_for(Duration::from_secs(600)), Duration::from_millis(50))
            .await
            .unwrap();
    let publisher = env.service("param-update", Some("publisher"));
    let channel = connect(&handle.addr.to_string(), &env.client_config(Some(&publisher))).await.unwrap();
    let mut client = V3FuzzerServiceClient::new(channel);
    let health = client.health(with_timeout(HealthRequest {})).await.unwrap().into_inner();
    assert_eq!(health.capabilities["mode"], "routine");

    let mut seed = 100u32;
    for (index, tier) in tiers.iter().enumerate() {
        let model = format!("privoke-v3-{tier}");
        let sampler = [Sampler::Bc01, Sampler::Au3, Sampler::Bc01][index];
        let mut base = originals[index].clone();
        for (stage, full) in [("heads", false), ("full", true)] {
            seed += 1;
            let request = allocate(&format!("{tier}-{stage}-{seed}"), &model, seed, &world.current(&model), sampler);
            assert_eq!(request.metadata["expected_base"], base, "{tier} {stage}: the scheduler takes the base from the store");
            let response: FuzzerTrainingResponse = if full {
                client.run_underlying_training_cycle(with_timeout(request)).await.unwrap().into_inner()
            } else {
                client.run_training_cycle(with_timeout(request)).await.unwrap().into_inner()
            };
            assert!(response.accepted, "{tier} {stage}: {response:?}");
            assert_eq!(response.base_version, base);
            assert_eq!(response.metadata["scope"], if full { "full_encoder" } else { "heads" });
            assert_eq!(response.metadata["semantic_layers"], "4");
            assert_eq!(response.metadata["sampler"], sampler.name());
            assert_eq!(world.current(&model), response.applied_version);
            base = response.applied_version;
        }
    }
    // Sent and executed: every fit request listed `[SEMANTIC]` only, and every evidence the cycles kept records layer 4 alone.
    let fits = world.fits.lock().unwrap().clone();
    assert_eq!(fits.len(), 6);
    assert!(fits.iter().all(|fit| fit.layers == vec![4]));
    for fit in &fits {
        let evidence = std::fs::read(engine.work_directory(&fit.request_id).join("evidence.json")).unwrap();
        let evidence: serde_json::Value = serde_json::from_slice(&evidence).unwrap();
        assert_eq!(evidence["layers"], serde_json::json!([4]), "{}", fit.request_id);
        assert_eq!(evidence["phases"]["training"]["layer"], 4);
    }
    assert!(engine.rows().await.unwrap().iter().all(|row| row.2.is_some()), "every cycle is journalled with its response");
    handle.shutdown().await.unwrap();
}
