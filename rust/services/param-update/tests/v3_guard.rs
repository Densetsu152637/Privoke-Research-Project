//! The recomputed guard (acceptance checks of stage V3-R2): param-update rebuilds the guard rows itself and scores the base and
//! the candidate with the Rust V3 encoder, whatever the trainer's evidence claims.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod golden_world;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use golden_world::{World, au3_manifest, bc01_paths, perform};
use privoke_contracts::proto::experimental_v3::Commit;
use privoke_curriculum::Example;
use privoke_curriculum::audience::BUNDLED_MANIFEST_SHA256;
use privoke_curriculum::classification::Classification;
use privoke_curriculum::v3::{self, AU3_SAMPLER, BC01_SAMPLER, RoutineRelease, routine_guard_rows};
use privoke_param_update::v3_guard::{
    ALLOCATION_MISMATCH, Allocation, COMMITMENT_MISMATCH, GUARD_ROWS_DIFFER, GuardGate, REQUEST_NOT_ALLOCATED, StaticAllocations, passes,
    score,
};
use privoke_param_update::v3_store::{AudienceSource, CheckpointStore, PinnedSources};
use privoke_semantic::safetensors;
use serde_json::Value as Json;

const MODEL: &str = "privoke-v3-efficient";
const REQUEST: &str = "commit v3-life-heads-1";

fn pinned() -> Arc<PinnedSources> {
    Arc::new(PinnedSources::new(
        bc01_paths(),
        AudienceSource::Trusted { path: au3_manifest(), sha256: BUNDLED_MANIFEST_SHA256.to_string() },
    ))
}

fn lifecycle(world: &World) -> &Json {
    world.golden["stories"].as_array().unwrap().iter().find(|story| story["name"] == "bc01-lifecycle").unwrap()
}

fn step<'a>(story: &'a Json, op: &str, label: &str) -> &'a Json {
    story["steps"].as_array().unwrap().iter().find(|step| step["op"] == op && step["label"] == label).unwrap()
}

/// A store with the ORIGINAL and the first candidate staged, a guard gate over `allocations`, and the commit of the candidate.
struct Case {
    _scratch: tempfile::TempDir,
    store: CheckpointStore,
    commit: Commit,
    evidence: Json,
}

fn case(world: &World, allocations: &Arc<StaticAllocations>) -> Case {
    let scratch = tempfile::tempdir().unwrap();
    let sources = pinned();
    let gate = Arc::new(GuardGate::new(sources.clone(), allocations.clone()));
    let store = CheckpointStore::open(scratch.path().join("store"), sources).unwrap().with_observer(gate);
    let story = lifecycle(world);
    let work = scratch.path().join("work");
    std::fs::create_dir_all(&work).unwrap();
    for (op, label) in [("bootstrap", "efficient"), ("stage", "evidence of v3-life-heads-1"), ("stage", "candidate of v3-life-heads-1")] {
        perform(world, &store, step(story, op, label), &work).unwrap();
    }
    let request = &step(story, "commit", REQUEST)["request"];
    let field = |name: &str| request[name].as_str().unwrap().to_string();
    let commit = Commit {
        request_id: field("request_id"),
        model_id: field("model_id"),
        expected_base: field("expected_base"),
        candidate: field("candidate"),
        evidence: field("evidence"),
    };
    let key = step(story, "stage", "evidence of v3-life-heads-1")["payload"]["evidence"].as_str().unwrap();
    let evidence: Json = serde_json::from_slice(&world.evidence(key)).unwrap();
    Case { _scratch: scratch, store, commit, evidence }
}

fn allocation(case: &Case) -> Allocation {
    Allocation {
        seed: case.evidence["source"]["seed"].as_u64().unwrap(),
        source_commitment: case.evidence["source_commitment"].as_str().unwrap().to_string(),
        expected_base: case.commit.expected_base.clone(),
    }
}

#[test]
fn a_candidate_is_refused_with_a_reason_unless_the_scheduler_allocated_it_and_the_evidence_matches_the_allocation() {
    let world = World::load();
    // No allocation: the request never came from the scheduler.
    let none = Arc::new(StaticAllocations::default());
    let case_none = case(&world, &none);
    let receipt = case_none.store.commit(&case_none.commit).unwrap();
    assert_eq!((receipt.status.as_str(), receipt.reason.as_str()), ("rejected", REQUEST_NOT_ALLOCATED));
    assert_eq!(case_none.store.resolve(MODEL).unwrap(), case_none.commit.expected_base, "nothing changed");

    let mismatches: [(&str, fn(&mut Allocation)); 2] = [
        (ALLOCATION_MISMATCH, |allocation| allocation.expected_base = "e".repeat(64)),
        (COMMITMENT_MISMATCH, |allocation| allocation.source_commitment = "f".repeat(64)),
    ];
    for (reason, tamper) in mismatches {
        let table = Arc::new(StaticAllocations::default());
        let case = case(&world, &table);
        let mut allocated = allocation(&case);
        tamper(&mut allocated);
        table.allocate(&case.commit.request_id, MODEL, allocated);
        let receipt = case.store.commit(&case.commit).unwrap();
        assert_eq!((receipt.status.as_str(), receipt.reason.as_str()), ("rejected", reason));
        assert_eq!(case.store.resolve(MODEL).unwrap(), case.commit.expected_base);
    }

    // The evidence claims the frozen guard and a pass; the rows param-update rebuilds from the allocation are other rows.
    let table = Arc::new(StaticAllocations::default());
    let forged = case(&world, &table);
    table.allocate(&forged.commit.request_id, MODEL, allocation(&forged));
    let receipt = forged.store.commit(&forged.commit).unwrap();
    assert_eq!((receipt.status.as_str(), receipt.reason.as_str()), ("rejected", GUARD_ROWS_DIFFER));
    assert_eq!(forged.store.resolve(MODEL).unwrap(), forged.commit.expected_base);
    assert!(forged.store.history(MODEL).unwrap().len() == 1, "the candidate never entered the history");
}

#[test]
fn the_rows_param_update_rebuilds_are_the_rows_the_fuzzer_gets() {
    let sources = pinned();
    let gate = GuardGate::new(sources.clone(), Arc::new(StaticAllocations::default()));
    let allocation = Allocation { seed: 20_261_123, source_commitment: "a".repeat(64), expected_base: "b".repeat(64) };
    let loaded = v3::load_sources_from(&bc01_paths()).unwrap();
    let release = v3::trusted_release(Some(au3_manifest().as_path()), Some(BUNDLED_MANIFEST_SHA256)).unwrap();
    let texts = |rows: &[Example]| rows.iter().map(|row| row.text.clone()).collect::<Vec<_>>();
    let bc01 = gate.rows(BC01_SAMPLER, &allocation).unwrap();
    assert_eq!(
        texts(&bc01),
        texts(&routine_guard_rows(RoutineRelease::Bc01(&loaded), allocation.seed, &allocation.source_commitment).unwrap())
    );
    let au3 = gate.rows(AU3_SAMPLER, &allocation).unwrap();
    assert_eq!(
        texts(&au3),
        texts(&routine_guard_rows(RoutineRelease::Au3(&release), allocation.seed, &allocation.source_commitment).unwrap())
    );
    assert_eq!((bc01.len(), au3.len()), (16, 16));
}

fn repo(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../crates").join(relative)
}

/// The toy V3 package of stage 22 (`privoke-semantic`'s synthetic checkpoint and `privoke-training`'s exported candidates) with
/// the product's own evidence: the guard rows and the predictions the Python product recorded for the base and the candidates.
#[test]
fn the_guard_is_scored_with_the_encoder_the_product_used_and_the_pass_rule_is_publication_passes() {
    let golden: Json = serde_json::from_slice(&std::fs::read(repo("privoke-training/tests/fixtures/v3_fit/golden.json")).unwrap()).unwrap();
    let rows: Vec<Example> = golden["guard"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| {
            Example::new(row["text"].as_str().unwrap(), Classification::from_packed(row["packed"].as_i64().unwrap()), 1.0, BTreeMap::new())
        })
        .collect();
    assert_eq!(rows.len(), 16);
    let package = repo("privoke-semantic/tests/fixtures/v3_synthetic");
    for scope in ["heads", "full_encoder"] {
        let candidate =
            safetensors::parse(&std::fs::read(repo(&format!("privoke-training/tests/fixtures/v3_fit/{scope}.safetensors"))).unwrap())
                .unwrap();
        let (base, changed) =
            score(&package.join("config.json"), &package.join("vocab.txt"), &package.join("model.safetensors"), candidate, &rows).unwrap();
        let recorded = &golden["scopes"][scope];
        let predictions = |guard: &Json| -> Vec<u16> {
            guard["rows"].as_array().unwrap().iter().map(|row| u16::try_from(row["prediction"].as_u64().unwrap()).unwrap()).collect()
        };
        assert_eq!(base.predictions, predictions(&recorded["base_guard"]), "{scope}: the base predictions are the product's");
        assert_eq!(changed.predictions, predictions(&recorded["candidate_guard"]), "{scope}: the candidate predictions are the product's");
        assert_eq!(
            (base.joint as u64, changed.joint as u64),
            (recorded["base_guard"]["joint_correct"].as_u64().unwrap(), recorded["candidate_guard"]["joint_correct"].as_u64().unwrap()),
            "{scope}: the joint counts"
        );
        let expected = recorded["candidate_guard"]["joint_correct"].as_u64() > recorded["base_guard"]["joint_correct"].as_u64()
            && recorded["action_harms"] == 0;
        assert_eq!(passes(&base, &changed), expected, "{scope}: the pass rule");
    }
}
