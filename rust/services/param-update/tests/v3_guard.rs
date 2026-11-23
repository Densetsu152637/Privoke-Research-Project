//! The recomputed guard (acceptance checks of stage V3-R2): param-update rebuilds the guard rows itself and scores the base and
//! the candidate with the Rust V3 encoder, whatever the trainer's evidence claims.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod golden_world;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use golden_world::{World, au3_manifest, bc01_paths, perform};
use privoke_contracts::json::Value;
use privoke_contracts::proto::experimental_v3::Commit;
use privoke_curriculum::Example;
use privoke_curriculum::audience::BUNDLED_MANIFEST_SHA256;
use privoke_curriculum::classification::Classification;
use privoke_curriculum::v3::{self, AU3_SAMPLER, BC01_SAMPLER, RoutineRelease, routine_guard_rows};
use privoke_param_update::v3_guard::{
    ALLOCATION_MISMATCH, Allocation, COMMITMENT_MISMATCH, GUARD_RECOMPUTED, GUARD_ROWS_DIFFER, GuardGate, GuardScorer,
    REQUEST_NOT_ALLOCATED, StaticAllocations, guard_inputs, passes, score, score_blobs,
};
use privoke_param_update::v3_store::{AudienceSource, Candidate, CheckpointStore, CommitObserver, PinnedSources, StoreError};
use privoke_semantic::safetensors;
use serde_json::Value as Json;

/// A way to make an allocation disagree with the commit.
type Tamper = fn(&mut Allocation);

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
        sampler: case.evidence["source"]["sampler"].as_str().unwrap().to_string(),
        scope: case.evidence["scope"].as_str().unwrap().to_string(),
        seed: case.evidence["source"]["seed"].as_u64().unwrap(),
        source_commitment: privoke_curriculum::v3::routine_commitment_of_source(
            &privoke_curriculum::value::parse_bytes(case.evidence["source"].to_string().as_bytes()).unwrap(),
            &privoke_curriculum::value::digest_of(
                &privoke_curriculum::value::parse_bytes(case.evidence["policy"].to_string().as_bytes()).unwrap(),
            )
            .unwrap(),
            case.evidence["source"]["seed"].as_u64().unwrap(),
        )
        .unwrap(),
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

    let mismatches: [(&str, Tamper); 4] = [
        (ALLOCATION_MISMATCH, |allocation| allocation.expected_base = "e".repeat(64)),
        // The trainer's evidence never chooses the release or the scope: the scheduler's allocation does.
        (ALLOCATION_MISMATCH, |allocation| allocation.sampler = AU3_SAMPLER.to_string()),
        (ALLOCATION_MISMATCH, |allocation| allocation.scope = "full_encoder".to_string()),
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
    let mut allocation = Allocation {
        sampler: BC01_SAMPLER.to_string(),
        scope: "heads".to_string(),
        seed: 20_261_123,
        source_commitment: "a".repeat(64),
        expected_base: "b".repeat(64),
    };
    let loaded = v3::load_sources_from(&bc01_paths()).unwrap();
    let release = v3::trusted_release(Some(au3_manifest().as_path()), Some(BUNDLED_MANIFEST_SHA256)).unwrap();
    let texts = |rows: &[Example]| rows.iter().map(|row| row.text.clone()).collect::<Vec<_>>();
    let bc01 = gate.rows(&allocation).unwrap();
    assert_eq!(
        texts(&bc01),
        texts(&routine_guard_rows(RoutineRelease::Bc01(&loaded), allocation.seed, &allocation.source_commitment).unwrap())
    );
    allocation.sampler = AU3_SAMPLER.to_string();
    let au3 = gate.rows(&allocation).unwrap();
    assert_eq!(
        texts(&au3),
        texts(&routine_guard_rows(RoutineRelease::Au3(&release), allocation.seed, &allocation.source_commitment).unwrap())
    );
    assert_eq!((bc01.len(), au3.len()), (16, 16));
}

/// A scorer that answers what the test says, whatever the checkpoints hold.
#[derive(Debug)]
struct Fixed(bool);

impl GuardScorer for Fixed {
    fn passes(&self, _store: &CheckpointStore, _manifest: &Value, _rows: &[Example]) -> Result<bool, StoreError> {
        Ok(self.0)
    }
}

/// The evidence of a case rewritten so that its guard is the rows param-update rebuilds (the way a routine source record would
/// carry them), whatever else it claims.
fn evidence_with_guard(case: &Case, allocation: &Allocation, rows: &[Example]) -> Json {
    let mut evidence = case.evidence.clone();
    // A routine schedule is built at the seed derived from the scheduler's seed and the commitment.
    evidence["source"]["seed"] = Json::from(v3::routine_guard_seed(allocation.seed, &allocation.source_commitment).unwrap());
    for (index, row) in rows.iter().enumerate() {
        evidence["source"]["guard_sidecar"][index]["text"] = Json::String(row.text.clone());
        for key in ["base_guard", "candidate_guard"] {
            evidence[key]["rows"][index]["target"] = Json::from(row.packed().unwrap());
        }
    }
    evidence
}

fn prepare(gate: &GuardGate, case: &Case, evidence: &Json) -> Option<String> {
    let manifest = case.store.manifest(&case.commit.candidate).unwrap();
    gate.prepare(&Candidate {
        store: &case.store,
        model_id: MODEL,
        manifest_sha: &case.commit.candidate,
        request_id: &case.commit.request_id,
        expected_base: &case.commit.expected_base,
        manifest: &manifest,
        evidence: Some(evidence),
    })
    .unwrap()
}

#[test]
fn a_candidate_whose_recomputed_guard_is_no_better_is_refused_whatever_its_evidence_claims_and_a_better_one_passes() {
    let world = World::load();
    let table = Arc::new(StaticAllocations::default());
    let case = case(&world, &table);
    let allocation = allocation(&case);
    table.allocate(&case.commit.request_id, MODEL, allocation.clone());
    let sources = pinned();
    let rows = GuardGate::new(sources.clone(), table.clone()).rows(&allocation).unwrap();
    let evidence = evidence_with_guard(&case, &allocation, &rows);
    // The evidence says the candidate beat its base: its own guard rows show a better joint count and no harm.
    assert!(privoke_contracts::v3::publication_passes(&case.evidence).unwrap(), "the claim of the evidence is a pass");
    let refused = GuardGate::new(sources.clone(), table.clone()).with_scorer(Arc::new(Fixed(false)));
    assert_eq!(prepare(&refused, &case, &evidence).as_deref(), Some(GUARD_RECOMPUTED), "the recomputation refuses the claimed pass");
    let better = GuardGate::new(sources, table).with_scorer(Arc::new(Fixed(true)));
    assert_eq!(prepare(&better, &case, &evidence), None, "a candidate that scores better passes the gate");
    // A trainer that trains on rows of a seed of its own choosing (the guard rows being right) is refused.
    let mut chosen = evidence.clone();
    chosen["source"]["seed"] = Json::from(1u64);
    assert_eq!(prepare(&better, &case, &chosen).as_deref(), Some(COMMITMENT_MISMATCH), "the schedule seed must be the derived one");
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

/// The production scoring path (scratch copies read through the store, the parent's checkpoint as the base, the candidate loaded
/// over it with `with_tensors`) on the stage 22 toy package, whose blobs are stored as they are: the toy config and vocabulary
/// are no pinned asset, so the manifest plumbing around it is checked separately on the golden world.
#[test]
fn the_production_scoring_path_equals_scoring_the_two_checkpoints_directly_and_the_base_is_the_parents() {
    let golden: Json = serde_json::from_slice(&std::fs::read(repo("privoke-training/tests/fixtures/v3_fit/golden.json")).unwrap()).unwrap();
    let rows: Vec<Example> = golden["guard"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| {
            Example::new(row["text"].as_str().unwrap(), Classification::from_packed(row["packed"].as_i64().unwrap()), 1.0, BTreeMap::new())
        })
        .collect();
    let package = repo("privoke-semantic/tests/fixtures/v3_synthetic");
    let candidates = |scope: &str| repo(&format!("privoke-training/tests/fixtures/v3_fit/{scope}.safetensors"));
    let scratch = tempfile::tempdir().unwrap();
    let store = CheckpointStore::open(scratch.path().join("store"), pinned()).unwrap();
    let put = |path: &Path| store.put(&std::fs::read(path).unwrap()).unwrap();
    let (config, vocab, base) =
        (put(&package.join("config.json")), put(&package.join("vocab.txt")), put(&package.join("model.safetensors")));
    let direct = |base_file: &Path, candidate_file: &Path| {
        let candidate = safetensors::parse(&std::fs::read(candidate_file).unwrap()).unwrap();
        score(&package.join("config.json"), &package.join("vocab.txt"), base_file, candidate, &rows).unwrap()
    };
    for scope in ["heads", "full_encoder"] {
        let candidate_blob = put(&candidates(scope));
        let (via_store_base, via_store_candidate) = score_blobs(&store, &config, &vocab, &base, &candidate_blob, &rows).unwrap();
        let (direct_base, direct_candidate) = direct(&package.join("model.safetensors"), &candidates(scope));
        assert_eq!(
            (&via_store_base, &via_store_candidate),
            (&direct_base, &direct_candidate),
            "{scope}: the store's bytes score as the files do"
        );
        assert_eq!(passes(&via_store_base, &via_store_candidate), passes(&direct_base, &direct_candidate), "{scope}");
        // The base the guard is scored against is the argument, not the candidate: swapping them swaps the two assessments.
        let (swapped_base, swapped_candidate) = score_blobs(&store, &config, &vocab, &candidate_blob, &base, &rows).unwrap();
        let (direct_swapped_base, direct_swapped_candidate) = direct(&candidates(scope), &package.join("model.safetensors"));
        assert_eq!((&swapped_base, &swapped_candidate), (&direct_swapped_base, &direct_swapped_candidate), "{scope}: swapped");
        if direct_base.predictions != direct_candidate.predictions {
            assert_ne!(swapped_base.predictions, via_store_base.predictions, "{scope}: the orientation is visible in the answer");
        }
    }
    // A blob the store does not hold is refused, not read from a path.
    assert!(score_blobs(&store, &config, &vocab, &"0".repeat(64), &base, &rows).is_err());
}

#[test]
fn the_scorer_is_given_the_parents_checkpoint_as_the_base_and_the_candidates_own_assets() {
    let world = World::load();
    let case = case(&world, &Arc::new(StaticAllocations::default()));
    let manifest = case.store.manifest(&case.commit.candidate).unwrap();
    let parent = case.store.manifest(&case.commit.expected_base).unwrap();
    let field = |document: &Value, key: &str| match document {
        Value::Object(map) => match map.get(key) {
            Some(Value::String(text)) => text.clone(),
            _ => panic!("{key}"),
        },
        _ => panic!("object"),
    };
    let inputs = guard_inputs(&case.store, &manifest).unwrap();
    assert_eq!(inputs.base_blob, field(&parent, "blob"));
    assert_eq!(inputs.candidate_blob, field(&manifest, "blob"));
    assert_ne!(inputs.base_blob, inputs.candidate_blob, "the candidate is not scored against itself");
    assert_eq!((inputs.config, inputs.vocab), (field(&manifest, "config"), field(&manifest, "vocab")));
}

#[test]
fn a_scratch_directory_an_interrupted_scoring_left_is_swept_when_the_store_opens() {
    let scratch = tempfile::tempdir().unwrap();
    let directory = scratch.path().join("store");
    drop(CheckpointStore::open(&directory, pinned()).unwrap());
    std::fs::create_dir_all(directory.join("guard-0123456789abcdef")).unwrap();
    std::fs::write(directory.join("guard-0123456789abcdef").join("base.safetensors"), b"copy").unwrap();
    drop(CheckpointStore::open(&directory, pinned()).unwrap());
    assert!(!directory.join("guard-0123456789abcdef").exists());
    assert!(directory.join("blobs").is_dir() && directory.join("catalog.sqlite").is_file(), "nothing else is touched");
}
