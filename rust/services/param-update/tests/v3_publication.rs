//! Signed, atomic publication of V3 versions (acceptance checks of stage V3-R2): the commit order, crash injection at every
//! boundary, a candidate that loses the race, rollback, startup reconciliation and the drift gate.
//!
//! The states are reached by replaying the steps of the checkpoint store golden (`v3_checkpoint_store_golden.json`: the same
//! synthetic package, the same candidates and evidence) against a store that has a [`Publisher`] attached. Nothing here depends on
//! the oracle's answers: the publication contract is new in V3-R2 and is specified by these tests.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod golden_world;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use golden_world::{World, au3_manifest, bc01_paths, perform};
use privoke_contracts::proto::experimental_v3::{Commit, Receipt, Rollback};
use privoke_contracts::publication::test_keys::{self, PRIMARY_ID};
use privoke_contracts::publication::{self, KeySet};
use privoke_curriculum::audience::BUNDLED_MANIFEST_SHA256;
use privoke_param_update::v3_policy::{DriftBounds, DriftGate};
use privoke_param_update::v3_publish::{CrashHook, Publisher};
use privoke_param_update::v3_store::{AudienceSource, ChainObserver, CheckpointStore, CommitObserver, PinnedSources, StoreError};
use serde_json::Value as Json;

const MODEL: &str = "privoke-v3-efficient";

fn pinned() -> Arc<PinnedSources> {
    Arc::new(PinnedSources::new(
        bc01_paths(),
        AudienceSource::Trusted { path: au3_manifest(), sha256: BUNDLED_MANIFEST_SHA256.to_string() },
    ))
}

fn keys() -> KeySet {
    test_keys::key_set()
}

/// One store and publisher over directories that outlive a "restart".
struct Rig {
    scratch: tempfile::TempDir,
    store: CheckpointStore,
    publisher: Arc<Publisher>,
}

impl Rig {
    fn store_dir(&self) -> PathBuf {
        self.scratch.path().join("store")
    }

    fn root(&self) -> PathBuf {
        self.scratch.path().join("published")
    }

    fn work(&self) -> PathBuf {
        self.scratch.path().join("work")
    }
}

fn hook(armed: &Arc<AtomicBool>, phase: &'static str) -> CrashHook {
    let armed = armed.clone();
    Arc::new(move |current: &str| -> Result<(), String> {
        if armed.load(Ordering::SeqCst) && current == phase { Err("simulated crash".to_string()) } else { Ok(()) }
    })
}

fn open(scratch: &Path, hook: CrashHook, gates: Vec<Arc<dyn CommitObserver>>) -> (CheckpointStore, Arc<Publisher>) {
    let publisher = Arc::new(Publisher::new(scratch.join("published"), PRIMARY_ID, test_keys::seed(PRIMARY_ID), hook).unwrap());
    let mut observers = gates;
    observers.push(publisher.clone());
    let store = CheckpointStore::open(scratch.join("store"), pinned()).unwrap().with_observer(Arc::new(ChainObserver::new(observers)));
    (store, publisher)
}

fn rig(hook: CrashHook, gates: Vec<Arc<dyn CommitObserver>>) -> Rig {
    let scratch = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(scratch.path().join("work")).unwrap();
    let (store, publisher) = open(scratch.path(), hook, gates);
    Rig { scratch, store, publisher }
}

fn story(world: &World) -> &Json {
    world.golden["stories"].as_array().unwrap().iter().find(|story| story["name"] == "bc01-lifecycle").unwrap()
}

fn step<'a>(story: &'a Json, op: &str, label: &str) -> &'a Json {
    story["steps"]
        .as_array()
        .unwrap()
        .iter()
        .find(|step| step["op"] == op && step["label"] == label)
        .unwrap_or_else(|| panic!("no {op} step labelled {label}"))
}

fn run(world: &World, rig: &Rig, op: &str, label: &str) -> Result<Json, StoreError> {
    perform(world, &rig.store, step(story(world), op, label), &rig.work())
}

fn stage(world: &World, rig: &Rig, version: &str) {
    run(world, rig, "stage", &format!("evidence of {version}")).unwrap();
    run(world, rig, "stage", &format!("candidate of {version}")).unwrap();
}

fn commit_of(world: &World, label: &str) -> Commit {
    let request = &step(story(world), "commit", label)["request"];
    let field = |name: &str| request[name].as_str().unwrap().to_string();
    Commit {
        request_id: field("request_id"),
        model_id: field("model_id"),
        expected_base: field("expected_base"),
        candidate: field("candidate"),
        evidence: field("evidence"),
    }
}

fn original_of(world: &World) -> String {
    step(story(world), "bootstrap", "efficient")["manifest"].as_str().unwrap().to_string()
}

const F1: &str = "commit v3-life-heads-1";
const F2: &str = "commit v3-life-heads-2";
const F3: &str = "a stale base is rejected, not an error";
const F4: &str = "a guard failure is rejected";

/// Bootstrap and publish the first version (`v3-life-heads-1`).
fn first_version(world: &World, rig: &Rig) -> Receipt {
    run(world, rig, "bootstrap", "efficient").unwrap();
    stage(world, rig, "v3-life-heads-1");
    rig.store.commit(&commit_of(world, F1)).unwrap()
}

fn assert_served(rig: &Rig, manifest: &str, sequence: u64) {
    let served = rig.publisher.served(MODEL).unwrap().expect("a version is served");
    assert_eq!(served.manifest_sha, manifest);
    let statement = publication::verify(&keys(), &served.statement).unwrap();
    assert_eq!((statement.manifest_sha.as_str(), statement.sequence, statement.model_id.as_str()), (manifest, sequence, MODEL));
    for name in ["manifest.json", "model.safetensors", "config.json", "vocab.txt", "statement.json"] {
        assert!(served.directory.join(name).is_file(), "{name} is published");
    }
}

fn staged_entries(rig: &Rig) -> usize {
    std::fs::read_dir(rig.root().join(".staging").join(MODEL)).map_or(0, |entries| entries.count())
}

fn quarantined_entries(rig: &Rig) -> usize {
    std::fs::read_dir(rig.root().join(".quarantine")).map_or(0, |entries| entries.count())
}

#[test]
fn a_commit_publishes_a_signed_version_with_a_higher_sequence_each_time() {
    let world = World::load();
    let rig = rig(hook(&Arc::new(AtomicBool::new(false)), "none"), Vec::new());
    assert!(rig.publisher.served(MODEL).unwrap().is_none(), "nothing is published before the first version");
    let receipt = first_version(&world, &rig);
    assert_eq!((receipt.status.as_str(), receipt.reason.as_str()), ("applied", ""));
    assert_served(&rig, &commit_of(&world, F1).candidate, 1);
    // The statement carries the manifest's own lineage.
    let served = rig.publisher.served(MODEL).unwrap().unwrap();
    let statement = publication::verify(&keys(), &served.statement).unwrap();
    assert_eq!((statement.parent, statement.original), (original_of(&world), original_of(&world)));
    stage(&world, &rig, "v3-life-heads-2");
    assert_eq!(rig.store.commit(&commit_of(&world, F2)).unwrap().status, "applied");
    assert_served(&rig, &commit_of(&world, F2).candidate, 2);
    assert_eq!(staged_entries(&rig), 0, "staging is released after publication");
    let rows = rig.store.publications(MODEL).unwrap();
    assert_eq!(rows.iter().map(|row| row.sequence).collect::<Vec<_>>(), vec![1, 2]);
    assert!(rows.iter().all(|row| row.key_id == PRIMARY_ID));
    // The replay of an applied request answers from its receipt and signs nothing new.
    assert_eq!(rig.store.commit(&commit_of(&world, F2)).unwrap().status, "applied");
    assert_eq!(rig.store.publications(MODEL).unwrap().len(), 2);
}

#[test]
fn a_candidate_that_loses_the_race_or_fails_the_guard_is_never_signed_or_published() {
    let world = World::load();
    let rig = rig(hook(&Arc::new(AtomicBool::new(false)), "none"), Vec::new());
    first_version(&world, &rig);
    stage(&world, &rig, "v3-life-heads-2");
    stage(&world, &rig, "v3-life-heads-3");
    stage(&world, &rig, "v3-life-regress-1");
    rig.store.commit(&commit_of(&world, F2)).unwrap();
    for (label, reason) in [(F3, "stale_base"), (F4, "guard_rejected")] {
        let request = commit_of(&world, label);
        let receipt = rig.store.commit(&request).unwrap();
        assert_eq!((receipt.status.as_str(), receipt.reason.as_str()), ("rejected", reason), "{label}");
        assert_eq!(rig.store.publications(MODEL).unwrap().len(), 2, "{label}: no statement exists for it");
        assert!(!rig.root().join(MODEL).join(&request.candidate).exists(), "{label}: nothing is published for it");
        assert_eq!(staged_entries(&rig), 0, "{label}: its staging is released");
        assert_served(&rig, &commit_of(&world, F2).candidate, 2);
        assert_eq!(rig.store.resolve(MODEL).unwrap(), commit_of(&world, F2).candidate);
    }
}

#[test]
fn a_crash_at_any_boundary_leaves_the_old_or_the_new_version_fully_served() {
    let world = World::load();
    // (phase, version served right after the crash, current in the authority after it, publications after it)
    let cases = [("staged", 1, 1, 1), ("signed", 1, 1, 1), ("committed", 1, 2, 2), ("renamed", 1, 2, 2), ("pointer", 2, 2, 2)];
    for (phase, served_sequence, authority, publications) in cases {
        let armed = Arc::new(AtomicBool::new(false));
        let rig = rig(hook(&armed, phase), Vec::new());
        first_version(&world, &rig);
        stage(&world, &rig, "v3-life-heads-2");
        let (first, second) = (commit_of(&world, F1).candidate, commit_of(&world, F2).candidate);
        armed.store(true, Ordering::SeqCst);
        let crashed = rig.store.commit(&commit_of(&world, F2));
        assert!(matches!(crashed, Err(StoreError::Storage(_))), "{phase}: the commit dies there");
        // Before any restart: a complete, signed version is served, never a missing or half-published one.
        let (version, sequence) = if served_sequence == 1 { (&first, 1) } else { (&second, 2) };
        assert_served(&rig, version, sequence);
        assert_eq!(rig.store.resolve(MODEL).unwrap(), if authority == 1 { first.clone() } else { second.clone() }, "{phase}");
        assert_eq!(rig.store.publications(MODEL).unwrap().len(), publications, "{phase}");
        // Restart: new store, new publisher, reconciliation from the authority.
        let scratch = rig.scratch;
        drop(rig.store);
        drop(rig.publisher);
        let (store, publisher) = open(scratch.path(), hook(&Arc::new(AtomicBool::new(false)), "none"), Vec::new());
        let report = publisher.reconcile(&store).unwrap();
        let restarted = Rig { scratch, store, publisher };
        if authority == 1 {
            assert_served(&restarted, &first, 1);
            assert!(report.quarantined >= 1, "{phase}: the staged directory of an uncommitted version is quarantined ({report:?})");
        } else {
            assert_served(&restarted, &second, 2);
        }
        if phase == "committed" {
            assert_eq!(report.promoted, 1, "an intact staged directory of a committed version is promoted ({report:?})");
        }
        assert_eq!(staged_entries(&restarted), 0, "{phase}: no staging survives reconciliation");
        // The request can be retried: it answers from its receipt or applies now, and the second version ends up served.
        let receipt = restarted.store.commit(&commit_of(&world, F2)).unwrap();
        assert_eq!(receipt.status, "applied", "{phase}");
        assert_served(&restarted, &second, 2);
        assert_eq!(restarted.store.publications(MODEL).unwrap().len(), 2, "{phase}: one statement per version");
        assert_eq!(staged_entries(&restarted), 0, "{phase}");
    }
}

#[test]
fn a_loser_that_dies_while_staged_leaves_no_statement_and_is_quarantined_at_restart() {
    let world = World::load();
    let armed = Arc::new(AtomicBool::new(false));
    let rig = rig(hook(&armed, "staged"), Vec::new());
    first_version(&world, &rig);
    stage(&world, &rig, "v3-life-heads-2");
    stage(&world, &rig, "v3-life-heads-3");
    rig.store.commit(&commit_of(&world, F2)).unwrap();
    armed.store(true, Ordering::SeqCst);
    assert!(rig.store.commit(&commit_of(&world, F3)).is_err());
    assert_eq!(staged_entries(&rig), 1, "the loser's staging is left as the crash leaves it");
    let scratch = rig.scratch;
    drop(rig.store);
    drop(rig.publisher);
    let (store, publisher) = open(scratch.path(), hook(&Arc::new(AtomicBool::new(false)), "none"), Vec::new());
    let report = publisher.reconcile(&store).unwrap();
    let restarted = Rig { scratch, store, publisher };
    assert!(report.quarantined >= 1);
    assert_eq!(staged_entries(&restarted), 0);
    assert!(quarantined_entries(&restarted) >= 1);
    assert_eq!(restarted.store.publications(MODEL).unwrap().len(), 2, "no signed statement exists for the loser");
    assert_served(&restarted, &commit_of(&world, F2).candidate, 2);
}

#[test]
fn a_rollback_is_a_new_signed_publication_of_a_version_in_the_history_and_nothing_else() {
    let world = World::load();
    let rig = rig(hook(&Arc::new(AtomicBool::new(false)), "none"), Vec::new());
    first_version(&world, &rig);
    stage(&world, &rig, "v3-life-heads-2");
    stage(&world, &rig, "v3-life-heads-3");
    rig.store.commit(&commit_of(&world, F2)).unwrap();
    let (original, first, second) = (original_of(&world), commit_of(&world, F1).candidate, commit_of(&world, F2).candidate);
    let rollback = |request_id: &str, manifest: &str| Rollback {
        request_id: request_id.to_string(),
        model_id: MODEL.to_string(),
        manifest: manifest.to_string(),
    };
    // Back to the ORIGINAL, which was never signed: it is published now with empty lineage and the next sequence.
    let receipt = rig.store.rollback(&rollback("rollback-1", &original)).unwrap();
    assert_eq!((receipt.status.as_str(), receipt.reason.as_str(), receipt.base.as_str()), ("applied", "rollback", second.as_str()));
    assert_served(&rig, &original, 3);
    let statement = publication::verify(&keys(), &rig.publisher.served(MODEL).unwrap().unwrap().statement).unwrap();
    assert_eq!((statement.parent.as_str(), statement.original.as_str()), ("", ""));
    assert_eq!(rig.store.resolve(MODEL).unwrap(), original);
    // The same request answers from its receipt; a different payload under its id is refused.
    assert_eq!(rig.store.rollback(&rollback("rollback-1", &original)).unwrap(), receipt);
    assert_eq!(
        rig.store.rollback(&rollback("rollback-1", &first)).unwrap_err(),
        StoreError::Invalid("Request ID reused with different commit content.".to_string())
    );
    // Forward to an earlier published version: its directory exists, its statement is renewed with a higher sequence.
    assert_eq!(rig.store.rollback(&rollback("rollback-2", &first)).unwrap().status, "applied");
    assert_served(&rig, &first, 4);
    // To the version already served: refused as a receipt, nothing is signed.
    let unchanged = rig.store.rollback(&rollback("rollback-3", &first)).unwrap();
    assert_eq!((unchanged.status.as_str(), unchanged.reason.as_str()), ("rejected", "already_current"));
    // A manifest outside the history (staged, never current), another model and a malformed digest are refused and change nothing.
    let outside = commit_of(&world, F3).candidate;
    assert_eq!(
        rig.store.rollback(&rollback("rollback-4", &outside)).unwrap_err(),
        StoreError::Invalid("Rollback target is not in the history of this model.".to_string())
    );
    let other_model = Rollback { model_id: "privoke-v3-balanced".to_string(), ..rollback("rollback-5", &first) };
    assert!(rig.store.rollback(&other_model).is_err());
    assert!(rig.store.rollback(&rollback("rollback-6", "ABC")).is_err());
    assert_eq!(rig.store.publications(MODEL).unwrap().len(), 4);
    assert_eq!(rig.store.resolve(MODEL).unwrap(), first);
    assert_eq!(staged_entries(&rig), 0);
}

#[test]
fn reconciliation_repairs_the_pointer_and_the_directories_from_the_authority() {
    let world = World::load();
    let rig = rig(hook(&Arc::new(AtomicBool::new(false)), "none"), Vec::new());
    first_version(&world, &rig);
    stage(&world, &rig, "v3-life-heads-2");
    rig.store.commit(&commit_of(&world, F2)).unwrap();
    let (first, second) = (commit_of(&world, F1).candidate, commit_of(&world, F2).candidate);
    let model_dir = rig.root().join(MODEL);
    // Damage: the pointer is gone, the served version lost its statement, an older version's directory is gone, and the tree holds
    // directories the authority does not reference.
    std::fs::remove_file(model_dir.join("current")).unwrap();
    std::fs::remove_file(model_dir.join(&second).join("statement.json")).unwrap();
    std::fs::remove_dir_all(model_dir.join(&first)).unwrap();
    std::fs::create_dir_all(model_dir.join("c".repeat(64))).unwrap();
    std::fs::create_dir_all(rig.root().join(".staging").join(MODEL).join(format!("{}.0000000000000000", "d".repeat(64)))).unwrap();
    std::fs::create_dir_all(rig.root().join(".staging").join("privoke-v3-unknown").join("junk")).unwrap();
    let report = rig.publisher.reconcile(&rig.store).unwrap();
    assert_eq!(report.rebuilt, 2, "the incomplete version and the missing one are rebuilt from the store ({report:?})");
    assert!(report.quarantined >= 4, "the unreferenced directories and the incomplete one are quarantined ({report:?})");
    assert_served(&rig, &second, 2);
    assert!(model_dir.join(&first).join("statement.json").is_file());
    assert!(!model_dir.join("c".repeat(64)).exists());
    assert_eq!(staged_entries(&rig), 0);
    // Reconciling a consistent tree changes nothing.
    assert_eq!(rig.publisher.reconcile(&rig.store).unwrap().quarantined, 0);
}

fn bounds(update: f64, cumulative: f64) -> DriftBounds {
    let mut text = format!("schema = 1\nstatus = \"provisional\"\nevidence_sha256 = \"{}\"\n", "a".repeat(64));
    for tier in ["efficient", "balanced", "quality"] {
        for scope in ["heads", "full_encoder"] {
            text.push_str(&format!("[{tier}.{scope}]\nmax_update_l2 = {update}\nmax_cumulative_l2 = {cumulative}\n"));
        }
    }
    DriftBounds::parse(&text).unwrap()
}

#[test]
fn an_over_budget_candidate_is_refused_before_anything_is_staged_signed_or_published() {
    let world = World::load();
    // The synthetic candidates move about 21 in L2 from their base and from the ORIGINAL.
    for (update, cumulative, applied) in [(1000.0, 1000.0, true), (10.0, 1000.0, false), (1000.0, 10.0, false)] {
        let gates: Vec<Arc<dyn CommitObserver>> = vec![Arc::new(DriftGate::new(bounds(update, cumulative)))];
        let rig = rig(hook(&Arc::new(AtomicBool::new(false)), "none"), gates);
        run(&world, &rig, "bootstrap", "efficient").unwrap();
        stage(&world, &rig, "v3-life-heads-1");
        let receipt = rig.store.commit(&commit_of(&world, F1)).unwrap();
        if applied {
            assert_eq!(receipt.status, "applied");
            assert_served(&rig, &commit_of(&world, F1).candidate, 1);
        } else {
            assert_eq!((receipt.status.as_str(), receipt.reason.as_str()), ("rejected", "drift_exceeded"), "{update} {cumulative}");
            assert_eq!(rig.store.resolve(MODEL).unwrap(), original_of(&world), "nothing changed");
            assert!(rig.store.publications(MODEL).unwrap().is_empty());
            assert!(rig.publisher.served(MODEL).unwrap().is_none());
            assert_eq!(staged_entries(&rig), 0);
        }
    }
}
