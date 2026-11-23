//! The V3 retention gate (acceptance checks of stage V3-R9): a regressing candidate is refused with a receipt and a
//! non-regressing one passes; the verdict is computed before the transaction, bound to the candidate and only checked by the
//! commit; and a slow retention check (a quality-tier scoring takes minutes) leaves every other call free to meet its deadline.
//!
//! The gate and the commit path are played on the golden world of the checkpoint store (the states are reached by replaying its
//! steps; its checkpoints are not loadable models), through a scorer seam. The real scoring path (the store's bytes, the candidate
//! loaded over the parent's checkpoint with `V3Model::with_tensors`) is played on the stage 22 toy package.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod golden_world;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use golden_world::{World, au3_manifest, bc01_paths, perform};
use privoke_contracts::digest::sha256_hex;
use privoke_contracts::json::Value;
use privoke_contracts::proto::experimental_v3::{Commit, Receipt, Rollback};
use privoke_curriculum::audience::BUNDLED_MANIFEST_SHA256;
use privoke_param_update::v3_retention::{RETENTION_REGRESSED, RetentionGate, RetentionReleases, RetentionScorer, Verdict, assess_blobs};
use privoke_param_update::v3_store::{
    AudienceSource, Candidate, ChainObserver, CheckpointStore, CommitObserver, PinnedSources, StoreError, Swap,
};
use privoke_semantic::V3Model;
use privoke_semantic::safetensors::{self, Tensor};
use privoke_training::reference::BankSpec;
use privoke_training::retention_v3::{ReleaseSpec, RetentionRelease, Rule, build_release, prediction_of};
use serde_json::{Value as Json, json};

const EFFICIENT: &str = "privoke-v3-efficient";
const BALANCED: &str = "privoke-v3-balanced";

fn pinned() -> Arc<PinnedSources> {
    Arc::new(PinnedSources::new(
        bc01_paths(),
        AudienceSource::Trusted { path: au3_manifest(), sha256: BUNDLED_MANIFEST_SHA256.to_string() },
    ))
}

fn story<'a>(world: &'a World, name: &str) -> &'a Json {
    world.golden["stories"].as_array().unwrap().iter().find(|story| story["name"] == name).unwrap()
}

fn step<'a>(story: &'a Json, op: &str, label: &str) -> &'a Json {
    story["steps"].as_array().unwrap().iter().find(|step| step["op"] == op && step["label"] == label).unwrap()
}

/// A release that carries no references: the scorers of these tests answer from their own seam.
fn release(model_id: &str) -> RetentionRelease {
    RetentionRelease {
        sha256: "f".repeat(64),
        model_id: model_id.to_string(),
        teacher: json!({}),
        rule: Rule { max_violations: 0 },
        references: Vec::new(),
    }
}

fn releases(models: &[&str]) -> RetentionReleases {
    RetentionReleases::from_releases(models.iter().map(|model| release(model)))
}

/// A scorer that answers what the test says and counts its calls.
#[derive(Debug)]
struct Counting {
    violations: usize,
    calls: AtomicUsize,
}

impl Counting {
    fn new(violations: usize) -> Arc<Self> {
        Arc::new(Self { violations, calls: AtomicUsize::new(0) })
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl RetentionScorer for Counting {
    fn assess(&self, _store: &CheckpointStore, _manifest: &Value, release: &RetentionRelease) -> Result<Verdict, StoreError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(Verdict { eligible: 180, violations: self.violations, max_violations: release.rule.max_violations })
    }
}

struct Rig {
    _scratch: tempfile::TempDir,
    store: Arc<CheckpointStore>,
    gate: Arc<RetentionGate>,
    world: World,
}

/// A store with both tiers bootstrapped, the candidates `heads-1`, `heads-2` and `heads-3` staged, and a retention gate that
/// judges with `scorer` over the releases of `models`.
fn rig(scorer: Arc<dyn RetentionScorer>, models: &[&str]) -> Rig {
    let world = World::load();
    let scratch = tempfile::tempdir().unwrap();
    let gate = Arc::new(RetentionGate::new(releases(models)).with_scorer(scorer));
    let store = CheckpointStore::open(scratch.path().join("store"), pinned())
        .unwrap()
        .with_observer(Arc::new(ChainObserver::new(vec![gate.clone()])));
    let work = scratch.path().join("work");
    std::fs::create_dir_all(&work).unwrap();
    let lifecycle = story(&world, "bc01-lifecycle");
    let tiers = story(&world, "two-tiers");
    perform(&world, &store, step(lifecycle, "bootstrap", "efficient"), &work).unwrap();
    perform(&world, &store, step(tiers, "bootstrap", "balanced"), &work).unwrap();
    for index in 1..=3 {
        for what in ["evidence", "candidate"] {
            let label = format!("{what} of v3-life-heads-{index}");
            perform(&world, &store, step(lifecycle, "stage", &label), &work).unwrap();
        }
    }
    Rig { _scratch: scratch, store: Arc::new(store), gate, world }
}

impl Rig {
    fn commit_of(&self, label: &str) -> Commit {
        let request = &step(story(&self.world, "bc01-lifecycle"), "commit", label)["request"];
        let field = |name: &str| request[name].as_str().unwrap().to_string();
        Commit {
            request_id: field("request_id"),
            model_id: field("model_id"),
            expected_base: field("expected_base"),
            candidate: field("candidate"),
            evidence: field("evidence"),
        }
    }

    fn original_of(&self, model: &str) -> String {
        let (name, label) = if model == EFFICIENT { ("bc01-lifecycle", "efficient") } else { ("two-tiers", "balanced") };
        step(story(&self.world, name), "bootstrap", label)["manifest"].as_str().unwrap().to_string()
    }
}

fn swap<'a>(store: &'a CheckpointStore, base: &'a str, candidate: &'a str, request: &'a str, rollback: bool) -> Swap<'a> {
    Swap { store, model_id: EFFICIENT, base, candidate, request_id: request, evidence: None, rollback }
}

fn outcome(receipt: &Receipt) -> (&str, &str) {
    (receipt.status.as_str(), receipt.reason.as_str())
}

#[test]
fn a_regressing_candidate_is_refused_with_a_receipt_and_a_non_regressing_one_passes() {
    // Regressed on one row of the bank: rejected, nothing changes, nothing is left of the verdict.
    let scorer = Counting::new(1);
    let rig = rig(scorer.clone(), &[EFFICIENT, BALANCED]);
    let commit = rig.commit_of("commit v3-life-heads-1");
    let receipt = rig.store.commit(&commit).unwrap();
    assert_eq!(outcome(&receipt), ("rejected", RETENTION_REGRESSED));
    assert_eq!(rig.store.resolve(EFFICIENT).unwrap(), commit.expected_base, "the candidate was not served");
    assert_eq!(rig.store.history(EFFICIENT).unwrap().len(), 1, "the candidate never entered the history");
    assert_eq!(scorer.calls(), 1);
    assert_eq!(rig.gate.verdict(EFFICIENT, &commit.candidate, &commit.request_id), None, "a refused commit leaves no verdict");
    // The refusal is idempotent: the receipt answers a retry, nothing is scored again.
    assert_eq!(outcome(&rig.store.commit(&commit).unwrap()), ("rejected", RETENTION_REGRESSED));
    assert_eq!(scorer.calls(), 1);

    // No regression: applied, served, and the verdict is released with the commit.
    let scorer = Counting::new(0);
    let rig = self::rig(scorer.clone(), &[EFFICIENT, BALANCED]);
    let commit = rig.commit_of("commit v3-life-heads-1");
    let receipt = rig.store.commit(&commit).unwrap();
    assert_eq!(outcome(&receipt), ("applied", ""));
    assert_eq!(rig.store.resolve(EFFICIENT).unwrap(), commit.candidate);
    assert_eq!(scorer.calls(), 1);
    assert_eq!(rig.gate.verdict(EFFICIENT, &commit.candidate, &commit.request_id), None);
}

#[test]
fn a_stale_base_is_not_scored_and_a_rollback_is_exempt() {
    let scorer = Counting::new(0);
    let rig = rig(scorer.clone(), &[EFFICIENT, BALANCED]);
    let first = rig.commit_of("commit v3-life-heads-1");
    assert_eq!(outcome(&rig.store.commit(&first).unwrap()), ("applied", ""));
    assert_eq!(outcome(&rig.store.commit(&rig.commit_of("commit v3-life-heads-2")).unwrap()), ("applied", ""));
    assert_eq!(scorer.calls(), 2);
    // heads-3 was fitted on the version that heads-2 replaced: `stale_base`, and the expensive scoring is not spent on it.
    let stale = rig.commit_of("a stale base is rejected, not an error");
    let calls = scorer.calls();
    assert_eq!(outcome(&rig.store.commit(&stale).unwrap()), ("rejected", "stale_base"));
    assert_eq!(scorer.calls(), calls, "a stale base is not scored");
    // A rollback to the ORIGINAL returns to a version that passed (here, the pinned release itself): no scoring.
    let rollback = Rollback { request_id: "rollback-1".to_string(), model_id: EFFICIENT.to_string(), manifest: rig.original_of(EFFICIENT) };
    assert_eq!(outcome(&rig.store.rollback(&rollback).unwrap()), ("applied", "rollback"));
    assert_eq!(rig.store.resolve(EFFICIENT).unwrap(), rig.original_of(EFFICIENT));
    assert_eq!(scorer.calls(), calls, "a rollback is not scored");
}

#[test]
fn a_tier_without_a_reference_release_is_an_error_not_a_pass() {
    let scorer = Counting::new(0);
    let rig = rig(scorer.clone(), &[BALANCED]);
    let commit = rig.commit_of("commit v3-life-heads-1");
    let error = rig.store.commit(&commit).unwrap_err();
    assert!(error.to_string().contains("No retention release is configured for privoke-v3-efficient"), "{error}");
    assert_eq!(rig.store.resolve(EFFICIENT).unwrap(), commit.expected_base);
    assert_eq!(
        rig.store.status(&commit.request_id).unwrap().status,
        "unknown",
        "no receipt: the request can be retried once the release is configured"
    );
    assert_eq!(scorer.calls(), 0);
}

/// The transaction asks for the verdict of exactly this candidate and this request: a commit that reaches its swap without a
/// passing verdict of its own (a wiring mistake, a rollback of the base back to current between the check and the swap) is refused.
#[test]
fn the_commit_only_checks_the_verdict_of_this_candidate_and_this_request() {
    let rig = rig(Counting::new(0), &[EFFICIENT, BALANCED]);
    let commit = rig.commit_of("commit v3-life-heads-1");
    let other = rig.commit_of("commit v3-life-heads-2");
    let manifest = rig.store.manifest(&commit.candidate).unwrap();
    let evidence = json!({});
    let connection = rusqlite::Connection::open_in_memory().unwrap();
    // Before `prepare` there is no verdict: the swap is refused.
    assert!(
        rig.gate.before_swap(&swap(&rig.store, &commit.expected_base, &commit.candidate, &commit.request_id, false), &connection).is_err()
    );
    // A rollback needs none.
    assert!(
        rig.gate.before_swap(&swap(&rig.store, &commit.expected_base, &commit.candidate, &commit.request_id, true), &connection).is_ok()
    );
    let candidate = Candidate {
        store: &rig.store,
        model_id: EFFICIENT,
        manifest_sha: &commit.candidate,
        request_id: &commit.request_id,
        expected_base: &commit.expected_base,
        manifest: &manifest,
        evidence: Some(&evidence),
    };
    assert_eq!(rig.gate.prepare(&candidate).unwrap(), None, "the candidate retains");
    assert_eq!(rig.gate.verdict(EFFICIENT, &commit.candidate, &commit.request_id).map(|verdict| verdict.passes()), Some(true));
    // The verdict belongs to the candidate and the request it was computed for.
    assert!(
        rig.gate.before_swap(&swap(&rig.store, &commit.expected_base, &commit.candidate, &commit.request_id, false), &connection).is_ok()
    );
    assert!(
        rig.gate.before_swap(&swap(&rig.store, &commit.expected_base, &other.candidate, &commit.request_id, false), &connection).is_err(),
        "another candidate"
    );
    assert!(
        rig.gate.before_swap(&swap(&rig.store, &commit.expected_base, &commit.candidate, "another request", false), &connection).is_err(),
        "another request"
    );
    // It is released when the commit is abandoned.
    rig.gate.abandon(EFFICIENT, &commit.candidate, &commit.request_id);
    assert!(
        rig.gate.before_swap(&swap(&rig.store, &commit.expected_base, &commit.candidate, &commit.request_id, false), &connection).is_err()
    );
    // A regressed verdict is never good enough for a swap, even if a caller reached it.
    let regressed = self::rig(Counting::new(2), &[EFFICIENT]);
    let candidate = Candidate { store: &regressed.store, ..candidate };
    assert_eq!(regressed.gate.prepare(&candidate).unwrap().as_deref(), Some(RETENTION_REGRESSED));
    let swap = swap(&regressed.store, &commit.expected_base, &commit.candidate, &commit.request_id, false);
    assert!(regressed.gate.before_swap(&swap, &connection).is_err());
}

/// A scorer that parks the scoring of one candidate until the test lets it go, as a quality-tier scoring takes minutes.
#[derive(Debug)]
struct Parked {
    manifest: Mutex<Option<Value>>,
    entered: Mutex<Option<mpsc::Sender<()>>>,
    resume: Mutex<mpsc::Receiver<()>>,
}

impl RetentionScorer for Parked {
    fn assess(&self, _store: &CheckpointStore, manifest: &Value, release: &RetentionRelease) -> Result<Verdict, StoreError> {
        if self.manifest.lock().unwrap().as_ref() == Some(manifest) {
            if let Some(sender) = self.entered.lock().unwrap().take() {
                sender.send(()).unwrap();
            }
            self.resume.lock().unwrap().recv_timeout(Duration::from_secs(120)).expect("the test lets the scoring go");
        }
        Ok(Verdict { eligible: 180, violations: 0, max_violations: release.rule.max_violations })
    }
}

/// The deadline an unrelated call must meet while a retention check runs: its own work is milliseconds.
const DEADLINE: Duration = Duration::from_secs(10);

/// The retention check runs before the transaction and holds no store lock (the plan's V3-R9 hoist): while one candidate's
/// scoring is parked, other calls complete within their deadline: a read of the other tier, the status of an earlier request, a
/// transaction on the other tier, and a whole commit (admission, gates, transaction) of the same tier, which applies and makes
/// the parked one stale.
#[test]
fn other_calls_meet_their_deadlines_while_a_slow_retention_check_runs() {
    let (entered_tx, entered_rx) = mpsc::channel();
    let (resume_tx, resume_rx) = mpsc::channel();
    let scorer = Arc::new(Parked { manifest: Mutex::new(None), entered: Mutex::new(Some(entered_tx)), resume: Mutex::new(resume_rx) });
    let rig = rig(scorer.clone(), &[EFFICIENT, BALANCED]);
    // heads-1 applies first (its scoring is immediate), so that heads-2 and heads-3 share the base heads-1 left.
    let first = rig.commit_of("commit v3-life-heads-1");
    assert_eq!(outcome(&rig.store.commit(&first).unwrap()), ("applied", ""));
    let slow = rig.commit_of("commit v3-life-heads-2");
    *scorer.manifest.lock().unwrap() = Some(rig.store.manifest(&slow.candidate).unwrap());
    let overtaking = rig.commit_of("a stale base is rejected, not an error");

    let balanced_original = rig.original_of(BALANCED);
    let store = rig.store.clone();
    let slow_commit = {
        let (store, slow) = (store.clone(), slow.clone());
        std::thread::spawn(move || store.commit(&slow).unwrap())
    };
    entered_rx.recv_timeout(Duration::from_secs(60)).expect("the slow candidate reaches its scoring");

    // The scoring of heads-2 is now parked inside `prepare`. Everything below must complete without waiting for it.
    let (done_tx, done_rx) = mpsc::channel();
    let other = {
        let (store, done) = (store.clone(), done_tx);
        let (first, overtaking) = (first.clone(), overtaking.clone());
        std::thread::spawn(move || {
            let mut timings: Vec<(&'static str, Duration)> = Vec::new();
            let mut time = |name: &'static str, work: &mut dyn FnMut()| {
                let started = Instant::now();
                work();
                timings.push((name, started.elapsed()));
            };
            time("resolve of the other tier", &mut || {
                assert_eq!(store.resolve(BALANCED).unwrap(), balanced_original);
            });
            time("status of an earlier request", &mut || {
                let receipt = store.status(&first.request_id).unwrap();
                assert_eq!(outcome(&receipt), ("applied", ""));
            });
            time("a transaction on the other tier", &mut || {
                let rollback = Rollback {
                    request_id: "balanced-noop".to_string(),
                    model_id: BALANCED.to_string(),
                    manifest: balanced_original.clone(),
                };
                let receipt = store.rollback(&rollback).unwrap();
                assert_eq!(outcome(&receipt), ("rejected", "already_current"));
            });
            time("a whole commit of the same tier", &mut || {
                let receipt = store.commit(&overtaking).unwrap();
                assert_eq!(outcome(&receipt), ("applied", ""));
            });
            done.send(timings).unwrap();
        })
    };
    let timings = done_rx
        .recv_timeout(DEADLINE)
        .expect("the other calls were blocked by the retention check that is still running (a lock is held across it)");
    other.join().unwrap();
    for (name, elapsed) in &timings {
        assert!(*elapsed < DEADLINE, "{name} took {elapsed:?}");
    }
    assert!(!slow_commit.is_finished(), "the slow check is still running while the others completed");

    // Let the scoring finish: it retains, but the overtaking commit already moved the base, so the receipt is `stale_base`.
    resume_tx.send(()).unwrap();
    let receipt = slow_commit.join().unwrap();
    assert_eq!(outcome(&receipt), ("rejected", "stale_base"));
    assert_eq!(rig.store.resolve(EFFICIENT).unwrap(), overtaking.candidate);
    assert_eq!(rig.gate.verdict(EFFICIENT, &slow.candidate, &slow.request_id), None, "the verdict is released");
}

// ---------------------------------------------------------------------------------------------------------------------------
// The real scoring path on the stage 22 toy package.
// ---------------------------------------------------------------------------------------------------------------------------

fn package() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../crates/privoke-semantic/tests/fixtures/v3_synthetic")
}

const GROUPS: usize = 6;
const PER_GROUP: usize = 4;
const TEACHER_PIN: &str = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";

/// A bank over the toy vocabulary whose rows the toy teacher predicts with a severity and a positive margin and gap.
fn bank(teacher: &V3Model) -> Vec<u8> {
    let words = ["account", "afraid", "age", "alone", "an", "and", "are", "arrested", "article", "at", "avenue", "bank", "be", "brother"];
    let mut state = 0x2545_f491_4f6c_dd1du64;
    let mut rows: Vec<Json> = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for _ in 0..600 {
        let mut text = Vec::new();
        for _ in 0..4 {
            state = state.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
            text.push(words[((state >> 33) as usize) % words.len()]);
        }
        let text = text.join(" ");
        if !seen.insert(text.clone()) {
            continue;
        }
        let (prediction, gap) = prediction_of(&teacher.logits(&text).unwrap()).unwrap();
        if prediction.packed & 0b11 == 0 || prediction.margin <= 1e-6 || gap <= 1e-6 {
            continue;
        }
        let index = rows.len();
        rows.push(json!({
            "id": format!("row-{index:02}"), "text": text, "packed_classification": 6,
            "metadata": {"taxonomy_partition": "train", "split": "train", "group_id": format!("g{}", index % GROUPS)}
        }));
        if rows.len() == GROUPS * PER_GROUP {
            break;
        }
    }
    assert_eq!(rows.len(), GROUPS * PER_GROUP, "the toy teacher found too few sensitive rows");
    serde_json::to_vec(&rows).unwrap()
}

fn toy_release(teacher: &V3Model) -> RetentionRelease {
    let bank = bank(teacher);
    let bank_sha = sha256_hex(&bank);
    let spec = BankSpec { sha256: &bank_sha, rows: GROUPS * PER_GROUP, groups: GROUPS };
    let identity = json!({"model_id": EFFICIENT, "manifest_sha256": TEACHER_PIN});
    let built = build_release(&bank, &spec, teacher, &identity, &|_| 0, &mut |_| {}).unwrap();
    let manifest_sha = built.manifest_sha256();
    let release_spec =
        ReleaseSpec { model_id: EFFICIENT, teacher_manifest_sha256: TEACHER_PIN, manifest_sha256: &manifest_sha, bank: spec };
    RetentionRelease::load(&bank, built.references.as_bytes(), built.manifest.as_bytes(), &release_spec).unwrap()
}

/// A safetensors file of float32 tensors (what the store holds as a checkpoint blob).
fn encode(tensors: &BTreeMap<String, Tensor>) -> Vec<u8> {
    let (mut header, mut body, mut offset) = (Vec::new(), Vec::new(), 0usize);
    for (name, tensor) in tensors {
        let dims: Vec<String> = tensor.shape.iter().map(ToString::to_string).collect();
        let bytes: Vec<u8> = tensor.data.iter().flat_map(|value| value.to_le_bytes()).collect();
        header.push(format!(
            "\"{name}\":{{\"dtype\":\"F32\",\"shape\":[{}],\"data_offsets\":[{offset},{}]}}",
            dims.join(","),
            offset + bytes.len()
        ));
        offset += bytes.len();
        body.extend_from_slice(&bytes);
    }
    let mut encoded = format!("{{{}}}", header.join(",")).into_bytes();
    while encoded.len() % 8 != 0 {
        encoded.push(b' ');
    }
    let mut file = (encoded.len() as u64).to_le_bytes().to_vec();
    file.extend_from_slice(&encoded);
    file.extend_from_slice(&body);
    file
}

/// The production scoring path (the store's hash-checked bytes, the parent's checkpoint as the shell, the candidate loaded over it
/// with `with_tensors`) gives what scoring the loaded candidate directly gives, refuses a candidate that forgot its sensitive
/// class and passes the unchanged teacher.
#[test]
fn the_real_scoring_path_judges_a_candidate_by_its_own_weights() {
    let dir = package();
    let teacher = V3Model::from_files(&dir.join("config.json"), &dir.join("model.safetensors"), &dir.join("vocab.txt")).unwrap();
    let release = toy_release(&teacher);
    let scratch = tempfile::tempdir().unwrap();
    let store = CheckpointStore::open(scratch.path().join("store"), pinned()).unwrap();
    let put = |bytes: &[u8]| store.put(bytes).unwrap();
    let base_bytes = std::fs::read(dir.join("model.safetensors")).unwrap();
    let (config, vocab, base) =
        (put(&std::fs::read(dir.join("config.json")).unwrap()), put(&std::fs::read(dir.join("vocab.txt")).unwrap()), put(&base_bytes));

    let direct = |tensors: BTreeMap<String, Tensor>| release.assess(&teacher.with_tensors(tensors).unwrap()).unwrap();
    let verdict = |blob: &str| assess_blobs(&store, &release, &config, &vocab, &base, blob, 2).unwrap();

    // The unchanged teacher retains everything.
    let unchanged = verdict(&base);
    assert_eq!((unchanged.violations, unchanged.eligible, unchanged.passes()), (0, release.references.len(), true));

    // A candidate whose S0 logit dominates reads every text as clean: it regressed on every eligible row.
    let mut forgetful = safetensors::parse(&base_bytes).unwrap();
    forgetful.get_mut("heads.sensitivity_bias").unwrap().data[0] += 1_000.0;
    let expected = direct(forgetful.clone());
    let refused = verdict(&put(&encode(&forgetful)));
    assert_eq!((refused.violations, refused.passes()), (expected.violations, expected.passes()));
    assert_eq!((refused.violations, refused.passes()), (release.references.len(), false));

    // The toy fits of stage 22 are other weights; whatever they do, the verdict is the rule applied to the loaded candidate.
    for scope in ["heads", "full_encoder"] {
        let path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("../../crates/privoke-training/tests/fixtures/v3_fit/{scope}.safetensors"));
        let bytes = std::fs::read(path).unwrap();
        let expected = direct(safetensors::parse(&bytes).unwrap());
        let judged = verdict(&put(&bytes));
        assert_eq!((judged.violations, judged.passes()), (expected.violations, expected.passes()), "{scope}");
    }
    // A blob the store does not hold is refused, not read from a path.
    assert!(assess_blobs(&store, &release, &config, &vocab, &base, &"0".repeat(64), 2).is_err());
}

#[test]
fn production_releases_are_refused_until_they_match_their_pins() {
    let scratch = tempfile::tempdir().unwrap();
    let missing = RetentionReleases::load(scratch.path(), &scratch.path().join("approved-train-bank.json"));
    assert!(missing.is_err(), "a missing bank or release is an error, never an empty gate");
    std::fs::write(scratch.path().join("approved-train-bank.json"), b"[]").unwrap();
    let wrong_bank = RetentionReleases::load(scratch.path(), &scratch.path().join("approved-train-bank.json"));
    assert!(wrong_bank.is_err(), "{wrong_bank:?}");
}

/// The production releases of the three tiers authenticate against the compiled pins and the approved bank. Environment gated
/// (the bank holds prompt text and is not in the repository): `PRIVOKE_V3_RETENTION_ROOT` and `PRIVOKE_V3_RETENTION_BANK`.
#[test]
fn the_production_releases_load_under_their_compiled_pins() {
    let (Some(root), Some(bank)) = (std::env::var_os("PRIVOKE_V3_RETENTION_ROOT"), std::env::var_os("PRIVOKE_V3_RETENTION_BANK")) else {
        eprintln!("PRIVOKE_V3_RETENTION_ROOT is unset: skipped");
        return;
    };
    let releases = RetentionReleases::load(Path::new(&root), Path::new(&bank)).unwrap();
    for model in ["privoke-v3-efficient", "privoke-v3-balanced", "privoke-v3-quality"] {
        let release = releases.get(model).unwrap();
        eprintln!("{model}: {} eligible, allows {}", release.references.len(), release.rule.max_violations);
        assert_eq!(release.rule.max_violations, release.references.len() / 20);
    }
}
