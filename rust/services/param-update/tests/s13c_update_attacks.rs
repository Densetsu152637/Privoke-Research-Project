//! Stage 13c-1 (`docs/plans/asiaccs-stage13-experiments.md`): the attack matrix against the real V3 guarded update path, in CI.
//!
//! Every row of `tests/s13c_rows.json` whose surface is `param-update`, `model-streaming` or `store` is driven here, against a real
//! [`CheckpointStore`] whose observers come from [`build_observers`] (the seam `main.rs` uses): the drift gate with the shipped
//! `config/v3-drift-bounds.toml`, the guard gate over a test allocation table, the retention gate and the signing `Publisher`.
//! Calls go through the real `CheckpointService` over mutual TLS as the `trainer` principal (a `publisher` principal for a
//! rollback). Rows with `wire_path: false` (crash points, at-rest corruption, the in-process model-streaming reads) use the store
//! and the model-streaming library directly. The client rows (`surface: client`) are `runtime-supervisor`'s `s13c_client_admission`.
//!
//! Stand-ins, as in `scheduler_chain.rs`: the checkpoints are generated here (the real tier layout, zero-filled except the first value
//! of each tensor, with the official `config.json` and `vocab.txt`; no weights are committed), the guard and retention scorers are
//! test doubles scripted per candidate, and the store's source validation accepts the evidence source (the golden test owns it). The
//! guard rows, the routine commitments and the evidence source are the real ones of the frozen BC01 release. The retention release
//! carries the allowance of the committed `config/v3-retention/efficient/manifest.json`. That release cannot be authenticated in CI
//! (its approved bank is not in the repository), so the test adds the retention gate in front of the publisher itself and
//! `build_observers` is given a configuration without retention.
//!
//! "Unchanged" is the authority, not the blob directory: the `current` row, the `versions`, the `publications` (count and highest
//! sequence) and the version model-streaming serves. Rejected candidates may leave orphan blobs, which are reported and not counted.
//!
//! With `S13C_OUT=<directory>` the test writes its rows to `<directory>/s13c_update_attacks.rows.json`. Every row asserts its own
//! expected outcome, so CI fails on any regression. CI bundles use stand-in weights and are never used against the containers.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::too_many_arguments, clippy::too_many_lines, clippy::type_complexity)]

mod common;
mod golden_world;
// The allocation format (`S13C_ALLOCATIONS`), defined once there and read strictly.
mod s13c_allocations;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};

use common::{Creds, Env, engine, generous, repo_root};
use golden_world::{au3_manifest, bc01_paths};
use privoke_contracts::digest::sha256_hex;
use privoke_contracts::json::Value;
use privoke_contracts::proto::experimental_v3::checkpoint_service_client::CheckpointServiceClient;
use privoke_contracts::proto::experimental_v3::{Chunk, Commit, Receipt, Rollback};
use privoke_contracts::publication::test_keys::{self, PRIMARY_ID};
use privoke_contracts::v3::{self as contract, CHUNK_BYTES, TIERS, Tier, VOCAB_SHA256, action_value, harm_count};
use privoke_curriculum::Example;
use privoke_curriculum::audience::BUNDLED_MANIFEST_SHA256;
use privoke_curriculum::v3::{self as curriculum, BC01_SAMPLER, Policy, RoutineRelease, routine_guard_rows, routine_guard_seed};
use privoke_curriculum::value;
use privoke_model_streaming::published::Published;
use privoke_model_streaming::releases::{ASSET_KEYS, STANDARD_IDS, StandardReleases, V3_ARCHITECTURE};
use privoke_param_update::build_observers;
use privoke_param_update::config::{PublicationConfig, V3Config};
use privoke_param_update::journal::{Journal, JournalAllocations, Stage};
use privoke_param_update::scheduler::{Commitments, PinnedCommitments};
use privoke_param_update::server::ServerHandle;
use privoke_param_update::v3_guard::{Allocation, Allocations, GuardScorer, StaticAllocations};
use privoke_param_update::v3_publish::{CrashHook, Publisher, Reconciled};
use privoke_param_update::v3_retention::{RetentionGate, RetentionReleases, RetentionScorer, Verdict};
use privoke_param_update::v3_store::{
    AudienceSource, ChainObserver, CheckpointHandler, CheckpointStore, PinnedSources, SourceEvidence, StoreError,
};
use privoke_training::retention_v3::{RetentionRelease, Rule};
use privoke_transport::{Limits, RateLimit};
use s13c_allocations::parse_allocations;
use serde_json::{Value as Json, json};
use tonic::transport::Channel;
use tonic::{Code, Status};

const MODEL: &str = "privoke-v3-efficient";
const HEADS: usize = 20 * 129;
/// The routine seed of every allocation.
const SEED: u32 = 20_261_124;
/// The scope label of every row of this study.
const SCOPE_LABEL: &str = "update path (Rust V3)";
/// The number of groups that must finish before the coverage of the manifest is judged (see [`group_done`]).
const GROUPS: usize = 9;

// ---------------------------------------------------------------------------------------------------------------------------
// The row manifest and the rows this test records.
// ---------------------------------------------------------------------------------------------------------------------------

fn manifest_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/s13c_rows.json")
}

fn manifest_rows() -> Vec<Json> {
    serde_json::from_slice(&std::fs::read(manifest_path()).unwrap()).unwrap()
}

fn manifest_row(id: &str) -> Json {
    manifest_rows().into_iter().find(|row| row["id"] == id).unwrap_or_else(|| panic!("{id} is not in s13c_rows.json"))
}

static ROWS: Mutex<Vec<Json>> = Mutex::new(Vec::new());
static FINISHED: AtomicUsize = AtomicUsize::new(0);

fn push_row(row: Json) {
    ROWS.lock().unwrap_or_else(PoisonError::into_inner).push(row);
}

/// A group of rows is finished. The last group to finish judges the whole: every manifest row of this binary has exactly one row, and
/// the rows are written to `S13C_OUT`. (A group that panics never counts, and fails its own test.)
fn group_done() {
    if FINISHED.fetch_add(1, Ordering::SeqCst) + 1 != GROUPS {
        return;
    }
    let mut rows = ROWS.lock().unwrap_or_else(PoisonError::into_inner).clone();
    rows.sort_by(|left, right| left["id"].as_str().cmp(&right["id"].as_str()));
    let recorded: Vec<String> = rows.iter().map(|row| row["id"].as_str().unwrap().to_string()).collect();
    let wanted: BTreeSet<String> =
        manifest_rows().iter().filter(|row| row["surface"] != "client").map(|row| row["id"].as_str().unwrap().to_string()).collect();
    assert_eq!(recorded.iter().cloned().collect::<BTreeSet<_>>(), wanted, "every manifest row of this binary has a row");
    assert_eq!(recorded.len(), wanted.len(), "no row is recorded twice");
    assert!(rows.iter().all(|row| row["property_met"] == true), "every row meets its property");
    if let Some(directory) = std::env::var_os("S13C_OUT").filter(|value| !value.is_empty()) {
        let directory = PathBuf::from(directory);
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::write(directory.join("s13c_update_attacks.rows.json"), serde_json::to_vec_pretty(&rows).unwrap()).unwrap();
    }
}

fn grpc_name(code: Code) -> String {
    let name = match code {
        Code::Ok => "OK",
        Code::InvalidArgument => "INVALID_ARGUMENT",
        Code::NotFound => "NOT_FOUND",
        Code::Internal => "INTERNAL",
        Code::DataLoss => "DATA_LOSS",
        Code::Unavailable => "UNAVAILABLE",
        Code::PermissionDenied => "PERMISSION_DENIED",
        Code::Unknown => "UNKNOWN",
        other => return format!("{other:?}").to_uppercase(),
    };
    name.to_string()
}

/// What a call answered.
#[derive(Debug, Clone)]
struct Outcome {
    code: Code,
    status: String,
    reason: String,
    message: String,
}

impl Outcome {
    fn of(result: Result<Receipt, Status>) -> Self {
        match result {
            Ok(receipt) => Self { code: Code::Ok, status: receipt.status, reason: receipt.reason, message: String::new() },
            Err(status) => {
                Self { code: status.code(), status: String::new(), reason: String::new(), message: status.message().to_string() }
            }
        }
    }

    fn of_stage(result: Result<String, Status>) -> Self {
        match result {
            Ok(_) => Self { code: Code::Ok, status: String::new(), reason: String::new(), message: String::new() },
            Err(status) => {
                Self { code: status.code(), status: String::new(), reason: String::new(), message: status.message().to_string() }
            }
        }
    }

    fn of_store(result: Result<Receipt, StoreError>) -> Self {
        match result {
            Ok(receipt) => Self::of(Ok(receipt)),
            Err(StoreError::Invalid(message)) => {
                Self { code: Code::InvalidArgument, status: String::new(), reason: String::new(), message }
            }
            Err(StoreError::Missing(message)) => Self { code: Code::NotFound, status: String::new(), reason: String::new(), message },
            Err(StoreError::Storage(message)) => Self { code: Code::Internal, status: String::new(), reason: String::new(), message },
        }
    }

    fn json(&self) -> Json {
        json!({"grpc_code": grpc_name(self.code), "receipt_status": self.status, "receipt_reason": self.reason, "message": self.message})
    }

    /// A refusal before any receipt: the code, and the message that names the check.
    fn assert_refused(&self, code: Code, message: &str) {
        assert_eq!((self.code, self.message.as_str()), (code, message), "{self:?}");
        assert!(self.status.is_empty(), "no receipt: {self:?}");
    }

    /// A `rejected` receipt with `reason`.
    fn assert_rejected(&self, reason: &str) {
        assert_eq!((self.code, self.status.as_str(), self.reason.as_str()), (Code::Ok, "rejected", reason), "{self:?}");
    }
}

// ---------------------------------------------------------------------------------------------------------------------------
// The frozen source: guard rows, commitments and the evidence source, computed once per seed.
// ---------------------------------------------------------------------------------------------------------------------------

struct SeedData {
    commitment: String,
    source: Json,
    targets: Vec<u16>,
}

struct Fixtures {
    pinned: Arc<PinnedSources>,
    commitments: PinnedCommitments,
    hashes: Value,
    seeds: Mutex<BTreeMap<u32, Arc<SeedData>>>,
}

/// The store's source validation is the golden test's business; the gates under test are the guard's and the others'.
#[derive(Debug)]
struct AcceptSources;

impl SourceEvidence for AcceptSources {
    fn validate(&self, _evidence: &Value) -> Result<(), StoreError> {
        Ok(())
    }
}

fn fixtures() -> &'static Fixtures {
    static FIXTURES: OnceLock<Fixtures> = OnceLock::new();
    FIXTURES.get_or_init(|| {
        let pinned = Arc::new(PinnedSources::new(
            bc01_paths(),
            AudienceSource::Trusted { path: au3_manifest(), sha256: BUNDLED_MANIFEST_SHA256.to_string() },
        ));
        let root = repo_root();
        let policy = value::canonical_bytes(&Policy::PILOT.to_value()).unwrap();
        let commitments = PinnedCommitments::new(&pinned, &root, &policy).unwrap();
        let hashes = curriculum::python_source_hashes(&root, &curriculum::BC01_SOURCE_FILES).unwrap();
        Fixtures { pinned, commitments, hashes, seeds: Mutex::new(BTreeMap::new()) }
    })
}

fn seed_data(seed: u32) -> Arc<SeedData> {
    let fixtures = fixtures();
    if let Some(found) = fixtures.seeds.lock().unwrap_or_else(PoisonError::into_inner).get(&seed) {
        return found.clone();
    }
    let commitment = fixtures.commitments.commitment(BC01_SAMPLER, seed).unwrap();
    let derived = routine_guard_seed(u64::from(seed), &commitment).unwrap();
    let sources = fixtures.pinned.bc01_sources().unwrap();
    let schedule = curriculum::schedule_bc01(derived, Policy::PILOT, sources.as_ref(), fixtures.hashes.clone()).unwrap();
    let rows = routine_guard_rows(RoutineRelease::Bc01(sources.as_ref()), u64::from(seed), &commitment).unwrap();
    let source: Json = serde_json::from_slice(&value::canonical_bytes(&schedule.source).unwrap()).unwrap();
    let targets = rows.iter().map(|row: &Example| row.packed().unwrap()).collect();
    let data = Arc::new(SeedData { commitment, source, targets });
    fixtures.seeds.lock().unwrap_or_else(PoisonError::into_inner).insert(seed, data.clone());
    data
}

// ---------------------------------------------------------------------------------------------------------------------------
// The toy checkpoints: the efficient tier's real layout, zero-filled except the first value of each tensor.
// ---------------------------------------------------------------------------------------------------------------------------

fn tier() -> &'static Tier {
    &TIERS[0]
}

fn fixture_file(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/v3_store").join(name)
}

/// The first value of the heads, and the first value of every encoder tensor: what a version differs in.
#[derive(Debug, Clone, Copy, PartialEq)]
struct Version {
    heads: f32,
    encoder: f32,
}

#[derive(Clone)]
struct Entry {
    name: String,
    shape: Vec<usize>,
    bytes: Vec<u8>,
}

fn entries(version: Version) -> Vec<Entry> {
    let tier = tier();
    let layers = tier.num_hidden_layers as usize;
    let rest = tier.parameters as usize - HEADS - layers - 1;
    let mut layout = vec![("encoder.embeddings.w".to_string(), rest)];
    layout.extend((0..layers).map(|index| (format!("encoder.encoder.layer.{index}.w"), 1)));
    layout.push(("encoder.pooler.dense.w".to_string(), 1));
    layout.push(("heads.w".to_string(), HEADS));
    layout
        .into_iter()
        .map(|(name, count)| {
            let mut bytes = vec![0u8; count * 4];
            let lead = if name.starts_with("heads.") { version.heads } else { version.encoder };
            bytes[..4].copy_from_slice(&lead.to_le_bytes());
            Entry { name, shape: vec![count], bytes }
        })
        .collect()
}

fn blob_of(entries: &[Entry]) -> Vec<u8> {
    let mut header = serde_json::Map::new();
    let mut body = Vec::new();
    for entry in entries {
        header.insert(
            entry.name.clone(),
            json!({"dtype": "F32", "shape": entry.shape, "data_offsets": [body.len(), body.len() + entry.bytes.len()]}),
        );
        body.extend_from_slice(&entry.bytes);
    }
    let header = serde_json::to_vec(&Json::Object(header)).unwrap();
    let mut file = (header.len() as u64).to_le_bytes().to_vec();
    file.extend_from_slice(&header);
    file.extend_from_slice(&body);
    file
}

/// The manifest's tensor inventory of `entries`, and the digest of each tensor.
fn inventory(entries: &[Entry]) -> (Json, BTreeMap<String, String>) {
    let mut tensors = serde_json::Map::new();
    let mut digests = BTreeMap::new();
    for entry in entries {
        let sha = sha256_hex(&entry.bytes);
        tensors.insert(entry.name.clone(), json!({"dtype": "F32", "shape": entry.shape, "sha256": sha}));
        digests.insert(entry.name.clone(), sha);
    }
    (Json::Object(tensors), digests)
}

fn canonical_json(document: &Json) -> Vec<u8> {
    value::canonical_bytes(&value::parse_bytes(document.to_string().as_bytes()).unwrap()).unwrap()
}

struct Parts<'a> {
    scope: &'a str,
    parent: &'a str,
    original: &'a str,
    evidence: &'a str,
    blob: &'a str,
    inventory: &'a Json,
}

fn manifest_json(parts: &Parts<'_>) -> Json {
    let tier = tier();
    json!({
        "schema": 1, "architecture": contract::ARCHITECTURE, "model_id": MODEL, "tier": tier.name, "parent": parts.parent,
        "original": parts.original, "blob": parts.blob, "config": tier.config_sha256, "vocab": VOCAB_SHA256, "evidence": parts.evidence,
        "source": {
            "repository": tier.repository, "revision": tier.revision, "weights_sha256": tier.weights_sha256,
            "config_sha256": tier.config_sha256, "vocab_sha256": VOCAB_SHA256
        },
        "tensors": parts.inventory, "parameter_count": tier.parameters, "scope": parts.scope
    })
}

fn digests_of(manifest: &Value) -> BTreeMap<String, String> {
    let Value::Object(map) = manifest else { panic!("object") };
    let Some(Value::Object(tensors)) = map.get("tensors") else { panic!("tensors") };
    tensors
        .iter()
        .map(|(name, tensor)| match tensor {
            Value::Object(fields) => match fields.get("sha256") {
                Some(Value::String(sha)) => (name.clone(), sha.clone()),
                _ => panic!("sha"),
            },
            _ => panic!("tensor"),
        })
        .collect()
}

fn text_of(document: &Value, key: &str) -> String {
    match document {
        Value::Object(map) => match map.get(key) {
            Some(Value::String(text)) => text.clone(),
            _ => String::new(),
        },
        _ => String::new(),
    }
}

/// How the guard rows of the evidence are shaped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Guard {
    /// The candidate corrects eight rows and harms none.
    Better,
    /// Honest evidence of a harm: the candidate takes a block action on a row whose target allows.
    Harm,
    /// The guard targets of the evidence are not the rows param-update rebuilds.
    SubstitutedRows,
}

/// How the source record of the evidence departs from the one the scheduler allocated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SourceFault {
    None,
    /// The source hashes name other files than the commitment covers.
    Hashes,
    /// The seed of the source record is not the one derived from the scheduler's seed (the trainer chose its own seed).
    Seed,
}

/// One candidate to build. The defaults are an honest heads fit over the base.
#[derive(Clone)]
struct Spec {
    request_id: String,
    base: String,
    scope: &'static str,
    version: Version,
    seed: u32,
    /// The evidence reports the changes of this version instead of the candidate's own (a dishonest `changed_tensors`).
    claimed: Option<Version>,
    /// A fault of the checkpoint that the manifest declares too (both agree on it).
    edit_both: Option<fn(&mut [Entry])>,
    /// A fault of the blob only (the manifest declares the unedited checkpoint).
    edit_blob: Option<fn(&mut [Entry])>,
    manifest_edit: Option<fn(&mut Json)>,
    guard: Guard,
    source: SourceFault,
}

impl Spec {
    fn heads(request_id: &str, base: &str, heads: f32) -> Self {
        Self {
            request_id: request_id.to_string(),
            base: base.to_string(),
            scope: "heads",
            version: Version { heads, encoder: 0.5 },
            seed: SEED,
            claimed: None,
            edit_both: None,
            edit_blob: None,
            manifest_edit: None,
            guard: Guard::Better,
            source: SourceFault::None,
        }
    }
}

/// A candidate, ready to stage and commit.
#[derive(Clone)]
struct Built {
    request_id: String,
    base: String,
    scope: &'static str,
    evidence: Vec<u8>,
    evidence_sha: String,
    blob: Vec<u8>,
    blob_sha: String,
    manifest: Vec<u8>,
    manifest_sha: String,
    heads: f32,
}

fn guard_rows(targets: &[u16], shape: Guard) -> (Vec<Json>, Vec<Json>) {
    let names = ["ALLOW", "WARN", "BLOCK"];
    let row = |prediction: u64, target: u64| {
        let action = |packed: u64, confidence: f64| action_value(u16::try_from(packed).unwrap(), Some(confidence));
        let (a, t) = (action(prediction, 0.999), action(target, 0.999));
        json!({
            "target": target, "prediction": prediction, "confidence": 0.999,
            "action": names[usize::try_from(a).unwrap()], "action_value": a,
            "target_action": names[usize::try_from(t).unwrap()], "target_action_value": t,
            "joint_correct": prediction == target && a == t
        })
    };
    let harmed = (shape == Guard::Harm)
        .then(|| targets.iter().position(|target| action_value(*target, Some(0.999)) == 0).expect("a guard row whose target allows"));
    targets
        .iter()
        .enumerate()
        .map(|(index, target)| {
            let target = u64::from(*target);
            let wrong = if target == 12 { 13 } else { 12 };
            let before = if harmed == Some(index) || index >= 8 { target } else { wrong };
            // 15 is a valid packed classification whose action is BLOCK.
            let after = if harmed == Some(index) { 15 } else { target };
            (row(before, target), row(after, target))
        })
        .unzip()
}

fn evidence_json(
    spec: &Spec,
    base_digests: &BTreeMap<String, String>,
    candidate_digests: &BTreeMap<String, String>,
    blob_sha: &str,
) -> Json {
    let tier = tier();
    let data = seed_data(spec.seed);
    let policy: Json = serde_json::from_slice(&value::canonical_bytes(&Policy::PILOT.to_value()).unwrap()).unwrap();
    let full = spec.scope == "full_encoder";
    let mut shown = data.targets.clone();
    if spec.guard == Guard::SubstitutedRows {
        shown[0] = if shown[0] == 12 { 13 } else { 12 };
    }
    let (before, after) = guard_rows(&shown, spec.guard);
    let summary = |rows: Vec<Json>| {
        let joint = rows.iter().filter(|row| row["joint_correct"] == true).count();
        let action = rows.iter().filter(|row| row["action"] == row["target_action"]).count();
        json!({"examples": rows.len(), "rows": rows, "joint_correct": joint, "action_correct": action})
    };
    let harms = harm_count(&Json::Array(before.clone()), &Json::Array(after.clone()));
    let (steps, rows, micro) =
        (policy["steps"].as_u64().unwrap(), policy["batch_rows"].as_u64().unwrap(), policy["microbatch"].as_u64().unwrap());
    let microbatches = steps * rows / micro;
    let layers = tier.num_hidden_layers;
    let (changed, changes) = contract::tensor_changes(base_digests, candidate_digests, layers as usize);
    let mut source = data.source.clone();
    if spec.source == SourceFault::Seed {
        source["seed"] = json!(source["seed"].as_u64().unwrap() + 1);
    }
    if spec.source == SourceFault::Hashes {
        let first = source["source_hashes"].as_object().unwrap().keys().next().unwrap().clone();
        source["source_hashes"][first] = Json::String(sha256_hex(b"tampered"));
    }
    json!({
        "schema": 1, "model_id": MODEL, "tier": tier.name, "request_id": spec.request_id, "base": spec.base, "scope": spec.scope,
        "layers": [4], "source_commitment": sha256_hex(b"source"), "policy": policy,
        "train_wire_sha256": sha256_hex(b"train"), "guard_wire_sha256": sha256_hex(b"guard"),
        "phases": {
            "training": {"layer": 4, "status": "ok", "examples": steps * rows},
            "base_heldout": {"layer": 4, "status": "ok", "examples": 16},
            "candidate_heldout": {"layer": 4, "status": "ok", "examples": 16}
        },
        "base_guard": summary(before), "candidate_guard": summary(after), "action_harms": harms,
        "changes": changes, "changed_tensors": changed,
        "counts": {
            "optimizer_steps": steps, "train_rows": steps * rows, "microbatch_forward": microbatches, "microbatch_backward": microbatches,
            "encoder_block_forward": microbatches * layers, "encoder_block_backward": if full { microbatches * layers } else { 0 }
        },
        "block_counts": {
            "forward": vec![microbatches; layers as usize], "backward": vec![if full { microbatches } else { 0 }; layers as usize]
        },
        "losses": (0..steps).map(|step| 1.0 / (step as f64 + 1.0)).collect::<Vec<_>>(),
        "gradient_trace": (0..steps)
            .map(|step| json!({"step": step + 1, "norm_before_clip": 1.0, "encoder_nonzero_gradients": u64::from(full)}))
            .collect::<Vec<_>>(),
        "parameter_count": tier.parameters, "trainable_count": if full { tier.parameters } else { 20 * (tier.hidden_size + 1) },
        "device": "cpu", "torch": "test", "seconds": 0.0, "cuda_peak_bytes": 0,
        "candidate_blob": blob_sha, "serialized_guard_parity": true, "capabilities": {}, "source": source
    })
}

fn build(base_manifest: &Value, spec: &Spec) -> Built {
    let mut checkpoint = entries(spec.version);
    if let Some(edit) = spec.edit_both {
        edit(&mut checkpoint);
    }
    let (declared, digests) = inventory(&checkpoint);
    let mut stored = checkpoint;
    if let Some(edit) = spec.edit_blob {
        edit(&mut stored);
    }
    let blob = blob_of(&stored);
    let blob_sha = sha256_hex(&blob);
    // What the evidence reports changed: the candidate's own tensors, or those of the version it pretends to be.
    let reported = match spec.claimed {
        Some(claimed) => inventory(&entries(claimed)).1,
        None => digests,
    };
    let evidence_document = evidence_json(spec, &digests_of(base_manifest), &reported, &blob_sha);
    let evidence = canonical_json(&evidence_document);
    let evidence_sha = sha256_hex(&evidence);
    let original = match text_of(base_manifest, "original") {
        original if original.is_empty() => spec.base.clone(),
        original => original,
    };
    let mut document = manifest_json(&Parts {
        scope: spec.scope,
        parent: &spec.base,
        original: &original,
        evidence: &evidence_sha,
        blob: &blob_sha,
        inventory: &declared,
    });
    if let Some(edit) = spec.manifest_edit {
        edit(&mut document);
    }
    let manifest = canonical_json(&document);
    Built {
        request_id: spec.request_id.clone(),
        base: spec.base.clone(),
        scope: spec.scope,
        evidence,
        evidence_sha,
        blob,
        blob_sha,
        manifest_sha: sha256_hex(&manifest),
        manifest,
        heads: spec.version.heads,
    }
}

// ---------------------------------------------------------------------------------------------------------------------------
// Scorer doubles, scripted per candidate.
// ---------------------------------------------------------------------------------------------------------------------------

/// The guard and retention scorers of the test: every candidate passes unless the script says otherwise. A candidate is named by its
/// checkpoint digest. (`Fixed` of `v3_guard.rs` is private to that test, so the doubles are written here.)
#[derive(Debug, Default)]
struct Script {
    guard_fails: Mutex<BTreeSet<String>>,
    violations: Mutex<BTreeMap<String, usize>>,
    assessed: Mutex<Vec<String>>,
}

impl Script {
    fn fail_guard(&self, built: &Built) {
        self.guard_fails.lock().unwrap_or_else(PoisonError::into_inner).insert(built.blob_sha.clone());
    }

    fn regress(&self, built: &Built, violations: usize) {
        self.violations.lock().unwrap_or_else(PoisonError::into_inner).insert(built.blob_sha.clone(), violations);
    }
}

impl GuardScorer for Script {
    fn passes(&self, _store: &CheckpointStore, manifest: &Value, _rows: &[Example]) -> Result<bool, StoreError> {
        Ok(!self.guard_fails.lock().unwrap_or_else(PoisonError::into_inner).contains(&text_of(manifest, "blob")))
    }
}

impl RetentionScorer for Script {
    fn assess(&self, _store: &CheckpointStore, manifest: &Value, release: &RetentionRelease) -> Result<Verdict, StoreError> {
        let blob = text_of(manifest, "blob");
        self.assessed.lock().unwrap_or_else(PoisonError::into_inner).push(blob.clone());
        let violations = self.violations.lock().unwrap_or_else(PoisonError::into_inner).get(&blob).copied().unwrap_or(0);
        Ok(Verdict { eligible: eligible_rows(), violations, max_violations: release.rule.max_violations })
    }
}

fn retention_manifest() -> (Vec<u8>, Json) {
    let bytes = std::fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join("config/v3-retention/efficient/manifest.json")).unwrap();
    let document = serde_json::from_slice(&bytes).unwrap();
    (bytes, document)
}

fn eligible_rows() -> usize {
    retention_manifest().1["eligible_ids"].as_array().unwrap().len()
}

/// The efficient tier's reference release with the allowance of the committed one (the approved bank is not in the repository, so
/// the references are empty and the double reports the violations).
fn retention_release() -> RetentionRelease {
    let (bytes, document) = retention_manifest();
    RetentionRelease {
        sha256: sha256_hex(&bytes),
        model_id: MODEL.to_string(),
        teacher: json!({}),
        rule: Rule { max_violations: usize::try_from(document["rule"]["max_violations"].as_u64().unwrap()).unwrap() },
        references: Vec::new(),
    }
}

// ---------------------------------------------------------------------------------------------------------------------------
// The world of one group: a store, its observers, the published root, the model-streaming view and (for wire rows) the server.
// ---------------------------------------------------------------------------------------------------------------------------

struct Pki {
    env: Env,
    trainer: Creds,
    operator: Creds,
}

impl Pki {
    fn new() -> Arc<Self> {
        let env = Env::new();
        let trainer = env.service("trainer-s13c", Some("trainer"));
        let operator = env.service("publisher-s13c", Some("publisher"));
        Arc::new(Self { env, trainer, operator })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Who {
    Trainer,
    Operator,
}

impl Who {
    fn identity(self) -> &'static str {
        match self {
            Self::Trainer => "trainer-s13c (trainer)",
            Self::Operator => "publisher-s13c (publisher)",
        }
    }
}

/// The authority and what is served, as the rows record it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Auth {
    current: String,
    versions: usize,
    publications: usize,
    max_sequence: u64,
    served: String,
}

impl Auth {
    fn json(&self) -> Json {
        json!({
            "store_current": self.current, "versions_count": self.versions, "publications_count": self.publications,
            "max_sequence": self.max_sequence, "served_manifest": self.served, "client_mark": null
        })
    }
}

/// Nothing changed in the authority; the served version is the same (or, for an at-rest fault, refuses instead of serving bytes
/// that do not match).
fn unchanged(before: &Auth, after: &Auth, fail_closed: bool) -> bool {
    let served = before.served == after.served || (fail_closed && after.served.starts_with("refused:"));
    (&before.current, before.versions, before.publications, before.max_sequence)
        == (&after.current, after.versions, after.publications, after.max_sequence)
        && served
}

struct Layout {
    store: PathBuf,
    published: PathBuf,
    key_file: PathBuf,
    original: PathBuf,
    release: PathBuf,
    releases: PathBuf,
}

struct Options {
    publication: bool,
    wire: bool,
}

struct World {
    pki: Arc<Pki>,
    _directory: tempfile::TempDir,
    layout: Layout,
    options: Options,
    store: Arc<CheckpointStore>,
    publisher: Option<Arc<Publisher>>,
    allocations: Arc<StaticAllocations>,
    script: Arc<Script>,
    armed: Arc<Mutex<Option<String>>>,
    server: Option<ServerHandle>,
    releases: StandardReleases,
    published: Published,
    pin: String,
    original: String,
    values: Mutex<BTreeMap<String, f32>>,
}

fn limits() -> Limits {
    Limits { request_timeout: std::time::Duration::from_secs(300), rate: RateLimit { per_second: 1000, burst: 1000 }, ..generous() }
}

fn package(directory: &Path, entries: &[Entry], manifest: &[u8]) {
    std::fs::create_dir_all(directory).unwrap();
    std::fs::write(directory.join("manifest.json"), manifest).unwrap();
    std::fs::write(directory.join("model.safetensors"), blob_of(entries)).unwrap();
    std::fs::copy(fixture_file("config-efficient.json"), directory.join("config.json")).unwrap();
    std::fs::copy(fixture_file("vocab.txt"), directory.join("vocab.txt")).unwrap();
}

/// A tiny package for a tier the study does not use, so that model-streaming's release store has the three it requires.
fn tiny_package(directory: &Path, id: &str) -> String {
    let assets: Vec<(&str, Vec<u8>)> =
        ASSET_KEYS.iter().map(|(name, _)| (*name, format!("{id} {name} stand-in bytes, long enough to be a file").into_bytes())).collect();
    let digest = |name: &str| sha256_hex(&assets.iter().find(|(candidate, _)| *candidate == name).unwrap().1);
    let manifest = format!(
        "{{\"architecture\":\"{V3_ARCHITECTURE}\",\"blob\":\"{}\",\"config\":\"{}\",\"evidence\":\"{}\",\"model_id\":\"{id}\",\
         \"original\":\"\",\"parent\":\"\",\"vocab\":\"{}\"}}\n",
        digest("model.safetensors"),
        digest("config.json"),
        digest("evidence.json"),
        digest("vocab.txt"),
    )
    .into_bytes();
    std::fs::create_dir_all(directory).unwrap();
    std::fs::write(directory.join("manifest.json"), &manifest).unwrap();
    for (name, bytes) in &assets {
        std::fs::write(directory.join(name), bytes).unwrap();
    }
    sha256_hex(&manifest)
}

fn crash_hook(armed: &Arc<Mutex<Option<String>>>) -> CrashHook {
    let armed = armed.clone();
    Arc::new(move |phase: &str| -> Result<(), String> {
        if armed.lock().unwrap_or_else(PoisonError::into_inner).as_deref() == Some(phase) {
            Err(format!("simulated crash at {phase}"))
        } else {
            Ok(())
        }
    })
}

impl World {
    async fn new(pki: &Arc<Pki>, options: Options) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        let layout = Layout {
            store: root.join("store"),
            published: root.join("published"),
            key_file: root.join("publication.key"),
            original: root.join("original"),
            release: root.join("release"),
            releases: root.join("releases"),
        };
        // The toy ORIGINAL and the toy pinned release (full-encoder scope) that descends from it.
        let original_entries = entries(Version { heads: 0.0, encoder: 0.0 });
        let (original_inventory, _) = inventory(&original_entries);
        let original_manifest = canonical_json(&manifest_json(&Parts {
            scope: "original",
            parent: "",
            original: "",
            evidence: "",
            blob: &sha256_hex(&blob_of(&original_entries)),
            inventory: &original_inventory,
        }));
        let original = sha256_hex(&original_manifest);
        let release_entries = entries(Version { heads: 1.0, encoder: 0.5 });
        let (release_inventory, _) = inventory(&release_entries);
        let release_manifest = canonical_json(&manifest_json(&Parts {
            scope: "full_encoder",
            parent: &sha256_hex(b"the heads release that the pin descends from"),
            original: &original,
            evidence: &sha256_hex(b"the evidence of the release"),
            blob: &sha256_hex(&blob_of(&release_entries)),
            inventory: &release_inventory,
        }));
        let pin = sha256_hex(&release_manifest);
        package(&layout.original, &original_entries, &original_manifest);
        package(&layout.release, &release_entries, &release_manifest);
        std::fs::write(layout.release.join("evidence.json"), b"the evidence of the release").unwrap();
        // The release store of model-streaming: the pinned release, with the evidence file its manifest names, and two tiny tiers.
        let served_pin = layout.releases.join(MODEL);
        package(&served_pin, &release_entries, &release_manifest);
        std::fs::write(served_pin.join("evidence.json"), b"the evidence of the release").unwrap();
        let mut pins = BTreeMap::from([(MODEL.to_string(), pin.clone())]);
        for id in STANDARD_IDS.iter().filter(|id| **id != MODEL) {
            pins.insert((*id).to_string(), tiny_package(&layout.releases.join(id), id));
        }
        std::fs::create_dir_all(&layout.published).unwrap();
        std::fs::create_dir_all(&layout.store).unwrap();
        let seed_hex: String = test_keys::seed(PRIMARY_ID).iter().map(|byte| format!("{byte:02x}")).collect();
        std::fs::write(&layout.key_file, seed_hex).unwrap();

        let allocations = Arc::new(StaticAllocations::default());
        let script = Arc::new(Script::default());
        let armed = Arc::new(Mutex::new(None));
        let mut world = Self {
            pki: pki.clone(),
            layout,
            options,
            store: Arc::new(CheckpointStore::open(root.join("placeholder"), Arc::new(AcceptSources)).unwrap()),
            publisher: None,
            allocations,
            script,
            armed,
            server: None,
            releases: StandardReleases::open_with_pins(&root.join("releases"), pins.clone()).unwrap(),
            published: Published::open(&root.join("published"), &root.join("store")).unwrap(),
            pin,
            original,
            values: Mutex::new(BTreeMap::new()),
            _directory: directory,
        };
        let (store, publisher, _) = world.open_stack(true);
        world.store = store;
        world.publisher = publisher;
        if world.options.wire {
            world.start_server().await;
        }
        world
    }

    /// Open the store with the production observers of `build_observers` (and the retention gate in front of the publisher), as the
    /// service does at start, and reconcile the publication.
    fn open_stack(&self, bootstrap: bool) -> (Arc<CheckpointStore>, Option<Arc<Publisher>>, Option<Reconciled>) {
        let config = V3Config {
            store: self.layout.store.clone(),
            initial: Vec::new(),
            pinned: Vec::new(),
            source_root: repo_root(),
            audience: None,
            drift_bounds: Path::new(env!("CARGO_MANIFEST_DIR")).join("config/v3-drift-bounds.toml"),
            publication: self.options.publication.then(|| PublicationConfig {
                root: self.layout.published.clone(),
                key_file: self.layout.key_file.clone(),
                key_id: PRIMARY_ID.to_string(),
            }),
            retention: None,
        };
        let allocations: Arc<dyn Allocations> = self.allocations.clone();
        let guard: Arc<dyn GuardScorer> = self.script.clone();
        let (mut observers, publisher) =
            build_observers(&config, fixtures().pinned.clone(), allocations, crash_hook(&self.armed), Some(guard), None).unwrap();
        assert_eq!(observers.len(), 2 + usize::from(publisher.is_some()), "drift gate, guard gate and, when published, the publisher");
        let retention = RetentionGate::new(RetentionReleases::from_releases([retention_release()])).with_scorer(self.script.clone());
        observers.insert(2, Arc::new(retention));
        let store = CheckpointStore::open(&self.layout.store, Arc::new(AcceptSources))
            .unwrap()
            .with_pins(BTreeMap::from([(MODEL.to_string(), self.pin.clone())]))
            .with_observer(Arc::new(ChainObserver::new(observers)));
        if bootstrap {
            store.bootstrap_pinned(&self.layout.original, &self.layout.release).unwrap();
        }
        let report = publisher.as_ref().map(|publisher| publisher.reconcile(&store).unwrap());
        (Arc::new(store), publisher, report)
    }

    async fn start_server(&mut self) {
        let model = common::copy_model(self._directory.path(), "privoke-baseline");
        let engine = Arc::new(engine(self._directory.path(), &model, "privoke-baseline"));
        self.server = Some(self.pki.env.start_with_checkpoint(engine, CheckpointHandler::new(self.store.clone()), limits()).await);
    }

    /// Restart the service: nothing is armed, the store and the publisher are opened again over the same directories, and the
    /// publication is reconciled from the authority.
    fn restart(&mut self) -> Option<Reconciled> {
        *self.armed.lock().unwrap_or_else(PoisonError::into_inner) = None;
        let (store, publisher, report) = self.open_stack(false);
        self.store = store;
        self.publisher = publisher;
        report
    }

    async fn stop(mut self) {
        if let Some(server) = self.server.take() {
            server.shutdown().await.unwrap();
        }
    }

    async fn client(&self, who: Who) -> CheckpointServiceClient<Channel> {
        let creds = if who == Who::Trainer { &self.pki.trainer } else { &self.pki.operator };
        let address = self.server.as_ref().expect("a wire world").addr;
        let channel =
            privoke_transport::client::connect(&address.to_string(), &self.pki.env.client_config(Some(creds))).await.expect("connect");
        CheckpointServiceClient::new(channel).max_decoding_message_size(2 * 1024 * 1024)
    }

    fn current(&self) -> String {
        self.store.resolve(MODEL).unwrap()
    }

    fn value_of(&self, manifest: &str) -> f32 {
        self.values.lock().unwrap_or_else(PoisonError::into_inner).get(manifest).copied().unwrap_or(1.0)
    }

    /// A heads candidate `delta` above the current version, for request `request_id`.
    fn heads(&self, request_id: &str, delta: f32) -> Spec {
        let base = self.current();
        Spec::heads(request_id, &base, self.value_of(&base) + delta)
    }

    fn build(&self, spec: &Spec) -> Built {
        let base = self.store.manifest(&spec.base).unwrap();
        let built = build(&base, spec);
        self.values.lock().unwrap_or_else(PoisonError::into_inner).insert(built.manifest_sha.clone(), built.heads);
        built
    }

    /// The scheduler's allocation of the request, in the format of `S13C_ALLOCATIONS`.
    fn allocate_as(&self, built: &Built, seed: u32, expected_base: &str) {
        let item = json!([{
            "request_id": built.request_id, "cycle": 0, "model_id": MODEL, "stage": built.scope, "attempt": 0,
            "sampler": BC01_SAMPLER, "seed": seed, "expected_base": expected_base,
            "source_commitment": seed_data(seed).commitment, "state": "allocated"
        }]);
        for row in parse_allocations(&item.to_string()).unwrap() {
            self.allocations.allocate(
                &row.request_id,
                &row.model_id,
                Allocation {
                    sampler: row.sampler,
                    scope: row.stage.name().to_string(),
                    seed: u64::from(row.seed),
                    source_commitment: row.source_commitment,
                    expected_base: row.expected_base,
                },
            );
        }
    }

    fn allocate(&self, built: &Built) {
        self.allocate_as(built, SEED, &built.base);
    }

    fn commit_of(built: &Built) -> Commit {
        Commit {
            request_id: built.request_id.clone(),
            model_id: MODEL.to_string(),
            expected_base: built.base.clone(),
            candidate: built.manifest_sha.clone(),
            evidence: built.evidence_sha.clone(),
        }
    }

    async fn upload(&self, data: &[u8], manifest: &[u8]) -> Result<String, Status> {
        let mut client = self.client(Who::Trainer).await;
        Ok(client.stage_checkpoint(tokio_stream::iter(chunks(data, manifest))).await?.into_inner().sha256)
    }

    /// Stage the evidence (a manifest-free upload), then the checkpoint with its manifest.
    async fn stage(&self, built: &Built) -> Result<(), Status> {
        self.upload(&built.evidence, b"").await?;
        self.upload(&built.blob, &built.manifest).await?;
        Ok(())
    }

    async fn commit(&self, commit: Commit) -> Result<Receipt, Status> {
        Ok(self.client(Who::Trainer).await.commit_candidate(commit).await?.into_inner())
    }

    async fn rollback(&self, request_id: &str, manifest: &str) -> Result<Receipt, Status> {
        let request = Rollback { request_id: request_id.to_string(), model_id: MODEL.to_string(), manifest: manifest.to_string() };
        Ok(self.client(Who::Operator).await.rollback_model(request).await?.into_inner())
    }

    /// Allocate, stage and commit a candidate that must be applied.
    async fn apply(&self, built: &Built) -> Receipt {
        self.allocate(built);
        self.stage(built).await.unwrap();
        let receipt = self.commit(Self::commit_of(built)).await.unwrap();
        assert_eq!((receipt.status.as_str(), receipt.reason.as_str()), ("applied", ""), "{}", built.request_id);
        receipt
    }

    fn served_with(&self, published: &Published) -> String {
        match published.current_package(&self.releases, MODEL) {
            Ok(package) => package.manifest_sha256,
            Err(status) => format!("refused:{}", grpc_name(status.code())),
        }
    }

    /// The authority and the version model-streaming serves, read the way model-streaming reads them.
    fn observe(&self) -> Auth {
        let publications = self.store.publications(MODEL).unwrap();
        Auth {
            current: self.current(),
            versions: self.store.history(MODEL).unwrap().len(),
            publications: publications.len(),
            max_sequence: publications.iter().map(|row| row.sequence).max().unwrap_or(0),
            served: self.served_with(&self.published),
        }
    }

    /// Blob files no version of the model references: what rejected candidates leave behind. Reported, not counted as a change.
    fn orphan_blobs(&self) -> usize {
        let mut referenced = BTreeSet::new();
        for sha in self.store.history(MODEL).unwrap() {
            let manifest = self.store.manifest(&sha).unwrap();
            referenced.insert(sha);
            for key in ["blob", "config", "vocab", "evidence"] {
                referenced.insert(text_of(&manifest, key));
            }
        }
        std::fs::read_dir(self.layout.store.join("blobs"))
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().to_string())
            .filter(|name| !name.starts_with("stage-") && !referenced.contains(name))
            .count()
    }

    fn receipt_of(&self, request_id: &str) -> Receipt {
        self.store.status(request_id).unwrap()
    }

    /// Record the row of one attack. `expected` must be the manifest's own value for the id.
    fn row(
        &self,
        id: &str,
        who: Who,
        surface: &str,
        variant: &str,
        attempted: Json,
        outcome: &Outcome,
        rejecting: (&str, &str, &str),
        before: &Auth,
        after: &Auth,
        expected: &str,
        property_met: bool,
        extra: Option<Json>,
    ) {
        let entry = manifest_row(id);
        assert_eq!(entry["expected"], expected, "{id}: the manifest and the test disagree on the expected outcome");
        assert_eq!(entry["legs"].as_array().unwrap().iter().filter(|leg| *leg == "ci").count(), 1, "{id}: a ci leg");
        let mut row = json!({
            "id": id, "attack_class": entry["attack_class"], "variant": variant, "combined": false, "chain": entry["chain"],
            "leg": "ci", "surface": surface, "identity": who.identity(), "scope_label": SCOPE_LABEL,
            "attempted": attempted, "expected": expected, "observed": outcome.json(),
            "rejecting_check": {"file": rejecting.0, "symbol": rejecting.1, "reason": rejecting.2},
            "active_before": before.json(), "active_after": after.json(), "orphan_blobs": self.orphan_blobs(),
            "property_met": property_met, "not_run_reason": null
        });
        if let Some(Json::Object(more)) = extra {
            for (key, item) in more {
                row[key] = item;
            }
        }
        assert!(property_met, "{id}: the property of {expected} does not hold ({before:?} then {after:?}; {outcome:?})");
        push_row(row);
    }
}

fn chunks(data: &[u8], manifest: &[u8]) -> Vec<Chunk> {
    let sha = sha256_hex(data);
    data.chunks(CHUNK_BYTES)
        .enumerate()
        .map(|(index, part)| Chunk {
            sha256: sha.clone(),
            offset: (index * CHUNK_BYTES) as u64,
            total_bytes: data.len() as u64,
            data: part.to_vec(),
            manifest_json: if index == 0 { manifest.to_vec() } else { Vec::new() },
        })
        .collect()
}

fn attempted(built: &Built, mutation: &str) -> Json {
    json!({
        "request_id": built.request_id, "model_id": MODEL, "expected_base": built.base, "candidate_sha": built.manifest_sha,
        "mutation": mutation
    })
}

const STORE: &str = "rust/services/param-update/src/v3_store/store.rs";
const SERVICE: &str = "rust/services/param-update/src/v3_store/service.rs";
const POLICY: &str = "rust/services/param-update/src/v3_policy.rs";
const GUARD: &str = "rust/services/param-update/src/v3_guard.rs";
const RETENTION: &str = "rust/services/param-update/src/v3_retention.rs";
const CONTRACT: &str = "rust/crates/privoke-contracts/src/v3.rs";
const PUBLISHED: &str = "rust/services/model-streaming/src/published.rs";
const PUBLISH: &str = "rust/services/param-update/src/v3_publish.rs";

async fn world(pki: &Arc<Pki>) -> World {
    World::new(pki, Options { publication: true, wire: true }).await
}

// ---------------------------------------------------------------------------------------------------------------------------
// Group 1: stale parent, replay and duplicate (classes 1 to 3), one world, each row on the state the previous one left.
// ---------------------------------------------------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stale_parent_replay_and_duplicate_change_nothing() {
    let pki = Pki::new();
    let world = world(&pki).await;
    let pin = world.pin.clone();

    // The positive control: a genuine candidate on the pin is applied, signed and served.
    let first = world.build(&world.heads("s13c-a", 0.5));
    let receipt = world.apply(&first).await;
    let after_first = world.observe();
    assert_eq!((after_first.current.as_str(), after_first.publications, after_first.max_sequence), (first.manifest_sha.as_str(), 1, 1));
    assert_eq!(after_first.served, first.manifest_sha, "model-streaming serves the version the authority names");

    // C1a: another candidate on the same base (the pin) loses, after the first was applied.
    let second = world.build(&Spec::heads("s13c-a2", &pin, 2.0));
    world.allocate(&second);
    world.stage(&second).await.unwrap();
    let before = world.observe();
    let outcome = Outcome::of(world.commit(World::commit_of(&second)).await);
    let after = world.observe();
    outcome.assert_rejected("stale_base");
    assert!(!world.store.publications(MODEL).unwrap().iter().any(|row| row.request_id == "s13c-a2"), "no statement exists for the loser");
    let met = unchanged(&before, &after, false);
    world.row(
        "C1a",
        Who::Trainer,
        "commit",
        "the candidate's parent was current, then another candidate on the same base was applied",
        attempted(&second, "a second candidate on the pin after the first was applied"),
        &outcome,
        (STORE, "commit compare-and-swap", "stale_base"),
        &before,
        &after,
        "rejected_unchanged",
        met,
        None,
    );

    // C2a: the first request is resent after a later update; the stored receipt answers and nothing is swapped.
    let later = world.build(&world.heads("s13c-b", 0.5));
    world.apply(&later).await;
    let before = world.observe();
    let outcome = Outcome::of(world.commit(World::commit_of(&first)).await);
    let after = world.observe();
    assert_eq!((outcome.status.as_str(), outcome.reason.as_str()), ("applied", ""), "the stored receipt");
    assert_eq!(receipt.candidate, first.manifest_sha);
    let met = unchanged(&before, &after, false) && after.current == later.manifest_sha;
    world.row(
        "C2a",
        Who::Trainer,
        "commit",
        "the same request id and content after a later update",
        attempted(&first, "the exact first commit, resent after the second version was applied"),
        &outcome,
        (STORE, "replay / replayed", "returns the stored receipt (receipt_status applied)"),
        &before,
        &after,
        "noop_unchanged",
        met,
        Some(json!({"receipt_status_stored": "applied"})),
    );

    // C2b: the same request id with different content.
    let before = world.observe();
    let reused = Commit { candidate: second.manifest_sha.clone(), evidence: second.evidence_sha.clone(), ..World::commit_of(&first) };
    let outcome = Outcome::of(world.commit(reused).await);
    let after = world.observe();
    outcome.assert_refused(Code::InvalidArgument, "Request ID reused with different commit content.");
    world.row(
        "C2b",
        Who::Trainer,
        "commit",
        "the same request id with different content",
        attempted(&first, "the first request id naming another candidate and evidence"),
        &outcome,
        (STORE, "replayed", "Request ID reused with different commit content."),
        &before,
        &after,
        "rejected_unchanged",
        unchanged(&before, &after, false),
        None,
    );

    // C3a: a candidate that is already current is committed again under a new request id, with its own evidence.
    let before = world.observe();
    let duplicate = Commit { request_id: "s13c-b-again".to_string(), ..World::commit_of(&later) };
    let outcome = Outcome::of(world.commit(duplicate).await);
    let after = world.observe();
    outcome.assert_refused(Code::InvalidArgument, "Commit identity differs from candidate/fit evidence.");
    assert_eq!(world.receipt_of("s13c-b-again").status, "unknown", "no receipt is recorded");
    world.row(
        "C3a",
        Who::Trainer,
        "commit",
        "a candidate that is already current is committed again under a new request id",
        attempted(&later, "the current candidate under request id s13c-b-again"),
        &outcome,
        (STORE, "commit identity check", "Commit identity differs from candidate/fit evidence."),
        &before,
        &after,
        "rejected_unchanged",
        unchanged(&before, &after, false),
        None,
    );

    // C3b: the same candidate staged twice is idempotent (content addressed); it is applied at most once.
    let third = world.build(&world.heads("s13c-c", 0.5));
    world.allocate(&third);
    world.stage(&third).await.unwrap();
    let before = world.observe();
    let blobs = std::fs::read_dir(world.layout.store.join("blobs")).unwrap().count();
    let outcome = Outcome::of_stage(world.upload(&third.blob, &third.manifest).await);
    let after = world.observe();
    assert_eq!(std::fs::read_dir(world.layout.store.join("blobs")).unwrap().count(), blobs, "the second stage stores nothing new");
    let met = unchanged(&before, &after, false) && outcome.code == Code::Ok;
    world.row(
        "C3b",
        Who::Trainer,
        "stage",
        "the same candidate is staged twice",
        attempted(&third, "the same blob and manifest uploaded again"),
        &outcome,
        (STORE, "put (content addressed)", "the second stage is idempotent"),
        &before,
        &after,
        "noop_unchanged",
        met,
        None,
    );
    world.commit(World::commit_of(&third)).await.unwrap();
    let publications = world.store.publications(MODEL).unwrap();
    assert_eq!(publications.iter().filter(|row| row.manifest == third.manifest_sha).count(), 1, "one application, one publication");

    // C1c: a rollback to a manifest that was never committed for the model.
    let never = world.build(&world.heads("s13c-d", 0.5));
    world.stage(&never).await.unwrap();
    let before = world.observe();
    let outcome = Outcome::of(world.rollback("s13c-rb", &never.manifest_sha).await);
    let after = world.observe();
    outcome.assert_refused(Code::InvalidArgument, "Rollback target is not in the history of this model.");
    world.row(
        "C1c",
        Who::Operator,
        "rollback",
        "a rollback to a manifest that was never committed for the model",
        attempted(&never, "RollbackModel to a staged, never committed manifest"),
        &outcome,
        (STORE, "rollback", "Rollback target is not in the history of this model."),
        &before,
        &after,
        "rejected_unchanged",
        unchanged(&before, &after, false),
        None,
    );

    // C1b: two distinct candidates, each with its own evidence and request id, race on one base.
    let base = world.current();
    let (left, right) = (
        world.build(&Spec::heads("s13c-x", &base, world.value_of(&base) + 0.5)),
        world.build(&Spec::heads("s13c-y", &base, world.value_of(&base) + 1.0)),
    );
    assert_ne!(left.manifest_sha, right.manifest_sha);
    for candidate in [&left, &right] {
        world.allocate(candidate);
        world.stage(candidate).await.unwrap();
    }
    let before = world.observe();
    let (a, b) = tokio::join!(world.commit(World::commit_of(&left)), world.commit(World::commit_of(&right)));
    let after = world.observe();
    let (a, b) = (Outcome::of(a), Outcome::of(b));
    let (winner, loser, loser_outcome) = if a.status == "applied" { (&left, &right, &b) } else { (&right, &left, &a) };
    loser_outcome.assert_rejected("stale_base");
    assert_eq!(world.current(), winner.manifest_sha);
    let publications = world.store.publications(MODEL).unwrap();
    assert!(!publications.iter().any(|row| row.request_id == loser.request_id), "the race loser never reaches before_swap");
    let met = after.publications == before.publications + 1
        && after.max_sequence == before.max_sequence + 1
        && after.served == winner.manifest_sha;
    world.row(
        "C1b",
        Who::Trainer,
        "commit",
        "two distinct candidates race on one base",
        attempted(loser, "two concurrent commits on one base; the row records the loser"),
        loser_outcome,
        (STORE, "commit compare-and-swap", "stale_base"),
        &before,
        &after,
        "rejected_unchanged",
        met,
        Some(json!({"race": {"winner_request": winner.request_id, "loser_request": loser.request_id, "applied": 1}})),
    );
    world.stop().await;
    group_done();
}

// ---------------------------------------------------------------------------------------------------------------------------
// Group 2: wrong identity, tensor name and shape, non-finite values (classes 4 to 7). Every attack is refused at admission.
// ---------------------------------------------------------------------------------------------------------------------------

fn rename_heads(entries: &mut [Entry]) {
    entries.iter_mut().find(|entry| entry.name == "heads.w").unwrap().name = "heads.renamed".to_string();
}

fn reshape_heads(entries: &mut [Entry]) {
    entries.iter_mut().find(|entry| entry.name == "heads.w").unwrap().shape = vec![20, 129];
}

fn nan_in_heads(entries: &mut [Entry]) {
    entries.iter_mut().find(|entry| entry.name == "heads.w").unwrap().bytes[4..8].copy_from_slice(&f32::NAN.to_le_bytes());
}

fn infinity_in_heads(entries: &mut [Entry]) {
    entries.iter_mut().find(|entry| entry.name == "heads.w").unwrap().bytes[4..8].copy_from_slice(&f32::INFINITY.to_le_bytes());
}

fn negative_infinity_in_heads(entries: &mut [Entry]) {
    entries.iter_mut().find(|entry| entry.name == "heads.w").unwrap().bytes[4..8].copy_from_slice(&f32::NEG_INFINITY.to_le_bytes());
}

fn wrong_original(document: &mut Json) {
    document["original"] = Json::String(sha256_hex(b"another original"));
}

/// A valid balanced-tier manifest that descends from an efficient version: the model and the tier changed.
fn other_tier(document: &mut Json) {
    let balanced = &TIERS[1];
    document["model_id"] = Json::String("privoke-v3-balanced".to_string());
    document["tier"] = Json::String(balanced.name.to_string());
    document["parameter_count"] = json!(balanced.parameters);
    document["config"] = Json::String(balanced.config_sha256.to_string());
    document["source"] = json!({
        "repository": balanced.repository, "revision": balanced.revision, "weights_sha256": balanced.weights_sha256,
        "config_sha256": balanced.config_sha256, "vocab_sha256": VOCAB_SHA256
    });
    document["tensors"] = json!({"x": {"dtype": "F32", "shape": [balanced.parameters], "sha256": sha256_hex(b"x")}});
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wrong_identity_tensor_and_values_are_refused_at_admission() {
    let pki = Pki::new();
    let world = world(&pki).await;
    let mut serial = 0;

    // A refusal while staging a (mutated) candidate: the evidence is staged first, then the checkpoint with its manifest.
    macro_rules! staging_row {
        ($id:expr, $variant:expr, $mutation:expr, $spec:expr, $file:expr, $symbol:expr, $message:expr) => {{
            serial += 1;
            let mut spec: Spec = $spec;
            spec.request_id = format!("s13c-{}-{serial}", $id.to_lowercase());
            let built = world.build(&spec);
            world.allocate(&built);
            let before = world.observe();
            world.upload(&built.evidence, b"").await.unwrap();
            let outcome = Outcome::of_stage(world.upload(&built.blob, &built.manifest).await);
            let after = world.observe();
            outcome.assert_refused(Code::InvalidArgument, $message);
            world.row(
                $id,
                Who::Trainer,
                "stage",
                $variant,
                attempted(&built, $mutation),
                &outcome,
                ($file, $symbol, $message),
                &before,
                &after,
                "rejected_unchanged",
                unchanged(&before, &after, false),
                None,
            );
        }};
    }

    let base = world.current();
    let plain = |heads: f32| Spec::heads("unused", &base, heads);

    // Class 4: wrong model or version id.
    let mut spec = plain(1.5);
    spec.manifest_edit = Some(other_tier);
    staging_row!(
        "C4b",
        "the manifest model_id, tier, config or vocab differs from the parent",
        "a valid balanced-tier manifest whose parent is an efficient version",
        spec,
        STORE,
        "admit_candidate",
        "Candidate changed immutable model provenance/config."
    );
    let mut spec = plain(1.5);
    spec.manifest_edit = Some(wrong_original);
    staging_row!(
        "C4c",
        "a wrong original",
        "the original field names another manifest",
        spec,
        STORE,
        "admit_candidate",
        "Candidate ORIGINAL binding mismatch."
    );

    // C4e: scope original, the ORIGINAL's own manifest and checkpoint offered as a candidate.
    let original_manifest = std::fs::read(world.layout.original.join("manifest.json")).unwrap();
    let original_blob = std::fs::read(world.layout.original.join("model.safetensors")).unwrap();
    let before = world.observe();
    let outcome = Outcome::of_stage(world.upload(&original_blob, &original_manifest).await);
    let after = world.observe();
    outcome.assert_refused(Code::InvalidArgument, "Candidates cannot claim ORIGINAL scope.");
    let claim = Built {
        request_id: "s13c-c4e".to_string(),
        base: base.clone(),
        scope: "heads",
        evidence: Vec::new(),
        evidence_sha: String::new(),
        blob: original_blob.clone(),
        blob_sha: sha256_hex(&original_blob),
        manifest_sha: sha256_hex(&original_manifest),
        manifest: original_manifest,
        heads: 0.0,
    };
    world.row(
        "C4e",
        Who::Trainer,
        "stage",
        "scope original",
        attempted(&claim, "the ORIGINAL manifest staged as a candidate"),
        &outcome,
        (STORE, "admit_candidate", "Candidates cannot claim ORIGINAL scope."),
        &before,
        &after,
        "rejected_unchanged",
        unchanged(&before, &after, false),
        None,
    );

    // C4a and C4d: a staged, admitted candidate whose commit names another model or another base.
    for (id, variant, mutation) in [
        ("C4a", "Commit.model_id differs from the manifest", "the commit names privoke-v3-balanced"),
        ("C4d", "expected_base differs from the manifest's parent", "the commit's expected base is the ORIGINAL"),
    ] {
        let built = world.build(&Spec::heads(&format!("s13c-{}", id.to_lowercase()), &base, 1.5));
        world.allocate(&built);
        world.stage(&built).await.unwrap();
        let mut commit = World::commit_of(&built);
        if id == "C4a" {
            commit.model_id = "privoke-v3-balanced".to_string();
        } else {
            commit.expected_base = world.original.clone();
        }
        let before = world.observe();
        let outcome = Outcome::of(world.commit(commit).await);
        let after = world.observe();
        outcome.assert_refused(Code::InvalidArgument, "Commit identity differs from candidate/fit evidence.");
        world.row(
            id,
            Who::Trainer,
            "commit",
            variant,
            attempted(&built, mutation),
            &outcome,
            (STORE, "commit identity check", "Commit identity differs from candidate/fit evidence."),
            &before,
            &after,
            "rejected_unchanged",
            unchanged(&before, &after, false),
            None,
        );
    }

    // Class 5: wrong tensor name.
    let mut spec = plain(1.5);
    spec.edit_both = Some(rename_heads);
    staging_row!(
        "C5a",
        "a tensor renamed in both the manifest and the blob",
        "the heads tensor renamed everywhere",
        spec,
        STORE,
        "admit_candidate",
        "Candidate changed admitted tensor inventory."
    );
    let mut spec = plain(1.5);
    spec.edit_blob = Some(rename_heads);
    staging_row!(
        "C5b",
        "the manifest inventory differs from the blob",
        "the heads tensor renamed in the blob only",
        spec,
        STORE,
        "verify_checkpoint",
        "Safetensors inventory differs from manifest."
    );

    // Class 6: wrong tensor shape.
    let mut spec = plain(1.5);
    spec.edit_both = Some(reshape_heads);
    staging_row!(
        "C6a",
        "the shape changed in both the manifest and the blob",
        "the heads tensor reshaped to 20 by 129 everywhere",
        spec,
        STORE,
        "admit_candidate",
        "Candidate changed admitted tensor inventory."
    );
    let mut spec = plain(1.5);
    spec.edit_blob = Some(reshape_heads);
    staging_row!(
        "C6b",
        "the shape changed only in the blob",
        "the heads tensor reshaped in the blob only",
        spec,
        STORE,
        "verify_checkpoint",
        "Safetensors inventory differs from manifest."
    );

    // Class 7: NaN and infinities in one heads coordinate.
    for (id, variant, edit) in [
        ("C7a", "NaN in one heads coordinate", nan_in_heads as fn(&mut [Entry])),
        ("C7b", "+Inf in one heads coordinate", infinity_in_heads),
        ("C7c", "-Inf in one heads coordinate", negative_infinity_in_heads),
    ] {
        let mut spec = plain(1.5);
        spec.edit_both = Some(edit);
        staging_row!(
            id,
            variant,
            variant,
            spec,
            "rust/crates/privoke-semantic/src/safetensors.rs",
            "finite check, called from verify_checkpoint",
            "Snapshot tensors must be finite float32."
        );
    }
    world.stop().await;
    group_done();
}

// ---------------------------------------------------------------------------------------------------------------------------
// Group 3: excessive parameter change (class 8, except the long run).
// ---------------------------------------------------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_update_beyond_its_bound_or_through_the_encoder_is_refused() {
    let pki = Pki::new();
    let world = world(&pki).await;

    // C8a: one update above max_update_l2 of the shipped bounds (4.2 for the efficient heads).
    let built = world.build(&world.heads("s13c-c8a", 5.0));
    world.allocate(&built);
    world.stage(&built).await.unwrap();
    let before = world.observe();
    let outcome = Outcome::of(world.commit(World::commit_of(&built)).await);
    let after = world.observe();
    outcome.assert_rejected("drift_exceeded");
    world.row(
        "C8a",
        Who::Trainer,
        "commit",
        "one update above max_update_l2",
        attempted(&built, "the heads move by 5.0 against a bound of 4.2"),
        &outcome,
        (POLICY, "DriftGate::prepare", "drift_exceeded"),
        &before,
        &after,
        "rejected_unchanged",
        unchanged(&before, &after, false),
        None,
    );

    // C8c: a HEADS candidate that changes encoder bytes, with honest evidence.
    let mut spec = world.heads("s13c-c8c", 0.5);
    spec.version.encoder += 0.25;
    let built = world.build(&spec);
    world.allocate(&built);
    let before = world.observe();
    let outcome = Outcome::of_stage(world.upload(&built.evidence, b"").await);
    let after = world.observe();
    outcome.assert_refused(Code::InvalidArgument, "HEADS changed pretrained encoder.");
    world.row(
        "C8c",
        Who::Trainer,
        "stage",
        "a HEADS candidate that changes encoder bytes, with honest evidence",
        attempted(&built, "scope heads, the encoder tensors changed, the evidence reports it"),
        &outcome,
        (CONTRACT, "validate_execution", "HEADS changed pretrained encoder."),
        &before,
        &after,
        "rejected_unchanged",
        unchanged(&before, &after, false),
        None,
    );

    // C8d: the same checkpoint, with evidence that reports a heads-only change.
    let mut spec = world.heads("s13c-c8d", 0.5);
    spec.version.encoder += 0.25;
    spec.claimed = Some(Version { heads: spec.version.heads, encoder: 0.5 });
    let built = world.build(&spec);
    world.allocate(&built);
    let before = world.observe();
    world.upload(&built.evidence, b"").await.unwrap();
    let outcome = Outcome::of_stage(world.upload(&built.blob, &built.manifest).await);
    let after = world.observe();
    outcome.assert_refused(Code::InvalidArgument, "Reported changes differ from actual checkpoint tensors.");
    world.row(
        "C8d",
        Who::Trainer,
        "stage",
        "the same with dishonest changed_tensors and changes",
        attempted(&built, "scope heads, the encoder tensors changed, the evidence reports heads only"),
        &outcome,
        (STORE, "admit_candidate", "Reported changes differ from actual checkpoint tensors."),
        &before,
        &after,
        "rejected_unchanged",
        unchanged(&before, &after, false),
        None,
    );
    world.stop().await;
    group_done();
}

/// C8b: updates each under the per-update bound, until the cumulative cap of 100 from the pinned release. Synthetic, in CI only.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn updates_each_under_the_bound_stop_at_the_cumulative_cap() {
    let pki = Pki::new();
    let world = world(&pki).await;
    let step = 4.19_f32;
    let mut applied = 0;
    let (before, built, outcome, after) = loop {
        let built = world.build(&world.heads(&format!("s13c-c8b-{}", applied + 1), step));
        world.allocate(&built);
        world.stage(&built).await.unwrap();
        let before = world.observe();
        let outcome = Outcome::of(world.commit(World::commit_of(&built)).await);
        let after = world.observe();
        if outcome.status == "applied" {
            applied += 1;
            assert!(applied < 40, "the cumulative cap never stopped the run");
            continue;
        }
        break (before, built, outcome, after);
    };
    outcome.assert_rejected("drift_exceeded");
    // 23 updates reach 96.4 and the 24th would reach 100.6 (the cap is 100 and every step is under 4.2).
    assert_eq!(applied, 23, "about 25 in-bound updates are applied before the cap");
    let met = unchanged(&before, &after, false) && after.publications == applied;
    world.row(
        "C8b",
        Who::Trainer,
        "commit",
        "a run of updates each under the per-update bound until the cumulative cap of 100",
        attempted(&built, "24 updates of 4.19 each on the heads; the row records the last"),
        &outcome,
        (POLICY, "DriftGate::prepare (cumulative from DriftGate::root)", "drift_exceeded"),
        &before,
        &after,
        "rejected_unchanged",
        met,
        Some(json!({"updates_applied": applied, "per_update_l2": step})),
    );
    world.stop().await;
    group_done();
}

// ---------------------------------------------------------------------------------------------------------------------------
// Group 4: truncated or corrupted artifacts (class 9) and the corrupted published asset served by model-streaming.
// ---------------------------------------------------------------------------------------------------------------------------

fn flip_first_byte(path: &Path) {
    let mut bytes = std::fs::read(path).unwrap();
    bytes[0] ^= 0xff;
    std::fs::write(path, bytes).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn truncated_and_corrupted_artifacts_are_refused_or_not_served() {
    let pki = Pki::new();
    let world = world(&pki).await;
    let base = world.current();
    let built = world.build(&Spec::heads("s13c-c9", &base, 1.5));
    let other = world.build(&Spec::heads("s13c-c9-other", &base, 2.0));
    let sha = sha256_hex(&built.blob);
    let total = built.blob.len() as u64;
    let mib = CHUNK_BYTES;
    let part = |sha: &str, offset: usize, length: usize, total: u64, manifest: &[u8]| Chunk {
        sha256: sha.to_string(),
        offset: offset as u64,
        total_bytes: total,
        data: built.blob[offset..offset + length].to_vec(),
        manifest_json: manifest.to_vec(),
    };
    let invalid = "Invalid bounded ordered checkpoint upload.";
    let corrupt = "Incomplete/corrupt checkpoint upload.";

    let uploads: Vec<(&str, &str, &str, Vec<Chunk>, &str, &str)> = vec![
        (
            "C9a",
            "the stream ends early",
            "one chunk of a longer declared blob",
            vec![part(&sha, 0, mib, total, b"")],
            "stage_checkpoint",
            corrupt,
        ),
        (
            "C9b",
            "an offset gap",
            "the second chunk starts one chunk too late",
            vec![part(&sha, 0, mib, total, b""), part(&sha, 2 * mib, mib, total, b"")],
            "stage_checkpoint",
            invalid,
        ),
        (
            "C9c",
            "the declared sha256 differs from the bytes",
            "the declared digest names other bytes",
            chunks(&built.blob, b"").into_iter().map(|chunk| Chunk { sha256: sha256_hex(b"other bytes"), ..chunk }).collect(),
            "stage_checkpoint",
            corrupt,
        ),
    ];
    for (id, variant, mutation, stream, symbol, message) in uploads {
        let before = world.observe();
        let mut client = world.client(Who::Trainer).await;
        let outcome = Outcome::of_stage(client.stage_checkpoint(tokio_stream::iter(stream)).await.map(|reply| reply.into_inner().sha256));
        let after = world.observe();
        outcome.assert_refused(Code::InvalidArgument, message);
        world.row(
            id,
            Who::Trainer,
            "stage",
            variant,
            attempted(&built, mutation),
            &outcome,
            (SERVICE, symbol, message),
            &before,
            &after,
            "rejected_unchanged",
            unchanged(&before, &after, false),
            None,
        );
    }

    // C9d: the manifest's blob differs from the uploaded bytes.
    let before = world.observe();
    let outcome = Outcome::of_stage(world.upload(&other.blob, &built.manifest).await);
    let after = world.observe();
    outcome.assert_refused(Code::InvalidArgument, "Candidate snapshot identity mismatch.");
    world.row(
        "C9d",
        Who::Trainer,
        "stage",
        "the manifest blob differs from the uploaded bytes",
        attempted(&built, "the manifest of one candidate with the checkpoint of another"),
        &outcome,
        (STORE, "stage", "Candidate snapshot identity mismatch."),
        &before,
        &after,
        "rejected_unchanged",
        unchanged(&before, &after, false),
        None,
    );

    // C9e: a store blob is corrupted at rest between the stage and the commit.
    let staged = world.build(&Spec::heads("s13c-c9e", &base, 1.5));
    world.allocate(&staged);
    world.stage(&staged).await.unwrap();
    flip_first_byte(&world.layout.store.join("blobs").join(&staged.blob_sha));
    let before = world.observe();
    let outcome = Outcome::of_store(world.store.commit(&World::commit_of(&staged)));
    let after = world.observe();
    outcome.assert_refused(Code::InvalidArgument, "Immutable blob hash mismatch.");
    world.row(
        "C9e",
        Who::Trainer,
        "commit",
        "a store blob is corrupted at rest before commit",
        attempted(&staged, "the first byte of the staged checkpoint flipped in the store"),
        &outcome,
        (STORE, "read", "Immutable blob hash mismatch."),
        &before,
        &after,
        "rejected_unchanged",
        unchanged(&before, &after, false),
        Some(json!({"label": "at-rest defence in depth"})),
    );

    // C9f (serve): a published asset is corrupted at rest before it is served; model-streaming refuses it.
    let version = world.build(&world.heads("s13c-c9f", 0.75));
    world.apply(&version).await;
    let before = world.observe();
    assert_eq!(before.served, version.manifest_sha);
    flip_first_byte(&world.layout.published.join(MODEL).join(&version.manifest_sha).join("model.safetensors"));
    let fresh = Published::open(&world.layout.published, &world.layout.store).unwrap();
    let served = world.served_with(&fresh);
    let streamed = fresh.stream_asset(MODEL, &version.manifest_sha, "model.safetensors", |_| true);
    assert_eq!(streamed.as_ref().map_err(Status::code), Err(Code::DataLoss), "the asset is re-hashed before it is streamed");
    let after = Auth { served, ..world.observe() };
    let outcome =
        Outcome { code: Code::DataLoss, status: String::new(), reason: String::new(), message: "model asset hash mismatch".to_string() };
    assert_eq!(after.served, "refused:DATA_LOSS", "the corrupted version is not served");
    world.row(
        "C9f-serve",
        Who::Trainer,
        "serve",
        "a published asset is corrupted at rest before serving",
        attempted(&version, "the first byte of the published checkpoint flipped"),
        &outcome,
        (PUBLISHED, "package / stream_asset re-hash", "model asset hash mismatch"),
        &before,
        &after,
        "rejected_unchanged",
        unchanged(&before, &after, true),
        Some(json!({"label": "at-rest defence in depth"})),
    );
    world.stop().await;
    group_done();
}

// ---------------------------------------------------------------------------------------------------------------------------
// Group 5: interrupted publication (class 10), on the store with a crash hook, followed by a restart and a reconciliation.
// ---------------------------------------------------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_interrupted_publication_is_recovered_or_never_applied() {
    let pki = Pki::new();
    for (id, phase, applied) in [
        ("C10a", "staged", false),
        ("C10b", "signed", false),
        ("C10c", "committed", true),
        ("C10d", "renamed", true),
        ("C10e", "pointer", true),
    ] {
        let mut world = World::new(&pki, Options { publication: true, wire: false }).await;
        let built = world.build(&world.heads(&format!("s13c-{}", id.to_lowercase()), 0.5));
        world.allocate(&built);
        world.store.stage(&built.evidence, b"").unwrap();
        world.store.stage(&built.blob, &built.manifest).unwrap();
        let before = world.observe();
        *world.armed.lock().unwrap_or_else(PoisonError::into_inner) = Some(phase.to_string());
        let outcome = Outcome::of_store(world.store.commit(&World::commit_of(&built)));
        assert_eq!(outcome.code, Code::Internal, "{id}: the commit dies at {phase}: {outcome:?}");
        assert!(outcome.message.contains(&format!("injected failure at {phase}")), "{outcome:?}");
        // What is served in the window between the crash and the restart: the old version, the new complete one, or nothing at all
        // (model-streaming reads the authority, and a missing directory fails closed); never anything partial.
        let window = world.observe();
        let pointer = world.publisher.as_ref().unwrap().served(MODEL).unwrap().map(|served| served.manifest_sha);
        let allowed: Vec<String> = match phase {
            "staged" | "signed" => vec![world.pin.clone()],
            "committed" => vec![built.manifest_sha.clone(), "refused:UNAVAILABLE".to_string()],
            _ => vec![built.manifest_sha.clone()],
        };
        assert!(allowed.contains(&window.served), "{id}: served before the restart must be one of {allowed:?}: {}", window.served);
        match phase {
            "staged" | "signed" | "committed" => assert!(pointer.is_none(), "{id}: no pointer yet: {pointer:?}"),
            _ => assert!(
                pointer.as_ref().is_none_or(|sha| *sha == built.manifest_sha),
                "{id}: the pointer names a complete version: {pointer:?}"
            ),
        }
        assert_eq!(window.current == built.manifest_sha, applied, "{id}: the authority applied the candidate only after the transaction");
        let report = world.restart().expect("a publisher reconciles");
        let after = world.observe();
        let met = if applied {
            after.current == built.manifest_sha
                && after.served == built.manifest_sha
                && after.publications == before.publications + 1
                && world.publisher.as_ref().unwrap().served(MODEL).unwrap().map(|served| served.manifest_sha)
                    == Some(built.manifest_sha.clone())
        } else {
            unchanged(&before, &after, false) && report.quarantined >= 1 && world.receipt_of(&built.request_id).status == "unknown"
        };
        let (file, symbol) = match phase {
            "staged" => (PUBLISH, "Publisher::prepare (CrashHook staged)"),
            "signed" => (PUBLISH, "Publisher::before_swap (CrashHook signed)"),
            "committed" => (PUBLISH, "Publisher::after_commit (CrashHook committed); reconcile promotes the staged directory"),
            "renamed" => (PUBLISH, "Publisher::publish (CrashHook renamed); reconcile repairs the pointer"),
            _ => (PUBLISH, "Publisher::publish (CrashHook pointer); reconcile cleans up"),
        };
        let reason = if applied { "applied before the crash; recovered by reconcile" } else { "the commit errors and rolls back" };
        world.row(
            id,
            Who::Trainer,
            "commit",
            &format!("a CrashHook failure at {phase}, then a restart and Publisher::reconcile"),
            attempted(&built, &format!("crash at {phase}")),
            &outcome,
            (file, symbol, reason),
            &before,
            &after,
            if applied { "applied_recovered" } else { "rejected_unchanged" },
            met,
            Some(json!({"crash": {
                "phase": phase, "served_before_restart": window.served, "pointer_before_restart": pointer,
                "authority_applied_before_restart": window.current == built.manifest_sha,
                "reconciled": {"promoted": report.promoted, "rebuilt": report.rebuilt, "quarantined": report.quarantined, "cleaned": report.cleaned, "pointers": report.pointers}
            }})),
        );
        world.stop().await;
    }
    group_done();
}

// ---------------------------------------------------------------------------------------------------------------------------
// Group 6: a better aggregate with broken guard cases (class 11).
// ---------------------------------------------------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_better_aggregate_with_a_broken_guard_is_refused_and_the_boundary_is_accepted() {
    let pki = Pki::new();
    let world = world(&pki).await;
    let allowance = retention_release().rule.max_violations;
    assert_eq!(allowance, 7, "the committed efficient release allows 7 of 155 rows");
    assert_eq!(eligible_rows(), 155);

    // A rejected commit of `spec`: the row, the receipt reason and an unchanged authority.
    macro_rules! rejected_row {
        ($id:expr, $variant:expr, $mutation:expr, $built:expr, $reason:expr, $file:expr, $symbol:expr $(; $extra:expr)?) => {{
            let built: &Built = $built;
            let extra: Option<Json> = None $(.or(Some($extra)))?;
            world.stage(built).await.unwrap();
            let before = world.observe();
            let outcome = Outcome::of(world.commit(World::commit_of(built)).await);
            let after = world.observe();
            outcome.assert_rejected($reason);
            world.row(
                $id,
                Who::Trainer,
                "commit",
                $variant,
                attempted(built, $mutation),
                &outcome,
                ($file, $symbol, $reason),
                &before,
                &after,
                "rejected_unchanged",
                unchanged(&before, &after, false),
                extra,
            );
        }};
    }
    let stubbed = json!({"label": "defence in depth: admission source validation stubbed in CI (production refuses this at stage)"});
    let base = world.current();
    let spec = |name: &str, heads: f32| Spec::heads(&format!("s13c-{name}"), &base, heads);

    // C11a: honest evidence of a guard harm (a better joint count with a worse action).
    let mut harm = spec("c11a", 1.25);
    harm.guard = Guard::Harm;
    let built = world.build(&harm);
    world.allocate(&built);
    rejected_row!(
        "C11a",
        "honest evidence of a guard harm",
        "evidence whose candidate guard blocks a row that should allow",
        &built,
        "guard_rejected",
        STORE,
        "commit via v3::publication_passes"
    );

    // C11b: the evidence claims a pass, the recomputed guard fails.
    let built = world.build(&spec("c11b", 1.5));
    world.allocate(&built);
    world.script.fail_guard(&built);
    rejected_row!(
        "C11b",
        "the evidence claims a pass, but the recomputed guard fails",
        "the guard scorer reports a failure",
        &built,
        "guard_recomputed",
        GUARD,
        "GuardGate::prepare"
    );

    // C11c: substituted guard rows.
    let mut substituted = spec("c11c", 1.75);
    substituted.guard = Guard::SubstitutedRows;
    let built = world.build(&substituted);
    world.allocate(&built);
    rejected_row!(
        "C11c",
        "substituted guard rows",
        "the first guard target of the evidence differs from the rebuilt row",
        &built,
        "guard_rows_differ",
        GUARD,
        "GuardGate::prepare";
        stubbed.clone()
    );

    // C11d: a trainer-chosen source (hashes that the commitment does not cover), and a trainer-chosen seed (the source record names a seed other than the derived one).
    let mut hashes = spec("c11d", 2.0);
    hashes.source = SourceFault::Hashes;
    let built = world.build(&hashes);
    world.allocate(&built);
    rejected_row!(
        "C11d",
        "a trainer-chosen source or seed",
        "the evidence source hashes are tampered",
        &built,
        "commitment_mismatch",
        GUARD,
        "GuardGate::prepare";
        json!({"label": "defence in depth: admission source validation stubbed in CI (production refuses this at stage); the seed-only variant is also asserted here, as commitment_mismatch"})
    );
    let mut seeded = spec("c11d-seed", 2.25);
    seeded.source = SourceFault::Seed;
    let built = world.build(&seeded);
    world.allocate(&built);
    world.stage(&built).await.unwrap();
    let outcome = Outcome::of(world.commit(World::commit_of(&built)).await);
    outcome.assert_rejected("commitment_mismatch");

    // C11e: an unallocated request id, and an allocation for another base.
    let built = world.build(&spec("c11e", 2.5));
    rejected_row!(
        "C11e",
        "an unallocated request id",
        "no allocation exists for the request",
        &built,
        "request_not_allocated",
        GUARD,
        "GuardGate::prepare"
    );
    let mismatched = world.build(&spec("c11e-base", 2.75));
    world.allocate_as(&mismatched, SEED, &sha256_hex(b"another base"));
    world.stage(&mismatched).await.unwrap();
    let outcome = Outcome::of(world.commit(World::commit_of(&mismatched)).await);
    outcome.assert_rejected("allocation_mismatch");

    // C11f: the reference rows regress beyond the allowance (8 of 155 against 7).
    let built = world.build(&spec("c11f", 3.0));
    world.allocate(&built);
    world.script.regress(&built, allowance + 1);
    rejected_row!(
        "C11f",
        "reference rows regress beyond the 5% allowance",
        "8 regressed reference rows against an allowance of 7",
        &built,
        "retention_regressed",
        RETENTION,
        "RetentionGate::prepare"
    );

    // The committed allowances of the other tiers (9 and 10 rows) bound a verdict the same way.
    for (tier, allowed, eligible) in [("balanced", 9usize, 197usize), ("quality", 10, 200)] {
        let manifest: Json = serde_json::from_slice(
            &std::fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join("config/v3-retention").join(tier).join("manifest.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(manifest["rule"]["max_violations"], allowed);
        assert_eq!(manifest["eligible_ids"].as_array().unwrap().len(), eligible);
        let verdict = |violations| Verdict { eligible, violations, max_violations: allowed };
        assert!(verdict(allowed).passes() && !verdict(allowed + 1).passes(), "{tier}: the boundary is the allowance");
    }

    // C11g: exactly the allowance is accepted, by design, and reported as a documented limit.
    let built = world.build(&spec("c11g", 3.25));
    world.allocate(&built);
    world.script.regress(&built, allowance);
    world.stage(&built).await.unwrap();
    let before = world.observe();
    let outcome = Outcome::of(world.commit(World::commit_of(&built)).await);
    let after = world.observe();
    assert_eq!((outcome.code, outcome.status.as_str(), outcome.reason.as_str()), (Code::Ok, "applied", ""), "{outcome:?}");
    let met = after.current == built.manifest_sha && after.served == built.manifest_sha && after.publications == before.publications + 1;
    world.row(
        "C11g",
        Who::Trainer,
        "commit",
        "the boundary: exactly the allowance",
        attempted(&built, "7 regressed reference rows against an allowance of 7"),
        &outcome,
        (RETENTION, "RetentionGate::prepare (violations <= max_violations)", "accepted by design: a documented limit"),
        &before,
        &after,
        "accepted_by_design",
        met,
        Some(json!({"label": "documented limit", "allowance": allowance, "eligible_rows": eligible_rows()})),
    );
    world.stop().await;
    group_done();
}

// ---------------------------------------------------------------------------------------------------------------------------
// Group 7: the chain without the Publisher (C1d).
// ---------------------------------------------------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_version_that_went_live_unsigned_is_never_a_rollback_target() {
    let pki = Pki::new();
    let world = World::new(&pki, Options { publication: false, wire: true }).await;
    assert!(world.publisher.is_none(), "build_observers builds no publisher without a publication configuration");
    let first = world.build(&world.heads("s13c-c1d-a", 0.5));
    world.apply(&first).await;
    let second = world.build(&world.heads("s13c-c1d-b", 0.5));
    world.apply(&second).await;
    assert!(world.store.publications(MODEL).unwrap().is_empty(), "nothing is signed without the Publisher");
    assert!(world.store.history(MODEL).unwrap().contains(&first.manifest_sha), "the first went live");
    let before = world.observe();
    let outcome = Outcome::of(world.rollback("s13c-c1d-rb", &first.manifest_sha).await);
    let after = world.observe();
    outcome.assert_refused(Code::InvalidArgument, "Rollback target was never published.");
    world.row(
        "C1d",
        Who::Operator,
        "rollback",
        "a rollback to a version that went live unsigned (chain no_publisher)",
        attempted(&first, "RollbackModel to a version applied without a publication"),
        &outcome,
        (STORE, "rollback", "Rollback target was never published."),
        &before,
        &after,
        "rejected_unchanged",
        unchanged(&before, &after, false),
        None,
    );
    world.stop().await;
    group_done();
}

// ---------------------------------------------------------------------------------------------------------------------------
// Group 8: a version directory planted in the published root (CS1).
// ---------------------------------------------------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_planted_version_directory_without_an_authority_row_is_never_served() {
    let pki = Pki::new();
    let world = World::new(&pki, Options { publication: true, wire: false }).await;
    let built = world.build(&world.heads("s13c-cs1", 0.5));
    world.store.stage(&built.evidence, b"").unwrap();
    world.store.stage(&built.blob, &built.manifest).unwrap();
    // A complete package, laid out as the publisher lays one out, with no publication in the authority.
    let planted = world.layout.published.join(MODEL).join(&built.manifest_sha);
    std::fs::create_dir_all(&planted).unwrap();
    std::fs::write(planted.join("manifest.json"), &built.manifest).unwrap();
    std::fs::write(planted.join("model.safetensors"), &built.blob).unwrap();
    std::fs::copy(fixture_file("config-efficient.json"), planted.join("config.json")).unwrap();
    std::fs::copy(fixture_file("vocab.txt"), planted.join("vocab.txt")).unwrap();
    std::fs::write(planted.join("evidence.json"), &built.evidence).unwrap();
    std::fs::write(planted.join("statement.json"), b"{}").unwrap();
    std::fs::write(world.layout.published.join(MODEL).join("current"), format!("{}\n", built.manifest_sha)).unwrap();
    let before = Auth { served: world.pin.clone(), ..world.observe() };
    let fresh = Published::open(&world.layout.published, &world.layout.store).unwrap();
    let by_version = fresh.package_at(&world.releases, MODEL, &built.manifest_sha);
    let streamed = fresh.stream_asset(MODEL, &built.manifest_sha, "model.safetensors", |_| true);
    let after = world.observe();
    let outcome = match &by_version {
        Err(status) => Outcome { code: status.code(), status: String::new(), reason: String::new(), message: status.message().to_string() },
        Ok(package) => panic!("a planted directory was served: {}", package.manifest_sha256),
    };
    assert_eq!(streamed.as_ref().map_err(Status::code), Err(Code::InvalidArgument), "the asset of a planted version is not streamed");
    assert!(!fresh.is_published(MODEL, &built.manifest_sha).unwrap(), "the authority holds no publication of it");
    world.row(
        "CS1",
        Who::Trainer,
        "serve",
        "a version directory placed in the publish root with no authority row",
        attempted(&built, "a complete directory and a current pointer, planted by hand"),
        &outcome,
        (PUBLISHED, "is_published (authority only)", "explicit standard model and manifest pin required"),
        &before,
        &after,
        "rejected_unchanged",
        unchanged(&before, &after, false) && after.served == world.pin,
        None,
    );
    world.stop().await;
    group_done();
}

// ---------------------------------------------------------------------------------------------------------------------------
// Group 9: the allocation format, and the manifest itself.
// ---------------------------------------------------------------------------------------------------------------------------

#[test]
fn every_row_of_the_manifest_is_well_formed() {
    let rows = manifest_rows();
    let mut seen = BTreeSet::new();
    for row in &rows {
        let id = row["id"].as_str().unwrap();
        assert!(seen.insert(id.to_string()), "{id} is listed twice");
        let keys: BTreeSet<&str> = row.as_object().unwrap().keys().map(String::as_str).collect();
        assert_eq!(
            keys,
            ["id", "attack_class", "expected", "chain", "surface", "wire_path", "legs", "ci_only_reason"].into_iter().collect(),
            "{id}"
        );
        assert!(["param-update", "model-streaming", "client", "store"].contains(&row["surface"].as_str().unwrap()), "{id}");
        assert!(
            ["rejected_unchanged", "noop_unchanged", "applied_recovered", "accepted_by_design"]
                .contains(&row["expected"].as_str().unwrap()),
            "{id}"
        );
        assert!(["main", "no_publisher"].contains(&row["chain"].as_str().unwrap()), "{id}");
        let legs: Vec<&str> = row["legs"].as_array().unwrap().iter().map(|leg| leg.as_str().unwrap()).collect();
        assert!(legs.contains(&"ci"), "{id}: every row runs in CI");
        let ci_only = legs == ["ci"];
        assert_eq!(ci_only, !row["ci_only_reason"].as_str().unwrap().is_empty(), "{id}: a CI-only row carries its reason");
        if row["wire_path"] == true {
            assert!(["param-update", "model-streaming"].contains(&row["surface"].as_str().unwrap()), "{id}");
        } else {
            assert!(ci_only, "{id}: a row without a wire path has no container leg");
        }
    }
    // The wire_path:false rows the plan names, and nothing else.
    let without_wire: BTreeSet<&str> = rows.iter().filter(|row| row["wire_path"] == false).map(|row| row["id"].as_str().unwrap()).collect();
    let named: BTreeSet<&str> =
        ["C10a", "C10b", "C10c", "C10d", "C10e", "C9e", "C9f-serve", "C9f-client", "C2c", "C2d", "C4f", "CS1", "CS2", "CS3", "CS4"]
            .into_iter()
            .collect();
    assert_eq!(without_wire, named);
    let ci_only: BTreeSet<&str> =
        rows.iter().filter(|row| row["legs"] == json!(["ci"]) && row["wire_path"] == true).map(|row| row["id"].as_str().unwrap()).collect();
    assert_eq!(ci_only, ["C1b", "C1d"].into_iter().collect::<BTreeSet<_>>());
    let classes: BTreeSet<String> = rows.iter().map(|row| row["attack_class"].to_string()).collect();
    assert_eq!(classes.len(), 12, "the eleven classes and the client signature class");
    // The efficient-tier allowance of the manifest of the retention release that the study relies on.
    assert_eq!(retention_release().rule.max_violations, 7);
}

#[test]
fn the_allocation_format_is_strict_and_the_journal_reads_what_it_wrote() {
    let item = |overrides: Json| {
        let mut item = json!({
            "request_id": "s13c-r1", "cycle": 0, "model_id": MODEL, "stage": "heads", "attempt": 0, "sampler": BC01_SAMPLER,
            "seed": SEED, "expected_base": sha256_hex(b"base"), "source_commitment": sha256_hex(b"commitment"), "state": "allocated"
        });
        for (key, replacement) in overrides.as_object().unwrap() {
            item[key] = replacement.clone();
        }
        item
    };
    let text = |items: Vec<Json>| Json::Array(items).to_string();
    let rows =
        parse_allocations(&text(vec![item(json!({})), item(json!({"request_id": "s13c-r2", "stage": "full_encoder", "attempt": 1}))]))
            .unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!((rows[1].stage, rows[1].attempt, rows[0].candidate.clone(), rows[0].reason.clone()), (Stage::FullEncoder, 1, None, None));

    // Unknown and missing fields, and values outside the columns, are refused.
    let mut with_extra = item(json!({}));
    with_extra["candidate"] = Json::Null;
    assert!(parse_allocations(&text(vec![with_extra])).unwrap_err().contains("unknown or missing"));
    let mut missing = item(json!({}));
    missing.as_object_mut().unwrap().remove("seed");
    assert!(parse_allocations(&text(vec![missing])).is_err());
    for bad in [
        json!({"state": "accepted"}),
        json!({"stage": "everything"}),
        json!({"sampler": "another_release"}),
        json!({"model_id": "privoke-v3-unknown"}),
        json!({"seed": 4_294_967_296_u64}),
        json!({"expected_base": "ABC"}),
        json!({"source_commitment": 7}),
        json!({"request_id": ""}),
        json!({"cycle": -1}),
    ] {
        assert!(parse_allocations(&text(vec![item(bad.clone())])).is_err(), "{bad}");
    }
    assert!(parse_allocations("{}").is_err() && parse_allocations("not json").is_err());

    // The journal the guard gate reads (`JournalAllocations`) answers with what the format wrote.
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("cycles.sqlite3");
    let mut journal = Journal::open(&path).unwrap();
    for row in &rows {
        journal.allocate(row).unwrap();
    }
    let read = JournalAllocations::new(&path).allocation("s13c-r2", MODEL).unwrap();
    assert_eq!(
        read,
        Allocation {
            sampler: BC01_SAMPLER.to_string(),
            scope: "full_encoder".to_string(),
            seed: u64::from(SEED),
            source_commitment: sha256_hex(b"commitment"),
            expected_base: sha256_hex(b"base"),
        }
    );
    assert!(JournalAllocations::new(&path).allocation("s13c-r2", "privoke-v3-balanced").is_none());
}
