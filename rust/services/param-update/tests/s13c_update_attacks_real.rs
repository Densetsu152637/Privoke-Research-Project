//! Stage 13c-2 (`docs/plans/asiaccs-stage13-experiments.md`): the real-weight and container legs of the V3 update-attack matrix.
//!
//! Four env-gated entry points; each prints why it skipped and passes when its variables are unset (CI has no weights and no stack).
//!
//! * `s13c_real_leg`: the **real-weight leg**. One genuine candidate is built by a real routine fit, as
//!   `v3-fuzzer/tests/scheduler_real.rs` does it (the real scheduler round, the routine engine and the real V3 runtime in process, the
//!   real store behind the chain `main.rs` installs through [`build_observers`]). The scorer-dependent rows C11b, C11f and C11g are
//!   then repeated against the real Rust V3 encoder (GuardGate and RetentionGate with their real scorers) on a fresh store, and every
//!   candidate of the container leg is derived from the genuine one and exported (`S13C_EXPORT_CANDIDATES` for weights and
//!   manifests, `S13C_EXPORT_EVIDENCE` for the evidence, which carries prompt text). Every fit's wall time is kept as `fit_timings`.
//! * `s13c_journal_seed`: writes `S13C_ALLOCATIONS` (the 13c-1 format) into the scheduler journal `S13C_JOURNAL` with
//!   `Journal::allocate`, while the param-update container is stopped.
//! * `s13c_compose_pki`: a disposable test PKI and publication key in the `PRIVOKE_PKI_DIR` layout of `docker-compose.prod.yml`,
//!   plus the test principals (trainer, publisher, a registered installation).
//! * `s13c_container_leg`: the **container leg**. Every `wire_path: true` row that is not CI-only, against the Compose `v3-training`
//!   param-update and model-streaming containers (`S13C_ENDPOINT`), over mutual TLS. The authority is read from the store volume, and
//!   the served version through model-streaming `GetModelPackage`.
//!
//! "Unchanged" is the authority, not the blob directory: the `current` row, the `versions`, the `publications` (count and highest
//! sequence) and the version model-streaming serves. Rejected candidates may leave orphan blobs, which are reported and not counted.
//! Rows go to `S13C_OUT` in the row shape of 13c-1. No weights, prompts or keys are committed; the test PKI and the publication key
//! are generated per run.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::too_many_arguments, clippy::too_many_lines, clippy::type_complexity)]

mod common;
mod s13c_allocations;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use privoke_contracts::digest::sha256_hex;
use privoke_contracts::proto::experimental_v3 as v3;
use privoke_contracts::proto::experimental_v3::checkpoint_service_client::CheckpointServiceClient;
use privoke_contracts::proto::experimental_v3::{Chunk, Commit, Receipt, Rollback, StatusRequest};
use privoke_contracts::proto::v1::model_streaming_service_client::ModelStreamingServiceClient;
use privoke_contracts::proto::v1::{FuzzerTrainingRequest, FuzzerTrainingResponse, ModelParametersRequest};
use privoke_contracts::v3::{CHUNK_BYTES, TIERS, action_value, harm_count, tensor_changes};
use privoke_curriculum::audience::BUNDLED_MANIFEST_SHA256;
use privoke_curriculum::v3::{self as curriculum, AU3_SOURCE_FILES, BC01_SOURCE_FILES, INPUTS, Policy};
use privoke_curriculum::value;
use privoke_model_streaming::published::Published;
use privoke_model_streaming::releases::StandardReleases;
use privoke_param_update::build_observers;
use privoke_param_update::config::{PublicationConfig, RetentionConfig, V3Config};
use privoke_param_update::journal::{AllocationRow, Journal, JournalAllocations, Stage};
use privoke_param_update::scheduler::{CallError, FuzzerCaller, FuzzerRequestConfig, PinnedCommitments, run};
use privoke_param_update::v3_guard::{Allocation, GuardGate, score_blobs};
use privoke_param_update::v3_policy::{DriftBounds, l2_distance};
use privoke_param_update::v3_publish::no_crash;
use privoke_param_update::v3_retention::{DEFAULT_THREADS, RetentionReleases, assess_blobs};
use privoke_param_update::v3_store::{ChainObserver, CheckpointStore, PinnedSources, StoreError};
use privoke_pki::ca::{CaDir, Validity};
use privoke_pki::{client as enrolment, files::write_atomic, registry_edit};
use privoke_semantic::safetensors::{self, Tensor};
use privoke_transport::ClientTlsConfig;
use privoke_v3_fuzzer::backend::{CheckpointBackend, FitBackend, blob_chunks};
use privoke_v3_fuzzer::contract::canonical;
use privoke_v3_fuzzer::cycle::{Engine, EngineParts};
use privoke_v3_fuzzer::source::{Closure, Sampler, Schedules, python_source_hashes};
use privoke_v3_runtime::assets::Admission;
use privoke_v3_runtime::checkpoint::Checkpoint;
use privoke_v3_runtime::evidence::EVIDENCE_SOURCES;
use privoke_v3_runtime::fit::ScheduleSources;
use privoke_v3_runtime::service::{Runtime, RuntimeParts};
use s13c_allocations::{allocation_json, parse_allocations};
use serde_json::{Value as Json, json};
use tonic::transport::Channel;
use tonic::{Code, Status};

const MODEL: &str = "privoke-v3-efficient";
const TIER: &str = "efficient";
/// The scope label of every row of this study.
const SCOPE_LABEL: &str = "update path (Rust V3)";
const ACTIONS: [&str; 3] = ["ALLOW", "WARN", "BLOCK"];

const STORE: &str = "rust/services/param-update/src/v3_store/store.rs";
const SERVICE: &str = "rust/services/param-update/src/v3_store/service.rs";
const EVIDENCE: &str = "rust/services/param-update/src/v3_store/evidence.rs";
const POLICY: &str = "rust/services/param-update/src/v3_policy.rs";
const GUARD: &str = "rust/services/param-update/src/v3_guard.rs";
const RETENTION: &str = "rust/services/param-update/src/v3_retention.rs";
const CONTRACT: &str = "rust/crates/privoke-contracts/src/v3.rs";
const CURRICULUM: &str = "rust/crates/privoke-curriculum/src/v3.rs";
const SAFETENSORS: &str = "rust/crates/privoke-semantic/src/safetensors.rs";

/// The reason of C8b, which runs synthetically in CI only (13c-2 plan).
const C8B_NOT_RUN: &str = "C8b needs about 25 consecutive in-bound updates to reach the cumulative cap of 100; it runs synthetically \
                           in CI only (stand-in weights and test scorers), and the real-weight and container legs build one genuine \
                           candidate";

fn say(text: &str) {
    use std::io::Write;
    let _ = writeln!(std::io::stderr(), "{text}");
}

fn var(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

fn var_or(name: &str, default: &str) -> String {
    var(name).unwrap_or_else(|| default.to_string())
}

fn path_var(name: &str) -> Option<PathBuf> {
    var(name).map(PathBuf::from)
}

fn read_json(path: &Path) -> Json {
    serde_json::from_slice(&std::fs::read(path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))).unwrap()
}

fn write_json(path: &Path, document: &Json) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, serde_json::to_vec_pretty(document).unwrap()).unwrap();
}

/// Canonical JSON bytes (the contract's encoding: sorted keys, Python number forms) of a serde document.
fn canonical_json(document: &Json) -> Vec<u8> {
    value::canonical_bytes(&value::parse_bytes(document.to_string().as_bytes()).unwrap()).unwrap()
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
        Code::FailedPrecondition => "FAILED_PRECONDITION",
        Code::Unknown => "UNKNOWN",
        other => return format!("{other:?}").to_uppercase(),
    };
    name.to_string()
}

// ---------------------------------------------------------------------------------------------------------------------------
// Tensors: the safetensors bytes of a candidate, its inventory digests and its distance from a base.
// ---------------------------------------------------------------------------------------------------------------------------

type Tensors = BTreeMap<String, Tensor>;

fn raw_bytes(data: &[f32]) -> Vec<u8> {
    data.iter().flat_map(|value| value.to_le_bytes()).collect()
}

fn tensor(shape: Vec<usize>, data: Vec<f32>) -> Tensor {
    let sha256 = sha256_hex(&raw_bytes(&data));
    Tensor { shape, data, sha256 }
}

/// A safetensors file of float32 tensors, in name order (the layout of the CI stand-ins; the store and the encoder read any order).
fn serialize(tensors: &Tensors) -> Vec<u8> {
    let mut header = serde_json::Map::new();
    let mut body = Vec::new();
    for (name, item) in tensors {
        let bytes = raw_bytes(&item.data);
        header.insert(name.clone(), json!({"dtype": "F32", "shape": item.shape, "data_offsets": [body.len(), body.len() + bytes.len()]}));
        body.extend_from_slice(&bytes);
    }
    let header = serde_json::to_vec(&Json::Object(header)).unwrap();
    let mut file = (header.len() as u64).to_le_bytes().to_vec();
    file.extend_from_slice(&header);
    file.extend_from_slice(&body);
    file
}

fn digests(tensors: &Tensors) -> BTreeMap<String, String> {
    tensors.iter().map(|(name, item)| (name.clone(), item.sha256.clone())).collect()
}

/// The L2 distance of two checkpoints over every tensor (the drift gate's own measure).
fn l2(left: &Tensors, right: &Tensors) -> f64 {
    l2_distance(left, right).unwrap()
}

/// A deterministic direction of unit L2 norm over the tensors `names` (xorshift64*, uniform in [-1, 1)).
fn direction(shapes: &Tensors, names: &[String], seed: u64) -> BTreeMap<String, Vec<f32>> {
    let mut state = seed.max(1);
    let mut next = move || {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        let bits = state.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 40;
        (bits as f64 / f64::from(1u32 << 24)).mul_add(2.0, -1.0)
    };
    let mut raw: BTreeMap<String, Vec<f64>> =
        names.iter().map(|name| (name.clone(), (0..shapes[name].data.len()).map(|_| next()).collect())).collect();
    let norm = raw.values().flatten().map(|value| value * value).sum::<f64>().sqrt();
    raw.iter_mut().map(|(name, values)| (name.clone(), values.iter_mut().map(|value| (*value / norm) as f32).collect())).collect()
}

/// `base + scale * step` on the tensors of `step`.
fn moved(base: &Tensors, step: &BTreeMap<String, Vec<f32>>, scale: f32) -> Tensors {
    let mut result = base.clone();
    for (name, values) in step {
        let item = &base[name];
        let data: Vec<f32> = item.data.iter().zip(values).map(|(value, delta)| value + scale * delta).collect();
        result.insert(name.clone(), tensor(item.shape.clone(), data));
    }
    result
}

/// `pin + alpha * (genuine - pin)` on every tensor the genuine candidate changed.
fn toward(pin: &Tensors, genuine: &Tensors, changed: &[String], alpha: f32) -> Tensors {
    let mut result = pin.clone();
    for name in changed {
        let data = pin[name].data.iter().zip(&genuine[name].data).map(|(p, g)| p + alpha * (g - p)).collect();
        result.insert(name.clone(), tensor(pin[name].shape.clone(), data));
    }
    result
}

fn changed_names(base: &Tensors, candidate: &Tensors) -> Vec<String> {
    base.iter().filter(|(name, item)| candidate[*name].sha256 != item.sha256).map(|(name, _)| name.clone()).collect()
}

// ---------------------------------------------------------------------------------------------------------------------------
// Candidates derived from the genuine one.
// ---------------------------------------------------------------------------------------------------------------------------

/// The pinned release (the parent of every candidate) and the genuine candidate the real fit built.
struct Lineage {
    pin: String,
    original: String,
    pin_tensors: Tensors,
    genuine_manifest: Json,
    genuine_manifest_bytes: Vec<u8>,
    genuine_blob: Vec<u8>,
    genuine_evidence: Json,
    genuine_evidence_bytes: Vec<u8>,
    genuine_tensors: Tensors,
    allocation: AllocationRow,
}

/// One candidate, ready to stage and commit.
#[derive(Clone, Debug)]
struct Built {
    role: String,
    request_id: String,
    scope: String,
    manifest: Vec<u8>,
    manifest_sha: String,
    blob: Vec<u8>,
    blob_sha: String,
    evidence: Vec<u8>,
    evidence_sha: String,
    /// Allocated (in the journal) with the genuine candidate's release, scope, seed and commitment, on base `pin`.
    allocated: bool,
    note: String,
}

impl Built {
    fn commit(&self, pin: &str) -> Commit {
        Commit {
            request_id: self.request_id.clone(),
            model_id: MODEL.to_string(),
            expected_base: pin.to_string(),
            candidate: self.manifest_sha.clone(),
            evidence: self.evidence_sha.clone(),
        }
    }

    fn index(&self, pin: &str, extra: Json) -> Json {
        let mut entry = json!({
            "role": self.role, "request_id": self.request_id, "scope": self.scope, "parent": pin,
            "manifest_sha": self.manifest_sha, "blob_sha": self.blob_sha, "evidence_sha": self.evidence_sha,
            "allocated": self.allocated, "note": self.note
        });
        if let Json::Object(more) = extra {
            for (key, item) in more {
                entry[key] = item;
            }
        }
        entry
    }
}

/// How a derived candidate departs from the genuine one.
struct Derive<'a> {
    role: &'a str,
    request_id: String,
    /// The checkpoint (the genuine one when `None`).
    tensors: Option<&'a Tensors>,
    /// The checkpoint the blob carries when it differs from what the manifest declares (a blob-only fault).
    blob_tensors: Option<&'a Tensors>,
    evidence: Option<&'a dyn Fn(&mut Json)>,
    manifest: Option<&'a dyn Fn(&mut Json)>,
    allocated: bool,
    note: &'a str,
}

impl<'a> Derive<'a> {
    fn new(role: &'a str, request_id: String, note: &'a str) -> Self {
        Self { role, request_id, tensors: None, blob_tensors: None, evidence: None, manifest: None, allocated: true, note }
    }
}

impl Lineage {
    fn genuine(&self) -> Built {
        Built {
            role: "genuine".to_string(),
            request_id: self.allocation.request_id.clone(),
            scope: self.allocation.stage.name().to_string(),
            manifest_sha: sha256_hex(&self.genuine_manifest_bytes),
            manifest: self.genuine_manifest_bytes.clone(),
            blob_sha: sha256_hex(&self.genuine_blob),
            blob: self.genuine_blob.clone(),
            evidence_sha: sha256_hex(&self.genuine_evidence_bytes),
            evidence: self.genuine_evidence_bytes.clone(),
            allocated: true,
            note: "the genuine candidate of the real routine fit".to_string(),
        }
    }

    fn derive(&self, spec: &Derive<'_>) -> Built {
        let declared = spec.tensors.unwrap_or(&self.genuine_tensors);
        let blob = match (spec.tensors, spec.blob_tensors) {
            (_, Some(blob)) => serialize(blob),
            (Some(tensors), None) => serialize(tensors),
            (None, None) => self.genuine_blob.clone(),
        };
        let blob_sha = sha256_hex(&blob);
        let mut evidence = self.genuine_evidence.clone();
        evidence["request_id"] = Json::String(spec.request_id.clone());
        evidence["candidate_blob"] = Json::String(blob_sha.clone());
        if let Some(edit) = spec.evidence {
            edit(&mut evidence);
        }
        let evidence_bytes = canonical_json(&evidence);
        let evidence_sha = sha256_hex(&evidence_bytes);
        let mut manifest = self.genuine_manifest.clone();
        manifest["blob"] = Json::String(blob_sha.clone());
        manifest["evidence"] = Json::String(evidence_sha.clone());
        for (name, item) in declared {
            if manifest["tensors"].get(name).is_some() {
                manifest["tensors"][name]["sha256"] = Json::String(item.sha256.clone());
            }
        }
        if let Some(edit) = spec.manifest {
            edit(&mut manifest);
        }
        let manifest_bytes = canonical_json(&manifest);
        Built {
            role: spec.role.to_string(),
            request_id: spec.request_id.clone(),
            scope: manifest["scope"].as_str().unwrap_or_default().to_string(),
            manifest_sha: sha256_hex(&manifest_bytes),
            manifest: manifest_bytes,
            blob_sha,
            blob,
            evidence_sha,
            evidence: evidence_bytes,
            allocated: spec.allocated,
            note: spec.note.to_string(),
        }
    }

    /// The allocation of a derived request: the genuine candidate's release, scope, seed and commitment, on the pin.
    fn allocation_for(&self, request_id: &str) -> AllocationRow {
        AllocationRow { request_id: request_id.to_string(), expected_base: self.pin.clone(), ..self.allocation.clone() }
    }

    fn guard_allocation(&self) -> Allocation {
        Allocation {
            sampler: self.allocation.sampler.clone(),
            scope: self.allocation.stage.name().to_string(),
            seed: u64::from(self.allocation.seed),
            source_commitment: self.allocation.source_commitment.clone(),
            expected_base: self.pin.clone(),
        }
    }
}

/// The evidence of a heads fit: the frozen counters of the heads scope (a no-op for heads evidence).
fn heads_shaped(evidence: &mut Json) {
    let tier = TIERS.iter().find(|tier| tier.name == TIER).unwrap();
    evidence["scope"] = Json::String("heads".to_string());
    evidence["trainable_count"] = json!(20 * (tier.hidden_size + 1));
    evidence["counts"]["encoder_block_backward"] = json!(0);
    let layers = evidence["block_counts"]["backward"].as_array().map_or(0, Vec::len);
    evidence["block_counts"]["backward"] = json!(vec![0; layers]);
    if let Some(trace) = evidence["gradient_trace"].as_array_mut() {
        for step in trace {
            step["encoder_nonzero_gradients"] = json!(0);
        }
    }
}

/// Rewrite `changed_tensors` and `changes` as the change from `base` to `candidate`.
fn report_changes(evidence: &mut Json, base: &Tensors, candidate: &Tensors) {
    let layers = TIERS.iter().find(|tier| tier.name == TIER).unwrap().num_hidden_layers as usize;
    let (changed, changes) = tensor_changes(&digests(base), &digests(candidate), layers);
    evidence["changed_tensors"] = json!(changed);
    evidence["changes"] = changes;
}

/// Recount a guard block after its rows were edited.
fn recount(guard: &mut Json) {
    let rows = guard["rows"].as_array().cloned().unwrap_or_default();
    guard["joint_correct"] = json!(rows.iter().filter(|row| row["joint_correct"] == true).count());
    guard["action_correct"] = json!(rows.iter().filter(|row| row["action"] == row["target_action"]).count());
}

fn set_action(row: &mut Json, packed_key: &str, action_key: &str, confidence: f64) {
    let packed = u16::try_from(row[packed_key].as_u64().unwrap()).unwrap();
    let action = action_value(packed, Some(confidence));
    row[action_key] = Json::String(ACTIONS[usize::try_from(action).unwrap()].to_string());
    row[format!("{action_key}_value")] = json!(action);
}

fn rejoin(row: &mut Json) {
    row["joint_correct"] = json!(row["prediction"] == row["target"] && row["action"] == row["target_action"]);
}

/// C11a: honest evidence of a guard harm. The candidate's guard now blocks one row whose target allows.
fn honest_harm(evidence: &mut Json) {
    let rows = evidence["candidate_guard"]["rows"].as_array_mut().unwrap();
    let index = rows.iter().position(|row| row["target_action_value"] == 0).expect("a guard row whose target allows");
    let row = &mut rows[index];
    row["prediction"] = json!(15);
    row["confidence"] = json!(0.999);
    set_action(row, "prediction", "action", 0.999);
    rejoin(row);
    recount(&mut evidence["candidate_guard"]);
    evidence["action_harms"] = json!(harm_count(&evidence["base_guard"]["rows"], &evidence["candidate_guard"]["rows"]));
}

/// C11c: the guard targets of the evidence are not the rows the scheduler's release dispatches.
fn substituted_rows(evidence: &mut Json) {
    for key in ["base_guard", "candidate_guard"] {
        let row = &mut evidence[key]["rows"][0];
        let target = row["target"].as_u64().unwrap();
        row["target"] = json!(if target == 12 { 13 } else { 12 });
        set_action(row, "target", "target_action", 0.999);
        rejoin(row);
        recount(&mut evidence[key]);
    }
    evidence["action_harms"] = json!(harm_count(&evidence["base_guard"]["rows"], &evidence["candidate_guard"]["rows"]));
}

/// C11d: a trainer-chosen source (the source hashes name other files than the commitment covers).
fn tampered_source_hashes(evidence: &mut Json) {
    let first = evidence["source"]["source_hashes"].as_object().unwrap().keys().next().unwrap().clone();
    evidence["source"]["source_hashes"][first] = Json::String(sha256_hex(b"tampered"));
}

/// C11d (second variant): the seed of the source record is not the one derived from the scheduler's.
fn trainer_seed(evidence: &mut Json) {
    evidence["source"]["seed"] = json!(evidence["source"]["seed"].as_u64().unwrap() + 1);
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
    document["source"]["config_sha256"] = Json::String(balanced.config_sha256.to_string());
    document["source"]["repository"] = Json::String(balanced.repository.to_string());
    document["source"]["revision"] = Json::String(balanced.revision.to_string());
    document["source"]["weights_sha256"] = Json::String(balanced.weights_sha256.to_string());
    // One tensor of the balanced parameter count, so that the manifest is a valid balanced-tier manifest (as in the CI row).
    document["tensors"] = json!({"x": {"dtype": "F32", "shape": [balanced.parameters], "sha256": sha256_hex(b"x")}});
}

// ---------------------------------------------------------------------------------------------------------------------------
// Rows: the shape of 13c-1, one per variant and leg.
// ---------------------------------------------------------------------------------------------------------------------------

fn manifest_rows() -> Vec<Json> {
    serde_json::from_slice(&std::fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/s13c_rows.json")).unwrap()).unwrap()
}

fn manifest_row(id: &str) -> Json {
    manifest_rows().into_iter().find(|row| row["id"] == id).unwrap_or_else(|| panic!("{id} is not in s13c_rows.json"))
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
        Self::of(result.map_err(privoke_param_update::v3_store::service::status_of))
    }

    fn json(&self) -> Json {
        json!({"grpc_code": grpc_name(self.code), "receipt_status": self.status, "receipt_reason": self.reason, "message": self.message})
    }

    fn refused(&self, code: Code, message: &str) -> bool {
        self.code == code && self.message == message && self.status.is_empty()
    }

    fn rejected(&self, reason: &str) -> bool {
        self.code == Code::Ok && self.status == "rejected" && self.reason == reason
    }

    fn applied(&self) -> bool {
        self.code == Code::Ok && self.status == "applied" && self.reason.is_empty()
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

fn unchanged(before: &Auth, after: &Auth) -> bool {
    before == after
}

fn attempted(request_id: &str, expected_base: &str, candidate: &str, mutation: &str) -> Json {
    json!({"request_id": request_id, "model_id": MODEL, "expected_base": expected_base, "candidate_sha": candidate, "mutation": mutation})
}

fn attempted_of(built: &Built, pin: &str, mutation: &str) -> Json {
    attempted(&built.request_id, pin, &built.manifest_sha, mutation)
}

/// The rows of one leg. A row's `property_met` is what its states show for its expected outcome (the rule of the report's
/// `--check`); whether the named check is the one that fired is judged separately, and a row whose check did not fire names what was
/// observed instead and is listed as a mismatch (the leg fails after its rows are written).
struct Recorder {
    leg: &'static str,
    rows: Vec<Json>,
    mismatches: Vec<String>,
}

impl Recorder {
    fn new(leg: &'static str) -> Self {
        Self { leg, rows: Vec::new(), mismatches: Vec::new() }
    }

    /// Record one attack. `fired` says whether the call ended at the named check (`rejecting`) with the expected answer.
    fn row(
        &mut self,
        id: &str,
        identity: &str,
        surface: &str,
        variant: &str,
        attempted: Json,
        outcome: &Outcome,
        rejecting: (&str, &str, &str),
        before: &Auth,
        after: &Auth,
        orphan_blobs: usize,
        fired: bool,
        extra: Option<Json>,
    ) {
        let entry = manifest_row(id);
        let expected = entry["expected"].as_str().unwrap();
        let property_met = match expected {
            "rejected_unchanged" | "noop_unchanged" => unchanged(before, after),
            _ => after.current != before.current && after.served == after.current,
        };
        let check = if fired {
            json!({"file": rejecting.0, "symbol": rejecting.1, "reason": rejecting.2})
        } else {
            self.mismatches.push(format!("{id}: expected {rejecting:?}, observed {}", outcome.json()));
            let reason = if outcome.reason.is_empty() { outcome.message.clone() } else { outcome.reason.clone() };
            json!({"file": "unattributed (the named check did not fire)", "symbol": "see observed", "reason": if reason.is_empty() { "none".to_string() } else { reason }})
        };
        let mut row = json!({
            "id": id, "attack_class": entry["attack_class"], "variant": variant, "combined": false, "chain": entry["chain"],
            "leg": self.leg, "surface": surface, "identity": identity, "scope_label": SCOPE_LABEL,
            "attempted": attempted, "expected": expected, "observed": outcome.json(),
            "rejecting_check": check,
            "active_before": before.json(), "active_after": after.json(), "orphan_blobs": orphan_blobs,
            "property_met": property_met, "not_run_reason": null
        });
        if let Some(Json::Object(more)) = extra {
            for (key, item) in more {
                row[key] = item;
            }
        }
        say(&format!("ROW {} {id}: property_met={property_met} fired={fired} observed={}", self.leg, outcome.json()));
        self.rows.push(row);
    }

    fn not_run(&mut self, id: &str, surface: &str, variant: &str, reason: &str) {
        let entry = manifest_row(id);
        let empty = json!({"request_id": "", "model_id": MODEL, "expected_base": "", "candidate_sha": "", "mutation": ""});
        say(&format!("ROW {} {id}: not run: {reason}", self.leg));
        self.rows.push(json!({
            "id": id, "attack_class": entry["attack_class"], "variant": variant, "combined": false, "chain": entry["chain"],
            "leg": self.leg, "surface": surface, "identity": "", "scope_label": SCOPE_LABEL, "attempted": empty,
            "expected": entry["expected"],
            "observed": {"grpc_code": "", "receipt_status": "", "receipt_reason": "", "message": ""},
            "rejecting_check": null, "active_before": null, "active_after": null, "orphan_blobs": 0, "property_met": null,
            "not_run_reason": reason
        }));
    }

    fn write(&self, out: Option<&Path>, name: &str) {
        if let Some(directory) = out {
            write_json(&directory.join(name), &Json::Array(self.rows.clone()));
            write_json(&directory.join(format!("{}-mismatches.json", self.leg)), &json!(self.mismatches));
        }
    }

    /// Fail the leg (after its rows are written) when a property does not hold or a named check did not fire.
    fn verdict(&self) {
        let unmet: Vec<String> =
            self.rows.iter().filter(|row| row["property_met"] == false).map(|row| format!("{} {}", row["id"], row["observed"])).collect();
        assert!(unmet.is_empty() && self.mismatches.is_empty(), "{} leg: unmet {unmet:?}; mismatches {:?}", self.leg, self.mismatches);
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

// ---------------------------------------------------------------------------------------------------------------------------
// The source root of the leg: the Python closure the evidence commits to and the pinned BC01 inputs, exactly as
// `scheduler_real.rs` lays them out. The container mounts the same directory as `V3_SOURCE_DIR`.
// ---------------------------------------------------------------------------------------------------------------------------

fn curriculum_fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../crates/privoke-curriculum/tests/fixtures")
}

fn prepare_source(root: &Path) {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let copy = |from: &Path, relative: &str| {
        let target = root.join(relative);
        std::fs::create_dir_all(target.parent().unwrap()).unwrap();
        std::fs::copy(from, target).unwrap_or_else(|error| panic!("{}: {error}", from.display()));
    };
    for relative in EVIDENCE_SOURCES.iter().copied().chain(BC01_SOURCE_FILES).chain(AU3_SOURCE_FILES) {
        copy(&repo.join(relative), relative);
    }
    for (_, relative, _) in INPUTS {
        copy(&curriculum_fixtures().join("bc01").join(Path::new(relative).file_name().unwrap()), relative);
    }
    // The AU3 release param-update loads as the bundled one when no custom release is configured (the container sets none).
    for entry in std::fs::read_dir(curriculum_fixtures().join("au3")).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name().to_string_lossy().to_string();
        copy(&entry.path(), &format!("services/privoke-fuzzer/data/{name}"));
    }
}

// ---------------------------------------------------------------------------------------------------------------------------
// The real fit: the store service, the runtime and the in-process fuzzer of `scheduler_real.rs`.
// ---------------------------------------------------------------------------------------------------------------------------

fn status_of(error: StoreError) -> Status {
    privoke_param_update::v3_store::service::status_of(error)
}

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

/// The real runtime as the fuzzer's fit backend, timing every fit.
struct TimedFit {
    runtime: Arc<Runtime>,
    timings: Arc<Mutex<Vec<(String, String, f64, String)>>>,
}

#[tonic::async_trait]
impl FitBackend for TimedFit {
    async fn fit_candidate(&self, request: v3::FitRequest, _timeout: Duration) -> Result<v3::FitResponse, Status> {
        let (request_id, scope) =
            (request.request_id.clone(), if request.scope == v3::Scope::Heads as i32 { "heads" } else { "full_encoder" });
        let started = Instant::now();
        let result = self.runtime.fit_candidate(request, Arc::new(AtomicBool::new(true))).await;
        let outcome = match &result {
            Ok(_) => "fitted".to_string(),
            Err(status) => format!("fit_error:{}", grpc_name(status.code())),
        };
        self.timings.lock().unwrap_or_else(PoisonError::into_inner).push((
            request_id,
            scope.to_string(),
            started.elapsed().as_secs_f64(),
            outcome,
        ));
        result
    }

    async fn fit_status(&self, request_id: &str) -> Result<v3::Receipt, Status> {
        self.runtime.fit_status(request_id).map_err(|error| Status::unknown(error.0))
    }

    async fn health(&self) -> Result<v3::HealthResponse, Status> {
        Ok(self.runtime.health())
    }
}

struct InProcess(Arc<Engine>);

impl FuzzerCaller for InProcess {
    async fn call(&self, stage: Stage, request: FuzzerTrainingRequest, _timeout: Duration) -> Result<FuzzerTrainingResponse, CallError> {
        let scope = if stage == Stage::Heads { v3::Scope::Heads } else { v3::Scope::FullEncoder };
        self.0.run(request, scope).await.map_err(|status| CallError { code: Some(status.code()), message: status.message().to_string() })
    }
}

/// The inputs of the real-weight leg.
struct RealInputs {
    packages: PathBuf,
    originals: PathBuf,
    bank: PathBuf,
    source: PathBuf,
    export_candidates: PathBuf,
    export_evidence: PathBuf,
    out: Option<PathBuf>,
    threads: usize,
    steps: u32,
    rounds: u32,
    seed: u32,
    cpus: String,
}

impl RealInputs {
    fn retention_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("config/v3-retention")
    }

    fn drift_bounds() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("config/v3-drift-bounds.toml")
    }

    fn pinned(&self) -> Arc<PinnedSources> {
        Arc::new(PinnedSources::from_root(&self.source, None))
    }

    /// The deployment configuration of `main.rs` over `state`: drift, guard, retention and the signing publisher with a test key.
    fn config(&self, state: &Path) -> V3Config {
        let key_file = state.join("publication.key");
        if !key_file.exists() {
            let seed: Vec<u8> = uuid::Uuid::new_v4().as_bytes().iter().chain(uuid::Uuid::new_v4().as_bytes()).copied().collect();
            std::fs::write(&key_file, seed.iter().map(|byte| format!("{byte:02x}")).collect::<String>()).unwrap();
        }
        V3Config {
            store: state.join("store"),
            initial: Vec::new(),
            pinned: Vec::new(),
            source_root: self.source.clone(),
            audience: None,
            drift_bounds: Self::drift_bounds(),
            publication: Some(PublicationConfig { root: state.join("published"), key_file, key_id: "s13c2-real-test".to_string() }),
            retention: Some(RetentionConfig { root: Self::retention_root(), bank: self.bank.clone() }),
        }
    }

    /// A store with the production chain of `build_observers` (real scorers) over the journal at `journal`, bootstrapped on the pin.
    fn open_store(&self, state: &Path, journal: &Path) -> Arc<CheckpointStore> {
        let config = self.config(state);
        std::fs::create_dir_all(state.join("published")).unwrap();
        let pinned = self.pinned();
        let (observers, publisher) =
            build_observers(&config, pinned.clone(), Arc::new(JournalAllocations::new(journal)), no_crash(), None, None).unwrap();
        assert_eq!(observers.len(), 4, "drift, guard, retention and the publisher");
        let store = CheckpointStore::open(&config.store, pinned).unwrap().with_observer(Arc::new(ChainObserver::new(observers)));
        store.bootstrap_pinned(&self.originals.join(TIER), &self.packages.join(MODEL)).unwrap();
        publisher.unwrap().reconcile(&store).unwrap();
        Arc::new(store)
    }
}

struct Fitted {
    lineage: Option<Lineage>,
    timings: Vec<Json>,
    failed: Vec<String>,
}

/// Real routine rounds until one produces a candidate on the pin that the full chain applies (at most `rounds`).
async fn fit_genuine(inputs: &RealInputs, work: &Path) -> Fitted {
    let audience = (inputs.source.join("services/privoke-fuzzer/data/audience-v3-manifest-v1.json"), BUNDLED_MANIFEST_SHA256.to_string());
    let policy = Policy { steps: inputs.steps };
    let policy_bytes = canonical(&policy.to_value()).unwrap();
    let paths: BTreeMap<&str, PathBuf> = INPUTS.iter().map(|(key, relative, _)| (*key, inputs.source.join(relative))).collect();
    let sources = curriculum::load_sources_from(&paths).unwrap();
    let release = curriculum::trusted_release(Some(audience.0.as_path()), Some(audience.1.as_str())).unwrap();
    let schedules = |sampler| {
        let hashes = python_source_hashes(&inputs.source, sampler).unwrap();
        match sampler {
            Sampler::Bc01 => Schedules::bc01(sources.clone(), hashes),
            Sampler::Au3 => Schedules::au3(release.clone(), hashes),
        }
    };
    let mut fitted = Fitted { lineage: None, timings: Vec::new(), failed: Vec::new() };
    for round in 0..inputs.rounds {
        let state = work.join(format!("fit-{round}"));
        let journal = state.join("training-cycles.sqlite3");
        Journal::open(&journal).unwrap();
        let store = inputs.open_store(&state, &journal);
        let pin = store.resolve(MODEL).unwrap();
        let service = Arc::new(StoreService(store.clone()));
        let runtime = Arc::new(
            Runtime::new(
                RuntimeParts {
                    directory: state.join("runtime"),
                    threads: inputs.threads,
                    closure: Closure::Fixed("s13c2-real".to_string()),
                    admission: Admission::Pinned,
                    schedules: ScheduleSources { root: inputs.source.clone(), audience: Some(audience.clone()) },
                },
                service.clone(),
            )
            .await
            .unwrap(),
        );
        let timings = Arc::new(Mutex::new(Vec::new()));
        let fit = Arc::new(TimedFit { runtime, timings: timings.clone() });
        let parts = EngineParts {
            policy: policy.to_value(),
            schedules: schedules(Sampler::Bc01),
            directory: state.join("fuzzer"),
            fit_timeout: Duration::from_secs(7200),
            closure: Closure::Fixed("s13c2-real".to_string()),
        };
        let engine = Engine::new(parts, fit, service.clone()).await.unwrap();
        let engine = Arc::new(engine.with_routine(vec![schedules(Sampler::Bc01), schedules(Sampler::Au3)]).unwrap());
        let commitments = PinnedCommitments::new(&inputs.pinned(), &inputs.source, &policy_bytes).unwrap();
        let config = FuzzerRequestConfig {
            target: "in-process".to_string(),
            prompt_count: (policy.window_batches() * 32) as i64,
            source_id: "s13c2-real".to_string(),
            timeout_seconds: 7200.0,
            interval_seconds: 0.0,
            initial_delay_seconds: 0.0,
            retry_seconds: 0.0,
            max_attempts: 1,
            seed: i64::from(inputs.seed + round),
            state_path: journal.clone(),
            policy_file: PathBuf::from("unused"),
            tiers: vec![TIER.to_string()],
        };
        let started = Instant::now();
        let outcome = run(&config, &InProcess(engine), store.as_ref(), &commitments).await;
        say(&format!("FIT round {round}: {:.1} s, scheduler {:?}", started.elapsed().as_secs_f64(), outcome.as_ref().err()));
        let rows = Journal::open(&journal).unwrap().allocations(0).unwrap();
        let mut receipts = BTreeMap::new();
        for row in &rows {
            let receipt = store.status(&row.request_id).unwrap();
            say(&format!(
                "FIT round {round}: {} request={} base={} journal={} receipt=({} {:?}) candidate={}",
                row.stage.name(),
                row.request_id,
                row.expected_base,
                row.state,
                receipt.status,
                receipt.reason,
                receipt.candidate
            ));
            receipts.insert(row.request_id.clone(), receipt);
        }
        for (request_id, scope, seconds, fit_outcome) in timings.lock().unwrap_or_else(PoisonError::into_inner).iter() {
            let outcome = match receipts.get(request_id) {
                Some(receipt) if receipt.status == "applied" => "applied".to_string(),
                Some(receipt) if !receipt.reason.is_empty() => format!("{}:{}", receipt.status, receipt.reason),
                _ => fit_outcome.clone(),
            };
            fitted.timings.push(json!({
                "request_id": request_id, "tier": TIER, "scope": scope, "wall_seconds": (seconds * 10.0).round() / 10.0,
                "cpus": inputs.cpus, "outcome": outcome
            }));
        }
        let genuine = rows.iter().find(|row| row.state == "accepted" && row.expected_base == pin);
        for row in rows.iter().filter(|row| Some(row.request_id.as_str()) != genuine.map(|found| found.request_id.as_str())) {
            if row.expected_base == pin {
                let receipt = &receipts[&row.request_id];
                fitted.failed.push(format!("{} ({} {})", row.request_id, receipt.status, receipt.reason));
            }
        }
        let Some(row) = genuine else { continue };
        let manifest_sha = row.candidate.clone().unwrap_or_else(|| receipts[&row.request_id].candidate.clone());
        let manifest_bytes = store.read(&manifest_sha).unwrap();
        let manifest: Json = serde_json::from_slice(&manifest_bytes).unwrap();
        let blob = store.read(manifest["blob"].as_str().unwrap()).unwrap();
        let evidence_bytes = store.read(manifest["evidence"].as_str().unwrap()).unwrap();
        let pin_manifest: Json = serde_json::from_slice(&store.read(&pin).unwrap()).unwrap();
        let pin_tensors = safetensors::parse(&store.read(pin_manifest["blob"].as_str().unwrap()).unwrap()).unwrap();
        // The manifest inventory digests are the digests of the raw tensor bytes this test also computes.
        for (name, item) in &pin_tensors {
            assert_eq!(pin_manifest["tensors"][name]["sha256"].as_str(), Some(item.sha256.as_str()), "{name}");
        }
        let genuine_tensors = safetensors::parse(&blob).unwrap();
        fitted.lineage = Some(Lineage {
            original: pin_manifest["original"].as_str().unwrap().to_string(),
            pin,
            pin_tensors,
            genuine_evidence: serde_json::from_slice(&evidence_bytes).unwrap(),
            genuine_evidence_bytes: evidence_bytes,
            genuine_manifest: manifest,
            genuine_manifest_bytes: manifest_bytes,
            genuine_blob: blob,
            genuine_tensors,
            allocation: AllocationRow { state: "allocated".to_string(), candidate: None, reason: None, ..row.clone() },
        });
        break;
    }
    fitted
}

// ---------------------------------------------------------------------------------------------------------------------------
// The real-weight world of the C11 rows: a fresh store on the pin with the production chain and real scorers.
// ---------------------------------------------------------------------------------------------------------------------------

struct RealWorld {
    store: Arc<CheckpointStore>,
    journal: PathBuf,
    state: PathBuf,
    releases: StandardReleases,
}

impl RealWorld {
    fn observe(&self) -> Auth {
        let publications = self.store.publications(MODEL).unwrap();
        let published = Published::open(&self.state.join("published"), &self.state.join("store")).unwrap();
        Auth {
            current: self.store.resolve(MODEL).unwrap(),
            versions: self.store.history(MODEL).unwrap().len(),
            publications: publications.len(),
            max_sequence: publications.iter().map(|row| row.sequence).max().unwrap_or(0),
            served: match published.current_package(&self.releases, MODEL) {
                Ok(package) => package.manifest_sha256,
                Err(status) => format!("refused:{}", grpc_name(status.code())),
            },
        }
    }

    fn orphan_blobs(&self) -> usize {
        orphans(&self.state.join("store"), &self.store.history(MODEL).unwrap(), |sha| {
            serde_json::from_slice(&self.store.read(sha).unwrap()).unwrap()
        })
    }

    fn allocate(&self, row: &AllocationRow) {
        Journal::open(&self.journal).unwrap().allocate(row).unwrap();
    }

    fn stage(&self, built: &Built) -> Result<(), StoreError> {
        self.store.stage(&built.evidence, b"")?;
        self.store.stage(&built.blob, &built.manifest)?;
        Ok(())
    }
}

/// Blob files no version of the model references (what rejected candidates leave behind).
fn orphans(store: &Path, history: &[String], manifest: impl Fn(&str) -> Json) -> usize {
    let mut referenced = BTreeSet::new();
    for sha in history {
        let document = manifest(sha);
        referenced.insert(sha.clone());
        for key in ["blob", "config", "vocab", "evidence"] {
            if let Some(text) = document[key].as_str() {
                referenced.insert(text.to_string());
            }
        }
    }
    std::fs::read_dir(store.join("blobs"))
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .map(|entry| entry.file_name().to_string_lossy().to_string())
                .filter(|name| !name.starts_with("stage-") && !referenced.contains(name))
                .count()
        })
        .unwrap_or(0)
}

/// What the real scorers say of one candidate over the pin.
#[derive(Debug, Clone, Copy)]
struct Scored {
    guard_passes: bool,
    base_joint: usize,
    candidate_joint: usize,
    violations: usize,
    eligible: usize,
    l2_from_pin: f64,
}

struct Scorer<'a> {
    world: &'a RealWorld,
    lineage: &'a Lineage,
    rows: Vec<privoke_curriculum::Example>,
    release: Arc<privoke_training::retention_v3::RetentionRelease>,
    config: String,
    vocab: String,
    pin_blob: String,
}

impl Scorer<'_> {
    fn score(&self, tensors: &Tensors, retention: bool) -> Scored {
        let blob = serialize(tensors);
        let sha = self.world.store.put(&blob).unwrap();
        let (base, candidate) = score_blobs(&self.world.store, &self.config, &self.vocab, &self.pin_blob, &sha, &self.rows).unwrap();
        let verdict = retention.then(|| {
            assess_blobs(&self.world.store, &self.release, &self.config, &self.vocab, &self.pin_blob, &sha, DEFAULT_THREADS).unwrap()
        });
        Scored {
            guard_passes: privoke_param_update::v3_guard::passes(&base, &candidate),
            base_joint: base.joint,
            candidate_joint: candidate.joint,
            violations: verdict.map_or(0, |verdict| verdict.violations),
            eligible: verdict.map_or(0, |verdict| verdict.eligible),
            l2_from_pin: l2(tensors, &self.lineage.pin_tensors),
        }
    }
}

fn scored_json(label: &str, scale: f64, noise_seed: u64, scored: &Scored) -> Json {
    json!({
        "candidate": label, "scale": scale, "direction": noise_seed, "guard_passes": scored.guard_passes,
        "base_joint": scored.base_joint, "candidate_joint": scored.candidate_joint, "retention_violations": scored.violations,
        "retention_eligible": scored.eligible, "l2_from_pin": (scored.l2_from_pin * 1e4).round() / 1e4
    })
}

/// The bound a candidate of `scope` must stay within (`max_update_l2` of the shipped drift bounds).
fn update_bound(scope: &str) -> f64 {
    DriftBounds::load(&RealInputs::drift_bounds()).unwrap().bound(TIER, scope).unwrap().max_update_l2
}

struct Search {
    c11b: Option<(Tensors, Scored)>,
    c11f: Option<(Tensors, Scored)>,
    c11g: Option<(Tensors, Scored)>,
    trace: Vec<Json>,
}

/// Find, with the real scorers, a candidate the recomputed guard refuses (C11b), one that passes the guard and regresses beyond the
/// allowance (C11f), and one that passes the guard and regresses by exactly the allowance (C11g), all within the update bound.
fn search(scorer: &Scorer<'_>, changed: &[String], bound: f64, allowance: usize) -> Search {
    let lineage = scorer.lineage;
    let mut result = Search { c11b: None, c11f: None, c11g: None, trace: Vec::new() };
    let genuine = scorer.score(&lineage.genuine_tensors, true);
    result.trace.push(scored_json("genuine", 0.0, 0, &genuine));
    // C11b: weights moved away from the genuine candidate (past the pin), with the genuine evidence still claiming a pass.
    for alpha in [0.5f32, 1.0, 1.5] {
        let tensors = toward(&lineage.pin_tensors, &lineage.genuine_tensors, changed, -alpha);
        if changed_names(&lineage.pin_tensors, &tensors) != changed {
            continue;
        }
        let scored = scorer.score(&tensors, false);
        result.trace.push(scored_json("away_from_genuine", f64::from(alpha), 0, &scored));
        if !scored.guard_passes && scored.l2_from_pin <= bound * 0.98 {
            result.c11b = Some((tensors, scored));
            break;
        }
    }
    // C11f and C11g: one head bias entry of the genuine candidate moved by a scale within the update bound (a concentrated
    // logit shift; spread heads noise within the bound barely moves retention). Every entry and sign is tried at the full budget,
    // then the scale is bisected for exactly the allowance on the directions that regress beyond it.
    let budget = (bound * bound - genuine.l2_from_pin * genuine.l2_from_pin).max(0.0).sqrt() * 0.95;
    let biases: Vec<String> =
        changed.iter().filter(|name| name.starts_with("heads.") && lineage.genuine_tensors[*name].shape.len() == 1).cloned().collect();
    let mut directions: Vec<(String, BTreeMap<String, Vec<f32>>)> = Vec::new();
    for name in &biases {
        for index in 0..lineage.genuine_tensors[name].data.len() {
            for sign in [1.0f32, -1.0] {
                let mut unit = vec![0.0f32; lineage.genuine_tensors[name].data.len()];
                unit[index] = sign;
                directions.push((format!("{name}[{index}]{}", if sign > 0.0 { "+" } else { "-" }), BTreeMap::from([(name.clone(), unit)])));
            }
        }
    }
    // Record one scored candidate in the trace and keep it when it has a property the search wants (in evaluation order).
    let record = |label: &str, scale: f64, tensors: Tensors, scored: Scored, result: &mut Search| {
        let mut entry = scored_json("genuine_plus_head_bias", scale, 0, &scored);
        entry["direction"] = json!(label);
        result.trace.push(entry);
        let within = scored.l2_from_pin <= bound * 0.98 && changed_names(&lineage.pin_tensors, &tensors) == changed;
        if within && scored.guard_passes && scored.violations > allowance && result.c11f.is_none() {
            result.c11f = Some((tensors.clone(), scored));
        }
        if within && scored.guard_passes && scored.violations == allowance && result.c11g.is_none() {
            result.c11g = Some((tensors, scored));
        }
    };
    let evaluate = |label: &str, step: &BTreeMap<String, Vec<f32>>, scale: f64, result: &mut Search| -> Scored {
        let tensors = moved(&lineage.genuine_tensors, step, scale as f32);
        let scored = scorer.score(&tensors, true);
        record(label, scale, tensors, scored, result);
        scored
    };
    // The sweep scores `batch` candidates at once (each scoring keeps its own production thread counts, so the verdicts are the
    // sequential ones; only the wall time changes), and records them in direction order.
    let batch: usize = var_or("S13C_SCORE_BATCH", "2").parse().unwrap();
    let mut beyond: Vec<(usize, usize)> = Vec::new();
    for (offset, group) in directions.chunks(batch.max(1)).enumerate() {
        let candidates: Vec<Tensors> = group.iter().map(|(_, step)| moved(&lineage.genuine_tensors, step, budget as f32)).collect();
        let scores: Vec<Scored> = std::thread::scope(|scope| {
            let handles: Vec<_> = candidates.iter().map(|tensors| scope.spawn(move || scorer.score(tensors, true))).collect();
            handles.into_iter().map(|handle| handle.join().unwrap()).collect()
        });
        for (position, ((label, _), (tensors, scored))) in group.iter().zip(candidates.into_iter().zip(scores)).enumerate() {
            if scored.guard_passes && scored.violations > allowance {
                beyond.push((scored.violations, offset * batch.max(1) + position));
            }
            record(label, budget, tensors, scored, &mut result);
        }
    }
    beyond.sort_unstable();
    for (_, index) in beyond.iter().take(4) {
        if result.c11g.is_some() {
            break;
        }
        let (label, step) = &directions[*index];
        let (mut low, mut high) = (0.0f64, budget);
        for _ in 0..10 {
            let middle = (low + high) / 2.0;
            let found = evaluate(label, step, middle, &mut result);
            if result.c11g.is_some() {
                break;
            }
            if found.violations < allowance {
                low = middle;
            } else {
                high = middle;
            }
        }
    }
    result
}

/// Another shape of the same element count: a vector becomes one row, a matrix is flattened (a 1-D head bias flattened stays
/// unchanged, which is no fault at all).
fn other_shape(shape: &[usize]) -> Vec<usize> {
    if shape.len() == 1 { vec![1, shape[0]] } else { vec![shape.iter().product()] }
}

/// C6a (the shape of one heads tensor changed in both the manifest and the blob) and C6b (in the blob only), from the genuine one.
fn shape_candidates(lineage: &Lineage, c6a: &str, c6b: &str) -> (Built, Built) {
    let name = lineage.genuine_tensors.keys().find(|name| name.starts_with("heads.")).unwrap().clone();
    let mut reshaped = lineage.genuine_tensors.clone();
    let item = reshaped.get_mut(&name).unwrap();
    item.shape = other_shape(&item.shape);
    let shape = item.shape.clone();
    assert_ne!(shape, lineage.genuine_tensors[&name].shape, "the mutation changes the shape");
    let manifest = |document: &mut Json| document["tensors"][&name]["shape"] = json!(shape);
    let mut spec = Derive::new("C6a", c6a.to_string(), "a heads tensor reshaped in both the manifest and the blob");
    spec.tensors = Some(&reshaped);
    spec.manifest = Some(&manifest);
    let both = lineage.derive(&spec);
    let mut spec = Derive::new("C6b", c6b.to_string(), "a heads tensor reshaped in the blob only");
    spec.blob_tensors = Some(&reshaped);
    (both, lineage.derive(&spec))
}

/// Re-derive the exported C6a and C6b candidates from the exported genuine one (stage 13c-2: the first export flattened a 1-D head
/// bias, which left its shape unchanged). Nothing else in the export changes; the request ids and their allocations stay.
#[test]
fn s13c_rederive_shape_candidates() {
    let (Some(models), Some(evidence)) = (path_var("S13C_EXPORT_CANDIDATES"), path_var("S13C_EXPORT_EVIDENCE")) else {
        say("PENDING: set S13C_EXPORT_CANDIDATES and S13C_EXPORT_EVIDENCE to re-derive the exported shape candidates");
        return;
    };
    let (mut index, built) = load_candidates(&models, &evidence);
    let genuine = &built["genuine"];
    let allocations = parse_allocations(&std::fs::read_to_string(models.join("allocations.json")).unwrap()).unwrap();
    let allocation = allocations.into_iter().find(|row| row.request_id == genuine.request_id).unwrap();
    let lineage = Lineage {
        pin: index["pin"].as_str().unwrap().to_string(),
        original: index["original"].as_str().unwrap().to_string(),
        pin_tensors: Tensors::new(),
        genuine_manifest: serde_json::from_slice(&genuine.manifest).unwrap(),
        genuine_manifest_bytes: genuine.manifest.clone(),
        genuine_blob: genuine.blob.clone(),
        genuine_evidence: serde_json::from_slice(&genuine.evidence).unwrap(),
        genuine_evidence_bytes: genuine.evidence.clone(),
        genuine_tensors: safetensors::parse(&genuine.blob).unwrap(),
        allocation,
    };
    let (c6a, c6b) = shape_candidates(&lineage, &built["C6a"].request_id, &built["C6b"].request_id);
    for candidate in [&c6a, &c6b] {
        std::fs::write(models.join("blobs").join(format!("{}.safetensors", candidate.blob_sha)), &candidate.blob).unwrap();
        std::fs::write(models.join("manifests").join(format!("{}.json", candidate.manifest_sha)), &candidate.manifest).unwrap();
        std::fs::write(evidence.join(format!("{}.json", candidate.evidence_sha)), &candidate.evidence).unwrap();
        let entry = index["candidates"].as_array_mut().unwrap().iter_mut().find(|entry| entry["role"] == candidate.role.as_str()).unwrap();
        entry["manifest_sha"] = json!(candidate.manifest_sha);
        entry["blob_sha"] = json!(candidate.blob_sha);
        entry["evidence_sha"] = json!(candidate.evidence_sha);
        entry["note"] = json!(format!("{} (re-derived from the exported genuine candidate)", candidate.note));
        say(&format!("REDERIVED {} manifest={}", candidate.role, candidate.manifest_sha));
    }
    write_json(&models.join("index.json"), &index);
}

// ---------------------------------------------------------------------------------------------------------------------------
// The real-weight leg.
// ---------------------------------------------------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s13c_real_leg() {
    let (Some(packages), Some(originals), Some(bank), Some(source), Some(export_candidates), Some(export_evidence)) = (
        path_var("PRIVOKE_V3_S13C_PACKAGES"),
        path_var("PRIVOKE_V3_S13C_ORIGINALS"),
        path_var("PRIVOKE_V3_S13C_BANK"),
        path_var("S13C_SOURCE_ROOT"),
        path_var("S13C_EXPORT_CANDIDATES"),
        path_var("S13C_EXPORT_EVIDENCE"),
    ) else {
        say("PENDING: set PRIVOKE_V3_S13C_PACKAGES, _ORIGINALS, _BANK, S13C_SOURCE_ROOT and S13C_EXPORT_* to run the real-weight leg");
        return;
    };
    let inputs = RealInputs {
        packages,
        originals,
        bank,
        source,
        export_candidates,
        export_evidence,
        out: path_var("S13C_OUT"),
        threads: var_or("PRIVOKE_V3_S13C_THREADS", "8").parse().unwrap(),
        steps: var_or("PRIVOKE_V3_S13C_STEPS", "64").parse().unwrap(),
        rounds: var_or("S13C_FIT_ROUNDS", "2").parse().unwrap(),
        seed: var_or("S13C_FIT_SEED", "20261126").parse().unwrap(),
        cpus: var_or("S13C_CPUS", "8"),
    };
    prepare_source(&inputs.source);
    let work = tempfile::tempdir().unwrap();
    let started = Instant::now();
    let fitted = fit_genuine(&inputs, work.path()).await;
    let mut recorder = Recorder::new("real");
    let mut summary = json!({
        "fit_timings": fitted.timings, "failed_requests": fitted.failed, "rounds_allowed": inputs.rounds,
        "threads": inputs.threads, "steps": inputs.steps, "cpus": inputs.cpus
    });
    let Some(lineage) = fitted.lineage else {
        let reason = format!("the genuine candidate failed in every real fit round: {}", fitted.failed.join("; "));
        for (id, variant) in [
            ("C11b", "the evidence claims a pass, but the recomputed guard fails"),
            ("C11f", "reference rows regress beyond the 5% allowance"),
            ("C11g", "the boundary: exactly the allowance"),
        ] {
            recorder.not_run(id, "commit", variant, &reason);
        }
        recorder.not_run("C8b", "commit", "a run of updates each under the per-update bound until the cumulative cap of 100", C8B_NOT_RUN);
        recorder.write(inputs.out.as_deref(), "s13c_update_attacks_real.rows.json");
        write_json(&inputs.export_candidates.join("real-leg.json"), &summary);
        panic!("GENUINE CANDIDATE FAILED: {reason}");
    };
    let genuine = lineage.genuine();
    say(&format!("GENUINE {} {} scope={} manifest={}", MODEL, genuine.request_id, genuine.scope, genuine.manifest_sha));
    let reserialised = canonical_json(&lineage.genuine_evidence) == lineage.genuine_evidence_bytes;
    summary["genuine_evidence_canonical_roundtrip"] = json!(reserialised);

    // The world of the real rows and of the scorer search: a fresh store on the pin, the production chain, real scorers.
    let state = work.path().join("rows");
    let journal = state.join("training-cycles.sqlite3");
    Journal::open(&journal).unwrap();
    let world = RealWorld {
        store: inputs.open_store(&state, &journal),
        journal,
        state: state.clone(),
        releases: StandardReleases::open(&inputs.packages).unwrap(),
    };
    assert_eq!(world.store.resolve(MODEL).unwrap(), lineage.pin);
    let changed = changed_names(&lineage.pin_tensors, &lineage.genuine_tensors);
    let bound = update_bound(&genuine.scope);
    let releases = RetentionReleases::load(&RealInputs::retention_root(), &inputs.bank).unwrap();
    let release = releases.get(MODEL).unwrap().clone();
    let allowance = release.rule.max_violations;
    let pin_manifest: Json = serde_json::from_slice(&world.store.read(&lineage.pin).unwrap()).unwrap();
    let guard = GuardGate::new(inputs.pinned(), Arc::new(JournalAllocations::new(&world.journal)));
    let scorer = Scorer {
        world: &world,
        lineage: &lineage,
        rows: guard.rows(&lineage.guard_allocation()).unwrap(),
        release,
        config: pin_manifest["config"].as_str().unwrap().to_string(),
        vocab: pin_manifest["vocab"].as_str().unwrap().to_string(),
        pin_blob: pin_manifest["blob"].as_str().unwrap().to_string(),
    };
    let search_started = Instant::now();
    let found = search(&scorer, &changed, bound, allowance);
    summary["search"] = json!({
        "seconds": (search_started.elapsed().as_secs_f64() * 10.0).round() / 10.0, "update_bound": bound, "allowance": allowance,
        "changed_tensors": changed.len(), "trace": found.trace
    });

    // The candidates of the container leg, all derived from the genuine one (request ids are unique per stack).
    let rid = |role: &str| format!("s13c2-{role}");
    let mut candidates: Vec<(Built, Json)> = vec![(genuine.clone(), json!({"row": "positive control, C2a, C3a"}))];
    let derived = |spec: Derive<'_>| lineage.derive(&spec);
    candidates
        .push((derived(Derive::new("C1a", rid("c1a"), "the genuine blob, its evidence rewritten to name another request")), json!({})));
    for role in ["C4a", "C4d"] {
        candidates.push((
            derived(Derive::new(role, rid(&role.to_lowercase()), "an admitted candidate whose commit names another model or base")),
            json!({}),
        ));
    }
    let manifest_edits: [(&str, &dyn Fn(&mut Json), &str); 2] = [
        ("C4b", &other_tier, "a balanced-tier manifest whose parent is the efficient pin"),
        ("C4c", &wrong_original, "the original field names another manifest"),
    ];
    for (role, edit, note) in manifest_edits {
        let mut spec = Derive::new(role, rid(&role.to_lowercase()), note);
        spec.manifest = Some(edit);
        candidates.push((derived(spec), json!({})));
    }
    let first_head = lineage.genuine_tensors.keys().find(|name| name.starts_with("heads.")).unwrap().clone();
    let edit_head = |edit: &dyn Fn(&mut Tensors, &str)| {
        let mut tensors = lineage.genuine_tensors.clone();
        edit(&mut tensors, &first_head);
        tensors
    };
    let renamed = edit_head(&|tensors, name| {
        let item = tensors.remove(name).unwrap();
        tensors.insert(format!("{name}_renamed"), item);
    });
    let nonfinite = |value: f32| {
        edit_head(&move |tensors: &mut Tensors, name: &str| {
            let item = &tensors[name];
            let mut data = item.data.clone();
            data[1] = value;
            let shape = item.shape.clone();
            tensors.insert(name.to_string(), tensor(shape, data));
        })
    };
    let (nan, positive, negative) = (nonfinite(f32::NAN), nonfinite(f32::INFINITY), nonfinite(f32::NEG_INFINITY));
    let rename_manifest = |document: &mut Json| {
        let entry = document["tensors"].as_object_mut().unwrap().remove(&first_head).unwrap();
        document["tensors"][format!("{first_head}_renamed")] = entry;
    };
    let mut spec = Derive::new("C5a", rid("c5a"), "a heads tensor renamed in both the manifest and the blob");
    spec.tensors = Some(&renamed);
    spec.manifest = Some(&rename_manifest);
    candidates.push((derived(spec), json!({})));
    let mut spec = Derive::new("C5b", rid("c5b"), "a heads tensor renamed in the blob only");
    spec.blob_tensors = Some(&renamed);
    candidates.push((derived(spec), json!({})));
    let (c6a, c6b) = shape_candidates(&lineage, &rid("c6a"), &rid("c6b"));
    candidates.push((c6a, json!({})));
    candidates.push((c6b, json!({})));
    for (role, tensors, note) in [
        ("C7a", &nan, "NaN in one heads coordinate"),
        ("C7b", &positive, "+Inf in one heads coordinate"),
        ("C7c", &negative, "-Inf in one heads coordinate"),
    ] {
        let mut spec = Derive::new(role, rid(&role.to_lowercase()), note);
        spec.tensors = Some(tensors);
        candidates.push((derived(spec), json!({})));
    }
    // C8: beyond the update bound; and a HEADS candidate that changes encoder bytes, with honest (C8c) and dishonest (C8d) evidence.
    let step =
        direction(&lineage.genuine_tensors, &changed.iter().filter(|name| name.starts_with("heads.")).cloned().collect::<Vec<_>>(), 1);
    let beyond = moved(&lineage.genuine_tensors, &step, (bound * 2.0) as f32);
    let mut spec = Derive::new("C8a", rid("c8a"), "the genuine candidate moved beyond max_update_l2 on its heads");
    spec.tensors = Some(&beyond);
    candidates.push((derived(spec), json!({"l2_from_pin": l2(&beyond, &lineage.pin_tensors), "update_bound": bound})));
    let mut through_encoder = lineage.genuine_tensors.clone();
    if !changed.iter().any(|name| name.starts_with("encoder.")) {
        let name = lineage.genuine_tensors.keys().find(|name| name.starts_with("encoder.encoder.layer.0.")).unwrap().clone();
        let item = &lineage.genuine_tensors[&name];
        let mut data = item.data.clone();
        data[0] += 0.25;
        through_encoder.insert(name, tensor(item.shape.clone(), data));
    }
    let heads_only = toward(
        &lineage.pin_tensors,
        &through_encoder,
        &changed.iter().filter(|name| name.starts_with("heads.")).cloned().collect::<Vec<_>>(),
        1.0,
    );
    let honest = |evidence: &mut Json| {
        heads_shaped(evidence);
        report_changes(evidence, &lineage.pin_tensors, &through_encoder);
    };
    let dishonest = |evidence: &mut Json| {
        heads_shaped(evidence);
        report_changes(evidence, &lineage.pin_tensors, &heads_only);
    };
    let heads_scope = |document: &mut Json| document["scope"] = Json::String("heads".to_string());
    let mut spec = Derive::new("C8c", rid("c8c"), "scope heads, encoder tensors changed, the evidence reports it");
    spec.tensors = Some(&through_encoder);
    spec.evidence = Some(&honest);
    spec.manifest = Some(&heads_scope);
    candidates.push((derived(spec), json!({})));
    let mut spec = Derive::new("C8d", rid("c8d"), "scope heads, encoder tensors changed, the evidence reports heads only");
    spec.tensors = Some(&through_encoder);
    spec.evidence = Some(&dishonest);
    spec.manifest = Some(&heads_scope);
    candidates.push((derived(spec), json!({})));
    // C11: a better aggregate with broken guard cases.
    let mut spec = Derive::new("C11a", rid("c11a"), "the genuine blob with honest evidence of a guard harm");
    spec.evidence = Some(&honest_harm);
    candidates.push((derived(spec), json!({})));
    let mut spec = Derive::new("C11c", rid("c11c"), "the genuine blob, the first guard target substituted in the evidence");
    spec.evidence = Some(&substituted_rows);
    candidates.push((derived(spec), json!({})));
    let mut spec = Derive::new("C11d", rid("c11d"), "the genuine blob, the evidence source hashes tampered");
    spec.evidence = Some(&tampered_source_hashes);
    candidates.push((derived(spec), json!({})));
    let mut spec = Derive::new("C11d-seed", rid("c11d-seed"), "the genuine blob, the evidence source names a trainer-chosen seed");
    spec.evidence = Some(&trainer_seed);
    candidates.push((derived(spec), json!({})));
    let mut spec = Derive::new("C11e", rid("c11e"), "the genuine blob under a request the scheduler never allocated");
    spec.allocated = false;
    candidates.push((derived(spec), json!({})));
    let searched = [("C11b", &found.c11b), ("C11f", &found.c11f), ("C11g", &found.c11g)];
    for (role, found) in searched {
        if let Some((tensors, scored)) = found {
            let mut spec = Derive::new(role, rid(&role.to_lowercase()), "found with the real scorers (see the search trace)");
            spec.tensors = Some(tensors);
            candidates.push((derived(spec), scored_json(role, 0.0, 0, scored)));
        }
    }

    // The real rows: C11b, C11f and C11g through the production chain with the real scorers, from the pin, the boundary last.
    for (id, variant, mutation, reason, symbol) in [
        (
            "C11b",
            "the evidence claims a pass, but the recomputed guard fails",
            "the genuine evidence over weights moved back toward the pin",
            "guard_recomputed",
            "GuardGate::prepare (V3Scorer, Rust V3 encoder)",
        ),
        (
            "C11f",
            "reference rows regress beyond the 5% allowance",
            "the genuine candidate with heads noise; real retention violations above the allowance",
            "retention_regressed",
            "RetentionGate::prepare (V3RetentionScorer, Rust V3 encoder)",
        ),
        (
            "C11g",
            "the boundary: exactly the allowance",
            "the genuine candidate with heads noise; real retention violations equal to the allowance",
            "",
            "RetentionGate::prepare (violations <= max_violations)",
        ),
    ] {
        let Some((built, scored)) = candidates.iter().find(|(built, _)| built.role == id) else {
            recorder.not_run(id, "commit", variant, "the real-scorer search found no candidate with this property within the update bound");
            continue;
        };
        let request_id = format!("{}-real", built.request_id);
        world.allocate(&lineage.allocation_for(&request_id));
        let built = lineage.derive(&{
            let mut spec = Derive::new(id, request_id, "real-leg copy");
            let tensors = match id {
                "C11b" => &found.c11b.as_ref().unwrap().0,
                "C11f" => &found.c11f.as_ref().unwrap().0,
                _ => &found.c11g.as_ref().unwrap().0,
            };
            spec.tensors = Some(tensors);
            spec
        });
        world.stage(&built).unwrap();
        let before = world.observe();
        let outcome = Outcome::of_store(world.store.commit(&built.commit(&lineage.pin)));
        let after = world.observe();
        let (met, rejecting_reason) = if id == "C11g" {
            (
                outcome.applied()
                    && after.current == built.manifest_sha
                    && after.served == built.manifest_sha
                    && after.publications == before.publications + 1,
                "accepted by design: a documented limit",
            )
        } else {
            (outcome.rejected(reason) && unchanged(&before, &after), reason)
        };
        let mut extra = json!({"allowance": allowance, "eligible_rows": scored["retention_eligible"]});
        if id == "C11g" {
            extra["label"] = json!("documented limit");
        }
        recorder.row(
            id,
            "in-process store (trainer path; real scorers)",
            "commit",
            variant,
            attempted_of(&built, &lineage.pin, mutation),
            &outcome,
            (if id == "C11b" { GUARD } else { RETENTION }, symbol, rejecting_reason),
            &before,
            &after,
            world.orphan_blobs(),
            met,
            Some(extra),
        );
    }
    recorder.not_run("C8b", "commit", "a run of updates each under the per-update bound until the cumulative cap of 100", C8B_NOT_RUN);

    // Export: weights and manifests with their provenance; the evidence (prompt-bearing) separately; the allocations.
    let mut index = Vec::new();
    let mut allocations = Vec::new();
    for (built, extra) in &candidates {
        std::fs::create_dir_all(inputs.export_candidates.join("blobs")).unwrap();
        std::fs::create_dir_all(inputs.export_candidates.join("manifests")).unwrap();
        std::fs::create_dir_all(&inputs.export_evidence).unwrap();
        let blob_path = inputs.export_candidates.join("blobs").join(format!("{}.safetensors", built.blob_sha));
        if !blob_path.exists() {
            std::fs::write(&blob_path, &built.blob).unwrap();
        }
        std::fs::write(inputs.export_candidates.join("manifests").join(format!("{}.json", built.manifest_sha)), &built.manifest).unwrap();
        std::fs::write(inputs.export_evidence.join(format!("{}.json", built.evidence_sha)), &built.evidence).unwrap();
        if built.allocated {
            let row = if built.role == "genuine" { lineage.allocation.clone() } else { lineage.allocation_for(&built.request_id) };
            allocations.push(allocation_json(&row));
        }
        index.push(built.index(&lineage.pin, extra.clone()));
    }
    // The rollback and the duplicate requests of the genuine sequence need no allocation; C3a's id is named here for the leg.
    let provenance = json!({
        "study": "V3UPDATK 13c-2", "model_id": MODEL, "tier": TIER, "pin": lineage.pin, "original": lineage.original,
        "genuine": {"request_id": genuine.request_id, "manifest_sha": genuine.manifest_sha, "scope": genuine.scope},
        "build": {"branch": var_or("S13C_BUILD_BRANCH", ""), "sha": var_or("S13C_BUILD_SHA", ""), "clean": var_or("S13C_BUILD_CLEAN", "")},
        "inputs": {
            "packages": inputs.packages, "originals": inputs.originals, "retention_root": RealInputs::retention_root(),
            "drift_bounds": RealInputs::drift_bounds(), "bank_sha256": sha256_hex(&std::fs::read(&inputs.bank).unwrap())
        },
        "requests": {"duplicate": rid("c3a-r4"), "rollback": rid("rollback-r2")},
        "candidates": index,
        "wall_seconds": (started.elapsed().as_secs_f64() * 10.0).round() / 10.0
    });
    write_json(&inputs.export_candidates.join("index.json"), &provenance);
    write_json(&inputs.export_candidates.join("allocations.json"), &Json::Array(allocations.clone()));
    assert!(parse_allocations(&Json::Array(allocations).to_string()).is_ok(), "the exported allocations are in the 13c-1 format");
    write_json(&inputs.export_candidates.join("real-leg.json"), &summary);
    recorder.write(inputs.out.as_deref(), "s13c_update_attacks_real.rows.json");
    if let Some(out) = inputs.out.as_deref() {
        write_json(&out.join("real-leg.json"), &summary);
    }
    recorder.verdict();
}

// ---------------------------------------------------------------------------------------------------------------------------
// The journal seed: `S13C_ALLOCATIONS` into the scheduler journal, with `Journal::allocate`, while param-update is stopped.
// ---------------------------------------------------------------------------------------------------------------------------

#[test]
fn s13c_journal_seed() {
    let (Some(journal), Some(allocations)) = (path_var("S13C_JOURNAL"), var("S13C_ALLOCATIONS")) else {
        say("PENDING: set S13C_JOURNAL and S13C_ALLOCATIONS (a JSON array, or a path to one) to seed the scheduler journal");
        return;
    };
    let text = if allocations.trim_start().starts_with('[') { allocations } else { std::fs::read_to_string(&allocations).unwrap() };
    let rows = parse_allocations(&text).unwrap_or_else(|error| panic!("S13C_ALLOCATIONS: {error}"));
    let mut handle = Journal::open(&journal).unwrap();
    for row in &rows {
        handle.allocate(row).unwrap();
    }
    let reader = JournalAllocations::new(&journal);
    for row in &rows {
        let read = privoke_param_update::v3_guard::Allocations::allocation(&reader, &row.request_id, &row.model_id);
        assert_eq!(read.map(|found| found.expected_base), Some(row.expected_base.clone()), "{}", row.request_id);
    }
    say(&format!("SEEDED {} allocations into {}", rows.len(), journal.display()));
}

// ---------------------------------------------------------------------------------------------------------------------------
// The test PKI of the Compose stack (`PRIVOKE_PKI_DIR` of docker-compose.prod.yml) and the test principals.
// ---------------------------------------------------------------------------------------------------------------------------

#[test]
fn s13c_compose_pki() {
    let Some(directory) = path_var("S13C_PKI_DIR") else {
        say("PENDING: set S13C_PKI_DIR to write a disposable test PKI for the Compose stack");
        return;
    };
    assert!(!directory.join("server-ca.pem").exists(), "{} already holds a PKI", directory.display());
    let validity = Validity::days(7);
    let client_ca = CaDir::init(&directory.join("ca/client"), "S13c2 Test Client CA", validity).unwrap();
    let server_ca = CaDir::init(&directory.join("ca/server"), "S13c2 Test Server CA", validity).unwrap();
    let names: Vec<String> =
        ["localhost", "127.0.0.1", "model-streaming-service", "telemetry-service", "param-update-service", "v3-fuzzer", "v3-runtime"]
            .iter()
            .map(|name| (*name).to_string())
            .collect();
    let server = server_ca.issue_server(&names, validity).unwrap();
    write_atomic(&directory.join("server/server.crt"), server.cert_pem.as_bytes(), false).unwrap();
    write_atomic(&directory.join("server/server.key"), server.key_pem.as_bytes(), false).unwrap();
    std::fs::copy(directory.join("ca/client/ca.crt"), directory.join("client-ca.pem")).unwrap();
    std::fs::copy(directory.join("ca/server/ca.crt"), directory.join("server-ca.pem")).unwrap();
    let registry = directory.join("live/registry.toml");
    std::fs::create_dir_all(directory.join("live")).unwrap();
    registry_edit::set_reporter(&registry, true).unwrap();
    for (name, role, folder) in [
        ("probe", "runtime", "svc"),
        ("param-update", "publisher", "svc"),
        ("v3-fuzzer", "trainer", "svc"),
        ("v3-runtime", "runtime", "svc"),
        ("s13c2-trainer", "trainer", "test"),
        ("s13c2-publisher", "publisher", "test"),
    ] {
        let issued = client_ca.issue_service(name, validity).unwrap();
        write_atomic(&directory.join(folder).join(format!("{name}.crt")), issued.cert_pem.as_bytes(), false).unwrap();
        write_atomic(&directory.join(folder).join(format!("{name}.key")), issued.key_pem.as_bytes(), false).unwrap();
        registry_edit::add_service(&registry, name, role, issued.not_after).unwrap();
    }
    let installation = directory.join("test/installation");
    std::fs::create_dir_all(&installation).unwrap();
    let enrolled = enrolment::enrol(&installation).unwrap();
    let csr = std::fs::read_to_string(&enrolled.csr_path).unwrap();
    let signed = client_ca.sign_installation(&csr, &enrolled.installation, validity).unwrap();
    write_atomic(&installation.join("client.crt"), signed.cert_pem.as_bytes(), false).unwrap();
    registry_edit::add_installation(&registry, &enrolled.installation, Some("s13c2-consumer"), signed.not_after).unwrap();
    let crl = client_ca.crl_pem(time::OffsetDateTime::now_utc(), time::Duration::days(7)).unwrap();
    write_atomic(&directory.join("live/crl.pem"), crl.as_bytes(), false).unwrap();
    // The publication key of the test stack: a fresh random Ed25519 seed (never the production key), as 64 hexadecimal characters.
    let material: Vec<u8> = uuid::Uuid::new_v4().as_bytes().iter().chain(uuid::Uuid::new_v4().as_bytes()).copied().collect();
    write_atomic(
        &directory.join("v3-publication.key"),
        material.iter().map(|byte| format!("{byte:02x}")).collect::<String>().as_bytes(),
        false,
    )
    .unwrap();
    let public = privoke_contracts::publication::public_key(&material.try_into().unwrap()).unwrap();
    std::fs::write(directory.join("v3-publication.pub"), public.iter().map(|byte| format!("{byte:02x}")).collect::<String>()).unwrap();
    say(&format!("PKI written to {} (installation {})", directory.display(), enrolled.installation));
}

// ---------------------------------------------------------------------------------------------------------------------------
// The container leg.
// ---------------------------------------------------------------------------------------------------------------------------

/// The Compose stack as the leg reaches it.
struct Stack {
    endpoint: String,
    model_endpoint: String,
    pki: PathBuf,
    server_name: String,
    store: PathBuf,
    installation: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Who {
    Trainer,
    Publisher,
}

impl Who {
    fn identity(self) -> &'static str {
        match self {
            Self::Trainer => "s13c2-trainer (trainer)",
            Self::Publisher => "s13c2-publisher (publisher)",
        }
    }
}

impl Stack {
    fn tls(&self, cert: PathBuf, key: PathBuf) -> ClientTlsConfig {
        ClientTlsConfig { server_ca: self.pki.join("server-ca.pem"), identity: Some((cert, key)), server_name: self.server_name.clone() }
    }

    async fn checkpoint(&self, who: Who) -> CheckpointServiceClient<Channel> {
        let name = if who == Who::Trainer { "s13c2-trainer" } else { "s13c2-publisher" };
        let config = self.tls(self.pki.join(format!("test/{name}.crt")), self.pki.join(format!("test/{name}.key")));
        let channel = privoke_transport::client::connect(&self.endpoint, &config).await.expect("connect to param-update");
        CheckpointServiceClient::new(channel).max_decoding_message_size(4 * 1024 * 1024)
    }

    async fn served(&self) -> String {
        let config = self.tls(self.pki.join("test/installation/client.crt"), self.pki.join("test/installation/client.key"));
        let channel = match privoke_transport::client::connect(&self.model_endpoint, &config).await {
            Ok(channel) => channel,
            Err(error) => return format!("refused:connect {error}"),
        };
        let mut client = ModelStreamingServiceClient::new(channel);
        let request = ModelParametersRequest { consumer_id: self.installation.clone(), model_id: MODEL.to_string() };
        match client.get_model_package(request).await {
            Ok(response) => response.into_inner().manifest_sha256,
            Err(status) => format!("refused:{}", grpc_name(status.code())),
        }
    }

    fn catalog(&self) -> rusqlite::Connection {
        rusqlite::Connection::open_with_flags(self.store.join("catalog.sqlite"), rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap()
    }

    /// The authority, read from the store's catalog, and the version model-streaming serves.
    async fn observe(&self) -> Auth {
        let (current, versions, publications, max_sequence) = {
            let db = self.catalog();
            let current: String = db.query_row("SELECT manifest FROM current WHERE model=?1", [MODEL], |row| row.get(0)).unwrap();
            let versions: i64 = db.query_row("SELECT COUNT(*) FROM versions WHERE model=?1", [MODEL], |row| row.get(0)).unwrap();
            let (publications, max_sequence): (i64, Option<i64>) = db
                .query_row("SELECT COUNT(*), MAX(sequence) FROM publications WHERE model=?1", [MODEL], |row| Ok((row.get(0)?, row.get(1)?)))
                .unwrap();
            (current, versions, publications, max_sequence)
        };
        Auth {
            current,
            versions: usize::try_from(versions).unwrap(),
            publications: usize::try_from(publications).unwrap(),
            max_sequence: u64::try_from(max_sequence.unwrap_or(0)).unwrap(),
            served: self.served().await,
        }
    }

    fn history(&self) -> Vec<String> {
        let db = self.catalog();
        let mut statement = db.prepare("SELECT manifest FROM versions WHERE model=?1").unwrap();
        statement.query_map([MODEL], |row| row.get::<_, String>(0)).unwrap().map(Result::unwrap).collect()
    }

    fn orphan_blobs(&self) -> usize {
        orphans(&self.store, &self.history(), |sha| {
            serde_json::from_slice(&std::fs::read(self.store.join("blobs").join(sha)).unwrap()).unwrap()
        })
    }

    async fn upload(&self, data: &[u8], manifest: &[u8]) -> Result<String, Status> {
        let mut client = self.checkpoint(Who::Trainer).await;
        Ok(client.stage_checkpoint(tokio_stream::iter(chunks(data, manifest))).await?.into_inner().sha256)
    }

    async fn stage(&self, built: &Built) -> Result<(), Status> {
        self.upload(&built.evidence, b"").await?;
        self.upload(&built.blob, &built.manifest).await?;
        Ok(())
    }

    async fn commit(&self, commit: Commit) -> Result<Receipt, Status> {
        Ok(self.checkpoint(Who::Trainer).await.commit_candidate(commit).await?.into_inner())
    }

    async fn rollback(&self, request_id: &str, manifest: &str) -> Result<Receipt, Status> {
        let request = Rollback { request_id: request_id.to_string(), model_id: MODEL.to_string(), manifest: manifest.to_string() };
        Ok(self.checkpoint(Who::Publisher).await.rollback_model(request).await?.into_inner())
    }

    async fn status(&self, request_id: &str) -> Receipt {
        self.checkpoint(Who::Trainer)
            .await
            .get_commit_status(StatusRequest { request_id: request_id.to_string() })
            .await
            .unwrap()
            .into_inner()
    }
}

/// The exported candidates, read back.
fn load_candidates(models: &Path, evidence: &Path) -> (Json, BTreeMap<String, Built>) {
    let index = read_json(&models.join("index.json"));
    let mut built = BTreeMap::new();
    for entry in index["candidates"].as_array().unwrap() {
        let text = |key: &str| entry[key].as_str().unwrap().to_string();
        let manifest = std::fs::read(models.join("manifests").join(format!("{}.json", text("manifest_sha")))).unwrap();
        let blob = std::fs::read(models.join("blobs").join(format!("{}.safetensors", text("blob_sha")))).unwrap();
        let proof = std::fs::read(evidence.join(format!("{}.json", text("evidence_sha")))).unwrap();
        assert_eq!(
            (sha256_hex(&manifest), sha256_hex(&blob), sha256_hex(&proof)),
            (text("manifest_sha"), text("blob_sha"), text("evidence_sha"))
        );
        built.insert(
            text("role"),
            Built {
                role: text("role"),
                request_id: text("request_id"),
                scope: text("scope"),
                manifest,
                manifest_sha: text("manifest_sha"),
                blob,
                blob_sha: text("blob_sha"),
                evidence: proof,
                evidence_sha: text("evidence_sha"),
                allocated: entry["allocated"] == true,
                note: text("note"),
            },
        );
    }
    (index, built)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s13c_container_leg() {
    let (Some(endpoint), Some(model_endpoint), Some(pki), Some(store), Some(models), Some(evidence), Some(originals)) = (
        var("S13C_ENDPOINT"),
        var("S13C_MODEL_ENDPOINT"),
        path_var("S13C_PKI_DIR"),
        path_var("S13C_STORE_DIR"),
        path_var("S13C_EXPORT_CANDIDATES"),
        path_var("S13C_EXPORT_EVIDENCE"),
        path_var("PRIVOKE_V3_S13C_ORIGINALS"),
    ) else {
        say(
            "PENDING: set S13C_ENDPOINT, S13C_MODEL_ENDPOINT, S13C_PKI_DIR, S13C_STORE_DIR, S13C_EXPORT_* and _ORIGINALS for the container leg",
        );
        return;
    };
    let installation = std::fs::read_to_string(pki.join("test/installation/installation.id")).unwrap().trim().to_string();
    let stack = Stack { endpoint, model_endpoint, pki, server_name: var_or("S13C_TLS_SERVER_NAME", "localhost"), store, installation };
    let out = path_var("S13C_OUT");
    let (index, candidates) = load_candidates(&models, &evidence);
    let pin = index["pin"].as_str().unwrap().to_string();
    let original = index["original"].as_str().unwrap().to_string();
    let get = |role: &str| candidates.get(role).unwrap_or_else(|| panic!("no exported candidate {role}")).clone();
    let mut recorder = Recorder::new("container");
    let trainer = Who::Trainer.identity();

    // The stack starts on the pin, served as the pinned release.
    let start = stack.observe().await;
    assert_eq!(
        (start.current.as_str(), start.publications, start.served.as_str()),
        (pin.as_str(), 0, pin.as_str()),
        "a fresh stack on the pin"
    );

    // 1. The positive control: the genuine candidate G as r1 on the pin is applied, signed and served.
    let genuine = get("genuine");
    stack.stage(&genuine).await.unwrap();
    let before = stack.observe().await;
    let control = Outcome::of(stack.commit(genuine.commit(&pin)).await);
    let applied = stack.observe().await;
    let control_met = control.applied()
        && applied.current == genuine.manifest_sha
        && applied.served == genuine.manifest_sha
        && applied.publications == before.publications + 1;
    say(&format!("CONTROL genuine {}: {:?} {applied:?}", genuine.request_id, control));
    if !control_met {
        if let Some(out) = out.as_deref() {
            write_json(
                &out.join("container-controls.json"),
                &json!([{"control": "publisher commit applied", "request_id": genuine.request_id, "observed": control.json(), "active_before": before.json(), "active_after": applied.json(), "met": false}]),
            );
        }
        panic!("GENUINE CANDIDATE FAILED in the container: the positive control was not applied: {control:?} {applied:?}");
    }
    let mut controls = vec![json!({
        "control": "publisher commit applied", "request_id": genuine.request_id, "observed": control.json(),
        "active_before": before.json(), "active_after": applied.json(), "met": control_met
    })];

    // 2. C3a: G again under a new request id, with G's own evidence (which names r1).
    let duplicate_id = index["requests"]["duplicate"].as_str().unwrap().to_string();
    let before = stack.observe().await;
    let outcome = Outcome::of(stack.commit(Commit { request_id: duplicate_id.clone(), ..genuine.commit(&pin) }).await);
    let after = stack.observe().await;
    let no_receipt = stack.status(&duplicate_id).await.status == "unknown";
    let message = "Commit identity differs from candidate/fit evidence.";
    recorder.row(
        "C3a",
        trainer,
        "commit",
        "a candidate that is already current is committed again under a new request id",
        attempted(&duplicate_id, &pin, &genuine.manifest_sha, "the current genuine candidate under a new request id"),
        &outcome,
        (STORE, "commit identity check", message),
        &before,
        &after,
        stack.orphan_blobs(),
        outcome.refused(Code::InvalidArgument, message) && no_receipt && unchanged(&before, &after),
        None,
    );

    // 3. C1a: G's blob with evidence naming r3, on the pin, after G was applied: stale_base from the compare-and-swap.
    let stale = get("C1a");
    stack.stage(&stale).await.unwrap();
    let before = stack.observe().await;
    let outcome = Outcome::of(stack.commit(stale.commit(&pin)).await);
    let after = stack.observe().await;
    recorder.row(
        "C1a",
        trainer,
        "commit",
        "the candidate's parent was current, then another candidate on the same base was applied",
        attempted_of(
            &stale,
            &pin,
            "the genuine blob re-staged with evidence naming another request, on the pin, after the genuine candidate was applied",
        ),
        &outcome,
        (STORE, "commit compare-and-swap", "stale_base"),
        &before,
        &after,
        stack.orphan_blobs(),
        outcome.rejected("stale_base") && unchanged(&before, &after),
        None,
    );

    // C2b: the request id r1 with different content.
    let before = stack.observe().await;
    let reused = Commit { candidate: stale.manifest_sha.clone(), evidence: stale.evidence_sha.clone(), ..genuine.commit(&pin) };
    let outcome = Outcome::of(stack.commit(reused).await);
    let after = stack.observe().await;
    let message = "Request ID reused with different commit content.";
    recorder.row(
        "C2b",
        trainer,
        "commit",
        "the same request id with different content",
        attempted(&genuine.request_id, &pin, &stale.manifest_sha, "the genuine request id naming another candidate and evidence"),
        &outcome,
        (STORE, "replayed", message),
        &before,
        &after,
        stack.orphan_blobs(),
        outcome.refused(Code::InvalidArgument, message) && unchanged(&before, &after),
        None,
    );

    // C3b: the same candidate staged twice is idempotent.
    let before = stack.observe().await;
    let blobs = std::fs::read_dir(stack.store.join("blobs")).unwrap().count();
    let outcome = Outcome::of_stage(stack.upload(&stale.blob, &stale.manifest).await);
    let after = stack.observe().await;
    let same_blobs = std::fs::read_dir(stack.store.join("blobs")).unwrap().count() == blobs;
    recorder.row(
        "C3b",
        trainer,
        "stage",
        "the same candidate is staged twice",
        attempted_of(&stale, &pin, "the same blob and manifest uploaded again"),
        &outcome,
        (STORE, "put (content addressed)", "the second stage is idempotent"),
        &before,
        &after,
        stack.orphan_blobs(),
        outcome.code == Code::Ok && same_blobs && unchanged(&before, &after),
        None,
    );

    // C1c: a rollback to a manifest that was never committed for the model (the staged, rejected C1a candidate).
    let before = stack.observe().await;
    let rollback_id = format!("{}-c1c", index["requests"]["rollback"].as_str().unwrap());
    let outcome = Outcome::of(stack.rollback(&rollback_id, &stale.manifest_sha).await);
    let after = stack.observe().await;
    let message = "Rollback target is not in the history of this model.";
    recorder.row(
        "C1c",
        Who::Publisher.identity(),
        "rollback",
        "a rollback to a manifest that was never committed for the model",
        attempted(&rollback_id, &pin, &stale.manifest_sha, "RollbackModel to a staged, never applied manifest"),
        &outcome,
        (STORE, "rollback", message),
        &before,
        &after,
        stack.orphan_blobs(),
        outcome.refused(Code::InvalidArgument, message) && unchanged(&before, &after),
        None,
    );

    // 4. The rollback control (the later update): RollbackModel to the pin as publisher.
    let rollback_id = index["requests"]["rollback"].as_str().unwrap().to_string();
    let before = stack.observe().await;
    let rolled = Outcome::of(stack.rollback(&rollback_id, &pin).await);
    let after = stack.observe().await;
    let rollback_met = rolled.code == Code::Ok
        && rolled.status == "applied"
        && rolled.reason == "rollback"
        && after.current == pin
        && after.max_sequence == before.max_sequence + 1
        && after.served == pin;
    assert!(rollback_met, "the rollback control failed: {rolled:?} {after:?}");
    controls.push(json!({
        "control": "rollback to the pin applied", "request_id": rollback_id, "observed": rolled.json(),
        "active_before": before.json(), "active_after": after.json(), "met": rollback_met
    }));

    // 5. C2a: the exact r1 commit again; the stored receipt answers and nothing is swapped.
    let before = stack.observe().await;
    let outcome = Outcome::of(stack.commit(genuine.commit(&pin)).await);
    let after = stack.observe().await;
    recorder.row(
        "C2a",
        trainer,
        "commit",
        "the same request id and content after a later update",
        attempted_of(&genuine, &pin, "the exact genuine commit, resent after the rollback to the pin"),
        &outcome,
        (STORE, "replay / replayed", "returns the stored receipt (receipt_status applied)"),
        &before,
        &after,
        stack.orphan_blobs(),
        outcome.applied() && unchanged(&before, &after) && after.current == pin,
        Some(json!({"receipt_status_stored": "applied"})),
    );

    // 6a. Refusals while staging (classes 4 to 9), from the pin.
    let staging = |id: &'static str,
                   variant: &'static str,
                   mutation: &'static str,
                   built: Built,
                   file: &'static str,
                   symbol: &'static str,
                   message: &'static str| { (id, variant, mutation, built, file, symbol, message) };
    let rows = vec![
        staging(
            "C4b",
            "the manifest model_id, tier, config or vocab differs from the parent",
            "a balanced-tier manifest whose parent is the efficient pin",
            get("C4b"),
            STORE,
            "admit_candidate",
            "Candidate changed immutable model provenance/config.",
        ),
        staging(
            "C4c",
            "a wrong original",
            "the original field names another manifest",
            get("C4c"),
            STORE,
            "admit_candidate",
            "Candidate ORIGINAL binding mismatch.",
        ),
        staging(
            "C5a",
            "a tensor renamed in both the manifest and the blob",
            "a heads tensor renamed everywhere",
            get("C5a"),
            STORE,
            "admit_candidate",
            "Candidate changed admitted tensor inventory.",
        ),
        staging(
            "C5b",
            "the manifest inventory differs from the blob",
            "a heads tensor renamed in the blob only",
            get("C5b"),
            STORE,
            "verify_checkpoint",
            "Safetensors inventory differs from manifest.",
        ),
        staging(
            "C6a",
            "the shape changed in both the manifest and the blob",
            "a heads tensor flattened everywhere",
            get("C6a"),
            STORE,
            "admit_candidate",
            "Candidate changed admitted tensor inventory.",
        ),
        staging(
            "C6b",
            "the shape changed only in the blob",
            "a heads tensor flattened in the blob only",
            get("C6b"),
            STORE,
            "verify_checkpoint",
            "Safetensors inventory differs from manifest.",
        ),
        staging(
            "C7a",
            "NaN in one heads coordinate",
            "NaN in one heads coordinate",
            get("C7a"),
            SAFETENSORS,
            "finite check, called from verify_checkpoint",
            "Snapshot tensors must be finite float32.",
        ),
        staging(
            "C7b",
            "+Inf in one heads coordinate",
            "+Inf in one heads coordinate",
            get("C7b"),
            SAFETENSORS,
            "finite check, called from verify_checkpoint",
            "Snapshot tensors must be finite float32.",
        ),
        staging(
            "C7c",
            "-Inf in one heads coordinate",
            "-Inf in one heads coordinate",
            get("C7c"),
            SAFETENSORS,
            "finite check, called from verify_checkpoint",
            "Snapshot tensors must be finite float32.",
        ),
        staging(
            "C8d",
            "the same with dishonest changed_tensors and changes",
            "scope heads, encoder tensors changed, the evidence reports heads only",
            get("C8d"),
            STORE,
            "admit_candidate",
            "Reported changes differ from actual checkpoint tensors.",
        ),
    ];
    for (id, variant, mutation, built, file, symbol, message) in rows {
        let before = stack.observe().await;
        let evidence_outcome = Outcome::of_stage(stack.upload(&built.evidence, b"").await);
        let outcome = Outcome::of_stage(stack.upload(&built.blob, &built.manifest).await);
        let after = stack.observe().await;
        recorder.row(
            id,
            trainer,
            "stage",
            variant,
            attempted_of(&built, &pin, mutation),
            &outcome,
            (file, symbol, message),
            &before,
            &after,
            stack.orphan_blobs(),
            evidence_outcome.code == Code::Ok && outcome.refused(Code::InvalidArgument, message) && unchanged(&before, &after),
            None,
        );
    }

    // C4e: the ORIGINAL's own manifest and checkpoint offered as a candidate.
    let original_manifest = std::fs::read(originals.join(TIER).join("manifest.json")).unwrap();
    let original_blob = std::fs::read(originals.join(TIER).join("model.safetensors")).unwrap();
    assert_eq!(sha256_hex(&original_manifest), original);
    let before = stack.observe().await;
    let outcome = Outcome::of_stage(stack.upload(&original_blob, &original_manifest).await);
    let after = stack.observe().await;
    let message = "Candidates cannot claim ORIGINAL scope.";
    recorder.row(
        "C4e",
        trainer,
        "stage",
        "scope original",
        attempted("s13c2-c4e", &pin, &original, "the ORIGINAL manifest staged as a candidate"),
        &outcome,
        (STORE, "admit_candidate", message),
        &before,
        &after,
        stack.orphan_blobs(),
        outcome.refused(Code::InvalidArgument, message) && unchanged(&before, &after),
        None,
    );

    // C8c: a HEADS candidate that changes encoder bytes, with honest evidence: refused when the evidence is staged.
    let built = get("C8c");
    let before = stack.observe().await;
    let outcome = Outcome::of_stage(stack.upload(&built.evidence, b"").await);
    let after = stack.observe().await;
    let message = "HEADS changed pretrained encoder.";
    recorder.row(
        "C8c",
        trainer,
        "stage",
        "a HEADS candidate that changes encoder bytes, with honest evidence",
        attempted_of(&built, &pin, "scope heads, encoder tensors changed, the evidence reports it"),
        &outcome,
        (CONTRACT, "validate_execution", message),
        &before,
        &after,
        stack.orphan_blobs(),
        outcome.refused(Code::InvalidArgument, message) && unchanged(&before, &after),
        None,
    );

    // C9a to C9c: faulty upload streams of an admitted candidate's blob.
    let source = get("C4a");
    let sha = sha256_hex(&source.blob);
    let total = source.blob.len() as u64;
    let part = |sha: &str, offset: usize, length: usize| Chunk {
        sha256: sha.to_string(),
        offset: offset as u64,
        total_bytes: total,
        data: source.blob[offset..offset + length].to_vec(),
        manifest_json: Vec::new(),
    };
    let (invalid, corrupt) = ("Invalid bounded ordered checkpoint upload.", "Incomplete/corrupt checkpoint upload.");
    let streams: Vec<(&str, &str, &str, Vec<Chunk>, &str)> = vec![
        ("C9a", "the stream ends early", "one chunk of a longer declared blob", vec![part(&sha, 0, CHUNK_BYTES)], corrupt),
        (
            "C9b",
            "an offset gap",
            "the second chunk starts one chunk too late",
            vec![part(&sha, 0, CHUNK_BYTES), part(&sha, 2 * CHUNK_BYTES, CHUNK_BYTES)],
            invalid,
        ),
        (
            "C9c",
            "the declared sha256 differs from the bytes",
            "the declared digest names other bytes",
            chunks(&source.blob, b"").into_iter().map(|chunk| Chunk { sha256: sha256_hex(b"other bytes"), ..chunk }).collect(),
            corrupt,
        ),
    ];
    for (id, variant, mutation, stream, message) in streams {
        let before = stack.observe().await;
        let mut client = stack.checkpoint(Who::Trainer).await;
        let outcome = Outcome::of_stage(client.stage_checkpoint(tokio_stream::iter(stream)).await.map(|reply| reply.into_inner().sha256));
        let after = stack.observe().await;
        recorder.row(
            id,
            trainer,
            "stage",
            variant,
            attempted_of(&source, &pin, mutation),
            &outcome,
            (SERVICE, "stage_checkpoint", message),
            &before,
            &after,
            stack.orphan_blobs(),
            outcome.refused(Code::InvalidArgument, message) && unchanged(&before, &after),
            None,
        );
    }
    // C9d: the manifest of one candidate with the checkpoint of another.
    let other = get("C8a");
    let before = stack.observe().await;
    let outcome = Outcome::of_stage(stack.upload(&other.blob, &source.manifest).await);
    let after = stack.observe().await;
    let message = "Candidate snapshot identity mismatch.";
    recorder.row(
        "C9d",
        trainer,
        "stage",
        "the manifest blob differs from the uploaded bytes",
        attempted_of(&source, &pin, "the manifest of one candidate with the checkpoint of another"),
        &outcome,
        (STORE, "stage", message),
        &before,
        &after,
        stack.orphan_blobs(),
        outcome.refused(Code::InvalidArgument, message) && unchanged(&before, &after),
        None,
    );

    // C4a and C4d: an admitted candidate whose commit names another model or another base.
    for (id, variant, mutation) in [
        ("C4a", "Commit.model_id differs from the manifest", "the commit names privoke-v3-balanced"),
        ("C4d", "expected_base differs from the manifest's parent", "the commit's expected base is the ORIGINAL"),
    ] {
        let built = get(id);
        stack.stage(&built).await.unwrap();
        let mut commit = built.commit(&pin);
        if id == "C4a" {
            commit.model_id = "privoke-v3-balanced".to_string();
        } else {
            commit.expected_base = original.clone();
        }
        let before = stack.observe().await;
        let outcome = Outcome::of(stack.commit(commit).await);
        let after = stack.observe().await;
        let message = "Commit identity differs from candidate/fit evidence.";
        recorder.row(
            id,
            trainer,
            "commit",
            variant,
            attempted_of(&built, &pin, mutation),
            &outcome,
            (STORE, "commit identity check", message),
            &before,
            &after,
            stack.orphan_blobs(),
            outcome.refused(Code::InvalidArgument, message) && unchanged(&before, &after),
            None,
        );
    }

    // 6b. The late-gate mutations of G from the pin: C8a and class 11, the boundary last.
    recorder.not_run("C8b", "commit", "a run of updates each under the per-update bound until the cumulative cap of 100", C8B_NOT_RUN);
    let late: Vec<(&str, &str, &str, &str, &str, &str)> = vec![
        (
            "C8a",
            "one update above max_update_l2",
            "the genuine candidate moved beyond the bound on its heads",
            "drift_exceeded",
            POLICY,
            "DriftGate::prepare",
        ),
        (
            "C11a",
            "honest evidence of a guard harm",
            "the genuine blob with evidence whose candidate guard blocks a row that should allow",
            "guard_rejected",
            STORE,
            "commit via v3::publication_passes",
        ),
        (
            "C11b",
            "the evidence claims a pass, but the recomputed guard fails",
            "the genuine evidence over weights moved back toward the pin",
            "guard_recomputed",
            GUARD,
            "GuardGate::prepare (V3Scorer, Rust V3 encoder)",
        ),
        ("C11e", "an unallocated request id", "no allocation exists for the request", "request_not_allocated", GUARD, "GuardGate::prepare"),
        (
            "C11f",
            "reference rows regress beyond the 5% allowance",
            "the genuine candidate with heads noise; real retention violations above the allowance",
            "retention_regressed",
            RETENTION,
            "RetentionGate::prepare (V3RetentionScorer, Rust V3 encoder)",
        ),
    ];
    for (id, variant, mutation, reason, file, symbol) in late {
        let Some(built) = candidates.get(id).cloned() else {
            recorder.not_run(id, "commit", variant, "the real-weight leg exported no candidate for this row (see its search trace)");
            continue;
        };
        stack.stage(&built).await.unwrap();
        let before = stack.observe().await;
        let outcome = Outcome::of(stack.commit(built.commit(&pin)).await);
        let after = stack.observe().await;
        recorder.row(
            id,
            trainer,
            "commit",
            variant,
            attempted_of(&built, &pin, mutation),
            &outcome,
            (file, symbol, reason),
            &before,
            &after,
            stack.orphan_blobs(),
            outcome.rejected(reason) && unchanged(&before, &after),
            None,
        );
    }
    // C11c and C11d: in production the admission source validation refuses them at stage (the CI rows reach GuardGate only because
    // CI stubs that validation); recorded here at the check that fired.
    for (id, variant, mutation, message, file, symbol) in [
        (
            "C11c",
            "substituted guard rows",
            "the first guard target of the evidence differs from the dispatched row",
            "Execution guard targets differ from dispatched pinned source.",
            EVIDENCE,
            "guard_targets (admission source validation)",
        ),
        (
            "C11d",
            "a trainer-chosen source or seed",
            "the evidence source hashes are tampered",
            "Execution source bytes differ from fit commitment.",
            CURRICULUM,
            "validate_source_evidence (admission source validation)",
        ),
    ] {
        let built = get(id);
        let before = stack.observe().await;
        let outcome = Outcome::of_stage(stack.upload(&built.evidence, b"").await);
        let staged =
            if outcome.code == Code::Ok { Outcome::of_stage(stack.upload(&built.blob, &built.manifest).await) } else { outcome.clone() };
        let after = stack.observe().await;
        let mut extra = json!({"label": "defence in depth: production refuses this at stage (admission source validation); the CI row reaches GuardGate"});
        if id == "C11d" {
            let seeded = get("C11d-seed");
            let seed_outcome = Outcome::of_stage(stack.upload(&seeded.evidence, b"").await);
            let seed_staged = if seed_outcome.code == Code::Ok {
                Outcome::of_stage(stack.upload(&seeded.blob, &seeded.manifest).await)
            } else {
                seed_outcome
            };
            extra["label"] = json!(format!(
                "defence in depth: production refuses this at stage (admission source validation); the seed-only variant answered {} {}",
                grpc_name(seed_staged.code),
                seed_staged.message
            ));
        }
        recorder.row(
            id,
            trainer,
            "stage",
            variant,
            attempted_of(&built, &pin, mutation),
            &staged,
            (file, symbol, message),
            &before,
            &after,
            stack.orphan_blobs(),
            staged.refused(Code::InvalidArgument, message) && unchanged(&before, &after),
            Some(extra),
        );
    }
    // C11g: exactly the allowance is applied, by design (a documented limit).
    match candidates.get("C11g").cloned() {
        None => recorder.not_run(
            "C11g",
            "commit",
            "the boundary: exactly the allowance",
            "the real-weight leg exported no candidate for this row (see its search trace)",
        ),
        Some(built) => {
            stack.stage(&built).await.unwrap();
            let before = stack.observe().await;
            let outcome = Outcome::of(stack.commit(built.commit(&pin)).await);
            let after = stack.observe().await;
            recorder.row(
                "C11g",
                trainer,
                "commit",
                "the boundary: exactly the allowance",
                attempted_of(&built, &pin, "the genuine candidate with heads noise; real retention violations equal to the allowance"),
                &outcome,
                (RETENTION, "RetentionGate::prepare (violations <= max_violations)", "accepted by design: a documented limit"),
                &before,
                &after,
                stack.orphan_blobs(),
                outcome.applied()
                    && after.current == built.manifest_sha
                    && after.served == built.manifest_sha
                    && after.publications == before.publications + 1,
                Some(json!({"label": "documented limit"})),
            );
        }
    }

    recorder.write(out.as_deref(), "s13c_update_attacks_container.rows.json");
    if let Some(out) = out.as_deref() {
        write_json(&out.join("container-controls.json"), &Json::Array(controls));
    }
    recorder.verdict();
}

// ---------------------------------------------------------------------------------------------------------------------------
// CI checks of the helpers the legs rely on.
// ---------------------------------------------------------------------------------------------------------------------------

#[test]
fn the_serializer_round_trips_and_the_digests_are_the_raw_tensor_bytes() {
    let mut tensors = Tensors::new();
    tensors.insert("heads.b".to_string(), tensor(vec![3], vec![0.5, -1.0, 2.0]));
    tensors.insert("encoder.w".to_string(), tensor(vec![2, 2], vec![1.0, 2.0, 3.0, 4.0]));
    let parsed = safetensors::parse(&serialize(&tensors)).unwrap();
    assert_eq!(parsed.keys().collect::<Vec<_>>(), tensors.keys().collect::<Vec<_>>());
    for (name, item) in &tensors {
        assert_eq!((&parsed[name].shape, &parsed[name].data, &parsed[name].sha256), (&item.shape, &item.data, &item.sha256), "{name}");
    }
    assert_eq!((other_shape(&[5]), other_shape(&[2, 3])), (vec![1, 5], vec![6]), "a vector becomes a row, a matrix is flattened");
    let step = direction(&tensors, &["heads.b".to_string()], 3);
    let norm: f64 = step["heads.b"].iter().map(|value| f64::from(*value).powi(2)).sum::<f64>().sqrt();
    assert!((norm - 1.0).abs() < 1e-5, "a unit direction: {norm}");
    let moved_tensors = moved(&tensors, &step, 2.0);
    assert!((l2(&moved_tensors, &tensors) - 2.0).abs() < 1e-4);
    assert_eq!(changed_names(&tensors, &moved_tensors), vec!["heads.b".to_string()]);
    assert_eq!(changed_names(&tensors, &toward(&tensors, &moved_tensors, &["heads.b".to_string()], 0.5)), vec!["heads.b".to_string()]);
}

#[test]
fn the_guard_edits_keep_the_evidence_consistent() {
    let row = |target: u64, prediction: u64| {
        let mut row = json!({"target": target, "prediction": prediction, "confidence": 0.999});
        set_action(&mut row, "prediction", "action", 0.999);
        set_action(&mut row, "target", "target_action", 0.999);
        rejoin(&mut row);
        row
    };
    let allow = (0..64u16).find(|packed| action_value(*packed, Some(0.999)) == 0).map(u64::from).unwrap();
    let mut evidence = json!({
        "base_guard": {"rows": [row(allow, allow), row(12, 12)]},
        "candidate_guard": {"rows": [row(allow, allow), row(12, 12)]},
        "action_harms": 0
    });
    recount(&mut evidence["base_guard"]);
    recount(&mut evidence["candidate_guard"]);
    let mut harmed = evidence.clone();
    honest_harm(&mut harmed);
    assert_eq!(harmed["candidate_guard"]["rows"][0]["action"], "BLOCK");
    assert!(harmed["action_harms"].as_u64().unwrap() >= 1, "{harmed}");
    let mut substituted = evidence.clone();
    substituted_rows(&mut substituted);
    assert_ne!(substituted["base_guard"]["rows"][0]["target"], evidence["base_guard"]["rows"][0]["target"]);
    assert_eq!(substituted["base_guard"]["rows"][0]["target"], substituted["candidate_guard"]["rows"][0]["target"]);
}
