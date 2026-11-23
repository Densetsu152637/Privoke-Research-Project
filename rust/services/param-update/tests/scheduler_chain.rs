//! G1 through the real commit path (stage V3-R6): the scheduler calls, over mutual TLS, a fake `V3FuzzerService` that stages and
//! commits real (toy) candidates into a real [`CheckpointStore`] seeded from a pinned release (`bootstrap_pinned`) for all three
//! tiers, through the real chain: admission, `DriftGate`, `GuardGate` over the scheduler's journal (`JournalAllocations`), a
//! retention gate and the signing `Publisher`.
//!
//! Toy parts, as in `v3_pinned.rs`: manifests with the real tier constants and a few zero-filled tensors named like the real
//! inventory (embeddings, every encoder block, the pooler, the heads) whose first values change, the public official config and
//! vocabulary of each tier, and the fit's evidence written by the test (the guard rows are the rows `routine_guard_rows` selects
//! from the real frozen BC01 release, and the evidence source is the real routine schedule). Stubs: the guard scorer answers
//! "better" (the encoder scoring is `v3_guard.rs`), and the retention gate carries a release without references judged by a fixed
//! scorer (the toy checkpoints are not models; the real scoring path is `v3_retention.rs` and the real-weight run).
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;
mod golden_world;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::{Env, repo_root};
use golden_world::{au3_manifest, bc01_paths};
use privoke_contracts::digest::sha256_hex;
use privoke_contracts::json::Value;
use privoke_contracts::proto::experimental_v3::v3_fuzzer_service_server::{V3FuzzerService, V3FuzzerServiceServer};
use privoke_contracts::proto::experimental_v3::{Commit, HealthRequest, HealthResponse};
use privoke_contracts::proto::v1::{FuzzerTrainingRequest, FuzzerTrainingResponse};
use privoke_contracts::publication::test_keys::{self, PRIMARY_ID};
use privoke_contracts::publication::{self, KeySet};
use privoke_contracts::v3::{self as contract, TIERS, Tier, VOCAB_SHA256, action_value, harm_count};
use privoke_curriculum::Example;
use privoke_curriculum::audience::BUNDLED_MANIFEST_SHA256;
use privoke_curriculum::v3::{
    self as curriculum, AU3_SAMPLER, BC01_SAMPLER, Policy, RoutineRelease, routine_guard_rows, routine_guard_seed,
};
use privoke_curriculum::value;
use privoke_param_update::journal::{Journal, JournalAllocations, Stage, model_of};
use privoke_param_update::scheduler::{Commitments, FuzzerRequestConfig, GrpcFuzzer, PinnedCommitments, run};
use privoke_param_update::v3_guard::{GuardGate, GuardScorer};
use privoke_param_update::v3_policy::{DriftBounds, DriftGate};
use privoke_param_update::v3_publish::{Publisher, no_crash};
use privoke_param_update::v3_retention::{RetentionGate, RetentionReleases, RetentionScorer, Verdict};
use privoke_param_update::v3_store::{AudienceSource, ChainObserver, CheckpointStore, PinnedSources, SourceEvidence, StoreError};
use privoke_training::retention_v3::{RetentionRelease, Rule};
use privoke_transport::startup::CloudTransport;
use privoke_transport::{AuthLayer, LimiterKey, Limits, Policy as TransportPolicy, Role, SecureListener, secure_server};
use serde_json::{Value as Json, json};
use tokio::sync::watch;
use tonic::{Request, Response, Status};

const HEADS: usize = 20 * 129;

/// The store's source validation is the golden test's business; the gates under test are the guard's and the others'.
#[derive(Debug)]
struct AcceptSources;

impl SourceEvidence for AcceptSources {
    fn validate(&self, _evidence: &Value) -> Result<(), StoreError> {
        Ok(())
    }
}

#[derive(Debug)]
struct Better;

impl GuardScorer for Better {
    fn passes(&self, _store: &CheckpointStore, _manifest: &Value, _rows: &[Example]) -> Result<bool, StoreError> {
        Ok(true)
    }
}

#[derive(Debug)]
struct Retains;

impl RetentionScorer for Retains {
    fn assess(&self, _store: &CheckpointStore, _manifest: &Value, release: &RetentionRelease) -> Result<Verdict, StoreError> {
        Ok(Verdict { eligible: 180, violations: 0, max_violations: release.rule.max_violations })
    }
}

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/v3_store")
}

/// The first value of the heads, and the first value of every encoder tensor: what a version differs in.
#[derive(Debug, Clone, Copy, PartialEq)]
struct Version {
    heads: f32,
    encoder: f32,
}

fn layout(tier: &Tier) -> Vec<(String, usize)> {
    let layers = tier.num_hidden_layers as usize;
    let rest = tier.parameters as usize - HEADS - layers - 1;
    let mut names = vec![("encoder.embeddings.w".to_string(), rest)];
    names.extend((0..layers).map(|index| (format!("encoder.encoder.layer.{index}.w"), 1)));
    names.push(("encoder.pooler.dense.w".to_string(), 1));
    names.push(("heads.w".to_string(), HEADS));
    names
}

fn tensor_bytes(name: &str, count: usize, version: Version) -> Vec<u8> {
    let mut bytes = vec![0u8; count * 4];
    let lead = if name.starts_with("heads.") { version.heads } else { version.encoder };
    bytes[..4].copy_from_slice(&lead.to_le_bytes());
    bytes
}

fn safetensors(tier: &Tier, version: Version) -> Vec<u8> {
    let mut header = serde_json::Map::new();
    let mut body = Vec::new();
    for (name, count) in layout(tier) {
        let bytes = tensor_bytes(&name, count, version);
        header.insert(name, json!({"dtype": "F32", "shape": [count], "data_offsets": [body.len(), body.len() + bytes.len()]}));
        body.extend_from_slice(&bytes);
    }
    let header = serde_json::to_vec(&Json::Object(header)).unwrap();
    let mut file = (header.len() as u64).to_le_bytes().to_vec();
    file.extend_from_slice(&header);
    file.extend_from_slice(&body);
    file
}

fn inventory(tier: &Tier, version: Version) -> Value {
    let tensors = layout(tier)
        .into_iter()
        .map(|(name, count)| {
            let bytes = tensor_bytes(&name, count, version);
            (
                name,
                value::object(vec![
                    ("dtype", value::string("F32")),
                    ("shape", Value::Array(vec![value::uint(count as u64)])),
                    ("sha256", value::string(&sha256_hex(&bytes))),
                ]),
            )
        })
        .collect::<Vec<_>>();
    value::object(tensors)
}

fn manifest(tier: &Tier, version: Version, scope: &str, parent: &str, original: &str, evidence: &str) -> Vec<u8> {
    let document = value::object(vec![
        ("schema", value::int(1)),
        ("architecture", value::string(contract::ARCHITECTURE)),
        ("model_id", value::string(&model_of(tier.name))),
        ("tier", value::string(tier.name)),
        ("parent", value::string(parent)),
        ("original", value::string(original)),
        ("blob", value::string(&sha256_hex(&safetensors(tier, version)))),
        ("config", value::string(tier.config_sha256)),
        ("vocab", value::string(VOCAB_SHA256)),
        ("evidence", value::string(evidence)),
        (
            "source",
            value::object(vec![
                ("repository", value::string(tier.repository)),
                ("revision", value::string(tier.revision)),
                ("weights_sha256", value::string(tier.weights_sha256)),
                ("config_sha256", value::string(tier.config_sha256)),
                ("vocab_sha256", value::string(VOCAB_SHA256)),
            ]),
        ),
        ("tensors", inventory(tier, version)),
        ("parameter_count", value::uint(tier.parameters)),
        ("scope", value::string(scope)),
    ]);
    value::canonical_bytes(&document).unwrap()
}

fn package(directory: &Path, tier: &Tier, version: Version, manifest: &[u8]) {
    std::fs::create_dir_all(directory).unwrap();
    std::fs::write(directory.join("manifest.json"), manifest).unwrap();
    std::fs::write(directory.join("model.safetensors"), safetensors(tier, version)).unwrap();
    std::fs::copy(fixtures().join(format!("config-{}.json", tier.name)), directory.join("config.json")).unwrap();
    std::fs::copy(fixtures().join("vocab.txt"), directory.join("vocab.txt")).unwrap();
}

fn digests(manifest: &Value) -> BTreeMap<String, String> {
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

/// The evidence of a candidate over `base`, with the routine source of the request and the guard targets of its rows.
#[allow(clippy::too_many_arguments)]
fn evidence(
    tier: &Tier,
    scope: &str,
    request_id: &str,
    base: &str,
    blob: &str,
    changes: &(Vec<String>, Json),
    source: &Json,
    targets: &[u16],
) -> Json {
    let policy: Json = serde_json::from_slice(&value::canonical_bytes(&Policy::PILOT.to_value()).unwrap()).unwrap();
    let full = scope == "full_encoder";
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
    let summary = |rows: Vec<Json>| {
        let joint = rows.iter().filter(|row| row["joint_correct"] == true).count();
        let action = rows.iter().filter(|row| row["action"] == row["target_action"]).count();
        json!({"examples": rows.len(), "rows": rows, "joint_correct": joint, "action_correct": action})
    };
    let (before, after): (Vec<Json>, Vec<Json>) = targets
        .iter()
        .enumerate()
        .map(|(index, target)| {
            let target = u64::from(*target);
            let wrong = if target == 12 { 13 } else { 12 };
            (row(if index < 8 { wrong } else { target }, target), row(target, target))
        })
        .unzip();
    let harms = harm_count(&Json::Array(before.clone()), &Json::Array(after.clone()));
    let (steps, rows, micro) =
        (policy["steps"].as_u64().unwrap(), policy["batch_rows"].as_u64().unwrap(), policy["microbatch"].as_u64().unwrap());
    let microbatches = steps * rows / micro;
    let layers = tier.num_hidden_layers;
    json!({
        "schema": 1, "model_id": model_of(tier.name), "tier": tier.name, "request_id": request_id, "base": base, "scope": scope,
        "layers": [4], "source_commitment": sha256_hex(b"source"), "policy": policy,
        "train_wire_sha256": sha256_hex(b"train"), "guard_wire_sha256": sha256_hex(b"guard"),
        "phases": {
            "training": {"layer": 4, "status": "ok", "examples": steps * rows},
            "base_heldout": {"layer": 4, "status": "ok", "examples": 16},
            "candidate_heldout": {"layer": 4, "status": "ok", "examples": 16}
        },
        "base_guard": summary(before), "candidate_guard": summary(after), "action_harms": harms,
        "changes": changes.1, "changed_tensors": changes.0,
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
        "candidate_blob": blob, "serialized_guard_parity": true, "capabilities": {}, "source": source
    })
}

fn canonical_json(document: &Json) -> Vec<u8> {
    value::canonical_bytes(&value::parse_bytes(document.to_string().as_bytes()).unwrap()).unwrap()
}

/// A way for the fake fuzzer to misreport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fault {
    None,
    /// The evidence source names other source hashes than the commitment the scheduler allocated covers.
    Commitment,
}

struct Shared {
    store: Arc<CheckpointStore>,
    sources: curriculum::Sources,
    release: privoke_curriculum::audience::AudienceRelease,
    hashes: BTreeMap<String, Value>,
    commitments: PinnedCommitments,
    /// The version (heads, encoder values) each model serves.
    versions: Mutex<BTreeMap<String, Version>>,
    faults: Mutex<BTreeMap<(String, String), Fault>>,
}

impl Shared {
    fn serve(&self, stage: Stage, request: FuzzerTrainingRequest) -> Result<Response<FuzzerTrainingResponse>, Status> {
        let model = request.model_id.clone();
        let tier = TIERS.iter().find(|tier| model_of(tier.name) == model).unwrap();
        let fault = self.faults.lock().unwrap().remove(&(model.clone(), stage.name().to_string())).unwrap_or(Fault::None);
        let sampler = request.metadata["sampler"].clone();
        let seed = u64::from(request.seed);
        // What the fuzzer computes: the routine commitment, the schedule at the derived seed, the guard rows.
        let commitment = self.commitments.commitment(&sampler, request.seed).unwrap();
        let schedule_seed = routine_guard_seed(seed, &commitment).unwrap();
        let (schedule, rows) = match sampler.as_str() {
            BC01_SAMPLER => (
                curriculum::schedule_bc01(schedule_seed, Policy::PILOT, &self.sources, self.hashes[&sampler].clone()).unwrap(),
                routine_guard_rows(RoutineRelease::Bc01(&self.sources), seed, &commitment).unwrap(),
            ),
            AU3_SAMPLER => (
                curriculum::build_au3(schedule_seed, Policy::PILOT, &self.release, self.hashes[&sampler].clone()).unwrap(),
                routine_guard_rows(RoutineRelease::Au3(&self.release), seed, &commitment).unwrap(),
            ),
            other => panic!("sampler {other}"),
        };
        let mut source: Json = serde_json::from_slice(&value::canonical_bytes(&schedule.source).unwrap()).unwrap();
        if fault == Fault::Commitment {
            let first = source["source_hashes"].as_object().unwrap().keys().next().unwrap().clone();
            source["source_hashes"][first] = Json::String(sha256_hex(b"tampered"));
        }
        let targets: Vec<u16> = rows.iter().map(|row| row.packed().unwrap()).collect();

        let base = self.store.resolve(&model).unwrap();
        assert_eq!(base, request.metadata["expected_base"], "the scheduler took the base from the store");
        let base_manifest = self.store.manifest(&base).unwrap();
        let original = match &base_manifest {
            Value::Object(map) => match map.get("original") {
                Some(Value::String(original)) if !original.is_empty() => original.clone(),
                _ => base.clone(),
            },
            _ => panic!("object"),
        };
        let current = *self.versions.lock().unwrap().get(&model).unwrap();
        let next = match stage {
            Stage::Heads => Version { heads: current.heads + 0.5, ..current },
            Stage::FullEncoder => Version { heads: current.heads + 0.5, encoder: current.encoder + 0.25 },
        };
        let blob = safetensors(tier, next);
        let probe = contract::parse(&manifest(tier, next, "heads", "", "", ""), contract::MAX_MANIFEST_BYTES).unwrap();
        let changes = contract::tensor_changes(&digests(&base_manifest), &digests(&probe), tier.num_hidden_layers as usize);
        let evidence_document = evidence(tier, stage.name(), &request.request_id, &base, &sha256_hex(&blob), &changes, &source, &targets);
        let evidence_sha = self.store.stage(&canonical_json(&evidence_document), b"").unwrap();
        let candidate_manifest = manifest(tier, next, stage.name(), &base, &original, &evidence_sha);
        let candidate = self.store.stage(&blob, &candidate_manifest).unwrap();
        let receipt = self
            .store
            .commit(&Commit {
                request_id: request.request_id.clone(),
                model_id: model.clone(),
                expected_base: base.clone(),
                candidate: candidate.clone(),
                evidence: evidence_sha,
            })
            .unwrap();
        let applied = receipt.status == "applied";
        if applied {
            self.versions.lock().unwrap().insert(model.clone(), next);
        }
        Ok(Response::new(FuzzerTrainingResponse {
            accepted: applied,
            model_id: model,
            base_version: base.clone(),
            applied_version: if applied { candidate } else { base },
            prompts_generated: 32,
            message: format!("{}: {}", receipt.status, receipt.reason),
            metadata: [("routine_commitment".to_string(), commitment)].into_iter().collect(),
        }))
    }
}

#[derive(Clone)]
struct Handler(Arc<Shared>);

#[tonic::async_trait]
impl V3FuzzerService for Handler {
    async fn run_training_cycle(&self, request: Request<FuzzerTrainingRequest>) -> Result<Response<FuzzerTrainingResponse>, Status> {
        let shared = self.0.clone();
        let request = request.into_inner();
        tokio::task::spawn_blocking(move || shared.serve(Stage::Heads, request)).await.unwrap()
    }

    async fn run_underlying_training_cycle(
        &self,
        request: Request<FuzzerTrainingRequest>,
    ) -> Result<Response<FuzzerTrainingResponse>, Status> {
        let shared = self.0.clone();
        let request = request.into_inner();
        tokio::task::spawn_blocking(move || shared.serve(Stage::FullEncoder, request)).await.unwrap()
    }

    async fn health(&self, _request: Request<HealthRequest>) -> Result<Response<HealthResponse>, Status> {
        Ok(Response::new(HealthResponse { ready: true, role: "v3-fuzzer".to_string(), capabilities: BTreeMap::new() }))
    }
}

fn policy() -> TransportPolicy {
    let run = [Role::Publisher, Role::Trainer];
    TransportPolicy::new()
        .allow("/privoke.experimental.v3.V3FuzzerService/RunTrainingCycle", &run, LimiterKey::Identity)
        .allow("/privoke.experimental.v3.V3FuzzerService/RunUnderlyingTrainingCycle", &run, LimiterKey::Identity)
        .allow("/privoke.experimental.v3.V3FuzzerService/Health", &run, LimiterKey::Identity)
}

async fn serve_fake(transport: CloudTransport, handler: Handler) -> (std::net::SocketAddr, watch::Sender<bool>) {
    let limits = Limits { request_timeout: Duration::from_secs(300), ..Limits::default() };
    let tls_watcher = transport.tls.spawn_watcher(Duration::from_millis(50));
    let registry_watcher = transport.registry.spawn_watcher(Duration::from_millis(50));
    let registry = transport.registry.registry();
    let listener = SecureListener::bind("127.0.0.1:0".parse().unwrap(), transport.tls.clone(), limits.clone()).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let auth = AuthLayer::new(policy(), registry, limits.rate);
    let (stop, receiver) = watch::channel(false);
    let server = secure_server(&limits, auth).add_service(V3FuzzerServiceServer::new(handler));
    tokio::spawn(async move {
        let _keep = (tls_watcher, registry_watcher, transport);
        let mut receiver = receiver;
        let _ = server
            .serve_with_incoming_shutdown(listener.incoming(), async move {
                let _ = receiver.wait_for(|stop| *stop).await;
            })
            .await;
    });
    (addr, stop)
}

fn bounds() -> DriftBounds {
    let mut text = format!("schema = 1\nstatus = \"calibrated\"\nevidence_sha256 = \"{}\"\n", sha256_hex(b"record"));
    for tier in ["efficient", "balanced", "quality"] {
        for scope in ["heads", "full_encoder"] {
            text.push_str(&format!("[{tier}.{scope}]\nmax_update_l2 = 10.0\nmax_cumulative_l2 = 100.0\n"));
        }
    }
    DriftBounds::parse(&text).unwrap()
}

fn keys() -> KeySet {
    test_keys::key_set()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_scheduler_trains_three_tiers_through_the_real_chain_and_every_version_is_signed() {
    let env = Env::new();
    let directory = tempfile::tempdir().unwrap();
    let pinned = Arc::new(PinnedSources::new(
        bc01_paths(),
        AudienceSource::Trusted { path: au3_manifest(), sha256: BUNDLED_MANIFEST_SHA256.to_string() },
    ));
    let journal_path = directory.path().join("cycles.sqlite3");
    let policy_bytes = value::canonical_bytes(&Policy::PILOT.to_value()).unwrap();
    let root = repo_root();
    let commitments = PinnedCommitments::new(&pinned, &root, &policy_bytes).unwrap();

    // Each tier: a toy ORIGINAL and a toy pinned release (full-encoder scope) descending from it.
    let mut pins = BTreeMap::new();
    let mut prepared = Vec::new();
    let release_version = Version { heads: 1.0, encoder: 0.5 };
    for tier in &TIERS {
        let original_manifest = manifest(tier, Version { heads: 0.0, encoder: 0.0 }, "original", "", "", "");
        let original_sha = sha256_hex(&original_manifest);
        let release_manifest = manifest(
            tier,
            release_version,
            "full_encoder",
            &sha256_hex(b"the heads release that the pin descends from"),
            &original_sha,
            &sha256_hex(b"the evidence of the release"),
        );
        let (original, release) =
            (directory.path().join(format!("{}-original", tier.name)), directory.path().join(format!("{}-release", tier.name)));
        package(&original, tier, Version { heads: 0.0, encoder: 0.0 }, &original_manifest);
        package(&release, tier, release_version, &release_manifest);
        pins.insert(model_of(tier.name), sha256_hex(&release_manifest));
        prepared.push((original, release));
    }
    let retention = RetentionGate::new(RetentionReleases::from_releases(TIERS.iter().map(|tier| RetentionRelease {
        sha256: "f".repeat(64),
        model_id: model_of(tier.name),
        teacher: json!({}),
        rule: Rule { max_violations: 0 },
        references: Vec::new(),
    })))
    .with_scorer(Arc::new(Retains));
    let publisher =
        Arc::new(Publisher::new(directory.path().join("published"), PRIMARY_ID, test_keys::seed(PRIMARY_ID), no_crash()).unwrap());
    Journal::open(&journal_path).unwrap();
    let observers: Vec<Arc<dyn privoke_param_update::v3_store::CommitObserver>> = vec![
        Arc::new(DriftGate::new(bounds())),
        Arc::new(GuardGate::new(pinned.clone(), Arc::new(JournalAllocations::new(&journal_path))).with_scorer(Arc::new(Better))),
        Arc::new(retention),
        publisher.clone(),
    ];
    let store = Arc::new(
        CheckpointStore::open(directory.path().join("store"), Arc::new(AcceptSources))
            .unwrap()
            .with_pins(pins.clone())
            .with_observer(Arc::new(ChainObserver::new(observers))),
    );
    let mut versions = BTreeMap::new();
    for ((original, release), tier) in prepared.iter().zip(&TIERS) {
        store.bootstrap_pinned(original, release).unwrap();
        assert_eq!(store.resolve(&model_of(tier.name)).unwrap(), pins[&model_of(tier.name)], "routine training starts from the pin");
        versions.insert(model_of(tier.name), release_version);
    }

    let hashes: BTreeMap<String, Value> = [
        (BC01_SAMPLER.to_string(), curriculum::python_source_hashes(&root, &curriculum::BC01_SOURCE_FILES).unwrap()),
        (AU3_SAMPLER.to_string(), curriculum::python_source_hashes(&root, &curriculum::AU3_SOURCE_FILES).unwrap()),
    ]
    .into_iter()
    .collect();
    let shared = Arc::new(Shared {
        store: store.clone(),
        sources: curriculum::load_sources_from(&bc01_paths()).unwrap(),
        release: curriculum::trusted_release(Some(au3_manifest().as_path()), Some(BUNDLED_MANIFEST_SHA256)).unwrap(),
        hashes,
        commitments: commitments.clone(),
        versions: Mutex::new(versions),
        faults: Mutex::new(BTreeMap::new()),
    });
    // One guard refusal: the balanced tier's HEADS evidence names source hashes the allocated commitment does not cover.
    shared.faults.lock().unwrap().insert((model_of("balanced"), "heads".to_string()), Fault::Commitment);
    let transport = env.tls_args().into_config().unwrap();
    let (addr, stop) = serve_fake(transport, Handler(shared.clone())).await;

    let config = FuzzerRequestConfig {
        target: addr.to_string(),
        prompt_count: 32,
        source_id: "param-update".to_string(),
        timeout_seconds: 600.0,
        interval_seconds: 0.0,
        initial_delay_seconds: 0.0,
        retry_seconds: 0.0,
        max_attempts: 1,
        seed: 20_261_124,
        state_path: journal_path.clone(),
        policy_file: directory.path().join("policy.json"),
        tiers: TIERS.iter().map(|tier| tier.name.to_string()).collect(),
    };
    let scheduler = env.service("param-update", Some("publisher"));
    let caller = GrpcFuzzer::new(config.target.clone(), env.client_config(Some(&scheduler)));
    run(&config, &caller, store.as_ref(), &commitments).await.unwrap();
    let _ = stop.send(true);

    // The journal: six stages, five accepted and the one the guard refused settled `rejected` with its reason.
    let rows = Journal::open(&journal_path).unwrap().allocations(0).unwrap();
    assert_eq!(rows.len(), 6);
    for row in &rows {
        let refused = row.model_id == model_of("balanced") && row.stage == Stage::Heads;
        assert_eq!(row.state, if refused { "rejected" } else { "accepted" }, "{row:?}");
        if refused {
            assert_eq!(row.reason.as_deref(), Some("rejected: commitment_mismatch"), "the guard's reason");
        }
    }
    // Every model: signed statements with consecutive sequences, serving what the store serves.
    let keys = keys();
    for tier in &TIERS {
        let model = model_of(tier.name);
        let expected_versions = if tier.name == "balanced" { 1 } else { 2 };
        let published = store.publications(&model).unwrap();
        assert_eq!(published.iter().map(|row| row.sequence).collect::<Vec<_>>(), (1..=expected_versions).collect::<Vec<u64>>(), "{model}");
        let served = publisher.served(&model).unwrap().expect("a version is served");
        assert_eq!(served.manifest_sha, store.resolve(&model).unwrap());
        let statement = publication::verify(&keys, &served.statement).unwrap();
        assert_eq!((statement.model_id.as_str(), statement.sequence), (model.as_str(), expected_versions));
        // The lineage: the last version's parent chain reaches the pin, and its original is the toy ORIGINAL.
        let manifest_document = store.manifest(&statement.manifest_sha).unwrap();
        let history = store.history(&model).unwrap();
        assert!(history.contains(&pins[&model]) && history.contains(&statement.manifest_sha));
        let Value::Object(fields) = &manifest_document else { panic!("object") };
        assert_eq!(fields.get("scope"), Some(&Value::String("full_encoder".to_string())), "{model} ends with its FULL_ENCODER version");
        assert_ne!(statement.parent, "", "a trained version names its parent");
    }
    // The refused stage changed nothing: balanced published its FULL version on top of the pin.
    let balanced = store.publications(&model_of("balanced")).unwrap();
    let full = publication::verify(&keys, &balanced[0].statement).unwrap();
    assert_eq!(full.parent, pins[&model_of("balanced")], "the FULL_ENCODER fit started from the unchanged pin");
}
