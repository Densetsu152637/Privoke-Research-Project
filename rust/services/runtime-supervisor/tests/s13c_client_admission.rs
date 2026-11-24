//! Stage 13c-1 (`docs/plans/asiaccs-stage13-experiments.md`): the client side of the V3 update attack matrix.
//!
//! The rows of `rust/services/param-update/tests/s13c_rows.json` whose surface is `client` (read by path through
//! `CARGO_MANIFEST_DIR/../param-update/tests/s13c_rows.json`) are driven here through the real `Fetcher` and `LineageAdmission` of the
//! supervisor, against a scripted model-streaming server that serves a synthetic efficient-tier chain (the pattern of
//! `lineage_fetch.rs`: official `config.json` and `vocab.txt`, stand-in weights, the deterministic test publication keys). Every row
//! asserts that the version is refused, that the client's high-water mark did not move and that nothing of the refused version was
//! admitted into the cache. `runtime-supervisor` is not a dependency of `param-update`, so these client checks cannot run in its test.
//!
//! With `S13C_OUT=<directory>` the rows are written to `<directory>/s13c_client_admission.rows.json`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::too_many_arguments)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use privoke_contracts::canonical::{self, Variant};
use privoke_contracts::digest::sha256_hex;
use privoke_contracts::json::Value;
use privoke_contracts::proto::v1::model_streaming_service_server::{ModelStreamingService, ModelStreamingServiceServer};
use privoke_contracts::proto::v1::{
    HealthRequest, HealthResponse, ModelAssetChunk, ModelAssetRequest, ModelPackageAsset, ModelPackageResponse, ModelParameterChunk,
    ModelParametersRequest, ModelParametersResponse,
};
use privoke_contracts::publication::test_keys::{self, PRIMARY_ID};
use privoke_contracts::publication::{self, Statement};
use privoke_contracts::v3::{self, LineageError, TierPin};
use privoke_supervisor::channel::ModelEndpoint;
use privoke_supervisor::fetch::{ASSETS, FetchConfig, FetchError, Fetcher, HIGH_WATER_FILE, LineageAdmission};
use privoke_transport::listener::loopback::LoopbackListener;
use serde_json::{Value as Json, json};
use tokio_stream::Stream;
use tonic::{Request, Response, Status};

const MODEL: &str = "privoke-v3-efficient";
const OTHER_MODEL: &str = "privoke-v3-balanced";
const CONFIG: &[u8] = include_bytes!("../../param-update/tests/fixtures/v3_store/config-efficient.json");
const VOCAB: &[u8] = include_bytes!("../../param-update/tests/fixtures/v3_store/vocab.txt");
const SCOPE_LABEL: &str = "update path (Rust V3)";
const CONTRACT: &str = "rust/crates/privoke-contracts/src/v3.rs";
const FETCH: &str = "rust/services/runtime-supervisor/src/fetch.rs";

/// One version the scripted server can serve.
#[derive(Clone)]
struct Version {
    sha: String,
    manifest: Vec<u8>,
    parent: String,
    original: String,
    assets: BTreeMap<String, Vec<u8>>,
}

fn text(value: &str) -> Value {
    Value::String(value.to_string())
}

/// A canonical manifest on the efficient tier that satisfies the manifest contract (`scope` is `heads` or `full_encoder`).
fn version(scope: &str, parent: &str, original: &str, tag: &str) -> Version {
    let tier = &v3::TIERS[0];
    let blob = format!("stand-in weights {tag}").into_bytes();
    let evidence = format!("stand-in evidence {tag}").into_bytes();
    let tensor = Value::Object(BTreeMap::from([
        ("dtype".to_string(), text("F32")),
        ("sha256".to_string(), text(&sha256_hex(tag.as_bytes()))),
        ("shape".to_string(), Value::Array(vec![Value::Int(tier.parameters.to_string())])),
    ]));
    let source = Value::Object(BTreeMap::from([
        ("config_sha256".to_string(), text(tier.config_sha256)),
        ("repository".to_string(), text(tier.repository)),
        ("revision".to_string(), text(tier.revision)),
        ("vocab_sha256".to_string(), text(v3::VOCAB_SHA256)),
        ("weights_sha256".to_string(), text(tier.weights_sha256)),
    ]));
    let manifest = Value::Object(BTreeMap::from([
        ("architecture".to_string(), text(v3::ARCHITECTURE)),
        ("blob".to_string(), text(&sha256_hex(&blob))),
        ("config".to_string(), text(tier.config_sha256)),
        ("evidence".to_string(), text(&sha256_hex(&evidence))),
        ("model_id".to_string(), text(MODEL)),
        ("original".to_string(), text(original)),
        ("parameter_count".to_string(), Value::Int(tier.parameters.to_string())),
        ("parent".to_string(), text(parent)),
        ("schema".to_string(), Value::Int("1".to_string())),
        ("scope".to_string(), text(scope)),
        ("source".to_string(), source),
        ("tensors".to_string(), Value::Object(BTreeMap::from([("tensor".to_string(), tensor)]))),
        ("tier".to_string(), text(tier.name)),
        ("vocab".to_string(), text(v3::VOCAB_SHA256)),
    ]));
    let manifest = canonical::to_bytes(&manifest, Variant::Utf8Lf).unwrap();
    let assets = BTreeMap::from([
        ("model.safetensors".to_string(), blob),
        ("config.json".to_string(), CONFIG.to_vec()),
        ("vocab.txt".to_string(), VOCAB.to_vec()),
        ("evidence.json".to_string(), evidence),
    ]);
    Version { sha: sha256_hex(&manifest), manifest, parent: parent.to_string(), original: original.to_string(), assets }
}

/// The synthetic chain: the pinned ORIGINAL, HEADS (parent: the pin), FULL (parent: HEADS), and a second HEADS on the pin.
struct Chain {
    pin: Version,
    heads: Version,
    full: Version,
    heads_again: Version,
}

fn chain() -> Chain {
    let pin = version("full_encoder", &sha256_hex(b"initial"), &sha256_hex(b"root"), "pin");
    let heads = version("heads", &pin.sha, &pin.original, "heads");
    let full = version("full_encoder", &heads.sha, &pin.original, "full");
    let heads_again = version("heads", &pin.sha, &pin.original, "heads-again");
    Chain { pin, heads, full, heads_again }
}

fn statement_for(key_id: &str, model: &str, version: &Version, sequence: u64) -> Vec<u8> {
    let statement = Statement {
        key_id: key_id.to_string(),
        model_id: model.to_string(),
        manifest_sha: version.sha.clone(),
        parent: version.parent.clone(),
        original: version.original.clone(),
        sequence,
    };
    publication::sign(&test_keys::seed(key_id), &statement).unwrap()
}

/// What the scripted server answers.
#[derive(Default)]
struct Serving {
    versions: BTreeMap<String, Version>,
    current: Option<(String, Vec<u8>)>,
    /// An asset whose streamed bytes differ from the bytes the package declares (corrupted at rest before serving).
    corrupt_asset: Option<String>,
}

impl Serving {
    fn serve(&mut self, version: &Version, statement: Vec<u8>) {
        self.versions.insert(version.sha.clone(), version.clone());
        self.current = Some((version.sha.clone(), statement));
    }

    fn package(&self, statement: Vec<u8>) -> ModelPackageResponse {
        let (sha, _) = self.current.clone().unwrap();
        let version = &self.versions[&sha];
        ModelPackageResponse {
            model_id: MODEL.into(),
            architecture: v3::ARCHITECTURE.into(),
            manifest_sha256: sha,
            manifest_json: version.manifest.clone(),
            assets: ASSETS
                .iter()
                .map(|(name, _)| ModelPackageAsset {
                    name: (*name).into(),
                    sha256: sha256_hex(&version.assets[*name]),
                    size_bytes: version.assets[*name].len() as u64,
                })
                .collect(),
            publication_statement: statement,
        }
    }
}

type BoxStream<T> = Pin<Box<dyn Stream<Item = Result<T, Status>> + Send>>;

struct Fake(Arc<Mutex<Serving>>);

#[tonic::async_trait]
impl ModelStreamingService for Fake {
    async fn get_model_parameters(&self, _: Request<ModelParametersRequest>) -> Result<Response<ModelParametersResponse>, Status> {
        Err(Status::unimplemented("not scripted"))
    }
    type StreamModelParametersStream = BoxStream<ModelParameterChunk>;
    async fn stream_model_parameters(
        &self,
        _: Request<ModelParametersRequest>,
    ) -> Result<Response<Self::StreamModelParametersStream>, Status> {
        Err(Status::unimplemented("not scripted"))
    }
    async fn health(&self, _: Request<HealthRequest>) -> Result<Response<HealthResponse>, Status> {
        Ok(Response::new(HealthResponse { service: "scripted".into(), status: "SERVING".into() }))
    }
    async fn get_model_package(&self, request: Request<ModelParametersRequest>) -> Result<Response<ModelPackageResponse>, Status> {
        let serving = self.0.lock().unwrap();
        assert_eq!(request.get_ref().model_id, MODEL);
        let (_, statement) = serving.current.clone().unwrap();
        Ok(Response::new(serving.package(statement)))
    }
    type StreamModelAssetStream = BoxStream<ModelAssetChunk>;
    async fn stream_model_asset(&self, request: Request<ModelAssetRequest>) -> Result<Response<Self::StreamModelAssetStream>, Status> {
        let serving = self.0.lock().unwrap();
        let version = serving.versions.get(&request.get_ref().manifest_sha256).ok_or_else(|| Status::not_found("version"))?;
        let name = request.get_ref().asset_name.clone();
        let declared = version.assets.get(&name).cloned().ok_or_else(|| Status::not_found("asset"))?;
        let sha = sha256_hex(&declared);
        let total = declared.len() as u64;
        let mut data = declared;
        if serving.corrupt_asset.as_deref() == Some(name.as_str()) {
            data[0] ^= 0xff;
        }
        let chunks: Vec<ModelAssetChunk> = data
            .chunks(1024 * 1024)
            .enumerate()
            .map(|(index, block)| ModelAssetChunk {
                model_id: MODEL.into(),
                manifest_sha256: version.sha.clone(),
                asset_name: name.clone(),
                sha256: sha.clone(),
                offset: (index * 1024 * 1024) as u64,
                total_bytes: total,
                data: block.to_vec(),
            })
            .collect();
        Ok(Response::new(Box::pin(tokio_stream::iter(chunks.into_iter().map(Ok)))))
    }
}

struct Rig {
    serving: Arc<Mutex<Serving>>,
    endpoint: ModelEndpoint,
    cache: tempfile::TempDir,
    chain: Chain,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
}

async fn rig() -> Rig {
    let serving = Arc::new(Mutex::new(Serving::default()));
    let listener = LoopbackListener::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let address = listener.local_addr().unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let service = ModelStreamingServiceServer::new(Fake(Arc::clone(&serving)));
    tokio::spawn(async move {
        let _ = tonic::transport::Server::builder()
            .add_service(service)
            .serve_with_incoming_shutdown(listener.incoming(), async {
                let _ = stopped.await;
            })
            .await;
    });
    let environment = BTreeMap::from([("PRIVOKE_CLOUD_TARGET".to_string(), address.to_string())]);
    Rig {
        serving,
        endpoint: ModelEndpoint::from_environment(&environment).unwrap(),
        cache: tempfile::tempdir().unwrap(),
        chain: chain(),
        stop: Some(stop),
    }
}

impl Rig {
    fn config(&self) -> FetchConfig {
        FetchConfig {
            consumer_id: "installation-1".into(),
            rpc_timeout: Duration::from_secs(20),
            download_timeout: Duration::from_secs(60),
            cache_root: self.cache.path().to_path_buf(),
        }
    }

    /// The admission of a client whose compiled tier pin is the synthetic ORIGINAL.
    fn admission(&self) -> LineageAdmission {
        LineageAdmission::new(test_keys::key_set(), self.cache.path()).with_pins(BTreeMap::from([(
            MODEL.to_string(),
            TierPin { manifest_sha: self.chain.pin.sha.clone(), original: self.chain.pin.original.clone() },
        )]))
    }

    fn serve(&self, version: &Version, statement: Vec<u8>) {
        self.serving.lock().unwrap().serve(version, statement);
    }

    async fn fetch(&self, admission: &LineageAdmission) -> Result<Option<privoke_supervisor::fetch::FetchedPackage>, FetchError> {
        let channel = self.endpoint.connect(Duration::from_secs(10)).await.unwrap();
        Fetcher::new().fetch(channel, &self.endpoint.target, MODEL, admission, &self.config()).await
    }

    fn model_directory(&self) -> PathBuf {
        self.cache.path().join(MODEL)
    }

    fn version_directory(&self, version: &Version) -> PathBuf {
        self.model_directory().join(&version.sha)
    }

    fn high_water(&self) -> Option<Vec<u8>> {
        std::fs::read(self.model_directory().join(HIGH_WATER_FILE)).ok()
    }

    /// What the client holds: the mark (the sequence and the manifest of the highest statement it accepted) and what the server offers.
    fn state(&self) -> Json {
        let mark = self.high_water().map(|wire| {
            let (statement, _) = publication::decode(&wire).unwrap();
            json!({"sequence": statement.sequence, "manifest_sha": statement.manifest_sha})
        });
        let offered = self.serving.lock().unwrap().current.clone().map(|(sha, _)| sha);
        json!({"store_current": null, "versions_count": null, "max_sequence": null, "served_manifest": offered, "client_mark": mark})
    }

    fn stop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
    }
}

fn reason_of(error: &FetchError) -> &'static str {
    match error {
        FetchError::Lineage(LineageError::Downgrade) => "Downgrade",
        FetchError::Lineage(LineageError::Replay { .. }) => "Replay",
        FetchError::Lineage(LineageError::WrongOriginal) => "WrongOriginal",
        FetchError::Lineage(LineageError::Unsigned) => "Unsigned",
        FetchError::Lineage(LineageError::Publication(publication::PublicationError::BadSignature)) => "BadSignature",
        FetchError::Lineage(LineageError::Publication(publication::PublicationError::UnknownKey)) => "UnknownKey",
        FetchError::Lineage(LineageError::StatementModel) => "StatementModel",
        FetchError::Lineage(LineageError::StatementManifest) => "StatementManifest",
        FetchError::Lineage(_) => "Lineage",
        FetchError::Invalid(message) if message.contains("incomplete or corrupted") => "AssetCorrupted",
        FetchError::Invalid(_) => "Invalid",
        _ => "Other",
    }
}

/// The statement with one hexadecimal digit of its signature changed (still a well-formed statement).
fn with_changed_signature(mut wire: Vec<u8>) -> Vec<u8> {
    let marker = b"\"signature\":\"";
    let start = wire.windows(marker.len()).position(|window| window == marker).unwrap() + marker.len() + 4;
    wire[start] = if wire[start] == b'0' { b'1' } else { b'0' };
    wire
}

fn manifest_rows() -> Vec<Json> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../param-update/tests/s13c_rows.json");
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

/// One attempt of the client: a version is offered, and the client must refuse it with `reason`, keep its mark, and cache nothing of
/// the refused version.
struct Attempt<'a> {
    version: &'a Version,
    statement: Vec<u8>,
    reason: &'static str,
    mutation: &'static str,
}

async fn refuse(rig: &Rig, admission: &LineageAdmission, attempt: &Attempt<'_>) -> (Json, Json, String) {
    rig.serve(attempt.version, attempt.statement.clone());
    let mark = rig.high_water();
    let before = rig.state();
    let manifest = rig.version_directory(attempt.version).join("manifest.json");
    let cached = std::fs::read(&manifest).ok();
    let error = rig.fetch(admission).await.expect_err(attempt.mutation);
    assert_eq!(reason_of(&error), attempt.reason, "{}: {error}", attempt.mutation);
    assert_eq!(rig.high_water(), mark, "{}: the high-water mark moved", attempt.mutation);
    // A version the client already held stays as it was; a version it never held is not admitted into the cache.
    assert_eq!(std::fs::read(&manifest).ok(), cached, "{}: a refused version was admitted or changed", attempt.mutation);
    (before, rig.state(), error.to_string())
}

#[tokio::test]
async fn the_client_refuses_every_forged_stale_or_corrupt_version_and_keeps_its_mark() {
    let mut rig = rig().await;
    let admission = rig.admission();
    let chain = chain();
    let mut rows: Vec<Json> = Vec::new();

    // The client accepted HEADS (1) and FULL (2); its mark is FULL's statement.
    let heads = statement_for(PRIMARY_ID, MODEL, &chain.heads, 1);
    rig.serve(&chain.heads, heads.clone());
    rig.fetch(&admission).await.unwrap().unwrap();
    let full = statement_for(PRIMARY_ID, MODEL, &chain.full, 2);
    rig.serve(&chain.full, full.clone());
    rig.fetch(&admission).await.unwrap().unwrap();
    assert_eq!(rig.high_water().unwrap(), full);

    let mut record = |id: &str, variant: &str, attempt: &Attempt<'_>, check: (&str, &str, &str), outcome: (Json, Json, String)| {
        let (before, after, message) = outcome;
        let entry = manifest_rows().into_iter().find(|row| row["id"] == id).unwrap_or_else(|| panic!("{id} is not in s13c_rows.json"));
        assert_eq!((entry["surface"].as_str(), entry["expected"].as_str()), (Some("client"), Some("rejected_unchanged")), "{id}");
        assert_eq!(entry["wire_path"], false, "{id}");
        rows.push(json!({
            "id": id, "attack_class": entry["attack_class"], "variant": variant, "combined": false, "chain": entry["chain"],
            "leg": "ci", "surface": "client", "identity": "installation client (LineageAdmission)", "scope_label": SCOPE_LABEL,
            "attempted": {
                "request_id": null, "model_id": MODEL, "expected_base": null, "candidate_sha": attempt.version.sha,
                "mutation": attempt.mutation
            },
            "expected": "rejected_unchanged",
            "observed": {"grpc_code": null, "receipt_status": null, "receipt_reason": null, "message": message},
            "rejecting_check": {"file": check.0, "symbol": check.1, "reason": check.2},
            "active_before": before, "active_after": after, "orphan_blobs": 0, "property_met": before == after, "not_run_reason": null
        }));
        assert_eq!(before, after, "{id}: the client's state changed");
    };

    // C2c: the client is served an older signed statement (a lower sequence than its mark).
    let attempt = Attempt {
        version: &chain.heads,
        statement: heads.clone(),
        reason: "Replay",
        mutation: "the sequence-1 statement after sequence 2",
    };
    let outcome = refuse(&rig, &admission, &attempt).await;
    record("C2c", "the client is served an older signed statement", &attempt, (CONTRACT, "admit_lineage", "LineageError::Replay"), outcome);

    // C2d: the client is served the unsigned pin after a signed version.
    let attempt = Attempt {
        version: &chain.pin,
        statement: Vec::new(),
        reason: "Downgrade",
        mutation: "the unsigned pinned ORIGINAL after a signed version",
    };
    let outcome = refuse(&rig, &admission, &attempt).await;
    record(
        "C2d",
        "the client is served the unsigned pin after a signed version",
        &attempt,
        (CONTRACT, "admit_lineage", "LineageError::Downgrade"),
        outcome,
    );

    // C4f: a statement for another manifest, for another model, and a version of another ORIGINAL.
    let attempt = Attempt {
        version: &chain.heads_again,
        statement: statement_for(PRIMARY_ID, MODEL, &chain.full, 9),
        reason: "StatementManifest",
        mutation: "a signed statement that names another manifest",
    };
    let outcome = refuse(&rig, &admission, &attempt).await;
    let other_model = Attempt {
        version: &chain.heads_again,
        statement: statement_for(PRIMARY_ID, OTHER_MODEL, &chain.heads_again, 9),
        reason: "StatementModel",
        mutation: "a signed statement that names another model",
    };
    refuse(&rig, &admission, &other_model).await;
    let foreign = version("heads", &sha256_hex(b"other"), &sha256_hex(b"other"), "foreign");
    let other_original = Attempt {
        version: &foreign,
        statement: statement_for(PRIMARY_ID, MODEL, &foreign, 9),
        reason: "WrongOriginal",
        mutation: "a signed version whose ORIGINAL is not the tier pin",
    };
    refuse(&rig, &admission, &other_original).await;
    record(
        "C4f",
        "the client receives a statement for another model or manifest",
        &attempt,
        (
            CONTRACT,
            "LineageError::StatementModel / StatementManifest / WrongOriginal",
            "StatementManifest; StatementModel and WrongOriginal were refused too",
        ),
        outcome,
    );

    // CS2, CS3 and CS4: an unknown key, a tampered statement and an unsigned manifest that is not the pin.
    let attempt = Attempt {
        version: &chain.heads_again,
        statement: statement_for("test-publication-3", MODEL, &chain.heads_again, 9),
        reason: "UnknownKey",
        mutation: "a statement signed by a key the client does not compile",
    };
    let outcome = refuse(&rig, &admission, &attempt).await;
    record(
        "CS2",
        "an unknown key",
        &attempt,
        ("rust/crates/privoke-contracts/src/publication.rs", "verify", "LineageError::Publication (unknown key)"),
        outcome,
    );
    let attempt = Attempt {
        version: &chain.heads_again,
        statement: with_changed_signature(statement_for(PRIMARY_ID, MODEL, &chain.heads_again, 9)),
        reason: "BadSignature",
        mutation: "one signature digit changed",
    };
    let outcome = refuse(&rig, &admission, &attempt).await;
    record(
        "CS3",
        "a tampered statement",
        &attempt,
        ("rust/crates/privoke-contracts/src/publication.rs", "verify", "LineageError::Publication (bad signature)"),
        outcome,
    );
    let attempt = Attempt {
        version: &chain.heads_again,
        statement: Vec::new(),
        reason: "Unsigned",
        mutation: "an unsigned manifest that is not the pin",
    };
    let outcome = refuse(&rig, &admission, &attempt).await;
    record("CS4", "an unsigned manifest that is not the pin", &attempt, (CONTRACT, "admit_lineage", "LineageError::Unsigned"), outcome);

    // C9f (client): a published asset corrupted at rest is streamed with bytes that do not match its declared digest.
    rig.serving.lock().unwrap().corrupt_asset = Some("model.safetensors".to_string());
    let attempt = Attempt {
        version: &chain.heads_again,
        statement: statement_for(PRIMARY_ID, MODEL, &chain.heads_again, 3),
        reason: "AssetCorrupted",
        mutation: "the checkpoint is streamed with its first byte flipped",
    };
    let outcome = refuse(&rig, &admission, &attempt).await;
    record(
        "C9f-client",
        "a published asset is corrupted at rest before serving, seen by the client",
        &attempt,
        (FETCH, "download / verify_package", "Model asset stream is incomplete or corrupted"),
        outcome,
    );
    // The same version, honestly served, is then admitted: the refusals above never spoiled the client.
    rig.serving.lock().unwrap().corrupt_asset = None;
    let next = statement_for(PRIMARY_ID, MODEL, &chain.heads_again, 3);
    rig.serve(&chain.heads_again, next.clone());
    rig.fetch(&admission).await.unwrap().unwrap();
    assert_eq!(rig.high_water().unwrap(), next);
    rig.stop();

    // Every `client` row of the manifest has a row here, and nothing else is recorded.
    let wanted: BTreeSet<String> =
        manifest_rows().iter().filter(|row| row["surface"] == "client").map(|row| row["id"].as_str().unwrap().to_string()).collect();
    let recorded: BTreeSet<String> = rows.iter().map(|row| row["id"].as_str().unwrap().to_string()).collect();
    assert_eq!(recorded, wanted);
    assert_eq!(rows.len(), wanted.len());
    if let Some(directory) = std::env::var_os("S13C_OUT").filter(|value| !value.is_empty()) {
        let directory = PathBuf::from(directory);
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::write(directory.join("s13c_client_admission.rows.json"), serde_json::to_vec_pretty(&rows).unwrap()).unwrap();
    }
}
