//! The supervisor fetch with `LineageAdmission` (stage V3-R4a): a scripted model-streaming server serves a synthetic chain
//! (a pinned ORIGINAL, HEADS and FULL versions, a rollback, a second-key version) whose manifests satisfy the manifest contract on
//! the efficient tier with the official `config.json` and `vocab.txt` (fixtures of param-update) and stand-in weights. The synthetic
//! ORIGINAL is the tier pin of the admission under test. Every rule is exercised through the real `Fetcher`, with the high-water
//! mark and the statements persisted in the cache and re-verified by a fresh fetcher (a restart). Stage V3-R4b adds, on the same chain,
//! the refresh loop, the offline start-up selection, the garbage collection and the advisory lock of the mark.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::rows::record;
use privoke_contracts::canonical::{self, Variant};
use privoke_contracts::digest::sha256_hex;
use privoke_contracts::json::Value;
use privoke_contracts::model_cache::{CacheRules, ModelCache};
use privoke_contracts::proto::v1::model_streaming_service_server::{ModelStreamingService, ModelStreamingServiceServer};
use privoke_contracts::proto::v1::{
    HealthRequest, HealthResponse, ModelAssetChunk, ModelAssetRequest, ModelPackageAsset, ModelPackageResponse, ModelParameterChunk,
    ModelParametersRequest, ModelParametersResponse,
};
use privoke_contracts::publication::test_keys::{self, PRIMARY_ID, SECONDARY_ID};
use privoke_contracts::publication::{self, Statement};
use privoke_contracts::v3::{self, LineageError, TierPin};
use privoke_supervisor::channel::ModelEndpoint;
use privoke_supervisor::fetch::{
    ASSETS, Admission, AdmittedManifest, FetchConfig, FetchError, Fetcher, HIGH_WATER_FILE, LineageAdmission, STATEMENT_FILE,
    verify_package,
};
use privoke_supervisor::refresh::{Refreshed, Refresher};
use privoke_transport::listener::loopback::LoopbackListener;
use tokio_stream::Stream;
use tonic::{Request, Response, Status};

const MODEL: &str = "privoke-v3-efficient";
const CONFIG: &[u8] = include_bytes!("../../param-update/tests/fixtures/v3_store/config-efficient.json");
const VOCAB: &[u8] = include_bytes!("../../param-update/tests/fixtures/v3_store/vocab.txt");

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

/// A canonical manifest on the efficient tier that satisfies the manifest contract. `scope` is `heads` or `full_encoder`; the
/// synthetic ORIGINAL is a `heads` version too, because every served version needs evidence to be fetched.
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

/// The synthetic chain: the pinned ORIGINAL, HEADS (parent: the pin), FULL (parent: HEADS), and a second HEADS after a rollback.
struct Chain {
    pin: Version,
    heads: Version,
    full: Version,
    heads_again: Version,
}

fn chain() -> Chain {
    // As the real pinned release: its own `original` is the ORIGINAL-scope manifest, which every trained version names too.
    let pin = version("full_encoder", &sha256_hex(b"initial"), &sha256_hex(b"root"), "pin");
    let heads = version("heads", &pin.sha, &pin.original, "heads");
    let full = version("full_encoder", &heads.sha, &pin.original, "full");
    let heads_again = version("heads", &pin.sha, &pin.original, "heads-again");
    Chain { pin, heads, full, heads_again }
}

fn statement_for(key_id: &str, version: &Version, sequence: u64) -> Vec<u8> {
    let statement = Statement {
        key_id: key_id.to_string(),
        model_id: MODEL.to_string(),
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
    unavailable: bool,
    /// From the second `GetModelPackage` call on, answer with this statement instead (a change during the download).
    later_statement: Option<Vec<u8>>,
    calls: usize,
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
        let mut serving = self.0.lock().unwrap();
        // The client fetches with the plain model id.
        assert_eq!(request.get_ref().model_id, MODEL);
        if serving.unavailable {
            return Err(Status::unavailable("the authority is behind"));
        }
        serving.calls += 1;
        let (_, first) = serving.current.clone().unwrap();
        let statement = match (&serving.later_statement, serving.calls) {
            (Some(later), 2..) => later.clone(),
            _ => first,
        };
        Ok(Response::new(serving.package(statement)))
    }
    type StreamModelAssetStream = BoxStream<ModelAssetChunk>;
    async fn stream_model_asset(&self, request: Request<ModelAssetRequest>) -> Result<Response<Self::StreamModelAssetStream>, Status> {
        let serving = self.0.lock().unwrap();
        let version = serving.versions.get(&request.get_ref().manifest_sha256).ok_or_else(|| Status::not_found("version"))?;
        let name = request.get_ref().asset_name.clone();
        let data = version.assets.get(&name).cloned().ok_or_else(|| Status::not_found("asset"))?;
        let sha = sha256_hex(&data);
        let total = data.len() as u64;
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
    fn admission(&self, keys: publication::KeySet) -> LineageAdmission {
        LineageAdmission::new(keys, self.cache.path()).with_pins(BTreeMap::from([(
            MODEL.to_string(),
            TierPin { manifest_sha: self.chain.pin.sha.clone(), original: self.chain.pin.original.clone() },
        )]))
    }

    fn serve(&self, version: &Version, statement: Vec<u8>) {
        self.serving.lock().unwrap().serve(version, statement);
    }

    /// One fetch by a fresh fetcher, as after a restart.
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

    fn stop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
    }
}

fn lineage_reason(error: &FetchError) -> &'static str {
    match error {
        FetchError::Lineage(LineageError::Downgrade) => "Downgrade",
        FetchError::Lineage(LineageError::Replay { .. }) => "Replay",
        FetchError::Lineage(LineageError::SequenceConflict(_)) => "SequenceConflict",
        FetchError::Lineage(LineageError::WrongOriginal) => "WrongOriginal",
        FetchError::Lineage(LineageError::Unsigned) => "Unsigned",
        FetchError::Lineage(LineageError::Publication(publication::PublicationError::BadSignature)) => "BadSignature",
        FetchError::Lineage(LineageError::Publication(publication::PublicationError::UnknownKey)) => "UnknownKey",
        FetchError::Lineage(LineageError::StatementLineage) => "StatementLineage",
        FetchError::Lineage(LineageError::StatementModel) => "StatementModel",
        FetchError::Lineage(LineageError::StatementManifest) => "StatementManifest",
        FetchError::Lineage(LineageError::HighWater(_)) => "HighWater",
        FetchError::Lineage(_) => "Lineage",
        FetchError::Invalid(message) if message.contains("does not verify") => "HighWater",
        FetchError::Invalid(_) => "Invalid",
        _ => "Other",
    }
}

/// Fetch and require a refusal with `reason`; record the row. The cache must hold nothing of the refused version and the
/// high-water mark must not have moved.
async fn refused(rig: &Rig, admission: &LineageAdmission, version: &Version, id: &str, name: &str, reason: &str) {
    let before = rig.high_water();
    let error = rig.fetch(admission).await.expect_err(name);
    record(id, name, "refused", "refused", lineage_reason(&error));
    assert_eq!(lineage_reason(&error), reason, "{id} {name}: {error}");
    assert_eq!(rig.high_water(), before, "{id} {name}: the high-water mark moved");
    // A refused version leaves no manifest that would mark a directory as complete (the pinned ORIGINAL may be cached from before).
    let manifest = rig.version_directory(version).join("manifest.json");
    if !version.sha.is_empty() && manifest.exists() {
        assert_eq!(std::fs::read(&manifest).unwrap(), version.manifest, "{id} {name}: a refused version changed a cached manifest");
    }
}

/// The statement with one hexadecimal digit of its signature changed (still a well-formed statement).
fn with_changed_signature(mut wire: Vec<u8>) -> Vec<u8> {
    let marker = b"\"signature\":\"";
    let start = wire.windows(marker.len()).position(|window| window == marker).unwrap() + marker.len() + 4;
    wire[start] = if wire[start] == b'0' { b'1' } else { b'0' };
    wire
}

fn names(directory: &Path) -> Vec<String> {
    let mut names: Vec<String> =
        std::fs::read_dir(directory).unwrap().map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned()).collect();
    names.sort();
    names
}

#[tokio::test]
async fn a_signed_chain_is_fetched_with_its_statements_and_the_mark_follows_it() {
    let mut rig = rig().await;
    let keys = test_keys::key_set();
    let admission = rig.admission(keys);
    let chain = chain();

    // First start: the unsigned pinned ORIGINAL is admitted; nothing is persisted but the package.
    rig.serve(&chain.pin, Vec::new());
    let package = rig.fetch(&admission).await.unwrap().unwrap();
    assert_eq!(package.pin, chain.pin.sha);
    assert!(rig.high_water().is_none());
    assert!(!rig.version_directory(&chain.pin).join(STATEMENT_FILE).exists());
    record("LF1", "first-start-unsigned-original", "accepted", "accepted", "");

    // HEADS (1), FULL (2): each is admitted, its statement is kept beside it, and the mark is the statement itself.
    let heads = statement_for(PRIMARY_ID, &chain.heads, 1);
    rig.serve(&chain.heads, heads.clone());
    rig.fetch(&admission).await.unwrap().unwrap();
    assert_eq!(rig.high_water().unwrap(), heads);
    assert_eq!(std::fs::read(rig.version_directory(&chain.heads).join(STATEMENT_FILE)).unwrap(), heads);
    assert_eq!(
        names(&rig.version_directory(&chain.heads)),
        ["config.json", "evidence.json", "manifest.json", "model.safetensors", "statement.json", "vocab.txt"]
    );
    record("LF2", "heads-signed-by-the-first-key", "accepted", "accepted", "");

    let full = statement_for(PRIMARY_ID, &chain.full, 2);
    rig.serve(&chain.full, full.clone());
    rig.fetch(&admission).await.unwrap().unwrap();
    assert_eq!(rig.high_water().unwrap(), full);

    // The same statement again is idempotent (the equal sequence of the same manifest).
    rig.fetch(&admission).await.unwrap().unwrap();
    assert_eq!(rig.high_water().unwrap(), full);

    // A signed rollback to the pinned ORIGINAL: a higher sequence for an earlier manifest.
    let rollback = statement_for(PRIMARY_ID, &chain.pin, 3);
    rig.serve(&chain.pin, rollback.clone());
    let again = rig.fetch(&admission).await.unwrap().unwrap();
    assert_eq!(again.pin, chain.pin.sha);
    assert_eq!(rig.high_water().unwrap(), rollback);
    assert_eq!(
        std::fs::read(rig.version_directory(&chain.pin).join(STATEMENT_FILE)).unwrap(),
        rollback,
        "the cached ORIGINAL carries the rollback statement"
    );
    record("LF3", "signed-rollback-to-the-original", "accepted", "accepted", "");

    // Key rotation: a version signed by the second key is admitted while both keys are compiled.
    let second = statement_for(SECONDARY_ID, &chain.heads_again, 4);
    rig.serve(&chain.heads_again, second.clone());
    rig.fetch(&admission).await.unwrap().unwrap();
    assert_eq!(rig.high_water().unwrap(), second);
    record("LF4", "version-signed-by-the-second-key", "accepted", "accepted", "");
    rig.stop();
}

#[tokio::test]
async fn forged_and_replayed_versions_are_refused_and_change_nothing() {
    let mut rig = rig().await;
    let admission = rig.admission(test_keys::key_set());
    let chain = chain();
    let heads = statement_for(PRIMARY_ID, &chain.heads, 1);
    let full = statement_for(PRIMARY_ID, &chain.full, 2);
    rig.serve(&chain.heads, heads.clone());
    rig.fetch(&admission).await.unwrap().unwrap();
    rig.serve(&chain.full, full.clone());
    rig.fetch(&admission).await.unwrap().unwrap();

    // Replay of a lower sequence.
    rig.serve(&chain.heads, heads.clone());
    refused(&rig, &admission, &chain.heads, "LF5", "replay-of-a-lower-sequence", "Replay").await;

    // The same sequence for another manifest.
    let conflicting = statement_for(PRIMARY_ID, &chain.heads_again, 2);
    rig.serve(&chain.heads_again, conflicting);
    refused(&rig, &admission, &chain.heads_again, "LF6", "same-sequence-other-manifest", "SequenceConflict").await;
    assert!(!rig.version_directory(&chain.heads_again).exists(), "nothing of a refused version is cached");

    // Downgrade to the unsigned pinned ORIGINAL after a signed version.
    rig.serve(&chain.pin, Vec::new());
    refused(&rig, &admission, &chain.pin, "LF7", "downgrade-to-unsigned-original", "Downgrade").await;

    // A bad signature, an unknown key and a statement for another manifest on a version with a higher sequence.
    let bad = with_changed_signature(statement_for(PRIMARY_ID, &chain.heads_again, 9));
    rig.serve(&chain.heads_again, bad);
    refused(&rig, &admission, &chain.heads_again, "LF8", "bad-signature", "BadSignature").await;
    rig.serve(&chain.heads_again, statement_for("test-publication-3", &chain.heads_again, 9));
    refused(&rig, &admission, &chain.heads_again, "LF9", "unknown-key", "UnknownKey").await;
    rig.serve(&chain.heads_again, statement_for(PRIMARY_ID, &chain.full, 9));
    refused(&rig, &admission, &chain.heads_again, "LF10", "statement-for-another-manifest", "StatementManifest").await;

    // A signed version whose ORIGINAL is not the tier pin.
    let foreign = version("heads", &sha256_hex(b"other"), &sha256_hex(b"other"), "foreign");
    rig.serve(&foreign, statement_for(PRIMARY_ID, &foreign, 9));
    refused(&rig, &admission, &foreign, "LF11", "wrong-original", "WrongOriginal").await;

    // The mark still names FULL: the next honest version is accepted.
    assert_eq!(rig.high_water().unwrap(), full);
    let next = statement_for(PRIMARY_ID, &chain.heads_again, 3);
    rig.serve(&chain.heads_again, next.clone());
    rig.fetch(&admission).await.unwrap().unwrap();
    assert_eq!(rig.high_water().unwrap(), next);
    rig.stop();
}

#[tokio::test]
async fn a_restart_reverifies_the_persisted_mark_and_the_cached_statements() {
    let mut rig = rig().await;
    let admission = rig.admission(test_keys::key_set());
    let chain = chain();
    rig.serve(&chain.pin, Vec::new());
    rig.fetch(&admission).await.unwrap().unwrap();
    let heads = statement_for(PRIMARY_ID, &chain.heads, 1);
    rig.serve(&chain.heads, heads.clone());
    rig.fetch(&admission).await.unwrap().unwrap();

    // A new process: the mark and the cached versions are read again from disk and verified under the compiled keys.
    let restarted = rig.admission(test_keys::key_set());
    verify_package(&rig.version_directory(&chain.heads), MODEL, &restarted).unwrap();
    let stale = verify_package(&rig.version_directory(&chain.pin), MODEL, &restarted).unwrap_err();
    record("LF12", "cached-unsigned-original-after-a-signed-version", "refused", "refused", lineage_reason(&stale));
    assert_eq!(lineage_reason(&stale), "Downgrade", "{stale}");

    // A client that dropped the key refuses the persisted state (fail closed) rather than forgetting the mark.
    let dropped = rig.admission(publication::KeySet::new());
    let error = verify_package(&rig.version_directory(&chain.heads), MODEL, &dropped).unwrap_err();
    assert!(error.to_string().contains("does not verify") || lineage_reason(&error) == "UnknownKey", "{error}");

    // A tampered mark does not verify: every version of the model is refused until the record is removed.
    let mark = rig.model_directory().join(HIGH_WATER_FILE);
    let forged = with_changed_signature(heads.clone());
    std::fs::write(&mark, &forged).unwrap();
    rig.serve(&chain.heads, heads.clone());
    let error = rig.fetch(&restarted).await.expect_err("a tampered mark");
    record("LF13", "tampered-high-water-record", "refused", "refused", lineage_reason(&error));
    assert_eq!(lineage_reason(&error), "HighWater", "{error}");

    // A mark that is not a statement of this model is refused too.
    std::fs::write(&mark, b"not a statement").unwrap();
    assert!(rig.fetch(&restarted).await.is_err());

    // Without a mark the floor is rebuilt from the cached statements that still verify: a deleted mark reopens nothing.
    std::fs::remove_file(&mark).unwrap();
    rig.serve(&chain.pin, Vec::new());
    let error = rig.fetch(&restarted).await.expect_err("a deleted mark");
    record("LF15", "deleted-mark-rebuilt-from-the-cache", "refused", "refused", lineage_reason(&error));
    assert_eq!(lineage_reason(&error), "Downgrade", "{error}");
    // A replay of the cached version's own lower sequence is refused against the rebuilt floor too.
    let full = statement_for(PRIMARY_ID, &chain.full, 5);
    rig.serve(&chain.full, full.clone());
    rig.fetch(&restarted).await.unwrap().unwrap();
    std::fs::remove_file(&mark).unwrap();
    rig.serve(&chain.heads, heads.clone());
    let error = rig.fetch(&restarted).await.expect_err("a replay after a deleted mark");
    assert_eq!(lineage_reason(&error), "Replay", "{error}");

    // Only an empty model cache is trust on first use (documented): the unsigned pinned ORIGINAL is admitted again.
    std::fs::remove_dir_all(rig.model_directory()).unwrap();
    rig.serve(&chain.pin, Vec::new());
    rig.fetch(&restarted).await.unwrap().unwrap();
    rig.stop();
}

#[tokio::test]
async fn a_mark_under_a_dropped_key_is_a_floor_that_a_current_key_must_clear() {
    let mut rig = rig().await;
    let chain = chain();
    let old_keys = test_keys::primary_only();
    let new_keys = publication::KeySet::new().with(SECONDARY_ID, publication::public_key(&test_keys::seed(SECONDARY_ID)).unwrap());
    let old = rig.admission(old_keys);
    rig.serve(&chain.heads, statement_for(PRIMARY_ID, &chain.heads, 3));
    rig.fetch(&old).await.unwrap().unwrap();

    // The client now compiles only the second key. The old mark is a floor, not a brick.
    let current = rig.admission(new_keys);
    // A deleted mark is rebuilt as a floor from the cached statement even though its key is gone (it cannot be verified, so it only
    // raises the floor): the model does not fall back to trust on first use.
    std::fs::remove_file(rig.model_directory().join(HIGH_WATER_FILE)).unwrap();
    assert_eq!(current.cache().read_high_water(MODEL).unwrap().unwrap().sequence, 3);
    // The version signed under the dropped key is refused (unknown key) ...
    let error = rig.fetch(&current).await.expect_err("the dropped key");
    assert_eq!(lineage_reason(&error), "UnknownKey", "{error}");
    // ... a new-key statement at or below the floor is a replay ...
    rig.serve(&chain.full, statement_for(SECONDARY_ID, &chain.full, 2));
    let error = rig.fetch(&current).await.expect_err("below the floor");
    assert_eq!(lineage_reason(&error), "Replay", "{error}");
    record("LF16", "mark-under-a-dropped-key-is-a-floor", "refused", "refused", lineage_reason(&error));
    // ... and one above it is admitted and replaces the mark.
    let next = statement_for(SECONDARY_ID, &chain.full, 4);
    rig.serve(&chain.full, next.clone());
    rig.fetch(&current).await.unwrap().unwrap();
    assert_eq!(rig.high_water().unwrap(), next);
    rig.stop();
}

#[tokio::test]
async fn an_unavailable_server_is_transient_and_changes_nothing() {
    let mut rig = rig().await;
    let admission = rig.admission(test_keys::key_set());
    let chain = chain();
    let heads = statement_for(PRIMARY_ID, &chain.heads, 1);
    rig.serve(&chain.heads, heads.clone());
    rig.fetch(&admission).await.unwrap().unwrap();
    let before = names(&rig.model_directory());

    rig.serving.lock().unwrap().unavailable = true;
    let error = rig.fetch(&admission).await.unwrap_err();
    assert!(error.is_transient(), "{error}");
    record("LF14", "unavailable-is-transient", "refused", "refused", "Transient");
    assert_eq!(rig.high_water().unwrap(), heads);
    assert_eq!(names(&rig.model_directory()), before);

    // A refusal by the rule is not transient.
    rig.serving.lock().unwrap().unavailable = false;
    rig.serve(&chain.pin, Vec::new());
    let error = rig.fetch(&admission).await.unwrap_err();
    assert!(!error.is_transient(), "{error}");

    rig.serve(&chain.heads, heads);
    rig.fetch(&admission).await.unwrap().unwrap();
    rig.stop();
}

#[tokio::test]
async fn a_statement_that_changes_during_the_download_is_not_admitted() {
    let mut rig = rig().await;
    let admission = rig.admission(test_keys::key_set());
    let chain = chain();
    rig.serve(&chain.heads, statement_for(PRIMARY_ID, &chain.heads, 1));
    rig.serving.lock().unwrap().later_statement = Some(statement_for(PRIMARY_ID, &chain.heads, 2));
    let error = rig.fetch(&admission).await.unwrap_err();
    assert!(error.to_string().contains("changed while assets were downloaded"), "{error}");
    assert!(rig.high_water().is_none(), "no mark is written for a package that was not admitted");
    assert!(!rig.version_directory(&chain.heads).join("manifest.json").exists());
    rig.stop();
}

// ---------------------------------------------------------------------------------------------------------------------------
// Stage V3-R4b: refresh, offline start-up, garbage collection, the signed mark against the cache, and the advisory lock.
// ---------------------------------------------------------------------------------------------------------------------------

async fn wait_for(what: &str, mut condition: impl FnMut() -> bool) {
    for _ in 0..300 {
        if condition() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("timed out waiting for {what}");
}

impl Rig {
    /// One refresh through `refresher` against the scripted server.
    async fn refresh(&self, refresher: &Refresher) -> Refreshed {
        let channel = self.endpoint.connect(Duration::from_secs(10)).await.unwrap();
        refresher.refresh(channel, &self.endpoint.target, MODEL).await
    }
}

#[tokio::test]
async fn a_published_candidate_replaces_the_cached_snapshot_after_the_interval() {
    let mut rig = rig().await;
    let chain = chain();
    let keys = test_keys::key_set();
    let admission = rig.admission(keys.clone());
    let refresher = Arc::new(Refresher::new(rig.admission(keys), rig.config()));
    rig.serve(&chain.pin, Vec::new());

    let (endpoint, interval) = (rig.endpoint.clone(), Duration::from_millis(1500));
    let task = {
        let refresher = Arc::clone(&refresher);
        tokio::spawn(async move { refresher.run(&endpoint, &[MODEL.to_string()], interval, Duration::from_secs(10)).await })
    };
    // The start-up refresh caches the unsigned pinned release, which is what a worker serves.
    wait_for("the start-up refresh", || admission.current_version(MODEL).as_deref() == Some(chain.pin.sha.as_str())).await;

    // The candidate is published; before the interval elapses the snapshot is unchanged ...
    let heads = statement_for(PRIMARY_ID, &chain.heads, 1);
    rig.serve(&chain.heads, heads.clone());
    let published = std::time::Instant::now();
    // ... and after it the signed candidate is the current version of the cache, with its statement and as the mark. The change
    // is the next tick's: the tick is 1.5 s after the start-up refresh, which was a fraction of a second ago.
    wait_for("the refresh after the interval", || admission.current_version(MODEL).as_deref() == Some(chain.heads.sha.as_str())).await;
    assert!(published.elapsed() >= interval / 3, "the candidate was admitted before the interval: {:?}", published.elapsed());
    assert_eq!(rig.high_water().unwrap(), heads);
    let selected = admission.cache().select(MODEL).unwrap().unwrap();
    assert_eq!(selected.statement, heads);
    assert!(selected.directory.ends_with(&chain.heads.sha));
    task.abort();
    record("RB1", "candidate-replaces-the-snapshot-after-the-interval", "accepted", "accepted", "");
    rig.stop();
}

#[tokio::test]
async fn an_offline_restart_serves_the_high_water_version() {
    let mut rig = rig().await;
    let chain = chain();
    let admission = rig.admission(test_keys::key_set());
    rig.serve(&chain.pin, Vec::new());
    rig.fetch(&admission).await.unwrap().unwrap();
    rig.serve(&chain.heads, statement_for(PRIMARY_ID, &chain.heads, 1));
    rig.fetch(&admission).await.unwrap().unwrap();
    let full = statement_for(PRIMARY_ID, &chain.full, 2);
    rig.serve(&chain.full, full.clone());
    rig.fetch(&admission).await.unwrap().unwrap();
    // The cache holds all three versions; the server now cannot be asked.
    assert!(rig.version_directory(&chain.pin).is_dir() && rig.version_directory(&chain.heads).is_dir());
    rig.serving.lock().unwrap().unavailable = true;

    // A new process over the same cache.
    let restarted = rig.admission(test_keys::key_set());
    let refresher = Refresher::new(restarted.clone(), rig.config());
    let outcome = rig.refresh(&refresher).await;
    assert!(matches!(outcome, Refreshed::Offline(_)), "{outcome:?}");
    let selected = restarted.cache().select(MODEL).unwrap().unwrap();
    assert_eq!(selected.manifest_sha, chain.full.sha, "the version at the mark, not the pin and not another directory");
    assert_eq!(selected.statement, full);
    verify_package(&selected.directory, MODEL, &restarted).unwrap();
    assert_eq!(rig.high_water().unwrap(), full);

    // The whole server gone: the answer is the same.
    rig.stop();
    tokio::time::sleep(Duration::from_millis(200)).await;
    let again = restarted.cache().select(MODEL).unwrap().unwrap();
    assert_eq!(again, selected);
    record("RB2", "offline-restart-serves-the-high-water-version", "accepted", "accepted", "");
}

#[tokio::test]
async fn garbage_collection_never_removes_the_pin_or_the_current_version() {
    let mut rig = rig().await;
    let chain = chain();
    let keys = test_keys::key_set();
    let refresher = Refresher::new(rig.admission(keys.clone()), rig.config());
    let admission = rig.admission(keys);

    rig.serve(&chain.pin, Vec::new());
    assert!(matches!(rig.refresh(&refresher).await, Refreshed::Updated { from: None, .. }));
    rig.serve(&chain.heads, statement_for(PRIMARY_ID, &chain.heads, 1));
    assert!(matches!(rig.refresh(&refresher).await, Refreshed::Updated { .. }));
    // The mark moves to FULL: HEADS is superseded and goes; the pin and FULL stay.
    rig.serve(&chain.full, statement_for(PRIMARY_ID, &chain.full, 2));
    match rig.refresh(&refresher).await {
        Refreshed::Updated { from, to, removed } => {
            assert_eq!((from.as_deref(), to.as_str()), (Some(chain.heads.sha.as_str()), chain.full.sha.as_str()));
            assert_eq!(removed, vec![chain.heads.sha.clone()]);
        }
        other => panic!("{other:?}"),
    }
    assert!(!rig.version_directory(&chain.heads).exists());
    assert!(rig.version_directory(&chain.pin).is_dir() && rig.version_directory(&chain.full).is_dir());

    // A download in progress (no statement) is not superseded.
    let partial = rig.model_directory().join(sha256_hex(b"partial"));
    std::fs::create_dir_all(&partial).unwrap();
    assert!(admission.collect_garbage(MODEL).unwrap().is_empty());
    assert!(partial.is_dir());

    // Another trained version, then a signed rollback to the pin: the pin is the current version and is kept.
    rig.serve(&chain.heads_again, statement_for(PRIMARY_ID, &chain.heads_again, 3));
    assert!(matches!(rig.refresh(&refresher).await, Refreshed::Updated { .. }));
    assert!(!rig.version_directory(&chain.full).exists(), "FULL is superseded by sequence 3");
    let rollback = statement_for(PRIMARY_ID, &chain.pin, 4);
    rig.serve(&chain.pin, rollback.clone());
    assert!(matches!(rig.refresh(&refresher).await, Refreshed::Updated { .. }));
    assert!(!rig.version_directory(&chain.heads_again).exists());
    assert!(rig.version_directory(&chain.pin).is_dir(), "the pin is never collected");
    let selected = admission.cache().select(MODEL).unwrap().unwrap();
    assert_eq!((selected.manifest_sha.as_str(), selected.statement), (chain.pin.sha.as_str(), rollback));
    assert!(partial.is_dir());

    // A collected version can be published again: it is fetched in full by the same fetcher.
    rig.serve(&chain.heads, statement_for(PRIMARY_ID, &chain.heads, 5));
    assert!(matches!(rig.refresh(&refresher).await, Refreshed::Updated { .. }));
    assert_eq!(admission.current_version(MODEL).as_deref(), Some(chain.heads.sha.as_str()));
    assert!(rig.version_directory(&chain.pin).is_dir(), "the pin survives the next collection too");
    verify_package(&rig.version_directory(&chain.heads), MODEL, &admission).unwrap();
    record("RB3", "garbage-collection-keeps-the-pin-and-the-current-version", "accepted", "accepted", "");
    rig.stop();
}

#[tokio::test]
async fn a_client_with_a_signed_mark_never_selects_the_unsigned_pin_or_a_lower_version_from_the_cache() {
    let mut rig = rig().await;
    let chain = chain();
    let admission = rig.admission(test_keys::key_set());
    let heads = statement_for(PRIMARY_ID, &chain.heads, 1);
    let full = statement_for(PRIMARY_ID, &chain.full, 2);
    rig.serve(&chain.pin, Vec::new());
    rig.fetch(&admission).await.unwrap().unwrap();
    // First start: no mark, so the cache selects the pinned release.
    let first = admission.cache().select(MODEL).unwrap().unwrap();
    assert_eq!((first.manifest_sha.as_str(), first.statement.is_empty()), (chain.pin.sha.as_str(), true));
    rig.serve(&chain.heads, heads.clone());
    rig.fetch(&admission).await.unwrap().unwrap();
    rig.serve(&chain.full, full.clone());
    rig.fetch(&admission).await.unwrap().unwrap();

    let cache = admission.cache();
    assert_eq!(cache.select(MODEL).unwrap().unwrap().manifest_sha, chain.full.sha);
    // The loader's admission of each cached version: only the one at the mark passes.
    let error = verify_package(&rig.version_directory(&chain.pin), MODEL, &admission).unwrap_err();
    record("RB4", "signed-mark-refuses-the-unsigned-pin-from-the-cache", "refused", "refused", lineage_reason(&error));
    assert_eq!(lineage_reason(&error), "Downgrade", "{error}");
    let error = verify_package(&rig.version_directory(&chain.heads), MODEL, &admission).unwrap_err();
    assert_eq!(lineage_reason(&error), "Replay", "{error}");
    verify_package(&rig.version_directory(&chain.full), MODEL, &admission).unwrap();

    // Every way of damaging the version at the mark is an error, never a fallback to another cached version.
    let statement_path = rig.version_directory(&chain.full).join(STATEMENT_FILE);
    std::fs::write(&statement_path, &heads).unwrap();
    assert!(cache.select(MODEL).unwrap_err().to_string().contains("does not carry the statement"));
    std::fs::remove_file(&statement_path).unwrap();
    assert!(cache.select(MODEL).is_err());
    std::fs::write(&statement_path, &full).unwrap();
    assert_eq!(cache.select(MODEL).unwrap().unwrap().manifest_sha, chain.full.sha);
    // A deleted mark is rebuilt from the cached statements: the selection does not move to the pin.
    std::fs::remove_file(rig.model_directory().join(HIGH_WATER_FILE)).unwrap();
    assert_eq!(cache.select(MODEL).unwrap().unwrap().manifest_sha, chain.full.sha);
    // A tampered mark refuses the whole model.
    std::fs::write(rig.model_directory().join(HIGH_WATER_FILE), with_changed_signature(full.clone())).unwrap();
    assert!(cache.select(MODEL).is_err());
    std::fs::write(rig.model_directory().join(HIGH_WATER_FILE), &full).unwrap();
    // The version at the mark is gone: an error that the next refresh repairs, not a fallback.
    let moved = rig.model_directory().join("moved");
    std::fs::rename(rig.version_directory(&chain.full), &moved).unwrap();
    assert!(cache.select(MODEL).unwrap_err().to_string().contains("is not in the cache"));
    std::fs::rename(&moved, rig.version_directory(&chain.full)).unwrap();
    assert_eq!(cache.select(MODEL).unwrap().unwrap().statement, full);
    rig.stop();
}

fn synthetic_writes(count: u64) -> Vec<(AdmittedManifest, Vec<u8>)> {
    (1..=count)
        .map(|sequence| {
            let sha = sha256_hex(format!("version {sequence}").as_bytes());
            let statement = Statement {
                key_id: PRIMARY_ID.to_string(),
                model_id: MODEL.to_string(),
                manifest_sha: sha.clone(),
                parent: String::new(),
                original: String::new(),
                sequence,
            };
            (
                AdmittedManifest { model_id: MODEL.to_string(), pin: sha, assets: BTreeMap::new() },
                publication::sign(&test_keys::seed(PRIMARY_ID), &statement).unwrap(),
            )
        })
        .collect()
}

/// The version directories of the synthetic writes (a writer of the mark requires the version to be in the cache).
fn stage(root: &Path, writes: &[(AdmittedManifest, Vec<u8>)]) {
    for (admitted, _) in writes {
        let directory = root.join(MODEL).join(&admitted.pin);
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::write(directory.join("manifest.json"), b"{}").unwrap();
    }
}

#[test]
fn the_writer_of_the_mark_waits_for_the_advisory_lock_and_reads_the_mark_again_under_it() {
    let cache = tempfile::tempdir().unwrap();
    let admission = LineageAdmission::new(test_keys::key_set(), cache.path());
    let writes = synthetic_writes(7);
    stage(cache.path(), &writes);
    let mark = cache.path().join(MODEL).join(HIGH_WATER_FILE);
    let guard = admission.cache().lock(MODEL).unwrap();
    let (done, finished) = std::sync::mpsc::channel();
    let writer = admission.clone();
    let low = writes[2].clone();
    let handle = std::thread::spawn(move || {
        let outcome = writer.accepted(&low.0, &low.1);
        done.send(()).unwrap();
        outcome
    });
    assert!(finished.recv_timeout(Duration::from_millis(600)).is_err(), "the writer must wait for the lock");
    assert!(!mark.exists());
    // Meanwhile the holder of the lock (another process) moves the mark to sequence 7.
    std::fs::write(&mark, &writes[6].1).unwrap();
    drop(guard);
    finished.recv_timeout(Duration::from_secs(20)).unwrap();
    let outcome = handle.join().unwrap();
    assert!(matches!(outcome, Err(FetchError::Lineage(LineageError::Replay { seen: 7, got: 3 }))), "{outcome:?}");
    assert_eq!(std::fs::read(&mark).unwrap(), writes[6].1, "the mark was lowered");
    assert!(!cache.path().join(MODEL).join(&writes[2].0.pin).join(STATEMENT_FILE).exists(), "a refused statement is not kept");
    record("RB5", "concurrent-writers-cannot-lower-the-mark", "accepted", "accepted", "");
}

#[test]
fn a_version_that_left_the_cache_is_not_recorded() {
    let cache = tempfile::tempdir().unwrap();
    let admission = LineageAdmission::new(test_keys::key_set(), cache.path());
    let writes = synthetic_writes(2);
    stage(cache.path(), &writes);
    // Another process's garbage collection removed the version between this fetch's verification and the record.
    std::fs::remove_dir_all(cache.path().join(MODEL).join(&writes[1].0.pin)).unwrap();
    let error = admission.accepted(&writes[1].0, &writes[1].1).unwrap_err();
    assert!(error.to_string().contains("no longer in the cache"), "{error}");
    assert!(!cache.path().join(MODEL).join(HIGH_WATER_FILE).exists());
    admission.accepted(&writes[0].0, &writes[0].1).unwrap();
}

#[test]
fn many_concurrent_writers_never_lower_the_mark() {
    use std::sync::atomic::{AtomicU64, Ordering};

    let cache = tempfile::tempdir().unwrap();
    let keys = test_keys::key_set();
    let writes = synthetic_writes(60);
    stage(cache.path(), &writes);
    let acknowledged = AtomicU64::new(0);
    let barrier = std::sync::Barrier::new(3);
    std::thread::scope(|scope| {
        let ascending: Vec<usize> = (0..writes.len()).collect();
        let descending: Vec<usize> = (0..writes.len()).rev().collect();
        for order in [ascending, descending] {
            scope.spawn(|| {
                // Each writer is its own admission, as another process would be.
                let admission = LineageAdmission::new(keys.clone(), cache.path());
                barrier.wait();
                for index in order {
                    let (admitted, statement) = &writes[index];
                    if admission.accepted(admitted, statement).is_ok() {
                        acknowledged.fetch_max(index as u64 + 1, Ordering::SeqCst);
                    }
                }
            });
        }
        scope.spawn(|| {
            let view = ModelCache::new(cache.path(), CacheRules::new(keys.clone()));
            barrier.wait();
            let mut seen = 0;
            for _ in 0..3000 {
                if let Ok(Some(mark)) = view.read_high_water(MODEL) {
                    assert!(mark.sequence >= seen, "the mark was lowered from {seen} to {}", mark.sequence);
                    seen = mark.sequence;
                }
            }
        });
    });
    let view = ModelCache::new(cache.path(), CacheRules::new(keys));
    let last = view.read_high_water(MODEL).unwrap().unwrap().sequence;
    assert!(last >= acknowledged.load(Ordering::SeqCst) && last == 60, "mark {last}");
}

#[tokio::test]
async fn a_version_served_again_under_a_higher_sequence_stays_selectable() {
    let mut rig = rig().await;
    let chain = chain();
    let keys = test_keys::key_set();
    let refresher = Refresher::new(rig.admission(keys.clone()), rig.config());
    let admission = rig.admission(keys);
    rig.serve(&chain.full, statement_for(PRIMARY_ID, &chain.full, 2));
    assert!(matches!(rig.refresh(&refresher).await, Refreshed::Updated { .. }));
    let selectable = || admission.cache().select(MODEL).unwrap().unwrap().manifest_sha == chain.full.sha;
    assert!(selectable());

    // The window of the record: the statement of the new sequence is beside the version, the mark is not yet there.
    let higher = statement_for(PRIMARY_ID, &chain.full, 3);
    std::fs::write(rig.version_directory(&chain.full).join(STATEMENT_FILE), &higher).unwrap();
    assert!(selectable(), "a statement above the mark for the same manifest keeps the version selectable");
    verify_package(&rig.version_directory(&chain.full), MODEL, &admission).unwrap();

    // The whole refresh: the same version under sequence 3 (the statement is written, then the mark).
    rig.serve(&chain.full, higher.clone());
    assert!(matches!(rig.refresh(&refresher).await, Refreshed::Unchanged { .. }));
    assert!(selectable());
    assert_eq!(rig.high_water().unwrap(), higher);

    // A refused re-serve (a lower sequence) leaves the statement and the selection as they were.
    rig.serve(&chain.full, statement_for(PRIMARY_ID, &chain.full, 2));
    assert!(matches!(rig.refresh(&refresher).await, Refreshed::Refused(_)));
    assert!(selectable());
    assert_eq!(std::fs::read(rig.version_directory(&chain.full).join(STATEMENT_FILE)).unwrap(), higher);
    rig.stop();
}
