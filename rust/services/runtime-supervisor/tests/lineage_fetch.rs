//! The supervisor fetch with `LineageAdmission` (stage V3-R4a): a scripted model-streaming server serves a synthetic chain
//! (a pinned ORIGINAL, HEADS and FULL versions, a rollback, a second-key version) whose manifests satisfy the manifest contract on
//! the efficient tier with the official `config.json` and `vocab.txt` (fixtures of param-update) and stand-in weights. The synthetic
//! ORIGINAL is the tier pin of the admission under test. Every rule is exercised through the real `Fetcher`, with the high-water
//! mark and the statements persisted in the cache and re-verified by a fresh fetcher (a restart).
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
use privoke_contracts::proto::v1::model_streaming_service_server::{ModelStreamingService, ModelStreamingServiceServer};
use privoke_contracts::proto::v1::{
    HealthRequest, HealthResponse, ModelAssetChunk, ModelAssetRequest, ModelPackageAsset, ModelPackageResponse, ModelParameterChunk,
    ModelParametersRequest, ModelParametersResponse,
};
use privoke_contracts::publication::test_keys::{self, PRIMARY_ID, SECONDARY_ID};
use privoke_contracts::publication::{self, Statement};
use privoke_contracts::v3::{self, LineageError};
use privoke_supervisor::channel::ModelEndpoint;
use privoke_supervisor::fetch::{
    ASSETS, FetchConfig, FetchError, Fetcher, HIGH_WATER_FILE, LineageAdmission, STATEMENT_FILE, verify_package,
};
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
    let pin = version("heads", &sha256_hex(b"root"), &sha256_hex(b"root"), "pin");
    let heads = version("heads", &pin.sha, &pin.sha, "heads");
    let full = version("full_encoder", &heads.sha, &pin.sha, "full");
    let heads_again = version("heads", &pin.sha, &pin.sha, "heads-again");
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
        LineageAdmission::new(keys, self.cache.path()).with_pins(BTreeMap::from([(MODEL.to_string(), self.chain.pin.sha.clone())]))
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
    let mut bad = statement_for(PRIMARY_ID, &chain.heads_again, 9);
    let flipped = if bad[bad.len() - 4] == b'0' { b'1' } else { b'0' };
    let position = bad.len() - 4;
    bad[position] = flipped;
    rig.serve(&chain.heads_again, bad);
    refused(&rig, &admission, &chain.heads_again, "LF8", "bad-signature", "BadSignature").await;
    rig.serve(&chain.heads_again, statement_for("test-publication-3", &chain.heads_again, 9));
    refused(&rig, &admission, &chain.heads_again, "LF9", "unknown-key", "UnknownKey").await;
    rig.serve(&chain.heads_again, statement_for(PRIMARY_ID, &chain.full, 9));
    let error = rig.fetch(&admission).await.expect_err("a statement for another manifest");
    record("LF10", "statement-for-another-manifest", "refused", "refused", "StatementManifest");
    assert!(error.to_string().contains("another manifest"), "{error}");

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
    let mut forged = heads.clone();
    let position = forged.len() - 4;
    forged[position] = if forged[position] == b'0' { b'1' } else { b'0' };
    std::fs::write(&mark, &forged).unwrap();
    rig.serve(&chain.heads, heads.clone());
    let error = rig.fetch(&restarted).await.expect_err("a tampered mark");
    record("LF13", "tampered-high-water-record", "refused", "refused", lineage_reason(&error));
    assert_eq!(lineage_reason(&error), "HighWater", "{error}");

    // A mark that is not a statement of this model is refused too.
    std::fs::write(&mark, b"not a statement").unwrap();
    assert!(rig.fetch(&restarted).await.is_err());

    // Without a mark (a wiped cache) the unsigned pinned ORIGINAL is trusted once again: trust on first use, documented.
    std::fs::remove_file(&mark).unwrap();
    rig.serve(&chain.pin, Vec::new());
    rig.fetch(&restarted).await.unwrap().unwrap();
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
