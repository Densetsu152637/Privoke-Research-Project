//! Model fetch: the supervisor downloads the package over mutual TLS, checks the pins and writes the user cache.
//!
//! Two kinds of test. The end-to-end ones run the real Rust model-streaming service in-process on certificates
//! generated for the test and fetch the real pinned standard releases (read from the main checkout, skipped when the
//! ignored `models/standard-releases` are not present). The tamper ones use a scripted server and a synthetic pin set,
//! so each rule of the fetch can be broken on its own: every one must end with an error and leave no final file that a
//! reader could load.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::pki::{TestPki, release_dir};
use privoke_contracts::digest::sha256_hex;
use privoke_contracts::proto::v1::model_streaming_service_server::{ModelStreamingService, ModelStreamingServiceServer};
use privoke_contracts::proto::v1::{
    HealthRequest, HealthResponse, ModelAssetChunk, ModelAssetRequest, ModelPackageAsset, ModelPackageResponse, ModelParameterChunk,
    ModelParametersRequest, ModelParametersResponse,
};
use privoke_contracts::v3;
use privoke_supervisor::channel::ModelEndpoint;
use privoke_supervisor::fetch::{
    Admission, AdmittedManifest, FetchConfig, FetchError, Fetcher, StandardAdmission, digest_file, verify_package,
};
use privoke_transport::listener::loopback::LoopbackListener;
use tokio_stream::Stream;
use tonic::{Request, Response, Status};

const ASSETS: [&str; 4] = ["model.safetensors", "config.json", "vocab.txt", "evidence.json"];

fn config(cache: &Path, consumer_id: &str) -> FetchConfig {
    FetchConfig {
        consumer_id: consumer_id.into(),
        rpc_timeout: Duration::from_secs(20),
        download_timeout: Duration::from_secs(60),
        cache_root: cache.to_path_buf(),
    }
}

// ---------------------------------------------------------------------------------------------------------------
// End to end against the real service and the real pinned releases.
// ---------------------------------------------------------------------------------------------------------------

fn source_dir(releases: &Path, model: &str) -> PathBuf {
    releases.join(model)
}

fn assert_cache_equals_release(cache: &Path, releases: &Path, model: &str) {
    let pin = v3::standard_pin(model).unwrap();
    let directory = cache.join(model).join(pin);
    for name in ["manifest.json", "model.safetensors", "config.json", "vocab.txt", "evidence.json"] {
        assert_eq!(
            digest_file(&directory.join(name)).unwrap(),
            digest_file(&source_dir(releases, model).join(name)).unwrap(),
            "{model}/{name}"
        );
    }
    assert_eq!(digest_file(&directory.join("manifest.json")).unwrap(), pin);
    let leftovers: Vec<_> = std::fs::read_dir(&directory)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with('.'))
        .collect();
    assert!(leftovers.is_empty(), "temporary files left behind: {leftovers:?}");
}

#[tokio::test]
async fn the_pinned_package_is_fetched_over_mutual_tls_verified_and_cached() {
    let Some(releases) = release_dir() else {
        eprintln!("the prepared standard releases are not available; skipped");
        return;
    };
    let pki = TestPki::new();
    let installation = pki.consumer("alice");
    let server = pki.start_server(Some(&releases)).await;
    let endpoint = ModelEndpoint::mutual_tls(&server.public_addr.to_string(), pki.tls(&installation)).unwrap();
    let cache = tempfile::tempdir().unwrap();
    let cache_root = cache.path().to_path_buf();

    let fetcher = Fetcher::new();
    let channel = endpoint.connect(Duration::from_secs(10)).await.unwrap();
    let package = fetcher
        .fetch(channel, &endpoint.target, "privoke-v3-efficient", &StandardAdmission, &config(&cache_root, &installation.id))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(package.model_id, "privoke-v3-efficient");
    assert_eq!(package.pin, v3::standard_pin("privoke-v3-efficient").unwrap());
    assert_eq!(package.directory, std::path::absolute(cache_root.join("privoke-v3-efficient").join(&package.pin)).unwrap());
    assert_cache_equals_release(&cache_root, &releases, "privoke-v3-efficient");

    // The same fetcher: the admitted package is only re-checked by its manifest.
    let channel = endpoint.connect(Duration::from_secs(10)).await.unwrap();
    let again = fetcher
        .fetch(channel, &endpoint.target, "privoke-v3-efficient", &StandardAdmission, &config(&cache_root, &installation.id))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(again, package);

    // A fresh fetcher (a restart): the existing files are re-hashed, not trusted, and not downloaded again.
    let weights = package.directory.join("model.safetensors");
    let modified = std::fs::metadata(&weights).unwrap().modified().unwrap();
    let channel = endpoint.connect(Duration::from_secs(10)).await.unwrap();
    let restarted = Fetcher::new()
        .fetch(channel, &endpoint.target, "privoke-v3-efficient", &StandardAdmission, &config(&cache_root, &installation.id))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(restarted, package);
    assert_eq!(std::fs::metadata(&weights).unwrap().modified().unwrap(), modified, "a verified asset is not downloaded again");
    verify_package(&package.directory, "privoke-v3-efficient", &StandardAdmission).unwrap();

    // `latest` resolves to the balanced tier, and an empty consumer id is accepted.
    let channel = endpoint.connect(Duration::from_secs(10)).await.unwrap();
    let latest =
        Fetcher::new().fetch(channel, &endpoint.target, "latest", &StandardAdmission, &config(&cache_root, "")).await.unwrap().unwrap();
    assert_eq!(latest.model_id, "privoke-v3-balanced");
    assert_cache_equals_release(&cache_root, &releases, "privoke-v3-balanced");
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn a_corrupted_cached_asset_is_an_error_and_is_never_overwritten() {
    let Some(releases) = release_dir() else {
        eprintln!("the prepared standard releases are not available; skipped");
        return;
    };
    let pki = TestPki::new();
    let installation = pki.consumer("alice");
    let server = pki.start_server(Some(&releases)).await;
    let endpoint = ModelEndpoint::mutual_tls(&server.public_addr.to_string(), pki.tls(&installation)).unwrap();
    let cache = tempfile::tempdir().unwrap();
    let cache_root = cache.path().to_path_buf();
    let channel = endpoint.connect(Duration::from_secs(10)).await.unwrap();
    let package = Fetcher::new()
        .fetch(channel, &endpoint.target, "privoke-v3-efficient", &StandardAdmission, &config(&cache_root, &installation.id))
        .await
        .unwrap()
        .unwrap();

    let vocab = package.directory.join("vocab.txt");
    let mut bytes = std::fs::read(&vocab).unwrap();
    bytes[0] ^= 1;
    std::fs::write(&vocab, &bytes).unwrap();
    let channel = endpoint.connect(Duration::from_secs(10)).await.unwrap();
    let error = Fetcher::new()
        .fetch(channel, &endpoint.target, "privoke-v3-efficient", &StandardAdmission, &config(&cache_root, &installation.id))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("Existing model cache asset is corrupted"), "{error}");
    assert_eq!(std::fs::read(&vocab).unwrap(), bytes, "the corrupted file is left for the user to look at, not silently replaced");
    assert!(verify_package(&package.directory, "privoke-v3-efficient", &StandardAdmission).is_err());
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn the_server_binds_the_caller_and_the_registry_decides_who_may_fetch() {
    let Some(releases) = release_dir() else {
        eprintln!("the prepared standard releases are not available; skipped");
        return;
    };
    let pki = TestPki::new();
    let registered = pki.consumer("alice");
    let unregistered = pki.installation("mallory", &pki.client_ca, false);
    let foreign = pki.installation("eve", &pki.foreign_ca, false);
    let server = pki.start_server(Some(&releases)).await;
    let address = server.public_addr.to_string();
    let cache = tempfile::tempdir().unwrap();

    // Another identity in `consumer_id`: the Python default "client-runtime" is refused by the Rust service.
    let endpoint = ModelEndpoint::mutual_tls(&address, pki.tls(&registered)).unwrap();
    let channel = endpoint.connect(Duration::from_secs(10)).await.unwrap();
    let error =
        Fetcher::new().fetch(channel, &address, "latest", &StandardAdmission, &config(cache.path(), "client-runtime")).await.unwrap_err();
    assert!(matches!(&error, FetchError::Rpc(status) if status.code() == tonic::Code::PermissionDenied), "{error}");

    // Not registered, signed by another CA, and no certificate: all refused, and nothing is written to the cache.
    for tls in [pki.tls(&unregistered), pki.tls(&foreign), privoke_transport::ClientTlsConfig { identity: None, ..pki.tls(&registered) }] {
        let endpoint = ModelEndpoint::mutual_tls(&address, tls).unwrap();
        let outcome = match endpoint.connect(Duration::from_secs(10)).await {
            Ok(channel) => Fetcher::new()
                .fetch(channel, &address, "latest", &StandardAdmission, &config(cache.path(), ""))
                .await
                .map(|_| ())
                .map_err(|e| e.to_string()),
            Err(error) => Err(error.to_string()),
        };
        assert!(outcome.is_err(), "an untrusted identity fetched a package");
    }
    assert_eq!(std::fs::read_dir(cache.path()).unwrap().count(), 0, "a refused fetch writes nothing");
    server.shutdown().await.unwrap();
}

#[test]
fn the_standard_admission_accepts_only_the_pinned_manifests() {
    let Some(releases) = release_dir() else {
        eprintln!("the prepared standard releases are not available; skipped");
        return;
    };
    let manifest = std::fs::read(releases.join("privoke-v3-balanced/manifest.json")).unwrap();
    let admitted = StandardAdmission.admit(&manifest, "latest").unwrap();
    assert_eq!(admitted.model_id, "privoke-v3-balanced");
    assert_eq!(admitted.pin, sha256_hex(&manifest));
    assert_eq!(admitted.assets.len(), 4);
    assert!(StandardAdmission.admit(&manifest, "privoke-v3-balanced").is_ok());
    assert!(StandardAdmission.admit(&manifest, "privoke-v3-quality").is_err(), "a different model than requested");
    let mut tampered = manifest.clone();
    let position = tampered.iter().position(|byte| *byte == b'a').unwrap();
    tampered[position] = b'b';
    assert!(StandardAdmission.admit(&tampered, "latest").is_err(), "a manifest that does not hash to its pin");
    assert!(StandardAdmission.admit(b"{}", "latest").is_err());
    assert!(StandardAdmission.admit(b"", "latest").is_err());
}

// ---------------------------------------------------------------------------------------------------------------
// Tamper tests: a scripted server and a synthetic pin set.
// ---------------------------------------------------------------------------------------------------------------

const MODEL: &str = "test-model";
type Mutator = Box<dyn Fn(&str, Vec<ModelAssetChunk>) -> Vec<ModelAssetChunk> + Send + Sync>;

struct Script {
    manifest: Vec<u8>,
    assets: BTreeMap<String, Vec<u8>>,
    /// The package the server answers with first, if it should differ from the honest one.
    first_package: Option<ModelPackageResponse>,
    /// The package the server answers with on the second call.
    second_package: Option<ModelPackageResponse>,
    mutate_stream: Option<Mutator>,
    package_calls: usize,
    asset_calls: Vec<String>,
    consumers: Vec<String>,
    fail_with: Option<Status>,
}

impl Script {
    fn honest() -> Self {
        let mut assets = BTreeMap::new();
        // 2.5 MiB so the weights cross the 1 MiB chunk boundary twice.
        assets.insert("model.safetensors".to_string(), (0..(2 * 1024 * 1024 + 512 * 1024)).map(|i| (i % 251) as u8).collect::<Vec<u8>>());
        assets.insert("config.json".to_string(), b"{\"hidden_size\":8}".to_vec());
        assets.insert("vocab.txt".to_string(), b"[PAD]\n[UNK]\nhello\n".to_vec());
        assets.insert("evidence.json".to_string(), b"{\"evidence\":true}".to_vec());
        // The manifest is opaque to the server; the synthetic admission reads its asset hashes from this layout.
        let lines: Vec<String> = ASSETS.iter().map(|name| format!("{name}={}", sha256_hex(&assets[*name]))).collect();
        Self {
            manifest: lines.join("\n").into_bytes(),
            assets,
            first_package: None,
            second_package: None,
            mutate_stream: None,
            package_calls: 0,
            asset_calls: Vec::new(),
            consumers: Vec::new(),
            fail_with: None,
        }
    }

    fn package(&self) -> ModelPackageResponse {
        ModelPackageResponse {
            model_id: MODEL.into(),
            architecture: v3::ARCHITECTURE.into(),
            manifest_sha256: sha256_hex(&self.manifest),
            manifest_json: self.manifest.clone(),
            assets: ASSETS
                .iter()
                .map(|name| ModelPackageAsset {
                    name: (*name).into(),
                    sha256: sha256_hex(&self.assets[*name]),
                    size_bytes: self.assets[*name].len() as u64,
                })
                .collect(),
        }
    }
}

struct Fake(Arc<Mutex<Script>>);

type BoxStream<T> = Pin<Box<dyn Stream<Item = Result<T, Status>> + Send>>;

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
        let mut script = self.0.lock().unwrap();
        script.consumers.push(request.get_ref().consumer_id.clone());
        if let Some(status) = script.fail_with.clone() {
            return Err(status);
        }
        script.package_calls += 1;
        let package = match (script.package_calls, &script.first_package, &script.second_package) {
            (1, Some(first), _) => first.clone(),
            (2.., _, Some(second)) => second.clone(),
            _ => script.package(),
        };
        Ok(Response::new(package))
    }
    type StreamModelAssetStream = BoxStream<ModelAssetChunk>;
    async fn stream_model_asset(&self, request: Request<ModelAssetRequest>) -> Result<Response<Self::StreamModelAssetStream>, Status> {
        let mut script = self.0.lock().unwrap();
        let name = request.get_ref().asset_name.clone();
        script.asset_calls.push(name.clone());
        let data = script.assets.get(&name).cloned().ok_or_else(|| Status::not_found("asset"))?;
        let sha = sha256_hex(&data);
        let total = data.len() as u64;
        let mut chunks: Vec<ModelAssetChunk> = data
            .chunks(1024 * 1024)
            .enumerate()
            .map(|(index, block)| ModelAssetChunk {
                model_id: MODEL.into(),
                manifest_sha256: sha256_hex(&script.manifest),
                asset_name: name.clone(),
                sha256: sha.clone(),
                offset: (index * 1024 * 1024) as u64,
                total_bytes: total,
                data: block.to_vec(),
            })
            .collect();
        if let Some(mutate) = &script.mutate_stream {
            chunks = mutate(&name, chunks);
        }
        Ok(Response::new(Box::pin(tokio_stream::iter(chunks.into_iter().map(Ok)))))
    }
}

/// The synthetic pin set: the model `test-model` is pinned to the hash of one particular manifest, whose body lists
/// the hash of each asset as `name=sha`.
struct SyntheticAdmission {
    pin: String,
}

impl Admission for SyntheticAdmission {
    fn admit(&self, manifest_json: &[u8], requested: &str) -> Result<AdmittedManifest, FetchError> {
        if sha256_hex(manifest_json) != self.pin {
            return Err(FetchError::Invalid("Model is not a pinned standard AU3 release".into()));
        }
        if !requested.is_empty() && requested != "latest" && requested != MODEL {
            return Err(FetchError::Invalid("Model package identity differs from request".into()));
        }
        let text = std::str::from_utf8(manifest_json).unwrap();
        let mut assets = BTreeMap::new();
        for line in text.lines() {
            let (name, sha) = line.split_once('=').unwrap();
            let key = ASSETS.iter().find(|candidate| **candidate == name).unwrap();
            assets.insert(*key, sha.to_string());
        }
        Ok(AdmittedManifest { model_id: MODEL.into(), pin: self.pin.clone(), assets })
    }
}

struct Rig {
    script: Arc<Mutex<Script>>,
    endpoint: ModelEndpoint,
    admission: SyntheticAdmission,
    cache: tempfile::TempDir,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
}

async fn rig(script: Script) -> Rig {
    let pin = sha256_hex(&script.manifest);
    let script = Arc::new(Mutex::new(script));
    let listener = LoopbackListener::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let address = listener.local_addr().unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let service = ModelStreamingServiceServer::new(Fake(Arc::clone(&script)));
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
        script,
        endpoint: ModelEndpoint::from_environment(&environment).unwrap(),
        admission: SyntheticAdmission { pin },
        cache: tempfile::tempdir().unwrap(),
        stop: Some(stop),
    }
}

impl Rig {
    async fn fetch(&self, fetcher: &Fetcher) -> Result<Option<privoke_supervisor::fetch::FetchedPackage>, FetchError> {
        let channel = self.endpoint.connect(Duration::from_secs(10)).await.unwrap();
        fetcher.fetch(channel, &self.endpoint.target, "latest", &self.admission, &config(self.cache.path(), "installation-1")).await
    }

    fn directory(&self) -> PathBuf {
        self.cache.path().join(MODEL).join(&self.admission.pin)
    }

    /// Files a loader could pick up: anything under the final names.
    fn visible_files(&self) -> Vec<String> {
        let Ok(entries) = std::fs::read_dir(self.directory()) else { return Vec::new() };
        let mut names: Vec<String> = entries.map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned()).collect();
        names.sort();
        names
    }

    fn stop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
    }
}

async fn expect_rejection(script: Script, needle: &str) -> Rig {
    let rig = rig(script).await;
    let error = rig.fetch(&Fetcher::new()).await.expect_err("a tampered package was accepted");
    assert!(error.to_string().contains(needle), "expected {needle:?}, got {error}");
    assert!(
        !rig.directory().join("manifest.json").exists(),
        "a rejected package must not leave a manifest: it marks the cache as complete"
    );
    let leftovers: Vec<String> = rig.visible_files().into_iter().filter(|name| name.starts_with('.')).collect();
    assert!(leftovers.is_empty(), "temporary files left behind: {leftovers:?}");
    rig
}

#[tokio::test]
async fn an_honest_server_fills_the_cache_exactly_and_the_consumer_id_is_the_one_configured() {
    let mut rig = rig(Script::honest()).await;
    let fetcher = Fetcher::new();
    let package = rig.fetch(&fetcher).await.unwrap().unwrap();
    assert_eq!(package.model_id, MODEL);
    assert_eq!(rig.visible_files(), ["config.json", "evidence.json", "manifest.json", "model.safetensors", "vocab.txt"]);
    verify_package(&package.directory, MODEL, &rig.admission).unwrap();
    {
        let script = rig.script.lock().unwrap();
        assert_eq!(script.package_calls, 2, "the manifest is read before and after the downloads");
        assert_eq!(script.asset_calls.len(), 4);
        assert!(script.consumers.iter().all(|consumer| consumer == "installation-1"));
    }
    // The second fetch with the same fetcher downloads nothing.
    rig.fetch(&fetcher).await.unwrap().unwrap();
    assert_eq!(rig.script.lock().unwrap().asset_calls.len(), 4);
    rig.stop();
}

#[tokio::test]
async fn a_flipped_byte_in_a_stream_is_caught_by_the_asset_hash() {
    let mut script = Script::honest();
    script.mutate_stream = Some(Box::new(|name, mut chunks| {
        if name == "model.safetensors" {
            let last = chunks.last_mut().unwrap();
            last.data[0] ^= 0xff;
        }
        chunks
    }));
    let mut rig = expect_rejection(script, "incomplete or corrupted").await;
    assert!(!rig.directory().join("model.safetensors").exists());
    rig.stop();
}

#[tokio::test]
async fn every_way_a_stream_can_change_identity_order_or_bounds_is_rejected() {
    type Tamper = fn(&mut Vec<ModelAssetChunk>);
    let cases: Vec<(&str, Tamper)> = vec![
        ("model id", |chunks| chunks[0].model_id = "other".into()),
        ("manifest pin", |chunks| chunks[0].manifest_sha256 = "0".repeat(64)),
        ("asset name", |chunks| chunks[0].asset_name = "config.json".into()),
        ("asset sha", |chunks| chunks[0].sha256 = "1".repeat(64)),
        ("offset skipped", |chunks| chunks[1].offset += 1),
        ("chunks swapped", |chunks| chunks.swap(0, 1)),
        ("total bytes", |chunks| chunks[0].total_bytes += 1),
        ("empty chunk", |chunks| chunks[0].data.clear()),
        ("oversized chunk", |chunks| chunks[0].data.extend(std::iter::repeat_n(0u8, 1024 * 1024 + 1))),
        ("data beyond the declared size", |chunks| {
            let extra = chunks.last().unwrap().clone();
            chunks.push(ModelAssetChunk { offset: extra.offset + extra.data.len() as u64, ..extra });
        }),
        ("truncated stream", |chunks| {
            chunks.pop();
        }),
        ("no data at all", |chunks| chunks.clear()),
    ];
    for (label, tamper) in cases {
        let mut script = Script::honest();
        script.mutate_stream = Some(Box::new(move |name, mut chunks| {
            if name == "model.safetensors" {
                tamper(&mut chunks);
            }
            chunks
        }));
        let mut rig = rig(script).await;
        let error = rig.fetch(&Fetcher::new()).await.expect_err(label);
        let text = error.to_string();
        assert!(text.contains("changed identity, order or bounds") || text.contains("incomplete or corrupted"), "{label}: {text}");
        assert!(!rig.directory().join("model.safetensors").exists(), "{label}: a rejected stream must not appear under its final name");
        assert!(!rig.directory().join("manifest.json").exists(), "{label}");
        assert!(rig.visible_files().iter().all(|name| !name.starts_with('.')), "{label}: temporary files left behind");
        rig.stop();
    }
}

#[tokio::test]
async fn a_package_that_does_not_match_its_pin_is_rejected_before_any_download() {
    // The manifest bytes do not hash to the pin the client holds.
    let honest = Script::honest();
    let mut script = Script::honest();
    let mut forged = honest.package();
    forged.manifest_json.push(b'\n');
    script.first_package = Some(forged);
    let mut rig = expect_rejection(script, "not a pinned standard AU3 release").await;
    assert!(rig.script.lock().unwrap().asset_calls.is_empty(), "nothing is downloaded for an unpinned manifest");
    rig.stop();
}

#[tokio::test]
async fn the_response_identity_must_agree_with_the_admitted_manifest() {
    let mut wrong_model = Script::honest();
    let mut package = wrong_model.package();
    package.model_id = "someone-else".into();
    wrong_model.first_package = Some(package);
    expect_rejection(wrong_model, "identity differs from admitted manifest").await.stop_now();

    let mut wrong_pin = Script::honest();
    let mut package = wrong_pin.package();
    package.manifest_sha256 = "2".repeat(64);
    wrong_pin.first_package = Some(package);
    expect_rejection(wrong_pin, "identity differs from admitted manifest").await.stop_now();
}

impl Rig {
    fn stop_now(mut self) {
        self.stop();
    }
}

#[tokio::test]
async fn asset_declarations_must_be_exactly_the_four_pinned_assets() {
    type Case = (&'static str, fn(&mut ModelPackageResponse), &'static str);
    let cases: Vec<Case> = vec![
        ("missing asset", |package| drop(package.assets.pop()), "exactly the declared assets"),
        (
            "extra asset",
            |package| package.assets.push(ModelPackageAsset { name: "extra.bin".into(), sha256: "3".repeat(64), size_bytes: 1 }),
            "exactly the declared assets",
        ),
        ("duplicate asset", |package| package.assets[3] = package.assets[2].clone(), "exactly the declared assets"),
        ("renamed asset", |package| package.assets[0].name = "../model.safetensors".into(), "exactly the declared assets"),
        ("asset hash differs from manifest", |package| package.assets[1].sha256 = "4".repeat(64), "declarations differ"),
        ("zero size", |package| package.assets[1].size_bytes = 0, "declarations differ"),
        ("size beyond the bound", |package| package.assets[0].size_bytes = v3::MAX_BLOB_BYTES + 1, "declarations differ"),
    ];
    for (label, tamper, needle) in cases {
        let mut script = Script::honest();
        let mut package = script.package();
        tamper(&mut package);
        script.first_package = Some(package);
        let mut rig = expect_rejection(script, needle).await;
        assert!(rig.script.lock().unwrap().asset_calls.is_empty(), "{label}: no download for a bad declaration");
        rig.stop();
    }
}

#[tokio::test]
async fn a_manifest_that_changes_during_the_download_is_not_admitted() {
    let honest = Script::honest();
    let mut script = Script::honest();
    let mut changed = honest.package();
    changed.assets[1].size_bytes += 1; // the second answer differs from the first
    script.second_package = Some(changed);
    let mut rig = expect_rejection(script, "changed while assets were downloaded").await;
    // The assets that were downloaded are individually verified, and the cache is still not marked complete.
    assert!(rig.directory().join("model.safetensors").exists());
    // With an honest server the same cache then completes, reusing the verified files.
    rig.script.lock().unwrap().second_package = None;
    let calls_before = rig.script.lock().unwrap().asset_calls.len();
    rig.fetch(&Fetcher::new()).await.unwrap().unwrap();
    assert_eq!(rig.script.lock().unwrap().asset_calls.len(), calls_before, "verified assets are not downloaded again");
    assert!(rig.directory().join("manifest.json").exists());
    rig.stop();
}

#[tokio::test]
async fn a_cached_asset_that_does_not_match_is_never_overwritten() {
    let mut rig = rig(Script::honest()).await;
    std::fs::create_dir_all(rig.directory()).unwrap();
    std::fs::write(rig.directory().join("config.json"), b"not the declared bytes").unwrap();
    let error = rig.fetch(&Fetcher::new()).await.unwrap_err();
    assert!(error.to_string().contains("Existing model cache asset is corrupted"), "{error}");
    assert_eq!(std::fs::read(rig.directory().join("config.json")).unwrap(), b"not the declared bytes");
    assert!(!rig.directory().join("manifest.json").exists());
    rig.stop();
}

#[tokio::test]
async fn a_cached_manifest_that_differs_is_not_replaced() {
    let mut rig = rig(Script::honest()).await;
    std::fs::create_dir_all(rig.directory()).unwrap();
    std::fs::write(rig.directory().join("manifest.json"), b"{}").unwrap();
    let error = rig.fetch(&Fetcher::new()).await.unwrap_err();
    assert!(error.to_string().contains("Cached model manifest differs"), "{error}");
    assert_eq!(std::fs::read(rig.directory().join("manifest.json")).unwrap(), b"{}");
    rig.stop();
}

#[tokio::test]
async fn the_cache_must_not_traverse_a_link() {
    let elsewhere = tempfile::tempdir().unwrap();
    let mut rig = rig(Script::honest()).await;
    let link = rig.cache.path().join(MODEL);
    if !make_directory_link(elsewhere.path(), &link) {
        eprintln!("this account cannot create directory links; skipped");
        rig.stop();
        return;
    }
    let error = rig.fetch(&Fetcher::new()).await.unwrap_err();
    assert!(error.to_string().contains("must not traverse symlinks"), "{error}");
    assert_eq!(std::fs::read_dir(elsewhere.path()).unwrap().count(), 0, "nothing was written through the link");
    rig.stop();
}

fn make_directory_link(target: &Path, link: &Path) -> bool {
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(target, link).is_ok()
    }
    #[cfg(windows)]
    {
        // A junction needs no privilege; `symlink_metadata` reports it as a reparse point.
        std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(link)
            .arg(target)
            .output()
            .is_ok_and(|output| output.status.success())
    }
}

#[tokio::test]
async fn server_errors_and_family_confusion_are_errors_and_a_legacy_answer_is_none() {
    // A status from the server comes through as one.
    let mut script = Script::honest();
    script.fail_with = Some(Status::unauthenticated("no identity"));
    let mut rig_a = rig(script).await;
    assert!(matches!(rig_a.fetch(&Fetcher::new()).await, Err(FetchError::Rpc(status)) if status.code() == tonic::Code::Unauthenticated));
    rig_a.stop();

    // A legacy (non-V3) model for a `latest` request is not this fetcher's job: no package, no error.
    let mut legacy = Script::honest();
    legacy.first_package =
        Some(ModelPackageResponse { model_id: "privoke-baseline".into(), architecture: "tiny".into(), ..Default::default() });
    let mut rig_b = rig(legacy).await;
    assert!(rig_b.fetch(&Fetcher::new()).await.unwrap().is_none());
    rig_b.stop();

    // A legacy answer that still carries a V3 manifest or assets is a different model family: an error.
    let mut confused = Script::honest();
    let mut package = confused.package();
    package.architecture = "tiny".into();
    confused.first_package = Some(package);
    let mut rig_c = rig(confused).await;
    let error = rig_c.fetch(&Fetcher::new()).await.unwrap_err();
    assert!(error.to_string().contains("different model family"), "{error}");
    rig_c.stop();
}
