//! The Rust model fetch against the Python fetch (D11): the same synthetic package, the same cache, the same refusals.
//!
//! `tests/fixtures/model_fetch_golden.json` is written by `evaluation/generate_model_fetch_golden.py`, which runs the
//! unchanged `v3_package.fetch_package` against a scripted client. Each case there names one mutation of an honest
//! server. This test builds the same server in Rust, fetches with the supervisor's `Fetcher`, and compares what
//! the Python fetch left behind: the cache directory (names and the SHA-256 and size of every file), the temporary files
//! left, the order of the asset requests, the number of package calls and the exact refusal text.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use privoke_contracts::digest::sha256_hex;
use privoke_contracts::proto::v1::model_streaming_service_server::{ModelStreamingService, ModelStreamingServiceServer};
use privoke_contracts::proto::v1::{
    HealthRequest, HealthResponse, ModelAssetChunk, ModelAssetRequest, ModelPackageAsset, ModelPackageResponse, ModelParameterChunk,
    ModelParametersRequest, ModelParametersResponse,
};
use privoke_contracts::v3;
use privoke_supervisor::channel::ModelEndpoint;
use privoke_supervisor::fetch::{Admission, AdmittedManifest, FetchConfig, FetchError, Fetcher};
use privoke_transport::listener::loopback::LoopbackListener;
use serde_json::Value;
use tokio_stream::Stream;
use tonic::{Request, Response, Status};

const GOLDEN: &str = include_str!("fixtures/model_fetch_golden.json");
const MODEL: &str = "test-model";
const ASSETS: [&str; 4] = ["model.safetensors", "config.json", "vocab.txt", "evidence.json"];
const CHUNK: usize = 1024 * 1024;
/// The architecture string a legacy (non-V3) package carries; the Python case uses the same one.
const LEGACY_ARCHITECTURE: &str = "privoke_tiny_transformer_v1";

fn honest_assets() -> BTreeMap<String, Vec<u8>> {
    BTreeMap::from([
        ("model.safetensors".to_string(), (0..(2 * 1024 * 1024 + 512 * 1024)).map(|i| (i % 251) as u8).collect()),
        ("config.json".to_string(), b"{\"hidden_size\":8}".to_vec()),
        ("vocab.txt".to_string(), b"[PAD]\n[UNK]\nhello\n".to_vec()),
        ("evidence.json".to_string(), b"{\"evidence\":true}".to_vec()),
    ])
}

fn manifest_for(assets: &BTreeMap<String, Vec<u8>>) -> Vec<u8> {
    ASSETS.iter().map(|name| format!("{name}={}", sha256_hex(&assets[*name]))).collect::<Vec<_>>().join("\n").into_bytes()
}

/// The scripted server: honest, with the mutation of one golden case applied.
struct Script {
    mutation: String,
    assets: BTreeMap<String, Vec<u8>>,
    manifest: Vec<u8>,
    package_calls: usize,
    asset_calls: Vec<String>,
    consumers: Vec<String>,
}

impl Script {
    fn new(mutation: &str) -> Self {
        let assets = honest_assets();
        let manifest = manifest_for(&assets);
        Self { mutation: mutation.into(), assets, manifest, package_calls: 0, asset_calls: Vec::new(), consumers: Vec::new() }
    }

    fn pin(&self) -> String {
        sha256_hex(&self.manifest)
    }

    fn honest_package(&self) -> ModelPackageResponse {
        ModelPackageResponse {
            model_id: MODEL.into(),
            architecture: v3::ARCHITECTURE.into(),
            manifest_sha256: self.pin(),
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

    fn package(&self, call: usize) -> ModelPackageResponse {
        let mut package = self.honest_package();
        if call >= 2 {
            if self.mutation == "manifest_changes_during_download" {
                package.model_id = "changed-model".into();
            }
            return package;
        }
        match self.mutation.as_str() {
            "manifest_not_pinned" => package.manifest_json[0] ^= 1,
            "response_pin_differs" => package.manifest_sha256 = "0".repeat(64),
            "response_model_id_differs" => package.model_id = "other-model".into(),
            "asset_missing" => {
                let _ = package.assets.remove(3);
            }
            "asset_extra" => package.assets.push(ModelPackageAsset { name: "extra.bin".into(), sha256: "0".repeat(64), size_bytes: 1 }),
            "asset_duplicate" => package.assets[3] = package.assets[2].clone(),
            "asset_sha_differs" => package.assets[0].sha256 = "0".repeat(64),
            "asset_size_zero" => package.assets[1].size_bytes = 0,
            "asset_size_too_large" => package.assets[0].size_bytes = v3::MAX_BLOB_BYTES + 1,
            "legacy_family_latest" | "legacy_family_v3_request" => {
                package.architecture = LEGACY_ARCHITECTURE.into();
                package.manifest_json = Vec::new();
                package.assets.clear();
            }
            "legacy_family_with_manifest" => package.architecture = LEGACY_ARCHITECTURE.into(),
            _ => {}
        }
        package
    }

    fn stream(&self, name: &str) -> Vec<ModelAssetChunk> {
        let data = &self.assets[name];
        let (total, digest, pin) = (data.len(), sha256_hex(data), self.pin());
        let mut chunks: Vec<ModelAssetChunk> = (0..total)
            .step_by(CHUNK)
            .map(|offset| ModelAssetChunk {
                model_id: MODEL.into(),
                manifest_sha256: pin.clone(),
                asset_name: name.into(),
                sha256: digest.clone(),
                offset: offset as u64,
                total_bytes: total as u64,
                data: data[offset..(offset + CHUNK).min(total)].to_vec(),
            })
            .collect();
        if !self.mutation.starts_with("stream_") || name != "model.safetensors" {
            return chunks;
        }
        match self.mutation.as_str() {
            "stream_flipped_byte" => chunks[1].data[10] ^= 1,
            "stream_truncated" => {
                let _ = chunks.pop();
            }
            "stream_offset_gap" => chunks[1].offset += 1,
            "stream_model_id" => chunks[0].model_id = "other-model".into(),
            "stream_manifest_sha" => chunks[1].manifest_sha256 = "0".repeat(64),
            "stream_asset_name" => chunks[0].asset_name = "config.json".into(),
            "stream_sha" => chunks[1].sha256 = "0".repeat(64),
            "stream_total_bytes" => chunks[0].total_bytes += 1,
            "stream_empty_chunk" => {
                let mut empty = chunks[1].clone();
                empty.data = Vec::new();
                chunks.insert(1, empty);
            }
            "stream_oversize_chunk" => {
                let merged = ModelAssetChunk { data: data[..2 * CHUNK].to_vec(), ..chunks[0].clone() };
                chunks = [vec![merged], chunks[2..].to_vec()].concat();
            }
            "stream_extra_data" => {
                let mut extra = chunks.last().unwrap().clone();
                extra.offset = total as u64;
                extra.data = b"x".to_vec();
                chunks.push(extra);
            }
            other => panic!("unknown stream mutation {other}"),
        }
        chunks
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
        script.package_calls += 1;
        Ok(Response::new(script.package(script.package_calls)))
    }
    type StreamModelAssetStream = BoxStream<ModelAssetChunk>;
    async fn stream_model_asset(&self, request: Request<ModelAssetRequest>) -> Result<Response<Self::StreamModelAssetStream>, Status> {
        let mut script = self.0.lock().unwrap();
        let name = request.get_ref().asset_name.clone();
        script.asset_calls.push(name.clone());
        let chunks = script.stream(&name);
        Ok(Response::new(Box::pin(tokio_stream::iter(chunks.into_iter().map(Ok)))))
    }
}

/// The synthetic pin set of the Python generator: `test-model` is pinned to the hash of one manifest of `name=sha` lines.
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
        let mut assets = BTreeMap::new();
        for line in std::str::from_utf8(manifest_json).unwrap().lines() {
            let (name, sha) = line.split_once('=').unwrap();
            assets.insert(*ASSETS.iter().find(|candidate| **candidate == name).unwrap(), sha.to_string());
        }
        Ok(AdmittedManifest { model_id: MODEL.into(), pin: self.pin.clone(), assets })
    }
}

/// What the cache directory holds: visible files with their SHA-256 and size, and the normalised hidden names.
fn listing(directory: &Path) -> (bool, BTreeMap<String, (String, u64)>, Vec<String>) {
    let Ok(entries) = std::fs::read_dir(directory) else { return (false, BTreeMap::new(), Vec::new()) };
    let (mut files, mut hidden) = (BTreeMap::new(), Vec::new());
    for entry in entries {
        let entry = entry.unwrap();
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with('.') {
            hidden.push(format!("{}-*", name.split('-').next().unwrap()));
        } else {
            let bytes = std::fs::read(entry.path()).unwrap();
            files.insert(name, (sha256_hex(&bytes), bytes.len() as u64));
        }
    }
    hidden.sort();
    (true, files, hidden)
}

fn cache_before(case: &str, directory: &Path, script: &Script) {
    if !matches!(case, "cached_assets_complete" | "cached_asset_corrupted" | "cached_manifest_differs") {
        return;
    }
    std::fs::create_dir_all(directory).unwrap();
    for name in ASSETS {
        std::fs::write(directory.join(name), &script.assets[name]).unwrap();
    }
    match case {
        "cached_assets_complete" => std::fs::write(directory.join("manifest.json"), &script.manifest).unwrap(),
        "cached_manifest_differs" => std::fs::write(directory.join("manifest.json"), [script.manifest.as_slice(), b"\n"].concat()).unwrap(),
        _ => std::fs::write(directory.join("vocab.txt"), b"corrupted").unwrap(),
    }
}

async fn run_case(case: &Value) {
    let name = case["name"].as_str().unwrap();
    let requested = case["request_model_id"].as_str().unwrap();
    let script = Script::new(name);
    let pin = script.pin();
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
    let endpoint = ModelEndpoint::from_environment(&environment).unwrap();

    let cache = tempfile::tempdir().unwrap();
    let directory: PathBuf = cache.path().join(MODEL).join(&pin);
    cache_before(name, &directory, &script.lock().unwrap());
    let config = FetchConfig {
        consumer_id: "installation-1".into(),
        rpc_timeout: Duration::from_secs(20),
        download_timeout: Duration::from_secs(60),
        cache_root: cache.path().to_path_buf(),
    };
    let admission = SyntheticAdmission { pin: pin.clone() };
    let fetcher = Fetcher::new();
    let fetch = || async {
        let channel = endpoint.connect(Duration::from_secs(10)).await.unwrap();
        fetcher.fetch(channel, &endpoint.target, requested, &admission, &config).await
    };

    let outcome = fetch().await;
    let (asset_calls_after_first, package_calls_after_first) = {
        let script = script.lock().unwrap();
        (script.asset_calls.clone(), script.package_calls)
    };
    match (&outcome, case["outcome"].as_str().unwrap()) {
        (Ok(Some(package)), "package") => {
            assert_eq!((package.model_id.as_str(), package.pin.as_str()), (MODEL, pin.as_str()), "{name}");
            let again = fetch().await.unwrap().unwrap();
            assert_eq!(&again, package, "{name}: a second fetch by the same fetcher returns the admitted package");
            let second_assets: Vec<String> = script.lock().unwrap().asset_calls[asset_calls_after_first.len()..].to_vec();
            let expected: Vec<String> =
                case["second_fetch_asset_calls"].as_array().unwrap().iter().map(|v| v.as_str().unwrap().into()).collect();
            assert_eq!(second_assets, expected, "{name}: assets requested by the second fetch");
            assert_eq!(case["second_fetch_same_package"], true);
        }
        (Ok(None), "none") => {}
        (Err(error), "error") => assert_eq!(error.to_string(), case["error"].as_str().unwrap(), "{name}: the refusal text"),
        (other, expected) => panic!("{name}: Python outcome {expected}, Rust {other:?}"),
    }

    let (exists, files, hidden) = listing(&directory);
    assert_eq!(exists, case["directory_exists"].as_bool().unwrap(), "{name}: the cache directory");
    let expected_files: BTreeMap<String, (String, u64)> = case["files"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(file, entry)| (file.clone(), (entry["sha256"].as_str().unwrap().to_string(), entry["size"].as_u64().unwrap())))
        .collect();
    assert_eq!(files, expected_files, "{name}: the files in the cache directory (bytes by SHA-256)");
    let expected_hidden: Vec<String> = case["hidden"].as_array().unwrap().iter().map(|v| v.as_str().unwrap().into()).collect();
    assert_eq!(hidden, expected_hidden, "{name}: temporary files left behind");

    let expected_assets: Vec<String> = case["asset_calls"].as_array().unwrap().iter().map(|v| v.as_str().unwrap().into()).collect();
    assert_eq!(asset_calls_after_first, expected_assets, "{name}: assets requested, in order");
    assert_eq!(package_calls_after_first as u64, case["package_calls"].as_u64().unwrap(), "{name}: GetModelPackage calls");
    let mut consumers = script.lock().unwrap().consumers.clone();
    consumers.sort();
    consumers.dedup();
    let expected_consumers: Vec<String> = case["consumers"].as_array().unwrap().iter().map(|v| v.as_str().unwrap().into()).collect();
    assert_eq!(consumers, expected_consumers, "{name}: the consumer id sent");
    let _ = stop.send(());
}

#[tokio::test]
async fn the_rust_fetch_leaves_the_cache_python_leaves_and_refuses_what_python_refuses() {
    let golden: Value = serde_json::from_str(GOLDEN).unwrap();
    let v3_golden = &golden["v3"];
    assert_eq!(v3_golden["architecture"], v3::ARCHITECTURE);
    assert_eq!(v3_golden["max_blob_bytes"].as_u64().unwrap(), v3::MAX_BLOB_BYTES);
    assert_eq!(v3_golden["chunk_bytes"].as_u64().unwrap(), v3::CHUNK_BYTES as u64);
    let cases = v3_golden["cases"].as_array().unwrap();
    assert!(cases.len() >= 29, "the golden lost cases");
    let (mut accepted, mut refused) = (0, 0);
    for case in cases {
        run_case(case).await;
        if case["outcome"] == "error" { refused += 1 } else { accepted += 1 }
    }
    eprintln!("model fetch golden (V3): {} cases identical to Python ({accepted} accepted, {refused} refused)", cases.len());
}
