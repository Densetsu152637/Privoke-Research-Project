//! Shared test environment: a private PKI issued at test time, the real model-streaming service in-process, and the
//! analysis service over them. No key or certificate is committed.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use privoke_analysis::config::{AnalysisConfig, ModelSource, WorkerSettings};
use privoke_contracts::proto::v1::privoke_runtime_service_client::PrivokeRuntimeServiceClient;
use privoke_model_streaming::catalog::Catalog;
use privoke_model_streaming::server::{self as model_server, Listen, ServerHandle as ModelServerHandle};
use privoke_model_streaming::service::ModelService;
use privoke_pki::ca::{CaDir, Validity};
use privoke_pki::{client as enrolment, files::write_atomic, registry_edit};
use privoke_transport::startup::CloudTlsArgs;
use privoke_transport::{ClientTlsConfig, Limits};
use time::{Duration as TimeDuration, OffsetDateTime};
use tonic::transport::Channel;

pub fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

/// The interpreter of a Python environment that can run the W1 worker (torch and the client-runtime requirements),
/// from `PRIVOKE_ANALYSIS_TEST_PYTHON`. Tests that need a real worker skip without it.
pub fn worker_python() -> Option<PathBuf> {
    std::env::var_os("PRIVOKE_ANALYSIS_TEST_PYTHON").filter(|value| !value.is_empty()).map(PathBuf::from)
}

/// A credential on disk.
pub struct Creds {
    pub id: String,
    pub cert: PathBuf,
    pub key: PathBuf,
}

pub struct Env {
    pub dir: tempfile::TempDir,
    client_ca: CaDir,
    pub models: tempfile::TempDir,
    pub cache: tempfile::TempDir,
}

impl Env {
    pub fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let validity = Validity::days(30);
        let client_ca = CaDir::init(&dir.path().join("client-ca"), "Test Client CA", validity).unwrap();
        let server_ca = CaDir::init(&dir.path().join("server-ca"), "Test Server CA", validity).unwrap();
        let server = server_ca.issue_server(&["localhost".to_string(), "127.0.0.1".to_string()], validity).unwrap();
        write_atomic(&dir.path().join("server.crt"), server.cert_pem.as_bytes(), false).unwrap();
        write_atomic(&dir.path().join("server.key"), server.key_pem.as_bytes(), true).unwrap();
        let models = tempfile::tempdir().unwrap();
        for name in ["privoke-baseline", "privoke-balanced", "privoke-efficient", "privoke-quality"] {
            std::fs::copy(repo_root().join("models").join(format!("{name}.json")), models.path().join(format!("{name}.json"))).unwrap();
        }
        let env = Self { dir, client_ca, models, cache: tempfile::tempdir().unwrap() };
        env.refresh_crl();
        registry_edit::set_reporter(&env.registry(), false).unwrap();
        env
    }

    /// Copies every `*.json` of `from` over the model directory (the prepared training models of the W1 capture).
    pub fn overlay_models(&self, from: &Path) {
        for entry in std::fs::read_dir(from).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().is_some_and(|extension| extension == "json") {
                std::fs::copy(&path, self.models.path().join(path.file_name().unwrap())).unwrap();
            }
        }
    }

    pub fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    pub fn registry(&self) -> PathBuf {
        self.path("registry.toml")
    }

    pub fn crl(&self) -> PathBuf {
        self.path("crl.pem")
    }

    pub fn refresh_crl(&self) {
        let pem = self.client_ca.crl_pem(OffsetDateTime::now_utc(), TimeDuration::days(7)).unwrap();
        write_atomic(&self.crl(), pem.as_bytes(), false).unwrap();
    }

    pub fn tls_args(&self) -> CloudTlsArgs {
        CloudTlsArgs {
            cert: Some(self.path("server.crt")),
            key: Some(self.path("server.key")),
            client_ca: Some(self.path("client-ca/ca.crt")),
            crl: Some(self.crl()),
            registry: Some(self.registry()),
        }
    }

    /// A registered service principal.
    pub fn service(&self, name: &str, role: &str) -> Creds {
        let issued = self.client_ca.issue_service(name, Validity::days(30)).unwrap();
        let dir = self.path(&format!("svc-{name}"));
        write_atomic(&dir.join("service.crt"), issued.cert_pem.as_bytes(), false).unwrap();
        write_atomic(&dir.join("service.key"), issued.key_pem.as_bytes(), true).unwrap();
        registry_edit::add_service(&self.registry(), name, role, issued.not_after).unwrap();
        Creds { id: name.to_string(), cert: dir.join("service.crt"), key: dir.join("service.key") }
    }

    /// A registered installation (role `consumer`).
    pub fn installation(&self, name: &str) -> Creds {
        let dir = self.path(name);
        std::fs::create_dir_all(&dir).unwrap();
        let enrolment = enrolment::enrol(&dir).unwrap();
        let csr = std::fs::read_to_string(&enrolment.csr_path).unwrap();
        let signed = self.client_ca.sign_installation(&csr, &enrolment.installation, Validity::days(30)).unwrap();
        write_atomic(&dir.join("client.crt"), signed.cert_pem.as_bytes(), false).unwrap();
        registry_edit::add_installation(&self.registry(), &enrolment.installation, Some(name), signed.not_after).unwrap();
        Creds { id: enrolment.installation, cert: dir.join("client.crt"), key: dir.join("client.key") }
    }

    pub fn client_config(&self, creds: &Creds) -> ClientTlsConfig {
        ClientTlsConfig {
            server_ca: self.path("server-ca/ca.crt"),
            identity: Some((creds.cert.clone(), creds.key.clone())),
            server_name: "localhost".to_string(),
        }
    }

    /// The real model-streaming service, in this process, over the test models.
    pub async fn start_model_streaming(&self) -> ModelServerHandle {
        let transport = self.tls_args().into_config().unwrap();
        let catalog = Catalog::load(self.models.path(), "privoke-balanced").unwrap();
        let any = "127.0.0.1:0".parse().unwrap();
        model_server::start(
            Listen { public: any, internal: any },
            ModelService::new(Arc::new(catalog)),
            transport,
            Limits::default(),
            Duration::from_millis(50),
        )
        .await
        .unwrap()
    }

    /// An analysis configuration that fetches from `model_address` as the registered `analysis` service.
    pub fn analysis_config(&self, model_address: std::net::SocketAddr, analysis: &Creds, python: &Path) -> AnalysisConfig {
        AnalysisConfig {
            bind: "127.0.0.1".parse().unwrap(),
            port: 1,
            allowed_services: vec!["fuzzer".into()],
            health_services: vec![],
            models: ModelSource {
                target: model_address.to_string(),
                server_ca: self.path("server-ca/ca.crt"),
                client_cert: analysis.cert.clone(),
                client_key: analysis.key.clone(),
                server_name: "localhost".into(),
            },
            cache_dir: self.cache.path().to_path_buf(),
            default_model_id: "privoke-balanced".into(),
            warm_models: vec!["privoke-balanced".into()],
            model_ttl: Duration::from_millis(200),
            pins: BTreeMap::new(),
            worker: WorkerSettings {
                python: python.to_path_buf(),
                shim: PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("python/worker_shim.py"),
                runtime_root: repo_root().join("extension/client-runtime"),
                workers: 1,
                queue: 16,
                request_deadline: Duration::from_secs(330),
                startup_timeout: Duration::from_secs(300),
                // Only Linux can deny sockets to the worker; the container is the quarantine.
                require_sandbox: cfg!(target_os = "linux"),
                memory_limit_bytes: None,
                max_processes: None,
            },
            rust_worker: None,
        }
    }
}

pub type Client = PrivokeRuntimeServiceClient<Channel>;

pub async fn connect(env: &Env, address: std::net::SocketAddr, creds: &Creds) -> Client {
    let channel = privoke_transport::client::connect(&address.to_string(), &env.client_config(creds)).await.expect("connect");
    PrivokeRuntimeServiceClient::new(channel)
}

/// One unary call with the request and response bytes exactly as given, over the service's own pass-through codec.
pub async fn raw_call(
    channel: Channel,
    path: &'static str,
    request: Vec<u8>,
    metadata: &[(String, String)],
) -> Result<Vec<u8>, tonic::Status> {
    let mut grpc = tonic::client::Grpc::new(channel);
    grpc.ready().await.map_err(|error| tonic::Status::unknown(error.to_string()))?;
    let mut request = tonic::Request::new(request);
    for (key, value) in metadata {
        request.metadata_mut().append(tonic::metadata::MetadataKey::from_bytes(key.as_bytes()).unwrap(), value.parse().unwrap());
    }
    let path = tonic::codegen::http::uri::PathAndQuery::from_static(path);
    Ok(grpc.unary(request, path, privoke_analysis::raw::RawCodec).await?.into_inner())
}

fn varint(bytes: &[u8], offset: &mut usize) -> u64 {
    let mut value = 0u64;
    let mut shift = 0;
    loop {
        let byte = bytes[*offset];
        *offset += 1;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return value;
        }
        shift += 7;
    }
}

/// Drops the wall-clock fields from a serialized response, byte for byte: the double field `elapsed_field` and the
/// `metadata` map entry whose key is `elapsed_ms`. A deterministic serialisation minus those fields is exactly what
/// the W1 parity helper re-serialises, and nothing else is touched.
pub fn strip_wall_clock(bytes: &[u8], elapsed_field: u64, metadata_field: Option<u64>) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut offset = 0;
    while offset < bytes.len() {
        let start = offset;
        let key = varint(bytes, &mut offset);
        let (field, wire) = (key >> 3, key & 7);
        let mut drop = false;
        match wire {
            0 => {
                varint(bytes, &mut offset);
            }
            1 => {
                offset += 8;
                drop = field == elapsed_field;
            }
            2 => {
                let length = varint(bytes, &mut offset) as usize;
                if Some(field) == metadata_field {
                    // The entry is `key = 1`, `value = 2`.
                    let entry = &bytes[offset..offset + length];
                    drop = entry.len() > 2
                        && entry[0] == 0x0a
                        && entry[2..].starts_with(b"elapsed_ms")
                        && entry[1] as usize == b"elapsed_ms".len();
                }
                offset += length;
            }
            5 => offset += 4,
            other => panic!("unsupported wire type {other}"),
        }
        if !drop {
            out.extend_from_slice(&bytes[start..offset]);
        }
    }
    out
}
