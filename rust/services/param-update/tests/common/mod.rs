//! Shared helpers: a private PKI issued at test time, in-process servers, mutual-TLS clients, model fixtures and
//! request builders. No key or certificate is committed; every run issues its own.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use privoke_contracts::proto::v1::param_update_service_client::ParamUpdateServiceClient;
use privoke_contracts::proto::v1::{Parameter, ParameterUpdateRequest};
use privoke_param_update::artifact_io;
use privoke_param_update::engine::{Engine, EngineConfig, no_hook, system_clock};
use privoke_param_update::policy::DriftPolicy;
use privoke_param_update::server::{self, ServerHandle};
use privoke_param_update::service::ParamUpdateHandler;
use privoke_param_update::v3_store::CheckpointHandler;
use privoke_pki::ca::{CaDir, Validity};
use privoke_pki::{client as enrolment, files::write_atomic, registry_edit};
use privoke_transport::startup::CloudTlsArgs;
use privoke_transport::{ClientTlsConfig, Limits, RateLimit};
use time::{Duration as TimeDuration, OffsetDateTime};
use tonic::transport::Channel;
use tonic::{Code, Status};

/// A credential on disk.
#[derive(Debug, Clone)]
pub struct Creds {
    pub id: String,
    pub cert: PathBuf,
    pub key: PathBuf,
}

/// The CAs, the server certificate, the registry and the CRL of one test.
#[derive(Debug)]
pub struct Env {
    pub dir: tempfile::TempDir,
    pub client_ca: CaDir,
    pub foreign_ca: CaDir,
}

impl Env {
    pub fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let validity = Validity::days(30);
        let client_ca = CaDir::init(&dir.path().join("client-ca"), "Test Client CA", validity).unwrap();
        let server_ca = CaDir::init(&dir.path().join("server-ca"), "Test Server CA", validity).unwrap();
        let foreign_ca = CaDir::init(&dir.path().join("foreign-ca"), "Foreign CA", validity).unwrap();
        let server = server_ca.issue_server(&["localhost".to_string(), "127.0.0.1".to_string()], validity).unwrap();
        write_atomic(&dir.path().join("server.crt"), server.cert_pem.as_bytes(), false).unwrap();
        write_atomic(&dir.path().join("server.key"), server.key_pem.as_bytes(), true).unwrap();
        let env = Self { dir, client_ca, foreign_ca };
        env.refresh_crl();
        registry_edit::set_reporter(&env.registry(), true).unwrap();
        env
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

    /// A service certificate under the client CA. It is registered with `role` when a role is given, so a test can
    /// also present a certificate that the CA signed but the registry does not know.
    pub fn service(&self, name: &str, role: Option<&str>) -> Creds {
        let issued = self.client_ca.issue_service(name, Validity::days(30)).unwrap();
        let dir = self.path(&format!("svc-{name}"));
        write_atomic(&dir.join("service.crt"), issued.cert_pem.as_bytes(), false).unwrap();
        write_atomic(&dir.join("service.key"), issued.key_pem.as_bytes(), true).unwrap();
        if let Some(role) = role {
            registry_edit::add_service(&self.registry(), name, role, issued.not_after).unwrap();
        }
        Creds { id: name.to_string(), cert: dir.join("service.crt"), key: dir.join("service.key") }
    }

    /// An installation certificate under the real client CA, registered (a `consumer`) or not.
    pub fn installation(&self, name: &str, register: bool) -> Creds {
        let dir = self.path(name);
        std::fs::create_dir_all(&dir).unwrap();
        let enrolment = enrolment::enrol(&dir).unwrap();
        let csr = std::fs::read_to_string(&enrolment.csr_path).unwrap();
        let signed = self.client_ca.sign_installation(&csr, &enrolment.installation, Validity::days(30)).unwrap();
        write_atomic(&dir.join("client.crt"), signed.cert_pem.as_bytes(), false).unwrap();
        if register {
            registry_edit::add_installation(&self.registry(), &enrolment.installation, Some(name), signed.not_after).unwrap();
        }
        Creds { id: enrolment.installation, cert: dir.join("client.crt"), key: dir.join("client.key") }
    }

    pub fn client_config(&self, creds: Option<&Creds>) -> ClientTlsConfig {
        ClientTlsConfig {
            server_ca: self.path("server-ca/ca.crt"),
            identity: creds.map(|creds| (creds.cert.clone(), creds.key.clone())),
            server_name: "localhost".to_string(),
        }
    }

    /// Start the in-process server over `engine`.
    pub async fn start(&self, engine: Arc<Engine>, limits: Limits) -> ServerHandle {
        let transport = self.tls_args().into_config().unwrap();
        let any: SocketAddr = "127.0.0.1:0".parse().unwrap();
        server::start(any, ParamUpdateHandler::new(engine), transport, limits, Duration::from_millis(50)).await.unwrap()
    }

    /// Start the in-process server over `engine` with the V3 `CheckpointService` on the same listener.
    pub async fn start_with_checkpoint(&self, engine: Arc<Engine>, checkpoint: CheckpointHandler, limits: Limits) -> ServerHandle {
        let transport = self.tls_args().into_config().unwrap();
        let any: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let handler = ParamUpdateHandler::new(engine);
        server::start_with_checkpoint(any, handler, Some(checkpoint), transport, limits, Duration::from_millis(50)).await.unwrap()
    }

    pub async fn updates(&self, address: SocketAddr, creds: Option<&Creds>) -> ParamUpdateServiceClient<Channel> {
        let channel = privoke_transport::client::connect(&address.to_string(), &self.client_config(creds)).await.expect("connect");
        ParamUpdateServiceClient::new(channel)
    }
}

pub fn generous() -> Limits {
    Limits { rate: RateLimit { per_second: 1000, burst: 1000 }, ..Limits::default() }
}

pub fn code<T>(result: Result<T, Status>) -> Code {
    match result {
        Ok(_) => Code::Ok,
        Err(status) => status.code(),
    }
}

pub fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

/// Copy `models/<name>.json` into `directory` and return its path.
pub fn copy_model(directory: &Path, name: &str) -> PathBuf {
    let target = directory.join(format!("{name}.json"));
    std::fs::copy(repo_root().join("models").join(format!("{name}.json")), &target).unwrap();
    target
}

pub fn config_for(directory: &Path, model: &Path, model_id: &str, drift: DriftPolicy) -> EngineConfig {
    EngineConfig {
        storage_path: directory.join("updates.jsonl"),
        model_artifact_path: model.to_path_buf(),
        expected_model_id: model_id.to_string(),
        max_abs_gradient: 1.0,
        drift,
    }
}

/// An engine with the stage 0 policy of the Python service (per-coordinate bound only).
pub fn engine(directory: &Path, model: &Path, model_id: &str) -> Engine {
    Engine::new(config_for(directory, model, model_id, DriftPolicy::Off), system_clock(), no_hook()).unwrap()
}

pub fn version_of(model: &Path) -> String {
    artifact_io::load(model).unwrap().typed.version
}

pub fn gradient(name: &str, shape: &[u32], values: &[f32]) -> Parameter {
    Parameter { name: name.to_string(), values: values.to_vec(), shape: shape.to_vec() }
}

pub fn update(source: &str, model: &str, base: &str, gradients: Vec<Parameter>, metadata: &[(&str, &str)]) -> ParameterUpdateRequest {
    ParameterUpdateRequest {
        source_id: source.to_string(),
        model_id: model.to_string(),
        base_version: base.to_string(),
        gradients,
        metadata: metadata.iter().map(|(key, value)| ((*key).to_string(), (*value).to_string())).collect(),
    }
}

/// The Python tests' `valid_request` against `privoke-baseline`.
pub fn baseline_update(base: &str, metadata: &[(&str, &str)]) -> ParameterUpdateRequest {
    update("test-fuzzer", "privoke-baseline", base, vec![gradient("head.sensitivity.bias", &[4], &[0.0, 0.0, 0.0, 0.01])], metadata)
}
