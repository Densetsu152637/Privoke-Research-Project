//! Shared helpers: a private PKI issued at test time (as the stage 5 tests do), scripted backends that answer from
//! recorded wire bytes, and the golden file. No key or certificate is committed; every run issues its own.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use privoke_contracts::proto::v1::{
    ComputeSemanticGradientsRequest, ComputeSemanticGradientsResponse, ParameterUpdateAck, ParameterUpdateRequest, ParameterUpdateStatus,
    ParameterUpdateStatusRequest,
};
use privoke_fuzzer::config::Scope;
use privoke_fuzzer::runtime::{CallOptions, RuntimeBackend};
use privoke_fuzzer::updates::UpdateBackend;
use privoke_pki::ca::{CaDir, Validity};
use privoke_pki::{files::write_atomic, registry_edit};
use privoke_transport::ClientTlsConfig;
use privoke_transport::startup::CloudTlsArgs;
use prost::Message;
use time::{Duration as TimeDuration, OffsetDateTime};
use tonic::Status;

pub const STATUS_PATH: &str = "/privoke.v1.ParamUpdateService/GetParameterUpdateStatus";
pub const SUBMIT_PATH: &str = "/privoke.v1.ParamUpdateService/SubmitParameterUpdate";
pub const HEADS_PATH: &str = "/privoke.v1.PrivokeRuntimeService/ComputeSemanticGradients";
pub const FULL_PATH: &str = "/privoke.v1.PrivokeRuntimeService/ComputeUnderlyingModelGradients";

pub fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

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

    /// A service certificate under the client CA, registered with `role` when a role is given (so a test can also
    /// present a certificate that the CA signed but the registry does not know).
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

    pub fn client_config(&self, creds: Option<&Creds>) -> ClientTlsConfig {
        ClientTlsConfig {
            server_ca: self.path("server-ca/ca.crt"),
            identity: creds.map(|creds| (creds.cert.clone(), creds.key.clone())),
            server_name: "localhost".to_string(),
        }
    }
}

/// The wire log of one cycle: every request that crossed a boundary, in order.
#[derive(Debug, Default)]
pub struct Wire {
    pub calls: Mutex<Vec<(String, Vec<u8>)>>,
    /// The options (admission header, deadline class) of each runtime call, in order.
    pub options: Mutex<Vec<CallOptions>>,
}

impl Wire {
    pub fn take(&self) -> Vec<(String, Vec<u8>)> {
        std::mem::take(&mut *self.calls.lock().unwrap())
    }

    pub fn take_options(&self) -> Vec<CallOptions> {
        std::mem::take(&mut *self.options.lock().unwrap())
    }

    fn push(&self, path: &str, bytes: Vec<u8>) {
        self.calls.lock().unwrap().push((path.to_string(), bytes));
    }
}

/// How the scripted runtime answers: a function of the scope and the request.
pub type RuntimeAnswer = Box<dyn FnMut(Scope, &ComputeSemanticGradientsRequest) -> Result<ComputeSemanticGradientsResponse, Status> + Send>;

/// How the scripted updater acknowledges a publication.
pub type AckAnswer = Box<dyn FnMut(&ParameterUpdateRequest) -> ParameterUpdateAck + Send>;

/// The runtime answers every call from a recorded response, or from a function of the request.
pub struct ScriptedRuntime {
    pub wire: Arc<Wire>,
    pub answer: Mutex<RuntimeAnswer>,
}

impl ScriptedRuntime {
    pub fn new(
        wire: Arc<Wire>,
        answer: impl FnMut(Scope, &ComputeSemanticGradientsRequest) -> Result<ComputeSemanticGradientsResponse, Status> + Send + 'static,
    ) -> Self {
        Self { wire, answer: Mutex::new(Box::new(answer)) }
    }

    pub fn replaying(wire: Arc<Wire>, response: Vec<u8>) -> Self {
        Self::new(wire, move |_scope, _request| Ok(ComputeSemanticGradientsResponse::decode(response.as_slice()).unwrap()))
    }
}

#[tonic::async_trait]
impl RuntimeBackend for ScriptedRuntime {
    async fn compute_gradients(
        &self,
        scope: Scope,
        request: ComputeSemanticGradientsRequest,
        options: CallOptions,
    ) -> Result<ComputeSemanticGradientsResponse, Status> {
        self.wire.options.lock().unwrap().push(options);
        self.wire.push(if scope == Scope::Heads { HEADS_PATH } else { FULL_PATH }, request.encode_to_vec());
        (self.answer.lock().unwrap())(scope, &request)
    }
}

/// The parameter-update service: no earlier receipt, and a scripted acknowledgement.
pub struct ScriptedUpdates {
    pub wire: Arc<Wire>,
    pub ack: Mutex<AckAnswer>,
}

impl ScriptedUpdates {
    pub fn new(wire: Arc<Wire>, ack: impl FnMut(&ParameterUpdateRequest) -> ParameterUpdateAck + Send + 'static) -> Self {
        Self { wire, ack: Mutex::new(Box::new(ack)) }
    }

    pub fn fixed(wire: Arc<Wire>, ack: Vec<u8>) -> Self {
        Self::new(wire, move |_| ParameterUpdateAck::decode(ack.as_slice()).unwrap())
    }
}

#[tonic::async_trait]
impl UpdateBackend for ScriptedUpdates {
    async fn status(&self, request: ParameterUpdateStatusRequest) -> Result<ParameterUpdateStatus, Status> {
        self.wire.push(STATUS_PATH, request.encode_to_vec());
        Ok(ParameterUpdateStatus { found: false, ..ParameterUpdateStatus::default() })
    }

    async fn submit(&self, request: ParameterUpdateRequest) -> Result<ParameterUpdateAck, Status> {
        self.wire.push(SUBMIT_PATH, request.encode_to_vec());
        Ok((self.ack.lock().unwrap())(&request))
    }
}

pub fn read_golden() -> serde_json::Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fuzzer_cycles_golden.json");
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

pub fn b64(text: &str) -> Vec<u8> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.decode(text).unwrap()
}
