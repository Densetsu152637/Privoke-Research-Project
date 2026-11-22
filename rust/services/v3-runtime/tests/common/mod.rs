//! Shared helpers: a private PKI issued at test time (as the stage 5 and 21 tests do) and a scripted checkpoint service. No key
//! or certificate is committed; every run issues its own.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use privoke_contracts::proto::experimental_v3 as v3;
use privoke_pki::ca::{CaDir, Validity};
use privoke_pki::{files::write_atomic, registry_edit};
use privoke_transport::ClientTlsConfig;
use privoke_transport::startup::CloudTlsArgs;
use privoke_v3_fuzzer::source::Closure;
use privoke_v3_runtime::checkpoint::Checkpoint;
use privoke_v3_runtime::server::{self, ServerHandle, limits_for};
use privoke_v3_runtime::service::{Runtime, RuntimeParts, V3RuntimeHandler};
use tonic::Status;

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
        let pem = self.client_ca.crl_pem(time::OffsetDateTime::now_utc(), time::Duration::days(7)).unwrap();
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

    /// A service certificate under the client CA, registered with `role` when a role is given (so a test can also present a
    /// certificate that the CA signed but the registry does not know).
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

/// The checkpoint service in memory: blobs by digest, one current snapshot per model, and the staged chunk streams.
#[derive(Debug, Default)]
pub struct Scripted {
    pub ready: Mutex<bool>,
    pub blobs: Mutex<BTreeMap<String, Vec<v3::Chunk>>>,
    pub current: Mutex<BTreeMap<String, String>>,
    pub staged: Mutex<Vec<Vec<v3::Chunk>>>,
    pub calls: Mutex<Vec<String>>,
}

impl Scripted {
    pub fn ready() -> Arc<Self> {
        let scripted = Self::default();
        *scripted.ready.lock().unwrap() = true;
        Arc::new(scripted)
    }
}

#[tonic::async_trait]
impl Checkpoint for Scripted {
    async fn resolve_current(&self, model_id: &str) -> Result<v3::Ref, Status> {
        self.calls.lock().unwrap().push(format!("resolve:{model_id}"));
        match self.current.lock().unwrap().get(model_id) {
            Some(sha256) => Ok(v3::Ref { sha256: sha256.clone() }),
            None => Err(Status::not_found("no current snapshot")),
        }
    }

    async fn fetch_blob(&self, sha256: &str) -> Result<Vec<v3::Chunk>, Status> {
        self.calls.lock().unwrap().push(format!("fetch:{sha256}"));
        self.blobs.lock().unwrap().get(sha256).cloned().ok_or_else(|| Status::not_found("no such blob"))
    }

    async fn stage_checkpoint(&self, chunks: Vec<v3::Chunk>) -> Result<v3::Ref, Status> {
        let sha256 = chunks.first().map(|chunk| chunk.sha256.clone()).unwrap_or_default();
        self.calls.lock().unwrap().push(format!("stage:{sha256}"));
        self.staged.lock().unwrap().push(chunks);
        Ok(v3::Ref { sha256 })
    }

    async fn health(&self) -> Result<v3::HealthResponse, Status> {
        Ok(v3::HealthResponse { ready: *self.ready.lock().unwrap(), role: "stub".to_string(), capabilities: BTreeMap::new() })
    }
}

pub struct Stack {
    pub env: Env,
    pub scripted: Arc<Scripted>,
    pub runtime: Arc<Runtime>,
    pub handle: ServerHandle,
    pub state: tempfile::TempDir,
}

/// A runtime over a scripted checkpoint service, behind the real mutual-TLS listener.
pub async fn start() -> Stack {
    let env = Env::new();
    let state = tempfile::tempdir().unwrap();
    let scripted = Scripted::ready();
    let parts = RuntimeParts { directory: state.path().join("state"), threads: 2, closure: Closure::Fixed("test-closure".to_string()) };
    let runtime = Arc::new(Runtime::new(parts, scripted.clone()).await.unwrap());
    let transport = env.tls_args().into_config().unwrap();
    let handle = server::start(
        "127.0.0.1:0".parse().unwrap(),
        V3RuntimeHandler::new(runtime.clone()),
        transport,
        limits_for(Duration::from_secs(600)),
        Duration::from_millis(50),
    )
    .await
    .unwrap();
    Stack { env, scripted, runtime, handle, state }
}
