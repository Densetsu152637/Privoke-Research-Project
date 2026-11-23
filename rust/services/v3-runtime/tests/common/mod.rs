//! Shared helpers: a private PKI issued at test time (as the stage 5 and 21 tests do) and a scripted checkpoint service. No key
//! or certificate is committed; every run issues its own.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

pub mod fit_support;

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine as _;
use privoke_contracts::proto::experimental_v3 as v3;
use privoke_contracts::proto::v1::{AnalyzePromptRequest, AnalyzePromptResponse};
use privoke_pki::ca::{CaDir, Validity};
use privoke_pki::{files::write_atomic, registry_edit};
use privoke_transport::ClientTlsConfig;
use privoke_transport::startup::CloudTlsArgs;
use privoke_v3_fuzzer::backend::blob_chunks;
use privoke_v3_fuzzer::contract::digest;
use privoke_v3_fuzzer::source::Closure;
use privoke_v3_runtime::assets::Admission;
use privoke_v3_runtime::checkpoint::Checkpoint;
use privoke_v3_runtime::server::{self, ServerHandle, limits_for};
use privoke_v3_runtime::service::{Runtime, RuntimeParts, V3RuntimeHandler};
use prost::Message;
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
    let parts = RuntimeParts {
        directory: state.path().join("state"),
        threads: 2,
        closure: Closure::Fixed("test-closure".to_string()),
        admission: Admission::Structural,
        schedules: no_schedules(),
    };
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

pub fn b64(text: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD.decode(text).unwrap()
}

/// Print a line straight to stderr (the harness hides `println!` of a passing test; the counts must reach the CI log).
pub fn say(text: &str) {
    use std::io::Write;
    let _ = writeln!(std::io::stderr(), "{text}");
}

/// A checkpoint service holding one snapshot: the manifest, and the three assets of the package directory.
pub fn serve_package(scripted: &Scripted, package: &std::path::Path, model_id: &str, manifest: &[u8]) -> String {
    let mut blobs = scripted.blobs.lock().unwrap();
    for name in ["model.safetensors", "config.json", "vocab.txt"] {
        let mut payload = std::fs::read(package.join(name)).unwrap();
        if name != "model.safetensors" && package.ends_with("v3_synthetic") {
            // The text assets are LF in the golden whatever the host checked out.
            payload = String::from_utf8(payload).unwrap().replace("\r\n", "\n").into_bytes();
        }
        blobs.insert(digest(&payload), blob_chunks(&payload));
    }
    let sha = digest(manifest);
    blobs.insert(sha.clone(), blob_chunks(manifest));
    scripted.current.lock().unwrap().insert(model_id.to_string(), sha.clone());
    sha
}

/// A runtime over `scripted` with its own state directory.
pub async fn runtime_over(scripted: &Arc<Scripted>, directory: &std::path::Path, admission: Admission) -> Arc<Runtime> {
    let parts = RuntimeParts {
        directory: directory.to_path_buf(),
        threads: 4,
        closure: Closure::Fixed("replay".to_string()),
        admission,
        schedules: no_schedules(),
    };
    Arc::new(Runtime::new(parts, scripted.clone()).await.unwrap())
}

/// What a replay of golden `AnalyzePrompt` rows measured.
#[derive(Debug, Default)]
pub struct Report {
    pub rows: usize,
    pub aborts: usize,
    pub error_rows: usize,
    pub finding_rows: usize,
    pub wire_equal: usize,
    pub boundary_confidences: usize,
    pub failures: Vec<String>,
}

impl Report {
    pub fn assert_clean(&self, label: &str) {
        say(&format!(
            "{label}: {} rows ({} aborts, {} error responses, {} with findings): {} byte-identical to the Python wire bytes (elapsed_ms cleared), {} confidences equal only under the rounding-boundary rule, {} failures",
            self.rows,
            self.aborts,
            self.error_rows,
            self.finding_rows,
            self.wire_equal,
            self.boundary_confidences,
            self.failures.len()
        ));
        assert!(self.failures.is_empty(), "{label}: first failures: {:#?}", &self.failures[..self.failures.len().min(8)]);
    }
}

/// The distance of an unrounded confidence from the nearest 3-decimal rounding boundary.
fn boundary_distance(raw: f64) -> f64 {
    (((raw * 1000.0).fract()).abs() - 0.5).abs() / 1000.0
}

/// Replay `rows` (the Python oracle's recorded requests and outcomes) through `runtime`. A confidence may differ from the
/// oracle's by one rounding step only when both unrounded values agree within 1e-5 and one lies within 2e-5 of the boundary
/// (the stage 14 rule); everything else, every decision, string and span, must be identical.
pub async fn replay(runtime: &Runtime, rows: &[serde_json::Value], raw: &(dyn Fn(&str) -> f64 + Sync)) -> Report {
    let mut report = Report::default();
    for row in rows {
        let id = row["id"].as_str().unwrap().to_string();
        let request = AnalyzePromptRequest::decode(b64(row["request"].as_str().unwrap()).as_slice()).unwrap();
        report.rows += 1;
        let outcome = &row["outcome"];
        let mine = runtime.analyze_prompt(request.clone()).await;
        if let Some(abort) = outcome.get("abort") {
            report.aborts += 1;
            match mine {
                Err(status) => {
                    let got = [privoke_v3_runtime::pyerr::code_name(status.code()).to_string(), status.message().to_string()];
                    if abort.as_array().unwrap().iter().map(|v| v.as_str().unwrap().to_string()).collect::<Vec<_>>() != got {
                        report.failures.push(format!("{id}: abort {got:?} differs from {abort}"));
                    }
                }
                Ok(_) => report.failures.push(format!("{id}: Rust answered, Python aborted with {abort}")),
            }
            continue;
        }
        let golden_bytes = b64(outcome["ok"].as_str().unwrap());
        let golden = AnalyzePromptResponse::decode(golden_bytes.as_slice()).unwrap();
        let Ok(mut response) = mine else {
            report.failures.push(format!("{id}: Rust aborted, Python answered"));
            continue;
        };
        response.elapsed_ms = 0.0;
        report.error_rows += usize::from(!golden.error.is_empty());
        report.finding_rows += usize::from(golden.evidence.is_some());
        if response.encode_to_vec() == golden_bytes {
            report.wire_equal += 1;
            continue;
        }
        let mut mine_confidences: Vec<&mut f64> = Vec::new();
        if let Some(evidence) = response.evidence.as_mut() {
            mine_confidences.push(&mut evidence.confidence);
        }
        for layer in &mut response.layers {
            for result in &mut layer.results {
                mine_confidences.push(&mut result.confidence);
            }
        }
        let mut golden_confidences: Vec<f64> = golden.evidence.iter().map(|evidence| evidence.confidence).collect();
        golden_confidences.extend(golden.layers.iter().flat_map(|layer| layer.results.iter().map(|result| result.confidence)));
        if mine_confidences.len() == golden_confidences.len() {
            for (slot, expected) in mine_confidences.into_iter().zip(golden_confidences) {
                if *slot == expected {
                    continue;
                }
                let rust_raw = raw(&request.text);
                let python_raw = row["raw_confidence"].as_f64();
                let step = ((*slot - expected).abs() - 0.001).abs() < 1e-9;
                let near = python_raw.is_some_and(|python| {
                    (python - rust_raw).abs() < 1e-5 && boundary_distance(python).min(boundary_distance(rust_raw)) < 2e-5
                });
                if step && near {
                    *slot = expected;
                    report.boundary_confidences += 1;
                }
            }
        }
        if response != golden {
            report.failures.push(format!(
                "{id}: response differs:
rust   {response:?}
python {golden:?}"
            ));
        }
    }
    report
}

/// Schedule sources for tests that never fit (nothing is read from them).
pub fn no_schedules() -> privoke_v3_runtime::fit::ScheduleSources {
    privoke_v3_runtime::fit::ScheduleSources { root: PathBuf::from("."), audience: None }
}
