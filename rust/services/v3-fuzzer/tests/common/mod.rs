//! Shared helpers: a private PKI issued at test time (as the stage 5 and 21 tests do), scripted backends that answer from the
//! bytes the Python oracle's fake services returned, and the replay of one golden file. No key or certificate is committed;
//! every run issues its own.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub mod fakes;

use base64::Engine as _;
use privoke_contracts::proto::experimental_v3 as v3;
use privoke_contracts::proto::v1::{FuzzerTrainingRequest, FuzzerTrainingResponse};
use privoke_curriculum::audience::{AudienceRelease, BUNDLED_MANIFEST_SHA256};
use privoke_curriculum::v3::{self as curriculum, Sources};
use privoke_curriculum::value::{self, Value};
use privoke_pki::ca::{CaDir, Validity};
use privoke_pki::{files::write_atomic, registry_edit};
use privoke_transport::ClientTlsConfig;
use privoke_transport::startup::CloudTlsArgs;
use privoke_v3_fuzzer::backend::{CheckpointBackend, FitBackend, blob_chunks};
use privoke_v3_fuzzer::contract::{self, MAX_MANIFEST_BYTES, digest};
use privoke_v3_fuzzer::cycle::{Engine, EngineParts};
use privoke_v3_fuzzer::pywire::fuzzer_response_bytes;
use privoke_v3_fuzzer::source::{Closure, Sampler, Schedules};
use prost::Message;
use tonic::{Code, Status};

pub const FIT: &str = "/privoke.experimental.v3.TrainingService/FitCandidate";
pub const FIT_STATUS: &str = "/privoke.experimental.v3.TrainingService/GetFitStatus";
pub const RESOLVE: &str = "/privoke.experimental.v3.CheckpointService/ResolveCurrent";
pub const FETCH: &str = "/privoke.experimental.v3.CheckpointService/FetchBlob";
pub const COMMIT: &str = "/privoke.experimental.v3.CheckpointService/CommitCandidate";
pub const COMMIT_STATUS: &str = "/privoke.experimental.v3.CheckpointService/GetCommitStatus";

pub fn b64(text: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD.decode(text).unwrap()
}

pub fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../crates/privoke-curriculum/tests/fixtures")
}

pub fn read_json(path: &Path) -> serde_json::Value {
    serde_json::from_slice(&std::fs::read(path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))).unwrap()
}

pub fn synthetic_golden() -> serde_json::Value {
    read_json(&Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/v3_fuzzer_cycles_golden.json"))
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

/// One wire message that crossed a boundary: the RPC path, the SHA-256 and the length of the request bytes.
pub type Call = (String, String, usize);

/// The runtime and the checkpoint service in one: each call is logged and answered from the golden `answers` of the cycle.
#[derive(Debug, Default)]
pub struct Scripted {
    pub calls: Mutex<Vec<Call>>,
    pub answers: Mutex<serde_json::Value>,
    pub fit_layers: Mutex<Vec<Vec<i32>>>,
    pub fit_rows: Mutex<Vec<(usize, usize)>>,
}

impl Scripted {
    pub fn set(&self, answers: serde_json::Value) {
        *self.answers.lock().unwrap() = answers;
        self.calls.lock().unwrap().clear();
    }

    pub fn take(&self) -> Vec<Call> {
        std::mem::take(&mut *self.calls.lock().unwrap())
    }

    pub fn log(&self, path: &str, bytes: &[u8]) {
        self.calls.lock().unwrap().push((path.to_string(), digest(bytes), bytes.len()));
    }

    fn answer(&self, key: &str) -> serde_json::Value {
        self.answers.lock().unwrap()[key].clone()
    }

    fn receipt(&self, key: &str) -> Result<v3::Receipt, Status> {
        match self.answer(key) {
            serde_json::Value::String(text) => Ok(v3::Receipt::decode(b64(&text).as_slice()).unwrap()),
            _ => Err(Status::unavailable("no scripted answer")),
        }
    }
}

#[tonic::async_trait]
impl FitBackend for Scripted {
    async fn fit_candidate(&self, request: v3::FitRequest, _timeout: Duration) -> Result<v3::FitResponse, Status> {
        self.log(FIT, &request.encode_to_vec());
        self.fit_layers.lock().unwrap().push(request.layers.clone());
        self.fit_rows.lock().unwrap().push((request.train.len(), request.guard.len()));
        let answer = self.answer("fit");
        match answer["response"].as_str() {
            Some(text) => Ok(v3::FitResponse::decode(b64(text).as_slice()).unwrap()),
            None => Err(Status::unavailable("scripted failure")),
        }
    }

    async fn fit_status(&self, request_id: &str) -> Result<v3::Receipt, Status> {
        self.log(FIT_STATUS, &v3::StatusRequest { request_id: request_id.to_string() }.encode_to_vec());
        self.receipt("fit_status")
    }

    async fn health(&self) -> Result<v3::HealthResponse, Status> {
        Ok(v3::HealthResponse { ready: true, role: "stub".to_string(), capabilities: BTreeMap::new() })
    }
}

#[tonic::async_trait]
impl CheckpointBackend for Scripted {
    async fn resolve_current(&self, model_id: &str) -> Result<v3::Ref, Status> {
        self.log(RESOLVE, &v3::Model { model_id: model_id.to_string() }.encode_to_vec());
        match self.answer("resolve") {
            serde_json::Value::String(sha256) => Ok(v3::Ref { sha256 }),
            _ => Err(Status::unavailable("no scripted answer")),
        }
    }

    async fn fetch_blob(&self, sha256: &str) -> Result<Vec<v3::Chunk>, Status> {
        self.log(FETCH, &v3::Ref { sha256: sha256.to_string() }.encode_to_vec());
        match self.answer("fetch") {
            serde_json::Value::String(text) => Ok(blob_chunks(&b64(&text))),
            _ => Err(Status::unavailable("no scripted answer")),
        }
    }

    async fn commit_candidate(&self, commit: v3::Commit) -> Result<v3::Receipt, Status> {
        self.log(COMMIT, &commit.encode_to_vec());
        match self.answer("commit")["receipt"].as_str() {
            Some(text) => Ok(v3::Receipt::decode(b64(text).as_slice()).unwrap()),
            None => Err(Status::unavailable("scripted failure")),
        }
    }

    async fn commit_status(&self, request_id: &str) -> Result<v3::Receipt, Status> {
        self.log(COMMIT_STATUS, &v3::StatusRequest { request_id: request_id.to_string() }.encode_to_vec());
        self.receipt("commit_status")
    }

    async fn health(&self) -> Result<v3::HealthResponse, Status> {
        Ok(v3::HealthResponse { ready: true, role: "stub".to_string(), capabilities: BTreeMap::new() })
    }
}

/// The pinned inputs of the two samplers, loaded once from the committed fixtures.
#[derive(Debug)]
pub struct Inputs {
    pub sources: Sources,
    pub release: AudienceRelease,
}

impl Inputs {
    pub fn load() -> Self {
        let root = fixtures();
        let paths: BTreeMap<&str, PathBuf> = [
            ("taxonomy", "bc01/taxonomy-coverage-v1.json"),
            ("pool", "bc01/pool-authored.json"),
            ("manifest", "bc01/benign-manifest.json"),
            ("proof", "bc01/exclusion-proof.json"),
        ]
        .into_iter()
        .map(|(key, relative)| (key, root.join(relative)))
        .collect();
        let sources = curriculum::load_sources_from(&paths).unwrap();
        let manifest = root.join("au3/audience-v3-manifest-v1.json");
        let release = curriculum::trusted_release(Some(manifest.as_path()), Some(BUNDLED_MANIFEST_SHA256)).unwrap();
        Self { sources, release }
    }

    pub fn schedules(&self, sampler: Sampler, source_hashes: Value) -> Schedules {
        match sampler {
            Sampler::Bc01 => Schedules::bc01(self.sources.clone(), source_hashes),
            Sampler::Au3 => Schedules::au3(self.release.clone(), source_hashes),
        }
    }
}

pub fn code_name(code: Code) -> String {
    let name = match code {
        Code::FailedPrecondition => "FAILED_PRECONDITION",
        Code::InvalidArgument => "INVALID_ARGUMENT",
        Code::AlreadyExists => "ALREADY_EXISTS",
        Code::Unknown => "UNKNOWN",
        Code::PermissionDenied => "PERMISSION_DENIED",
        other => return format!("{other:?}"),
    };
    name.to_string()
}

/// The engine of one golden sequence: its policy, its sampler, its recorded source digests and the scripted services.
pub async fn engine_for(sequence: &serde_json::Value, inputs: &Inputs, directory: &Path, scripted: &Arc<Scripted>) -> Engine {
    engine_with(sequence, inputs, directory, scripted, scripted.clone()).await
}

/// [`engine_for`] with the checkpoint service of the caller's choice (the runtime stays scripted).
pub async fn engine_with(
    sequence: &serde_json::Value,
    inputs: &Inputs,
    directory: &Path,
    scripted: &Arc<Scripted>,
    checkpoint: Arc<dyn CheckpointBackend>,
) -> Engine {
    let policy = contract::parse(&b64(sequence["policy_json"].as_str().unwrap()), MAX_MANIFEST_BYTES).unwrap();
    let sampler = Sampler::parse(sequence["sampler"].as_str().unwrap()).unwrap();
    let hashes = value::parse_bytes(sequence["source_hashes"].to_string().as_bytes()).unwrap();
    let parts = EngineParts {
        policy,
        schedules: inputs.schedules(sampler, hashes),
        directory: directory.to_path_buf(),
        fit_timeout: Duration::from_secs(60),
        closure: Closure::Fixed(sequence["source_closure"].as_str().unwrap().to_string()),
    };
    Engine::new(parts, scripted.clone(), checkpoint).await.unwrap()
}

pub fn scope_of(cycle: &serde_json::Value) -> v3::Scope {
    match cycle["scope"].as_str().unwrap() {
        "heads" => v3::Scope::Heads,
        _ => v3::Scope::FullEncoder,
    }
}

/// The counts of one replay.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Counts {
    pub sequences: usize,
    pub cycles: usize,
    pub ok: usize,
    pub aborted: usize,
    pub raised: usize,
    pub wire_messages: usize,
    pub files: usize,
    pub rows: usize,
}

impl Counts {
    pub fn add(&mut self, other: Counts) {
        self.sequences += other.sequences;
        self.cycles += other.cycles;
        self.ok += other.ok;
        self.aborted += other.aborted;
        self.raised += other.raised;
        self.wire_messages += other.wire_messages;
        self.files += other.files;
        self.rows += other.rows;
    }
}

/// Replay one sequence and require everything observable to equal the oracle's: the health answer, each cycle's response or
/// abort, every wire message (path, length and SHA-256, in order), every file of the work directory (name, length and SHA-256)
/// and the rows of the `cycles` table.
pub async fn replay_sequence(sequence: &serde_json::Value, inputs: &Inputs) -> Counts {
    replay_sequence_with(sequence, inputs, |scripted| scripted.clone()).await
}

/// [`replay_sequence`] against the checkpoint service that `checkpoint` builds over the scripted services (which log every wire
/// message the cycle sends, whoever answers it).
pub async fn replay_sequence_with(
    sequence: &serde_json::Value,
    inputs: &Inputs,
    checkpoint: impl FnOnce(&Arc<Scripted>) -> Arc<dyn CheckpointBackend>,
) -> Counts {
    let label = sequence["label"].as_str().unwrap();
    let state = tempfile::tempdir().unwrap();
    let scripted = Arc::new(Scripted::default());
    let service = checkpoint(&scripted);
    let engine = engine_with(sequence, inputs, &state.path().join("state"), &scripted, service).await;
    let mut counts = Counts { sequences: 1, ..Counts::default() };
    assert_eq!(engine.health().unwrap().encode_to_vec(), b64(sequence["health"].as_str().unwrap()), "{label}: health");

    for cycle in sequence["cycles"].as_array().unwrap() {
        let name = format!("{label} / {}", cycle["label"].as_str().unwrap());
        scripted.set(cycle["answers"].clone());
        let request = FuzzerTrainingRequest::decode(b64(cycle["request"].as_str().unwrap()).as_slice()).unwrap();
        let outcome = engine.run(request.clone(), scope_of(cycle)).await;
        counts.cycles += 1;
        let expected = &cycle["outcome"];
        if let Some(response) = expected.get("ok") {
            let response_bytes = b64(response.as_str().unwrap());
            let actual = outcome.unwrap_or_else(|status| panic!("{name}: expected a response, got {status:?}"));
            assert_eq!(fuzzer_response_bytes(&actual), response_bytes, "{name}: response bytes");
            assert_eq!(FuzzerTrainingResponse::decode(response_bytes.as_slice()).unwrap(), actual, "{name}: response message");
            counts.ok += 1;
        } else if let Some(abort) = expected.get("abort") {
            let status = outcome.expect_err(&name);
            assert_eq!(
                (code_name(status.code()), status.message().to_string()),
                (abort[0].as_str().unwrap().to_string(), abort[1].as_str().unwrap().to_string()),
                "{name}: abort"
            );
            counts.aborted += 1;
        } else {
            let error = &expected["error"];
            let status = outcome.expect_err(&name);
            assert_eq!(status.code(), Code::Unknown, "{name}: an uncaught exception is UNKNOWN");
            assert_eq!(status.message(), error[1].as_str().unwrap(), "{name}: {} message", error[0].as_str().unwrap());
            counts.raised += 1;
        }

        let wire: Vec<serde_json::Value> =
            scripted.take().into_iter().map(|(path, sha, length)| serde_json::json!([path, sha, length])).collect();
        assert_eq!(serde_json::Value::Array(wire), cycle["wire"], "{name}: wire messages");
        counts.wire_messages += cycle["wire"].as_array().unwrap().len();

        let work = engine.work_directory(&request.request_id);
        match cycle["work_dir"].as_str() {
            None => assert!(!work.exists(), "{name}: no work directory is created"),
            Some(directory) => {
                assert_eq!(work.file_name().unwrap().to_string_lossy(), directory, "{name}: work directory name");
                let mut actual = serde_json::Map::new();
                for entry in std::fs::read_dir(&work).unwrap() {
                    let path = entry.unwrap().path();
                    let bytes = std::fs::read(&path).unwrap();
                    actual
                        .insert(path.file_name().unwrap().to_string_lossy().to_string(), serde_json::json!([digest(&bytes), bytes.len()]));
                }
                assert_eq!(serde_json::Value::Object(actual), cycle["files"], "{name}: work directory files");
                counts.files += cycle["files"].as_object().unwrap().len();
            }
        }
    }

    let rows: Vec<serde_json::Value> = engine
        .rows()
        .await
        .unwrap()
        .into_iter()
        .map(|(id, fingerprint, response)| {
            serde_json::json!([id, fingerprint, response.map(|bytes| base64::engine::general_purpose::STANDARD.encode(bytes))])
        })
        .collect();
    assert_eq!(serde_json::Value::Array(rows), sequence["sqlite"], "{label}: cycles rows");
    counts.rows += sequence["sqlite"].as_array().unwrap().len();

    // Semantic-only: every fit request listed exactly the semantic layer, never an empty list.
    let layers = scripted.fit_layers.lock().unwrap();
    assert!(layers.iter().all(|list| *list == vec![4]), "{label}: every fit request selects exactly [SEMANTIC]");
    counts
}
