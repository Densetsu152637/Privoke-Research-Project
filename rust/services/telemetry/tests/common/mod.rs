//! Shared helpers: a private PKI issued at test time, an in-process server, mutual-TLS clients (optionally bound to a
//! chosen loopback source address) and packet builders. No key or certificate is committed; every run issues its own.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use hyper_util::rt::TokioIo;
use privoke_contracts::proto::v1::TelemetryPacket;
use privoke_contracts::proto::v1::telemetry_service_client::TelemetryServiceClient;
use privoke_pki::ca::{CaDir, Validity};
use privoke_pki::{client as enrolment, files::write_atomic, registry_edit};
use privoke_telemetry::daily::DailyCap;
use privoke_telemetry::server::{self, Listen, ServerHandle};
use privoke_telemetry::service::TelemetryCollector;
use privoke_telemetry::storage::TelemetryStore;
use privoke_transport::startup::CloudTlsArgs;
use privoke_transport::tls::build_client_config;
use privoke_transport::{ClientTlsConfig, Limits};
use rustls::pki_types::ServerName;
use time::{Duration as TimeDuration, OffsetDateTime};
use tokio::net::TcpSocket;
use tokio_rustls::TlsConnector;
use tonic::transport::{Channel, Endpoint, Uri};
use tonic::{Code, Status};

/// A credential on disk.
#[derive(Debug, Clone)]
pub struct Creds {
    pub id: String,
    pub cert: PathBuf,
    pub key: PathBuf,
}

/// The two CAs, the server certificate, the registry and the CRL of one test.
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
        let foreign_ca = CaDir::init(&dir.path().join("foreign-ca"), "Foreign Client CA", validity).unwrap();
        let server = server_ca.issue_server(&["localhost".to_string(), "127.0.0.1".to_string()], validity).unwrap();
        write_atomic(&dir.path().join("server.crt"), server.cert_pem.as_bytes(), false).unwrap();
        write_atomic(&dir.path().join("server.key"), server.key_pem.as_bytes(), true).unwrap();
        client_ca.issue_reporter(validity).unwrap();
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

    pub fn database(&self) -> PathBuf {
        self.path("data/telemetry-ldp-v1.sqlite3")
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

    /// An installation certificate under the real client CA, registered or not.
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

    /// An installation certificate from a CA the server does not trust.
    pub fn foreign(&self, name: &str) -> Creds {
        let dir = self.path(name);
        std::fs::create_dir_all(&dir).unwrap();
        let enrolment = enrolment::enrol(&dir).unwrap();
        let csr = std::fs::read_to_string(&enrolment.csr_path).unwrap();
        let signed = self.foreign_ca.sign_installation(&csr, &enrolment.installation, Validity::days(30)).unwrap();
        write_atomic(&dir.join("client.crt"), signed.cert_pem.as_bytes(), false).unwrap();
        Creds { id: enrolment.installation, cert: dir.join("client.crt"), key: dir.join("client.key") }
    }

    pub fn service(&self, name: &str, role: &str) -> Creds {
        let issued = self.client_ca.issue_service(name, Validity::days(30)).unwrap();
        let dir = self.path(&format!("svc-{name}"));
        write_atomic(&dir.join("service.crt"), issued.cert_pem.as_bytes(), false).unwrap();
        write_atomic(&dir.join("service.key"), issued.key_pem.as_bytes(), true).unwrap();
        registry_edit::add_service(&self.registry(), name, role, issued.not_after).unwrap();
        Creds { id: name.to_string(), cert: dir.join("service.crt"), key: dir.join("service.key") }
    }

    pub fn reporter(&self) -> Creds {
        let (cert, key) = self.client_ca.reporter().unwrap().unwrap();
        let dir = self.path("reporter");
        write_atomic(&dir.join("reporter.crt"), cert.as_bytes(), false).unwrap();
        write_atomic(&dir.join("reporter.key"), key.as_bytes(), true).unwrap();
        Creds { id: "reporter".into(), cert: dir.join("reporter.crt"), key: dir.join("reporter.key") }
    }

    pub fn client_config(&self, creds: Option<&Creds>) -> ClientTlsConfig {
        ClientTlsConfig {
            server_ca: self.path("server-ca/ca.crt"),
            identity: creds.map(|creds| (creds.cert.clone(), creds.key.clone())),
            server_name: "localhost".to_string(),
        }
    }

    /// Start the in-process server over a fresh database.
    pub async fn start(&self, limits: Limits, daily_cap: u32) -> ServerHandle {
        let transport = self.tls_args().into_config().unwrap();
        let store = TelemetryStore::open(self.database()).unwrap();
        let any = "127.0.0.1:0".parse().unwrap();
        server::start(
            Listen { public: any, internal: any },
            TelemetryCollector::new(store, DailyCap::new(daily_cap)),
            transport,
            limits,
            Duration::from_millis(50),
        )
        .await
        .unwrap()
    }

    /// A client from the default loopback source address.
    pub async fn client(&self, address: SocketAddr, creds: Option<&Creds>) -> TelemetryServiceClient<Channel> {
        let channel = privoke_transport::client::connect(&address.to_string(), &self.client_config(creds)).await.expect("connect");
        TelemetryServiceClient::new(channel)
    }

    /// A client whose TCP connection leaves from `source` (a loopback address such as `127.0.0.2`), so the server
    /// sees that address as the peer. Everything else matches `privoke_transport::client::connect`.
    pub async fn client_from(&self, source: IpAddr, address: SocketAddr, creds: &Creds) -> TelemetryServiceClient<Channel> {
        let config = build_client_config(&self.client_config(Some(creds))).unwrap();
        let connector = TlsConnector::from(config);
        let name = ServerName::try_from("localhost".to_string()).unwrap();
        let service = tower::service_fn(move |_uri: Uri| {
            let connector = connector.clone();
            let name = name.clone();
            async move {
                let socket = TcpSocket::new_v4()?;
                socket.bind(SocketAddr::new(source, 0))?;
                let tcp = socket.connect(address).await?;
                let stream = connector.connect(name, tcp).await?;
                Ok::<_, io::Error>(TokioIo::new(stream))
            }
        });
        let endpoint = Endpoint::from_shared(format!("http://{address}")).unwrap();
        TelemetryServiceClient::new(endpoint.connect_with_connector(service).await.expect("connect from source"))
    }
}

pub fn code<T>(result: Result<T, Status>) -> Code {
    match result {
        Ok(_) => Code::Ok,
        Err(status) => status.code(),
    }
}

pub fn valid_packet() -> TelemetryPacket {
    packet(|_| {})
}

/// The Python tests' `valid_packet` with `change` applied.
pub fn packet(change: impl FnOnce(&mut TelemetryPacket)) -> TelemetryPacket {
    let mut packet = TelemetryPacket {
        time_bucket: "12-16_UTC".into(),
        action: "WARN".into(),
        primary_category: "HEALTH".into(),
        risk_bucket: "0.5-0.8".into(),
        model_version: "v0.3.0".into(),
        privacy_mechanism: "grr_rr_v1".into(),
        privacy_epsilon: 1.0,
    };
    change(&mut packet);
    packet
}

pub fn temp_store() -> (tempfile::TempDir, TelemetryStore) {
    let directory = tempfile::tempdir().unwrap();
    let store = TelemetryStore::open(directory.path().join("telemetry.db")).unwrap();
    (directory, store)
}

pub fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

pub fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(name)
}

/// The host Python environment for the emitter check (`PRIVOKE_HOST_PYTHON`, an interpreter that has `grpcio` and
/// `protobuf`) and a directory holding the generated `privoke/v1` protobuf modules (`PRIVOKE_PY_GENERATED`, made with
/// `evaluation/setup-host.py` or `python -m grpc_tools.protoc`). `None` when either is not configured.
pub fn host_python() -> Option<(PathBuf, PathBuf)> {
    let python = std::env::var_os("PRIVOKE_HOST_PYTHON").filter(|value| !value.is_empty())?;
    let generated = std::env::var_os("PRIVOKE_PY_GENERATED").filter(|value| !value.is_empty())?;
    Some((python.into(), generated.into()))
}

/// Run `emitter_check.py` with the given credential against `target` (`host:port`); returns the exit success flag
/// and the stdout summary line.
pub fn run_emitter(
    python: &Path,
    generated: &Path,
    target: &str,
    ca: &Path,
    creds: &Creds,
    mode: &str,
    reports: u32,
) -> (bool, String, String) {
    let output = std::process::Command::new(python)
        .arg("-I")
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/emitter_check.py"))
        .args(["--target", target, "--mode", mode, "--reports", &reports.to_string()])
        .arg("--cert")
        .arg(&creds.cert)
        .arg("--key")
        .arg(&creds.key)
        .arg("--ca")
        .arg(ca)
        .arg("--generated")
        .arg(generated)
        .output()
        .expect("run the host Python emitter check");
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).trim().to_string(),
        String::from_utf8_lossy(&output.stderr).trim().to_string(),
    )
}
