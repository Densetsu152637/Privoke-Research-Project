//! Shared harness: a real transport server over the tool-issued files, and a health client.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use privoke_pki::ca::{CaDir, Validity};
use privoke_transport::client;
use privoke_transport::registry::RegistryFileReloader;
use privoke_transport::reload::WatcherGuard;
use privoke_transport::tls::{ClientTlsConfig, ServerTlsConfig};
use privoke_transport::{AuthLayer, LimiterKey, Limits, Policy, ReloadableTls, Role, SecureListener, secure_server};
use tokio::sync::oneshot;
use tonic_health::pb::HealthCheckRequest;
use tonic_health::pb::health_client::HealthClient;

pub const BIN: &str = env!("CARGO_BIN_EXE_privoke-pki");

pub fn pki(args: &[&str]) -> String {
    let output = Command::new(BIN).args(args).output().unwrap();
    assert!(output.status.success(), "privoke-pki {args:?} failed: {}", String::from_utf8_lossy(&output.stderr));
    String::from_utf8_lossy(&output.stdout).into_owned()
}

pub fn pki_fails(args: &[&str]) -> String {
    let output = Command::new(BIN).args(args).output().unwrap();
    assert!(!output.status.success(), "privoke-pki {args:?} unexpectedly succeeded");
    String::from_utf8_lossy(&output.stderr).into_owned()
}

pub fn s(path: &Path) -> &str {
    path.to_str().unwrap()
}

/// An operator workspace: client CA, server CA, server certificate, reporter credential, registry and CRL paths.
pub struct Operator {
    pub dir: tempfile::TempDir,
}

impl Operator {
    pub fn new() -> Self {
        let operator = Self { dir: tempfile::tempdir().unwrap() };
        pki(&["init-ca", "--dir", s(&operator.client_ca()), "--name", "Test Client CA"]);
        pki(&["init-ca", "--dir", s(&operator.server_ca()), "--name", "Test Server CA"]);
        pki(&[
            "issue-server",
            "--ca-dir",
            s(&operator.server_ca()),
            "--dns",
            "localhost",
            "--dns",
            "127.0.0.1",
            "--out-dir",
            s(&operator.server_dir()),
        ]);
        pki(&["issue-reporter", "--ca-dir", s(&operator.client_ca())]);
        pki(&["crl", "--ca-dir", s(&operator.client_ca()), "--out", s(&operator.crl())]);
        privoke_pki::registry_edit::set_reporter(&operator.registry(), true).unwrap();
        operator
    }

    pub fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    pub fn client_ca(&self) -> PathBuf {
        self.path("client-ca")
    }

    pub fn server_ca(&self) -> PathBuf {
        self.path("server-ca")
    }

    pub fn server_dir(&self) -> PathBuf {
        self.path("server")
    }

    pub fn crl(&self) -> PathBuf {
        self.path("crl.pem")
    }

    pub fn registry(&self) -> PathBuf {
        self.path("registry.toml")
    }

    pub fn ca(&self) -> CaDir {
        CaDir::open(&self.client_ca()).unwrap()
    }

    pub fn server_ca_pem(&self) -> String {
        std::fs::read_to_string(self.server_ca().join("ca.crt")).unwrap()
    }

    pub fn refresh_crl(&self) {
        pki(&["crl", "--ca-dir", s(&self.client_ca()), "--out", s(&self.crl())]);
    }

    pub fn validity(days: i64) -> Validity {
        Validity::days(days)
    }

    /// A client configuration over a credential directory that holds `client.crt`, `client.key` and `server-ca.pem`.
    pub fn client_config(&self, dir: &Path) -> ClientTlsConfig {
        ClientTlsConfig {
            server_ca: self.server_ca().join("ca.crt"),
            identity: Some((dir.join("client.crt"), dir.join("client.key"))),
            server_name: "localhost".to_string(),
        }
    }
}

pub struct Server {
    pub address: SocketAddr,
    pub tls: ReloadableTls,
    pub registry: RegistryFileReloader,
    shutdown: Option<oneshot::Sender<()>>,
    _guards: (WatcherGuard, WatcherGuard),
}

impl Drop for Server {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
    }
}

impl Server {
    pub async fn start(operator: &Operator) -> Self {
        let tls = ReloadableTls::load(ServerTlsConfig::new(
            operator.server_dir().join("server.crt"),
            operator.server_dir().join("server.key"),
            operator.client_ca().join("ca.crt"),
            operator.crl(),
        ))
        .unwrap();
        let registry = RegistryFileReloader::load(operator.registry()).unwrap();
        let guards = (tls.spawn_watcher(Duration::from_millis(50)), registry.spawn_watcher(Duration::from_millis(50)));
        let limits = Limits::default();
        let policy =
            Policy::new().allow("/grpc.health.v1.Health/Check", &[Role::Consumer, Role::Publisher, Role::Reporter], LimiterKey::Identity);
        let auth = AuthLayer::new(policy, registry.registry(), limits.rate);
        let listener = SecureListener::bind("127.0.0.1:0".parse().unwrap(), tls.clone(), limits.clone()).await.unwrap();
        let address = listener.local_addr().unwrap();
        let (_reporter, health) = tonic_health::server::health_reporter();
        let (shutdown, signal) = oneshot::channel::<()>();
        let server = secure_server(&limits, auth).add_service(health);
        tokio::spawn(async move {
            let _ = server
                .serve_with_incoming_shutdown(listener.incoming(), async {
                    let _ = signal.await;
                })
                .await;
        });
        Self { address, tls, registry, shutdown: Some(shutdown), _guards: guards }
    }

    pub async fn connect(&self, config: &ClientTlsConfig) -> Result<HealthClient<tonic::transport::Channel>, tonic::Status> {
        let channel =
            client::connect(&self.address.to_string(), config).await.map_err(|error| tonic::Status::unavailable(error.to_string()))?;
        Ok(HealthClient::new(channel))
    }

    /// Connect and call; every failure is an `Err`.
    pub async fn check(&self, config: &ClientTlsConfig) -> Result<(), tonic::Status> {
        self.connect(config).await?.check(HealthCheckRequest { service: String::new() }).await.map(|_| ())
    }
}

pub async fn eventually<F, Fut>(mut check: F) -> bool
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        if check().await {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}
