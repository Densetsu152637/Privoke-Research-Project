//! The Rust reporter against the Rust telemetry service (stage 4) in process, over mutual TLS with the shared reporter
//! credential: delivery, refusal of a credential that is not the reporter's, and outage and recovery of the delivery
//! path (reports sent while the collector is down are lost and still spend budget; reports after it returns arrive).
//! Certificates are issued at test time; nothing here is committed key material.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::mpsc;
use std::time::Duration;

use privoke_contracts::proto::v1::GetTelemetrySummaryRequest;
use privoke_contracts::proto::v1::telemetry_service_client::TelemetryServiceClient;
use privoke_pki::ca::{CaDir, Validity};
use privoke_pki::{files::write_atomic, registry_edit};
use privoke_telemetry::daily::DailyCap;
use privoke_telemetry::server::{self, Listen, ServerHandle};
use privoke_telemetry::service::TelemetryCollector;
use privoke_telemetry::storage::TelemetryStore;
use privoke_telemetry_client::grpc::{GrpcTransport, ReporterChannel, ReporterEndpoint};
use privoke_telemetry_client::{
    AnalysisInput, AnalysisResult, DeliveryObserver, DeliveryOutcome, OsRandom, ReportOutcome, ReporterParts, ReporterSettings,
    TelemetryReporter,
};
use privoke_transport::startup::CloudTlsArgs;
use privoke_transport::{ClientTlsConfig, Limits, RateLimit};
use time::{Duration as TimeDuration, OffsetDateTime};

struct Pki {
    dir: tempfile::TempDir,
    client_ca: CaDir,
}

#[derive(Clone)]
struct Credential {
    cert: PathBuf,
    key: PathBuf,
}

impl Pki {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let validity = Validity::days(30);
        let client_ca = CaDir::init(&dir.path().join("client-ca"), "Test Client CA", validity).unwrap();
        let server_ca = CaDir::init(&dir.path().join("server-ca"), "Test Server CA", validity).unwrap();
        let server = server_ca.issue_server(&["localhost".to_string(), "127.0.0.1".to_string()], validity).unwrap();
        write_atomic(&dir.path().join("server.crt"), server.cert_pem.as_bytes(), false).unwrap();
        write_atomic(&dir.path().join("server.key"), server.key_pem.as_bytes(), true).unwrap();
        client_ca.issue_reporter(validity).unwrap();
        let pki = Self { dir, client_ca };
        let crl = pki.client_ca.crl_pem(OffsetDateTime::now_utc(), TimeDuration::days(7)).unwrap();
        write_atomic(&pki.path("crl.pem"), crl.as_bytes(), false).unwrap();
        registry_edit::set_reporter(&pki.path("registry.toml"), true).unwrap();
        pki
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn reporter(&self) -> Credential {
        let (cert, key) = self.client_ca.reporter().unwrap().unwrap();
        write_atomic(&self.path("reporter/reporter.crt"), cert.as_bytes(), false).unwrap();
        write_atomic(&self.path("reporter/reporter.key"), key.as_bytes(), true).unwrap();
        Credential { cert: self.path("reporter/reporter.crt"), key: self.path("reporter/reporter.key") }
    }

    fn service(&self, name: &str, role: &str) -> Credential {
        let issued = self.client_ca.issue_service(name, Validity::days(30)).unwrap();
        let directory = self.path(&format!("svc-{name}"));
        write_atomic(&directory.join("service.crt"), issued.cert_pem.as_bytes(), false).unwrap();
        write_atomic(&directory.join("service.key"), issued.key_pem.as_bytes(), true).unwrap();
        registry_edit::add_service(&self.path("registry.toml"), name, role, issued.not_after).unwrap();
        Credential { cert: directory.join("service.crt"), key: directory.join("service.key") }
    }

    fn tls_config(&self, credential: &Credential) -> ClientTlsConfig {
        ClientTlsConfig {
            server_ca: self.path("server-ca/ca.crt"),
            identity: Some((credential.cert.clone(), credential.key.clone())),
            server_name: "localhost".to_string(),
        }
    }

    async fn start(&self, public: SocketAddr) -> ServerHandle {
        let transport = CloudTlsArgs {
            cert: Some(self.path("server.crt")),
            key: Some(self.path("server.key")),
            client_ca: Some(self.path("client-ca/ca.crt")),
            crl: Some(self.path("crl.pem")),
            registry: Some(self.path("registry.toml")),
        }
        .into_config()
        .unwrap();
        std::fs::create_dir_all(self.path("data")).unwrap();
        let store = TelemetryStore::open(self.path("data/telemetry-ldp-v1.sqlite3")).unwrap();
        let internal: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let limits = Limits { rate: RateLimit { per_second: 1000, burst: 1000 }, ..Limits::default() };
        server::start(
            Listen { public, internal },
            TelemetryCollector::new(store, DailyCap::new(1000)),
            transport,
            limits,
            Duration::from_millis(50),
        )
        .await
        .unwrap()
    }

    /// The number of stored reports, read on the internal listener. `reader` must have been issued before the server
    /// started: the registry is polled, and a service added afterwards may not be admitted yet.
    async fn summary_count(&self, server: &ServerHandle, reader: &Credential) -> u64 {
        let channel = privoke_transport::client::connect(&server.internal_addr.to_string(), &self.tls_config(reader)).await.unwrap();
        let mut client = TelemetryServiceClient::new(channel);
        client.get_telemetry_summary(GetTelemetrySummaryRequest {}).await.unwrap().into_inner().sample_count
    }
}

fn analysis(action: &str) -> AnalysisInput {
    AnalysisInput {
        action: action.to_string(),
        result: Some(AnalysisResult { classification: None, model_version: Some("v0.3.0".to_string()) }),
    }
}

struct Harness {
    reporter: Arc<TelemetryReporter>,
    outcomes: mpsc::Receiver<DeliveryOutcome>,
}

fn reporter(pki: &Pki, credential: &Credential, target: SocketAddr, ledger: &Path) -> Harness {
    let endpoint = ReporterEndpoint { target: target.to_string(), channel: ReporterChannel::MutualTls(pki.tls_config(credential)) };
    let transport = GrpcTransport::new(endpoint).unwrap();
    let (sender, outcomes) = mpsc::channel();
    let observer: DeliveryObserver = Arc::new(move |outcome: &DeliveryOutcome| {
        let _ = sender.send(outcome.clone());
    });
    let settings = ReporterSettings {
        event_epsilon: 0.5,
        daily_epsilon: 2.0,
        ledger_path: Some(ledger.to_path_buf()),
        timeout: Duration::from_secs(10),
        queue_size: 16,
    };
    let reporter = TelemetryReporter::with_parts(
        settings,
        ReporterParts {
            transport: Box::new(transport),
            random: Box::new(OsRandom),
            clock: Box::new(OffsetDateTime::now_utc),
            observer: Some(observer),
        },
    )
    .unwrap();
    Harness { reporter: Arc::new(reporter), outcomes }
}

fn wait_for(harness: &Harness, count: usize) -> Vec<DeliveryOutcome> {
    (0..count).map(|_| harness.outcomes.recv_timeout(Duration::from_secs(30)).expect("a delivery outcome")).collect()
}

async fn close(harness: &Harness) {
    let reporter = Arc::clone(&harness.reporter);
    tokio::task::spawn_blocking(move || reporter.close(Duration::from_secs(30))).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_reporter_delivers_with_the_reporter_credential_and_stops_at_the_daily_cap() {
    let pki = Pki::new();
    let reader = pki.service("summary-reader", "runtime");
    let server = pki.start("127.0.0.1:0".parse().unwrap()).await;
    let harness = reporter(&pki, &pki.reporter(), server.public_addr, &pki.path("ledger/budget.sqlite3"));
    for action in ["ALLOW", "WARN", "BLOCK", "ALLOW"] {
        assert_eq!(harness.reporter.report(&analysis(action)), ReportOutcome::Queued);
    }
    let outcomes = tokio::task::block_in_place(|| wait_for(&harness, 4));
    assert!(outcomes.iter().all(|outcome| *outcome == DeliveryOutcome::Accepted), "{outcomes:?}");
    // Daily epsilon 2.0 at 0.5 per report: the fifth report is suppressed before anything is built or sent.
    assert_eq!(harness.reporter.report(&analysis("ALLOW")), ReportOutcome::BudgetExhausted);
    close(&harness).await;
    assert_eq!(pki.summary_count(&server, &reader).await, 4);
    server.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_credential_that_is_not_the_reporters_is_refused_and_still_spends_budget() {
    let pki = Pki::new();
    let reader = pki.service("summary-reader", "runtime");
    let impostor = pki.service("client-runtime", "runtime");
    let server = pki.start("127.0.0.1:0".parse().unwrap()).await;
    let harness = reporter(&pki, &impostor, server.public_addr, &pki.path("ledger/budget.sqlite3"));
    for _ in 0..2 {
        assert_eq!(harness.reporter.report(&analysis("WARN")), ReportOutcome::Queued);
    }
    let outcomes = tokio::task::block_in_place(|| wait_for(&harness, 2));
    for outcome in &outcomes {
        assert_eq!(*outcome, DeliveryOutcome::RpcFailed { code: "StatusCode.PERMISSION_DENIED".to_string() }, "{outcomes:?}");
    }
    close(&harness).await;
    assert_eq!(pki.summary_count(&server, &reader).await, 0);
    server.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_outage_loses_the_reports_sent_during_it_and_the_next_ones_arrive() {
    let pki = Pki::new();
    let reader = pki.service("summary-reader", "runtime");
    // A loopback port that nothing listens on yet.
    let address: SocketAddr = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap()
    };
    let harness = reporter(&pki, &pki.reporter(), address, &pki.path("ledger/budget.sqlite3"));
    for _ in 0..2 {
        assert_eq!(harness.reporter.report(&analysis("ALLOW")), ReportOutcome::Queued);
    }
    let during = tokio::task::block_in_place(|| wait_for(&harness, 2));
    for outcome in &during {
        assert_eq!(*outcome, DeliveryOutcome::RpcFailed { code: "StatusCode.UNAVAILABLE".to_string() }, "{during:?}");
    }
    // The collector comes back on the same address; the same reporter, with no restart, delivers again.
    let server = pki.start(address).await;
    for _ in 0..2 {
        assert_eq!(harness.reporter.report(&analysis("BLOCK")), ReportOutcome::Queued);
    }
    let after = tokio::task::block_in_place(|| wait_for(&harness, 2));
    assert!(after.iter().all(|outcome| *outcome == DeliveryOutcome::Accepted), "{after:?}");
    // The two lost reports were never refunded: all four reservations of the daily 2.0 are spent.
    assert_eq!(harness.reporter.report(&analysis("ALLOW")), ReportOutcome::BudgetExhausted);
    close(&harness).await;
    assert_eq!(pki.summary_count(&server, &reader).await, 2);
    server.shutdown().await.unwrap();
}
