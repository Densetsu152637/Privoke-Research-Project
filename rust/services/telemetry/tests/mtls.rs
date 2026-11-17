//! Mutual TLS end to end, in process and against the built binary: the authorisation policy (R10 in its in-process
//! form), per-source limits, no stored or logged identity, fail-closed startup and the `healthcheck` subcommand.
//! The container form of R10 and the Python emitter check are in `container.rs` and `emitter.rs`.
//!
//! Source addresses other than `127.0.0.1` come from binding the client socket to `127.0.0.2` and `127.0.0.3`, which
//! are loopback on Windows and Linux; the server sees them as distinct peers holding the same certificate.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::io::Read;
use std::net::{IpAddr, SocketAddr, TcpListener};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use common::{Creds, Env, code, packet, valid_packet};
use privoke_contracts::digest::sha256_hex;
use privoke_contracts::proto::v1::{GetTelemetrySummaryRequest, TelemetryHealthRequest};
use privoke_transport::{Limits, RateLimit};
use tonic::Code;

const BINARY: &str = env!("CARGO_BIN_EXE_telemetry-service");

fn source(last: u8) -> IpAddr {
    IpAddr::from([127, 0, 0, last])
}

fn generous() -> Limits {
    Limits { rate: RateLimit { per_second: 1000, burst: 1000 }, ..Limits::default() }
}

#[tokio::test]
async fn reporters_record_on_the_public_listener_and_only_services_read_the_summary() {
    let env = Env::new();
    let reporter = env.reporter();
    let runtime = env.service("client-runtime", "runtime");
    let server = env.start(generous(), 100).await;

    let mut client = env.client(server.public_addr, Some(&reporter)).await;
    assert_eq!(client.health(TelemetryHealthRequest {}).await.unwrap().into_inner().status, "SERVING");
    let response = client.record_telemetry(valid_packet()).await.unwrap().into_inner();
    assert!(response.accepted);
    assert_eq!(response.message, "Protected report added to aggregates.");
    // The summary is not served to the credential that every installation holds.
    assert_eq!(code(client.get_telemetry_summary(GetTelemetrySummaryRequest {}).await), Code::Unimplemented);

    // The internal listener serves registered services only: summary and health, never RecordTelemetry.
    let mut internal = env.client(server.internal_addr, Some(&runtime)).await;
    assert_eq!(internal.get_telemetry_summary(GetTelemetrySummaryRequest {}).await.unwrap().into_inner().sample_count, 1);
    assert_eq!(internal.health(TelemetryHealthRequest {}).await.unwrap().into_inner().service, "telemetry-service");
    assert_eq!(code(internal.record_telemetry(valid_packet()).await), Code::Unimplemented);
    let mut reporter_internal = env.client(server.internal_addr, Some(&reporter)).await;
    assert_eq!(code(reporter_internal.get_telemetry_summary(GetTelemetrySummaryRequest {}).await), Code::PermissionDenied);
    assert_eq!(code(reporter_internal.health(TelemetryHealthRequest {}).await), Code::PermissionDenied);
    // A service identity cannot report: the public listener is the reporter's.
    let mut service_public = env.client(server.public_addr, Some(&runtime)).await;
    assert_eq!(code(service_public.record_telemetry(valid_packet()).await), Code::PermissionDenied);
    server.shutdown().await.unwrap();
}

/// R10 in process: no certificate, and a registered installation certificate, are both refused; neither stores a
/// report. The same rows run against the container in `container.rs`.
#[tokio::test]
async fn r10_requests_without_a_certificate_or_with_an_installation_certificate_are_rejected() {
    let env = Env::new();
    let reporter = env.reporter();
    let installation = env.installation("alice", true);
    let stranger = env.installation("mallory", false);
    let foreign = env.foreign("foreign");
    // Registered before the server starts: the registry file is reloaded by polling, so a service added after the
    // start is admitted only once a poll lands, and a fast machine reaches the call first.
    let runtime = env.service("client-runtime", "runtime");
    let server = env.start(generous(), 100).await;

    // No client certificate: the handshake or the first call fails; the server answers nothing.
    let channel = privoke_transport::client::connect(&server.public_addr.to_string(), &env.client_config(None)).await;
    if let Ok(channel) = channel {
        let mut client = privoke_contracts::proto::v1::telemetry_service_client::TelemetryServiceClient::new(channel);
        assert!(client.record_telemetry(valid_packet()).await.is_err(), "a peer without a certificate was answered");
    }
    // A certificate from a CA the server does not trust.
    let channel = privoke_transport::client::connect(&server.public_addr.to_string(), &env.client_config(Some(&foreign))).await;
    if let Ok(channel) = channel {
        let mut client = privoke_contracts::proto::v1::telemetry_service_client::TelemetryServiceClient::new(channel);
        assert!(client.record_telemetry(valid_packet()).await.is_err(), "a foreign-CA peer was answered");
    }
    // An installation (non-reporter) certificate, registered or not, on either listener.
    for creds in [&installation, &stranger] {
        let mut public = env.client(server.public_addr, Some(creds)).await;
        assert_eq!(code(public.record_telemetry(valid_packet()).await), Code::PermissionDenied, "{}", creds.id);
        assert_eq!(code(public.health(TelemetryHealthRequest {}).await), Code::PermissionDenied, "{}", creds.id);
        // On the internal listener the summary and health are the only RPCs, and an installation holds neither role.
        let mut internal = env.client(server.internal_addr, Some(creds)).await;
        assert_eq!(code(internal.get_telemetry_summary(GetTelemetrySummaryRequest {}).await), Code::PermissionDenied, "{}", creds.id);
        assert_eq!(code(internal.health(TelemetryHealthRequest {}).await), Code::PermissionDenied, "{}", creds.id);
        assert_eq!(code(internal.record_telemetry(valid_packet()).await), Code::Unimplemented, "{}", creds.id);
    }
    // The positive control: the reporter credential works on the same listener.
    let mut client = env.client(server.public_addr, Some(&reporter)).await;
    assert!(client.record_telemetry(valid_packet()).await.unwrap().into_inner().accepted);
    let mut internal = env.client(server.internal_addr, Some(&runtime)).await;
    assert_eq!(
        internal.get_telemetry_summary(GetTelemetrySummaryRequest {}).await.unwrap().into_inner().sample_count,
        1,
        "only the reporter's report was stored"
    );
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn the_reporter_credential_is_refused_when_the_registry_switch_is_off_and_after_revocation() {
    let env = Env::new();
    let reporter = env.reporter();
    let server = env.start(generous(), 100).await;
    let mut client = env.client(server.public_addr, Some(&reporter)).await;
    assert!(client.record_telemetry(valid_packet()).await.is_ok());

    privoke_pki::registry_edit::set_reporter(&env.registry(), false).unwrap();
    let mut refused = false;
    for _ in 0..100 {
        if code(client.record_telemetry(valid_packet()).await) == Code::PermissionDenied {
            refused = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(refused, "turning the reporter switch off did not reach the open connection");
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn two_clients_with_the_same_reporter_certificate_at_different_source_ips_are_limited_independently() {
    let env = Env::new();
    let reporter = env.reporter();
    // One request per second after a burst of three; the daily cap is out of the way.
    let server = env.start(Limits { rate: RateLimit { per_second: 1, burst: 3 }, ..Limits::default() }, 10_000).await;

    let address = server.public_addr;
    let mut first = env.client_from(source(2), address, &reporter).await;
    let mut second = env.client_from(source(3), address, &reporter).await;

    // Exhaust the first source until the limiter answers.
    let mut accepted_first = 0;
    let mut limited = false;
    for _ in 0..8 {
        match code(first.record_telemetry(valid_packet()).await) {
            Code::Ok => accepted_first += 1,
            Code::ResourceExhausted => {
                limited = true;
                break;
            }
            other => panic!("unexpected {other:?}"),
        }
    }
    assert!(limited, "the first source was never limited");
    assert!((3..=4).contains(&accepted_first), "burst of three plus at most one refill, got {accepted_first}");

    // A second connection from the same source address shares that bucket: it is keyed by IP, not by connection.
    let mut first_again = env.client_from(source(2), address, &reporter).await;
    assert_eq!(code(first_again.record_telemetry(valid_packet()).await), Code::ResourceExhausted);

    // The second source holds the same certificate and is untouched by the first one's exhaustion.
    let mut accepted_second = 0;
    for _ in 0..3 {
        assert_eq!(code(second.record_telemetry(valid_packet()).await), Code::Ok);
        accepted_second += 1;
    }
    assert_eq!(accepted_second, 3, "the second source received its full burst");
    // ... and is limited on its own account afterwards.
    let mut second_limited = false;
    for _ in 0..4 {
        if code(second.record_telemetry(valid_packet()).await) == Code::ResourceExhausted {
            second_limited = true;
            break;
        }
    }
    assert!(second_limited, "the second source was never limited");
    // A third source is still fresh.
    let mut third = env.client_from(source(4), address, &reporter).await;
    assert_eq!(code(third.record_telemetry(valid_packet()).await), Code::Ok);
    eprintln!("LIMITS independent: source .2 accepted {accepted_first} then limited; source .3 accepted 3 then limited; source .4 fresh");
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn the_daily_cap_counts_accepted_reports_per_source() {
    let env = Env::new();
    let reporter = env.reporter();
    let runtime = env.service("client-runtime", "runtime");
    let server = env.start(generous(), 2).await;
    let address = server.public_addr;
    let mut first = env.client_from(source(2), address, &reporter).await;
    let mut second = env.client_from(source(3), address, &reporter).await;

    assert_eq!(code(first.record_telemetry(valid_packet()).await), Code::Ok);
    // A rejected packet does not use the allowance.
    assert_eq!(code(first.record_telemetry(packet(|p| p.privacy_mechanism = "none".into())).await), Code::InvalidArgument);
    assert_eq!(code(first.record_telemetry(valid_packet()).await), Code::Ok);
    assert_eq!(code(first.record_telemetry(valid_packet()).await), Code::ResourceExhausted, "third accepted report from one source");
    // The same certificate from another source has its own allowance.
    assert_eq!(code(second.record_telemetry(valid_packet()).await), Code::Ok);
    assert_eq!(code(second.record_telemetry(valid_packet()).await), Code::Ok);
    assert_eq!(code(second.record_telemetry(valid_packet()).await), Code::ResourceExhausted);

    let mut internal = env.client(server.internal_addr, Some(&runtime)).await;
    assert_eq!(internal.get_telemetry_summary(GetTelemetrySummaryRequest {}).await.unwrap().into_inner().sample_count, 4);
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn an_oversize_message_is_refused_and_not_stored() {
    let env = Env::new();
    let reporter = env.reporter();
    let runtime = env.service("client-runtime", "runtime");
    let server = env.start(Limits { max_message_bytes: 4096, ..generous() }, 100).await;
    let mut client = env.client(server.public_addr, Some(&reporter)).await;
    let oversize = packet(|p| p.model_version = "x".repeat(8192));
    let status = client.record_telemetry(oversize).await.expect_err("an oversize packet must be refused");
    assert!(matches!(status.code(), Code::OutOfRange | Code::ResourceExhausted | Code::InvalidArgument), "{status:?}");
    let mut internal = env.client(server.internal_addr, Some(&runtime)).await;
    assert_eq!(internal.get_telemetry_summary(GetTelemetrySummaryRequest {}).await.unwrap().into_inner().sample_count, 0);
    server.shutdown().await.unwrap();
}

// -- the built binary ---------------------------------------------------------------------------------------

fn free_ports() -> (u16, u16) {
    let first = TcpListener::bind("127.0.0.1:0").unwrap();
    let second = TcpListener::bind("127.0.0.1:0").unwrap();
    (first.local_addr().unwrap().port(), second.local_addr().unwrap().port())
}

struct Process(Child);

impl Process {
    /// Stop the process and return what it wrote to stderr.
    fn stop(mut self) -> String {
        let _ = self.0.kill();
        let _ = self.0.wait();
        let mut text = String::new();
        if let Some(mut stderr) = self.0.stderr.take() {
            let _ = stderr.read_to_string(&mut text);
        }
        text
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn command(env: &Env, skip: Option<&str>) -> Command {
    let args = env.tls_args();
    let mut command = Command::new(BINARY);
    let flags = [
        ("--cert", args.cert.unwrap()),
        ("--key", args.key.unwrap()),
        ("--client-ca", args.client_ca.unwrap()),
        ("--crl", args.crl.unwrap()),
        ("--registry", args.registry.unwrap()),
    ];
    for (flag, path) in flags {
        if Some(flag) != skip {
            command.arg(flag).arg(path);
        }
    }
    command
        .env("TELEMETRY_BIND", "127.0.0.1")
        .env("TELEMETRY_DB_PATH", env.database())
        .env_remove("TELEMETRY_PORT")
        .env_remove("TELEMETRY_PUBLIC_PORT");
    command
}

fn spawn(env: &Env, public: u16, internal: u16) -> Process {
    let child = command(env, None)
        .args(["--reload-poll-secs", "1"])
        .env("TELEMETRY_PORT", internal.to_string())
        .env("TELEMETRY_PUBLIC_PORT", public.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    Process(child)
}

async fn wait_serving(env: &Env, creds: &Creds, address: SocketAddr, process: &mut Process) {
    for _ in 0..200 {
        if let Some(status) = process.0.try_wait().unwrap() {
            panic!("the binary exited early: {status}");
        }
        if let Ok(channel) = privoke_transport::client::connect(&address.to_string(), &env.client_config(Some(creds))).await
            && privoke_contracts::proto::v1::telemetry_service_client::TelemetryServiceClient::new(channel)
                .health(TelemetryHealthRequest {})
                .await
                .is_ok()
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("the binary never answered Health");
}

fn certificate_der(path: &std::path::Path) -> Vec<u8> {
    use base64::Engine;
    let pem = std::fs::read_to_string(path).unwrap();
    let body: String = pem.lines().filter(|line| !line.starts_with("-----")).collect();
    base64::engine::general_purpose::STANDARD.decode(body).unwrap()
}

fn all_bytes_under(directory: &std::path::Path) -> Vec<(std::path::PathBuf, Vec<u8>)> {
    let mut found = Vec::new();
    for entry in std::fs::read_dir(directory).unwrap() {
        let path = entry.unwrap().path();
        if path.is_file() {
            found.push((path.clone(), std::fs::read(&path).unwrap()));
        }
    }
    found
}

fn contains(haystack: &[u8], needle: &str) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|window| window == needle.as_bytes())
}

/// Nothing in the database and nothing in the process log can name or fingerprint a reporter, an installation or a
/// source address, however the request ended (accepted, invalid, denied, refused by a limit).
#[tokio::test]
async fn no_identity_column_and_no_identity_log_line() {
    let env = Env::new();
    let reporter = env.reporter();
    let installation = env.installation("alice", true);
    let (public, internal) = free_ports();
    let mut process = spawn(&env, public, internal);
    let address: SocketAddr = format!("127.0.0.1:{public}").parse().unwrap();
    wait_serving(&env, &reporter, address, &mut process).await;

    // Each outcome, from distinct source addresses: accepted, invalid, denied (installation certificate), and a
    // reporter-switch refusal after the switch is turned off.
    let mut from_two = env.client_from(source(2), address, &reporter).await;
    let mut from_three = env.client_from(source(3), address, &reporter).await;
    let mut accepted: i64 = 0;
    for client in [&mut from_two, &mut from_three] {
        assert_eq!(code(client.record_telemetry(valid_packet()).await), Code::Ok);
        accepted += 1;
        assert_eq!(code(client.record_telemetry(packet(|p| p.action = "DENY".into())).await), Code::InvalidArgument);
    }
    let mut alice = env.client_from(source(4), address, &installation).await;
    assert_eq!(code(alice.record_telemetry(valid_packet()).await), Code::PermissionDenied);
    privoke_pki::registry_edit::set_reporter(&env.registry(), false).unwrap();
    let mut refused = false;
    for _ in 0..200 {
        match code(from_two.record_telemetry(valid_packet()).await) {
            Code::PermissionDenied => {
                refused = true;
                break;
            }
            Code::Ok => accepted += 1,
            other => panic!("unexpected {other:?}"),
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(refused, "the registry change was never applied");

    let log = process.stop();
    assert!(log.contains("telemetry-service listening"), "the process wrote no startup line: {log:?}");

    // What identifies a peer: the URNs, the installation id, the certificate fingerprints and serials, source addresses.
    let reporter_der = certificate_der(&reporter.cert);
    let installation_der = certificate_der(&installation.cert);
    let forbidden = [
        "urn:privoke".to_string(),
        "reporter".to_string(),
        installation.id.clone(),
        sha256_hex(&reporter_der),
        sha256_hex(&installation_der),
        "127.0.0.2".to_string(),
        "127.0.0.3".to_string(),
        "127.0.0.4".to_string(),
        "127.0.0.1".to_string(),
        "alice".to_string(),
    ];
    for needle in &forbidden {
        assert!(!contains(log.as_bytes(), needle), "the log names {needle:?}:\n{log}");
    }

    // The files of the database directory (main file, WAL and shared memory) hold none of it either.
    let files = all_bytes_under(env.database().parent().unwrap());
    assert!(files.iter().any(|(path, bytes)| path.extension().is_some_and(|e| e == "sqlite3") && !bytes.is_empty()));
    for (path, bytes) in &files {
        for needle in &forbidden {
            assert!(!contains(bytes, needle), "{} contains {needle:?}", path.display());
        }
        for der in [&reporter_der, &installation_der] {
            assert!(!bytes.windows(32).any(|window| window == &der[der.len() - 32..]), "{} holds certificate bytes", path.display());
        }
    }

    // Schema: exactly two tables, and no column can hold an identity, an address or a time.
    let connection = rusqlite::Connection::open(env.database()).unwrap();
    let tables: Vec<String> = connection
        .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(tables, ["telemetry_counts", "telemetry_strata"]);
    let mut columns = Vec::new();
    for table in &tables {
        let found: Vec<String> = connection
            .prepare(&format!("PRAGMA table_info({table})"))
            .unwrap()
            .query_map([], |row| row.get(1))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        columns.extend(found.into_iter().map(|column| format!("{table}.{column}")));
    }
    assert_eq!(
        columns,
        [
            "telemetry_counts.epsilon_micros",
            "telemetry_counts.dimension",
            "telemetry_counts.value",
            "telemetry_counts.observed_count",
            "telemetry_strata.epsilon_micros",
            "telemetry_strata.sample_count"
        ]
    );
    let total: i64 = connection.query_row("SELECT SUM(sample_count) FROM telemetry_strata", [], |row| row.get(0)).unwrap();
    assert_eq!(total, accepted, "exactly the accepted reports were counted, none of the refused ones");
    let strings: Vec<String> = connection
        .prepare("SELECT DISTINCT value FROM telemetry_counts")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    let domain: std::collections::BTreeSet<&str> = ["ALLOW", "BLOCK", "WARN", "HEALTH", "0.5-0.8", "v0.3.0", "12-16_UTC"].into();
    assert!(strings.iter().all(|value| domain.contains(value.as_str())), "a stored value is outside the fixed domains: {strings:?}");
}

#[test]
fn a_cloud_binary_started_without_any_tls_input_exits_non_zero_and_binds_nothing() {
    for skip in ["--cert", "--key", "--client-ca", "--crl", "--registry"] {
        let env = Env::new();
        let (public, internal) = free_ports();
        let output = command(&env, Some(skip))
            .env("TELEMETRY_PORT", internal.to_string())
            .env("TELEMETRY_PUBLIC_PORT", public.to_string())
            .output()
            .unwrap();
        assert!(!output.status.success(), "started without {skip}");
        let message = String::from_utf8_lossy(&output.stderr);
        assert!(message.contains(skip), "{skip}: {message}");
        assert!(!message.contains("listening"), "{skip}: bound before the verifier existed");
        assert!(!env.database().exists(), "{skip}: the database was opened before the verifier existed");
        assert!(TcpListener::bind(("127.0.0.1", public)).is_ok());
    }
}

#[test]
fn the_binary_refuses_a_legacy_database_without_modifying_it() {
    let env = Env::new();
    std::fs::create_dir_all(env.database().parent().unwrap()).unwrap();
    let connection = rusqlite::Connection::open(env.database()).unwrap();
    connection.execute("CREATE TABLE telemetry_events (event_id TEXT, source_id TEXT, risk_score REAL)", []).unwrap();
    drop(connection);
    let before = std::fs::read(env.database()).unwrap();
    let (public, internal) = free_ports();
    let output =
        command(&env, None).env("TELEMETRY_PORT", internal.to_string()).env("TELEMETRY_PUBLIC_PORT", public.to_string()).output().unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("legacy unprotected"));
    assert_eq!(std::fs::read(env.database()).unwrap(), before);
}

#[tokio::test]
async fn the_healthcheck_subcommand_needs_a_registered_service_identity() {
    let env = Env::new();
    let reporter = env.reporter();
    let runtime = env.service("healthcheck", "runtime");
    let (public, internal) = free_ports();
    let mut process = spawn(&env, public, internal);
    wait_serving(&env, &reporter, format!("127.0.0.1:{public}").parse().unwrap(), &mut process).await;

    let probe = |creds: &Creds| {
        Command::new(BINARY)
            .arg("healthcheck")
            .arg("--address")
            .arg(format!("127.0.0.1:{internal}"))
            .arg("--server-ca")
            .arg(env.path("server-ca/ca.crt"))
            .arg("--client-cert")
            .arg(&creds.cert)
            .arg("--client-key")
            .arg(&creds.key)
            .output()
            .unwrap()
    };
    assert!(probe(&runtime).status.success(), "a registered service identity must pass");
    assert!(!probe(&reporter).status.success(), "the reporter credential must not pass the internal health probe");
}
