//! Mutual TLS end to end: the two listeners over certificates issued by the stage 2 tool, the authorisation policy,
//! and the cloud binary's fail-closed startup and `healthcheck` subcommand. These are the in-process counterparts of
//! the container rows run by `evaluation/update_security.py --target rust`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use common::{release_dir_for_tests, write_test_artifact};
use privoke_contracts::proto::v1::model_streaming_service_client::ModelStreamingServiceClient;
use privoke_contracts::proto::v1::param_update_service_client::ParamUpdateServiceClient;
use privoke_contracts::proto::v1::{HealthRequest, ModelAssetRequest, ModelParametersRequest, ParameterUpdateRequest};
use privoke_model_streaming::catalog::Catalog;
use privoke_model_streaming::healthcheck::{self, HealthcheckArgs};
use privoke_model_streaming::releases::StandardReleases;
use privoke_model_streaming::server::{self, Listen, ServerHandle};
use privoke_model_streaming::service::ModelService;
use privoke_pki::ca::{CaDir, Validity};
use privoke_pki::{client as enrolment, files::write_atomic, registry_edit};
use privoke_transport::startup::CloudTlsArgs;
use privoke_transport::{ClientTlsConfig, Limits};
use time::{Duration as TimeDuration, OffsetDateTime};
use tonic::transport::Channel;
use tonic::{Code, Status};

const BINARY: &str = env!("CARGO_BIN_EXE_model-streaming-service");

/// A credential on disk.
struct Creds {
    id: String,
    cert: PathBuf,
    key: PathBuf,
}

struct Env {
    dir: tempfile::TempDir,
    client_ca: CaDir,
    _server_ca: CaDir,
    foreign_ca: CaDir,
    models: tempfile::TempDir,
}

impl Env {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let validity = Validity::days(30);
        let client_ca = CaDir::init(&dir.path().join("client-ca"), "Test Client CA", validity).unwrap();
        let server_ca = CaDir::init(&dir.path().join("server-ca"), "Test Server CA", validity).unwrap();
        let foreign_ca = CaDir::init(&dir.path().join("foreign-ca"), "Foreign Client CA", validity).unwrap();
        let server = server_ca.issue_server(&["localhost".to_string(), "127.0.0.1".to_string()], validity).unwrap();
        write_atomic(&dir.path().join("server.crt"), server.cert_pem.as_bytes(), false).unwrap();
        write_atomic(&dir.path().join("server.key"), server.key_pem.as_bytes(), true).unwrap();
        client_ca.issue_reporter(validity).unwrap();
        let env = Self { dir, client_ca, _server_ca: server_ca, foreign_ca, models: tempfile::tempdir().unwrap() };
        env.refresh_crl();
        registry_edit::set_reporter(&env.registry(), true).unwrap();
        let (_baseline_dir, baseline) = write_test_artifact();
        std::fs::copy(baseline, env.models.path().join("privoke-baseline.json")).unwrap();
        env
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn registry(&self) -> PathBuf {
        self.path("registry.toml")
    }

    fn crl(&self) -> PathBuf {
        self.path("crl.pem")
    }

    fn refresh_crl(&self) {
        let pem = self.client_ca.crl_pem(OffsetDateTime::now_utc(), TimeDuration::days(7)).unwrap();
        write_atomic(&self.crl(), pem.as_bytes(), false).unwrap();
    }

    fn tls_args(&self) -> CloudTlsArgs {
        CloudTlsArgs {
            cert: Some(self.path("server.crt")),
            key: Some(self.path("server.key")),
            client_ca: Some(self.path("client-ca/ca.crt")),
            crl: Some(self.crl()),
            registry: Some(self.registry()),
        }
    }

    fn enrol(&self, name: &str, ca: &CaDir, register: bool) -> Creds {
        let dir = self.path(name);
        std::fs::create_dir_all(&dir).unwrap();
        let enrolment = enrolment::enrol(&dir).unwrap();
        let csr = std::fs::read_to_string(&enrolment.csr_path).unwrap();
        let signed = ca.sign_installation(&csr, &enrolment.installation, Validity::days(30)).unwrap();
        write_atomic(&dir.join("client.crt"), signed.cert_pem.as_bytes(), false).unwrap();
        if register {
            registry_edit::add_installation(&self.registry(), &enrolment.installation, Some(name), signed.not_after).unwrap();
        }
        Creds { id: enrolment.installation, cert: dir.join("client.crt"), key: dir.join("client.key") }
    }

    fn consumer(&self, name: &str) -> Creds {
        self.enrol(name, &self.client_ca, true)
    }

    fn unregistered(&self, name: &str) -> Creds {
        self.enrol(name, &self.client_ca, false)
    }

    fn foreign(&self, name: &str) -> Creds {
        self.enrol(name, &self.foreign_ca, false)
    }

    fn service(&self, name: &str, role: &str) -> Creds {
        let issued = self.client_ca.issue_service(name, Validity::days(30)).unwrap();
        let dir = self.path(&format!("svc-{name}"));
        write_atomic(&dir.join("service.crt"), issued.cert_pem.as_bytes(), false).unwrap();
        write_atomic(&dir.join("service.key"), issued.key_pem.as_bytes(), true).unwrap();
        registry_edit::add_service(&self.registry(), name, role, issued.not_after).unwrap();
        Creds { id: name.to_string(), cert: dir.join("service.crt"), key: dir.join("service.key") }
    }

    fn reporter(&self) -> Creds {
        let (cert, key) = self.client_ca.reporter().unwrap().unwrap();
        let dir = self.path("reporter");
        write_atomic(&dir.join("reporter.crt"), cert.as_bytes(), false).unwrap();
        write_atomic(&dir.join("reporter.key"), key.as_bytes(), true).unwrap();
        Creds { id: "reporter".into(), cert: dir.join("reporter.crt"), key: dir.join("reporter.key") }
    }

    fn client_config(&self, creds: Option<&Creds>) -> ClientTlsConfig {
        ClientTlsConfig {
            server_ca: self.path("server-ca/ca.crt"),
            identity: creds.map(|creds| (creds.cert.clone(), creds.key.clone())),
            server_name: "localhost".to_string(),
        }
    }

    async fn start(&self, latest: &str, with_releases: bool) -> ServerHandle {
        let transport = self.tls_args().into_config().unwrap();
        let mut catalog = Catalog::load(self.models.path(), latest).unwrap();
        if with_releases {
            catalog.releases = Some(StandardReleases::open(&release_dir_for_tests().unwrap()).unwrap());
        }
        let any = "127.0.0.1:0".parse().unwrap();
        server::start(
            Listen { public: any, internal: any },
            ModelService::new(Arc::new(catalog)),
            transport,
            Limits::default(),
            Duration::from_millis(50),
        )
        .await
        .unwrap()
    }
}

type Client = ModelStreamingServiceClient<Channel>;

async fn connect(env: &Env, address: std::net::SocketAddr, creds: Option<&Creds>) -> Client {
    let channel = privoke_transport::client::connect(&address.to_string(), &env.client_config(creds)).await.expect("connect");
    ModelStreamingServiceClient::new(channel)
}

fn code<T>(result: Result<T, Status>) -> Code {
    match result {
        Ok(_) => Code::Ok,
        Err(status) => status.code(),
    }
}

fn parameters(consumer: &str, model: &str) -> ModelParametersRequest {
    ModelParametersRequest { consumer_id: consumer.into(), model_id: model.into() }
}

async fn stream_code(client: &mut Client, request: ModelParametersRequest) -> (Code, usize) {
    match client.stream_model_parameters(request).await {
        Err(status) => (status.code(), 0),
        Ok(response) => {
            let mut stream = response.into_inner();
            let mut count = 0;
            loop {
                match stream.message().await {
                    Ok(Some(_)) => count += 1,
                    Ok(None) => return (Code::Ok, count),
                    Err(status) => return (status.code(), count),
                }
            }
        }
    }
}

#[tokio::test]
async fn public_listener_serves_exactly_the_consumer_rpcs() {
    let env = Env::new();
    let consumer = env.consumer("alice");
    let server = env.start("privoke-baseline", false).await;
    let mut client = connect(&env, server.public_addr, Some(&consumer)).await;

    assert_eq!(client.health(HealthRequest {}).await.unwrap().into_inner().status, "SERVING");
    let (status, chunks) = stream_code(&mut client, parameters(&consumer.id, "privoke-baseline")).await;
    assert!(status == Code::Ok && chunks > 0, "{status:?} {chunks}");
    assert_eq!(stream_code(&mut client, parameters("", "latest")).await.0, Code::Ok, "an empty consumer_id is accepted");
    // A legacy model has no package: GetModelPackage answers with its identity only (the corpus row).
    let package = client.get_model_package(parameters(&consumer.id, "privoke-baseline")).await.unwrap().into_inner();
    assert!(package.assets.is_empty() && package.manifest_sha256.is_empty() && package.model_id == "privoke-baseline");
    // R9: the private RPC and the update service are not served here at all.
    assert_eq!(code(client.get_model_parameters(parameters(&consumer.id, "privoke-baseline")).await), Code::Unimplemented);
    let mut updates = ParamUpdateServiceClient::new(
        privoke_transport::client::connect(&server.public_addr.to_string(), &env.client_config(Some(&consumer))).await.unwrap(),
    );
    let update = ParameterUpdateRequest {
        source_id: consumer.id.clone(),
        model_id: "privoke-baseline".into(),
        base_version: "v1".into(),
        ..Default::default()
    };
    assert_eq!(code(updates.submit_parameter_update(update).await), Code::Unimplemented);
    // T9 to T11 shape: a legacy model id or a wrong pin never starts an asset stream.
    let asset = ModelAssetRequest {
        consumer_id: consumer.id.clone(),
        model_id: "privoke-baseline".into(),
        manifest_sha256: "0".repeat(64),
        asset_name: "config.json".into(),
    };
    assert_eq!(code(client.stream_model_asset(asset).await), Code::InvalidArgument);
    // T5 and T6.
    assert_eq!(stream_code(&mut client, parameters(&consumer.id, "privoke-not-a-model")).await.0, Code::NotFound);
    assert_eq!(stream_code(&mut client, parameters(&consumer.id, "../etc/passwd")).await.0, Code::NotFound);
    assert_eq!(code(client.get_model_package(parameters(&consumer.id, "../privoke-v3-balanced")).await), Code::NotFound);
    // T4: a control character in the claimed identity is refused before any lookup.
    assert!(matches!(
        stream_code(&mut client, parameters("bad\nconsumer", "privoke-baseline")).await.0,
        Code::PermissionDenied | Code::InvalidArgument
    ));
    // T2: a consumer cannot claim another consumer's identity.
    assert_eq!(stream_code(&mut client, parameters("server-client-runtime", "privoke-baseline")).await.0, Code::PermissionDenied);
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn v3_package_and_assets_are_fetched_over_mutual_tls_and_verify_their_pin() {
    let Some(_) = release_dir_for_tests() else {
        eprintln!("the prepared standard releases are not available; skipped");
        return;
    };
    let env = Env::new();
    let consumer = env.consumer("alice");
    let server = env.start("privoke-v3-balanced", true).await;
    let mut client = connect(&env, server.public_addr, Some(&consumer)).await;
    // G8: the default V3 package is public to registered installations.
    let package = client.get_model_package(parameters(&consumer.id, "latest")).await.unwrap().into_inner();
    assert_eq!(package.model_id, "privoke-v3-balanced");
    assert_eq!(package.manifest_sha256, privoke_model_streaming::releases::standard_pin("privoke-v3-balanced").unwrap());
    assert_eq!(package.assets.len(), 4);
    for asset in package.assets.iter().filter(|asset| asset.size_bytes < 1024 * 1024) {
        let request = ModelAssetRequest {
            consumer_id: consumer.id.clone(),
            model_id: package.model_id.clone(),
            manifest_sha256: package.manifest_sha256.clone(),
            asset_name: asset.name.clone(),
        };
        let mut stream = client.stream_model_asset(request).await.unwrap().into_inner();
        let mut bytes = Vec::new();
        while let Some(chunk) = stream.message().await.unwrap() {
            assert_eq!(chunk.offset, bytes.len() as u64);
            bytes.extend_from_slice(&chunk.data);
        }
        assert_eq!(privoke_contracts::digest::sha256_hex(&bytes), asset.sha256, "{}", asset.name);
    }
    // The legacy float RPC refuses a V3 model on the internal listener, and is not served on the public one.
    assert_eq!(code(client.get_model_parameters(parameters(&consumer.id, "privoke-v3-balanced")).await), Code::Unimplemented);
    let runtime = env.service("client-runtime", "runtime");
    let mut internal = connect(&env, server.internal_addr, Some(&runtime)).await;
    assert_eq!(code(internal.get_model_parameters(parameters("", "privoke-v3-balanced")).await), Code::FailedPrecondition);
    // T9: a wrong pin never starts the stream.
    let wrong = ModelAssetRequest {
        consumer_id: consumer.id.clone(),
        model_id: "privoke-v3-balanced".into(),
        manifest_sha256: "0".repeat(64),
        asset_name: "config.json".into(),
    };
    assert_eq!(code(client.stream_model_asset(wrong).await), Code::InvalidArgument);
    // T10: a non-allowlisted asset name.
    let traversal = ModelAssetRequest {
        consumer_id: consumer.id.clone(),
        model_id: "privoke-v3-balanced".into(),
        manifest_sha256: package.manifest_sha256.clone(),
        asset_name: "../preparation.json".into(),
    };
    assert_eq!(code(client.stream_model_asset(traversal).await), Code::InvalidArgument);
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn peers_without_a_registered_installation_are_refused_everywhere() {
    let env = Env::new();
    let unregistered = env.unregistered("mallory");
    let foreign = env.foreign("foreign");
    let reporter = env.reporter();
    let server = env.start("privoke-baseline", false).await;

    // R7 and R8 with an unregistered installation and with the reporter credential: PERMISSION_DENIED, no data.
    for creds in [&unregistered, &reporter] {
        let mut client = connect(&env, server.public_addr, Some(creds)).await;
        assert_eq!(code(client.health(HealthRequest {}).await), Code::PermissionDenied, "{}", creds.id);
        assert_eq!(code(client.get_model_package(parameters("", "latest")).await), Code::PermissionDenied, "{}", creds.id);
        let asset = ModelAssetRequest {
            model_id: "privoke-v3-balanced".into(),
            manifest_sha256: "0".repeat(64),
            asset_name: "config.json".into(),
            ..Default::default()
        };
        assert_eq!(code(client.stream_model_asset(asset).await), Code::PermissionDenied, "{}", creds.id);
        assert_eq!(stream_code(&mut client, parameters("", "privoke-baseline")).await.0, Code::PermissionDenied, "{}", creds.id);
    }
    // R4: a certificate from a foreign CA fails the handshake; no RPC is answered.
    for creds in [Some(&foreign), None] {
        let channel = privoke_transport::client::connect(&server.public_addr.to_string(), &env.client_config(creds)).await;
        match channel {
            Err(_) => {}
            Ok(channel) => {
                let mut client = ModelStreamingServiceClient::new(channel);
                assert!(client.health(HealthRequest {}).await.is_err(), "a peer without a trusted client certificate was answered");
            }
        }
    }
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn internal_listener_serves_service_roles_only() {
    let env = Env::new();
    let consumer = env.consumer("alice");
    let runtime = env.service("client-runtime", "runtime");
    let publisher = env.service("param-update", "publisher");
    let trainer = env.service("fuzzer", "trainer");
    let unregistered = env.client_ca.issue_service("stranger", Validity::days(30)).unwrap();
    let stranger_dir = env.path("svc-stranger");
    write_atomic(&stranger_dir.join("service.crt"), unregistered.cert_pem.as_bytes(), false).unwrap();
    write_atomic(&stranger_dir.join("service.key"), unregistered.key_pem.as_bytes(), true).unwrap();
    let stranger = Creds { id: "stranger".into(), cert: stranger_dir.join("service.crt"), key: stranger_dir.join("service.key") };
    let server = env.start("privoke-baseline", false).await;

    for creds in [&runtime, &publisher, &trainer] {
        let mut client = connect(&env, server.internal_addr, Some(creds)).await;
        assert_eq!(client.health(HealthRequest {}).await.unwrap().into_inner().status, "SERVING");
        let response = client.get_model_parameters(parameters("param-update-service", "privoke-baseline")).await.unwrap().into_inner();
        assert_eq!(response.model_id, "privoke-baseline");
        // Everything else is the public listener's.
        assert_eq!(stream_code(&mut client, parameters("", "privoke-baseline")).await.0, Code::Unimplemented);
        assert_eq!(code(client.get_model_package(parameters("", "latest")).await), Code::Unimplemented);
    }
    let mut client = connect(&env, server.internal_addr, Some(&consumer)).await;
    assert_eq!(
        code(client.get_model_parameters(parameters(&consumer.id, "privoke-baseline")).await),
        Code::PermissionDenied,
        "a consumer on the internal listener"
    );
    let mut client = connect(&env, server.internal_addr, Some(&stranger)).await;
    assert_eq!(
        code(client.get_model_parameters(parameters("", "privoke-baseline")).await),
        Code::PermissionDenied,
        "an unregistered service"
    );
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn deny_list_reaches_an_open_connection_and_a_new_registration_needs_no_restart() {
    let env = Env::new();
    let consumer = env.consumer("alice");
    let late = env.unregistered("late");
    let server = env.start("privoke-baseline", false).await;
    let mut client = connect(&env, server.public_addr, Some(&consumer)).await;
    client.health(HealthRequest {}).await.expect("registered installation is served");
    let mut late_client = connect(&env, server.public_addr, Some(&late)).await;
    assert_eq!(code(late_client.health(HealthRequest {}).await), Code::PermissionDenied);

    registry_edit::deny(&env.registry(), &privoke_transport::Identity::Installation(consumer.id.clone()), Some("test")).unwrap();
    registry_edit::add_installation(&env.registry(), &late.id, Some("late"), OffsetDateTime::now_utc().unix_timestamp() + 3600).unwrap();
    let mut denied = false;
    let mut admitted = false;
    for _ in 0..100 {
        denied = denied || code(client.health(HealthRequest {}).await) == Code::PermissionDenied;
        admitted = admitted || code(late_client.health(HealthRequest {}).await) == Code::Ok;
        if denied && admitted {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(denied, "the deny list did not reach the open connection");
    assert!(admitted, "a newly registered installation was not admitted without a restart");
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn healthcheck_requires_a_registered_service_identity() {
    let env = Env::new();
    let runtime = env.service("healthcheck", "runtime");
    let consumer = env.consumer("alice");
    let server = env.start("privoke-baseline", false).await;
    let address = server.internal_addr.to_string();
    let args = |creds: &Creds| HealthcheckArgs {
        address: Some(address.clone()),
        server_ca: Some(env.path("server-ca/ca.crt")),
        client_cert: Some(creds.cert.clone()),
        client_key: Some(creds.key.clone()),
        server_name: None,
    };
    healthcheck::run(args(&runtime), 50051).await.expect("a registered service identity probes the internal listener");
    assert!(healthcheck::run(args(&consumer), 50051).await.is_err(), "a consumer identity must not pass the internal health probe");
    let mut wrong_ca = args(&runtime);
    wrong_ca.server_ca = Some(env.path("foreign-ca/ca.crt"));
    assert!(healthcheck::run(wrong_ca, 50051).await.is_err(), "a server certificate from an untrusted CA must fail the probe");
    server.shutdown().await.unwrap();
}

/// The two ports a test server will use, found by binding and releasing them.
fn free_ports() -> (u16, u16) {
    let first = TcpListener::bind("127.0.0.1:0").unwrap();
    let second = TcpListener::bind("127.0.0.1:0").unwrap();
    (first.local_addr().unwrap().port(), second.local_addr().unwrap().port())
}

struct Process(Child);

impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn spawn_binary(env: &Env, public: u16, internal: u16) -> Process {
    let args = env.tls_args();
    let child = Command::new(BINARY)
        .arg("--cert")
        .arg(args.cert.unwrap())
        .arg("--key")
        .arg(args.key.unwrap())
        .arg("--client-ca")
        .arg(args.client_ca.unwrap())
        .arg("--crl")
        .arg(args.crl.unwrap())
        .arg("--registry")
        .arg(args.registry.unwrap())
        .env("MODEL_ARTIFACT_DIR", env.models.path())
        .env("MODEL_LATEST_ID", "privoke-baseline")
        .env("MODEL_STREAMING_BIND", "127.0.0.1")
        .env("MODEL_STREAMING_PORT", internal.to_string())
        .env("MODEL_STREAMING_PUBLIC_PORT", public.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    Process(child)
}

#[tokio::test]
async fn the_binary_serves_both_listeners_and_its_healthcheck_subcommand_passes() {
    let env = Env::new();
    let consumer = env.consumer("alice");
    let runtime = env.service("healthcheck", "runtime");
    let (public, internal) = free_ports();
    let mut process = spawn_binary(&env, public, internal);
    let public_address: std::net::SocketAddr = format!("127.0.0.1:{public}").parse().unwrap();

    let mut served = false;
    for _ in 0..200 {
        if let Some(status) = process.0.try_wait().unwrap() {
            panic!("the binary exited early: {status}");
        }
        if let Ok(channel) = privoke_transport::client::connect(&public_address.to_string(), &env.client_config(Some(&consumer))).await
            && ModelStreamingServiceClient::new(channel).health(HealthRequest {}).await.is_ok()
        {
            served = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(served, "the binary never answered Health on the public listener");

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
            .env("MODEL_ARTIFACT_DIR", env.models.path())
            .output()
            .unwrap()
    };
    assert!(probe(&runtime).status.success(), "healthcheck with a registered service identity must exit 0");
    assert!(!probe(&consumer).status.success(), "healthcheck with a consumer identity must exit non-zero");
}

fn run_without(skip: &str) -> std::process::Output {
    let env = Env::new();
    let args = env.tls_args();
    let mut command = Command::new(BINARY);
    let flags: [(&str, PathBuf); 5] = [
        ("--cert", args.cert.unwrap()),
        ("--key", args.key.unwrap()),
        ("--client-ca", args.client_ca.unwrap()),
        ("--crl", args.crl.unwrap()),
        ("--registry", args.registry.unwrap()),
    ];
    for (flag, path) in &flags {
        if *flag != skip {
            command.arg(flag).arg(path);
        }
    }
    command
        .env("MODEL_ARTIFACT_DIR", env.models.path())
        .env("MODEL_LATEST_ID", "privoke-baseline")
        .env("MODEL_STREAMING_BIND", "127.0.0.1")
        .output()
        .unwrap()
}

#[test]
fn startup_without_any_authentication_input_exits_nonzero_before_binding() {
    for flag in ["--cert", "--key", "--client-ca", "--crl", "--registry"] {
        let output = run_without(flag);
        assert_eq!(output.status.code(), Some(1), "without {flag}");
        let message = String::from_utf8_lossy(&output.stderr);
        assert!(message.contains(flag), "the refusal names {flag}: {message}");
    }
}

#[test]
fn there_is_no_insecure_flag() {
    for flag in ["--insecure", "--no-tls", "--plaintext", "--disable-auth"] {
        let output = Command::new(BINARY).arg(flag).output().unwrap();
        assert_eq!(output.status.code(), Some(2), "{flag} must be an unknown argument");
    }
}
