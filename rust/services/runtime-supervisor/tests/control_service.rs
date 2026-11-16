//! The port of `test_supervisor_service.py` plus the control RPCs end to end. The model-streaming health check runs
//! over mutual TLS against an in-process Rust model-streaming server, with certificates generated at test time.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use common::pki::TestPki;
use common::{free_port, port_is_open, wait_until};
use privoke_contracts::proto::v1::privoke_runtime_control_service_client::PrivokeRuntimeControlServiceClient;
use privoke_contracts::proto::v1::{RuntimeHealthRequest, SetRuntimeEnabledRequest};
use privoke_supervisor::channel::ModelEndpoint;
use privoke_supervisor::control::{BoxFuture, ControlService, ModelHealth, model_streaming_health, serve_loopback};
use privoke_supervisor::process::{OsLauncher, RuntimeProcessSupervisor, SupervisorSettings};
use tonic::Code;

const TEST_CHILD: &str = env!("CARGO_BIN_EXE_privoke-supervisor-test-child");

struct CountingHealth(Arc<AtomicUsize>);

impl ModelHealth for CountingHealth {
    fn check(&self) -> BoxFuture<(String, String)> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { ("model-streaming-service".to_string(), "SERVING".to_string()) })
    }
}

fn idle_supervisor(port: u16) -> Arc<RuntimeProcessSupervisor> {
    let settings =
        SupervisorSettings::new(std::path::Path::new("."), BTreeMap::new(), port, Some(vec![TEST_CHILD.to_string(), "exit".to_string()]));
    Arc::new(RuntimeProcessSupervisor::new(settings, Box::new(OsLauncher)))
}

#[tokio::test]
async fn model_streaming_health_check_is_lazy() {
    use privoke_contracts::proto::v1::privoke_runtime_control_service_server::PrivokeRuntimeControlService;
    let calls = Arc::new(AtomicUsize::new(0));
    let service = ControlService::new(idle_supervisor(free_port()), Arc::new(CountingHealth(Arc::clone(&calls))));
    assert_eq!(calls.load(Ordering::SeqCst), 0, "building the service performs no health call");
    let response = service.model_streaming_health(tonic::Request::new(RuntimeHealthRequest {})).await.unwrap().into_inner();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!((response.service.as_str(), response.status.as_str()), ("model-streaming-service", "SERVING"));
}

#[tokio::test]
async fn supervisor_performs_model_streaming_health_rpc_over_mutual_tls() {
    let pki = TestPki::new();
    let installation = pki.consumer("alice");
    let server = pki.start_server(None).await;
    let endpoint = ModelEndpoint::mutual_tls(&server.public_addr.to_string(), pki.tls(&installation)).unwrap();
    assert_eq!(
        model_streaming_health(&endpoint, Duration::from_secs(5)).await,
        ("model-streaming-service".to_string(), "SERVING".to_string())
    );
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn health_is_not_serving_when_the_server_cannot_be_trusted_or_does_not_trust_us() {
    let pki = TestPki::new();
    let server = pki.start_server(None).await;
    let address = server.public_addr.to_string();
    let not_serving = ("model-streaming-service".to_string(), "NOT_SERVING".to_string());

    // An installation the registry does not know, one signed by another CA, and a client that pins the wrong server CA.
    let unregistered = pki.installation("unregistered", &pki.client_ca, false);
    let foreign = pki.installation("foreign", &pki.foreign_ca, false);
    let registered = pki.consumer("registered");
    let wrong_ca = privoke_transport::ClientTlsConfig { server_ca: pki.path("client-ca/ca.crt"), ..pki.tls(&registered) };
    for tls in [pki.tls(&unregistered), pki.tls(&foreign), wrong_ca] {
        let endpoint = ModelEndpoint::mutual_tls(&address, tls).unwrap();
        assert_eq!(model_streaming_health(&endpoint, Duration::from_secs(5)).await, not_serving);
    }
    // No certificate at all.
    let anonymous = privoke_transport::ClientTlsConfig { identity: None, ..pki.tls(&registered) };
    assert_eq!(model_streaming_health(&ModelEndpoint::mutual_tls(&address, anonymous).unwrap(), Duration::from_secs(5)).await, not_serving);
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn unavailable_model_streaming_service_is_not_serving() {
    let environment: BTreeMap<String, String> = BTreeMap::from([("PRIVOKE_CLOUD_TARGET".to_string(), "127.0.0.1:1".to_string())]);
    let endpoint = ModelEndpoint::from_environment(&environment).unwrap();
    assert_eq!(
        model_streaming_health(&endpoint, Duration::from_millis(500)).await,
        ("model-streaming-service".to_string(), "NOT_SERVING".to_string())
    );
}

#[tokio::test]
async fn control_rpcs_start_report_and_stop_the_runtime_over_loopback() {
    let runtime_port = free_port();
    let mut settings = SupervisorSettings::new(
        std::path::Path::new("."),
        common_environment(),
        runtime_port,
        Some(vec![TEST_CHILD.to_string(), "listen-env".to_string()]),
    );
    settings.startup_timeout = Duration::from_secs(20);
    let supervisor = Arc::new(RuntimeProcessSupervisor::new(settings, Box::new(OsLauncher)));
    let calls = Arc::new(AtomicUsize::new(0));
    let service = ControlService::new(Arc::clone(&supervisor), Arc::new(CountingHealth(calls)));
    let (bound, listening) = tokio::sync::oneshot::channel();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(serve_loopback("127.0.0.1:0".parse().unwrap(), service, bound, async {
        let _ = stopped.await;
    }));
    let address = listening.await.unwrap();
    assert!(address.ip().is_loopback());
    let mut client = PrivokeRuntimeControlServiceClient::connect(format!("http://{address}")).await.unwrap();

    let initial = client.status(RuntimeHealthRequest {}).await.unwrap().into_inner();
    assert!(!initial.enabled);
    assert_eq!(initial.status, "STOPPED");

    let started = client.set_runtime_enabled(SetRuntimeEnabledRequest { enabled: true, use_local_stack: None }).await.unwrap().into_inner();
    assert!(started.enabled, "{}", started.message);
    assert_eq!(started.status, "RUNNING");
    assert_ne!(started.process_id, 0);
    assert!(port_is_open(runtime_port));
    assert_eq!(client.status(RuntimeHealthRequest {}).await.unwrap().into_inner().process_id, started.process_id);

    // A change of stack restarts the owned child: a new process, still on loopback.
    let switched =
        client.set_runtime_enabled(SetRuntimeEnabledRequest { enabled: true, use_local_stack: Some(true) }).await.unwrap().into_inner();
    assert!(switched.enabled, "{}", switched.message);
    assert_ne!(switched.process_id, started.process_id);
    assert_eq!(supervisor.environment().unwrap()["PRIVOKE_USE_LOCAL_STACK"], "true");

    let stopped_status =
        client.set_runtime_enabled(SetRuntimeEnabledRequest { enabled: false, use_local_stack: None }).await.unwrap().into_inner();
    assert!(!stopped_status.enabled);
    assert!(wait_until(Duration::from_secs(10), || !port_is_open(runtime_port)), "the runtime port is released");

    let _ = stop.send(());
    server.await.unwrap().unwrap();
}

#[tokio::test]
async fn a_malformed_stack_setting_is_invalid_argument_over_the_wire() {
    let environment = BTreeMap::from([("PRIVOKE_USE_LOCAL_STACK".to_string(), "sometimes".to_string())]);
    let settings = SupervisorSettings::new(
        std::path::Path::new("."),
        environment,
        free_port(),
        Some(vec![TEST_CHILD.to_string(), "exit".to_string()]),
    );
    let supervisor = Arc::new(RuntimeProcessSupervisor::new(settings, Box::new(OsLauncher)));
    let service = ControlService::new(supervisor, Arc::new(CountingHealth(Arc::new(AtomicUsize::new(0)))));
    let (bound, listening) = tokio::sync::oneshot::channel();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(serve_loopback("127.0.0.1:0".parse().unwrap(), service, bound, async {
        let _ = stopped.await;
    }));
    let mut client = PrivokeRuntimeControlServiceClient::connect(format!("http://{}", listening.await.unwrap())).await.unwrap();
    let error = client.set_runtime_enabled(SetRuntimeEnabledRequest { enabled: true, use_local_stack: Some(true) }).await.unwrap_err();
    assert_eq!(error.code(), Code::InvalidArgument);
    let _ = stop.send(());
    server.await.unwrap().unwrap();
}

#[tokio::test]
async fn the_control_listener_refuses_a_non_loopback_address() {
    let service = ControlService::new(idle_supervisor(free_port()), Arc::new(CountingHealth(Arc::new(AtomicUsize::new(0)))));
    let (bound, _listening) = tokio::sync::oneshot::channel();
    let outcome = serve_loopback("0.0.0.0:0".parse().unwrap(), service, bound, std::future::pending()).await;
    assert!(outcome.is_err(), "a plaintext control service must never listen on a routable interface");
}

fn common_environment() -> BTreeMap<String, String> {
    std::env::vars().collect()
}
