//! The model-streaming health check behind `ModelStreamingHealth`, over mutual TLS against an in-process Rust
//! model-streaming server, with certificates generated at test time. It is lazy, and every failure is `NOT_SERVING`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use common::pki::TestPki;
use privoke_contracts::proto::v1::RuntimeHealthResponse;
use privoke_supervisor::channel::ModelEndpoint;
use privoke_supervisor::controller::{Controller, Request};
use privoke_supervisor::health::{BoxFuture, ModelHealth, model_streaming_health};
use privoke_supervisor::runtime::RuntimeController;
use privoke_supervisor::worker::WorkerSettings;
use prost::Message;

struct CountingHealth(Arc<AtomicUsize>);

impl ModelHealth for CountingHealth {
    fn check(&self) -> BoxFuture<(String, String)> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { ("model-streaming-service".to_string(), "SERVING".to_string()) })
    }
}

#[tokio::test]
async fn model_streaming_health_check_is_lazy() {
    let runtime = Arc::new(RuntimeController::new(
        WorkerSettings::from_environment(&BTreeMap::new(), std::path::Path::new(".")).unwrap(),
        BTreeMap::new(),
    ));
    let calls = Arc::new(AtomicUsize::new(0));
    let controller = Controller::new(runtime, Arc::new(CountingHealth(Arc::clone(&calls))));
    assert_eq!(calls.load(Ordering::SeqCst), 0, "building the controller performs no health call");
    let request: Request = serde_json::from_str(r#"{"v":1,"id":3,"method":"ModelStreamingHealth","payload":""}"#).unwrap();
    let reply: serde_json::Value = serde_json::from_str(&controller.handle(request).await).unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let response = RuntimeHealthResponse::decode(STANDARD.decode(reply["payload"].as_str().unwrap()).unwrap().as_slice()).unwrap();
    assert_eq!((response.service.as_str(), response.status.as_str()), ("model-streaming-service", "SERVING"));
}

#[tokio::test]
async fn health_check_performs_the_model_streaming_rpc_over_mutual_tls() {
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
