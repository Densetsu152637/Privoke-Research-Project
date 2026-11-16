//! Plaintext exists only behind the `workstation-loopback` feature, only on loopback, and never authenticates.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::sync::Arc;
use std::sync::atomic::AtomicUsize;

use common::{Service, default_policy, default_registry};
use privoke_proto::v1::HealthRequest;
use privoke_proto::v1::model_streaming_service_client::ModelStreamingServiceClient;
use privoke_proto::v1::model_streaming_service_server::ModelStreamingServiceServer;
use privoke_transport::listener::loopback::LoopbackListener;
use privoke_transport::{AuthLayer, Limits, SharedRegistry, TransportError};
use tonic::Code;
use tonic::transport::{Endpoint, Server};

#[tokio::test]
async fn refuses_to_bind_anything_but_loopback() {
    for address in ["0.0.0.0:0", "192.0.2.1:0", "10.0.0.1:0"] {
        let error = LoopbackListener::bind(address.parse().unwrap()).await.unwrap_err();
        assert!(matches!(error, TransportError::NotLoopback(_)), "{address}: {error}");
    }
    LoopbackListener::bind("127.0.0.1:0".parse().unwrap()).await.expect("loopback is allowed");
}

async fn serve_plaintext(auth: Option<AuthLayer>) -> std::net::SocketAddr {
    let listener = LoopbackListener::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let address = listener.local_addr().unwrap();
    let service = ModelStreamingServiceServer::new(Service { calls: Arc::new(AtomicUsize::new(0)) });
    tokio::spawn(async move {
        match auth {
            Some(auth) => Server::builder().layer(auth).add_service(service).serve_with_incoming(listener.incoming()).await,
            None => Server::builder().add_service(service).serve_with_incoming(listener.incoming()).await,
        }
    });
    address
}

#[tokio::test]
async fn serves_plaintext_on_loopback_for_the_workstation() {
    let address = serve_plaintext(None).await;
    let channel = Endpoint::from_shared(format!("http://{address}")).unwrap().connect().await.unwrap();
    let response = ModelStreamingServiceClient::new(channel).health(HealthRequest {}).await.unwrap();
    assert_eq!(response.into_inner().status, "SERVING");
}

#[tokio::test]
async fn the_authorisation_layer_never_admits_a_plaintext_peer() {
    let auth = AuthLayer::new(default_policy(), SharedRegistry::new(default_registry()), Limits::default().rate);
    let address = serve_plaintext(Some(auth)).await;
    let channel = Endpoint::from_shared(format!("http://{address}")).unwrap().connect().await.unwrap();
    let status = ModelStreamingServiceClient::new(channel).health(HealthRequest {}).await.unwrap_err();
    assert_eq!(status.code(), Code::Unauthenticated);
}
