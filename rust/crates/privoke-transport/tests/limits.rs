//! Limits that replace nginx: body size, request timeout, per-IP connection cap, handshake timeout and connection age.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::time::{Duration, Instant};

use common::{ALICE, LeafSpec, Options, Pki, TestServer, eventually};
use privoke_proto::v1::{HealthRequest, ModelParametersRequest};
use privoke_transport::Limits;
use tokio::io::AsyncReadExt;
use tonic::Code;

fn request(model: &str) -> ModelParametersRequest {
    ModelParametersRequest { consumer_id: String::new(), model_id: model.to_string() }
}

#[tokio::test]
async fn oversized_messages_are_refused_and_small_ones_pass() {
    let pki = Pki::new();
    let limits = Limits { max_message_bytes: 1024, ..Limits::default() };
    let server = TestServer::start_with(&pki, Options { limits, ..Options::default() }).await;
    let alice = pki.client_ca.leaf(LeafSpec::installation(ALICE));
    let mut client = server.connect(&pki.client_config("alice", Some(&alice))).await.unwrap();
    client.get_model_parameters(request("small")).await.expect("a small message passes");
    let status = client.get_model_parameters(request(&"x".repeat(4096))).await.unwrap_err();
    assert!(matches!(status.code(), Code::ResourceExhausted | Code::OutOfRange), "{status:?}");
    assert_eq!(server.handler_calls(), 1, "the oversized request reached the handler");
}

#[tokio::test]
async fn slow_handlers_hit_the_request_timeout() {
    let pki = Pki::new();
    let limits = Limits { request_timeout: Duration::from_millis(300), ..Limits::default() };
    let server = TestServer::start_with(&pki, Options { limits, ..Options::default() }).await;
    let alice = pki.client_ca.leaf(LeafSpec::installation(ALICE));
    let mut client = server.connect(&pki.client_config("alice", Some(&alice))).await.unwrap();
    let started = Instant::now();
    let status = client.get_model_parameters(request("slow")).await.unwrap_err();
    assert!(matches!(status.code(), Code::Cancelled | Code::DeadlineExceeded), "{status:?}");
    assert!(started.elapsed() < Duration::from_secs(3), "the timeout did not fire: {:?}", started.elapsed());
}

#[tokio::test]
async fn connections_per_ip_are_capped_and_released() {
    let pki = Pki::new();
    let limits = Limits { max_connections_per_ip: 2, ..Limits::default() };
    let server = TestServer::start_with(&pki, Options { limits, ..Options::default() }).await;
    let alice = pki.client_ca.leaf(LeafSpec::installation(ALICE));
    let config = pki.client_config("alice", Some(&alice));

    let mut first = server.connect(&config).await.unwrap();
    let mut second = server.connect(&config).await.unwrap();
    first.health(HealthRequest {}).await.unwrap();
    second.health(HealthRequest {}).await.unwrap();
    assert!(server.health(&config).await.is_err(), "a third connection from one IP was served");

    drop(first);
    assert!(eventually(Duration::from_secs(5), || async { server.health(&config).await.is_ok() }).await, "the slot was not released");
    second.health(HealthRequest {}).await.expect("the surviving connection is unaffected");
}

#[tokio::test]
async fn silent_clients_are_dropped_at_the_handshake_timeout() {
    let pki = Pki::new();
    let limits = Limits { handshake_timeout: Duration::from_millis(300), ..Limits::default() };
    let server = TestServer::start_with(&pki, Options { limits, ..Options::default() }).await;
    let mut socket = tokio::net::TcpStream::connect(server.address).await.unwrap();
    let mut buffer = [0u8; 16];
    let read =
        tokio::time::timeout(Duration::from_secs(5), socket.read(&mut buffer)).await.expect("the server never closed the idle socket");
    assert!(matches!(read, Ok(0) | Err(_)), "the server sent data to a client that sent nothing");
}

#[tokio::test]
async fn old_connections_are_drained_even_with_an_rpc_in_flight() {
    let pki = Pki::new();
    let limits = Limits {
        max_connection_age: Duration::from_millis(400),
        max_connection_age_grace: Duration::from_millis(200),
        request_timeout: Duration::from_secs(30),
        ..Limits::default()
    };
    let server = TestServer::start_with(&pki, Options { limits, ..Options::default() }).await;
    let alice = pki.client_ca.leaf(LeafSpec::installation(ALICE));
    let mut client = server.connect(&pki.client_config("alice", Some(&alice))).await.unwrap();
    let started = Instant::now();
    // The handler would sleep five seconds; the connection is drained long before.
    let status = client.get_model_parameters(request("slow")).await.unwrap_err();
    assert!(started.elapsed() < Duration::from_secs(4), "the connection outlived its maximum age: {:?} {status:?}", started.elapsed());
}
