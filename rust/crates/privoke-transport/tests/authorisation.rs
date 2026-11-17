//! Authorisation: the (role, RPC) policy, UNIMPLEMENTED for unlisted methods, registry membership and rate limits.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::{ALICE, BOB, CAROL, LeafSpec, Options, Pki, TestServer, default_registry};
use privoke_proto::v1::{HealthRequest, ModelAssetRequest, ModelParametersRequest};
use privoke_transport::{Limits, RateLimit};
use tonic::Code;

fn parameters(model: &str) -> ModelParametersRequest {
    ModelParametersRequest { consumer_id: String::new(), model_id: model.to_string() }
}

#[tokio::test]
async fn roles_gate_each_method_and_unlisted_methods_are_unimplemented() {
    let pki = Pki::new();
    let server = TestServer::start(&pki).await;
    let alice = pki.client_ca.leaf(LeafSpec::installation(ALICE));
    let publisher = pki.client_ca.leaf(LeafSpec::urn("urn:privoke:service:publisher"));
    let reporter = pki.client_ca.leaf(LeafSpec::urn("urn:privoke:reporter"));

    let mut consumer = server.connect(&pki.client_config("alice", Some(&alice))).await.unwrap();
    consumer.health(HealthRequest {}).await.expect("consumer may call Health");
    consumer.get_model_parameters(parameters("m")).await.expect("consumer may fetch parameters");
    // A consumer is not a publisher.
    assert_eq!(consumer.get_model_package(parameters("m")).await.unwrap_err().code(), Code::PermissionDenied);
    // An RPC the listener does not serve at all is UNIMPLEMENTED, regardless of role.
    let unlisted = consumer.stream_model_asset(ModelAssetRequest::default()).await.unwrap_err();
    assert_eq!(unlisted.code(), Code::Unimplemented);

    let mut publisher = server.connect(&pki.client_config("publisher", Some(&publisher))).await.unwrap();
    let package = publisher.get_model_package(parameters("m")).await.expect("publisher may call GetModelPackage");
    // The authorised principal is visible to the service through request extensions.
    assert_eq!(package.into_inner().model_id, "urn:privoke:service:publisher");
    assert_eq!(publisher.get_model_parameters(parameters("m")).await.unwrap_err().code(), Code::PermissionDenied);

    // The reporter credential may call Health but nothing that needs the consumer role.
    let mut reporter = server.connect(&pki.client_config("reporter", Some(&reporter))).await.unwrap();
    reporter.health(HealthRequest {}).await.expect("reporter may call Health");
    assert_eq!(reporter.get_model_parameters(parameters("m")).await.unwrap_err().code(), Code::PermissionDenied);
}

#[tokio::test]
async fn certificates_from_the_right_ca_still_need_a_registry_entry() {
    let pki = Pki::new();
    let server = TestServer::start(&pki).await;
    let unregistered = pki.client_ca.leaf(LeafSpec::installation(CAROL));
    let mut client = server.connect(&pki.client_config("carol", Some(&unregistered))).await.unwrap();
    assert_eq!(client.health(HealthRequest {}).await.unwrap_err().code(), Code::PermissionDenied);
    let unregistered_service = pki.client_ca.leaf(LeafSpec::urn("urn:privoke:service:unknown"));
    let mut service = server.connect(&pki.client_config("unknown", Some(&unregistered_service))).await.unwrap();
    assert_eq!(service.health(HealthRequest {}).await.unwrap_err().code(), Code::PermissionDenied);
    assert_eq!(server.handler_calls(), 0);

    // Registering the installation admits it, with no restart.
    server.registry.replace(default_registry().with_installation(CAROL));
    client.health(HealthRequest {}).await.expect("registered installation is served");
}

#[tokio::test]
async fn the_reporter_credential_is_refused_when_the_registry_does_not_admit_it() {
    let pki = Pki::new();
    let server = TestServer::start_with(
        &pki,
        Options { registry: privoke_transport::Registry::new().with_installation(ALICE), ..Options::default() },
    )
    .await;
    let reporter = pki.client_ca.leaf(LeafSpec::urn("urn:privoke:reporter"));
    let mut client = server.connect(&pki.client_config("reporter", Some(&reporter))).await.unwrap();
    assert_eq!(client.health(HealthRequest {}).await.unwrap_err().code(), Code::PermissionDenied);
}

#[tokio::test]
async fn rate_limits_are_per_identity_and_do_not_leak_between_peers() {
    let pki = Pki::new();
    let limits = Limits { rate: RateLimit { per_second: 1, burst: 3 }, ..Limits::default() };
    let server = TestServer::start_with(&pki, Options { limits, ..Options::default() }).await;
    let alice = pki.client_ca.leaf(LeafSpec::installation(ALICE));
    let bob = pki.client_ca.leaf(LeafSpec::installation(BOB));
    let mut alice_client = server.connect(&pki.client_config("alice", Some(&alice))).await.unwrap();
    let mut bob_client = server.connect(&pki.client_config("bob", Some(&bob))).await.unwrap();

    let mut refused = 0;
    for _ in 0..8 {
        if let Err(status) = alice_client.health(HealthRequest {}).await {
            assert_eq!(status.code(), Code::ResourceExhausted);
            refused += 1;
        }
    }
    assert!(refused >= 4, "burst of 3 should leave at least 4 of 8 refused, got {refused}");
    bob_client.health(HealthRequest {}).await.expect("another installation has its own bucket");
}

#[tokio::test]
async fn source_ip_keyed_rules_share_one_bucket_across_identities() {
    let pki = Pki::new();
    let limits = Limits { rate: RateLimit { per_second: 1, burst: 2 }, ..Limits::default() };
    let server = TestServer::start_with(&pki, Options { limits, ..Options::default() }).await;
    let alice = pki.client_ca.leaf(LeafSpec::installation(ALICE));
    let bob = pki.client_ca.leaf(LeafSpec::installation(BOB));
    let mut alice_client = server.connect(&pki.client_config("alice", Some(&alice))).await.unwrap();
    let mut bob_client = server.connect(&pki.client_config("bob", Some(&bob))).await.unwrap();

    // StreamModelParameters is keyed by source IP. Both clients come from 127.0.0.1, so they share the bucket.
    let mut codes = Vec::new();
    for turn in 0..5 {
        let client = if turn % 2 == 0 { &mut alice_client } else { &mut bob_client };
        match client.stream_model_parameters(parameters("m")).await {
            Ok(_) => codes.push(Code::Ok),
            Err(status) => codes.push(status.code()),
        }
    }
    assert!(codes.contains(&Code::ResourceExhausted), "shared bucket was never exhausted: {codes:?}");
    // The handler returns UNIMPLEMENTED once admitted, which proves the limit, not the handler, produced the refusals.
    assert!(codes.contains(&Code::Unimplemented), "no request was admitted: {codes:?}");
}
