//! CRL hot reload, refusal of unusable CRLs, and registry changes on open connections.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::time::Duration;

use common::{ALICE, BOB, Ca, LeafSpec, Pki, TestServer, eventually};
use privoke_proto::v1::HealthRequest;
use privoke_transport::{Identity, ReloadableTls};
use time::Duration as TimeDuration;

#[tokio::test]
async fn revoking_one_installation_takes_effect_without_a_restart() {
    let pki = Pki::new();
    let server = TestServer::start(&pki).await;
    let alice = pki.client_ca.leaf(LeafSpec::installation(ALICE));
    let bob = pki.client_ca.leaf(LeafSpec::installation(BOB));
    let alice_client = pki.client_config("alice", Some(&alice));
    let bob_client = pki.client_config("bob", Some(&bob));
    server.health(&alice_client).await.unwrap();
    server.health(&bob_client).await.unwrap();
    let generation = server.tls.status().generation;

    pki.write_crl(&[alice.serial]);

    assert!(
        eventually(Duration::from_secs(10), || async { server.health(&alice_client).await.is_err() }).await,
        "revoked installation was still accepted after the CRL changed"
    );
    server.health(&bob_client).await.expect("control installation must keep connecting");
    assert!(server.tls.status().generation > generation);
    assert_eq!(server.tls.status().last_error, None);
}

#[tokio::test]
async fn corrupt_crl_keeps_the_previous_configuration() {
    let pki = Pki::new();
    let server = TestServer::start(&pki).await;
    let alice = pki.client_ca.leaf(LeafSpec::installation(ALICE));
    let client = pki.client_config("alice", Some(&alice));
    server.health(&client).await.unwrap();
    let generation = server.tls.status().generation;

    pki.replace_crl_text("-----BEGIN X509 CRL-----\nbm90IGEgY3Js\n-----END X509 CRL-----\n");

    assert!(eventually(Duration::from_secs(10), || async { server.tls.status().last_error.is_some() }).await, "refusal was not recorded");
    assert_eq!(server.tls.status().generation, generation, "a corrupt CRL replaced the configuration");
    server.health(&client).await.expect("the previous configuration must keep serving");
}

#[tokio::test]
async fn crl_signed_by_another_authority_is_refused() {
    let pki = Pki::new();
    let server = TestServer::start(&pki).await;
    let alice = pki.client_ca.leaf(LeafSpec::installation(ALICE));
    let client = pki.client_config("alice", Some(&alice));
    let impostor = Ca::new("Impostor CA");
    pki.replace_crl_text(&impostor.crl(&[], TimeDuration::days(7)));

    assert!(eventually(Duration::from_secs(10), || async { server.tls.status().last_error.is_some() }).await);
    let error = server.tls.status().last_error.unwrap();
    assert!(error.contains("not signed by the client CA"), "{error}");
    server.health(&client).await.unwrap();
}

#[tokio::test]
async fn stale_crl_is_refused_at_reload_and_at_startup() {
    let pki = Pki::new();
    let server = TestServer::start(&pki).await;
    let generation = server.tls.status().generation;
    pki.replace_crl_text(&pki.client_ca.crl(&[], TimeDuration::seconds(-60)));
    assert!(eventually(Duration::from_secs(10), || async { server.tls.status().last_error.is_some() }).await);
    assert!(server.tls.status().last_error.unwrap().contains("stale"));
    assert_eq!(server.tls.status().generation, generation);
    drop(server);

    // At startup the same file means the server refuses to start rather than running unprotected.
    let error = ReloadableTls::load(pki.server_config()).unwrap_err();
    assert!(error.to_string().contains("stale"), "{error}");
}

#[tokio::test]
async fn empty_or_missing_crl_prevents_startup() {
    let pki = Pki::new();
    pki.replace_crl_text("");
    assert!(ReloadableTls::load(pki.server_config()).is_err());
    std::fs::remove_file(pki.path("crl.pem")).unwrap();
    assert!(ReloadableTls::load(pki.server_config()).is_err());
}

#[tokio::test]
async fn a_good_crl_after_a_bad_one_restores_reloading() {
    let pki = Pki::new();
    let server = TestServer::start(&pki).await;
    let alice = pki.client_ca.leaf(LeafSpec::installation(ALICE));
    let client = pki.client_config("alice", Some(&alice));
    pki.replace_crl_text("garbage");
    assert!(eventually(Duration::from_secs(10), || async { server.tls.status().last_error.is_some() }).await);
    pki.write_crl(&[alice.serial]);
    assert!(eventually(Duration::from_secs(10), || async { server.tls.status().last_error.is_none() }).await);
    assert!(eventually(Duration::from_secs(10), || async { server.health(&client).await.is_err() }).await);
}

#[tokio::test]
async fn deny_listed_installation_is_refused_on_an_open_connection() {
    let pki = Pki::new();
    let server = TestServer::start(&pki).await;
    let alice = pki.client_ca.leaf(LeafSpec::installation(ALICE));
    let client = pki.client_config("alice", Some(&alice));
    let mut open = server.connect(&client).await.unwrap();
    open.health(HealthRequest {}).await.expect("registered installation is served");

    // The same TLS connection stays open; only the registry changes.
    server.registry.replace(common::default_registry().deny(Identity::Installation(ALICE.to_string())));

    let status = open.health(HealthRequest {}).await.expect_err("deny-listed installation must be refused");
    assert_eq!(status.code(), tonic::Code::PermissionDenied);
    assert_eq!(server.handler_calls(), 1);
}
