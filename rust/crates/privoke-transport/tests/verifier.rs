//! The client-certificate verifier: a registered installation with a good certificate is served, and each of the
//! six required failure modes is refused at the handshake without the service handler ever running.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::{ALICE, Ca, Eku, LeafSpec, Pki, TestServer};
use time::{Duration, OffsetDateTime};

#[tokio::test]
async fn accepts_a_valid_registered_installation() {
    let pki = Pki::new();
    let server = TestServer::start(&pki).await;
    let alice = pki.client_ca.leaf(LeafSpec::installation(ALICE));
    let client = pki.client_config("alice", Some(&alice));
    server.health(&client).await.unwrap();
    assert_eq!(server.handler_calls(), 1);
}

#[tokio::test]
async fn refuses_every_invalid_credential_before_the_handler_runs() {
    let pki = Pki::new();
    let server = TestServer::start(&pki).await;
    let now = OffsetDateTime::now_utc();

    // 1. No certificate at all.
    let anonymous = pki.client_config("anonymous", None);
    assert!(server.health(&anonymous).await.is_err(), "anonymous client was served");

    // 2. A valid-looking certificate from a CA the server does not trust.
    let foreign_ca = Ca::new("Foreign CA");
    let foreign = foreign_ca.leaf(LeafSpec::installation(ALICE));
    assert!(server.health(&pki.client_config("foreign", Some(&foreign))).await.is_err(), "foreign CA was accepted");

    // 3. Expired.
    let expired = pki.client_ca.leaf(LeafSpec {
        not_before: now - Duration::days(30),
        not_after: now - Duration::days(1),
        ..LeafSpec::installation(ALICE)
    });
    assert!(server.health(&pki.client_config("expired", Some(&expired))).await.is_err(), "expired certificate was accepted");

    // 4. Not yet valid.
    let future = pki.client_ca.leaf(LeafSpec {
        not_before: now + Duration::days(1),
        not_after: now + Duration::days(30),
        ..LeafSpec::installation(ALICE)
    });
    assert!(server.health(&pki.client_config("future", Some(&future))).await.is_err(), "not-yet-valid certificate was accepted");

    // 5. Missing client-auth EKU: no EKU extension at all, and an EKU that lists only serverAuth.
    let no_eku = pki.client_ca.leaf(LeafSpec { eku: Eku::Absent, ..LeafSpec::installation(ALICE) });
    assert!(server.health(&pki.client_config("no-eku", Some(&no_eku))).await.is_err(), "certificate without an EKU was accepted");
    let server_eku = pki.client_ca.leaf(LeafSpec { eku: Eku::Server, ..LeafSpec::installation(ALICE) });
    assert!(server.health(&pki.client_config("server-eku", Some(&server_eku))).await.is_err(), "serverAuth-only certificate was accepted");

    // 6. Missing or malformed PriVoke identity.
    let no_identity = pki.client_ca.leaf(LeafSpec { urn: None, ..LeafSpec::installation(ALICE) });
    assert!(
        server.health(&pki.client_config("no-identity", Some(&no_identity))).await.is_err(),
        "certificate without identity was accepted"
    );
    let malformed = pki.client_ca.leaf(LeafSpec::urn("urn:privoke:installation:not-a-uuid"));
    assert!(server.health(&pki.client_config("malformed", Some(&malformed))).await.is_err(), "malformed identity was accepted");

    assert_eq!(server.handler_calls(), 0, "a refused client reached the handler");

    // The positive control still works afterwards.
    let alice = pki.client_ca.leaf(LeafSpec::installation(ALICE));
    server.health(&pki.client_config("alice", Some(&alice))).await.unwrap();
    assert_eq!(server.handler_calls(), 1);
}

#[tokio::test]
async fn refuses_a_revoked_certificate_present_in_the_initial_crl() {
    let pki = Pki::new();
    let revoked = pki.client_ca.leaf(LeafSpec::installation(ALICE));
    let control = pki.client_ca.leaf(LeafSpec::installation(common::BOB));
    pki.write_crl(&[revoked.serial]);
    let server = TestServer::start(&pki).await;
    assert!(server.health(&pki.client_config("revoked", Some(&revoked))).await.is_err(), "revoked certificate was accepted");
    assert_eq!(server.handler_calls(), 0);
    server.health(&pki.client_config("control", Some(&control))).await.unwrap();
}

#[tokio::test]
async fn refuses_a_client_that_does_not_trust_the_server() {
    let pki = Pki::new();
    let server = TestServer::start(&pki).await;
    let alice = pki.client_ca.leaf(LeafSpec::installation(ALICE));
    let mut client = pki.client_config("alice", Some(&alice));
    client.server_name = "wrong.example".to_string();
    assert!(server.health(&client).await.is_err(), "client accepted a certificate for the wrong name");
}
