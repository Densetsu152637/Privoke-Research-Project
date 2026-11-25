//! The registry file format, expiry, and hot reload of the file into a running server.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::time::Duration;

use common::{ALICE, BOB, CAROL, LeafSpec, Options, Pki, TestServer, eventually};
use privoke_proto::v1::HealthRequest;
use privoke_transport::registry::{Denial, Registry, RegistryFile, RegistryFileReloader};
use privoke_transport::{Identity, Role};

const FULL: &str = r#"
version = 1
reporter = true

[[installation]]
id = "11111111-1111-4111-8111-111111111111"
label = "alice laptop"
expires = "2027-05-01T00:00:00Z"

[[installation]]
id = "22222222-2222-4222-8222-222222222222"

[[service]]
name = "param-update"
role = "publisher"

[[service]]
name = "fuzzer"
role = "trainer"

[[deny]]
urn = "urn:privoke:installation:33333333-3333-4333-8333-333333333333"
reason = "device lost"
"#;

fn installation(id: &str) -> Identity {
    Identity::Installation(id.to_string())
}

#[test]
fn a_full_file_round_trips_and_resolves_every_kind() {
    let file = RegistryFile::from_toml(FULL).unwrap();
    assert_eq!(RegistryFile::from_toml(&file.to_toml().unwrap()).unwrap(), file);
    let registry = file.to_registry().unwrap();
    let now = 1_800_000_000; // inside alice's validity
    assert_eq!(registry.resolve_at(&installation(ALICE), now).unwrap().role, Role::Consumer);
    assert_eq!(registry.resolve_at(&installation(BOB), now).unwrap().role, Role::Consumer);
    assert_eq!(registry.resolve_at(&Identity::Service("param-update".into()), now).unwrap().role, Role::Publisher);
    assert_eq!(registry.resolve_at(&Identity::Service("fuzzer".into()), now).unwrap().role, Role::Trainer);
    assert_eq!(registry.resolve_at(&Identity::Reporter, now).unwrap().role, Role::Reporter);
    assert_eq!(registry.resolve_at(&installation(CAROL), now), Err(Denial::Denied));
    assert_eq!(registry.resolve_at(&installation("44444444-4444-4444-8444-444444444444"), now), Err(Denial::Unregistered));
    assert_eq!(registry.resolve_at(&Identity::Service("other".into()), now), Err(Denial::Unregistered));
}

#[test]
fn entries_expire_and_the_deny_list_wins() {
    let registry = RegistryFile::from_toml(FULL).unwrap().to_registry().unwrap();
    let after = 1_900_000_000; // 2030, past alice's 2027-05-01 expiry
    assert_eq!(registry.resolve_at(&installation(ALICE), after), Err(Denial::Expired));
    assert!(registry.resolve_at(&installation(BOB), after).is_ok(), "no expiry means no expiry");
    let denied = Registry::new().with_installation(ALICE).deny(installation(ALICE));
    assert_eq!(denied.resolve(&installation(ALICE)), Err(Denial::Denied));
    assert_eq!(Registry::new().with_installation_until(ALICE, 1).resolve(&installation(ALICE)), Err(Denial::Expired));
}

#[test]
fn invalid_files_are_refused_with_a_reason() {
    let cases = [
        ("", "version"),
        ("version = 2\n", "unsupported version"),
        ("version = 1\nunknown = true\n", "unknown field"),
        ("version = 1\n[[installation]]\nid = \"ABC\"\n", "lowercase UUID"),
        (
            "version = 1\n[[installation]]\nid = \"11111111-1111-4111-8111-111111111111\"\n[[installation]]\nid = \"11111111-1111-4111-8111-111111111111\"\n",
            "duplicate installation",
        ),
        ("version = 1\n[[installation]]\nid = \"11111111-1111-4111-8111-111111111111\"\nexpires = \"tomorrow\"\n", "expiry"),
        (
            "version = 1\n[[installation]]\nid = \"11111111-1111-4111-8111-111111111111\"\nexpires = \"2027-05-01T00:00:00+02:00\"\n",
            "must be UTC",
        ),
        ("version = 1\n[[service]]\nname = \"x\"\nrole = \"consumer\"\n", "unknown role"),
        ("version = 1\n[[service]]\nname = \"Bad Name\"\nrole = \"publisher\"\n", "malformed"),
        (
            "version = 1\n[[service]]\nname = \"a\"\nrole = \"publisher\"\n[[service]]\nname = \"a\"\nrole = \"trainer\"\n",
            "duplicate service",
        ),
        ("version = 1\n[[deny]]\nurn = \"urn:other:thing\"\n", "not a PriVoke identity"),
    ];
    for (text, expected) in cases {
        let error = RegistryFile::from_toml(text).unwrap_err().to_string();
        assert!(error.contains(expected), "{text:?}: {error}");
    }
}

#[tokio::test]
async fn a_running_server_follows_the_registry_file_and_survives_bad_edits() {
    let pki = Pki::new();
    let path = pki.write("registry.toml", &format!("version = 1\n\n[[installation]]\nid = \"{ALICE}\"\n"));
    let reloader = RegistryFileReloader::load(&path).unwrap();
    let _watch = reloader.spawn_watcher(Duration::from_millis(50));
    let server = TestServer::start_with(&pki, Options { shared_registry: Some(reloader.registry()), ..Options::default() }).await;
    let alice = pki.client_ca.leaf(LeafSpec::installation(ALICE));
    let bob = pki.client_ca.leaf(LeafSpec::installation(BOB));
    let mut alice_client = server.connect(&pki.client_config("alice", Some(&alice))).await.unwrap();
    let mut bob_client = server.connect(&pki.client_config("bob", Some(&bob))).await.unwrap();
    alice_client.health(HealthRequest {}).await.unwrap();
    assert_eq!(bob_client.health(HealthRequest {}).await.unwrap_err().code(), tonic::Code::PermissionDenied);

    // Admit bob and deny alice in one edit; both take effect on the already-open connections.
    pki.write(
        "registry.toml",
        &format!(
            "version = 1\n\n[[installation]]\nid = \"{ALICE}\"\n\n[[installation]]\nid = \"{BOB}\"\n\n[[deny]]\nurn = \"urn:privoke:installation:{ALICE}\"\n"
        ),
    );
    assert!(
        eventually(Duration::from_secs(10), || async { bob_client.clone().health(HealthRequest {}).await.is_ok() }).await,
        "bob was not admitted"
    );
    assert_eq!(alice_client.health(HealthRequest {}).await.unwrap_err().code(), tonic::Code::PermissionDenied);
    let generation = reloader.status().generation;

    // A broken edit changes nothing and is reported.
    pki.write("registry.toml", "version = 1\n[[installation]]\nid = \"nonsense\"\n");
    assert!(eventually(Duration::from_secs(10), || async { reloader.status().last_error.is_some() }).await);
    assert_eq!(reloader.status().generation, generation);
    bob_client.health(HealthRequest {}).await.expect("the previous registry must stay in force");
    assert_eq!(alice_client.health(HealthRequest {}).await.unwrap_err().code(), tonic::Code::PermissionDenied);

    // Removing the file is also refused, and a good file restores reloading.
    std::fs::remove_file(&path).unwrap();
    assert!(
        eventually(Duration::from_secs(10), || async { reloader.status().last_error.as_deref().is_some_and(|e| e.contains("missing")) })
            .await
    );
    pki.write("registry.toml", &format!("version = 1\n\n[[installation]]\nid = \"{ALICE}\"\n"));
    assert!(eventually(Duration::from_secs(10), || async { reloader.status().last_error.is_none() }).await);
    assert!(eventually(Duration::from_secs(10), || async { alice_client.clone().health(HealthRequest {}).await.is_ok() }).await);
}

#[test]
fn the_first_load_fails_closed() {
    let pki = Pki::new();
    assert!(RegistryFileReloader::load(pki.path("absent.toml")).is_err());
    let bad = pki.write("bad.toml", "version = 1\n[[deny]]\nurn = \"x\"\n");
    assert!(RegistryFileReloader::load(bad).is_err());
}
