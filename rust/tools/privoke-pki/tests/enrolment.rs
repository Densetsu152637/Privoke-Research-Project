//! Stage 2 acceptance: enrolment, renewal, offline expiry and revocation, end to end over real mutual TLS.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::path::{Path, PathBuf};

use common::{Operator, Server, eventually, pki, pki_fails, s};
use privoke_pki::ca::Validity;
use privoke_pki::client::{self, CredentialState};
use privoke_pki::registry_edit;
use privoke_transport::identity::Identity;
use privoke_transport::tls::ClientTlsConfig;
use time::{Duration, OffsetDateTime};

fn installation_id(dir: &Path) -> String {
    std::fs::read_to_string(dir.join("installation.id")).unwrap().trim().to_string()
}

/// Enrol through the CLI and have the operator sign and register; returns the credential directory.
fn enrol_and_sign(operator: &Operator, name: &str) -> PathBuf {
    let dir = operator.path(name);
    let bundle = operator.path(&format!("{name}-bundle"));
    pki(&["enrol", "--dir", s(&dir)]);
    let id = installation_id(&dir);
    pki(&[
        "sign",
        "--ca-dir",
        s(&operator.client_ca()),
        "--csr",
        s(&dir.join("client.csr")),
        "--installation",
        &id,
        "--out-dir",
        s(&bundle),
        "--server-ca",
        s(&operator.server_ca().join("ca.crt")),
        "--registry",
        s(&operator.registry()),
        "--label",
        name,
    ]);
    pki(&[
        "install-cert",
        "--dir",
        s(&dir),
        "--cert",
        s(&bundle.join("client.crt")),
        "--server-ca",
        s(&bundle.join("server-ca.pem")),
        "--reporter-cert",
        s(&bundle.join("reporter.crt")),
        "--reporter-key",
        s(&bundle.join("reporter.key")),
    ]);
    dir
}

fn config(operator: &Operator, dir: &Path) -> ClientTlsConfig {
    operator.client_config(dir)
}

#[tokio::test]
async fn enrol_sign_install_then_a_mutual_tls_call_is_accepted() {
    let operator = Operator::new();
    let dir = enrol_and_sign(&operator, "alice");
    let server = Server::start(&operator).await;

    // The installation certificate, issued for the id the installation generated, is accepted.
    server.check(&config(&operator, &dir)).await.expect("enrolled installation must be served");

    // The reporter credential delivered with the enrolment is accepted too, and it is not the installation's identity.
    let reporter = ClientTlsConfig {
        server_ca: dir.join("server-ca.pem"),
        identity: Some((dir.join("reporter.crt"), dir.join("reporter.key"))),
        server_name: "localhost".into(),
    };
    server.check(&reporter).await.expect("reporter credential must be served");

    // The key never left the installation: the bundle holds no installation key.
    assert!(!operator.path("alice-bundle").join("client.key").exists());
    // Status reports a valid certificate close to 180 days.
    let status = client::status(&dir, OffsetDateTime::now_utc()).unwrap();
    assert_eq!(status.state, CredentialState::Valid);
    assert!((178..=180).contains(&status.days_left.unwrap()), "{status:?}");
}

#[tokio::test]
async fn an_unregistered_or_unenrolled_holder_is_not_served() {
    let operator = Operator::new();
    let dir = operator.path("mallory");
    pki(&["enrol", "--dir", s(&dir)]);
    let id = installation_id(&dir);
    // Signed by the real CA but never registered: certificate valid, registry refuses.
    pki(&[
        "sign",
        "--ca-dir",
        s(&operator.client_ca()),
        "--csr",
        s(&dir.join("client.csr")),
        "--installation",
        &id,
        "--out-dir",
        s(&operator.path("m-bundle")),
    ]);
    pki(&["install-cert", "--dir", s(&dir), "--cert", s(&operator.path("m-bundle").join("client.crt"))]);
    let server = Server::start(&operator).await;
    let status = server.check(&config(&operator, &dir)).await.unwrap_err();
    assert_eq!(status.code(), tonic::Code::PermissionDenied);
}

#[tokio::test]
async fn renewal_keeps_the_uuid_and_both_certificates_work_until_the_old_one_expires() {
    let operator = Operator::new();
    let dir = enrol_and_sign(&operator, "alice");
    let id = installation_id(&dir);
    let old_cert = std::fs::read_to_string(dir.join("client.crt")).unwrap();
    let old_key = std::fs::read_to_string(dir.join("client.key")).unwrap();
    let server = Server::start(&operator).await;
    server.check(&config(&operator, &dir)).await.unwrap();

    // Renew: new key and CSR, same id; the active pair is untouched until the new certificate is installed.
    let output = pki(&["renew", "--dir", s(&dir)]);
    assert!(output.contains(&id));
    assert_eq!(std::fs::read_to_string(dir.join("client.key")).unwrap(), old_key);
    assert_ne!(std::fs::read_to_string(dir.join("client.next.key")).unwrap(), old_key);
    let bundle = operator.path("renewal-bundle");
    pki(&[
        "sign",
        "--ca-dir",
        s(&operator.client_ca()),
        "--csr",
        s(&dir.join("client.next.csr")),
        "--installation",
        &id,
        "--out-dir",
        s(&bundle),
        "--registry",
        s(&operator.registry()),
    ]);
    // The old certificate still works while the renewal is in flight.
    server.check(&config(&operator, &dir)).await.expect("old certificate must work before the new one is installed");
    let installed = pki(&["install-cert", "--dir", s(&dir), "--cert", s(&bundle.join("client.crt"))]);
    assert!(installed.contains("renewal promoted"), "{installed}");
    assert!(!dir.join("client.next.key").exists());

    // New pair active.
    assert_ne!(std::fs::read_to_string(dir.join("client.crt")).unwrap(), old_cert);
    server.check(&config(&operator, &dir)).await.expect("renewed certificate must work");
    // The old pair, kept as client.prev.*, is also still valid: both are accepted until the old one expires.
    let previous = ClientTlsConfig {
        server_ca: operator.server_ca().join("ca.crt"),
        identity: Some((dir.join("client.prev.crt"), dir.join("client.prev.key"))),
        server_name: "localhost".into(),
    };
    server.check(&previous).await.expect("the old certificate stays valid until it expires");
    // Same identity both times, and one registry entry whose expiry follows the newest certificate.
    let file = privoke_transport::registry::RegistryFile::read(&operator.registry()).unwrap();
    assert_eq!(file.installations.iter().filter(|entry| entry.id == id).count(), 1);
}

#[tokio::test]
async fn an_expired_certificate_is_refused_and_status_says_local_inspection_still_works() {
    let operator = Operator::new();
    let dir = operator.path("alice");
    let enrolment = client::enrol(&dir).unwrap();
    let id = enrolment.installation;
    // Issued 10 days ago for one day, as an installation that stayed offline past expiry would hold.
    let long_ago = Validity { now: OffsetDateTime::now_utc() - Duration::days(10), duration: Duration::days(1) };
    let signed = operator.ca().sign_installation(&std::fs::read_to_string(dir.join("client.csr")).unwrap(), &id, long_ago).unwrap();
    registry_edit::add_installation(&operator.registry(), &id, None, OffsetDateTime::now_utc().unix_timestamp() + 86_400).unwrap();

    // install-cert will not store an expired certificate...
    let refused = client::install_cert(&dir, &signed.cert_pem, None, None, OffsetDateTime::now_utc()).unwrap_err();
    assert!(refused.to_string().contains("expired"), "{refused}");
    // ...and a copy placed by hand is refused by the real server at the handshake.
    std::fs::write(dir.join("client.crt"), &signed.cert_pem).unwrap();
    let server = Server::start(&operator).await;
    assert!(server.check(&config(&operator, &dir)).await.is_err(), "expired certificate was served");

    let status = client::status(&dir, OffsetDateTime::now_utc()).unwrap();
    assert_eq!(status.state, CredentialState::Expired);
    assert!(status.days_left.unwrap() < 0);
    assert!(status.message.contains("Local inspection keeps using the cached"), "{}", status.message);
    assert!(status.message.contains("renew"));
}

#[test]
fn status_warns_thirty_days_ahead_and_works_without_a_network() {
    let operator = Operator::new();
    let dir = enrol_and_sign(&operator, "alice");
    let now = OffsetDateTime::now_utc();
    let at = |days: i64| client::status(&dir, now + Duration::days(days)).unwrap();
    assert_eq!(at(100).state, CredentialState::Valid);
    assert_eq!(at(149).state, CredentialState::Valid);
    assert_eq!(at(152).state, CredentialState::ExpiringSoon);
    assert!(at(160).message.contains("renew"));
    assert_eq!(at(181).state, CredentialState::Expired);
    let fresh = client::status(&operator.path("nobody"), now).unwrap();
    assert_eq!(fresh.state, CredentialState::NotInstalled);
}

#[tokio::test]
async fn revocation_by_crl_and_by_deny_list() {
    let operator = Operator::new();
    let alice = enrol_and_sign(&operator, "alice");
    let bob = enrol_and_sign(&operator, "bob");
    let alice_id = installation_id(&alice);
    let server = Server::start(&operator).await;
    server.check(&config(&operator, &alice)).await.unwrap();
    server.check(&config(&operator, &bob)).await.unwrap();

    // CRL: revoke alice's certificate, publish a new CRL, and her next handshake fails while bob's still works.
    let output = pki(&["revoke", "--ca-dir", s(&operator.client_ca()), "--installation", &alice_id]);
    assert!(output.contains("1 certificate(s)"), "{output}");
    operator.refresh_crl();
    assert!(
        eventually(|| async { server.check(&config(&operator, &alice)).await.is_err() }).await,
        "revoked certificate still accepted after the CRL changed"
    );
    server.check(&config(&operator, &bob)).await.expect("the control installation must keep connecting");

    // Deny list: an open connection is refused at the next RPC, before any CRL change.
    let mut open = server.connect(&config(&operator, &bob)).await.unwrap();
    open.check(tonic_health::pb::HealthCheckRequest { service: String::new() }).await.unwrap();
    let bob_id = installation_id(&bob);
    registry_edit::deny(&operator.registry(), &Identity::Installation(bob_id), Some("device lost")).unwrap();
    assert!(
        eventually(|| async {
            open.clone()
                .check(tonic_health::pb::HealthCheckRequest { service: String::new() })
                .await
                .is_err_and(|status| status.code() == tonic::Code::PermissionDenied)
        })
        .await,
        "deny-listed installation was still served on its open connection"
    );
}

#[tokio::test]
async fn service_principals_and_reporter_revocation() {
    let operator = Operator::new();
    pki(&[
        "sign-service",
        "--ca-dir",
        s(&operator.client_ca()),
        "--name",
        "param-update",
        "--role",
        "publisher",
        "--out-dir",
        s(&operator.path("svc")),
        "--registry",
        s(&operator.registry()),
    ]);
    let server = Server::start(&operator).await;
    let service = ClientTlsConfig {
        server_ca: operator.server_ca().join("ca.crt"),
        identity: Some((operator.path("svc").join("param-update.crt"), operator.path("svc").join("param-update.key"))),
        server_name: "localhost".into(),
    };
    server.check(&service).await.expect("registered publisher must be served");
    let file = privoke_transport::registry::RegistryFile::read(&operator.registry()).unwrap();
    assert_eq!(file.services[0].role, "publisher");

    // Revoking the reporter revokes every holder of the shared credential: CRL plus registry.
    let reporter_dir = operator.client_ca().join("reporter");
    let reporter = ClientTlsConfig {
        server_ca: operator.server_ca().join("ca.crt"),
        identity: Some((reporter_dir.join("reporter.crt"), reporter_dir.join("reporter.key"))),
        server_name: "localhost".into(),
    };
    server.check(&reporter).await.expect("reporter is admitted by the baseline registry");
    pki(&["revoke", "--ca-dir", s(&operator.client_ca()), "--reporter", "--registry", s(&operator.registry())]);
    operator.refresh_crl();
    assert!(eventually(|| async { server.check(&reporter).await.is_err() }).await);
}

#[test]
fn signing_refuses_anything_outside_the_profile() {
    let operator = Operator::new();
    let dir = operator.path("alice");
    pki(&["enrol", "--dir", s(&dir)]);
    let id = installation_id(&dir);
    let csr = s(&dir.join("client.csr")).to_string();
    let sign = |installation: &str, csr: &str| {
        pki_fails(&[
            "sign",
            "--ca-dir",
            s(&operator.client_ca()),
            "--csr",
            csr,
            "--installation",
            installation,
            "--out-dir",
            s(&operator.path("out")),
        ])
    };

    // The operator named a different installation than the CSR carries.
    assert!(sign("99999999-9999-4999-8999-999999999999", &csr).contains("does not match"));
    // A malformed installation id.
    assert!(sign("Not-A-UUID", &csr).contains("not a lowercase UUID"));
    // A CSR with a service identity, a DNS SAN, or a broken signature.
    let key = rcgen::KeyPair::generate().unwrap();
    for (name, san) in [
        ("service", rcgen::SanType::URI("urn:privoke:service:param-update".to_string().try_into().unwrap())),
        ("dns", rcgen::SanType::DnsName("example.com".to_string().try_into().unwrap())),
    ] {
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.subject_alt_names.push(san);
        let path = operator.path(&format!("{name}.csr"));
        std::fs::write(&path, params.serialize_request(&key).unwrap().pem().unwrap()).unwrap();
        assert!(!sign(&id, s(&path)).is_empty(), "{name} CSR was signed");
    }
    let tampered = std::fs::read_to_string(&csr).unwrap();
    let mut lines: Vec<String> = tampered.lines().map(str::to_string).collect();
    let middle = lines.len() / 2;
    lines[middle] = lines[middle].chars().rev().collect();
    let path = operator.path("tampered.csr");
    std::fs::write(&path, lines.join("\n")).unwrap();
    assert!(!sign(&id, s(&path)).is_empty(), "a tampered CSR was signed");
    assert!(!operator.path("out").join("client.crt").exists(), "a refused signing left a certificate behind");
}

#[test]
fn installation_refuses_the_wrong_certificate() {
    let operator = Operator::new();
    let alice = operator.path("alice");
    let bob = operator.path("bob");
    pki(&["enrol", "--dir", s(&alice)]);
    pki(&["enrol", "--dir", s(&bob)]);
    let (alice_id, bob_id) = (installation_id(&alice), installation_id(&bob));
    let bundle = operator.path("bundle");
    pki(&[
        "sign",
        "--ca-dir",
        s(&operator.client_ca()),
        "--csr",
        s(&bob.join("client.csr")),
        "--installation",
        &bob_id,
        "--out-dir",
        s(&bundle),
    ]);
    // Bob's certificate in Alice's directory: wrong identity.
    let error = pki_fails(&["install-cert", "--dir", s(&alice), "--cert", s(&bundle.join("client.crt"))]);
    assert!(error.contains("differs from the expected"), "{error}");
    assert!(!alice.join("client.crt").exists());
    // A certificate for Alice's id but another key.
    let other = operator.path("other");
    pki(&["enrol", "--dir", s(&other)]);
    std::fs::write(other.join("installation.id"), format!("{alice_id}\n")).unwrap();
    let fake_csr = operator.path("fake.csr");
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params.subject_alt_names.push(rcgen::SanType::URI(format!("urn:privoke:installation:{alice_id}").try_into().unwrap()));
    std::fs::write(&fake_csr, params.serialize_request(&key).unwrap().pem().unwrap()).unwrap();
    pki(&[
        "sign",
        "--ca-dir",
        s(&operator.client_ca()),
        "--csr",
        s(&fake_csr),
        "--installation",
        &alice_id,
        "--out-dir",
        s(&operator.path("fake-bundle")),
    ]);
    let error = pki_fails(&["install-cert", "--dir", s(&alice), "--cert", s(&operator.path("fake-bundle").join("client.crt"))]);
    assert!(error.contains("does not match the private key") || error.contains("neither"), "{error}");
}

#[test]
fn commands_refuse_to_clobber_or_skip_steps() {
    let operator = Operator::new();
    assert!(pki_fails(&["init-ca", "--dir", s(&operator.client_ca()), "--name", "again"]).contains("already holds a CA key"));
    let dir = operator.path("alice");
    pki(&["enrol", "--dir", s(&dir)]);
    assert!(pki_fails(&["enrol", "--dir", s(&dir)]).contains("already enrolled"));
    assert!(pki_fails(&["renew", "--dir", s(&operator.path("never"))]).contains("not enrolled"));
    assert!(
        pki_fails(&["revoke", "--ca-dir", s(&operator.client_ca()), "--installation", "99999999-9999-4999-8999-999999999999"])
            .contains("never issued")
    );
    assert!(pki_fails(&["init-ca", "--dir", s(&operator.path("x")), "--name", "x", "--days", "0"]).contains("--days"));
}

#[cfg(unix)]
#[test]
fn private_keys_are_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let operator = Operator::new();
    let dir = enrol_and_sign(&operator, "alice");
    for path in
        [dir.join("client.key"), dir.join("reporter.key"), operator.client_ca().join("ca.key"), operator.server_dir().join("server.key")]
    {
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600, "{}", path.display());
    }
}
