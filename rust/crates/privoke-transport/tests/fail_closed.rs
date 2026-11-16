//! Fail-closed startup: a cloud binary that lacks any of `--cert`, `--key`, `--client-ca`, `--crl` or `--registry`
//! exits non-zero before it binds, and no feature or flag disables authentication.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

use common::{ALICE, BOB, LeafSpec, Pki};
use privoke_transport::client;
use privoke_transport::startup::{CloudTlsArgs, REQUIRED_FLAGS};
use tonic_health::pb::HealthCheckRequest;
use tonic_health::pb::health_client::HealthClient;

const PROBE: &str = env!("CARGO_BIN_EXE_privoke-listener-probe");

struct Files {
    pki: Pki,
    registry: PathBuf,
}

fn files() -> Files {
    let pki = Pki::new();
    let registry = pki.write("installations.toml", "# registry contents belong to stage 2\n");
    Files { pki, registry }
}

fn flags(files: &Files) -> Vec<(&'static str, PathBuf)> {
    vec![
        ("--cert", files.pki.path("server.pem")),
        ("--key", files.pki.path("server.key")),
        ("--client-ca", files.pki.path("client-ca.pem")),
        ("--crl", files.pki.path("crl.pem")),
        ("--registry", files.registry.clone()),
    ]
}

fn args_without(files: &Files, omitted: Option<&str>) -> CloudTlsArgs {
    let mut args = CloudTlsArgs::default();
    for (flag, path) in flags(files) {
        if Some(flag) == omitted {
            continue;
        }
        match flag {
            "--cert" => args.cert = Some(path),
            "--key" => args.key = Some(path),
            "--client-ca" => args.client_ca = Some(path),
            "--crl" => args.crl = Some(path),
            _ => args.registry = Some(path),
        }
    }
    args
}

#[test]
fn fail_closed_library_refuses_each_missing_input() {
    let files = files();
    args_without(&files, None).into_config().expect("all five inputs make a valid configuration");
    for flag in REQUIRED_FLAGS {
        let error = args_without(&files, Some(flag)).into_config().unwrap_err().to_string();
        assert!(error.contains(&format!("missing required {flag}")), "{flag}: {error}");
    }
}

#[test]
fn fail_closed_library_refuses_unusable_inputs() {
    let files = files();
    for (flag, name) in [("--cert", "server.pem"), ("--key", "server.key"), ("--client-ca", "client-ca.pem"), ("--crl", "crl.pem")] {
        let path = files.pki.path(name);
        let original = std::fs::read(&path).unwrap();

        std::fs::write(&path, b"").unwrap();
        let error = args_without(&files, None).into_config().unwrap_err().to_string();
        assert!(error.contains(flag), "empty {flag}: {error}");

        std::fs::write(&path, b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n").unwrap();
        assert!(args_without(&files, None).into_config().is_err(), "garbage {flag} was accepted");

        std::fs::remove_file(&path).unwrap();
        assert!(args_without(&files, None).into_config().is_err(), "missing file for {flag} was accepted");
        std::fs::write(&path, original).unwrap();
    }
    std::fs::remove_file(&files.registry).unwrap();
    assert!(args_without(&files, None).into_config().unwrap_err().to_string().contains("--registry"));
}

fn probe(files: &Files, omitted: Option<&str>, extra: &[&str]) -> std::process::Output {
    let mut command = Command::new(PROBE);
    for (flag, path) in flags(files) {
        if Some(flag) != omitted {
            command.arg(flag).arg(path);
        }
    }
    command.args(extra).stdin(Stdio::null()).output().unwrap()
}

#[test]
fn fail_closed_binary_exits_non_zero_before_binding() {
    let files = files();
    let bare = Command::new(PROBE).stdin(Stdio::null()).output().unwrap();
    assert!(!bare.status.success(), "started with no arguments");
    for flag in REQUIRED_FLAGS {
        let output = probe(&files, Some(flag), &[]);
        assert!(!output.status.success(), "started without {flag}");
        assert_eq!(output.status.code(), Some(1), "{flag}");
        assert!(String::from_utf8_lossy(&output.stderr).contains(flag), "{flag}: {}", String::from_utf8_lossy(&output.stderr));
        assert!(!String::from_utf8_lossy(&output.stdout).contains("listening"), "bound a socket without {flag}");
    }
}

#[test]
fn fail_closed_binary_has_no_plaintext_or_insecure_switch() {
    let files = files();
    for flag in ["--insecure", "--plaintext", "--no-tls", "--disable-auth", "--allow-anonymous"] {
        let output = probe(&files, None, &[flag]);
        assert!(!output.status.success(), "{flag} was accepted");
        assert_eq!(output.status.code(), Some(2), "{flag} must be an unknown argument");
        assert!(!String::from_utf8_lossy(&output.stdout).contains("listening"));
    }
}

#[tokio::test]
async fn fail_closed_binary_serves_only_authenticated_registered_clients() {
    let files = files();
    let mut command = Command::new(PROBE);
    for (flag, path) in flags(&files) {
        command.arg(flag).arg(path);
    }
    struct Kill(std::process::Child);
    impl Drop for Kill {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let child = command
        .args(["--admit-installation", ALICE, "--reload-poll-ms", "100"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut child = Kill(child);
    let mut line = String::new();
    BufReader::new(child.0.stdout.take().unwrap()).read_line(&mut line).unwrap();
    let address = line.trim().strip_prefix("listening ").unwrap_or_else(|| panic!("unexpected probe output {line:?}")).to_string();

    let outcome = async {
        let alice = files.pki.client_ca.leaf(LeafSpec::installation(ALICE));
        let bob = files.pki.client_ca.leaf(LeafSpec::installation(BOB));
        let call = |name: &'static str, leaf: Option<&common::Leaf>| {
            let config = files.pki.client_config(name, leaf);
            let address = address.clone();
            async move {
                let channel = client::connect(&address, &config).await.map_err(|error| tonic::Status::unavailable(error.to_string()))?;
                HealthClient::new(channel).check(HealthCheckRequest { service: String::new() }).await.map(|_| ())
            }
        };
        call("alice", Some(&alice)).await.expect("registered installation is served");
        assert_eq!(call("bob", Some(&bob)).await.unwrap_err().code(), tonic::Code::PermissionDenied);
        assert!(call("anonymous", None).await.is_err());
    };
    let result = tokio::time::timeout(Duration::from_secs(20), outcome).await;
    result.expect("probe test timed out");
}

fn tree(extra: &[&str]) -> String {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../Cargo.toml");
    let output = Command::new(env!("CARGO"))
        .args(["tree", "--locked", "--offline", "-p", "privoke-transport", "-e", "features"])
        .args(extra)
        .arg("--manifest-path")
        .arg(manifest)
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    String::from_utf8(output.stdout).unwrap()
}

#[test]
fn fail_closed_release_dependency_tree_has_no_plaintext_feature() {
    // A cloud build resolves the crate without dev-dependencies and without the feature.
    assert!(!tree(&["-e", "no-dev"]).contains("workstation-loopback"), "the loopback feature is enabled in the non-dev tree");
    // Control: the dev-dependency edge of this test suite does enable it, so the check can detect the feature.
    assert!(tree(&[]).contains("workstation-loopback"));
}
