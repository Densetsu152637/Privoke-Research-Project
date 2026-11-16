//! R10 against the built container, on loopback, plus the Python emitter against the container.
//!
//! Set `TELEMETRY_CONTAINER_IMAGE` to an image built from `rust/services/telemetry/Dockerfile` to run it; otherwise the
//! test reports itself skipped and passes. Docker only hosts the container: every client runs on the host. The
//! container gets a distinct name, two ephemeral loopback ports and a fresh volume, all removed afterwards. The
//! certificates are issued by this test; only the server certificate and key, the client CA certificate, the CRL and
//! the registry are mounted (never a CA key).
//!
//! R10: a request with no client certificate is rejected, and so is a request with an installation (non-reporter)
//! certificate.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::net::TcpListener;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use common::{Env, code, host_python, packet, run_emitter, valid_packet};
use privoke_contracts::proto::v1::telemetry_service_client::TelemetryServiceClient;
use privoke_contracts::proto::v1::{GetTelemetrySummaryRequest, TelemetryHealthRequest};
use tonic::Code;

const NAME: &str = "privoke-s04-telemetry-r10";
const VOLUME: &str = "privoke-s04-telemetry-r10-data";

fn docker(arguments: &[&str]) -> std::process::Output {
    Command::new("docker").args(arguments).output().expect("run docker")
}

fn text(output: &std::process::Output) -> String {
    format!("{}{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr)).trim().to_string()
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

/// Removes the container and the volume however the test ends.
struct Cleanup;

impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = docker(&["rm", "-f", NAME]);
        let _ = docker(&["volume", "rm", "-f", VOLUME]);
    }
}

fn copy(from: &Path, to: &Path) {
    std::fs::create_dir_all(to.parent().unwrap()).unwrap();
    std::fs::copy(from, to).unwrap_or_else(|error| panic!("copy {}: {error}", from.display()));
}

#[tokio::test(flavor = "multi_thread")]
async fn r10_against_the_container_and_the_python_emitter() {
    let Some(image) = std::env::var("TELEMETRY_CONTAINER_IMAGE").ok().filter(|value| !value.is_empty()) else {
        eprintln!("SKIPPED: set TELEMETRY_CONTAINER_IMAGE to run the container checks");
        return;
    };
    let env = Env::new();
    let reporter = env.reporter();
    let installation = env.installation("alice", true);
    let stranger = env.installation("mallory", false);
    let probe = env.service("healthcheck", "runtime");
    let runtime = env.service("client-runtime", "runtime");

    // Only what the container needs. The registry is final: nothing below edits it.
    let mount = env.path("mount");
    copy(&env.path("server.crt"), &mount.join("server.crt"));
    copy(&env.path("server.key"), &mount.join("server.key"));
    copy(&env.path("client-ca/ca.crt"), &mount.join("client-ca.crt"));
    copy(&env.path("server-ca/ca.crt"), &mount.join("server-ca.crt"));
    copy(&env.crl(), &mount.join("crl.pem"));
    copy(&env.registry(), &mount.join("registry.toml"));
    copy(&probe.cert, &mount.join("probe.crt"));
    copy(&probe.key, &mount.join("probe.key"));

    let _ = docker(&["rm", "-f", NAME]);
    let _ = docker(&["volume", "rm", "-f", VOLUME]);
    let _cleanup = Cleanup;
    let (public_port, internal_port) = (free_port(), free_port());
    let mount_argument = format!("{}:/pki:ro", mount.display());
    let run = docker(&[
        "run",
        "-d",
        "--name",
        NAME,
        "-p",
        &format!("127.0.0.1:{public_port}:58443"),
        "-p",
        &format!("127.0.0.1:{internal_port}:50055"),
        "-v",
        &mount_argument,
        "-v",
        &format!("{VOLUME}:/data"),
        &image,
        "--cert",
        "/pki/server.crt",
        "--key",
        "/pki/server.key",
        "--client-ca",
        "/pki/client-ca.crt",
        "--crl",
        "/pki/crl.pem",
        "--registry",
        "/pki/registry.toml",
    ]);
    assert!(run.status.success(), "docker run failed: {}", text(&run));

    let public: std::net::SocketAddr = format!("127.0.0.1:{public_port}").parse().unwrap();
    let internal: std::net::SocketAddr = format!("127.0.0.1:{internal_port}").parse().unwrap();
    let mut serving = false;
    for _ in 0..100 {
        let state = text(&docker(&["inspect", "-f", "{{.State.Running}}", NAME]));
        assert_eq!(state, "true", "the container stopped:\n{}", text(&docker(&["logs", NAME])));
        if let Ok(channel) = privoke_transport::client::connect(&internal.to_string(), &env.client_config(Some(&runtime))).await
            && TelemetryServiceClient::new(channel).health(TelemetryHealthRequest {}).await.is_ok()
        {
            serving = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(serving, "the container never answered Health:\n{}", text(&docker(&["logs", NAME])));

    // -- R10 -------------------------------------------------------------------------------------------------
    // 1. No client certificate: the TLS layer or the first call refuses; no application answer.
    let channel = privoke_transport::client::connect(&public.to_string(), &env.client_config(None)).await;
    let mut no_certificate = "refused at the handshake".to_string();
    if let Ok(channel) = channel {
        let result = TelemetryServiceClient::new(channel).record_telemetry(valid_packet()).await;
        assert!(result.is_err(), "R10: a request without a certificate was answered");
        no_certificate = format!("refused on first use ({})", result.unwrap_err().code());
    }
    // 2. An installation (non-reporter) certificate, registered and unregistered, on both listeners.
    let mut outcomes = Vec::new();
    for creds in [&installation, &stranger] {
        let mut on_public = TelemetryServiceClient::new(
            privoke_transport::client::connect(&public.to_string(), &env.client_config(Some(creds))).await.unwrap(),
        );
        let record = code(on_public.record_telemetry(valid_packet()).await);
        assert_eq!(record, Code::PermissionDenied, "R10: installation certificate on RecordTelemetry");
        let mut on_internal = TelemetryServiceClient::new(
            privoke_transport::client::connect(&internal.to_string(), &env.client_config(Some(creds))).await.unwrap(),
        );
        let summary = code(on_internal.get_telemetry_summary(GetTelemetrySummaryRequest {}).await);
        assert_eq!(summary, Code::PermissionDenied, "R10: installation certificate on GetTelemetrySummary");
        outcomes.push(format!(
            "{} record={record:?} summary={summary:?}",
            if creds.id == installation.id { "registered" } else { "unregistered" }
        ));
    }
    // 3. Positive control and the rest of the policy.
    let mut client = TelemetryServiceClient::new(
        privoke_transport::client::connect(&public.to_string(), &env.client_config(Some(&reporter))).await.unwrap(),
    );
    assert!(client.record_telemetry(valid_packet()).await.unwrap().into_inner().accepted, "the reporter credential must be accepted");
    assert_eq!(code(client.record_telemetry(packet(|p| p.privacy_mechanism = "none".into())).await), Code::InvalidArgument);
    assert_eq!(code(client.get_telemetry_summary(GetTelemetrySummaryRequest {}).await), Code::Unimplemented);
    let mut service = TelemetryServiceClient::new(
        privoke_transport::client::connect(&internal.to_string(), &env.client_config(Some(&runtime))).await.unwrap(),
    );
    assert_eq!(service.get_telemetry_summary(GetTelemetrySummaryRequest {}).await.unwrap().into_inner().sample_count, 1);
    eprintln!("R10 container: no certificate: {no_certificate}; installation certificates: {}", outcomes.join("; "));

    // The container's own healthcheck subcommand, run inside it with a mounted service identity.
    let health = docker(&[
        "exec",
        NAME,
        "/telemetry-service",
        "healthcheck",
        "--address",
        "127.0.0.1:50055",
        "--server-ca",
        "/pki/server-ca.crt",
        "--client-cert",
        "/pki/probe.crt",
        "--client-key",
        "/pki/probe.key",
    ]);
    assert!(health.status.success(), "healthcheck inside the container failed: {}", text(&health));

    // -- The Python emitter against the container --------------------------------------------------------------
    if let Some((python, generated)) = host_python() {
        let ca = env.path("server-ca/ca.crt");
        let (ok, stdout, stderr) = run_emitter(&python, &generated, &public.to_string(), &ca, &installation, "refused", 4);
        assert!(ok, "the installation certificate was not refused by the container:\n{stdout}\n{stderr}");
        eprintln!("EMITTER container, installation certificate: {stdout}");
        let (ok, stdout, stderr) = run_emitter(&python, &generated, &public.to_string(), &ca, &reporter, "deliver", 4);
        assert!(ok, "the emitter did not deliver to the container:\n{stdout}\n{stderr}");
        eprintln!("EMITTER container, reporter credential: {stdout}");
        let summary = service.get_telemetry_summary(GetTelemetrySummaryRequest {}).await.unwrap().into_inner();
        assert_eq!(summary.sample_count, 5, "one control report plus four emitter reports");
    } else {
        eprintln!("SKIPPED the emitter part: set PRIVOKE_HOST_PYTHON and PRIVOKE_PY_GENERATED");
    }

    // The container's log names no peer.
    let logs = text(&docker(&["logs", NAME]));
    for needle in ["urn:privoke", "reporter", installation.id.as_str(), "alice", "127.0.0.1", "172."] {
        assert!(!logs.contains(needle), "the container log names {needle:?}:\n{logs}");
    }
    assert!(logs.contains("telemetry-service listening"), "{logs}");
    eprintln!("container log ({} bytes) holds no peer identity or address", logs.len());
}
