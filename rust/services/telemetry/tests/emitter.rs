//! The stage 6 emitter-over-mutual-TLS check, against this service. The real Python emitter
//! (`extension/client-runtime/src/telemetry/event_emitter.py`) sends reports with the reporter credential to the Rust
//! service in process; the reports must be accepted and counted, and the same emitter given an installation
//! certificate as its telemetry credential must be refused.
//!
//! Needs the host Python environment (`PRIVOKE_HOST_PYTHON`, `PRIVOKE_PY_GENERATED`); the test reports itself skipped
//! and passes when they are not configured, so `cargo test --workspace` stays runnable on a host without them.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::{Env, host_python, run_emitter};
use privoke_contracts::proto::v1::GetTelemetrySummaryRequest;
use privoke_transport::{Limits, RateLimit};

#[tokio::test(flavor = "multi_thread")]
async fn the_python_emitter_delivers_over_mutual_tls_with_the_reporter_credential() {
    let Some((python, generated)) = host_python() else {
        eprintln!("SKIPPED: set PRIVOKE_HOST_PYTHON and PRIVOKE_PY_GENERATED to run the emitter check");
        return;
    };
    let env = Env::new();
    let reporter = env.reporter();
    let installation = env.installation("alice", true);
    let runtime = env.service("client-runtime", "runtime");
    let server = env.start(Limits { rate: RateLimit { per_second: 1000, burst: 1000 }, ..Limits::default() }, 100).await;
    let ca = env.path("server-ca/ca.crt");
    let target = server.public_addr.to_string();

    // A non-reporter credential in the telemetry slot: every submission is refused, nothing is stored.
    let (python_a, generated_a, target_a, ca_a, installation_a) =
        (python.clone(), generated.clone(), target.clone(), ca.clone(), installation.clone());
    let (ok, stdout, stderr) =
        tokio::task::spawn_blocking(move || run_emitter(&python_a, &generated_a, &target_a, &ca_a, &installation_a, "refused", 4))
            .await
            .unwrap();
    assert!(ok, "the installation certificate was not refused:\n{stdout}\n{stderr}");
    eprintln!("EMITTER refused with an installation certificate: {stdout}");
    let mut internal = env.client(server.internal_addr, Some(&runtime)).await;
    assert_eq!(internal.get_telemetry_summary(GetTelemetrySummaryRequest {}).await.unwrap().into_inner().sample_count, 0);

    // The reporter credential: four reports accepted and counted.
    let (python_b, generated_b, target_b, ca_b, reporter_b) =
        (python.clone(), generated.clone(), target.clone(), ca.clone(), reporter.clone());
    let (ok, stdout, stderr) =
        tokio::task::spawn_blocking(move || run_emitter(&python_b, &generated_b, &target_b, &ca_b, &reporter_b, "deliver", 4))
            .await
            .unwrap();
    assert!(ok, "the emitter did not deliver:\n{stdout}\n{stderr}");
    eprintln!("EMITTER delivered with the reporter credential: {stdout}");
    let summary = internal.get_telemetry_summary(GetTelemetrySummaryRequest {}).await.unwrap().into_inner();
    assert_eq!(summary.sample_count, 4, "four emitter reports were stored");
    // Every emitted packet was epsilon 0.5, so one stratum holds them all and each dimension's noisy counts sum to 4.
    for dimension in &summary.dimensions {
        assert_eq!(dimension.values.iter().map(|value| value.observed_noisy_count).sum::<u64>(), 4, "{}", dimension.dimension);
    }
    server.shutdown().await.unwrap();
}
