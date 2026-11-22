//! The telemetry reporter inside the controller (stage 18 wired into stage W4): the controller owns it, the worker has
//! none. The transport is scripted, so no network is involved. The worker is the stand-in W1 worker behind the real pool.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use privoke_contracts::proto::v1::{AnalyzePromptRequest, TelemetryPacket};
use privoke_supervisor::controller::{Controller, Request};
use privoke_supervisor::health::{BoxFuture, ModelHealth};
use privoke_supervisor::runtime::RuntimeController;
use privoke_supervisor::telemetry::Telemetry;
use privoke_supervisor::worker::WorkerSettings;
use privoke_telemetry_client::{
    DeliveryFailure, MECHANISM, OsRandom, PacketTransport, ReporterParts, ReporterSettings, TelemetryReporter, domain,
};
use prost::Message;
use serde_json::Value;
use time::OffsetDateTime;

const TEST_WORKER: &str = env!("CARGO_BIN_EXE_privoke-supervisor-test-worker");
const LAYER_REGEX: i32 = 2;

/// Records what the reporter would have sent.
#[derive(Clone, Default)]
struct Scripted(Arc<Mutex<Vec<TelemetryPacket>>>);

impl PacketTransport for Scripted {
    fn send(&mut self, packet: &TelemetryPacket, _timeout: Duration) -> Result<bool, DeliveryFailure> {
        self.0.lock().unwrap().push(packet.clone());
        Ok(true)
    }
}

struct NoHealth;

impl ModelHealth for NoHealth {
    fn check(&self) -> BoxFuture<(String, String)> {
        Box::pin(async { ("model-streaming-service".to_string(), "SERVING".to_string()) })
    }
}

fn reporter(ledger: PathBuf, sent: &Scripted) -> TelemetryReporter {
    let settings = ReporterSettings { event_epsilon: 0.5, daily_epsilon: 8.0, ledger_path: Some(ledger), ..ReporterSettings::default() };
    let parts = ReporterParts {
        transport: Box::new(sent.clone()),
        random: Box::new(OsRandom),
        clock: Box::new(OffsetDateTime::now_utc),
        observer: None,
    };
    TelemetryReporter::with_parts(settings, parts).unwrap()
}

async fn started_runtime() -> Arc<RuntimeController> {
    let mut settings = WorkerSettings::from_environment(&BTreeMap::new(), Path::new(".")).unwrap();
    settings.command = PathBuf::from(TEST_WORKER);
    settings.args = vec!["ok".into()];
    let runtime = Arc::new(RuntimeController::new(settings, BTreeMap::new()));
    let status = runtime.set_enabled(true, None).await.unwrap();
    assert!(status.enabled, "{}", status.message);
    runtime
}

async fn analyze(controller: &Controller, id: u64, text: &str, layers: &[i32]) -> Value {
    let request = AnalyzePromptRequest {
        text: text.into(),
        request_id: format!("canary-request-{id}"),
        layers: layers.to_vec(),
        ..Default::default()
    };
    let body = serde_json::json!({"v": 1, "id": id, "method": "AnalyzePrompt", "payload": STANDARD.encode(request.encode_to_vec())});
    let request: Request = serde_json::from_value(body).unwrap();
    serde_json::from_str(&controller.handle(request).await).unwrap()
}

/// Destructuring without `..` fails to compile if the packet ever gains a field this test has not looked at.
fn assert_only_allowed_fields(packet: &TelemetryPacket) {
    let TelemetryPacket { time_bucket, action, primary_category, risk_bucket, model_version, privacy_mechanism, privacy_epsilon } = packet;
    assert!(domain("time_bucket").unwrap().contains(&time_bucket.as_str()), "time_bucket {time_bucket}");
    assert!(domain("action").unwrap().contains(&action.as_str()), "action {action}");
    assert!(domain("primary_category").unwrap().contains(&primary_category.as_str()), "primary_category {primary_category}");
    assert!(domain("risk_bucket").unwrap().contains(&risk_bucket.as_str()), "risk_bucket {risk_bucket}");
    assert!(domain("model_version").unwrap().contains(&model_version.as_str()), "model_version {model_version}");
    assert_eq!(privacy_mechanism, MECHANISM);
    assert_eq!(*privacy_epsilon, 0.5);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn each_analysis_that_passes_the_controller_is_reported_with_allowed_fields_only() {
    let directory = tempfile::tempdir().unwrap();
    let sent = Scripted::default();
    let telemetry = Telemetry::new(reporter(directory.path().join("ledger.sqlite3"), &sent));
    let runtime = started_runtime().await;
    let controller = Controller::new(Arc::clone(&runtime), Arc::new(NoHealth)).with_telemetry(telemetry.clone());

    let secret = "canary-secret-text BLOCKME";
    for (id, text) in [(1, "hello"), (2, secret), (3, "hello again")] {
        let reply = analyze(&controller, id, text, &[LAYER_REGEX]).await;
        assert_eq!(reply["ok"], true, "{reply}");
    }
    runtime.shutdown().await;
    telemetry.close().await;

    let packets = sent.0.lock().unwrap().clone();
    assert_eq!(packets.len(), 3, "one report per analysis result");
    for packet in &packets {
        assert_only_allowed_fields(packet);
        let rendered = format!("{packet:?}");
        for forbidden in ["canary", "BLOCKME", "stand-in"] {
            assert!(!rendered.contains(forbidden), "{forbidden} reached a packet: {rendered}");
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn without_a_reporter_nothing_is_sent_and_the_reply_is_the_workers() {
    let directory = tempfile::tempdir().unwrap();
    let sent = Scripted::default();
    // A reporter exists but the controller was never given it: telemetry is off.
    let unattached = Telemetry::new(reporter(directory.path().join("ledger.sqlite3"), &sent));
    let runtime = started_runtime().await;
    let controller = Controller::new(Arc::clone(&runtime), Arc::new(NoHealth));

    let reply = analyze(&controller, 1, "hello", &[LAYER_REGEX]).await;
    assert_eq!(reply["ok"], true, "{reply}");
    runtime.shutdown().await;
    unattached.close().await;
    assert!(sent.0.lock().unwrap().is_empty(), "a controller without telemetry reports nothing");

    // And the environment switches it off: not enabled, or enabled without a target.
    let cases: [&[(&str, &str)]; 3] = [&[], &[("TELEMETRY_ENABLED", "false")], &[("TELEMETRY_ENABLED", "true")]];
    for pairs in cases {
        let environment: BTreeMap<String, String> = pairs.iter().map(|(name, value)| (name.to_string(), value.to_string())).collect();
        assert!(Telemetry::from_environment(&environment).unwrap().is_none(), "{pairs:?}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_analysis_is_not_reported() {
    let directory = tempfile::tempdir().unwrap();
    let sent = Scripted::default();
    let telemetry = Telemetry::new(reporter(directory.path().join("ledger.sqlite3"), &sent));
    let runtime = started_runtime().await;
    let controller = Controller::new(Arc::clone(&runtime), Arc::new(NoHealth)).with_telemetry(telemetry.clone());

    // The worker refuses an empty layer list: an error reply, not a decision, and so no report.
    let refused = analyze(&controller, 1, "hello", &[]).await;
    assert_eq!(refused["ok"], false, "{refused}");
    runtime.shutdown().await;
    // The runtime is stopped now: the next call is an error reply too.
    let stopped = analyze(&controller, 2, "hello", &[LAYER_REGEX]).await;
    assert_eq!(stopped["ok"], false, "{stopped}");
    telemetry.close().await;
    assert!(sent.0.lock().unwrap().is_empty());
}
