//! The controller as a browser sees it: the real `privoke-supervisor native-host` process, a stand-in W1 worker behind the
//! real pool, and native-messaging frames on stdio. The Python worker is covered in `real_worker.rs`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::time::{Duration, Instant};

use common::session::{Host, HostOptions, LAYER_NER, LAYER_REGEX, LAYER_SEMANTIC, analysis, decode, listening_sockets};
use common::{process_alive, wait_until};
use privoke_contracts::proto::v1::{RuntimeHealthResponse, SetRuntimeEnabledRequest};
use prost::Message;
use serde_json::json;

fn host(mode: &'static str) -> Host {
    Host::start(HostOptions { mode: Some(mode), ..HostOptions::default() })
}

fn started(mode: &'static str) -> (Host, u32) {
    let mut host = host(mode);
    let status = host.set_enabled(1, true);
    assert!(status.enabled, "{}", status.message);
    assert_eq!(status.status, "RUNNING");
    assert_ne!(status.process_id, 0);
    let pid = status.process_id;
    (host, pid)
}

#[test]
fn enable_analyze_and_disable_round_trip_and_the_disabled_worker_is_gone() {
    let mut host = host("ok");
    assert!(!host.status(1).enabled, "nothing runs until the extension enables it");
    let enabled = host.set_enabled(2, true);
    assert!(enabled.enabled, "{}", enabled.message);
    let worker = enabled.process_id;
    assert!(process_alive(worker));
    assert_eq!(host.status(3).process_id, worker);

    let response = analysis(&host.analyze(4, "hello there", &[LAYER_REGEX, LAYER_NER]));
    assert_eq!((response.request_id.as_str(), response.action.as_str(), response.allowed), ("r4", "ALLOW", true));
    let blocked = analysis(&host.analyze(5, "please BLOCKME", &[LAYER_REGEX]));
    assert_eq!((blocked.action.as_str(), blocked.allowed), ("BLOCK", false));

    let disabled = host.set_enabled(6, false);
    assert!(!disabled.enabled);
    assert!(wait_until(Duration::from_secs(10), || !process_alive(worker)), "disabling stops the worker");
    let refused = host.analyze(7, "hello", &[LAYER_REGEX]);
    assert_eq!((refused["ok"].clone(), refused["code"].clone()), (json!(false), json!("FAILED_PRECONDITION")));
}

#[test]
fn analysis_before_the_runtime_is_enabled_is_an_error_not_a_decision() {
    let mut host = host("ok");
    let reply = host.analyze(1, "hello", &[LAYER_REGEX]);
    assert_eq!(reply["ok"], false);
    assert_eq!(reply["code"], "FAILED_PRECONDITION");
    assert!(reply.get("payload").is_none());
}

#[test]
fn the_layer_selection_is_passed_through_exactly_and_an_empty_one_is_refused() {
    let (mut host, _) = started("ok");
    let semantic_only = analysis(&host.analyze(2, "hello", &[LAYER_SEMANTIC]));
    assert_eq!(semantic_only.layers.iter().map(|layer| layer.layer).collect::<Vec<_>>(), vec![LAYER_SEMANTIC]);
    let all = analysis(&host.analyze(3, "hello", &[LAYER_REGEX, LAYER_NER, LAYER_SEMANTIC]));
    assert_eq!(all.layers.iter().map(|layer| layer.layer).collect::<Vec<_>>(), vec![LAYER_REGEX, LAYER_NER, LAYER_SEMANTIC]);

    let empty = host.analyze(4, "hello", &[]);
    assert_eq!((empty["ok"].clone(), empty["code"].clone()), (json!(false), json!("INVALID_ARGUMENT")));
    assert!(empty["message"].as_str().unwrap().contains("INVALID_LAYERS"), "{empty}");
}

#[test]
fn malformed_requests_get_an_error_reply_with_their_id_or_end_the_session() {
    let (mut host, _) = started("ok");
    host.send(&json!({"v": 1, "id": 10, "method": "NoSuchMethod"}));
    let unknown = host.recv(Duration::from_secs(10)).unwrap();
    assert_eq!((unknown["id"].clone(), unknown["code"].clone()), (json!(10), json!("UNIMPLEMENTED")));

    host.send(&json!({"v": 2, "id": 11, "method": "Status"}));
    assert_eq!(host.recv(Duration::from_secs(10)).unwrap()["code"], "INVALID_ARGUMENT");

    host.send(&json!({"v": 1, "id": 12, "method": "AnalyzePrompt", "payload": "***not base64***"}));
    assert_eq!(host.recv(Duration::from_secs(10)).unwrap()["code"], "INVALID_ARGUMENT");

    host.send(&json!({"v": 1, "id": 13, "method": "AnalyzePrompt"}));
    assert_eq!(host.recv(Duration::from_secs(10)).unwrap()["code"], "INVALID_ARGUMENT");

    host.send(&json!({"v": 1, "id": 14, "method": 7}));
    let wrong_type = host.recv(Duration::from_secs(10)).unwrap();
    assert_eq!((wrong_type["id"].clone(), wrong_type["ok"].clone()), (json!(14), json!(false)));

    // A request with no id cannot be answered: the session ends and the browser fails everything pending.
    host.send(&json!({"v": 1, "method": "Status"}));
    assert!(host.recv(Duration::from_secs(10)).is_none());
    assert!(host.wait_exit(Duration::from_secs(10)).is_some_and(|status| !status.success()));
}

#[test]
fn invalid_json_and_oversized_frames_end_the_session_without_a_reply() {
    let mut host = host("ok");
    host.send_raw(b"{not json");
    assert!(host.recv(Duration::from_secs(10)).is_none());
    assert!(host.wait_exit(Duration::from_secs(10)).is_some_and(|status| !status.success()));

    let mut host = self::host("ok");
    host.send_raw(&vec![b' '; 1024 * 1024 + 1]);
    assert!(host.recv(Duration::from_secs(10)).is_none());
    assert!(host.wait_exit(Duration::from_secs(10)).is_some_and(|status| !status.success()));
}

#[test]
fn several_requests_in_flight_are_each_answered_with_their_own_id() {
    let (mut host, _) = started("ok");
    for id in 100..108 {
        host.analyze_request(id, &format!("text {id}"), &[LAYER_REGEX]);
    }
    let mut answered = Vec::new();
    for _ in 0..8 {
        let reply = host.recv(Duration::from_secs(30)).unwrap();
        let id = reply["id"].as_u64().unwrap();
        assert_eq!(analysis(&reply).request_id, format!("r{id}"));
        answered.push(id);
    }
    answered.sort_unstable();
    assert_eq!(answered, (100..108).collect::<Vec<_>>());
}

#[test]
fn closing_the_port_stops_the_worker_and_the_controller() {
    let (mut host, worker) = started("ok");
    assert!(process_alive(worker));
    host.close_input();
    let exit = host.wait_exit(Duration::from_secs(15)).expect("the controller exits when the browser closes the port");
    assert!(exit.success(), "{exit:?}");
    assert!(wait_until(Duration::from_secs(10), || !process_alive(worker)), "no orphaned worker");
}

#[test]
fn killing_the_controller_kills_the_worker() {
    let (mut host, worker) = started("ok");
    assert!(process_alive(worker));
    // No cleanup by the controller, as a crash or `taskkill /F` would leave it.
    host.kill();
    assert!(wait_until(Duration::from_secs(10), || !process_alive(worker)), "the sandbox ties the worker's life to the controller's");
}

#[test]
fn a_worker_that_dies_mid_request_is_an_unavailable_error_and_is_not_retried() {
    let (mut host, _) = started("crash");
    let started_at = Instant::now();
    let reply = host.analyze(2, "hello", &[LAYER_REGEX]);
    assert_eq!((reply["ok"].clone(), reply["code"].clone()), (json!(false), json!("UNAVAILABLE")), "{reply}");
    assert!(started_at.elapsed() < Duration::from_secs(10));
    // The pool restarts it; until it is back the status says so and analysis stays an error.
    let after = host.analyze(3, "hello", &[LAYER_REGEX]);
    assert_eq!(after["ok"], false);
}

#[test]
fn a_hung_worker_ends_at_the_deadline_with_deadline_exceeded() {
    let mut host = Host::start(HostOptions {
        mode: Some("hang"),
        env: vec![("PRIVOKE_RUNTIME_REQUEST_TIMEOUT_SECONDS", "1.5".into())],
        ..HostOptions::default()
    });
    assert!(host.set_enabled(1, true).enabled);
    let started_at = Instant::now();
    let reply = host.analyze(2, "hello", &[LAYER_REGEX]);
    assert_eq!((reply["ok"].clone(), reply["code"].clone()), (json!(false), json!("DEADLINE_EXCEEDED")), "{reply}");
    let elapsed = started_at.elapsed();
    assert!(elapsed >= Duration::from_millis(1400) && elapsed < Duration::from_secs(10), "{elapsed:?}");
}

#[test]
fn a_worker_that_refuses_to_start_leaves_the_runtime_disabled_with_the_reason() {
    let mut host = host("startup-fail");
    let status = host.set_enabled(1, true);
    assert!(!status.enabled);
    assert!(status.message.contains("STARTUP_FAILED"), "{}", status.message);
    assert_eq!(host.analyze(2, "hello", &[LAYER_REGEX])["code"], "FAILED_PRECONDITION");
}

#[test]
fn a_worker_that_never_announces_itself_times_out_the_start() {
    let mut host = Host::start(HostOptions {
        mode: Some("exit-early"),
        env: vec![("PRIVOKE_RUNTIME_START_TIMEOUT_SECONDS", "2".into())],
        ..HostOptions::default()
    });
    let started_at = Instant::now();
    let status = host.set_enabled(1, true);
    assert!(!status.enabled);
    assert!(status.message.contains("Client runtime failed to start"), "{}", status.message);
    assert!(started_at.elapsed() < Duration::from_secs(20));
}

#[test]
fn a_reply_too_large_for_native_messaging_is_resource_exhausted() {
    let (mut host, _) = started("big");
    let reply = host.analyze(2, "hello", &[LAYER_REGEX]);
    assert_eq!((reply["ok"].clone(), reply["code"].clone()), (json!(false), json!("RESOURCE_EXHAUSTED")), "{reply}");
}

#[test]
fn an_oversized_analysis_request_is_refused_before_the_worker_sees_it() {
    let (mut host, _) = started("ok");
    let reply = host.analyze(2, &"x".repeat(300_000), &[LAYER_REGEX]);
    assert_eq!((reply["ok"].clone(), reply["code"].clone()), (json!(false), json!("RESOURCE_EXHAUSTED")), "{reply}");
}

#[test]
fn status_and_model_streaming_health_answer_with_the_runtime_messages() {
    let mut host = host("ok");
    let health = host.call(1, "ModelStreamingHealth", Some(&[]));
    let health: RuntimeHealthResponse = decode(&health);
    assert_eq!((health.service.as_str(), health.status.as_str()), ("model-streaming-service", "NOT_SERVING"), "no target is configured");
    let switch = SetRuntimeEnabledRequest { enabled: true, use_local_stack: Some(true) }.encode_to_vec();
    let reply = host.call(2, "SetRuntimeEnabled", Some(&switch));
    assert_eq!(reply["ok"], true);
    assert!(decode::<privoke_contracts::proto::v1::RuntimeControlStatus>(&reply).enabled);
}

#[test]
fn the_controller_and_its_worker_listen_on_no_port() {
    let (host, worker) = started("ok");
    assert!(listening_sockets(host.child.id()).is_empty(), "the controller listens on nothing");
    assert!(listening_sockets(worker).is_empty(), "the worker listens on nothing");
}
