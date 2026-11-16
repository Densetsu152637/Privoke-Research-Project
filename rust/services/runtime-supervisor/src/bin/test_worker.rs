//! A stand-in for the W1 worker, speaking the pool's framing with W1 frames inside. Built only with the `test-helpers`
//! feature. It exists so the controller's session, lifecycle and failure behaviour can be tested without Python.
//!
//! Modes (the first argument): `ok` (default), `startup-fail`, `exit-early`, `hang`, `crash` (dies on the first
//! analysis), `big` (answers with more than a native-messaging message may hold) and `slow` (answers after one second).
//!
//! An `AnalyzePrompt` with no layers is refused with `INVALID_LAYERS`, as the real worker does. Otherwise the answer
//! echoes the request id and one executed layer per requested layer; the text `BLOCKME` is blocked.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::{self, Write};
use std::time::Duration;

use privoke_contracts::proto::v1::{AnalyzePromptRequest, AnalyzePromptResponse, RuntimeHealthResponse, RuntimeLayerExecution};
use privoke_supervisor::worker::{Kind, Method, decode, encode_frame};
use privoke_worker_pool::{read_frame_sync, write_frame_sync};
use prost::Message;

fn send(out: &mut impl Write, kind: Kind, method: u8, id: u64, payload: &[u8]) {
    write_frame_sync(out, &encode_frame(kind, method, id, payload)).expect("write");
}

fn main() {
    let mode = std::env::args().nth(1).unwrap_or_else(|| "ok".into());
    let mut out = io::stdout().lock();
    let mut input = io::stdin().lock();
    match mode.as_str() {
        "exit-early" => std::process::exit(7),
        "startup-fail" => {
            send(&mut out, Kind::Error, 0, 0, br#"{"code": "STARTUP_FAILED", "message": "the stand-in refuses to start"}"#);
            std::process::exit(4);
        }
        _ => send(&mut out, Kind::Ready, 0, 0, br#"{"implementation": "stand-in", "protocol_version": 1}"#),
    }
    while let Ok(frame) = read_frame_sync(&mut input) {
        let Ok((header, payload)) = decode(&frame) else { std::process::exit(5) };
        let id = header.request_id;
        match mode.as_str() {
            "hang" => std::thread::sleep(Duration::from_secs(3600)),
            "crash" => std::process::exit(1),
            "slow" => std::thread::sleep(Duration::from_secs(1)),
            _ => {}
        }
        if header.method == Method::Health as u8 {
            let body = RuntimeHealthResponse { service: "stand-in".into(), status: "SERVING".into() };
            send(&mut out, Kind::Response, header.method, id, &body.encode_to_vec());
            continue;
        }
        let Ok(request) = AnalyzePromptRequest::decode(payload) else {
            send(&mut out, Kind::Error, header.method, id, br#"{"code": "INVALID_PAYLOAD", "message": "not an AnalyzePromptRequest"}"#);
            continue;
        };
        if request.layers.is_empty() {
            send(&mut out, Kind::Error, header.method, id, br#"{"code": "INVALID_LAYERS", "message": "an empty layer list is refused"}"#);
            continue;
        }
        let blocked = request.text.contains("BLOCKME");
        let mut response = AnalyzePromptResponse {
            request_id: request.request_id.clone(),
            action: if blocked { "BLOCK" } else { "ALLOW" }.into(),
            allowed: !blocked,
            reason: "stand-in".into(),
            elapsed_ms: 1.0,
            layers: request
                .layers
                .iter()
                .map(|layer| RuntimeLayerExecution { layer: *layer, status: "COMPLETED".into(), ..Default::default() })
                .collect(),
            ..Default::default()
        };
        if mode == "big" {
            response.masked_text = "x".repeat(1_300_000);
        }
        send(&mut out, Kind::Response, header.method, id, &response.encode_to_vec());
    }
}
