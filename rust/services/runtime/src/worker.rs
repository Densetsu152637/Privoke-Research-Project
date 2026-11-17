//! The worker process around [`Service`]: the ready announcement, the sandbox self-check and the serve loop.
//!
//! The pool (W2) starts this binary and talks to it on stdin and stdout with a 4-byte little-endian length. Each pool
//! frame carries exactly one W1 frame (the 20-byte header and the protobuf payload), the same carriage as
//! `worker_shim.py` gives the Python worker, so the analysis service and the controller start this binary where they
//! start the shim. Frames leave on the original stdout (see `worker_side::claim_frame_output`) and stdout itself is
//! stderr.

use std::io::{self, Read, Write};

use privoke_ner_layer::SpacyBackend;
use privoke_worker_pool::{read_frame_sync, write_frame_sync};

use crate::frames::{self, Kind, Method};
use crate::request::Layer;
use crate::service::Service;

/// `IMPLEMENTATION` of the READY frame.
pub const IMPLEMENTATION: &str = "privoke-client-runtime-rust";
/// The warm-up prompt (`WARMUP_TEXT` of `worker_main.py`).
pub const WARMUP_TEXT: &str = "Worker warm-up: the weather is mild today.";

/// Exit codes of the worker (`worker_main.py`).
pub mod exit {
    /// The request pipe closed cleanly.
    pub const OK: i32 = 0;
    /// Bad command line.
    pub const USAGE: i32 = 2;
    /// The sandbox self-check found network capability.
    pub const SANDBOX: i32 = 3;
    /// Start-up failed.
    pub const STARTUP: i32 = 4;
    /// The stream broke.
    pub const STREAM: i32 = 5;
    /// The response pipe closed while writing.
    pub const PIPE_CLOSED: i32 = 6;
}

/// The network capabilities the process still has; an empty list means sandboxed. A self-check only: enforcement is the
/// operating-system layer's job (W2). It opens a loopback socket of each kind and closes it at once.
pub fn sandbox_self_check() -> Vec<&'static str> {
    let mut findings = Vec::new();
    if std::net::TcpListener::bind(("127.0.0.1", 0)).is_ok() {
        findings.push("tcp4");
    }
    if std::net::UdpSocket::bind(("127.0.0.1", 0)).is_ok() {
        findings.push("udp4");
    }
    if std::net::TcpListener::bind(("::1", 0)).is_ok() {
        findings.push("tcp6");
    }
    findings
}

/// The READY frame: the JSON of `worker_main.py`'s announcement, with this implementation's name.
pub fn ready_frame(loaded: &[String], sandbox_self_check: &str) -> Vec<u8> {
    let limits: serde_json::Map<String, serde_json::Value> = [
        Method::AnalyzePrompt,
        Method::DetectAnnotationPresence,
        Method::Health,
        Method::ComputeSemanticGradients,
        Method::ComputeUnderlyingModelGradients,
        Method::ComputePresenceGradients,
    ]
    .into_iter()
    .map(|method| {
        let limits = method.limits();
        (
            method.name().to_string(),
            serde_json::json!({
                "max_request_payload": limits.max_request,
                "max_response_payload": limits.max_response,
                "default_deadline_ms": limits.default_deadline_ms,
                "max_deadline_ms": limits.max_deadline_ms,
            }),
        )
    })
    .collect();
    let ready = serde_json::json!({
        "protocol_version": frames::VERSION,
        "implementation": IMPLEMENTATION,
        "pid": std::process::id(),
        "sandbox_self_check": sandbox_self_check,
        "telemetry": "disabled",
        "loaded": loaded,
        "limits": limits,
    });
    frames::encode_frame(Kind::Ready, 0, 0, ready.to_string().as_bytes())
}

/// Warms the layers up (`_warm_up`): each must run `ok` on the warm-up prompt. Returns the names of the loaded layers.
pub async fn warm_up<A: SpacyBackend>(service: &Service<A>, layers: &[Layer]) -> Result<Vec<String>, String> {
    if layers.is_empty() {
        return Ok(Vec::new());
    }
    let executions = service.pipeline().analyse(WARMUP_TEXT, layers, None).await.map_err(|error| error.to_string())?;
    let failed: Vec<String> = executions
        .iter()
        .filter(|execution| execution.status != crate::pipeline::Status::Ok)
        .map(|execution| format!("{}: {}", execution.layer.name(), execution.error.clone().unwrap_or_default()))
        .collect();
    if failed.is_empty() {
        Ok(layers.iter().map(|layer| layer.name().to_string()).collect())
    } else {
        Err(format!("Warm-up failed: {}", failed.join("; ")))
    }
}

/// Serves pool frames until the controller closes the request pipe. Returns the exit code.
pub fn serve<A: SpacyBackend>(
    service: &Service<A>,
    runtime: &tokio::runtime::Runtime,
    input: &mut impl Read,
    output: &mut impl Write,
) -> i32 {
    loop {
        let frame = match read_frame_sync(input) {
            Ok(frame) => frame,
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return exit::OK,
            Err(error) => {
                eprintln!("worker: stream broken: {error}");
                let answer = frames::encode_error(0, frames::code::MALFORMED_FRAME, "The request stream is broken.");
                let _ = write_frame_sync(output, &answer);
                return exit::STREAM;
            }
        };
        let answer = runtime.block_on(service.handle_frame(&frame));
        if write_frame_sync(output, &answer).is_err() {
            return exit::PIPE_CLOSED;
        }
    }
}
