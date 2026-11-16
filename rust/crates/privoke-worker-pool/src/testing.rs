//! A JSON envelope protocol for the pool's own tests and test binaries (feature `test-worker`).
//!
//! The ready frame is `{"type":"ready",...}` or `{"type":"fatal","reason":"..."}`. A request is
//! `{"id":N,"op":"...",...}` and its answer is `{"id":N,"ok":true,"result":...}` or `{"id":N,"ok":false,"error":"..."}`.

use serde_json::Value;

use crate::{Hello, Protocol, Reply};

/// The test protocol.
#[derive(Clone, Copy, Debug, Default)]
pub struct JsonProtocol;

impl Protocol for JsonProtocol {
    type Info = Value;

    fn parse_hello(&self, frame: &[u8]) -> Result<Hello<Value>, String> {
        let value: Value = serde_json::from_slice(frame).map_err(|e| format!("malformed ready frame: {e}"))?;
        match value["type"].as_str() {
            Some("ready") => Ok(Hello::Ready(value)),
            Some("fatal") => Ok(Hello::Fatal(value["reason"].as_str().unwrap_or("no reason given").to_string())),
            other => Err(format!("unexpected first frame of type {other:?}")),
        }
    }

    fn parse_reply(&self, frame: &[u8], request_id: u64) -> Reply {
        let value: Value = match serde_json::from_slice(frame) {
            Ok(value) => value,
            Err(e) => return Reply::Violation(format!("malformed response frame: {e}")),
        };
        if value["id"].as_u64() != Some(request_id) {
            return Reply::Violation(format!("response id {} does not match request id {request_id}", value["id"]));
        }
        if value["ok"].as_bool() != Some(true) {
            return Reply::Reported(value["error"].as_str().unwrap_or("unspecified error").to_string());
        }
        Reply::Answer(value["result"].to_string())
    }
}
