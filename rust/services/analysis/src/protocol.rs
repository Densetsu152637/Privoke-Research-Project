//! The pool [`Protocol`] for the W1 worker.
//!
//! The pool hands a reply back as text, and a runtime response is binary protobuf, so an answer travels as standard
//! base64. A worker error becomes `Reported("<CODE>\u{1f}<message>")`, which [`split_reported`] undoes.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use privoke_worker_pool::{Hello, Protocol, Reply};

use crate::frames::{self, Kind};

/// Separates the worker's error code from its message inside a `Reported` string.
const SEPARATOR: char = '\u{1f}';

/// What the worker announced in its READY frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerInfo {
    /// The READY frame's JSON payload (`protocol_version`, `pid`, `sandbox_self_check`, `telemetry`, `loaded`, ...).
    pub ready_json: String,
}

/// The W1 protocol over the pool's frames.
#[derive(Debug, Clone, Copy, Default)]
pub struct WorkerProtocol;

/// The error frame's JSON `{"code": ..., "message": ...}`, read without a JSON dependency: the worker writes it with
/// sorted keys and ASCII escapes, and a value we cannot read still reports its code.
fn error_fields(payload: &[u8]) -> (String, String) {
    let text = String::from_utf8_lossy(payload);
    let field = |name: &str| -> String {
        let marker = format!("\"{name}\": \"");
        let Some(start) = text.find(&marker).map(|index| index + marker.len()) else { return String::new() };
        let mut out = String::new();
        let mut chars = text[start..].chars();
        while let Some(character) = chars.next() {
            match character {
                '"' => break,
                '\\' => match chars.next() {
                    Some('n') => out.push('\n'),
                    Some('t') => out.push('\t'),
                    Some('u') => {
                        let digits: String = chars.by_ref().take(4).collect();
                        out.push(u32::from_str_radix(&digits, 16).ok().and_then(char::from_u32).unwrap_or('?'));
                    }
                    Some(other) => out.push(other),
                    None => break,
                },
                other => out.push(other),
            }
        }
        out
    };
    (field("code"), field("message"))
}

/// Splits a `Reported` string back into the worker's code and message.
pub fn split_reported(text: &str) -> (&str, &str) {
    text.split_once(SEPARATOR).unwrap_or(("INTERNAL", text))
}

impl Protocol for WorkerProtocol {
    type Info = WorkerInfo;

    fn parse_hello(&self, frame: &[u8]) -> Result<Hello<WorkerInfo>, String> {
        let (header, payload) = frames::decode(frame)?;
        match header.kind {
            kind if kind == Kind::Ready as u8 => Ok(Hello::Ready(WorkerInfo { ready_json: String::from_utf8_lossy(payload).into_owned() })),
            // SANDBOX_VIOLATION and STARTUP_FAILED end the worker with a non-restartable exit code.
            kind if kind == Kind::Error as u8 => {
                let (code, message) = error_fields(payload);
                Ok(Hello::Fatal(format!("{code}: {message}")))
            }
            other => Err(format!("unexpected first frame of kind {other}")),
        }
    }

    fn parse_reply(&self, frame: &[u8], request_id: u64) -> Reply {
        let (header, payload) = match frames::decode(frame) {
            Ok(decoded) => decoded,
            Err(reason) => return Reply::Violation(reason),
        };
        if header.request_id != request_id {
            return Reply::Violation(format!("answer for request {} while serving {request_id}", header.request_id));
        }
        match header.kind {
            kind if kind == Kind::Response as u8 => Reply::Answer(STANDARD.encode(payload)),
            kind if kind == Kind::Error as u8 => {
                let (code, message) = error_fields(payload);
                Reply::Reported(format!("{code}{SEPARATOR}{message}"))
            }
            other => Reply::Violation(format!("unexpected frame of kind {other} in answer to request {request_id}")),
        }
    }
}

/// Decodes the text an answer was carried in.
pub fn decode_answer(text: &str) -> Result<Vec<u8>, String> {
    STANDARD.decode(text).map_err(|error| format!("the worker's answer is not valid base64: {error}"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn frame(kind: u8, request_id: u64, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        out.extend_from_slice(&[1, kind, 1, 0]);
        out.extend_from_slice(&request_id.to_be_bytes());
        out.extend_from_slice(&0u32.to_be_bytes());
        out.extend_from_slice(payload);
        out
    }

    #[test]
    fn answers_carry_the_exact_bytes() {
        let bytes: Vec<u8> = (0..=255).collect();
        let Reply::Answer(text) = WorkerProtocol.parse_reply(&frame(2, 7, &bytes), 7) else { panic!("not an answer") };
        assert_eq!(decode_answer(&text).unwrap(), bytes);
    }

    #[test]
    fn worker_errors_keep_their_code_and_message() {
        let payload = br#"{"code": "INVALID_LAYERS", "message": "An explicit \"non-empty\" layer\nselection is required"}"#;
        let Reply::Reported(text) = WorkerProtocol.parse_reply(&frame(3, 4, payload), 4) else { panic!("not reported") };
        let (code, message) = split_reported(&text);
        assert_eq!(code, "INVALID_LAYERS");
        assert_eq!(message, "An explicit \"non-empty\" layer\nselection is required");
    }

    #[test]
    fn a_mismatched_id_or_kind_is_a_violation() {
        assert!(matches!(WorkerProtocol.parse_reply(&frame(2, 8, b""), 7), Reply::Violation(_)));
        assert!(matches!(WorkerProtocol.parse_reply(&frame(4, 7, b""), 7), Reply::Violation(_)));
        assert!(matches!(WorkerProtocol.parse_reply(b"short", 7), Reply::Violation(_)));
    }

    #[test]
    fn ready_and_startup_errors_are_read_as_hello() {
        assert!(matches!(WorkerProtocol.parse_hello(&frame(4, 0, b"{}")), Ok(Hello::Ready(_))));
        let refused = frame(3, 0, br#"{"code": "SANDBOX_VIOLATION", "message": "sockets"}"#);
        let Ok(Hello::Fatal(reason)) = WorkerProtocol.parse_hello(&refused) else { panic!("not fatal") };
        assert_eq!(reason, "SANDBOX_VIOLATION: sockets");
        assert!(WorkerProtocol.parse_hello(&frame(2, 0, b"")).is_err());
    }
}
