//! A Python exception as `AnalyzePrompt` reports it: `type(error).__name__ + ": " + str(error)` in `error`, and `str(error)` in
//! the layer's `error`.
//!
//! Only the failures that this service can produce are modelled: contract and artifact violations are `ValueError` (the message is
//! the Python text), an unknown visibility hint is `KeyError`, a failed call to the checkpoint service is a gRPC error and a
//! file-system failure is `OSError`. The text of a gRPC error is the shape of `grpc._InactiveRpcError.__str__` without its
//! `debug_error_string` (a transport detail that has no Rust counterpart).

use std::fmt;

use privoke_runtime::model::InvalidVisibility;
use privoke_semantic::SemanticError;
use tonic::{Code, Status};

/// A raised Python exception.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PyError {
    /// `type(error).__name__`.
    pub kind: &'static str,
    /// `str(error)`.
    pub message: String,
}

impl PyError {
    /// A `ValueError`.
    pub fn value(message: impl Into<String>) -> Self {
        Self { kind: "ValueError", message: message.into() }
    }

    /// A `KeyError` for a missing key: `str` of a `KeyError` is the `repr` of the key.
    pub fn key(key: &str) -> Self {
        Self { kind: "KeyError", message: repr(key) }
    }

    /// A failed call to the checkpoint service.
    pub fn rpc(status: &Status) -> Self {
        Self {
            kind: "_InactiveRpcError",
            message: format!(
                "<_InactiveRpcError of RPC that terminated with:\n\tstatus = StatusCode.{}\n\tdetails = \"{}\">",
                code_name(status.code()),
                status.message()
            ),
        }
    }
}

impl fmt::Display for PyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.kind, self.message)
    }
}

impl std::error::Error for PyError {}

impl From<privoke_v3_fuzzer::Error> for PyError {
    fn from(error: privoke_v3_fuzzer::Error) -> Self {
        Self::value(error.0)
    }
}

impl From<SemanticError> for PyError {
    fn from(error: SemanticError) -> Self {
        Self::value(error.to_string())
    }
}

impl From<InvalidVisibility> for PyError {
    fn from(error: InvalidVisibility) -> Self {
        Self::value(error.to_string())
    }
}

impl From<std::io::Error> for PyError {
    fn from(error: std::io::Error) -> Self {
        Self { kind: "OSError", message: error.to_string() }
    }
}

/// `grpc.StatusCode.<name>`.
pub fn code_name(code: Code) -> &'static str {
    match code {
        Code::Ok => "OK",
        Code::Cancelled => "CANCELLED",
        Code::Unknown => "UNKNOWN",
        Code::InvalidArgument => "INVALID_ARGUMENT",
        Code::DeadlineExceeded => "DEADLINE_EXCEEDED",
        Code::NotFound => "NOT_FOUND",
        Code::AlreadyExists => "ALREADY_EXISTS",
        Code::PermissionDenied => "PERMISSION_DENIED",
        Code::ResourceExhausted => "RESOURCE_EXHAUSTED",
        Code::FailedPrecondition => "FAILED_PRECONDITION",
        Code::Aborted => "ABORTED",
        Code::OutOfRange => "OUT_OF_RANGE",
        Code::Unimplemented => "UNIMPLEMENTED",
        Code::Internal => "INTERNAL",
        Code::Unavailable => "UNAVAILABLE",
        Code::DataLoss => "DATA_LOSS",
        Code::Unauthenticated => "UNAUTHENTICATED",
    }
}

/// `repr(text)` of a Python `str`.
pub fn repr(text: &str) -> String {
    let quote = if text.contains('\'') && !text.contains('"') { '"' } else { '\'' };
    let mut out = String::with_capacity(text.len() + 2);
    out.push(quote);
    for character in text.chars() {
        match character {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            other if other == quote => {
                out.push('\\');
                out.push(other);
            }
            other if (other as u32) < 0x20 || other as u32 == 0x7f => out.push_str(&format!("\\x{:02x}", other as u32)),
            other => out.push(other),
        }
    }
    out.push(quote);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_error_prints_the_repr_of_the_key() {
        assert_eq!(PyError::key("pu").to_string(), "KeyError: 'pu'");
        assert_eq!(PyError::key("it's").to_string(), "KeyError: \"it's\"");
        assert_eq!(PyError::key("a\"b'c").to_string(), "KeyError: 'a\"b\\'c'");
        assert_eq!(PyError::key("line\nbreak\\").to_string(), "KeyError: 'line\\nbreak\\\\'");
        assert_eq!(PyError::key("\u{1}").to_string(), "KeyError: '\\x01'");
    }

    #[test]
    fn a_value_error_prints_its_message_and_an_rpc_error_names_the_status() {
        assert_eq!(PyError::value("Snapshot belongs to another model.").to_string(), "ValueError: Snapshot belongs to another model.");
        let rpc = PyError::rpc(&Status::not_found("no such model"));
        assert_eq!(rpc.kind, "_InactiveRpcError");
        assert!(rpc.message.contains("StatusCode.NOT_FOUND") && rpc.message.contains("no such model"), "{rpc}");
    }
}
