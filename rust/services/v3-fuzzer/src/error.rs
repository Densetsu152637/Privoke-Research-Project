//! One error type: a Python `ValueError`, `RuntimeError` or `OSError` with its message, and the two ways a cycle ends
//! without a response.

use std::fmt;

use tonic::Status;

/// Why a configuration, contract or storage operation was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error(pub String);

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

impl From<privoke_curriculum::Error> for Error {
    fn from(error: privoke_curriculum::Error) -> Self {
        Self(error.to_string())
    }
}

impl From<privoke_training::TrainingError> for Error {
    fn from(error: privoke_training::TrainingError) -> Self {
        Self(error.to_string())
    }
}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Self(error.to_string())
    }
}

impl From<rusqlite::Error> for Error {
    fn from(error: rusqlite::Error) -> Self {
        Self(error.to_string())
    }
}

/// The crate's result type.
pub type Result<T> = std::result::Result<T, Error>;

/// An error with a message.
pub fn invalid<T>(message: impl Into<String>) -> Result<T> {
    Err(Error(message.into()))
}

/// How a cycle ends without a response: `context.abort` (a named gRPC status) or an exception that the Python servicer did
/// not catch (gRPC reports it as `UNKNOWN`, whatever the exception type).
#[derive(Debug)]
pub enum Failure {
    /// `context.abort(code, message)`.
    Abort(Status),
    /// A `ValueError`, `RuntimeError`, `OSError` or `grpc.RpcError` that propagates out of the handler.
    Raised(String),
}

impl Failure {
    /// A dependency call that failed and was not recovered (`grpc.RpcError` propagating).
    pub fn rpc(status: &Status) -> Self {
        Self::Raised(format!("{:?}: {}", status.code(), status.message()))
    }
}

impl From<Error> for Failure {
    fn from(error: Error) -> Self {
        Self::Raised(error.0)
    }
}

impl From<Failure> for Status {
    fn from(failure: Failure) -> Self {
        match failure {
            Failure::Abort(status) => status,
            Failure::Raised(message) => Status::unknown(message),
        }
    }
}
