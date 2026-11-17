//! Error types: [`Error`] for startup and configuration, [`Failure`] for request handling.

use std::fmt;

/// A startup, configuration or probe failure. The text is for logs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error(pub String);

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

impl From<String> for Error {
    fn from(message: String) -> Self {
        Self(message)
    }
}

impl From<&str> for Error {
    fn from(message: &str) -> Self {
        Self(message.to_string())
    }
}

/// Result alias for startup and configuration.
pub type Result<T> = std::result::Result<T, Error>;

/// The public message of a persistence failure on the update path (Python's `server.py`).
pub const PERSISTENCE_FAILED: &str = "Model artifact persistence failed.";
/// The public message of a failed receipt lookup.
pub const LOOKUP_FAILED: &str = "Update receipt lookup failed.";

/// Why a request was refused, by gRPC status class. Messages of the first three go to the caller; an internal
/// failure sends only its fixed public message and logs the detail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Failure {
    /// `INVALID_ARGUMENT`: validation, a conflicting reuse of a request id, an update the artifact refuses.
    Invalid(String),
    /// `FAILED_PRECONDITION`: a stale base version or an exhausted drift budget.
    Precondition(String),
    /// `ALREADY_EXISTS`: a request id that belongs to a different training request.
    AlreadyExists(String),
    /// `INTERNAL`: storage failed.
    Internal {
        /// What the caller sees.
        message: &'static str,
        /// What the log keeps.
        detail: String,
    },
}

impl Failure {
    /// An `INVALID_ARGUMENT` failure.
    pub fn invalid(message: impl Into<String>) -> Self {
        Self::Invalid(message.into())
    }

    /// An `INTERNAL` failure with a fixed public message.
    pub fn internal(message: &'static str, detail: impl fmt::Display) -> Self {
        Self::Internal { message, detail: detail.to_string() }
    }

    /// A storage failure on the update path.
    pub fn persistence(detail: impl fmt::Display) -> Self {
        Self::internal(PERSISTENCE_FAILED, detail)
    }

    /// The text a caller would see.
    pub fn message(&self) -> &str {
        match self {
            Self::Invalid(message) | Self::Precondition(message) | Self::AlreadyExists(message) => message,
            Self::Internal { message, .. } => message,
        }
    }

    /// The text for a log: the detail of an internal failure, otherwise the message.
    pub fn detail(&self) -> String {
        match self {
            Self::Internal { detail, .. } => detail.clone(),
            other => other.message().to_string(),
        }
    }

    /// The gRPC status, logging the detail of an internal failure.
    pub fn to_status(&self) -> tonic::Status {
        match self {
            Self::Invalid(message) => tonic::Status::invalid_argument(message.clone()),
            Self::Precondition(message) => tonic::Status::failed_precondition(message.clone()),
            Self::AlreadyExists(message) => tonic::Status::already_exists(message.clone()),
            Self::Internal { message, detail } => {
                crate::util::log(format_args!("{message} {detail:?}"));
                tonic::Status::internal(*message)
            }
        }
    }
}

impl fmt::Display for Failure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message())
    }
}

impl std::error::Error for Failure {}

impl From<rusqlite::Error> for Failure {
    fn from(error: rusqlite::Error) -> Self {
        Self::persistence(error)
    }
}

impl From<std::io::Error> for Failure {
    fn from(error: std::io::Error) -> Self {
        Self::persistence(error)
    }
}
