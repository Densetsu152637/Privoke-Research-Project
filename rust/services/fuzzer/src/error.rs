//! One error type: a Python `ValueError` or `OSError` with its message.

use std::fmt;

/// Why a configuration, request or evidence operation was refused.
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
