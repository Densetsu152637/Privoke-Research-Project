//! The service's error type: a message, as Go's `fmt.Errorf` values were.

use std::fmt;

/// A validation or load failure. The text is for logs; the gRPC layer maps failures to fixed status messages.
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

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Self(error.to_string())
    }
}

/// Result alias used across the service.
pub type Result<T> = std::result::Result<T, Error>;

/// `Err(Error(format!(..)))`.
#[macro_export]
macro_rules! fail {
    ($($argument:tt)*) => {
        return Err($crate::error::Error(format!($($argument)*)))
    };
}
