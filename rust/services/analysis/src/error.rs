//! The service's error type.

use std::fmt;

/// A configuration or start-up failure. The text is for the operator's log.
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

/// Result alias.
pub type Result<T> = std::result::Result<T, Error>;

/// `return Err(Error(format!(..)))`.
#[macro_export]
macro_rules! fail {
    ($($argument:tt)*) => {
        return Err($crate::error::Error(format!($($argument)*)))
    };
}
