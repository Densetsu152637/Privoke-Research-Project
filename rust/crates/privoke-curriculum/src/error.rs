//! One error type for the ported curricula: Python's `ValueError` and its relatives.

use privoke_contracts::canonical::CanonicalError;
use privoke_contracts::json::JsonError;

use crate::pyrandom::RandomError;

/// Why a curriculum, schedule or aggregation step refused its input.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// A `ValueError` of the Python implementation: the message is the Python one where it has one.
    #[error("{0}")]
    Invalid(String),
    /// A file could not be read.
    #[error("cannot read {path}: {reason}")]
    Io {
        /// The path.
        path: String,
        /// The operating system's reason.
        reason: String,
    },
    /// A JSON document is malformed.
    #[error("invalid JSON: {0}")]
    Json(#[from] JsonError),
    /// A value cannot be written canonically.
    #[error("cannot canonicalise: {0}")]
    Canonical(#[from] CanonicalError),
    /// A `random` call was refused.
    #[error("random: {0}")]
    Random(#[from] RandomError),
}

/// The crate's result type.
pub type Result<T> = std::result::Result<T, Error>;

/// A `ValueError` with `message`.
pub fn invalid<T>(message: impl Into<String>) -> Result<T> {
    Err(Error::Invalid(message.into()))
}

/// Read a file, naming the path on failure.
pub fn read_file(path: &std::path::Path) -> Result<Vec<u8>> {
    std::fs::read(path).map_err(|error| Error::Io { path: path.display().to_string(), reason: error.to_string() })
}
