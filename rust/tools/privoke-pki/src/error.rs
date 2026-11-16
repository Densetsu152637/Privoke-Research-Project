//! The tool's error type.

use std::path::{Path, PathBuf};

/// Why an operation was refused or failed.
#[derive(Debug, thiserror::Error)]
pub enum PkiError {
    /// A file operation failed.
    #[error("{path}: {source}")]
    Io {
        /// The file.
        path: PathBuf,
        /// The cause.
        source: std::io::Error,
    },
    /// The request violates the certificate profile or the enrolment rules.
    #[error("refused: {0}")]
    Refused(String),
    /// Certificate or key handling failed.
    #[error("certificate error: {0}")]
    Certificate(String),
    /// A ledger or registry file is malformed.
    #[error("{0}")]
    Data(String),
}

impl PkiError {
    pub(crate) fn io(path: &Path, source: std::io::Error) -> Self {
        Self::Io { path: path.to_path_buf(), source }
    }

    pub(crate) fn refused(message: impl Into<String>) -> Self {
        Self::Refused(message.into())
    }

    pub(crate) fn certificate(error: impl std::fmt::Display) -> Self {
        Self::Certificate(error.to_string())
    }
}
