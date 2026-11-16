//! Error type shared by the transport modules.

use std::path::PathBuf;

/// Everything that can stop a listener or client from being built or reloaded.
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    /// A socket operation failed.
    #[error("socket error: {0}")]
    Socket(#[from] std::io::Error),
    /// A PEM file is missing a required object or is malformed.
    #[error("{path}: {reason}")]
    Pem {
        /// The file.
        path: PathBuf,
        /// What is wrong.
        reason: String,
    },
    /// The CRL set is unusable: unsigned by the client CA, stale, empty or malformed.
    #[error("CRL refused: {0}")]
    Crl(String),
    /// A rustls configuration was refused.
    #[error("TLS configuration refused: {0}")]
    Tls(String),
    /// A required startup setting is missing or invalid. The process must exit before binding.
    #[error("startup refused: {0}")]
    Startup(String),
    /// The plaintext loopback listener was asked to bind a non-loopback address.
    #[error("plaintext loopback listener refuses non-loopback address {0}")]
    NotLoopback(std::net::SocketAddr),
}

impl TransportError {
    pub(crate) fn pem(path: impl Into<PathBuf>, reason: impl Into<String>) -> Self {
        Self::Pem { path: path.into(), reason: reason.into() }
    }
}
