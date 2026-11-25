//! Errors of the privacy kernel and the ledger. Each variant records the Python exception class the oracle raises, so
//! a log line can say the same thing (`telemetry privacy processing failed; report suppressed (RuntimeError)`).

use std::io;

/// Why the operating-system random source failed (CPython: `OSError` from `os.urandom`).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("random source unavailable: {0}")]
pub struct RandomError(pub String);

/// A fault of the ledger file: the reason is kept for the cause chain and never carries report data.
#[derive(Debug, thiserror::Error)]
pub enum LedgerFault {
    /// A filesystem operation on the ledger or its directory failed.
    #[error("ledger file: {0}")]
    Io(#[from] io::Error),
    /// SQLite refused an operation (corrupt file, lock timeout, constraint).
    #[error("ledger database: {0}")]
    Sqlite(#[from] rusqlite::Error),
    /// The ledger opened but its contents fail the accounting checks.
    #[error("{0}")]
    Invalid(String),
}

/// Failure of the kernel, the ledger or the report builder.
#[derive(Debug, thiserror::Error)]
pub enum PrivacyError {
    /// A caller error: bad epsilon, domain, value or dimension set (CPython `ValueError`). The text is the oracle's.
    #[error("{0}")]
    Invalid(String),
    /// The ledger could not be read or written, so nothing may be sent (CPython `RuntimeError`).
    #[error("telemetry privacy budget unavailable; report suppressed")]
    LedgerUnavailable(#[source] LedgerFault),
    /// The random source failed (CPython `OSError`).
    #[error(transparent)]
    Random(#[from] RandomError),
}

impl PrivacyError {
    /// The Python exception class name the oracle would log for this failure.
    pub fn python_class(&self) -> &'static str {
        match self {
            Self::Invalid(_) => "ValueError",
            Self::LedgerUnavailable(_) => "RuntimeError",
            Self::Random(_) => "OSError",
        }
    }

    pub(crate) fn invalid(message: impl Into<String>) -> Self {
        Self::Invalid(message.into())
    }
}

/// Failure to set up the reporter or its transport.
#[derive(Debug, thiserror::Error)]
pub enum ReporterError {
    /// The privacy configuration is out of range.
    #[error(transparent)]
    Config(#[from] PrivacyError),
    /// The delivery thread or its runtime could not start.
    #[error("reporter start: {0}")]
    Start(#[from] io::Error),
    /// The telemetry endpoint or credential is not usable.
    #[error("telemetry endpoint: {0}")]
    Endpoint(String),
}
