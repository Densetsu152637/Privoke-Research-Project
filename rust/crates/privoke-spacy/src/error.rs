//! Errors of the spaCy client and the gRPC-style status each one maps to.

use std::time::Duration;

/// The status a caller reports to its own client. Names follow gRPC; the runtime maps them one to one.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StatusKind {
    /// The request itself is unusable, for example text above the length limit. Not retried.
    InvalidArgument,
    /// The bounded queue is full.
    ResourceExhausted,
    /// No worker could answer: none ready, the worker crashed or timed out, or the bundle was refused.
    Unavailable,
}

/// Why a request got no answer.
#[derive(Debug, thiserror::Error)]
pub enum SpacyError {
    /// The text is empty or longer than the configured limit.
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
    /// The queue holds `capacity` waiting requests.
    #[error("the spaCy queue is full ({capacity} waiting requests)")]
    ResourceExhausted {
        /// The configured queue capacity.
        capacity: usize,
    },
    /// No worker is ready (still loading, restarting after a crash, or refused by the bundle check).
    #[error("no spaCy worker is ready: {0}")]
    NotReady(String),
    /// The worker serving this request crashed or closed its pipe. The request is not retried.
    #[error("the spaCy worker failed while serving this request: {0}")]
    WorkerFailed(String),
    /// The request did not finish before its deadline. A worker that was serving it is killed and restarted.
    #[error("the spaCy request missed its {0:?} deadline")]
    DeadlineExceeded(Duration),
    /// The worker answered, but with an error (for example a Python exception).
    #[error("the spaCy worker reported an error: {0}")]
    WorkerReported(String),
    /// A frame or a payload broke the protocol, or offsets did not match the text.
    #[error("spaCy protocol violation: {0}")]
    Protocol(String),
    /// The pool is shutting down.
    #[error("the spaCy pool is shut down")]
    Shutdown,
}

impl SpacyError {
    /// The status to report. Every failure except invalid input and a full queue is `Unavailable`, which makes the
    /// NER layer fail and blocks an otherwise ALLOW decision, as the Python pipeline does today.
    pub fn status(&self) -> StatusKind {
        match self {
            Self::InvalidArgument(_) => StatusKind::InvalidArgument,
            Self::ResourceExhausted { .. } => StatusKind::ResourceExhausted,
            _ => StatusKind::Unavailable,
        }
    }
}

/// Invalid pool configuration, or a failure to start the pool.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// A value is out of range.
    #[error("invalid spaCy pool configuration: {0}")]
    Invalid(String),
    /// The pool was started outside a Tokio runtime.
    #[error("the spaCy pool must be started inside a Tokio runtime")]
    NoRuntime,
}
