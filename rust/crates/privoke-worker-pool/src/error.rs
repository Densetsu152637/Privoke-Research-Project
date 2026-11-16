//! Errors of the pool.

use std::time::Duration;

/// Why a request got no answer.
#[derive(Debug, thiserror::Error)]
pub enum PoolError {
    /// The queue holds `capacity` waiting requests.
    #[error("the request queue is full ({capacity} waiting requests)")]
    ResourceExhausted {
        /// The configured queue capacity.
        capacity: usize,
    },
    /// No worker is ready (still loading, restarting after a crash, or refused at startup).
    #[error("no worker is ready: {0}")]
    NotReady(String),
    /// The worker serving this request crashed, broke the protocol or closed its pipe. The request is not retried.
    #[error("the worker failed while serving this request: {0}")]
    WorkerFailed(String),
    /// The request did not finish before its deadline. A worker that was serving it is killed and restarted.
    #[error("the request missed its {0:?} deadline")]
    DeadlineExceeded(Duration),
    /// The worker answered, but with an error of its own.
    #[error("the worker reported an error: {0}")]
    WorkerReported(String),
    /// The pool is shutting down.
    #[error("the pool is shut down")]
    Shutdown,
}

/// Invalid pool configuration, or a failure to start the pool.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// A value is out of range.
    #[error("invalid worker pool configuration: {0}")]
    Invalid(String),
    /// The pool was started outside a Tokio runtime.
    #[error("the worker pool must be started inside a Tokio runtime")]
    NoRuntime,
}
