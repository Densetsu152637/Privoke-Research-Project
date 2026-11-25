//! The quarantined analysis microservice (stage W3 of the server rewrite).
//!
//! A thin tonic front end for the existing `PrivokeRuntimeService`, for one caller: the fuzzer. It never runs analysis
//! itself. Each request goes to a supervised pool of W1 Python workers (`extension/client-runtime/src/worker_main.py`)
//! over the W1 pipe protocol, and the worker's bytes come back as the response.
//!
//! * [`config`]: process configuration from the environment.
//! * [`frames`]: the W1 frame codec and error-code mapping.
//! * [`protocol`]: the [`privoke_worker_pool::Protocol`] for the W1 worker.
//! * [`models`]: fetches models over mutual TLS from model-streaming, checks them, and keeps the read-only cache.
//! * [`raw`]: the gRPC surface, over a pass-through codec so responses stay byte-exact.
//! * [`service`]: the call handling and its fuzzer-only policy.
//! * [`server`]: wiring: transport, pool, cache and listener.
//! * [`healthcheck`]: the `healthcheck` subcommand.

pub mod config;
pub mod error;
pub mod frames;
pub mod healthcheck;
pub mod models;
pub mod protocol;
pub mod raw;
pub mod server;
pub mod service;
pub mod util;

pub use error::{Error, Result};
