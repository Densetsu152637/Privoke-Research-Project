//! The PriVoke parameter-update service and training-cycle scheduler in Rust (stage 5 of the server rewrite). It
//! replaces `services/param-update-service` (Python), which stays in place as the parity oracle.
//!
//! The service is the guarded legacy update path. A registered `publisher` sends a gradient update built on the model
//! version it saw; the service validates it, checks the base version (compare-and-swap), applies it, publishes the new
//! artifact with one atomic rename and records a durable receipt per request id, so a retry is answered exactly once and
//! a different payload under a used id is refused. Modules mirror the Python files:
//!
//! * [`validate`] (`validation.py`) and [`window`] (`window_training.validate_publication`): what an update may contain;
//! * [`apply`] and [`artifact_io`] (`privoke_model.artifact`): the arithmetic and the atomic, fsynced write;
//! * [`receipts`] (`receipts.py`), [`audit`] (`audit.py`) and [`bootstrap`] (`bootstrap.py`);
//! * [`engine`] (`server.py`'s service class without the transport) and [`service`] plus [`server`] (the transport);
//! * [`journal`] (`training_cycles.py`) and [`scheduler`] (`fuzzer_requests.py`): the training-cycle scheduler.
//!
//! The V3 checkpoint store ([`v3_store`], `checkpoint_store.py` and `checkpoint_server.py`) is served on the same listener to the
//! publisher and trainer roles.
//!
//! New here: [`policy`] (the per-update and cumulative drift bounds), publisher authorisation and identity binding
//! (`privoke-transport`), fail-closed startup, and the [`healthcheck`] subcommand. [`pyfmt`] holds the Python text and
//! number behaviour the artifact, receipt and journal formats depend on.

pub mod apply;
pub mod artifact_io;
pub mod audit;
pub mod bootstrap;
pub mod config;
pub mod engine;
pub mod error;
pub mod healthcheck;
pub mod journal;
pub mod policy;
pub mod pyfmt;
pub mod receipts;
pub mod scheduler;
pub mod server;
pub mod service;
pub mod util;
pub mod v3_store;
pub mod validate;
pub mod window;

pub use error::{Error, Failure, Result};

/// The service name reported by `Health` and by the `healthcheck` subcommand.
pub const SERVICE_NAME: &str = "param-update-service";
