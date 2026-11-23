//! The PriVoke parameter-update service and training-cycle scheduler in Rust (stage 5 of the server rewrite). It
//! replaces `services/param-update-service` (Python), which stays in place as the parity oracle.
//!
//! The V1 gradient update path (`SubmitParameterUpdate`: validation, application, drift bounds, per-request receipts) was
//! removed in stage V3-R8b: V1 models are served for detection and no longer trained, so the RPC is `UNIMPLEMENTED`. The
//! status lookup, `Health` and the V1 model bootstrap stay. Modules mirror the Python files:
//!
//! * [`artifact_io`] (`privoke_model.artifact`): the atomic, fsynced write of the model artifact;
//! * [`receipts`] (`receipts.py`), [`audit`] (`audit.py`) and [`bootstrap`] (`bootstrap.py`);
//! * [`engine`] (`server.py`'s service class without the transport) and [`service`] plus [`server`] (the transport);
//! * [`journal`] (`training_cycles.py`) and [`scheduler`] (`fuzzer_requests.py`): the training-cycle scheduler.
//!
//! The V3 checkpoint store ([`v3_store`], `checkpoint_store.py` and `checkpoint_server.py`) is served on the same listener to the
//! publisher and trainer roles.
//!
//! New here: publisher authorisation and identity binding
//! (`privoke-transport`), fail-closed startup, and the [`healthcheck`] subcommand. [`pyfmt`] holds the Python text and
//! number behaviour the artifact, receipt and journal formats depend on.

pub mod artifact_io;
pub mod audit;
pub mod bootstrap;
pub mod config;
pub mod engine;
pub mod error;
pub mod healthcheck;
pub mod journal;
pub mod pyfmt;
pub mod receipts;
pub mod scheduler;
pub mod server;
pub mod service;
pub mod util;
pub mod v3_guard;
pub mod v3_policy;
pub mod v3_publish;
pub mod v3_retention;
pub mod v3_store;

pub use error::{Error, Failure, Result};

/// The service name reported by `Health` and by the `healthcheck` subcommand.
pub const SERVICE_NAME: &str = "param-update-service";
