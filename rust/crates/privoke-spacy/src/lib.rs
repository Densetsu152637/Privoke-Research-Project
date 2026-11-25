//! spaCy for the NER layer, through two backends with one API: the framed protocol, offset conversion, the in-process
//! interpreter thread (stage 11b) and a supervised worker pool (stage 11).
//!
//! * **[`InProcess`] is the default.** CPython 3.11 is embedded in the host (runtime worker) process through PyO3 on one
//!   dedicated interpreter thread that owns the GIL and the loaded `en_core_web_sm`, reached through a channel. No
//!   child process is created. The PyO3 engine is behind the `in-process` feature, so the workspace builds and tests
//!   without Python.
//! * **[`SpacyPool`] is for tests and as the parity oracle.** It starts the separate `privoke-spacy-worker` binary
//!   (the same embedded CPython and Python code) as supervised child processes.
//!
//! ```ignore
//! let spacy = Spacy::start(&SpacyConfig::default())?; // in process, bundle = directory of the running executable
//! spacy.wait_ready(Duration::from_secs(120)).await?;
//! let analysis = spacy.analyze("Alice lives in Paris.", Selection::Full).await?;
//! ```
//!
//! Failures map to a [`StatusKind`]: `ResourceExhausted` for a full queue, `InvalidArgument` for unusable text, and
//! `Unavailable` for everything else, which fails the NER layer and so blocks an otherwise ALLOW decision.

pub mod backend;
pub mod error;
#[cfg(feature = "fake-worker")]
pub mod fake;
pub mod inprocess;
pub mod offsets;
pub mod pool;
pub mod protocol;
#[cfg(feature = "in-process")]
mod python;

pub use backend::{Spacy, SpacyConfig};
pub use error::{ConfigError, SpacyError, StatusKind};
pub use inprocess::{DEFAULT_MODEL, Engine, InProcess, InProcessConfig, StartFailure, Started};
pub use offsets::{OffsetMap, Span};
pub use pool::{BRIDGE_DEADLINE, Backoff, PoolConfig, SandboxPolicy, SpacyPool};
pub use protocol::{Analysis, Entity, RawAnalysis, Selection, Token, WorkerInfo};
