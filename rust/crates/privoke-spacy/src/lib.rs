//! Client for the spaCy worker (stage 11): the framed protocol, offset conversion and a supervised worker pool.
//!
//! The worker is the separate `privoke-spacy-worker` binary, which embeds CPython 3.11 through PyO3 and serves the
//! unchanged spaCy `en_core_web_sm`. This crate has no Python dependency; it starts the worker as a child process.
//!
//! ```ignore
//! let pool = SpacyPool::start(PoolConfig::new(bundle_dir.join("privoke-spacy-worker.exe")))?;
//! pool.wait_ready(Duration::from_secs(60)).await?;
//! let analysis = pool.analyze("Alice lives in Paris.", Selection::Full).await?;
//! ```
//!
//! Failures map to a [`StatusKind`]: `ResourceExhausted` for a full queue, `InvalidArgument` for unusable text, and
//! `Unavailable` for everything else, which fails the NER layer and so blocks an otherwise ALLOW decision.

pub mod error;
pub mod offsets;
pub mod pool;
pub mod protocol;

pub use error::{ConfigError, SpacyError, StatusKind};
pub use offsets::{OffsetMap, Span};
pub use pool::{BRIDGE_DEADLINE, Backoff, PoolConfig, SpacyPool};
pub use protocol::{Analysis, Entity, RawAnalysis, Selection, Token, WorkerInfo};
