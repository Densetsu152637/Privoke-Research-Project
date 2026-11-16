//! A protocol-agnostic supervised worker pool with an operating-system sandbox (stage W2).
//!
//! The pool starts worker processes, waits for each one to announce itself, serves requests from a bounded queue under
//! one deadline per request, never retries a request on a second worker, and restarts failed workers with
//! exponential backoff. It knows frames (a length prefix and bytes), not what they mean: a [`Protocol`] interprets the
//! first frame and each answer. `privoke-spacy` is the first user; the analysis service (W3) and the client
//! controller (W4) are the next.
//!
//! Every worker runs under a [`SandboxPolicy`]: it dies with the parent, may be held to a memory and process limit,
//! gets a clean environment with an explicit `PYTHONHOME`, and on Linux cannot use the network. Windows has no network
//! denial here; see [`sandbox`].
//!
//! ```ignore
//! let mut cfg = PoolConfig::new(worker_exe);
//! cfg.sandbox = SandboxPolicy::strict(bundle_dir);
//! let pool = WorkerPool::start(MyProtocol, cfg)?;
//! pool.wait_ready(Duration::from_secs(60)).await?;
//! let id = pool.next_id();
//! let answer = pool.submit(id, encode_request(id)).await?;
//! ```

pub mod error;
pub mod frame;
pub mod pool;
pub mod protocol;
pub mod sandbox;
pub mod worker_side;

#[cfg(feature = "test-worker")]
pub mod testing;

pub use error::{ConfigError, PoolError};
pub use frame::{MAX_FRAME_BYTES, read_frame, read_frame_sync, write_frame, write_frame_sync};
pub use pool::{Backoff, PoolConfig, WorkerPool};
pub use protocol::{Hello, Protocol, Reply};
pub use sandbox::{SandboxPolicy, network_denial_enforced};
