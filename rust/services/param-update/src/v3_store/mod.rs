//! The V3 checkpoint store and its `CheckpointService` (stage V3-R1 of the routine-training plan; stage 10 of the server rewrite
//! folded in). It replaces `services/pretrained-v3/src/checkpoint_store.py` and `checkpoint_server.py`, which stay in place as
//! the parity oracle.
//!
//! * [`store`]: the content-addressed blobs, the `current(model, manifest)` authority table, `admit_candidate` (lineage,
//!   provenance, config, inventory, checkpoint bytes, execution evidence), `stage` and the compare-and-swap `commit` with
//!   request-id idempotence;
//! * [`evidence`]: `validate_source_evidence`, the check that the fit's source record is the pinned frozen source;
//! * [`service`]: the gRPC handlers served on the internal mutual-TLS listener.
//!
//! The SQLite `current` table is the single authority for every later stage: published directories, pointers and signed
//! statements are derived from it.

pub mod evidence;
pub mod service;
pub mod store;

pub use evidence::{AudienceSource, PinnedSources, SourceEvidence};
pub use service::CheckpointHandler;
pub use store::{Candidate, ChainObserver, CheckpointStore, CommitObserver, NoObserver, StoreError, Swap};
