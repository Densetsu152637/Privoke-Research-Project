//! What the V3 routine training and the V1 presence gate still need of the old training crate.
//!
//! Stage V3-R8b removed the V1 Tiny training (gradients, FULL Adam, window and retention loops): V1 models are served for
//! detection and are no longer trained (decision U4 of `docs/plans/v3-routine-training.md`). The Python code stays frozen as
//! the oracle of the committed goldens.
//!
//! * [`presence`]: the sparse annotation-presence model, inference only (the presence gate and `DetectAnnotationPresence`).
//! * [`pycompat`]: Python's `math.fsum` and `training_text_key`.
//! * [`adamw`], [`bert_backward`], [`v3_model`] and [`v3_fit`]: the V3 encoder fit (CPU, float32, AdamW).
//! * [`reference`], [`retention_common`] and [`retention_v3`]: the V3 retention reference and rule.
//!
//! The crate never loads libtorch. CUDA is out of scope. Everything is LLM-only (it never runs a detector layer).

// The numeric kernels index several parallel buffers by one position; iterator rewrites would obscure the maths.
#![allow(clippy::needless_range_loop)]

pub mod adamw;
pub mod bert_backward;
pub mod error;
pub mod presence;
pub mod pycompat;
pub mod reference;
pub mod retention_common;
pub mod retention_v3;
pub mod v3_fit;
pub mod v3_model;

pub use error::TrainingError;
