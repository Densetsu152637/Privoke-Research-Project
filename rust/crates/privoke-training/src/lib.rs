//! Gradients and local training of the Tiny transformer in Rust (stage 19, decision D4).
//!
//! * [`net`]: the Tiny network with a hand-written reverse-mode backward pass. The arithmetic is float64 over float32
//!   weights, like the stage 14 reference backend; torch computes the same gradients in float32, so the two agree to
//!   float32 rounding (the stage's tolerance is an absolute 1e-6).
//! * [`objective`]: the supervised objectives of `supervised_training.supervised_last_block_deltas` (legacy summed
//!   category BCE, mean category BCE, and the two decision-margin objectives) and the class-balanced reweighting.
//! * [`adam`]: the FULL projected Adam of `full_adam_training.py` (float64 moments, one thread, 64 fixed steps, a
//!   float32 cumulative delta capped at 0.05).
//! * [`rpc`], [`routes`] and [`admission`]: the gradient RPC computation of `_compute_training_gradients`, its local-SGD,
//!   backtracking and TRAIN-diagnostics routes (with the Python trace strings of [`trace`]), and the artifact policy and
//!   admission checks that choose the route.
//!
//! The crate never loads libtorch. CUDA is out of scope. Everything is LLM-only (it never runs a detector layer).

// The numeric kernels index several parallel buffers by one position; iterator rewrites would obscure the maths.
#![allow(clippy::needless_range_loop)]

pub mod adam;
pub mod adamw;
pub mod admission;
pub mod bert_backward;
pub mod error;
pub mod net;
pub mod objective;
pub mod presence;
pub mod reference;
pub mod retention;
pub mod routes;
pub mod rpc;
pub mod trace;
pub mod v3_model;
pub mod window;

pub use error::TrainingError;
pub use net::{Params, Tensor, TinyNet};
pub use objective::{Example, Objective, Target};
