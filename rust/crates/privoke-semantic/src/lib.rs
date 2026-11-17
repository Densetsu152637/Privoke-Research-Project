//! Semantic inference of the PriVoke client runtime in Rust (stage 14, decision D3).
//!
//! * [`v3`]: the pretrained BERT encoder of the standard V3 releases with its affine task heads, tokenised with the
//!   `tokenizers` crate (the same implementation, at the same version, as the Python wheel the reference runtime uses).
//! * [`tiny`]: the legacy Tiny transformer, both readouts.
//! * [`layer`]: the semantic layer as the pipeline runs it (normalise, classify, remap spans).
//! * `open_classifier` (cargo feature `external-classifier`, on by default), [`open_prompt`], [`open_response`]: the external
//!   OpenAI-compatible classifier client (stage 16), which implements the same [`SemanticClassifier`] trait over `reqwest`
//!   with rustls. Without the feature the crate links no HTTP stack; the prompt and response code stay (they are pure).
//!
//! # Backend
//!
//! The numeric kernels are the dependency-free reference backend in [`math`]: float32 weights, float64 activations,
//! one rounding to float32 at the head output. It was chosen over `tch-rs`, `candle` and `ort` because the stage's measured spike could
//! not be run (no libtorch or ONNX runtime in the CI image, and local builds are not part of this stage's workflow); see
//! `docs/runtime/rust-workspace.md#privoke-semantic-stage-14` for the decision record. The kernels sit behind
//! [`math::Dense`] and [`math::attention`], so another backend replaces them without touching the model code.
//!
//! # Scope
//!
//! Everything here is LLM-only: it never runs the regex or NER layers. The sparse presence, scratch-presence and
//! pretrained-context models are not ported (see the workspace document).

pub mod bert;
pub mod error;
pub mod labels;
pub mod layer;
pub mod math;
#[cfg(feature = "external-classifier")]
pub mod open_classifier;
pub mod open_prompt;
pub mod open_response;
pub mod safetensors;
pub mod tiny;
pub mod v3;

pub use error::SemanticError;
pub use labels::Prediction;
pub use layer::{Finding, LayerHit, LayerOutcome, SemanticClassifier, analyse_semantic_layer};
#[cfg(feature = "external-classifier")]
pub use open_classifier::{OpenClassifier, OpenConfig, OpenOptions, OpenRequest};
pub use open_response::ExternalResult;
pub use tiny::{TinyModel, TinyPrediction};
pub use v3::{V3Logits, V3Model};
