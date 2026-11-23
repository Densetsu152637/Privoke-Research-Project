//! The Rust analysis runtime (stage 17 of the server rewrite): the `PrivokeRuntimeService` analysis RPCs as a worker
//! behind the W1 frame protocol, in the W2 pool, with spaCy in the same process (stage 11b).
//!
//! * [`model`]: classification values, the action policy and the evidence aggregation (`classification/*`,
//!   `pipeline.strongest_result`).
//! * [`request`]: request validation with Python's messages (`hosting/serialization.py`, `hosting/grpc_server.py`).
//! * [`pipeline`]: the layers and their order (`pipeline.py`) over `privoke-rules` and `privoke-ner-layer`.
//! * [`semantic`]: the semantic layer over read-only model roots (legacy Tiny artifacts and pinned V3 packages), alone or
//!   behind a presence gate.
//! * [`store`]: the read-only artifact reader (`LocalModelProvider` and `load_artifact`) of the presence and gradient RPCs.
//! * [`presence`] and [`gate`]: the sparse presence model, `DetectAnnotationPresence` and the gate trace.
//! * [`training`]: `ComputeSemanticGradients`, `ComputeUnderlyingModelGradients` and `ComputePresenceGradients` over the
//!   stage 19 computations, for the request shapes it ported.
//! * [`response`]: the combined evidence, the visibility hint, the masked text and the response bytes.
//! * [`wire`]: the protobuf encoder that writes what Python's `SerializeToString(deterministic=True)` writes.
//! * [`frames`]: the W1 frame codec, limits and error codes.
//! * [`service`]: the request handling, one frame in and one frame out.
//! * [`worker`]: the ready announcement, the sandbox self-check and the serve loop over the pool's framing.
//!
//! Served by this worker: `AnalyzePrompt` for the regex, NER and (with model roots) semantic layers, the sparse presence
//! gate, `DetectAnnotationPresence`, the gradient methods for the shapes stage 19 ported, and `Health`. The model fetch
//! (D11) and the pretrained contextual encoder stay elsewhere; see the stage 17 record in
//! `docs/plans/rust-server-rewrite.md`.

pub mod frames;
pub mod gate;
pub mod model;
pub mod pipeline;
pub mod presence;
pub mod request;
pub mod response;
pub mod semantic;
pub mod service;
pub mod snapshot;
pub mod store;
pub mod training;
pub mod wire;
pub mod worker;

pub use frames::{FrameError, Kind, Method, Request};
pub use pipeline::{LayerExecution, Pipeline, PipelineOptions, Status};
pub use service::{Service, ServiceOptions};
