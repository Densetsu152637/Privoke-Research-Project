//! The Rust analysis runtime (stage 17 of the server rewrite): the `PrivokeRuntimeService` analysis RPCs as a worker
//! behind the W1 frame protocol, in the W2 pool, with spaCy in the same process (stage 11b).
//!
//! * [`model`]: classification values, the action policy and the evidence aggregation (`classification/*`,
//!   `pipeline.strongest_result`).
//! * [`request`]: request validation with Python's messages (`hosting/serialization.py`, `hosting/grpc_server.py`).
//! * [`pipeline`]: the layers and their order (`pipeline.py`) over `privoke-rules` and `privoke-ner-layer`.
//! * [`response`]: the combined evidence, the visibility hint, the masked text and the response bytes.
//! * [`wire`]: the protobuf encoder that writes what Python's `SerializeToString(deterministic=True)` writes.
//! * [`frames`]: the W1 frame codec, limits and error codes.
//! * [`service`]: the request handling, one frame in and one frame out.
//! * [`worker`]: the ready announcement, the sandbox self-check and the serve loop over the pool's framing.
//!
//! Served by this worker: `AnalyzePrompt` for the regex and NER layers, and `Health`. The semantic layer, the model fetch
//! (D11), `DetectAnnotationPresence` and the gradient methods stay on the Python worker for now; see the stage 17 record in
//! `docs/plans/rust-server-rewrite.md`.

pub mod frames;
pub mod model;
pub mod pipeline;
pub mod request;
pub mod response;
pub mod service;
pub mod wire;
pub mod worker;

pub use frames::{FrameError, Kind, Method, Request};
pub use pipeline::{LayerExecution, Pipeline, PipelineOptions, Status};
pub use service::{Service, ServiceOptions};
