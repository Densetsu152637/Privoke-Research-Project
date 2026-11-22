//! `PrivokeRuntimeService` as a W1 worker: one request frame in, one frame out.
//!
//! The handlers are the servicer's (`hosting/grpc_server.py`): a failure inside `AnalyzePrompt` is an ordinary
//! `AnalyzePromptResponse` with its `error` set, and `ERROR` frames are for protocol faults only. The worker never
//! runs an implicit pipeline: an empty layer list, or `DETECTION_LAYER_RUNTIME`, is `INVALID_LAYERS`.
//!
//! Served here: `AnalyzePrompt` for the regex and NER layers and, when the worker was given model roots, the semantic layer
//! (behind a sparse presence gate too), `DetectAnnotationPresence`, the three gradient methods for the request shapes
//! stage 19 ported, and `Health`. A request this worker does not serve is refused with an error frame
//! (`UNSUPPORTED_LAYERS`, or `UNSUPPORTED_ROUTE` before anything has run), never answered wrongly; the controller sends
//! the same call to the Python worker.

use std::sync::Arc;
use std::time::Instant;

use privoke_contracts::proto::v1::{AnalyzePromptRequest, DetectAnnotationPresenceRequest, RuntimeHealthRequest};
use privoke_ner_layer::SpacyBackend;
use prost::Message;

use crate::frames::{self, FrameError, Kind, Method, Request, code};
use crate::gate::{Gate, is_scratch_presence_model};
use crate::pipeline::Pipeline;
use crate::presence;
use crate::request::{DEFAULT_MAX_TEXT_CHARS, Layer, is_gate_model, parse_prompt_request, regex_first, requested_layers};
use crate::response::{Elapsed, decide, encode_analysis, error_response, health_response};
use crate::store::ArtifactStore;
use crate::training::Trainer;

/// The semantic model a presence gate requires (`ORIGINAL_SEMANTIC_MODEL_ID`).
const GATE_SEMANTIC_MODEL_ID: &str = "privoke-balanced";

/// Settings of the service.
#[derive(Debug, Clone, Copy)]
pub struct ServiceOptions {
    /// The longest prompt in characters (`DEFAULT_MAX_TEXT_CHARS`).
    pub max_text_chars: usize,
    /// Leave the wall-clock fields out of every response. Only the conformance comparison sets it.
    pub clear_elapsed: bool,
}

impl Default for ServiceOptions {
    fn default() -> Self {
        Self { max_text_chars: DEFAULT_MAX_TEXT_CHARS, clear_elapsed: false }
    }
}

/// The runtime's request handling over a pipeline.
#[derive(Debug)]
pub struct Service<A> {
    pipeline: Pipeline<A>,
    options: ServiceOptions,
    trainer: Option<Trainer>,
}

impl<A: SpacyBackend> Service<A> {
    /// A service over a pipeline.
    pub fn new(pipeline: Pipeline<A>, options: ServiceOptions) -> Self {
        Self { pipeline, options, trainer: None }
    }

    /// Adds the gradient RPCs over the model store (the same roots the pipeline's models are read from).
    #[must_use]
    pub fn with_training(mut self, store: Arc<ArtifactStore>) -> Self {
        self.trainer = Some(Trainer::new(store, self.options.max_text_chars));
        self
    }

    /// The pipeline.
    pub fn pipeline(&self) -> &Pipeline<A> {
        &self.pipeline
    }

    /// One whole frame in, the frame to send back out. Never panics on input: every fault is an `ERROR` frame.
    pub async fn handle_frame(&self, frame: &[u8]) -> Vec<u8> {
        let request = match frames::decode_request(frame) {
            Ok(request) => request,
            Err(error) => return frames::encode_error(error.request_id, error.code, &error.message),
        };
        let (id, method) = (request.request_id, request.method);
        match self.handle(request).await {
            Ok(payload) => frames::encode_frame(Kind::Response, method as u8, id, &payload),
            Err(error) => frames::encode_error(id, error.code, &error.message),
        }
    }

    /// Dispatches a decoded request to its handler and checks the deadline and the response limit.
    pub async fn handle(&self, request: Request) -> Result<Vec<u8>, FrameError> {
        let limits = request.method.limits();
        let started = Instant::now();
        let payload = match request.method {
            Method::Health => {
                decode::<RuntimeHealthRequest>(&request, "RuntimeHealthRequest")?;
                health_response()
            }
            Method::AnalyzePrompt => self.analyze_prompt(&request).await?,
            Method::DetectAnnotationPresence => self.detect_presence(&request)?,
            Method::ComputeSemanticGradients | Method::ComputeUnderlyingModelGradients | Method::ComputePresenceGradients => {
                self.compute_gradients(&request)?
            }
        };
        if started.elapsed().as_millis() > u128::from(request.deadline_ms) {
            return Err(FrameError::new(
                code::DEADLINE_EXCEEDED,
                format!("{} exceeded its {} ms deadline.", request.method.name(), request.deadline_ms),
                request.request_id,
            ));
        }
        if payload.len() > limits.max_response {
            return Err(FrameError::new(
                code::RESPONSE_TOO_LARGE,
                format!("{} response of {} bytes exceeds the {} byte limit.", request.method.name(), payload.len(), limits.max_response),
                request.request_id,
            ));
        }
        Ok(payload)
    }

    async fn analyze_prompt(&self, request: &Request) -> Result<Vec<u8>, FrameError> {
        let message = decode::<AnalyzePromptRequest>(request, "AnalyzePromptRequest")?;
        if message.layers.is_empty() {
            return Err(FrameError::new(
                code::INVALID_LAYERS,
                "An explicit non-empty layer selection is required; an empty list would select the complete detector pipeline.",
                request.request_id,
            ));
        }
        if message.layers.contains(&1) {
            return Err(FrameError::new(
                code::INVALID_LAYERS,
                "DETECTION_LAYER_RUNTIME selects the complete pipeline; name layers explicitly.",
                request.request_id,
            ));
        }
        // The scratch presence gates are served by the Python worker only; a gate
        // needs the presence models as well as the semantic ones.
        if message.layers.contains(&Layer::Semantic.proto_value())
            && (!self.pipeline.serves_semantic()
                || message
                    .semantic_presence_gate
                    .as_ref()
                    .is_some_and(|gate| is_scratch_presence_model(&gate.model_id) || !self.pipeline.serves_gate()))
        {
            return Err(FrameError::new(
                code::UNSUPPORTED_LAYERS,
                "This semantic selection is served by the Python worker; the Rust worker serves the regex and NER layers and, with model roots, semantic models, sparse presence gates and presence inference.",
                request.request_id,
            ));
        }
        let bytes = match self.analyse(&message).await {
            Ok(bytes) => bytes,
            // Any exception in the Python handler is the response's `error`, under the request's own request_id.
            Err(text) => error_response(&message.request_id, &text),
        };
        Ok(bytes)
    }

    fn detect_presence(&self, request: &Request) -> Result<Vec<u8>, FrameError> {
        let message = decode::<DetectAnnotationPresenceRequest>(request, "DetectAnnotationPresenceRequest")?;
        if message.layers.is_empty() {
            return Err(empty_layers(request));
        }
        let Some(models) = self.pipeline.presence() else {
            return Err(FrameError::new(
                code::UNSUPPORTED_ROUTE,
                "This worker was given no model roots, so the Python worker serves DetectAnnotationPresence.",
                request.request_id,
            ));
        };
        Ok(presence::detect(models, &message, self.options.max_text_chars, self.options.clear_elapsed))
    }

    fn compute_gradients(&self, request: &Request) -> Result<Vec<u8>, FrameError> {
        match &self.trainer {
            Some(trainer) => trainer.handle(request),
            None => Err(FrameError::new(
                code::UNSUPPORTED_ROUTE,
                "This worker was given no model roots, so the Python worker serves the gradient RPCs.",
                request.request_id,
            )),
        }
    }

    async fn analyse(&self, message: &AnalyzePromptRequest) -> Result<Vec<u8>, String> {
        let prompt = parse_prompt_request(message, self.options.max_text_chars)?;
        let layers = requested_layers(&message.layers)?;
        let order = regex_first(message.regex_execution_order)?;
        // `_semantic_presence_gate`, then the checks `analyse_text` repeats.
        let mut gate = None;
        if let Some(requested) = &message.semantic_presence_gate {
            if !is_gate_model(&requested.model_id) {
                return Err("Gate model_id must explicitly name a supported presence model.".to_string());
            }
            if !layers.contains(&Layer::Semantic) {
                return Err("Semantic presence gate requires the semantic layer.".to_string());
            }
            if message.semantic_model_id != GATE_SEMANTIC_MODEL_ID {
                return Err("Semantic presence gate requires explicit semantic_model_id='privoke-balanced'.".to_string());
            }
            if requested.threshold.is_some_and(|threshold| !threshold.is_finite() || !(0.0..=1.0).contains(&threshold)) {
                return Err("Gate threshold must be finite and in [0, 1].".to_string());
            }
            gate = Some(Gate { model_id: requested.model_id.clone(), threshold: requested.threshold });
        }
        let analysis_started = Instant::now();
        let executions = self
            .pipeline
            .analyse_gated(
                &prompt.text,
                &layers,
                order,
                (!message.semantic_model_id.is_empty()).then_some(message.semantic_model_id.as_str()),
                gate.as_ref(),
            )
            .await
            .map_err(|error| error.to_string())?;
        let analysis = decide(prompt, executions).map_err(|error| error.to_string())?;
        let elapsed = if self.options.clear_elapsed {
            Elapsed::Cleared
        } else {
            Elapsed::Measured(analysis_started.elapsed().as_secs_f64() * 1000.0)
        };
        encode_analysis(&analysis, elapsed).map_err(|error| error.to_string())
    }
}

/// The refusal of an empty layer list, which would select the complete detector pipeline.
pub(crate) fn empty_layers(request: &Request) -> FrameError {
    FrameError::new(
        code::INVALID_LAYERS,
        "An explicit non-empty layer selection is required; an empty list would select the complete detector pipeline.",
        request.request_id,
    )
}

pub(crate) fn decode<M: Message + Default>(request: &Request, name: &str) -> Result<M, FrameError> {
    M::decode(request.payload.as_slice())
        .map_err(|error| FrameError::new(code::INVALID_PAYLOAD, format!("Payload is not a valid {name}: {error}"), request.request_id))
}
