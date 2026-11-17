//! `PrivokeRuntimeService` as a W1 worker: one request frame in, one frame out.
//!
//! The handlers are the servicer's (`hosting/grpc_server.py`): a failure inside `AnalyzePrompt` is an ordinary
//! `AnalyzePromptResponse` with its `error` set, and `ERROR` frames are for protocol faults only. The worker never
//! runs an implicit pipeline: an empty layer list, or `DETECTION_LAYER_RUNTIME`, is `INVALID_LAYERS`.
//!
//! Served here: `AnalyzePrompt` for the regex and NER layers and, when the worker was given model roots, the plain semantic
//! layer, and `Health`. The presence gate, `DetectAnnotationPresence` and the gradient methods are served by the Python worker; the supervisor's routing keeps them away from this one, and a
//! request that reaches it anyway is refused with an error frame, never answered wrongly.

use std::time::Instant;

use privoke_contracts::proto::v1::{AnalyzePromptRequest, RuntimeHealthRequest};
use privoke_ner_layer::SpacyBackend;
use prost::Message;

use crate::frames::{self, FrameError, Kind, Method, Request, code};
use crate::pipeline::Pipeline;
use crate::request::{DEFAULT_MAX_TEXT_CHARS, Layer, is_gate_model, parse_prompt_request, regex_first, requested_layers};
use crate::response::{Elapsed, decide, encode_analysis, error_response, health_response};

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
}

impl<A: SpacyBackend> Service<A> {
    /// A service over a pipeline.
    pub fn new(pipeline: Pipeline<A>, options: ServiceOptions) -> Self {
        Self { pipeline, options }
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
            other => {
                return Err(FrameError::new(
                    code::UNKNOWN_METHOD,
                    format!("{} is not served by the Rust worker; the supervisor routes it to the Python worker.", other.name()),
                    request.request_id,
                ));
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
        // The presence gate is served by the Python worker only. (The pretrained contextual encoder is a semantic model like
        // the others: without its asset directory it is the layer's error, as in the Python runtime.)
        if message.layers.contains(&Layer::Semantic.proto_value())
            && (!self.pipeline.serves_semantic() || message.semantic_presence_gate.is_some())
        {
            return Err(FrameError::new(
                code::UNSUPPORTED_LAYERS,
                "This semantic selection is served by the Python worker; the Rust worker serves the regex and NER layers and, with model roots, plain semantic models.",
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

    async fn analyse(&self, message: &AnalyzePromptRequest) -> Result<Vec<u8>, String> {
        let prompt = parse_prompt_request(message, self.options.max_text_chars)?;
        let layers = requested_layers(&message.layers)?;
        let order = regex_first(message.regex_execution_order)?;
        if let Some(gate) = &message.semantic_presence_gate {
            if !is_gate_model(&gate.model_id) {
                return Err("Gate model_id must explicitly name a supported presence model.".to_string());
            }
            if !layers.contains(&Layer::Semantic) {
                return Err("Semantic presence gate requires the semantic layer.".to_string());
            }
        }
        let analysis_started = Instant::now();
        let executions = self
            .pipeline
            .analyse(&prompt.text, &layers, order, (!message.semantic_model_id.is_empty()).then_some(message.semantic_model_id.as_str()))
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

fn decode<M: Message + Default>(request: &Request, name: &str) -> Result<M, FrameError> {
    M::decode(request.payload.as_slice())
        .map_err(|error| FrameError::new(code::INVALID_PAYLOAD, format!("Payload is not a valid {name}: {error}"), request.request_id))
}
