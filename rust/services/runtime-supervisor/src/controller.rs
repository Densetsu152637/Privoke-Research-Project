//! The native-messaging session: the extension's runtime client talks to the controller here, over one port.
//!
//! This replaces the gRPC-Web bridge on `127.0.0.1:8080` and the control service on `127.0.0.1:50056`. The request and
//! response messages are the same protobuf messages (`runtime.proto`), carried as base64 inside a small JSON envelope,
//! so the extension keeps its codec and its semantics. The controller listens on nothing.
//!
//! ```text
//! request  {"v":1,"id":7,"method":"AnalyzePrompt","payload":"<base64 AnalyzePromptRequest>"}
//! success  {"v":1,"id":7,"ok":true,"payload":"<base64 AnalyzePromptResponse>"}
//! failure  {"v":1,"id":7,"ok":false,"code":"UNAVAILABLE","message":"..."}
//! ```
//!
//! | Method | Request message | Response message |
//! | --- | --- | --- |
//! | `AnalyzePrompt` | `AnalyzePromptRequest` | `AnalyzePromptResponse` |
//! | `Status` | `RuntimeHealthRequest` (empty) | `RuntimeControlStatus` |
//! | `SetRuntimeEnabled` | `SetRuntimeEnabledRequest` | `RuntimeControlStatus` |
//! | `ModelStreamingHealth` | `RuntimeHealthRequest` (empty) | `RuntimeHealthResponse` |
//!
//! Several requests may be in flight; each reply carries its request's `id` and replies may arrive in any order.
//!
//! Failure policy (fail closed): a failure of any kind is an error reply, never a decision. A frame that cannot be
//! parsed, or carries no usable `id`, ends the session without a reply, so the extension sees the port close and fails
//! everything it is waiting for. End of input (the browser closing the port or exiting) stops the runtime, which kills
//! the worker.

use std::io::{Read, Write};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use privoke_contracts::proto::v1::{RuntimeControlStatus, RuntimeHealthResponse, SetRuntimeEnabledRequest};
use prost::Message;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

use crate::health::ModelHealth;
use crate::native_host::{self, HostError, MAX_MESSAGE_BYTES};
use crate::runtime::{CallError, RuntimeController, RuntimeStatus};

/// The envelope version.
pub const PROTOCOL_VERSION: u32 = 1;

/// One request envelope.
#[derive(Debug, Deserialize)]
pub struct Request {
    /// The envelope version, [`PROTOCOL_VERSION`].
    pub v: u32,
    /// Chosen by the extension; echoed in the reply.
    pub id: u64,
    /// The method name.
    pub method: String,
    /// The base64 protobuf request.
    #[serde(default)]
    pub payload: Option<String>,
}

#[derive(Serialize)]
struct Reply {
    v: u32,
    id: u64,
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    payload: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    code: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
}

impl Reply {
    fn success(id: u64, payload: String) -> Self {
        Self { v: PROTOCOL_VERSION, id, ok: true, payload: Some(payload), code: None, message: None }
    }

    fn failure(id: u64, error: &CallError) -> Self {
        Self { v: PROTOCOL_VERSION, id, ok: false, payload: None, code: Some(error.code), message: Some(error.message.clone()) }
    }

    /// The compact JSON body. A reply above the browsers' 1 MB cap is replaced by an error: it would be dropped
    /// otherwise, and the caller must learn that, not wait for it.
    fn to_json(&self) -> String {
        let body = serde_json::to_string(self).unwrap_or_default();
        if body.len() <= MAX_MESSAGE_BYTES {
            return body;
        }
        let error = CallError::new("RESOURCE_EXHAUSTED", "The reply is larger than a native-messaging message may be.");
        serde_json::to_string(&Self::failure(self.id, &error)).unwrap_or_default()
    }
}

/// The controller's methods, shared by every session.
#[derive(Clone)]
pub struct Controller {
    runtime: Arc<RuntimeController>,
    health: Arc<dyn ModelHealth>,
}

impl std::fmt::Debug for Controller {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("Controller").finish_non_exhaustive()
    }
}

fn status_message(status: RuntimeStatus) -> RuntimeControlStatus {
    RuntimeControlStatus {
        enabled: status.enabled,
        status: status.status.to_string(),
        message: status.message,
        process_id: status.process_id,
    }
}

fn encode(message: &impl Message) -> String {
    STANDARD.encode(message.encode_to_vec())
}

fn decode_payload(request: &Request) -> Result<Vec<u8>, CallError> {
    let text = request.payload.as_deref().ok_or_else(|| CallError::new("INVALID_ARGUMENT", "The request has no payload."))?;
    STANDARD.decode(text).map_err(|_| CallError::new("INVALID_ARGUMENT", "The payload is not base64."))
}

impl Controller {
    /// A controller over a runtime and a health check.
    pub fn new(runtime: Arc<RuntimeController>, health: Arc<dyn ModelHealth>) -> Self {
        Self { runtime, health }
    }

    /// The runtime this controller drives.
    pub fn runtime(&self) -> &Arc<RuntimeController> {
        &self.runtime
    }

    async fn dispatch(&self, request: &Request) -> Result<String, CallError> {
        if request.v != PROTOCOL_VERSION {
            return Err(CallError::new("INVALID_ARGUMENT", format!("Unsupported protocol version {}.", request.v)));
        }
        match request.method.as_str() {
            "AnalyzePrompt" => self.runtime.analyze(&decode_payload(request)?).await,
            "Status" => Ok(encode(&status_message(self.runtime.status()))),
            "SetRuntimeEnabled" => {
                let message = SetRuntimeEnabledRequest::decode(decode_payload(request)?.as_slice())
                    .map_err(|_| CallError::new("INVALID_ARGUMENT", "The payload is not a SetRuntimeEnabledRequest."))?;
                let status = self.runtime.set_enabled(message.enabled, message.use_local_stack).await?;
                Ok(encode(&status_message(status)))
            }
            "ModelStreamingHealth" => {
                let (service, status) = self.health.check().await;
                Ok(encode(&RuntimeHealthResponse { service, status }))
            }
            other => Err(CallError::new("UNIMPLEMENTED", format!("Unknown method {other:?}."))),
        }
    }

    /// One request to one reply body.
    pub async fn handle(&self, request: Request) -> String {
        match self.dispatch(&request).await {
            Ok(payload) => Reply::success(request.id, payload),
            Err(error) => Reply::failure(request.id, &error),
        }
        .to_json()
    }

    /// Parses a frame body. An object with a usable `id` that is otherwise unusable gets an error reply; anything else
    /// has nobody to answer and ends the session.
    fn parse(body: &[u8]) -> Result<Request, ParseFailure> {
        let value: serde_json::Value =
            serde_json::from_slice(body).map_err(|error| ParseFailure::Fatal(format!("invalid JSON: {error}")))?;
        let id = value
            .get("id")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| ParseFailure::Fatal("the request has no integer id".into()))?;
        serde_json::from_value::<Request>(value)
            .map_err(|error| ParseFailure::Reply(Reply::failure(id, &CallError::new("INVALID_ARGUMENT", error.to_string())).to_json()))
    }
}

enum ParseFailure {
    Reply(String),
    Fatal(String),
}

enum Incoming {
    Body(Vec<u8>),
    End,
    Failed(HostError),
}

/// Serves one browser connection until it ends. `input` and `output` are the native-messaging streams.
///
/// Reading and writing run on their own threads; each request runs as its own task. When the session ends for any
/// reason the runtime is stopped before this returns, so no worker outlives the connection.
pub async fn run_session(
    mut input: impl Read + Send + 'static,
    mut output: impl Write + Send + 'static,
    controller: Controller,
) -> Result<(), HostError> {
    let (incoming_tx, mut incoming) = mpsc::unbounded_channel();
    std::thread::Builder::new()
        .name("native-reader".into())
        .spawn(move || {
            loop {
                match native_host::read_frame(&mut input) {
                    Ok(Some(body)) => {
                        if incoming_tx.send(Incoming::Body(body)).is_err() {
                            return;
                        }
                    }
                    Ok(None) => {
                        let _ = incoming_tx.send(Incoming::End);
                        return;
                    }
                    Err(error) => {
                        let _ = incoming_tx.send(Incoming::Failed(error));
                        return;
                    }
                }
            }
        })
        .map_err(|error| HostError::Io(error.to_string()))?;

    let (outgoing_tx, outgoing_rx) = std::sync::mpsc::channel::<String>();
    let writer = std::thread::Builder::new()
        .name("native-writer".into())
        .spawn(move || {
            while let Ok(body) = outgoing_rx.recv() {
                if native_host::write_frame(&mut output, body.as_bytes()).is_err() {
                    return;
                }
            }
        })
        .map_err(|error| HostError::Io(error.to_string()))?;

    let controller = Arc::new(controller);
    let outcome = loop {
        match incoming.recv().await {
            Some(Incoming::Body(body)) => match Controller::parse(&body) {
                Ok(request) => {
                    let (controller, outgoing) = (Arc::clone(&controller), outgoing_tx.clone());
                    tokio::spawn(async move {
                        let _ = outgoing.send(controller.handle(request).await);
                    });
                }
                Err(ParseFailure::Reply(reply)) => {
                    let _ = outgoing_tx.send(reply);
                }
                Err(ParseFailure::Fatal(message)) => break Err(HostError::Protocol(message)),
            },
            Some(Incoming::End) | None => break Ok(()),
            Some(Incoming::Failed(error)) => break Err(error),
        }
    };

    // Whatever ended the session, the worker goes with it.
    controller.runtime.shutdown().await;
    drop(outgoing_tx);
    let _ = tokio::time::timeout(Duration::from_secs(2), tokio::task::spawn_blocking(move || writer.join())).await;
    outcome
}
