//! The worker as the W2 pool runs it: a child process speaking pool frames on stdin and stdout, each carrying one W1
//! frame. spaCy is the Python-free stand-in engine (`--spacy fake`), so the test needs no interpreter; the real
//! interpreter is the stage 23 bundle test.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::{BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use privoke_contracts::proto::v1::{
    AnalyzePromptRequest, AnalyzePromptResponse, ComputeSemanticGradientsResponse, DetectAnnotationPresenceRequest,
    DetectAnnotationPresenceResponse, RuntimeHealthRequest, RuntimeHealthResponse,
};
use privoke_runtime::frames::{self, HEADER_LEN, Kind, code};
use privoke_worker_pool::{read_frame_sync, write_frame_sync};
use prost::Message;

struct Worker {
    child: Child,
    input: Option<ChildStdin>,
    output: BufReader<ChildStdout>,
    next_id: u64,
}

impl Drop for Worker {
    fn drop(&mut self) {
        // Never leave a process behind, whatever the test did.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn spawn(extra: &[&str], environment: &[(&str, &str)]) -> Worker {
    let mut command = Command::new(env!("CARGO_BIN_EXE_privoke-runtime-worker"));
    command.args(["--spacy", "fake", "--warm-layers", "regex"]).args(extra);
    for (name, value) in environment {
        command.env(name, value);
    }
    let mut child = command.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().expect("the worker starts");
    let input = child.stdin.take();
    let output = BufReader::new(child.stdout.take().expect("stdout is piped"));
    Worker { child, input, output, next_id: 100 }
}

/// A decoded frame: kind, request id and payload.
struct Frame {
    kind: u8,
    request_id: u64,
    payload: Vec<u8>,
}

impl Worker {
    fn read(&mut self) -> Frame {
        let frame = read_frame_sync(&mut self.output).expect("the worker answers");
        assert!(frame.len() >= HEADER_LEN);
        let mut id = [0u8; 8];
        id.copy_from_slice(&frame[8..16]);
        Frame { kind: frame[5], request_id: u64::from_be_bytes(id), payload: frame[HEADER_LEN..].to_vec() }
    }

    fn send_raw(&mut self, pool_frame: &[u8]) {
        let input = self.input.as_mut().expect("stdin is open");
        write_frame_sync(input, pool_frame).expect("the worker reads");
        input.flush().unwrap();
    }

    fn call(&mut self, method: u8, payload: &[u8]) -> Frame {
        self.next_id += 1;
        let id = self.next_id;
        self.send_raw(&frames::encode_frame(Kind::Request, method, id, payload));
        let answer = self.read();
        assert_eq!(answer.request_id, id);
        answer
    }

    fn analyze(&mut self, request: &AnalyzePromptRequest) -> Frame {
        self.call(1, &request.encode_to_vec())
    }
}

fn error_code(frame: &Frame) -> String {
    assert_eq!(frame.kind, Kind::Error as u8, "{}", String::from_utf8_lossy(&frame.payload));
    let body: serde_json::Value = serde_json::from_slice(&frame.payload).expect("the error body is JSON");
    body["code"].as_str().expect("a code").to_owned()
}

fn prompt(text: &str, layers: &[i32]) -> AnalyzePromptRequest {
    AnalyzePromptRequest { text: text.to_owned(), layers: layers.to_vec(), request_id: "t".into(), ..AnalyzePromptRequest::default() }
}

#[test]
fn ready_then_health_and_analysis() {
    let mut worker = spawn(&[], &[]);
    let ready = worker.read();
    assert_eq!((ready.kind, ready.request_id), (Kind::Ready as u8, 0));
    let announcement: serde_json::Value = serde_json::from_slice(&ready.payload).unwrap();
    assert_eq!(announcement["protocol_version"], 1);
    assert_eq!(announcement["implementation"], "privoke-client-runtime-rust");
    assert_eq!(announcement["telemetry"], "disabled");
    assert_eq!(announcement["loaded"], serde_json::json!(["regex"]));
    assert_eq!(announcement["limits"]["AnalyzePrompt"]["max_request_payload"], 262_144);

    let health = worker.call(3, &RuntimeHealthRequest {}.encode_to_vec());
    assert_eq!(health.kind, Kind::Response as u8);
    let health = RuntimeHealthResponse::decode(health.payload.as_slice()).unwrap();
    assert_eq!((health.service.as_str(), health.status.as_str()), ("client-runtime", "SERVING"));

    // The regex layer finds the address and the analysis warns or blocks on it.
    let regex = worker.analyze(&prompt("Please write to alice.smith@example.com today.", &[2]));
    assert_eq!(regex.kind, Kind::Response as u8);
    let response = AnalyzePromptResponse::decode(regex.payload.as_slice()).unwrap();
    assert_eq!(response.request_id, "t");
    assert_eq!(response.layers.len(), 1);
    assert_eq!((response.layers[0].layer, response.layers[0].status.as_str()), (2, "ok"));
    assert!(!response.layers[0].results.is_empty() && response.evidence.is_some(), "{response:?}");
    assert_ne!(response.action, "ALLOW");
    assert!(response.metadata.contains_key("elapsed_ms") && response.elapsed_ms > 0.0);

    // The NER layer runs in this process, on the stand-in engine.
    let ner = worker.analyze(&prompt("We met in Paris last week", &[3]));
    let response = AnalyzePromptResponse::decode(ner.payload.as_slice()).unwrap();
    assert_eq!((response.layers[0].layer, response.layers[0].status.as_str()), (3, "ok"), "{response:?}");
}

#[test]
fn never_runs_an_implicit_pipeline_and_refuses_what_it_does_not_serve() {
    let mut worker = spawn(&[], &[]);
    worker.read();
    assert_eq!(error_code(&worker.analyze(&prompt("hello", &[]))), code::INVALID_LAYERS);
    assert_eq!(error_code(&worker.analyze(&prompt("hello", &[1]))), code::INVALID_LAYERS);
    assert_eq!(error_code(&worker.analyze(&prompt("hello", &[2, 4]))), code::UNSUPPORTED_LAYERS);
    // Without model roots the worker reads no model: what needs one is refused before it runs, and the controller sends it
    // to the Python worker. An empty layer list is refused whatever the roots are.
    let presence = DetectAnnotationPresenceRequest {
        request_id: "p".into(),
        text: "my passport".into(),
        model_id: "privoke-presence-efficient".into(),
        layers: vec![4],
    };
    assert_eq!(error_code(&worker.call(2, &presence.encode_to_vec())), code::UNSUPPORTED_ROUTE);
    assert_eq!(error_code(&worker.call(2, b"")), code::INVALID_LAYERS);
    for method in [4, 5, 6] {
        assert_eq!(error_code(&worker.call(method, b"")), code::UNSUPPORTED_ROUTE);
    }
    assert_eq!(error_code(&worker.call(1, &[0xff, 0xff, 0xff])), code::INVALID_PAYLOAD);
    // A validation failure is an ordinary response with its error set, under the request's own id.
    let empty = worker.analyze(&prompt("   ", &[2]));
    assert_eq!(empty.kind, Kind::Response as u8);
    let response = AnalyzePromptResponse::decode(empty.payload.as_slice()).unwrap();
    assert_eq!((response.request_id.as_str(), response.error.as_str()), ("t", "Prompt text must not be empty."));
    // The worker is still serving.
    assert_eq!(worker.call(3, b"").kind, Kind::Response as u8);
}

#[test]
fn malformed_frames_get_an_error_frame_and_the_worker_survives() {
    let mut worker = spawn(&[], &[]);
    worker.read();
    worker.send_raw(b"short");
    assert_eq!(error_code(&worker.read()), code::MALFORMED_FRAME);
    let mut wrong_version = frames::encode_frame(Kind::Request, 3, 5, b"");
    wrong_version[4] = 9;
    worker.send_raw(&wrong_version);
    let answer = worker.read();
    assert_eq!(answer.request_id, 5);
    assert_eq!(error_code(&answer), code::UNSUPPORTED_VERSION);
    assert_eq!(worker.call(3, b"").kind, Kind::Response as u8);
}

#[test]
fn the_text_limit_is_an_option_and_closing_the_pipe_ends_the_worker_cleanly() {
    let mut worker = spawn(&["--max-text-chars", "10"], &[]);
    worker.read();
    let long = worker.analyze(&prompt("this prompt is longer than ten characters", &[2]));
    let response = AnalyzePromptResponse::decode(long.payload.as_slice()).unwrap();
    assert_eq!(response.error, "Prompt text exceeds 10 characters.");
    drop(worker.input.take());
    let status = worker.child.wait().expect("the worker exits");
    assert_eq!(status.code(), Some(0));
}

#[test]
fn the_sandbox_self_check_refuses_a_process_that_can_open_sockets() {
    let mut worker = spawn(&[], &[("PRIVOKE_WORKER_SANDBOX", "1")]);
    let first = worker.read();
    if first.kind == Kind::Ready as u8 {
        // An operating system that denies sockets to this process: the check passed.
        let announcement: serde_json::Value = serde_json::from_slice(&first.payload).unwrap();
        assert_eq!(announcement["sandbox_self_check"], "passed");
    } else {
        assert_eq!(error_code(&first), code::SANDBOX_VIOLATION);
        assert_eq!(worker.child.wait().expect("the worker exits").code(), Some(3));
    }
}

#[test]
fn a_bad_command_line_is_a_usage_error() {
    let status = Command::new(env!("CARGO_BIN_EXE_privoke-runtime-worker"))
        .args(["--spacy", "fake", "--warm-layers", "semantic"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("the worker runs");
    assert_eq!(status.code(), Some(2));
}

#[test]
fn with_model_roots_the_worker_serves_and_warms_the_semantic_layer() {
    let models = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../models");
    let models = models.to_string_lossy().into_owned();
    let mut worker = spawn(&["--model-root", &models, "--warm-semantic-model", "privoke-balanced"], &[]);
    let ready = worker.read();
    assert_eq!(ready.kind, Kind::Ready as u8, "{}", String::from_utf8_lossy(&ready.payload));
    let announcement: serde_json::Value = serde_json::from_slice(&ready.payload).unwrap();
    assert_eq!(announcement["loaded"], serde_json::json!(["regex", "semantic:privoke-balanced"]));

    let mut request = prompt("I was diagnosed with type 2 diabetes last March and take metformin daily.", &[4]);
    request.semantic_model_id = "privoke-balanced".into();
    let answer = worker.analyze(&request);
    let response = AnalyzePromptResponse::decode(answer.payload.as_slice()).unwrap();
    assert_eq!(response.error, "");
    assert_eq!(response.layers.len(), 1);
    assert_eq!((response.layers[0].layer, response.layers[0].status.as_str()), (4, "ok"));
    assert_eq!(response.metadata.get("privoke.semantic.model_id").map(String::as_str), Some("privoke-balanced"));
    assert_eq!(response.metadata.get("privoke.semantic.architecture").map(String::as_str), Some("privoke_tiny_transformer_v1"));

    // The model alias has no target, and an unknown model is the layer's error: both block an ALLOW.
    let latest = AnalyzePromptResponse::decode(worker.analyze(&prompt("hello there", &[4])).payload.as_slice()).unwrap();
    assert!(latest.error.contains("latest is not resolvable"), "{latest:?}");
    assert_eq!(latest.action, "BLOCK");
    request.semantic_model_id = "privoke-nope".into();
    let unknown = AnalyzePromptResponse::decode(worker.analyze(&request).payload.as_slice()).unwrap();
    assert!(unknown.error.contains("is not available in the worker model roots"), "{unknown:?}");

    // The pretrained contextual encoder is a semantic model like the others: with no artifact in the roots it is the
    // layer's error, never a decision.
    request.semantic_model_id = "privoke-pretrained-context-minilm".into();
    let contextual = AnalyzePromptResponse::decode(worker.analyze(&request).payload.as_slice()).unwrap();
    assert!(contextual.error.contains("is not available in the worker model roots"), "{contextual:?}");
    assert_eq!(contextual.action, "BLOCK");
}

fn golden_case(id: &str) -> serde_json::Value {
    let fixture: serde_json::Value = serde_json::from_str(include_str!("fixtures/worker_golden.json")).unwrap();
    fixture["cases"].as_array().unwrap().iter().find(|case| case["id"] == id).unwrap_or_else(|| panic!("no case {id}")).clone()
}

impl Worker {
    /// Sends a recorded request (its metadata block included) and returns the answer frame.
    fn replay(&mut self, case: &serde_json::Value) -> Frame {
        self.next_id += 1;
        let id = self.next_id;
        let method = u8::try_from(case["method"].as_u64().unwrap()).unwrap();
        let payload = STANDARD.decode(case["request"].as_str().unwrap()).unwrap();
        let metadata: Vec<(String, String)> = case["metadata"]
            .as_array()
            .unwrap()
            .iter()
            .map(|pair| (pair[0].as_str().unwrap().to_owned(), pair[1].as_str().unwrap().to_owned()))
            .collect();
        let pairs: Vec<(&str, &str)> = metadata.iter().map(|(key, value)| (key.as_str(), value.as_str())).collect();
        let mut body = if pairs.is_empty() { Vec::new() } else { frames::encode_metadata(&pairs) };
        body.extend_from_slice(&payload);
        let mut frame = frames::encode_frame(Kind::Request, method, id, &body);
        if !pairs.is_empty() {
            frame[7] = 1;
        }
        self.send_raw(&frame);
        let answer = self.read();
        assert_eq!(answer.request_id, id);
        answer
    }
}

#[test]
fn with_model_roots_the_worker_serves_presence_and_gradients_and_declines_the_rest() {
    let models = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/worker_models");
    let models = models.to_string_lossy().into_owned();
    let mut worker = spawn(&["--model-root", &models], &[]);
    let ready = worker.read();
    assert_eq!(ready.kind, Kind::Ready as u8, "{}", String::from_utf8_lossy(&ready.payload));

    let presence = worker.replay(&golden_case("privoke-presence-efficient/0"));
    assert_eq!(presence.kind, Kind::Response as u8);
    let presence = DetectAnnotationPresenceResponse::decode(presence.payload.as_slice()).unwrap();
    assert_eq!((presence.error.as_str(), presence.model_id.as_str()), ("", "privoke-presence-efficient"));
    assert!(presence.probability > 0.0 && presence.elapsed_ms > 0.0, "{presence:?}");
    assert_eq!(presence.executions.len(), 1);

    // A gradient request with its admission header in the metadata block, over the pool's framing.
    let gradients = worker.replay(&golden_case("synthetic-legacy-sum/full_encoder"));
    assert_eq!(gradients.kind, Kind::Response as u8, "{}", String::from_utf8_lossy(&gradients.payload));
    let gradients = ComputeSemanticGradientsResponse::decode(gradients.payload.as_slice()).unwrap();
    assert_eq!(gradients.error, "");
    assert_eq!(gradients.metadata.get("training_scope").map(String::as_str), Some("full_encoder"));
    assert!(!gradients.gradients.is_empty() && !gradients.metrics.is_empty());

    // The same request without its header is Python's refusal, as a response.
    let mut without = golden_case("synthetic-legacy-sum/full_encoder");
    without["metadata"] = serde_json::json!([]);
    let refused = ComputeSemanticGradientsResponse::decode(worker.replay(&without).payload.as_slice()).unwrap();
    assert_eq!(refused.error, "Summed-category decision-margin training requires explicit objective admission.");

    // A malformed metadata block is a protocol fault: an error frame, and the worker survives.
    let mut bad = frames::encode_frame(Kind::Request, 4, 5, &[0, 1, 0]);
    bad[7] = 1;
    worker.send_raw(&bad);
    let answer = worker.read();
    assert_eq!((error_code(&answer), answer.request_id), (code::INVALID_METADATA.to_string(), 5));
    assert_eq!(worker.call(3, b"").kind, Kind::Response as u8);
}
