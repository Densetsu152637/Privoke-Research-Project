//! Replay of the stage 0 native-messaging transcripts (`tests/conformance/native_messaging.json`).
//!
//! Every transcript is replayed twice: through the library (`native_host::serve` on in-memory streams) and through
//! the real `privoke-supervisor native-host` process over its stdin and stdout. The bytes written must equal the
//! recorded bytes. The three recorded cases that depend on the machine are given the state they were recorded in
//! (a listener on the bridge port; a listener on the control port; a supervisor entry that does not exist).
//!
//! Normalisation, as in `tests/conformance/normalization.toml`: `<ROOT>` stands for the repository root and path
//! separators are `/`. One more, specific to this host: the recording used the real ports 8080 and 50056, and the
//! replay must not take them (a real runtime may hold them), so it listens on ephemeral ports and the two numbers in
//! the control-port message are mapped back to 8080 and 50056 before the frame is rebuilt and compared. The frame
//! length is recomputed from the normalised body, so the framing is still compared byte for byte.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::io::Cursor;
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use common::{free_port, hex_decode};
use privoke_supervisor::native_host::{self, HostConfig};
use serde_json::Value;

const BINARY: &str = env!("CARGO_BIN_EXE_privoke-supervisor");

fn transcripts() -> Vec<Value> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../tests/conformance/native_messaging.json");
    let document: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    assert_eq!(document["schema"], 1);
    assert_eq!(document["max_message_bytes"], native_host::MAX_MESSAGE_BYTES);
    assert_eq!(document["host_name"], native_host::HOST_NAME);
    document["transcripts"].as_array().unwrap().clone()
}

/// What state to give the host so that it meets the situation the transcript recorded.
struct Scene {
    bridge_port: u16,
    control_port: u16,
    entry: PathBuf,
    root: PathBuf,
    _held: Vec<TcpListener>,
}

fn scene(label: &str, root: &std::path::Path) -> Scene {
    let mut held = Vec::new();
    let mut hold = || {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        held.push(listener);
        port
    };
    let (bridge_port, control_port) = match label {
        "bridge-already-running" | "two-messages-in-sequence" => (hold(), free_port()),
        "control-port-conflict" => (free_port(), hold()),
        _ => (free_port(), free_port()),
    };
    // The entry the Python host looked for; it never exists in the replay.
    let entry = root.join("extension").join("runtime-supervisor").join("src").join("main.py");
    Scene { bridge_port, control_port, entry, root: root.to_path_buf(), _held: held }
}

impl Scene {
    fn host_config(&self) -> HostConfig {
        let mut host = HostConfig::standard(self.entry.clone(), Some(self.root.clone()), self.root.join("supervisor.log"));
        host.bridge_port = self.bridge_port;
        host.control_port = self.control_port;
        host
    }
}

/// Map a captured output back to the recorded world: ports, `<ROOT>`, separators. Returns the rebuilt byte stream.
fn normalise(output: &[u8], scene: &Scene) -> Vec<u8> {
    let mut rebuilt = Vec::new();
    let mut rest = output;
    while !rest.is_empty() {
        let length = u32::from_ne_bytes(rest[..4].try_into().unwrap()) as usize;
        assert!(rest.len() - 4 >= length, "frame length exceeds the output");
        let body = std::str::from_utf8(&rest[4..4 + length]).unwrap().to_string();
        let root = scene.root.to_string_lossy().replace('\\', "/");
        let body = body
            .replace("\\\\", "/")
            .replace(&root, "<ROOT>")
            .replace(&format!("port {}", scene.control_port), "port 50056")
            .replace(&format!("port {}", scene.bridge_port), "port 8080");
        rebuilt.extend_from_slice(&u32::try_from(body.len()).unwrap().to_ne_bytes());
        rebuilt.extend_from_slice(body.as_bytes());
        rest = &rest[4 + length..];
    }
    rebuilt
}

fn expected_bytes(transcript: &Value) -> Vec<u8> {
    let recorded = transcript["response_hex"].as_str().unwrap();
    if recorded == "normalised-see-responses" {
        // Rebuild it from the recorded reply object: the host writes ok, started, message.
        let reply = &transcript["responses"][0];
        let body = format!(
            "{{\"ok\":{},\"started\":{},\"message\":{}}}",
            reply["ok"],
            reply["started"],
            native_host_string(reply["message"].as_str().unwrap())
        );
        let mut bytes = u32::try_from(body.len()).unwrap().to_ne_bytes().to_vec();
        bytes.extend_from_slice(body.as_bytes());
        return bytes;
    }
    hex_decode(recorded)
}

fn native_host_string(text: &str) -> String {
    privoke_supervisor::pyjson::dump_string(text)
}

fn expected_error(transcript: &Value) -> Option<(&str, bool)> {
    let error = transcript.get("error")?;
    Some((error["message"].as_str().unwrap(), error.get("message_is_informational").and_then(Value::as_bool).unwrap_or(false)))
}

#[test]
fn every_transcript_replays_through_the_library() {
    let transcripts = transcripts();
    assert_eq!(transcripts.len(), 17);
    let root = tempfile::tempdir().unwrap();
    let mut replayed = 0;
    for transcript in &transcripts {
        let label = transcript["label"].as_str().unwrap();
        let scene = scene(label, root.path());
        let request = hex_decode(transcript["request_hex"].as_str().unwrap());
        let mut output = Vec::new();
        let outcome = native_host::serve(&mut Cursor::new(request), &mut output, &scene.host_config());
        match expected_error(transcript) {
            Some((message, informational)) => {
                let error = outcome.expect_err(label).to_string();
                if !informational {
                    assert_eq!(error, message, "{label}");
                }
                assert_eq!(output, Vec::<u8>::new(), "{label}: an error writes no reply");
            }
            None => {
                outcome.expect(label);
                assert_eq!(normalise(&output, &scene), expected_bytes(transcript), "{label}");
            }
        }
        replayed += 1;
    }
    assert_eq!(replayed, 17);
}

#[test]
fn every_transcript_replays_through_the_binary() {
    let transcripts = transcripts();
    let root = tempfile::tempdir().unwrap();
    let mut replayed = 0;
    for transcript in &transcripts {
        let label = transcript["label"].as_str().unwrap();
        let scene = scene(label, root.path());
        let request = hex_decode(transcript["request_hex"].as_str().unwrap());
        let mut child = Command::new(BINARY)
            // Browsers start the host with only the calling origin, no subcommand; it must be ignored.
            .arg("chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/")
            .env("PRIVOKE_TEST_HOST_BRIDGE_PORT", scene.bridge_port.to_string())
            .env("PRIVOKE_TEST_HOST_CONTROL_PORT", scene.control_port.to_string())
            .env("PRIVOKE_TEST_HOST_ENTRY", &scene.entry)
            .env("PRIVOKE_REPOSITORY_ROOT", &scene.root)
            .env("PRIVOKE_SUPERVISOR_LOG", scene.root.join("supervisor.log"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        {
            use std::io::Write;
            let mut stdin = child.stdin.take().unwrap();
            stdin.write_all(&request).unwrap();
        }
        let result = child.wait_with_output().unwrap();
        match expected_error(transcript) {
            Some((message, informational)) => {
                assert_eq!(result.status.code(), Some(1), "{label}");
                assert!(result.stdout.is_empty(), "{label}: an error writes no reply");
                let stderr = String::from_utf8_lossy(&result.stderr);
                if !informational {
                    assert_eq!(stderr.trim(), message, "{label}");
                }
            }
            None => {
                assert!(result.status.success(), "{label}: {}", String::from_utf8_lossy(&result.stderr));
                assert_eq!(normalise(&result.stdout, &scene), expected_bytes(transcript), "{label}");
            }
        }
        replayed += 1;
    }
    assert_eq!(replayed, 17);
}

#[test]
fn the_action_is_matched_exactly_and_unknown_json_forms_are_unsupported_not_crashes() {
    // Beyond the recorded transcripts: shapes Python's json.loads accepts and serde_json would not.
    let root = tempfile::tempdir().unwrap();
    let scene = scene("unsupported-action", root.path());
    let unsupported = native_host::Reply {
        ok: false,
        started: false,
        process_id: None,
        message: "Unsupported native launcher request.".into(),
        log_path: None,
    }
    .to_json();
    for body in [
        r#"{"action":NaN}"#,
        r#"{"action":"\ud83d"}"#,
        r#"{"action":"ensure_supervisor ","x":1e999}"#,
        r#"{"action":"Ensure_Supervisor"}"#,
        r#"{"action":["ensure_supervisor"]}"#,
        r#"{"ACTION":"ensure_supervisor"}"#,
        "12345678901234567890123456789",
        r#""just a string""#,
    ] {
        let mut request = u32::try_from(body.len()).unwrap().to_ne_bytes().to_vec();
        request.extend_from_slice(body.as_bytes());
        let mut output = Vec::new();
        native_host::serve(&mut Cursor::new(request), &mut output, &scene.host_config()).unwrap();
        assert_eq!(&output[4..], unsupported.as_bytes(), "{body}");
    }
}

#[test]
fn reply_text_is_ascii_escaped_like_python() {
    let reply = native_host::Reply {
        ok: false,
        started: false,
        process_id: None,
        message: "caf\u{e9} \u{4e2d} \u{1f600} \"q\" \\".into(),
        log_path: Some("C:\\Users\\x".into()),
    };
    assert_eq!(
        reply.to_json(),
        r#"{"ok":false,"started":false,"message":"caf\u00e9 \u4e2d \ud83d\ude00 \"q\" \\","log_path":"C:\\Users\\x"}"#
    );
}
