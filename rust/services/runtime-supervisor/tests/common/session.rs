//! A native-messaging client for the controller: starts the real `privoke-supervisor native-host` process and speaks
//! the frames a browser would.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{Receiver, channel};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use privoke_contracts::proto::v1::{AnalyzePromptRequest, AnalyzePromptResponse, RuntimeControlStatus, SetRuntimeEnabledRequest};
use prost::Message;
use serde_json::{Value, json};

pub const SUPERVISOR: &str = env!("CARGO_BIN_EXE_privoke-supervisor");
pub const TEST_WORKER: &str = env!("CARGO_BIN_EXE_privoke-supervisor-test-worker");

pub const LAYER_REGEX: i32 = 2;
pub const LAYER_NER: i32 = 3;
pub const LAYER_SEMANTIC: i32 = 4;

/// A running controller and the browser's side of its port.
pub struct Host {
    pub child: Child,
    stdin: Option<ChildStdin>,
    replies: Receiver<Option<Value>>,
    _root: tempfile::TempDir,
}

pub struct HostOptions {
    /// Stand-in worker mode, or `None` to run the real Python worker (`python` must then be set).
    pub mode: Option<&'static str>,
    pub python: Option<PathBuf>,
    pub env: Vec<(&'static str, String)>,
}

impl Default for HostOptions {
    fn default() -> Self {
        Self { mode: Some("ok"), python: None, env: Vec::new() }
    }
}

impl Host {
    pub fn start(options: HostOptions) -> Self {
        Self::start_in(options, None)
    }

    pub fn start_in(options: HostOptions, repository_root: Option<&Path>) -> Self {
        let root = tempfile::tempdir().unwrap();
        let mut command = Command::new(SUPERVISOR);
        command.arg("native-host").stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null());
        command.env("PRIVOKE_REPOSITORY_ROOT", repository_root.unwrap_or_else(|| root.path()));
        command.env("PRIVOKE_CREDENTIAL_DIR", root.path().join("credentials")).env("MODEL_PACKAGE_CACHE_DIR", root.path().join("cache"));
        command.env_remove("PRIVOKE_CLOUD_TARGET").env_remove("PRIVOKE_CLOUD_MODEL_TARGET").env_remove("PRIVOKE_USE_LOCAL_STACK");
        if let Some(mode) = options.mode {
            command.env("PRIVOKE_TEST_WORKER_COMMAND", [TEST_WORKER, mode].join("\u{1f}"));
        }
        if let Some(python) = &options.python {
            command.env("PRIVOKE_RUNTIME_PYTHON", python);
        }
        for (name, value) in &options.env {
            command.env(name, value);
        }
        let mut child = command.spawn().unwrap();
        let stdin = child.stdin.take();
        let mut stdout = child.stdout.take().unwrap();
        let (sender, replies) = channel();
        std::thread::spawn(move || {
            loop {
                let mut header = [0u8; 4];
                if stdout.read_exact(&mut header).is_err() {
                    let _ = sender.send(None);
                    return;
                }
                let mut body = vec![0u8; u32::from_ne_bytes(header) as usize];
                if stdout.read_exact(&mut body).is_err() {
                    let _ = sender.send(None);
                    return;
                }
                if sender.send(Some(serde_json::from_slice(&body).unwrap())).is_err() {
                    return;
                }
            }
        });
        Self { child, stdin, replies, _root: root }
    }

    pub fn send_raw(&mut self, body: &[u8]) {
        let stdin = self.stdin.as_mut().unwrap();
        // The controller may end the session at the header, before the body is read, so a broken pipe is not a failure.
        let _ = stdin.write_all(&u32::try_from(body.len()).unwrap().to_ne_bytes());
        let _ = stdin.write_all(body);
        let _ = stdin.flush();
    }

    pub fn send(&mut self, value: &Value) {
        self.send_raw(value.to_string().as_bytes());
    }

    /// The next reply, or `None` when the controller closed its output (or nothing came within the timeout).
    pub fn recv(&mut self, timeout: Duration) -> Option<Value> {
        self.replies.recv_timeout(timeout).unwrap_or_default()
    }

    pub fn request(&mut self, id: u64, method: &str, payload: Option<&[u8]>) {
        let mut value = json!({"v": 1, "id": id, "method": method});
        if let Some(payload) = payload {
            value["payload"] = Value::String(STANDARD.encode(payload));
        }
        self.send(&value);
    }

    /// One request and its reply, assuming nothing else is in flight.
    pub fn call(&mut self, id: u64, method: &str, payload: Option<&[u8]>) -> Value {
        self.request(id, method, payload);
        let reply = self.recv(Duration::from_secs(90)).expect("a reply");
        assert_eq!(reply["id"], id);
        reply
    }

    pub fn set_enabled(&mut self, id: u64, enabled: bool) -> RuntimeControlStatus {
        let request = SetRuntimeEnabledRequest { enabled, use_local_stack: None }.encode_to_vec();
        let reply = self.call(id, "SetRuntimeEnabled", Some(&request));
        assert_eq!(reply["ok"], true, "{reply}");
        decode(&reply)
    }

    pub fn status(&mut self, id: u64) -> RuntimeControlStatus {
        let reply = self.call(id, "Status", Some(&[]));
        assert_eq!(reply["ok"], true, "{reply}");
        decode(&reply)
    }

    pub fn analyze_request(&mut self, id: u64, text: &str, layers: &[i32]) {
        let request =
            AnalyzePromptRequest { text: text.into(), request_id: format!("r{id}"), layers: layers.to_vec(), ..Default::default() };
        self.request(id, "AnalyzePrompt", Some(&request.encode_to_vec()));
    }

    pub fn analyze(&mut self, id: u64, text: &str, layers: &[i32]) -> Value {
        self.analyze_request(id, text, layers);
        let reply = self.recv(Duration::from_secs(90)).expect("a reply");
        assert_eq!(reply["id"], id);
        reply
    }

    pub fn kill(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }

    pub fn close_input(&mut self) {
        self.stdin = None;
    }

    pub fn wait_exit(&mut self, timeout: Duration) -> Option<std::process::ExitStatus> {
        let deadline = std::time::Instant::now() + timeout;
        while std::time::Instant::now() < deadline {
            if let Some(status) = self.child.try_wait().unwrap() {
                return Some(status);
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        None
    }
}

impl Drop for Host {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub fn decode<M: Message + Default>(reply: &Value) -> M {
    M::decode(STANDARD.decode(reply["payload"].as_str().expect("a payload")).unwrap().as_slice()).unwrap()
}

pub fn analysis(reply: &Value) -> AnalyzePromptResponse {
    assert_eq!(reply["ok"], true, "{reply}");
    decode(reply)
}

/// The Python of the client runtime's virtual environment, from this checkout or the main checkout that owns this
/// linked worktree. `PRIVOKE_TEST_RUNTIME_PYTHON` overrides. `None` when there is none, and the real-worker test skips.
pub fn runtime_python() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("PRIVOKE_TEST_RUNTIME_PYTHON").filter(|value| !value.is_empty()) {
        return Some(path.into());
    }
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let relative = ["extension/client-runtime/.venv/Scripts/python.exe", "extension/client-runtime/.venv/bin/python"];
    for candidate in relative.iter().map(|path| root.join(path)) {
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    let pointer = std::fs::read_to_string(root.join(".git")).ok()?;
    let git_dir = PathBuf::from(pointer.trim().strip_prefix("gitdir:")?.trim());
    let main = git_dir.parent()?.parent()?.parent()?.to_path_buf();
    relative.iter().map(|path| main.join(path)).find(|candidate| candidate.is_file())
}

/// The repository root that holds the client runtime sources: this checkout.
pub fn repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..").canonicalize().unwrap()
}

/// The listening TCP sockets owned by `pid`, from the operating system.
pub fn listening_sockets(pid: u32) -> Vec<String> {
    if cfg!(windows) {
        let output = Command::new("netstat").args(["-ano", "-p", "tcp"]).output().unwrap();
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter(|line| line.contains("LISTENING") && line.split_whitespace().last() == Some(&pid.to_string()))
            .map(|line| line.trim().to_string())
            .collect()
    } else {
        let mut inodes = Vec::new();
        if let Ok(entries) = std::fs::read_dir(format!("/proc/{pid}/fd")) {
            for entry in entries.flatten() {
                if let Ok(target) = std::fs::read_link(entry.path())
                    && let Some(inode) = target.to_string_lossy().strip_prefix("socket:[")
                {
                    inodes.push(inode.trim_end_matches(']').to_string());
                }
            }
        }
        ["tcp", "tcp6"]
            .iter()
            .filter_map(|table| std::fs::read_to_string(format!("/proc/{pid}/net/{table}")).ok())
            .flat_map(|text| text.lines().skip(1).map(str::to_string).collect::<Vec<_>>())
            .filter(|line| {
                let fields: Vec<_> = line.split_whitespace().collect();
                fields.get(3) == Some(&"0A") && fields.get(9).is_some_and(|inode| inodes.iter().any(|owned| owned == inode))
            })
            .collect()
    }
}
