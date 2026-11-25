//! Shared helpers of the `open_*` tests: the Python golden, the stage 0 prompts and an in-process HTTP server.

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use serde_json::Value;

/// The placeholder key of every test (not a credential).
pub const PLACEHOLDER_KEY: &str = "PLACEHOLDER";

pub fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

pub fn read_json(path: &std::path::Path) -> Value {
    let text = std::fs::read_to_string(path).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

/// `tests/fixtures/open_classifier_golden.json`, made by `evaluation/generate_open_classifier_golden.py`.
pub fn golden() -> Value {
    read_json(&manifest_dir().join("tests/fixtures/open_classifier_golden.json"))
}

/// The stage 0 worker-frame prompt with this id.
pub fn corpus_prompt(id: &str) -> String {
    let path = manifest_dir().join("../../../tests/conformance/worker-frames/prompts.json");
    let corpus = read_json(&path);
    corpus["prompts"]
        .as_array()
        .and_then(|prompts| prompts.iter().find(|prompt| prompt["id"] == id))
        .and_then(|prompt| prompt["text"].as_str())
        .unwrap_or_else(|| panic!("no corpus prompt {id}"))
        .to_string()
}

/// A lookup over a fixed list of variables, as `OpenConfig::resolve` takes it.
pub fn env_of(pairs: Vec<(String, String)>) -> impl Fn(&str) -> Option<String> {
    move |name| pairs.iter().find(|(key, _)| key == name).map(|(_, value)| value.clone())
}

/// What the server saw.
#[derive(Debug, Clone)]
pub struct Recorded {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Recorded {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(key, _)| key.eq_ignore_ascii_case(name)).map(|(_, value)| value.as_str())
    }
}

/// One scripted answer.
#[derive(Debug, Clone)]
pub enum Reply {
    Respond {
        status: u16,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    },
    /// Accept the request and never answer.
    Hang,
}

impl Reply {
    pub fn json(status: u16, body: &str) -> Self {
        Self::Respond { status, headers: Vec::new(), body: body.as_bytes().to_vec() }
    }
}

/// A loopback HTTP/1.1 server that records each request and replays the script (the last reply repeats).
#[derive(Debug)]
pub struct MockServer {
    pub addr: SocketAddr,
    pub requests: Arc<Mutex<Vec<Recorded>>>,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl MockServer {
    pub fn start(script: Vec<Reply>) -> Self {
        assert!(!script.is_empty());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let handle = {
            let (requests, stop) = (Arc::clone(&requests), Arc::clone(&stop));
            std::thread::spawn(move || serve(&listener, &script, &requests, &stop))
        };
        Self { addr, requests, stop, handle: Some(handle) }
    }

    /// `http://127.0.0.1:<port>/v1`.
    pub fn base_url(&self) -> String {
        format!("http://{}/v1", self.addr)
    }

    pub fn recorded(&self) -> Vec<Recorded> {
        self.requests.lock().unwrap().clone()
    }
}

impl Drop for MockServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn serve(listener: &TcpListener, script: &[Reply], requests: &Arc<Mutex<Vec<Recorded>>>, stop: &Arc<AtomicBool>) {
    let mut served = 0usize;
    let mut workers = Vec::new();
    while !stop.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _)) => {
                let reply = script[served.min(script.len() - 1)].clone();
                served += 1;
                let (requests, stop) = (Arc::clone(requests), Arc::clone(stop));
                workers.push(std::thread::spawn(move || handle(stream, &reply, &requests, &stop)));
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => std::thread::sleep(Duration::from_millis(2)),
            Err(_) => break,
        }
    }
    for worker in workers {
        let _ = worker.join();
    }
}

fn handle(mut stream: TcpStream, reply: &Reply, requests: &Arc<Mutex<Vec<Recorded>>>, stop: &Arc<AtomicBool>) {
    stream.set_nonblocking(false).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let Some(recorded) = read_request(&mut stream) else {
        return;
    };
    requests.lock().unwrap().push(recorded);
    match reply {
        Reply::Respond { status, headers, body } => {
            let mut head = format!(
                "HTTP/1.1 {status} Reply\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n",
                body.len()
            );
            for (name, value) in headers {
                head.push_str(&format!("{name}: {value}\r\n"));
            }
            head.push_str("\r\n");
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.write_all(body);
            let _ = stream.flush();
        }
        Reply::Hang => {
            let started = Instant::now();
            while !stop.load(Ordering::SeqCst) && started.elapsed() < Duration::from_secs(10) {
                std::thread::sleep(Duration::from_millis(5));
            }
        }
    }
}

fn read_request(stream: &mut TcpStream) -> Option<Recorded> {
    let mut data = Vec::new();
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        if let Some(position) = data.windows(4).position(|window| window == b"\r\n\r\n") {
            break position;
        }
        let read = stream.read(&mut chunk).ok()?;
        if read == 0 {
            return None;
        }
        data.extend_from_slice(&chunk[..read]);
    };
    let head = String::from_utf8_lossy(&data[..head_end]).to_string();
    let mut lines = head.split("\r\n");
    let mut request_line = lines.next()?.split(' ');
    let method = request_line.next()?.to_string();
    let path = request_line.next()?.to_string();
    let headers: Vec<(String, String)> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_string()))
        .collect();
    let length: usize = headers.iter().find(|(name, _)| name == "content-length").and_then(|(_, value)| value.parse().ok()).unwrap_or(0);
    let mut body = data[head_end + 4..].to_vec();
    while body.len() < length {
        let read = stream.read(&mut chunk).ok()?;
        if read == 0 {
            return None;
        }
        body.extend_from_slice(&chunk[..read]);
    }
    body.truncate(length);
    Some(Recorded { method, path, headers, body })
}
