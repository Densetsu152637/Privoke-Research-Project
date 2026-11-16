//! A stand-in for the stage 17 runtime worker: one process that hosts the in-process spaCy backend and speaks the worker
//! frame protocol, so that the W2 pool supervises it exactly as it will supervise the runtime worker.
//!
//! Options: `--engine fake` (default, no Python), or `--bundle DIR [--model NAME]` for the real interpreter (needs the
//! `in-process` feature, and the executable must sit in the bundle directory). `--max-chars N` sets the text limit.
//!
//! The ready frame, the requests and the answers are those of `privoke_spacy::protocol`. Test requests (feature
//! `test-hooks`): `test_crash` crashes the interpreter inside this process, `test_print` prints from Python,
//! `test_children` lists this process's own child processes (Linux). Everything else is the real request path:
//! `analyze` and `lemma_index` go through `InProcess`.

use std::io::{self, Write};
use std::process::ExitCode;
use std::time::Duration;

use privoke_spacy::fake::{FakeEngine, fake_info};
use privoke_spacy::protocol::Selection;
use privoke_spacy::{InProcess, InProcessConfig, SpacyError};
use privoke_worker_pool::{read_frame_sync, worker_side, write_frame_sync};
use serde::Deserialize;

const EXIT_BUNDLE_REFUSED: u8 = 78;

#[derive(Deserialize)]
struct Request {
    id: u64,
    op: String,
    #[serde(default)]
    selection: Option<String>,
    #[serde(default)]
    text: Option<String>,
}

fn arg(name: &str) -> Option<String> {
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        if a == name {
            return args.next();
        }
    }
    None
}

fn start(cfg: &InProcessConfig) -> Result<InProcess, String> {
    if let Some(bundle) = arg("--bundle") {
        let mut real = cfg.clone();
        real.bundle = bundle.into();
        if let Some(model) = arg("--model") {
            real.model = model;
        }
        return InProcess::start(&real).map_err(|e| e.to_string());
    }
    InProcess::start_with(cfg, || Ok((Box::new(FakeEngine) as Box<dyn privoke_spacy::Engine>, fake_info()))).map_err(|e| e.to_string())
}

/// The ids of this process's child processes, from `/proc`. `None` where that is not implemented.
#[cfg(all(target_os = "linux", feature = "test-hooks"))]
fn child_processes() -> Option<Vec<u32>> {
    let me = std::process::id();
    let mut children = Vec::new();
    for entry in std::fs::read_dir("/proc").ok()?.flatten() {
        let Some(pid) = entry.file_name().to_str().and_then(|n| n.parse::<u32>().ok()) else { continue };
        let Ok(stat) = std::fs::read_to_string(entry.path().join("stat")) else { continue };
        // "pid (comm) state ppid ...": comm may hold spaces and parentheses, so split after the last ')'.
        let ppid = stat.rsplit_once(')').and_then(|(_, rest)| rest.split_whitespace().nth(1)).and_then(|v| v.parse::<u32>().ok());
        if ppid == Some(me) {
            children.push(pid);
        }
    }
    Some(children)
}

fn error_reply(id: u64, message: &str) -> String {
    serde_json::json!({"id": id, "ok": false, "error": message}).to_string()
}

fn reply(id: u64, outcome: Result<String, SpacyError>) -> String {
    match outcome {
        Ok(body) => format!(r#"{{"id":{id},"ok":true,"result":{body}}}"#),
        // A failure is reported and the process lives on; only a real crash ends it.
        Err(other) => error_reply(id, &other.to_string()),
    }
}

async fn serve_one(backend: &InProcess, request: Request) -> String {
    let id = request.id;
    match request.op.as_str() {
        "analyze" => match (request.selection.as_deref(), request.text.as_deref()) {
            (Some(selection @ ("full" | "tagger")), Some(text)) => {
                let selection = if selection == "full" { Selection::Full } else { Selection::TaggerOnly };
                reply(id, backend.analyze_raw(text, selection).await.map(|raw| raw.as_str().to_string()))
            }
            _ => error_reply(id, "analyze needs a selection of full or tagger, and a text"),
        },
        "lemma_index" => {
            reply(id, backend.lemma_index().await.map(|words| serde_json::to_string(&*words).unwrap_or_else(|_| "[]".to_string())))
        }
        #[cfg(feature = "test-hooks")]
        "test_crash" => reply(id, backend.run_test_request(&privoke_spacy::protocol::Request::TestCrash { id }).await),
        #[cfg(feature = "test-hooks")]
        "test_print" => reply(id, backend.run_test_request(&privoke_spacy::protocol::Request::TestPrint { id }).await),
        #[cfg(feature = "test-hooks")]
        "test_children" => {
            #[cfg(target_os = "linux")]
            let listed = child_processes().map_or_else(|| "null".to_string(), |c| serde_json::json!(c).to_string());
            #[cfg(not(target_os = "linux"))]
            let listed = "null".to_string();
            reply(id, Ok(listed))
        }
        other => error_reply(id, &format!("unknown op {other:?}")),
    }
}

fn run() -> io::Result<ExitCode> {
    // Frames leave on a duplicate of the original stdout; stdout itself now points at stderr.
    let mut frames = worker_side::claim_frame_output()?;
    let mut cfg = InProcessConfig::default();
    if let Some(n) = arg("--max-chars").and_then(|v| v.parse().ok()) {
        cfg.max_text_chars = n;
    }
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    let backend = match start(&cfg) {
        Ok(backend) => backend,
        Err(reason) => {
            eprintln!("privoke-spacy-host: cannot start: {reason}");
            return Ok(ExitCode::FAILURE);
        }
    };
    if let Err(err) = runtime.block_on(backend.wait_ready(Duration::from_secs(300))) {
        eprintln!("privoke-spacy-host: cannot start: {err}");
        let refused = err.to_string().contains("refused");
        if refused {
            let fatal = serde_json::json!({"type": "fatal", "reason": err.to_string()}).to_string();
            write_frame_sync(&mut frames, fatal.as_bytes())?;
            return Ok(ExitCode::from(EXIT_BUNDLE_REFUSED));
        }
        return Ok(ExitCode::FAILURE);
    }
    let info = backend.worker_info().ok_or_else(|| io::Error::other("ready without an announcement"))?;
    let ready = serde_json::json!({
        "type": "ready", "protocol": info.protocol, "spacy": info.spacy, "model": info.model,
        "model_version": info.model_version, "python": info.python, "lock_sha256": info.lock_sha256,
    });
    write_frame_sync(&mut frames, ready.to_string().as_bytes())?;
    let mut input = io::BufReader::new(io::stdin().lock());
    loop {
        let frame = match read_frame_sync(&mut input) {
            Ok(frame) => frame,
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(ExitCode::SUCCESS),
            Err(e) => return Err(e),
        };
        let request: Request =
            serde_json::from_slice(&frame).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("malformed request: {e}")))?;
        let answer = runtime.block_on(serve_one(&backend, request));
        write_frame_sync(&mut frames, answer.as_bytes())?;
        frames.flush()?;
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(err) => {
            eprintln!("privoke-spacy-host: {err}");
            ExitCode::FAILURE
        }
    }
}
