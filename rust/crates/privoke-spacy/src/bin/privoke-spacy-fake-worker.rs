//! A protocol-compatible stand-in for `privoke-spacy-worker`, with no Python. The pool tests drive it.
//!
//! Options: `--startup-delay-ms N`, `--fatal REASON`, `--exit-at-start`, `--spawn-log PATH`.
//! Text triggers: `CRASH` exits, `HANG` never answers, `SLEEP:<ms>` answers late, `BADID` answers with the wrong id,
//! `ERR` answers with an error. Anything else is split on spaces into tokens, and `Paris` is a `GPE` entity.

use std::io::{self, Read, Write};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn write_frame(out: &mut impl Write, payload: &str) -> io::Result<()> {
    out.write_all(&(payload.len() as u32).to_le_bytes())?;
    out.write_all(payload.as_bytes())?;
    out.flush()
}

fn read_frame(input: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut len = [0u8; 4];
    input.read_exact(&mut len)?;
    let mut payload = vec![0u8; u32::from_le_bytes(len) as usize];
    input.read_exact(&mut payload)?;
    Ok(payload)
}

fn analysis(text: &str, full: bool) -> serde_json::Value {
    let mut tokens = Vec::new();
    let mut ents = Vec::new();
    let mut offset = 0usize;
    for (i, word) in text.split(' ').enumerate() {
        let len = word.chars().count();
        if !word.is_empty() {
            let lower = word.to_lowercase();
            tokens.push(serde_json::json!([word, offset, " ", true, lower, "NN", "NOUN", lower, "dep", i]));
            if full && word == "Paris" {
                ents.push(serde_json::json!([offset, offset + len, "GPE"]));
            }
        }
        offset += len + 1;
    }
    serde_json::json!({ "tokens": tokens, "ents": ents })
}

fn main() {
    let mut args = std::env::args().skip(1);
    let (mut delay, mut fatal, mut exit_at_start, mut spawn_log) = (0u64, None, false, None);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--startup-delay-ms" => delay = args.next().and_then(|v| v.parse().ok()).unwrap_or(0),
            "--fatal" => fatal = args.next(),
            "--exit-at-start" => exit_at_start = true,
            "--spawn-log" => spawn_log = args.next(),
            _ => {}
        }
    }
    if let Some(path) = spawn_log {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_millis());
        if let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
            let _ = writeln!(file, "{now}");
        }
    }
    if exit_at_start {
        std::process::exit(1);
    }
    std::thread::sleep(Duration::from_millis(delay));
    let (mut stdin, mut stdout) = (io::stdin().lock(), io::stdout().lock());
    if let Some(reason) = fatal {
        let _ = write_frame(&mut stdout, &serde_json::json!({"type": "fatal", "reason": reason}).to_string());
        std::process::exit(78);
    }
    let ready = serde_json::json!({"type": "ready", "protocol": 1, "spacy": "fake", "model": "fake", "model_version": "0"});
    if write_frame(&mut stdout, &ready.to_string()).is_err() {
        return;
    }
    while let Ok(frame) = read_frame(&mut stdin) {
        let request: serde_json::Value = serde_json::from_slice(&frame).unwrap_or_default();
        let id = request["id"].as_u64().unwrap_or(0);
        let text = request["text"].as_str().unwrap_or("");
        let reply = match request["op"].as_str() {
            Some("lemma_index") => serde_json::json!({"id": id, "ok": true, "result": ["alpha", "beta"]}),
            _ if text == "CRASH" => std::process::exit(3),
            _ if text == "HANG" => loop {
                std::thread::sleep(Duration::from_secs(3600));
            },
            _ if text == "ERR" => serde_json::json!({"id": id, "ok": false, "error": "boom"}),
            _ if text == "BADID" => serde_json::json!({"id": id + 1000, "ok": true, "result": {}}),
            _ => {
                if let Some(ms) = text.strip_prefix("SLEEP:").and_then(|v| v.parse().ok()) {
                    std::thread::sleep(Duration::from_millis(ms));
                }
                let full = request["selection"].as_str() != Some("tagger");
                serde_json::json!({"id": id, "ok": true, "result": analysis(text, full)})
            }
        };
        if write_frame(&mut stdout, &reply.to_string()).is_err() {
            return;
        }
    }
}
