//! Bundle side of the parity gate: sends every document of every set to the worker pool, in both selections, and writes
//! the SHA-256 of each result as received over the pipe (`<set>.<selection>.all.hashes`, one line per document).
//!
//! ```text
//! cargo run --release --example parity-dump --features embed -- --worker <bundle>/privoke-spacy-worker.exe \
//!     --sets <work>/sets --out <work>/bundle [--workers 4]
//! ```
//!
//! It also decodes every result against its text, which checks that each token and entity offset converts to UTF-8
//! and UTF-16 positions that match the text. A document that fails, in the pool or in the decode, is written as
//! `ERROR <message>` so it is a mismatch, never a skipped line.

use std::fmt::Write as _;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use privoke_spacy::{PoolConfig, Selection, SpacyPool};
use sha2::{Digest, Sha256};
use tokio::sync::Semaphore;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let worker = PathBuf::from(arg("--worker").ok_or("--worker is required")?);
    let sets = PathBuf::from(arg("--sets").ok_or("--sets is required")?);
    let out = PathBuf::from(arg("--out").ok_or("--out is required")?);
    let workers: usize = arg("--workers").map_or(Ok(4), |v| v.parse())?;
    std::fs::create_dir_all(&out)?;

    let mut config = PoolConfig::new(&worker);
    config.workers = workers;
    config.queue_capacity = 4096;
    config.max_text_chars = 1_000_000; // the gate covers every document; the runtime's own limit is a pool setting
    config.request_deadline = Duration::from_secs(29);
    let pool = Arc::new(SpacyPool::start(config)?);
    pool.wait_ready(Duration::from_secs(300)).await?;
    let info = pool.worker_info().ok_or("no worker info")?;
    std::fs::write(
        out.join("identity.json"),
        serde_json::to_string_pretty(&serde_json::json!({
            "spacy": info.spacy, "model": info.model, "model_version": info.model_version, "python": info.python,
            "lock_sha256": info.lock_sha256, "workers": workers,
        }))?,
    )?;
    let lemma = pool.lemma_index().await?;
    // The reference hashes the JSON array text (sorted, compact, ASCII with lower-case \u escapes); rebuild it the same way.
    let body = serde_json::to_string(&*lemma)?;
    let mut ascii = String::new();
    for c in body.chars() {
        if c.is_ascii() {
            ascii.push(c);
        } else {
            let mut units = [0u16; 2];
            for u in c.encode_utf16(&mut units) {
                let _ = write!(ascii, "\\u{u:04x}");
            }
        }
    }
    std::fs::write(out.join("lemma_index.sha256"), format!("{}\n", hex(&Sha256::digest(ascii.as_bytes()))))?;

    let manifest: serde_json::Value = serde_json::from_slice(&std::fs::read(sets.join("sets.json"))?)?;
    let order: Vec<String> = serde_json::from_value(manifest["order"].clone())?;
    let limit = Arc::new(Semaphore::new(workers * 4));
    for name in order {
        let texts: Vec<Arc<String>> = std::fs::read_to_string(sets.join(format!("{name}.jsonl")))?
            .lines()
            .map(|l| serde_json::from_str::<String>(l).map(Arc::new))
            .collect::<Result<_, _>>()?;
        for selection in [Selection::Full, Selection::TaggerOnly] {
            let started = Instant::now();
            let mut tasks = Vec::with_capacity(texts.len());
            for text in &texts {
                let permit = limit.clone().acquire_owned().await?;
                let (pool, text) = (pool.clone(), text.clone());
                tasks.push(tokio::spawn(async move {
                    let _permit = permit;
                    match pool.analyze_raw(&text, selection).await {
                        Ok(raw) => match raw.decode(&text) {
                            Ok(_) => hex(&Sha256::digest(raw.as_str().as_bytes())),
                            Err(e) => format!("ERROR decode: {e}"),
                        },
                        Err(e) => format!("ERROR {e}"),
                    }
                }));
            }
            let mut lines = String::new();
            let mut errors = 0usize;
            for task in tasks {
                let line = task.await?;
                errors += usize::from(line.starts_with("ERROR"));
                lines.push_str(&line);
                lines.push('\n');
            }
            std::fs::write(out.join(format!("{name}.{}.all.hashes", selection.as_str())), lines)?;
            eprintln!(
                "[bundle] {name} {}: {} documents, {errors} errors, {:.0}s",
                selection.as_str(),
                texts.len(),
                started.elapsed().as_secs_f64()
            );
        }
    }
    Ok(())
}
