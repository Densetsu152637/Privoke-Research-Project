//! Parity of the Rust NER layer with Python, per recorded set and per configuration, through the real spaCy worker.
//!
//! ```text
//! cargo run --release -p privoke-ner-layer --example parity -- \
//!     --worker <bundle>/privoke-spacy-worker.exe --golden <golden dir> [--workers 4] [--no-pattern] [set ...]
//! ```
//!
//! The golden directory is written by `evaluation/generate_ner_golden.py sets` (one `<set>.jsonl` per set, or
//! `<set>.<n>of<m>.jsonl` shards). For every row and every recorded configuration the example runs the Rust NER layer
//! (normalisation, spaCy through the stage 11 worker pool, post-filter, remapping) and the pattern detector, and
//! compares results and post-filter decision logs with the recorded Python output. It exits non-zero on any difference.

#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "../tests/common/mod.rs"]
mod common;

use std::collections::{BTreeMap, HashSet};
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, Instant};

use privoke_spacy::{PoolConfig, SpacyPool};
use serde_json::Value;
use tokio::sync::Semaphore;

fn arg(name: &str) -> Option<String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1).cloned())
}

fn flag(name: &str) -> bool {
    std::env::args().skip(1).any(|a| a == name)
}

#[derive(Default)]
struct Tally {
    rows: usize,
    layer: BTreeMap<String, (usize, usize)>,
    pattern: BTreeMap<String, (usize, usize)>,
    diffs: Vec<String>,
    different_rows: Vec<String>,
}

fn set_name(path: &std::path::Path) -> String {
    let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
    // `<set>.<n>of<m>` shards belong to `<set>`.
    match stem.rsplit_once('.') {
        Some((set, shard)) if shard.contains("of") => set.to_owned(),
        _ => stem.to_owned(),
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let (Some(worker), Some(golden)) = (arg("--worker"), arg("--golden")) else {
        eprintln!("usage: parity --worker <worker exe> --golden <dir> [--workers N] [--no-pattern] [set ...]");
        return ExitCode::from(2);
    };
    let workers: usize = arg("--workers").and_then(|v| v.parse().ok()).unwrap_or(4);
    let skip_pattern = flag("--no-pattern");
    let positional: Vec<String> = {
        let args: Vec<String> = std::env::args().skip(1).collect();
        let mut out = Vec::new();
        let mut i = 0;
        while i < args.len() {
            if matches!(args[i].as_str(), "--worker" | "--golden" | "--workers") {
                i += 2;
            } else if args[i].starts_with("--") {
                i += 1;
            } else {
                out.push(args[i].clone());
                i += 1;
            }
        }
        out
    };
    let mut files: Vec<PathBuf> = std::fs::read_dir(&golden)
        .expect("golden directory")
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "jsonl"))
        .filter(|p| positional.is_empty() || positional.contains(&set_name(p)))
        .collect();
    files.sort();

    let mut config = PoolConfig::new(&worker);
    config.workers = workers;
    config.queue_capacity = 4096;
    config.max_text_chars = 1_000_000;
    config.request_deadline = Duration::from_secs(29);
    let pool = Arc::new(SpacyPool::start(config).expect("pool starts"));
    pool.wait_ready(Duration::from_secs(300)).await.expect("worker is ready");
    let info = pool.worker_info().expect("worker info");
    println!("worker: spaCy {:?}, model {:?} {:?}, python {:?}", info.spacy, info.model, info.model_version, info.python);
    // Python records `PRIVOKE_NER_MODEL` (default `en_core_web_sm`), not the model package's own `meta["name"]`.
    let model = privoke_ner_layer::detector::DEFAULT_MODEL.to_owned();
    let lexicon: Arc<HashSet<String>> = Arc::new(pool.lemma_index().await.expect("lemma index").iter().cloned().collect());
    println!("lexicon: {} words", lexicon.len());

    let limit = Arc::new(Semaphore::new(workers * 4));
    let mut tallies: BTreeMap<String, Tally> = BTreeMap::new();
    let mut all_identical = true;
    for file in files {
        let set = set_name(&file);
        let started = Instant::now();
        let reader = BufReader::new(std::fs::File::open(&file).expect("golden file"));
        let mut tasks = Vec::new();
        for line in reader.lines().map_while(Result::ok).filter(|l| !l.trim().is_empty()) {
            let permit = limit.clone().acquire_owned().await.expect("semaphore");
            let (pool, lexicon, model) = (pool.clone(), lexicon.clone(), model.clone());
            tasks.push(tokio::spawn(async move {
                let _permit = permit;
                let row: Value = serde_json::from_str(&line).expect("golden row");
                let report = common::check_row(&*pool, lexicon, &model, &row, skip_pattern).await;
                (row["id"].to_string(), report)
            }));
            // Bound the number of rows in flight so a large set does not hold every task at once.
            if tasks.len() >= workers * 64 {
                drain(&mut tasks, tallies.entry(set.clone()).or_default()).await;
            }
        }
        drain(&mut tasks, tallies.entry(set.clone()).or_default()).await;
        let tally = &tallies[&set];
        println!("[{set}] {} rows so far, file {} done in {:.0}s", tally.rows, file.display(), started.elapsed().as_secs_f64());
    }
    println!("\n{:<14} {:>8}  {:>28}  {:>28}", "set", "rows", "NER layer (identical/total)", "pattern detector");
    for (set, tally) in &tallies {
        let sum = |m: &BTreeMap<String, (usize, usize)>| m.values().fold((0, 0), |a, b| (a.0 + b.0, a.1 + b.1));
        let (layer, pattern) = (sum(&tally.layer), sum(&tally.pattern));
        println!("{set:<14} {:>8}  {:>13} / {:<12}  {:>13} / {:<12}", tally.rows, layer.0, layer.1, pattern.0, pattern.1);
        for (name, (same, total)) in &tally.layer {
            println!("    layer {name:<20} {same} / {total}");
        }
        for (name, (same, total)) in &tally.pattern {
            println!("    pattern {name:<18} {same} / {total}");
        }
        if layer.0 != layer.1 || pattern.0 != pattern.1 {
            all_identical = false;
            for diff in tally.diffs.iter().take(6) {
                println!("  DIFF {diff}");
            }
            println!("  rows with a difference: {}", tally.different_rows.iter().take(40).cloned().collect::<Vec<_>>().join(", "));
        }
    }
    if all_identical { ExitCode::SUCCESS } else { ExitCode::FAILURE }
}

async fn drain(tasks: &mut Vec<tokio::task::JoinHandle<(String, common::RowReport)>>, tally: &mut Tally) {
    for task in tasks.drain(..) {
        let (id, report) = task.await.expect("row task");
        tally.rows += 1;
        let mut different = false;
        for (name, same) in report.layer {
            let entry = tally.layer.entry(name).or_default();
            entry.1 += 1;
            entry.0 += usize::from(same);
            different |= !same;
        }
        for (name, same) in report.pattern {
            let entry = tally.pattern.entry(name).or_default();
            entry.1 += 1;
            entry.0 += usize::from(same);
            different |= !same;
        }
        if different {
            tally.different_rows.push(id);
            for diff in report.diffs {
                if tally.diffs.len() < 12 {
                    tally.diffs.push(diff);
                }
            }
        }
    }
}
