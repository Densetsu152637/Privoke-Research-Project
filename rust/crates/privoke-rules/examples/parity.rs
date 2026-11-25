//! Parity counts per recorded set.
//!
//! ```text
//! cargo run --release -p privoke-rules --example parity -- <golden dir> [set ...]
//! ```
//!
//! The golden directory is written by `evaluation/generate_rules_golden.py sets`. For each set
//! the example prints how many normalisations and regex-layer runs are identical to Python, and
//! exits non-zero if any differs.

#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "../tests/common/mod.rs"]
mod common;

use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::ExitCode;

use common::{Detectors, Tally, compare_row};
use serde_json::Value;

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let Some(dir) = args.next().map(PathBuf::from) else {
        eprintln!("usage: parity <golden dir> [set ...]");
        return ExitCode::from(2);
    };
    let wanted: Vec<String> = args.collect();
    let mut files: Vec<PathBuf> = match std::fs::read_dir(&dir) {
        Ok(entries) => entries
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "jsonl"))
            .filter(|path| path.file_stem().and_then(|stem| stem.to_str()).is_some_and(|stem| stem != "unicode_sweep"))
            .filter(|path| {
                wanted.is_empty() || path.file_stem().and_then(|stem| stem.to_str()).is_some_and(|stem| wanted.iter().any(|w| w == stem))
            })
            .collect(),
        Err(error) => {
            eprintln!("{}: {error}", dir.display());
            return ExitCode::from(2);
        }
    };
    files.sort();
    let mut detectors = Detectors::default();
    let mut all_identical = true;
    println!("{:<20} {:>8} {:>22} {:>22}", "set", "rows", "normalisation", "regex layer");
    for file in files {
        let reader = match std::fs::File::open(&file) {
            Ok(handle) => BufReader::new(handle),
            Err(error) => {
                eprintln!("{}: {error}", file.display());
                return ExitCode::from(2);
            }
        };
        let (mut norm, mut layer) = (Tally::default(), Tally::default());
        let mut rows = 0;
        for line in reader.lines().map_while(Result::ok).filter(|line| !line.trim().is_empty()) {
            let Ok(row) = serde_json::from_str::<Value>(&line) else {
                eprintln!("{}: malformed row", file.display());
                return ExitCode::from(2);
            };
            rows += 1;
            compare_row(&row, &mut detectors, &mut norm, &mut layer);
        }
        let name = file.file_stem().and_then(|stem| stem.to_str()).unwrap_or("?");
        println!("{name:<20} {rows:>8} {:>10}/{:<11} {:>10}/{:<11}", norm.identical, norm.compared, layer.identical, layer.compared);
        for difference in norm.differences.iter().chain(&layer.differences) {
            println!("  DIFF {difference}");
        }
        all_identical &= norm.identical == norm.compared && layer.identical == layer.compared;
    }
    if all_identical { ExitCode::SUCCESS } else { ExitCode::from(1) }
}
