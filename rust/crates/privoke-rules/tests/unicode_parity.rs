//! Python's Unicode behaviour reproduced by `pyunicode`: NFKC, `lower`, `upper` and the
//! character classes, against rows written by `evaluation/generate_rules_golden.py sweep`.
//!
//! The committed sample covers a stride of code points and random sequences. With
//! `PRIVOKE_RULES_GOLDEN_DIR` set, the full sweep of every code point (ignored by Git) runs too.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

use privoke_rules::pyunicode::{combining_class, is_decimal, is_format, is_space, is_word, lower, nfkc, upper};
use serde_json::Value;

fn check_file(path: &Path) -> usize {
    let reader = BufReader::new(std::fs::File::open(path).unwrap_or_else(|error| panic!("{}: {error}", path.display())));
    let mut rows = 0;
    let mut failures = Vec::new();
    for line in reader.lines().map_while(Result::ok).filter(|line| !line.trim().is_empty()) {
        let row: Value = serde_json::from_str(&line).expect("row");
        rows += 1;
        let expect = |key: &str| row[key].as_str().unwrap_or_default().to_owned();
        if let Some(cp) = row["cp"].as_u64() {
            let c = char::from_u32(cp as u32).expect("scalar value");
            let s = c.to_string();
            let checks = [
                (nfkc(&s) == expect("nfkc"), "nfkc"),
                (lower(&s) == expect("lower"), "lower"),
                (upper(&s) == expect("upper"), "upper"),
                (is_space(c) == row["space"].as_bool().unwrap_or(false), "space"),
                (is_word(c) == row["word"].as_bool().unwrap_or(false), "word"),
                (is_decimal(c) == row["digit"].as_bool().unwrap_or(false), "digit"),
                (is_format(c) == row["cf"].as_bool().unwrap_or(false), "cf"),
                (u64::from(combining_class(c)) == row["ccc"].as_u64().unwrap_or(0), "ccc"),
            ];
            for (ok, name) in checks {
                if !ok {
                    failures.push(format!("U+{cp:04X} {name}"));
                }
            }
        } else {
            let s = expect("text");
            for (name, actual) in [("nfkc", nfkc(&s)), ("lower", lower(&s)), ("upper", upper(&s))] {
                if actual != expect(name) {
                    failures.push(format!("sequence {:?} {name}: {actual:?} != {:?}", s, expect(name)));
                }
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{} failures in {}:\n{}",
        failures.len(),
        path.display(),
        failures.iter().take(20).cloned().collect::<Vec<_>>().join("\n")
    );
    rows
}

#[test]
fn committed_sample_matches_python() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/unicode_sample.jsonl");
    assert!(check_file(&path) > 1000);
}

#[test]
fn full_sweep_matches_python() {
    let Some(dir) = std::env::var_os("PRIVOKE_RULES_GOLDEN_DIR") else { return };
    let path = PathBuf::from(dir).join("unicode_sweep.jsonl");
    if path.exists() {
        let rows = check_file(&path);
        eprintln!("unicode sweep: {rows} rows identical");
    }
}
