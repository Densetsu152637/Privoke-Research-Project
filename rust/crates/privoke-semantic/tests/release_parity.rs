//! Parity on the pinned V3 releases and the recorded sets. LOCAL ONLY: the release store (`models/standard-releases`) and
//! the golden made from recorded sets are not in the repository, so without them these tests print why and pass.
//!
//! ```text
//! PRIVOKE_V3_RELEASES=<checkout>/models/standard-releases
//! PRIVOKE_SEMANTIC_GOLDEN=<checkout>/evaluation/results/semantic-golden-20261117
//! cargo test -p privoke-semantic --release --test release_parity -- --nocapture
//! ```
//!
//! The golden comes from `evaluation/generate_semantic_golden.py releases|sets`, which runs the product's Python classes
//! with an explicit semantic-only layer list. Every file is `v3-<tier>-<set>.json` (V3) or `tiny-<model>-<set>.json`
//! (the tracked legacy models, loaded from the repository's `models/`). Results are LLM-only and reported separately from
//! any product-pipeline result.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::path::PathBuf;

use common::{Report, check_tiny_row, check_v3_row, read_json, repo_root};
use privoke_semantic::{TinyModel, V3Model};

fn env_dir(name: &str) -> Option<PathBuf> {
    std::env::var_os(name).map(PathBuf::from).filter(|path| path.is_dir())
}

/// Golden files whose names start with `prefix`, sorted.
fn golden_files(dir: &std::path::Path, prefix: &str) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            name.starts_with(prefix) && name.ends_with(".json")
        })
        .collect();
    files.sort();
    files
}

#[test]
fn pinned_v3_releases_match_torch() {
    let (Some(releases), Some(golden)) = (env_dir("PRIVOKE_V3_RELEASES"), env_dir("PRIVOKE_SEMANTIC_GOLDEN")) else {
        eprintln!(
            "skipped: PRIVOKE_V3_RELEASES and PRIVOKE_SEMANTIC_GOLDEN are not set (the release store and the recorded-set golden are local only)"
        );
        return;
    };
    let mut checked = 0;
    for tier in ["efficient", "balanced", "quality"] {
        let files = golden_files(&golden, &format!("v3-{tier}-"));
        if files.is_empty() {
            eprintln!("skipped: no golden for tier {tier} in {}", golden.display());
            continue;
        }
        let id = format!("privoke-v3-{tier}");
        let model = V3Model::load_release(&releases.join(&id), &id).unwrap();
        for file in files {
            let data = read_json(&file);
            assert_eq!(data["meta"]["layers"], serde_json::json!(["semantic"]), "{} is not semantic-only golden", file.display());
            let mut report = Report::default();
            for row in data["rows"].as_array().unwrap() {
                check_v3_row(&model, row, &mut report);
            }
            report.assert_clean(&format!("{} ({})", id, file.file_name().unwrap().to_string_lossy()));
            checked += report.rows;
        }
    }
    println!("pinned V3 releases: {checked} rows replayed");
}

#[test]
fn tracked_tiny_models_match_numpy_on_recorded_sets() {
    let Some(golden) = env_dir("PRIVOKE_SEMANTIC_GOLDEN") else {
        eprintln!("skipped: PRIVOKE_SEMANTIC_GOLDEN is not set (the recorded-set golden is local only)");
        return;
    };
    let mut checked = 0;
    for name in ["privoke-baseline", "privoke-efficient", "privoke-balanced", "privoke-quality"] {
        let files = golden_files(&golden, &format!("tiny-{name}-"));
        if files.is_empty() {
            eprintln!("skipped: no golden for {name} in {}", golden.display());
            continue;
        }
        let model = TinyModel::from_file(&repo_root().join("models").join(format!("{name}.json"))).unwrap();
        for file in files {
            let data = read_json(&file);
            let mut report = Report::default();
            for row in data["rows"].as_array().unwrap() {
                check_tiny_row(&model, row, &mut report);
            }
            report.assert_clean(&format!("{name} ({})", file.file_name().unwrap().to_string_lossy()));
            checked += report.rows;
        }
    }
    println!("tracked Tiny models: {checked} rows replayed");
}
