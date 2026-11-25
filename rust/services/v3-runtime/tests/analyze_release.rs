//! Parity of `AnalyzePrompt` with the Python `RuntimeServer` on the pinned standard V3 releases and the recorded sets. Gated:
//! without `PRIVOKE_V3_RUNTIME_GOLDEN` and `PRIVOKE_V3_RELEASES` it prints why it skipped and passes (CI has neither).
//!
//! ```text
//! PRIVOKE_V3_RUNTIME_GOLDEN   the directory written by `generate_v3_runtime_golden.py analyze-real` (one file per tier and set)
//! PRIVOKE_V3_RELEASES         models/standard-releases (privoke-v3-<tier>/ with manifest.json, config.json, vocab.txt, model.safetensors)
//! ```
//!
//! The manifest is admitted with the real pins (`Admission::Pinned`), so this also checks `validate_manifest` on the releases.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::path::PathBuf;

use common::{Report, Scripted, replay, runtime_over, say, serve_package};
use privoke_semantic::V3Model;
use privoke_v3_runtime::assets::Admission;

fn env_dir(name: &str) -> Option<PathBuf> {
    std::env::var_os(name).map(PathBuf::from).filter(|path| path.is_dir())
}

#[tokio::test]
async fn the_pinned_releases_replay_identically_on_the_recorded_sets() {
    let (Some(golden_dir), Some(releases)) = (env_dir("PRIVOKE_V3_RUNTIME_GOLDEN"), env_dir("PRIVOKE_V3_RELEASES")) else {
        say("PENDING: set PRIVOKE_V3_RUNTIME_GOLDEN and PRIVOKE_V3_RELEASES to replay the pinned releases (not run in CI)");
        return;
    };
    let mut total = Report::default();
    let mut files: Vec<PathBuf> = std::fs::read_dir(&golden_dir).unwrap().map(|entry| entry.unwrap().path()).collect();
    files.sort();
    for tier in ["efficient", "balanced", "quality"] {
        let model_id = format!("privoke-v3-{tier}");
        let release = releases.join(&model_id);
        let prefix = format!("{tier}-");
        let tier_files: Vec<&PathBuf> =
            files.iter().filter(|path| path.file_name().unwrap().to_string_lossy().starts_with(&prefix)).collect();
        if tier_files.is_empty() {
            continue;
        }
        let scripted = Scripted::ready();
        serve_package(&scripted, &release, &model_id, &std::fs::read(release.join("manifest.json")).unwrap());
        let state = tempfile::tempdir().unwrap();
        let runtime = runtime_over(&scripted, state.path(), Admission::Pinned).await;
        let model =
            V3Model::from_files(&release.join("config.json"), &release.join("model.safetensors"), &release.join("vocab.txt")).unwrap();
        let raw = |text: &str| model.predict(text).map(|prediction| prediction.confidence_raw).unwrap_or(0.0);
        for path in tier_files {
            let document: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
            let rows = document["rows"].as_array().unwrap();
            let report = replay(&runtime, rows, &raw).await;
            report.assert_clean(&format!("{tier} {}", document["meta"]["set"].as_str().unwrap()));
            total.rows += report.rows;
            total.aborts += report.aborts;
            total.error_rows += report.error_rows;
            total.finding_rows += report.finding_rows;
            total.wire_equal += report.wire_equal;
            total.boundary_confidences += report.boundary_confidences;
        }
    }
    assert!(total.rows > 0, "the golden directory held no rows for any tier");
    total.assert_clean("AnalyzePrompt, pinned V3 releases, all tiers and sets");
}
