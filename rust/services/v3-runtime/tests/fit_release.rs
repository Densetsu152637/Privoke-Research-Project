//! Parity of `FitCandidate` with the Python `RuntimeServer` on a real ORIGINAL V3 package. Gated: without
//! `PRIVOKE_V3_RUNTIME_FIT_GOLDEN` and `PRIVOKE_V3_PACKAGE` it prints why it skipped and passes (CI has neither).
//!
//! ```text
//! PRIVOKE_V3_RUNTIME_FIT_GOLDEN   the file written by `generate_v3_runtime_golden.py fit-real` (pilot and 64-step fits, both scopes)
//! PRIVOKE_V3_PACKAGE              the package directory the golden was made from (manifest.json, config.json, vocab.txt, model.safetensors)
//! ```
//!
//! The manifest is admitted with the real pins (`Admission::Pinned`) and the fit runs the validated `v3_fit::fit` (tier pins
//! included), so this also checks `validate_manifest` on the ORIGINAL and on every candidate manifest. The schedule is the frozen BC01
//! schedule over the committed pinned inputs, which carry the same bytes as the pinned study inputs.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::path::PathBuf;

use common::fit_support::{checkout, replay_golden};
use common::say;
use privoke_v3_runtime::assets::Admission;

#[tokio::test]
async fn the_real_package_fits_replay_within_the_stage_19_tolerance() {
    let (Some(golden), Some(package)) =
        (std::env::var_os("PRIVOKE_V3_RUNTIME_FIT_GOLDEN").map(PathBuf::from), std::env::var_os("PRIVOKE_V3_PACKAGE").map(PathBuf::from))
    else {
        say("PENDING: set PRIVOKE_V3_RUNTIME_FIT_GOLDEN and PRIVOKE_V3_PACKAGE to replay the real-package fits (not run in CI)");
        return;
    };
    let golden: serde_json::Value = serde_json::from_slice(&std::fs::read(golden).unwrap()).unwrap();
    let model_id = golden["meta"]["model_id"].as_str().unwrap().to_string();
    let root = tempfile::tempdir().unwrap();
    checkout(root.path());
    let started = std::time::Instant::now();
    let counts = replay_golden(&golden, &package, &model_id, Admission::Pinned, root.path(), 4, &["full-64"]).await;
    say(&format!("FitCandidate real package: {} fits in {:.1} s", counts.fits, started.elapsed().as_secs_f64()));
    assert_eq!(counts.fits, golden["cases"].as_array().unwrap().len());
}
