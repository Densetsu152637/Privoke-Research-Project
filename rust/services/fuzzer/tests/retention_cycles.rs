//! Complete ORIGINAL retention cycles against the Python oracle, over the real retained releases (RUST-S21G item 5). Env-gated.
//!
//! A retention cycle needs the approved TRAIN bank, the ORIGINAL teacher artifact, the references and the manifest of a profile, and
//! the study's retained cycles hold the runtime responses that are bound to them. The bank holds prompt text, so the golden of
//! `evaluation/generate_retention_cycle_golden.py` is local (`tests/local/`, ignored by Git) and the sidecars are read from a checkout
//! that holds the retained results. The test is skipped unless both are named:
//!
//! * `PRIVOKE_FUZZER_RETENTION_GOLDEN`: the path of `retention_cycles_golden.json`;
//! * `PRIVOKE_FUZZER_RETENTION_RESULTS`: the `evaluation/results` directory the golden's sidecar paths are relative to.
//!
//! Each retained cycle of `sensitive-retention-pilot03` (gate) and `sensitive-retention-pilot04` (gate and hinge) is replayed: its
//! recorded runtime request is reproduced by the oracle (and so must be by Rust), the release is retained before compute and bound
//! to the response, a published update and a refusal by the per-row predicate are both covered, and every wire message, the dump
//! (the retained release, the sampling audit, the attempts and the complete cycle records) and the reservation rows are identical.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::path::PathBuf;

#[tokio::test]
async fn the_retained_retention_cycles_replay_identically_to_the_python_oracle() {
    let (Some(golden), Some(results)) =
        (std::env::var_os("PRIVOKE_FUZZER_RETENTION_GOLDEN"), std::env::var_os("PRIVOKE_FUZZER_RETENTION_RESULTS"))
    else {
        eprintln!("skipped: PRIVOKE_FUZZER_RETENTION_GOLDEN and PRIVOKE_FUZZER_RETENTION_RESULTS are not set");
        return;
    };
    common::cycle_replay::replay(&PathBuf::from(golden), "fuzzer ORIGINAL retention cycle replay", Some(&PathBuf::from(results))).await;
}
