//! The recorded frozen-window cycles against the Python oracle, over the real retained releases (RUST-S21H item 1). Env-gated.
//!
//! A window cycle needs the frozen window (512 TRAIN rows and a 16-row guard), the approved TRAIN bank, the ORIGINAL teacher, the task-logit
//! references and the component manifest of its cell, the taxonomy dataset and the authenticated benign snapshot, and the study's retained
//! cycles hold the runtime responses that are bound to them. All of it holds prompt text, so the golden of
//! `evaluation/generate_window_cycle_golden.py` is local (`tests/local/`, ignored by Git) and the sidecars are read from a checkout that
//! holds the retained results and models. The test is skipped unless both are named:
//!
//! * `PRIVOKE_FUZZER_WINDOW_GOLDEN`: the path of `window_cycles_golden.json`;
//! * `PRIVOKE_FUZZER_WINDOW_ROOT`: the root of the checkout the golden's sidecar paths are relative to (it holds `evaluation/results` and
//!   `models/experiments`).
//!
//! The three host fits of the task-query window study are replayed: `v1-window-42` and `-44` end in a terminal no-update receipt (and
//! answer a repeated request from it), `v1-window-43` selects a checkpoint, retains the cycle and publishes. Each recorded runtime request
//! is reproduced by the oracle (and so must be by Rust); every wire message, the admission header, the deadline (the larger of the
//! configured timeout and 180 s), the dump (the retained window inputs, the physical attempts and their verdicts, the window admission and
//! outcome receipts, the complete cycle records) and the reservation rows are identical, and so are the refusals of a wrong seed, a wrong
//! scope, a wrong count, an orphan pin and a response that does not report the window optimizer.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::path::PathBuf;

#[tokio::test]
async fn the_recorded_window_cycles_replay_identically_to_the_python_oracle() {
    let (Some(golden), Some(root)) = (std::env::var_os("PRIVOKE_FUZZER_WINDOW_GOLDEN"), std::env::var_os("PRIVOKE_FUZZER_WINDOW_ROOT"))
    else {
        eprintln!("skipped: PRIVOKE_FUZZER_WINDOW_GOLDEN and PRIVOKE_FUZZER_WINDOW_ROOT are not set");
        return;
    };
    common::cycle_replay::replay(&PathBuf::from(golden), "fuzzer frozen window cycle replay", Some(&PathBuf::from(root))).await;
}
