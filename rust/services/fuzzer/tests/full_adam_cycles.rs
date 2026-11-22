//! The FULL Adam policy cycle against the Python oracle (RUST-S21F item 1).
//!
//! `tests/fixtures/full_adam_cycles_golden.json` is written by `evaluation/generate_full_adam_cycle_golden.py`: the maintained
//! Python `FuzzerTrainingService` ran policy-admitted FULL projected Adam cycles with the runtime replaced by the response bytes
//! of retained cycles of the iterative fuzzer study and the parameter-update service replaced by a fake. Here the Rust engine runs
//! the same requests against scripted backends and everything observable must be identical:
//!
//! * every wire message (the receipt lookup, the gradient request, the publication), byte for byte and in order;
//! * the admission header and the deadline class of every runtime call;
//! * the cycle's response, or its abort code and message;
//! * every file of the durable dump (the physical attempt reservation, the attempt record, its admission verdict, a reservation
//!   rejection, the complete cycle records) and the reservation rows, byte for byte after the normalisation of timestamps and
//!   of the dump path (timestamp file names become ordinals, the dump directory becomes `<DUMP>`).
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::cycle_replay::replay_fixture;

#[tokio::test]
async fn the_full_adam_cycles_replay_identically_to_the_python_oracle() {
    replay_fixture("full_adam_cycles_golden.json", "fuzzer FULL Adam cycle replay").await;
}

/// The rehearsal and benign coverage cycles and the ORIGINAL retention refusals before the release is read (RUST-S21G item 5):
/// the same replay, over the Python oracle's golden of the strategies' admission, audits, retained evidence and projections.
#[tokio::test]
async fn the_rehearsal_and_benign_cycles_replay_identically_to_the_python_oracle() {
    replay_fixture("coverage_cycles_golden.json", "fuzzer rehearsal and benign coverage cycle replay").await;
}

/// TRAIN diagnostics and FULL backtracking (RUST-S21G item 3): the selected one-fit step and the known rejection, the diagnostics
/// only cycles, the compact publication and the refusals of tampered evidence.
#[tokio::test]
async fn the_diagnostics_and_backtracking_cycles_replay_identically_to_the_python_oracle() {
    replay_fixture("backtracking_cycles_golden.json", "fuzzer TRAIN diagnostics and backtracking cycle replay").await;
}

/// The frozen window cycle's admission and the checks before any source is read (RUST-S21H item 1): the Python oracle's golden of
/// eight refusals that need no window, no component release and no study data. The recorded fits are `tests/window_cycles.rs`.
#[tokio::test]
async fn the_window_refusals_replay_identically_to_the_python_oracle() {
    replay_fixture("window_refusals_golden.json", "fuzzer window admission refusals replay").await;
}
