//! Cycle replay against the Python oracle (acceptance check 2 of the second half of stage 21).
//!
//! `tests/fixtures/v3_fuzzer_cycles_golden.json` is written by `evaluation/generate_v3_fuzzer_golden.py synthetic`: the maintained
//! Python `FuzzerServer` ran each cycle with the V3 runtime and the checkpoint service replaced by scripted answers (a runtime
//! evidence document and a candidate manifest that satisfy `validate_execution` and `validate_manifest`), over the committed
//! pinned inputs of `privoke-curriculum`. Here the Rust engine runs the same requests against scripted backends that serve the
//! same bytes, and everything observable must be identical:
//!
//! * the `Health` answer;
//! * the response, or the abort code and message, or the message of the uncaught exception (`UNKNOWN`);
//! * every wire message the cycle sends (the resolution, the fit request with its frozen schedule, the manifest fetch, the
//!   commit and the status lookups), byte for byte by SHA-256 and in the same order;
//! * every file of the work directory (request, source, fit, evidence, commit, receipt and the failure markers), byte for byte;
//! * the rows of the `cycles` table, byte for byte, including the identities left with no response.
//!
//! The G5 normalisation (`tests/conformance/normalization.toml`) lists timestamps and server-generated identifiers; none occurs
//! in these records, so the comparison is exact.
//!
//! The second test replays the retained real fits (the audience pilots and the 18 pretrained cells) from a LOCAL golden that
//! holds their prompt text; it runs only when `PRIVOKE_V3_FUZZER_RECORDED_GOLDEN` names that file, and is skipped otherwise.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::{Counts, Inputs, read_json, replay_sequence, synthetic_golden};

fn report(kind: &str, golden: &serde_json::Value, counts: Counts) {
    eprintln!(
        "v3-fuzzer {kind} replay ({}): {} sequences, {} cycles ({} responses, {} aborts, {} uncaught exceptions), {} of {} wire messages, {} work-directory files and {} cycles rows identical to the Python oracle",
        golden["oracle"].as_str().unwrap(),
        counts.sequences,
        counts.cycles,
        counts.ok,
        counts.aborted,
        counts.raised,
        counts.wire_messages,
        counts.wire_messages,
        counts.files,
        counts.rows,
    );
}

async fn replay_all(golden: &serde_json::Value) -> Counts {
    let inputs = Inputs::load();
    let mut counts = Counts::default();
    for sequence in golden["sequences"].as_array().unwrap() {
        counts.add(replay_sequence(sequence, &inputs).await);
    }
    counts
}

#[tokio::test]
async fn the_synthetic_cycles_replay_identically_to_the_python_oracle() {
    let golden = synthetic_golden();
    assert_eq!(golden["kind"], "synthetic");
    let counts = replay_all(&golden).await;
    report("synthetic", &golden, counts);
    // The golden covers the whole contract: every kind of outcome and every marker file.
    assert_eq!((counts.sequences, counts.cycles, counts.ok, counts.aborted, counts.raised), (3, 19, 8, 3, 8));
    assert_eq!(counts.rows, 14);
    for marker in ["fit-status-after-error.pb", "unknown-commit.pb"] {
        let found = golden["sequences"]
            .as_array()
            .unwrap()
            .iter()
            .any(|sequence| sequence["cycles"].as_array().unwrap().iter().any(|cycle| cycle["files"].get(marker).is_some()));
        assert!(found, "the golden has a cycle that leaves {marker}");
    }
}

#[tokio::test]
async fn the_recorded_fits_replay_identically_to_the_python_oracle() {
    let Some(path) = std::env::var_os("PRIVOKE_V3_FUZZER_RECORDED_GOLDEN") else {
        eprintln!("v3-fuzzer recorded replay skipped: PRIVOKE_V3_FUZZER_RECORDED_GOLDEN is not set");
        return;
    };
    let golden = read_json(std::path::Path::new(&path));
    assert_eq!(golden["kind"], "recorded");
    let counts = replay_all(&golden).await;
    report("recorded", &golden, counts);
    let succeeded = counts.ok;
    assert!(counts.cycles > 0, "the local golden holds cycles");
    eprintln!("v3-fuzzer recorded replay: {succeeded} of {} recorded fits published their recorded response", counts.cycles);
}
