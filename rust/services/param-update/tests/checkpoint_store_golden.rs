//! The V3 checkpoint store against its Python oracle (acceptance check 1 of stage V3-R1).
//!
//! `tests/fixtures/v3_checkpoint_store_golden.json` is written by `evaluation/generate_checkpoint_store_golden.py`: the unchanged
//! `services/pretrained-v3/src/checkpoint_store.py` ran a scripted sequence of bootstraps, stagings, commits and lookups on a
//! synthetic package (three stories: a BC01 lifecycle with one refusal per admission rule, an AU3 pilot and a two-tier catalog),
//! and every outcome, every refusal reason and the whole catalog after each step were recorded. Here the Rust store runs the same
//! operations over the same bytes, and everything observable must be identical:
//!
//! * the answer of each operation, or the refusal and its text;
//! * the blobs on disk, the `current` table and the `receipts` table (fingerprint and payload bytes) after each step.
//!
//! The golden holds no prompt text. The weights are a closed-form function of (salt, index) that this test reproduces, and every
//! reproduced file is checked against its recorded SHA-256; an evidence document is recorded without its `source` member, which
//! the test regenerates from the committed pinned inputs of `privoke-curriculum` and checks against the recorded SHA-256 too.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

mod golden_world;

use golden_world::{World, au3_manifest, bc01_paths, perform, snapshot};
use privoke_curriculum::audience::BUNDLED_MANIFEST_SHA256;
use privoke_param_update::v3_store::{AudienceSource, CheckpointStore, PinnedSources, StoreError};

/// Counts of one replay, reported for the CI log.
#[derive(Debug, Default)]
struct Counts {
    stories: usize,
    steps: usize,
    answers: usize,
    refusals: usize,
    missing: usize,
    applied: usize,
    stale_base: usize,
    guard_rejected: usize,
    blobs: usize,
    receipts: usize,
}

#[test]
fn the_store_replays_the_python_oracle_identically() {
    let world = World::load();
    let mut counts = Counts::default();
    for story in world.golden["stories"].as_array().unwrap() {
        let name = story["name"].as_str().unwrap();
        let scratch = tempfile::tempdir().unwrap();
        let directory = scratch.path().join("store");
        let pinned =
            PinnedSources::new(bc01_paths(), AudienceSource::Trusted { path: au3_manifest(), sha256: BUNDLED_MANIFEST_SHA256.to_string() });
        let store = CheckpointStore::open(&directory, Arc::new(pinned)).unwrap();
        counts.stories += 1;
        for (index, step) in story["steps"].as_array().unwrap().iter().enumerate() {
            let label = format!("{name}/{index} {} {}", step["op"].as_str().unwrap(), step["label"].as_str().unwrap_or_default());
            let actual = perform(&world, &store, step, scratch.path());
            let expected = &step["outcome"];
            counts.steps += 1;
            match (&actual, expected.get("ok"), expected.get("error")) {
                (Ok(answer), Some(ok), None) => {
                    assert_eq!(answer, ok, "{label}: the answer");
                    counts.answers += 1;
                    if step["op"] == "commit" {
                        match answer["status"].as_str().unwrap() {
                            "applied" => counts.applied += 1,
                            _ if answer["reason"] == "stale_base" => counts.stale_base += 1,
                            _ => counts.guard_rejected += 1,
                        }
                    }
                }
                (Err(error), None, Some(refusal)) => {
                    counts.refusals += 1;
                    match (refusal["class"].as_str().unwrap(), refusal["message"].as_str()) {
                        ("ValueError", Some(message)) => {
                            assert_eq!(error, &StoreError::Invalid(message.to_string()), "{label}: the reason")
                        }
                        ("FileNotFoundError", _) => {
                            assert!(matches!(error, StoreError::Missing(_)), "{label}: a missing blob, got {error:?}");
                            counts.missing += 1;
                        }
                        (class, _) => assert!(matches!(error, StoreError::Invalid(_)), "{label}: a refusal like {class}, got {error:?}"),
                    }
                }
                _ => panic!("{label}: the oracle answered {expected} and the store {actual:?}"),
            }
            let after = snapshot(&directory);
            assert_eq!(after, step["after"], "{label}: the catalog after the step");
            counts.blobs += after["blobs"].as_array().unwrap().len();
            counts.receipts += after["receipts"].as_array().unwrap().len();
        }
    }
    eprintln!(
        "v3 checkpoint store replay ({}): {} stories, {} steps ({} answers, {} refusals of which {} missing blobs), commits {} applied, {} stale_base, {} guard_rejected; {} blob listings and {} receipt rows identical to the Python oracle",
        world.golden["oracle"].as_str().unwrap(),
        counts.stories,
        counts.steps,
        counts.answers,
        counts.refusals,
        counts.missing,
        counts.applied,
        counts.stale_base,
        counts.guard_rejected,
        counts.blobs,
        counts.receipts,
    );
    // The golden covers the whole contract.
    assert_eq!((counts.stories, counts.steps), (3, 98));
    assert_eq!((counts.applied, counts.stale_base, counts.guard_rejected), (6, 3, 2));
}
