//! `v3::routine_guard_rows`: the one definition of how a routine seed selects the 16 guard rows of a routine cycle.
//!
//! The contract is new in V3-R2 (the Python oracle is frozen), so it is specified here: deterministic in (seed, commitment),
//! 16 rows, BC01 guard rows drawn from the permanent guard groups (never a TRAIN group of any seed), AU3 the release's pinned
//! guard.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use std::collections::BTreeSet;

use privoke_curriculum::text::training_text_key;
use privoke_curriculum::v3::{self, Policy, RoutineRelease, routine_guard_rows, routine_guard_seed};
use support::{au3_release, bc01_paths};

fn commitment(label: &str) -> String {
    privoke_curriculum::value::sha256(label.as_bytes())
}

fn texts(rows: &[privoke_curriculum::Example]) -> Vec<String> {
    rows.iter().map(|row| row.text.clone()).collect()
}

#[test]
fn the_selection_is_deterministic_bounded_and_bound_to_its_inputs() {
    let sources = v3::load_sources_from(&bc01_paths()).unwrap();
    let release = RoutineRelease::Bc01(&sources);
    let first = routine_guard_rows(release, 20_261_123, &commitment("a")).unwrap();
    assert_eq!(first.len(), 16);
    assert_eq!(first, routine_guard_rows(release, 20_261_123, &commitment("a")).unwrap(), "the same inputs select the same rows");
    // Different seeds and commitments reach different derived seeds, and so (over several of them) different rows.
    let mut selections = BTreeSet::new();
    for seed in 0..6u64 {
        selections.insert(texts(&routine_guard_rows(release, seed, &commitment("a")).unwrap()));
    }
    for label in ["b", "c", "d"] {
        selections.insert(texts(&routine_guard_rows(release, 1, &commitment(label)).unwrap()));
    }
    assert!(selections.len() > 1, "the rows depend on the seed or the commitment");
    assert_ne!(routine_guard_seed(1, &commitment("a")).unwrap(), routine_guard_seed(2, &commitment("a")).unwrap());
    assert_ne!(routine_guard_seed(1, &commitment("a")).unwrap(), routine_guard_seed(1, &commitment("b")).unwrap());
    assert!(routine_guard_seed(1, &commitment("a")).unwrap() <= u64::from(u32::MAX));
    // The commitment is a lowercase SHA-256.
    assert!(routine_guard_rows(release, 1, "ABC").is_err());
    assert!(routine_guard_rows(release, 1, &commitment("a").to_uppercase()).is_err());
}

#[test]
fn bc01_guard_rows_never_share_a_text_with_the_train_rows_of_a_frozen_schedule() {
    let sources = v3::load_sources_from(&bc01_paths()).unwrap();
    for seed in [42u64, 43, 20_261_123] {
        let guard = routine_guard_rows(RoutineRelease::Bc01(&sources), seed, &commitment("train-source")).unwrap();
        let schedule = v3::schedule_bc01(seed, Policy::PILOT, &sources, privoke_curriculum::value::object::<&str>(vec![])).unwrap();
        let train: BTreeSet<String> = schedule.training.iter().map(|row| training_text_key(&row.text)).collect();
        let guard_keys: BTreeSet<String> = guard.iter().map(|row| training_text_key(&row.text)).collect();
        assert_eq!(guard_keys.len(), 16, "seed {seed}: sixteen distinct guard texts");
        assert!(train.is_disjoint(&guard_keys), "seed {seed}: a guard text is a TRAIN text");
    }
}

#[test]
fn au3_guard_rows_are_the_releases_pinned_guard_whatever_the_seed() {
    let release = au3_release();
    let rows = routine_guard_rows(RoutineRelease::Au3(&release), 1, &commitment("a")).unwrap();
    assert_eq!(rows.len(), 16);
    assert_eq!(rows, routine_guard_rows(RoutineRelease::Au3(&release), 99, &commitment("z")).unwrap());
    assert_eq!(
        texts(&rows),
        release.guard.iter().map(|row| privoke_curriculum::value::str_at(row, "text").unwrap().to_string()).collect::<Vec<_>>()
    );
}
