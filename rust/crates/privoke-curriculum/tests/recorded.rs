//! Every recorded schedule and sampling digest is reproduced exactly, for every recorded seed.
//!
//! * The recorded AU3 source records (`controlled_studies_20261014`, `audience_v3_20261013`) pin the train and guard
//!   wire digests, the sidecar digest and the exposure counts of the frozen stream. The golden file keeps those
//!   digests; the Python source hashes are inputs, because they pin the Python bytes of the time.
//! * The retained audits of the BC01 and rehearsal fits (`iterative_fuzzer_20261011`) pin every sampling digest of one
//!   cycle, including the expanded wire commitment, for 55 seeds.
//!
//! `tests/golden/recorded.json` is written by `evaluation/generate_curriculum_golden.py recorded` from the read-only
//! retained evidence, which also confirms that the live Python agrees with each record.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use privoke_curriculum::audience;
use privoke_curriculum::benign;
use privoke_curriculum::taxonomy;
use privoke_curriculum::trainer::iter_training_examples;
use privoke_curriculum::types::BatchTrainingConfig;
use privoke_curriculum::v3::{self, Policy};
use privoke_curriculum::value::{self, Value};
use privoke_curriculum::{Example, anchor};
use support::{audit_digest, bc01_paths, benign_release, fixture, golden, to_value};

#[test]
fn every_recorded_audience_schedule_is_reproduced() {
    let golden = golden("recorded.json");
    let release = support::au3_release();
    let entries = golden["audience_sources"].as_array().unwrap();
    assert_eq!(entries.len(), 6);
    let mut seeds = std::collections::BTreeSet::new();
    for entry in entries {
        let label = entry["file"].as_str().unwrap();
        assert_eq!(entry["live_python_agrees"], true, "{label}: the maintained Python must agree with the record");
        let seed = entry["seed"].as_u64().unwrap();
        seeds.insert(seed);
        let policy = if entry["window_batches"].as_u64().unwrap() == 1 { Policy::PILOT } else { Policy { steps: 64 } };
        assert_eq!(release.sha256, entry["audience_manifest"].as_str().unwrap());
        let schedule = v3::build_au3(seed, policy, &release, to_value(&entry["source_hashes"])).unwrap();
        let source = &schedule.source;
        let text = |key: &str| value::str_at(source, key).unwrap().to_string();
        assert_eq!(text("train_wire_sha256"), entry["train_wire_sha256"].as_str().unwrap(), "{label}: train wire");
        assert_eq!(text("guard_wire_sha256"), entry["guard_wire_sha256"].as_str().unwrap(), "{label}: guard wire");
        assert_eq!(text("sidecar_sha256"), entry["sidecar_sha256"].as_str().unwrap(), "{label}: sidecar");
        assert_eq!(value::digest_of(source).unwrap(), entry["source_commitment"].as_str().unwrap(), "{label}: whole source record");
        let groups = value::object(vec![
            ("train", value::require(source, "train_groups").unwrap().clone()),
            ("guard", value::require(source, "guard_groups").unwrap().clone()),
        ]);
        assert_eq!(value::digest_of(&groups).unwrap(), entry["groups_sha256"].as_str().unwrap(), "{label}: groups");
        for (key, expected) in entry["counts"].as_object().unwrap() {
            assert_eq!(value::i64_at(source, key).unwrap(), expected.as_i64().unwrap(), "{label}: {key}");
        }
        // The trusted validation accepts exactly what was built, and the evidence round trip reconstructs the wires.
        v3::validate_au3(&schedule, policy, &release).unwrap();
    }
    assert!(seeds.contains(&42) && seeds.contains(&43) && seeds.contains(&44), "recorded seeds 42, 43 and 44");
}

fn rehearsal_audit(
    dataset: &taxonomy::TaxonomyDataset,
    manifest: &anchor::RehearsalManifest,
    seed: u64,
) -> std::collections::BTreeMap<String, String> {
    let (training, guard) = anchor::generate_partition(dataset, manifest, seed).unwrap();
    let config = BatchTrainingConfig { seed, ..BatchTrainingConfig::default() };
    let expanded = iter_training_examples(&training, &[], &config).unwrap();
    anchor::audit_expanded(dataset, manifest, &training, &expanded, &guard, &config).unwrap()
}

fn benign_audit(
    dataset: &taxonomy::TaxonomyDataset,
    release: &benign::BenignRelease,
    seed: u64,
) -> std::collections::BTreeMap<String, String> {
    let (training, guard): (Vec<Example>, Vec<Example>) = benign::generate_partition(dataset, release, seed).unwrap();
    let config = BatchTrainingConfig { seed, ..BatchTrainingConfig::default() };
    let expanded = iter_training_examples(&training, &[], &config).unwrap();
    benign::audit_expanded(dataset, release, &training, &expanded, &guard, &config).unwrap()
}

#[test]
fn every_retained_sampling_audit_is_reproduced() {
    let golden = golden("recorded.json");
    let dataset = taxonomy::load_snapshot(&std::fs::read(fixture("bc01/taxonomy-coverage-v1.json")).unwrap()).unwrap();
    let manifest = anchor::load_snapshot(&anchor::prepare_manifest(&dataset).unwrap(), &dataset).unwrap();
    let pinned = benign_release(&fixture("bc01"), &dataset);
    let entries = golden["retained_audits"].as_array().unwrap();
    assert_eq!(entries.len(), 55, "55 distinct retained audits");
    let (mut rehearsal, mut benign_count, mut refused) = (0, 0, 0);
    for entry in entries {
        let seed = entry["seed"].as_u64().unwrap();
        let file = entry["file"].as_str().unwrap();
        if entry.get("oracle_refuses").is_some() {
            // A superseded benign manifest that the maintained Python itself refuses.
            refused += 1;
            continue;
        }
        assert_eq!(entry["live_python_agrees"], true, "{file}: the maintained Python must agree with the retained audit");
        let audit = match entry["strategy"].as_str().unwrap() {
            "taxonomy_anchor_rehearsal_v1" => {
                rehearsal += 1;
                rehearsal_audit(&dataset, &manifest, seed)
            }
            "taxonomy_benign_coverage_v1" => {
                benign_count += 1;
                let variant = entry["variant"].as_str().unwrap();
                if variant == "pinned" {
                    benign_audit(&dataset, &pinned, seed)
                } else {
                    benign_audit(&dataset, &benign_release(&fixture(&format!("benign-{variant}")), &dataset), seed)
                }
            }
            other => panic!("unknown strategy {other}"),
        };
        assert_eq!(audit_digest(&audit), entry["audit_sha256"].as_str().unwrap(), "{file}: strategy {} seed {seed}", entry["strategy"]);
        assert_eq!(audit.len() as u64, entry["keys"].as_u64().unwrap(), "{file}: audit keys");
    }
    assert_eq!((rehearsal, benign_count, refused), (49, 3, 3), "reproduced rehearsal and benign audits, and the audits the oracle refuses");
}

#[test]
fn recorded_inputs_keep_their_pinned_digests() {
    for (key, _, sha) in v3::INPUTS {
        let path = &bc01_paths()[key];
        assert_eq!(value::sha256(&std::fs::read(path).unwrap()), sha, "fixture {key} must be the byte-identical recorded input");
    }
    let _ = Value::Null;
}
