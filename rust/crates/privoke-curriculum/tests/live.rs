//! Parity with the maintained Python fuzzer on seeds beyond the recorded ones.
//!
//! `tests/golden/live.json` is written by `evaluation/generate_curriculum_golden.py live`: the Python curricula ran on
//! the same pinned inputs (committed byte-identically under `tests/fixtures`) and every selection is hashed.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use std::collections::BTreeMap;

use privoke_contracts::proto::v1::FuzzerTrainingRequest;
use privoke_curriculum::classification::Classification;
use privoke_curriculum::curriculum::{self, MemoryState, ReserveOptions};
use privoke_curriculum::generator::{self, PartitionSources};
use privoke_curriculum::trainer::iter_training_examples;
use privoke_curriculum::types::BatchTrainingConfig;
use privoke_curriculum::v3::{self, Policy};
use privoke_curriculum::value::{self, Value};
use privoke_curriculum::{Example, anchor, audience, benign, presence, privacy_heads, taxonomy};
use support::{audit_digest, bc01_paths, fixture, golden, partition_matches, repo_root, rows_digest, to_value};

fn dataset() -> taxonomy::TaxonomyDataset {
    taxonomy::load_snapshot(&std::fs::read(fixture("bc01/taxonomy-coverage-v1.json")).unwrap()).unwrap()
}

#[test]
fn legacy_generator_on_the_builtin_dataset() {
    let golden = golden("live.json");
    for entry in golden["generator_default"].as_array().unwrap() {
        let seed = entry["seed"].as_u64().unwrap();
        if let Some(partition) = entry.get("partition") {
            let (training, heldout) = generator::generate_training_partition(32, 16, seed, &PartitionSources::default()).unwrap();
            partition_matches(partition, &training, &heldout, &format!("legacy partition seed {seed}"));
        } else {
            let count = entry["count"].as_i64().unwrap();
            let rows = generator::generate_training_prompts(count, seed, None, &[], &[]).unwrap();
            assert_eq!(rows_digest(&rows), entry["sha256"].as_str().unwrap(), "legacy prompts seed {seed} count {count}");
        }
    }
}

#[test]
fn taxonomy_anchor_and_benign_partitions() {
    let golden = golden("live.json");
    let dataset = dataset();
    assert_eq!(dataset.sha256, golden["taxonomy_dataset_sha256"].as_str().unwrap());
    let manifest = anchor::load_snapshot(&anchor::prepare_manifest(&dataset).unwrap(), &dataset).unwrap();
    assert_eq!(manifest.sha256, golden["rehearsal_manifest_sha256"].as_str().unwrap());
    let release = support::benign_release(&fixture("bc01"), &dataset);
    assert_eq!(release.sha256, golden["benign_release_sha256"].as_str().unwrap());
    assert_eq!(benign::legacy_snapshot_commitment(&dataset).unwrap(), golden["legacy_snapshot_commitment"].as_str().unwrap());
    for entry in golden["taxonomy_partitions"].as_array().unwrap() {
        let seed = entry["seed"].as_u64().unwrap();
        let (training, guard) = taxonomy::generate_partition(&dataset, seed).unwrap();
        partition_matches(entry, &training, &guard, &format!("taxonomy seed {seed}"));
        let audit = taxonomy::audit_originals(&dataset, &training, &guard).unwrap();
        assert_eq!(audit_digest(&audit), entry["audit_sha256"].as_str().unwrap(), "taxonomy audit seed {seed}");
    }
    for entry in golden["anchor_partitions"].as_array().unwrap() {
        let seed = entry["seed"].as_u64().unwrap();
        let (training, guard) = anchor::generate_partition(&dataset, &manifest, seed).unwrap();
        partition_matches(entry, &training, &guard, &format!("anchor seed {seed}"));
    }
    for entry in golden["benign_partitions"].as_array().unwrap() {
        let seed = entry["seed"].as_u64().unwrap();
        let (training, guard) = benign::generate_partition(&dataset, &release, seed).unwrap();
        partition_matches(entry, &training, &guard, &format!("benign seed {seed}"));
    }
    // The strategy dispatch of the partition entry point reaches the same selections.
    let (training, guard) = generator::generate_training_partition(
        32,
        16,
        7,
        &PartitionSources {
            sampling_strategy: Some("taxonomy_benign_coverage_v1"),
            taxonomy_dataset: Some(&dataset),
            benign_release: Some(&release),
            ..PartitionSources::default()
        },
    )
    .unwrap();
    assert_eq!((training, guard), benign::generate_partition(&dataset, &release, 7).unwrap());
}

#[test]
fn audience_release_partitions_and_audits() {
    let golden = golden("live.json");
    let release = support::au3_release();
    let pinned = &golden["audience_release"];
    assert_eq!(release.sha256, pinned["sha256"].as_str().unwrap());
    assert_eq!((release.train.len(), release.rehearsal.len()), (3120, 6240));
    let concat = |rows: &[Value]| -> String {
        let mut bytes = Vec::new();
        for row in rows {
            bytes.extend(value::canonical_bytes(row).unwrap());
        }
        value::sha256(&bytes)
    };
    assert_eq!(concat(&release.train), pinned["train_sha256"].as_str().unwrap());
    assert_eq!(concat(&release.guard), pinned["guard_sha256"].as_str().unwrap());
    for entry in golden["audience_partitions"].as_array().unwrap() {
        let (seed, count) = (entry["seed"].as_u64().unwrap(), entry["count"].as_i64().unwrap());
        let (training, guard) = audience::generate_partition(&release, seed, count).unwrap();
        partition_matches(entry, &training, &guard, &format!("audience seed {seed} count {count}"));
        let mut audit = audience::audit_originals(&release, &training, &guard, Some(seed), None).unwrap();
        audit.remove("audience_implementation_sha256");
        assert_eq!(audit_digest(&audit), entry["audit_sha256"].as_str().unwrap(), "audience audit seed {seed}");
        let config = BatchTrainingConfig { seed, ..BatchTrainingConfig::default() };
        let expanded = iter_training_examples(&training, &[], &config).unwrap();
        let mut audit = audience::audit_expanded(&release, &training, &expanded, &guard, &config, None).unwrap();
        audit.remove("audience_implementation_sha256");
        assert_eq!(audit_digest(&audit), entry["expanded_audit_sha256"].as_str().unwrap(), "audience expanded audit seed {seed}");
    }
    let entry = &golden["audience_partitions"][0];
    let seed = entry["seed"].as_u64().unwrap();
    let dispatched = generator::generate_training_partition(
        32,
        16,
        seed,
        &PartitionSources {
            sampling_strategy: Some("audience_coverage_v1"),
            audience_release: Some(&release),
            ..PartitionSources::default()
        },
    )
    .unwrap();
    assert_eq!(dispatched, audience::generate_partition(&release, seed, 32).unwrap());
}

#[test]
fn frozen_v3_schedules() {
    let golden = golden("live.json");
    let release = support::au3_release();
    let sources = v3::load_sources_from(&bc01_paths()).unwrap();
    let entries = golden["v3_schedules"].as_array().unwrap();
    assert_eq!(entries.len(), 16);
    for entry in entries {
        let seed = entry["seed"].as_u64().unwrap();
        let policy = if entry["policy"].as_str().unwrap() == "pilot" { Policy::PILOT } else { Policy { steps: 64 } };
        let hashes = to_value(&entry["source_hashes"]);
        let label = format!("{} seed {seed} {}", entry["sampler"], entry["policy"]);
        let schedule = match entry["sampler"].as_str().unwrap() {
            "au3" => v3::build_au3(seed, policy, &release, hashes).unwrap(),
            "bc01" => v3::schedule_bc01(seed, policy, &sources, hashes).unwrap(),
            other => panic!("unknown sampler {other}"),
        };
        let text = |key: &str| value::str_at(&schedule.source, key).unwrap().to_string();
        assert_eq!(text("train_wire_sha256"), entry["train_wire_sha256"].as_str().unwrap(), "{label}: train wire");
        assert_eq!(text("guard_wire_sha256"), entry["guard_wire_sha256"].as_str().unwrap(), "{label}: guard wire");
        assert_eq!(text("sidecar_sha256"), entry["sidecar_sha256"].as_str().unwrap(), "{label}: sidecar");
        assert_eq!(value::digest_of(&schedule.source).unwrap(), entry["source_commitment"].as_str().unwrap(), "{label}: source record");
        if entry["sampler"] == "bc01" {
            v3::validate_bc01(&schedule, policy, &sources).unwrap();
        }
    }
}

#[test]
fn privacy_head_pools_match_the_python_build() {
    let golden = golden("live.json");
    let resource =
        value::parse_bytes(&std::fs::read(repo_root().join("evaluation/datasets/privacy-heads-v3-scenarios-v1.json")).unwrap()).unwrap();
    let pools = privacy_heads::build(&resource).unwrap();
    for (split, entry) in golden["privacy_heads"].as_object().unwrap() {
        let rows = &pools[split.as_str()];
        assert_eq!(rows.len() as u64, entry["rows"].as_u64().unwrap(), "{split}: rows");
        let mut bytes = Vec::new();
        for row in rows {
            bytes.extend(value::canonical_bytes(row).unwrap());
        }
        assert_eq!(value::sha256(&bytes), entry["sha256"].as_str().unwrap(), "{split}: canonical rows");
    }
    assert_eq!(privacy_heads::audit_components(&resource).unwrap(), to_value(&golden["privacy_heads_components"]));
}

#[test]
fn seeded_augmentation_stream() {
    let golden = golden("live.json");
    let examples: Vec<Example> = (0..24)
        .map(|index| {
            let metadata = BTreeMap::from([("i".to_string(), index.to_string())]);
            Example::new(
                format!("Please note that John Doe lives at number {index}."),
                Classification(28),
                1.0 + f64::from(index) / 10.0,
                metadata,
            )
        })
        .collect();
    for entry in golden["augmentation"].as_array().unwrap() {
        let config = BatchTrainingConfig {
            seed: entry["seed"].as_u64().unwrap(),
            transformations_per_example: entry["transformations"].as_i64().unwrap(),
            ..BatchTrainingConfig::default()
        };
        let stream = iter_training_examples(&examples, &examples[..4], &config).unwrap();
        assert_eq!(
            rows_digest(&stream),
            entry["sha256"].as_str().unwrap(),
            "seed {} transformations {}",
            config.seed,
            config.transformations_per_example
        );
    }
}

#[test]
fn contextual_role_quota_sampler() {
    let golden = golden("live.json");
    let path = fixture("role-quota-synthetic.json");
    for entry in golden["role_quota"]["partitions"].as_array().unwrap() {
        let seed = entry["seed"].as_u64().unwrap();
        let sources = PartitionSources {
            dataset_path: Some(&path),
            sampling_strategy: Some("contextual_role_quota_v1"),
            ..PartitionSources::default()
        };
        let (training, heldout) = generator::generate_training_partition(256, 16, seed, &sources).unwrap();
        partition_matches(entry, &training, &heldout, &format!("role quota seed {seed}"));
        assert_eq!(audit_digest(&generator::contextual_sampling_audit(&training).unwrap()), entry["audit_sha256"].as_str().unwrap());
    }
}

#[test]
fn presence_partitions() {
    let golden = golden("live.json");
    let path = fixture("presence-synthetic.jsonl");
    for entry in golden["presence"]["partitions"].as_array().unwrap() {
        let (seed, count, heldout) =
            (entry["seed"].as_u64().unwrap(), entry["count"].as_i64().unwrap(), entry["heldout"].as_i64().unwrap());
        let (selected, held) = presence::generate_presence_training_partition(count, heldout, seed, &path).unwrap();
        let ids = |rows: &[presence::PresenceExample]| rows.iter().map(|row| row.example_id.clone()).collect::<Vec<_>>();
        let expected = |key: &str| entry[key].as_array().unwrap().iter().map(|id| id.as_str().unwrap().to_string()).collect::<Vec<_>>();
        assert_eq!(ids(&selected), expected("selected"), "presence seed {seed} count {count}");
        assert_eq!(ids(&held), expected("held"), "presence held-out seed {seed} count {count}");
    }
}

#[test]
fn synthetic_curriculum_allocation_and_fingerprints() {
    let golden = golden("live.json");
    let section = &golden["curriculum"];
    let curriculum = curriculum::load_curriculum(&fixture("curriculum/manifest.json")).unwrap();
    assert_eq!(curriculum.manifest_sha256, section["manifest_sha256"].as_str().unwrap());
    let mut state = MemoryState::default();
    for call in section["calls"].as_array().unwrap() {
        let metadata: BTreeMap<String, String> =
            call["metadata"].as_object().unwrap().iter().map(|(key, item)| (key.clone(), item.as_str().unwrap().to_string())).collect();
        let request = FuzzerTrainingRequest {
            request_id: call["request_id"].as_str().unwrap().to_string(),
            source_id: "study".to_string(),
            model_id: "privoke-balanced".to_string(),
            prompt_count: 32,
            seed: 1337,
            metadata,
        };
        let count = call["count"].as_i64().unwrap();
        let label = call["request_id"].as_str().unwrap();
        let settings = value::object(vec![("count", value::int(count)), ("replay_fraction", Value::Float(0.25))]);
        assert_eq!(
            curriculum::request_fingerprint(&request, &curriculum, &settings).unwrap(),
            call["fingerprint"].as_str().unwrap(),
            "{label}: fingerprint"
        );
        let batch = curriculum::reserve_batch(&curriculum, &mut state, &request, count, ReserveOptions::default()).unwrap();
        assert_eq!(rows_digest(&batch.examples), call["examples_sha256"].as_str().unwrap(), "{label}: examples");
        assert_eq!(rows_digest(&batch.replay), call["replay_sha256"].as_str().unwrap(), "{label}: replay");
        assert_eq!(rows_digest(&batch.heldout), call["heldout_sha256"].as_str().unwrap(), "{label}: gate");
        let expected: BTreeMap<String, String> =
            call["audit"].as_object().unwrap().iter().map(|(key, item)| (key.clone(), item.as_str().unwrap().to_string())).collect();
        assert_eq!(batch.audit, expected, "{label}: audit");
    }
}
