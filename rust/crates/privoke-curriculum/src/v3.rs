//! `pretrained-v3/src/{fuzzer_training,audience_schedule}.py`: the frozen common ordered streams of the V3 fits.
//!
//! Two samplers are frozen. `audience_common_frozen_stream_v1` (AU3) draws from the pinned audience release;
//! `existing_taxonomy_benign_common_frozen_stream_v1` (BC01) draws from the taxonomy and benign TRAIN snapshots.
//! Both emit the exact protobuf rows the V3 fit consumes, a sidecar that names every source row and transform, and
//! the digests that bind them.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use privoke_contracts::proto::v1::{RuntimeClassification, RuntimeTrainingExample};
use prost::Message;

use crate::audience::{self, AudienceRelease};
use crate::benign::{self, BenignRelease};
use crate::error::{Error, Result, invalid, read_file};
use crate::pyrandom::Random;
use crate::taxonomy::{self, TaxonomyDataset};
use crate::text::{random_pii_transform, synthetic_common_name, training_text_key, transform_variants};
use crate::types::Example;
use crate::value::{self, Value};

/// The AU3 sampler tag.
pub const AU3_SAMPLER: &str = "audience_common_frozen_stream_v1";
/// The BC01 sampler tag.
pub const BC01_SAMPLER: &str = "existing_taxonomy_benign_common_frozen_stream_v1";
/// Seed spacing between window batches.
pub const BATCH_SEED_STRIDE: u64 = 1009;
/// Transform names in `transform_variants` order.
pub const TRANSFORM_NAMES: [&str; 3] = ["identity", "review_prefix", "synthetic_name"];

/// The four pinned BC01 inputs: key, repository-relative path and SHA-256.
pub const INPUTS: [(&str, &str, &str); 4] = [
    (
        "taxonomy",
        "evaluation/results/iterative_fuzzer_20261011/taxonomy-coverage/release/taxonomy-coverage-v1.json",
        "3b777f328a8e08140ee964facbd559c694673336b4c5655320befdd84aef66e0",
    ),
    (
        "pool",
        "evaluation/results/iterative_fuzzer_20261011/train-benign-coverage/pool-authored.json",
        "7c6ed6f6d751d2568141f715abd7ee8235fec937d9d1c0f6c0e29d0f2b9b99d7",
    ),
    (
        "manifest",
        "evaluation/results/iterative_fuzzer_20261011/train-benign-coverage/r1/benign-manifest.json",
        "c817db3579b93f88ac2028d1f226884e3882ec9405b3bd2a868bdd5fa0a38ec9",
    ),
    (
        "proof",
        "evaluation/results/iterative_fuzzer_20261011/train-benign-coverage/r1/exclusion-proof.json",
        "77392a02fe414419ff909a639d42fbe2ee2fdec6b08ba52be6868ba43089d61a",
    ),
];

/// The frozen V3 work policy: the budget in optimizer steps, 64, 256 or 512, or the two-step pilot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Policy {
    /// `steps`.
    pub steps: u32,
}

impl Policy {
    /// The pilot policy of two steps.
    pub const PILOT: Policy = Policy { steps: 2 };

    /// `window_batches`: one batch for the pilot, eight otherwise.
    pub fn window_batches(self) -> usize {
        if self.steps == 2 { 1 } else { 8 }
    }

    /// The frozen policy dict (`POLICY` with this budget).
    pub fn to_value(self) -> Value {
        let pilot = self.steps == 2;
        value::object(vec![
            ("schema", value::int(1)),
            ("optimizer", value::string("adamw")),
            ("head_lr", Value::Float(0.001)),
            ("encoder_lr", Value::Float(0.00002)),
            ("betas", Value::Array(vec![Value::Float(0.9), Value::Float(0.999)])),
            ("eps", Value::Float(1e-8)),
            ("weight_decay", Value::Float(0.0)),
            ("clip_norm", Value::Float(1.0)),
            ("microbatch", value::int(4)),
            ("steps", value::int(i64::from(self.steps))),
            ("window_batches", value::int(if pilot { 1 } else { 8 })),
            ("batch_rows", value::int(64)),
            ("epochs", value::int(if pilot { 2 } else { i64::from(self.steps / 8) })),
            ("guard_rows", value::int(16)),
            ("dropout", Value::Bool(false)),
            ("max_tokens", value::int(512)),
            ("category_threshold", Value::Float(0.5)),
            ("objective", value::string("sensitivity_ce+visibility_ce+category_mean_bce")),
            ("checkpoint_selection", value::string("final_only")),
            ("publication", value::string("joint_improve_action_harm_zero_v1")),
        ])
    }

    /// `validate_policy(value, pilot=value["steps"] == 2)`.
    pub fn from_value(policy: &Value) -> Result<Policy> {
        let steps = value::get(policy, "steps").and_then(value::as_i64);
        let candidate = match steps {
            Some(2) => Policy::PILOT,
            Some(64) => Policy { steps: 64 },
            Some(256) => Policy { steps: 256 },
            Some(512) => Policy { steps: 512 },
            _ => return invalid("Predeclared v3 work budget must be 64, 256 or 512 steps."),
        };
        if *policy != candidate.to_value() {
            return invalid("Policy differs from the frozen v3 contract.");
        }
        Ok(candidate)
    }
}

/// `wire(row)`: the protobuf training row of an example.
pub fn wire(row: &Example) -> Result<RuntimeTrainingExample> {
    let target = row.classification()?;
    Ok(RuntimeTrainingExample {
        text: row.text.clone(),
        has_target: true,
        weight: row.weight,
        target: Some(RuntimeClassification {
            sensitivity: target.sensitivity().to_string(),
            visibility: target.visibility()?.to_string(),
            categories: target.categories().iter().map(|name| name.to_string()).collect(),
            packed: u32::from(target.pack()),
        }),
    })
}

/// The concatenated deterministic serialisation of rows, as `b"".join(r.SerializeToString(deterministic=True))`.
pub fn wire_bytes(rows: &[RuntimeTrainingExample]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for row in rows {
        bytes.extend(row.encode_to_vec());
    }
    bytes
}

fn metadata_value(metadata: &BTreeMap<String, String>) -> Value {
    value::from_string_map(metadata)
}

fn sidecar_fields(row: &Example, source_id: &str, family: &str, partition: &str, transform: &str, original_text: &str) -> Result<Value> {
    let target = row.classification()?;
    Ok(value::object(vec![
        ("source_id", value::string(source_id)),
        ("group_id", value::string(row.meta("group_id")?)),
        ("family", value::string(family)),
        ("partition", value::string(partition)),
        ("metadata", metadata_value(&row.metadata)),
        ("transform", value::string(transform)),
        ("original_text", value::string(original_text)),
        ("text", value::string(&row.text)),
        ("weight", Value::Float(row.weight)),
        ("target", target.to_value()?),
        ("packed_target", value::int(i64::from(target.pack()))),
    ]))
}

/// `audience_schedule.record(row, transform=, original_text=)`.
pub fn au3_record(row: &Example, transform: &str, original_text: Option<&str>) -> Result<Value> {
    let partition = if row.meta("split")? == "train" { "train" } else { "guard" };
    sidecar_fields(
        row,
        row.meta("example_id")?,
        row.meta("primary_category")?,
        partition,
        transform,
        original_text.filter(|text| !text.is_empty()).unwrap_or(&row.text),
    )
}

/// `fuzzer_training.sidecar(row, transform=, original_text=)`.
pub fn bc01_sidecar(row: &Example, transform: &str, original_text: Option<&str>) -> Result<Value> {
    let source_id = row.metadata.get("benign_row_id").or_else(|| row.metadata.get("taxonomy_row_id")).map_or("", String::as_str);
    let group = row.meta("group_id")?;
    let family = row.metadata.get("primary_category").map_or(group, String::as_str);
    let partition = row.metadata.get("partition").or_else(|| row.metadata.get("taxonomy_partition")).map_or("", String::as_str);
    sidecar_fields(row, source_id, family, partition, transform, original_text.unwrap_or(&row.text))
}

/// The digests of the Python sources a schedule pins, keyed by repository-relative path.
pub fn python_source_hashes(root: &Path, relative_paths: &[&str]) -> Result<Value> {
    let mut hashes = BTreeMap::new();
    for relative in relative_paths {
        hashes.insert((*relative).to_string(), value::string(&value::sha256(&read_file(&root.join(relative))?)));
    }
    Ok(Value::Object(hashes))
}

/// The three Python files the AU3 `source_hashes` pin.
pub const AU3_SOURCE_FILES: [&str; 3] = [
    "services/pretrained-v3/src/audience_schedule.py",
    "services/privoke-fuzzer/src/prompt_generation/audience_coverage.py",
    "services/privoke-fuzzer/src/training/transforms.py",
];

/// The four Python files the BC01 `source_hashes` pin.
pub const BC01_SOURCE_FILES: [&str; 4] = [
    "services/pretrained-v3/src/fuzzer_training.py",
    "services/privoke-fuzzer/src/prompt_generation/taxonomy_coverage.py",
    "services/privoke-fuzzer/src/prompt_generation/benign_coverage.py",
    "services/privoke-fuzzer/src/training/transforms.py",
];

/// A built schedule: the training rows, the guard rows and the source record.
#[derive(Debug, Clone, PartialEq)]
pub struct Schedule {
    /// Training rows, original then transformed per source row.
    pub training: Vec<RuntimeTrainingExample>,
    /// Guard rows.
    pub guard: Vec<RuntimeTrainingExample>,
    /// The source record (`source` in Python), including the digests.
    pub source: Value,
}

fn sorted_set(values: impl IntoIterator<Item = String>) -> Vec<String> {
    values.into_iter().collect::<BTreeSet<_>>().into_iter().collect()
}

fn variant_index(original: &str, text: &str) -> Result<usize> {
    transform_variants(original)
        .iter()
        .position(|variant| variant == text)
        .ok_or_else(|| Error::Invalid("transform text is not a variant".to_string()))
}

/// `audience_schedule.build(seed, policy, release)`; `source_hashes` is the `source_hashes` member of the record.
pub fn build_au3(seed: u64, policy: Policy, release: &AudienceRelease, source_hashes: Value) -> Result<Schedule> {
    let (_, guard) = audience::generate_partition(release, seed, 32)?;
    let mut training: Vec<RuntimeTrainingExample> = Vec::new();
    let mut records: Vec<Value> = Vec::new();
    for index in 0..policy.window_batches() as u64 {
        let batch_seed = seed + index * BATCH_SEED_STRIDE;
        let (originals, _) = audience::generate_partition(release, batch_seed, 32)?;
        let mut rng = Random::new(batch_seed);
        for original in &originals {
            let text = random_pii_transform(&original.text, &mut rng)?;
            // `variants.index(text)`: the first variant equal to the drawn text names the transform.
            let variants =
                [original.text.clone(), format!("Please review this prompt: {}", original.text), synthetic_common_name(&original.text)];
            let position = variants
                .iter()
                .position(|variant| *variant == text)
                .ok_or_else(|| Error::Invalid("transform text is not a variant".to_string()))?;
            let transformed = Example { text, target: original.target, weight: original.weight, metadata: original.metadata.clone() };
            training.push(wire(original)?);
            training.push(wire(&transformed)?);
            records.push(au3_record(original, "original", None)?);
            records.push(au3_record(&transformed, TRANSFORM_NAMES[position], Some(&original.text))?);
        }
    }
    let guards: Vec<RuntimeTrainingExample> = guard.iter().map(wire).collect::<Result<_>>()?;
    let train_groups =
        sorted_set(records.iter().map(|record| value::str_at(record, "group_id").map(str::to_string)).collect::<Result<Vec<_>>>()?);
    let guard_groups = sorted_set(guard.iter().map(|row| row.meta("group_id").map(str::to_string)).collect::<Result<Vec<_>>>()?);
    let unique_sources = records.iter().map(|record| value::str_at(record, "source_id")).collect::<Result<BTreeSet<_>>>()?.len();
    let unique_texts = training.iter().map(|row| training_text_key(&row.text)).collect::<BTreeSet<_>>().len();
    let guard_records: Vec<Value> = guard.iter().map(|row| au3_record(row, "original", None)).collect::<Result<_>>()?;
    let originals_count = training.len() / 2;
    let sidecars = value::object(vec![("train", Value::Array(records.clone())), ("guard", Value::Array(guard_records.clone()))]);
    let source = value::object(vec![
        ("schema", value::int(1)),
        ("sampler", value::string(AU3_SAMPLER)),
        ("seed", value::uint(seed)),
        ("inputs", value::object(vec![("audience_manifest", value::string(&release.sha256))])),
        ("train_rows", value::int(training.len() as i64)),
        ("guard_rows", value::int(guards.len() as i64)),
        ("ordered_original_count", value::int(originals_count as i64)),
        ("train_sidecar", Value::Array(records)),
        ("guard_sidecar", Value::Array(guard_records)),
        ("train_wire_sha256", value::string(&value::sha256(&wire_bytes(&training)))),
        ("guard_wire_sha256", value::string(&value::sha256(&wire_bytes(&guards)))),
        ("source_hashes", source_hashes),
        ("train_occurrences", value::int(training.len() as i64)),
        ("original_occurrences", value::int(originals_count as i64)),
        ("unique_source_ids", value::int(unique_sources as i64)),
        ("repeated_source_occurrences", value::int(originals_count as i64 - unique_sources as i64)),
        ("unique_normalized_texts", value::int(unique_texts as i64)),
        ("repeated_text_occurrences", value::int((training.len() - unique_texts) as i64)),
        ("guard_occurrences", value::int(guards.len() as i64)),
        ("guard_unique_source_ids", value::int(guards.len() as i64)),
        ("train_groups", value::strings(&train_groups)),
        ("guard_groups", value::strings(&guard_groups)),
        ("sidecar_sha256", value::string(&value::digest_of(&sidecars)?)),
    ]);
    Ok(Schedule { training, guard: guards, source })
}

/// `audience_schedule.validate(training, guard, source, policy)`: the actual rows and the record must equal the
/// trusted deterministic schedule. Returns the exposure counts the record carries.
pub fn validate_au3(schedule: &Schedule, policy: Policy, release: &AudienceRelease) -> Result<Value> {
    let seed = value::i64_at(&schedule.source, "seed")? as u64;
    let hashes = value::require(&schedule.source, "source_hashes")?.clone();
    let expected = build_au3(seed, policy, release, hashes)?;
    if value::canonical_bytes(&schedule.source)? != value::canonical_bytes(&expected.source)?
        || schedule.training != expected.training
        || schedule.guard != expected.guard
    {
        return invalid("AU3 actual source wires/sidecars/quotas differ from trusted deterministic schedule.");
    }
    let keys = [
        "train_occurrences",
        "original_occurrences",
        "unique_source_ids",
        "repeated_source_occurrences",
        "unique_normalized_texts",
        "repeated_text_occurrences",
        "guard_occurrences",
        "guard_unique_source_ids",
        "train_groups",
        "guard_groups",
    ];
    let mut counts = BTreeMap::new();
    for key in keys {
        counts.insert(key.to_string(), value::require(&expected.source, key)?.clone());
    }
    Ok(Value::Object(counts))
}

/// The pinned BC01 sources, loaded and validated under every invariance transform.
#[derive(Debug, Clone, PartialEq)]
pub struct Sources {
    /// The taxonomy dataset.
    pub dataset: TaxonomyDataset,
    /// The benign release.
    pub release: BenignRelease,
}

/// `load_sources(input_root)` with explicit paths per input key (`taxonomy`, `pool`, `manifest`, `proof`).
pub fn load_sources_from(paths: &BTreeMap<&str, PathBuf>) -> Result<Sources> {
    for (key, _, sha) in INPUTS {
        let path = paths.get(key).ok_or_else(|| Error::Invalid(format!("missing input path {key}")))?;
        if value::sha256(&read_file(path)?) != sha {
            return invalid(format!("Approved fuzzer TRAIN source bytes changed: {key}"));
        }
    }
    let dataset = taxonomy::load_dataset(paths.get("taxonomy").map(PathBuf::as_path))?;
    let release = benign::load_release(&paths["pool"], &paths["manifest"], &paths["proof"], &dataset)?;
    // Validate all permanent families under every allowed transformation, not only the sampled window.
    let mut variants: BTreeMap<String, (String, u16)> = BTreeMap::new();
    for row in dataset.rows.iter().chain(&release.pool.rows) {
        let record = bc01_sidecar(row, "original", None)?;
        let binding = (value::str_at(&record, "partition")?.to_string(), row.packed().unwrap_or(0));
        for text in transform_variants(&row.text) {
            let key = training_text_key(&text);
            if variants.get(&key).is_some_and(|existing| *existing != binding) {
                return invalid("Permanent partitions/targets conflict under an invariant transform.");
            }
            variants.insert(key, binding.clone());
        }
    }
    Ok(Sources { dataset, release })
}

/// `load_sources(input_root)`: the pinned inputs under a repository root.
pub fn load_sources(root: &Path) -> Result<Sources> {
    let paths: BTreeMap<&str, PathBuf> = INPUTS.iter().map(|(key, relative, _)| (*key, root.join(relative))).collect();
    load_sources_from(&paths)
}

fn bc01_inputs() -> Value {
    value::object(INPUTS.iter().map(|(key, _, sha)| (*key, value::string(sha))).collect())
}

/// `fuzzer_training.schedule(seed, policy, input_root)` for the BC01 sampler; `source_hashes` is the record's member.
pub fn schedule_bc01(seed: u64, policy: Policy, sources: &Sources, source_hashes: Value) -> Result<Schedule> {
    let (dataset, release) = (&sources.dataset, &sources.release);
    let mut training = Vec::new();
    let mut records = Vec::new();
    let (_, guard) = benign::generate_partition(dataset, release, seed)?;
    for index in 0..policy.window_batches() as u64 {
        let batch_seed = seed + index * BATCH_SEED_STRIDE;
        let (rows, _) = benign::generate_partition(dataset, release, batch_seed)?;
        let mut rng = Random::new(batch_seed);
        for row in &rows {
            let text = random_pii_transform(&row.text, &mut rng)?;
            let variant = variant_index(&row.text, &text)?;
            let transformed = Example { text, target: row.target, weight: row.weight, metadata: row.metadata.clone() };
            training.push(wire(row)?);
            training.push(wire(&transformed)?);
            records.push(bc01_sidecar(row, "original", None)?);
            records.push(bc01_sidecar(&transformed, TRANSFORM_NAMES[variant], Some(&row.text))?);
        }
    }
    let guard_wire: Vec<RuntimeTrainingExample> = guard.iter().map(wire).collect::<Result<_>>()?;
    let guard_records: Vec<Value> = guard.iter().map(|row| bc01_sidecar(row, "original", None)).collect::<Result<_>>()?;
    let mut source = value::object(vec![
        ("schema", value::int(1)),
        ("sampler", value::string(BC01_SAMPLER)),
        ("seed", value::uint(seed)),
        ("inputs", bc01_inputs()),
        ("train_rows", value::int(training.len() as i64)),
        ("guard_rows", value::int(guard_wire.len() as i64)),
        ("ordered_original_count", value::int((training.len() / 2) as i64)),
        ("train_sidecar", Value::Array(records.clone())),
        ("guard_sidecar", Value::Array(guard_records.clone())),
        ("train_wire_sha256", value::string(&value::sha256(&wire_bytes(&training)))),
        ("guard_wire_sha256", value::string(&value::sha256(&wire_bytes(&guard_wire)))),
        ("source_hashes", source_hashes),
    ]);
    let schedule = Schedule { training, guard: guard_wire, source: source.clone() };
    let counts = validate_bc01(&schedule, policy, sources)?;
    if let (Value::Object(map), Value::Object(extra)) = (&mut source, counts) {
        map.extend(extra);
        let sidecars = value::object(vec![("train", Value::Array(records)), ("guard", Value::Array(guard_records))]);
        map.insert("sidecar_sha256".to_string(), value::string(&value::digest_of(&sidecars)?));
    }
    Ok(Schedule { source, ..schedule })
}

/// `validate_schedule(...)` for the BC01 sampler: actual serialised rows against the pinned source, the permanent
/// split and the transforms. Returns the exposure counts.
pub fn validate_bc01(schedule: &Schedule, policy: Policy, sources: &Sources) -> Result<Value> {
    let (dataset, release) = (&sources.dataset, &sources.release);
    let source = &schedule.source;
    let (training, guard) = (&schedule.training, &schedule.guard);
    if value::get(source, "schema").and_then(value::as_i64) != Some(1)
        || value::get(source, "sampler").and_then(value::as_str) != Some(BC01_SAMPLER)
        || value::get(source, "inputs") != Some(&bc01_inputs())
    {
        return invalid("Pinned source proof differs from admitted inputs.");
    }
    let train_meta = value::array_at(source, "train_sidecar")?;
    let guard_meta = value::array_at(source, "guard_sidecar")?;
    if training.len() != policy.window_batches() * 64
        || guard.len() != 16
        || train_meta.len() != training.len()
        || guard_meta.len() != guard.len()
    {
        return invalid("Actual schedule/sidecar denominator mismatch.");
    }
    let mut source_rows: BTreeMap<String, &Example> = BTreeMap::new();
    for row in dataset.rows.iter().chain(&release.pool.rows) {
        if let Some(id) = row.metadata.get("benign_row_id").or_else(|| row.metadata.get("taxonomy_row_id")) {
            source_rows.insert(id.clone(), row);
        }
    }
    let mut seen_targets: BTreeMap<String, u32> = BTreeMap::new();
    for (partition, rows, metadata) in [("train", training, train_meta), ("guard", guard, guard_meta)] {
        for (row, record) in rows.iter().zip(metadata) {
            let source_id = value::str_at(record, "source_id")?;
            let original = source_rows.get(source_id).ok_or_else(|| Error::Invalid("Schedule source ID is not admitted.".to_string()))?;
            let expected = bc01_sidecar(original, "original", None)?;
            for key in ["source_id", "group_id", "family", "partition", "original_text", "target", "packed_target", "weight"] {
                if value::get(record, key) != value::get(&expected, key) {
                    return invalid(format!("Schedule sidecar differs from pinned source: {key}"));
                }
            }
            let target = row
                .target
                .as_ref()
                .ok_or_else(|| Error::Invalid("Serialized row differs from sidecar/permanent partition.".to_string()))?;
            if value::str_at(record, "partition")? != partition
                || row.text != value::str_at(record, "text")?
                || row.weight != 1.0
                || !row.has_target
            {
                return invalid("Serialized row differs from sidecar/permanent partition.");
            }
            let named = value::object(vec![
                ("sensitivity", value::string(&target.sensitivity)),
                ("visibility", value::string(&target.visibility)),
                ("categories", value::strings(&target.categories)),
            ]);
            if value::get(record, "packed_target").and_then(value::as_i64) != Some(i64::from(target.packed))
                || value::get(record, "target") != Some(&named)
            {
                return invalid("Serialized named/packed target differs from pinned source.");
            }
            let transform = value::str_at(record, "transform")?;
            let allowed = transform_variants(&original.text);
            let wanted = if transform == "original" {
                original.text.clone()
            } else {
                let position = TRANSFORM_NAMES.iter().position(|name| *name == transform);
                match (partition, position) {
                    ("train", Some(position)) => allowed[position].clone(),
                    _ => return invalid("Unadmitted transformation."),
                }
            };
            if row.text != wanted {
                return invalid("Actual text differs from named invariant transformation.");
            }
            let key = training_text_key(&row.text);
            if seen_targets.get(&key).is_some_and(|existing| *existing != target.packed) {
                return invalid("Conflicting targets for a normalized schedule text.");
            }
            seen_targets.insert(key, target.packed);
        }
    }
    // Validate the selected original stream against the maintained sampler per batch.
    let seed = value::i64_at(source, "seed")? as u64;
    for batch in 0..policy.window_batches() {
        let batch_seed = seed + batch as u64 * BATCH_SEED_STRIDE;
        let (expected, _) = benign::generate_partition(dataset, release, batch_seed)?;
        let mut rng = Random::new(batch_seed);
        let records = &train_meta[batch * 64..(batch + 1) * 64];
        for (index, original) in expected.iter().enumerate() {
            let (first, transformed) = (&records[2 * index], &records[2 * index + 1]);
            let metadata = metadata_value(&original.metadata);
            if value::get(first, "metadata") != Some(&metadata) || value::get(transformed, "metadata") != Some(&metadata) {
                return invalid("Actual provenance metadata differs from the maintained sampler.");
            }
            let expected_id = value::str_at(&bc01_sidecar(original, "original", None)?, "source_id")?.to_string();
            if value::str_at(first, "source_id")? != expected_id
                || value::str_at(first, "transform")? != "original"
                || value::str_at(transformed, "source_id")? != value::str_at(first, "source_id")?
                || value::str_at(transformed, "transform")? == "original"
            {
                return invalid("Actual original/transform ordering differs from sampler.");
            }
            if value::str_at(transformed, "text")? != random_pii_transform(&original.text, &mut rng)? {
                return invalid("Actual transformed stream differs from the frozen seed.");
            }
        }
    }
    let (_, expected_guard) = benign::generate_partition(dataset, release, seed)?;
    let expected_ids: Vec<String> = expected_guard
        .iter()
        .map(|row| value::str_at(&bc01_sidecar(row, "original", None)?, "source_id").map(str::to_string))
        .collect::<Result<_>>()?;
    let actual_ids: Vec<String> =
        guard_meta.iter().map(|record| value::str_at(record, "source_id").map(str::to_string)).collect::<Result<_>>()?;
    if actual_ids != expected_ids {
        return invalid("Actual guard differs from the common seed guard.");
    }
    let guard_metadata: Vec<Option<&Value>> = guard_meta.iter().map(|record| value::get(record, "metadata")).collect();
    let expected_metadata: Vec<Value> = expected_guard.iter().map(|row| metadata_value(&row.metadata)).collect();
    if guard_metadata.iter().zip(&expected_metadata).any(|(actual, expected)| *actual != Some(expected)) {
        return invalid("Actual guard metadata differs from pinned source.");
    }
    let train_groups =
        sorted_set(train_meta.iter().map(|record| value::str_at(record, "group_id").map(str::to_string)).collect::<Result<Vec<_>>>()?);
    let guard_groups =
        sorted_set(guard_meta.iter().map(|record| value::str_at(record, "group_id").map(str::to_string)).collect::<Result<Vec<_>>>()?);
    let train_texts: BTreeSet<String> = training.iter().map(|row| training_text_key(&row.text)).collect();
    let guard_texts: BTreeSet<String> = guard.iter().map(|row| training_text_key(&row.text)).collect();
    if train_groups.iter().any(|group| guard_groups.contains(group)) || train_texts.intersection(&guard_texts).next().is_some() {
        return invalid("TRAIN/guard group or normalized-text overlap.");
    }
    for (key, rows) in [("train", training), ("guard", guard)] {
        let committed = value::str_at(source, &format!("{key}_wire_sha256"))?;
        if committed != value::sha256(&wire_bytes(rows)) {
            return invalid("Actual wire commitment mismatch.");
        }
    }
    let unique_sources = train_meta.iter().map(|record| value::str_at(record, "source_id")).collect::<Result<BTreeSet<_>>>()?.len();
    let unique_texts = train_texts.len();
    let guard_unique = guard_meta.iter().map(|record| value::str_at(record, "source_id")).collect::<Result<BTreeSet<_>>>()?.len();
    let originals = training.len() / 2;
    Ok(value::object(vec![
        ("train_occurrences", value::int(training.len() as i64)),
        ("original_occurrences", value::int(originals as i64)),
        ("unique_source_ids", value::int(unique_sources as i64)),
        ("repeated_source_occurrences", value::int(originals as i64 - unique_sources as i64)),
        ("unique_normalized_texts", value::int(unique_texts as i64)),
        ("repeated_text_occurrences", value::int((training.len() - unique_texts) as i64)),
        ("guard_occurrences", value::int(guard.len() as i64)),
        ("guard_unique_source_ids", value::int(guard_unique as i64)),
        ("train_groups", value::strings(&train_groups)),
        ("guard_groups", value::strings(&guard_groups)),
    ]))
}

/// The wire rows `validate_source_evidence` reconstructs from a sidecar list.
fn rows_from_sidecar(records: &[Value]) -> Result<Vec<RuntimeTrainingExample>> {
    let mut rows = Vec::with_capacity(records.len());
    for record in records {
        let target = value::require(record, "target")?;
        rows.push(RuntimeTrainingExample {
            text: value::str_at(record, "text")?.to_string(),
            has_target: true,
            weight: value::get(record, "weight").and_then(value::as_number).unwrap_or(1.0),
            target: Some(RuntimeClassification {
                sensitivity: value::str_at(target, "sensitivity")?.to_string(),
                visibility: value::str_at(target, "visibility")?.to_string(),
                categories: value::array_at(target, "categories")?.iter().filter_map(value::as_str).map(str::to_string).collect(),
                packed: value::i64_at(record, "packed_target")? as u32,
            }),
        });
    }
    Ok(rows)
}

/// `validate_source_evidence(evidence)` for the AU3 sampler: reconstruct the committed wires from the sidecars and
/// validate the whole source against the trusted deterministic schedule.
pub fn validate_source_evidence_au3(evidence: &Value, release: &AudienceRelease) -> Result<()> {
    let source = value::require(evidence, "source")?;
    if value::digest_of(source)? != value::str_at(evidence, "source_commitment")? {
        return invalid("Execution source bytes differ from fit commitment.");
    }
    let policy = Policy::from_value(value::require(evidence, "policy")?)?;
    let schedule = Schedule {
        training: rows_from_sidecar(value::array_at(source, "train_sidecar")?)?,
        guard: rows_from_sidecar(value::array_at(source, "guard_sidecar")?)?,
        source: source.clone(),
    };
    let counts = validate_au3(&schedule, policy, release)?;
    if value::as_object(&counts).is_some_and(|map| map.iter().any(|(key, expected)| value::get(source, key) != Some(expected))) {
        return invalid("Source exposure counts differ from actual rows.");
    }
    let sidecars = value::object(vec![
        ("train", value::require(source, "train_sidecar")?.clone()),
        ("guard", value::require(source, "guard_sidecar")?.clone()),
    ]);
    if value::get(source, "sidecar_sha256").and_then(value::as_str) != Some(value::digest_of(&sidecars)?.as_str()) {
        return invalid("Source sidecar commitment differs.");
    }
    for key in ["train_wire_sha256", "guard_wire_sha256"] {
        if value::get(source, key) != value::get(evidence, key) {
            return invalid("Evidence wire differs from actual source.");
        }
    }
    Ok(())
}

/// The release as `audience_schedule.trusted_release()` loads it: a custom manifest needs both a path and a pin.
pub fn trusted_release(manifest_path: Option<&Path>, manifest_sha256: Option<&str>) -> Result<AudienceRelease> {
    if manifest_path.is_some() != manifest_sha256.is_some() {
        return invalid("Custom v3 audience release requires both trusted path and pin.");
    }
    audience::load_release(manifest_path, manifest_sha256)
}
