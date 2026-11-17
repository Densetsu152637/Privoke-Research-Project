//! `prompt_generation.train_window` with the window contract of `privoke_model.window_training` that it validates
//! against: the bounded BC01 TRAIN families and their actual transformed wire rows, frozen for one fit.

use std::collections::BTreeSet;

use privoke_contracts::digest::derived_seed;

use crate::benign::{self, BenignRelease};
use crate::classification::Classification;
use crate::error::{Error, Result, invalid};
use crate::taxonomy::TaxonomyDataset;
use crate::text::training_text_key;
use crate::trainer::iter_training_examples;
use crate::types::{BatchTrainingConfig, Example};
use crate::value::{self, Value};

/// `window_training.SAMPLER`.
pub const SAMPLER: &str = "taxonomy_benign_train_window_v1";
/// `window_training.SELECTOR`.
pub const SELECTOR: &str = "transported_train_component_rank_v1";
/// `window_training.COMPONENTS`.
pub const COMPONENTS: [&str; 5] = ["sensitivity", "severity", "category", "visibility", "action"];

fn adam_config() -> Value {
    value::object(vec![
        ("steps", value::int(64)),
        ("eta", Value::Float(0.003)),
        ("beta1", Value::Float(0.9)),
        ("beta2", Value::Float(0.999)),
        ("epsilon", Value::Float(1e-8)),
        ("delta_cap", Value::Float(0.05)),
        ("margin_coefficient", value::int(1)),
        ("device", value::string("cpu")),
        ("moment_dtype", value::string("float64")),
        ("gradient_denominator", value::int(1)),
        ("microbatch_size", value::int(32)),
        ("cpu_threads", value::int(1)),
    ])
}

/// `window_training.CONFIG`.
pub fn config() -> Value {
    value::object(vec![
        ("adam", adam_config()),
        ("blocks", value::int(8)),
        ("block_rows", value::int(64)),
        ("epochs", value::int(8)),
        ("candidate_seeds", value::int(64)),
        ("checkpoints", Value::Array((8..=64).step_by(8).map(value::int).collect())),
        ("epsilon", Value::Float(1e-6)),
        ("margin_cap", Value::Float(1.0)),
        ("auxiliary_coefficient", value::int(1)),
        ("normalization", value::string("category_bits_then_components_then_rows_v1")),
        ("main_normalization", value::string("eight_times_block_over_frozen_window_weight_v1")),
        ("selector", value::string(SELECTOR)),
        ("component_order", value::strings(&COMPONENTS)),
    ])
}

/// `derived_seed(seed, purpose, index)`.
pub fn seed_for(seed: u64, purpose: &str, index: u64) -> Result<u64> {
    Ok(derived_seed(seed, purpose, index)?)
}

/// `schedule(seed)`: eight permutations of the eight blocks, ordered by hashed seeds so no runtime RNG is involved.
pub fn schedule(seed: u64) -> Result<Vec<usize>> {
    let mut order = Vec::with_capacity(64);
    for epoch in 0..8u64 {
        let mut keyed: Vec<(u64, usize)> = Vec::with_capacity(8);
        for block in 0..8usize {
            keyed.push((seed_for(seed, "epoch", epoch * 8 + block as u64)?, block));
        }
        keyed.sort_unstable();
        order.extend(keyed.into_iter().map(|(_, block)| block));
    }
    Ok(order)
}

fn source(row: &Example) -> Result<Value> {
    let packed = row.packed().ok_or_else(|| Error::Invalid("Window requires explicit targets and finite positive weights.".to_string()))?;
    let id = row
        .metadata
        .get("benign_row_id")
        .or_else(|| row.metadata.get("taxonomy_row_id"))
        .ok_or_else(|| Error::Invalid("missing source id".to_string()))?;
    let partition = row
        .metadata
        .get("taxonomy_partition")
        .or_else(|| row.metadata.get("split"))
        .ok_or_else(|| Error::Invalid("missing partition".to_string()))?;
    Ok(value::object(vec![
        ("text", value::string(&row.text)),
        ("packed", value::int(i64::from(packed))),
        ("weight", Value::Float(row.weight)),
        ("id", value::string(id)),
        ("group", value::string(row.meta("group_id")?)),
        ("partition", value::string(partition)),
        ("family_kind", value::string(if row.metadata.contains_key("benign_row_id") { "benign" } else { "taxonomy" })),
    ]))
}

/// `prepare_window(dataset, release, seed)`: at most 64 candidates; greedy new-family coverage, then earliest unused blocks.
pub fn prepare_window(dataset: &TaxonomyDataset, release: &BenignRelease, seed: u64) -> Result<Value> {
    benign::validate_legacy_snapshot(dataset)?;
    benign::validate_release(release, dataset)?;
    struct Candidate {
        index: u64,
        seed: u64,
        originals: Vec<Example>,
        groups: BTreeSet<String>,
    }
    let mut candidates: Vec<Candidate> = Vec::new();
    for index in 0..64u64 {
        let candidate_seed = seed_for(seed, "candidate", index)?;
        let (originals, _) = benign::generate_partition(dataset, release, candidate_seed)?;
        let groups: BTreeSet<String> = originals
            .iter()
            .filter(|row| row.metadata.contains_key("taxonomy_row_id"))
            .map(|row| row.meta("group_id").map(str::to_string))
            .collect::<Result<_>>()?;
        candidates.push(Candidate { index, seed: candidate_seed, originals, groups });
    }
    let mut selected: Vec<Candidate> = Vec::new();
    let mut covered: BTreeSet<String> = BTreeSet::new();
    while selected.len() < 8 {
        let position = candidates
            .iter()
            .enumerate()
            .min_by_key(|(_, candidate)| (std::cmp::Reverse(candidate.groups.difference(&covered).count()), candidate.index))
            .map(|(position, _)| position)
            .ok_or_else(|| {
                Error::Invalid("Bounded64-candidate search cannot cover all20 permanent TRAIN families in8blocks.".to_string())
            })?;
        let chosen = candidates.remove(position);
        covered.extend(chosen.groups.iter().cloned());
        selected.push(chosen);
    }
    let expected: BTreeSet<String> =
        dataset.partitions.iter().filter(|(_, partition)| partition.as_str() == "train").map(|(group, _)| group.clone()).collect();
    if covered != expected || expected.len() != 20 {
        return invalid("Bounded64-candidate search cannot cover all20 permanent TRAIN families in8blocks.");
    }
    let (_, guard) = benign::generate_partition(dataset, release, seed)?;
    let mut blocks = Vec::new();
    let mut all_rows: Vec<Value> = Vec::new();
    for candidate in &selected {
        let config = BatchTrainingConfig {
            learning_rate: 0.003,
            max_gradient: 0.05,
            transformations_per_example: 1,
            seed: candidate.seed,
            ..BatchTrainingConfig::default()
        };
        let expanded = iter_training_examples(&candidate.originals, &[], &config)?;
        let (_, candidate_guard) = benign::generate_partition(dataset, release, candidate.seed)?;
        benign::audit_expanded(dataset, release, &candidate.originals, &expanded, &candidate_guard, &config)?;
        let rows: Vec<Value> = expanded.iter().map(source).collect::<Result<_>>()?;
        all_rows.extend(rows.iter().cloned());
        blocks.push(value::object(vec![("seed", value::uint(candidate.seed)), ("rows", Value::Array(rows))]));
    }
    let ids: BTreeSet<&str> = all_rows.iter().map(|row| value::str_at(row, "id")).collect::<Result<_>>()?;
    let texts: BTreeSet<String> = all_rows.iter().map(|row| value::str_at(row, "text").map(training_text_key)).collect::<Result<_>>()?;
    let result = value::object(vec![
        ("schema", value::int(1)),
        ("sampler", value::string(SAMPLER)),
        ("seed", value::uint(seed)),
        ("config", config()),
        (
            "sources",
            value::object(vec![
                ("taxonomy", value::string(&dataset.sha256)),
                ("benign", value::string(&release.sha256)),
                ("pool", value::string(&release.pool.sha256)),
                ("proof", value::string(&release.proof_sha256)),
            ]),
        ),
        ("blocks", Value::Array(blocks)),
        ("guard", Value::Array(guard.iter().map(source).collect::<Result<_>>()?)),
        (
            "provenance",
            value::object(vec![
                ("wire_rows", value::int(512)),
                ("unique_source_ids", value::int(ids.len() as i64)),
                ("unique_texts", value::int(texts.len() as i64)),
                ("taxonomy_families", value::int(20)),
                ("repeated_source_presentations", value::int(512 - ids.len() as i64)),
                ("fit_release", Value::Bool(false)),
            ]),
        ),
    ]);
    validate_window(&result)?;
    Ok(result)
}

fn is_sha256(value: &Value) -> bool {
    value::as_str(value).is_some_and(|text| text.len() == 64 && text.chars().all(|character| matches!(character, '0'..='9' | 'a'..='f')))
}

fn validate_row(row: &Value) -> Result<()> {
    let keys: BTreeSet<&str> = value::as_object(row).map(|map| map.keys().map(String::as_str).collect()).unwrap_or_default();
    let expected: BTreeSet<&str> = ["text", "packed", "weight", "id", "group", "partition", "family_kind"].into_iter().collect();
    let packed = value::get(row, "packed").and_then(value::as_i64);
    let weight = value::get(row, "weight").and_then(value::as_number);
    let strings_ok =
        ["text", "id", "group"].iter().all(|key| value::get(row, key).and_then(value::as_str).is_some_and(|text| !text.is_empty()));
    let kind_ok = matches!(value::get(row, "family_kind").and_then(value::as_str), Some("taxonomy" | "benign"));
    if keys != expected
        || !packed.is_some_and(|packed| (0..=65535).contains(&packed))
        || !weight.is_some_and(|weight| weight.is_finite() && weight > 0.0)
        || !strings_ok
        || !kind_ok
    {
        return invalid("Malformed frozen source row.");
    }
    Classification::from_packed(packed.unwrap_or(0)).visibility()?;
    Ok(())
}

/// `validate_window(value)`.
pub fn validate_window(window: &Value) -> Result<()> {
    let keys: BTreeSet<&str> = value::as_object(window).map(|map| map.keys().map(String::as_str).collect()).unwrap_or_default();
    let top: BTreeSet<&str> = ["schema", "sampler", "seed", "config", "sources", "blocks", "guard", "provenance"].into_iter().collect();
    let blocks = value::get(window, "blocks").and_then(value::as_array);
    let guard = value::get(window, "guard").and_then(value::as_array);
    let sources = value::get(window, "sources");
    let source_keys: BTreeSet<&str> =
        sources.and_then(value::as_object).map(|map| map.keys().map(String::as_str).collect()).unwrap_or_default();
    if keys != top
        || value::get(window, "schema").and_then(value::as_i64) != Some(1)
        || value::get(window, "sampler").and_then(value::as_str) != Some(SAMPLER)
        || value::get(window, "seed").and_then(value::as_i64).is_none()
        || value::get(window, "config") != Some(&config())
        || blocks.map(Vec::len) != Some(8)
        || guard.map(Vec::len) != Some(16)
        || source_keys != ["taxonomy", "benign", "pool", "proof"].into_iter().collect()
        || !sources.and_then(value::as_object).is_some_and(|map| map.values().all(is_sha256))
    {
        return invalid("Invalid frozen TRAIN window contract.");
    }
    let (mut groups, mut guard_groups): (BTreeSet<String>, BTreeSet<String>) = (BTreeSet::new(), BTreeSet::new());
    let (mut ids, mut texts): (Vec<String>, Vec<String>) = (Vec::new(), Vec::new());
    for block in blocks.map_or(&[][..], Vec::as_slice) {
        let block_keys: BTreeSet<&str> = value::as_object(block).map(|map| map.keys().map(String::as_str).collect()).unwrap_or_default();
        let rows = value::get(block, "rows").and_then(value::as_array);
        if block_keys != ["seed", "rows"].into_iter().collect()
            || value::get(block, "seed").and_then(value::as_i64).is_none()
            || rows.map(Vec::len) != Some(64)
        {
            return invalid("Invalid frozen TRAIN block.");
        }
        for row in rows.map_or(&[][..], Vec::as_slice) {
            validate_row(row)?;
            if value::str_at(row, "partition")? != "train" {
                return invalid("Window may access permanent TRAIN only.");
            }
            if value::str_at(row, "family_kind")? == "taxonomy" {
                groups.insert(value::str_at(row, "group")?.to_string());
            }
            ids.push(value::str_at(row, "id")?.to_string());
            texts.push(training_text_key(value::str_at(row, "text")?));
        }
    }
    let guard_rows = guard.map_or(&[][..], Vec::as_slice);
    for row in guard_rows {
        validate_row(row)?;
        if value::str_at(row, "partition")? != "guard" {
            return invalid("Guard must retain permanent guard membership.");
        }
        guard_groups.insert(value::str_at(row, "group")?.to_string());
    }
    let unique_texts: BTreeSet<&String> = texts.iter().collect();
    let guard_texts: BTreeSet<String> =
        guard_rows.iter().map(|row| value::str_at(row, "text").map(training_text_key)).collect::<Result<_>>()?;
    if groups.len() != 20
        || groups.intersection(&guard_groups).next().is_some()
        || unique_texts.iter().any(|text| guard_texts.contains(*text))
    {
        return invalid("Window requires all20 TRAIN families and separate guard groups/texts.");
    }
    let unique_ids: BTreeSet<&String> = ids.iter().collect();
    let actual = value::object(vec![
        ("wire_rows", value::int(512)),
        ("unique_source_ids", value::int(unique_ids.len() as i64)),
        ("unique_texts", value::int(unique_texts.len() as i64)),
        ("taxonomy_families", value::int(20)),
        ("repeated_source_presentations", value::int(512 - unique_ids.len() as i64)),
        ("fit_release", Value::Bool(false)),
    ]);
    if value::get(window, "provenance") != Some(&actual) {
        return invalid("Window source multiplicity accounting differs.");
    }
    Ok(())
}

/// `flat_rows(window)`.
pub fn flat_rows(window: &Value) -> Result<Vec<&Value>> {
    let mut out = Vec::new();
    for block in value::array_at(window, "blocks")? {
        out.extend(value::array_at(block, "rows")?.iter());
    }
    Ok(out)
}

/// `validate_sources(window, dataset, release)`.
pub fn validate_sources(window: &Value, dataset: &TaxonomyDataset, release: &BenignRelease) -> Result<()> {
    let seed = value::i64_at(window, "seed")? as u64;
    if *window != prepare_window(dataset, release, seed)? {
        return invalid("Frozen window differs from bounded deterministic authenticated source selection.");
    }
    Ok(())
}

/// `examples(window)`: the training stream and the guard, as examples.
pub fn examples(window: &Value) -> Result<(Vec<Example>, Vec<Example>)> {
    validate_window(window)?;
    let convert = |row: &Value| -> Result<Example> {
        let mut metadata = std::collections::BTreeMap::new();
        metadata.insert("source_id".to_string(), value::str_at(row, "id")?.to_string());
        metadata.insert("group_id".to_string(), value::str_at(row, "group")?.to_string());
        let weight = value::get(row, "weight").and_then(value::as_number).unwrap_or(1.0);
        Ok(Example::new(value::str_at(row, "text")?, Classification::from_packed(value::i64_at(row, "packed")?), weight, metadata))
    };
    let flat: Vec<Example> = flat_rows(window)?.into_iter().map(convert).collect::<Result<_>>()?;
    let guard: Vec<Example> = value::array_at(window, "guard")?.iter().map(convert).collect::<Result<_>>()?;
    Ok((flat, guard))
}
