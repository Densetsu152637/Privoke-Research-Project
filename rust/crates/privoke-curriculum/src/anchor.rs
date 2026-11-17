//! `prompt_generation.anchor_rehearsal`: the fixed gold-target permanent-TRAIN bank of 16 plus 16 anchors.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::Path;

use crate::classification;
use crate::error::{Error, Result, invalid, read_file};
use crate::pyrandom::Random;
use crate::taxonomy::{self, TaxonomyDataset, counter_value, counts, digest_sorted};
use crate::text::{training_text_key, transform_variants};
use crate::trainer::iter_training_examples;
use crate::types::{BatchTrainingConfig, Example};
use crate::value::{self, Value};

/// The strategy name.
pub const STRATEGY: &str = "taxonomy_anchor_rehearsal_v1";
/// The table version.
pub const TABLE_VERSION: &str = "pc43_fixed_16_plus_16_v1";
/// The accepted permanent-TRAIN dataset SHA.
pub const DATASET_SHA256: &str = "3b777f328a8e08140ee964facbd559c694673336b4c5655320befdd84aef66e0";
/// Metadata key of the bank digest.
pub const BANK_KEY: &str = "rehearsal_bank_sha256";
/// Metadata key of the manifest digest.
pub const MANIFEST_KEY: &str = "rehearsal_manifest_sha256";
/// Actual-disclosure audiences per family slot: the anchor family takes the first, the complement the second.
pub const ACTUAL: [(&str, [&str; 2]); 10] = [
    ("HEALTH", ["P3", "P0"]),
    ("POLITICS", ["P0", "P4"]),
    ("RELIGION", ["P3", "P1"]),
    ("CRIMINAL", ["P4", "P2"]),
    ("FINANCIAL", ["P0", "P3"]),
    ("SEXUAL", ["P4", "P0"]),
    ("CHILD", ["P1", "P3"]),
    ("LOCATION", ["P2", "P4"]),
    ("IDENTITY", ["PU", "P2"]),
    ("THIRD_PARTY", ["P2", "PU"]),
];
const FICTION: [[(&str, &str); 4]; 2] = [
    [("HEALTH", "P0"), ("POLITICS", "P1"), ("RELIGION", "P2"), ("CRIMINAL", "P3")],
    [("FINANCIAL", "P4"), ("SEXUAL", "PU"), ("CHILD", "P0"), ("LOCATION", "PU")],
];
const MILD: [[(&str, &str); 2]; 2] = [[("HEALTH", "P1"), ("RELIGION", "PU")], [("POLITICS", "P1"), ("CRIMINAL", "PU")]];

/// `digest(value)`: SHA-256 of the canonical bytes.
pub fn digest(value: &Value) -> Result<String> {
    value::digest_of(value)
}

/// `RehearsalManifest`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RehearsalManifest {
    /// SHA-256 of the manifest bytes.
    pub sha256: String,
    /// SHA-256 of the bank membership.
    pub bank_sha256: String,
    /// The manifest bytes.
    pub payload: Vec<u8>,
}

/// `bank(dataset)`: only positively validated permanent TRAIN rows, never guard rows.
pub fn bank(dataset: &TaxonomyDataset) -> Result<Vec<Example>> {
    if dataset.sha256 != DATASET_SHA256 {
        return invalid("Rehearsal requires the exact accepted permanent-TRAIN dataset SHA.");
    }
    let mut result: Vec<Example> = Vec::new();
    for (family, role) in ["anchor", "complement"].iter().enumerate() {
        let mut groups: BTreeMap<&str, Vec<String>> = BTreeMap::new();
        for (category, _) in ACTUAL {
            let mut found = BTreeSet::new();
            for row in &dataset.rows {
                let group = row.meta("group_id")?;
                if row.meta("primary_category")? == category && dataset.partitions.get(group).map(String::as_str) == Some("train") {
                    found.insert(group.to_string());
                }
            }
            groups.insert(category, found.into_iter().collect());
        }
        if groups.values().any(|found| found.len() != 2) {
            return invalid("Rehearsal needs exactly two positively proven TRAIN families per category.");
        }
        let mut slots: Vec<(&str, &str, &str)> =
            ACTUAL.iter().map(|(category, audiences)| (*category, "actual", audiences[family])).collect();
        slots.extend(FICTION[family].iter().map(|(category, audience)| (*category, "fiction", *audience)));
        slots.extend(MILD[family].iter().map(|(category, audience)| (*category, "mild", *audience)));
        let mut half: Vec<Example> = Vec::new();
        for (category, control, audience) in slots {
            let row = taxonomy::row(dataset, &groups[category][family], control, audience)?;
            if row.meta_opt("split") != Some("train") || row.meta_opt("taxonomy_partition") != Some("train") || row.weight != 1.0 {
                return invalid("Rehearsal slot is not an original unit-weight permanent TRAIN row.");
            }
            let mut metadata = row.metadata.clone();
            metadata.insert("taxonomy_strategy".to_string(), STRATEGY.to_string());
            metadata.insert("rehearsal_role".to_string(), (*role).to_string());
            half.push(Example { text: row.text.clone(), target: row.target, weight: row.weight, metadata });
        }
        let (sensitivity, visibility, _) = counts(&half)?;
        let expected: BTreeMap<String, i64> =
            [("S0", 4), ("S1", 2), ("S2", 3), ("S3", 7)].iter().map(|(name, count)| (name.to_string(), *count)).collect();
        let visibility_expected: BTreeMap<String, i64> = classification::visibility_names().map(|name| (name.to_string(), 2)).collect();
        if sensitivity != expected || visibility != visibility_expected {
            return invalid("Rehearsal half differs from the accepted target/visibility table.");
        }
        result.extend(half);
    }
    let mut seen: BTreeMap<String, String> = BTreeMap::new();
    for row in &result {
        for variant in transform_variants(&row.text) {
            let key = training_text_key(&variant);
            let identity = row.meta("taxonomy_row_id")?.to_string();
            if seen.get(&key).is_some_and(|existing| *existing != identity) {
                return invalid("Rehearsal cross-original transformed-text/target collision.");
            }
            seen.insert(key, identity);
        }
    }
    let texts: BTreeSet<String> = result.iter().map(|row| training_text_key(&row.text)).collect();
    let ids: BTreeSet<&str> = result.iter().filter_map(|row| row.meta_opt("taxonomy_row_id")).collect();
    let groups: BTreeSet<&str> = result.iter().filter_map(|row| row.meta_opt("group_id")).collect();
    if texts.len() != 32 || ids.len() != 32 || groups.len() != 20 {
        return invalid("Rehearsal originals must be unique and cover all twenty TRAIN families.");
    }
    let (_, _, categories) = counts(&result)?;
    if taxonomy::AUDIENCES.iter().any(|(category, _)| categories.get(*category).copied().unwrap_or(0) < taxonomy::CATEGORY_MINIMUM) {
        return invalid("Rehearsal lost required source category coverage.");
    }
    Ok(result)
}

/// `row_commitment(row)`.
pub fn row_commitment(row: &Example) -> Result<Value> {
    let target = row.classification()?;
    Ok(value::object(vec![
        ("id", value::string(row.meta("taxonomy_row_id")?)),
        ("group", value::string(row.meta("group_id")?)),
        ("role", value::string(row.meta("rehearsal_role")?)),
        ("category", value::string(row.meta("primary_category")?)),
        ("control", value::string(row.meta("control")?)),
        ("partition", value::string(row.meta("taxonomy_partition")?)),
        ("text_sha256", value::string(&value::sha256(row.text.as_bytes()))),
        ("target", target.to_value()?),
        ("packed", value::int(i64::from(target.pack()))),
        ("weight", Value::Float(row.weight)),
    ]))
}

/// `prepare_manifest(dataset)`: the canonical manifest bytes.
pub fn prepare_manifest(dataset: &TaxonomyDataset) -> Result<Vec<u8>> {
    let rows = bank(dataset)?;
    let membership: Vec<Value> = rows.iter().map(row_commitment).collect::<Result<_>>()?;
    let bank_sha256 = digest(&Value::Array(membership.clone()))?;
    let sensitivity: BTreeMap<String, i64> = taxonomy::SENSITIVITY_COUNTS.iter().map(|(name, count)| (name.to_string(), *count)).collect();
    let visibility: BTreeMap<String, i64> = classification::visibility_names().map(|name| (name.to_string(), 4)).collect();
    let manifest = value::object(vec![
        ("schema", value::int(1)),
        ("strategy", value::string(STRATEGY)),
        ("table_version", value::string(TABLE_VERSION)),
        ("dataset_sha256", value::string(&dataset.sha256)),
        ("bank_sha256", value::string(&bank_sha256)),
        ("bank", Value::Array(membership)),
        ("originals", value::int(32)),
        ("anchor_originals", value::int(16)),
        ("complement_originals", value::int(16)),
        ("expanded", value::int(64)),
        ("sensitivity_counts", counter_value(&sensitivity)),
        ("sensitive_visibility_counts", counter_value(&visibility)),
        ("weights", value::object(vec![("anchor", value::int(1)), ("complement", value::int(1)), ("new_example_weight", value::int(1))])),
        ("expansion", value::string("unchanged_legacy_seeded_one_invariance_transform_v1")),
        ("guard", value::string("unchanged_same_seed_taxonomy_coverage_v1_16_rows")),
        ("partition_recipe", value::string(taxonomy::PARTITION_RECIPE)),
        ("exclusion_validation", dataset.exclusion_validation.clone()),
        ("fit_release", Value::Bool(false)),
        ("expansion_exclusion_status", value::string("requires_actual_v2_subset_proof_against_pinned_validated_TC02_superset")),
        ("coverage_change", value::string("fixed_both_TRAIN_families_and_PC43_audiences")),
    ]);
    taxonomy::canonical_bytes(&manifest)
}

/// `load_snapshot(payload, dataset)`.
pub fn load_snapshot(payload: &[u8], dataset: &TaxonomyDataset) -> Result<RehearsalManifest> {
    if payload != prepare_manifest(dataset)? {
        return invalid("Rehearsal manifest bytes/schema/membership/targets/config differ from the accepted contract.");
    }
    let manifest = value::parse_bytes(payload)?;
    Ok(RehearsalManifest {
        sha256: value::sha256(payload),
        bank_sha256: value::str_at(&manifest, "bank_sha256")?.to_string(),
        payload: payload.to_vec(),
    })
}

/// `load_manifest(path, dataset)`.
pub fn load_manifest(path: Option<&Path>, dataset: &TaxonomyDataset) -> Result<RehearsalManifest> {
    let Some(path) = path else {
        return invalid("Rehearsal requires an explicit manifest path.");
    };
    load_snapshot(&read_file(path)?, dataset)
}

/// `validate_pins(metadata, manifest, dataset)`.
pub fn validate_pins(metadata: &BTreeMap<String, String>, manifest: &RehearsalManifest, dataset: &TaxonomyDataset) -> Result<()> {
    let expected = [
        ("taxonomy_dataset_sha256", dataset.sha256.as_str()),
        (BANK_KEY, manifest.bank_sha256.as_str()),
        (MANIFEST_KEY, manifest.sha256.as_str()),
    ];
    if metadata.get("contextual_sampling_strategy").map(String::as_str) != Some(STRATEGY)
        || expected.iter().any(|(key, value)| metadata.get(*key).map(String::as_str) != Some(*value))
    {
        return invalid("Rehearsal requires matching explicit strategy/dataset/bank/manifest SHA pins.");
    }
    load_snapshot(&manifest.payload, dataset).map(|_| ())
}

/// `generate_partition(dataset, manifest, seed)`.
pub fn generate_partition(dataset: &TaxonomyDataset, manifest: &RehearsalManifest, seed: u64) -> Result<(Vec<Example>, Vec<Example>)> {
    load_snapshot(&manifest.payload, dataset)?;
    let mut selected = bank(dataset)?;
    Random::new(seed).shuffle(&mut selected);
    let training: Vec<Example> = selected
        .iter()
        .enumerate()
        .map(|(index, row)| {
            let mut metadata = row.metadata.clone();
            metadata.insert("generation_seed".to_string(), seed.to_string());
            metadata.insert("generation_index".to_string(), index.to_string());
            Example { text: row.text.clone(), target: row.target, weight: row.weight, metadata }
        })
        .collect();
    let (_, guard) = taxonomy::generate_partition(dataset, seed)?;
    audit_originals(dataset, manifest, &training, &guard, seed)?;
    Ok((training, guard))
}

/// `audit_originals(dataset, manifest, originals, guard, seed)`.
pub fn audit_originals(
    dataset: &TaxonomyDataset,
    manifest: &RehearsalManifest,
    originals: &[Example],
    guard: &[Example],
    seed: u64,
) -> Result<BTreeMap<String, String>> {
    load_snapshot(&manifest.payload, dataset)?;
    let bank_rows = bank(dataset)?;
    let expected: BTreeMap<&str, &Example> =
        bank_rows.iter().map(|row| row.meta("taxonomy_row_id").map(|id| (id, row))).collect::<Result<_>>()?;
    let mut ordered: Vec<&str> = bank_rows.iter().map(|row| row.meta("taxonomy_row_id")).collect::<Result<_>>()?;
    let original_ids: Vec<&str> = originals.iter().map(|row| row.meta_opt("taxonomy_row_id").unwrap_or("")).collect();
    let mut sorted_original = original_ids.clone();
    sorted_original.sort_unstable();
    let mut sorted_expected: Vec<&str> = expected.keys().copied().collect();
    sorted_expected.sort_unstable();
    if originals.len() != 32 || sorted_original != sorted_expected {
        return invalid("Rehearsal original membership differs from the fixed bank.");
    }
    Random::new(seed).shuffle(&mut ordered);
    if original_ids != ordered {
        return invalid("Rehearsal original order differs from the declared seed.");
    }
    for (index, row) in originals.iter().enumerate() {
        let source = expected[row.meta("taxonomy_row_id")?];
        let mut metadata = source.metadata.clone();
        metadata.insert("generation_seed".to_string(), seed.to_string());
        metadata.insert("generation_index".to_string(), index.to_string());
        if row.text != source.text || row.packed() != source.packed() || row.weight != 1.0 || row.metadata != metadata {
            return invalid("Rehearsal original target/text/weight/provenance differs.");
        }
    }
    let (_, expected_guard) = taxonomy::generate_partition(dataset, seed)?;
    if guard != expected_guard.as_slice() {
        return invalid("Rehearsal requires the unchanged same-seed v1 guard.");
    }
    let guard_keys: BTreeSet<String> = guard.iter().map(|row| training_text_key(&row.text)).collect();
    let possible: BTreeSet<String> =
        originals.iter().flat_map(|row| transform_variants(&row.text)).map(|text| training_text_key(&text)).collect();
    if guard_keys.intersection(&possible).next().is_some() {
        return invalid("Rehearsal transformed training texts overlap the guard.");
    }
    let (sensitivity, visibility, categories) = counts(originals)?;
    let commitments: Vec<Value> = originals.iter().map(row_commitment).collect::<Result<_>>()?;
    let bank_groups: BTreeSet<String> = bank_rows.iter().map(|row| row.meta("group_id").map(str::to_string)).collect::<Result<_>>()?;
    let mut audit = BTreeMap::new();
    let mut put = |key: &str, text: String| {
        audit.insert(key.to_string(), text);
    };
    put("contextual_sampling_strategy", STRATEGY.to_string());
    put("taxonomy_dataset_sha256", dataset.sha256.clone());
    put(BANK_KEY, manifest.bank_sha256.clone());
    put(MANIFEST_KEY, manifest.sha256.clone());
    put("sampling_table_version", TABLE_VERSION.to_string());
    put("sampling_training_rows", "32".to_string());
    put("sampling_training_unique_texts", "32".to_string());
    put("sampling_training_groups", "20".to_string());
    put("sampling_guard_rows", "16".to_string());
    put("sampling_guard_groups", "16".to_string());
    put("sampling_anchor_rows", "16".to_string());
    put("sampling_complement_rows", "16".to_string());
    put("sampling_anchor_clean_rows", "4".to_string());
    put("sampling_anchor_sensitive_rows", "12".to_string());
    put("sampling_sensitivity_counts", value::dumps(&counter_value(&sensitivity))?);
    put("sampling_sensitive_visibility_counts", value::dumps(&counter_value(&visibility))?);
    put("sampling_category_counts", value::dumps(&counter_value(&categories))?);
    put("sampling_training_ids_sha256", digest_sorted(expected.keys().map(|id| id.to_string()))?);
    put("sampling_training_groups_sha256", digest_sorted(bank_groups)?);
    put(
        "sampling_guard_groups_sha256",
        digest_sorted(guard.iter().map(|row| row.meta("group_id").map(str::to_string)).collect::<Result<Vec<_>>>()?)?,
    );
    put("sampling_original_order_sha256", digest(&Value::Array(commitments))?);
    put("sampling_seed", seed.to_string());
    Ok(audit)
}

/// `wire_commitment(rows)`: the ordered protobuf training fields. `named` selects the full target (anchor and
/// expanded rows) or the packed-only guard constructor of the runtime client.
pub fn wire_commitment(rows: &[Example], named: bool) -> Result<String> {
    let mut items = Vec::with_capacity(rows.len());
    for row in rows {
        let target = row.classification()?;
        let (sensitivity, visibility, categories) = if named {
            (
                target.sensitivity().to_string(),
                target.visibility()?.to_string(),
                target.categories().iter().map(|name| name.to_string()).collect::<Vec<_>>(),
            )
        } else {
            (String::new(), String::new(), Vec::new())
        };
        items.push(value::object(vec![
            ("text", value::string(&row.text)),
            ("has_target", Value::Bool(true)),
            ("weight", Value::Float(row.weight)),
            (
                "target",
                value::object(vec![
                    ("packed", value::int(i64::from(target.pack()))),
                    ("sensitivity", value::string(&sensitivity)),
                    ("visibility", value::string(&visibility)),
                    ("categories", value::strings(&categories)),
                ]),
            ),
        ]));
    }
    digest(&Value::Array(items))
}

/// `audit_expanded(dataset, manifest, originals, expanded, guard, config)`.
pub fn audit_expanded(
    dataset: &TaxonomyDataset,
    manifest: &RehearsalManifest,
    originals: &[Example],
    expanded: &[Example],
    guard: &[Example],
    config: &BatchTrainingConfig,
) -> Result<BTreeMap<String, String>> {
    let mut audit = audit_originals(dataset, manifest, originals, guard, config.seed)?;
    if config.transformations_per_example != 1
        || config.new_example_weight != 1.0
        || expanded.len() != 64
        || expanded != iter_training_examples(originals, &[], config)?.as_slice()
    {
        return invalid("Rehearsal expansion/weight/seed differs from unchanged legacy transforms.");
    }
    for (index, original) in originals.iter().enumerate() {
        if expanded[index * 2..index * 2 + 2].iter().any(|row| !transform_variants(&original.text).contains(&row.text)) {
            return invalid("Rehearsal expansion is outside the pinned validated source transform superset.");
        }
    }
    audit.insert("sampling_expanded_rows".to_string(), "64".to_string());
    audit.insert(
        "sampling_expanded_unique_texts".to_string(),
        expanded.iter().map(|row| training_text_key(&row.text)).collect::<BTreeSet<_>>().len().to_string(),
    );
    audit.insert(
        "sampling_expanded_ids_sha256".to_string(),
        digest_sorted(expanded.iter().map(|row| row.meta("taxonomy_row_id").map(str::to_string)).collect::<Result<Vec<_>>>()?)?,
    );
    audit.insert("sampling_expanded_wire_sha256".to_string(), wire_commitment(expanded, true)?);
    Ok(audit)
}

/// `persist_audit(manifest, audit)`: retain complete immutable sampling evidence before the physical RPC.
pub fn persist_audit(manifest: &RehearsalManifest, audit: &BTreeMap<String, String>, dump_dir: Option<&Path>) -> Result<(String, String)> {
    let Some(directory) = dump_dir else {
        return invalid("Rehearsal requires durable complete sampling evidence.");
    };
    let manifest_text =
        String::from_utf8(manifest.payload.clone()).map_err(|_| Error::Invalid("manifest is not valid UTF-8".to_string()))?;
    let record = value::object(vec![
        ("schema", value::int(1)),
        ("manifest_utf8", value::string(&manifest_text)),
        ("audit", value::from_string_map(audit)),
    ]);
    let payload = taxonomy::canonical_bytes(&record)?;
    let sha = value::sha256(&payload);
    let folder = directory.join("rehearsal-audits");
    let path = folder.join(format!("{sha}.json"));
    let io_error = |error: std::io::Error| Error::Io { path: path.display().to_string(), reason: error.to_string() };
    std::fs::create_dir_all(&folder).map_err(io_error)?;
    match std::fs::OpenOptions::new().write(true).create_new(true).open(&path) {
        Ok(mut stream) => {
            stream.write_all(&payload).map_err(io_error)?;
            stream.sync_all().map_err(io_error)?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            if read_file(&path)? != payload {
                return invalid("Rehearsal immutable sampling evidence conflicts.");
            }
        }
        Err(error) => return Err(io_error(error)),
    }
    Ok((path.display().to_string(), sha))
}

/// `validate_retained_audit(evidence, metadata)`: the retained record, after checking it against the publication.
pub fn validate_retained_audit(path: &Path, expected_sha256: &str, metadata: &BTreeMap<String, String>) -> Result<Value> {
    let payload = read_file(path)?;
    if value::sha256(&payload) != expected_sha256 {
        return invalid("Rehearsal retained sampling evidence checksum differs.");
    }
    let record = value::parse_bytes(&payload)?;
    let manifest_bytes = value::str_at(&record, "manifest_utf8")?.as_bytes();
    let manifest = value::parse_bytes(manifest_bytes)?;
    let audit = value::object_at(&record, "audit")?;
    let bank_digest = digest(value::require(&manifest, "bank")?)?;
    let matches = |key: &str, expected: &str| metadata.get(key).map(String::as_str) == Some(expected);
    let audit_matches =
        audit.iter().all(|(key, item)| value::as_str(item).is_some_and(|text| metadata.get(key).map(String::as_str) == Some(text)));
    if value::i64_at(&record, "schema")? != 1
        || !matches(MANIFEST_KEY, &value::sha256(manifest_bytes))
        || !matches(BANK_KEY, &bank_digest)
        || !matches("taxonomy_dataset_sha256", value::str_at(&manifest, "dataset_sha256")?)
        || !audit_matches
    {
        return invalid("Rehearsal full retained audit differs from outgoing publication.");
    }
    Ok(record)
}
