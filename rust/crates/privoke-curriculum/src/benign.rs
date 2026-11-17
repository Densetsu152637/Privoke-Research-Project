//! `prompt_generation.benign_coverage`: opt-in ordinary-benign TRAIN exposure replacing four fiction rows.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::Path;

use crate::anchor::{digest, wire_commitment};
use crate::classification;
use crate::error::{Error, Result, invalid, read_file};
use crate::pyrandom::Random;
use crate::taxonomy::{self, TaxonomyDataset, counter_value, counts, digest_sorted};
use crate::text::{training_text_key, transform_variants};
use crate::trainer::iter_training_examples;
use crate::types::{BatchTrainingConfig, Example};
use crate::value::{self, Value};

/// The strategy name.
pub const STRATEGY: &str = "taxonomy_benign_coverage_v1";
/// The source label of the authored pool.
pub const SOURCE: &str = "independently_authored_ordinary_benign_v1";
/// The accepted permanent-TRAIN dataset SHA.
pub const DATASET_SHA256: &str = "3b777f328a8e08140ee964facbd559c694673336b4c5655320befdd84aef66e0";
/// The independently derived legacy snapshot commitment.
pub const LEGACY_SNAPSHOT_SHA256: &str = "04db8a469aa5c430f9333829da015f01b4377eb5268c58c1451c63b0a51dcced";
/// Metadata key of the pool digest.
pub const POOL_KEY: &str = "benign_pool_sha256";
/// Metadata key of the manifest digest.
pub const MANIFEST_KEY: &str = "benign_manifest_sha256";
/// Metadata key of the exclusion proof digest.
pub const PROOF_KEY: &str = "benign_exclusion_proof_sha256";
/// Replacement slots: primary category and audience of the fiction rows that the pool replaces.
pub const SLOTS: [(&str, &str); 4] = [("HEALTH", "P0"), ("POLITICS", "P1"), ("RELIGION", "P2"), ("CRIMINAL", "P3")];

/// `legacy_snapshot_commitment(dataset)`: every ordered source and guard field.
pub fn legacy_snapshot_commitment(dataset: &TaxonomyDataset) -> Result<String> {
    let mut rows = Vec::with_capacity(dataset.rows.len());
    for row in &dataset.rows {
        let target = row.classification()?;
        rows.push(value::object(vec![
            ("text", value::string(&row.text)),
            ("target", target.to_value()?),
            ("packed", value::int(i64::from(target.pack()))),
            ("weight", Value::Float(row.weight)),
            ("metadata", value::from_string_map(&row.metadata)),
        ]));
    }
    let partitions = value::from_string_map(&dataset.partitions);
    digest(&value::object(vec![
        ("dataset_sha256", value::string(&dataset.sha256)),
        ("rows", Value::Array(rows)),
        ("partitions", partitions),
        ("exclusion_validation", dataset.exclusion_validation.clone()),
    ]))
}

/// `validate_legacy_snapshot(dataset)`.
pub fn validate_legacy_snapshot(dataset: &TaxonomyDataset) -> Result<()> {
    if dataset.sha256 != DATASET_SHA256 || legacy_snapshot_commitment(dataset)? != LEGACY_SNAPSHOT_SHA256 {
        return invalid("Benign coverage legacy snapshot differs from independently pinned accepted content.");
    }
    Ok(())
}

/// `policy_contract()`.
pub fn policy_contract() -> Value {
    let slots = Value::Array(SLOTS.iter().map(|(category, audience)| value::strings(&[category, audience])).collect());
    value::object(vec![
        ("strategy", value::string(STRATEGY)),
        ("version", value::int(1)),
        ("replacement_slots", slots),
        ("base", taxonomy::policy_contract()),
        ("selection", value::string("independent_seeded_choice_sorted_pool_per_visibility_v1")),
        ("replacement", value::string("four_fiction_rows_in_place_after_complete_legacy_generation")),
        ("originals", value::int(32)),
        ("expanded", value::int(64)),
        ("ordinary_benign", value::int(4)),
        ("fiction", value::int(4)),
        ("unit_weights", Value::Bool(true)),
        ("guard", value::string("unchanged_ordered_same_seed_v1_guard")),
        ("transforms", value::string("unchanged_legacy_seeded_one_invariance_transform_v1")),
    ])
}

/// `BenignPool`.
#[derive(Debug, Clone, PartialEq)]
pub struct BenignPool {
    /// SHA-256 of the pool bytes.
    pub sha256: String,
    /// The pool bytes.
    pub payload: Vec<u8>,
    /// The authored rows.
    pub rows: Vec<Example>,
}

/// `BenignRelease`.
#[derive(Debug, Clone, PartialEq)]
pub struct BenignRelease {
    /// SHA-256 of the manifest bytes.
    pub sha256: String,
    /// SHA-256 of the exclusion proof bytes.
    pub proof_sha256: String,
    /// The manifest bytes.
    pub payload: Vec<u8>,
    /// The proof bytes.
    pub proof_payload: Vec<u8>,
    /// The pool.
    pub pool: BenignPool,
}

fn key_set(value: &Value) -> BTreeSet<&str> {
    value::as_object(value).map(|map| map.keys().map(String::as_str).collect()).unwrap_or_default()
}

/// `load_pool_snapshot(payload)`.
pub fn load_pool_snapshot(payload: &[u8]) -> Result<BenignPool> {
    let pool = value::parse_bytes(payload)?;
    let top: BTreeSet<&str> =
        ["schema", "source", "authorship", "label_status", "permanent_partition", "fit_release", "rows"].into_iter().collect();
    let text_is = |key: &str, expected: &str| value::get(&pool, key).and_then(value::as_str) == Some(expected);
    let authorship_ok = value::get(&pool, "authorship").and_then(value::as_str).is_some_and(|text| !text.trim().is_empty());
    if payload != taxonomy::canonical_bytes(&pool)?.as_slice()
        || key_set(&pool) != top
        || value::get(&pool, "schema").and_then(value::as_i64) != Some(1)
        || !text_is("source", SOURCE)
        || !text_is("label_status", "assistant_provisional")
        || !text_is("permanent_partition", "train")
        || value::get(&pool, "fit_release") != Some(&Value::Bool(false))
        || !authorship_ok
    {
        return invalid("Benign pool requires canonical independent positive permanent TRAIN provenance.");
    }
    let row_keys: BTreeSet<&str> = ["id", "text", "weight", "classification", "packed_classification", "metadata"].into_iter().collect();
    let meta_keys: BTreeSet<&str> = [
        "group_id",
        "split",
        "partition",
        "source",
        "control",
        "label_status",
        "sensitivity_rationale",
        "category_rationale",
        "visibility_rationale",
    ]
    .into_iter()
    .collect();
    let mut rows: Vec<Example> = Vec::new();
    let (mut ids, mut groups, mut keys) = (BTreeSet::new(), BTreeSet::new(), BTreeSet::new());
    let raw_rows: &[Value] = value::get(&pool, "rows").and_then(value::as_array).map_or(&[], Vec::as_slice);
    for raw in raw_rows {
        if key_set(raw) != row_keys {
            return invalid("Unsupported benign row schema.");
        }
        let target = taxonomy::target(value::require(raw, "classification")?)?;
        let meta = value::require(raw, "metadata")?;
        let strings = value::string_map(meta);
        let (identity, text) = (value::get(raw, "id").and_then(value::as_str), value::get(raw, "text").and_then(value::as_str));
        let message = "Benign rows require own TRAIN identities, unit weights and explicit S0/visibility/empty-category targets.";
        let (Some(strings), Some(identity), Some(text)) = (strings, identity, text) else {
            return invalid(message);
        };
        let weight_ok = value::get(raw, "weight").and_then(value::as_number) == Some(1.0);
        let packed_ok = value::get(raw, "packed_classification").and_then(value::as_i64) == Some(i64::from(target.pack()));
        let slot_visibility = target.visibility().is_ok_and(|name| SLOTS.iter().any(|(_, audience)| *audience == name));
        let group = strings.get("group_id").map(String::as_str).unwrap_or_default();
        if key_set(meta) != meta_keys
            || strings.values().any(|text| text.trim().is_empty())
            || strings.get("source").map(String::as_str) != Some(SOURCE)
            || strings.get("split").map(String::as_str) != Some("train")
            || strings.get("partition").map(String::as_str) != Some("train")
            || strings.get("control").map(String::as_str) != Some("ordinary_benign")
            || strings.get("label_status").map(String::as_str) != Some("assistant_provisional")
            || !group.starts_with("ordinary-benign-train-")
            || identity != format!("{group}/00")
            || training_text_key(text).is_empty()
            || !weight_ok
            || !packed_ok
            || target.sensitivity() != "S0"
            || !slot_visibility
            || !target.categories().is_empty()
        {
            return invalid(message);
        }
        if ids.contains(identity) || groups.contains(group) || keys.contains(&training_text_key(text)) {
            return invalid("Benign pool must contain distinct originals and independent declared source groups.");
        }
        ids.insert(identity.to_string());
        groups.insert(group.to_string());
        keys.insert(training_text_key(text));
        let mut metadata = strings.clone();
        metadata.insert("benign_row_id".to_string(), identity.to_string());
        rows.push(Example::new(text, target, 1.0, metadata));
    }
    let mut per_visibility: BTreeMap<&str, usize> = BTreeMap::new();
    for row in &rows {
        *per_visibility.entry(row.classification()?.visibility()?).or_default() += 1;
    }
    if rows.len() < 32 || SLOTS.iter().any(|(_, audience)| per_visibility.get(*audience).copied().unwrap_or(0) < 8) {
        return invalid("Benign pool requires at least32 originals and eight per selected visibility.");
    }
    let mut seen: BTreeMap<String, String> = BTreeMap::new();
    for row in &rows {
        for text in transform_variants(&row.text) {
            let key = training_text_key(&text);
            let identity = row.meta("benign_row_id")?.to_string();
            if seen.get(&key).is_some_and(|existing| *existing != identity) {
                return invalid("Benign pool has a cross-original transform collision.");
            }
            seen.insert(key, identity);
        }
    }
    Ok(BenignPool { sha256: value::sha256(payload), payload: payload.to_vec(), rows })
}

/// `transform_commitment(pool)`.
pub fn transform_commitment(pool: &BenignPool) -> Result<String> {
    let mut items = Vec::new();
    for row in &pool.rows {
        let target = row.classification()?;
        for text in transform_variants(&row.text) {
            items.push(value::object(vec![
                ("id", value::string(row.meta("benign_row_id")?)),
                ("text_sha256", value::string(&value::sha256(text.as_bytes()))),
                ("target", target.to_value()?),
                ("packed", value::int(i64::from(target.pack()))),
                ("weight", Value::Float(row.weight)),
            ]));
        }
    }
    digest(&Value::Array(items))
}

/// `validate_pool(pool)`.
pub fn validate_pool(pool: &BenignPool) -> Result<()> {
    let rebuilt = load_pool_snapshot(&pool.payload)?;
    if rebuilt.sha256 != pool.sha256 || rebuilt.rows != pool.rows {
        return invalid("Benign pool snapshot differs from its frozen bytes.");
    }
    Ok(())
}

fn is_lower_hex64(text: &str) -> bool {
    text.len() == 64 && text.chars().all(|character| matches!(character, '0'..='9' | 'a'..='f'))
}

/// `prepare_manifest(pool, dataset, proof_payload)`.
pub fn prepare_manifest(pool: &BenignPool, dataset: &TaxonomyDataset, proof_payload: &[u8]) -> Result<Vec<u8>> {
    validate_pool(pool)?;
    validate_legacy_snapshot(dataset)?;
    let proof = value::parse_bytes(proof_payload)?;
    let empty = value::object(Vec::<(String, Value)>::new());
    let validation = value::get(&proof, "exclusion_validation").unwrap_or(&empty);
    let proof_keys: BTreeSet<&str> = [
        "schema",
        "strategy",
        "status",
        "pool_sha256",
        "dataset_sha256",
        "label_review_sha256",
        "all_transform_variants",
        "transform_commitment_sha256",
        "source_overlap_counts",
        "exclusion_validation",
        "fit_release",
    ]
    .into_iter()
    .collect();
    let text_is = |key: &str, expected: &str| value::get(&proof, key).and_then(value::as_str) == Some(expected);
    let overlap = value::object(vec![("ids", value::int(0)), ("groups", value::int(0)), ("texts", value::int(0))]);
    let review = value::get(&proof, "label_review_sha256").and_then(value::as_str);
    if proof_payload != taxonomy::canonical_bytes(&proof)?.as_slice()
        || key_set(&proof) != proof_keys
        || value::get(&proof, "schema").and_then(value::as_i64) != Some(1)
        || !text_is("strategy", STRATEGY)
        || !text_is("status", "passed")
        || !text_is("pool_sha256", &pool.sha256)
        || !text_is("dataset_sha256", &dataset.sha256)
        || value::get(&proof, "all_transform_variants") != Some(&Value::Bool(true))
        || value::get(&proof, "fit_release") != Some(&Value::Bool(false))
        || !text_is("transform_commitment_sha256", &transform_commitment(pool)?)
        || value::get(&proof, "source_overlap_counts") != Some(&overlap)
        || !review.is_some_and(is_lower_hex64)
        || *validation != dataset.exclusion_validation
        || value::get(validation, "status").and_then(value::as_str) != Some("passed")
        || value::get(validation, "all_transform_variants") != Some(&Value::Bool(true))
    {
        return invalid("Benign coverage requires a fresh hash-bound reviewed all-transform exclusion proof.");
    }
    // New source rows must also be disjoint from every legacy source/guard family.
    let legacy_ids: BTreeSet<&str> = dataset.rows.iter().filter_map(|row| row.meta_opt("taxonomy_row_id")).collect();
    let legacy_keys: BTreeSet<String> =
        dataset.rows.iter().flat_map(|row| transform_variants(&row.text)).map(|text| training_text_key(&text)).collect();
    for row in &pool.rows {
        let collides = legacy_ids.contains(row.meta("benign_row_id")?)
            || dataset.partitions.contains_key(row.meta("group_id")?)
            || transform_variants(&row.text).iter().any(|text| legacy_keys.contains(&training_text_key(text)));
        if collides {
            return invalid("Benign pool collides with legacy source/guard identities or transformations.");
        }
    }
    taxonomy::canonical_bytes(&value::object(vec![
        ("schema", value::int(1)),
        ("strategy", value::string(STRATEGY)),
        ("dataset_sha256", value::string(&dataset.sha256)),
        ("legacy_snapshot_commitment_sha256", value::string(LEGACY_SNAPSHOT_SHA256)),
        ("pool_sha256", value::string(&pool.sha256)),
        ("exclusion_proof_sha256", value::string(&value::sha256(proof_payload))),
        ("label_review_sha256", value::string(review.unwrap_or_default())),
        ("pool_transform_commitment_sha256", value::string(&transform_commitment(pool)?)),
        ("policy", policy_contract()),
        ("fit_release", Value::Bool(false)),
    ]))
}

/// `load_snapshot(payload, pool, dataset, proof_payload)`.
pub fn load_snapshot(payload: &[u8], pool: &BenignPool, dataset: &TaxonomyDataset, proof_payload: &[u8]) -> Result<BenignRelease> {
    if payload != prepare_manifest(pool, dataset, proof_payload)?.as_slice() {
        return invalid("Benign canonical manifest/config/source/proof differs.");
    }
    Ok(BenignRelease {
        sha256: value::sha256(payload),
        proof_sha256: value::sha256(proof_payload),
        payload: payload.to_vec(),
        proof_payload: proof_payload.to_vec(),
        pool: pool.clone(),
    })
}

/// `load_release(pool_path, manifest_path, proof_path, dataset)`.
pub fn load_release(pool_path: &Path, manifest_path: &Path, proof_path: &Path, dataset: &TaxonomyDataset) -> Result<BenignRelease> {
    let pool = load_pool_snapshot(&read_file(pool_path)?)?;
    load_snapshot(&read_file(manifest_path)?, &pool, dataset, &read_file(proof_path)?)
}

/// `validate_release(release, dataset)`.
pub fn validate_release(release: &BenignRelease, dataset: &TaxonomyDataset) -> Result<()> {
    if load_snapshot(&release.payload, &release.pool, dataset, &release.proof_payload)? != *release {
        return invalid("Benign release snapshot differs from its frozen bytes.");
    }
    Ok(())
}

/// `validate_pins(metadata, release, dataset)`.
pub fn validate_pins(metadata: &BTreeMap<String, String>, release: &BenignRelease, dataset: &TaxonomyDataset) -> Result<()> {
    validate_release(release, dataset)?;
    let expected = [
        ("taxonomy_dataset_sha256", dataset.sha256.as_str()),
        (POOL_KEY, release.pool.sha256.as_str()),
        (MANIFEST_KEY, release.sha256.as_str()),
        (PROOF_KEY, release.proof_sha256.as_str()),
    ];
    if metadata.get("contextual_sampling_strategy").map(String::as_str) != Some(STRATEGY)
        || expected.iter().any(|(key, value)| metadata.get(*key).map(String::as_str) != Some(*value))
    {
        return invalid("Benign coverage requires explicit matching dataset/pool/manifest/proof pins.");
    }
    Ok(())
}

/// `_select(dataset, release, seed)`: complete legacy generation first, then four independently chosen replacements.
fn select(dataset: &TaxonomyDataset, release: &BenignRelease, seed: u64) -> Result<(Vec<Example>, Vec<Example>)> {
    let (originals, guard) = taxonomy::generate_partition(dataset, seed)?;
    let mut rng = Random::new(seed);
    let mut replacement: BTreeMap<(&str, &str), &Example> = BTreeMap::new();
    for (category, audience) in SLOTS {
        let mut pool: Vec<&Example> =
            release.pool.rows.iter().filter(|row| row.target.is_some_and(|target| target.visibility().ok() == Some(audience))).collect();
        pool.sort_by(|left, right| left.meta_opt("benign_row_id").cmp(&right.meta_opt("benign_row_id")));
        replacement.insert((category, audience), *rng.choice(&pool)?);
    }
    let mut selected = Vec::with_capacity(originals.len());
    for (index, row) in originals.iter().enumerate() {
        let slot = (row.meta("primary_category")?, row.classification()?.visibility()?);
        let (source, mut metadata) = match replacement.get(&slot) {
            Some(replaced) if row.meta_opt("control") == Some("fiction") => {
                let mut metadata = replaced.metadata.clone();
                metadata.insert("generation_seed".to_string(), seed.to_string());
                metadata.insert("generation_index".to_string(), index.to_string());
                (*replaced, metadata)
            }
            _ => (row, row.metadata.clone()),
        };
        metadata.insert("taxonomy_strategy".to_string(), STRATEGY.to_string());
        selected.push(Example { text: source.text.clone(), target: source.target, weight: source.weight, metadata });
    }
    Ok((selected, guard))
}

/// `generate_partition(dataset, release, seed)`.
pub fn generate_partition(dataset: &TaxonomyDataset, release: &BenignRelease, seed: u64) -> Result<(Vec<Example>, Vec<Example>)> {
    validate_release(release, dataset)?;
    let (rows, guard) = select(dataset, release, seed)?;
    audit_originals(dataset, release, &rows, &guard, seed)?;
    Ok((rows, guard))
}

fn source_id(row: &Example) -> String {
    row.metadata.get("benign_row_id").or_else(|| row.metadata.get("taxonomy_row_id")).cloned().unwrap_or_default()
}

/// `audit_originals(dataset, release, originals, guard, seed)`.
pub fn audit_originals(
    dataset: &TaxonomyDataset,
    release: &BenignRelease,
    originals: &[Example],
    guard: &[Example],
    seed: u64,
) -> Result<BTreeMap<String, String>> {
    validate_release(release, dataset)?;
    let (expected, expected_guard) = select(dataset, release, seed)?;
    if originals != expected.as_slice() || guard != expected_guard.as_slice() {
        return invalid("Benign actual originals/order/targets/weights/provenance or unchanged ordered guard differ.");
    }
    let (sensitivity, visibility, categories) = counts(originals)?;
    let mut control: BTreeMap<&str, usize> = BTreeMap::new();
    for row in originals {
        *control.entry(row.meta("control")?).or_default() += 1;
    }
    let expected_control: BTreeMap<&str, usize> =
        [("actual", 20), ("fiction", 4), ("mild", 4), ("ordinary_benign", 4)].into_iter().collect();
    let expected_sensitivity: BTreeMap<String, i64> =
        taxonomy::SENSITIVITY_COUNTS.iter().map(|(name, count)| (name.to_string(), *count)).collect();
    let expected_visibility: BTreeMap<String, i64> = classification::visibility_names().map(|name| (name.to_string(), 4)).collect();
    let unique: BTreeSet<String> = originals.iter().map(|row| training_text_key(&row.text)).collect();
    if originals.len() != 32
        || unique.len() != 32
        || sensitivity != expected_sensitivity
        || visibility != expected_visibility
        || control != expected_control
        || taxonomy::AUDIENCES.iter().any(|(category, _)| categories.get(*category).copied().unwrap_or(0) < taxonomy::CATEGORY_MINIMUM)
    {
        return invalid("Benign actual selection violates unchanged quotas or declared four/four controls.");
    }
    let guard_keys: BTreeSet<String> = guard.iter().map(|row| training_text_key(&row.text)).collect();
    let possible: BTreeSet<String> =
        originals.iter().flat_map(|row| transform_variants(&row.text)).map(|text| training_text_key(&text)).collect();
    if guard_keys.intersection(&possible).next().is_some() {
        return invalid("Benign possible transformed inputs overlap the same-seed guard.");
    }
    let ids: Vec<String> = originals.iter().map(source_id).collect();
    let groups: BTreeSet<String> = originals.iter().map(|row| row.meta("group_id").map(str::to_string)).collect::<Result<_>>()?;
    let guard_groups: Vec<String> = guard.iter().map(|row| row.meta("group_id").map(str::to_string)).collect::<Result<_>>()?;
    let mut audit = BTreeMap::new();
    let mut put = |key: &str, text: String| {
        audit.insert(key.to_string(), text);
    };
    put("contextual_sampling_strategy", STRATEGY.to_string());
    put("taxonomy_dataset_sha256", dataset.sha256.clone());
    put(POOL_KEY, release.pool.sha256.clone());
    put(MANIFEST_KEY, release.sha256.clone());
    put(PROOF_KEY, release.proof_sha256.clone());
    put("sampling_training_rows", "32".to_string());
    put("sampling_training_unique_texts", "32".to_string());
    put("sampling_training_groups", groups.len().to_string());
    put("sampling_guard_rows", "16".to_string());
    put("sampling_guard_groups", guard_groups.iter().collect::<BTreeSet<_>>().len().to_string());
    put("sampling_sensitivity_counts", value::dumps(&counter_value(&sensitivity))?);
    put("sampling_sensitive_visibility_counts", value::dumps(&counter_value(&visibility))?);
    put("sampling_category_counts", value::dumps(&counter_value(&categories))?);
    put("sampling_training_ids_sha256", digest_sorted(ids)?);
    put("sampling_training_groups_sha256", digest_sorted(groups)?);
    put("sampling_guard_groups_sha256", digest_sorted(guard_groups)?);
    put("sampling_ordinary_benign_rows", "4".to_string());
    put("sampling_fiction_rows", "4".to_string());
    put("sampling_seed", seed.to_string());
    put("sampling_original_order_sha256", wire_commitment(originals, true)?);
    put("sampling_guard_wire_sha256", wire_commitment(guard, false)?);
    Ok(audit)
}

/// `audit_expanded(dataset, release, originals, expanded, guard, config)`.
pub fn audit_expanded(
    dataset: &TaxonomyDataset,
    release: &BenignRelease,
    originals: &[Example],
    expanded: &[Example],
    guard: &[Example],
    config: &BatchTrainingConfig,
) -> Result<BTreeMap<String, String>> {
    let mut audit = audit_originals(dataset, release, originals, guard, config.seed)?;
    let allowed = originals.iter().enumerate().all(|(index, original)| {
        expanded
            .get(index * 2..index * 2 + 2)
            .is_some_and(|rows| rows.iter().all(|actual| transform_variants(&original.text).contains(&actual.text)))
    });
    if config.transformations_per_example != 1
        || config.new_example_weight != 1.0
        || expanded.len() != 64
        || expanded != iter_training_examples(originals, &[], config)?.as_slice()
        || !allowed
    {
        return invalid("Benign actual expansion is outside reviewed source/target/unit-weight/legacy-transform membership.");
    }
    audit.insert("sampling_expanded_rows".to_string(), "64".to_string());
    audit.insert(
        "sampling_expanded_unique_texts".to_string(),
        expanded.iter().map(|row| training_text_key(&row.text)).collect::<BTreeSet<_>>().len().to_string(),
    );
    audit.insert("sampling_expanded_ids_sha256".to_string(), digest_sorted(expanded.iter().map(source_id))?);
    audit.insert("sampling_expanded_wire_sha256".to_string(), wire_commitment(expanded, true)?);
    Ok(audit)
}

/// `persist_audit(release, audit)`: retain the complete source and audit before the physical RPC.
pub fn persist_audit(release: &BenignRelease, audit: &BTreeMap<String, String>, dump_dir: Option<&Path>) -> Result<(String, String)> {
    let Some(directory) = dump_dir else {
        return invalid("Benign coverage requires durable complete source/audit evidence.");
    };
    let text =
        |bytes: &[u8]| String::from_utf8(bytes.to_vec()).map_err(|_| Error::Invalid("retained source is not valid UTF-8".to_string()));
    let record = value::object(vec![
        ("schema", value::int(1)),
        ("manifest_utf8", value::string(&text(&release.payload)?)),
        ("pool_utf8", value::string(&text(&release.pool.payload)?)),
        ("proof_utf8", value::string(&text(&release.proof_payload)?)),
        ("audit", value::from_string_map(audit)),
    ]);
    let payload = taxonomy::canonical_bytes(&record)?;
    let sha = value::sha256(&payload);
    let folder = directory.join("benign-audits");
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
                return invalid("Benign immutable sampling evidence conflicts.");
            }
        }
        Err(error) => return Err(io_error(error)),
    }
    Ok((path.display().to_string(), sha))
}

/// `validate_retained_audit(evidence, metadata)`.
pub fn validate_retained_audit(path: &Path, expected_sha256: &str, metadata: &BTreeMap<String, String>) -> Result<Value> {
    let payload = read_file(path)?;
    if value::sha256(&payload) != expected_sha256 {
        return invalid("Benign retained audit checksum differs.");
    }
    let record = value::parse_bytes(&payload)?;
    let audit = value::object_at(&record, "audit")?;
    let matches = |key: &str, field: &str| {
        metadata.get(key).map(String::as_str)
            == value::get(&record, field).and_then(value::as_str).map(|text| value::sha256(text.as_bytes())).as_deref()
    };
    let audit_matches =
        audit.iter().all(|(key, item)| value::as_str(item).is_some_and(|text| metadata.get(key).map(String::as_str) == Some(text)));
    if value::i64_at(&record, "schema")? != 1
        || !audit_matches
        || !matches(MANIFEST_KEY, "manifest_utf8")
        || !matches(POOL_KEY, "pool_utf8")
        || !matches(PROOF_KEY, "proof_utf8")
    {
        return invalid("Benign retained source/pin/audit evidence differs from publication.");
    }
    Ok(record)
}
