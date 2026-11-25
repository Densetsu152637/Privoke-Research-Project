//! `prompt_generation.taxonomy_coverage`: the versioned TRAIN-only taxonomy exposure, the 32 plus 16 row partition.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use crate::classification::{self, Classification};
use crate::error::{Result, invalid, read_file};
use crate::pyrandom::Random;
use crate::text::{training_text_key, transform_variants};
use crate::types::{BatchTrainingConfig, Example};
use crate::value::{self, Value};

/// The strategy name.
pub const STRATEGY: &str = "taxonomy_coverage_v1";
/// Pinned source bytes.
pub const SOURCE_SHA256: &str = "ceeb394020f6c5de6e1d6d4737c7c7c6d3b6eae8122391660b9986325a3f7ece";
/// Pinned renderer bytes.
pub const RENDERER_SHA256: &str = "ee2c6310a759ea5162bd2cd8a46518f883b3bf2cf8dc825071411d9deed2d62e";
/// The permanent partition recipe.
pub const PARTITION_RECIPE: &str = "sort_four_family_ids_per_primary_category_first_two_train_last_two_guard_v1";
/// Primary categories with the two actual-disclosure audiences each contributes, in `AUDIENCES` order.
pub const AUDIENCES: [(&str, [&str; 2]); 10] = [
    ("HEALTH", ["P0", "P3"]),
    ("POLITICS", ["P0", "P4"]),
    ("RELIGION", ["P1", "P3"]),
    ("CRIMINAL", ["P2", "P4"]),
    ("FINANCIAL", ["P0", "P3"]),
    ("SEXUAL", ["P0", "P4"]),
    ("CHILD", ["P1", "P3"]),
    ("LOCATION", ["P2", "P4"]),
    ("IDENTITY", ["P2", "PU"]),
    ("THIRD_PARTY", ["P2", "PU"]),
];
/// Fiction audiences, zipped with the categories (so the first eight categories).
pub const CLEAN_AUDIENCES: [&str; 8] = ["P0", "P1", "P2", "P3", "P4", "PU", "P0", "PU"];
/// Mild audiences, zipped with the categories (so the first four categories).
pub const MILD_AUDIENCES: [&str; 4] = ["P1", "P1", "PU", "PU"];
/// Sensitivity counts of the 32 originals.
pub const SENSITIVITY_COUNTS: [(&str, i64); 4] = [("S0", 8), ("S1", 4), ("S2", 6), ("S3", 14)];
/// Per-category minimum counts.
pub const CATEGORY_MINIMUM: i64 = 2;
/// Guard positive slots: category, control, audience.
pub const GUARD_POSITIVE_SLOTS: [(&str, &str, &str); 8] = [
    ("POLITICS", "mild", "P1"),
    ("RELIGION", "mild", "PU"),
    ("FINANCIAL", "actual", "P0"),
    ("LOCATION", "actual", "P2"),
    ("HEALTH", "actual", "P3"),
    ("SEXUAL", "actual", "P4"),
    ("CHILD", "actual", "P0"),
    ("IDENTITY", "actual", "PU"),
];

/// `canonical_bytes(value)`: sorted keys, compact, UTF-8, one trailing newline.
pub fn canonical_bytes(value: &Value) -> Result<Vec<u8>> {
    value::canonical_bytes(value)
}

/// `policy_contract()` as the JSON value the release stores.
pub fn policy_contract() -> Value {
    let audiences = value::object(AUDIENCES.iter().map(|(category, audiences)| (*category, value::strings(audiences))).collect());
    let slots = Value::Array(
        GUARD_POSITIVE_SLOTS.iter().map(|(category, control, audience)| value::strings(&[category, control, audience])).collect(),
    );
    let counts = value::object(SENSITIVITY_COUNTS.iter().map(|(name, count)| (*name, value::int(*count))).collect());
    let minimums = value::object(AUDIENCES.iter().map(|(category, _)| (*category, value::int(CATEGORY_MINIMUM))).collect());
    value::object(vec![
        ("strategy", value::string(STRATEGY)),
        ("partition_recipe", value::string(PARTITION_RECIPE)),
        ("audiences", audiences),
        ("clean_audiences", value::strings(&CLEAN_AUDIENCES)),
        ("mild_audiences", value::strings(&MILD_AUDIENCES)),
        ("sensitivity_counts", counts),
        ("category_minimums", minimums),
        ("guard_positive_slots", slots),
        ("category_closure", value::string("preserve_actual_source_full_sets_third_party_4_or_6_v1")),
        ("originals", value::int(32)),
        ("guard", value::int(16)),
        ("transforms", value::int(1)),
        ("semantic_execution_contract", value::string("explicit_semantic_only_success_training_base_candidate_v1")),
    ])
}

/// `TaxonomyDataset`.
#[derive(Debug, Clone, PartialEq)]
pub struct TaxonomyDataset {
    /// SHA-256 of the release bytes.
    pub sha256: String,
    /// The 640 rows in release order.
    pub rows: Vec<Example>,
    /// Permanent partition per source group.
    pub partitions: BTreeMap<String, String>,
    /// The retained exclusion validation record.
    pub exclusion_validation: Value,
}

/// `_target(value)`: explicit canonical classification components.
pub fn target(value: &Value) -> Result<Classification> {
    const MESSAGE: &str = "Taxonomy rows require explicit canonical classification components.";
    let Some(map) = value::as_object(value) else { return invalid(MESSAGE) };
    if map.len() != 3 || !["sensitivity", "visibility", "categories"].iter().all(|key| map.contains_key(*key)) {
        return invalid(MESSAGE);
    }
    let (Some(sensitivity), Some(visibility), Some(categories)) = (
        value::get(value, "sensitivity").and_then(value::as_str),
        value::get(value, "visibility").and_then(value::as_str),
        value::get(value, "categories").and_then(value::as_array),
    ) else {
        return invalid("Taxonomy rows contain unsupported or duplicate classification labels.");
    };
    let names: Vec<&str> = categories.iter().filter_map(value::as_str).collect();
    let unique: BTreeSet<&str> = names.iter().copied().collect();
    if !classification::is_sensitivity(sensitivity)
        || !classification::is_visibility(visibility)
        || names.len() != categories.len()
        || names.iter().any(|name| !classification::is_category(name))
        || unique.len() != names.len()
    {
        return invalid("Taxonomy rows contain unsupported or duplicate classification labels.");
    }
    let ordered: Vec<&str> = classification::category_names().filter(|name| unique.contains(name)).collect();
    let result = classification::initialise_unpacked(sensitivity, visibility, &ordered)?;
    if result.to_value()? != *value {
        return invalid("Taxonomy classification categories must use canonical enum order.");
    }
    Ok(result)
}

fn int_is(value: Option<&Value>, expected: i64) -> bool {
    value.and_then(value::as_i64) == Some(expected)
}

/// `load_dataset(path)`.
pub fn load_dataset(path: Option<&Path>) -> Result<TaxonomyDataset> {
    let Some(path) = path else {
        return invalid("Taxonomy coverage requires an explicit prepared dataset path.");
    };
    load_snapshot(&read_file(path)?)
}

/// `load_snapshot(payload)`: parse exactly the bytes whose digest is used before durable lookup.
pub fn load_snapshot(payload: &[u8]) -> Result<TaxonomyDataset> {
    let release = value::parse_bytes(payload)?;
    let policy = value::parse_bytes(&canonical_bytes(&policy_contract())?)?;
    if !value::is_object(&release)
        || !int_is(value::get(&release, "schema_version"), 1)
        || value::get(&release, "strategy").and_then(value::as_str) != Some(STRATEGY)
        || value::get(&release, "policy") != Some(&policy)
    {
        return invalid("Unsupported taxonomy release or policy plan.");
    }
    let empty = value::object(Vec::<(String, Value)>::new());
    let provenance = value::get(&release, "provenance").unwrap_or(&empty);
    let text_is = |key: &str, expected: &str| value::get(provenance, key).and_then(value::as_str) == Some(expected);
    if !text_is("source_sha256", SOURCE_SHA256)
        || !text_is("renderer_sha256", RENDERER_SHA256)
        || !text_is("source_split", "historical_train")
        || !text_is("label_status", "assistant_provisional")
        || !text_is("partition_recipe", PARTITION_RECIPE)
    {
        return invalid("Unsupported taxonomy TRAIN provenance.");
    }
    let validation = value::get(provenance, "exclusion_validation").unwrap_or(&empty);
    if value::get(validation, "status").and_then(value::as_str) != Some("passed")
        || value::get(validation, "all_transform_variants") != Some(&Value::Bool(true))
    {
        return invalid("Taxonomy release requires completed exclusion validation.");
    }
    let mut rows: Vec<Example> = Vec::new();
    let mut ids = BTreeSet::new();
    let mut texts = BTreeSet::new();
    let mut families: BTreeMap<String, (String, String)> = BTreeMap::new();
    let raw_rows: &[Value] = value::get(&release, "rows").and_then(value::as_array).map_or(&[], Vec::as_slice);
    for raw in raw_rows {
        if !value::is_object(raw) {
            return invalid("Taxonomy rows must be objects.");
        }
        let Some(classification_value) = value::get(raw, "classification") else {
            return invalid("Taxonomy rows require explicit canonical classification components.");
        };
        let target = target(classification_value)?;
        if value::get(raw, "packed_classification").and_then(value::as_i64) != Some(i64::from(target.pack())) {
            return invalid("Taxonomy named and packed targets disagree.");
        }
        let empty_meta = value::object(Vec::<(String, Value)>::new());
        let meta = value::get(raw, "metadata").unwrap_or(&empty_meta);
        if !value::is_object(meta) {
            return invalid("Taxonomy rows require metadata objects.");
        }
        let meta_str = |key: &str| value::get(meta, key).and_then(value::as_str);
        let (group, category, partition) = (meta_str("group_id"), meta_str("primary_category"), meta_str("taxonomy_partition"));
        let (Some(group), Some(category), Some(partition)) = (group, category, partition) else {
            return invalid("Taxonomy rows require declared TRAIN source groups and partitions.");
        };
        if group.trim().is_empty()
            || !AUDIENCES.iter().any(|(name, _)| *name == category)
            || !["train", "guard"].contains(&partition)
            || meta_str("split") != Some("train")
            || meta_str("label_status") != Some("assistant_provisional")
            || meta_str("target_convention") != Some("asserted_personal_disclosure_v1")
        {
            return invalid("Taxonomy rows require declared TRAIN source groups and partitions.");
        }
        let family = (category.to_string(), partition.to_string());
        if families.get(group).is_some_and(|existing| *existing != family) {
            return invalid("Taxonomy family crosses category or permanent partition.");
        }
        families.insert(group.to_string(), family);
        let (text, identity) = (value::get(raw, "text").and_then(value::as_str), value::get(raw, "id").and_then(value::as_str));
        let (Some(text), Some(identity)) = (text, identity) else {
            return invalid("Taxonomy rows require explicit nonempty text and IDs.");
        };
        if training_text_key(text).is_empty() || identity.is_empty() {
            return invalid("Taxonomy rows require explicit nonempty text and IDs.");
        }
        if ids.contains(identity) || texts.contains(&training_text_key(text)) {
            return invalid("Taxonomy release contains duplicate IDs or normalized texts.");
        }
        ids.insert(identity.to_string());
        texts.insert(training_text_key(text));
        let control = meta_str("control");
        let annotations = value::get(meta, "annotations").unwrap_or(&empty);
        let annotation_categories = value::get(annotations, "categories").and_then(value::as_object);
        let row_categories: BTreeSet<&str> = value::get(classification_value, "categories")
            .and_then(value::as_array)
            .map(|items| items.iter().filter_map(value::as_str).collect())
            .unwrap_or_default();
        let annotated: BTreeSet<&str> = annotation_categories.map(|map| map.keys().map(String::as_str).collect()).unwrap_or_default();
        let supported = ["actual", "fiction", "mild", "mixed", "hypothetical_real_premise"];
        let (Some(control), Some(_)) = (control.filter(|control| supported.contains(control)), annotation_categories) else {
            return invalid("Taxonomy rows require complete source category evidence and supported controls.");
        };
        if annotated != row_categories {
            return invalid("Taxonomy rows require complete source category evidence and supported controls.");
        }
        let severity = if ["FINANCIAL", "LOCATION", "THIRD_PARTY"].contains(&category) { "S2" } else { "S3" };
        let expected_sensitivity = if control == "fiction" {
            "S0"
        } else if control == "mild" {
            "S1"
        } else {
            severity
        };
        let has_categories = !target.categories().is_empty();
        if target.sensitivity() != expected_sensitivity
            || (["fiction", "mild"].contains(&control) && has_categories)
            || (!["fiction", "mild"].contains(&control) && !target.categories().contains(&category))
        {
            return invalid("Taxonomy source targets violate the reviewed disclosure convention.");
        }
        let mut metadata = BTreeMap::new();
        if let Some(map) = value::as_object(meta) {
            for (key, item) in map {
                let text = match item {
                    Value::String(text) => text.clone(),
                    other => value::dumps(other)?,
                };
                metadata.insert(key.clone(), text);
            }
        }
        metadata.insert("taxonomy_strategy".to_string(), STRATEGY.to_string());
        metadata.insert("taxonomy_row_id".to_string(), identity.to_string());
        rows.push(Example::new(text, target, 1.0, metadata));
    }
    if rows.len() != 640 || families.len() != 40 {
        return invalid("Taxonomy release requires 640 rows from forty complete TRAIN families.");
    }
    for (category, _) in AUDIENCES {
        let groups: Vec<&String> = families.iter().filter(|(_, (candidate, _))| candidate == category).map(|(group, _)| group).collect();
        let partitions: Vec<&str> = groups.iter().map(|group| families[*group].1.as_str()).collect();
        if groups.len() != 4 || partitions != ["train", "train", "guard", "guard"] {
            return invalid("Taxonomy family partition differs from the permanent recipe.");
        }
    }
    let dataset = TaxonomyDataset {
        sha256: value::sha256(payload),
        rows,
        partitions: families.iter().map(|(group, (_, partition))| (group.clone(), partition.clone())).collect(),
        exclusion_validation: validation.clone(),
    };
    // Every family must support each required control/audience before any reservation.
    for group in families.keys() {
        if dataset.rows.iter().filter(|row| row.metadata.get("group_id") == Some(group)).count() != 16 {
            return invalid("Taxonomy release requires sixteen rows per complete family.");
        }
        for (control, audiences) in [
            ("actual", classification::VISIBILITY.map(|(name, _)| name).to_vec()),
            ("fiction", classification::VISIBILITY.map(|(name, _)| name).to_vec()),
            ("mild", vec!["P1", "PU"]),
        ] {
            for audience in audiences {
                row(&dataset, group, control, audience)?;
            }
        }
    }
    Ok(dataset)
}

/// `prepare_release(source_bytes, renderer_bytes, exclusion_validation)`: export the pinned historical TRAIN split.
pub fn prepare_release(source_bytes: &[u8], renderer_bytes: &[u8], exclusion_validation: &Value) -> Result<Vec<u8>> {
    if value::sha256(source_bytes) != SOURCE_SHA256 {
        return invalid("Taxonomy preparation requires the pinned historical TRAIN bytes.");
    }
    if value::sha256(renderer_bytes) != RENDERER_SHA256 {
        return invalid("Taxonomy preparation requires the reviewed renderer bytes.");
    }
    let text = std::str::from_utf8(source_bytes).map_err(|_| crate::error::Error::Invalid("source is not valid UTF-8".to_string()))?;
    let mut rows: Vec<Value> = Vec::new();
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        rows.push(privoke_contracts::json::parse(line)?);
    }
    let mut families: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for row in &rows {
        let meta = value::require(row, "metadata")?;
        if value::get(meta, "split").and_then(value::as_str) != Some("train") {
            return invalid("Taxonomy preparation accepts TRAIN membership only.");
        }
        families
            .entry(value::str_at(meta, "primary_category")?.to_string())
            .or_default()
            .insert(value::str_at(meta, "group_id")?.to_string());
    }
    let category_set: BTreeSet<&str> = families.keys().map(String::as_str).collect();
    let expected: BTreeSet<&str> = AUDIENCES.iter().map(|(name, _)| *name).collect();
    if category_set != expected || families.values().any(|groups| groups.len() != 4) {
        return invalid("Taxonomy release requires four families per primary category.");
    }
    let mut partitions: BTreeMap<String, &str> = BTreeMap::new();
    for groups in families.values() {
        for (index, group) in groups.iter().enumerate() {
            partitions.insert(group.clone(), if index < 2 { "train" } else { "guard" });
        }
    }
    for row in &mut rows {
        let packed = target(value::require(row, "classification")?)?.pack();
        let Value::Object(map) = row else { return invalid("Taxonomy rows must be objects.") };
        map.insert("packed_classification".to_string(), value::int(i64::from(packed)));
        let group = match map.get("metadata") {
            Some(meta) => value::str_at(meta, "group_id")?.to_string(),
            None => return invalid("Taxonomy rows require metadata objects."),
        };
        if let Some(Value::Object(meta)) = map.get_mut("metadata") {
            meta.insert("taxonomy_partition".to_string(), value::string(partitions.get(&group).copied().unwrap_or("guard")));
        }
    }
    let provenance = value::object(vec![
        ("source_sha256", value::string(SOURCE_SHA256)),
        ("renderer_sha256", value::string(RENDERER_SHA256)),
        ("source_split", value::string("historical_train")),
        ("label_status", value::string("assistant_provisional")),
        ("partition_recipe", value::string(PARTITION_RECIPE)),
        ("fit_release", Value::Bool(false)),
        ("exclusion_validation", exclusion_validation.clone()),
    ]);
    let release = value::object(vec![
        ("schema_version", value::int(1)),
        ("strategy", value::string(STRATEGY)),
        ("policy", value::parse_bytes(&canonical_bytes(&policy_contract())?)?),
        ("rows", Value::Array(rows)),
        ("provenance", provenance),
    ]);
    let payload = canonical_bytes(&release)?;
    load_snapshot(&payload)?;
    Ok(payload)
}

/// `_row(dataset, group, control, audience)`: the unique row of a family for one control and audience.
pub fn row<'a>(dataset: &'a TaxonomyDataset, group: &str, control: &str, audience: &str) -> Result<&'a Example> {
    let mut matches = dataset.rows.iter().filter(|row| {
        row.metadata.get("group_id").map(String::as_str) == Some(group)
            && row.metadata.get("control").map(String::as_str) == Some(control)
            && row.target.is_some_and(|target| target.visibility().ok() == Some(audience))
    });
    match (matches.next(), matches.next()) {
        (Some(found), None) => Ok(found),
        _ => invalid("Taxonomy family cannot supply a unique required control/audience slot."),
    }
}

fn group_of(row: &Example) -> Result<&str> {
    row.meta("group_id")
}

fn train_groups(dataset: &TaxonomyDataset, category: &str, partition: &str) -> Result<Vec<String>> {
    let mut groups = BTreeSet::new();
    for row in &dataset.rows {
        if row.meta("primary_category")? == category && row.meta("taxonomy_partition")? == partition {
            groups.insert(group_of(row)?.to_string());
        }
    }
    Ok(groups.into_iter().collect())
}

/// `generate_partition(dataset, seed)`: the 32 training originals and the 16 guard rows.
pub fn generate_partition(dataset: &TaxonomyDataset, seed: u64) -> Result<(Vec<Example>, Vec<Example>)> {
    let mut rng = Random::new(seed);
    let mut selected: Vec<&Example> = Vec::new();
    let mut heldout: Vec<Example> = Vec::new();
    let mut chosen: BTreeMap<&str, String> = BTreeMap::new();
    for (category, audiences) in AUDIENCES {
        let groups = train_groups(dataset, category, "train")?;
        let group = rng.choice(&groups)?.clone();
        for audience in audiences {
            selected.push(row(dataset, &group, "actual", audience)?);
        }
        chosen.insert(category, group);
    }
    for ((category, _), audience) in AUDIENCES.iter().zip(CLEAN_AUDIENCES) {
        selected.push(row(dataset, &chosen[category], "fiction", audience)?);
    }
    for ((category, _), audience) in AUDIENCES.iter().zip(MILD_AUDIENCES) {
        selected.push(row(dataset, &chosen[category], "mild", audience)?);
    }
    let mut guard_groups: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    for (category, _) in AUDIENCES {
        guard_groups.insert(category, train_groups(dataset, category, "guard")?);
    }
    for (category, _) in AUDIENCES {
        if let Some(groups) = guard_groups.get_mut(category) {
            rng.shuffle(groups);
        }
    }
    let mut used = BTreeSet::new();
    for (((clean_category, _), clean_audience), (category, control, audience)) in
        AUDIENCES.iter().zip(CLEAN_AUDIENCES).zip(GUARD_POSITIVE_SLOTS)
    {
        let group = guard_groups[clean_category][0].clone();
        heldout.push(row(dataset, &group, "fiction", clean_audience)?.clone());
        used.insert(group);
        let group = guard_groups[category][1].clone();
        if used.contains(&group) {
            return invalid("Taxonomy guard source groups collide.");
        }
        heldout.push(row(dataset, &group, control, audience)?.clone());
        used.insert(group);
    }
    rng.shuffle(&mut selected);
    let training: Vec<Example> = selected
        .iter()
        .enumerate()
        .map(|(index, source)| {
            let mut metadata = source.metadata.clone();
            metadata.insert("generation_seed".to_string(), seed.to_string());
            metadata.insert("generation_index".to_string(), index.to_string());
            Example { text: source.text.clone(), target: source.target, weight: source.weight, metadata }
        })
        .collect();
    audit_originals(dataset, &training, &heldout)?;
    Ok((training, heldout))
}

/// `Counter` of sensitivity names, of visibilities of sensitive rows, and of category names.
pub type Counts = (BTreeMap<String, i64>, BTreeMap<String, i64>, BTreeMap<String, i64>);

/// `_counts(rows)`.
pub fn counts(rows: &[Example]) -> Result<Counts> {
    let mut sensitivity: BTreeMap<String, i64> = BTreeMap::new();
    let mut visibility: BTreeMap<String, i64> = BTreeMap::new();
    let mut categories: BTreeMap<String, i64> = BTreeMap::new();
    for row in rows {
        let target = row.classification()?;
        *sensitivity.entry(target.sensitivity().to_string()).or_default() += 1;
        if target.is_sensitive() {
            *visibility.entry(target.visibility()?.to_string()).or_default() += 1;
        }
        for category in target.categories() {
            *categories.entry(category.to_string()).or_default() += 1;
        }
    }
    Ok((sensitivity, visibility, categories))
}

/// `Counter` values as a JSON object.
pub fn counter_value(counter: &BTreeMap<String, i64>) -> Value {
    Value::Object(counter.iter().map(|(key, count)| (key.clone(), value::int(*count))).collect())
}

/// `_digest(values)`: SHA-256 of the canonical, sorted list.
pub fn digest_sorted<I: IntoIterator<Item = String>>(values: I) -> Result<String> {
    let mut sorted: Vec<String> = values.into_iter().collect();
    sorted.sort();
    value::digest_of(&value::strings(&sorted))
}

fn visibility_counts_fixed(count: i64) -> BTreeMap<String, i64> {
    classification::visibility_names().map(|name| (name.to_string(), count)).collect()
}

/// `audit_originals(dataset, training, heldout)`.
pub fn audit_originals(dataset: &TaxonomyDataset, training: &[Example], heldout: &[Example]) -> Result<BTreeMap<String, String>> {
    let (sensitivity, visibility, categories) = counts(training)?;
    let groups: BTreeSet<Option<String>> = training.iter().map(|row| row.metadata.get("group_id").cloned()).collect();
    let guard_groups: BTreeSet<Option<String>> = heldout.iter().map(|row| row.metadata.get("group_id").cloned()).collect();
    let unique_texts: BTreeSet<String> = training.iter().map(|row| training_text_key(&row.text)).collect();
    let expected_sensitivity: BTreeMap<String, i64> = SENSITIVITY_COUNTS.iter().map(|(name, count)| (name.to_string(), *count)).collect();
    if training.len() != 32
        || unique_texts.len() != 32
        || groups.len() != 10
        || sensitivity != expected_sensitivity
        || visibility != visibility_counts_fixed(4)
        || AUDIENCES.iter().any(|(category, _)| categories.get(*category).copied().unwrap_or(0) < CATEGORY_MINIMUM)
    {
        return invalid("Actual taxonomy training selection does not satisfy the fixed quotas.");
    }
    let (guard_sensitivity, guard_visibility, _) = counts(heldout)?;
    let expected_guard: BTreeMap<String, i64> =
        [("S0", 8), ("S1", 2), ("S2", 2), ("S3", 4)].iter().map(|(name, count)| (name.to_string(), *count)).collect();
    let alternating: Vec<bool> = heldout.iter().map(|row| row.classification().map(Classification::is_sensitive)).collect::<Result<_>>()?;
    let expected_alternating: Vec<bool> = (0..16).map(|index| index % 2 == 1).collect();
    let partition_is = |group: &Option<String>, expected: &str| {
        group.as_ref().and_then(|group| dataset.partitions.get(group)).map(String::as_str) == Some(expected)
    };
    if heldout.len() != 16
        || guard_groups.len() != 16
        || groups.intersection(&guard_groups).next().is_some()
        || groups.iter().any(|group| !partition_is(group, "train"))
        || guard_groups.iter().any(|group| !partition_is(group, "guard"))
        || guard_sensitivity != expected_guard
        || guard_visibility.keys().map(String::as_str).collect::<BTreeSet<_>>()
            != classification::visibility_names().collect::<BTreeSet<_>>()
        || alternating != expected_alternating
    {
        return invalid("Actual taxonomy guard violates its fixed quotas or permanent source partition.");
    }
    let guard_texts: BTreeSet<String> = heldout.iter().map(|row| training_text_key(&row.text)).collect();
    let possible: BTreeSet<String> =
        training.iter().flat_map(|row| transform_variants(&row.text)).map(|text| training_text_key(&text)).collect();
    if guard_texts.len() != 16 || guard_texts.intersection(&possible).next().is_some() {
        return invalid("Taxonomy guard overlaps a possible transformed training text.");
    }
    let source: BTreeMap<&str, &Example> =
        dataset.rows.iter().filter_map(|row| row.metadata.get("taxonomy_row_id").map(|id| (id.as_str(), row))).collect();
    for row in training.iter().chain(heldout) {
        let original = row.metadata.get("taxonomy_row_id").and_then(|id| source.get(id.as_str()));
        let consistent = original.is_some_and(|original| {
            row.text == original.text
                && row.packed() == original.packed()
                && row.weight == 1.0
                && ["group_id", "taxonomy_partition", "primary_category", "control"]
                    .iter()
                    .all(|key| row.metadata.get(*key) == original.metadata.get(*key))
        });
        if !consistent {
            return invalid("Taxonomy row differs from its snapshotted source target or provenance.");
        }
    }
    let mut selected_groups: BTreeMap<String, String> = BTreeMap::new();
    for row in training {
        let category = row.meta("primary_category")?.to_string();
        let group = row.meta("group_id")?.to_string();
        if *selected_groups.entry(category).or_insert_with(|| group.clone()) != group {
            return invalid("Taxonomy selection must use one TRAIN family per primary category.");
        }
    }
    let expected_categories: BTreeSet<&str> = AUDIENCES.iter().map(|(name, _)| *name).collect();
    if selected_groups.keys().map(String::as_str).collect::<BTreeSet<_>>() != expected_categories {
        return invalid("Taxonomy selection omits a primary category family.");
    }
    let mut expected: Vec<&Example> = Vec::new();
    for (category, audiences) in AUDIENCES {
        for audience in audiences {
            expected.push(row(dataset, &selected_groups[category], "actual", audience)?);
        }
    }
    for ((category, _), audience) in AUDIENCES.iter().zip(CLEAN_AUDIENCES) {
        expected.push(row(dataset, &selected_groups[*category], "fiction", audience)?);
    }
    for ((category, _), audience) in AUDIENCES.iter().zip(MILD_AUDIENCES) {
        expected.push(row(dataset, &selected_groups[*category], "mild", audience)?);
    }
    let multiset = |rows: Vec<&str>| {
        let mut out: BTreeMap<String, usize> = BTreeMap::new();
        for id in rows {
            *out.entry(id.to_string()).or_default() += 1;
        }
        out
    };
    let selected_ids = multiset(training.iter().map(|row| row.meta("taxonomy_row_id")).collect::<Result<_>>()?);
    let expected_ids = multiset(expected.iter().map(|row| row.meta("taxonomy_row_id")).collect::<Result<_>>()?);
    if selected_ids != expected_ids {
        return invalid("Actual taxonomy selection differs from the fixed source/audience slot plan.");
    }
    let group_names = |set: &BTreeSet<Option<String>>| set.iter().flatten().cloned().collect::<Vec<String>>();
    let mut audit = BTreeMap::new();
    audit.insert("contextual_sampling_strategy".to_string(), STRATEGY.to_string());
    audit.insert("taxonomy_dataset_sha256".to_string(), dataset.sha256.clone());
    audit.insert("sampling_training_rows".to_string(), "32".to_string());
    audit.insert("sampling_training_unique_texts".to_string(), "32".to_string());
    audit.insert("sampling_training_groups".to_string(), "10".to_string());
    audit.insert("sampling_guard_rows".to_string(), "16".to_string());
    audit.insert("sampling_guard_groups".to_string(), "16".to_string());
    audit.insert("sampling_sensitivity_counts".to_string(), value::dumps(&counter_value(&sensitivity))?);
    audit.insert("sampling_sensitive_visibility_counts".to_string(), value::dumps(&counter_value(&visibility))?);
    audit.insert("sampling_category_counts".to_string(), value::dumps(&counter_value(&categories))?);
    audit.insert(
        "sampling_training_ids_sha256".to_string(),
        digest_sorted(training.iter().map(|row| row.meta("taxonomy_row_id").map(str::to_string)).collect::<Result<Vec<_>>>()?)?,
    );
    audit.insert("sampling_training_groups_sha256".to_string(), digest_sorted(group_names(&groups))?);
    audit.insert("sampling_guard_groups_sha256".to_string(), digest_sorted(group_names(&guard_groups))?);
    Ok(audit)
}

/// `audit_expanded(dataset, originals, expanded, heldout, config)`.
pub fn audit_expanded(
    dataset: &TaxonomyDataset,
    originals: &[Example],
    expanded: &[Example],
    heldout: &[Example],
    config: &BatchTrainingConfig,
) -> Result<BTreeMap<String, String>> {
    let mut audit = audit_originals(dataset, originals, heldout)?;
    if config.transformations_per_example != 1 || expanded.len() != 64 {
        return invalid("Taxonomy coverage requires exactly one transformation and 64 actual training rows.");
    }
    for (index, original) in originals.iter().enumerate() {
        for (offset, actual) in expanded[index * 2..index * 2 + 2].iter().enumerate() {
            let allowed: Vec<String> = if offset == 1 { transform_variants(&original.text).to_vec() } else { vec![original.text.clone()] };
            if !allowed.contains(&actual.text)
                || actual.packed() != original.packed()
                || actual.metadata != original.metadata
                || actual.weight != original.weight * config.new_example_weight
            {
                return invalid("Actual taxonomy augmentation changed a target, weight or source provenance.");
            }
        }
    }
    let (sensitivity, visibility, categories) = counts(expanded)?;
    let (_, _, original_categories) = counts(originals)?;
    let doubled_sensitivity: BTreeMap<String, i64> = SENSITIVITY_COUNTS.iter().map(|(name, count)| (name.to_string(), count * 2)).collect();
    let doubled_categories: BTreeMap<String, i64> = original_categories.iter().map(|(name, count)| (name.clone(), count * 2)).collect();
    if sensitivity != doubled_sensitivity || visibility != visibility_counts_fixed(8) || categories != doubled_categories {
        return invalid("Actual expanded taxonomy batch lost declared positive exposure.");
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
    Ok(audit)
}
