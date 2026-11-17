//! `prompt_generation.audience_coverage`: the pinned TRAIN-only audience coverage (AU3) for the automatic requester.
//!
//! Catalog rows stay dict [`Value`]s because the release pins `digest(canonical(row))` over the PH3 rehearsal rows.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path};

use crate::classification::{self, target_from_value, visibility_names};
use crate::error::{Error, Result, invalid, read_file};
use crate::pyrandom::Random;
use crate::text::{format_named, training_text_key};
use crate::trainer::iter_training_examples;
use crate::types::{BatchTrainingConfig, Example};
use crate::value::{self, Value};

/// The sampler strategy name.
pub const STRATEGY: &str = "audience_coverage_v1";
/// The legacy strategy name.
pub const LEGACY: &str = "legacy_random_v1";
/// The generator version of the rendered rows.
pub const VERSION: &str = "audience_contrast_v3_v1";
/// SHA-256 of the bundled manifest.
pub const BUNDLED_MANIFEST_SHA256: &str = "7f17f43473deb4235ed189508008576abd19cf5eba0e9912d4c4ba4c58d7c010";
/// The ten primary categories, in sampler order.
pub const CATEGORIES: [&str; 10] =
    ["HEALTH", "POLITICS", "RELIGION", "CRIMINAL", "FINANCIAL", "SEXUAL", "CHILD", "LOCATION", "IDENTITY", "THIRD_PARTY"];
/// Files whose bytes bind the sampler, rendering and augmentation before a durable receipt lookup.
pub const CLOSURE_FILES: [&str; 10] = [
    "services/privoke-fuzzer/src/prompt_generation/audience_coverage.py",
    "services/privoke-fuzzer/src/prompt_generation/privacy_heads_curriculum.py",
    "services/privoke-fuzzer/src/prompt_generation/generator.py",
    "services/privoke-fuzzer/src/training/transforms.py",
    "services/privoke-fuzzer/src/training/types.py",
    "services/privoke-fuzzer/src/training/trainer.py",
    "services/privoke-fuzzer/src/fuzzer_service.py",
    "services/privoke-fuzzer/src/config.py",
    "shared/python/privoke_model/training_data.py",
    "shared/python/privoke_contracts/classification.py",
];

/// `digest(payload)`.
pub fn digest(payload: &[u8]) -> String {
    value::sha256(payload)
}

/// `implementation_closure()`: the digest over the byte digests of the Python files, read from `root`.
pub fn implementation_closure(root: &Path) -> Result<(String, Value)> {
    let mut files = BTreeMap::new();
    for name in CLOSURE_FILES {
        files.insert(name.to_string(), value::string(&digest(&read_file(&root.join(name))?)));
    }
    let files = Value::Object(files);
    Ok((digest(&value::canonical_bytes(&files)?), files))
}

fn target_of(row: &Value) -> Result<classification::Classification> {
    target_from_value(value::require(row, "classification")?)
}

fn row_meta(row: &Value) -> Result<&Value> {
    value::require(row, "metadata")
}

fn meta_str<'a>(row: &'a Value, key: &str) -> Result<&'a str> {
    value::str_at(row_meta(row)?, key)
}

/// `render_catalog(catalog)`: one permanent split, with complete named and packed targets.
pub fn render_catalog(catalog: &Value) -> Result<Vec<Value>> {
    let split = value::str_at(catalog, "split")?;
    if !["train", "validation", "fresh_eval"].contains(&split) || value::str_at(catalog, "label_status")? != "assistant_provisional" {
        return invalid("Unknown audience catalog partition/label status.");
    }
    let families = value::array_at(catalog, "families")?;
    let catalog_sha256 = digest(&value::canonical_bytes(catalog)?);
    let audience_table = value::object_at(catalog, "audience")?;
    if audience_table.keys().map(String::as_str).collect::<BTreeSet<_>>() != visibility_names().collect::<BTreeSet<_>>() {
        return invalid("Audience catalog must cover all six classes.");
    }
    let expected_expressions = if split == "train" { 8 } else { 4 };
    if audience_table.values().any(|items| value::as_array(items).map(Vec::len) != Some(expected_expressions)) {
        return invalid("Audience expression diversity budget differs.");
    }
    let entities = value::array_at(catalog, "entities")?;
    let mild_families = value::i64_at(catalog, "mild_families")? as usize;
    let control_names = value::array_at(catalog, "control_names")?;
    let actual_framings = value::array_at(catalog, "actual_framings")?;
    let clean_framings = value::array_at(catalog, "clean_framings")?;
    let rationales = value::object_at(catalog, "audience_rationales")?;
    let resource_id = value::str_at(catalog, "resource_id")?;
    let mut rows = Vec::new();
    for (family_index, family) in families.iter().enumerate() {
        let mild = value::str_at(family, "primary_category")? == "NONE";
        for (visibility_index, visibility) in visibility_names().enumerate() {
            for variant in 0..4usize {
                let actual_choices: Vec<bool> = if mild { vec![variant < 3] } else { vec![false, true] };
                for actual in actual_choices {
                    let expression_index = (family_index * 3 + variant) % expected_expressions;
                    let expressions = value::as_array(&audience_table[visibility])
                        .ok_or_else(|| Error::Invalid("audience expressions must be a list".to_string()))?;
                    let expression = pick_str(expressions, expression_index)?;
                    let entity = pick_str(entities, (family_index + variant * 5 + visibility_index * 7) % entities.len())?;
                    let mut entity_fields = BTreeMap::new();
                    entity_fields.insert("entity", entity);
                    let evidence = format_named(expression, &entity_fields)?;
                    let mut fact = value::str_at(family, "fact")?.to_string();
                    let mut components = vec![value::str_at(family, "component_id")?.to_string()];
                    let mut categories: Vec<String> = string_list(value::require(family, "categories")?)?;
                    let mut sensitivity = value::str_at(family, "sensitivity")?.to_string();
                    if actual && !mild && variant >= 2 {
                        let secondary = &families[(family_index + 7) % (families.len() - mild_families)];
                        fact.push_str("; ");
                        fact.push_str(value::str_at(secondary, "fact")?);
                        let mut merged: BTreeSet<String> = categories.into_iter().collect();
                        merged.extend(string_list(value::require(secondary, "categories")?)?);
                        categories = merged.into_iter().collect();
                        let other = value::str_at(secondary, "sensitivity")?;
                        if other > sensitivity.as_str() {
                            sensitivity = other.to_string();
                        }
                        components.push(value::str_at(secondary, "component_id")?.to_string());
                    }
                    let control = if actual && mild {
                        "mild_personal".to_string()
                    } else if actual {
                        "actual_disclosure".to_string()
                    } else {
                        pick_str(control_names, variant)?.to_string()
                    };
                    let framing = pick_str(if actual { actual_framings } else { clean_framings }, variant)?;
                    let topic = value::str_at(family, "topic")?;
                    let mut body_fields = BTreeMap::new();
                    body_fields.insert("fact", fact.as_str());
                    body_fields.insert("topic", topic);
                    let body = format_named(framing, &body_fields)?;
                    let text = if variant % 2 == 0 { format!("{body} {evidence}") } else { format!("{evidence} {body}") };
                    let classification = classification::target(
                        if actual { sensitivity.as_str() } else { "S0" },
                        visibility,
                        if actual { categories.as_slice() } else { &[] },
                    )?;
                    let family_id = value::str_at(family, "family_id")?;
                    let identifier = format!("{family_id}/{visibility}/{variant}/{}", i32::from(actual));
                    let allowed: Vec<&str> =
                        if matches!(classification.sensitivity(), "S0" | "S1") { vec!["ALLOW"] } else { vec!["WARN", "BLOCK"] };
                    let expression_id = format!("AU3/{split}/{visibility}/expression/{expression_index}");
                    let component_ids = value::dumps(&value::strings(&components))?;
                    let asserted =
                        if actual { value::dumps(&value::strings(&components))? } else { value::dumps(&Value::Array(Vec::new()))? };
                    let metadata = value::object(vec![
                        ("example_id", value::string(&identifier)),
                        ("family_id", value::string(family_id)),
                        ("group_id", value::string(family_id)),
                        ("parent_id", value::string(family_id)),
                        ("split", value::string(split)),
                        ("source_resource", value::string(resource_id)),
                        ("source_resource_sha256", value::string(&catalog_sha256)),
                        ("generator", value::string(VERSION)),
                        ("training_role", value::string("authored_audience_contrast")),
                        ("primary_category", value::string(value::str_at(family, "primary_category")?)),
                        ("control", value::string(&control)),
                        ("subject_relationship", value::string(value::str_at(family, "subject_relationship")?)),
                        ("component_ids", value::string(&component_ids)),
                        ("asserted_component_ids", value::string(&asserted)),
                        ("coarse_situation_id", value::string(value::str_at(family, "coarse_situation_id")?)),
                        ("body_framing_group_id", value::string(&format!("AU3/{split}/body/{variant}/{}", i32::from(actual)))),
                        ("audience_expression_id", value::string(&expression_id)),
                        ("audience_expression_group_id", value::string(&expression_id)),
                        ("audience_class", value::string(visibility)),
                        ("audience_evidence", value::string(&evidence)),
                        (
                            "visibility_rationale",
                            value::string(
                                value::as_str(
                                    rationales.get(visibility).ok_or_else(|| Error::Invalid("missing audience rationale".to_string()))?,
                                )
                                .unwrap_or_default(),
                            ),
                        ),
                        (
                            "category_rationale",
                            value::string(if actual {
                                "All explicitly asserted actual domains, including named secondary facts."
                            } else {
                                "No actual person's completed record is supplied; domain words alone are not disclosure."
                            }),
                        ),
                        (
                            "sensitivity_rationale",
                            value::string(if actual && mild {
                                "Actual mild preference/routine."
                            } else if actual {
                                "Explicit actual personal fact with all asserted domains retained."
                            } else {
                                "Explicitly absent, unfilled or wholly invented record; no real referent."
                            }),
                        ),
                        ("entity_pool_id", value::string(&format!("AU3/{split}/neutral_titles"))),
                        ("entity_value", value::string(entity)),
                        ("label_status", value::string("assistant_provisional")),
                        ("variant", value::string(&variant.to_string())),
                    ]);
                    let packed = value::int(i64::from(classification.pack()));
                    rows.push(value::object(vec![
                        ("id", value::string(&identifier)),
                        ("case_id", value::string(&identifier)),
                        ("family_id", value::string(family_id)),
                        ("group_id", value::string(family_id)),
                        ("partition", value::string(split)),
                        ("text", value::string(&text)),
                        ("classification", classification.to_value()?),
                        ("packed", packed.clone()),
                        ("packed_classification", packed),
                        ("weight", Value::Float(1.0)),
                        ("required_sensitive", Value::Bool(classification.is_sensitive())),
                        ("allowed_actions", value::strings(&allowed)),
                        ("ambiguous", Value::Bool(false)),
                        ("context_truth_eligible", Value::Bool(true)),
                        ("action_accuracy_eligible", Value::Bool(true)),
                        ("label_status", value::string("assistant_provisional")),
                        ("metadata", metadata),
                    ]));
                }
            }
        }
    }
    validate_rows(&rows, split)?;
    Ok(rows)
}

fn pick_str(items: &[Value], index: usize) -> Result<&str> {
    items.get(index).and_then(value::as_str).ok_or_else(|| Error::Invalid("catalog list entry missing or not a string".to_string()))
}

fn string_list(item: &Value) -> Result<Vec<String>> {
    match value::as_array(item) {
        Some(items) => items
            .iter()
            .map(|entry| {
                value::as_str(entry)
                    .map(str::to_string)
                    .ok_or_else(|| Error::Invalid("Categories must be an explicit unique supported list.".to_string()))
            })
            .collect(),
        None => invalid("Categories must be an explicit unique supported list."),
    }
}

/// `legacy_train_rows(resource)`: the unchanged PH3 TRAIN rows from a TRAIN-only restricted catalog.
pub fn legacy_train_rows(resource: &Value) -> Result<Vec<Value>> {
    let only_train =
        |key: &str| -> Result<bool> { Ok(value::object_at(resource, key)?.keys().map(String::as_str).collect::<Vec<_>>() == ["train"]) };
    let families = value::array_at(resource, "families")?;
    if !only_train("splits")?
        || !only_train("auxiliary")?
        || families.iter().any(|family| value::get(family, "split").and_then(value::as_str) != Some("train"))
    {
        return invalid("Runtime rehearsal catalog must contain TRAIN only.");
    }
    let mut rows = Vec::new();
    for family in families {
        for audience in visibility_names() {
            for variant in 0..4 {
                for actual in [false, true] {
                    rows.push(crate::privacy_heads::row(resource, family, "train", audience, variant, actual, false)?);
                }
            }
        }
    }
    for family in value::array_at(value::require(resource, "auxiliary")?, "train")? {
        for audience in visibility_names() {
            for variant in 0..4 {
                rows.push(crate::privacy_heads::row(resource, family, "train", audience, variant, variant < 3, true)?);
            }
        }
    }
    if rows.len() != 6240 {
        return invalid("PH3 TRAIN rehearsal row budget changed.");
    }
    validate_rows(&rows, "train")?;
    Ok(rows)
}

/// `validate_rows(rows, partition)`.
pub fn validate_rows(rows: &[Value], partition: &str) -> Result<()> {
    let mut ids = BTreeSet::new();
    let mut keys = BTreeSet::new();
    let required: BTreeSet<&str> = [
        "example_id",
        "parent_id",
        "source_resource",
        "source_resource_sha256",
        "generator",
        "training_role",
        "primary_category",
        "control",
        "subject_relationship",
        "component_ids",
        "asserted_component_ids",
        "coarse_situation_id",
        "body_framing_group_id",
        "audience_expression_id",
        "audience_expression_group_id",
        "audience_class",
        "audience_evidence",
        "visibility_rationale",
        "category_rationale",
        "sensitivity_rationale",
        "entity_pool_id",
        "entity_value",
        "label_status",
    ]
    .into_iter()
    .collect();
    for row in rows {
        let named = value::get(row, "classification");
        let named_keys: BTreeSet<&str> =
            named.and_then(value::as_object).map(|map| map.keys().map(String::as_str).collect()).unwrap_or_default();
        let (Some(named), true) = (named, named_keys == ["sensitivity", "visibility", "categories"].into_iter().collect::<BTreeSet<_>>())
        else {
            return invalid("Audience rows need complete named truth.");
        };
        let classification = target_from_value(named)?;
        let packed = Some(i64::from(classification.pack()));
        let meta = row_meta(row)?;
        let weight_ok = value::get(row, "weight").is_none_or(|weight| value::as_number(weight) == Some(1.0));
        if classification.to_value()? != *named
            || value::get(row, "packed").and_then(value::as_i64) != packed
            || value::get(row, "packed_classification").and_then(value::as_i64) != packed
            || value::get(row, "partition").and_then(value::as_str) != Some(partition)
            || value::get(meta, "split").and_then(value::as_str) != Some(partition)
            || value::get(row, "ambiguous") != Some(&Value::Bool(false))
            || !weight_ok
            || !value::get(row, "context_truth_eligible").is_some_and(classification::is_truthy)
            || value::get(row, "visibility_hint").is_some_and(classification::is_truthy)
        {
            return invalid("Audience row target/partition/weight/eligibility mismatch.");
        }
        let text = value::str_at(row, "text")?;
        let key = training_text_key(text);
        let identifier = value::str_at(row, "id")?;
        if key.is_empty() || keys.contains(&key) || ids.contains(identifier) || text.contains('{') || text.contains('}') {
            return invalid("Empty, duplicate or unrendered audience row.");
        }
        if value::str_at(row, "group_id")? != value::str_at(row, "family_id")?
            || value::str_at(meta, "group_id")? != value::str_at(row, "group_id")?
        {
            return invalid("Audience row group provenance mismatch.");
        }
        let allowed: Vec<&str> = if matches!(classification.sensitivity(), "S0" | "S1") { vec!["ALLOW"] } else { vec!["WARN", "BLOCK"] };
        let actual_allowed: Vec<&str> = value::array_at(row, "allowed_actions")?.iter().filter_map(value::as_str).collect();
        if actual_allowed != allowed || value::array_at(row, "allowed_actions")?.len() != allowed.len() {
            return invalid("Audience allowed actions disagree with disclosed severity.");
        }
        if identifier.starts_with("AU3/") {
            let present: BTreeSet<&str> = value::as_object(meta).map(|map| map.keys().map(String::as_str).collect()).unwrap_or_default();
            let all_text =
                value::as_object(meta).is_some_and(|map| map.values().all(|item| value::as_str(item).is_some_and(|text| !text.is_empty())));
            if !required.is_subset(&present)
                || !all_text
                || value::str_at(meta, "audience_class")? != classification.visibility()?
                || value::str_at(meta, "label_status")? != "assistant_provisional"
            {
                return invalid("Audience row lacks complete explicit source/label provenance.");
            }
        }
        ids.insert(identifier.to_string());
        keys.insert(key);
    }
    Ok(())
}

/// `example(row, seed, index)`.
pub fn example(row: &Value, seed: Option<(u64, usize)>) -> Result<Example> {
    let mut metadata = value::string_map(row_meta(row)?).ok_or_else(|| Error::Invalid("Audience metadata must be strings.".to_string()))?;
    if let Some((seed, index)) = seed {
        metadata.insert("generation_seed".to_string(), seed.to_string());
        metadata.insert("generation_index".to_string(), index.to_string());
        metadata.insert("sampler".to_string(), STRATEGY.to_string());
    }
    Ok(Example::new(value::str_at(row, "text")?, target_of(row)?, 1.0, metadata))
}

/// `Release`.
#[derive(Debug, Clone, PartialEq)]
pub struct AudienceRelease {
    /// The 3120 rendered AU3 TRAIN rows.
    pub train: Vec<Value>,
    /// The 6240 unchanged PH3 rehearsal rows.
    pub rehearsal: Vec<Value>,
    /// The 16 validation guard rows.
    pub guard: Vec<Value>,
    /// The manifest.
    pub manifest: Value,
    /// SHA-256 of the manifest bytes.
    pub sha256: String,
}

/// `load_release(manifest_path, expected_sha256)`; `None` selects the bundled manifest and its pin.
pub fn load_release(manifest_path: Option<&Path>, expected_sha256: Option<&str>) -> Result<AudienceRelease> {
    let default_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../services/privoke-fuzzer/data/audience-v3-manifest-v1.json");
    load_release_from(manifest_path.unwrap_or(&default_path), manifest_path.is_none(), expected_sha256)
}

/// `load_release` for an explicit path; `bundled` selects the bundled pin when no pin is supplied.
pub fn load_release_from(path: &Path, bundled: bool, expected_sha256: Option<&str>) -> Result<AudienceRelease> {
    let raw = read_file(path)?;
    let sha = digest(&raw);
    let expected = match (bundled, expected_sha256) {
        (true, None) => Some(BUNDLED_MANIFEST_SHA256),
        (false, None) => return invalid("Custom audience manifest requires an explicit trusted SHA256 pin."),
        (_, pin) => pin,
    };
    if expected.is_some_and(|pin| sha != pin) {
        return invalid("Audience manifest hash differs from trusted pin.");
    }
    let manifest = value::parse_bytes(&raw)?;
    let files = value::object_at(&manifest, "files")?;
    if value::i64_at(&manifest, "schema")? != 1
        || value::str_at(&manifest, "strategy")? != STRATEGY
        || files.keys().map(String::as_str).collect::<BTreeSet<_>>()
            != ["train_catalog", "rehearsal_catalog", "guard"].into_iter().collect()
    {
        return invalid("Wrong audience runtime manifest.");
    }
    let parent = path.parent().unwrap_or(Path::new("."));
    let mut values: BTreeMap<&str, Value> = BTreeMap::new();
    for (key, descriptor) in files {
        let relative = Path::new(value::str_at(descriptor, "path")?);
        if relative.is_absolute() || relative.components().any(|component| component == Component::ParentDir) {
            return invalid("Audience runtime inputs must remain inside release directory.");
        }
        let bytes = read_file(&parent.join(relative))?;
        if digest(&bytes) != value::str_at(descriptor, "sha256")? {
            return invalid(format!("Audience runtime source bytes changed: {key}"));
        }
        values.insert(key.as_str(), value::parse_bytes(&bytes)?);
    }
    let train_catalog = &values["train_catalog"];
    if value::get(train_catalog, "split").and_then(value::as_str) != Some("train") {
        return invalid("Automatic audience generation accepts TRAIN catalog only.");
    }
    let train = render_catalog(train_catalog)?;
    let rehearsal = legacy_train_rows(&values["rehearsal_catalog"])?;
    let guard: Vec<Value> = value::as_array(&values["guard"]).cloned().ok_or_else(|| Error::Invalid("guard must be a list".to_string()))?;
    validate_rows(&guard, "validation")?;
    let mut rehearsal_bytes = Vec::new();
    for row in &rehearsal {
        rehearsal_bytes.extend(value::canonical_bytes(row)?);
    }
    if train.len() != 3120 || guard.len() != 16 || digest(&rehearsal_bytes) != value::str_at(&manifest, "ph3_train_sha256")? {
        return invalid("Audience release row budget or immutable PH3 ancestry differs.");
    }
    let all_train: Vec<Value> = train.iter().chain(&rehearsal).cloned().collect();
    validate_rows(&all_train, "train")?;
    let train_keys: BTreeSet<String> =
        all_train.iter().map(|row| value::str_at(row, "text").map(training_text_key)).collect::<Result<_>>()?;
    let guard_keys: BTreeSet<String> = guard.iter().map(|row| value::str_at(row, "text").map(training_text_key)).collect::<Result<_>>()?;
    let train_groups: BTreeSet<&str> = all_train.iter().map(|row| value::str_at(row, "group_id")).collect::<Result<_>>()?;
    let guard_groups: BTreeSet<&str> = guard.iter().map(|row| value::str_at(row, "group_id")).collect::<Result<_>>()?;
    if train_keys.intersection(&guard_keys).next().is_some() || train_groups.intersection(&guard_groups).next().is_some() {
        return invalid("Audience TRAIN/guard overlap.");
    }
    Ok(AudienceRelease { train, rehearsal, guard, manifest, sha256: sha })
}

/// `validate_count(count, heldout_count)`: multiples of 32 originals and 16 guard rows.
pub fn validate_count(count: i64, heldout_count: i64) -> Result<()> {
    if count < 32 || count % 32 != 0 || heldout_count != 16 {
        return invalid("Audience coverage requires multiples of 32 originals and 16 guard rows.");
    }
    Ok(())
}

fn visibility_of(row: &Value) -> Result<&str> {
    value::str_at(value::require(row, "classification")?, "visibility")
}

fn sensitivity_of(row: &Value) -> Result<&str> {
    value::str_at(value::require(row, "classification")?, "sensitivity")
}

/// `choose(candidates)`: prefer an unseen family and expression before taking a sibling in this cycle.
fn choose<'a>(candidates: Vec<&'a Value>, chosen: &mut Vec<&'a Value>, used: &mut BTreeSet<String>, rng: &mut Random) -> Result<()> {
    let mut eligible: Vec<&'a Value> = Vec::new();
    for row in candidates {
        if !used.contains(value::str_at(row, "id")?) {
            eligible.push(row);
        }
    }
    if eligible.is_empty() {
        return invalid("Audience TRAIN pool cannot satisfy quota without replacement.");
    }
    let mut seen_groups: BTreeSet<&str> = BTreeSet::new();
    let mut seen_expressions: BTreeSet<Option<&str>> = BTreeSet::new();
    for row in chosen.iter() {
        seen_groups.insert(value::str_at(row, "group_id")?);
        seen_expressions.insert(value::get(row_meta(row)?, "audience_expression_id").and_then(value::as_str));
    }
    let mut preferred: Vec<&'a Value> = Vec::new();
    for row in &eligible {
        let expression = value::get(row_meta(row)?, "audience_expression_id").and_then(value::as_str);
        if !seen_groups.contains(value::str_at(row, "group_id")?) && !seen_expressions.contains(&expression) {
            preferred.push(*row);
        }
    }
    let pool = if preferred.is_empty() { &eligible } else { &preferred };
    let row: &'a Value = pool[rng.choice_index(pool.len())?];
    chosen.push(row);
    used.insert(value::str_at(row, "id")?.to_string());
    Ok(())
}

/// `generate_partition(release, seed, count)`: quota-driven selection without replacement, then the pinned guard.
pub fn generate_partition(release: &AudienceRelease, seed: u64, count: i64) -> Result<(Vec<Example>, Vec<Example>)> {
    validate_count(count, 16)?;
    let mut rng = Random::new(seed);
    let mut chosen: Vec<&Value> = Vec::new();
    let mut used: BTreeSet<String> = BTreeSet::new();
    let mut sensitive: BTreeMap<&str, Vec<&Value>> = BTreeMap::new();
    for category in CATEGORIES {
        let mut rows = Vec::new();
        for row in &release.train {
            if meta_str(row, "primary_category")? == category && meta_str(row, "control")? == "actual_disclosure" {
                rows.push(row);
            }
        }
        sensitive.insert(category, rows);
    }
    for block in 0..(count / 32) as u64 {
        let mut categories: Vec<&str> = CATEGORIES.to_vec();
        rng.shuffle(&mut categories);
        let head: Vec<&str> = categories[..2].to_vec();
        categories.extend(head);
        for (index, audience) in visibility_names().enumerate() {
            for category in &categories[index * 2..index * 2 + 2] {
                let mut candidates = Vec::new();
                for row in &sensitive[category] {
                    if visibility_of(row)? == audience {
                        candidates.push(*row);
                    }
                }
                choose(candidates, &mut chosen, &mut used, &mut rng)?;
            }
            let mut clean = Vec::new();
            let mut mild = Vec::new();
            for row in &release.train {
                if visibility_of(row)? == audience {
                    if sensitivity_of(row)? == "S0" && meta_str(row, "primary_category")? != "NONE" {
                        clean.push(row);
                    }
                    if meta_str(row, "primary_category")? == "NONE" {
                        mild.push(row);
                    }
                }
            }
            choose(clean, &mut chosen, &mut used, &mut rng)?;
            choose(mild, &mut chosen, &mut used, &mut rng)?;
        }
        let mut replay: Vec<&Value> = release.rehearsal.iter().collect();
        rng.shuffle(&mut replay);
        for index in 0..8u64 {
            let audience = visibility_names().nth(((index + seed + block) % 6) as usize).unwrap_or("PU");
            let wanted = index % 2 == 1;
            let mut candidates = Vec::new();
            for row in &replay {
                if visibility_of(row)? == audience && value::get(row, "required_sensitive") == Some(&Value::Bool(wanted)) {
                    candidates.push(*row);
                }
            }
            choose(candidates, &mut chosen, &mut used, &mut rng)?;
        }
    }
    rng.shuffle(&mut chosen);
    let training: Vec<Example> = chosen.iter().enumerate().map(|(index, row)| example(row, Some((seed, index)))).collect::<Result<_>>()?;
    let guard: Vec<Example> = release.guard.iter().map(|row| example(row, None)).collect::<Result<_>>()?;
    audit_originals(release, &training, &guard, Some(seed), None)?;
    Ok((training, guard))
}

/// `audit_originals(release, training, guard, seed)`. The returned audit carries `implementation_sha256` when given.
pub fn audit_originals(
    release: &AudienceRelease,
    training: &[Example],
    guard: &[Example],
    seed: Option<u64>,
    implementation_sha256: Option<&str>,
) -> Result<BTreeMap<String, String>> {
    validate_count(training.len() as i64, guard.len() as i64)?;
    let mut source: BTreeMap<&str, &Value> = BTreeMap::new();
    for row in release.train.iter().chain(&release.rehearsal) {
        source.insert(value::str_at(row, "id")?, row);
    }
    let mut keys = BTreeSet::new();
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut categories = BTreeSet::new();
    let mut roles: BTreeMap<(String, &str), usize> = BTreeMap::new();
    let mut replay_labels: BTreeMap<bool, usize> = BTreeMap::new();
    for (index, row) in training.iter().enumerate() {
        let identifier = row.meta_opt("example_id");
        let expected = identifier.and_then(|id| source.get(id));
        let Some(expected) = expected else {
            return invalid("Actual audience selection differs from pinned TRAIN source.");
        };
        if row.text != value::str_at(expected, "text")?
            || row.packed().map(i64::from) != value::get(expected, "packed").and_then(value::as_i64)
            || row.weight != 1.0
        {
            return invalid("Actual audience selection differs from pinned TRAIN source.");
        }
        let mut allowed =
            value::string_map(row_meta(expected)?).ok_or_else(|| Error::Invalid("Audience metadata must be strings.".to_string()))?;
        for key in ["generation_seed", "generation_index", "sampler"] {
            match row.metadata.get(key) {
                Some(found) => allowed.insert(key.to_string(), found.clone()),
                None => return invalid("Actual audience metadata differs from pinned TRAIN provenance."),
            };
        }
        if row.metadata != allowed || row.meta_opt("sampler") != Some(STRATEGY) {
            return invalid("Actual audience metadata differs from pinned TRAIN provenance.");
        }
        if row.meta_opt("generation_index") != Some(index.to_string().as_str())
            || seed.is_some_and(|seed| row.meta_opt("generation_seed") != Some(seed.to_string().as_str()))
        {
            return invalid("Actual audience generation seed/order differs.");
        }
        if !keys.insert(identifier.unwrap_or_default().to_string()) {
            return invalid("Audience selection repeats a source row within cycle.");
        }
        if row.meta_opt("generator") == Some(VERSION) {
            let visibility = row.classification()?.visibility()?;
            *counts.entry(visibility.to_string()).or_default() += 1;
            let role = if row.meta("primary_category")? == "NONE" {
                "mild_source"
            } else if row.meta("control")? == "actual_disclosure" {
                "actual"
            } else {
                "hard_clean"
            };
            *roles.entry((visibility.to_string(), role)).or_default() += 1;
            if row.meta("control")? == "actual_disclosure" {
                categories.insert(row.meta("primary_category")?.to_string());
            }
        } else {
            *replay_labels.entry(row.classification()?.is_sensitive()).or_default() += 1;
        }
    }
    let blocks = training.len() / 32;
    let expected_categories: BTreeSet<String> = CATEGORIES.iter().map(|name| name.to_string()).collect();
    let role_count =
        |visibility: &str, role: &str| roles.iter().find(|((v, r), _)| v == visibility && *r == role).map_or(0, |(_, count)| *count);
    if categories != expected_categories
        || visibility_names().any(|visibility| counts.get(visibility).copied().unwrap_or(0) != training.len() / 8)
    {
        return invalid("Actual audience/category quotas differ.");
    }
    let role_ok = visibility_names()
        .all(|v| role_count(v, "actual") == 2 * blocks && role_count(v, "hard_clean") == blocks && role_count(v, "mild_source") == blocks);
    let sensitive_replay = replay_labels.get(&true).copied().unwrap_or(0);
    let clean_replay = replay_labels.get(&false).copied().unwrap_or(0);
    if !role_ok || sensitive_replay != 4 * blocks || clean_replay != 4 * blocks || replay_labels.len() != 2 {
        return invalid("Actual audience role/rehearsal clean-sensitive quotas differ.");
    }
    let guard_actual: Vec<(&str, Option<u16>, f64)> = guard.iter().map(|row| (row.text.as_str(), row.packed(), row.weight)).collect();
    let mut guard_expected: Vec<(&str, Option<u16>, f64)> = Vec::new();
    for row in &release.guard {
        guard_expected.push((value::str_at(row, "text")?, Some(value::i64_at(row, "packed")? as u16), 1.0));
    }
    if guard_actual != guard_expected {
        return invalid("Actual audience guard differs from permanent release.");
    }
    let au3_rows: usize = counts.values().sum();
    let counts_value = Value::Object(counts.iter().map(|(name, count)| (name.clone(), value::int(*count as i64))).collect());
    let mut role_value = BTreeMap::new();
    for visibility in visibility_names() {
        let per_role: BTreeMap<String, Value> = ["actual", "hard_clean", "mild_source"]
            .iter()
            .map(|role| (role.to_string(), value::int(role_count(visibility, role) as i64)))
            .collect();
        role_value.insert(visibility.to_string(), Value::Object(per_role));
    }
    let selected_ids: Vec<String> = training.iter().map(|row| row.meta("example_id").map(str::to_string)).collect::<Result<_>>()?;
    let expression_groups: BTreeSet<Option<&str>> = training
        .iter()
        .filter(|row| row.meta_opt("generator") == Some(VERSION))
        .map(|row| row.meta_opt("audience_expression_group_id"))
        .collect();
    let mut audit = BTreeMap::new();
    audit.insert("contextual_sampling_strategy".to_string(), STRATEGY.to_string());
    audit.insert("audience_manifest_sha256".to_string(), release.sha256.clone());
    audit.insert("audience_implementation_sha256".to_string(), implementation_sha256.unwrap_or_default().to_string());
    audit.insert("sampling_training_rows".to_string(), training.len().to_string());
    audit.insert("sampling_au3_rows".to_string(), au3_rows.to_string());
    audit.insert("sampling_rehearsal_rows".to_string(), (training.len() - au3_rows).to_string());
    audit.insert("sampling_primary_categories".to_string(), categories.len().to_string());
    audit.insert("sampling_audience_counts".to_string(), value::dumps(&counts_value)?);
    audit.insert("sampling_role_counts".to_string(), value::dumps(&Value::Object(role_value))?);
    audit.insert("sampling_rehearsal_sensitive_rows".to_string(), sensitive_replay.to_string());
    audit.insert("sampling_rehearsal_clean_rows".to_string(), clean_replay.to_string());
    audit.insert("sampling_selected_ids_sha256".to_string(), value::digest_of(&value::strings(&selected_ids))?);
    audit.insert("sampling_audience_expression_groups".to_string(), expression_groups.len().to_string());
    Ok(audit)
}

/// `audit_expanded(release, originals, expanded, guard, config)`.
pub fn audit_expanded(
    release: &AudienceRelease,
    originals: &[Example],
    expanded: &[Example],
    guard: &[Example],
    config: &BatchTrainingConfig,
    implementation_sha256: Option<&str>,
) -> Result<BTreeMap<String, String>> {
    let mut result = audit_originals(release, originals, guard, Some(config.seed), implementation_sha256)?;
    let expected = iter_training_examples(originals, &[], config)?;
    if expanded != expected.as_slice() || expanded.iter().any(|row| row.weight != 1.0) {
        return invalid("Actual audience transformed stream/weights differ from admitted invariants.");
    }
    result.insert("sampling_expanded_exposures".to_string(), expanded.len().to_string());
    result.insert(
        "sampling_expanded_unique_texts".to_string(),
        expanded.iter().map(|row| training_text_key(&row.text)).collect::<BTreeSet<_>>().len().to_string(),
    );
    Ok(result)
}
