//! `prompt_generation.privacy_heads_curriculum`: the family-separated privacy-head fuzzer data, no model access.
//!
//! Rows stay dict [`Value`]s because the release manifest pins a digest over `canonical(row)` for each of them.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use privoke_rules::pyunicode;

use crate::classification::{self, Classification, category_names, target_from_value, visibility_names};
use crate::error::{Error, Result, invalid, read_file};
use crate::prompt_seed::load_prompt_dataset;
use crate::pyrandom::Random;
use crate::text::{format_named, training_text_key};
use crate::types::Example;
use crate::value::{self, Value};

/// The generator version string.
pub const VERSION: &str = "privacy_heads_fact_contrast_v2";
/// Permanent splits.
pub const SPLITS: [&str; 3] = ["train", "validation", "eval"];
/// Rows per split.
pub const COUNTS: [(&str, usize); 3] = [("train", 6240), ("validation", 1560), ("eval", 1560)];
/// The rubric sources a resource must declare.
pub const RUBRIC_PATHS: [&str; 4] = [
    "paper/research/contextual-cascade-rubric.md",
    "evaluation/datasets/synthetic-teacher-templates-v2.json",
    "shared/python/privoke_contracts/classification.py",
    "extension/client-runtime/src/classification/classification_policy.py",
];

/// `.strip()` with Python's whitespace.
pub fn py_strip(text: &str) -> &str {
    text.trim_matches(pyunicode::is_space)
}

fn is_boundary(chars: &[char], index: usize) -> bool {
    let before = index > 0 && pyunicode::is_word(chars[index - 1]);
    let after = index < chars.len() && pyunicode::is_word(chars[index]);
    before != after
}

/// `re.sub(rf"\b{re.escape(literal)}\b", replacement, text)`.
fn replace_word_literal(text: &str, literal: &str, replacement: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let needle: Vec<char> = literal.chars().collect();
    if needle.is_empty() {
        return text.to_string();
    }
    let mut out = String::with_capacity(text.len());
    let mut index = 0;
    while index < chars.len() {
        let end = index + needle.len();
        if end <= chars.len() && chars[index..end] == needle[..] && is_boundary(&chars, index) && is_boundary(&chars, end) {
            out.push_str(replacement);
            index = end;
        } else {
            out.push(chars[index]);
            index += 1;
        }
    }
    out
}

/// `re.sub(r"\b\d+\b", "NUMBER", text)`.
fn replace_numbers(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut index = 0;
    while index < chars.len() {
        if pyunicode::is_decimal(chars[index]) && is_boundary(&chars, index) {
            let mut end = index;
            while end < chars.len() && pyunicode::is_decimal(chars[end]) {
                end += 1;
            }
            if is_boundary(&chars, end) {
                out.push_str("NUMBER");
                index = end;
                continue;
            }
        }
        out.push(chars[index]);
        index += 1;
    }
    out
}

/// `component_skeleton(text, entity_values)`: the asserted facts without personal entity or amount substitutions.
pub fn component_skeleton(text: &str, entity_values: &[String]) -> String {
    let mut shaped = training_text_key(text);
    for entity in entity_values {
        shaped = replace_word_literal(&shaped, &training_text_key(entity), "ENTITY");
    }
    replace_numbers(&shaped)
}

/// `skeleton(text, entity)`: split entity values and numbers removed.
pub fn skeleton(text: &str, entity: &str) -> String {
    replace_numbers(&replace_word_literal(&training_text_key(text), &pyunicode::lower(entity), "ENTITY"))
}

struct ComponentRecord {
    id: String,
    split: String,
    text: String,
    skeleton: String,
    coarse_situation_id: String,
    coarse_description: String,
}

fn component(component: &Value, split: &str) -> Result<ComponentRecord> {
    let entities: Vec<String> = value::get(component, "entity_values")
        .and_then(value::as_array)
        .map(|items| items.iter().filter_map(value::as_str).map(str::to_string).collect())
        .unwrap_or_default();
    let fact = value::str_at(component, "fact")?;
    Ok(ComponentRecord {
        id: value::str_at(component, "component_id")?.to_string(),
        split: split.to_string(),
        text: fact.to_string(),
        skeleton: component_skeleton(fact, &entities),
        coarse_situation_id: value::str_at(component, "coarse_situation_id")?.to_string(),
        coarse_description: value::str_at(component, "coarse_situation_description")?.to_string(),
    })
}

fn component_records(resource: &Value) -> Result<Vec<ComponentRecord>> {
    let mut result = Vec::new();
    for family in value::array_at(resource, "families")? {
        let split = value::str_at(family, "split")?;
        result.push(component(family, split)?);
        result.push(component(value::require(family, "secondary")?, split)?);
    }
    for (split, families) in value::object_at(resource, "auxiliary")? {
        for family in value::as_array(families).map_or(&[][..], Vec::as_slice) {
            result.push(component(family, split)?);
        }
    }
    Ok(result)
}

/// `audit_components(resource)`: shared assertion components and coarser mechanisms stay in one split.
pub fn audit_components(resource: &Value) -> Result<Value> {
    let records = component_records(resource)?;
    let mut ids = BTreeSet::new();
    let mut inventories: [BTreeMap<String, String>; 4] = [BTreeMap::new(), BTreeMap::new(), BTreeMap::new(), BTreeMap::new()];
    for row in &records {
        if !ids.insert(row.id.clone()) || row.coarse_description.is_empty() {
            return invalid("Missing/duplicate assertion component lineage.");
        }
        let values = [row.text.clone(), training_text_key(&row.text), row.skeleton.clone(), row.coarse_situation_id.clone()];
        for (inventory, key) in inventories.iter_mut().zip(values) {
            if inventory.get(&key).is_some_and(|split| *split != row.split) {
                return invalid("Assertion component or coarse situation crosses permanent splits.");
            }
            inventory.insert(key, row.split.clone());
        }
    }
    Ok(value::object(vec![
        ("components", value::int(records.len() as i64)),
        ("unique_normalized_components", value::int(inventories[1].len() as i64)),
        ("unique_component_skeletons", value::int(inventories[2].len() as i64)),
        ("coarse_situation_groups", value::int(inventories[3].len() as i64)),
        ("cross_split_component_or_situation_overlaps", value::int(0)),
    ]))
}

fn count_of(counts: &BTreeMap<(String, String), usize>, split: &str, category: &str) -> usize {
    counts.get(&(split.to_string(), category.to_string())).copied().unwrap_or(0)
}

/// `validate_resource(resource)`: permanent allocation and explicit facts before any descendants exist.
pub fn validate_resource(resource: &Value) -> Result<()> {
    let rubric: Vec<String> = value::get(resource, "rubric_sources")
        .and_then(value::as_array)
        .map(|items| items.iter().filter_map(value::as_str).map(str::to_string).collect())
        .unwrap_or_default();
    if value::get(resource, "schema_version").and_then(value::as_i64) != Some(1)
        || value::get(resource, "generator_version").and_then(value::as_str) != Some(VERSION)
        || value::get(resource, "label_status").and_then(value::as_str) != Some("assistant_provisional")
        || rubric != RUBRIC_PATHS
    {
        return invalid("Unsupported resource/provenance contract.");
    }
    let split_set: BTreeSet<&str> = SPLITS.into_iter().collect();
    let keys = |key: &str| -> Result<BTreeSet<&str>> { Ok(value::object_at(resource, key)?.keys().map(String::as_str).collect()) };
    if keys("splits")? != split_set || keys("auxiliary")? != split_set {
        return invalid("All permanent splits are required.");
    }
    let mut seen_ids = BTreeSet::new();
    let mut predicates = BTreeSet::new();
    let mut templates: BTreeMap<String, &str> = BTreeMap::new();
    let mut entities: BTreeMap<String, &str> = BTreeMap::new();
    let mut counts: BTreeMap<(String, String), usize> = BTreeMap::new();
    let audiences: BTreeSet<&str> = visibility_names().collect();
    for split in SPLITS {
        let config = value::require(value::require(resource, "splits")?, split)?;
        let variants = value::array_at(config, "variants")?;
        let controls = value::array_at(config, "controls")?;
        let audience = value::object_at(config, "audience")?;
        let split_entities = value::array_at(config, "entities")?;
        let unique_entities: BTreeSet<&str> = split_entities.iter().filter_map(value::as_str).collect();
        if variants.len() != 4
            || controls.len() != 4
            || audience.keys().map(String::as_str).collect::<BTreeSet<_>>() != audiences
            || split_entities.len() != 24
            || unique_entities.len() != 24
        {
            return invalid("Incomplete split framing/entity allocation.");
        }
        for item in variants.iter().chain(controls).chain(audience.values()) {
            let key = training_text_key(value::as_str(item).unwrap_or_default());
            if templates.get(&key).is_some_and(|existing| *existing != split) {
                return invalid("Narrative template crosses permanent splits.");
            }
            templates.insert(key, split);
        }
        for item in split_entities {
            let key = training_text_key(value::as_str(item).unwrap_or_default());
            if entities.contains_key(&key) {
                return invalid("Entity vocabulary crosses permanent splits.");
            }
            entities.insert(key, split);
        }
        let auxiliary = value::as_array(value::require(value::require(resource, "auxiliary")?, split)?).map_or(0, Vec::len);
        if auxiliary != if split == "train" { 20 } else { 5 } {
            return invalid("Auxiliary family denominator differs.");
        }
    }
    let categories: BTreeSet<&str> = category_names().collect();
    for family in value::array_at(resource, "families")? {
        let split = value::str_at(family, "split")?;
        let primary = value::str_at(family, "primary_category")?;
        if !SPLITS.contains(&split) || !categories.contains(primary) {
            return invalid("Unsupported permanent family allocation.");
        }
        let family_categories = string_list(value::require(family, "categories")?)?;
        classification::target(value::str_at(family, "sensitivity")?, "PU", &family_categories)?;
        let has_rationale = value::get(family, "label_rationale").is_some_and(classification::is_truthy);
        if !family_categories.iter().any(|name| name == primary) || !has_rationale {
            return invalid("Family lacks explicit target closure/rationale.");
        }
        if value::get(family, "subject_relationship").and_then(value::as_str) == Some("other_child")
            && !family_categories.iter().any(|name| name == "THIRD_PARTY")
        {
            return invalid("Minor disclosure must retain third-party closure.");
        }
        if value::get(family, "asserted_other_health") == Some(&Value::Bool(true)) && !family_categories.iter().any(|name| name == "HEALTH")
        {
            return invalid("Third-party health predicate loses its health category.");
        }
        let secondary = value::require(family, "secondary")?;
        let secondary_categories = string_list(value::require(secondary, "categories")?)?;
        classification::target(value::str_at(secondary, "sensitivity")?, "PU", &secondary_categories)?;
        if value::str_at(secondary, "split")? != split || !value::get(secondary, "label_rationale").is_some_and(classification::is_truthy) {
            return invalid("Secondary assertion loses split/target rationale.");
        }
        let relationship = value::get(secondary, "subject_relationship").and_then(value::as_str);
        if matches!(relationship, Some("other_child" | "other_adult")) && !secondary_categories.iter().any(|name| name == "THIRD_PARTY") {
            return invalid("Secondary assertion loses its explicit third-party category.");
        }
        *counts.entry((split.to_string(), primary.to_string())).or_default() += 1;
    }
    for split in SPLITS {
        let mut group: Vec<&Value> = value::array_at(resource, "families")?
            .iter()
            .filter(|family| value::get(family, "split").and_then(value::as_str) == Some(split))
            .collect();
        if let Some(extra) = value::as_array(value::require(value::require(resource, "auxiliary")?, split)?) {
            group.extend(extra.iter());
        }
        for family in group {
            let identifier = value::str_at(family, "family_id")?;
            let predicate = training_text_key(value::str_at(family, "fact")?);
            if !identifier.starts_with(&format!("PH3/{split}/"))
                || seen_ids.contains(identifier)
                || predicate.is_empty()
                || predicates.contains(&predicate)
                || !value::get(family, "topic").is_some_and(classification::is_truthy)
            {
                return invalid("Duplicate or inconsistent scenario family.");
            }
            let fact = value::str_at(family, "fact")?;
            if fact.contains('{') || fact.contains('}') {
                return invalid("Fact predicates must be rendered literal assertions.");
            }
            seen_ids.insert(identifier.to_string());
            predicates.insert(predicate);
        }
        let quota = if split == "train" { 12 } else { 3 };
        if category_names().any(|category| count_of(&counts, split, category) != quota) {
            return invalid("Per-category family quotas differ.");
        }
    }
    let exclusions = value::get(resource, "ambiguous_exclusions").and_then(value::as_array);
    if !exclusions.is_some_and(|items| {
        !items.is_empty() && items.iter().all(|item| value::get(item, "reason").is_some_and(classification::is_truthy))
    }) {
        return invalid("Predeclared ambiguity exclusions are required.");
    }
    audit_components(resource)?;
    Ok(())
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

/// `_row(resource, family, split, visibility, variant, actual, auxiliary)`.
pub fn row(
    resource: &Value,
    family: &Value,
    split: &str,
    visibility: &str,
    variant: usize,
    actual: bool,
    auxiliary: bool,
) -> Result<Value> {
    let config = value::require(value::require(resource, "splits")?, split)?;
    let visibility_index =
        visibility_names().position(|name| name == visibility).ok_or_else(|| Error::Invalid("unknown visibility".to_string()))?;
    let entity = value::as_str(
        value::array_at(config, "entities")?
            .get(visibility_index * 4 + variant)
            .ok_or_else(|| Error::Invalid("entity index out of range".to_string()))?,
    )
    .ok_or_else(|| Error::Invalid("entities must be strings".to_string()))?;
    let mut categories: Vec<String> =
        if actual { value::get(family, "categories").map(string_list).transpose()?.unwrap_or_default() } else { Vec::new() };
    let mut severity: String = if actual {
        if auxiliary { "S1".to_string() } else { value::str_at(family, "sensitivity")?.to_string() }
    } else {
        "S0".to_string()
    };
    let mut fact = value::str_at(family, "fact")?.to_string();
    let mut additional_rationale = String::new();
    let family_id = value::str_at(family, "family_id")?;
    let family_slot: usize = family_id
        .rsplit('/')
        .next()
        .and_then(|slot| slot.parse().ok())
        .ok_or_else(|| Error::Invalid("family id has no numeric slot".to_string()))?;
    let multilabel_slot = (variant + visibility_index + family_slot) % 4 >= 2;
    let secondary_component = if actual && !auxiliary && multilabel_slot { Some(value::require(family, "secondary")?) } else { None };
    if let Some(secondary) = secondary_component {
        fact.push_str("; ");
        fact.push_str(value::str_at(secondary, "fact")?);
        let mut merged: BTreeSet<String> = categories.into_iter().collect();
        merged.extend(string_list(value::require(secondary, "categories")?)?);
        categories = merged.into_iter().collect();
        let secondary_severity = value::str_at(secondary, "sensitivity")?;
        if classification::sensitivity_value(secondary_severity)? > classification::sensitivity_value(&severity)? {
            severity = secondary_severity.to_string();
        }
        additional_rationale = value::str_at(secondary, "label_rationale")?.to_string();
    }
    let classification = classification::target(&severity, visibility, &categories)?;
    let template = value::as_str(
        value::array_at(config, if actual { "variants" } else { "controls" })?
            .get(variant)
            .ok_or_else(|| Error::Invalid("template index out of range".to_string()))?,
    )
    .ok_or_else(|| Error::Invalid("templates must be strings".to_string()))?;
    let topic = value::str_at(family, "topic")?;
    let mut fields = BTreeMap::new();
    fields.insert("fact", fact.as_str());
    fields.insert("topic", topic);
    let body = format_named(template, &fields)?;
    let audience_template = value::str_at(value::require(config, "audience")?, visibility)?;
    let mut entity_fields = BTreeMap::new();
    entity_fields.insert("entity", entity);
    let audience = format_named(audience_template, &entity_fields)?;
    let text = format!("{body} {audience}");
    let identifier = format!("{family_id}/{visibility}/{variant}/{}", i32::from(actual));
    let control = if actual && auxiliary {
        "mild_personal"
    } else if actual {
        "actual_disclosure"
    } else {
        match ["generic_instruction", "unfilled_form", "invented_scene", "absent_record"].get(variant) {
            Some(name) => name,
            None => return invalid("tuple index out of range"),
        }
    };
    let allowed: Vec<&str> = if severity == "S0" || severity == "S1" { vec!["ALLOW"] } else { vec!["WARN", "BLOCK"] };
    let label_status = value::str_at(resource, "label_status")?;
    let rubric = value::require(resource, "rubric")?;
    let packed = i64::from(classification.pack());
    let family_components = {
        let mut ids = vec![value::str_at(family, "component_id")?.to_string()];
        if let Some(secondary) = secondary_component {
            ids.push(value::str_at(secondary, "component_id")?.to_string());
        }
        ids
    };
    let asserted: Vec<String> = if actual {
        let mut ids = vec![value::str_at(family, "component_id")?.to_string()];
        if !auxiliary && multilabel_slot {
            ids.push(value::str_at(value::require(family, "secondary")?, "component_id")?.to_string());
        }
        ids
    } else {
        Vec::new()
    };
    let category_rationale = if actual {
        py_strip(&format!("{} {}", value::str_at(family, "label_rationale")?, additional_rationale)).to_string()
    } else {
        "No actual personal disclosure is asserted; domain mention alone is not disclosure.".to_string()
    };
    let primary = value::get(family, "primary_category").and_then(value::as_str).unwrap_or("NONE");
    let metadata = value::object(vec![
        ("example_id", value::string(&identifier)),
        ("group_id", value::string(family_id)),
        ("family_id", value::string(family_id)),
        ("parent_id", value::string(family_id)),
        ("split", value::string(split)),
        ("primary_category", value::string(primary)),
        ("training_role", value::string("authored_privacy_fact_contrast")),
        ("control", value::string(control)),
        ("generator", value::string(VERSION)),
        ("generation_seed", value::string("13102026")),
        ("variant", value::string(&variant.to_string())),
        ("label_status", value::string(label_status)),
        ("entity_pool_id", value::string(&format!("PH3/{split}/audience_titles"))),
        ("entity_value", value::string(entity)),
        ("template_id", value::string(&format!("PH3/{split}/variant/{variant}/{}", i32::from(actual)))),
        ("sensitivity_rationale", value::string(value::str_at(rubric, &severity)?)),
        ("visibility_evidence", value::string(&audience)),
        ("visibility_rationale", value::string(value::str_at(rubric, "visibility")?)),
        ("category_rationale", value::string(&category_rationale)),
        (
            "control_rationale",
            value::string(if actual {
                "Explicitly asserted actual personal fact."
            } else {
                "The text explicitly removes actual personal records, persons or completed details."
            }),
        ),
        ("scenario_predicate", value::string(value::str_at(family, "fact")?)),
        ("auxiliary", value::string(if auxiliary { "true" } else { "false" })),
        ("subject_relationship", value::string(value::get(family, "subject_relationship").and_then(value::as_str).unwrap_or("self"))),
        ("component_ids", value::string(&value::dumps(&value::strings(&family_components))?)),
        ("asserted_component_ids", value::string(&value::dumps(&value::strings(&asserted))?)),
        ("coarse_situation_id", value::string(value::str_at(family, "coarse_situation_id")?)),
        ("coarse_situation_description", value::string(value::str_at(family, "coarse_situation_description")?)),
        ("template_group_id", value::string(value::str_at(family, "template_group_id")?)),
        ("source_resource", value::string(value::str_at(resource, "resource_id")?)),
    ]);
    Ok(value::object(vec![
        ("id", value::string(&identifier)),
        ("case_id", value::string(&identifier)),
        ("group_id", value::string(family_id)),
        ("family_id", value::string(family_id)),
        ("text", value::string(&text)),
        ("partition", value::string(if split == "eval" { "fresh_eval" } else { split })),
        ("classification", classification.to_value()?),
        ("packed_classification", value::int(packed)),
        ("packed", value::int(packed)),
        ("required_sensitive", Value::Bool(classification.is_sensitive())),
        ("allowed_actions", value::strings(&allowed)),
        ("expected_action", if allowed.len() == 1 { value::string(allowed[0]) } else { Value::Null }),
        ("minimum_action", value::string(allowed[0])),
        ("ambiguous", Value::Bool(false)),
        ("context_truth_eligible", Value::Bool(true)),
        ("action_accuracy_eligible", Value::Bool(true)),
        ("label_status", value::string(label_status)),
        ("metadata", metadata),
    ]))
}

/// `build(resource)`: unique original rows in fixed source order, with no replacement, per split.
pub fn build(resource: &Value) -> Result<BTreeMap<String, Vec<Value>>> {
    validate_resource(resource)?;
    let mut pools: BTreeMap<String, Vec<Value>> = SPLITS.iter().map(|split| (split.to_string(), Vec::new())).collect();
    for family in value::array_at(resource, "families")? {
        let split = value::str_at(family, "split")?;
        for visibility in visibility_names() {
            for variant in 0..4 {
                for actual in [false, true] {
                    pools.entry(split.to_string()).or_default().push(row(resource, family, split, visibility, variant, actual, false)?);
                }
            }
        }
    }
    for split in SPLITS {
        for family in value::array_at(value::require(resource, "auxiliary")?, split)? {
            for visibility in visibility_names() {
                for variant in 0..4 {
                    pools.entry(split.to_string()).or_default().push(row(resource, family, split, visibility, variant, variant < 3, true)?);
                }
            }
        }
    }
    audit(&pools, resource)?;
    Ok(pools)
}

/// `audit(pools, resource)`: fail closed on conflicting targets, duplicate rows and family leakage.
pub fn audit(pools: &BTreeMap<String, Vec<Value>>, resource: &Value) -> Result<Value> {
    validate_resource(resource)?;
    let mut ids = BTreeSet::new();
    let mut texts = BTreeSet::new();
    let mut skeletons: BTreeMap<String, &str> = BTreeMap::new();
    let mut groups: BTreeMap<String, &str> = BTreeMap::new();
    let mut parent_splits: BTreeMap<String, &str> = BTreeMap::new();
    let mut summary: BTreeMap<String, Value> = BTreeMap::new();
    let mut family_map: BTreeMap<String, &Value> = BTreeMap::new();
    for family in value::array_at(resource, "families")? {
        family_map.insert(value::str_at(family, "family_id")?.to_string(), family);
    }
    for families in value::object_at(resource, "auxiliary")?.values() {
        for family in value::as_array(families).map_or(&[][..], Vec::as_slice) {
            family_map.insert(value::str_at(family, "family_id")?.to_string(), family);
        }
    }
    for split in SPLITS {
        let rows = pools.get(split).map_or(&[][..], Vec::as_slice);
        let expected_rows = COUNTS.iter().find(|(name, _)| *name == split).map_or(0, |(_, count)| *count);
        if rows.len() != expected_rows {
            return invalid("Unique original row budget differs.");
        }
        let mut sensitivity: BTreeMap<String, i64> = BTreeMap::new();
        let mut visibility: BTreeMap<String, i64> = BTreeMap::new();
        let mut categories: BTreeMap<String, i64> = BTreeMap::new();
        let mut control: BTreeMap<String, i64> = BTreeMap::new();
        let mut cardinality: BTreeMap<String, i64> = BTreeMap::new();
        let mut combinations: BTreeSet<Vec<String>> = BTreeSet::new();
        for item in rows {
            let classification_value = value::require(item, "classification")?;
            let keys: BTreeSet<&str> =
                value::as_object(classification_value).map(|map| map.keys().map(String::as_str).collect()).unwrap_or_default();
            if keys != ["sensitivity", "visibility", "categories"].into_iter().collect() {
                return invalid("Every row needs an explicit complete target.");
            }
            let expected = target_from_value(classification_value)?;
            if expected.to_value()? != *classification_value
                || value::get(item, "packed_classification").and_then(value::as_i64) != Some(i64::from(expected.pack()))
            {
                return invalid("Named and packed target differ.");
            }
            let meta = value::require(item, "metadata")?;
            if value::str_at(meta, "split")? != split || value::str_at(item, "group_id")? != value::str_at(meta, "group_id")? {
                return invalid("Row partition/group disagrees with lineage.");
            }
            let family_id = value::str_at(item, "family_id")?;
            let Some(family) = family_map.get(family_id) else {
                return invalid("Row has no admitted scenario parent.");
            };
            let is_auxiliary = value::str_at(meta, "auxiliary")? == "true";
            let variant: usize =
                value::str_at(meta, "variant")?.parse().map_err(|_| Error::Invalid("variant must be an integer".to_string()))?;
            let actual = matches!(value::str_at(meta, "control")?, "mild_personal" | "actual_disclosure");
            let visibility_name = value::str_at(classification_value, "visibility")?;
            if *item != row(resource, family, split, visibility_name, variant, actual, is_auxiliary)? {
                return invalid("Actual row differs from declared fact-preserving rendering.");
            }
            if value::get(item, "visibility_hint").is_some_and(classification::is_truthy)
                || value::get(item, "context_truth_eligible").is_none_or(|flag| !classification::is_truthy(flag))
                || value::get(item, "ambiguous").is_some_and(classification::is_truthy)
            {
                return invalid("Primary admission cannot add hints or ambiguous truth.");
            }
            let text = value::str_at(item, "text")?;
            let key = training_text_key(text);
            let identifier = value::str_at(item, "id")?;
            if key.is_empty() || texts.contains(&key) || ids.contains(identifier) || text.contains('{') || text.contains('}') {
                return invalid("Empty, duplicate or unrendered row.");
            }
            for (identity, inventory) in [(family_id, &mut groups), (value::str_at(meta, "parent_id")?, &mut parent_splits)] {
                if inventory.get(identity).is_some_and(|existing| *existing != split) {
                    return invalid("Scenario lineage crosses permanent splits.");
                }
                inventory.insert(identity.to_string(), split);
            }
            let shaped = skeleton(text, value::str_at(meta, "entity_value")?);
            if skeletons.get(&shaped).is_some_and(|existing| *existing != split) {
                return invalid("Entity/number-only template crosses splits.");
            }
            skeletons.insert(shaped, split);
            ids.insert(identifier.to_string());
            texts.insert(key);
            *sensitivity.entry(expected.sensitivity().to_string()).or_default() += 1;
            *visibility.entry(visibility_name.to_string()).or_default() += 1;
            for category in expected.categories() {
                *categories.entry(category.to_string()).or_default() += 1;
            }
            *cardinality.entry(expected.categories().len().to_string()).or_default() += 1;
            *control.entry(value::str_at(meta, "control")?.to_string()).or_default() += 1;
            if !expected.categories().is_empty() {
                combinations.insert(expected.categories().iter().map(|name| name.to_string()).collect());
            }
        }
        let expected_auxiliary = if split == "train" { 360 } else { 90 };
        if sensitivity.get("S1").copied().unwrap_or(0) != expected_auxiliary {
            return invalid("Mild-personal supervision quota differs.");
        }
        if visibility_names().any(|name| visibility.get(name).copied().unwrap_or(0) != (expected_rows / 6) as i64) {
            return invalid("Meaningful visibility strata must remain balanced.");
        }
        if category_names().any(|name| categories.get(name).copied().unwrap_or(0) == 0) {
            return invalid("Every category requires positive examples.");
        }
        if combinations.len() < 15 {
            return invalid("Insufficient valid full category-set combinations.");
        }
        let families: BTreeSet<&str> = rows.iter().map(|item| value::str_at(item, "family_id")).collect::<Result<_>>()?;
        let counter =
            |map: &BTreeMap<String, i64>| Value::Object(map.iter().map(|(key, count)| (key.clone(), value::int(*count))).collect());
        summary.insert(
            split.to_string(),
            value::object(vec![
                ("rows", value::int(rows.len() as i64)),
                ("families", value::int(families.len() as i64)),
                ("category_set_combinations", value::int(combinations.len() as i64)),
                ("sensitivity", counter(&sensitivity)),
                ("visibility", counter(&visibility)),
                ("categories", counter(&categories)),
                ("control", counter(&control)),
                ("cardinality", counter(&cardinality)),
            ]),
        );
    }
    Ok(Value::Object(summary))
}

/// `fuzzer_training_examples(dataset_path, count, seed)`: only the released TRAIN JSONL, in a seeded order.
pub fn fuzzer_training_examples(dataset_path: &Path, count: i64, seed: u64) -> Result<Vec<Example>> {
    let payload = read_file(dataset_path)?;
    let text = String::from_utf8(payload).map_err(|_| Error::Invalid("TRAIN release is not valid UTF-8".to_string()))?;
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        let row = privoke_contracts::json::parse(line)?;
        let value = value::get(&row, "classification");
        let keys: BTreeSet<&str> = value.and_then(value::as_object).map(|map| map.keys().map(String::as_str).collect()).unwrap_or_default();
        let (Some(value), true) = (value, keys == ["sensitivity", "visibility", "categories"].into_iter().collect::<BTreeSet<_>>()) else {
            return invalid("TRAIN fitting requires explicit complete named targets before PromptSeed loading.");
        };
        let expected: Classification = target_from_value(value)?;
        let packed = i64::from(expected.pack());
        if expected.to_value()? != *value
            || value::get(&row, "packed").and_then(value::as_i64) != Some(packed)
            || value::get(&row, "packed_classification").and_then(value::as_i64) != Some(packed)
        {
            return invalid("TRAIN fitting named/packed classification mismatch.");
        }
    }
    let mut seeds = load_prompt_dataset(Some(dataset_path))?;
    if seeds.iter().any(|item| item.metadata.get("split").map(String::as_str) != Some("train")) {
        return invalid("Fuzzer fitting accepts only the permanent TRAIN release.");
    }
    if count <= 0 || count as usize > seeds.len() {
        return invalid("Requested unique rows exhaust the admitted TRAIN pool.");
    }
    let keys: Vec<String> = seeds.iter().map(|item| training_text_key(&item.template)).collect();
    if keys.iter().collect::<BTreeSet<_>>().len() != keys.len() {
        return invalid("TRAIN release contains duplicate texts.");
    }
    Random::new(seed).shuffle(&mut seeds);
    Ok(seeds.into_iter().take(count as usize).map(|item| Example::new(item.template, item.classification, 1.0, item.metadata)).collect())
}
