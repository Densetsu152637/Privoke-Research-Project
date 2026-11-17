//! `prompt_generation.presence`: strict binary annotation-presence curriculum loading and partitioning.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use crate::error::{Result, invalid};
use crate::prompt_seed::load_json_records;
use crate::pyrandom::Random;
use crate::text::training_text_key;
use crate::value::{self, Value};

/// `PresenceExample`.
#[derive(Debug, Clone, PartialEq)]
pub struct PresenceExample {
    /// `text`.
    pub text: String,
    /// `sensitive`.
    pub sensitive: bool,
    /// `example_id`.
    pub example_id: String,
    /// `group_id`.
    pub group_id: String,
    /// `weight`.
    pub weight: f64,
}

fn nonblank<'a>(row: &'a Value, key: &str, message: &str) -> Result<&'a str> {
    match value::get(row, key).and_then(value::as_str) {
        Some(text) if !text.trim_matches(privoke_rules::pyunicode::is_space).is_empty() => Ok(text),
        _ => invalid(message),
    }
}

/// `load_presence_dataset(path)`: JSONL rows without converting binary labels into contextual grades.
pub fn load_presence_dataset(path: &Path) -> Result<Vec<PresenceExample>> {
    let rows = load_json_records(
        path,
        &["examples", "data"],
        "Presence dataset does not exist",
        "Presence dataset must be a JSON array or JSONL file.",
    )?;
    let mut examples = Vec::new();
    let mut ids = BTreeSet::new();
    let mut normalized: BTreeMap<String, bool> = BTreeMap::new();
    for row in &rows {
        if !value::is_object(row) {
            return invalid("Presence dataset entries must be objects.");
        }
        let strip = |text: &str| text.trim_matches(privoke_rules::pyunicode::is_space).to_string();
        let example_id = strip(nonblank(row, "id", "Presence dataset entries need a nonempty string id.")?);
        if ids.contains(&example_id) {
            return invalid("Presence dataset ids must be unique.");
        }
        let text = nonblank(row, "text", "Presence dataset entries need nonempty text.")?;
        let Some(Value::Bool(sensitive)) = value::get(row, "sensitive") else {
            return invalid("Presence dataset sensitive labels must be strict booleans.");
        };
        let group_id = strip(nonblank(row, "group_id", "Presence dataset entries need a nonempty group_id.")?);
        let key = training_text_key(text);
        if key.is_empty() {
            return invalid("Presence dataset text must remain nonempty after normalization.");
        }
        if normalized.get(&key).is_some_and(|label| label != sensitive) {
            return invalid("Normalized presence text has conflicting binary labels.");
        }
        normalized.insert(key, *sensitive);
        ids.insert(example_id.clone());
        examples.push(PresenceExample { text: text.to_string(), sensitive: *sensitive, example_id, group_id, weight: 1.0 });
    }
    Ok(examples)
}

/// `generate_presence_training_partition(count, heldout_count, seed, dataset_path)`: disjoint normalised texts and
/// source groups, retaining both strata. Returns the training rows and the held-out rows.
pub fn generate_presence_training_partition(
    count: i64,
    heldout_count: i64,
    seed: u64,
    dataset_path: &Path,
) -> Result<(Vec<PresenceExample>, Vec<PresenceExample>)> {
    if count < 2 || heldout_count < 2 {
        return invalid("Presence training requires at least two training and two held-out examples.");
    }
    let rows = load_presence_dataset(dataset_path)?;
    let mut by_label: [Vec<PresenceExample>; 2] = [Vec::new(), Vec::new()];
    for row in rows {
        by_label[usize::from(row.sensitive)].push(row);
    }
    if by_label.iter().any(|items| items.len() < 2) {
        return invalid("Presence dataset needs at least two examples in each binary stratum.");
    }
    let mut rng = Random::new(seed);
    for items in &mut by_label {
        rng.shuffle(items);
    }
    let mut heldout: Vec<PresenceExample> = Vec::new();
    let mut heldout_groups: BTreeSet<String> = BTreeSet::new();
    let mut heldout_texts: BTreeSet<String> = BTreeSet::new();
    let mut cursors = [0usize; 2];
    // Alternate labels first so held-out data always contains both strata.
    for index in 0..heldout_count {
        let label = (index % 2) as usize;
        let mut chosen = None;
        while cursors[label] < by_label[label].len() {
            let row = &by_label[label][cursors[label]];
            cursors[label] += 1;
            if !heldout_groups.contains(&row.group_id) && !heldout_texts.contains(&training_text_key(&row.text)) {
                chosen = Some(row.clone());
                break;
            }
        }
        let Some(chosen) = chosen else {
            return invalid("Presence dataset cannot supply enough distinct held-out examples or source groups.");
        };
        heldout_groups.insert(chosen.group_id.clone());
        heldout_texts.insert(training_text_key(&chosen.text));
        heldout.push(chosen);
    }
    let mut remaining: Vec<PresenceExample> = by_label
        .iter()
        .flatten()
        .filter(|row| !heldout_groups.contains(&row.group_id) && !heldout_texts.contains(&training_text_key(&row.text)))
        .cloned()
        .collect();
    rng.shuffle(&mut remaining);
    let count = count as usize;
    let mut selected: Vec<PresenceExample> = Vec::new();
    let mut seen_texts = heldout_texts.clone();
    for label in [false, true] {
        let Some(first) = remaining.iter().find(|row| row.sensitive == label) else {
            return invalid("Presence dataset cannot supply training examples across both strata.");
        };
        seen_texts.insert(training_text_key(&first.text));
        selected.push(first.clone());
    }
    for row in &remaining {
        if selected.len() == count {
            break;
        }
        if selected.contains(row) {
            continue;
        }
        let key = training_text_key(&row.text);
        if seen_texts.contains(&key) {
            continue;
        }
        selected.push(row.clone());
        seen_texts.insert(key);
        if selected.len() == count {
            break;
        }
    }
    let labels: BTreeSet<bool> = selected.iter().map(|row| row.sensitive).collect();
    if selected.len() != count || labels.len() != 2 {
        return invalid("Presence dataset cannot supply the requested training examples across both strata and disjoint groups.");
    }
    Ok((selected, heldout))
}
