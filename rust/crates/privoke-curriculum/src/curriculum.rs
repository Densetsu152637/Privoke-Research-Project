//! `prompt_generation.curriculum`: the immutable synthetic curriculum and its durable, idempotent batch allocation.
//!
//! Held-out families never enter training or replay. The cursor advances when a request is reserved, including
//! candidates the publication gate later rejects. Retries reuse that reservation.
//!
//! The durable state (SQLite in the Python service) is the [`CursorState`] trait: the fuzzer service of stage 21
//! implements it over its database, while [`MemoryState`] serves tests. Reads and writes of one reservation are
//! staged and applied only when the reservation succeeds, as the Python transaction rolls back on error.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path};

use prost::Message;

use crate::classification;
use crate::error::{Error, Result, invalid, read_file};
use crate::prompt_seed::{first_value, string_metadata};
use crate::pyrandom::Random;
use crate::text::training_text_key;
use crate::types::Example;
use crate::value::{self, Value};

/// Curriculum roles of TRAIN rows.
pub const ROLES: [&str; 3] = ["grammar", "teacher", "evolved"];
/// Sampler policies.
pub const SAMPLER_POLICIES: [&str; 2] = ["deterministic_v1", "seeded_family_v1"];

/// `Curriculum`.
#[derive(Debug, Clone, PartialEq)]
pub struct Curriculum {
    /// `curriculum_id`.
    pub curriculum_id: String,
    /// SHA-256 of the manifest bytes.
    pub manifest_sha256: String,
    /// The rows of `train`, `replay` and `heldout`, in file order.
    pub splits: BTreeMap<String, Vec<Value>>,
}

/// `CurriculumBatch`.
#[derive(Debug, Clone, PartialEq)]
pub struct CurriculumBatch {
    /// New training examples.
    pub examples: Vec<Example>,
    /// Replay anchors.
    pub replay: Vec<Example>,
    /// The fixed gate rows.
    pub heldout: Vec<Example>,
    /// The audit metadata.
    pub audit: BTreeMap<String, String>,
}

fn is_sensitive(row: &Value) -> Result<bool> {
    let label = value::require(row, "classification")?;
    Ok(value::str_at(label, "sensitivity")? != "S0" || !value::array_at(label, "categories")?.is_empty())
}

/// `_example(row)`: only the validated contextual target is authoritative.
pub fn example(row: &Value) -> Result<Example> {
    let mut item = value::Object::new();
    item.insert("text".to_string(), value::require(row, "text")?.clone());
    item.insert("classification".to_string(), value::require(row, "classification")?.clone());
    item.insert("metadata".to_string(), value::require(row, "metadata")?.clone());
    let item = Value::Object(item);
    let text = match first_value(&item, &["text", "prompt", "input"]).and_then(value::as_str) {
        Some(text) if !text.is_empty() => text.to_string(),
        _ => return invalid("Each training example needs a non-empty text/prompt/input field."),
    };
    Ok(Example {
        text,
        target: classification::from_mapping(&item)?,
        weight: 1.0,
        metadata: string_metadata(value::get(&item, "metadata")),
    })
}

/// `load_curriculum(manifest_path)`: validate content hashes, explicit targets and separation before sampling.
pub fn load_curriculum(manifest_path: &Path) -> Result<Curriculum> {
    let io_error = |error: std::io::Error| Error::Io { path: manifest_path.display().to_string(), reason: error.to_string() };
    let path = std::fs::canonicalize(manifest_path).map_err(io_error)?;
    let payload = read_file(&path)?;
    let manifest = value::parse_bytes(&payload)?;
    if value::get(&manifest, "schema_version").and_then(value::as_i64) != Some(1)
        || !value::get(&manifest, "curriculum_id").is_some_and(classification::is_truthy)
    {
        return invalid("Curriculum requires schema_version=1 and curriculum_id.");
    }
    let parent = path.parent().unwrap_or(Path::new("."));
    let sensitivities = ["S0", "S1", "S2", "S3"];
    let mut splits: BTreeMap<String, Vec<Value>> = BTreeMap::new();
    let mut seen_ids = BTreeSet::new();
    let mut seen_texts = BTreeSet::new();
    let mut split_groups: BTreeSet<String> = BTreeSet::new();
    for split in ["train", "replay", "heldout"] {
        let entry = value::require(value::require(&manifest, "splits")?, split)?;
        let relative = Path::new(value::str_at(entry, "path")?);
        let target = std::fs::canonicalize(parent.join(relative)).map_err(io_error)?;
        if relative.is_absolute() || relative.components().any(|component| component == Component::ParentDir) || !target.starts_with(parent)
        {
            return invalid("Curriculum split paths must remain inside its directory.");
        }
        let data = read_file(&target)?;
        if value::sha256(&data) != value::str_at(entry, "sha256")? {
            return invalid(format!("Curriculum {split} hash does not match its manifest."));
        }
        let text = String::from_utf8(data).map_err(|_| Error::Invalid("curriculum split is not valid UTF-8".to_string()))?;
        let mut rows = Vec::new();
        for line in text.lines().filter(|line| !line.trim().is_empty()) {
            rows.push(privoke_contracts::json::parse(line)?);
        }
        if rows.is_empty() || rows.len() > 100_000 {
            return invalid("Curriculum split must contain between 1 and 100000 rows.");
        }
        let mut groups: BTreeSet<String> = BTreeSet::new();
        for row in &rows {
            let empty = value::object(Vec::<(String, Value)>::new());
            let label = value::get(row, "classification").unwrap_or(&empty);
            let metadata = value::get(row, "metadata").unwrap_or(&empty);
            let categories = value::get(label, "categories").and_then(value::as_array);
            let label_ok = value::get(label, "sensitivity").and_then(value::as_str).is_some_and(|name| sensitivities.contains(&name))
                && value::get(label, "visibility").and_then(value::as_str).is_some_and(classification::is_visibility)
                && categories.is_some_and(|items| items.iter().all(|item| value::as_str(item).is_some_and(classification::is_category)));
            if !label_ok {
                return invalid("Curriculum rows require explicit valid contextual targets.");
            }
            let group = value::get(metadata, "group_id").filter(|group| classification::is_truthy(group));
            let provenance_ok = value::get(metadata, "label_status").and_then(value::as_str) == Some("assistant_provisional")
                && group.is_some()
                && value::get(metadata, "parent_id").and_then(value::as_str).is_some()
                && value::get(metadata, "generator").is_some_and(classification::is_truthy);
            if !provenance_ok {
                return invalid("Curriculum rows require provisional provenance and parent families.");
            }
            let role = value::get(metadata, "curriculum_role").and_then(value::as_str);
            if split == "train" && !role.is_some_and(|role| ROLES.contains(&role)) {
                return invalid("Training rows require grammar, teacher or evolved roles.");
            }
            if split == "replay" && role != Some("replay") {
                return invalid("Replay rows require the replay role.");
            }
            let candidate = example(row)?;
            let row_id = value::get(row, "id").and_then(value::as_str);
            let Some(row_id) = row_id.filter(|id| !id.is_empty() && !seen_ids.contains(*id)) else {
                return invalid("Curriculum IDs must be unique non-empty strings.");
            };
            let key = training_text_key(&candidate.text);
            if seen_texts.contains(&key) {
                return invalid("Curriculum canonical texts must be globally unique.");
            }
            seen_ids.insert(row_id.to_string());
            seen_texts.insert(key);
            groups.insert(classification::py_str(group.unwrap_or(&Value::Null)));
        }
        if groups.intersection(&split_groups).next().is_some() {
            return invalid("Curriculum parent families overlap between splits.");
        }
        split_groups.extend(groups);
        let mut labels = BTreeSet::new();
        for row in &rows {
            labels.insert(is_sensitive(row)?);
        }
        if labels.len() != 2 {
            return invalid("Every curriculum split must contain both classes.");
        }
        splits.insert(split.to_string(), rows);
    }
    for rows in splits.values() {
        let by_id: BTreeMap<&str, &Value> =
            rows.iter().filter_map(|row| value::get(row, "id").and_then(value::as_str).map(|id| (id, row))).collect();
        for row in rows {
            let metadata = value::require(row, "metadata")?;
            let parent_id = value::str_at(metadata, "parent_id")?;
            if !parent_id.is_empty() {
                let same_family = by_id.get(parent_id).is_some_and(|parent| {
                    value::get(parent, "metadata").and_then(|meta| value::get(meta, "group_id")) == value::get(metadata, "group_id")
                });
                if !same_family {
                    return invalid("Curriculum descendants must reference a parent in the same split and family.");
                }
            }
        }
    }
    if splits["heldout"].len() != 16 || splits["replay"].len() < 64 {
        return invalid("Curriculum requires exactly 16 fixed gate rows and at least 64 replay anchors.");
    }
    let curriculum_id = classification::py_str(value::require(&manifest, "curriculum_id")?);
    Ok(Curriculum { curriculum_id, manifest_sha256: value::sha256(&payload), splits })
}

/// `request_fingerprint(request, curriculum, settings)`.
pub fn request_fingerprint(
    request: &privoke_contracts::proto::v1::FuzzerTrainingRequest,
    curriculum: &Curriculum,
    settings: &Value,
) -> Result<String> {
    let mut data = b"synthetic-curriculum:v1\0".to_vec();
    data.extend_from_slice(curriculum.manifest_sha256.as_bytes());
    data.push(0);
    let settings = match settings {
        Value::Object(map) if map.is_empty() => value::object(Vec::<(String, Value)>::new()),
        other => other.clone(),
    };
    data.extend_from_slice(value::dumps_compact(&settings)?.as_bytes());
    data.push(0);
    data.extend_from_slice(&request.encode_to_vec());
    Ok(value::sha256(&data))
}

/// `sampler_settings(request)`: the sampler seed stays stable while the trainer's cycle seed changes.
pub fn sampler_settings(metadata: &BTreeMap<String, String>) -> Result<(String, u64)> {
    let policy = metadata.get("curriculum_sampler_policy").map_or("deterministic_v1", String::as_str);
    let raw = metadata.get("curriculum_sampler_seed").map_or("0", String::as_str);
    if !SAMPLER_POLICIES.contains(&policy) {
        return invalid("Unknown curriculum_sampler_policy.");
    }
    let seed_error = || Error::Invalid("curriculum_sampler_seed must be an unsigned 32-bit integer.".to_string());
    if raw.is_empty() || !raw.chars().all(|character| character.is_ascii_digit()) {
        return Err(seed_error());
    }
    let seed: u64 =
        raw.trim_start_matches('0').parse().or_else(|_| if raw.chars().all(|c| c == '0') { Ok(0) } else { Err(seed_error()) })?;
    if seed >= 1 << 32 {
        return Err(seed_error());
    }
    if policy == "deterministic_v1" && seed != 0 {
        return invalid("deterministic_v1 requires curriculum_sampler_seed=0.");
    }
    Ok((policy.to_string(), seed))
}

fn sampler_value(policy: &str, seed: u64) -> Value {
    value::object(vec![("policy", value::string(policy)), ("seed", value::uint(seed))])
}

fn ids_digest(ids: &[String]) -> Result<String> {
    Ok(value::sha256(value::dumps_compact(&value::strings(ids))?.as_bytes()))
}

fn id_of(row: &Value) -> Result<&str> {
    value::str_at(row, "id")
}

fn group_of(row: &Value) -> Result<String> {
    Ok(classification::py_str(value::get(value::require(row, "metadata")?, "group_id").unwrap_or(&Value::Null)))
}

/// Rows sorted by ID, grouped by family in first-seen order.
fn families_by_id(pool: &[&Value]) -> Result<Vec<(String, Vec<Value>)>> {
    let mut sorted: Vec<&Value> = pool.to_vec();
    let mut keyed: Vec<(String, &Value)> = Vec::with_capacity(sorted.len());
    for row in sorted.drain(..) {
        keyed.push((id_of(row)?.to_string(), row));
    }
    keyed.sort_by(|left, right| left.0.cmp(&right.0));
    let mut order: Vec<(String, Vec<Value>)> = Vec::new();
    let mut index_of: BTreeMap<String, usize> = BTreeMap::new();
    for (_, row) in keyed {
        let group = group_of(row)?;
        let position = *index_of.entry(group.clone()).or_insert_with(|| {
            order.push((group.clone(), Vec::new()));
            order.len() - 1
        });
        order[position].1.push(row.clone());
    }
    Ok(order)
}

/// `_family_order(rows)`: interleave parent families before revisiting their lexical descendants.
fn family_order(rows: &[&Value]) -> Result<Vec<Value>> {
    let families = families_by_id(rows)?;
    let longest = families.iter().map(|(_, items)| items.len()).max().unwrap_or(0);
    let mut out = Vec::new();
    for index in 0..longest {
        for (_, family) in &families {
            if let Some(row) = family.get(index) {
                out.push(row.clone());
            }
        }
    }
    Ok(out)
}

/// `_epoch_order(pool, sampler, stratum, epoch)`.
fn epoch_order(pool: &[Value], policy: &str, seed: u64, stratum: &str, epoch: i64) -> Result<Vec<Value>> {
    if policy == "deterministic_v1" {
        return Ok(pool.to_vec());
    }
    // A stable SHA namespace avoids process-randomised Python hashes; each round visits every family before its next descendant.
    let key = Value::Array(vec![value::uint(seed), value::string(stratum), value::int(epoch)]);
    let mut rng = Random::from_text(&value::sha256(value::dumps_compact(&key)?.as_bytes()));
    let references: Vec<&Value> = pool.iter().collect();
    let mut families = families_by_id(&references)?;
    let mut groups: Vec<String> = families.iter().map(|(group, _)| group.clone()).collect();
    groups.sort();
    rng.shuffle(&mut groups);
    for (_, rows) in &mut families {
        rng.shuffle(rows);
    }
    let by_group: BTreeMap<&str, &Vec<Value>> = families.iter().map(|(group, rows)| (group.as_str(), rows)).collect();
    let longest = families.iter().map(|(_, rows)| rows.len()).max().unwrap_or(0);
    let mut out = Vec::new();
    for index in 0..longest {
        for group in &groups {
            if let Some(row) = by_group.get(group.as_str()).and_then(|rows| rows.get(index)) {
                out.push(row.clone());
            }
        }
    }
    Ok(out)
}

/// The durable allocation and cursor state of the Python SQLite database.
pub trait CursorState {
    /// The fingerprint and allocation stored for a request identity.
    fn allocation(&self, identity: &str) -> Option<(String, Value)>;
    /// Store a new allocation.
    fn store_allocation(&mut self, identity: &str, fingerprint: &str, allocation: &Value);
    /// The cursor position stored for a stratum key.
    fn cursor(&self, key: &str) -> Option<i64>;
    /// Store a cursor position.
    fn set_cursor(&mut self, key: &str, position: i64);
}

/// An in-memory [`CursorState`].
#[derive(Debug, Default, Clone)]
pub struct MemoryState {
    batches: BTreeMap<String, (String, Value)>,
    cursors: BTreeMap<String, i64>,
}

impl CursorState for MemoryState {
    fn allocation(&self, identity: &str) -> Option<(String, Value)> {
        self.batches.get(identity).cloned()
    }

    fn store_allocation(&mut self, identity: &str, fingerprint: &str, allocation: &Value) {
        self.batches.insert(identity.to_string(), (fingerprint.to_string(), allocation.clone()));
    }

    fn cursor(&self, key: &str) -> Option<i64> {
        self.cursors.get(key).copied()
    }

    fn set_cursor(&mut self, key: &str, position: i64) {
        self.cursors.insert(key.to_string(), position);
    }
}

struct Take<'a> {
    state: &'a dyn CursorState,
    staged: BTreeMap<String, i64>,
}

#[allow(clippy::too_many_arguments)]
fn take(
    scratch: &mut Take<'_>,
    curriculum: &Curriculum,
    model_id: &str,
    stratum: &str,
    pool: &[Value],
    count: usize,
    chosen: &mut Vec<String>,
    sampler: (&str, u64),
) -> Result<Value> {
    let mut namespace = vec![value::string(&curriculum.manifest_sha256), value::string(model_id), value::string(stratum)];
    // Keep legacy deterministic cursor identities so existing reservations resume.
    if sampler.0 != "deterministic_v1" {
        namespace.push(value::string(sampler.0));
        namespace.push(value::uint(sampler.1));
    }
    let key = value::dumps(&Value::Array(namespace))?;
    let position_in = scratch.staged.get(&key).copied().or_else(|| scratch.state.cursor(&key)).unwrap_or(0);
    let mut position = position_in;
    let start = position;
    let length = pool.len() as i64;
    if length == 0 {
        return invalid("Curriculum pool or hard examples cannot satisfy balanced quotas.");
    }
    let mut epoch: Option<i64> = None;
    let mut order: Vec<Value> = Vec::new();
    for _ in 0..count {
        loop {
            if epoch != Some(position / length) {
                epoch = Some(position / length);
                order = epoch_order(pool, sampler.0, sampler.1, stratum, position / length)?;
            }
            let row_id = id_of(&order[(position % length) as usize])?.to_string();
            position += 1;
            if !chosen.contains(&row_id) {
                chosen.push(row_id);
                break;
            }
        }
    }
    scratch.staged.insert(key, position);
    Ok(value::object(vec![
        ("start", value::int(start)),
        ("stop", value::int(position)),
        ("pool_size", value::int(length)),
        ("start_epoch", value::int(start / length)),
        ("stop_epoch", value::int(position / length)),
    ]))
}

/// The optional arguments of `reserve_batch`.
#[derive(Debug, Clone, Copy)]
pub struct ReserveOptions<'a> {
    /// `replay_fraction`.
    pub replay_fraction: f64,
    /// `fingerprint`.
    pub fingerprint: Option<&'a str>,
    /// `model_id`.
    pub model_id: Option<&'a str>,
}

impl Default for ReserveOptions<'_> {
    fn default() -> Self {
        Self { replay_fraction: 0.25, fingerprint: None, model_id: None }
    }
}

/// `reserve_batch(curriculum, state_path, request, count, replay_fraction, fingerprint=, model_id=)`.
pub fn reserve_batch(
    curriculum: &Curriculum,
    state: &mut dyn CursorState,
    request: &privoke_contracts::proto::v1::FuzzerTrainingRequest,
    count: i64,
    options: ReserveOptions<'_>,
) -> Result<CurriculumBatch> {
    let (policy, seed) = sampler_settings(&request.metadata)?;
    let replay_fraction = options.replay_fraction;
    if count < 1 || !replay_fraction.is_finite() || replay_fraction <= 0.0 || replay_fraction >= 1.0 {
        return invalid("Batch count must be positive and replay_fraction finite between zero and one.");
    }
    let stage = request.metadata.get("curriculum_stage").map_or("all", String::as_str);
    if stage != "all" && !ROLES.contains(&stage) {
        return invalid("curriculum_stage must be all, grammar, teacher or evolved.");
    }
    let hard_text = request.metadata.get("curriculum_hard_ids").map_or("[]", String::as_str);
    let hard_ids: Vec<String> = match privoke_contracts::json::parse(hard_text)? {
        Value::Array(items) if items.len() <= 8 && items.iter().all(|item| matches!(item, Value::String(_))) => {
            items.iter().filter_map(value::as_str).map(str::to_string).collect()
        }
        _ => return invalid("curriculum_hard_ids must contain at most eight distinct training IDs."),
    };
    if hard_ids.iter().collect::<BTreeSet<_>>().len() != hard_ids.len() {
        return invalid("curriculum_hard_ids must contain at most eight distinct training IDs.");
    }
    let train_rows: Vec<&Value> = curriculum
        .splits
        .get("train")
        .map_or(&[][..], Vec::as_slice)
        .iter()
        .filter(|row| {
            stage == "all"
                || value::get(row, "metadata").and_then(|meta| value::get(meta, "curriculum_role")).and_then(value::as_str) == Some(stage)
        })
        .collect();
    let eligible: BTreeMap<&str, &Value> = train_rows.iter().map(|row| id_of(row).map(|id| (id, *row))).collect::<Result<_>>()?;
    if hard_ids.iter().any(|id| !eligible.contains_key(id.as_str())) {
        return invalid("Hard-example mining may only select eligible TRAIN rows.");
    }
    let replay_count = (count as f64 * replay_fraction) as i64;
    let new_count = count - replay_count;
    if replay_count < 2 || new_count < 2.max(hard_ids.len() as i64) {
        return invalid("Curriculum batches must include both new and replay classes.");
    }
    let sampler = sampler_value(&policy, seed);
    let fingerprint_settings = if policy == "deterministic_v1" {
        None
    } else {
        Some(value::object(vec![
            ("caller_fingerprint", options.fingerprint.map_or(Value::Null, value::string)),
            ("count", value::int(count)),
            ("replay_fraction", Value::Float(replay_fraction)),
            ("sampler", sampler.clone()),
        ]))
    };
    let fingerprint = match (&fingerprint_settings, options.fingerprint) {
        (None, Some(given)) if !given.is_empty() => given.to_string(),
        (None, _) => request_fingerprint(
            request,
            curriculum,
            &value::object(vec![("count", value::int(count)), ("replay_fraction", Value::Float(replay_fraction))]),
        )?,
        (Some(settings), _) => request_fingerprint(request, curriculum, settings)?,
    };
    let model_id = options.model_id.unwrap_or(&request.model_id);
    let identity = value::dumps(&value::strings(&[request.source_id.as_str(), model_id, request.request_id.as_str()]))?;
    let allocation = match state.allocation(&identity) {
        Some((stored, allocation)) => {
            if stored != fingerprint {
                return invalid("request_id belongs to a different curriculum request.");
            }
            allocation
        }
        None => {
            let mut scratch = Take { state: &*state, staged: BTreeMap::new() };
            let mut chosen: Vec<String> = hard_ids.clone();
            let mut positions: BTreeMap<String, Value> = BTreeMap::new();
            let roles: Vec<&str> = if stage == "all" { ROLES.to_vec() } else { vec![stage] };
            let strata: Vec<(&str, bool)> = roles.iter().flat_map(|role| [(*role, false), (*role, true)]).collect();
            // Balance both labels and roles, including any hard examples already selected.
            let mut targets: BTreeMap<(&str, bool), i64> = strata.iter().map(|key| (*key, new_count / strata.len() as i64)).collect();
            for key in strata.iter().take((new_count % strata.len() as i64) as usize) {
                *targets.entry(*key).or_default() += 1;
            }
            for (role, sensitive) in &strata {
                let mut members: Vec<&Value> = Vec::new();
                for row in &train_rows {
                    let row_role = value::get(row, "metadata").and_then(|meta| value::get(meta, "curriculum_role")).and_then(value::as_str);
                    if row_role == Some(*role) && is_sensitive(row)? == *sensitive {
                        members.push(row);
                    }
                }
                let pool = family_order(&members)?;
                let mut already = 0;
                for item in &hard_ids {
                    let row = eligible[item.as_str()];
                    let row_role = value::get(row, "metadata").and_then(|meta| value::get(meta, "curriculum_role")).and_then(value::as_str);
                    if row_role == Some(*role) && is_sensitive(row)? == *sensitive {
                        already += 1;
                    }
                }
                let target = targets[&(*role, *sensitive)];
                let required = target - already;
                if required < 0 || pool.is_empty() || (pool.len() as i64) < target {
                    return invalid("Curriculum pool or hard examples cannot satisfy balanced quotas.");
                }
                let stratum = format!("{role}:{}", if *sensitive { "True" } else { "False" });
                let taken =
                    take(&mut scratch, curriculum, model_id, &stratum, &pool, required as usize, &mut chosen, (policy.as_str(), seed))?;
                positions.insert(stratum, taken);
            }
            let mut replay: Vec<String> = Vec::new();
            let replay_rows: Vec<&Value> = curriculum.splits.get("replay").map_or(&[][..], Vec::as_slice).iter().collect();
            for (sensitive, required) in [(false, replay_count / 2), (true, replay_count - replay_count / 2)] {
                let mut members: Vec<&Value> = Vec::new();
                for row in &replay_rows {
                    if is_sensitive(row)? == sensitive {
                        members.push(row);
                    }
                }
                let pool = family_order(&members)?;
                if (pool.len() as i64) < required {
                    return invalid("Replay pool cannot satisfy this batch size.");
                }
                let stratum = format!("replay:{}", if sensitive { "True" } else { "False" });
                let taken =
                    take(&mut scratch, curriculum, model_id, &stratum, &pool, required as usize, &mut replay, (policy.as_str(), seed))?;
                positions.insert(stratum, taken);
            }
            let allocation = value::object(vec![
                ("train", value::strings(&chosen)),
                ("replay", value::strings(&replay)),
                ("positions", Value::Object(positions)),
            ]);
            let staged = scratch.staged;
            for (key, position) in staged {
                state.set_cursor(&key, position);
            }
            state.store_allocation(&identity, &fingerprint, &allocation);
            allocation
        }
    };
    let by_id: BTreeMap<&str, &Value> =
        curriculum.splits.values().flatten().filter_map(|row| value::get(row, "id").and_then(value::as_str).map(|id| (id, row))).collect();
    let resolve = |ids: &Value| -> Result<Vec<Example>> {
        let mut out = Vec::new();
        for item in value::as_array(ids).map_or(&[][..], Vec::as_slice) {
            let id = value::as_str(item).unwrap_or_default();
            out.push(example(by_id.get(id).ok_or_else(|| Error::Invalid(format!("unknown curriculum row {id}")))?)?);
        }
        Ok(out)
    };
    let train_ids = value::require(&allocation, "train")?;
    let replay_ids = value::require(&allocation, "replay")?;
    let examples = resolve(train_ids)?;
    let replay = resolve(replay_ids)?;
    let heldout_rows = curriculum.splits.get("heldout").map_or(&[][..], Vec::as_slice);
    let heldout: Vec<Example> = heldout_rows.iter().map(example).collect::<Result<_>>()?;
    let string_ids = |ids: &Value| -> Vec<String> {
        value::as_array(ids).map_or_else(Vec::new, |items| items.iter().filter_map(value::as_str).map(str::to_string).collect())
    };
    let gate_ids: Vec<String> = heldout_rows.iter().map(|row| id_of(row).map(str::to_string)).collect::<Result<_>>()?;
    let mut audit = BTreeMap::new();
    audit.insert("curriculum_id".to_string(), curriculum.curriculum_id.clone());
    audit.insert("curriculum_manifest_sha256".to_string(), curriculum.manifest_sha256.clone());
    audit.insert("curriculum_stage".to_string(), stage.to_string());
    audit.insert("curriculum_new_count".to_string(), examples.len().to_string());
    audit.insert("curriculum_replay_count".to_string(), replay.len().to_string());
    audit.insert("curriculum_hard_count".to_string(), hard_ids.len().to_string());
    audit.insert("curriculum_train_ids_sha256".to_string(), ids_digest(&string_ids(train_ids))?);
    audit.insert("curriculum_replay_ids_sha256".to_string(), ids_digest(&string_ids(replay_ids))?);
    audit.insert("curriculum_sampler_policy".to_string(), policy.clone());
    audit.insert("curriculum_sampler_seed".to_string(), seed.to_string());
    audit.insert("curriculum_sampler_positions".to_string(), value::dumps(value::get(&allocation, "positions").unwrap_or(&Value::Null))?);
    audit.insert("curriculum_gate_ids_sha256".to_string(), ids_digest(&gate_ids)?);
    Ok(CurriculumBatch { examples, replay, heldout, audit })
}
