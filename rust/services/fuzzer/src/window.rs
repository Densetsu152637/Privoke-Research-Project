//! The frozen window route of the fuzzer (RUST-S21H): `privoke_model/window_training.py` (the contract the fuzzer re-derives) and
//! `training/window_evidence.py` (the retained inputs, the authenticated response, the retained trace admission and the compact
//! publication).
//!
//! The runtime computes the 64 Adam steps and the TRAIN-only checkpoint selection (`privoke_training::window`, stage 19). The
//! fuzzer does not trust that response: it re-derives the schedule, the recurrence identities, the checkpoint counts and
//! component predicates, the selection, the terminal outcome, the work accounting and the compact summary from the retained
//! immutable inputs ([`validate_trace`]), and binds the response to the frozen ordered wire rows ([`validate_response`]).
//!
//! The window contract itself ([`privoke_training::window::Window::parse`]) and the authenticated component release
//! ([`privoke_training::window::Release::load`]) are the stage 19 ports.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use base64::Engine as _;
use privoke_contracts::fingerprint::parameter_fingerprint;
use privoke_contracts::json::{self, Value};
use privoke_contracts::proto::v1::{ComputeSemanticGradientsRequest, ComputeSemanticGradientsResponse};
use privoke_curriculum::Example;
use privoke_curriculum::classification::{Classification, sensitivity_value};
use privoke_curriculum::value;
use privoke_training::admission::WINDOW_CONFIG_CANONICAL;
use privoke_training::window::{self as contract, Checkpoint, Release, Row, Window};
use prost::Message;

use crate::config::FuzzerConfig;
use crate::error::{Error, Result, invalid};
use crate::policy::{Expectations, Metadata, SUM_MARGIN, WINDOW_ELIGIBILITY, WINDOW_POLICY};
use crate::runtime::{BatchUpdate, FULL_ENCODER_STRATEGY, SEMANTIC_LAYER};

/// `TRACE_KEY`.
pub const TRACE_KEY: &str = "train_window_trace_v1";
/// `SUMMARY_KEY`.
pub const SUMMARY_KEY: &str = "train_window_summary_v1";
/// `CONFIG_KEY`.
pub const CONFIG_KEY: &str = "train_window_config_v1";
/// `WINDOW_KEY`.
pub const WINDOW_KEY: &str = "train_window_manifest_sha256";
/// `REFERENCE_KEY`.
pub const REFERENCE_KEY: &str = "original_train_component_manifest_sha256";
const MAX_TRACE_BYTES: usize = 4 * 1024 * 1024;
const MAX_FILE_BYTES: usize = 4 * 1024 * 1024;
const PROMPTS: i64 = 256;

/// The independently configured pins Python reads from the environment (`FUZZ_WINDOW_MANIFEST_SHA256`,
/// `FUZZ_COMPONENT_MANIFEST_SHA256` and `FUZZ_COMPONENT_TEACHER_SHA256`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Pins {
    /// The frozen window.
    pub window: Option<String>,
    /// The component manifest.
    pub component: Option<String>,
    /// The ORIGINAL teacher raw file.
    pub teacher: Option<String>,
}

impl Pins {
    /// The pins of a configuration.
    pub fn of(config: &FuzzerConfig) -> Self {
        Self {
            window: config.window_manifest_sha256.clone(),
            component: config.component_manifest_sha256.clone(),
            teacher: config.component_teacher_sha256.clone(),
        }
    }
}

fn is_sha256(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

fn canonical(document: &Value) -> Result<String> {
    Ok(value::dumps_compact(document)?)
}

fn parse(text: &str) -> Result<Value> {
    json::parse(text).map_err(|error| Error(error.to_string()))
}

fn contract_error(error: impl std::fmt::Display) -> Error {
    Error(error.to_string())
}

/// `type(x) in (int, float)` and finite (a boolean is neither).
fn finite(document: Option<&Value>) -> Option<f64> {
    match document {
        Some(Value::Int(_)) => document.and_then(value::as_number),
        Some(Value::Float(number)) if number.is_finite() => Some(*number),
        _ => None,
    }
}

fn int_of(document: Option<&Value>) -> Option<i64> {
    match document {
        Some(Value::Int(digits)) => digits.parse().ok(),
        _ => None,
    }
}

fn text_of<'a>(document: &'a Value, key: &str) -> Option<&'a str> {
    value::get(document, key).and_then(value::as_str)
}

fn field<'a>(document: &'a Value, key: &str) -> Result<&'a Value> {
    value::get(document, key).ok_or_else(|| Error(format!("'{key}'")))
}

/// `read_pinned(path, pin)`: an explicit non-symlink path whose canonical bytes hash to the independently configured pin.
pub fn read_pinned(path: Option<&Path>, pin: Option<&str>) -> Result<Vec<u8>> {
    let (Some(path), Some(pin)) = (path, pin.filter(|pin| is_sha256(pin))) else {
        return invalid("Window/reference requires explicit non-symlink path and independently configured SHA256.");
    };
    if std::fs::symlink_metadata(path).is_ok_and(|meta| meta.file_type().is_symlink()) {
        return invalid("Window/reference requires explicit non-symlink path and independently configured SHA256.");
    }
    let payload = std::fs::read(path)?;
    let document = value::parse_bytes(&payload)?;
    if payload.len() > MAX_FILE_BYTES || value::canonical_bytes(&document)? != payload || value::sha256(&payload) != pin {
        return invalid("Canonical immutable release differs from trusted pin.");
    }
    Ok(payload)
}

/// The authenticated component release with the immutable bytes the retained evidence keeps.
#[derive(Debug, Clone)]
pub struct Components {
    /// The bank bytes.
    pub bank: Vec<u8>,
    /// The references bytes.
    pub references: Vec<u8>,
    /// The manifest bytes.
    pub manifest: Vec<u8>,
    /// The ORIGINAL teacher artifact's path, as given.
    pub teacher_path: String,
    /// The accepted raw-file pin of the teacher.
    pub teacher_sha256: String,
    /// The release.
    pub release: Release,
    /// `teacher["model_id"]` of the manifest's profile.
    pub model_id: String,
}

fn authenticate(
    bank: Vec<u8>,
    references: Vec<u8>,
    manifest: Vec<u8>,
    teacher_path: &str,
    teacher_sha256: &str,
    trusted: Option<&str>,
    model_id: Option<&str>,
) -> Result<Components> {
    let teacher = std::fs::read(teacher_path)?;
    // `Release::load` fuses the structure checks with the trust anchor: without a configured pin the manifest's own hash
    // stands in, and the pin comparison of the cycle (which Python makes against `None`) then refuses.
    let own = value::sha256(&manifest);
    let release =
        Release::load(&bank, &references, &manifest, &teacher, trusted.unwrap_or(&own), teacher_sha256).map_err(contract_error)?;
    let document = value::parse_bytes(&manifest)?;
    let profile = value::get(&document, "teacher").and_then(|teacher| text_of(teacher, "profile")).unwrap_or_default();
    let identity = format!("privoke-{profile}");
    if model_id.is_some_and(|expected| expected != identity) {
        return invalid("Component reference teacher/bank/profile differs.");
    }
    Ok(Components {
        bank,
        references,
        manifest,
        teacher_path: teacher_path.to_string(),
        teacher_sha256: teacher_sha256.to_string(),
        release,
        model_id: identity,
    })
}

/// `load_components(...)`: four explicit non-symlink sidecars authenticated against the configured pins.
pub fn load_components(
    paths: [Option<&Path>; 4],
    model_id: &str,
    trusted: Option<&str>,
    teacher_sha256: Option<&str>,
) -> Result<Components> {
    let given: Vec<&Path> = paths.iter().flatten().copied().collect();
    if given.len() != 4 || given.iter().any(|path| std::fs::symlink_metadata(path).is_ok_and(|meta| meta.file_type().is_symlink())) {
        return invalid("Component retention requires four non-symlink sidecar paths.");
    }
    let (bank, references, manifest) = (std::fs::read(given[0])?, std::fs::read(given[1])?, std::fs::read(given[2])?);
    authenticate(bank, references, manifest, &given[3].display().to_string(), teacher_sha256.unwrap_or_default(), trusted, Some(model_id))
}

/// `validate_policy(metadata)`: the artifact policy of a window response.
pub fn validate_policy(metadata: &Metadata) -> Result<bool> {
    let get = |key: &str| metadata.get(key).map(String::as_str);
    if get("contextual_training_optimizer") != Some(WINDOW_POLICY) {
        if [CONFIG_KEY, WINDOW_KEY, REFERENCE_KEY].iter().any(|key| metadata.contains_key(*key)) {
            return invalid("Orphan window/checkpoint artifact policy.");
        }
        return Ok(false);
    }
    let pins = [WINDOW_KEY, REFERENCE_KEY].iter().all(|key| get(key).is_some_and(is_sha256));
    let foreign = [
        "contextual_training_backtracking_policy",
        "contextual_training_diagnostics_policy",
        "full_projected_adam_config_v1",
        "original_train_retention_manifest_sha256",
    ]
    .iter()
    .any(|key| metadata.contains_key(*key));
    if get("contextual_training_strategy") != Some(FULL_ENCODER_STRATEGY)
        || get("contextual_training_objective") != Some(SUM_MARGIN)
        || get("contextual_candidate_eligibility") != Some(WINDOW_ELIGIBILITY)
        || get(CONFIG_KEY) != Some(WINDOW_CONFIG_CANONICAL)
        || !pins
        || foreign
    {
        return invalid("Window policy requires exact exclusive FULL optimizer/objective/config/pins.");
    }
    Ok(true)
}

/// `validate_admission(admission, metadata)`: the artifact must carry exactly the settings admitted before the gradient.
pub fn validate_admission(admission: &Expectations, metadata: &Metadata) -> Result<()> {
    if !validate_policy(metadata)? {
        return invalid("Window artifact requires explicit matching pre-gradient admission.");
    }
    let mut request = Metadata::new();
    for (key, text) in [
        ("expected_contextual_training_optimizer", WINDOW_POLICY),
        ("expected_contextual_training_objective", SUM_MARGIN),
        ("expected_contextual_candidate_eligibility", WINDOW_ELIGIBILITY),
        ("expected_contextual_training_scope", "full_encoder"),
    ] {
        request.insert(key.to_string(), text.to_string());
    }
    for (key, source) in [("expected_train_window_config_v1", CONFIG_KEY), ("expected_train_window_manifest_sha256", WINDOW_KEY)] {
        request.insert(key.to_string(), metadata.get(source).cloned().unwrap_or_default());
    }
    request
        .insert("expected_original_train_component_manifest_sha256".to_string(), metadata.get(REFERENCE_KEY).cloned().unwrap_or_default());
    let expected = crate::policy::window_expectations(&request)?;
    if expected.as_ref() != Some(admission) {
        return invalid("Window artifact differs from admitted effective settings.");
    }
    Ok(())
}

/// `validate_request(window, examples, guard)`: the ordered texts, targets and raw weights are the frozen ones.
pub fn validate_request(window: &Window, examples: &[Example], guard: &[Example]) -> Result<()> {
    let explicit = |rows: &[Example]| rows.iter().all(|row| row.target.is_some() && row.weight.is_finite() && row.weight > 0.0);
    if !explicit(examples) || !explicit(guard) {
        return invalid("Window requires explicit targets and finite positive weights.");
    }
    let same = |examples: &[Example], rows: Vec<&Row>| {
        examples.len() == rows.len()
            && examples.iter().zip(rows).all(|(example, row)| {
                example.text == row.text && example.target.map(Classification::pack) == Some(row.packed) && example.weight == row.weight
            })
    };
    if !same(examples, window.rows()) || !same(guard, window.guard.iter().collect()) {
        return invalid("Actual ordered request texts/targets/raw weights differ from frozen window.");
    }
    Ok(())
}

/// A parsed, validated trace with its canonical text.
#[derive(Debug, Clone)]
pub struct Trace {
    /// The parsed trace.
    pub value: Value,
    /// Its canonical text (the retained metadata value).
    pub raw: String,
    /// `selected` or `no_update`.
    pub status: String,
    /// The terminal reason.
    pub reason: String,
    /// The base state fingerprint.
    pub base: String,
}

fn strings_of(document: &Value) -> Vec<(String, i64)> {
    value::as_object(document)
        .map(|map| map.iter().filter_map(|(key, item)| int_of(Some(item)).map(|number| (key.clone(), number))).collect())
        .unwrap_or_default()
}

fn pair_list(document: Option<&Value>) -> Option<Vec<(u16, f64)>> {
    let mut out = Vec::new();
    for item in value::as_array(document?)? {
        let pair = value::as_array(item)?;
        if pair.len() != 2 {
            return None;
        }
        let packed = int_of(pair.first())?;
        let confidence = finite(pair.get(1))?;
        if !(0..=65_535).contains(&packed) || !(0.0..=0.999).contains(&confidence) || (confidence * 1000.0).round() / 1000.0 != confidence {
            return None;
        }
        out.push((u16::try_from(packed).ok()?, confidence));
    }
    Some(out)
}

/// The checkpoint of a trace row, with its recorded counts and violations (validated by [`validate_trace`]).
fn checkpoint_of(row: &Value) -> Result<Checkpoint> {
    let malformed = || Error("Malformed checkpoint output.".to_string());
    let counts = strings_of(field(row, "counts")?).into_iter().collect::<BTreeMap<_, _>>();
    let components = field(row, "component_violations")?;
    let mut violations = [0usize; 5];
    for (slot, name) in contract::COMPONENTS.iter().enumerate() {
        violations[slot] = usize::try_from(int_of(value::get(components, name)).ok_or_else(malformed)?).map_err(|_| malformed())?;
    }
    Ok(Checkpoint {
        step: usize::try_from(int_of(value::get(row, "step")).ok_or_else(malformed)?).map_err(|_| malformed())?,
        fingerprint: text_of(row, "fingerprint").ok_or_else(malformed)?.to_string(),
        counts,
        loss: finite(value::get(row, "loss")).ok_or_else(malformed)?,
        predictions: pair_list(value::get(row, "predictions")).ok_or_else(malformed)?,
        original_predictions: pair_list(value::get(row, "original_predictions")).ok_or_else(malformed)?,
        violations: usize::try_from(int_of(value::get(row, "violations")).ok_or_else(malformed)?).map_err(|_| malformed())?,
        component_violations: violations,
    })
}

/// `execution_phases(trace)`: the actual semantic phases and example counts the response must declare.
pub fn execution_phases(trace: &Value) -> Result<Vec<(String, i64)>> {
    let work = field(trace, "work")?;
    let rows = |document: &Value| int_of(value::get(document, "rows_completed")).ok_or_else(|| Error("'rows_completed'".to_string()));
    let mut phases = vec![
        ("training".to_string(), rows(field(trace, "main")?)?),
        ("original_train_component_backward".to_string(), rows(field(trace, "auxiliary")?)?),
    ];
    let recorded = field(work, "phases")?;
    let mut ordered: Vec<String> = Vec::new();
    for step in std::iter::once(0).chain(contract::CHECKPOINTS) {
        for part in ["window", "original_train"] {
            ordered.push(format!("checkpoint_{step}_{part}"));
        }
    }
    if !matches!(field(trace, "guard")?, Value::Null) {
        ordered.push("base_heldout".to_string());
        ordered.push("candidate_heldout".to_string());
    }
    for name in ordered {
        phases.push((name.clone(), rows(field(recorded, &name)?)?));
    }
    Ok(phases)
}

/// `packed_exact_rate(rows, checkpoint)`: the configured legacy packed-classification exact floor.
pub fn packed_exact_rate(targets: &[u16], checkpoint: &Checkpoint) -> Result<f64> {
    if targets.len() != checkpoint.predictions.len() || targets.is_empty() {
        return invalid("Exact TRAIN metric membership differs.");
    }
    let hits = targets.iter().zip(&checkpoint.predictions).filter(|(packed, prediction)| **packed == prediction.0).count();
    Ok(hits as f64 / targets.len() as f64)
}

fn checkpoints_of(trace: &Value) -> Result<Vec<Checkpoint>> {
    value::array_at(trace, "checkpoints")?.iter().map(checkpoint_of).collect()
}

/// `summary(trace, raw)`: the bounded winner and terminal summary.
fn summary(trace: &Value, raw: &str) -> Result<Value> {
    let checkpoints = checkpoints_of(trace)?;
    let step =
        usize::try_from(int_of(value::get(trace, "selected_step")).unwrap_or(-1)).map_err(|_| Error("'selected_step'".to_string()))?;
    let selected = checkpoints.iter().find(|row| row.step == step).ok_or_else(|| Error("StopIteration".to_string()))?;
    let phases = field(field(trace, "work")?, "phases")?;
    let mut checkpoint_rows = 0;
    for (name, phase) in value::as_object(phases).into_iter().flatten() {
        if name.starts_with("checkpoint_") {
            checkpoint_rows += int_of(value::get(phase, "rows_completed")).unwrap_or(0);
        }
    }
    let rows = |document: &str| field(trace, document).and_then(|inner| field(inner, "rows_completed")).cloned();
    let guard_passed = match field(trace, "guard")? {
        Value::Null => false,
        guard => value::get(guard, "passed") == Some(&Value::Bool(true)),
    };
    let copy = |key: &str| field(trace, key).cloned();
    Ok(value::object(vec![
        ("schema", value::int(1)),
        ("policy", value::string(WINDOW_POLICY)),
        ("trace_sha256", value::string(&value::sha256(raw.as_bytes()))),
        ("window", copy("window_sha256")?),
        ("references", copy("references_sha256")?),
        ("base", copy("base")?),
        ("terminal", copy("terminal")?),
        ("selected", copy("selected")?),
        ("selected_step", copy("selected_step")?),
        ("delta", copy("selected_delta")?),
        ("published", copy("published")?),
        ("status", copy("status")?),
        ("reason", copy("reason")?),
        ("main_rows", rows("main")?),
        ("auxiliary_rows", rows("auxiliary")?),
        ("checkpoint_rows", value::int(checkpoint_rows)),
        ("violations", value::int(i64::try_from(selected.violations).unwrap_or(i64::MAX))),
        ("guard_passed", Value::Bool(guard_passed)),
        ("sensitive_progress", Value::Bool(contract::progress(selected, &checkpoints[0]))),
    ]))
}

/// `validate_guard(guard, rows)`: the selected candidate's unchanged held-out guard, recomputed from its recorded predictions.
fn validate_guard(guard: &Value, rows: &[Row]) -> Result<()> {
    let differs = || Error("Selected guard predicates differ.".to_string());
    let before = pair_list(value::get(guard, "before")).ok_or_else(differs)?;
    let after = pair_list(value::get(guard, "after")).ok_or_else(differs)?;
    if before.len() != 16 || after.len() != 16 {
        return invalid("Selected guard execution membership differs.");
    }
    let targets: Vec<Classification> = rows.iter().map(|row| Classification(row.packed)).collect();
    let counts = |predictions: &[(u16, f64)]| -> [i64; 3] {
        let pairs = targets.iter().zip(predictions);
        let exact = pairs.clone().filter(|(target, prediction)| target.pack() == prediction.0).count();
        let recall =
            pairs.clone().filter(|(target, prediction)| target.is_sensitive() && Classification(prediction.0).is_sensitive()).count();
        let specificity =
            pairs.filter(|(target, prediction)| !target.is_sensitive() && !Classification(prediction.0).is_sensitive()).count();
        [exact as i64, recall as i64, specificity as i64]
    };
    let (base_counts, candidate_counts) = (counts(&before), counts(&after));
    let mut regressions = 0usize;
    for ((target, base), candidate) in targets.iter().zip(&before).zip(&after) {
        let level = |packed: u16| sensitivity_value(Classification(packed).sensitivity()).map_err(Error::from);
        let sensitivity_drop = level(candidate.0)? < level(target.pack())?.min(level(base.0)?);
        let action_drop = contract::action_value(candidate.0, Some(candidate.1))
            < contract::action_value(target.pack(), None).min(contract::action_value(base.0, Some(base.1)));
        regressions += usize::from(sensitivity_drop || action_drop);
    }
    let rate = regressions as f64 / 16.0;
    let passed = candidate_counts.iter().zip(&base_counts).all(|(after, before)| after >= before) && regressions == 0;
    let triple = |counts: [i64; 3]| {
        value::object(vec![("exact", value::int(counts[0])), ("recall", value::int(counts[1])), ("specificity", value::int(counts[2]))])
    };
    let keys: BTreeSet<&str> = value::as_object(guard).map(|map| map.keys().map(String::as_str).collect()).unwrap_or_default();
    let expected_keys: BTreeSet<&str> =
        ["before", "after", "base_counts", "candidate_counts", "regression_rate", "passed"].into_iter().collect();
    if keys != expected_keys
        || value::get(guard, "base_counts") != Some(&triple(base_counts))
        || value::get(guard, "candidate_counts") != Some(&triple(candidate_counts))
        || value::get(guard, "regression_rate").and_then(value::as_number) != Some(rate)
        || value::get(guard, "passed") != Some(&Value::Bool(passed))
    {
        return Err(differs());
    }
    Ok(())
}

fn phase_value(count: i64, layers: i64) -> Value {
    value::object(vec![
        ("rows_attempted", value::int(count)),
        ("rows_completed", value::int(count)),
        ("blocks_attempted", value::int(count * layers)),
        ("blocks_completed", value::int(count * layers)),
    ])
}

/// `validate_trace(metadata, window=, release=, gradients=, shapes=)`: independently derive the checkpoint decisions and the work
/// from the retained immutable inputs.
pub fn validate_trace(
    metadata: &Metadata,
    window: &Window,
    release: &Release,
    gradients: &BTreeMap<String, Vec<f64>>,
    shapes: &BTreeMap<String, Vec<u64>>,
) -> Result<Trace> {
    if !validate_policy(metadata)? {
        return Err(Error(format!("'{REFERENCE_KEY}'")));
    }
    let reference = metadata.get(REFERENCE_KEY).map_or("", String::as_str);
    if reference != release.sha256 {
        return invalid("Component release differs from distinct trusted configured pin.");
    }
    let Some(raw) = metadata.get(TRACE_KEY).filter(|raw| raw.len() <= MAX_TRACE_BYTES) else {
        return invalid("Missing or excessive window trace.");
    };
    let trace = parse(raw)?;
    let identity = || Error("Window trace source/config/identity differs.".to_string());
    let steps = value::as_array(field(&trace, "steps")?).ok_or_else(identity)?;
    let rows = value::as_array(field(&trace, "checkpoints")?).ok_or_else(identity)?;
    let stepped: Vec<Option<i64>> = rows.iter().map(|row| int_of(value::get(row, "step"))).collect();
    let wanted: Vec<Option<i64>> = std::iter::once(0).chain(contract::CHECKPOINTS.iter().map(|step| *step as i64)).map(Some).collect();
    let config = parse(WINDOW_CONFIG_CANONICAL)?;
    let base = text_of(&trace, "base").ok_or_else(identity)?.to_string();
    if raw != &canonical(&trace)?
        || value::get(&trace, "schema") != Some(&value::int(1))
        || text_of(&trace, "policy") != Some(WINDOW_POLICY)
        || value::get(&trace, "config") != Some(&config)
        || text_of(&trace, "window_sha256") != Some(window.sha256.as_str())
        || text_of(&trace, "window_sha256") != metadata.get(WINDOW_KEY).map(String::as_str)
        || text_of(&trace, "references_sha256") != Some(reference)
        || Some(&base) != metadata.get("base_parameter_fingerprint")
        || steps.len() != 64
        || stepped != wanted
    {
        return Err(identity());
    }
    let mut previous = base.clone();
    let recurrence = || Error("Window Adam recurrence/schedule evidence differs.".to_string());
    for (step, (block, row)) in (1..=64i64).zip(contract::schedule(&window.seed).into_iter().zip(steps)) {
        let hashes = ["before", "after", "gradient", "moments", "delta"].iter().all(|key| text_of(row, key).is_some_and(is_sha256));
        let losses = ["main_loss", "auxiliary_loss"].iter().all(|key| finite(value::get(row, key)).is_some_and(|loss| loss >= 0.0));
        let clipped = int_of(value::get(row, "clipped")).is_some_and(|count| count >= 0);
        if int_of(value::get(row, "step")) != Some(step)
            || int_of(value::get(row, "block")) != i64::try_from(block).ok()
            || text_of(row, "before") != Some(previous.as_str())
            || !hashes
            || !losses
            || !clipped
        {
            return Err(recurrence());
        }
        previous = text_of(row, "after").unwrap_or_default().to_string();
    }
    if text_of(&trace, "terminal") != Some(previous.as_str()) {
        return invalid("Terminal fingerprint differs from step64.");
    }
    let references = &release.references;
    let targets: Vec<u16> = window.rows().iter().map(|row| row.packed).collect();
    let model_config = parse(metadata.get("model_config").ok_or_else(|| Error("'model_config'".to_string()))?)?;
    let layers = match value::get(&model_config, "num_layers") {
        None => 1,
        Some(item) => int_of(Some(item)).ok_or_else(|| Error("Malformed model configuration.".to_string()))?,
    };
    let mut expected_phases: BTreeMap<String, i64> = BTreeMap::new();
    let mut checkpoints: Vec<Checkpoint> = Vec::new();
    for row in rows {
        let checkpoint = checkpoint_of(row).map_err(|_| Error("Malformed checkpoint output.".to_string()))?;
        let step = checkpoint.step;
        let fingerprint = if step == 0 { base.as_str() } else { text_of(&steps[step - 1], "after").unwrap_or_default() };
        let recomputed = contract::checkpoint_counts(&targets, &checkpoint.predictions).map_err(contract_error)?;
        if checkpoint.fingerprint != fingerprint || checkpoint.counts != recomputed {
            return invalid("Checkpoint state/independently recomputed counts differ.");
        }
        if checkpoint.original_predictions.len() != references.len() {
            return invalid("ORIGINAL TRAIN checkpoint membership differs.");
        }
        let predicates: Vec<[bool; 5]> = references
            .iter()
            .zip(&checkpoint.original_predictions)
            .map(|(reference, prediction)| {
                contract::component_predicates(reference.gold, reference.original, reference.confidence, prediction.0, prediction.1)
            })
            .collect();
        let mut by_component = [0usize; 5];
        for predicate in &predicates {
            for (slot, ok) in predicate.iter().enumerate() {
                by_component[slot] += usize::from(!ok);
            }
        }
        if checkpoint.violations != predicates.iter().filter(|predicate| !predicate.iter().all(|ok| *ok)).count()
            || checkpoint.component_violations != by_component
            || checkpoint.loss < 0.0
        {
            return invalid("Checkpoint ORIGINAL component predicates/loss differ.");
        }
        expected_phases.insert(format!("checkpoint_{step}_window"), 512);
        expected_phases.insert(format!("checkpoint_{step}_original_train"), references.len() as i64);
        checkpoints.push(checkpoint);
    }
    let selected = contract::select(&checkpoints);
    if int_of(value::get(&trace, "selected_step")) != i64::try_from(selected.step).ok()
        || text_of(&trace, "selected") != Some(selected.fingerprint.as_str())
    {
        return invalid("Selected checkpoint differs from fixed TRAIN-only eligibility/rank.");
    }
    let guard = field(&trace, "guard")?;
    if !matches!(guard, Value::Null) {
        if selected.step == 0 {
            return invalid("BASE fallback must not execute a guard.");
        }
        expected_phases.insert("base_heldout".to_string(), 16);
        expected_phases.insert("candidate_heldout".to_string(), 16);
        validate_guard(guard, &window.guard)?;
    }
    let status = text_of(&trace, "status").unwrap_or_default().to_string();
    let reason = text_of(&trace, "reason").unwrap_or_default().to_string();
    if status != "selected" && status != "no_update" {
        return invalid("Successful trace requires known terminal outcome.");
    }
    let guard_passed = value::get(guard, "passed") == Some(&Value::Bool(true));
    let expected_outcome = if selected.step == 0 {
        ("no_update", "base_selected")
    } else if matches!(guard, Value::Null) {
        ("no_update", "no_transported_encoder_change")
    } else if guard_passed {
        ("selected", "guard_passed")
    } else {
        ("no_update", "guard_failed")
    };
    let delta = field(&trace, "selected_delta")?;
    if (status.as_str(), reason.as_str()) != expected_outcome || (selected.step == 0 && !matches!(delta, Value::Null)) {
        return invalid("Window terminal status/reason/BASE delta is contradictory.");
    }
    let published = text_of(&trace, "published").unwrap_or_default();
    if status == "selected" {
        if selected.step == 0 || matches!(guard, Value::Null) || !guard_passed || gradients.is_empty() {
            return invalid("Publication requires sensitive progress and selected candidate guard.");
        }
        let fingerprint = parameter_fingerprint(gradients, Some(shapes)).map_err(contract_error)?;
        if published != selected.fingerprint || delta != &value::string(&fingerprint) {
            return invalid("Selected delta/published state differs from winner.");
        }
    } else if !gradients.is_empty() || published != base {
        return invalid("Known no_update must retain immutable BASE without deltas.");
    }
    if selected.step != 0 && text_of(&steps[selected.step - 1], "delta") != value::as_str(delta) {
        return invalid("Selected delta differs from exact transported step.");
    }
    let recorded = field(field(&trace, "work")?, "phases")?;
    let recorded_names: BTreeSet<&str> = value::as_object(recorded).map(|map| map.keys().map(String::as_str).collect()).unwrap_or_default();
    if recorded_names != expected_phases.keys().map(String::as_str).collect::<BTreeSet<_>>() {
        return invalid("Unexpected/fabricated NumPy execution phase.");
    }
    for (name, count) in &expected_phases {
        if value::get(recorded, name) != Some(&phase_value(*count, layers)) {
            return invalid("Observed NumPy row/block accounting differs.");
        }
    }
    let count = references.len() as i64;
    for (work, rows, batches) in [(field(&trace, "main")?, 4096, 128), (field(&trace, "auxiliary")?, 64 * count, 64 * ((count + 31) / 32))]
    {
        let expected = value::object(vec![
            ("directions_attempted", value::int(64)),
            ("directions_completed", value::int(64)),
            ("rows_attempted", value::int(rows)),
            ("rows_completed", value::int(rows)),
            ("microbatch_forward_attempted", value::int(batches)),
            ("microbatch_forward_completed", value::int(batches)),
            ("microbatch_backward_started", value::int(batches)),
            ("microbatch_backward_completed", value::int(batches)),
            ("torch_block_forwards_attempted", value::int(batches * layers)),
            ("torch_block_forwards_completed", value::int(batches * layers)),
        ]);
        if work != &expected {
            return invalid("Observed main/auxiliary backward accounting differs.");
        }
    }
    let work = field(&trace, "work")?;
    if int_of(value::get(work, "objective_attempted")) != Some(9) || int_of(value::get(work, "objective_completed")) != Some(9) {
        return invalid("Checkpoint objective accounting differs.");
    }
    let expected_summary = canonical(&summary(&trace, raw)?)?;
    if metadata.get(SUMMARY_KEY) != Some(&expected_summary) || expected_summary.len() > 2048 {
        return invalid("Compact winner/terminal summary differs from full retained trace.");
    }
    if metadata.get("updated_parameter_fingerprint").map(String::as_str) != Some(published)
        || metadata.get("window_outcome").map(String::as_str) != Some(status.as_str())
    {
        return invalid("Response outcome/state differs from trace.");
    }
    Ok(Trace { value: trace, raw: raw.clone(), status, reason, base })
}

fn tensor_maps(response: &ComputeSemanticGradientsResponse) -> (BTreeMap<String, Vec<f64>>, BTreeMap<String, Vec<u64>>) {
    let values = response
        .gradients
        .iter()
        .map(|parameter| (parameter.name.clone(), parameter.values.iter().map(|number| f64::from(*number)).collect()))
        .collect();
    let shapes = response.gradients.iter().map(|p| (p.name.clone(), p.shape.iter().map(|size| u64::from(*size)).collect())).collect();
    (values, shapes)
}

/// `validate_response(request, response, admission, window, release)`: the authenticated window response.
pub fn validate_response(
    request: &ComputeSemanticGradientsRequest,
    response: &ComputeSemanticGradientsResponse,
    admission: &Expectations,
    window: &Window,
    release: &Release,
) -> Result<Trace> {
    if request.layers != [SEMANTIC_LAYER]
        || response.request_id != request.request_id
        || response.model_id != request.model_id
        || response.base_version.is_empty()
        || !response.error.is_empty()
    {
        return invalid("Window RPC identity/explicit semantic-only execution differs.");
    }
    let metadata: Metadata = response.metadata.iter().map(|(key, text)| (key.clone(), text.clone())).collect();
    validate_admission(admission, &metadata)?;
    let wire = |rows: &[privoke_contracts::proto::v1::RuntimeTrainingExample]| -> Vec<(String, u32, f64)> {
        rows.iter()
            .filter(|row| row.has_target)
            .map(|row| (row.text.clone(), row.target.as_ref().map_or(0, |t| t.packed), row.weight))
            .collect()
    };
    let frozen = |rows: Vec<&Row>| -> Vec<(String, u32, f64)> {
        rows.into_iter().map(|row| (row.text.clone(), u32::from(row.packed), row.weight)).collect()
    };
    if wire(&request.examples) != frozen(window.rows()) || wire(&request.heldout_examples) != frozen(window.guard.iter().collect()) {
        return invalid("Physical request differs from frozen ordered wire rows.");
    }
    let names: BTreeSet<&str> = response.gradients.iter().map(|parameter| parameter.name.as_str()).collect();
    if names.len() != response.gradients.len() {
        return invalid("Duplicate selected tensor delta.");
    }
    let (gradients, shapes) = tensor_maps(response);
    let config = parse(metadata.get("model_config").ok_or_else(|| Error("'model_config'".to_string()))?)?;
    if config != parse(&release.teacher_config.to_string())? {
        return invalid("Returned complete CURRENT config/readout differs from authenticated ORIGINAL references.");
    }
    crate::runtime::validate_readout_identity(metadata.get("architecture").ok_or_else(|| Error("'architecture'".to_string()))?, &config)?;
    let expected = crate::runtime::full_encoder_tensor_shapes(&config)?;
    if metadata.get("training_scope").map(String::as_str) != Some("full_encoder")
        || metadata.get("executed_contextual_training_optimizer").map(String::as_str) != Some(WINDOW_POLICY)
    {
        return invalid("Window route requires actual FULL execution.");
    }
    let inventory = |name: &String, shape: &Vec<u64>| -> bool {
        gradients.get(name).is_some_and(|values| {
            values.len() as u64 == shape.iter().product::<u64>() && values.iter().all(|number| number.is_finite() && number.abs() <= 0.05)
        })
    };
    if !gradients.is_empty() && (shapes != expected || !expected.iter().all(|(name, shape)| inventory(name, shape))) {
        return invalid("Selected FULL tensor inventory/shapes/cap differs.");
    }
    let trained = parse(metadata.get("trained_parameter_names").ok_or_else(|| Error("'trained_parameter_names'".to_string()))?)?;
    let sorted: Vec<Value> = expected.keys().map(|name| value::string(name)).collect();
    let empty: BTreeMap<String, Vec<f64>> = expected.keys().map(|name| (name.clone(), Vec::new())).collect();
    let inventory_fingerprint = parameter_fingerprint(&empty, Some(&expected)).map_err(contract_error)?;
    if trained != Value::Array(sorted)
        || metadata.get("trained_parameter_inventory_fingerprint").map(String::as_str) != Some(inventory_fingerprint.as_str())
    {
        return invalid("Window output inventory differs from independently derived architecture.");
    }
    let trace = validate_trace(&metadata, window, release, &gradients, &expected)?;
    let phases = execution_phases(&trace.value)?;
    let phase_ok = response.executions.len() == phases.len()
        && response.executions.iter().zip(&phases).all(|(run, (name, count))| {
            &run.phase == name && i64::from(run.examples) == *count && run.layer == 4 && run.status == "ok" && run.error.is_empty()
        });
    if !phase_ok {
        return invalid("Window response actual semantic phases/counts differ.");
    }
    let checkpoints = checkpoints_of(&trace.value)?;
    let step = int_of(value::get(&trace.value, "selected_step")).unwrap_or(0);
    let selected =
        checkpoints.iter().find(|row| i64::try_from(row.step).ok() == Some(step)).ok_or_else(|| Error("StopIteration".to_string()))?;
    let targets: Vec<u16> = window.rows().iter().map(|row| row.packed).collect();
    let expected_metrics: BTreeMap<String, f64> = BTreeMap::from([
        ("examples".to_string(), 512.0),
        ("candidate_train_exact_match_rate".to_string(), packed_exact_rate(&targets, selected)?),
        ("exact_match_rate".to_string(), packed_exact_rate(&targets, &checkpoints[0])?),
        ("candidate_train_objective_loss".to_string(), selected.loss),
        ("base_train_objective_loss".to_string(), checkpoints[0].loss),
    ]);
    let actual: BTreeMap<String, f64> = response.metrics.iter().map(|(key, number)| (key.clone(), *number)).collect();
    if actual != expected_metrics {
        return invalid("Window selected metrics differ from retained TRAIN scores.");
    }
    Ok(trace)
}

/// `persist_inputs(window, release, directory)`: the immutable window and component bytes the response was bound to.
pub fn persist_inputs(window: &Value, components: &Components, directory: &Path) -> std::result::Result<Value, crate::attempts::Failure> {
    let encoder = base64::engine::general_purpose::STANDARD;
    let record = value::object(vec![
        ("schema", value::int(1)),
        ("window", window.clone()),
        ("bank", value::string(&encoder.encode(&components.bank))),
        ("references", value::string(&encoder.encode(&components.references))),
        ("manifest", value::string(&encoder.encode(&components.manifest))),
        ("teacher_path", value::string(&components.teacher_path)),
        ("teacher_sha256", value::string(&components.teacher_sha256)),
    ]);
    let digest = value::sha256(&value::canonical_bytes(window)?);
    let path = crate::attempts::write_attempt(&directory.join("window-inputs").join(digest), &record)?;
    let bytes = std::fs::read(&path)?;
    Ok(value::object(vec![("path", value::string(&path.display().to_string())), ("sha256", value::string(&value::sha256(&bytes)))]))
}

/// `retained_inputs(evidence)`: the original retained bytes, re-authenticated against the independently configured pins.
pub fn retained_inputs(evidence: &Value, pins: &Pins) -> Result<(Window, Release)> {
    let path = text_of(evidence, "path").ok_or_else(|| Error("'path'".to_string()))?;
    let raw = std::fs::read(path)?;
    if value::sha256(&raw) != text_of(evidence, "sha256").unwrap_or_default() {
        return invalid("Retained window/component input bytes differ.");
    }
    let record = value::parse_bytes(&raw)?;
    let decoded = |name: &str| -> Result<Vec<u8>> {
        base64::engine::general_purpose::STANDARD
            .decode(text_of(&record, name).unwrap_or_default())
            .map_err(|error| Error(error.to_string()))
    };
    let (bank, references, manifest) = (decoded("bank")?, decoded("references")?, decoded("manifest")?);
    let teacher_path = text_of(&record, "teacher_path").unwrap_or_default().to_string();
    let teacher_sha256 = text_of(&record, "teacher_sha256").unwrap_or_default().to_string();
    let window_payload = value::canonical_bytes(field(&record, "window")?)?;
    let differs = || Error("Retained inputs differ from independently configured accepted window/component/teacher pins.".to_string());
    if pins.window.as_deref() != Some(value::sha256(&window_payload).as_str())
        || pins.component.as_deref() != Some(value::sha256(&manifest).as_str())
        || pins.teacher.as_deref() != Some(teacher_sha256.as_str())
    {
        return Err(differs());
    }
    let window = Window::parse(&window_payload, pins.window.as_deref().unwrap_or_default()).map_err(contract_error)?;
    let components = authenticate(bank, references, manifest, &teacher_path, &teacher_sha256, pins.component.as_deref(), None)?;
    Ok((window, components.release))
}

fn decode_text(evidence: &Value, name: &str) -> Result<Vec<u8>> {
    base64::engine::general_purpose::STANDARD.decode(text_of(evidence, name).unwrap_or_default()).map_err(|error| Error(error.to_string()))
}

/// `validate_update(update)`: the retained physical attempt, the raw request and response and the update are one and the same.
pub fn validate_update(update: &BatchUpdate, pins: &Pins) -> Result<Trace> {
    let evidence = &update.execution_evidence;
    let attempt = text_of(evidence, "physical_attempt").ok_or_else(|| Error("'physical_attempt'".to_string()))?;
    let record = value::parse_bytes(&std::fs::read(attempt)?)?;
    for key in ["request_protobuf_base64", "response_protobuf_base64", "invocation_metadata"] {
        if value::get(&record, key) != value::get(evidence, key) {
            return invalid("Window retained physical attempt differs from raw request/response/header.");
        }
    }
    let request =
        ComputeSemanticGradientsRequest::decode(decode_text(evidence, "request_protobuf_base64")?.as_slice()).map_err(contract_error)?;
    let response =
        ComputeSemanticGradientsResponse::decode(decode_text(evidence, "response_protobuf_base64")?.as_slice()).map_err(contract_error)?;
    let layers = Value::Array(vec![value::int(4)]);
    if text_of(&record, "request_protobuf_sha256") != Some(value::sha256(&request.encode_to_vec()).as_str())
        || text_of(&record, "request_id") != Some(request.request_id.as_str())
        || text_of(&record, "model_id") != Some(request.model_id.as_str())
        || text_of(&record, "training_stage") != Some("full_encoder")
        || value::get(evidence, "request_layers") != Some(&layers)
    {
        return invalid("Window physical attempt identity/hash/semantic selection differs.");
    }
    let (gradients, shapes) = tensor_maps(&response);
    let held: BTreeMap<String, Vec<f64>> = update.gradients.iter().cloned().collect();
    let held_shapes: BTreeMap<String, Vec<u64>> =
        update.shapes.iter().map(|(name, shape)| (name.clone(), shape.iter().map(|size| u64::from(*size)).collect())).collect();
    let metadata: Metadata = response.metadata.iter().map(|(key, text)| (key.clone(), text.clone())).collect();
    let metrics: BTreeMap<String, f64> = response.metrics.iter().map(|(key, number)| (key.clone(), *number)).collect();
    if metadata != update.metadata
        || metrics != update.metrics
        || gradients != held
        || shapes != held_shapes
        || update.model_id != response.model_id
        || update.base_version != response.base_version
        || text_of(evidence, "rpc") != Some("ComputeUnderlyingModelGradients")
    {
        return invalid("Window update differs from actual immutable runtime response.");
    }
    let (window, release) = retained_inputs(field(evidence, "window_inputs")?, pins)?;
    let header = value::get(evidence, "invocation_metadata")
        .and_then(value::as_array)
        .and_then(|pairs| pairs.first())
        .and_then(value::as_array)
        .and_then(|pair| pair.get(1))
        .and_then(value::as_str)
        .ok_or_else(|| Error("'invocation_metadata'".to_string()))?;
    let admission = crate::policy::parse_training_admission_header(header)?;
    validate_response(&request, &response, &admission, &window, &release)
}

/// `validate_training_update` for a window update: only a selected checkpoint above the minimum publishes.
pub fn validate_publishable(update: &BatchUpdate, pins: &Pins, minimum: f64) -> Result<()> {
    let trace = validate_update(update, pins)?;
    let exact =
        update.metrics.get("candidate_train_exact_match_rate").ok_or_else(|| Error("'candidate_train_exact_match_rate'".to_string()))?;
    if trace.status != "selected" || *exact <= minimum {
        return invalid("Window policy has no publishable sensitive-progress checkpoint.");
    }
    Ok(())
}

/// `publication_metadata(update, metadata, extra, directory)`: the compact publication, bound to the retained complete cycle.
pub fn publication_metadata(
    update: &BatchUpdate,
    metadata: BTreeMap<String, String>,
    extra: &BTreeMap<String, String>,
    directory: Option<&Path>,
    pins: &Pins,
) -> Result<BTreeMap<String, String>> {
    let trace = validate_update(update, pins)?;
    if trace.status != "selected" {
        return invalid("BASE/no_update outcome cannot publish parameters.");
    }
    let key = |name: &str| extra.get(name).cloned().ok_or_else(|| Error(format!("'{name}'")));
    let request = privoke_contracts::proto::v1::FuzzerTrainingRequest {
        source_id: key("request_source_id")?,
        request_id: key("request_id")?,
        ..Default::default()
    };
    let directory = directory.ok_or_else(|| Error("Window publication requires durable evidence.".to_string()))?;
    let path = directory
        .join("training-cycles")
        .join(crate::evidence::cycle_identity(&request, "full_encoder")?)
        .join(format!("{}.json", trace.base));
    let retained = value::parse_bytes(&std::fs::read(path)?)?;
    let strings = |name: &str| value::get(&retained, name).and_then(value::as_str);
    let held_metrics = Value::Object(update.metrics.iter().map(|(name, number)| (name.clone(), Value::Float(*number))).collect());
    if value::get(&retained, "metadata") != Some(&value::from_string_map(&update.metadata))
        || value::get(&retained, "metrics") != Some(&held_metrics)
        || value::get(&retained, "execution_evidence") != Some(&update.execution_evidence)
        || value::get(&retained, "gate_passed") != Some(&Value::Bool(true))
        || strings("request_id") != Some(request.request_id.as_str())
        || strings("source_id") != Some(request.source_id.as_str())
        || strings("model_id") != Some(update.model_id.as_str())
        || strings("base_version") != Some(update.base_version.as_str())
        || strings("training_stage") != Some("full_encoder")
    {
        return invalid("Publication differs from durably retained completed cycle.");
    }
    let mut result = metadata;
    result.remove(TRACE_KEY);
    let bound = value::object(
        ["metadata", "metrics", "execution_evidence", "gate_passed", "request_id", "source_id", "model_id", "base_version"]
            .iter()
            .map(|name| (*name, value::get(&retained, name).cloned().unwrap_or(Value::Null)))
            .collect(),
    );
    result.insert("training_evidence_sha256".to_string(), value::sha256(canonical(&bound)?.as_bytes()));
    if result.len() > 64 || result.values().any(|text| text.len() > 2048) {
        return invalid("Window compact publication exceeds unchanged metadata quota.");
    }
    Ok(result)
}

/// The prompt count of a window cycle.
pub const WINDOW_PROMPTS: i64 = PROMPTS;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn artifact() -> Metadata {
        let mut metadata = Metadata::new();
        for (key, text) in [
            ("contextual_training_optimizer", WINDOW_POLICY),
            ("contextual_training_strategy", FULL_ENCODER_STRATEGY),
            ("contextual_training_objective", SUM_MARGIN),
            ("contextual_candidate_eligibility", WINDOW_ELIGIBILITY),
            (CONFIG_KEY, WINDOW_CONFIG_CANONICAL),
        ] {
            metadata.insert(key.to_string(), text.to_string());
        }
        metadata.insert(WINDOW_KEY.to_string(), "a".repeat(64));
        metadata.insert(REFERENCE_KEY.to_string(), "b".repeat(64));
        metadata
    }

    fn admission(window: &str, component: &str) -> Expectations {
        let mut request = Metadata::new();
        for (key, text) in [
            ("expected_contextual_training_optimizer", WINDOW_POLICY),
            ("expected_contextual_training_objective", SUM_MARGIN),
            ("expected_contextual_candidate_eligibility", WINDOW_ELIGIBILITY),
            ("expected_contextual_training_scope", "full_encoder"),
            ("expected_train_window_config_v1", WINDOW_CONFIG_CANONICAL),
            ("expected_train_window_manifest_sha256", window),
            ("expected_original_train_component_manifest_sha256", component),
        ] {
            request.insert(key.to_string(), text.to_string());
        }
        crate::policy::window_expectations(&request).unwrap().unwrap()
    }

    #[test]
    fn the_artifact_policy_is_exact_and_exclusive() {
        assert!(validate_policy(&artifact()).unwrap());
        let mut foreign = artifact();
        foreign.insert("full_projected_adam_config_v1".to_string(), "{}".to_string());
        assert_eq!(
            validate_policy(&foreign).unwrap_err().0,
            "Window policy requires exact exclusive FULL optimizer/objective/config/pins."
        );
        let mut short = artifact();
        short.insert(WINDOW_KEY.to_string(), "short".to_string());
        assert!(validate_policy(&short).is_err());
        let mut orphan = Metadata::new();
        assert!(!validate_policy(&orphan).unwrap());
        orphan.insert(WINDOW_KEY.to_string(), "a".repeat(64));
        assert_eq!(validate_policy(&orphan).unwrap_err().0, "Orphan window/checkpoint artifact policy.");
    }

    #[test]
    fn the_artifact_must_carry_exactly_the_admitted_settings() {
        validate_admission(&admission(&"a".repeat(64), &"b".repeat(64)), &artifact()).unwrap();
        assert_eq!(
            validate_admission(&admission(&"c".repeat(64), &"b".repeat(64)), &artifact()).unwrap_err().0,
            "Window artifact differs from admitted effective settings."
        );
        assert_eq!(
            validate_admission(&admission(&"a".repeat(64), &"b".repeat(64)), &Metadata::new()).unwrap_err().0,
            "Window artifact requires explicit matching pre-gradient admission."
        );
    }

    #[test]
    fn pins_come_from_the_configuration() {
        let config = FuzzerConfig::from_lookup(|name| match name {
            "FUZZ_WINDOW_MANIFEST_SHA256" => Some("w".to_string()),
            "FUZZ_COMPONENT_MANIFEST_SHA256" => Some("c".to_string()),
            "FUZZ_COMPONENT_TEACHER_SHA256" => Some("t".to_string()),
            _ => None,
        })
        .unwrap();
        assert_eq!(
            Pins::of(&config),
            Pins { window: Some("w".to_string()), component: Some("c".to_string()), teacher: Some("t".to_string()) }
        );
    }

    #[test]
    fn a_window_needs_an_explicit_pinned_path() {
        assert_eq!(
            read_pinned(None, Some(&"a".repeat(64))).unwrap_err().0,
            "Window/reference requires explicit non-symlink path and independently configured SHA256."
        );
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("window.json");
        std::fs::write(&path, b"{\"a\": 1}\n").unwrap();
        assert_eq!(read_pinned(Some(&path), Some(&"a".repeat(64))).unwrap_err().0, "Canonical immutable release differs from trusted pin.");
        let canonical = b"{\"a\":1}\n";
        std::fs::write(&path, canonical).unwrap();
        assert_eq!(read_pinned(Some(&path), Some(&value::sha256(canonical))).unwrap(), canonical);
    }

    #[test]
    fn the_exact_rate_counts_the_packed_hits_of_the_checkpoint() {
        let checkpoint = Checkpoint {
            step: 8,
            fingerprint: String::new(),
            counts: BTreeMap::new(),
            loss: 0.0,
            predictions: vec![(1, 0.5), (2, 0.5), (3, 0.5), (4, 0.5)],
            original_predictions: Vec::new(),
            violations: 0,
            component_violations: [0; 5],
        };
        assert_eq!(packed_exact_rate(&[1, 2, 0, 0], &checkpoint).unwrap(), 0.5);
        assert_eq!(packed_exact_rate(&[1], &checkpoint).unwrap_err().0, "Exact TRAIN metric membership differs.");
    }

    #[test]
    fn the_phases_follow_the_recorded_work_in_the_contract_order() {
        let mut recorded: Vec<(String, Value)> = Vec::new();
        for step in std::iter::once(0usize).chain(contract::CHECKPOINTS) {
            for part in ["window", "original_train"] {
                recorded.push((format!("checkpoint_{step}_{part}"), value::object(vec![("rows_completed", value::int(7))])));
            }
        }
        let trace = |guard: Value| {
            value::object(vec![
                ("main", value::object(vec![("rows_completed", value::int(4096))])),
                ("auxiliary", value::object(vec![("rows_completed", value::int(640))])),
                ("guard", guard),
                (
                    "work",
                    value::object(vec![(
                        "phases",
                        Value::Object(
                            recorded
                                .iter()
                                .cloned()
                                .chain([
                                    ("base_heldout".to_string(), value::object(vec![("rows_completed", value::int(16))])),
                                    ("candidate_heldout".to_string(), value::object(vec![("rows_completed", value::int(16))])),
                                ])
                                .collect(),
                        ),
                    )]),
                ),
            ])
        };
        let without = execution_phases(&trace(Value::Null)).unwrap();
        assert_eq!(without.len(), 2 + 18);
        assert_eq!(without[2], ("checkpoint_0_window".to_string(), 7));
        assert_eq!(without[19], ("checkpoint_64_original_train".to_string(), 7));
        let with = execution_phases(&trace(value::object::<&str>(vec![]))).unwrap();
        assert_eq!(&with[20..], [("base_heldout".to_string(), 16), ("candidate_heldout".to_string(), 16)]);
    }
}
