//! ORIGINAL retention evidence: `privoke_model/sensitive_retention.py` (the raw trace, the bounded summary and the extra
//! execution phases) and `training/sensitive_retention_evidence.py` (the retained release snapshot and its binding to the actual
//! ordered TRAIN rows). The release itself is authenticated by [`privoke_training::retention::Release::load`].
//!
//! The retention policies add an auxiliary safety pass over the eligible ORIGINAL TRAIN references to the FULL Adam fit.
//! A retention update is published only if no eligible row violates its target-capped per-row predicate.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use privoke_contracts::json::{self, Value};
use privoke_curriculum::classification::{Classification, sensitivity_value};
use privoke_curriculum::value;
use privoke_training::retention::{GATE_POLICY, HINGE_POLICY, Release};

use crate::error::{Error, Result, invalid};
use crate::full_adam::{self, ELIGIBILITY, ELIGIBILITY_KEY, EXECUTED_KEY, OPTIMIZER_KEY, SUMMARY_KEY};
use crate::policy::{FULL_ADAM_POLICY, Metadata};

/// `MANIFEST_KEY`.
pub const MANIFEST_KEY: &str = "original_train_retention_manifest_sha256";
/// `TRACE_KEY`.
pub const TRACE_KEY: &str = "original_train_retention_trace_v1";
/// `SUMMARY_KEY` of the retention policies.
pub const RETENTION_SUMMARY_KEY: &str = "original_train_retention_summary_v1";
const MAX_TRACE_BYTES: usize = 524_288;

fn canonical(document: &Value) -> Result<String> {
    Ok(value::dumps_compact(document)?)
}

fn parse(text: &str) -> Result<Value> {
    json::parse(text).map_err(|error| Error(error.to_string()))
}

fn keys(document: &Value) -> BTreeSet<&str> {
    value::as_object(document).map(|map| map.keys().map(String::as_str).collect()).unwrap_or_default()
}

/// A JSON integer (`type(x) is int`, a boolean excluded) in `low..=high`.
fn int_in(document: Option<&Value>, low: i64, high: i64) -> bool {
    matches!(document, Some(Value::Int(digits)) if digits.parse::<i64>().is_ok_and(|number| (low..=high).contains(&number)))
}

/// `type(x) in (int, float)` and finite.
fn finite(document: Option<&Value>) -> Option<f64> {
    match document {
        Some(Value::Int(_)) => document.and_then(value::as_number),
        Some(Value::Float(number)) if number.is_finite() => Some(*number),
        _ => None,
    }
}

fn is_retention(policy: &str) -> bool {
    policy == GATE_POLICY || policy == HINGE_POLICY
}

/// `execution_phases(metadata)`: only a validated bounded summary may extend the three-phase contract.
pub fn execution_phases(metadata: &Metadata) -> Result<Vec<(&'static str, usize)>> {
    let raw = metadata.get(RETENTION_SUMMARY_KEY).ok_or_else(|| Error(format!("'{RETENTION_SUMMARY_KEY}'")))?;
    let summary = parse(raw)?;
    let count = match value::get(&summary, "eligible") {
        Some(Value::Int(digits)) => digits.parse::<i64>().ok(),
        Some(_) => None,
        None => return invalid("'eligible'"),
    };
    let Some(count) = count.filter(|count| (20..=200).contains(count)) else {
        return invalid("Retention auxiliary execution count differs.");
    };
    let count = usize::try_from(count).unwrap_or(0);
    let mut phases = vec![("base_original_train_safety", count), ("original_train_safety", count)];
    if metadata.get(OPTIMIZER_KEY).map(String::as_str) == Some(HINGE_POLICY) {
        phases.insert(0, ("original_train_hinge", 64 * count));
    }
    Ok(phases)
}

/// The per-row fields and the target-capped predicate of one safety row.
fn validate_safety_row(row: &Value) -> Result<()> {
    let malformed = || Error("Malformed target-capped per-row safety trace.".to_string());
    let names: BTreeSet<&str> = [
        "id",
        "gold",
        "original",
        "candidate",
        "original_confidence",
        "candidate_confidence",
        "gold_action",
        "original_action",
        "candidate_action",
        "violation",
        "original_margin",
        "candidate_margin",
        "hinge",
    ]
    .into_iter()
    .collect();
    if keys(row) != names
        || !["gold", "original", "candidate"].iter().all(|name| int_in(value::get(row, name), 0, 65_535))
        || !["gold_action", "original_action", "candidate_action"].iter().all(|name| int_in(value::get(row, name), 0, 2))
        || !["original_confidence", "candidate_confidence"].iter().all(|name| {
            finite(value::get(row, name))
                .is_some_and(|number| (0.0..=0.999).contains(&number) && format!("{number:.3}").parse::<f64>().ok() == Some(number))
        })
        || !matches!(value::get(row, "violation"), Some(Value::Bool(_)))
    {
        return Err(malformed());
    }
    let margins = ["original_margin", "candidate_margin", "hinge"].map(|name| finite(value::get(row, name)));
    let [Some(original), Some(candidate), Some(hinge)] = margins else {
        return invalid("Retention raw per-row margin/exact hinge differs.");
    };
    if hinge != (original - candidate).max(0.0) {
        return invalid("Retention raw per-row margin/exact hinge differs.");
    }
    let number = |name: &str| value::get(row, name).and_then(value::as_i64).unwrap_or(0);
    let (target, source, selected) = (
        Classification::from_packed(number("gold")),
        Classification::from_packed(number("original")),
        Classification::from_packed(number("candidate")),
    );
    let level = |classification: Classification| sensitivity_value(classification.sensitivity()).unwrap_or(0);
    let violation = !selected.is_sensitive()
        || level(selected) < level(target).min(level(source))
        || number("candidate_action") < number("gold_action").min(number("original_action"));
    if value::get(row, "violation") != Some(&Value::Bool(violation)) {
        return invalid("Per-row target-capped safety predicate differs.");
    }
    Ok(())
}

fn validate_auxiliary(policy: &str, auxiliary: &Value, count: usize) -> Result<()> {
    if keys(auxiliary) != ["counts", "steps"].into_iter().collect() {
        return invalid("Retention auxiliary work schema differs.");
    }
    let counts = value::get(auxiliary, "counts").cloned().unwrap_or(Value::Null);
    let steps = value::get(auxiliary, "steps").and_then(value::as_array);
    if policy == GATE_POLICY {
        let empty = value::as_object(&counts).is_some_and(|map| map.is_empty()) && steps.is_some_and(|rows| rows.is_empty());
        if !empty {
            return invalid("Gate-only control must not perform padded auxiliary gradients.");
        }
        return Ok(());
    }
    let batches = count.div_ceil(32) as i64;
    let rows = count as i64;
    let expected = [
        ("directions_attempted", 64),
        ("directions_completed", 64),
        ("rows_attempted", 64 * rows),
        ("rows_completed", 64 * rows),
        ("microbatch_forward_attempted", 64 * batches),
        ("microbatch_forward_completed", 64 * batches),
        ("microbatch_backward_started", 64 * batches),
        ("microbatch_backward_completed", 64 * batches),
    ];
    if expected.iter().any(|(name, number)| value::get(&counts, name).and_then(value::as_i64) != Some(*number))
        || steps.is_none_or(|rows| rows.len() != 64)
    {
        return invalid("Retention actual auxiliary work count differs.");
    }
    let step_names: BTreeSet<&str> = [
        "step",
        "main_loss",
        "auxiliary_loss",
        "main_gradient_norm",
        "auxiliary_gradient_norm",
        "gradient_dot",
        "active_rows",
        "maximum_hinge",
        "original_state_parity_scaled_error",
    ]
    .into_iter()
    .collect();
    for (index, step) in steps.unwrap_or(&Vec::new()).iter().enumerate() {
        let numeric = ["main_loss", "auxiliary_loss", "main_gradient_norm", "auxiliary_gradient_norm", "gradient_dot", "maximum_hinge"];
        let parity = value::get(step, "original_state_parity_scaled_error");
        let parity_ok = match parity {
            Some(Value::Null) => true,
            other => finite(other).is_some_and(|number| number >= 0.0),
        };
        let numbers_ok =
            numeric.iter().all(|name| finite(value::get(step, name)).is_some_and(|number| *name == "gradient_dot" || number >= 0.0));
        if keys(step) != step_names
            || value::get(step, "step").and_then(value::as_i64) != Some(index as i64 + 1)
            || !numbers_ok
            || !int_in(value::get(step, "active_rows"), 0, count as i64)
            || !parity_ok
        {
            return invalid("Malformed independently normalized main/auxiliary diagnostics.");
        }
    }
    Ok(())
}

/// `sensitive_retention.validate_trace`: the retention policy's raw trace and bounded summary. The embedded FULL Adam recurrence
/// is validated by the plain FULL Adam rules over a metadata copy that names it.
pub fn validate_trace(
    metadata: &Metadata,
    scope: &str,
    examples: usize,
    candidate_fingerprint: &str,
    delta_fingerprint: &str,
) -> Result<Option<Value>> {
    privoke_training::admission::validate_policy(metadata).map_err(|error| Error(error.to_string()))?;
    let policy = metadata.get(OPTIMIZER_KEY).ok_or_else(|| Error(format!("'{OPTIMIZER_KEY}'")))?;
    if scope != "full_encoder" || metadata.get(EXECUTED_KEY) != Some(policy) {
        return invalid("Retention requires actual FULL execution; HEAD is not admitted.");
    }
    let Some(raw) = metadata.get(TRACE_KEY).filter(|raw| raw.len() <= MAX_TRACE_BYTES) else {
        return invalid("Missing or excessive ORIGINAL retention raw trace.");
    };
    let trace = parse(raw)?;
    let manifest = metadata.get(MANIFEST_KEY).ok_or_else(|| Error(format!("'{MANIFEST_KEY}'")))?;
    let names: BTreeSet<&str> = ["schema", "policy", "manifest_sha256", "adam", "auxiliary", "base_safety", "safety"].into_iter().collect();
    if raw != &canonical(&trace)?
        || keys(&trace) != names
        || value::get(&trace, "schema") != Some(&value::int(1))
        || value::get(&trace, "policy") != Some(&value::string(policy))
        || value::get(&trace, "manifest_sha256") != Some(&value::string(manifest))
    {
        return invalid("Retention trace identity differs from immutable admission.");
    }
    let adam = value::get(&trace, "adam").cloned().unwrap_or(Value::Null);
    let adam_field = |name: &str| value::get(&adam, name).cloned().unwrap_or(Value::Null);
    let adam_text = canonical(&adam)?;
    let mut base_meta = metadata.clone();
    base_meta.insert(OPTIMIZER_KEY.to_string(), FULL_ADAM_POLICY.to_string());
    base_meta.insert(ELIGIBILITY_KEY.to_string(), ELIGIBILITY.to_string());
    base_meta.insert(EXECUTED_KEY.to_string(), FULL_ADAM_POLICY.to_string());
    base_meta.insert(full_adam::TRACE_KEY.to_string(), adam_text.clone());
    base_meta.remove(MANIFEST_KEY);
    base_meta.insert(
        SUMMARY_KEY.to_string(),
        canonical(&value::object(vec![
            ("schema", value::int(1)),
            ("policy", value::string(FULL_ADAM_POLICY)),
            ("trace_sha256", value::string(&value::sha256(adam_text.as_bytes()))),
            ("base", adam_field("base")),
            ("final", adam_field("final")),
            ("delta", adam_field("delta")),
            ("counts", adam_field("counts")),
            ("eligibility", value::string(ELIGIBILITY)),
            ("metric", value::string("candidate_train_exact_match_rate")),
        ]))?,
    );
    full_adam::validate_trace(&base_meta, scope, examples, candidate_fingerprint, delta_fingerprint)?;
    let safety = value::get(&trace, "safety").and_then(value::as_array);
    let distinct = |rows: &Vec<Value>| {
        rows.iter().filter_map(|row| value::get(row, "id").and_then(value::as_str)).collect::<BTreeSet<_>>().len() == rows.len()
    };
    let Some(safety) = safety.filter(|rows| (20..=200).contains(&rows.len()) && distinct(rows)) else {
        return invalid("Retention safety trace requires distinct eligible rows.");
    };
    let base_safety = value::get(&trace, "base_safety").and_then(value::as_array);
    let ids = |rows: &Vec<Value>| rows.iter().map(|row| value::get(row, "id").cloned()).collect::<Vec<_>>();
    if base_safety.is_none_or(|rows| rows.len() != safety.len() || ids(rows) != ids(safety)) {
        return invalid("Retention base/final auxiliary membership differs.");
    }
    for row in base_safety.unwrap_or(&Vec::new()).iter().chain(safety) {
        validate_safety_row(row)?;
    }
    let auxiliary = value::get(&trace, "auxiliary").cloned().unwrap_or(Value::Null);
    validate_auxiliary(policy, &auxiliary, safety.len())?;
    let violations = safety.iter().filter(|row| value::get(row, "violation") == Some(&Value::Bool(true))).count() as i64;
    let summary = value::object(vec![
        ("schema", value::int(1)),
        ("policy", value::string(policy)),
        ("manifest_sha256", value::string(manifest)),
        ("trace_sha256", value::string(&value::sha256(raw.as_bytes()))),
        ("base", adam_field("base")),
        ("final", adam_field("final")),
        ("delta", adam_field("delta")),
        ("eligible", value::int(safety.len() as i64)),
        ("violations", value::int(violations)),
        ("auxiliary", value::get(&auxiliary, "counts").cloned().unwrap_or(Value::Null)),
    ]);
    let text = canonical(&summary)?;
    if metadata.get(RETENTION_SUMMARY_KEY) != Some(&text) || text.len() > 2048 {
        return invalid("Retention bounded summary differs from complete retained raw trace.");
    }
    Ok(Some(trace))
}

/// `validate_training_update`'s retention predicate: the bounded summary must report no violation.
pub fn require_no_violations(metadata: &Metadata) -> Result<()> {
    if !metadata.get(OPTIMIZER_KEY).is_some_and(|policy| is_retention(policy)) {
        return Ok(());
    }
    let summary = parse(metadata.get(RETENTION_SUMMARY_KEY).ok_or_else(|| Error(format!("'{RETENTION_SUMMARY_KEY}'")))?)?;
    if value::get(&summary, "violations").and_then(value::as_i64) != Some(0) {
        return invalid("ORIGINAL TRAIN target-capped per-row admission failed; no update published.");
    }
    Ok(())
}

/// `validate_source_bindings(metadata, release)`: reject changed membership, gold or ORIGINAL baseline, even if the aggregate
/// counts pass. The release was authenticated when it was loaded; here its manifest must be the one the update names.
pub fn validate_source_bindings(metadata: &Metadata, release: &Release) -> Result<()> {
    let manifest = metadata.get(MANIFEST_KEY).ok_or_else(|| Error(format!("'{MANIFEST_KEY}'")))?;
    if &release.sha256 != manifest {
        return invalid("Retention profile or requested immutable manifest pin differs.");
    }
    let trace = parse(metadata.get(TRACE_KEY).ok_or_else(|| Error(format!("'{TRACE_KEY}'")))?)?;
    for name in ["base_safety", "safety"] {
        let rows = value::get(&trace, name).and_then(value::as_array).ok_or_else(|| Error(format!("'{name}'")))?;
        if rows.len() != release.references.len() {
            return invalid("Retention actual safety membership differs from immutable eligible TRAIN.");
        }
        for (row, reference) in rows.iter().zip(&release.references) {
            let same = value::get(row, "id").and_then(value::as_str) == Some(reference.id.as_str())
                && value::get(row, "gold").and_then(value::as_i64) == Some(i64::from(reference.gold))
                && value::get(row, "original").and_then(value::as_i64) == Some(i64::from(reference.original))
                && value::get(row, "original_confidence").and_then(value::as_number) == Some(reference.confidence)
                && value::get(row, "original_margin").and_then(value::as_number) == Some(reference.margin);
            if !same {
                return invalid("Retention actual ordered TRAIN/gold/ORIGINAL baseline differs.");
            }
        }
    }
    Ok(())
}

/// The immutable bytes of an authenticated release: the three sidecars and the teacher's path, with the loaded release.
#[derive(Debug, Clone)]
pub struct Snapshot {
    /// The bank bytes.
    pub bank: Vec<u8>,
    /// The references bytes.
    pub references: Vec<u8>,
    /// The manifest bytes.
    pub manifest: Vec<u8>,
    /// The teacher artifact's path, as the retained evidence names it.
    pub teacher_path: String,
    /// The authenticated release.
    pub release: Release,
}

fn read_bytes(path: &Path) -> Result<Vec<u8>> {
    if std::fs::symlink_metadata(path)?.file_type().is_symlink() {
        return invalid("Retention requires four explicit non-symlink read-only sidecar paths.");
    }
    Ok(std::fs::read(path)?)
}

/// `load_release` and `validate_trusted_release`: four explicit sidecars, authenticated against the trusted manifest pin.
pub fn load_snapshot(bank: &Path, references: &Path, manifest: &Path, teacher: &Path, trusted_sha256: &str) -> Result<Snapshot> {
    let (bank, references, manifest, teacher_bytes) =
        (read_bytes(bank)?, read_bytes(references)?, read_bytes(manifest)?, read_bytes(teacher)?);
    let release = Release::load(&bank, &references, &manifest, &teacher_bytes, trusted_sha256).map_err(|error| Error(error.to_string()))?;
    Ok(Snapshot { bank, references, manifest, teacher_path: teacher.display().to_string(), release })
}

fn is_sha256(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

/// The release of a cycle: `load_release(bank, reference, manifest, teacher, model_id=..., expected_sha256=<the request's pin>)`
/// and then `validate_trusted_release(..., trusted_sha256=<the server's configured pin>)`, in the Python order.
///
/// [`Release::load`] fuses the structure checks with the trust anchor, so it runs with the manifest's own hash (which passes its
/// anchor) to check the structure, and the request pin, the model and the configured trust pin are compared afterwards with the
/// Python messages.
pub fn load_requested(paths: [Option<&Path>; 4], model_id: &str, request_pin: &str, trusted_sha256: Option<&str>) -> Result<Snapshot> {
    let given: Vec<&Path> = paths.iter().flatten().copied().collect();
    if given.len() != 4 || given.iter().any(|path| std::fs::symlink_metadata(path).is_ok_and(|meta| meta.file_type().is_symlink())) {
        return invalid("Retention requires four explicit non-symlink read-only sidecar paths.");
    }
    let (bank, references, manifest) = (std::fs::read(given[0])?, std::fs::read(given[1])?, std::fs::read(given[2])?);
    let teacher_bytes = std::fs::read(given[3])?;
    let release = Release::load(&bank, &references, &manifest, &teacher_bytes, &value::sha256(&manifest))
        .map_err(|error| Error(error.to_string()))?;
    if release.model_id != model_id || release.sha256 != request_pin {
        return invalid("Retention profile or requested immutable manifest pin differs.");
    }
    if !trusted_sha256.is_some_and(is_sha256) || trusted_sha256 != Some(request_pin) {
        return invalid("Retention requires a distinct trusted configured accepted manifest SHA, matching the request.");
    }
    Ok(Snapshot { bank, references, manifest, teacher_path: given[3].display().to_string(), release })
}

/// `persist_release(release, model_id)`: the immutable release evidence, retained before any compute.
pub fn persist_release(snapshot: &Snapshot, model_id: &str, directory: Option<&Path>) -> Result<Value> {
    if snapshot.release.model_id != model_id {
        return invalid("Retention profile or requested immutable manifest pin differs.");
    }
    let Some(directory) = directory else { return invalid("Retention requires durable release evidence before compute.") };
    let encoder = base64::engine::general_purpose::STANDARD;
    let sha256 = &snapshot.release.sha256;
    let path: PathBuf = directory.join("original-train-retention").join(sha256).join("release.json");
    let payload = value::canonical_bytes(&value::object(vec![
        ("schema", value::int(1)),
        ("manifest_sha256", value::string(sha256)),
        ("bank", value::string(&encoder.encode(&snapshot.bank))),
        ("references", value::string(&encoder.encode(&snapshot.references))),
        ("manifest", value::string(&encoder.encode(&snapshot.manifest))),
        ("teacher_path", value::string(&snapshot.teacher_path)),
    ]))?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if path.exists() {
        if std::fs::read(&path)? != payload {
            return invalid("Existing immutable retention release evidence differs.");
        }
    } else {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new().write(true).create_new(true).open(&path)?;
        file.write_all(&payload)?;
        file.flush()?;
        file.sync_all()?;
    }
    Ok(value::object(vec![
        ("path", value::string(&path.display().to_string())),
        ("sha256", value::string(&value::sha256(&payload))),
        ("manifest_sha256", value::string(sha256)),
    ]))
}

/// `retained_release(evidence, model_id)`: re-authenticate the retained release from its evidence record.
pub fn retained_release(evidence: &Value, model_id: &str) -> Result<Snapshot> {
    if keys(evidence) != ["path", "sha256", "manifest_sha256"].into_iter().collect() {
        return invalid("Missing retained ORIGINAL release identity.");
    }
    let text = |name: &str| value::get(evidence, name).and_then(value::as_str).unwrap_or_default().to_string();
    let payload = std::fs::read(text("path"))?;
    if value::sha256(&payload) != text("sha256") {
        return invalid("Retained ORIGINAL release bytes differ.");
    }
    let raw = value::parse_bytes(&payload)?;
    if value::canonical_bytes(&raw)? != payload {
        return invalid("Retention sidecar must be canonical JSON with one LF.");
    }
    let names: BTreeSet<&str> = ["schema", "manifest_sha256", "bank", "references", "manifest", "teacher_path"].into_iter().collect();
    if keys(&raw) != names || value::get(&raw, "schema") != Some(&value::int(1)) {
        return invalid("Retained ORIGINAL release schema differs.");
    }
    let decoded = |name: &str| -> Result<Vec<u8>> {
        let encoded = value::get(&raw, name).and_then(value::as_str).unwrap_or_default();
        base64::engine::general_purpose::STANDARD.decode(encoded).map_err(|error| Error(error.to_string()))
    };
    let (bank, references, manifest) = (decoded("bank")?, decoded("references")?, decoded("manifest")?);
    let teacher_path = value::get(&raw, "teacher_path").and_then(value::as_str).unwrap_or_default().to_string();
    let snapshot = load_snapshot_from_bytes(bank, references, manifest, &teacher_path, &text("manifest_sha256"))?;
    if snapshot.release.model_id != model_id {
        return invalid("Retention profile or requested immutable manifest pin differs.");
    }
    if value::get(&raw, "manifest_sha256").and_then(value::as_str) != Some(snapshot.release.sha256.as_str()) {
        return invalid("Retained ORIGINAL release manifest differs.");
    }
    Ok(snapshot)
}

fn load_snapshot_from_bytes(bank: Vec<u8>, references: Vec<u8>, manifest: Vec<u8>, teacher_path: &str, trusted: &str) -> Result<Snapshot> {
    let teacher = std::fs::read(teacher_path)?;
    let release = Release::load(&bank, &references, &manifest, &teacher, trusted).map_err(|error| Error(error.to_string()))?;
    Ok(Snapshot { bank, references, manifest, teacher_path: teacher_path.to_string(), release })
}
