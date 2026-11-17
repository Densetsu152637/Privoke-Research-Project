//! The guarded update path: the ported cases of `test_security_validation.py` and `test_update_receipts.py`, the injected
//! crash windows, the bootstrap cases of `test_model_bootstrap.py`, and the drift bounds that are new in Rust.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::path::Path;
use std::sync::Arc;

use common::{baseline_update, config_for, copy_model, engine, gradient, update, version_of};
use privoke_contracts::json::Value;
use privoke_contracts::proto::v1::{ParameterUpdateRequest, ParameterUpdateStatusRequest};
use privoke_param_update::artifact_io::{self, Loaded};
use privoke_param_update::bootstrap::{PREPARATION_CODE_REVISION, bootstrap_model, prepare_full_encoder_artifact};
use privoke_param_update::engine::{Engine, Hook, no_hook, system_clock};
use privoke_param_update::error::Failure;
use privoke_param_update::policy::DriftPolicy;
use privoke_param_update::receipts::{DRIFT_METADATA_KEY, DriftRecord, Receipt, ReceiptStore};
use privoke_param_update::validate::validate_parameter_update;

fn fail_receipt_put(only_base: Option<String>) -> Hook {
    Arc::new(move |phase: &str, detail: &str| -> Result<(), String> {
        let matches_base = only_base.as_deref().is_none_or(|base| base == detail);
        if phase == "receipt_put" && matches_base { Err("simulated interrupted commit".to_string()) } else { Ok(()) }
    })
}

fn status_request(fingerprint: &str) -> ParameterUpdateStatusRequest {
    ParameterUpdateStatusRequest {
        source_id: "fuzzer".into(),
        request_id: "cycle-1".into(),
        request_source_id: "experiment".into(),
        model_id: "privoke-baseline".into(),
        request_fingerprint: fingerprint.into(),
    }
}

// ---- validation and the guarded apply (test_security_validation.py)

#[test]
fn applies_an_update_to_the_versioned_artifact() {
    let directory = tempfile::tempdir().unwrap();
    let model = copy_model(directory.path(), "privoke-baseline");
    let engine = engine(directory.path(), &model, "privoke-baseline");
    let initial = artifact_io::load(&model).unwrap().typed;
    let revision = initial.metadata()["training_revision"].parse::<i64>().unwrap() + 1;
    let ack = engine.submit(&baseline_update(&initial.version, &[])).unwrap();
    let stored = artifact_io::load(&model).unwrap().typed;
    assert!(ack.accepted);
    assert_eq!(ack.applied_version, format!("{}+train.{revision}", initial.metadata()["release_version"]));
    assert_eq!(stored.version, ack.applied_version);
    assert_eq!(stored.metadata()["training_revision"], revision.to_string());
    assert_eq!(stored.metadata()["last_update_source"], "test-fuzzer");
    assert!(!stored.checksum.is_empty());
}

#[test]
fn a_stale_base_version_is_failed_precondition_and_changes_nothing() {
    let directory = tempfile::tempdir().unwrap();
    let model = copy_model(directory.path(), "privoke-baseline");
    let engine = engine(directory.path(), &model, "privoke-baseline");
    let before = std::fs::read(&model).unwrap();
    let failure = engine.submit(&baseline_update("v0.0.0-stale", &[])).unwrap_err();
    assert!(matches!(failure, Failure::Precondition(_)));
    assert_eq!(failure.message(), format!("Stale base_version 'v0.0.0-stale'; current version is '{}'.", version_of(&model)));
    assert_eq!(std::fs::read(&model).unwrap(), before);
}

#[test]
fn health_is_not_serving_when_storage_is_unwritable_and_serving_otherwise() {
    let directory = tempfile::tempdir().unwrap();
    let model = copy_model(directory.path(), "privoke-baseline");
    let healthy = engine(directory.path(), &model, "privoke-baseline");
    assert_eq!(healthy.health().status, "SERVING");
    assert_eq!(healthy.health().service, "param-update-service");
    assert!(directory.path().join("updates.jsonl").exists(), "the storage probe creates the audit file");

    let broken = tempfile::tempdir().unwrap();
    let model = copy_model(broken.path(), "privoke-baseline");
    let config = config_for(broken.path(), &model, "privoke-baseline", DriftPolicy::Off);
    std::fs::create_dir(&config.storage_path).unwrap();
    let engine = Engine::new(config, system_clock(), no_hook()).unwrap();
    assert_eq!(engine.health().status, "NOT_SERVING");
}

#[test]
fn rejects_a_same_size_but_wrong_artifact_shape() {
    let directory = tempfile::tempdir().unwrap();
    let model = copy_model(directory.path(), "privoke-baseline");
    let engine = engine(directory.path(), &model, "privoke-baseline");
    let mut request = baseline_update(&version_of(&model), &[]);
    request.gradients[0].shape = vec![1, 4];
    let failure = engine.submit(&request).unwrap_err();
    assert!(failure.message().contains("shape mismatch"), "{failure}");
}

#[test]
fn a_large_embedding_needs_the_validated_full_artifact_and_its_exact_shape() {
    let directory = tempfile::tempdir().unwrap();
    let source_path = copy_model(directory.path(), "privoke-balanced");
    let source = artifact_io::load(&source_path).unwrap();
    let prepared = prepare_full_encoder_artifact(&source, "v0.4.0+test", 1, &"a".repeat(40), max_tokens(&source)).unwrap();
    let full_path = directory.path().join("full.json");
    artifact_io::write_atomic(&full_path, &prepared).unwrap();
    let full = artifact_io::load(&full_path).unwrap();
    let tensor = &full.typed.parameters["token_embedding"];
    let mut request = update(
        "test-fuzzer",
        &full.typed.model_id,
        &full.typed.version,
        vec![gradient("token_embedding", &tensor.shape, &vec![0.0001; tensor.values.len()])],
        &[],
    );
    // Without an artifact, and against the legacy artifact, the tensor is over the 4,096-value bound.
    assert!(validate_parameter_update(&request, &full.typed.model_id, 1.0, None).is_err());
    assert!(validate_parameter_update(&request, &full.typed.model_id, 1.0, Some(&source.typed)).is_err());
    validate_parameter_update(&request, &full.typed.model_id, 1.0, Some(&full.typed)).unwrap();

    let engine = engine(directory.path(), &full_path, &full.typed.model_id);
    let ack = engine.submit(&request).unwrap();
    let stored = artifact_io::load(&full_path).unwrap();
    assert_eq!(stored.typed.version, ack.applied_version);
    assert_ne!(stored.typed.parameters["token_embedding"].values, tensor.values);

    request.gradients[0].shape = vec![1, u32::try_from(tensor.values.len()).unwrap()];
    assert!(validate_parameter_update(&request, &full.typed.model_id, 1.0, Some(&full.typed)).is_err());
}

// ---- receipts and the crash windows (test_update_receipts.py)

fn receipt_request(model: &Path) -> ParameterUpdateRequest {
    update(
        "fuzzer",
        "privoke-baseline",
        &version_of(model),
        vec![gradient("head.sensitivity.bias", &[4], &[0.0, 0.0, 0.0, 0.01])],
        &[
            ("request_id", "cycle-1"),
            ("request_source_id", "experiment"),
            ("training_request_fingerprint", "intent-1"),
            ("generated_prompt_count", "8"),
        ],
    )
}

fn audit_lines(directory: &Path) -> usize {
    std::fs::read_to_string(directory.join("updates.jsonl")).unwrap().lines().count()
}

#[test]
fn a_duplicate_update_and_a_restart_preserve_the_original_outcome() {
    let directory = tempfile::tempdir().unwrap();
    let model = copy_model(directory.path(), "privoke-baseline");
    let request = receipt_request(&model);
    let first = engine(directory.path(), &model, "privoke-baseline").submit(&request).unwrap();
    let published = std::fs::read(&model).unwrap();
    let second = engine(directory.path(), &model, "privoke-baseline").submit(&request).unwrap();
    assert_eq!(second.applied_version, first.applied_version);
    assert_eq!(std::fs::read(&model).unwrap(), published);
    assert_eq!(audit_lines(directory.path()), 1);
    let status = engine(directory.path(), &model, "privoke-baseline").status(&status_request("intent-1")).unwrap();
    assert!(status.found);
    assert_eq!(status.ack.unwrap().applied_version, first.applied_version);
    assert_eq!(status.prompts_generated, 8);
}

#[test]
fn conflicting_reuse_of_a_request_id_is_rejected_without_another_update() {
    let directory = tempfile::tempdir().unwrap();
    let model = copy_model(directory.path(), "privoke-baseline");
    let mut request = receipt_request(&model);
    engine(directory.path(), &model, "privoke-baseline").submit(&request).unwrap();
    let published = std::fs::read(&model).unwrap();
    request.gradients[0].values[3] = 0.02;
    let failure = engine(directory.path(), &model, "privoke-baseline").submit(&request).unwrap_err();
    assert!(failure.message().contains("different parameter update"), "{failure}");
    let mismatch = engine(directory.path(), &model, "privoke-baseline").status(&status_request("changed-intent")).unwrap_err();
    assert!(matches!(mismatch, Failure::AlreadyExists(_)));
    assert!(mismatch.message().contains("different training request"));
    assert_eq!(std::fs::read(&model).unwrap(), published);
}

fn engine_with_hook(directory: &Path, model: &Path, hook: Hook) -> Engine {
    Engine::new(config_for(directory, model, "privoke-baseline", DriftPolicy::Off), system_clock(), hook).unwrap()
}

#[test]
fn the_model_commit_recovers_after_a_receipt_database_failure() {
    let directory = tempfile::tempdir().unwrap();
    let model = copy_model(directory.path(), "privoke-baseline");
    let request = receipt_request(&model);
    let failure = engine_with_hook(directory.path(), &model, fail_receipt_put(None)).submit(&request).unwrap_err();
    assert!(matches!(failure, Failure::Internal { .. }));
    assert_eq!(failure.message(), "Model artifact persistence failed.");
    let published = std::fs::read(&model).unwrap();
    let status = engine(directory.path(), &model, "privoke-baseline").status(&status_request("intent-1")).unwrap();
    assert!(status.found);
    let replay = engine(directory.path(), &model, "privoke-baseline").submit(&request).unwrap();
    assert_eq!(replay.applied_version, status.ack.unwrap().applied_version);
    assert_eq!(std::fs::read(&model).unwrap(), published);
}

#[test]
fn concurrent_services_commit_the_same_request_once() {
    let directory = tempfile::tempdir().unwrap();
    let model = copy_model(directory.path(), "privoke-baseline");
    let request = receipt_request(&model);
    let versions: Vec<String> = std::thread::scope(|scope| {
        let workers: Vec<_> = (0..2)
            .map(|_| scope.spawn(|| engine(directory.path(), &model, "privoke-baseline").submit(&request).unwrap().applied_version))
            .collect();
        workers.into_iter().map(|worker| worker.join().unwrap()).collect()
    });
    assert_eq!(versions[0], versions[1]);
    assert_eq!(audit_lines(directory.path()), 1);
}

#[test]
fn recovery_is_durable_before_another_interrupted_publication() {
    let directory = tempfile::tempdir().unwrap();
    let model = copy_model(directory.path(), "privoke-baseline");
    let request = receipt_request(&model);
    engine_with_hook(directory.path(), &model, fail_receipt_put(None)).submit(&request).unwrap_err();
    let first_version = version_of(&model);
    let mut second = request.clone();
    second.base_version = first_version.clone();
    second.metadata.insert("request_id".into(), "cycle-2".into());
    engine_with_hook(directory.path(), &model, fail_receipt_put(Some(first_version.clone()))).submit(&second).unwrap_err();
    let status = engine(directory.path(), &model, "privoke-baseline").status(&status_request("intent-1")).unwrap();
    assert_eq!(status.ack.unwrap().applied_version, first_version);
    let applied = engine(directory.path(), &model, "privoke-baseline").submit(&second).unwrap();
    assert_eq!(applied.applied_version, version_of(&model));
}

#[test]
fn an_anonymous_update_cannot_erase_a_pending_receipt() {
    let directory = tempfile::tempdir().unwrap();
    let model = copy_model(directory.path(), "privoke-baseline");
    let request = receipt_request(&model);
    engine_with_hook(directory.path(), &model, fail_receipt_put(None)).submit(&request).unwrap_err();
    let first_version = version_of(&model);
    let mut anonymous = request.clone();
    anonymous.base_version = first_version.clone();
    anonymous.metadata.clear();
    engine(directory.path(), &model, "privoke-baseline").submit(&anonymous).unwrap();
    let status = engine(directory.path(), &model, "privoke-baseline").status(&status_request("intent-1")).unwrap();
    assert_eq!(status.ack.unwrap().applied_version, first_version);
}

// ---- the drift bounds (GAP-NO-CUMULATIVE-BOUND)

fn bounded(directory: &Path, model: &Path, per_update: f64, budget: f64, hook: Hook) -> Engine {
    let drift = DriftPolicy::Enforce { max_update_l2: per_update, max_cumulative_l2: budget };
    Engine::new(config_for(directory, model, "privoke-baseline", drift), system_clock(), hook).unwrap()
}

fn unit_update(model: &Path, request_id: &str) -> ParameterUpdateRequest {
    update(
        "fuzzer",
        "privoke-baseline",
        &version_of(model),
        vec![gradient("head.sensitivity.bias", &[4], &[0.5, 0.5, 0.5, 0.5])],
        &[("request_id", request_id)],
    )
}

#[test]
fn drift_spread_over_many_small_updates_is_rejected_at_the_budget() {
    let directory = tempfile::tempdir().unwrap();
    let model = copy_model(directory.path(), "privoke-baseline");
    let engine = bounded(directory.path(), &model, 2.0, 3.5, no_hook());
    // Each update has norm 1.0, under the per-update bound of 2.0.
    let first = unit_update(&model, "r1");
    let mut versions = Vec::new();
    for index in 1..=3 {
        versions.push(engine.submit(&unit_update(&model, &format!("r{index}"))).unwrap().applied_version);
    }
    let published = std::fs::read(&model).unwrap();
    let refused = engine.submit(&unit_update(&model, "r4")).unwrap_err();
    assert!(matches!(refused, Failure::Precondition(_)), "{refused}");
    assert!(refused.message().contains("drift budget"), "{refused}");
    assert_eq!(std::fs::read(&model).unwrap(), published, "a refused update changes nothing");
    // A replay is answered from its receipt, so exhausting the budget never fails an idempotent retry.
    assert_eq!(engine.submit(&first).unwrap().applied_version, versions[0]);
    assert_eq!(std::fs::read(&model).unwrap(), published);
}

#[test]
fn a_single_update_over_the_per_update_bound_is_rejected() {
    let directory = tempfile::tempdir().unwrap();
    let model = copy_model(directory.path(), "privoke-baseline");
    let engine = bounded(directory.path(), &model, 2.0, 100.0, no_hook());
    let before = std::fs::read(&model).unwrap();
    // Six coordinates at the 1.0 per-coordinate bound have norm 2.449.
    let wide = update("fuzzer", "privoke-baseline", &version_of(&model), vec![gradient("head.visibility.bias", &[6], &[1.0; 6])], &[]);
    let refused = engine.submit(&wide).unwrap_err();
    assert!(matches!(refused, Failure::Invalid(_)));
    assert!(refused.message().contains("per-update bound"), "{refused}");
    assert_eq!(std::fs::read(&model).unwrap(), before);
    // Exactly at the bound is accepted: four coordinates at 1.0 have norm 2.0.
    let at_bound = update("fuzzer", "privoke-baseline", &version_of(&model), vec![gradient("head.sensitivity.bias", &[4], &[1.0; 4])], &[]);
    engine.submit(&at_bound).unwrap();
}

#[test]
fn the_drift_total_survives_an_interrupted_publication() {
    let directory = tempfile::tempdir().unwrap();
    let model = copy_model(directory.path(), "privoke-baseline");
    // The budget admits one unit update (total 1.0) but not a second (2.0 > 1.5).
    bounded(directory.path(), &model, 2.0, 1.5, fail_receipt_put(None)).submit(&unit_update(&model, "r1")).unwrap_err();
    let after_crash = artifact_io::load(&model).unwrap();
    let record = DriftRecord::parse(&after_crash.typed.metadata()[DRIFT_METADATA_KEY]).unwrap();
    assert!((record.cumulative_l2 - 1.0).abs() < 1e-9);
    // The database transaction rolled back, so the running total is restored from the artifact before the next bound check.
    let refused = bounded(directory.path(), &model, 2.0, 1.5, no_hook()).submit(&unit_update(&model, "r2")).unwrap_err();
    assert!(matches!(refused, Failure::Precondition(_)), "{refused}");
}

#[test]
fn the_drift_record_is_written_only_when_the_policy_is_enforced() {
    let directory = tempfile::tempdir().unwrap();
    let off_model = copy_model(directory.path(), "privoke-baseline");
    engine(directory.path(), &off_model, "privoke-baseline").submit(&unit_update(&off_model, "r1")).unwrap();
    assert!(!artifact_io::load(&off_model).unwrap().typed.metadata().contains_key(DRIFT_METADATA_KEY));

    let other = tempfile::tempdir().unwrap();
    let on_model = copy_model(other.path(), "privoke-baseline");
    bounded(other.path(), &on_model, 2.0, 100.0, no_hook()).submit(&unit_update(&on_model, "r1")).unwrap();
    let loaded = artifact_io::load(&on_model).unwrap();
    let record = DriftRecord::parse(&loaded.typed.metadata()[DRIFT_METADATA_KEY]).unwrap();
    assert_eq!(record.anchor, "v0.3.0");
    assert!((record.update_l2 - 1.0).abs() < 1e-9 && (record.cumulative_l2 - 1.0).abs() < 1e-9);
    // The receipt itself is the Python one.
    let receipt = Receipt::parse(&loaded.typed.metadata()["last_update_receipt"]).unwrap();
    assert_eq!(receipt.applied_version, loaded.typed.version);
}

// ---- bootstrap (test_model_bootstrap.py)

const RECEIPT_TEXT: &str = r#"{"key": "receipt-key", "model_id": "privoke-balanced", "base_version": "v0.3.0+train.8", "applied_version": "v0.3.0+train.9", "payload_digest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "request_fingerprint": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "prompts_generated": 32}"#;

fn max_tokens(loaded: &Loaded) -> i64 {
    let Value::Object(root) = &loaded.root else { panic!("artifact is not an object") };
    let Some(Value::Object(config)) = root.get("config") else { panic!("no config") };
    let Some(Value::Int(digits)) = config.get("max_tokens") else { panic!("no max_tokens") };
    digits.parse().unwrap()
}

fn add_to_value(root: &mut Value, tensor: &str, index: usize, delta: f64) {
    let Value::Object(map) = root else { panic!("artifact is not an object") };
    let Some(Value::Object(parameters)) = map.get_mut("parameters") else { panic!("no parameters") };
    let Some(Value::Object(fields)) = parameters.get_mut(tensor) else { panic!("no tensor") };
    let Some(Value::Array(values)) = fields.get_mut("values") else { panic!("no values") };
    let current = match &values[index] {
        Value::Float(number) => *number,
        Value::Int(digits) => digits.parse::<f64>().unwrap(),
        other => panic!("unexpected value {other:?}"),
    };
    values[index] = Value::Float(current + delta);
}

fn persist(path: &Path, root: &Value) -> Loaded {
    let mut sealed = root.clone();
    artifact_io::seal(&mut sealed).unwrap();
    artifact_io::write_atomic(path, &sealed).unwrap();
    artifact_io::load(path).unwrap()
}

/// An artifact that represents an existing online update: shifted weights, a later version and a recovery receipt.
struct Bootstrap {
    directory: tempfile::TempDir,
    model: std::path::PathBuf,
    audit: std::path::PathBuf,
    original: Loaded,
}

impl Bootstrap {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let model = directory.path().join("model.json");
        let audit = directory.path().join("updates.jsonl");
        let mut root = artifact_io::load(&copy_model(directory.path(), "privoke-balanced")).unwrap().root;
        add_to_value(&mut root, "head.sensitivity.bias", 0, 0.002);
        add_to_value(&mut root, "position_embedding", 0, 0.003);
        if let Value::Object(map) = &mut root {
            map.insert("version".into(), Value::String("v0.3.0+train.9".into()));
            artifact_io::metadata_mut(map).insert("last_update_receipt".into(), Value::String(RECEIPT_TEXT.into()));
        }
        let original = persist(&model, &root);
        Self { directory, model, audit, original }
    }

    fn migrate(&self, hook: &Hook) -> Result<Loaded, Failure> {
        bootstrap_model(&self.model, &self.audit, "privoke-balanced", 256, &system_clock(), hook)
    }

    fn receipt(&self, audit: &Path) -> Option<Receipt> {
        ReceiptStore::begin(audit).unwrap().get("receipt-key").unwrap()
    }
}

fn expected_receipt() -> Receipt {
    Receipt::parse(RECEIPT_TEXT).unwrap()
}

fn tensor_values(loaded: &Loaded, name: &str) -> Vec<Value> {
    let Value::Object(root) = &loaded.root else { panic!("artifact is not an object") };
    let Some(Value::Object(parameters)) = root.get("parameters") else { panic!("no parameters") };
    let Some(Value::Object(fields)) = parameters.get(name) else { panic!("no tensor {name}") };
    let Some(Value::Array(values)) = fields.get("values") else { panic!("no values") };
    values.clone()
}

#[test]
fn the_wrong_selected_id_neither_imports_a_foreign_receipt_nor_changes_the_model() {
    let fixture = Bootstrap::new();
    let before = std::fs::read(&fixture.model).unwrap();
    let failure = bootstrap_model(&fixture.model, &fixture.audit, "privoke-quality", 256, &system_clock(), &no_hook()).unwrap_err();
    assert!(failure.message().contains("selected model ID"), "{failure}");
    assert_eq!(std::fs::read(&fixture.model).unwrap(), before);
    assert_eq!(fixture.receipt(&fixture.audit), None);
}

#[test]
fn the_learned_prefix_and_other_weights_are_preserved_and_a_restart_reuses_the_exact_bytes() {
    let fixture = Bootstrap::new();
    let prepared = fixture.migrate(&no_hook()).unwrap();
    assert_eq!(max_tokens(&prepared), 256);
    for name in fixture.original.typed.parameters.keys() {
        let before = tensor_values(&fixture.original, name);
        let after = tensor_values(&prepared, name);
        assert_eq!(after[..before.len()], before[..], "{name}");
    }
    assert_eq!(prepared.typed.metadata()["preparation_base_checksum"], fixture.original.typed.checksum);
    assert_eq!(prepared.typed.metadata()["preparation_source_revision"], PREPARATION_CODE_REVISION);
    assert_eq!(fixture.receipt(&fixture.audit), Some(expected_receipt()));
    let before = std::fs::read(&fixture.model).unwrap();
    let again = fixture.migrate(&no_hook()).unwrap();
    assert_eq!(again.typed, prepared.typed);
    assert_eq!(std::fs::read(&fixture.model).unwrap(), before);
}

#[test]
fn a_crash_at_each_boundary_recovers_without_a_reset_or_a_lost_receipt() {
    let fixture = Bootstrap::new();
    for boundary in ["after_checkpoint", "before_prepare", "before_publish", "after_publish"] {
        persist(&fixture.model, &fixture.original.root);
        // A different owned audit path starts each case with an empty receipt database.
        let audit = fixture.directory.path().join(format!("{boundary}.jsonl"));
        let before = std::fs::read(&fixture.model).unwrap();
        let wanted = boundary.to_string();
        let crash: Hook = Arc::new(move |phase: &str, _detail: &str| -> Result<(), String> {
            if phase == wanted { Err("simulated crash".to_string()) } else { Ok(()) }
        });
        let failure = bootstrap_model(&fixture.model, &audit, "privoke-balanced", 256, &system_clock(), &crash).unwrap_err();
        assert!(failure.detail().contains("simulated crash"), "{boundary}: {failure:?}");
        if boundary != "after_publish" {
            assert_eq!(std::fs::read(&fixture.model).unwrap(), before, "{boundary}");
        }
        assert_eq!(fixture.receipt(&audit), Some(expected_receipt()), "{boundary}");
        let result = bootstrap_model(&fixture.model, &audit, "privoke-balanced", 256, &system_clock(), &no_hook()).unwrap();
        assert_eq!(result.typed.metadata()["preparation_base_checksum"], fixture.original.typed.checksum, "{boundary}");
    }
}

#[test]
fn the_checkpoint_boundary_reloads_the_actual_changed_model_and_binds_its_checksum() {
    let fixture = Bootstrap::new();
    let mut changed_root = fixture.original.root.clone();
    add_to_value(&mut changed_root, "head.sensitivity.bias", 1, 0.004);
    let changed = persist(&fixture.model, &changed_root);
    persist(&fixture.model, &fixture.original.root);
    let (path, root) = (fixture.model.clone(), changed.root.clone());
    let between: Hook = Arc::new(move |phase: &str, _detail: &str| -> Result<(), String> {
        if phase == "after_checkpoint" {
            let mut sealed = root.clone();
            artifact_io::seal(&mut sealed).map_err(|failure| failure.to_string())?;
            artifact_io::write_atomic(&path, &sealed).map_err(|failure| failure.to_string())?;
        }
        Ok(())
    });
    let prepared = fixture.migrate(&between).unwrap();
    assert_eq!(prepared.typed.metadata()["preparation_base_checksum"], changed.typed.checksum);
    assert_eq!(tensor_values(&prepared, "head.sensitivity.bias")[1], tensor_values(&changed, "head.sensitivity.bias")[1]);
}

#[test]
fn an_existing_larger_context_is_never_shrunk() {
    let fixture = Bootstrap::new();
    let mut source_root = fixture.original.root.clone();
    if let Value::Object(map) = &mut source_root {
        artifact_io::metadata_mut(map).remove("last_update_receipt");
    }
    let source = persist(&fixture.model, &source_root);
    let full = prepare_full_encoder_artifact(&source, "v0.4.0.ctx512", 1, PREPARATION_CODE_REVISION, 512).unwrap();
    persist(&fixture.model, &full);
    let before = std::fs::read(&fixture.model).unwrap();
    assert_eq!(max_tokens(&fixture.migrate(&no_hook()).unwrap()), 512);
    assert_eq!(std::fs::read(&fixture.model).unwrap(), before);
}

#[test]
fn a_fresh_shipped_input_is_supported_without_modifying_the_repository() {
    let fixture = Bootstrap::new();
    let shipped = artifact_io::load(&common::repo_root().join("models/privoke-balanced.json")).unwrap();
    persist(&fixture.model, &shipped.root);
    let prepared = fixture.migrate(&no_hook()).unwrap();
    assert_eq!(prepared.typed.metadata()["preparation_base_checksum"], shipped.typed.checksum);
}
