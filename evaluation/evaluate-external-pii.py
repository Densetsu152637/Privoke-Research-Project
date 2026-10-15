"""Score frozen baseline or expanded presence profiles on approved partitions only."""
from __future__ import annotations

import argparse
from collections import defaultdict
from datetime import datetime, timezone
import hashlib
import importlib
import importlib.util
import json
import math
from pathlib import Path
import re
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "shared/python"))

from privoke_model.artifact import load_artifact  # noqa: E402
from privoke_model.presence import PRESENCE_ARCHITECTURE, SparsePresenceModel  # noqa: E402
from privoke_model.training_data import training_text_key  # noqa: E402
from privoke_eval.metrics import compute_metrics  # noqa: E402
from privoke_eval.presence_evidence import artifact_identity, load_frozen_fit  # noqa: E402
from privoke_eval.presence_rpc import response_record, validate_response  # noqa: E402

PROFILES = ("efficient", "balanced", "quality")
PARTITIONS = ("validation", "nemotron_heldout", "meddies_heldout")
PARTITION_NAMES = ("train", *PARTITIONS)
EXPECTED_BASE_VALIDATION_SHA256 = "d2d0c538e49f5bbc7a8f85887b9b8cfddb188a5ab9aae55c69ce26ae932be6d1"
BOOTSTRAP_ITERATIONS = 2000
BOOTSTRAP_SEED = 10102026
MIN_GROUPS_FOR_SOURCE_CI = 20


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def read_json(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("Expected a JSON object.")
    return value


def write_json(path: Path, value: dict, *, exclusive: bool = False) -> str:
    raw = (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + "\n").encode("utf-8")
    path.parent.mkdir(parents=True, exist_ok=True)
    mode = "xb" if exclusive else "wb"
    with path.open(mode) as handle:
        handle.write(raw)
        handle.flush()
    return sha256_bytes(raw)


def confined_path(root: Path, relative: str) -> Path:
    if not isinstance(relative, str) or not relative:
        raise ValueError("Prepared manifest has an invalid partition locator.")
    root = root.resolve()
    path = (root / relative).resolve()
    if root not in path.parents:
        raise ValueError("Prepared partition locator escapes the prepared directory.")
    return path


def read_jsonl(path: Path) -> list[dict]:
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line:
            continue
        row = json.loads(line)
        if not isinstance(row, dict):
            raise ValueError("Prepared partition contains a non-object row.")
        rows.append(row)
    return rows


def validate_row(row: dict, *, partition: str) -> None:
    required = ("id", "group_id", "text", "text_key", "expected_has_pii")
    if any(not isinstance(row.get(key), str) or not row[key] for key in required[:4]):
        raise ValueError(f"Prepared {partition} row is missing strict identity or text fields.")
    if type(row.get("expected_has_pii")) is not bool:
        raise ValueError(f"Prepared {partition} labels must be strict booleans.")
    if partition in ("nemotron_heldout", "meddies_heldout") and row["expected_has_pii"] is not True:
        raise ValueError(f"{partition} is an explicit-positive diagnostic partition.")
    text = row["text"]
    if not text.strip() or len(text) > 500_000:
        raise ValueError(f"Prepared {partition} row text is empty or exceeds the bounded RPC limit.")
    if row["text_key"] != training_text_key(text):
        raise ValueError(f"Prepared {partition} normalized text key is not canonical.")
    for key in ("source", "source_family", "domain", "document_type", "document_format", "document_label"):
        value = row.get(key)
        if value is not None and (not isinstance(value, str) or len(value) > 256):
            raise ValueError(f"Prepared {partition} metadata field is invalid.")
    categories = row.get("expected_categories", row.get("categories"))
    if categories is not None and (not isinstance(categories, list)
                                   or any(not isinstance(value, str) or len(value) > 128 for value in categories)):
        raise ValueError(f"Prepared {partition} categories are invalid.")


def validate_prepared(prepared_root: Path, *, prepared_source_revision: str,
                      protocol_sha256: str) -> dict:
    prepared_root = prepared_root.resolve()
    manifest_path = prepared_root / "manifest.json"
    raw_manifest = manifest_path.read_bytes()
    manifest = json.loads(raw_manifest.decode("utf-8"))
    if (not isinstance(manifest, dict) or manifest.get("status") != "prepared"
            or manifest.get("schema_version") != 1
            or manifest.get("source_revision") != prepared_source_revision
            or manifest.get("protocol_sha256") != protocol_sha256):
        raise ValueError("Prepared manifest status, schema, or source/protocol binding is invalid.")
    files = manifest.get("partition_files")
    hashes = manifest.get("partition_sha256")
    counts = manifest.get("rows")
    if (not isinstance(files, dict) or set(files) != set(PARTITION_NAMES)
            or not isinstance(hashes, dict) or set(hashes) != set(PARTITION_NAMES)
            or not isinstance(counts, dict) or set(counts) != set(PARTITION_NAMES)):
        raise ValueError("Prepared manifest must bind exactly train, validation and the two source diagnostics.")
    paths, rows = {}, {}
    for name in PARTITION_NAMES:
        path = confined_path(prepared_root, files[name])
        digest = sha256_file(path)
        if not isinstance(hashes[name], str) or digest != hashes[name]:
            raise ValueError(f"Prepared {name} partition digest mismatch.")
        minimum = 1 if name in ("train", "validation") else 0
        if type(counts[name]) is not int or counts[name] < minimum:
            raise ValueError(f"Prepared {name} row count is invalid.")
        paths[name] = path
        if name != "train":
            partition_rows = read_jsonl(path)
            if len(partition_rows) != counts[name]:
                raise ValueError(f"Prepared {name} row count differs from manifest.")
            for row in partition_rows:
                validate_row(row, partition=name)
            ids = [row["id"] for row in partition_rows]
            if len(ids) != len(set(ids)):
                raise ValueError(f"Prepared {name} contains duplicate row IDs.")
            rows[name] = partition_rows
    reference = manifest.get("prepared_reference")
    if not isinstance(reference, dict) or reference.get("validation_sha256") != EXPECTED_BASE_VALIDATION_SHA256:
        raise ValueError("Prepared reference does not bind the unchanged 968-row validation partition.")
    validation_sha = hashes["validation"]
    if validation_sha != EXPECTED_BASE_VALIDATION_SHA256:
        raise ValueError("Prepared validation bytes differ from the frozen 968-row reference.")
    if counts["validation"] != 968:
        raise ValueError("Prepared validation partition must contain exactly 968 frozen reference rows.")
    return {"root": prepared_root, "manifest": manifest,
            "manifest_sha256": sha256_bytes(raw_manifest), "manifest_path": manifest_path,
            "partition_paths": paths, "partition_rows": rows}


def load_external_fit(fit_root: Path, prepared_root: Path, *,
                      source_revision: str, protocol_sha256: str) -> dict:
    """Load the fitter's public strict all-profile verifier without importing fit code."""
    path = ROOT / "evaluation/fit-external-pii-profiles.py"
    if not path.is_file():
        raise RuntimeError("The external profile fitter with its public loader is not integrated.")
    spec = importlib.util.spec_from_file_location("fit_external_pii_profiles_for_scoring", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("Cannot load the public external fit verifier.")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.load_completed_fit(Path(fit_root), Path(prepared_root), source_revision=source_revision,
                                     protocol_sha256=protocol_sha256)


def load_baseline_fit(fit_root: Path, profile: str) -> dict:
    manifest_path = fit_root / "run-manifest.json"
    manifest = read_json(manifest_path)
    source_revision = manifest.get("source_revision")
    protocol_sha256 = manifest.get("protocol_sha256")
    if not isinstance(source_revision, str) or not isinstance(protocol_sha256, str):
        raise ValueError("Baseline fit lacks its original source/protocol binding.")
    verified = load_frozen_fit(fit_root / "profiles/efficient/selection.json", manifest_path,
                               fit_source_revision=source_revision,
                               protocol_sha256=protocol_sha256)
    profile_entry = verified["profiles"].get(profile)
    if not isinstance(profile_entry, dict):
        raise ValueError("Baseline profile is not one of the three frozen profiles.")
    return {"manifest": verified["manifest"], "manifest_sha256": verified["manifest_sha256"],
            "source_revision": source_revision, "protocol_sha256": protocol_sha256,
            "profiles": verified["profiles"], **profile_entry}


def bind_prepared_to_fit(prepared: dict, fit_manifest: dict) -> str:
    prepared_revision = fit_manifest.get("prepared_source_revision")
    if (not isinstance(prepared_revision, str)
            or not re.fullmatch(r"[0-9a-f]{40,64}", prepared_revision)
            or prepared["manifest"].get("source_revision") != prepared_revision
            or prepared["manifest_sha256"] != fit_manifest.get("prepared_manifest_sha256")
            or prepared["manifest"].get("partition_sha256") != fit_manifest.get("partition_sha256")):
        raise ValueError("Prepared source revision or input digests differ from the frozen fit manifest.")
    return prepared_revision


def identity_for_artifact(artifact: dict) -> dict:
    return artifact_identity(artifact)


def selection_matches_profile(selection: dict, profile: str) -> bool:
    return selection.get("profile", profile) == profile


def verify_profile_bundle(bundle: dict, *, profile: str, fit_root: Path,
                          source_revision: str, protocol_sha256: str,
                          prepared: dict) -> dict:
    manifest = bundle.get("manifest")
    profiles = bundle.get("profiles")
    if (not isinstance(manifest, dict) or manifest.get("status") != "complete"
            or manifest.get("source_revision") != source_revision
            or manifest.get("protocol_sha256") != protocol_sha256
            or not isinstance(profiles, dict) or set(profiles) != set(PROFILES)):
        raise ValueError("Expanded fit is incomplete, missing an exact three-profile freeze, or wrong source/protocol.")
    entry = profiles[profile]
    if not isinstance(entry, dict) or not isinstance(entry.get("selection"), dict):
        raise ValueError("Expanded fit lacks the requested frozen profile selection.")
    selection, artifact = entry["selection"], entry.get("artifact")
    artifact_path = Path(entry.get("artifact_path", "")).resolve()
    fit_root = fit_root.resolve()
    if fit_root not in artifact_path.parents:
        raise ValueError("Expanded artifact path escapes its fit directory.")
    if not isinstance(artifact, dict) or not artifact_path.is_file():
        raise ValueError("Expanded fit lacks its selected artifact.")
    if (not selection_matches_profile(selection, profile) or selection.get("status") != "selected"
            or selection.get("source_revision") != source_revision
            or selection.get("protocol_sha256") != protocol_sha256
            or sha256_file(artifact_path) != selection.get("selected_artifact_sha256")):
        raise ValueError("Expanded selection or artifact bytes differ from the completed fit.")
    if (artifact.get("architecture") != PRESENCE_ARCHITECTURE
            or artifact.get("model_id") != f"privoke-presence-{profile}"
            or artifact.get("config", {}).get("profile") != profile
            or artifact.get("metadata", {}).get("profile") != profile
            or artifact.get("metadata", {}).get("task") != "annotation_presence"
            or artifact.get("metadata", {}).get("source_revision") != source_revision
            or artifact.get("metadata", {}).get("protocol_sha256") != protocol_sha256
            or identity_for_artifact(artifact) != selection.get("artifact_identity")):
        raise ValueError("Expanded artifact does not match the frozen presence identity.")
    input_hashes = selection.get("input_hashes")
    fitted_partition_hashes = input_hashes.get("partition_sha256") if isinstance(input_hashes, dict) else None
    declared_partition_hashes = prepared["manifest"]["partition_sha256"]
    if (not isinstance(input_hashes, dict)
            or input_hashes.get("manifest_sha256") != prepared["manifest_sha256"]
            or not isinstance(fitted_partition_hashes, dict)
            or any(fitted_partition_hashes.get(name) != declared_partition_hashes[name]
                   for name in ("train", "validation"))):
        raise ValueError("Expanded selection does not bind every prepared partition digest.")
    if bundle.get("manifest_sha256") != sha256_file(fit_root / "run-manifest.json"):
        raise ValueError("Expanded run-manifest digest differs from the public fit verifier.")
    return {"manifest": manifest, "manifest_sha256": bundle.get("manifest_sha256"),
            "selection": selection, "artifact": artifact, "artifact_path": artifact_path,
            "artifact_sha256": sha256_file(artifact_path),
            "profiles": profiles, "source_revision": source_revision,
            "protocol_sha256": protocol_sha256}


def profile_file_bindings(root: Path, bundle: dict) -> dict:
    paths = {"run_manifest": root / "run-manifest.json"}
    for optional in ("fit-freeze.json", "diagnostics.json"):
        path = root / optional
        if path.is_file():
            paths[optional] = path
    for name, entry in bundle["profiles"].items():
        paths[f"{name}_selection"] = root / "profiles" / name / "selection.json"
        paths[f"{name}_artifact"] = Path(entry["artifact_path"])
    return {name: {"path": path.resolve().as_posix(), "sha256": sha256_file(path)}
            for name, path in sorted(paths.items())}


def write_fit_preflight_receipt(*, fit_root: Path, prepared_root: Path,
                                baseline_fit_root: Path, source_revision: str,
                                protocol_file: Path, protocol_sha256: str,
                                output: Path) -> dict:
    """Run the strict completed-fit verifier on Linux and emit hash-only evidence."""
    if sha256_file(protocol_file) != protocol_sha256:
        raise ValueError("Protocol file differs from its frozen digest.")
    bundle = load_external_fit(fit_root, prepared_root, source_revision=source_revision,
                               protocol_sha256=protocol_sha256)
    prepared = validate_prepared(prepared_root,
        prepared_source_revision=bundle["manifest"].get("prepared_source_revision"),
        protocol_sha256=protocol_sha256)
    prepared_revision = bind_prepared_to_fit(prepared, bundle["manifest"])
    baselines = load_baseline_fit(baseline_fit_root, "balanced")
    bind_baseline_reference(baselines, prepared)
    profiles = {}
    for profile in PROFILES:
        candidate = verify_profile_bundle(bundle, profile=profile, fit_root=fit_root,
            source_revision=source_revision, protocol_sha256=protocol_sha256, prepared=prepared)
        baseline = baselines["profiles"][profile]
        selection_path = Path(fit_root) / "profiles" / profile / "selection.json"
        profiles[profile] = {
            "selection_path": selection_path.relative_to(Path(fit_root).resolve()).as_posix(),
            "selection_sha256": sha256_file(selection_path),
            "artifact_path": candidate["artifact_path"].relative_to(Path(fit_root).resolve()).as_posix(),
            "artifact_sha256": candidate["artifact_sha256"],
            "artifact_identity": identity_for_artifact(candidate["artifact"]),
            "baseline_selection_path": Path("profiles").joinpath(profile, "selection.json").as_posix(),
            "baseline_selection_sha256": sha256_file(Path(baseline_fit_root) / "profiles" / profile / "selection.json"),
            "baseline_artifact_path": baseline["artifact_path"].relative_to(Path(baseline_fit_root).resolve()).as_posix(),
            "baseline_artifact_sha256": baseline["artifact_sha256"],
            "baseline_artifact_identity": identity_for_artifact(baseline["artifact"])}
    receipt = {"schema_version": 1, "status": "verified",
        "fit_source_revision": source_revision, "prepared_source_revision": prepared_revision,
        "protocol_sha256": protocol_sha256,
        "prepared_manifest_sha256": prepared["manifest_sha256"],
        "partition_sha256": prepared["manifest"]["partition_sha256"],
        "partition_rows": prepared["manifest"]["rows"],
        "fit_manifest_sha256": bundle["manifest_sha256"],
        "freeze_sha256": bundle["freeze_sha256"],
        "diagnostics_sha256": sha256_file(Path(fit_root) / "diagnostics.json"),
        "baseline_manifest_sha256": baselines["manifest_sha256"],
        "baseline_source_revision": baselines["source_revision"],
        "baseline_protocol_sha256": baselines["protocol_sha256"], "profiles": profiles}
    write_json(output, receipt, exclusive=True)
    return receipt


def bind_baseline_reference(baseline: dict, prepared: dict) -> None:
    original = baseline["selection"].get("input_hashes", {}).get("partition_sha256", {})
    reference = prepared["manifest"].get("prepared_reference", {})
    if (original.get("validation") != reference.get("validation_sha256")
            or original.get("train") != reference.get("train_sha256")):
        raise ValueError("Prepared data does not preserve the exact baseline train/validation reference.")


def load_runtime_stubs():
    generated = ROOT / "extension/client-runtime/generated"
    generated_text = generated.as_posix()
    if generated_text not in sys.path:
        sys.path.insert(0, generated_text)
    importlib.invalidate_caches()
    runtime_pb2 = importlib.import_module("privoke.v1.runtime_pb2")
    runtime_pb2_grpc = importlib.import_module("privoke.v1.runtime_pb2_grpc")
    return runtime_pb2, runtime_pb2_grpc


def safe_error_reason(exc: Exception) -> str:
    if isinstance(exc, ModuleNotFoundError):
        missing = getattr(exc, "name", None)
        return f"missing_module:{missing}" if isinstance(missing, str) else "missing_module"
    if isinstance(exc, ImportError):
        return "import_error"
    if isinstance(exc, TimeoutError):
        return "timeout"
    return "runtime_error"


def opaque_id(value: str, *, namespace: str) -> str:
    return sha256_bytes((namespace + "\0" + value).encode("utf-8"))


def score_row(stub, pb, model, artifact: dict, identity: dict,
              row: dict, request_id: str) -> dict:
    text = row["text"]
    request_sha = sha256_bytes(text.encode("utf-8"))
    local_probability = model.predict_probability(text)
    if not math.isfinite(local_probability) or not 0.0 <= local_probability <= 1.0:
        raise ValueError("Local serialized-model inference returned an invalid probability.")
    response = stub.DetectAnnotationPresence(
        pb.DetectAnnotationPresenceRequest(request_id=request_id, text=text,
                                           model_id=artifact["model_id"], layers=[pb.DETECTION_LAYER_SEMANTIC]),
        timeout=120)
    checked = validate_response(
        response_record(response), request_id=request_id, expected_identity=identity,
        present_enum=pb.ANNOTATION_PRESENCE_PRESENT,
        absent_enum=pb.ANNOTATION_PRESENCE_ABSENT,
        expected_probability=local_probability)
    categories = row.get("expected_categories", row.get("categories"))
    safe = {
        "row_id_sha256": opaque_id(row["id"], namespace="external-pii-row-v1"),
        "group_id_sha256": opaque_id(row["group_id"], namespace="external-pii-group-v1"),
        "request_id": request_id,
        "request_sha256": request_sha,
        "expected_has_pii": row["expected_has_pii"],
        "probability": checked["probability"],
        "local_probability": local_probability,
        "threshold": checked["threshold"],
        "predicted_present": checked["predicted_label"] == pb.ANNOTATION_PRESENCE_PRESENT,
        "predicted_label_enum": checked["predicted_label"],
        "elapsed_ms": checked["elapsed_ms"],
        "response_identity": checked["identity"],
        "source": row.get("source", row.get("source_family", row["group_id"].split(":", 1)[0])),
        "source_family": row.get("source_family", row["group_id"].split(":", 1)[0]),
        "category": categories,
        "domain": row.get("domain"),
        "document_type": row.get("document_type"),
        "document_format": row.get("document_format", row.get("text_format")),
        "word_count": len(text.split()),
    }
    return safe


def point_metrics(rows: list[dict], predictions: list[dict]) -> dict:
    labels = [int(row["expected_has_pii"]) for row in rows]
    predicted = [int(item["predicted_present"]) for item in predictions]
    return compute_metrics(labels, predicted, bootstrap_iterations=0, loaded_samples=len(rows))


def group_report(rows: list[dict], predictions: list[dict], *, include_ci: bool) -> dict:
    labels = [int(row["expected_has_pii"]) for row in rows]
    predicted = [int(item["predicted_present"]) for item in predictions]
    result = point_metrics(rows, predictions)
    result["row_count"] = len(rows)
    result["positive_examples"] = sum(labels)
    result["absent_examples"] = len(labels) - sum(labels)
    result["group_count"] = len({row["group_id"] for row in rows})
    if include_ci:
        if not labels or len(set(labels)) < 2:
            result["confidence_intervals_95"] = {
                "status": "not_computed", "reason": "partition_lacks_both_label_strata",
                "iterations": 0}
        elif result["group_count"] < MIN_GROUPS_FOR_SOURCE_CI:
            result["confidence_intervals_95"] = {
                "status": "not_computed",
                "reason": f"fewer_than_{MIN_GROUPS_FOR_SOURCE_CI}_source_groups",
                "iterations": 0,
            }
        else:
            sampled = compute_metrics(
                labels, predicted, bootstrap_iterations=BOOTSTRAP_ITERATIONS,
                seed=BOOTSTRAP_SEED,
                group_ids=[opaque_id(row["group_id"], namespace="external-pii-group-v1")
                           for row in rows],
                loaded_samples=len(rows))
            result["confidence_intervals_95"] = {
                "status": "complete",
                "method": ("cluster_bootstrap_by_source_group" if len(set(row["group_id"] for row in rows)) < len(rows)
                           else "metrics_helper_unique_group_ids"),
                "iterations": BOOTSTRAP_ITERATIONS, "seed": BOOTSTRAP_SEED,
                "intervals": sampled["confidence_intervals_95"],
            }
    else:
        result["confidence_intervals_95"] = {
            "status": "not_computed", "reason": "source_stratum_interval_not_in_primary_plan",
            "iterations": 0}
    return result


def metrics_by_stratum(rows: list[dict], predictions: list[dict], field: str) -> dict:
    groups: dict[str, list[int]] = defaultdict(list)
    for index, row in enumerate(rows):
        value = row.get(field)
        if field == "expected_categories":
            categories = row.get("expected_categories", row.get("categories"))
            values = categories if isinstance(categories, list) and categories else ["unavailable"]
        else:
            values = [value if isinstance(value, str) and value else "unavailable"]
        for item in values:
            groups[str(item)].append(index)
    result = {}
    for name, indexes in sorted(groups.items()):
        selected_rows = [rows[index] for index in indexes]
        selected_predictions = [predictions[index] for index in indexes]
        result[name] = group_report(selected_rows, selected_predictions, include_ci=False)
    return result


def word_length_bucket(count: int) -> str:
    if count < 20:
        return "0-19"
    if count < 50:
        return "20-49"
    if count < 100:
        return "50-99"
    return "100+"


def prediction_metrics(rows: list[dict], predictions: list[dict]) -> dict:
    enriched = []
    for source_row, prediction in zip(rows, predictions):
        item = dict(source_row)
        item["group_id"] = prediction["group_id_sha256"]
        item["_word_bucket"] = word_length_bucket(prediction["word_count"])
        item["source"] = prediction["source"]
        item["expected_categories"] = prediction["category"]
        item["document_format"] = prediction["document_format"]
        enriched.append(item)
    return {
        "overall": group_report(enriched, predictions, include_ci=True),
        "by_source": metrics_by_stratum(enriched, predictions, "source"),
        "prompt_detection_recall_by_source_category": metrics_by_stratum(
            enriched, predictions, "expected_categories"),
        "by_domain": metrics_by_stratum(enriched, predictions, "domain"),
        "by_document_format": metrics_by_stratum(enriched, predictions, "document_format"),
        "by_word_length": metrics_by_stratum(enriched, predictions, "_word_bucket"),
    }


def run(*, fit_root: Path, prepared_root: Path, baseline_fit_root: Path,
        profile: str, control: str, partition: str, output: Path,
        source_revision: str, fit_source_revision: str,
        protocol_file: Path, protocol_sha256: str,
        runtime_image_id: str, evaluator_image_id: str, target: str) -> dict:
    if profile not in PROFILES or control not in ("baseline", "expanded") or partition not in PARTITIONS:
        raise ValueError("Profile, control, or partition is outside the fixed scorer allowlist.")
    output = output.resolve()
    if output.exists():
        raise FileExistsError("Output directory must be fresh and unused.")
    output.mkdir(parents=True, exist_ok=False)
    started = datetime.now(timezone.utc).isoformat()
    state = {"schema_version": 1, "status": "running", "started_at_utc": started,
             "profile": profile, "control": control, "partition": partition,
             "source_revision": source_revision, "protocol_file": protocol_file.as_posix(),
             "protocol_sha256": protocol_sha256,
             "runtime_image_id": runtime_image_id, "evaluator_image_id": evaluator_image_id,
             "target": target, "bootstrap": {"iterations": BOOTSTRAP_ITERATIONS,
                                                   "seed": BOOTSTRAP_SEED,
                                                   "method": "shared_metrics_helper_cluster_when_groups_repeat_else_class_stratified_or_wilson"},
             "errors": [], "rows": 0, "successful_rows": 0}
    manifest_path = output / "run-manifest.json"
    predictions = []
    try:
        if not runtime_image_id.strip() or not evaluator_image_id.strip() or not target.strip():
            raise ValueError("Runtime/evaluator image IDs and RPC target must be recorded.")
        if sha256_file(protocol_file) != protocol_sha256:
            raise ValueError("Protocol file digest differs from the requested protocol binding.")
        candidate_bundle = load_external_fit(fit_root, prepared_root, source_revision=fit_source_revision,
                                             protocol_sha256=protocol_sha256)
        fit_manifest = candidate_bundle["manifest"]
        prepared_source_revision = fit_manifest.get("prepared_source_revision")
        prepared = validate_prepared(prepared_root, prepared_source_revision=prepared_source_revision,
                                     protocol_sha256=protocol_sha256)
        prepared_source_revision = bind_prepared_to_fit(prepared, fit_manifest)
        expanded = verify_profile_bundle(candidate_bundle, profile=profile,
                                         fit_root=fit_root, source_revision=fit_source_revision,
                                         protocol_sha256=protocol_sha256, prepared=prepared)
        baseline = load_baseline_fit(baseline_fit_root.resolve(), profile)
        bind_baseline_reference(baseline, prepared)
        expanded_files_before = profile_file_bindings(fit_root.resolve(), candidate_bundle)
        baseline_files_before = profile_file_bindings(baseline_fit_root.resolve(), baseline)
        if (candidate_bundle.get("manifest_sha256") != sha256_file(fit_root / "run-manifest.json")
                or baseline["manifest_sha256"] != sha256_file(baseline_fit_root / "run-manifest.json")):
            raise ValueError("A frozen fit manifest digest changed during load.")
        chosen = baseline if control == "baseline" else expanded
        artifact, artifact_path = chosen["artifact"], chosen["artifact_path"]
        rows = prepared["partition_rows"][partition]
        bindings = {
            "protocol": {"path": protocol_file.resolve().as_posix(), "sha256": sha256_file(protocol_file)},
            "prepared_manifest": {"path": prepared["manifest_path"].as_posix(), "sha256": prepared["manifest_sha256"]},
            "partitions": {name: {"path": prepared["partition_paths"][name].as_posix(),
                                  "sha256": sha256_file(prepared["partition_paths"][name])}
                           for name in PARTITION_NAMES},
            "expanded_fit_manifest_sha256": candidate_bundle.get("manifest_sha256"),
            "expanded_frozen_files": expanded_files_before,
            "expanded_artifact": {"path": expanded["artifact_path"].as_posix(),
                                  "sha256": expanded["artifact_sha256"]},
            "baseline_fit_manifest_sha256": baseline["manifest_sha256"],
            "baseline_frozen_files": baseline_files_before,
            "baseline_artifact": {"path": baseline["artifact_path"].as_posix(),
                                  "sha256": baseline["artifact_sha256"]},
        }
        state.update({"fit_source_revision": fit_source_revision,
                      "prepared_source_revision": prepared_source_revision,
                      "bindings_before": bindings,
                      "prepared_manifest_sha256": prepared["manifest_sha256"],
                      "partition_sha256": prepared["manifest"]["partition_sha256"][partition],
                      "partition_rows": len(rows), "artifact_identity": identity_for_artifact(artifact),
                      "artifact_sha256": chosen["artifact_sha256"],
                      "expanded_fit_manifest_sha256": candidate_bundle.get("manifest_sha256"),
                      "baseline_fit_manifest_sha256": baseline["manifest_sha256"]})
        write_json(manifest_path, state, exclusive=True)
        if rows:
            model = SparsePresenceModel.from_artifact(artifact)
            import grpc
            pb, grpc_pb = load_runtime_stubs()
            request_prefix = f"external-pii-{uuid.uuid4().hex}"
            with grpc.insecure_channel(target) as channel:
                stub = grpc_pb.PrivokeRuntimeServiceStub(channel)
                for index, row in enumerate(rows):
                    request_id = f"{request_prefix}-{index:06d}"
                    try:
                        predictions.append(score_row(stub, pb, model, artifact,
                                                     state["artifact_identity"], row, request_id))
                    except Exception as exc:
                        predictions.append({
                            "row_id_sha256": opaque_id(row["id"], namespace="external-pii-row-v1"),
                            "group_id_sha256": opaque_id(row["group_id"], namespace="external-pii-group-v1"),
                            "request_id": request_id,
                            "request_sha256": sha256_bytes(row["text"].encode("utf-8")),
                            "expected_has_pii": row["expected_has_pii"],
                            "error_type": type(exc).__name__,
                            "error_sha256": sha256_bytes(str(exc).encode("utf-8")),
                        })
                        state["errors"].append({"row_id_sha256": predictions[-1]["row_id_sha256"],
                                                "request_id": request_id,
                                                "error_type": type(exc).__name__,
                                                "error_sha256": predictions[-1]["error_sha256"]})
        write_json(output / "predictions.json", {"rows": predictions}, exclusive=True)
        state["rows"] = len(rows)
        state["successful_rows"] = len(rows) - len(state["errors"])
        if not rows:
            state["metrics"] = None
            state["status"] = "not_scored"
            state["failure_reason"] = "zero_partition_rows_no_external_coverage"
        elif not state["errors"]:
            state["metrics"] = prediction_metrics(rows, predictions)
            state["status"] = "complete"
        else:
            state["metrics"] = None
            state["status"] = "failed"
            state["failure_reason"] = "one_or_more_rpc_or_parity_failures"
        after = {
            "protocol": sha256_file(protocol_file),
            "prepared_manifest": sha256_file(prepared["manifest_path"]),
            "partitions": {name: sha256_file(prepared["partition_paths"][name]) for name in PARTITION_NAMES},
            "expanded_fit_manifest": sha256_file(fit_root / "run-manifest.json"),
            "expanded_artifact": sha256_file(expanded["artifact_path"]),
            "baseline_fit_manifest": sha256_file(baseline_fit_root / "run-manifest.json"),
            "baseline_artifact": sha256_file(baseline["artifact_path"]),
            "expanded_frozen_files": profile_file_bindings(fit_root.resolve(), candidate_bundle),
            "baseline_frozen_files": profile_file_bindings(baseline_fit_root.resolve(), baseline),
        }
        state["bindings_after_sha256"] = after
        expected_after = {
            "protocol": bindings["protocol"]["sha256"],
            "prepared_manifest": bindings["prepared_manifest"]["sha256"],
            "partitions": {name: bindings["partitions"][name]["sha256"] for name in PARTITION_NAMES},
            "expanded_fit_manifest": bindings["expanded_fit_manifest_sha256"],
            "expanded_artifact": bindings["expanded_artifact"]["sha256"],
            "baseline_fit_manifest": bindings["baseline_fit_manifest_sha256"],
            "baseline_artifact": bindings["baseline_artifact"]["sha256"],
            "expanded_frozen_files": bindings["expanded_frozen_files"],
            "baseline_frozen_files": bindings["baseline_frozen_files"],
        }
        if after != expected_after:
            state["status"] = "failed"
            state["metrics"] = None
            state["failure_reason"] = "input_binding_changed_during_scoring"
            state["errors"].append({"error_type": "BindingMismatch"})
        state["finished_at_utc"] = datetime.now(timezone.utc).isoformat()
        state["predictions_sha256"] = sha256_file(output / "predictions.json")
        write_json(manifest_path, state)
        return state
    except Exception as exc:
        state.update({"status": "failed", "failure_stage": "validation_or_setup",
                      "error_type": type(exc).__name__,
                      "error_reason": safe_error_reason(exc),
                      "error_sha256": sha256_bytes(str(exc).encode("utf-8")),
                      "rows": len(predictions), "successful_rows": 0,
                      "finished_at_utc": datetime.now(timezone.utc).isoformat()})
        if predictions:
            try:
                write_json(output / "predictions.json", {"rows": predictions}, exclusive=True)
                state["predictions_sha256"] = sha256_file(output / "predictions.json")
            except FileExistsError:
                pass
        write_json(manifest_path, state)
        return state


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--fit-preflight-receipt", action="store_true")
    result.add_argument("--fit-root", type=Path)
    result.add_argument("--prepared", type=Path)
    result.add_argument("--baseline-fit-root", type=Path)
    result.add_argument("--profile", choices=PROFILES)
    result.add_argument("--control", choices=("baseline", "expanded"))
    result.add_argument("--partition", choices=PARTITIONS)
    result.add_argument("--output", type=Path)
    result.add_argument("--source-revision")
    result.add_argument("--fit-source-revision")
    result.add_argument("--protocol-file", type=Path)
    result.add_argument("--protocol-sha256")
    result.add_argument("--runtime-image-id")
    result.add_argument("--evaluator-image-id")
    result.add_argument("--target")
    return result


def main(argv=None) -> int:
    args = parser().parse_args(argv)
    if args.fit_preflight_receipt:
        required = (args.fit_root, args.prepared, args.baseline_fit_root, args.output,
                    args.fit_source_revision, args.protocol_file, args.protocol_sha256)
        if any(value is None for value in required):
            raise SystemExit("fit preflight requires fit/prepared/baseline roots, output, fit source revision and protocol binding")
        receipt = write_fit_preflight_receipt(fit_root=args.fit_root, prepared_root=args.prepared,
            baseline_fit_root=args.baseline_fit_root, source_revision=args.fit_source_revision,
            protocol_file=args.protocol_file, protocol_sha256=args.protocol_sha256, output=args.output)
        print(json.dumps({"status": receipt["status"], "profiles": len(receipt["profiles"]),
                          "fit_manifest_sha256": receipt["fit_manifest_sha256"],
                          "prepared_manifest_sha256": receipt["prepared_manifest_sha256"]}, sort_keys=True))
        return 0
    required = (args.fit_root, args.prepared, args.baseline_fit_root, args.profile, args.control,
                args.partition, args.output, args.source_revision, args.fit_source_revision,
                args.protocol_file, args.protocol_sha256, args.runtime_image_id,
                args.evaluator_image_id, args.target)
    if any(value is None for value in required):
        raise SystemExit("scoring requires all standard scorer arguments")
    run_record = run(fit_root=args.fit_root, prepared_root=args.prepared,
                     baseline_fit_root=args.baseline_fit_root, profile=args.profile,
                     control=args.control, partition=args.partition, output=args.output,
                     source_revision=args.source_revision, fit_source_revision=args.fit_source_revision,
                     protocol_file=args.protocol_file,
                     protocol_sha256=args.protocol_sha256, runtime_image_id=args.runtime_image_id,
                     evaluator_image_id=args.evaluator_image_id, target=args.target)
    print(json.dumps({"status": run_record.get("status"),
                      "output": args.output.as_posix(),
                      "rows": run_record.get("rows"),
                      "successful_rows": run_record.get("successful_rows"),
                      "failure_reason": run_record.get("failure_reason"),
                      "error_type": run_record.get("error_type")}, sort_keys=True))
    return 0 if run_record.get("status") == "complete" else 1


if __name__ == "__main__":
    raise SystemExit(main())
