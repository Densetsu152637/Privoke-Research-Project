"""Fit three bounded sparse annotation-presence release profiles.

This phase reads pinned train/validation/development metadata for integrity but
never computes development probabilities. All profile selections are frozen
before the separate RPC evaluator is permitted to score development.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import platform
import re
import sys
import time
import traceback
import warnings

# Set before importing NumPy/scikit-learn so fit and vectorizer work stay bounded.
for _thread_var in ("OPENBLAS_NUM_THREADS", "OMP_NUM_THREADS", "MKL_NUM_THREADS"):
    os.environ[_thread_var] = "1"

import numpy as np
import scipy
import sklearn
import threadpoolctl
from sklearn.exceptions import ConvergenceWarning
from sklearn.linear_model import LogisticRegression
from threadpoolctl import threadpool_limits

from privoke_model.artifact import float32, load_artifact, validate_artifact
from privoke_model.fingerprint import parameter_fingerprint
from privoke_model.presence import PROFILE_MAX_FEATURES
from privoke_model.training_data import training_text_key
from privoke_eval.presence_training import (
    C_VALUES,
    RECALL_FLOOR,
    artifact_identity,
    binary_metrics,
    build_artifact,
    make_vectorizer,
    runtime_probabilities,
    select_threshold,
    serialized_runtime_model,
    source_family,
)

ROOT = Path(__file__).resolve().parents[1]
PROFILE_ORDER = ("efficient", "balanced", "quality")


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def write_json_exclusive(path: Path, value) -> str:
    raw = (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + "\n").encode("utf-8")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())
    return hashlib.sha256(raw).hexdigest()


def write_manifest(path: Path, value) -> None:
    temporary = path.with_name(f".{path.name}.tmp")
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + "\n"
    temporary.write_text(raw, encoding="utf-8", newline="\n")
    os.replace(temporary, path)


def load_control_validator():
    """Reuse the previously audited strict v3 identity and final-digest checks."""
    path = ROOT / "evaluation/fit-text-control.py"
    spec = importlib.util.spec_from_file_location("fit_text_control_validator", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("Cannot load the pinned text-control input validator.")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def package_info() -> dict:
    return {"python": sys.version.split()[0], "platform": platform.platform(),
            "numpy": np.__version__, "scipy": scipy.__version__,
            "scikit_learn": sklearn.__version__, "threadpoolctl": threadpoolctl.__version__,
            "threads": {name: os.environ[name] for name in
                        ("OPENBLAS_NUM_THREADS", "OMP_NUM_THREADS", "MKL_NUM_THREADS")},
            "threadpool_limit": 1}


def row_predictions(rows, probabilities, threshold):
    if len(rows) != len(probabilities):
        raise ValueError("Presence row/probability length mismatch.")
    records = []
    for row, probability in zip(rows, probabilities):
        if type(row.get("expected_has_pii")) is not bool:
            raise ValueError("Presence target must be a strict boolean.")
        if not math.isfinite(probability) or not 0.0 <= probability <= 1.0:
            raise ValueError("Presence probability is non-finite or outside [0, 1].")
        records.append({"id": row["id"], "group_id": row["group_id"],
                        "source_family": source_family(row["group_id"]),
                        "expected_has_pii": row["expected_has_pii"],
                        "probability": probability, "prediction": probability >= threshold})
    return records


def _profile_metadata(profile, c_value, source_revision, protocol_sha256, input_hashes):
    return {"release_version": "v1.0.0", "training_revision": "0",
            "training_strategy": "train_only_sparse_tfidf_logistic",
            "task": "annotation_presence", "profile": profile,
            "normalization": "training_text_key_v1", "arithmetic": "float32_parameters_float64_features_fsum_v1",
            "selected_C": repr(float(c_value)), "training_seed": "7102026",
            "dataset_revision": "4a13e9ffe6fd0d275efbde8afd4d8d8f1ffc2133",
            "source_revision": source_revision, "protocol_sha256": protocol_sha256,
            "prepared_manifest_sha256": input_hashes["manifest_sha256"],
            "train_sha256": input_hashes["partition_sha256"]["train"],
            "validation_sha256": input_hashes["partition_sha256"]["validation"],
            "locked_development_sha256": input_hashes["locked_sha256"]["development"],
            "bootstrap_source_sha256": input_hashes["bootstrap_source_sha256"],
            "weight_format": "json-float32"}


def fit_candidate(vectorizer, x_train, train_rows, validation_rows, profile, c_value,
                  source_revision, protocol_sha256, input_hashes, candidate_dir):
    y_train = np.asarray([row["expected_has_pii"] for row in train_rows], dtype=np.int8)
    y_validation = np.asarray([row["expected_has_pii"] for row in validation_rows], dtype=np.int8)
    estimator = LogisticRegression(C=c_value, class_weight="balanced", solver="lbfgs",
                                   max_iter=1000, tol=1e-4, random_state=7102026)
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        estimator.fit(x_train, y_train)
    warning_records = [{"category": item.category.__name__, "message": str(item.message)} for item in caught]
    converged = not any(issubclass(item.category, ConvergenceWarning) for item in caught)
    artifact_unthresholded = build_artifact(
        vectorizer, estimator, profile, 0.5,
        _profile_metadata(profile, c_value, source_revision, protocol_sha256, input_hashes))
    calibration_path = candidate_dir / f"C-{c_value:g}-calibration.json"
    write_json_exclusive(calibration_path, artifact_unthresholded)
    # Calibration uses the same bytes the runtime loader will validate.
    artifact_unthresholded = load_artifact(calibration_path)
    model = serialized_runtime_model(artifact_unthresholded)
    train_probability = runtime_probabilities(model, train_rows)
    validation_probability = runtime_probabilities(model, validation_rows)
    threshold, validation_metrics = select_threshold(
        [bool(value) for value in y_validation], validation_probability, RECALL_FLOOR)
    calibrated = build_artifact(
        vectorizer, estimator, profile, threshold,
        _profile_metadata(profile, c_value, source_revision, protocol_sha256, input_hashes))
    validate_artifact(calibrated)
    calibrated_model = serialized_runtime_model(calibrated)
    # Confirm serialization, threshold and runtime arithmetic are identical.
    reloaded_probability = runtime_probabilities(calibrated_model, validation_rows)
    if reloaded_probability != validation_probability:
        raise ValueError("Calibrated artifact changed runtime probabilities.")
    validation_predictions = row_predictions(validation_rows, reloaded_probability, threshold)
    train_predictions = row_predictions(train_rows, train_probability, threshold)
    identity = artifact_identity(calibrated)
    fingerprint = parameter_fingerprint(
        {name: tensor["values"] for name, tensor in calibrated["parameters"].items()},
        {name: tensor["shape"] for name, tensor in calibrated["parameters"].items()})
    if identity["parameter_fingerprint"] != fingerprint:
        raise ValueError("Serialized presence artifact fingerprint mismatch.")
    return {"C": float(c_value), "converged": converged, "warnings": warning_records,
            "threshold": threshold, "validation_metrics": validation_metrics,
            "train_metrics_at_validation_threshold": binary_metrics(
                [bool(value) for value in y_train], train_probability, threshold),
            "validation_predictions": validation_predictions,
            "train_predictions": train_predictions,
            "artifact": calibrated, "artifact_identity": identity}


def _fit_profile(profile, train_rows, validation_rows, output, source_revision,
                 protocol_sha256, input_hashes):
    vectorizer = make_vectorizer(profile)
    train_docs = [training_text_key(row["text"]) for row in train_rows]
    # This is the only vocabulary/IDF fitting call; validation uses transform only.
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        x_train = vectorizer.fit_transform(train_docs)
    vectorizer_warnings = [{"category": item.category.__name__, "message": str(item.message)} for item in caught]
    if x_train.shape[1] == 0:
        raise ValueError(f"{profile} produced no train vocabulary.")
    candidates, failures = [], []
    profile_dir = output / "profiles" / profile
    candidate_dir = profile_dir / "candidates"
    candidate_dir.mkdir(parents=True, exist_ok=True)
    for c_value in C_VALUES:
        try:
            candidate = fit_candidate(vectorizer, x_train, train_rows, validation_rows, profile, c_value,
                                      source_revision, protocol_sha256, input_hashes, candidate_dir)
            candidates.append(candidate)
        except Exception as exc:
            failures.append({"C": c_value, "error_type": type(exc).__name__, "error": str(exc),
                             "traceback": traceback.format_exc()})
    candidate_records = []
    for candidate in candidates:
        artifact_path = candidate_dir / f"C-{candidate['C']:g}-artifact.json"
        artifact_sha256 = write_json_exclusive(artifact_path, candidate["artifact"])
        candidate_records.append({key: value for key, value in candidate.items() if key != "artifact"} |
                                 {"artifact_file": artifact_path.relative_to(output).as_posix(),
                                  "artifact_sha256": artifact_sha256})
    eligible = [item for item in candidates if item["converged"]]
    common = {"profile": profile, "candidate_C_values": list(C_VALUES),
        "candidates": candidate_records, "candidate_failures": failures,
        "vectorizer_warnings": vectorizer_warnings,
        "source_revision": source_revision, "protocol_sha256": protocol_sha256,
        "input_hashes": {key: input_hashes[key] for key in
                          ("manifest_sha256", "partition_sha256", "locked_manifest_sha256",
                           "locked_sha256", "bootstrap_source_sha256")}}
    if not eligible:
        selection = {"status": "failed", **common,
                     "failure": "No converged valid candidate for this profile."}
        write_json_exclusive(profile_dir / "selection.json", selection)
        del vectorizer, x_train
        return selection
    selected = max(eligible, key=lambda item: (
        item["validation_metrics"]["balanced_accuracy"],
        item["validation_metrics"]["specificity"],
        item["validation_metrics"]["recall"], -item["C"]))
    selected_path = profile_dir / "artifact.json"
    selected_artifact_sha = write_json_exclusive(selected_path, selected["artifact"])
    if selected_artifact_sha != candidate_records[
            [item["C"] for item in candidates].index(selected["C"])]["artifact_sha256"]:
        raise ValueError("Selected artifact bytes differ from the selected C candidate artifact.")
    selection = {"status": "selected", **common,
        "selected_C": selected["C"], "threshold": selected["threshold"],
        "recall_floor": RECALL_FLOOR,
        "threshold_rule": "maximum validation specificity subject to recall >= 0.90; ties higher recall then higher threshold",
        "selection_rule": "validation balanced_accuracy, specificity, recall, then lower C",
        "selected_artifact_file": selected_path.relative_to(output).as_posix(),
        "selected_artifact_sha256": selected_artifact_sha,
        "artifact_identity": selected["artifact_identity"],
        "feature_counts": {name: len(selected["artifact"]["config"]["branches"][name]["features"])
                           for name in ("word", "char")},
        "parameter_value_count": sum(len(tensor["values"])
                                      for tensor in selected["artifact"]["parameters"].values()),
        "artifact_bytes": selected_path.stat().st_size,
        "config_bytes": len(json.dumps(selected["artifact"]["config"], ensure_ascii=False,
                                        allow_nan=False, separators=(",", ":")).encode("utf-8")),
    }
    write_json_exclusive(profile_dir / "selection.json", selection)
    # Drop large matrices and estimator references before fitting the next profile.
    del vectorizer, x_train
    return selection


def write_training_curriculum(rows, path):
    seen_ids = set()
    records = []
    for row in rows:
        if type(row.get("expected_has_pii")) is not bool:
            raise ValueError("Training curriculum target must be a strict boolean.")
        if row["id"] in seen_ids:
            raise ValueError("Training curriculum contains duplicate IDs.")
        seen_ids.add(row["id"])
        records.append({"id": row["id"], "text": row["text"],
                        "sensitive": row["expected_has_pii"], "group_id": row["group_id"]})
    raw = "".join(json.dumps(record, ensure_ascii=False, sort_keys=True, allow_nan=False) + "\n"
                   for record in records).encode("utf-8")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())
    return {"rows": len(records), "sha256": hashlib.sha256(raw).hexdigest(),
            "positive": sum(record["sensitive"] for record in records),
            "clean": sum(not record["sensitive"] for record in records),
            "fields": ["id", "text", "sensitive", "group_id"]}


def run_fit(prepared, locked_root, bootstrap_source, output, source_revision, protocol_sha256):
    output.mkdir(parents=True, exist_ok=False)
    manifest_path = output / "run-manifest.json"
    protocol_path = ROOT / "paper/research/model-refactor-protocol.md"
    manifest = {"status": "running", "stage": "input_validation", "started_at_utc": time.time(),
                "source_revision": source_revision, "protocol_sha256": protocol_sha256,
                "protocol_file_sha256": sha256_file(protocol_path),
                "fit_script_sha256": sha256_file(Path(__file__)),
                "helper_sha256": sha256_file(ROOT / "evaluation/privoke_eval/presence_training.py"),
                "packages": package_info(), "profiles": {}, "errors": []}
    write_manifest(manifest_path, manifest)
    try:
        if manifest["protocol_file_sha256"] != protocol_sha256:
            raise ValueError("Supplied prospective protocol digest does not match the protocol file.")
        validator = load_control_validator()
        inputs = validator.validate_identity_inputs(prepared, locked_root, bootstrap_source)
        manifest["input_validation"] = {key: value for key, value in inputs.items() if key != "partitions"}
        train_rows = inputs["partitions"]["train"]
        manifest["training_curriculum"] = write_training_curriculum(
            train_rows, output / "curriculum" / "prompts.jsonl")
        manifest["stage"] = "profile_fitting_validation"
        write_manifest(manifest_path, manifest)
        validation_rows = inputs["partitions"]["validation"]
        for profile in PROFILE_ORDER:
            try:
                with threadpool_limits(limits=1):
                    profile_selection = _fit_profile(
                        profile, train_rows, validation_rows, output, source_revision,
                        protocol_sha256, manifest["input_validation"])
                manifest["profiles"][profile] = profile_selection
                if profile_selection.get("status") != "selected":
                    manifest["errors"].append({"profile": profile, "type": "ProfileFitFailed",
                        "error": profile_selection.get("failure", "Profile did not select a model.")})
                write_manifest(manifest_path, manifest)
            except Exception as exc:
                manifest["profiles"][profile] = {"status": "failed", "error_type": type(exc).__name__,
                    "error": str(exc), "traceback": traceback.format_exc()}
                manifest["errors"].append({"profile": profile, "type": type(exc).__name__,
                    "error": str(exc), "traceback": traceback.format_exc()})
                write_manifest(manifest_path, manifest)
        if manifest["errors"]:
            raise RuntimeError("One or more presence profiles failed; all attempts are retained.")
        manifest["selections_frozen_before_development_scoring"] = True
        manifest["stage"] = "fit_complete_development_not_scored"
        manifest["status"] = "complete"
        manifest["finished_at_utc"] = time.time()
        write_manifest(manifest_path, manifest)
        return manifest
    except Exception as exc:
        manifest["status"] = "failed"
        manifest["error"] = {"type": type(exc).__name__, "message": str(exc),
                              "traceback": traceback.format_exc()}
        manifest["finished_at_utc"] = time.time()
        write_manifest(manifest_path, manifest)
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prepared", type=Path, required=True)
    parser.add_argument("--locked-root", type=Path, required=True)
    parser.add_argument("--bootstrap-source", type=Path, default=ROOT / "models/generate_baseline.py")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--protocol-sha256", required=True)
    args = parser.parse_args(argv)
    if not re.fullmatch(r"[0-9a-f]{40,64}", args.source_revision):
        parser.error("--source-revision must be a full lowercase Git object ID.")
    if not re.fullmatch(r"[0-9a-f]{64}", args.protocol_sha256):
        parser.error("--protocol-sha256 must be a lowercase SHA-256 digest.")
    output = args.output.resolve()
    results_root = (ROOT / "evaluation/results").resolve()
    if results_root not in output.parents:
        parser.error("--output must be a fresh child under evaluation/results.")
    protocol = ROOT / "paper/research/model-refactor-protocol.md"
    if not protocol.is_file():
        parser.error("Prospective model-refactor protocol is not present in this source revision.")
    run_fit(args.prepared, args.locked_root, args.bootstrap_source, output,
            args.source_revision, args.protocol_sha256)
    print(json.dumps({"status": "complete", "output": output.as_posix(),
                      "development_scored": False}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
