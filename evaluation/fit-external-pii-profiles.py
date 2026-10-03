"""Fit frozen sparse presence profiles and score external diagnostic partitions.

Input partitions are prepared by the separate provenance-audited preparation
caller. This fitter opens no locked development or final data.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
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

for _name in ("OPENBLAS_NUM_THREADS", "OMP_NUM_THREADS", "MKL_NUM_THREADS"):
    os.environ[_name] = "1"

import numpy as np
import scipy
import sklearn
import threadpoolctl
from sklearn.exceptions import ConvergenceWarning
from sklearn.linear_model import LogisticRegression
from threadpoolctl import threadpool_limits

from privoke_model.artifact import load_artifact, validate_artifact
from privoke_model.presence import SparsePresenceModel
from privoke_model.training_data import training_text_key
from privoke_eval.presence_evidence import load_frozen_fit as load_frozen_base_fit
from privoke_eval.presence_training import (
    RECALL_FLOOR, artifact_identity, binary_metrics,
    build_artifact, make_vectorizer, metrics_by_family, runtime_probabilities,
    select_threshold, serialized_runtime_model, source_family,
)

ROOT = Path(__file__).resolve().parents[1]
PROFILES = ("efficient", "balanced", "quality")
C_VALUES = (1.0, 10.0)
PARTITIONS = ("train", "validation", "nemotron_heldout", "meddies_heldout")
FROZEN_VALIDATION_SHA256 = "d2d0c538e49f5bbc7a8f85887b9b8cfddb188a5ab9aae55c69ce26ae932be6d1"
FROZEN_ORIGINAL_TRAIN_SHA256 = "da9a1b095587264714c5ae99c8a0f92329a04f6fc237a8ace7d71e837ede429d"
FROZEN_BOOTSTRAP_SOURCE_SHA256 = "75422c421d1a80d0cc3321979fb049f1045f02f334586d6fe62d8832f8a5a7dd"
ORIGINAL_TRAIN_ROW_COUNT = 3832
BASELINE_SOURCE_REVISION = "d52bf84d83addb827cc21b96f0be8ecc995bfaaa"
HEX64 = re.compile(r"[0-9a-f]{64}\Z")


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def read_jsonl(path: Path) -> list[dict]:
    rows = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSONL at {path.name}:{line_number}.") from exc
            if not isinstance(value, dict):
                raise ValueError(f"JSONL row at {path.name}:{line_number} must be an object.")
            rows.append(value)
    return rows


def write_exclusive(path: Path, value) -> str:
    raw = (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2,
                       allow_nan=False) + "\n").encode("utf-8")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())
    return sha256_bytes(raw)


def write_status(path: Path, value) -> None:
    temporary = path.with_name("." + path.name + ".tmp")
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2,
                     allow_nan=False) + "\n"
    temporary.write_text(raw, encoding="utf-8", newline="\n")
    os.replace(temporary, path)


def package_info() -> dict:
    return {"python": sys.version.split()[0], "platform": platform.platform(),
            "numpy": np.__version__, "scipy": scipy.__version__,
            "scikit_learn": sklearn.__version__, "threadpoolctl": threadpoolctl.__version__,
            "threads": {name: os.environ[name] for name in
                        ("OPENBLAS_NUM_THREADS", "OMP_NUM_THREADS", "MKL_NUM_THREADS")},
            "threadpool_limit": 1}


def partition_summary(rows: list[dict]) -> dict:
    """Count-only partition provenance; never copies source text or raw row IDs."""
    def counts(field):
        values = defaultdict(int)
        for row in rows:
            value = row.get(field, "__unavailable__")
            if value is None or value == "":
                value = "__unavailable__"
            values[str(value)] += 1
        return dict(sorted(values.items()))
    label_counts = {"positive": sum(row["expected_has_pii"] is True for row in rows),
                    "negative": sum(row["expected_has_pii"] is False for row in rows)}
    return {"rows": len(rows), "groups": len({row["group_id"] for row in rows}),
            "labels": label_counts, "source": counts("source"), "domain": counts("domain"),
            "document_format": counts("document_format")}


def _as_sha(value, name):
    if not isinstance(value, str) or not HEX64.fullmatch(value):
        raise ValueError(f"Prepared manifest {name} must be a lowercase SHA-256 digest.")
    return value


def validate_rows(rows: list[dict], name: str, *, require_metadata: bool = False) -> dict:
    ids, groups, texts = set(), set(), set()
    labels = []
    required = {"id", "group_id", "text", "text_key", "expected_has_pii"}
    metadata_required = {"source", "expected_categories", "domain", "document_format"}
    for index, row in enumerate(rows):
        row_required = required | (metadata_required if require_metadata else set())
        if not row_required.issubset(row):
            raise ValueError(f"{name} row {index} lacks required fields {sorted(row_required - set(row))}.")
        for field in ("id", "group_id"):
            if not isinstance(row[field], str) or not row[field].strip():
                raise ValueError(f"{name} row {index} has invalid {field}.")
        if "source" in row and (not isinstance(row["source"], str) or not row["source"].strip()):
            raise ValueError(f"{name} row {index} has invalid source.")
        for field in ("domain", "document_format"):
            if field in row and row[field] is not None and not isinstance(row[field], str):
                raise ValueError(f"{name} row {index} has invalid {field}.")
        if not isinstance(row["text"], str) or not row["text"].strip():
            raise ValueError(f"{name} row {index} has empty text.")
        if type(row["expected_has_pii"]) is not bool:
            raise ValueError(f"{name} row {index} target must be a strict boolean.")
        if "expected_categories" in row and (not isinstance(row["expected_categories"], list) or any(
                not isinstance(item, str) or not item for item in row["expected_categories"])):
            raise ValueError(f"{name} row {index} categories must be a string list.")
        key = training_text_key(row["text"])
        if not key or row["text_key"] != key:
            raise ValueError(f"{name} row {index} text_key is not canonical training_text_key.")
        if row["id"] in ids or key in texts:
            raise ValueError(f"{name} contains duplicate IDs or normalized text.")
        ids.add(row["id"])
        groups.add(row["group_id"])
        texts.add(key)
        labels.append(row["expected_has_pii"])
    return {"ids": ids, "groups": groups, "texts": texts,
            "positives": sum(labels), "negatives": len(labels) - sum(labels)}


def validate_prepared(prepared: Path, protocol_sha256: str,
                      original_train_reference: Path) -> dict:
    """Validate the exact declared preparation bundle; never open locked data."""
    manifest_path = prepared / "manifest.json"
    raw_manifest = manifest_path.read_bytes()
    manifest = json.loads(raw_manifest.decode("utf-8"))
    if manifest.get("status") != "prepared" or manifest.get("schema_version") != 1:
        raise ValueError("Prepared manifest must have status=prepared and schema_version=1.")
    if manifest.get("protocol_sha256") != protocol_sha256:
        raise ValueError("Prepared manifest protocol digest differs from the requested protocol.")
    _as_sha(manifest.get("source_audit_sha256"), "source_audit_sha256")
    _as_sha(manifest.get("exclusion_index_sha256"), "exclusion_index_sha256")
    bootstrap_sha = _as_sha(manifest.get("bootstrap_source_sha256"), "bootstrap_source_sha256")
    if bootstrap_sha != FROZEN_BOOTSTRAP_SOURCE_SHA256:
        raise ValueError("Prepared manifest bootstrap source differs from the frozen exclusion source.")
    source_revision = manifest.get("source_revision")
    if not isinstance(source_revision, str) or not re.fullmatch(r"[0-9a-f]{40,64}", source_revision):
        raise ValueError("Prepared manifest source_revision must be a full lowercase Git object ID.")
    refs = manifest.get("prepared_reference")
    if (not isinstance(refs, dict)
            or refs.get("validation_sha256") != FROZEN_VALIDATION_SHA256
            or refs.get("train_sha256") != FROZEN_ORIGINAL_TRAIN_SHA256):
        raise ValueError("Prepared source references do not bind the frozen v3 train/validation inputs.")
    partition_files, partition_hashes, row_counts, partitions, identities = {}, {}, {}, {}, {}
    for name in PARTITIONS:
        relative = manifest.get("partition_files", {}).get(name)
        if relative != f"{name.replace('_heldout', '-heldout')}.jsonl":
            raise ValueError(f"Prepared {name} file locator is not the expected fixed name.")
        path = (prepared / relative).resolve()
        if prepared.resolve() not in path.parents:
            raise ValueError("Prepared partition locator escapes its root.")
        digest = sha256_file(path)
        expected = _as_sha(manifest.get("partition_sha256", {}).get(name), f"{name} partition_sha256")
        if digest != expected:
            raise ValueError(f"Prepared {name} bytes do not match the manifest digest.")
        rows = read_jsonl(path)
        if manifest.get("rows", {}).get(name) != len(rows):
            raise ValueError(f"Prepared {name} row count differs from the manifest.")
        identities[name] = validate_rows(rows, name, require_metadata=name.endswith("heldout"))
        partition_files[name] = relative
        partition_hashes[name] = digest
        row_counts[name] = len(rows)
        partitions[name] = rows
    if partition_hashes["validation"] != FROZEN_VALIDATION_SHA256 or row_counts["validation"] != 968:
        raise ValueError("Prepared validation rows do not match the frozen 968-row reference.")
    original_train_bytes = original_train_reference.read_bytes()
    original_train_hash = sha256_bytes(original_train_bytes)
    if original_train_hash != FROZEN_ORIGINAL_TRAIN_SHA256:
        raise ValueError("Original frozen training reference digest mismatch.")
    original_train_rows = read_jsonl(original_train_reference)
    train_bytes = (prepared / partition_files["train"]).read_bytes()
    recorded_prefix_bytes = refs.get("train_bytes")
    if type(recorded_prefix_bytes) is not int or recorded_prefix_bytes != len(original_train_bytes):
        raise ValueError("Prepared manifest train_bytes does not match the frozen source prefix length.")
    if len(original_train_rows) != ORIGINAL_TRAIN_ROW_COUNT:
        raise ValueError(f"Original source training reference must contain exactly {ORIGINAL_TRAIN_ROW_COUNT:,} rows.")
    if (not original_train_bytes.endswith(b"\n")
            or train_bytes[:recorded_prefix_bytes] != original_train_bytes):
        raise ValueError("Expanded train JSONL does not preserve the original train bytes as its prefix.")
    if len(partitions["train"]) < len(original_train_rows):
        raise ValueError("Augmented train partition is shorter than its frozen original prefix.")
    if partitions["train"][:len(original_train_rows)] != original_train_rows:
        raise ValueError("Augmented train partition changed the original frozen training prefix.")
    if any(row_counts[name] > 1000 for name in ("nemotron_heldout", "meddies_heldout")):
        raise ValueError("An external diagnostic partition exceeds its 1,000-row target cap.")
    if row_counts["train"] > 20000:
        raise ValueError("Expanded training data exceed the fixed 20,000-row training cap.")
    # Cross-split disjointness is conservative: no shared source groups or text.
    for i, left in enumerate(PARTITIONS):
        for right in PARTITIONS[i + 1:]:
            for key in ("ids", "groups", "texts"):
                overlap = identities[left][key] & identities[right][key]
                if overlap:
                    raise ValueError(f"Prepared {left}/{right} {key} overlap.")
    for name in ("train", "validation"):
        identity = identities[name]
        if min(identity["positives"], identity["negatives"]) < 50:
            raise ValueError(f"Prepared {name} needs at least 50 examples of each class.")
    added_rows = partitions["train"][len(original_train_rows):]
    validate_rows(added_rows, "added train", require_metadata=True)
    if any(row["expected_has_pii"] is not True for row in added_rows):
        raise ValueError("Added-source train rows must be verified positive annotations only.")
    for name in ("nemotron_heldout", "meddies_heldout"):
        if any(row["expected_has_pii"] is not True for row in partitions[name]):
            raise ValueError(f"{name} must contain only verified positive rows; unlabelled rows cannot become negatives.")
    prepared_sha = sha256_bytes(raw_manifest)
    return {"manifest": manifest, "manifest_sha256": prepared_sha,
            "original_train_reference_sha256": original_train_hash,
            "partition_sha256": partition_hashes, "partition_rows": row_counts,
            "partition_files": partition_files, "partitions": partitions,
            "identities": identities}


def _metadata(profile, c_value, source_revision, protocol_sha256, inputs):
    return {"release_version": "v1.0.0", "training_revision": "0",
            "training_strategy": "external_piimb_sparse_tfidf_logistic",
            "task": "annotation_presence", "profile": profile,
            "normalization": "training_text_key_v1",
            "arithmetic": "float32_parameters_float64_features_fsum_v1",
            "selected_C": repr(float(c_value)), "training_seed": "7102026",
            "source_revision": source_revision, "protocol_sha256": protocol_sha256,
            "prepared_manifest_sha256": inputs["manifest_sha256"],
            "train_sha256": inputs["partition_sha256"]["train"],
            "validation_sha256": inputs["partition_sha256"]["validation"],
            "source_audit_sha256": inputs["manifest"]["source_audit_sha256"],
            "exclusion_index_sha256": inputs["manifest"]["exclusion_index_sha256"],
            "bootstrap_source_sha256": inputs["manifest"]["bootstrap_source_sha256"],
            "weight_format": "json-float32"}


def prediction_rows(rows, probabilities, threshold):
    if len(rows) != len(probabilities):
        raise ValueError("Row/probability count mismatch.")
    out = []
    for row, probability in zip(rows, probabilities):
        if not math.isfinite(probability) or not 0 <= probability <= 1:
            raise ValueError("Shared runtime produced an invalid probability.")
        out.append({"id_sha256": sha256_bytes(row["id"].encode("utf-8")),
                    "group_id_sha256": sha256_bytes(row["group_id"].encode("utf-8")),
                    "source_family": source_family(row["group_id"]),
                    "expected_has_pii": row["expected_has_pii"],
                    "probability": probability, "prediction": probability >= threshold})
    return out


def _metric_groups(rows, probabilities, threshold):
    """Pooled and source/category/domain/format/length strata; absent classes null."""
    if len(rows) != len(probabilities):
        raise ValueError("Metric rows and probabilities are not aligned.")
    if not rows:
        return {"pooled": {"rows": 0, "tp": 0, "tn": 0, "fp": 0, "fn": 0,
                           "positive_examples": 0, "absent_examples": 0,
                           "recall": None, "specificity": None, "balanced_accuracy": None}}
    groups = defaultdict(lambda: ([], []))
    for row, probability in zip(rows, probabilities):
        label = row["expected_has_pii"]
        entries = [("source_family", source_family(row["group_id"])),
                   ("domain", row.get("domain", "__unavailable__")),
                   ("document_format", row.get("document_format", "__unavailable__"))]
        categories = row.get("expected_categories", []) or ["__none__"]
        entries.extend(("category", value) for value in categories)
        length = len(row["text"])
        length_bin = "lt256" if length < 256 else "256_1023" if length < 1024 else "ge1024"
        entries.append(("text_length_chars", length_bin))
        for dimension, value in entries:
            groups[(dimension, value)][0].append(label)
            groups[(dimension, value)][1].append(probability)
    result = {"pooled": {"rows": len(rows), **binary_metrics(
        [row["expected_has_pii"] for row in rows], probabilities, threshold)}}
    for (dimension, value), (labels, scores) in sorted(groups.items()):
        result.setdefault(dimension, {})[value] = {"rows": len(labels),
                                                   **binary_metrics(labels, scores, threshold)}
    return result


def _candidate_fit(profile, c_value, vectorizer, x_train, train_rows, validation_rows,
                   source_revision, protocol_sha256, inputs, output):
    y_train = np.asarray([int(row["expected_has_pii"]) for row in train_rows], dtype=np.int8)
    estimator = LogisticRegression(C=c_value, class_weight="balanced", solver="lbfgs",
                                   max_iter=1000, tol=1e-4, random_state=7102026)
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        estimator.fit(x_train, y_train)
    warning_records = [{"category": item.category.__name__, "message": str(item.message)}
                       for item in caught]
    converged = not any(issubclass(item.category, ConvergenceWarning) for item in caught)
    base_artifact = build_artifact(vectorizer, estimator, profile, 0.5,
                                   _metadata(profile, c_value, source_revision, protocol_sha256, inputs))
    base_model = serialized_runtime_model(base_artifact)
    validation_probabilities = runtime_probabilities(base_model, validation_rows)
    threshold, metrics = select_threshold(
        [row["expected_has_pii"] for row in validation_rows], validation_probabilities, RECALL_FLOOR)
    artifact = build_artifact(vectorizer, estimator, profile, threshold,
                              _metadata(profile, c_value, source_revision, protocol_sha256, inputs))
    validate_artifact(artifact)
    model = serialized_runtime_model(artifact)
    if runtime_probabilities(model, validation_rows) != validation_probabilities:
        raise ValueError("Serialized candidate changed runtime validation probabilities.")
    path = output / "profiles" / profile / f"C-{c_value:g}-artifact.json"
    digest = write_exclusive(path, artifact)
    predictions = prediction_rows(validation_rows, validation_probabilities, threshold)
    return {"C": c_value, "converged": converged, "warnings": warning_records,
            "threshold": threshold, "validation_metrics": metrics,
            "validation_strata": _metric_groups(validation_rows, validation_probabilities, threshold),
            "validation_predictions": predictions,
            "artifact_file": path.relative_to(output).as_posix(),
            "artifact_sha256": digest, "artifact_identity": artifact_identity(artifact)}


def fit_profiles(prepared: Path, output: Path, *, source_revision: str,
                 protocol_sha256: str, protocol_file: Path,
                 original_train_reference: Path, baseline_fit_root: Path) -> dict:
    if sha256_file(protocol_file) != protocol_sha256:
        raise ValueError("Supplied protocol digest does not match protocol file bytes.")
    if not re.fullmatch(r"[0-9a-f]{40,64}", source_revision):
        raise ValueError("source_revision must be a full lowercase Git object ID.")
    output.mkdir(parents=True, exist_ok=False)
    run = {"status": "running", "stage": "input_validation", "source_revision": source_revision,
           "protocol_sha256": protocol_sha256, "protocol_file_sha256": sha256_file(protocol_file),
           "script_sha256": sha256_file(Path(__file__)),
           "helper_sha256": sha256_file(ROOT / "evaluation/privoke_eval/presence_training.py"),
           "packages": package_info(), "profiles": {}, "errors": [], "started_at_unix": time.time()}
    run_path = output / "run-manifest.json"
    write_status(run_path, run)
    try:
        inputs = validate_prepared(prepared, protocol_sha256, original_train_reference)
        baseline_profiles = _load_baseline_models(baseline_fit_root)
        run["prepared_manifest_sha256"] = inputs["manifest_sha256"]
        run["prepared_source_revision"] = inputs["manifest"]["source_revision"]
        run["prepared_provenance"] = {key: inputs["manifest"][key] for key in
                                       ("source_audit_sha256", "exclusion_index_sha256",
                                        "bootstrap_source_sha256")}
        run["partition_sha256"] = inputs["partition_sha256"]
        run["partition_rows"] = inputs["partition_rows"]
        run["partition_summaries"] = {name: partition_summary(rows)
                                       for name, rows in inputs["partitions"].items()}
        run["original_train_reference_sha256"] = inputs["original_train_reference_sha256"]
        run["baseline_fit_manifest_sha256"] = baseline_profiles["manifest_sha256"]
        run["baseline_profiles"] = {name: artifact_identity(item[0])
                                     for name, item in baseline_profiles["profiles"].items()}
        train_rows, validation_rows = inputs["partitions"]["train"], inputs["partitions"]["validation"]
        run["stage"] = "fit_profiles_validation_only"
        write_status(run_path, run)
        for profile in PROFILES:
            profile_record = {"status": "running", "candidate_C_values": list(C_VALUES),
                              "warnings": [], "candidate_failures": []}
            run["profiles"][profile] = profile_record
            profile_dir = output / "profiles" / profile
            profile_dir.mkdir(parents=True, exist_ok=True)
            try:
                vectorizer = make_vectorizer(profile)
                train_texts = [training_text_key(row["text"]) for row in train_rows]
                with warnings.catch_warnings(record=True) as vector_warnings:
                    warnings.simplefilter("always")
                    x_train = vectorizer.fit_transform(train_texts)
                profile_record["vectorizer_warnings"] = [
                    {"category": w.category.__name__, "message": str(w.message)} for w in vector_warnings]
                if x_train.shape[1] == 0:
                    raise ValueError("Train-only vectorizer produced no columns.")
                candidates = []
                with threadpool_limits(limits=1):
                    for c_value in C_VALUES:
                        try:
                            candidates.append(_candidate_fit(
                                profile, c_value, vectorizer, x_train, train_rows, validation_rows,
                                source_revision, protocol_sha256, inputs, output))
                        except Exception as exc:
                            failure = {"C": c_value, "error_type": type(exc).__name__,
                                       "error": str(exc), "traceback": traceback.format_exc()}
                            profile_record["candidate_failures"].append(failure)
                converged = [item for item in candidates if item["converged"]]
                if not converged:
                    profile_record.update({"status": "failed", "candidates": candidates,
                                           "failure": "No converged valid candidate."})
                else:
                    input_hashes = {"manifest_sha256": inputs["manifest_sha256"],
                                    "partition_sha256": {name: inputs["partition_sha256"][name]
                                                         for name in ("train", "validation")}}
                    selected = max(converged, key=lambda item: (
                        item["validation_metrics"]["balanced_accuracy"],
                        item["validation_metrics"]["specificity"],
                        item["validation_metrics"]["recall"], -item["C"]))
                    profile_record.update({"status": "selected", "candidates": candidates,
                        "selected_C": selected["C"], "threshold": selected["threshold"],
                        "selected_artifact_file": selected["artifact_file"],
                        "selected_artifact_sha256": selected["artifact_sha256"],
                        "artifact_identity": selected["artifact_identity"],
                        "source_revision": source_revision, "protocol_sha256": protocol_sha256,
                        "input_hashes": input_hashes,
                        "selection_rule": "validation balanced_accuracy, specificity, recall, then lower C",
                        "threshold_rule": "maximum validation specificity subject to recall >= 0.90; ties higher recall then higher threshold"})
            except Exception as exc:
                profile_record.update({"status": "failed", "error_type": type(exc).__name__,
                                       "error": str(exc), "traceback": traceback.format_exc()})
            selection_path = profile_dir / "selection.json"
            selection_sha = write_exclusive(selection_path, profile_record)
            run.setdefault("selection_sha256", {})[profile] = selection_sha
            write_status(run_path, run)
        if any(item.get("status") != "selected" for item in run["profiles"].values()):
            raise RuntimeError("Every fixed profile must select a converged validation candidate before diagnostics.")
        freeze = {"schema_version": 1, "status": "all_profiles_frozen",
                  "selections_frozen_before_diagnostic_scoring": True,
                  "source_revision": source_revision, "protocol_sha256": protocol_sha256,
                  "prepared_manifest_sha256": inputs["manifest_sha256"],
                  "prepared_source_revision": inputs["manifest"]["source_revision"],
                  "prepared_provenance": run["prepared_provenance"],
                  "partition_sha256": inputs["partition_sha256"],
                  "selection_sha256": run["selection_sha256"],
                  "baseline_fit_manifest_sha256": baseline_profiles["manifest_sha256"],
                  "baseline_profiles": run["baseline_profiles"],
                  "profiles": run["profiles"], "candidate_C_values": list(C_VALUES)}
        freeze_path = output / "fit-freeze.json"
        freeze_sha256 = write_exclusive(freeze_path, freeze)
        run["fit_freeze_sha256"] = freeze_sha256
        run["selection_frozen_before_diagnostic_scoring"] = True
        run["selections_frozen_before_diagnostic_scoring"] = True
        # Every selection is frozen before any development scoring; this fitter
        # does not open development at all.
        run["selections_frozen_before_development_scoring"] = True
        run["stage"] = "validation_frozen"
        write_status(run_path, run)
        # Diagnostics begin only after the durable freeze file and its digest exist.
        diagnostics = score_diagnostics(inputs, output, freeze_path, freeze_sha256,
                                        baseline_profiles["profiles"])
        run["diagnostics_sha256"] = sha256_file(output / "diagnostics.json")
        run["diagnostic_status"] = diagnostics["status"]
        run["status"] = "complete"
        run["stage"] = "diagnostics_scored"
        run["finished_at_unix"] = time.time()
        write_status(run_path, run)
        return run
    except Exception as exc:
        run["status"] = "failed"
        run["failure"] = {"stage": run.get("stage"), "type": type(exc).__name__,
                          "error": str(exc), "traceback": traceback.format_exc()}
        run["finished_at_unix"] = time.time()
        write_status(run_path, run)
        raise


def _load_profile_artifact(output: Path, freeze: dict, profile: str) -> tuple[dict, SparsePresenceModel]:
    record = freeze["profiles"][profile]
    path = (output / record["selected_artifact_file"]).resolve()
    if output.resolve() not in path.parents or sha256_file(path) != record["selected_artifact_sha256"]:
        raise ValueError(f"Frozen {profile} selected artifact digest mismatch.")
    artifact = load_artifact(path)
    if artifact_identity(artifact) != record["artifact_identity"]:
        raise ValueError(f"Frozen {profile} selected artifact identity mismatch.")
    if artifact["metadata"].get("selected_C") != repr(float(record["selected_C"])):
        raise ValueError(f"Frozen {profile} artifact C differs from selection.")
    return artifact, serialized_runtime_model(artifact)


def verify_frozen_selections(output: Path, freeze_path: Path, freeze_sha256: str,
                             profiles_manifest: dict, selection_sha256: dict,
                             source_revision: str, protocol_sha256: str,
                             input_hashes: dict,
                             validation_rows: list[dict]) -> tuple[dict, dict]:
    """Recheck every selection and candidate artifact before diagnostic inference."""
    if sha256_file(freeze_path) != freeze_sha256:
        raise ValueError("Frozen fit-selection manifest changed before diagnostic scoring.")
    freeze = read_json(freeze_path)
    if (freeze.get("status") != "all_profiles_frozen"
            or freeze.get("selections_frozen_before_diagnostic_scoring") is not True
            or freeze.get("profiles") != profiles_manifest
            or set(profiles_manifest) != set(PROFILES)
            or freeze.get("candidate_C_values") != list(C_VALUES)):
        raise ValueError("Diagnostics require the exact persisted three-profile/two-C freeze.")
    selected_models = {}
    for profile in PROFILES:
        record = profiles_manifest[profile]
        selection_path = output / "profiles" / profile / "selection.json"
        if (record.get("status") != "selected"
                or sha256_file(selection_path) != selection_sha256.get(profile)
                or read_json(selection_path) != record):
            raise ValueError(f"Frozen {profile} selection file does not match its digest/content.")
        expected_inputs = {"manifest_sha256": input_hashes["manifest_sha256"],
                           "partition_sha256": {key: input_hashes["partition_sha256"][key]
                                                for key in ("train", "validation")}}
        if (record.get("source_revision") != source_revision
                or record.get("protocol_sha256") != protocol_sha256
                or record.get("input_hashes") != expected_inputs):
            raise ValueError(f"Frozen {profile} selection provenance differs from the fit inputs.")
        candidates = record.get("candidates")
        failures = record.get("candidate_failures")
        if not isinstance(candidates, list) or not isinstance(failures, list):
            raise ValueError(f"Frozen {profile} candidate/failure records are malformed.")
        covered = [item.get("C") for item in candidates] + [item.get("C") for item in failures]
        if len(covered) != len(set(covered)) or set(covered) != set(C_VALUES):
            raise ValueError(f"Frozen {profile} records do not account for each fixed C exactly once.")
        for candidate in candidates:
            if type(candidate.get("converged")) is not bool:
                raise ValueError(f"Frozen {profile} candidate lacks strict convergence status.")
            path = (output / candidate["artifact_file"]).resolve()
            if output.resolve() not in path.parents or sha256_file(path) != candidate.get("artifact_sha256"):
                raise ValueError(f"Frozen {profile} candidate artifact digest mismatch.")
            artifact = load_artifact(path)
            metadata = artifact.get("metadata", {})
            if (artifact_identity(artifact) != candidate.get("artifact_identity")
                    or metadata.get("selected_C") != repr(float(candidate["C"]))
                    or candidate.get("threshold") != artifact["config"]["threshold"]
                    or artifact.get("config", {}).get("profile") != profile
                    or metadata.get("source_revision") != source_revision
                    or metadata.get("protocol_sha256") != protocol_sha256
                    or metadata.get("prepared_manifest_sha256") != input_hashes["manifest_sha256"]
                    or metadata.get("train_sha256") != input_hashes["partition_sha256"]["train"]
                    or metadata.get("validation_sha256") != input_hashes["partition_sha256"]["validation"]):
                raise ValueError(f"Frozen {profile} candidate identity/provenance mismatch.")
            probabilities = runtime_probabilities(serialized_runtime_model(artifact), validation_rows)
            threshold, metrics = select_threshold(
                [row["expected_has_pii"] for row in validation_rows], probabilities, RECALL_FLOOR)
            if (threshold != candidate.get("threshold")
                    or metrics != candidate.get("validation_metrics")
                    or prediction_rows(validation_rows, probabilities, threshold)
                    != candidate.get("validation_predictions")
                    or _metric_groups(validation_rows, probabilities, threshold)
                    != candidate.get("validation_strata")):
                raise ValueError(f"Frozen {profile} validation evidence does not recompute from its artifact.")
        eligible = [item for item in candidates if item.get("converged") is True]
        if not eligible:
            raise ValueError(f"Frozen {profile} has no converged candidate.")
        ranked = max(eligible, key=lambda item: (
            item["validation_metrics"]["balanced_accuracy"],
            item["validation_metrics"]["specificity"],
            item["validation_metrics"]["recall"], -item["C"]))
        if (record.get("selected_C") != ranked["C"]
                or record.get("threshold") != ranked["threshold"]
                or record.get("selected_artifact_sha256") != ranked["artifact_sha256"]
                or record.get("artifact_identity") != ranked["artifact_identity"]):
            raise ValueError(f"Frozen {profile} selection does not replay validation-only ranking.")
        selected_models[profile] = _load_profile_artifact(output, freeze, profile)
    return freeze, selected_models


def score_diagnostics(inputs: dict, output: Path, freeze_path: Path, freeze_sha256: str,
                      baseline_profiles: dict) -> dict:
    """Verify complete immutable freeze before any external diagnostic inference."""
    run = read_json(output / "run-manifest.json")
    freeze = read_json(freeze_path)
    _, selected_models = verify_frozen_selections(
        output, freeze_path, freeze_sha256, run["profiles"], run["selection_sha256"],
        run["source_revision"], run["protocol_sha256"],
        {"manifest_sha256": inputs["manifest_sha256"],
         "partition_sha256": inputs["partition_sha256"]},
        inputs["partitions"]["validation"])
    partitions = inputs["partitions"]
    results = {}
    for partition_name in ("validation", "nemotron_heldout", "meddies_heldout"):
        rows = partitions[partition_name]
        result_profiles = {}
        for profile in PROFILES:
            artifact, model = selected_models[profile]
            threshold = artifact["config"]["threshold"]
            probabilities = runtime_probabilities(model, rows)
            result_profiles[profile] = {"model_identity": artifact_identity(artifact),
                "metrics": _metric_groups(rows, probabilities, threshold),
                "predictions": prediction_rows(rows, probabilities, threshold)}
        for base_profile, (base_artifact, base_model) in baseline_profiles.items():
            base_probs = runtime_probabilities(base_model, rows)
            base_threshold = base_artifact["config"]["threshold"]
            result_profiles[f"{base_profile}_control_base"] = {
                "model_identity": artifact_identity(base_artifact),
                "metrics": _metric_groups(rows, base_probs, base_threshold),
                "predictions": prediction_rows(rows, base_probs, base_threshold)}
        paired = {}
        for profile in PROFILES:
            candidate_predictions = result_profiles[profile]["predictions"]
            control_predictions = result_profiles[f"{profile}_control_base"]["predictions"]
            changes = {"positive": {"candidate_only": 0, "control_only": 0,
                                     "both": 0, "neither": 0},
                       "negative": {"candidate_only": 0, "control_only": 0,
                                     "both": 0, "neither": 0}}
            for candidate_row, control_row in zip(candidate_predictions, control_predictions):
                if (candidate_row["id_sha256"] != control_row["id_sha256"]
                        or candidate_row["expected_has_pii"] != control_row["expected_has_pii"]):
                    raise ValueError("Candidate/control predictions are not paired on identical rows.")
                label = "positive" if candidate_row["expected_has_pii"] else "negative"
                candidate_yes, control_yes = candidate_row["prediction"], control_row["prediction"]
                cell = ("both" if candidate_yes and control_yes else
                        "candidate_only" if candidate_yes else
                        "control_only" if control_yes else "neither")
                changes[label][cell] += 1
            paired[profile] = changes
        results[partition_name] = {"models": result_profiles, "paired_candidate_vs_base": paired}
    result = {"schema_version": 1, "status": "complete",
              "fit_freeze_sha256": freeze_sha256,
              "source_revision": freeze["source_revision"], "protocol_sha256": freeze["protocol_sha256"],
              "partition_sha256": inputs["partition_sha256"], "results": results}
    write_exclusive(output / "diagnostics.json", result)
    return result


def _load_baseline_models(fit_root: Path):
    """Load all three exact original fitted bases from the completed profile fit."""
    run_path = fit_root / "run-manifest.json"
    run = read_json(run_path)
    base_source = run.get("source_revision")
    base_protocol = run.get("protocol_sha256")
    if base_source != BASELINE_SOURCE_REVISION or not isinstance(base_protocol, str) or not HEX64.fullmatch(base_protocol):
        raise ValueError("Baseline fit root source/protocol identity is not the completed pinned fit.")
    verified = {}
    for profile in PROFILES:
        selection_path = fit_root / "profiles" / profile / "selection.json"
        verified[profile] = load_frozen_base_fit(
            selection_path, run_path, fit_source_revision=base_source,
            protocol_sha256=base_protocol)
    profiles = {name: (item["artifact"], serialized_runtime_model(item["artifact"]))
                for name, item in verified.items()}
    return {"manifest_sha256": sha256_file(run_path), "profiles": profiles}


def load_completed_fit(output: Path, prepared: Path, *, source_revision: str,
                       protocol_sha256: str,
                       original_train_reference: Path | None = None) -> dict:
    """Public strict loader for later scoring callers; does not read development/final."""
    output = Path(output).resolve()
    prepared = Path(prepared).resolve()
    if original_train_reference is None:
        original_train_reference = ROOT / "evaluation/results/representation_20261004_v3/prepared/train.jsonl"
    original_train_reference = Path(original_train_reference).resolve()
    inputs = validate_prepared(prepared, protocol_sha256, original_train_reference)
    manifest_path = output / "run-manifest.json"
    run = read_json(manifest_path)
    if (run.get("status") != "complete"
            or run.get("selections_frozen_before_diagnostic_scoring") is not True
            or run.get("selections_frozen_before_development_scoring") is not True
            or run.get("source_revision") != source_revision
            or run.get("protocol_sha256") != protocol_sha256
            or run.get("prepared_manifest_sha256") != inputs["manifest_sha256"]
            or run.get("partition_sha256") != inputs["partition_sha256"]
            or not isinstance(run.get("profiles"), dict)
            or set(run["profiles"]) != set(PROFILES)):
        raise ValueError("External fit manifest is incomplete or has mismatched source/protocol identity.")
    freeze_path = output / "fit-freeze.json"
    freeze_sha = sha256_file(freeze_path)
    if freeze_sha != run.get("fit_freeze_sha256"):
        raise ValueError("External fit freeze digest mismatch.")
    freeze, _ = verify_frozen_selections(
        output, freeze_path, freeze_sha, run["profiles"], run["selection_sha256"],
        source_revision, protocol_sha256,
        {"manifest_sha256": inputs["manifest_sha256"],
         "partition_sha256": inputs["partition_sha256"]},
        inputs["partitions"]["validation"])
    diagnostic_path = output / "diagnostics.json"
    if sha256_file(diagnostic_path) != run.get("diagnostics_sha256"):
        raise ValueError("External diagnostic report digest mismatch.")
    diagnostics = read_json(diagnostic_path)
    if (diagnostics.get("status") != "complete"
            or diagnostics.get("fit_freeze_sha256") != freeze_sha
            or diagnostics.get("source_revision") != source_revision
            or diagnostics.get("protocol_sha256") != protocol_sha256
            or diagnostics.get("partition_sha256") != inputs["partition_sha256"]):
        raise ValueError("External diagnostic report differs from the frozen fit inputs.")
    profiles = {}
    for profile in PROFILES:
        selection = run["profiles"][profile]
        artifact_path = (output / selection["selected_artifact_file"]).resolve()
        profiles[profile] = {"selection": selection, "artifact": load_artifact(artifact_path),
                             "artifact_path": artifact_path}
    return {"manifest": run, "manifest_sha256": sha256_file(manifest_path),
            "freeze_sha256": freeze_sha, "profiles": profiles}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prepared", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--protocol-file", type=Path, required=True)
    parser.add_argument("--protocol-sha256", required=True)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--baseline-fit-root", type=Path, required=True)
    parser.add_argument("--original-train-reference", type=Path,
                        default=ROOT / "evaluation/results/representation_20261004_v3/prepared/train.jsonl")
    args = parser.parse_args(argv)
    if not HEX64.fullmatch(args.protocol_sha256):
        parser.error("--protocol-sha256 must be lowercase SHA-256.")
    if not re.fullmatch(r"[0-9a-f]{40,64}", args.source_revision):
        parser.error("--source-revision must be a full lowercase Git object ID.")
    prepared = args.prepared.resolve()
    output = args.output.resolve()
    fit_profiles(prepared, output, source_revision=args.source_revision,
                 protocol_sha256=args.protocol_sha256, protocol_file=args.protocol_file.resolve(),
                 original_train_reference=args.original_train_reference.resolve(),
                 baseline_fit_root=args.baseline_fit_root.resolve())
    print(json.dumps({"status": "complete", "output": output.as_posix(),
                      "development_scored": False, "final_opened": False}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
