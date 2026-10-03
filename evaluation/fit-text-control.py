"""Run the pinned offline lexical text-feature control on v3 prepared rows."""
import argparse
import ast
from collections import defaultdict
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import platform
import re
import sys
import traceback
import warnings

import numpy as np
import scipy
import sklearn
import threadpoolctl
from sklearn.exceptions import ConvergenceWarning
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import FeatureUnion
from threadpoolctl import threadpool_limits

from privoke_model.training_data import training_text_key


ROOT = Path(__file__).resolve().parents[1]
PARTITIONS = ("train", "validation", "development")
EXPECTED_PREPARED_MANIFEST_SHA256 = "1ddd514c1660a9ebd1288f93937f17b5aa6c91517573c2d25b37f74846486767"
EXPECTED_LOCKED_MANIFEST_SHA256 = "57461a8cbbb667e6471b32f6ea80896a0249e54e2a7bde1feff1bd9f982a3a88"
EXPECTED_LOCKED_SHA256 = {
    "development": "65bf02af1f9f7167a5aa5eaaa8aeac54111c90d009585ed36570d3ce0a635095",
    "final": "613a78b9e5fa677904125b4c056fb8d57d15fb6ebd9c443a75f406ae3ac05515",
}
EXPECTED_PARTITIONS = {
    "train": (3832, "da9a1b095587264714c5ae99c8a0f92329a04f6fc237a8ace7d71e837ede429d"),
    "validation": (968, "d2d0c538e49f5bbc7a8f85887b9b8cfddb188a5ab9aae55c69ce26ae932be6d1"),
    "development": (502, "45f91e320482dde4d0724cdf42a341649d52e33aeae326f059c714edc97cc706"),
}
EXPECTED_REVISION = "4a13e9ffe6fd0d275efbde8afd4d8d8f1ffc2133"
EXPECTED_BOOTSTRAP_SHA256 = "75422c421d1a80d0cc3321979fb049f1045f02f334586d6fe62d8832f8a5a7dd"
C_VALUES = (0.1, 1.0, 10.0)
SEED = 7102026


def load_probe_helpers():
    """Reuse the frozen representation diagnostic's audited row and metric logic."""
    helper_path = ROOT / "evaluation/fit-representation-probe.py"
    spec = importlib.util.spec_from_file_location("fit_representation_probe_helpers", helper_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("Could not load frozen representation validation helpers.")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


PROBE = load_probe_helpers()


def sha256_file(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def read_jsonl(path):
    return PROBE.read_jsonl(path)


def source_family(group_id):
    family = group_id.split(":", 1)[0]
    if not family:
        raise ValueError("Source group has no family prefix.")
    return family


def validate_disjoint_partitions(partitions):
    identities = {}
    for name in PARTITIONS:
        rows = partitions[name]
        if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
            raise ValueError(f"Prepared {name} partition must be a list of objects.")
        identities[name] = PROBE.validate_partition_rows(rows, name)
        if name in ("train", "validation"):
            labels = [row["expected_has_pii"] for row in rows]
            if min(sum(labels), len(labels) - sum(labels)) < 50:
                raise ValueError(f"Prepared {name} has fewer than 50 examples of each label.")
    for left, right in (("train", "validation"), ("train", "development"),
                        ("validation", "development")):
        for identity in ("ids", "groups", "texts"):
            if identities[left][identity] & identities[right][identity]:
                raise ValueError(f"Prepared {left}/{right} {identity} overlap.")
    return identities


def bootstrap_text_keys(bootstrap_source):
    tree = ast.parse(Path(bootstrap_source).read_text(encoding="utf-8"))
    function = next((node for node in tree.body
                     if isinstance(node, ast.FunctionDef) and node.name == "training_samples"), None)
    if function is None:
        raise ValueError("Pinned bootstrap source lacks training_samples().")
    namespace = {}
    exec(compile(ast.Module(body=[function], type_ignores=[]), "bootstrap_samples", "exec"), namespace)
    samples = namespace["training_samples"]()
    if len(samples) != 43:
        raise ValueError("Pinned bootstrap source must return exactly 43 training samples.")
    return {training_text_key(row[0]) for row in samples}


def validate_bootstrap_disjoint(partitions, bootstrap_keys):
    for name in ("train", "validation"):
        overlap = {row["text_key"] for row in partitions[name]} & bootstrap_keys
        if overlap:
            raise ValueError(f"Prepared {name} overlaps normalized bootstrap training text.")


def validate_identity_inputs(prepared_dir, locked_root, bootstrap_source):
    """Fail closed unless inputs are exactly the already-audited v3 partitions."""
    prepared_dir, locked_root, bootstrap_source = map(Path, (prepared_dir, locked_root, bootstrap_source))
    manifest_path = prepared_dir / "manifest.json"
    manifest_bytes = manifest_path.read_bytes()
    if hashlib.sha256(manifest_bytes).hexdigest() != EXPECTED_PREPARED_MANIFEST_SHA256:
        raise ValueError("Prepared manifest is not the pinned v3 manifest.")
    manifest = json.loads(manifest_bytes)
    if (manifest.get("dataset") != "piimb" or manifest.get("revision") != EXPECTED_REVISION
            or manifest.get("seed") != 5102026 or manifest.get("validation_seed") != 6102026):
        raise ValueError("Prepared manifest dataset or seed identity differs from v3.")
    if manifest.get("rows") != {name: EXPECTED_PARTITIONS[name][0] for name in PARTITIONS}:
        raise ValueError("Prepared manifest row counts differ from v3.")
    if manifest.get("locked_sha256") != EXPECTED_LOCKED_SHA256:
        raise ValueError("Prepared manifest protected-partition digests differ from v3.")

    partition_rows, partition_hashes = {}, {}
    for name in PARTITIONS:
        path = prepared_dir / f"{name}.jsonl"
        digest = sha256_file(path)
        expected_count, expected_digest = EXPECTED_PARTITIONS[name]
        if digest != expected_digest or digest != manifest.get("partition_sha256", {}).get(name):
            raise ValueError(f"Prepared {name} digest is not the pinned v3 digest.")
        rows = read_jsonl(path)
        if len(rows) != expected_count:
            raise ValueError(f"Prepared {name} row count differs from v3.")
        partition_rows[name] = rows
        partition_hashes[name] = digest
    identities = validate_disjoint_partitions(partition_rows)

    locked_manifest_path = locked_root / "manifest.json"
    locked_manifest_bytes = locked_manifest_path.read_bytes()
    if hashlib.sha256(locked_manifest_bytes).hexdigest() != EXPECTED_LOCKED_MANIFEST_SHA256:
        raise ValueError("Locked manifest differs from the pinned public-data manifest.")
    locked_manifest = json.loads(locked_manifest_bytes)
    locked_hashes = {}
    for name, expected_digest in EXPECTED_LOCKED_SHA256.items():
        path = locked_root / f"{name}.jsonl"
        digest = sha256_file(path)
        if digest != expected_digest or digest != locked_manifest.get("partitions", {}).get(name, {}).get("sha256"):
            raise ValueError(f"Locked {name} digest differs from the pinned reference.")
        locked_hashes[name] = digest

    # Only the locked development file is parsed; final is verified by digest only.
    locked_development = read_jsonl(locked_root / "development.jsonl")
    PROBE.validate_development_source(partition_rows["development"], locked_development)

    bootstrap_digest = sha256_file(bootstrap_source)
    if (bootstrap_digest != EXPECTED_BOOTSTRAP_SHA256
            or bootstrap_digest != manifest.get("bootstrap_source_sha256")):
        raise ValueError("Bootstrap source differs from the pinned v3 manifest.")
    bootstrap_keys = bootstrap_text_keys(bootstrap_source)
    validate_bootstrap_disjoint(partition_rows, bootstrap_keys)

    return {"manifest": manifest, "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
            "locked_manifest_sha256": hashlib.sha256(locked_manifest_bytes).hexdigest(),
            "locked_sha256": locked_hashes, "partition_sha256": partition_hashes,
            "partitions": partition_rows, "bootstrap_source_sha256": bootstrap_digest}


def make_vectorizer():
    common = {"min_df": 2, "max_features": 40000, "lowercase": False,
              "use_idf": True, "smooth_idf": True, "sublinear_tf": True,
              "norm": "l2", "dtype": np.float64}
    word = TfidfVectorizer(analyzer="word", ngram_range=(1, 2),
                           token_pattern=r"(?u)\b\w\w+\b", **common)
    char = TfidfVectorizer(analyzer="char", ngram_range=(3, 5), **common)
    return FeatureUnion([("word", word), ("char", char)], n_jobs=1)


def vectorizer_configuration():
    return {"type": "sklearn.pipeline.FeatureUnion", "transformer_weights": None,
            "branches": {
                "word": {"analyzer": "word", "ngram_range": [1, 2],
                         "token_pattern": r"(?u)\b\w\w+\b"},
                "char": {"analyzer": "char", "ngram_range": [3, 5]},
            },
            "shared": {"min_df": 2, "max_features": 40000, "lowercase": False,
                       "use_idf": True, "smooth_idf": True, "sublinear_tf": True,
                       "norm": "l2", "dtype": "float64", "input_text": "training_text_key(full_text)"}}


def export_vectorizer(vectorizer):
    branches = {}
    dimensions = 0
    for name, branch in vectorizer.transformer_list:
        vocabulary = {feature: int(index) for feature, index in branch.vocabulary_.items()}
        ordered_features = [feature for feature, _ in sorted(vocabulary.items(), key=lambda item: item[1])]
        idf = [float(value) for value in branch.idf_]
        if len(ordered_features) != len(idf) or not all(math.isfinite(value) for value in idf):
            raise ValueError(f"Vectorizer branch {name} has invalid vocabulary/IDF values.")
        branches[name] = {"vocabulary": vocabulary, "idf": idf, "features_by_index": ordered_features,
                          "n_features": len(ordered_features)}
        dimensions += len(ordered_features)
    return {"configuration": vectorizer_configuration(), "branches": branches,
            "n_features": dimensions, "column_order": "word then char; branch vocabulary indices ascending"}


def row_probabilities(rows, probability, threshold):
    predicted = np.asarray(probability) >= threshold
    records = PROBE.make_rows([row["id"] for row in rows], [row["group_id"] for row in rows],
                              np.asarray([row["expected_has_pii"] for row in rows], dtype=np.int8),
                              probability, predicted)
    for row, record in zip(rows, records):
        record["source_family"] = source_family(row["group_id"])
    return records


def metrics_by_family(rows, records):
    y_by_family, pred_by_family = defaultdict(list), defaultdict(list)
    for row, record in zip(rows, records):
        family = source_family(row["group_id"])
        y_by_family[family].append(int(row["expected_has_pii"]))
        pred_by_family[family].append(bool(record["prediction"]))
    result = {}
    for family in sorted(y_by_family):
        y = np.asarray(y_by_family[family], dtype=np.int8)
        pred = np.asarray(pred_by_family[family], dtype=bool)
        metric = PROBE.scores(y, pred)
        positives = int(y.sum())
        negatives = int(len(y) - positives)
        if positives == 0:
            metric["recall"] = None
        if negatives == 0:
            metric["specificity"] = None
        if positives == 0 or negatives == 0:
            metric["balanced_accuracy"] = None
        result[family] = {"rows": int(len(y)), "positive": int(y.sum()),
                          "negative": negatives, **metric}
    return result


def package_versions():
    return {"python": sys.version.split()[0], "platform": platform.platform(),
            "numpy": np.__version__, "scipy": scipy.__version__, "scikit_learn": sklearn.__version__,
            "threadpoolctl": threadpoolctl.__version__}


def thread_settings():
    return {name: os.environ.get(name) for name in
            ("OPENBLAS_NUM_THREADS", "OMP_NUM_THREADS", "MKL_NUM_THREADS")}


def model_record(vectorizer_record, estimator):
    coefficients = [float(value) for value in estimator.coef_.ravel()]
    intercept = [float(value) for value in estimator.intercept_.ravel()]
    if len(coefficients) != vectorizer_record["n_features"]:
        raise ValueError("Logistic coefficient dimension differs from exported vectorizer columns.")
    if not all(math.isfinite(value) for value in coefficients + intercept):
        raise ValueError("Logistic coefficients or intercept are non-finite.")
    return {"classes": [int(value) for value in estimator.classes_],
            "coefficients": coefficients, "intercept": intercept,
            "coefficient_dimension": len(coefficients)}


def fit_validation_candidates(train_rows, validation_rows):
    """Fit train-only text features and validation-only candidates/thresholds."""
    with threadpool_limits(limits=1):
        return _fit_validation_candidates(train_rows, validation_rows)


def _fit_validation_candidates(train_rows, validation_rows):
    train_docs = [training_text_key(row["text"]) for row in train_rows]
    validation_docs = [training_text_key(row["text"]) for row in validation_rows]
    y_train = np.asarray([row["expected_has_pii"] for row in train_rows], dtype=np.int8)
    y_validation = np.asarray([row["expected_has_pii"] for row in validation_rows], dtype=np.int8)
    vectorizer = make_vectorizer()
    vectorizer_warnings = []
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        x_train = vectorizer.fit_transform(train_docs)
        x_validation = vectorizer.transform(validation_docs)
    vectorizer_warnings = [{"category": item.category.__name__, "message": str(item.message)} for item in caught]
    vectorizer_record = export_vectorizer(vectorizer)
    if x_train.shape[1] != vectorizer_record["n_features"] or x_validation.shape[1] != vectorizer_record["n_features"]:
        raise ValueError("Train/validation vector dimensions differ from exported vocabulary.")

    candidates, failures = [], []
    for c_value in C_VALUES:
        estimator = LogisticRegression(C=c_value, class_weight="balanced", solver="lbfgs",
                                       max_iter=1000, tol=1e-4, random_state=SEED)
        candidate_warnings = []
        try:
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always")
                estimator.fit(x_train, y_train)
            candidate_warnings = [{"category": item.category.__name__, "message": str(item.message)}
                                  for item in caught]
            converged = not any(issubclass(item.category, ConvergenceWarning) for item in caught)
            validation_probability = estimator.predict_proba(x_validation)[:, list(estimator.classes_).index(1)]
            train_probability = estimator.predict_proba(x_train)[:, list(estimator.classes_).index(1)]
            if not np.isfinite(validation_probability).all() or not np.isfinite(train_probability).all():
                raise ValueError("Candidate produced non-finite probabilities.")
            threshold, validation_metrics = PROBE.select_threshold(y_validation, validation_probability)
            train_records = row_probabilities(train_rows, train_probability, threshold)
            validation_records = row_probabilities(validation_rows, validation_probability, threshold)
            candidates.append({"C": c_value, "converged": converged, "warnings": candidate_warnings,
                "threshold": float(threshold), "validation_metrics": validation_metrics,
                "train_metrics_at_validation_threshold": PROBE.scores(y_train, train_probability >= threshold),
                "train_source_family_metrics_at_validation_threshold": metrics_by_family(train_rows, train_records),
                "validation_source_family_metrics": metrics_by_family(validation_rows, validation_records),
                "train_predictions": train_records, "validation_predictions": validation_records,
                "estimator": estimator})
        except Exception as exc:
            failures.append({"C": c_value, "error_type": type(exc).__name__, "error": str(exc),
                             "warnings": candidate_warnings})

    eligible = [candidate for candidate in candidates if candidate["converged"]]
    if not eligible:
        return vectorizer, vectorizer_record, vectorizer_warnings, candidates, failures, None
    selected = max(eligible, key=lambda candidate: (
        candidate["validation_metrics"]["balanced_accuracy"],
        candidate["validation_metrics"]["specificity"],
        candidate["validation_metrics"]["recall"], -candidate["C"]))
    selection = {"status": "selected", "selected_C": selected["C"],
        "selected_threshold": selected["threshold"],
        "logistic_regression": {"class_weight": "balanced", "solver": "lbfgs",
            "max_iter": 1000, "tol": 1e-4, "random_state": SEED, "C_values": list(C_VALUES)},
        "selection_rule": "validation balanced_accuracy, specificity, recall, then lower C",
        "threshold_rule": "max validation specificity subject to recall >= 0.90; ties higher recall then threshold",
        "vectorizer": vectorizer_record,
        "candidates": [{key: value for key, value in candidate.items() if key != "estimator"}
                       | {"model": model_record(vectorizer_record, candidate["estimator"])}
                       for candidate in candidates],
        "candidate_failures": failures,
        "vectorizer_warnings": vectorizer_warnings}
    return vectorizer, vectorizer_record, vectorizer_warnings, candidates, failures, selection


def score_development_after_selection(vectorizer, candidates, development_rows, selection_path):
    """Development vectorization is gated on a physically persisted selection file."""
    selection_path = Path(selection_path)
    if not selection_path.is_file():
        raise ValueError("Validation selection artifact must be persisted before development scoring.")
    selection = json.loads(selection_path.read_text(encoding="utf-8"))
    if selection.get("status") != "selected" or not selection.get("candidates"):
        raise ValueError("Persisted validation selection artifact is incomplete.")
    _verify_selection_binding(selection, vectorizer, candidates)
    docs = [training_text_key(row["text"]) for row in development_rows]
    x_development = vectorizer.transform(docs)
    outputs = []
    y_development = np.asarray([row["expected_has_pii"] for row in development_rows], dtype=np.int8)
    for candidate in candidates:
        if not candidate["converged"]:
            continue
        estimator = candidate["estimator"]
        probability = estimator.predict_proba(x_development)[:, list(estimator.classes_).index(1)]
        if not np.isfinite(probability).all():
            raise ValueError(f"C={candidate['C']} produced non-finite development probabilities.")
        records = row_probabilities(development_rows, probability, candidate["threshold"])
        outputs.append({"C": candidate["C"], "threshold_from_validation": candidate["threshold"],
                        "metrics": PROBE.scores(y_development, probability >= candidate["threshold"]),
                        "source_family_metrics": metrics_by_family(development_rows, records),
                        "predictions": records})
    return outputs


def _verify_selection_binding(selection, vectorizer, candidates):
    """Reject a missing, tampered, or independently substituted selection artifact."""
    expected_vectorizer = export_vectorizer(vectorizer)
    if selection.get("vectorizer") != expected_vectorizer:
        raise ValueError("Persisted selection vectorizer differs from the fitted train-only vectorizer.")
    serialized = selection["candidates"]
    by_c = {item.get("C"): item for item in serialized if isinstance(item, dict)}
    if len(by_c) != len(serialized):
        raise ValueError("Persisted selection has duplicate or malformed candidate C values.")
    fitted_by_c = {item["C"]: item for item in candidates}
    if set(by_c) != set(fitted_by_c):
        raise ValueError("Persisted selection candidate set differs from fitted validation candidates.")
    for c_value, candidate in fitted_by_c.items():
        stored = by_c[c_value]
        expected_model = model_record(expected_vectorizer, candidate["estimator"])
        if (stored.get("converged") is not candidate["converged"]
                or stored.get("threshold") != candidate["threshold"]
                or stored.get("validation_metrics") != candidate["validation_metrics"]
                or stored.get("model") != expected_model):
            raise ValueError(f"Persisted selection candidate C={c_value} differs from fitted validation state.")
    eligible = [candidate for candidate in candidates if candidate["converged"]]
    if not eligible:
        raise ValueError("Persisted selection has no converged candidate.")
    chosen = max(eligible, key=lambda candidate: (
        candidate["validation_metrics"]["balanced_accuracy"],
        candidate["validation_metrics"]["specificity"],
        candidate["validation_metrics"]["recall"], -candidate["C"]))
    if (selection.get("selected_C") != chosen["C"]
            or selection.get("selected_threshold") != chosen["threshold"]):
        raise ValueError("Persisted selected C/threshold differs from validation-only ranking.")


def write_fresh_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(value, handle, indent=2, ensure_ascii=False, allow_nan=False)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())


def write_manifest(path, manifest):
    temporary = Path(path).with_suffix(".tmp")
    temporary.write_text(json.dumps(manifest, indent=2, ensure_ascii=False, allow_nan=False) + "\n",
                         encoding="utf-8", newline="\n")
    os.replace(temporary, path)


def run_control(prepared_dir, locked_root, bootstrap_source, output, source_revision, protocol_sha256):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    manifest_path = output / "run-manifest.json"
    run_manifest = {"status": "running", "stage": "input_validation",
        "started_at_utc": datetime.now(timezone.utc).isoformat(), "source_revision": source_revision,
        "protocol_sha256": protocol_sha256, "script_sha256": sha256_file(__file__),
        "packages": package_versions(), "thread_settings": thread_settings(),
        "threadpool_limit": 1, "phases": {}}
    write_manifest(manifest_path, run_manifest)
    try:
        inputs = validate_identity_inputs(prepared_dir, locked_root, bootstrap_source)
        run_manifest["inputs"] = {key: value for key, value in inputs.items() if key != "partitions"}
        run_manifest["phases"]["input_validation"] = {"status": "passed"}
        run_manifest["stage"] = "validation_fit"
        write_manifest(manifest_path, run_manifest)

        vectorizer, vectorizer_record, vectorizer_warnings, candidates, failures, selection = \
            fit_validation_candidates(inputs["partitions"]["train"], inputs["partitions"]["validation"])
        if selection is None:
            selection = {"status": "failed", "failure": "No converged candidate with an eligible validation threshold.",
                         "candidates": [{key: value for key, value in item.items() if key != "estimator"}
                                        for item in candidates], "candidate_failures": failures,
                         "vectorizer": vectorizer_record, "vectorizer_warnings": vectorizer_warnings}
            write_fresh_json(output / "selection.json", selection)
            raise RuntimeError(selection["failure"])
        selection.update({"source_revision": source_revision, "protocol_sha256": protocol_sha256,
                          "packages": package_versions(), "thread_settings": thread_settings(),
                          "threadpool_limit": 1, "input_hashes": run_manifest["inputs"]})
        write_fresh_json(output / "selection.json", selection)
        run_manifest["phases"]["validation_fit"] = {"status": "passed",
            "selection_sha256": sha256_file(output / "selection.json"),
            "eligible_C": [item["C"] for item in candidates if item["converged"]],
            "candidate_failures": failures}
        run_manifest["stage"] = "development_scoring"
        write_manifest(manifest_path, run_manifest)

        development = score_development_after_selection(
            vectorizer, candidates, inputs["partitions"]["development"], output / "selection.json")
        report = {"status": "complete", "selected_C": selection["selected_C"],
            "selected_threshold": selection["selected_threshold"],
            "selection_sha256": sha256_file(output / "selection.json"),
            "source_revision": source_revision, "protocol_sha256": protocol_sha256,
            "packages": package_versions(), "thread_settings": thread_settings(),
            "threadpool_limit": 1, "vectorizer": vectorizer_record,
            "vectorizer_warnings": vectorizer_warnings,
            "validation_selection": {"selected_C": selection["selected_C"],
                "selected_threshold": selection["selected_threshold"],
                "candidate_validation_metrics": [{"C": item["C"], "converged": item["converged"],
                    "threshold": item.get("threshold"), "metrics": item.get("validation_metrics"),
                    "warnings": item.get("warnings", [])} for item in candidates],
                "candidate_split_metrics_by_family": [{"C": item["C"],
                    "train_in_sample": item.get("train_source_family_metrics_at_validation_threshold"),
                    "validation": item.get("validation_source_family_metrics")}
                    for item in candidates],
                "candidate_failures": failures},
            "development_candidates": development,
            "source_family_definition": "group_id prefix before first colon; family metrics are descriptive",
            "interpretation_limits": ["custom within-corpus diagnostic, not independent PIIMB evaluation",
                "annotation-presence only; no severity/category/action labels",
                "full text features are not truncated to encoder token limit",
                "development reused after validation selection; no final data scored"]}
        write_fresh_json(output / "report.json", report)
        run_manifest["phases"]["development_scoring"] = {"status": "passed",
            "report_sha256": sha256_file(output / "report.json")}
        run_manifest["status"] = "complete"
        run_manifest["stage"] = "complete"
        run_manifest["finished_at_utc"] = datetime.now(timezone.utc).isoformat()
        write_manifest(manifest_path, run_manifest)
        return output
    except Exception as exc:
        failure = {"status": "failed", "stage": run_manifest["stage"],
                   "error_type": type(exc).__name__, "error": str(exc),
                   "traceback": traceback.format_exc(), "source_revision": source_revision,
                   "protocol_sha256": protocol_sha256}
        failure_path = output / "failure.json"
        if not failure_path.exists():
            write_fresh_json(failure_path, failure)
        run_manifest["status"] = "failed"
        run_manifest["failure"] = {"stage": failure["stage"], "error_type": failure["error_type"],
                                    "error": failure["error"], "failure_sha256": sha256_file(failure_path)}
        run_manifest["finished_at_utc"] = datetime.now(timezone.utc).isoformat()
        write_manifest(manifest_path, run_manifest)
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prepared", type=Path, required=True, help="Exact v3 prepared directory")
    parser.add_argument("--locked-root", type=Path, required=True, help="Locked-public data directory")
    parser.add_argument("--bootstrap-source", type=Path, default=ROOT / "models/generate_baseline.py")
    parser.add_argument("--output", type=Path, required=True, help="Fresh output directory")
    parser.add_argument("--source-revision", required=True, help="Integrated source commit supplied by caller")
    parser.add_argument("--protocol-sha256", required=True, help="SHA-256 of text-control-protocol.md")
    args = parser.parse_args(argv)
    if not re.fullmatch(r"[0-9a-f]{40,64}", args.source_revision):
        parser.error("--source-revision must be a full lowercase Git object ID.")
    if not re.fullmatch(r"[0-9a-f]{64}", args.protocol_sha256):
        parser.error("--protocol-sha256 must be a lowercase SHA-256 digest.")
    results_root = (ROOT / "evaluation/results").resolve()
    output = args.output.resolve()
    if results_root not in output.parents:
        parser.error("--output must be a fresh child directory under evaluation/results.")
    run_control(args.prepared, args.locked_root, args.bootstrap_source, output,
                args.source_revision, args.protocol_sha256)
    print(json.dumps({"status": "complete", "output": output.as_posix()}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
