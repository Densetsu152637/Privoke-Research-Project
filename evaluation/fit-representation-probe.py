"""Fit predefined offline logistic probes to exported frozen 32D features."""
import argparse
import hashlib
import json
import math
import warnings
from pathlib import Path

import numpy as np
import sklearn
from sklearn.exceptions import ConvergenceWarning
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_DIM = 32
CS = (0.1, 1.0, 10.0)


def validate_feature_rows(rows, expected, dimension=EXPECTED_DIM):
    if len(rows) != len(expected):
        raise ValueError("Feature row count differs from partition.")
    expected_by_id = {str(row["id"]): row for row in expected}
    if len(expected_by_id) != len(expected):
        raise ValueError("Partition IDs are not unique.")
    actual = {str(row.get("id")): row for row in rows}
    if len(actual) != len(rows) or set(actual) != set(expected_by_id):
        raise ValueError("Feature IDs are missing, duplicated or unexpected.")
    aligned = []
    for identifier, source in expected_by_id.items():
        row = actual[identifier]
        if row.get("group_id") != source["group_id"] or bool(row.get("expected_has_pii")) != bool(source["expected_has_pii"]):
            raise ValueError("Feature label or group differs from partition.")
        vector = row.get("pooled")
        if not isinstance(vector, list) or len(vector) != dimension:
            raise ValueError(f"Feature vector must have {dimension} dimensions.")
        if not all(isinstance(v, (int, float)) and math.isfinite(float(v)) for v in vector):
            raise ValueError("Feature vector contains a non-finite value.")
        if type(row.get("original_binary")) is not bool:
            raise ValueError("Original binary prediction is missing or invalid.")
        aligned.append(row)
    return aligned


def scores(y, pred):
    positives = int(y.sum()); negatives = len(y) - positives
    tp = int(np.sum((y == 1) & pred)); tn = int(np.sum((y == 0) & ~pred))
    recall = tp / positives if positives else 0.0
    specificity = tn / negatives if negatives else 0.0
    return {"tp": tp, "tn": tn, "fp": negatives - tn, "fn": positives - tp,
            "recall": recall, "specificity": specificity, "balanced_accuracy": (recall + specificity) / 2}


def select_threshold(y, probability):
    candidates = sorted(set([0.0, 1.0, *map(float, probability)]))
    eligible = []
    for threshold in candidates:
        measured = scores(y, probability >= threshold)
        if measured["recall"] >= 0.9:
            eligible.append((measured["specificity"], measured["recall"], threshold, measured))
    if not eligible:
        raise ValueError("No validation threshold meets the 90% recall floor.")
    specificity, recall, threshold, measured = max(eligible, key=lambda item: (item[0], item[1], item[2]))
    return threshold, measured


def verify_locked(original, reference_path, dev_rows, locked_path):
    raw = locked_path.read_bytes()
    lock_manifest = json.loads(locked_path.with_name("manifest.json").read_text(encoding="utf-8"))
    digest = hashlib.sha256(raw).hexdigest()
    if digest != lock_manifest["partitions"]["development"]["sha256"]:
        raise ValueError("Locked development digest mismatch.")
    expected = {row["id"]: (bool(row["expected_has_pii"]), row["group_id"])
                for row in (json.loads(line) for line in raw.decode().splitlines() if line.strip())}
    ref = json.loads(reference_path.read_text(encoding="utf-8"))
    if ref.get("errors") != 0 or ref.get("metrics", {}).get("evaluated_samples") != 502:
        raise ValueError("Archived live semantic report is incomplete or contains errors.")
    reference_rows = ref["metadata"]["predictions"]
    ref_map = {row["example_id"]: row for row in reference_rows}
    actual = {row["id"]: row for row in dev_rows}
    if len(expected) != 502 or len(ref_map) != len(reference_rows) or set(ref_map) != set(expected) or set(actual) != set(expected):
        raise ValueError("Original semantic predictions do not cover the exact 502 locked IDs.")
    for key, (label, group) in expected.items():
        refrow, row = ref_map[key], actual[key]
        if (bool(refrow["expected_has_pii"]), refrow.get("group_id"), refrow.get("status")) != (label, group, "ok"):
            raise ValueError("Archived live prediction labels/groups differ from locked source.")
        if bool(row["expected_has_pii"]) != label or row["group_id"] != group or row["original_binary"] != bool(refrow["detected_sensitive"]):
            raise ValueError("Offline original binary prediction differs from archived live semantic result.")
    return digest, hashlib.sha256(reference_path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True, help="Feature bundle emitted by run-representation-diagnostic.py")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise SystemExit("Refusing to overwrite diagnostic output.")
    bundle = json.loads(args.input.read_text(encoding="utf-8"))
    if bundle.get("runtime_config", {}).get("hidden_size") != EXPECTED_DIM:
        raise ValueError("Original encoder configuration is not the expected 32-dimensional model.")
    for name, path in bundle["partition_paths"].items():
        if hashlib.sha256(Path(path).read_bytes()).hexdigest() != bundle["partition_sha256"][name]:
            raise ValueError(f"{name} partition digest mismatch.")
    parts = bundle["partitions"]
    aligned = {name: validate_feature_rows(parts[name]["features"], parts[name]["rows"])
               for name in ("train", "validation", "development")}
    for name in ("train", "validation"):
        groups = {row["group_id"] for row in parts[name]["rows"]}
        text_keys = {row["text_key"] for row in parts[name]["rows"]}
        if groups != {row["group_id"] for row in aligned[name]} or text_keys != {row["text_key"] for row in parts[name]["rows"]}:
            raise ValueError("Partition group/text integrity validation failed.")
    train_groups = {row["group_id"] for row in parts["train"]["rows"]}
    val_groups = {row["group_id"] for row in parts["validation"]["rows"]}
    train_texts = {row["text_key"] for row in parts["train"]["rows"]}
    val_texts = {row["text_key"] for row in parts["validation"]["rows"]}
    if train_groups & val_groups or train_texts & val_texts:
        raise ValueError("Train/validation group or text overlap.")
    lock_hash, reference_hash = verify_locked(aligned["development"], Path(bundle["original_semantic_reference"]),
                                              parts["development"]["rows"], Path(bundle["locked_development"]))
    y_train = np.asarray([row["expected_has_pii"] for row in aligned["train"]], dtype=np.int8)
    y_val = np.asarray([row["expected_has_pii"] for row in aligned["validation"]], dtype=np.int8)
    y_dev = np.asarray([row["expected_has_pii"] for row in aligned["development"]], dtype=np.int8)
    x_train = np.asarray([row["pooled"] for row in aligned["train"]], dtype=np.float64)
    x_val = np.asarray([row["pooled"] for row in aligned["validation"]], dtype=np.float64)
    x_dev = np.asarray([row["pooled"] for row in aligned["development"]], dtype=np.float64)
    results = []
    for c in CS:
        scaler = StandardScaler().fit(x_train)
        model = LogisticRegression(C=c, class_weight="balanced", solver="lbfgs", max_iter=1000, random_state=7102026)
        with warnings.catch_warnings(record=True) as captured:
            warnings.simplefilter("always", ConvergenceWarning)
            model.fit(scaler.transform(x_train), y_train)
        converged = not any(issubclass(item.category, ConvergenceWarning) for item in captured)
        item = {"C": c, "converged": converged, "warnings": [str(w.message) for w in captured]}
        if converged:
            val_prob = model.predict_proba(scaler.transform(x_val))[:, list(model.classes_).index(1)]
            threshold, val_metrics = select_threshold(y_val, val_prob)
            dev_prob = model.predict_proba(scaler.transform(x_dev))[:, list(model.classes_).index(1)]
            item["validation_rows"] = [{"id": row["id"], "group_id": row["group_id"],
                "expected_has_pii": bool(y_val[index]), "probability": float(val_prob[index]),
                "prediction": bool(val_prob[index] >= threshold)} for index, row in enumerate(aligned["validation"])]
            item["development_rows"] = [{"id": row["id"], "group_id": row["group_id"],
                "expected_has_pii": bool(y_dev[index]), "probability": float(dev_prob[index]),
                "prediction": bool(dev_prob[index] >= threshold)} for index, row in enumerate(aligned["development"])]
            item.update({"threshold": threshold, "validation": val_metrics,
                         "development": scores(y_dev, dev_prob >= threshold),
                         "validation_probability": val_prob.tolist(), "development_probability": dev_prob.tolist(),
                         "scaler_mean": scaler.mean_.tolist(), "scaler_scale": scaler.scale_.tolist(),
                         "coefficient": model.coef_[0].tolist(), "intercept": float(model.intercept_[0])})
        results.append(item)
    eligible = [item for item in results if item["converged"]]
    if not eligible:
        raise ValueError("All predefined fits failed to converge.")
    selected = max(eligible, key=lambda item: (item["validation"]["balanced_accuracy"],
                  item["validation"]["specificity"], item["validation"]["recall"], -item["C"]))
    rules = json.loads(Path(bundle["rule_union"]).read_text(encoding="utf-8"))
    rule_expected_hashes = bundle["rule_source_sha256"]
    for name, digest in rule_expected_hashes.items():
        recorded = {key.replace("\\", "/"): value for key, value in rules.get("source_sha256", {}).items()}
        if recorded.get(name.replace("\\", "/")) != digest:
            raise ValueError("Revised rule source hash record mismatch.")
    rule_rows = rules["layers"]["regex-ner"]["metadata"]["predictions"]
    rule_map = {row["example_id"]: row for row in rule_rows}
    if len(rule_map) != len(rule_rows) or set(rule_map) != set(parts["development"]["rows"] and [r["id"] for r in parts["development"]["rows"]]):
        raise ValueError("Rule+NER union keys do not match locked development.")
    for row in parts["development"]["rows"]:
        rule_row = rule_map[row["id"]]
        if (rule_row.get("status"), rule_row.get("group_id"), bool(rule_row.get("expected_has_pii"))) != (
                "ok", row["group_id"], bool(row["expected_has_pii"])):
            raise ValueError("Rule+NER union has errors or mismatched locked labels/groups.")
    union_rows = aligned["development"]
    chosen_prob = np.asarray(selected["development_probability"])
    probe = chosen_prob >= selected["threshold"]
    union = np.asarray([probe[i] or bool(rule_map[row["id"]]["detected_sensitive"])
                        for i, row in enumerate(union_rows)])
    selected["development_with_reused_regex_ner"] = scores(y_dev, union)
    selected["development_with_reused_regex_ner_rows"] = [
        {"id": row["id"], "group_id": row["group_id"], "expected_has_pii": bool(y_dev[index]),
         "probe_probability": float(chosen_prob[index]), "probe_prediction": bool(probe[index]),
         "reused_regex_ner_prediction": bool(rule_map[row["id"]]["detected_sensitive"]),
         "union_prediction": bool(union[index])}
        for index, row in enumerate(union_rows)]
    output = {"scope": "offline frozen-representation annotation-presence diagnostic; validation-frozen selection; not deployment",
              "versions": {"numpy": np.__version__, "sklearn": sklearn.__version__},
              "config": {"feature_dimensions": EXPECTED_DIM, "Cs": CS, "class_weight": "balanced", "solver": "lbfgs",
                         "max_iter": 1000, "random_state": 7102026, "recall_floor": 0.9},
              "input_sha256": hashlib.sha256(args.input.read_bytes()).hexdigest(),
              "locked_development_sha256": lock_hash, "original_semantic_reference_sha256": reference_hash,
              "fits": results, "selected_C": selected["C"], "selected_threshold": selected["threshold"],
              "selection": "validation balanced accuracy, specificity, recall, then lower C",
              "development_with_reused_regex_ner_scope": "reused-output diagnostic, not live pipeline",
              "selected_development_with_reused_regex_ner": selected["development_with_reused_regex_ner"]}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(output, indent=2), encoding="utf-8")
    print(json.dumps({"selected_C": output["selected_C"], "threshold": output["selected_threshold"],
                      "development": selected["development"], "development_with_reused_regex_ner": selected["development_with_reused_regex_ner"]}))


if __name__ == "__main__":
    main()
