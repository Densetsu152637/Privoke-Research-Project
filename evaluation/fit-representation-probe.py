"""Fit validation-selected, offline logistic probes to frozen encoder features."""
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

from privoke_model.training_data import training_text_key

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_DIM = 32
CS = (0.1, 1.0, 10.0)
PARTITIONS = ("train", "validation", "development")


def read_jsonl(path):
    return [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]


def require_sha256(path, expected, label):
    actual = hashlib.sha256(Path(path).read_bytes()).hexdigest()
    if actual != expected:
        raise ValueError(f"{label} hash mismatch.")
    return actual


def validate_partition_rows(rows, name):
    seen_ids = set()
    seen_texts = set()
    for row in rows:
        if not isinstance(row.get("id"), str) or not row["id"]:
            raise ValueError(f"{name} has a missing or malformed ID.")
        if not isinstance(row.get("group_id"), str) or not row["group_id"]:
            raise ValueError(f"{name} has a missing or malformed source group.")
        if type(row.get("expected_has_pii")) is not bool:
            raise ValueError(f"{name} has a missing or malformed boolean truth label.")
        if not isinstance(row.get("text"), str) or not row["text"]:
            raise ValueError(f"{name} has missing text.")
        key = training_text_key(row["text"])
        if not key or row.get("text_key") != key:
            raise ValueError(f"{name} normalized text key does not match its text.")
        if row["id"] in seen_ids or key in seen_texts:
            raise ValueError(f"{name} contains duplicate IDs or normalized text.")
        seen_ids.add(row["id"])
        seen_texts.add(key)
    return {"ids": seen_ids, "groups": {row["group_id"] for row in rows},
            "texts": {row["text_key"] for row in rows}}


def validate_bundle_metadata(source_rows, bundle_rows, name):
    """Compare text-free metadata to the canonical partition rows."""
    keys = ("id", "group_id", "text_key", "expected_has_pii")
    if not isinstance(bundle_rows, list) or len(bundle_rows) != len(source_rows):
        raise ValueError(f"Bundle {name} rows differ from source partition JSONL.")
    if any(not isinstance(row, dict) or set(row) != set(keys) for row in bundle_rows):
        raise ValueError(f"Bundle {name} metadata is malformed.")
    projected = [{key: row[key] for key in keys} for row in source_rows]
    if projected != bundle_rows:
        raise ValueError(f"Bundle {name} rows differ from source partition JSONL.")
    return projected


def validate_feature_rows(features, expected, dimension=EXPECTED_DIM):
    if len(features) != len(expected):
        raise ValueError("Feature row count differs from partition.")
    expected_by_id = {row["id"]: row for row in expected}
    if len(expected_by_id) != len(expected):
        raise ValueError("Partition IDs are not unique.")
    actual = {row.get("id"): row for row in features}
    if len(actual) != len(features) or set(actual) != set(expected_by_id):
        raise ValueError("Feature IDs are missing, duplicated or unexpected.")
    aligned = []
    for identifier, source in expected_by_id.items():
        row = actual[identifier]
        if type(row.get("expected_has_pii")) is not bool or row["expected_has_pii"] != source["expected_has_pii"]:
            raise ValueError("Feature truth label is malformed or differs from partition.")
        if row.get("group_id") != source["group_id"]:
            raise ValueError("Feature source group differs from partition.")
        vector = row.get("pooled")
        if not isinstance(vector, list) or len(vector) != dimension:
            raise ValueError(f"Feature vector must have {dimension} dimensions.")
        if not all(isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(float(v)) for v in vector):
            raise ValueError("Feature vector contains a non-finite or invalid value.")
        if type(row.get("original_binary")) is not bool:
            raise ValueError("Original binary prediction is missing or invalid.")
        aligned.append(row)
    return aligned


def validate_development_source(prepared_rows, locked_rows):
    """Require every prepared dev ID to retain its exact locked text and truth provenance."""
    def by_id(rows, source):
        mapping = {}
        for row in rows:
            if (not isinstance(row.get("id"), str) or type(row.get("expected_has_pii")) is not bool
                    or not isinstance(row.get("group_id"), str) or not isinstance(row.get("text"), str)):
                raise ValueError(f"{source} has malformed ID, group, text or truth metadata.")
            if row["id"] in mapping:
                raise ValueError(f"{source} has duplicate IDs.")
            mapping[row["id"]] = (row["text"], training_text_key(row["text"]),
                                   row["expected_has_pii"], row["group_id"])
        return mapping
    prepared = by_id(prepared_rows, "Prepared development partition")
    locked = by_id(locked_rows, "Locked development partition")
    if prepared != locked:
        raise ValueError("Prepared development rows differ from locked text/truth/group metadata by ID.")
    return prepared


def scores(y, pred):
    positives = int(y.sum())
    negatives = len(y) - positives
    tp = int(np.sum((y == 1) & pred))
    tn = int(np.sum((y == 0) & ~pred))
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


def verify_locked(features, reference_path, locked_rows, locked_development_path, locked_manifest_path):
    ref = json.loads(Path(reference_path).read_text(encoding="utf-8"))
    errors = ref.get("errors")
    if type(errors) is not list or errors or ref.get("metrics", {}).get("evaluated_samples") != len(locked_rows):
        raise ValueError("Archived live semantic report is incomplete or contains errors.")
    reference_rows = ref["metadata"]["predictions"]
    ref_map = {row["example_id"]: row for row in reference_rows}
    feature_map = {row["id"]: row for row in features}
    expected_map = {row["id"]: row for row in locked_rows}
    if (len(locked_rows) != 502 or len(expected_map) != len(locked_rows)
            or len(ref_map) != len(reference_rows) or set(ref_map) != set(expected_map)
            or set(feature_map) != set(expected_map)):
        raise ValueError("Original semantic rows do not cover exact locked development IDs.")
    for identifier, expected in expected_map.items():
        if type(expected.get("expected_has_pii")) is not bool:
            raise ValueError("Locked development truth label is malformed.")
        refrow, feature = ref_map[identifier], feature_map[identifier]
        if (type(refrow.get("expected_has_pii")) is not bool
                or type(refrow.get("detected_sensitive")) is not bool
                or (refrow["expected_has_pii"], refrow.get("group_id"), refrow.get("status")) !=
                   (expected["expected_has_pii"], expected["group_id"], "ok")):
            raise ValueError("Archived live prediction truth/group/status differs from locked source.")
        if (feature["expected_has_pii"] != expected["expected_has_pii"]
                or feature["group_id"] != expected["group_id"]
                or feature["original_binary"] != refrow["detected_sensitive"]):
            raise ValueError("Offline original binary prediction differs from archived live semantic result.")
    manifest_raw = Path(locked_manifest_path).read_bytes()
    manifest = json.loads(manifest_raw)
    development_raw = Path(locked_development_path).read_bytes()
    if hashlib.sha256(development_raw).hexdigest() != manifest["partitions"]["development"]["sha256"]:
        raise ValueError("Locked development JSONL hash differs from its manifest.")
    return (hashlib.sha256(development_raw).hexdigest(), hashlib.sha256(manifest_raw).hexdigest(),
            hashlib.sha256(Path(reference_path).read_bytes()).hexdigest())


def make_rows(ids, groups, labels, probabilities, predictions):
    return [{"id": ids[i], "group_id": groups[i], "expected_has_pii": bool(labels[i]),
             "probability": float(probabilities[i]), "prediction": bool(predictions[i])}
            for i in range(len(ids))]


def write_fresh(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as handle:
        json.dump(value, handle, indent=2, allow_nan=False)
        handle.write("\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    bundle = json.loads(args.input.read_text(encoding="utf-8"))
    input_digest = hashlib.sha256(args.input.read_bytes()).hexdigest()
    fit_records = []
    current_stage = "input_validation"
    try:
        if bundle.get("runtime_config", {}).get("hidden_size") != EXPECTED_DIM:
            raise ValueError("Original encoder configuration is not the expected 32-dimensional model.")
        study_manifest_path = Path(bundle["study_manifest_path"])
        manifest_bytes = study_manifest_path.read_bytes()
        if hashlib.sha256(manifest_bytes).hexdigest() != bundle["study_manifest_sha256"]:
            raise ValueError("Study manifest digest mismatch.")
        study_manifest = json.loads(manifest_bytes)
        partitions, identities, features = {}, {}, {}
        for name in PARTITIONS:
            path = Path(bundle["partition_paths"][name])
            raw = path.read_bytes()
            digest = hashlib.sha256(raw).hexdigest()
            if digest != bundle["partition_sha256"].get(name) or digest != study_manifest["partition_sha256"].get(name):
                raise ValueError(f"{name} partition digest mismatch.")
            source_rows = read_jsonl(path)
            bundle_rows = bundle["partitions"][name]["rows"]
            validate_bundle_metadata(source_rows, bundle_rows, name)
            partitions[name] = source_rows
            identities[name] = validate_partition_rows(source_rows, name)
            serialized_ids = "\n".join(sorted(identities[name]["ids"]))
            serialized_groups = "\n".join(sorted(identities[name]["groups"]))
            serialized_texts = "\n".join(sorted(identities[name]["texts"]))
            digest_record = study_manifest["partition_digests"][name]
            for key, value in (("ids_sha256", serialized_ids), ("groups_sha256", serialized_groups),
                               ("text_keys_sha256", serialized_texts)):
                if hashlib.sha256(value.encode()).hexdigest() != digest_record.get(key):
                    raise ValueError(f"{name} {key} does not match the study manifest.")
            features[name] = validate_feature_rows(bundle["partitions"][name]["features"], source_rows)
            labels = [row["expected_has_pii"] for row in source_rows]
            if name in ("train", "validation") and min(sum(labels), len(labels) - sum(labels)) < 50:
                raise ValueError(f"{name} requires at least 50 examples of each binary truth class.")
        for a, b in (("train", "validation"), ("train", "development"), ("validation", "development")):
            for key in ("ids", "groups", "texts"):
                if identities[a][key] & identities[b][key]:
                    raise ValueError(f"{a}/{b} {key} overlap.")
        bootstrap_path = ROOT / "models/generate_baseline.py"
        if hashlib.sha256(bootstrap_path.read_bytes()).hexdigest() != study_manifest["bootstrap_source_sha256"]:
            raise ValueError("Bootstrap source hash differs from the prepared study manifest.")
        import ast
        tree = ast.parse(bootstrap_path.read_text(encoding="utf-8"))
        function = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "training_samples")
        namespace = {}
        exec(compile(ast.Module(body=[function], type_ignores=[]), "bootstrap_samples", "exec"), namespace)
        bootstrap_keys = {training_text_key(row[0]) for row in namespace["training_samples"]()}
        if any(identities[name]["texts"] & bootstrap_keys for name in ("train", "validation")):
            raise ValueError("Training/validation text overlaps bootstrap training samples.")
        locked_root = Path(bundle["locked_directory"])
        locked_manifest = json.loads((locked_root / "manifest.json").read_text(encoding="utf-8"))
        protected = {"ids": set(), "groups": set(), "texts": set()}
        locked_rows = {}
        for split in ("development", "final"):
            path = locked_root / f"{split}.jsonl"
            raw = path.read_bytes()
            digest = hashlib.sha256(raw).hexdigest()
            if digest != locked_manifest["partitions"][split]["sha256"] or digest != study_manifest["locked_sha256"][split]:
                raise ValueError(f"Protected {split} partition digest mismatch.")
            rows = read_jsonl(path)
            locked_ids = set()
            for row in rows:
                if (not isinstance(row.get("id"), str) or not row["id"]
                        or not isinstance(row.get("group_id"), str) or not row["group_id"]
                        or not isinstance(row.get("text"), str) or not row["text"]
                        or type(row.get("expected_has_pii")) is not bool):
                    raise ValueError(f"Protected {split} partition has malformed rows.")
                if row["id"] in locked_ids:
                    raise ValueError(f"Protected {split} partition has duplicate IDs.")
                locked_ids.add(row["id"])
            locked_rows[split] = rows
            idset = {row["id"] for row in rows}
            groupset = {row["group_id"] for row in rows}
            textset = {training_text_key(row["text"]) for row in rows}
            if any(identities[name][key] & values for name in ("train", "validation")
                   for key, values in (("ids", idset), ("groups", groupset), ("texts", textset))):
                raise ValueError(f"Training/validation rows overlap protected {split} IDs, groups or text.")
            protected["ids"].update(idset)
            protected["groups"].update(groupset)
            protected["texts"].update(textset)
        validate_development_source(partitions["development"], locked_rows["development"])
        if (identities["development"]["ids"] != {row["id"] for row in locked_rows["development"]}
                or identities["development"]["groups"] != {row["group_id"] for row in locked_rows["development"]}
                or identities["development"]["texts"] != {training_text_key(row["text"]) for row in locked_rows["development"]}):
            raise ValueError("Development partition differs from the locked development IDs/groups/text keys.")
        if ({row["id"] for row in locked_rows["development"]} & {row["id"] for row in locked_rows["final"]}
                or {row["group_id"] for row in locked_rows["development"]} & {row["group_id"] for row in locked_rows["final"]}
                or {training_text_key(row["text"]) for row in locked_rows["development"]}
                   & {training_text_key(row["text"]) for row in locked_rows["final"]}):
            raise ValueError("Locked development and final partitions overlap.")
        reference_path = Path(bundle["original_semantic_reference"])
        rule_union_path = Path(bundle["rule_union"])
        require_sha256(reference_path, bundle["original_semantic_reference_sha256"], "Archived original semantic report")
        require_sha256(rule_union_path, bundle["rule_union_sha256"], "Reused rule report")
        lock_hash, lock_manifest_hash, reference_hash = verify_locked(
            features["development"], reference_path, locked_rows["development"],
            locked_root / "development.jsonl", locked_root / "manifest.json")
        y_train = np.asarray([row["expected_has_pii"] for row in partitions["train"]], dtype=np.int8)
        y_val = np.asarray([row["expected_has_pii"] for row in partitions["validation"]], dtype=np.int8)
        x_train = np.asarray([row["pooled"] for row in features["train"]], dtype=np.float64)
        x_val = np.asarray([row["pooled"] for row in features["validation"]], dtype=np.float64)
        fit_records, fitted = [], {}
        current_stage = "validation_fitting"
        for c in CS:
            entry = {"C": c, "converged": False, "warnings": [], "error": None}
            try:
                scaler = StandardScaler().fit(x_train)
                model = LogisticRegression(C=c, class_weight="balanced", solver="lbfgs", max_iter=1000,
                                           random_state=7102026)
                with warnings.catch_warnings(record=True) as captured:
                    warnings.simplefilter("always", ConvergenceWarning)
                    model.fit(scaler.transform(x_train), y_train)
                entry["warnings"] = [str(item.message) for item in captured]
                if any(issubclass(item.category, ConvergenceWarning) for item in captured):
                    entry["error"] = "LogisticRegression did not converge."
                    fit_records.append(entry)
                    continue
                entry["converged"] = True
                val_prob = model.predict_proba(scaler.transform(x_val))[:, list(model.classes_).index(1)]
                threshold, val_metrics = select_threshold(y_val, val_prob)
                entry.update({"converged": True, "threshold": threshold, "validation": val_metrics,
                              "validation_rows": make_rows([r["id"] for r in partitions["validation"]],
                                  [r["group_id"] for r in partitions["validation"]], y_val, val_prob, val_prob >= threshold),
                              "scaler_mean": scaler.mean_.tolist(), "scaler_scale": scaler.scale_.tolist(),
                              "coefficient": model.coef_[0].tolist(), "intercept": float(model.intercept_[0])})
                fitted[c] = (scaler, model)
            except Exception as exc:
                entry["error"] = f"{type(exc).__name__}: {exc}"
            fit_records.append(entry)
        eligible = [item for item in fit_records if item["converged"] and item["error"] is None
                    and "validation" in item]
        if not eligible:
            failed = {"status": "failed", "failure": "No predefined fit converged and met validation selection requirements.",
                      "input_sha256": input_digest, "fits": fit_records,
                      "provenance": {"study_manifest_sha256": bundle["study_manifest_sha256"],
                                     "locked_development_jsonl_sha256": study_manifest["locked_sha256"]["development"],
                                     "locked_manifest_sha256": lock_manifest_hash,
                                     "locked_final_sha256": study_manifest["locked_sha256"]["final"]}}
            write_fresh(args.output, failed)
            return 1
        selected = max(eligible, key=lambda item: (item["validation"]["balanced_accuracy"],
                       item["validation"]["specificity"], item["validation"]["recall"], -item["C"]))
        selected_c = selected["C"]
        # Freeze selection before reading development features for any probe scoring.
        frozen = {"status": "selected_before_development_scoring", "selected_C": selected_c,
                  "threshold": selected["threshold"], "validation": selected["validation"],
                  "selection": "validation balanced accuracy, specificity, recall, then lower C",
                  "scaler_mean": selected["scaler_mean"], "scaler_scale": selected["scaler_scale"],
                  "coefficient": selected["coefficient"], "intercept": selected["intercept"],
                  "input_sha256": input_digest,
                  "study_manifest_sha256": bundle["study_manifest_sha256"],
                  "locked_development_jsonl_sha256": study_manifest["locked_sha256"]["development"],
                  "locked_manifest_sha256": lock_manifest_hash,
                  "locked_final_sha256": study_manifest["locked_sha256"]["final"]}
        selection_path = Path(args.output).with_name(Path(args.output).stem + "-selection.json")
        write_fresh(selection_path, frozen)
        current_stage = "development_scoring"
        y_dev = np.asarray([row["expected_has_pii"] for row in partitions["development"]], dtype=np.int8)
        x_dev = np.asarray([row["pooled"] for row in features["development"]], dtype=np.float64)
        development_by_c = {}
        for item in eligible:
            scaler, model = fitted[item["C"]]
            probability = model.predict_proba(scaler.transform(x_dev))[:, list(model.classes_).index(1)]
            prediction = probability >= item["threshold"]
            item["development"] = scores(y_dev, prediction)
            item["development_rows"] = make_rows([r["id"] for r in partitions["development"]],
                [r["group_id"] for r in partitions["development"]], y_dev, probability, prediction)
            development_by_c[item["C"]] = probability
        selected = next(item for item in fit_records if item["C"] == selected_c)
        rules = json.loads(Path(bundle["rule_union"]).read_text(encoding="utf-8"))
        current_stage = "reused_rule_union_validation"
        expected_hashes = {key.replace("\\", "/"): value for key, value in bundle["rule_source_sha256"].items()}
        recorded_hashes = {key.replace("\\", "/"): value for key, value in rules.get("source_sha256", {}).items()}
        if recorded_hashes != expected_hashes:
            raise ValueError("Revised rule source hash record mismatch.")
        rule_rows = rules["layers"]["regex-ner"]["metadata"]["predictions"]
        rule_map = {row["example_id"]: row for row in rule_rows}
        if len(rule_map) != len(rule_rows) or set(rule_map) != identities["development"]["ids"]:
            raise ValueError("Rule+NER union keys do not match locked development.")
        for row in partitions["development"]:
            rule_row = rule_map[row["id"]]
            if (rule_row.get("status"), rule_row.get("group_id"), type(rule_row.get("expected_has_pii")),
                    rule_row.get("expected_has_pii")) != ("ok", row["group_id"], bool, row["expected_has_pii"]):
                raise ValueError("Rule+NER union has errors or mismatched locked labels/groups.")
            if type(rule_row.get("detected_sensitive")) is not bool:
                raise ValueError("Rule+NER union has malformed binary predictions.")
        chosen_prob = development_by_c[selected_c]
        probe = chosen_prob >= selected["threshold"]
        union = np.asarray([probe[i] or rule_map[row["id"]]["detected_sensitive"]
                            for i, row in enumerate(partitions["development"])])
        union_metrics = scores(y_dev, union)
        output = {"status": "complete", "scope": "offline frozen-representation annotation-presence diagnostic; validation-frozen selection; not deployment",
                  "versions": {"numpy": np.__version__, "sklearn": sklearn.__version__},
                  "config": {"feature_dimensions": EXPECTED_DIM, "Cs": CS, "class_weight": "balanced", "solver": "lbfgs",
                             "max_iter": 1000, "random_state": 7102026, "recall_floor": 0.9},
                  "input_sha256": input_digest, "selection_artifact": selection_path.name,
                  "locked_development_jsonl_sha256": lock_hash,
                  "locked_manifest_sha256": lock_manifest_hash,
                  "original_semantic_reference_sha256": reference_hash,
                  "fits": fit_records, "selected_C": selected_c, "selected_threshold": selected["threshold"],
                  "development_with_reused_regex_ner_scope": "reused-output diagnostic, not live pipeline",
                  "selected_development_with_reused_regex_ner": union_metrics,
                  "selected_development_with_reused_regex_ner_rows": [
                      {"id": row["id"], "group_id": row["group_id"], "expected_has_pii": row["expected_has_pii"],
                       "probe_probability": float(chosen_prob[i]), "probe_prediction": bool(probe[i]),
                       "reused_regex_ner_prediction": rule_map[row["id"]]["detected_sensitive"],
                       "union_prediction": bool(union[i])}
                      for i, row in enumerate(partitions["development"])]}
        write_fresh(args.output, output)
        print(json.dumps({"status": "complete", "selected_C": selected_c,
                          "threshold": selected["threshold"], "development": selected["development"],
                          "development_with_reused_regex_ner": union_metrics}))
        return 0
    except Exception as exc:
        failure = {"status": "failed", "error": f"{type(exc).__name__}: {exc}", "input_sha256": input_digest,
                   "stage": current_stage, "fits": fit_records}
        output_path = Path(args.output)
        if not output_path.exists():
            write_fresh(output_path, failure)
        raise


if __name__ == "__main__":
    raise SystemExit(main())
