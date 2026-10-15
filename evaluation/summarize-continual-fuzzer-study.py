"""Independently reconcile archived continual-study predictions and allocations.

Reads only explicit completed study outputs, never a corpus or a live service.
"""
import argparse
from collections import Counter
from contextlib import closing
import hashlib
import json
from pathlib import Path
import sqlite3
import struct


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def counts(rows):
    if any(row["status"] != "ok" for row in rows):
        raise ValueError("Incomplete checkpoint cannot support a complete comparison.")
    values = Counter((row["expected_has_pii"], row["detected_sensitive"]) for row in rows)
    tp, tn, fp, fn = (values[(True, True)], values[(False, False)],
                      values[(False, True)], values[(True, False)])
    recall, specificity = tp / (tp + fn), tn / (tn + fp)
    return {"true_positives": tp, "true_negatives": tn, "false_positives": fp,
            "false_negatives": fn, "recall": recall, "specificity": specificity,
            "precision": tp / (tp + fp), "f1": 2 * tp / (2 * tp + fp + fn),
            "accuracy": (tp + tn) / len(rows), "balanced_accuracy": (recall + specificity) / 2}


def summarize(root):
    protocol = read(root / "protocol.json")
    timed = protocol.get("duration_seconds_per_profile", 0)
    if (not timed and protocol["cycles_per_profile"] != 20) or protocol["prompt_count"] != 256:
        raise ValueError("This audit requires a prescribed duration or 20 rounds, with 256-row batches.")
    curriculum = read(root / "curriculum/manifest.json")
    lookup = {}
    for split, entry in curriculum["splits"].items():
        path = (root / "curriculum" / entry["path"]).resolve()
        if not path.is_relative_to((root / "curriculum").resolve()) or digest(path) != entry["sha256"]:
            raise ValueError("Curriculum commitment changed before audit.")
        for line in path.read_text(encoding="utf-8").splitlines():
            row = json.loads(line)
            lookup[row["id"]] = (split, row)
    results = {}
    image_sets = []
    total_rounds = 0
    with closing(sqlite3.connect(f"{(root / 'state/after-quality.sqlite3').as_uri()}?mode=ro", uri=True)) as database:
        reservations = list(database.execute("SELECT identity, fingerprint, allocation FROM batches"))
    for short in ("efficient", "balanced", "quality"):
        directory, model_id = root / short, f"privoke-{short}"
        manifest = read(directory / "run-manifest.json")
        if manifest["status"] != "complete":
            raise ValueError("All prescribed profiles must finish before summarizing.")
        model = manifest["models"][model_id]
        rounds = model["rounds"]
        final_cycle = model.get("final_cycle", 20)
        if timed:
            if (model.get("timed_training_seconds", 0) < timed
                    or model["duration_finished_unix"] - model["duration_started_unix"] < timed
                    or final_cycle != len(rounds) or final_cycle < 2):
                raise ValueError("Prescribed repeated training duration was not completed.")
            if (manifest["config"]["duration_seconds"] != timed
                    or manifest["config"]["round_pause_seconds"] != protocol["round_pause_seconds"]):
                raise ValueError("Controller duration/pause differs from the frozen protocol.")
        operations = read(root / f"operations-{short}.json")
        image_sets.append({name: row["image_id"] for name, row in operations["containers"].items()})
        checkpoints = {}
        baseline = None
        for cycle, saved in sorted(model["checkpoints"].items(), key=lambda item: int(item[0])):
            path = directory / model_id / saved["path"]
            snapshot_path = directory / model_id / saved["snapshot_path"]
            if digest(path) != saved["sha256"] or digest(snapshot_path) != saved["snapshot_sha256"]:
                raise ValueError("Archived checkpoint or weights changed.")
            report = read(path)
            if baseline is None:
                baseline = report
            layers = {}
            for layer, evidence in report.items():
                rows = evidence["predictions"]
                recalculated = counts(rows)
                if (recalculated["true_positives"] + recalculated["false_negatives"] != 264
                        or recalculated["true_negatives"] + recalculated["false_positives"] != 238
                        or len({row["group_id"] for row in rows}) != 465):
                    raise ValueError("Endpoint strata/groups differ from the pinned endpoint.")
                if any(abs(recalculated[key] - evidence["metrics"][key]) > 1e-12 for key in recalculated):
                    raise ValueError("Independent confusion/rate arithmetic differs.")
                before = {row["id"]: row for row in baseline[layer]["predictions"]}
                after = {row["id"]: row for row in rows}
                if len(after) != 502 or before.keys() != after.keys():
                    raise ValueError("Endpoint IDs/counts differ.")
                if any((row["expected_has_pii"], row["group_id"]) !=
                       (before[key]["expected_has_pii"], before[key]["group_id"]) for key, row in after.items()):
                    raise ValueError("Endpoint labels/groups differ.")
                layers[layer] = {"metrics": recalculated,
                                 "binary_prediction_changes": sum(before[key]["detected_sensitive"] != row["detected_sensitive"] for key, row in after.items()),
                                 "contextual_classification_changes": sum(before[key]["raw"]["classification"] != row["raw"]["classification"] for key, row in after.items()),
                                 "paired_vs_baseline": evidence.get("paired_vs_baseline")}
            checkpoints[cycle] = layers
        first = read(directory / model_id / "snapshot-000.json")
        last = read(directory / model_id / f"snapshot-{final_cycle:03d}.json")
        artifact = read(directory / "published-artifact.json")
        if artifact["version"] != last["identity"]["model_version"]:
            raise ValueError("Exported artifact version differs from the final checkpoint.")
        changed = {}
        for name, parameter in first["parameters"].items():
            values = last["parameters"][name]["values"]
            # The JSON artifact stores Python floats; protobuf parameters and
            # actual inference use float32. Reconcile at the serving precision.
            exported = [struct.unpack("<f", struct.pack("<f", value))[0]
                        for value in artifact["parameters"][name]["values"]]
            if exported != values:
                raise ValueError("Exported artifact weights differ from the archived checkpoint.")
            if len(values) != len(parameter["values"]):
                raise ValueError("Parameter shape changed.")
            if values != parameter["values"]:
                if not name.startswith("head."):
                    raise ValueError("Frozen encoder changed during a head-only study.")
                changed[name] = max(abs(a - b) for a, b in zip(parameter["values"], values))
        if model["accepted_updates"] and (not changed or first["identity"] == last["identity"]):
            raise ValueError("Training did not produce an actual model change.")
        if len(rounds) != final_cycle or sum(row["response"]["accepted"] for row in rounds) != model["accepted_updates"]:
            raise ValueError("Attempt/acceptance counts differ.")
        for row in rounds:
            if digest(directory / model_id / row["response_path"]) != row["response_sha256"]:
                raise ValueError("Archived training response changed.")
        selected = [(json.loads(identity), json.loads(allocation)) for identity, _, allocation in reservations
                    if json.loads(identity)[1] == model_id]
        if len(selected) != final_cycle:
            raise ValueError("Durable allocation count differs from attempts.")
        unique_train, unique_replay, roles = set(), set(), Counter()
        for _, allocation in selected:
            if (len(allocation["train"]), len(allocation["replay"])) != (192, 64):
                raise ValueError("Durable batch sizes differ from protocol.")
            for split in ("train", "replay"):
                for row_id in allocation[split]:
                    actual_split, row = lookup[row_id]
                    if actual_split != split:
                        raise ValueError("Guard or other split entered training.")
                    roles[row["metadata"]["curriculum_role"]] += 1
            unique_train.update(allocation["train"])
            unique_replay.update(allocation["replay"])
        total_rounds += len(rounds)
        results[short] = {"attempts": len(rounds), "final_cycle": final_cycle,
                          "timed_training_seconds": model.get("timed_training_seconds"),
                          "accepted_updates": model["accepted_updates"], "rejected_attempts": len(rounds) - model["accepted_updates"],
                          "checkpoints": checkpoints, "changed_head_max_abs_delta": changed,
                          "encoder_unchanged": True, "unique_train_rows": len(unique_train),
                          "unique_replay_rows": len(unique_replay), "row_exposures_by_role": dict(roles),
                          "started_at": manifest["started_at"], "finished_at": manifest["finished_at"]}
    if any(images != image_sets[0] for images in image_sets):
        raise ValueError("Serving images differed across profiles.")
    return {"schema_version": 1, "protocol_sha256": digest(root / "protocol.json"),
            "same_images_across_profiles": True, "profiles": results,
            "endpoint_rows": 502, "endpoint_positive": 264, "endpoint_negative": 238,
            "source_groups": 465, "rounds": total_rounds, "independent_arithmetic_verified": True}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--study-root", type=Path, required=True)
    args = parser.parse_args()
    result = summarize(args.study_root.resolve())
    output = args.study_root / "summary.json"
    output.write_text(json.dumps(result, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(output), "accepted_updates": {k: v["accepted_updates"] for k, v in result["profiles"].items()}}))
