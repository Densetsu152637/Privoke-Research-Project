"""Verify and aggregate the fixed external-PII paired profile study."""
from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path
import random
from typing import Any

PROFILES = ("efficient", "balanced", "quality")
CONTROLS = ("baseline", "expanded")
PARTITIONS = ("validation", "nemotron_heldout", "meddies_heldout")
EXPECTED_VALIDATION_SHA256 = "d2d0c538e49f5bbc7a8f85887b9b8cfddb188a5ab9aae55c69ce26ae932be6d1"
BOOTSTRAP_SEED = 10102026
BOOTSTRAP_ITERATIONS = 2000
MIN_GROUPS = 20


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def read_json(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"Expected a JSON object at {path.name}.")
    return value


def _rate(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def confusion(rows: list[dict]) -> dict:
    tp = sum(row["truth"] and row["prediction"] for row in rows)
    tn = sum(not row["truth"] and not row["prediction"] for row in rows)
    fp = sum(not row["truth"] and row["prediction"] for row in rows)
    fn = sum(row["truth"] and not row["prediction"] for row in rows)
    positives, negatives = tp + fn, tn + fp
    recall, specificity = _rate(tp, positives), _rate(tn, negatives)
    balanced = ((recall + specificity) / 2
                if recall is not None and specificity is not None else None)
    return {"examples": len(rows), "positive_examples": positives,
            "negative_examples": negatives, "tp": tp, "tn": tn, "fp": fp, "fn": fn,
            "recall": recall, "specificity": specificity,
            "balanced_accuracy": balanced}


def _percentile(values: list[float], probability: float) -> float:
    values = sorted(values)
    offset = (len(values) - 1) * probability
    low = math.floor(offset)
    high = math.ceil(offset)
    return values[low] + (values[high] - values[low]) * (offset - low)


def paired_group_bootstrap(base: list[dict], candidate: list[dict], *,
                           seed: int = BOOTSTRAP_SEED,
                           iterations: int = BOOTSTRAP_ITERATIONS) -> dict:
    if len(base) != len(candidate) or not base:
        raise ValueError("Paired bootstrap inputs must have equal, nonzero row counts.")
    if any((a["row_id_sha256"], a["group_id_sha256"], a["truth"])
           != (b["row_id_sha256"], b["group_id_sha256"], b["truth"])
           for a, b in zip(base, candidate)):
        raise ValueError("Paired rows do not match by opaque identity, group, and label.")
    groups: dict[str, list[int]] = {}
    for index, row in enumerate(base):
        groups.setdefault(row["group_id_sha256"], []).append(index)
    metrics = ("recall", "specificity", "balanced_accuracy")
    deltas = {key: [] for key in metrics}
    point_base, point_candidate = confusion(base), confusion(candidate)
    point = {key: (point_candidate[key] - point_base[key]
                   if point_candidate[key] is not None and point_base[key] is not None else None)
             for key in metrics}
    if len(groups) < MIN_GROUPS:
        return {"method": "paired_source_group_bootstrap", "iterations": 0,
                "seed": seed, "group_count": len(groups), "point_delta": point,
                "confidence_intervals_95": None,
                "interval_status": "not_computed",
                "interval_reason": f"fewer_than_{MIN_GROUPS}_source_groups"}

    rng = random.Random(seed)
    group_names = sorted(groups)
    for _ in range(iterations):
        sampled = [rng.choice(group_names) for _ in group_names]
        indexes = [index for name in sampled for index in groups[name]]
        b = confusion([base[index] for index in indexes])
        c = confusion([candidate[index] for index in indexes])
        for key in metrics:
            if b[key] is not None and c[key] is not None:
                deltas[key].append(c[key] - b[key])
    intervals = {}
    for key, values in deltas.items():
        intervals[key] = ({"lower": _percentile(values, .025),
                           "upper": _percentile(values, .975),
                           "valid_replicates": len(values)}
                          if len(values) >= math.ceil(iterations * .95) else None)
    has_supported_metric = point["recall"] is not None or point["specificity"] is not None
    return {"method": "paired_source_group_bootstrap", "iterations": iterations,
            "seed": seed, "group_count": len(groups), "point_delta": point,
            "confidence_intervals_95": intervals,
            "valid_replicates": {key: len(values) for key, values in deltas.items()},
            "interval_status": ("complete" if has_supported_metric and
                                any(interval is not None for interval in intervals.values())
                                else "not_computed"),
            "interval_reason": (None if any(interval is not None for interval in intervals.values())
                                else "metric_unestimable_or_too_many_resamples_lacked_a_denominator")}


def _prediction_rows(path: Path, expected_sha: str, expected_count: int) -> list[dict]:
    if not isinstance(expected_sha, str) or sha256_file(path) != expected_sha:
        raise ValueError("Prediction file does not match the recorded SHA-256.")
    payload = read_json(path)
    records = payload.get("rows")
    if not isinstance(records, list) or len(records) != expected_count:
        raise ValueError("Prediction row count differs from the score manifest.")
    seen = set()
    normalized = []
    for item in records:
        if not isinstance(item, dict) or "error_type" in item:
            raise ValueError("Scored prediction rows must be successful records.")
        rid, gid = item.get("row_id_sha256"), item.get("group_id_sha256")
        truth, prediction = item.get("expected_has_pii"), item.get("predicted_present")
        if (not _is_sha(rid) or not _is_sha(gid) or rid in seen
                or type(truth) is not bool or type(prediction) is not bool):
            raise ValueError("Prediction row identity, label, or boolean prediction is invalid.")
        seen.add(rid)
        normalized.append({**item, "truth": truth, "prediction": prediction})
    return normalized


def _is_sha(value: Any) -> bool:
    return (isinstance(value, str) and len(value) == 64
            and all(character in "0123456789abcdef" for character in value))


def _validate_controller(study: Path) -> tuple[dict, str]:
    controller_path = study / "run-manifest.json"
    controller = read_json(controller_path)
    if (controller.get("schema_version") != 1 or controller.get("status") != "complete"
            or controller.get("phase") != "complete"
            or controller.get("restoration_verified") is not True
            or controller.get("errors") != []):
        raise ValueError("Controller is not a clean completed run with verified restoration.")
    source = controller.get("execution_source_revision")
    fit_source = controller.get("fit_source_revision")
    protocol = controller.get("protocol_sha256")
    prepared = controller.get("prepared_manifest_sha256")
    if not all(isinstance(value, str) and value for value in (source, fit_source)):
        raise ValueError("Controller source revisions are missing.")
    if not all(_is_sha(value) for value in (protocol, prepared)):
        raise ValueError("Controller protocol or prepared-manifest binding is invalid.")
    plan = controller.get("plan")
    expected = [{"profile": profile, "control": control, "partition": partition}
                for profile in PROFILES for control in CONTROLS for partition in PARTITIONS]
    if plan != expected:
        raise ValueError("Controller fixed 18-run plan differs from the approved plan.")
    scores = controller.get("scores")
    if not isinstance(scores, list) or len(scores) != len(expected):
        raise ValueError("Controller does not contain exactly 18 score records.")
    if controller.get("images_before") != controller.get("images_after"):
        raise ValueError("Persistent Docker service image identities changed during the study.")
    images = controller.get("images_before")
    if (not isinstance(images, dict) or "client-runtime" not in images
            or any(not isinstance(value, str) or len(value) != 71 or not value.startswith("sha256:")
                   or any(character not in "0123456789abcdef" for character in value[7:])
                   for value in images.values())
            or not isinstance(controller.get("evaluator_image_id"), str)
            or len(controller["evaluator_image_id"]) != 71
            or not controller["evaluator_image_id"].startswith("sha256:")
            or any(character not in "0123456789abcdef" for character in controller["evaluator_image_id"][7:])
            or not isinstance(controller.get("evaluator_image_ids"), list)
            or controller["evaluator_image_ids"] != [controller["evaluator_image_id"]]):
        raise ValueError("Controller image identity evidence is incomplete or inconsistent.")
    seen = set()
    for record, triplet in zip(scores, expected):
        key = (record.get("profile"), record.get("control"), record.get("partition"))
        if key != (triplet["profile"], triplet["control"], triplet["partition"]) or key in seen:
            raise ValueError("Controller score order or identities differ from the fixed plan.")
        if record.get("status") != "complete" or record.get("container_exit_code") != 0:
            raise ValueError("All fixed score records must complete successfully.")
        if type(record.get("rows")) is not int or record["rows"] <= 0:
            raise ValueError("Each planned partition score must include rows.")
        if (record["partition"] == "validation" and record["rows"] != 968
                or record["partition"] != "validation" and record["rows"] > 1000):
            raise ValueError("Partition row count is outside the frozen validation or source caps.")
        if record.get("successful_rows") != record.get("rows"):
            raise ValueError("A score record reports unsuccessful rows.")
        if not _is_sha(record.get("run_manifest_sha256")) or not _is_sha(record.get("predictions_sha256")):
            raise ValueError("Controller lacks score-manifest or prediction file digests.")
        seen.add(key)
    return controller, sha256_file(controller_path)


def _validate_score(study: Path, controller: dict, record: dict) -> tuple[dict, list[dict]]:
    profile, control, partition = record["profile"], record["control"], record["partition"]
    directory = study / profile / control / partition
    manifest_path = directory / "run-manifest.json"
    if sha256_file(manifest_path) != record["run_manifest_sha256"]:
        raise ValueError(f"Score run-manifest digest mismatch for {profile}/{control}/{partition}.")
    manifest = read_json(manifest_path)
    if (manifest.get("status") != "complete" or manifest.get("schema_version") != 1
            or manifest.get("profile") != profile or manifest.get("control") != control
            or manifest.get("partition") != partition or manifest.get("rows") != record["rows"]
            or manifest.get("successful_rows") != record["successful_rows"]
            or manifest.get("errors") != []
            or manifest.get("predictions_sha256") != record["predictions_sha256"]
            or manifest.get("metrics") != record.get("metrics")):
        raise ValueError("Score manifest status, identity, or row counts are invalid.")
    if (manifest.get("source_revision") != controller["execution_source_revision"]
            or manifest.get("fit_source_revision") != controller["fit_source_revision"]
            or manifest.get("protocol_sha256") != controller["protocol_sha256"]
            or manifest.get("prepared_manifest_sha256") != controller["prepared_manifest_sha256"]):
        raise ValueError("Score manifest source, protocol, or prepared-data provenance differs.")
    partition_hashes = controller.get("partition_sha256")
    if (not isinstance(partition_hashes, dict) or
            manifest.get("partition_sha256") != partition_hashes.get(partition)):
        raise ValueError("Score manifest partition digest differs from the controller binding.")
    if partition == "validation" and (manifest.get("partition_sha256") != EXPECTED_VALIDATION_SHA256
                                      or manifest.get("rows") != 968):
        raise ValueError("Validation score is not the frozen 968-row control.")
    if manifest.get("runtime_image_id") != controller["images_before"].get("client-runtime"):
        raise ValueError("Scorer runtime image differs from the controller's preflight image.")
    if manifest.get("evaluator_image_id") != record.get("evaluator_image_id"):
        raise ValueError("Scorer evaluator image differs from its controller record.")
    predictions_path = directory / "predictions.json"
    rows = _prediction_rows(predictions_path, record["predictions_sha256"], record["rows"])
    for row in rows:
        if partition != "validation" and row["truth"] is not True:
            raise ValueError("External diagnostics must contain only explicitly positive labels.")
    # Cross-check the controller/scorer summaries against the independently counted rows.
    overall = manifest.get("metrics", {}).get("overall")
    if not isinstance(overall, dict):
        raise ValueError("Completed score manifest is missing recomputable metrics.")
    recomputed = confusion(rows)
    if (overall.get("evaluated_samples") != len(rows)
            or overall.get("row_count") != len(rows)
            or overall.get("positive_examples") != recomputed["positive_examples"]
            or overall.get("absent_examples") != recomputed["negative_examples"]):
        raise ValueError("Score aggregate denominators differ from its prediction rows.")
    for key in ("recall", "specificity", "balanced_accuracy"):
        expected = None if recomputed[key] is None else round(recomputed[key], 4)
        if overall.get(key) != expected:
            raise ValueError(f"Score's {key} differs from the independently recomputed rows.")
    return manifest, rows


def _stratified(rows: list[dict], dimension: str) -> dict:
    buckets: dict[str, list[dict]] = {}
    for row in rows:
        if dimension == "category":
            labels = row.get("category")
            values = labels if isinstance(labels, list) and labels else ["unavailable"]
        elif dimension == "length":
            count = row.get("word_count")
            if type(count) is not int or count < 0:
                raise ValueError("Prediction record word_count is invalid.")
            values = ["0-19" if count < 20 else "20-49" if count < 50 else
                      "50-99" if count < 100 else "100+"]
        else:
            value = row.get({"source": "source_family", "domain": "domain",
                             "format": "document_format"}[dimension])
            values = [value if isinstance(value, str) and value else "unavailable"]
        for value in values:
            if not isinstance(value, str) or len(value) > 256:
                raise ValueError("Prediction stratum value is invalid.")
            buckets.setdefault(value, []).append(row)
    return {name: confusion(group) for name, group in sorted(buckets.items())}


def _safe_family_summary(rows: list[dict]) -> dict:
    return {"by_source_family": _stratified(rows, "source"),
            "prompt_detection_recall_by_source_category": _stratified(rows, "category"),
            "by_domain": _stratified(rows, "domain"),
            "by_document_format": _stratified(rows, "format"),
            "by_word_length": _stratified(rows, "length")}


def summarize(study: Path) -> dict:
    study = study.resolve()
    controller, controller_sha = _validate_controller(study)
    runs = {}
    row_counts = {}
    common_bindings = {}
    for record in controller["scores"]:
        key = (record["profile"], record["control"], record["partition"])
        manifest, rows = _validate_score(study, controller, record)
        runs[key] = rows
        row_counts[key[2]] = record["rows"]
        binding = (manifest["prepared_manifest_sha256"], manifest["partition_sha256"])
        prior = common_bindings.setdefault(key[2], binding)
        if prior != binding:
            raise ValueError("Matched records have inconsistent prepared-partition bindings.")
    # All six runs per partition must have the same examples, groups, labels and ordering.
    for profile in PROFILES:
        for partition in PARTITIONS:
            baseline = runs[(profile, "baseline", partition)]
            expanded = runs[(profile, "expanded", partition)]
            if len(baseline) != len(expanded):
                raise ValueError("Baseline and expanded scores have different partition sizes.")
            if any((a["row_id_sha256"], a["group_id_sha256"], a["truth"])
                   != (b["row_id_sha256"], b["group_id_sha256"], b["truth"])
                   for a, b in zip(baseline, expanded)):
                raise ValueError("Baseline and expanded rows are not exactly paired.")
            for control in CONTROLS:
                reference = runs[(profile, control, partition)]
                for other_profile in PROFILES:
                    other = runs[(other_profile, control, partition)]
                    if [(r["row_id_sha256"], r["group_id_sha256"], r["truth"]) for r in reference] != [
                            (r["row_id_sha256"], r["group_id_sha256"], r["truth"]) for r in other]:
                        raise ValueError("Profiles do not score the same ordered rows and labels.")

    report = {"schema_version": 1, "status": "verified", "study_manifest_sha256": controller_sha,
              "provenance": {"execution_source_revision": controller["execution_source_revision"],
                             "fit_source_revision": controller["fit_source_revision"],
                             "protocol_sha256": controller["protocol_sha256"],
                             "prepared_manifest_sha256": controller["prepared_manifest_sha256"],
                             "partition_sha256": controller["partition_sha256"],
                             "runtime_image_ids": controller["images_before"],
                             "evaluator_image_id": controller["evaluator_image_id"]},
              "bootstrap": {"method": "paired_source_group_resampling",
                            "iterations": BOOTSTRAP_ITERATIONS, "seed": BOOTSTRAP_SEED,
                            "minimum_groups": MIN_GROUPS},
              "profiles": {}}
    for profile in PROFILES:
        profile_report = {"partitions": {}}
        for partition in PARTITIONS:
            base = runs[(profile, "baseline", partition)]
            candidate = runs[(profile, "expanded", partition)]
            profile_report["partitions"][partition] = {
                "baseline": {"overall": confusion(base), "strata": _safe_family_summary(base)},
                "expanded": {"overall": confusion(candidate), "strata": _safe_family_summary(candidate)},
                "paired_delta_expanded_minus_baseline": paired_group_bootstrap(base, candidate),
            }
        profile_report["matched_validation"] = {
            "baseline": confusion(runs[(profile, "baseline", "validation")]),
            "expanded": confusion(runs[(profile, "expanded", "validation")]),
            "paired_delta_expanded_minus_baseline": paired_group_bootstrap(
                runs[(profile, "baseline", "validation")],
                runs[(profile, "expanded", "validation")]),
        }
        profile_report["partition_examples"] = row_counts
        report["profiles"][profile] = profile_report
    return report


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--study", type=Path, required=True,
                        help="Completed fixed study directory created by run-external-pii-study.py")
    parser.add_argument("--output", type=Path, required=True,
                        help="Fresh JSON output path beneath evaluation/results")
    args = parser.parse_args(argv)
    results_root = (Path(__file__).resolve().parent / "results").resolve()
    output = args.output.resolve()
    if results_root not in output.parents:
        parser.error("--output must be a new file beneath evaluation/results.")
    if output.exists():
        parser.error("--output must be fresh and unused.")
    try:
        report = summarize(args.study)
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open("x", encoding="utf-8", newline="\n") as stream:
            json.dump(report, stream, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False)
            stream.write("\n")
    except Exception as exc:
        parser.exit(1, f"summary failed ({type(exc).__name__}): {exc}\n")
    print(json.dumps({"status": report["status"], "output": output.as_posix(),
                      "profiles": len(report["profiles"])}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
