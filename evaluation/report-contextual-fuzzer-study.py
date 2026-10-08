"""Read-only quality reconciliation for preserved contextual fuzzer evidence.

Print deterministic JSON or Markdown; never infer, train, contact services, or
open final data. --partial exposes missing measurements without certifying them.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import math
from pathlib import Path
import statistics
import struct
import sys
from unittest.mock import patch

VALIDATION_SHA = "d2d0c538e49f5bbc7a8f85887b9b8cfddb188a5ab9aae55c69ce26ae932be6d1"
DEVELOPMENT_SHA = "65bf02af1f9f7167a5aa5eaaa8aeac54111c90d009585ed36570d3ce0a635095"
FIXTURE_SHA = "d6c7d5d87235cd6b0f9d24eac43b30c3ace9f0bf4f421ef5d5d812de79827a17"
PROFILES = ("efficient", "balanced", "quality")
HEADS = {f"head.{head}.{part}" for head in ("sensitivity", "visibility", "category") for part in ("weight", "bias")}
BLOCK = ("attention.query.weight", "attention.key.weight", "attention.value.weight", "attention.output.weight", "attention.output.bias", "ffn.input.weight", "ffn.input.bias", "ffn.output.weight", "ffn.output.bias")
RANK = {"ALLOW": 0, "WARN": 1, "BLOCK": 2}


def digest(content):
    return hashlib.sha256(content).hexdigest()


def read_bytes(path, commitment=None):
    path = Path(path)
    if path.name.casefold() == "final.jsonl":
        raise ValueError("Final partition access is forbidden.")
    content = path.read_bytes()
    if commitment is not None and digest(content) != commitment:
        raise ValueError(f"Preserved byte commitment changed: {path}")
    return content


def read(path, commitment=None):
    return json.loads(read_bytes(path, commitment))


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")


def model_summary(path, commitment):
    artifact = read(path, commitment)
    expected = digest(canonical({k: v for k, v in artifact.items() if k != "checksum"}).encode())
    if artifact.get("architecture") != "privoke_tiny_transformer_v1" or artifact.get("checksum") != expected:
        raise ValueError("Model architecture/internal checksum mismatch.")
    parameters, trainables, tensors = artifact["parameters"], [], []
    for name, tensor in sorted(parameters.items()):
        values, shape = tensor["values"], tensor["shape"]
        if type(tensor.get("trainable")) is not bool or not shape or any(type(n) is not int or n < 1 for n in shape) or math.prod(shape) != len(values) or any(type(x) not in (int, float) or not math.isfinite(x) for x in values):
            raise ValueError("Invalid model tensor shape/value/trainability.")
        if tensor["trainable"]:
            trainables.append(name)
        tensors.append([name, shape, [struct.unpack("<f", struct.pack("<f", x))[0] for x in values]])
    config, metadata = artifact["config"], artifact.get("metadata", {})
    strategy = metadata.get("contextual_training_strategy")
    layers = config.get("num_layers", 1)
    expected_trainables = HEADS
    if strategy == "contextual_last_block_sgd_v1":
        prefix = "" if layers == 1 else f"layers.{layers - 1}."
        expected_trainables = HEADS | {prefix + name for name in BLOCK}
    elif strategy is not None:
        raise ValueError("Unrecognized contextual training strategy.")
    if set(trainables) != expected_trainables:
        raise ValueError("Trainable tensors differ from the declared contextual scope.")
    fingerprint = digest(json.dumps(tensors, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode())
    training_fingerprint = digest(json.dumps([[name, None, values] for name, _, values in tensors], separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode())
    identity = {"model_id": artifact["model_id"], "model_version": artifact["version"], "artifact_checksum": artifact["checksum"], "parameter_fingerprint": fingerprint}
    summary = {**identity, "training_metadata_parameter_fingerprint": training_fingerprint, "artifact_path": str(path), "artifact_file_sha256": commitment, "architecture": artifact["architecture"], "parameters": sum(len(t["values"]) for t in parameters.values()), "trainable_parameters": sum(len(parameters[name]["values"]) for name in trainables), "trainable_tensors": trainables, "frozen_tensors": sorted(set(parameters) - set(trainables)), "training_scope": "last encoder block plus six contextual heads" if strategy else "six contextual heads; encoder frozen", "config": config, "artifact_training_metadata": metadata}
    return summary, identity


def endpoint(path, commitment, count, positive):
    content = read_bytes(path, commitment)
    rows = [json.loads(line) for line in content.decode("utf-8").splitlines() if line.strip()]
    if len(rows) != count or len({r["id"] for r in rows}) != count or any(type(r.get("expected_has_pii")) is not bool or not isinstance(r.get("group_id"), str) or not r["group_id"] for r in rows) or sum(r["expected_has_pii"] for r in rows) != positive:
        raise ValueError("Frozen endpoint ID/group/class counts changed.")
    return {str(r.get("example_id", "local-jsonl:" + r["id"])): (r["expected_has_pii"], r["group_id"]) for r in rows}


def metrics(counts):
    tp, tn, fp, fn = (counts[key] for key in ("tp", "tn", "fp", "fn"))
    positive, negative = tp + fn, tn + fp
    recall = tp / positive if positive else None
    specificity = tn / negative if negative else None
    return {**counts, "positive_support": positive, "negative_support": negative, "rows": positive + negative, "recall": recall, "specificity": specificity, "precision": tp / (tp + fp) if tp + fp else None, "f1": 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else None, "balanced_accuracy": (recall + specificity) / 2 if recall is not None and specificity is not None else None}


def counts_from(rows):
    counts = dict.fromkeys(("tp", "tn", "fp", "fn"), 0)
    for row in rows:
        counts[("tp" if row["detected_sensitive"] else "fn") if row["expected_has_pii"] else ("fp" if row["detected_sensitive"] else "tn")] += 1
    return counts


def source_strata(rows):
    families = {}
    for row in rows:
        family = row["group_id"].removeprefix("piimb:").split(":", 1)[0]
        if family in ("ai4privacy-en", "ai4privacy-multi"):
            family = "AI4Privacy/OpenPII"
        families.setdefault(family, []).append(row)
    return {name: {**metrics(counts_from(values)), "recorded_source_groups": len({r["group_id"] for r in values})} for name, values in sorted(families.items())}


def latency(rows):
    values = sorted(row["elapsed_ms"] for row in rows)
    if any(type(x) not in (int, float) or not math.isfinite(x) or x < 0 for x in values):
        raise ValueError("Missing or invalid latency observations.")
    location = (len(values) - 1) * .95
    lower, upper = math.floor(location), math.ceil(location)
    return {"requests": len(values), "first_ms": rows[0]["elapsed_ms"], "median_ms": statistics.median(values), "p95_ms": values[lower] + (values[upper] - values[lower]) * (location - lower), "scope": "Returned service elapsed_ms, first request included; excludes browser/bridge and does not establish representative production latency."}


def verify_report(evidence, reference, identity, declared):
    report = read(evidence["path"], evidence["sha256"])
    rows = report["metadata"]["predictions"]
    joined = {r["example_id"]: (r["expected_has_pii"], r["group_id"]) for r in rows}
    if report.get("errors") or len(rows) != len(reference) or joined != reference or any(r.get("status") != "ok" or type(r.get("detected_sensitive")) is not bool or type(r.get("expected_has_pii")) is not bool for r in rows):
        raise ValueError("Incomplete, erroneous or unmatched report.")
    identity_observations = 0
    for row in rows:
        for layer in row.get("layers", []):
            if layer.get("status") not in ("ok", "skipped") or (layer.get("error") and layer.get("status") != "skipped"):
                raise ValueError("Runtime layer error in scored evidence.")
            if layer.get("layer") == "DETECTION_LAYER_SEMANTIC" and layer.get("status") == "ok":
                for item in layer.get("results", []):
                    if any(item.get("metadata", {}).get(k) != v for k, v in identity.items()):
                        raise ValueError("Returned model identity or parameter fingerprint mismatch.")
                    identity_observations += 1
    if identity_observations == 0:
        raise ValueError("Report supplies no returned semantic identity evidence.")
    counts = counts_from(rows)
    names = {"tp": "true_positives", "tn": "true_negatives", "fp": "false_positives", "fn": "false_negatives"}
    if counts != declared or any(report["metrics"].get(names[k]) != value for k, value in counts.items()) or report["metrics"].get("evaluated_samples") != len(rows) or report["metrics"].get("runtime_errors") != 0:
        raise ValueError("Raw predictions, declared counts and report aggregates disagree.")
    summary = {"evidence": evidence, "metrics": metrics(counts), "source_strata": source_strata(rows), "latency": latency(rows), "semantic_identity_observations": identity_observations}
    return summary, {r["example_id"]: r for r in rows}


def layer_signal(row, layer_name):
    return any(item.get("sensitivity") in ("S1", "S2", "S3") or item.get("categories") for layer in row.get("layers", []) if layer.get("layer") == layer_name and layer.get("status") == "ok" for item in layer.get("results", []))


def pipeline_rescue(semantic, pipeline):
    if set(semantic) != set(pipeline):
        raise ValueError("Semantic/pipeline rows do not pair.")
    result = {"positive_semantic_misses_detected_by_pipeline": 0, "positive_semantic_detections_lost_in_pipeline": 0, "clean_pipeline_only_flags": 0, "clean_pipeline_only_with_returned_regex_signal": 0, "clean_pipeline_only_with_returned_ner_signal": 0, "clean_semantic_flags_removed_in_pipeline": 0}
    for key, before in semantic.items():
        after = pipeline[key]
        if (before["expected_has_pii"], before["group_id"]) != (after["expected_has_pii"], after["group_id"]):
            raise ValueError("Layer pairing truth/groups changed.")
        if before["expected_has_pii"]:
            result["positive_semantic_misses_detected_by_pipeline"] += not before["detected_sensitive"] and after["detected_sensitive"]
            result["positive_semantic_detections_lost_in_pipeline"] += before["detected_sensitive"] and not after["detected_sensitive"]
        else:
            introduced = not before["detected_sensitive"] and after["detected_sensitive"]
            result["clean_pipeline_only_flags"] += introduced
            result["clean_pipeline_only_with_returned_regex_signal"] += introduced and layer_signal(after, "DETECTION_LAYER_REGEX")
            result["clean_pipeline_only_with_returned_ner_signal"] += introduced and layer_signal(after, "DETECTION_LAYER_NER")
            result["clean_semantic_flags_removed_in_pipeline"] += before["detected_sensitive"] and not after["detected_sensitive"]
    result["interpretation"] = "Matched returned-output transitions; regex/NER signals may overlap and are descriptive co-occurrences, not causal or contextual-safety attribution."
    return result


def paired_quality(before, after):
    if set(before) != set(after) or any((before[k]["expected_has_pii"], before[k]["group_id"]) != (after[k]["expected_has_pii"], after[k]["group_id"]) for k in before):
        raise ValueError("Candidate and baseline do not pair exactly.")
    old, new = metrics(counts_from(before.values())), metrics(counts_from(after.values()))
    result = {"count_difference_candidate_minus_baseline": {k: new[k] - old[k] for k in ("tp", "tn", "fp", "fn")}, "rate_difference": {k: new[k] - old[k] if new[k] is not None and old[k] is not None else None for k in ("recall", "specificity", "precision", "f1")}, "new_positive_misses": sum(before[k]["expected_has_pii"] and before[k]["detected_sensitive"] and not after[k]["detected_sensitive"] for k in before), "positive_misses_corrected": sum(before[k]["expected_has_pii"] and not before[k]["detected_sensitive"] and after[k]["detected_sensitive"] for k in before), "new_clean_flags": sum(not before[k]["expected_has_pii"] and not before[k]["detected_sensitive"] and after[k]["detected_sensitive"] for k in before), "clean_flags_corrected": sum(not before[k]["expected_has_pii"] and before[k]["detected_sensitive"] and not after[k]["detected_sensitive"] for k in before)}
    return result


def measurements(binding, model, identity, reference, endpoint_name="validation"):
    summaries, prediction_rows = {}, {}
    if set(binding["reports"]) != {"semantic", "pipeline"} or set(binding["validation"]) != {"semantic", "pipeline"}:
        raise ValueError("Both semantic and pipeline evidence are required.")
    for layer, evidence in binding["reports"].items():
        summaries[layer], prediction_rows[layer] = verify_report(evidence, reference, identity, binding["validation"][layer])
    return {"model": model, endpoint_name: summaries, "pipeline_rescue": pipeline_rescue(prediction_rows["semantic"], prediction_rows["pipeline"])}, prediction_rows


def training_quality(response, plan=None):
    metadata = response.get("metadata", {})
    metric_names = ("examples", "total_weight", "exact_match_rate", "average_loss", "supervised_objective_loss", "heldout_examples", "candidate_heldout_examples", "heldout_sensitive_examples", "candidate_heldout_sensitive_examples", "heldout_clean_examples", "candidate_heldout_clean_examples", "heldout_exact_match_rate", "candidate_heldout_exact_match_rate", "heldout_sensitive_recall", "candidate_heldout_sensitive_recall", "heldout_clean_specificity", "candidate_heldout_clean_specificity", "candidate_heldout_safety_regression_rate")
    recorded = {}
    for name in metric_names:
        if name in metadata:
            try:
                value = float(metadata[name])
            except (TypeError, ValueError) as exc:
                raise ValueError("Invalid recorded training metric.") from exc
            if not math.isfinite(value):
                raise ValueError("Nonfinite recorded training metric.")
            recorded[name] = value
    comparisons = {}
    for suffix in ("exact_match_rate", "sensitive_recall", "clean_specificity"):
        before, after = "heldout_" + suffix, "candidate_heldout_" + suffix
        comparisons[suffix] = {"before": recorded.get(before), "after": recorded.get(after), "nonregressing": recorded[after] >= recorded[before] if before in recorded and after in recorded else None}
    comparisons["severity_and_action"] = {"candidate_safety_regression_rate": recorded.get("candidate_heldout_safety_regression_rate"), "passed": recorded.get("candidate_heldout_safety_regression_rate") == 0 if "candidate_heldout_safety_regression_rate" in recorded else None, "scope": "Existing combined per-example target/baseline severity/action floor; not independent privacy truth."}
    inventory = response.get("partition_inventory")
    if inventory is not None:
        if inventory.get("group_overlap") != 0:
            raise ValueError("Training and held-out groups overlap.")
        for partition, expected_rows in (("train", 256), ("heldout", 16)):
            values = inventory[partition]
            if values["rows"] != expected_rows or sum(values["sensitivity_counts"].values()) != expected_rows or sum(values["role_counts"].values()) != expected_rows or values["groups"] != len(values["opaque_group_labels"]) or not 1 <= values["groups"] <= expected_rows or any(key not in ("S0", "S1", "S2", "S3") or type(value) is not int or value < 0 for key, value in values["sensitivity_counts"].items()):
                raise ValueError("Recorded sampling inventory has invalid counts.")
        if inventory["heldout"]["groups"] != 16 or set(inventory["train"]["opaque_group_labels"]) & set(inventory["heldout"]["opaque_group_labels"]):
            raise ValueError("Recorded whole-family split is not disjoint.")
    if plan is not None and "learning_rate" in metadata and float(metadata["learning_rate"]) != plan["rate"]:
        raise ValueError("Recorded training learning rate differs from plan.")
    if plan is not None:
        strategy = "contextual_last_block_sgd_v1" if plan["strategy"] == "last_block" else "transformer_classification_head_finetune"
        if "strategy" in metadata and metadata["strategy"] != strategy:
            raise ValueError("Recorded supervised strategy differs from plan.")
        if "max_gradient" in metadata and float(metadata["max_gradient"]) != plan["max_gradient"]:
            raise ValueError("Recorded gradient bound differs from plan.")
        if "transformations_per_example" in metadata and int(metadata["transformations_per_example"]) != plan["transforms"]:
            raise ValueError("Recorded augmentation differs from plan.")
    coverage = None if inventory is None else {key: {"rows": inventory[key]["rows"], "sensitivity_positive_rows": sum(value for label, value in inventory[key]["sensitivity_counts"].items() if label != "S0"), "sensitivity_positive_fraction": sum(value for label, value in inventory[key]["sensitivity_counts"].items() if label != "S0") / inventory[key]["rows"], "groups": inventory[key]["groups"]} for key in ("train", "heldout")}
    if response.get("accepted") is True:
        if coverage is None or any(comparisons[key]["nonregressing"] is not True for key in ("exact_match_rate", "sensitive_recall", "clean_specificity")) or comparisons["severity_and_action"]["passed"] is not True or recorded.get("exact_match_rate", 0) <= 0:
            raise ValueError("Accepted response has absent or failing recorded publication guards.")
        if any(recorded.get(key) != value for key, value in {"examples": 256, "heldout_examples": 16, "candidate_heldout_examples": 16, "heldout_sensitive_examples": coverage["heldout"]["sensitivity_positive_rows"], "candidate_heldout_sensitive_examples": coverage["heldout"]["sensitivity_positive_rows"], "heldout_clean_examples": 16 - coverage["heldout"]["sensitivity_positive_rows"], "candidate_heldout_clean_examples": 16 - coverage["heldout"]["sensitivity_positive_rows"]}.items()):
            raise ValueError("Actual sampled supports and training guard supports disagree.")
    return {"recorded_metrics": recorded, "metric_absence": [name for name in metric_names if name not in recorded], "heldout_checks": comparisons, "actual_partition_inventory": inventory, "sensitivity_label_coverage": coverage, "metadata": metadata, "fingerprint_formats": {"training_metadata": "SHA-256 of sorted name/null-shape/float32-values triples", "returned_inference_identity": "SHA-256 of sorted name/actual-shape/float32-values triples; distinct format"}, "loss_scope": {"average_loss": "Legacy weighted classification-distance diagnostic, not optimized cross entropy.", "supervised_objective_loss": "Weighted sensitivity CE + visibility CE + summed category BCE for the last-block arm; numerical scale differs from legacy average_loss and must not be compared as the same objective."}}


def fixture_summary(state, study, reference_identity, winner_identity):
    assessment = state.get("finalized")
    if assessment is None:
        return None
    path = study / "final-assessment.json"
    if not path.exists():
        return {"assessment": assessment, "fixture_measured": False}
    if read(path) != assessment:
        raise ValueError("Final assessment and state disagree.")
    cases = [json.loads(line) for line in read_bytes(state["fixture"], FIXTURE_SHA).decode().splitlines() if line.strip()]
    if len(cases) != 48 or len({c["case_id"] for c in cases}) != 48 or Counter("ambiguous" if c["ambiguous"] else "disclosure" if c["required_sensitive"] else "control" for c in cases) != Counter({"control": 24, "disclosure": 17, "ambiguous": 7}):
        raise ValueError("Reviewed fixture composition changed.")
    before, after = read(study / "fixture-live.json"), read(study / "fixture-winner.json")
    if set(before) != {c["case_id"] for c in cases} or set(after) != set(before):
        raise ValueError("Incomplete contextual fixture comparison.")
    losses, overblocking, actions, failures = [], [], [], {"live": [], "winner": []}
    identity_observations = {"live": 0, "winner": 0}
    for case in cases:
        for label, observations, identity in (("live", before, reference_identity), ("winner", after, winner_identity)):
            observation = observations[case["case_id"]]
            response = observation["raw"]
            request = observation["request_id"]
            if not isinstance(request, str) or not request.startswith("ctx-fixture-") or len(request) != 52 or any(character not in "0123456789abcdef" for character in request[12:]) or response.get("request_id") != request or response.get("error") or response.get("action") != observation["action"]:
                raise ValueError("Fixture request/response correlation changed.")
            for layer in response.get("layers", []):
                if layer.get("status") not in ("ok", "skipped") or (layer.get("error") and layer.get("status") != "skipped"):
                    raise ValueError("Fixture runtime layer failed.")
                if layer.get("layer") == "DETECTION_LAYER_SEMANTIC" and layer.get("status") == "ok":
                    items = layer.get("results", [])
                    if any(any(item.get("metadata", {}).get(key) != value for key, value in identity.items()) for item in items):
                        raise ValueError("Fixture returned model identity changed or absent.")
                    identity_observations[label] += len(items)
        old, new = before[case["case_id"]]["action"], after[case["case_id"]]["action"]
        if old not in RANK or new not in RANK:
            raise ValueError("Invalid fixture actions.")
        required = case.get("minimum_action") or case.get("expected_action")
        eligible = not case["ambiguous"]
        if eligible and case["required_sensitive"]:
            if RANK[old] >= RANK[required] > RANK[new]:
                losses.append(case["case_id"])
            for label, action in (("live", old), ("winner", new)):
                if RANK[action] < RANK[required]:
                    failures[label].append(case["case_id"])
        if eligible and case["required_sensitive"] is False and old == "ALLOW" and new != "ALLOW":
            overblocking.append(case["case_id"])
        actions.append({"case_id": case["case_id"], "quantitative_eligible": eligible, "required_sensitive": case["required_sensitive"], "required_action": required, "live_action": old, "winner_action": new, "action_downgrade": RANK[new] < RANK[old]})
    if not all(identity_observations.values()):
        raise ValueError("Fixture supplies no returned model identity evidence for live or winner.")
    declared = assessment["contextual_gate"]
    if losses != declared["private_action_losses"] or overblocking != declared["added_clean_interventions"] or declared["passed"] != (not losses and not overblocking):
        raise ValueError("Per-case fixture evidence disagrees with retention gate.")
    if any(len({value["request_id"] for value in observations.values()}) != 48 for observations in (before, after)):
        raise ValueError("Fixture request IDs repeat.")
    return {"assessment": assessment, "fixture_measured": True, "semantic_identity_observations": identity_observations, "identity_scope": "Empty successful semantic responses have no per-case identity item; provenance combines explicit model selection, frozen sources/catalog/images and matching returned identities elsewhere in each collection.", "new_private_action_losses": losses, "new_clean_interventions": overblocking, "existing_and_remaining_private_failures": failures, "per_case_actions": actions, "quantitative_cases": 41, "ambiguous_excluded": 7, "provenance": {"fixture_sha256": FIXTURE_SHA, "assessment_sha256": digest(read_bytes(path)), "fixture_live_sha256": digest(read_bytes(study / "fixture-live.json")), "fixture_winner_sha256": digest(read_bytes(study / "fixture-winner.json"))}}


def retention_summary(state, study, selection):
    assessment = state.get("finalized")
    if assessment is None:
        return None
    if selection is None:
        raise ValueError("Endpoint assessed without frozen selection.")
    winner = selection["winner"]
    if winner is None:
        if assessment.get("retained") is not False or "reference_reports" in assessment:
            raise ValueError("No-winner assessment contradicts frozen selection.")
        return {"assessment": assessment, "development_measured": False, "fixture_measured": False}
    if not (study / "final-assessment.json").exists() or read(study / "final-assessment.json") != assessment:
        raise ValueError("Final assessment copy absent or changed.")
    reference = endpoint(state["development"], DEVELOPMENT_SHA, 502, 264)
    original = state["live_backups"]["balanced"]
    model, identity = model_summary(original["path"], original["sha256"])
    candidate_model, candidate_identity = model_summary(winner["artifact"], winner["artifact_sha256"])
    old, old_rows = measurements({"reports": assessment["reference_reports"], "validation": assessment["reference"]}, model, identity, reference, endpoint_name="development")
    new, new_rows = measurements({"reports": assessment["candidate_reports"], "validation": assessment["candidate"]}, candidate_model, candidate_identity, reference, endpoint_name="development")
    fixture = fixture_summary(state, study, identity, candidate_identity)
    scored = new["development"]["pipeline"]["metrics"]
    qualifies = scored["recall"] >= .9 and scored["tn"] > old["development"]["pipeline"]["metrics"]["tn"] and fixture["assessment"]["contextual_gate"]["passed"]
    if assessment["retained"] != qualifies or assessment.get("final_access") is not False:
        raise ValueError("Retention decision disagrees with reconciled endpoint evidence.")
    return {"assessment": assessment, "development_measured": True, "development_sha256": DEVELOPMENT_SHA, "development_scope": "Reused exploratory endpoint, assessed after frozen selection", "live_balanced_development": old, "winner_development": new, "paired_development": {layer: paired_quality(old_rows[layer], new_rows[layer]) for layer in ("semantic", "pipeline")}, "fixture": fixture}


def quality_report(study, partial=False):
    study = Path(study).resolve()
    state_bytes = read_bytes(study / "state.json")
    state = json.loads(state_bytes)
    for binding in state["source_freeze"].values():
        read_bytes(binding["path"], binding["sha256"])
    for relative, commitment in state["computation_source_sha256"].items():
        read_bytes(study / "source-freeze" / "tree" / relative, commitment)
    preparation = read(Path(state["prepared"]) / "manifest.json", state["preparation_manifest_sha256"])
    read_bytes(Path(state["prepared"]) / "prompts.jsonl", preparation["curriculum_sha256"])
    validation = endpoint(state["validation"], VALIDATION_SHA, 968, 475)
    complete = state.get("baseline_complete") is True and len(state["records"]) == 54 and bool(state.get("selection")) and bool(state.get("finalized")) and state.get("restoration_verified") is True and not state.get("failure") and not state.get("unknown_outcome")
    if not partial and not complete:
        raise ValueError("Study is incomplete or failed; --partial is required and does not certify completion.")
    baselines, baseline_rows = {}, {}
    for profile in PROFILES:
        binding = state.get("baselines", {}).get(profile)
        if binding is None:
            if state.get("baseline_complete"):
                raise ValueError("Complete baseline flag has missing profile evidence.")
            baselines[profile] = {"status": "not yet measured"}
            continue
        model, identity = model_summary(binding["artifact"], binding["sha256"])
        baselines[profile], baseline_rows[profile] = measurements(binding, model, identity, validation)
        baselines[profile]["status"] = "verified complete validation measurement"
    planned = state["planned_attempts"]
    expected_grid = {(profile, strategy, rate, seed) for profile in PROFILES for strategy in ("heads", "last_block") for rate in (.003, .01, .03) for seed in (42, 1337, 2026)}
    if len(planned) != 54 or {r["index"] for r in planned} != set(range(54)) or {(r["profile"], r["strategy"], r["rate"], r["seed"]) for r in planned} != expected_grid or any((r["prompt_count"], r["heldout_count"], r["max_gradient"], r["transforms"], r["request_id"]) != (256, 16, .05, 0, f"{state['prefix']}-{r['index']:02d}") for r in planned):
        raise ValueError("Study does not declare all 54 distinct attempts.")
    observed = {r["index"]: r for r in state["records"]}
    if len(observed) != len(state["records"]) or not set(observed).issubset({r["index"] for r in planned}):
        raise ValueError("Duplicate or undeclared attempt records.")
    attempts = []
    for plan in planned:
        record = observed.get(plan["index"])
        if record is None:
            directory = study / f"attempt-{plan['index']:02d}"
            pending = {**plan, "status": "in flight or pending; not a completed attempt" if directory.exists() else "not attempted", "quality": None}
            if (directory / "response.json").exists():
                content = read_bytes(directory / "response.json")
                response = json.loads(content)
                if response.get("request") != plan or type(response.get("accepted")) is not bool:
                    raise ValueError("Pending response differs from frozen attempt.")
                pending.update(status="response preserved; accepted but unscored" if response.get("accepted") else "response preserved; rejected but not finalized", accepted=response.get("accepted"), training=training_quality(response, plan), response_evidence={"path": str(directory / "response.json"), "sha256": digest(content), "binding": "Observed pending bytes; absent from committed attempt records"}, pending_reason=state.get("failure") or state.get("unknown_outcome") or "Attempt not committed to state")
                if (directory / "candidate.json").exists():
                    candidate_content = read_bytes(directory / "candidate.json")
                    pending["unscored_model"], _ = model_summary(directory / "candidate.json", digest(candidate_content))
            attempts.append(pending)
            continue
        if any(record.get(k) != v for k, v in plan.items()):
            raise ValueError("Attempt settings differ from the frozen plan.")
        response = read(record["response_path"], record["response_sha256"])
        if type(response.get("accepted")) is not bool or response["accepted"] != record["accepted"] or response.get("request") != plan:
            raise ValueError("Response and attempt identity/settings disagree.")
        item = {**plan, "accepted": record["accepted"], "wall_seconds": record.get("wall_seconds"), "recovery_scoring_seconds": record.get("recovery_scoring_seconds"), "timing_limitation": record.get("timing_limitation"), "execution_revision": record.get("execution_revision", 0), "recovery_manifest": record.get("recovery_manifest"), "response_evidence": {"path": record["response_path"], "sha256": record["response_sha256"]}, "training": training_quality(response, plan)}
        if record.get("recovery_manifest"):
            amendment = read(record["recovery_manifest"]["path"], record["recovery_manifest"]["sha256"])
            if amendment != state["execution_amendments"][record["execution_revision"] - 1] or any(amendment.get(key) is not False for key in ("training_request_repeated", "training_data_or_parameters_changed", "selection_rule_changed")) or amendment["old_computation_source_sha256"] != amendment["new_computation_source_sha256"] or amendment["protocol_canonical_lf_sha256"] != state["protocol_canonical_lf_sha256"]:
                raise ValueError("Recovery amendment changes the declared training/selection evidence.")
            read_bytes(study / "source-freeze/controller.py", amendment["old_controller_sha256"])
            read_bytes(Path(record["recovery_manifest"]["path"]).parent / "controller.py", amendment["new_controller_sha256"])
            if set(amendment["bound_artifact_sha256"]) != {"request.json", "base.json", "candidate.json", "response.json"}:
                raise ValueError("Recovery does not bind all original attempt evidence.")
            for filename, commitment in amendment["bound_artifact_sha256"].items():
                read_bytes(study / f"attempt-{plan['index']:02d}" / filename, commitment)
        if record["accepted"]:
            model, identity = model_summary(record["artifact"], record["artifact_sha256"])
            if response["metadata"].get("base_parameter_fingerprint") != baselines[plan["profile"]]["model"]["training_metadata_parameter_fingerprint"] or response["metadata"].get("updated_parameter_fingerprint") != model["training_metadata_parameter_fingerprint"]:
                raise ValueError("Training metadata value-only fingerprints do not match preserved parameters.")
            receipt = response.get("receipt", {})
            if record.get("identity") != identity or response.get("applied_version") != identity["model_version"] or response.get("model_id") != identity["model_id"] or response.get("prompts_generated") != 256 or response.get("base_version") != baselines[plan["profile"]]["model"]["model_version"] or not receipt.get("found") or not receipt.get("accepted") or any(receipt.get(key) != response.get(key) for key in ("model_id", "base_version", "applied_version", "prompts_generated")):
                raise ValueError("Published model and durable acknowledgment identity disagree.")
            item["quality"], candidate_rows = measurements(record, model, identity, validation)
            item["paired_original_validation"] = {layer: paired_quality(baseline_rows[plan["profile"]][layer], candidate_rows[layer]) for layer in ("semantic", "pipeline")}
            pipeline = item["quality"]["validation"]["pipeline"]["metrics"]
            baseline_tn = baselines[plan["profile"]]["validation"]["pipeline"]["metrics"]["tn"]
            eligible = pipeline["recall"] >= .9 and pipeline["tn"] > baseline_tn
            if record.get("eligible") != eligible:
                raise ValueError("Declared candidate eligibility disagrees with verified counts.")
            item.update(status="accepted/scored validation-eligible" if eligible else "accepted/scored validation-ineligible", eligibility={"recall_at_least_90_percent": pipeline["recall"] >= .9, "strict_specificity_gain": pipeline["tn"] > baseline_tn, "eligible": eligible})
        else:
            if response.get("receipt", {}).get("found"):
                raise ValueError("Rejected response conflicts with durable publication receipt.")
            item.update(status="rejected; no quality score claimed", rejection_reason=response.get("error") or response.get("message") or "No reason recorded", quality=None)
        attempts.append(item)
    result = {"study": str(study), "study_prefix": state["prefix"], "report_status": "complete reconciled study" if complete else "PARTIAL exploratory checkpoint; incomplete evidence is not certified", "state_file_sha256_at_read": digest(state_bytes), "source_revision": state["source_revision"], "source_freeze": state["source_freeze"], "study_images": state.get("study_images"), "resources": state.get("resources"), "training_data_counts": preparation["counts"], "validation": {"sha256": VALIDATION_SHA, "rows": 968, "positive": 475, "negative": 493, "scope": "Reused exploratory selection evidence"}, "baselines": baselines, "attempt_summary": dict(Counter(item["status"] for item in attempts)), "attempts": attempts, "failure": state.get("failure"), "unknown_outcome": state.get("unknown_outcome"), "restoration_verified": state.get("restoration_verified", False), "limitations": ["Model quality means measured behavior, not profile names, tensor count or context size.", "Encoders originate in seeded repository-owned random initialization; original heads use authored bootstrap supervision.", "Public annotation negatives and authored contextual targets are provisional; no independent human contextual/action truth is established.", "Validation and development are reused exploratory samples. This report provides no final generalization, causal capacity, statistical superiority or deployment-safety claim.", "Annotation-presence truth cannot establish severity, visibility, complete span recovery or action correctness.", "Only the explicitly supplied study is consumed; failed v1 evidence is separate and is not pooled with v2.", "Final examples and labels are never opened or scored."]}
    if state.get("selection"):
        result["selection"] = read(state["selection"]["path"], state["selection"]["sha256"])
        if len(observed) != 54 or result["selection"].get("candidate_count") != 54 or result["selection"].get("development_access_for_selection") is not False:
            raise ValueError("Selection was not frozen over all 54 validation attempts.")
        eligible = [item for item in attempts if item.get("eligibility", {}).get("eligible")]
        def rank(item):
            counts = item["quality"]["validation"]["pipeline"]["metrics"]
            return (counts["tn"], counts["tp"], -1, -item["rate"], -item["seed"], -PROFILES.index(item["profile"]), -("heads", "last_block").index(item["strategy"]))
        expected = observed[max(eligible, key=rank)["index"]] if eligible else None
        if result["selection"]["winner"] != expected:
            raise ValueError("Frozen winner differs from deterministic predeclared validation ranking.")
    result["reporter"] = {"path": str(Path(__file__).resolve()), "sha256": digest(read_bytes(__file__))}
    result["computation_source_sha256"] = state["computation_source_sha256"]
    result["execution_revisions"] = state.get("execution_revisions")
    result["execution_amendments"] = state.get("execution_amendments", [])
    result["limitations"] += ["Confidence calibration and representative production latency have not been established.", "The grid uses seeds 42, 1337 and 2026 only; no broad seed-stability or capacity advantage is established."]
    result["contextual_retention"] = retention_summary(state, study, result.get("selection"))
    return result


def percent(value):
    return "—" if value is None else f"{100 * value:.2f}%"


def markdown(report):
    def cell(value):
        return str(value).replace("|", "\\|").replace("\n", " ").replace("\r", " ")
    lines = ["# Contextual fuzzer model quality", "", report["report_status"], "", f"Evidence: [{report['study_prefix']}](<{report['study']}>) · state SHA-256 `{report['state_file_sha256_at_read']}`.", "", "Quality is assessed from matched semantic and full-pipeline predictions. Capacity names do not establish accuracy. Validation contains 475 positive and 493 negative rows, reused for exploratory selection; final remains uninspected and unscored. A dash means an absent measurement or undefined rate, never zero.", "", "| Original profile | Layer | TP / TN / FP / FN | Recall | Specificity | Precision | F1 |", "| --- | --- | --- | ---: | ---: | ---: | ---: |"]
    measured = []
    for profile, baseline in report["baselines"].items():
        if "validation" not in baseline:
            lines.append(f"| {profile} | pending | — | — | — | — | — |")
            continue
        for layer, details in baseline["validation"].items():
            m = details["metrics"]
            lines.append(f"| {profile} | {layer} | {m['tp']} / {m['tn']} / {m['fp']} / {m['fn']} | {percent(m['recall'])} | {percent(m['specificity'])} | {percent(m['precision'])} | {percent(m['f1'])} |")
        measured.append((f"original {profile}", baseline))
    lines += ["", "| Attempt | Profile / strategy | Rate / seed | Status / reason | Semantic recall / specificity | Pipeline recall / specificity | Train / held-out sensitivity-positive rows |", "| ---: | --- | --- | --- | ---: | ---: | ---: |"]
    for item in report["attempts"]:
        m = item["quality"]["validation"]["pipeline"]["metrics"] if item.get("quality") else {}
        semantic = item["quality"]["validation"]["semantic"]["metrics"] if item.get("quality") else {}
        coverage = item.get("training", {}).get("sensitivity_label_coverage")
        coverage_text = f"{coverage['train']['sensitivity_positive_rows']}/256; {coverage['heldout']['sensitivity_positive_rows']}/16" if coverage else "—"
        reason = item.get("rejection_reason") or item.get("pending_reason")
        lines.append(f"| {item['index']} | {item['profile']} / {item['strategy']} | {item['rate']} / {item['seed']} | {cell(item['status'] + (': ' + cell(reason) if reason else ''))} | {percent(semantic.get('recall'))} / {percent(semantic.get('specificity'))} | {percent(m.get('recall'))} / {percent(m.get('specificity'))} | {coverage_text} |")
        if item.get("quality"):
            measured.append((f"attempt {item['index']}", item["quality"]))
    lines += ["", "Sampling coverage counts authored sensitivity labels S1/S2/S3. It does not supply external presence, severity or action truth. Full role counts and opaque whole-family IDs/labels are retained in JSON.", "", "| Accepted attempt | Layer | Positive / negative support | TP / TN / FP / FN | Recall | Specificity | Precision | F1 |", "| ---: | --- | ---: | --- | ---: | ---: | ---: | ---: |"]
    for item in report["attempts"]:
        if not item.get("quality"):
            continue
        for layer, evidence in item["quality"]["validation"].items():
            m = evidence["metrics"]
            lines.append(f"| {item['index']} | {layer} | {m['positive_support']} / {m['negative_support']} | {m['tp']} / {m['tn']} / {m['fp']} / {m['fn']} | {percent(m['recall'])} | {percent(m['specificity'])} | {percent(m['precision'])} | {percent(m['f1'])} |")
    lines += ["", "| Measured model | Layer | Balanced accuracy |", "| --- | --- | ---: |"]
    for label, evidence in measured:
        for layer, details in evidence["validation"].items():
            lines.append(f"| {label} | {layer} | {percent(details['metrics']['balanced_accuracy'])} |")
    lines += ["", "Balanced accuracy averages recall and specificity. It is undefined when either class is absent; these descriptive scores do not establish statistical superiority.", "", "| Measured model | Version | Parameters / trainable | Hidden / FF / layers / heads / context / vocabulary | Scope |", "| --- | --- | ---: | --- | --- |"]
    for label, evidence in measured:
        model = evidence["model"]
        c = model["config"]
        dimensions = " / ".join(str(c.get(key, "—")) for key in ("hidden_size", "intermediate_size", "num_layers", "num_attention_heads", "max_tokens", "vocab_size"))
        lines.append(f"| {label} | {model['model_version']} | {model['parameters']} / {model['trainable_parameters']} | {dimensions} | {model['training_scope']} |")
    lines += ["", "| Model | Semantic misses rescued by pipeline | Semantic detections lost | Clean pipeline-only flags | With regex / NER signal | Clean semantic flags removed |", "| --- | ---: | ---: | ---: | ---: | ---: |"]
    for label, evidence in measured:
        rescue = evidence["pipeline_rescue"]
        lines.append(f"| {label} | {rescue['positive_semantic_misses_detected_by_pipeline']} | {rescue['positive_semantic_detections_lost_in_pipeline']} | {rescue['clean_pipeline_only_flags']} | {rescue['clean_pipeline_only_with_returned_regex_signal']} / {rescue['clean_pipeline_only_with_returned_ner_signal']} | {rescue['clean_semantic_flags_removed_in_pipeline']} |")
    lines += ["", "Regex/NER signals may overlap. These matched output transitions describe co-occurrences, not causal attribution or contextual privacy correctness.", "", "| Model / source | Layer | Positive / negative support | TP / TN / FP / FN | Recall | Specificity | Precision | F1 |", "| --- | --- | ---: | --- | ---: | ---: | ---: | ---: |"]
    for label, evidence in measured:
        for layer, details in evidence["validation"].items():
            for source, m in details["source_strata"].items():
                lines.append(f"| {label} / {source} | {layer} | {m['positive_support']} / {m['negative_support']} | {m['tp']} / {m['tn']} / {m['fp']} / {m['fn']} | {percent(m['recall'])} | {percent(m['specificity'])} | {percent(m['precision'])} | {percent(m['f1'])} |")
    lines += ["", "| Accepted attempt | Layer | Δ TP / TN / FP / FN | New / corrected positive misses | New / corrected clean flags | Precision / F1 |", "| ---: | --- | --- | ---: | ---: | ---: |"]
    for item in report["attempts"]:
        if not item.get("quality"):
            continue
        for layer, change in item["paired_original_validation"].items():
            delta = change["count_difference_candidate_minus_baseline"]
            m = item["quality"]["validation"][layer]["metrics"]
            lines.append(f"| {item['index']} | {layer} | {' / '.join(f'{delta[k]:+d}' for k in ('tp','tn','fp','fn'))} | {change['new_positive_misses']} / {change['positive_misses_corrected']} | {change['new_clean_flags']} / {change['clean_flags_corrected']} | {percent(m['precision'])} / {percent(m['f1'])} |")
    lines += ["", "| Attempt | Row-based held-out exact before → after | Sensitive recall before → after | Clean specificity before → after | Severity/action regression | Diagnostic loss | Supervised objective |", "| ---: | ---: | ---: | ---: | ---: | ---: | ---: |"]
    for item in report["attempts"]:
        if not item.get("training"):
            continue
        values, guards = item["training"]["recorded_metrics"], item["training"]["heldout_checks"]
        pairs = [percent(guards[k]["before"]) + " → " + percent(guards[k]["after"]) for k in ("exact_match_rate", "sensitive_recall", "clean_specificity")]
        lines.append(f"| {item['index']} | {' | '.join(pairs)} | {percent(values.get('candidate_heldout_safety_regression_rate'))} | {values.get('average_loss', '—')} | {values.get('supervised_objective_loss', '—')} |")
    lines += ["", "Legacy average_loss is a weighted classification-distance diagnostic. The last-block supervised_objective_loss is weighted sensitivity CE + visibility CE + summed category BCE. Their scales and meanings differ. Held-out exact/recall/specificity and severity/action guards use row counts, not example weights. The existing severity/action floor is a publication guard, not independent privacy truth.", "", "| Model | Layer | First / median / p95 service ms |", "| --- | --- | ---: |"]
    for label, evidence in measured:
        for layer, details in evidence["validation"].items():
            times = details["latency"]
            lines.append(f"| {label} | {layer} | {times['first_ms']:.2f} / {times['median_ms']:.2f} / {times['p95_ms']:.2f} |")
    lines += ["", "Service elapsed_ms includes the first request and excludes browser/bridge overhead; these measurements do not establish representative production latency.", ""]
    retention = report.get("contextual_retention")
    if retention and retention.get("development_measured"):
        lines += ["| Frozen endpoint | Layer | TP / TN / FP / FN | Recall | Specificity | Precision | F1 |", "| --- | --- | --- | ---: | ---: | ---: | ---: |"]
        for label, evidence in (("live balanced", retention["live_balanced_development"]), ("frozen winner", retention["winner_development"])):
            for layer, details in evidence["development"].items():
                m = details["metrics"]
                lines.append(f"| {label} | {layer} | {m['tp']} / {m['tn']} / {m['fp']} / {m['fn']} | {percent(m['recall'])} | {percent(m['specificity'])} | {percent(m['precision'])} | {percent(m['f1'])} |")
        lines += ["", f"Development pipeline balanced accuracy: live balanced {percent(retention['live_balanced_development']['development']['pipeline']['metrics']['balanced_accuracy'])}; frozen winner {percent(retention['winner_development']['development']['pipeline']['metrics']['balanced_accuracy'])}.", "", "Development contains 264 positive and 238 negative rows, reused exploratory evidence assessed only after frozen selection.", "", "| Development model / source | Layer | Positive / negative support | Recall | Specificity | Precision | F1 |", "| --- | --- | ---: | ---: | ---: | ---: | ---: |"]
        for label, evidence in (("live balanced", retention["live_balanced_development"]), ("frozen winner", retention["winner_development"])):
            for layer, details in evidence["development"].items():
                for source, m in details["source_strata"].items():
                    lines.append(f"| {label} / {source} | {layer} | {m['positive_support']} / {m['negative_support']} | {percent(m['recall'])} | {percent(m['specificity'])} | {percent(m['precision'])} | {percent(m['f1'])} |")
        fixture = retention["fixture"]
        lines += ["", f"Retained research artifact: {retention['assessment']['retained']}. Contextual gate: {fixture['assessment']['contextual_gate']['passed']}; newly introduced private action failures: {fixture['new_private_action_losses']}; newly introduced clean interventions: {fixture['new_clean_interventions']}. The 41 quantitative cases carry provisional contextual labels; seven ambiguous cases are excluded from the gate. Per-case comparisons remain in JSON.", ""]
        failures = fixture["existing_and_remaining_private_failures"]
        controls = [case for case in fixture["per_case_actions"] if case["quantitative_eligible"] and case["required_sensitive"] is False]
        allowed = {label: sum(case[label + "_action"] == "ALLOW" for case in controls) for label in ("live", "winner")}
        lines += [f"Private disclosures meeting the minimum action: live {17 - len(failures['live'])}/17; winner {17 - len(failures['winner'])}/17. Clean controls receiving ALLOW: live {allowed['live']}/24; winner {allowed['winner']}/24. Existing failures remain quality limitations even when no new failure is introduced.", "", fixture["identity_scope"], ""]
    elif retention:
        lines += [f"Frozen endpoint: {cell(retention['assessment'])}. No development or contextual fixture score is claimed.", ""]
    lines += ["Model identities and immutable file commitments:", ""]
    for label, evidence in measured:
        model = evidence["model"]
        lines.append(f"- {label}: `{model['model_id']}`, `{model['model_version']}`; internal checksum `{model['artifact_checksum']}`; inference fingerprint `{model['parameter_fingerprint']}`; [{Path(model['artifact_path']).name}](<{model['artifact_path']}>) file SHA-256 `{model['artifact_file_sha256']}`.")
    lines += ["", f"Reporter SHA-256: `{report['reporter']['sha256']}`. The complete JSON retains report/source commitments, config fields, exact trainable/frozen tensor names, paired development/source-stratum rates, actual sampling inventories, publication metadata and provisional contextual per-case actions.", "", *[f"- {limitation}" for limitation in report["limitations"]]]
    return "\n".join(lines) + "\n"


def self_test():
    """Synthetic in-memory checks; no filesystem, research data or services."""
    absent = metrics({"tp": 0, "tn": 2, "fp": 1, "fn": 0})
    assert absent["recall"] is None and absent["specificity"] == 2 / 3
    assert metrics(dict.fromkeys(("tp", "tn", "fp", "fn"), 0))["precision"] is None
    def row(identifier, truth, detected):
        return {"example_id": identifier, "group_id": "source:" + identifier, "expected_has_pii": truth, "detected_sensitive": detected, "layers": []}
    assert source_strata([row("positive-only", True, True)])["source"]["specificity"] is None
    before = {"p": row("p", True, False), "n": row("n", False, False)}
    after = {"p": row("p", True, True), "n": row("n", False, True)}
    rescued = pipeline_rescue(before, after)
    assert rescued["positive_semantic_misses_detected_by_pipeline"] == 1 and rescued["clean_pipeline_only_flags"] == 1
    paired = paired_quality(before, after)
    assert paired["positive_misses_corrected"] == 1 and paired["new_clean_flags"] == 1 and paired["count_difference_candidate_minus_baseline"] == {"tp": 1, "tn": -1, "fp": 1, "fn": -1}
    try:
        paired_quality(before, {"other": row("other", True, True)})
    except ValueError:
        pass
    else:
        raise AssertionError("Unmatched pairs accepted.")
    diagnostic = training_quality({"metadata": {"average_loss": "0.2", "heldout_exact_match_rate": "0.5", "candidate_heldout_exact_match_rate": "0.4"}})
    assert diagnostic["heldout_checks"]["exact_match_rate"]["nonregressing"] is False and "supervised_objective_loss" in diagnostic["metric_absence"]
    with patch.dict(globals(), {"read": lambda path, commitment: raw}):
        path = Path("synthetic-report.json")
        identity = {"model_id": "synthetic", "model_version": "test", "artifact_checksum": "a", "parameter_fingerprint": "b"}
        raw_rows = [row("p", True, True), row("n", False, False)]
        for item in raw_rows:
            item.update(status="ok", elapsed_ms=1.0, layers=[{"layer": "DETECTION_LAYER_SEMANTIC", "status": "ok", "results": [{"metadata": identity}]}])
        counts = {"tp": 1, "tn": 1, "fp": 0, "fn": 0}
        raw = {"errors": [], "metadata": {"predictions": raw_rows}, "metrics": {"evaluated_samples": 2, "runtime_errors": 0, "true_positives": 1, "true_negatives": 1, "false_positives": 0, "false_negatives": 0}}
        reference = {r["example_id"]: (r["expected_has_pii"], r["group_id"]) for r in raw_rows}
        def score():
            return verify_report({"path": str(path), "sha256": "mock-bound-input"}, reference, identity, counts)
        assert score()[0]["metrics"]["f1"] == 1
        def must_reject():
            try:
                score()
            except ValueError:
                return
            raise AssertionError("Corrupted count/truth/model evidence accepted.")
        raw["metrics"]["true_positives"] = 0
        must_reject()
        raw["metrics"]["true_positives"] = 1
        raw_rows[0]["expected_has_pii"] = False
        must_reject()
        raw_rows[0]["expected_has_pii"] = True
        raw_rows[0]["layers"][0]["results"][0]["metadata"] = {**identity, "parameter_fingerprint": "wrong"}
        must_reject()
        raw_rows[0]["layers"][0]["results"][0]["metadata"] = identity
        raw_rows[0]["layers"].append({"layer": "DETECTION_LAYER_NER", "status": "skipped", "error": "Skipped after regex returned BLOCK."})
        assert score()[0]["metrics"]["rows"] == 2
        raw_rows[0]["layers"][-1]["status"] = "error"
        must_reject()
        try:
            read_bytes(Path("final.jsonl"))
        except ValueError:
            pass
        else:
            raise AssertionError("Protected final path accepted.")
    print("Quality reporter checks passed: null supports, paired rescue/transitions, loss/guard scope, count/truth/fingerprint rejection, skipped explanation versus runtime failure, final-path refusal.", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--study", type=Path)
    parser.add_argument("--partial", action="store_true")
    parser.add_argument("--format", choices=("json", "markdown"), default="json")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return
    if args.study is None:
        parser.error("--study is required unless --self-test is specified.")
    report = quality_report(args.study, partial=args.partial)
    print(markdown(report) if args.format == "markdown" else json.dumps(report, indent=2, allow_nan=False), end="" if args.format == "markdown" else "\n")


if __name__ == "__main__":
    main()
