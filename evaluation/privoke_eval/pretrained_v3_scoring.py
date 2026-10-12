"""Host-only semantic endpoint scoring with immutable requested-case records."""
from __future__ import annotations

import json
from pathlib import Path

from .pretrained_v3_study import (ROOT, assert_semantic, canonical, channel, digest,
                                  exclusive, runtime_pb2, runtime_pb2_grpc)
from privoke_contracts.classification import Classification

ENDPOINTS = {
    "context320": {"path": "evaluation/results/accelerated_all_surfaces_20261010/input-preparation/assessment-renditions/context-integrated-1.jsonl", "sha256": "47abc757af20bde769aff04405c8706ee054b999a4339c0c1fec0199bd82e629", "rows": 320, "role": "primary_reused_development"},
    "context64": {"path": "evaluation/results/iterative_fuzzer_20261011/block01/validation.jsonl", "sha256": "67e7dfddc3a136b5c9178a22198937758564473da9d46ef0b666e6ea70d5069c", "rows": 64, "role": "primary_reused_development"},
    "binary502": {"path": "evaluation/results/locked-public/development.jsonl", "sha256": "65bf02af1f9f7167a5aa5eaaa8aeac54111c90d009585ed36570d3ce0a635095", "rows": 502, "role": "secondary_binary_development"},
    "hazard48": {"path": "evaluation/results/contextual_fixtures_20261004_v1/support/fixture.jsonl", "sha256": "d6c7d5d87235cd6b0f9d24eac43b30c3ace9f0bf4f421ef5d5d812de79827a17", "rows": 48, "role": "secondary_hazard"},
}
ENDPOINTS["context320"].update(eligible=320, sensitive=160, clean=160)
ENDPOINTS["context64"].update(eligible=64, sensitive=32, clean=32)
ENDPOINTS["binary502"].update(eligible=502, sensitive=264, clean=238)
ENDPOINTS["hazard48"].update(eligible=41, excluded_ambiguous=7,
                             eligible_action_sets={"ALLOW": 24, "BLOCK|WARN": 15, "BLOCK": 2})


def endpoint_rows(kind, item):
    """Only the four predeclared reused DEVELOPMENT/support inputs are readable."""
    if kind not in ENDPOINTS or item != ENDPOINTS[kind]:
        raise ValueError("Endpoint is not in the fixed v3 DEVELOPMENT input map.")
    path = ROOT / item["path"]
    payload = path.read_bytes()
    if digest(payload) != item["sha256"]:
        raise ValueError("Frozen endpoint byte identity differs: " + kind)
    rows = [json.loads(line) for line in payload.decode().splitlines() if line.strip()]
    if len(rows) != item["rows"]:
        raise ValueError("Endpoint requested denominator differs: " + kind)
    eligible = [truth_record(row, kind) for row in rows if truth_record(row, kind)["eligible"]]
    if len(eligible) != item["eligible"]:
        raise ValueError("Endpoint eligible denominator differs: " + kind)
    if kind == "hazard48":
        from collections import Counter
        counts = dict(Counter("|".join(row["allowed_actions"]) for row in eligible))
        if counts != item["eligible_action_sets"] or sum(bool(row["ambiguous"]) for row in rows) != item["excluded_ambiguous"]:
            raise ValueError("Hazard ambiguity/action-set denominator differs.")
    elif sum(row["expected_sensitive"] if kind == "binary502" else sensitive(row["target"]) for row in eligible) != item["sensitive"]:
        raise ValueError("Endpoint sensitive/clean denominator differs: " + kind)
    return rows


def truth_record(row, kind):
    if kind == "binary502":
        return {"id": row["id"], "group_id": row["group_id"], "eligible": True,
                "expected_sensitive": row["expected_has_pii"]}
    if kind == "hazard48":
        eligible = not row["ambiguous"] and row.get("action_accuracy_eligible", True) and row.get("context_truth_eligible", True)
        allowed = row.get("allowed_actions")
        action = row.get("minimum_action") or row.get("expected_action")
        if not allowed:
            allowed = [a for a in ("ALLOW", "WARN", "BLOCK") if not row.get("minimum_action")
                       or ("ALLOW", "WARN", "BLOCK").index(a) >= ("ALLOW", "WARN", "BLOCK").index(action)] if row.get("minimum_action") else [action] if action else ["ALLOW", "WARN", "BLOCK"]
        return {"id": row["case_id"], "group_id": row["family_id"], "eligible": eligible,
                "target": {"sensitivity": row.get("expected_sensitivity")}, "allowed_actions": sorted(set(allowed))}
    return {"id": row["id"], "group_id": row["group_id"], "eligible": True,
            "target": row["classification"], "allowed_actions": sorted(set(row["allowed_actions"]))}


def sensitive(value):
    return value["sensitivity"] != "S0" or bool(value.get("categories"))


def case_metrics(record, kind):
    """Errors, including conservative BLOCK errors, are incorrect in every metric."""
    names = ("binary",) if kind == "binary502" else ("severity", "action") if kind == "hazard48" else ("severity", "category", "visibility", "action", "packed_exact", "joint", "binary")
    result = {key: False for key in names}
    if record["status"] != "ok":
        return result
    prediction = record["classification"]
    if kind == "binary502":
        return {"binary": sensitive(prediction) == record["expected_sensitive"]}
    target = record["target"]
    result.update(severity=prediction["sensitivity"] == target["sensitivity"], action=record["action"] in set(record["allowed_actions"]))
    if kind != "hazard48":
        result.update(category=set(prediction["categories"]) == set(target["categories"]),
                      visibility=prediction["visibility"] == target["visibility"], binary=sensitive(prediction) == sensitive(target))
        result["packed_exact"] = all(result[key] for key in ("severity", "category", "visibility"))
        result["joint"] = result["packed_exact"] and result["action"]
    return result


def summarize_records(records, kind):
    eligible = [r for r in records if r["eligible"]]
    metric_names = case_metrics({"status": "error"}, kind)
    metrics = {key: {"correct": sum(case_metrics(r, kind)[key] for r in eligible), "denominator": len(eligible)} for key in metric_names}
    metrics.update(requested=len(records), eligible=len(eligible), successful=sum(r["status"] == "ok" for r in eligible),
                   errors=sum(r["status"] != "ok" for r in eligible))
    if kind != "hazard48":
        for label, wanted in (("sensitive_recall", True), ("clean_specificity", False)):
            selected = [r for r in eligible if (r["expected_sensitive"] if kind == "binary502" else sensitive(r["target"])) == wanted]
            metrics[label] = {"correct": sum(r["status"] == "ok" and sensitive(r["classification"]) == wanted for r in selected), "denominator": len(selected)}
    return metrics


def score_endpoint(stub, manifest, snapshot, kind, item, output):
    """Reserve each request before RPC; incomplete rows require reconciliation."""
    output = Path(output)
    records = []
    for index, row in enumerate(endpoint_rows(kind, item)):
        record = truth_record(row, kind)
        directory = output / "rows" / f"{index:04d}"
        request = runtime_pb2.AnalyzePromptRequest(request_id="v3-score-" + digest(canonical([snapshot, kind, index]))[:40],
            text=row["text"], semantic_model_id=manifest["model_id"], layers=[4],
            visibility_hint=row.get("visibility_hint", "") if kind == "hazard48" else "", metadata={"v3_checkpoint": snapshot})
        request_bytes = request.SerializeToString(deterministic=True)
        if (directory / "record.json").exists():
            if (directory / "request.pb").read_bytes() != request_bytes:
                raise ValueError("Retained scoring request differs.")
            records.append(json.loads((directory / "record.json").read_bytes()))
            continue
        if (directory / "request.pb").exists():
            raise ValueError("Incomplete scoring row retained; reconcile its response before resuming: " + str(directory))
        exclusive(directory / "request.pb", request_bytes)
        try:
            response = stub.AnalyzePrompt(request, timeout=120)
        except Exception as error:
            exclusive(directory / "transport-error.json", canonical({"error": type(error).__name__ + ": " + str(error)}))
            record.update(status="transport_error", error=str(error), classification=None, action=None)
        else:
            exclusive(directory / "response.pb", response.SerializeToString(deterministic=True))
            if response.request_id != request.request_id:
                raise ValueError("Scored response belongs to another request.")
            # Layer or identity violations invalidate the study. Runtime errors retain
            # their requested denominators but can never earn BLOCK correctness.
            assert_semantic(response, manifest["model_id"], snapshot, manifest, allow_error=True)
            if response.error or response.layers[0].status != "ok":
                record.update(status="error", error=response.error or response.layers[0].error, classification=None, action=None)
            else:
                prediction = Classification(response.classification.packed).to_dict()
                named = {"sensitivity": response.classification.sensitivity, "visibility": response.classification.visibility,
                         "categories": list(response.classification.categories)}
                if named != prediction:
                    raise ValueError("Scored named and packed classification differ.")
                record.update(status="ok", classification=prediction, action=response.action, elapsed_ms=response.elapsed_ms)
            record.update(actual_layer=response.layers[0].layer, actual_status=response.layers[0].status,
                          metadata=dict(response.metadata))
        record.update(snapshot=snapshot, model_id=manifest["model_id"], request_sha256=digest(request_bytes))
        exclusive(directory / "record.json", canonical(record))
        records.append(record)
    summary = summarize_records(records, kind)
    from .pretrained_v3_study import retain
    retain(output / "summary.json", canonical(summary))
    return summary


def audit_endpoint_records(manifest, snapshot, kind, item, output):
    """Rebuild truth and predictions from immutable fixture/request/response bytes."""
    output = Path(output)
    records = []
    for index, row in enumerate(endpoint_rows(kind, item)):
        directory = output / "rows" / f"{index:04d}"
        record = json.loads((directory / "record.json").read_bytes())
        truth = truth_record(row, kind)
        if any(record.get(key) != value for key, value in truth.items()):
            raise ValueError("Retained endpoint truth differs from frozen fixture.")
        request_bytes = (directory / "request.pb").read_bytes()
        request = runtime_pb2.AnalyzePromptRequest.FromString(request_bytes)
        if (request.text != row["text"] or list(request.layers) != [4] or request.semantic_model_id != manifest["model_id"]
                or request.metadata.get("v3_checkpoint") != snapshot or record["request_sha256"] != digest(request_bytes)
                or request.visibility_hint != (row.get("visibility_hint", "") if kind == "hazard48" else "")):
            raise ValueError("Retained endpoint stimulus/identity differs.")
        if record["status"] == "transport_error":
            if not (directory / "transport-error.json").exists() or (directory / "response.pb").exists():
                raise ValueError("Transport error evidence differs.")
        else:
            response = runtime_pb2.AnalyzePromptResponse.FromString((directory / "response.pb").read_bytes())
            if response.request_id != request.request_id:
                raise ValueError("Retained response belongs to another request.")
            assert_semantic(response, manifest["model_id"], snapshot, manifest, allow_error=True)
            if record["metadata"] != dict(response.metadata) or record["actual_status"] != response.layers[0].status:
                raise ValueError("Retained actual execution differs from response bytes.")
            failed = bool(response.error or response.layers[0].error or response.layers[0].status != "ok")
            if record["status"] != ("error" if failed else "ok"):
                raise ValueError("Retained endpoint outcome differs from actual execution.")
            if not failed and (record["classification"] != Classification(response.classification.packed).to_dict() or record["action"] != response.action):
                raise ValueError("Retained endpoint prediction differs from actual response.")
        records.append(record)
    return records


def paired_difference(before, after, kind):
    if [(r["id"], r["group_id"], r["eligible"]) for r in before] != [(r["id"], r["group_id"], r["eligible"]) for r in after]:
        raise ValueError("Paired endpoint rows differ.")
    for a, b in zip(before, after):
        if {k: a.get(k) for k in ("target", "allowed_actions", "expected_sensitive")} != {k: b.get(k) for k in ("target", "allowed_actions", "expected_sensitive")}:
            raise ValueError("Paired endpoint targets differ.")
    eligible = [(a, b) for a, b in zip(before, after) if a["eligible"]]
    result = {}
    for metric in case_metrics({"status": "error"}, kind):
        values = [(case_metrics(a, kind)[metric], case_metrics(b, kind)[metric]) for a, b in eligible]
        net = sum(int(b) - int(a) for a, b in values)
        result[metric] = {"net_correct": net, "denominator": len(values), "rate_difference": net / len(values) if values else None,
                          "improved": sum(b and not a for a, b in values), "regressed": sum(a and not b for a, b in values)}
    if kind != "binary502":
        rank = {"ALLOW": 0, "WARN": 1, "BLOCK": 2}
        comparable = [(a, b) for a, b in eligible if a["status"] == b["status"] == "ok"]
        def distance(row, direction):
            allowed = [rank[v] for v in row["allowed_actions"]]
            actual = rank[row["action"]]
            return max(0, min(allowed) - actual) if direction == "under" else max(0, actual - max(allowed))
        result["action_harms"] = {direction: sum(distance(b, direction) > distance(a, direction) for a, b in comparable)
                                  for direction in ("under", "over")}
        result["action_harms"].update(comparable=len(comparable), requested_eligible=len(eligible),
                                     error_pairs=len(eligible) - len(comparable))
    return result
