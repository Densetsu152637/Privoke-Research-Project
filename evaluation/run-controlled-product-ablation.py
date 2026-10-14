"""AB14: prospective host product-detector counterfactuals; no fitting/final access."""
from __future__ import annotations
import argparse
import base64
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import sys
import time
from types import MethodType

STUDY = "controlled_studies_20261014"
CONFIGS = {"regex": [2], "ner": [3], "semantic": [4], "nonsemantic": [2, 3], "no_regex": [3, 4], "no_ner": [2, 4], "product": [2, 3, 4]}
CORE = None


def initialize(repository):
    global CORE
    sys.path.insert(0, str(repository / "evaluation"))
    from privoke_eval import pipeline_v1_v3 as core
    CORE = core
    for key, value in core.PRODUCT_ENV.items():
        os.environ[key] = value
    core.configure(repository)
    core.configure_numeric()
    return core


def prepare(repository, output):
    c = CORE
    previous = repository / "evaluation/results/pipeline_v1_v3_20261014/runs/cpu-01/protocol.json"
    source = c.read(previous)
    c.require(c.file_hash(previous) == "938f626bec9b5810a34e6e9f33d1d28f0070fbc10ac6a570e568b41c39346ed7", "Historical protocol drift")
    entry = next(e for e in source["entries"] if e["name"] == "v3-balanced")
    c.validate_assets(entry)
    c.require(entry["identity"]["artifact_checksum"] == c.V3_PINS["balanced"], "Package differs")
    c.require(c.file_hash(source["data_manifest"]) == c.DATA_SHA, "AU3 manifest differs")
    rows = c.rows_for(source)
    c.require(len(rows) == 1560 and len({r["id"] for r in rows}) == 1560, "Case cardinality differs")
    from src.regex.rule_detector import RuleDetector
    effective = c.rules_inventory(RuleDetector())
    files = c.source_files(repository)
    own = c.file_hash(Path(__file__))
    protocol = {"study_id": STUDY, "scope": "separately authorized product detector ablation", "repository": str(repository),
        "created_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "script_sha256": own,
        "parent_protocol": str(previous), "parent_protocol_sha256": c.file_hash(previous), "data_manifest": source["data_manifest"],
        "data_manifest_sha256": c.DATA_SHA, "fresh_sha256": c.FRESH_SHA, "rows": 1560,
        "ordered_rows_sha256": c.digest(c.canonical(rows)), "entry": entry, "configs": CONFIGS,
        "source_files": files, "source_closure": c.digest(c.canonical(files)), "environment": c.environment(),
        "effective_regex_rules": effective, "effective_regex_rules_sha256": c.digest(c.canonical(effective)),
        "analysis": {"reference": "product", "metrics": ["binary", "action", "joint", "under_enforcement_distance", "over_enforcement_distance"],
            "paired_bootstrap": {"draws": 2000, "seed": 42, "groups_separately": ["family_id", "group_id"], "interval": "linear percentile 95%"},
            "cohort": "all product over-enforced cases; historical shared139 membership compared descriptively", "no_error_exclusions": True},
        "prohibited": ["protected final access", "training", "model promotion", "tuning", "favorable-result retries"]}
    c.retain(output / "protocol.json", protocol)
    # Retain the actual dirty execution sources, not just a clean commit identifier.
    for name in files:
        c.retain(output / "source-capture" / name, (repository / name).read_bytes())
    c.retain(output / "source-capture/ablation-script.py", Path(__file__).read_bytes())
    return {"protocol_sha256": c.file_hash(output / "protocol.json"), "source_closure": protocol["source_closure"], "requests": 10920}


def validate(output):
    c = CORE
    p = c.read(output / "protocol.json")
    c.require(p["configs"] == CONFIGS and p["rows"] == 1560 and p["study_id"] == STUDY, "Protocol shape drift")
    c.require(c.file_hash(Path(__file__)) == p["script_sha256"], "Harness changed after freeze")
    c.require(c.source_files(p["repository"]) == p["source_files"], "Runtime source drift")
    c.require(c.environment() == p["environment"], "Dependency environment drift")
    c.require(c.file_hash(p["data_manifest"]) == p["data_manifest_sha256"], "Data manifest drift")
    c.validate_assets(p["entry"])
    c.require(c.digest(c.canonical(c.rows_for(p))) == p["ordered_rows_sha256"], "Ordered case/truth drift")
    return p


def outcome(payload, entry, request):
    c = CORE
    from privoke.v1 import runtime_pb2
    actual, traces, metadata = [], [], {}
    try:
        response = runtime_pb2.AnalyzePromptResponse.FromString(payload)
        actual = [t.layer for t in response.layers]
        metadata = dict(response.metadata)
        c.require(response.request_id == request.request_id and actual == list(request.layers), "Returned layer order/identity differs")
        traces = [{"layer": t.layer, "status": t.status, "error": t.error,
                   "findings": [c.detection(r, request.text) for r in t.results]} for t in response.layers]
        c.require(not response.error and all(t["status"] in ("ok", "skipped") for t in traces), "Runtime/layer error")
        skipped = [t for t in traces if t["status"] == "skipped"]
        if skipped:
            c.require(traces[0]["layer"] == 2 and traces[0]["status"] == "ok"
                      and any(f["action"] == "BLOCK" for f in traces[0]["findings"])
                      and all(t["layer"] in (3, 4) and t["error"] == "Skipped after regex returned BLOCK." and not t["findings"] for t in skipped)
                      and len(skipped) == len(traces) - 1, "Invalid regex skip provenance")
        for t in traces:
            c.require(t["status"] != "ok" or not t["error"], "Successful layer has error")
        semantic = next((t for t in traces if t["layer"] == 4), None)
        if semantic and semantic["status"] == "ok":
            c.require(all(metadata.get("privoke.semantic." + k) == entry["identity"][k]
                          for k in ("model_id", "model_version", "artifact_checksum", "parameter_fingerprint")), "Semantic package identity differs")
        else:
            c.require(not any(k.startswith("privoke.semantic.") for k in metadata), "Unexecuted semantic impersonation")
        c.require(list(request.layers) != [4] or semantic["status"] == "ok", "Semantic-only request skipped")
        c.require(response.action in ("ALLOW", "WARN", "BLOCK") and response.allowed == (response.action != "BLOCK"), "Invalid policy action")
        return {"status": "ok", "classification": c.classification(response.classification), "action": response.action,
                "actual_layers": actual, "traces": traces, "metadata": metadata, "server_elapsed_ms": response.elapsed_ms}
    except Exception as error:
        return {"status": "invalid_response", "error": type(error).__name__ + ": " + str(error), "classification": None,
                "action": None, "actual_layers": actual, "traces": traces, "metadata": metadata}


def serve(output, port):
    c = CORE
    p = validate(output)
    from privoke_eval import pipeline_v1_v3_serving as serving
    from privoke.v1 import runtime_pb2_grpc
    from src.hosting.grpc_server import PrivokeRuntimeService
    import grpc
    from src.NER.ner_detector import EntityNERDetector
    from src.regex.rule_detector import RuleDetector
    ner = EntityNERDetector()
    c.require(ner.backend_name == "spacy" and ner.model_name == "en_core_web_sm", "NER readiness differs")
    c.require(c.rules_inventory(RuleDetector()) == p["effective_regex_rules"], "Effective rules drift")
    semantic = serving.load_semantic(p["entry"])
    parity = serving.adapter_parity(p, p["entry"], semantic)
    native = serving.service(p["entry"], semantic)
    def analyze(self, request, context):
        if (list(request.layers) not in CONFIGS.values() or request.regex_execution_order != 1 or request.visibility_hint
                or request.HasField("semantic_presence_gate") or request.semantic_model_id != p["entry"]["identity"]["model_id"]):
            context.abort(grpc.StatusCode.INVALID_ARGUMENT, "Frozen explicit detector ablation request required")
        return PrivokeRuntimeService.AnalyzePrompt(self, request, context)
    native.AnalyzePrompt = MethodType(analyze, native)
    server = grpc.server(ThreadPoolExecutor(max_workers=1))
    runtime_pb2_grpc.add_PrivokeRuntimeServiceServicer_to_server(native, server)
    c.require(server.add_insecure_port("127.0.0.1:" + str(port)), "Private port unavailable")
    server.start()
    ready = {"pid": os.getpid(), "port": port, "protocol_sha256": c.file_hash(output / "protocol.json"),
             "identity": p["entry"]["identity"], "parity": parity, "training_disabled": True, "resources": c.resource_snapshot()}
    c.retain(output / "ready.json", ready)
    print("AB14 ready", flush=True)
    try:
        server.wait_for_termination()
    finally:
        server.stop(2).wait()


def request(p, row, config):
    from privoke.v1 import runtime_pb2
    key = "ab14-" + CORE.digest(CORE.canonical([CORE.file_hash(OUTPUT / "protocol.json"), config, row["id"]]))[:40]
    return runtime_pb2.AnalyzePromptRequest(request_id=key, text=row["text"], source=row.get("source") or "",
        target_app=row.get("target_app") or "", layers=CONFIGS[config], regex_execution_order=1,
        semantic_model_id=p["entry"]["identity"]["model_id"], metadata={"study": STUDY, "configuration": config})


def records(p, config, journal):
    result = []
    for row in CORE.rows_for(p):
        req = request(p, row, config)
        call = journal.calls[req.request_id]
        CORE.require(base64.b64decode(call["reserve"]["request_pb"]) == req.SerializeToString(deterministic=True), "Request drift")
        terminal = call["terminal"]
        value = outcome(base64.b64decode(terminal["response_pb"]), p["entry"], req) if "response_pb" in terminal else {
            "status": "transport_error", "classification": None, "action": None, "traces": [], "error": terminal["transport_error"]}
        result.append(dict(value, id=row["id"], family_id=row["family_id"], group_id=row["group_id"],
                           target=row["classification"], allowed_actions=row["allowed_actions"]))
    return result


def run(output, port):
    import grpc
    from privoke.v1 import runtime_pb2_grpc
    c = CORE
    p = validate(output)
    ready = c.read(output / "ready.json")
    c.require(ready["protocol_sha256"] == c.file_hash(output / "protocol.json") and ready["port"] == port, "Server readiness differs")
    with grpc.insecure_channel("127.0.0.1:" + str(port)) as channel:
        grpc.channel_ready_future(channel).result(timeout=15)
        stub = runtime_pb2_grpc.PrivokeRuntimeServiceStub(channel)
        for config in CONFIGS:
            journal = c.Journal(output / config / "journal.jsonl")
            for index, row in enumerate(c.rows_for(p)):
                req = request(p, row, config)
                if req.request_id in journal.calls:
                    continue
                wire = req.SerializeToString(deterministic=True)
                journal.append("reserve", req.request_id, request_pb=base64.b64encode(wire).decode(), request_sha256=c.digest(wire), configuration=config, case_id=row["id"], index=index)
                started = time.perf_counter_ns()
                try:
                    response = stub.AnalyzePrompt(req, timeout=120)
                    payload = response.SerializeToString(deterministic=True)
                    journal.append("terminal", req.request_id, started_ns=started, ended_ns=time.perf_counter_ns(), response_pb=base64.b64encode(payload).decode(), response_sha256=c.digest(payload))
                except Exception as error:
                    journal.append("terminal", req.request_id, started_ns=started, ended_ns=time.perf_counter_ns(), transport_error=type(error).__name__ + ": " + str(error))
                if index % 100 == 0:
                    print(config, index + 1, flush=True)
            values = records(p, config, journal)
            c.retain(output / config / "records.json", values)
            print(config, dict(Counter(r["status"] for r in values)), flush=True)
    return audit(output)


def metric(record, name):
    if record["status"] != "ok":
        return 0
    target, predicted = record["target"], record["classification"]
    if name == "binary":
        return int((predicted["sensitivity"] != "S0" or bool(predicted["categories"])) == (target["sensitivity"] != "S0" or bool(target["categories"])))
    action = record["action"] in record["allowed_actions"]
    if name == "action":
        return int(action)
    return int(action and all(set(predicted[k]) == set(target[k]) if k == "categories" else predicted[k] == target[k] for k in ("sensitivity", "visibility", "categories")))


def distance(record):
    if record["status"] != "ok":
        return None
    rank = {"ALLOW": 0, "WARN": 1, "BLOCK": 2}
    action = rank[record["action"]]
    allowed = [rank[a] for a in record["allowed_actions"]]
    return max(0, min(allowed) - action), max(0, action - max(allowed))


def contrast(reference, candidate):
    import numpy as np
    c = CORE
    c.require([r["id"] for r in reference] == [r["id"] for r in candidate], "Case pairing differs")
    result = {"n": len(reference), "metrics": {}}
    for name in ("binary", "action", "joint"):
        delta = np.array([metric(b, name) - metric(a, name) for a, b in zip(reference, candidate)])
        estimates = {}
        for key in ("family_id", "group_id"):
            groups = sorted({r[key] for r in reference})
            sums = np.array([sum(int(delta[i]) for i, r in enumerate(reference) if r[key] == g) for g in groups])
            sizes = np.array([sum(r[key] == g for r in reference) for g in groups])
            draws = np.random.default_rng(42).integers(0, len(groups), size=(2000, len(groups)))
            values = sums[draws].sum(1) / sizes[draws].sum(1)
            estimates[key] = {"groups": len(groups), "low": float(np.quantile(values, .025)), "high": float(np.quantile(values, .975))}
        result["metrics"][name] = {"reference_correct": sum(metric(r, name) for r in reference), "candidate_correct": sum(metric(r, name) for r in candidate),
            "improved": int((delta == 1).sum()), "regressed": int((delta == -1).sum()), "net": int(delta.sum()), "paired_rate_intervals": estimates}
    paired = [(distance(a), distance(b), a["id"]) for a, b in zip(reference, candidate)]
    result["action_distance"] = {"paired_success": sum(a is not None and b is not None for a, b, _ in paired), "under_increased": sum(b[0] > a[0] for a, b, _ in paired if a is not None and b is not None),
        "over_increased": sum(b[1] > a[1] for a, b, _ in paired if a is not None and b is not None),
        "over_reduced": sum(b[1] < a[1] for a, b, _ in paired if a is not None and b is not None),
        "product_over_enforced": sum(a[1] > 0 for a, b, _ in paired if a is not None),
        "product_over_enforced_resolved": sum(a[1] > 0 and b == (0, 0) for a, b, _ in paired if a is not None and b is not None),
        "lost_correct_actions": [a["id"] for a, b in zip(reference, candidate) if metric(a, "action") and not metric(b, "action")],
        "gained_correct_actions": [a["id"] for a, b in zip(reference, candidate) if not metric(a, "action") and metric(b, "action")]}
    return result


def audit(output):
    c = CORE
    p = validate(output)
    values = {}
    for config in CONFIGS:
        journal = c.Journal(output / config / "journal.jsonl")
        c.require(len(journal.calls) == 1560, "Incomplete configuration")
        values[config] = records(p, config, journal)
        c.retain(output / config / "records.json", values[config])
    summary = {"study_id": STUDY, "protocol_sha256": c.file_hash(output / "protocol.json"), "requests": 10920, "rows": 1560,
        "configurations": {name: {"statuses": dict(Counter(r["status"] for r in rows)),
            "layer_statuses": dict(Counter(str(t["layer"]) + ":" + t["status"] for r in rows for t in r["traces"])),
            "correct": {m: sum(metric(r, m) for r in rows) for m in ("binary", "action", "joint")},
            "under_over": {"under": sum(distance(r)[0] > 0 for r in rows if distance(r) is not None), "over": sum(distance(r)[1] > 0 for r in rows if distance(r) is not None)}} for name, rows in values.items()},
        "contrasts_to_product": {name: contrast(values["product"], rows) for name, rows in values.items() if name != "product"},
        "journal_hashes": {name: c.file_hash(output / name / "journal.jsonl") for name in CONFIGS},
        "interpretation": "Single fixed AU3 package, reused assistant-provisional synthetic cases; product ablation, not semantic-only study or population causal estimate"}
    c.retain(output / "analysis.json", summary)
    return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare", "serve", "run", "audit"))
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--port", type=int, default=50191)
    parser.add_argument("--allow-product-pipeline", action="store_true", required=True)
    args = parser.parse_args()
    OUTPUT = args.output.resolve()
    initialize(args.repository.resolve())
    value = prepare(args.repository.resolve(), OUTPUT) if args.action == "prepare" else serve(OUTPUT, args.port) if args.action == "serve" else run(OUTPUT, args.port) if args.action == "run" else audit(OUTPUT)
    if value is not None:
        print(CORE.canonical(value).decode(), end="")
