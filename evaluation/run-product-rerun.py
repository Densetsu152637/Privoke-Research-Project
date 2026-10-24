"""PR24: full-product rerun of PIPE3 (package comparison) and AB14 (balanced detector ablation).

SCOPE: separately authorized whole-product / detector analysis (full-product evidence, never
semantic-only or LLM-only). Host-only: a loopback native gRPC runtime in this process, requests
from this process; no Docker, no training, no downloads. The harness (this file and
``privoke_eval``) is identical for both arms; ``--runtime-root`` selects the detector/runtime
source tree (old = clean export of e6c177ff, new = this branch), so detector code/config is the
only difference. Packages, inputs and policy come from the frozen historical PIPE3 protocol.

Actions: ``run`` (one arm), ``analyze`` (old/new/historical comparison, aggregates only).
"""
from __future__ import annotations
import argparse
import base64
import json
import math
import os
import sys
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import MethodType

HARNESS = Path(__file__).resolve().parent
sys.path.insert(0, str(HARNESS))
from study_scope import add_product_pipeline_argument, require_product_pipeline  # noqa: E402
from privoke_eval import pipeline_v1_v3 as core  # noqa: E402

STUDY = "product_rerun_20261024"
CONFIGS = {"regex": [2], "ner": [3], "semantic": [4], "nonsemantic": [2, 3],
           "no_regex": [3, 4], "no_ner": [2, 4], "product": [2, 3, 4]}
ABLATION_ENTRY = "v3-balanced"
FLAGS = ("PRIVOKE_CASE_PRESERVING_DETECTORS", "PRIVOKE_NER_POSTFILTER")
DEFAULT_SOURCE = Path("D:/Git Repositories/Privoke-Research-Project")


# ---------------------------------------------------------------- scoring helpers
def positive(c):
    return c["sensitivity"] != "S0" or bool(c["categories"])


def metric(record, name):
    if record["status"] != "ok":
        return 0
    target, predicted = record["target"], record["classification"]
    if name == "binary":
        return int(positive(predicted) == positive(target))
    action = record["action"] in record["allowed_actions"]
    if name == "action":
        return int(action)
    return int(action and all(set(predicted[k]) == set(target[k]) if k == "categories" else predicted[k] == target[k]
                              for k in ("sensitivity", "visibility", "categories")))


def distance(record):
    if record["status"] != "ok":
        return None
    rank = {"ALLOW": 0, "WARN": 1, "BLOCK": 2}
    action, allowed = rank[record["action"]], [rank[a] for a in record["allowed_actions"]]
    return max(0, min(allowed) - action), max(0, action - max(allowed))


def mcnemar_exact(improved, regressed):
    n = improved + regressed
    if n == 0:
        return 1.0
    k = min(improved, regressed)
    tail = sum(math.comb(n, i) for i in range(k + 1)) / 2 ** n
    return min(1.0, 2 * tail)


def cluster_interval(reference, candidate, name, field, draws=2000):
    import numpy as np
    delta = np.array([metric(b, name) - metric(a, name) for a, b in zip(reference, candidate)])
    groups = sorted({r[field] for r in reference})
    index = {g: i for i, g in enumerate(groups)}
    sums, sizes = np.zeros(len(groups)), np.zeros(len(groups))
    for d, r in zip(delta, reference):
        sums[index[r[field]]] += d
        sizes[index[r[field]]] += 1
    pick = np.random.default_rng(42).integers(0, len(groups), size=(draws, len(groups)))
    values = sums[pick].sum(1) / sizes[pick].sum(1)
    return {"clusters": len(groups), "low": float(np.quantile(values, .025)), "high": float(np.quantile(values, .975))}


def paired(reference, candidate, intervals=True):
    core.require([r["id"] for r in reference] == [r["id"] for r in candidate], "Case pairing differs")
    result = {"n": len(reference), "metrics": {}}
    for name in ("binary", "action", "joint"):
        delta = [metric(b, name) - metric(a, name) for a, b in zip(reference, candidate)]
        improved, regressed = sum(d == 1 for d in delta), sum(d == -1 for d in delta)
        entry = {"reference_correct": sum(metric(r, name) for r in reference),
                 "candidate_correct": sum(metric(r, name) for r in candidate),
                 "improved": improved, "regressed": regressed, "net": improved - regressed,
                 "mcnemar_exact_p": mcnemar_exact(improved, regressed)}
        if intervals and improved + regressed:
            entry["paired_rate_interval_95"] = {f: cluster_interval(reference, candidate, name, f) for f in ("family_id", "group_id")}
        result["metrics"][name] = entry
    pairs = [(distance(a), distance(b)) for a, b in zip(reference, candidate)]
    ok = [(a, b) for a, b in pairs if a is not None and b is not None]
    result["action_distance"] = {
        "paired_success": len(ok),
        "under_cases_reference": sum(a[0] > 0 for a, _ in ok), "under_cases_candidate": sum(b[0] > 0 for _, b in ok),
        "over_cases_reference": sum(a[1] > 0 for a, _ in ok), "over_cases_candidate": sum(b[1] > 0 for _, b in ok),
        "over_resolved": sum(a[1] > 0 and b == (0, 0) for a, b in ok),
        "lost_correct_actions": sum(metric(a, "action") and not metric(b, "action") for a, b in zip(reference, candidate)),
        "gained_correct_actions": sum(not metric(a, "action") and metric(b, "action") for a, b in zip(reference, candidate))}
    return result


def summarize(records):
    under = [distance(r) for r in records]
    layers, findings = Counter(), Counter()
    for r in records:
        for t in r["traces"]:
            layers[str(t["layer"]) + ":" + t["status"]] += 1
            findings[str(t["layer"])] += len(t["findings"])
    tp = sum(positive(r["target"]) and r["status"] == "ok" and positive(r["classification"]) for r in records)
    fn = sum(positive(r["target"]) for r in records) - tp
    tn = sum((not positive(r["target"])) and r["status"] == "ok" and not positive(r["classification"]) for r in records)
    fp = sum(not positive(r["target"]) for r in records) - tn
    return {"n": len(records), "statuses": dict(Counter(r["status"] for r in records)),
            "correct": {m: sum(metric(r, m) for r in records) for m in ("binary", "action", "joint")},
            "confusion_binary": {"TP": tp, "FN": fn, "TN": tn, "FP": fp, "sensitive": tp + fn, "clean": tn + fp},
            "under_cases": sum(d is not None and d[0] > 0 for d in under), "over_cases": sum(d is not None and d[1] > 0 for d in under),
            "layer_statuses": dict(layers), "layer_finding_counts": dict(findings),
            "regex_early_block": sum(any(t["status"] == "skipped" for t in r["traces"]) for r in records),
            "action_counts": dict(Counter(r["action"] for r in records))}


# ---------------------------------------------------------------- runtime arm
def outcome(payload, entry, request, layers):
    if layers == core.LAYERS:
        return core.response_outcome(payload, entry, request)
    from privoke.v1 import runtime_pb2
    actual, traces, metadata = [], [], {}
    try:
        response = runtime_pb2.AnalyzePromptResponse.FromString(payload)
        actual, metadata = [t.layer for t in response.layers], dict(response.metadata)
        core.require(response.request_id == request.request_id and actual == list(layers), "Returned layer order/identity differs")
        traces = [{"layer": t.layer, "status": t.status, "error": t.error,
                   "findings": [core.detection(r, request.text) for r in t.results]} for t in response.layers]
        core.require(not response.error and all(t["status"] in ("ok", "skipped") for t in traces), "Runtime/layer error")
        skipped = [t for t in traces if t["status"] == "skipped"]
        if skipped:
            core.require(traces[0]["layer"] == 2 and any(f["action"] == "BLOCK" for f in traces[0]["findings"])
                         and all(t["layer"] in (3, 4) and t["error"] == "Skipped after regex returned BLOCK." and not t["findings"] for t in skipped)
                         and len(skipped) == len(traces) - 1, "Invalid regex skip provenance")
        semantic = next((t for t in traces if t["layer"] == 4), None)
        if semantic and semantic["status"] == "ok":
            core.require(all(metadata.get("privoke.semantic." + k) == entry["identity"][k]
                             for k in ("model_id", "model_version", "artifact_checksum", "parameter_fingerprint")), "Semantic identity differs")
        else:
            core.require(not any(k.startswith("privoke.semantic.") for k in metadata), "Unexecuted semantic impersonation")
        core.require(list(layers) != [4] or semantic["status"] == "ok", "Semantic-only request skipped")
        core.require(response.action in ("ALLOW", "WARN", "BLOCK") and response.allowed == (response.action != "BLOCK"), "Invalid action")
        return {"status": "ok", "classification": core.classification(response.classification), "action": response.action,
                "actual_layers": actual, "traces": traces, "metadata": metadata, "server_elapsed_ms": response.elapsed_ms}
    except Exception as error:
        return {"status": "invalid_response", "error": type(error).__name__ + ": " + str(error), "classification": None,
                "action": None, "actual_layers": actual, "traces": traces, "metadata": metadata}


def make_request(entry, row, key, layers, tag):
    from privoke.v1 import runtime_pb2
    return runtime_pb2.AnalyzePromptRequest(
        request_id=key, text=row["text"], source=row.get("source") or "", target_app=row.get("target_app") or "",
        layers=layers, regex_execution_order=1, semantic_model_id=entry["identity"]["model_id"],
        metadata={"study": STUDY, "package": entry["name"], "configuration": tag})


def request_key(arm, name, tag, row_id):
    return "pr24-" + core.digest(core.canonical([arm, name, tag, row_id]))[:40]


def records_for(journal, entry, rows, arm, tag, layers):
    out = []
    for row in rows:
        key = request_key(arm, entry["name"], tag, row["id"])
        call = journal.calls[key]
        request = make_request(entry, row, key, layers, tag)
        core.require(base64.b64decode(call["reserve"]["request_pb"]) == request.SerializeToString(deterministic=True), "Journal stimulus drift")
        terminal = call["terminal"]
        value = outcome(base64.b64decode(terminal["response_pb"]), entry, request, layers) if "response_pb" in terminal else {
            "status": "transport_error", "error": terminal["transport_error"], "classification": None, "action": None, "traces": []}
        out.append(dict(value, id=row["id"], family_id=row["family_id"], group_id=row["group_id"],
                        target=row["classification"], allowed_actions=row["allowed_actions"],
                        host_elapsed_ns=terminal["ended_ns"] - terminal["started_ns"]))
    return out


def run_configuration(stub, journal, entry, rows, arm, tag, layers, log):
    for index, row in enumerate(rows):
        key = request_key(arm, entry["name"], tag, row["id"])
        if key in journal.calls:
            continue
        request = make_request(entry, row, key, layers, tag)
        wire = request.SerializeToString(deterministic=True)
        journal.append("reserve", key, request_pb=base64.b64encode(wire).decode(), request_sha256=core.digest(wire),
                       model=entry["name"], repeat=0, index=index, case_id=row["id"], warmup=False, configuration=tag)
        started = time.perf_counter_ns()
        try:
            response = stub.AnalyzePrompt(request, timeout=300)
            payload = response.SerializeToString(deterministic=True)
            journal.append("terminal", key, started_ns=started, ended_ns=time.perf_counter_ns(),
                           response_pb=base64.b64encode(payload).decode(), response_sha256=core.digest(payload))
        except Exception as error:
            journal.append("terminal", key, started_ns=started, ended_ns=time.perf_counter_ns(),
                           transport_error=type(error).__name__ + ": " + str(error))
        if (index + 1) % 200 == 0:
            log(f"{entry['name']} {tag} {index + 1}/{len(rows)}")
    return records_for(journal, entry, rows, arm, tag, layers)


def serve_entry(entry, allowed, port):
    import grpc
    from privoke.v1 import runtime_pb2_grpc
    from privoke_eval import pipeline_v1_v3_serving as serving
    from src.hosting.grpc_server import PrivokeRuntimeService
    semantic = serving.load_semantic(entry)
    native = serving.service(entry, semantic)

    def analyze(self, request, context):
        if (list(request.layers) not in allowed or request.regex_execution_order != 1 or request.visibility_hint
                or request.HasField("semantic_presence_gate") or request.semantic_model_id != entry["identity"]["model_id"]):
            context.abort(grpc.StatusCode.INVALID_ARGUMENT, "Frozen explicit detector request required")
        return PrivokeRuntimeService.AnalyzePrompt(self, request, context)

    native.AnalyzePrompt = MethodType(analyze, native)
    server = grpc.server(ThreadPoolExecutor(max_workers=1))
    runtime_pb2_grpc.add_PrivokeRuntimeServiceServicer_to_server(native, server)
    core.require(server.add_insecure_port("127.0.0.1:" + str(port)), "Loopback port unavailable")
    server.start()
    return server, semantic


def runtime_probe():
    """Record the effective detector configuration of the loaded runtime tree."""
    import src
    from src.config import GLOBAL_CONFIG
    from src.regex.rule_detector import RuleDetector
    rules = core.rules_inventory(RuleDetector())
    return {"src_path": list(getattr(src, "__path__", [])), "flags_env": {k: os.environ.get(k) for k in FLAGS},
            "case_preserving_detectors": getattr(GLOBAL_CONFIG, "case_preserving_detectors", "absent"),
            "ner_postfilter": getattr(GLOBAL_CONFIG, "ner_postfilter", "absent"),
            "wait_for_regex": GLOBAL_CONFIG.wait_for_regex, "regex_rule_count": len(rules),
            "effective_regex_rules_sha256": core.digest(core.canonical(rules))}


def run(args):
    for key, value in core.PRODUCT_ENV.items():
        os.environ[key] = value
    for key in FLAGS:
        core.require(key not in os.environ, key + " must be unset so tree defaults apply")
    root = core.configure(args.runtime_root)
    core.configure_numeric()
    out = Path(args.output).resolve() / args.arm
    out.mkdir(parents=True, exist_ok=True)
    logfile = (out / "progress.log").open("a", encoding="utf-8")

    def log(message):
        line = time.strftime("%H:%M:%S ") + message
        print(line, flush=True)
        logfile.write(line + "\n")
        logfile.flush()

    import spacy
    spacy.require_cpu()
    from src.NER.ner_detector import EntityNERDetector
    ner = EntityNERDetector()
    core.require(ner.backend_name == "spacy" and ner.model_name == "en_core_web_sm" and "ner" in ner.nlp.pipe_names, "NER readiness")
    probe = runtime_probe()
    log("runtime " + json.dumps(probe))
    hist = core.read(args.historical_protocol)
    core.require(core.file_hash(args.historical_protocol) == args.historical_protocol_sha256, "Historical protocol drift")
    core.require(core.file_hash(hist["data_manifest"]) == core.DATA_SHA, "Data manifest drift")
    for entry in hist["entries"]:
        core.validate_assets(entry)
    rows = core.rows_for(hist)
    core.require(len(rows) == 1560 and len({r["id"] for r in rows}) == 1560, "Case cardinality")
    if args.limit:
        rows = rows[:args.limit]   # smoke testing only; never used for reported results
    warm = core.rows_for(hist, "train")[:4]
    closure = core.source_files(root)
    meta = {"arm": args.arm, "runtime_root": str(root), "source_head_label": args.source_label, "runtime_probe": probe,
            "source_closure": core.digest(core.canonical(closure)), "source_files": closure,
            "environment": core.environment(), "ordered_rows_sha256": core.digest(core.canonical(rows)),
            "historical_protocol_sha256": args.historical_protocol_sha256,
            "package_assets": {e["name"]: e["assets"] for e in hist["entries"]},
            "package_identity": {e["name"]: e["identity"] for e in hist["entries"]}, "rows": len(rows),
            "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    core.retain(out / "arm-meta.json", meta)
    port = args.port
    names = args.packages or list(core.NAMES)
    for name in names:
        entry = next(e for e in hist["entries"] if e["name"] == name)
        configs = [("u1-product", core.LAYERS)]
        if name == ABLATION_ENTRY and not args.skip_ablation:
            configs += [("u2-" + c, l) for c, l in CONFIGS.items()]
        allowed = [list(l) for _, l in configs]
        t0 = time.time()
        server, _ = serve_entry(entry, allowed, port)
        try:
            import grpc
            from privoke.v1 import runtime_pb2_grpc
            journal_path = out / name / "journal.jsonl"
            journal = core.Journal(journal_path)
            with grpc.insecure_channel("127.0.0.1:" + str(port)) as channel:
                grpc.channel_ready_future(channel).result(timeout=60)
                stub = runtime_pb2_grpc.PrivokeRuntimeServiceStub(channel)
                warm_journal = core.Journal(out / name / "warmup.jsonl")
                for row in warm:   # warmups, never scored
                    run_configuration(stub, warm_journal, entry, [row], args.arm, "warmup", core.LAYERS, log)
                for tag, layers in configs:
                    values = run_configuration(stub, journal, entry, rows, args.arm, tag, layers, log)
                    core.retain(out / name / (tag + ".records.json"), values)
                    log(f"{name} {tag} {json.dumps(summarize(values)['correct'])} statuses={dict(Counter(v['status'] for v in values))}")
        finally:
            server.stop(2).wait()
        log(f"{name} done in {time.time() - t0:.0f}s")
        port += 1
    core.retain(out / "complete.json", {"arm": args.arm, "packages": names, "journal_hashes": {
        n: core.file_hash(out / n / "journal.jsonl") for n in names}})
    return 0


# ---------------------------------------------------------------- historical reader
def historical_unit1(args):
    """First-pass records of the original PIPE3 run, rebuilt from its raw journals."""
    hist = core.read(args.historical_protocol)
    sha = core.file_hash(args.historical_protocol)
    all_rows = core.rows_for(hist)
    out = {}
    for entry in hist["entries"]:
        journal = core.Journal(Path(args.historical_results) / "models" / entry["name"] / "raw.jsonl")
        records = []
        for index, row in enumerate(all_rows):
            key = core.request_id(sha, entry["name"], 0, row["id"])
            records.append(core.record_for(journal.calls[key], entry, row, core.request_for(entry, row, key)))
        out[entry["name"]] = records
    return out


def historical_unit2(args):
    base = Path(args.historical_ablation)
    return {c: json.loads((base / c / "records.json").read_text(encoding="utf-8")) for c in CONFIGS}


def load_arm(path, names):
    base = Path(path)
    unit1, unit2 = {}, {}
    for name in names:
        unit1[name] = json.loads((base / name / "u1-product.records.json").read_text(encoding="utf-8"))
    for c in CONFIGS:
        file = base / ABLATION_ENTRY / ("u2-" + c + ".records.json")
        if file.exists():
            unit2[c] = json.loads(file.read_text(encoding="utf-8"))
    return unit1, unit2


def strip(records):
    return [{k: v for k, v in r.items() if k not in ("traces", "metadata", "evidence", "masked_text", "evidence_span_origins")} for r in records]


def same_outcome(a, b):
    return sum(x["classification"] == y["classification"] and x["action"] == y["action"] for x, y in zip(a, b))


def over_set(records):
    return {r["id"] for r in records if distance(r) is not None and distance(r)[1] > 0}


def analyze(args):
    old1, old2 = load_arm(Path(args.output) / "old", core.NAMES)
    new1, new2 = load_arm(Path(args.output) / "new", core.NAMES)
    h1, h2 = historical_unit1(args), historical_unit2(args)
    out = {"study_id": STUDY, "scope": "FULL-PRODUCT (regex+NER+semantic cascade) evidence; not semantic-only or LLM-only",
           "unit1": {"packages": {}, "tiers": {}, "shared_over_enforced": {}}, "unit2": {}}
    arms = {"historical": h1, "old": old1, "new": new1}
    for name in core.NAMES:
        entry = {a: summarize(arms[a][name]) for a in arms}
        entry["paired_new_minus_old"] = paired(old1[name], new1[name])
        entry["paired_old_minus_historical"] = paired(h1[name], old1[name], intervals=False)
        entry["identical_outcome_old_vs_historical"] = same_outcome(h1[name], old1[name])
        entry["identical_outcome_new_vs_old"] = same_outcome(old1[name], new1[name])
        out["unit1"]["packages"][name] = entry
    for tier in core.TIERS:
        out["unit1"]["tiers"][tier] = {a: paired(arms[a]["v1-" + tier], arms[a]["v3-" + tier], intervals=a != "historical") for a in arms}
    for a in arms:
        sets = {t: over_set(arms[a]["v3-" + t]) for t in core.TIERS}
        out["unit1"]["shared_over_enforced"][a] = {
            "v3_intersection": len(set.intersection(*sets.values())), "v3_union": len(set.union(*sets.values())),
            "per_tier": {t: len(s) for t, s in sets.items()},
            "v1_intersection": len(set.intersection(*(over_set(arms[a]["v1-" + t]) for t in core.TIERS)))}
    ho, hn = set.intersection(*(over_set(h1["v3-" + t]) for t in core.TIERS)), set.intersection(*(over_set(new1["v3-" + t]) for t in core.TIERS))
    oo = set.intersection(*(over_set(old1["v3-" + t]) for t in core.TIERS))
    out["unit1"]["shared_over_enforced"]["overlap"] = {"historical_and_old": len(ho & oo), "old_and_new": len(oo & hn), "historical_and_new": len(ho & hn)}
    arms2 = {"historical": h2, "old": old2, "new": new2}
    for a, recs in arms2.items():
        out["unit2"][a] = {c: summarize(recs[c]) for c in CONFIGS if c in recs}
    out["unit2"]["contrasts"] = {}
    for a, recs in arms2.items():
        if "product" not in recs:
            continue
        out["unit2"]["contrasts"][a] = {c: paired(recs["product"], recs[c], intervals=a != "historical") for c in CONFIGS if c != "product" and c in recs}
    out["unit2"]["paired_new_minus_old"] = {c: paired(old2[c], new2[c]) for c in CONFIGS if c in old2 and c in new2}
    out["unit2"]["paired_old_minus_historical"] = {c: paired(h2[c], old2[c], intervals=False) for c in CONFIGS if c in old2}
    if "product" in new2 and "no_ner" in new2:
        out["unit2"]["no_ner_equals_product"] = {a: same_outcome(r["product"], r["no_ner"]) for a, r in arms2.items() if "no_ner" in r}
    out["unit2"]["u1_balanced_vs_u2_product_identical"] = {
        "old": same_outcome(old1[ABLATION_ENTRY], old2["product"]), "new": same_outcome(new1[ABLATION_ENTRY], new2["product"])}
    # trace-level detector summaries (counts only)
    core.retain(Path(args.output) / "analysis.json", out)
    print(core.canonical(out["unit1"]["tiers"]["balanced"]["new"]["metrics"]).decode()[:2000])
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("run", "analyze"))
    parser.add_argument("--arm", choices=("old", "new"))
    parser.add_argument("--runtime-root", type=Path)
    parser.add_argument("--source-label", default="")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--port", type=int, default=50291)
    parser.add_argument("--packages", nargs="*")
    parser.add_argument("--skip-ablation", action="store_true")
    parser.add_argument("--limit", type=int, default=0, help="smoke test only")
    parser.add_argument("--source-checkout", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--historical-protocol-sha256", default="938f626bec9b5810a34e6e9f33d1d28f0070fbc10ac6a570e568b41c39346ed7")
    add_product_pipeline_argument(parser)
    args = parser.parse_args(argv)
    require_product_pipeline(args, parser)
    sc = args.source_checkout
    args.historical_results = sc / "evaluation/results/pipeline_v1_v3_20261014/runs/cpu-01"
    args.historical_protocol = args.historical_results / "protocol.json"
    args.historical_ablation = sc / "evaluation/results/controlled_studies_20261014/ablation-02"
    if args.action == "run":
        if not args.arm or not args.runtime_root:
            parser.error("--arm and --runtime-root required")
        return run(args)
    return analyze(args)


if __name__ == "__main__":
    raise SystemExit(main())
