"""Six new native semantic-only RPC runs on sealed AU3 FRESH; no imported scores."""
from pathlib import Path
import time

import numpy as np

from . import audience_v3 as core
from . import privacy_heads_v3_comparison as raw

def model_identity(manifest, sha):
    from .privacy_encoder_v3_comparison import model_identity as identity
    return identity(manifest, sha)


def expected_names():
    return [phase + "-" + tier for phase in ("before", "after") for tier in core.TIERS]


def freeze_registry(results):
    results = Path(results)
    protocol, binding, _, _ = core.validate(results)
    core.approval(results, "postfit-acceptance.json")
    accepted = core.read(results / "postfit-acceptance.json")["training_audits"]
    core.require(set(accepted) == set(core.TIERS), "All-three postfit audits required")
    entries, seals = [], {}
    for tier in core.TIERS:
        core.audit_training(results, tier)
        audit = results / "training-audit" / (tier + ".json")
        core.require(accepted[tier] == core.file_hash(audit), "Postfit audit pin differs")
        outputs = core.read(results / "exports" / (tier + ".json"))
        native = core.read(results / "native-verification" / (tier + ".json"))
        files = {str(audit): core.file_hash(audit),
                 str(results / "exports" / (tier + ".json")): core.file_hash(results / "exports" / (tier + ".json")),
                 str(results / "native-verification" / (tier + ".json")): core.file_hash(results / "native-verification" / (tier + ".json"))}
        files.update(core.read(audit)["checkpoint_inventory"])
        for proof in native["exports"].values():
            files.update(proof["raw"])
        seals[tier] = files
        parent_dir = Path(binding["models"]) / "initials" / tier
        before = {"directory": str(parent_dir), "manifest_sha256": core.PARENTS[tier],
                  "blob": protocol["parents"][tier]["blob"]}
        for phase, item in (("before", before), ("after", outputs["selected"])):
            manifest = core.check_assets(item["directory"], item["manifest_sha256"])
            entries.append({"name": phase + "-" + tier, "phase": phase, "tier": tier, "family": "v3",
                            **item, "identity": model_identity(manifest, item["manifest_sha256"])})
    entries.sort(key=lambda e: expected_names().index(e["name"]))
    registry = {"schema": 1, "study_id": core.STUDY_ID,
                "protocol_sha256": core.file_hash(results / "protocol.json"), "source_closure": protocol["source_closure"],
                "postfit_acceptance_sha256": core.file_hash(results / "postfit-acceptance.json"),
                "entries": entries, "all_tier_seals": seals, "fresh_eval": protocol["dataset_files"]["fresh_eval"],
                "layers": [4], "visibility_hints": "", "new_accuracy_requests": 6 * protocol["dataset_files"]["fresh_eval"]["rows"],
                "uncertainty": {"cluster_fields": ["family_id", "audience_expression_group_id"], "seed": 42,
                                "replicates": 2000, "percentiles": [2.5, 97.5], "meaning": "separate_dependence_sensitivities"},
                "claim": "synthetic_assistant_provisional_paired_FRESH_CURRENT_EN3_vs_AU3_no_benchmark_tuning"}
    core.retain(results / "comparison/registry.json", registry)
    return registry


def validate_registry(results):
    results = Path(results)
    protocol, binding, _, _ = core.validate(results)
    registry = core.read(results / "comparison/registry.json")
    core.require(registry["schema"] == 1 and registry["study_id"] == core.STUDY_ID
                 and registry["protocol_sha256"] == core.file_hash(results / "protocol.json")
                 and registry["source_closure"] == protocol["source_closure"]
                 and registry["fresh_eval"] == protocol["dataset_files"]["fresh_eval"]
                 and registry["layers"] == [4] and registry["visibility_hints"] == ""
                 and [e["name"] for e in registry["entries"]] == expected_names(), "AU3 fresh registry drift")
    core.require(registry["postfit_acceptance_sha256"] == core.approval(results, "postfit-acceptance.json"), "Postfit gate drift")
    for tier in core.TIERS:
        for path, sha in registry["all_tier_seals"][tier].items():
            core.require(core.file_hash(path) == sha, "Sealed audit/native raw proof changed")
        core.validate_exports(results, tier)  # Includes BOTH selected and terminal asset/checkpoint bindings.
    for entry in registry["entries"]:
        manifest = core.check_assets(entry["directory"], entry["manifest_sha256"])
        core.require(entry["identity"] == model_identity(manifest, entry["manifest_sha256"])
                     and entry["blob"] == manifest["blob"], "Registry native identity drift")
        if entry["phase"] == "before":
            core.require(entry["manifest_sha256"] == core.PARENTS[entry["tier"]], "BEFORE is not CURRENT parent")
        else:
            selected = core.read(results / "exports" / (entry["tier"] + ".json"))["selected"]
            core.require(all(entry.get(k) == v for k, v in selected.items()), "AFTER is not selected AU3 export")
    return registry, binding


def evaluation_rows(results):
    registry, binding = validate_registry(results)
    core.approval(results, "test-acceptance.json")
    gate = core.read(Path(results) / "test-acceptance.json")
    core.require(gate["registry_sha256"] == core.file_hash(Path(results) / "comparison/registry.json"), "Test-opening seal differs")
    rows = core.data.load_partition(binding["data_manifest"], "fresh_eval", evaluation_authorized=True)
    core.require(len(rows) == registry["fresh_eval"]["rows"] and all(not r.get("visibility_hint") for r in rows), "FRESH denominator/hints differ")
    return registry, binding, rows


def request_id(registry_sha, name, row, index, *, warmup=False):
    return "au3-" + ("warmup-" if warmup else "") + core.digest(core.canonical([registry_sha, name, row["id"], index]))[:40]


def response_outcome(payload, entry, request):
    """A received invalid wire is a terminal incorrect case, never a replay."""
    from privoke.v1 import runtime_pb2
    layers, metadata = [], {}
    try:
        response = runtime_pb2.AnalyzePromptResponse.FromString(payload)
        layers, metadata = [v.layer for v in response.layers], dict(response.metadata)
        core.require(layers == [4], "Actual sole semantic execution missing or different")
        expected = {"privoke.semantic." + k: str(v) for k, v in entry["identity"].items()}
        core.require(all(metadata.get(k) == v for k, v in expected.items()), "Actual native identity differs")
        return raw.response_record(response, entry, request)
    except Exception as error:
        return {"status": "invalid_response", "error": type(error).__name__ + ": " + str(error),
                "actual_layers": layers, "metadata": metadata, "classification": None, "action": None}


def attempt_record(entry, row, directory, request_id, *, unrecorded=False):
    """Reconstruct only from complete retained stimulus, outcome and timing."""
    directory = Path(directory)
    request = raw.request_for(entry, row, request_id)
    payload = (directory / "request.pb").read_bytes()
    core.require(payload == request.SerializeToString(deterministic=True), "Wire stimulus differs")
    timing = core.read(directory / "timing.json")
    start, end = timing["started_perf_counter_ns"], timing["ended_perf_counter_ns"]
    core.require(type(start) is int and type(end) is int and 0 <= start <= end, "Invalid RPC timing")
    response, failure = directory / "response.pb", directory / "transport-error.json"
    core.require(response.exists() != failure.exists(), "Unknown or conflicting reserved RPC outcome; reconcile without replay")
    expected = {"request.pb", "timing.json", "response.pb" if response.exists() else "transport-error.json"}
    if not unrecorded:
        expected.add("record.json")
    core.require({p.name for p in directory.iterdir()} == expected, "Missing/extraneous RPC evidence")
    if response.exists():
        outcome = response_outcome(response.read_bytes(), entry, request)
    else:
        error = core.read(failure)
        outcome = {"status": "transport_error", "error": error["error"], "classification": None,
                   "action": None, "actual_layers": [], "metadata": {}}
    return dict(outcome, id=row["id"], group_id=row["group_id"], family_id=row["family_id"],
                target=row["classification"], allowed_actions=row["allowed_actions"],
                request_sha256=core.digest(payload), host_elapsed_ns=end - start)


def audit_call(entry, row, directory, request_id):
    record = core.read(Path(directory) / "record.json")
    reconstructed = attempt_record(entry, row, directory, request_id)
    core.require(record == reconstructed, "Raw RPC record differs")
    return reconstructed


def invoke(stub, entry, row, directory, request_id):
    directory = Path(directory)
    if (directory / "record.json").exists():
        return audit_call(entry, row, directory, request_id)
    if (directory / "request.pb").exists():
        core.require((directory / "timing.json").exists()
                     and ((directory / "response.pb").exists() or (directory / "transport-error.json").exists()),
                     "Unknown reserved RPC outcome; reconcile without replay")
    else:
        request = raw.request_for(entry, row, request_id)
        core.retain(directory / "request.pb", request.SerializeToString(deterministic=True))
        start = time.perf_counter_ns()
        try:
            response = stub.AnalyzePrompt(request, timeout=120)
        except Exception as error:
            end = time.perf_counter_ns()
            core.retain(directory / "transport-error.json", {"type": type(error).__name__, "error": str(error)})
        else:
            end = time.perf_counter_ns()
            core.retain(directory / "response.pb", response.SerializeToString(deterministic=True))
        core.retain(directory / "timing.json", {"started_perf_counter_ns": start, "ended_perf_counter_ns": end})
    core.retain(directory / "record.json", attempt_record(entry, row, directory, request_id, unrecorded=True))
    return audit_call(entry, row, directory, request_id)


def task_scores(matrix):
    """Per-class support includes ERROR predictions; no error is a correct row."""
    labels = list(matrix)
    scores = {}
    for label in labels:
        tp = matrix[label][label]
        support = sum(matrix[label].values())
        fp = sum(matrix[other][label] for other in labels if other != label)
        fn = support - tp
        scores[label] = {"tp": tp, "fp": fp, "fn": fn, "support": support,
                         "precision": tp / (tp + fp) if tp + fp else None,
                         "recall": tp / support if support else None,
                         "f1": 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else None}
    defined = [v["f1"] for v in scores.values() if v["f1"] is not None]
    return {"per_class": scores, "macro_f1": sum(defined) / len(defined) if defined else None,
            "macro_defined_classes": len(defined)}


def summarize(records):
    result = raw.summarize(records)
    result["observed_groups"] = result.pop("independent_groups")
    result["observed_families"] = len({r["family_id"] for r in records})
    result["dependence"] = "Rows share families and audience expressions; group/family counts do not imply independence."
    distances = [raw.action_distance(r) for r in records]
    result["action_distance"].update({key + "_cases": sum(d is not None and d[key] > 0 for d in distances)
                                       for key in ("under", "over")})
    result["task_scores"] = {task: task_scores(result["confusion"][task]) for task in ("sensitivity", "visibility")}
    result["audience_recall"] = {label: result["task_scores"]["visibility"]["per_class"][label]
                                 for label in core.en.ph.LABELS["visibility"]}
    result["category_error_policy"] = "Errors incorrect for exact metrics; positive category targets become FN; no negative prediction imputation claim."
    return result


def cluster_interval(before, after, rows, field, *, replicates=2000):
    core.require(len(before) == len(after) == len(rows), "Cluster pairing denominator differs")
    groups = {}
    metrics = list(raw.case_metrics({"status": "error"}))
    for a, b, row in zip(before, after, rows):
        core.require(a["id"] == b["id"] == row["id"], "Cluster IDs differ")
        group = row["family_id"] if field == "family_id" else row["metadata"][field]
        core.require(isinstance(group, str) and bool(group), "Missing cluster identity")
        counts, count = groups.setdefault(group, (np.zeros(len(metrics), dtype=np.int64), [0]))
        am, bm = raw.case_metrics(a), raw.case_metrics(b)
        counts += np.array([int(bm[k]) - int(am[k]) for k in metrics])
        count[0] += 1
    n = len(groups)
    base = {"cluster_field": field, "clusters": n, "rows": len(rows), "seed": 42, "replicates": replicates,
            "meaning": "dependence_sensitivity_not_crossed_independence"}
    if n < 2:
        return dict(base, intervals=None, unavailable="Fewer than two supported clusters")
    totals = np.stack([v[0] for v in groups.values()])
    sizes = np.array([v[1][0] for v in groups.values()])
    indices = np.random.default_rng(42).integers(0, n, size=(replicates, n))
    deltas = totals[indices].sum(axis=1) / sizes[indices].sum(axis=1)[:, None]
    limits = np.percentile(deltas, [2.5, 97.5], axis=0)
    observed = totals.sum(axis=0) / sizes.sum()
    return dict(base, intervals={k: {"after_minus_before": float(observed[i]), "low": float(limits[0, i]),
                                    "high": float(limits[1, i])} for i, k in enumerate(metrics)})


def paired(before, after, rows):
    result = raw.paired(before, after)
    result["by_true_visibility"] = {}
    result["uncertainty"] = {}
    distances = [(raw.action_distance(a), raw.action_distance(b)) for a, b in zip(before, after)
                 if a["status"] == b["status"] == "ok"]
    result["action_harms"].update({key + "_distance_delta": sum(b[key] - a[key] for a, b in distances)
                                    for key in ("under", "over")})
    result["action_harms"].update({key + "_cases_delta": sum(int(b[key] > 0) - int(a[key] > 0) for a, b in distances)
                                    for key in ("under", "over")})
    slices = {"all": list(range(len(rows)))}
    slices.update({label: [i for i, row in enumerate(rows) if row["classification"]["visibility"] == label]
                   for label in core.en.ph.LABELS["visibility"]})
    for label, indices in slices.items():
        a, b, selected = ([items[i] for i in indices] for items in (before, after, rows))
        if label != "all":
            result["by_true_visibility"][label] = raw.paired(a, b)
        result["uncertainty"][label] = {field: cluster_interval(a, b, selected, field)
                                        for field in ("family_id", "audience_expression_group_id")}
    return result


def evaluate(results, name, target, ready_file):
    import grpc
    from privoke.v1 import runtime_pb2_grpc
    registry, binding, rows = evaluation_rows(results)
    entry = next(e for e in registry["entries"] if e["name"] == name)
    registry_sha = core.file_hash(Path(results) / "comparison/registry.json")
    ready = core.read(ready_file)
    core.require(ready["identity"] == entry["identity"] and ready["registry_sha256"] == registry_sha
                 and ready["source_closure"] == registry["source_closure"] and ready["training_disabled"]
                 and ready["native_inference"] and ready["environment"]["torch_threads"] == 4
                 and ready["environment"]["deterministic"]
                 and ready["environment"]["packages"]["torch"] == "2.11.0+cpu", "Native ready identity/environment differs")
    output = Path(results) / "comparison/models" / name
    core.retain(output / "server-ready.json", ready)
    records = []
    with grpc.insecure_channel(target) as channel:
        grpc.channel_ready_future(channel).result(timeout=180)
        stub = runtime_pb2_grpc.PrivokeRuntimeServiceStub(channel)
        for index, row in enumerate(core.data.load_partition(binding["data_manifest"], "train")[:4]):
            result = invoke(stub, entry, row, output / "warmup" / f"{index:04d}",
                                request_id(registry_sha, name, row, index, warmup=True))
            core.require(result["status"] == "ok", "TRAIN warmup failed")
        for index, row in enumerate(rows):
            records.append(invoke(stub, entry, row, output / "rows" / f"{index:04d}", request_id(registry_sha, name, row, index)))
            if index % 100 == 0:
                print(f"{name}: {index + 1}/{len(rows)}", flush=True)
    result = summarize(records)
    core.retain(output / "summary.json", result)
    core.retain(output / "complete.json", {"registry_sha256": registry_sha, "requested": len(rows),
                                           "summary_sha256": core.file_hash(output / "summary.json")})
    return result


def audit(results):
    registry, binding, rows = evaluation_rows(results)
    registry_sha = core.file_hash(Path(results) / "comparison/registry.json")
    summaries, records, inventory = {}, {}, {}
    for entry in registry["entries"]:
        output = Path(results) / "comparison/models" / entry["name"]
        core.require({p.name for p in (output / "rows").iterdir()} == {f"{i:04d}" for i in range(len(rows))}, "Fresh row coverage differs")
        values = [audit_call(entry, row, output / "rows" / f"{i:04d}", request_id(registry_sha, entry["name"], row, i))
                  for i, row in enumerate(rows)]
        for i, row in enumerate(core.data.load_partition(binding["data_manifest"], "train")[:4]):
            outcome = audit_call(entry, row, output / "warmup" / f"{i:04d}", request_id(registry_sha, entry["name"], row, i, warmup=True))
            core.require(outcome["status"] == "ok", "Warmup audit failed")
        summary = summarize(values)
        core.require(summary == core.read(output / "summary.json")
                     and core.read(output / "complete.json") == {"registry_sha256": registry_sha, "requested": len(rows),
                     "summary_sha256": core.file_hash(output / "summary.json")}, "Fresh summary/completion differs")
        records[entry["name"]], summaries[entry["name"]] = values, summary
        for path in output.rglob("*"):
            if path.is_file():
                inventory[path.relative_to(Path(results)).as_posix()] = core.file_hash(path)
    result = {"schema": 1, "study_id": core.STUDY_ID, "registry_sha256": registry_sha,
              "new_accuracy_requests": len(rows) * 6, "imported_accuracy_cases": 0, "results": summaries,
              "paired_after_minus_before": {tier: paired(records["before-" + tier], records["after-" + tier], rows) for tier in core.TIERS},
              "limitations": ["Synthetic assistant-provisional labels; family and expression correlations remain.",
                              "Both separate clustering sensitivities reported; neither proves crossed independence.",
                              "Fresh scores select no model, tier, epoch, recipe or threshold; no refit after opening.",
                              "Errors count incorrect; action harm comparisons expose error pairs; latency is descriptive."],
              "raw_inventory_sha256": core.digest(core.canonical(inventory))}
    core.retain(Path(results) / "comparison/raw-inventory.json", inventory)
    core.retain(Path(results) / "comparison/analysis.json", result)
    return result
