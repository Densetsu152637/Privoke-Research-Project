"""Prospective 18-cell v3 plan, resource-only budget, endpoint audit and exports."""
from __future__ import annotations

import math
from pathlib import Path
import subprocess

from . import pretrained_v3_study as study
from .pretrained_v3_scoring import ENDPOINTS, paired_difference, score_endpoint, audit_endpoint_records, summarize_records
from privoke_model.v3_contract import POLICY, TIERS, parse, validate_manifest, validate_execution, publication_passes

ROOT = study.ROOT
RUN = ROOT / "models/experiments/pretrained_v3_20261012"
STUDY_ID = "pretrained_v3_20261012"
SEEDS = (42, 43, 44)
PILOTS = (("efficient", "heads", 42), ("efficient", "full_encoder", 42), ("quality", "full_encoder", 42))
MAX_TOTAL_FIT_SECONDS = 14400


def read(path):
    return parse(Path(path).read_bytes(), 80 * 1024 * 1024)


def matrix():
    return [{"id": f"{tier}-{scope}-{seed}", "tier": tier, "scope": scope, "seed": seed}
            for seed in SEEDS for tier in TIERS for scope in ("heads", "full_encoder")]


def source_closure():
    files = study.source_inventory()
    names = ("evaluation/privoke_eval/pretrained_v3_study.py", "evaluation/privoke_eval/pretrained_v3_plan.py",
             "evaluation/privoke_eval/pretrained_v3_scoring.py", "evaluation/run-pretrained-v3-study.py",
             "evaluation/prepare-pretrained-v3.py", "evaluation/setup-host.py", "evaluation/host_environment.py",
             "evaluation/Dockerfile.pretrained-v3", "evaluation/compose.pretrained-v3-study.yml",
             "evaluation/requirements-pretrained-v3-server.txt", "evaluation/tests/test_pretrained_v3.py",
             "evaluation/tests/test_pretrained_v3_controller.py", ".dockerignore")
    for name in names:
        files[name] = study.digest((ROOT / name).read_bytes())
    for path in (ROOT / "extension/client-runtime/generated").rglob("*.py"):
        files[path.relative_to(ROOT).as_posix()] = study.digest(path.read_bytes())
    return dict(sorted(files.items()))


def resource_budget(pilots, *, max_total_seconds, vram_capacity_bytes):
    """No guard/endpoint quality field participates in this prospective choice."""
    coordinates = [(p["tier"], p["scope"], p["seed"]) for p in pilots]
    if sorted(coordinates) != sorted(PILOTS) or len(pilots) != 3:
        raise ValueError("Exactly the three predeclared pilot coordinates required.")
    if max_total_seconds != MAX_TOTAL_FIT_SECONDS or vram_capacity_bytes <= 0:
        raise ValueError("V3-R1 requires the predeclared 14400-second total resource limit and measured positive VRAM capacity.")
    work = {"optimizer_steps": 2, "train_rows": 128, "microbatch_forward": 32, "microbatch_backward": 32}
    if any(any(p["work"].get(k) != v for k, v in work.items()) or not math.isfinite(p["seconds"]) or p["seconds"] <= 0
           or not 0 < p["cuda_peak_bytes"] < .9 * vram_capacity_bytes for p in pilots):
        raise ValueError("Pilots lack actual two-step CUDA work or exceed the resource allowance.")
    seconds = {(p["tier"], p["scope"]): p["seconds"] / 2 for p in pilots}
    worst = max(seconds.values())
    # Unmeasured balanced scopes and quality HEADS use the slowest measured arm;
    # an explicit 50% allowance covers the longer main stream and guard overhead.
    per_step_sum = sum(seconds.get((tier, scope), worst) for tier in TIERS for scope in ("heads", "full_encoder")) * len(SEEDS)
    estimates = {str(steps): 1.5 * steps * per_step_sum for steps in (64, 256, 512)}
    admitted = [steps for steps in (64, 256, 512) if estimates[str(steps)] <= max_total_seconds and 1.5 * steps * worst < 7200]
    if not admitted: raise ValueError("No predeclared budget fits the resource limit; stop for root decision.")
    return {"basis": "resource_only_no_quality_selection", "steps": max(admitted),
            "max_total_seconds": max_total_seconds, "vram_capacity_bytes": vram_capacity_bytes,
            "pilot_seconds_per_step": {tier + "-" + scope: value for (tier, scope), value in seconds.items()},
            "pilot_peak_bytes": max(p["cuda_peak_bytes"] for p in pilots), "estimated_total_seconds": estimates,
            "estimate_allowance": 1.5, "unmeasured_scopes_use_slowest_pilot": True}


def freeze_plan(directory, pilot_cells, image_id, *, max_total_seconds, vram_capacity_bytes):
    directory = Path(directory).resolve()
    if directory.exists() and any(directory.iterdir()): raise ValueError("Plan directory must be fresh.")
    pilots = [read(Path(cell) / "summary.json") for cell in pilot_cells]
    for cell, summary in zip(pilot_cells, pilots):
        policy = read(Path(cell) / "policy.json")
        evidence = validate_execution(read(Path(cell) / "terminal-evidence.json"))
        if (policy["steps"] != 2 or evidence["policy"] != policy or summary["work"] != evidence["counts"]
                or any(summary[key] != evidence[key] for key in ("tier", "scope", "seconds", "cuda_peak_bytes"))
                or summary["seed"] != evidence["source"]["seed"]):
            raise ValueError("Pilot summary differs from actual work evidence.")
        if summary["image_id"] != image_id or study.check_binding(Path(cell))["server_source_closure"] != study.source_identity():
            raise ValueError("Pilots must use the same exact image and server sources as the main plan.")
        binding = read(Path(cell) / "cell.json")
        execution = study.check_binding(Path(cell))
        audit_cell({"directory": str(cell), "tier": summary["tier"], "scope": summary["scope"], "seed": summary["seed"]},
            {"policy": policy, "originals": {summary["tier"]: {"manifest": binding["original_manifest"]}},
             "schedules": {str(summary["seed"]): {"source_commitment": execution["source_commitment"]}}})
    choice = resource_budget(pilots, max_total_seconds=max_total_seconds, vram_capacity_bytes=vram_capacity_bytes)
    closure = source_closure()
    policy = dict(POLICY, steps=choice["steps"], epochs=choice["steps"] // 8)
    sources = {}
    for seed in SEEDS:
        _, _, source = study.schedule(seed, policy)
        study.exclusive(directory / "schedules" / (str(seed) + ".json"), study.canonical(source))
        sources[str(seed)] = {key: source[key] for key in ("train_wire_sha256", "guard_wire_sha256", "sidecar_sha256")}
        sources[str(seed)]["source_commitment"] = study.digest(study.canonical(source))
    cells = matrix()
    for cell in cells:
        path = RUN / "cells" / cell["id"]
        cell["directory"] = str(path)
        study.init_cell(path, cell["tier"], cell["scope"], cell["seed"], steps=choice["steps"])
        binding = study.bind_cell(path, image_id)
        if binding["source_commitment"] != sources[str(cell["seed"])]["source_commitment"]:
            raise ValueError("Paired frozen schedule differs.")
    originals = {}
    for tier in TIERS:
        payload = (RUN / "initials" / tier / "manifest.json").read_bytes()
        manifest = validate_manifest(parse(payload))
        originals[tier] = {"manifest": study.digest(payload), "blob": manifest["blob"], "source": manifest["source"]}
    plan = {"schema": 1, "study_id": STUDY_ID, "revision": "V3-R1", "cells": cells, "policy": policy,
            "resource_selection": choice, "pilots": [{"directory": str(Path(p).resolve()), "summary_sha256": study.digest((Path(p) / "summary.json").read_bytes())} for p in pilot_cells],
            "image_id": image_id, "host_environment": study.host_environment(), "source_files": closure,
            "source_closure": study.digest(study.canonical(closure)), "server_source_closure": study.source_identity(),
            "git_head_at_freeze": subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True, capture_output=True, check=True).stdout.strip(),
            "originals": originals, "schedules": sources, "endpoints": ENDPOINTS,
            "scoring": "all_18_raw_terminal_candidates_and_3_originals_regardless_of_publication",
            "exports": [{"tier": tier, "scope": "full_encoder", "seed": 42} for tier in TIERS],
            "protected_final_access": False, "promotion": False,
            "interpretation": "reused_development_primary_context320_context64_secondary_binary_hazard_no_fresh_generalization"}
    for name, sha in closure.items():
        study.retain(directory / "source-bytes" / sha, (ROOT / name).read_bytes())
    study.exclusive(directory / "protocol.json", study.canonical(plan))
    return plan


def validate_plan(directory):
    directory = Path(directory)
    plan = read(directory / "protocol.json")
    expected = matrix()
    if plan["study_id"] != STUDY_ID or [{k: cell[k] for k in ("id", "tier", "scope", "seed")} for cell in plan["cells"]] != expected:
        raise ValueError("Exact frozen 18-cell plan required.")
    if plan["source_files"] != source_closure() or plan["host_environment"] != study.host_environment() or plan["endpoints"] != ENDPOINTS:
        raise ValueError("Frozen source/environment/endpoints changed.")
    for cell in plan["cells"]:
        path = Path(cell["directory"])
        binding = read(path / "cell.json")
        execution = study.check_binding(path)
        if (any(binding[key] != cell[key] for key in ("tier", "scope", "seed")) or read(path / "policy.json") != plan["policy"]
                or binding["original_manifest"] != plan["originals"][cell["tier"]]["manifest"]
                or execution["image_id"] != plan["image_id"]
                or execution["source_commitment"] != plan["schedules"][str(cell["seed"])]["source_commitment"]):
            raise ValueError("Frozen cell binding differs from protocol.")
        for name, key in (("model.safetensors", "blob"), ("manifest.json", "manifest")):
            if study.digest((RUN / "initials" / cell["tier"] / name).read_bytes()) != plan["originals"][cell["tier"]][key]:
                raise ValueError("Independently pinned ORIGINAL bytes changed.")
    return plan


def stop(cell):
    result = study.compose(Path(cell), "stop", "fuzzer", "runtime", "checkpoint")
    if result.returncode: raise RuntimeError("Owned v3 service stop failed: " + result.stderr)


def run_plan(directory):
    """Each cell has one durable reservation. Resume requires known reconciliation."""
    plan = validate_plan(directory)
    completed = []
    for cell in plan["cells"]:
        path = Path(cell["directory"])
        if (path / "summary.json").exists():
            audit_cell(cell, plan)
            completed.append(cell["id"])
            continue
        if (path / "host-dispatch.pb").exists():
            raise ValueError("Reserved cell without terminal audit: reconcile " + cell["id"] + " before continuing.")
        try:
            study.start(path)
            study.cycle(path)
            audit_cell(cell, plan)
            completed.append(cell["id"])
        finally:
            stop(path)
    study.retain(Path(directory) / "fit-completion.json", study.canonical({"completed": completed, "physical_attempts": 18}))
    return completed


def audit_cell(cell, plan):
    from checkpoint_store import CheckpointStore
    path = Path(cell["directory"])
    summary = read(path / "summary.json")
    manifest_bytes = (path / "terminal-manifest.json").read_bytes()
    manifest = validate_manifest(parse(manifest_bytes))
    evidence = validate_execution(read(path / "terminal-evidence.json"))
    request = study.parameters_pb2.FuzzerTrainingRequest.FromString((path / "host-dispatch.pb").read_bytes())
    receipt = study.pb.Receipt.FromString((path / "host-receipt.pb").read_bytes())
    sha = study.digest(manifest_bytes)
    if (summary["candidate"] != sha or manifest["blob"] != study.digest((path / "terminal-candidate.safetensors").read_bytes())
            or manifest["evidence"] != study.digest((path / "terminal-evidence.json").read_bytes())
            or evidence["request_id"] != request.request_id or receipt.request_id != request.request_id
            or receipt.candidate != sha or receipt.status not in ("applied", "rejected")
            or summary["status"] != receipt.status or summary["reason"] != receipt.reason
            or evidence["policy"] != plan["policy"] or evidence["source_commitment"] != plan["schedules"][str(cell["seed"])]["source_commitment"]
            or manifest["parent"] != plan["originals"][cell["tier"]]["manifest"]
            or manifest["scope"] != cell["scope"] or manifest["tier"] != cell["tier"]):
        raise ValueError("Retained terminal cell identity/work differs from protocol.")
    store = CheckpointStore(path / "checkpoint")
    try:
        store.admit_candidate(manifest)
        if store.status(request.request_id) != {key: getattr(receipt, key) for key in ("status", "request_id", "model_id", "base", "candidate", "reason")}:
            raise ValueError("Durable publication receipt differs from retained host receipt.")
        expected = sha if receipt.status == "applied" else manifest["parent"]
        if store.resolve(manifest["model_id"]) != expected or summary["published"] != expected:
            raise ValueError("Effective serving pointer differs from terminal audit.")
    finally:
        store.db.close()
    return {"manifest": sha, "publication_status": receipt.status, "guard_passed": publication_passes(evidence),
            "effective": summary["published"], "work": evidence["counts"], "seconds": evidence["seconds"], "cuda_peak_bytes": evidence["cuda_peak_bytes"]}


def candidates_for_scoring(plan):
    candidates = []
    for cell in plan["cells"]:
        audit = audit_cell(cell, plan)
        candidates.append({"name": cell["id"], "directory": cell["directory"], "snapshot": audit["manifest"], **audit})
    for tier in TIERS:
        cell = next(c for c in plan["cells"] if c["tier"] == tier and c["scope"] == "heads" and c["seed"] == 42)
        candidates.append({"name": "original-" + tier, "directory": cell["directory"], "snapshot": plan["originals"][tier]["manifest"], "publication_status": "original_control"})
    return candidates


def score_plan(directory):
    directory = Path(directory); plan = validate_plan(directory)
    candidates = candidates_for_scoring(plan)
    study.retain(directory / "endpoint-candidates.json", study.canonical(candidates))
    for candidate in candidates:
        output = directory / "endpoints" / candidate["name"]
        if (output / "complete.json").exists(): continue
        path = Path(candidate["directory"])
        try:
            study.start(path, output=output / "startup", roles=("checkpoint", "runtime"))
            with study.channel("127.0.0.1:50173") as connection:
                manifest = validate_manifest(parse(study.fetch(study.rpc.CheckpointServiceStub(connection), candidate["snapshot"])))
            with study.channel("127.0.0.1:50171") as connection:
                stub = study.runtime_pb2_grpc.PrivokeRuntimeServiceStub(connection)
                summaries = {kind: score_endpoint(stub, manifest, candidate["snapshot"], kind, item, output / kind) for kind, item in plan["endpoints"].items()}
            study.exclusive(output / "complete.json", study.canonical({"snapshot": candidate["snapshot"], "summaries": summaries}))
        finally:
            stop(path)
    return analyze_plan(directory)


def analyze_plan(directory):
    directory = Path(directory); plan = validate_plan(directory)
    candidates = candidates_for_scoring(plan)
    if len(candidates) != 21: raise ValueError("All 18 raw candidates plus three ORIGINAL controls required.")
    counts, records = {}, {}
    for candidate in candidates:
        output = directory / "endpoints" / candidate["name"]
        complete = read(output / "complete.json")
        if complete["snapshot"] != candidate["snapshot"]: raise ValueError("Endpoint model differs from terminal candidate.")
        manifest_path = Path(candidate["directory"]) / "terminal-manifest.json" if not candidate["name"].startswith("original-") else RUN / "initials" / candidate["name"].removeprefix("original-") / "manifest.json"
        manifest = validate_manifest(read(manifest_path))
        records[candidate["name"]] = {kind: audit_endpoint_records(manifest, candidate["snapshot"], kind, item, output / kind) for kind, item in ENDPOINTS.items()}
        counts[candidate["name"]] = {kind: summarize_records(rows, kind) for kind, rows in records[candidate["name"]].items()}
        if counts[candidate["name"]] != complete["summaries"]: raise ValueError("Scoring aggregate differs from retained actual case records.")
        for kind, item in ENDPOINTS.items():
            if len(records[candidate["name"]][kind]) != item["rows"]:
                raise ValueError("Missing requested endpoint case records.")
    full_minus_heads, candidate_minus_original, effective = {}, {}, {}
    for cell in plan["cells"]:
        name = cell["id"]; original = "original-" + cell["tier"]
        candidate_minus_original[name] = {kind: paired_difference(records[original][kind], records[name][kind], kind) for kind in ENDPOINTS}
        status = next(c for c in candidates if c["name"] == name)["publication_status"]
        effective[name] = {"source": name if status == "applied" else original, "publication_status": status,
                           "counts": counts[name if status == "applied" else original]}
        if cell["scope"] == "full_encoder":
            heads = f"{cell['tier']}-heads-{cell['seed']}"
            full_minus_heads[name] = {kind: paired_difference(records[heads][kind], records[name][kind], kind) for kind in ENDPOINTS}
    result = {"study_id": STUDY_ID, "endpoint_roles": {k: v["role"] for k, v in ENDPOINTS.items()},
              "raw_terminal_counts": counts, "full_minus_heads": full_minus_heads,
              "candidate_minus_original": candidate_minus_original, "effective_publication_results": effective,
              "costs": {c["name"]: {key: c[key] for key in ("work", "seconds", "cuda_peak_bytes")} for c in candidates if not c["name"].startswith("original-")},
              "inference": "descriptive_paired_reused_development_three_seeds_no_independent_generalization"}
    result["full_minus_heads_across_seeds"] = aggregate_seed_differences(full_minus_heads)
    result["candidate_minus_original_across_seeds"] = aggregate_seed_differences(candidate_minus_original)
    result["total_fit_seconds"] = sum(c["seconds"] for c in candidates if not c["name"].startswith("original-"))
    study.retain(directory / "analysis.json", study.canonical(result))
    return result


def aggregate_seed_differences(differences):
    groups = {}
    for name, endpoints in differences.items():
        group = name.rsplit("-", 1)[0]
        groups.setdefault(group, []).append(endpoints)
    result = {}
    for group, seeds in groups.items():
        if len(seeds) != 3: raise ValueError("Three prespecified paired seeds required.")
        result[group] = {}
        for kind in ENDPOINTS:
            result[group][kind] = {}
            for metric in seeds[0][kind]:
                if metric == "action_harms":
                    result[group][kind][metric] = {key: sum(seed[kind][metric][key] for seed in seeds) for key in seeds[0][kind][metric]}
                    continue
                rows = [seed[kind][metric] for seed in seeds]
                denominator = sum(row["denominator"] for row in rows)
                net = sum(row["net_correct"] for row in rows)
                result[group][kind][metric] = {"seed_count": 3, "net_correct": net, "denominator": denominator,
                    "rate_difference": net / denominator if denominator else None,
                    "improved": sum(row["improved"] for row in rows), "regressed": sum(row["regressed"] for row in rows),
                    "note": "same_reused_cases_across_seeds_not_independent_case_replicates"}
    return result


def export_fixed_models(directory):
    directory = Path(directory); plan = validate_plan(directory)
    if not (directory / "analysis.json").exists(): raise ValueError("Complete 21-model endpoint audit precedes export.")
    exports = []
    for tier in TIERS:
        cell = next(c for c in plan["cells"] if c["tier"] == tier and c["scope"] == "full_encoder" and c["seed"] == 42)
        path = Path(cell["directory"]); audit = audit_cell(cell, plan)
        target = RUN / "final-models" / tier
        for source, name in ((path / "terminal-candidate.safetensors", "model.safetensors"),
                             (path / "terminal-manifest.json", "manifest.json"),
                             (path / "terminal-evidence.json", "training-evidence.json"),
                             (RUN / "initials" / tier / "config.json", "config.json"),
                             (RUN / "initials" / tier / "vocab.txt", "vocab.txt")):
            study.retain(target / name, source.read_bytes())
        record = {"selection": "predeclared_FULL_seed42_no_best_seed_selection", "tier": tier, "cell": cell["id"],
                  "candidate": audit["manifest"], "publication_status": audit["publication_status"], "guard_passed": audit["guard_passed"],
                  "source_directory": str(path), "export_directory": str(target), "protocol_sha256": study.digest((directory / "protocol.json").read_bytes()),
                  "promotion": False, "all_other_cells_retained": True}
        study.retain(target / "export.json", study.canonical(record)); exports.append(record)
    study.retain(directory / "exports.json", study.canonical(exports))
    return exports
