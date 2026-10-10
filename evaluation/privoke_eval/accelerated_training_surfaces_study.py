"""Fixed-budget all-surface supervisor; fitting is gated by a hash-bound approval."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import importlib
import json
import math
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = "accelerated-training-surfaces-v1"
SEEDS = (42, 43, 44)
TINY = ("baseline", "efficient", "balanced", "quality")
PROFILES = ("efficient", "balanced", "quality")
SCOPES = ("heads", "last_block", "full_encoder")
OBJECTIVES = ("class_balanced_contextual_v1", "class_balanced_contextual_mean_category_v1", "class_balanced_contextual_decision_margin_v1")
OPTIMIZERS = ("local_sgd_1_v1", "local_sgd_4_v1")
DEFAULTS = {"learning_rate": .03, "max_gradient": .05, "transforms_per_example": 1,
            "heldout_count": 16, "minimum_exact_match_rate": 0., "prompt_count": 32}
SERVICES = ("model-streaming-service", "param-update-service", "client-runtime", "privoke-fuzzer")
IDENTITY = ("model_id", "model_version", "artifact_checksum", "parameter_fingerprint")


def canonical(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def read(path):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("Duplicate JSON key")
            result[key] = value
        return result
    return json.loads(Path(path).read_bytes(), object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Non-finite JSON")))


def write(path, value, *, immutable=False):
    path = Path(path)
    raw = canonical(value)
    if immutable and path.exists():
        if path.read_bytes() != raw:
            raise ValueError(f"Immutable evidence changed: {path.name}")
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as stream:
        temporary = Path(stream.name)
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def matrix(study_id):
    cells = []
    def add(group, profile, surface, scope, *, sampling="procedural", objective=None, optimizer=None, label=None):
        for seed in SEEDS:
            key = f"{group}-{profile}-{label or scope}-{seed}"
            model = (f"privoke-{profile}" if surface == "tiny" else
                     f"privoke-presence-{profile}" if surface == "sparse_presence" else
                     f"privoke-scratch-presence-{profile}-{'head-only' if scope == 'heads' else 'full-encoder'}" if surface == "scratch_presence" else
                     "privoke-pretrained-context-minilm")
            kind = "offline" if group.startswith("offline") else "online"
            cells.append({"id": key, "kind": kind, "group": group, "profile": profile,
                "surface": surface, "model_id": model, "scope": scope, "seed": seed,
                "sampling": sampling, "objective": ("binary_presence" if surface in ("sparse_presence", "scratch_presence") else "contextual") if kind == "offline" else objective,
                "optimizer": ("lbfgs" if surface == "sparse_presence" else "numpy_float64_adam_coupled_l2_after_global_clip_v1" if surface in ("minilm","random_control") else "Adam") if kind == "offline" else optimizer,
                "project": f"{study_id}-{key}" if kind == "online" else None,
                "stage_slots": 96 if kind == "online" else None,
                "cycles": 48 if scope == "dual" else 96 if kind == "online" else None,
                "optimizer_steps": None if surface == "sparse_presence" and kind == "offline" else 96 if kind == "offline" else None,
                "batch_size": 16 if surface == "scratch_presence" else 32,
                "solver_budget": {"solver":"lbfgs","max_iter":1000,"tol":.0001,"C":1.0,"class_weight":"balanced"} if surface == "sparse_presence" and kind == "offline" else None})
    for profile in TINY:
        for scope in (*SCOPES, "dual"):
            add("main", profile, "tiny", scope)
    for scope in SCOPES:
        for index, objective in enumerate(OBJECTIVES):
            add("objective", "balanced", "tiny", scope, objective=objective, label=f"{scope}-o{index}")
        for index, optimizer in enumerate(OPTIMIZERS):
            add("optimizer", "balanced", "tiny", scope, objective=OBJECTIVES[1], optimizer=optimizer, label=f"{scope}-p{index}")
    for scope in ("heads", "full_encoder", "dual"):
        add("curriculum", "balanced", "tiny", scope, sampling="curriculum")
    for profile in TINY:
        for scope in ("heads", "full_encoder"):
            add("offline-tiny", profile, "tiny", scope)
    for profile in PROFILES:
        add("online-presence", profile, "sparse_presence", "heads")
        add("offline-presence", profile, "sparse_presence", "heads")
        for scope in ("heads", "full_encoder"):
            add("offline-scratch", profile, "scratch_presence", scope)
    for surface in ("minilm", "random_control"):
        add("offline-representation", "balanced", surface, "heads", label=surface)
    if len(cells) != 168 or sum(c["kind"] == "online" for c in cells) != 111 or len({c["id"] for c in cells}) != 168:
        raise ValueError("Study matrix mismatch")
    for cell in cells:
        if cell["kind"]=="online":
            seeds=[cell["seed"]+(slot//2 if cell["scope"]=="dual" else slot) for slot in range(96)]
            cell["stage_seed_plan_sha256"]=digest(seeds)
        cell["seed_role"]="batch order only; scratch initialization fixed12102026" if cell["surface"]=="scratch_presence" else "nominal replicate; lbfgs may be deterministic" if cell["surface"]=="sparse_presence" and cell["kind"]=="offline" else "fixed training/order realization"
    return cells


def file_commitment(path):
    path = Path(path).resolve(strict=True)
    # Protected final material is never an input to this supervisor.
    if any("final" in part.lower() and "artifact" not in part.lower() for part in path.parts):
        raise ValueError("Protected/final paths are not permitted study inputs")
    return {"path": str(path), "sha256": sha(path)}


def verify_files(value):
    if isinstance(value, dict):
        if "path" in value and "sha256" in value:
            if file_commitment(value["path"])["sha256"] != value["sha256"]:
                raise ValueError("Frozen input bytes changed")
        for nested in value.values():
            verify_files(nested)
    elif isinstance(value, list):
        for nested in value:
            verify_files(nested)


def source_inventory():
    prefixes = ("evaluation/privoke_eval", "services/privoke-fuzzer/src", "services/param-update-service/app",
                "extension/client-runtime/src", "shared/python", "shared/proto", "models")
    result = {}
    for prefix in prefixes:
        for path in sorted((ROOT / prefix).rglob("*")):
            if path.is_file() and "__pycache__" not in path.parts and path.suffix in (".py", ".proto", ".json"):
                result[path.relative_to(ROOT).as_posix()] = sha(path)
    for name in ("evaluation/run-accelerated-training-surfaces-study.py", "evaluation/host_environment.py", "evaluation/compose.accelerated-training-surfaces.yml", "evaluation/run-accelerated-training-surfaces-worker.py", "evaluation/Dockerfile.accelerated-training-surfaces-worker", "evaluation/requirements-accelerated-training-surfaces.txt"):
        result[name] = sha(ROOT / name)
    return dict(sorted(result.items()))


def command(args, **kwargs):
    return subprocess.run([str(v) for v in args], check=True, capture_output=True, text=True, **kwargs).stdout


def revision():
    result = command(["git", "-C", ROOT, "rev-parse", "HEAD"]).strip()
    if command(["git", "-C", ROOT, "status", "--porcelain", "--untracked-files=normal"]).strip():
        raise ValueError("Commit computation sources before protocol preparation")
    return result


def assessment_inventory(inputs):
    result = {}
    for task in ("context", "presence"):
        item = inputs["assessments"][task]
        rows = [json.loads(line) for line in Path(item["path"]).read_text(encoding="utf-8").splitlines() if line.strip()]
        ids = [r["id"] for r in rows]
        if len(rows) != 320 or len(set(ids)) != 320 or any(not r.get("group_id", r.get("family_id")) for r in rows):
            raise ValueError("Fresh primary assessment requires 320 unique grouped rows")
        result[task] = {"rows": len(rows), "ids_sha256": digest(sorted(ids)), "sha256": item["sha256"]}
    receipt = inputs["assessment_review"]
    if receipt.get("status") != "accepted" or receipt.get("assessment_hashes") != {k: v["sha256"] for k,v in result.items()}:
        raise ValueError("Independent assessment review and exclusion receipt required")
    if receipt.get("training_overlap") != 0 or receipt.get("guard_overlap") != 0:
        raise ValueError("Assessment leakage audit failed")
    return result


def prepare(output, config, study_id):
    if not re.fullmatch(r"privoke-all-surfaces-[a-z0-9-]+", study_id):
        raise ValueError("Unique privoke-all-surfaces- project prefix required")
    config = read(config)
    verify_files(config)
    images = config["images"]
    if set(images) != set(SERVICES) or any(not re.fullmatch(r"sha256:[0-9a-f]{64}", v) for v in images.values()):
        raise ValueError("Exactly four immutable service image identities required")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}",config["offline_worker_image"]):raise ValueError("Immutable offline worker image required")
    protocol = {"schema_version": SCHEMA, "study_id": study_id, "source_revision": revision(),
        "source_files": source_inventory(), "cells": matrix(study_id), "settings": DEFAULTS,
        "offline_worker_image":config["offline_worker_image"], "offline_worker_attestation":config["offline_worker_attestation"],
        "inputs": config["inputs"], "images": images, "image_attestation": config["image_attestation"],
        "ports": config["ports"], "checkpoint_slots": [0, 32, 64, 96], "concurrency": 2,
        "assessment_inventory": assessment_inventory(config["inputs"]),
        "training_cohort_policy":{"sparse_presence_offline_rows":3832,"scratch_presence_offline_rows":3684,"scratch_shared_native_admission_cap":64,"different_cohorts_require_disclosure":True},
        "secondary_fixture_context":"historical_text_only_replay_v1; visibility hints omitted uniformly; action targets retained as transfer targets",
        "qualification_rules":{"context":"context_joint16of160_12of120_union_tolerances3_2_3_action_v1","presence":"presence_specificity8of160_recall144of160_allseed_v1","seed_aggregation":"same>=2of3 pass gain thresholds; every seed passes explicit vetoes; deterministic sparse solver duplicates not stochastic corroboration"},
        "objective": "Now that these things have been refactored, run accelerated fuzzer training rounds on all models and then test them to see how they have improved. This should cover all training surfaces.",
        "objective_attribution": "active goal objective; not a verified verbatim quotation",
        "analysis": {"fixed_final_only": True, "bootstrap_iterations": 2000, "bootstrap_seed": 10102026,
            "decision": "per-cell improvement and harms; no global improvement unless every eligible cell qualifies",
            "no_promotion": True, "assessment_blind_to_fitters": True}}
    all_ports=[v+offset for v in protocol["ports"].values() for offset in (0,100)]
    if len(set(all_ports)) != 8 or any(type(v) is not int or not 1024 <= v <= 65535 for v in all_ports):
        raise ValueError("Four distinct unprivileged localhost ports required")
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    write(output / "protocol.json", protocol, immutable=True)
    write(output / "supervisor.json", {"status": "prepared", "protocol_sha256": sha(output / "protocol.json"), "cells": {}})
    return protocol


def verify_protocol(output, *, execution=False):
    output = Path(output)
    protocol, state = read(output / "protocol.json"), read(output / "supervisor.json")
    if (protocol["schema_version"] != SCHEMA or protocol["cells"] != matrix(protocol["study_id"])
            or protocol["settings"] != DEFAULTS or state["protocol_sha256"] != sha(output / "protocol.json")
            or protocol["source_files"] != source_inventory() or protocol["source_revision"] != revision()):
        raise ValueError("Frozen matrix/settings/source/protocol differs")
    verify_files(protocol["inputs"])
    verify_review_gates(protocol)
    if assessment_inventory(protocol["inputs"]) != protocol["assessment_inventory"]:
        raise ValueError("Assessment review differs")
    if execution:
        approval = read(output / "approval.json")
        if (approval.get("status") != "accepted" or approval.get("protocol_sha256") != sha(output / "protocol.json")
                or approval.get("assessment_inventory") != protocol["assessment_inventory"] or state["status"] != "frozen"):
            raise ValueError("Root protocol and labels acceptance required before any fitting/scoring")
    return protocol, state


def freeze(output, approval):
    protocol, state = verify_protocol(output)
    accepted = read(approval)
    if accepted.get("status") != "accepted" or accepted.get("protocol_sha256") != sha(Path(output)/"protocol.json") or accepted.get("assessment_inventory") != protocol["assessment_inventory"]:
        raise ValueError("Approval does not bind exact protocol and assessments")
    attest = protocol["image_attestation"]
    if attest.get("images") != protocol["images"] or attest.get("source_files") != protocol["source_files"] or attest.get("status") != "passed":
        raise ValueError("Source-compatible image attestation required")
    worker=protocol["offline_worker_attestation"]
    if worker.get("status")!="passed" or worker.get("image")!=protocol["offline_worker_image"] or worker.get("source_files")!=protocol["source_files"] or not worker.get("dependencies") or not worker.get("linux_adapter_tests_passed") or worker.get("requirements_sha256")!=protocol["source_files"]["evaluation/requirements-accelerated-training-surfaces.txt"] or worker.get("recipe_sha256")!=protocol["source_files"]["evaluation/Dockerfile.accelerated-training-surfaces-worker"] or not worker.get("pip_freeze_sha256") or not worker.get("pip_check_passed"):
        raise ValueError("Pinned Linux offline worker attestation required")
    write(Path(output)/"approval.json", accepted, immutable=True)
    state["status"] = "frozen"
    write(Path(output)/"supervisor.json", state)


def prepare_base(cell, inputs, destination, source_revision):
    from privoke_model.artifact import load_artifact
    from privoke_model.contextual_training import (prepare_full_encoder_artifact, prepare_contextual_training_artifact,
        prepare_training_objective_artifact, prepare_training_optimizer_artifact, LAST_BLOCK_STRATEGY)
    item = inputs["base_artifacts"][cell["model_id"]]
    artifact = load_artifact(item["path"])
    if cell["surface"] == "tiny":
        artifact = prepare_full_encoder_artifact(artifact, version="as10-base-"+cell["id"],
            generated_at_unix=1791590400, source_revision=source_revision, max_tokens=256)
        if cell["scope"] == "last_block":
            artifact = prepare_contextual_training_artifact(artifact, LAST_BLOCK_STRATEGY)
        artifact = prepare_training_objective_artifact(artifact, cell["objective"] if cell["kind"]=="online" else None)
        artifact = prepare_training_optimizer_artifact(artifact, cell["optimizer"] if cell["kind"]=="online" else None)
    write(destination, artifact, immutable=True)
    return artifact


def validate_tensor_transition(before, after, allowed, *, accepted):
    if set(before["parameters"]) != set(after["parameters"]):
        raise ValueError("Tensor inventory changed")
    changed = []
    for name, tensor in before["parameters"].items():
        actual = after["parameters"][name]
        if tensor["shape"] != actual["shape"] or len(actual["values"]) != math.prod(actual["shape"]):
            raise ValueError("Tensor shape/length changed")
        if any(type(v) not in (float,int) or not math.isfinite(v) for v in actual["values"]):
            raise ValueError("Non-finite tensor")
        if tensor["values"] != actual["values"]:
            changed.append(name)
    if set(changed) - set(allowed):
        raise ValueError("Training changed a frozen tensor")
    if not accepted and (changed or before["identity"] != after["identity"]):
        raise ValueError("Rejected attempt changed serving state")
    if accepted and (before["identity"]["model_version"] == after["identity"]["model_version"]):
        raise ValueError("Accepted publication has no distinct version")
    return changed


def allowed_tensors(cell, artifact):
    from privoke_model.contextual_training import HEAD_NAMES, contextual_trainable_names, LAST_BLOCK_STRATEGY, FULL_ENCODER_STRATEGY
    if cell["surface"] == "sparse_presence":
        return sorted(n for n in artifact["parameters"] if n.startswith("head.presence."))
    strategy = LAST_BLOCK_STRATEGY if cell["scope"] == "last_block" else FULL_ENCODER_STRATEGY if cell["scope"] in ("full_encoder", "dual") else None
    return sorted(contextual_trainable_names(artifact["config"], strategy) if strategy else HEAD_NAMES)


def automation_module():
    path = str(ROOT / "services/param-update-service/app")
    if path not in sys.path:
        sys.path.insert(0, path)
    return importlib.import_module("fuzzer_requests")


def measure_context(client, rows, cell, identity, tag):
    from privoke_eval.continual_fuzzer_study import require_semantic_execution, LayerIsolationError
    predictions=[]
    for row in rows:
        record={"id":row["id"],"group_id":row.get("group_id",row.get("family_id")),
            "target":row["classification"],"allowed_actions":row.get("allowed_actions") or [target_action(row["classification"])],"quantitative":row.get("quantitative",True)}
        try:
            admit_network_text(row["text"],cell)
            value=client.analyze(row,cell["model_id"],"semantic",digest([tag,row["id"]])[:40])
            require_semantic_execution(value["raw"])
            if not value["identities"] or any(v!=identity for v in value["identities"]):
                raise LayerIsolationError("Semantic response lacks exact pinned identity")
            record.update(status="ok",classification=value["raw"]["classification"],action=value["raw"]["action"],
                execution_mode="network_protobuf_v1",raw=value["raw"],identities=value["identities"])
        except LayerIsolationError:
            raise
        except Exception as exc:
            record.update(status="error",error=str(exc))
        predictions.append(record)
    return {"semantic":{"predictions":predictions}}


def rows(item):
    if sha(item["path"]) != item["sha256"]:
        raise ValueError("Endpoint bytes changed")
    return [json.loads(line) for line in Path(item["path"]).read_text(encoding="utf-8").splitlines() if line.strip()]


def checkpoint(client, protocol, cell, directory, slot, snapshot):
    write(directory/f"snapshot-{slot:03d}.json",snapshot,immutable=True)
    if slot not in (0,96):return
    destination = directory / f"assessment-{slot:03d}.json"
    if destination.exists():
        if read(destination)["identity"] != snapshot["identity"]:
            raise ValueError("Cannot remeasure archived checkpoint on changed artifact")
        return
    collected={}
    for name,task,data in endpoint_specs(protocol,cell):
        if task=="context":
            measured=measure_context(client,data,cell,snapshot["identity"],f"{cell['id']}:{slot}:{name}")
        elif cell["surface"] in ("sparse_presence","scratch_presence"):
            from privoke_eval.accelerated_training_surfaces_presence import measure_presence
            measured=measure_presence(client,data,cell,snapshot["identity"])
        else:
            measured=measure_binary_proxy(client,data,cell,snapshot["identity"],f"{cell['id']}:{slot}:{name}")
        collected[name]={"task":task,"layers":measured}
    if client.snapshot(cell["model_id"])["identity"]!=snapshot["identity"]:
        raise ValueError("Model changed during immutable checkpoint")
    primary=collected["primary"]
    write(destination,{"slot":slot,"identity":snapshot["identity"],"task":primary["task"],"layers":primary["layers"],
        "endpoints":collected,"execution_mode":"network_protobuf_v1"},immutable=True)


def run_online(client, protocol, cell, directory, artifact):
    """Use the actual public automatic requester, with synchronous stage snapshots."""
    from google.protobuf.json_format import MessageToDict
    from privoke.v1 import parameters_pb2 as PP
    module = automation_module()
    initial_path = directory / "snapshot-000.json"
    initial = read(initial_path) if initial_path.exists() else client.snapshot(cell["model_id"])
    if not initial_path.exists():
        if initial["identity"]["model_id"]!=cell["model_id"] or initial["parameters"]!=wire_parameters(artifact):
            raise ValueError("Fresh serving base differs from prepared artifact")
    write(initial_path, initial, immutable=True)
    checkpoint(client, protocol, cell, directory, 0, initial)
    stages = ("heads", "full_encoder") if cell["scope"] == "dual" else ("full_encoder",) if cell["scope"] == "full_encoder" else ("heads",)
    config = module.FuzzerRequestConfig(target=f"127.0.0.1:{protocol['ports']['fuzzer']}", prompt_count=32,
        model_id=cell["model_id"], source_id=cell["project"], timeout_seconds=300, interval_seconds=0,
        initial_delay_seconds=0, retry_seconds=2, max_attempts=3, seed=cell["seed"],
        train_underlying=cell["scope"] in ("full_encoder","dual"), state_path=str(directory/"training-cycles.sqlite3"))
    allowed = allowed_tensors(cell, artifact)
    def observe(cycle, stage, event):
        slot = cycle["sequence"] * len(stages) + stages.index(stage) + 1
        path = directory / f"stage-{slot:03d}.json"
        current = client.snapshot(cell["model_id"])
        pending = directory / f"pending-{slot:03d}.json"
        value = cycle["stages"][stage]
        if event == "pending":
            if pending.exists():
                if read(pending)["request_hex"] != value["request_protobuf_hex"]:
                    raise ValueError("Pending request commitment changed")
            else:
                write(pending, {"request_hex":value["request_protobuf_hex"], "base":current}, immutable=True)
            return
        if path.exists():
            saved = read(path)
            if saved["request_hex"] != value["request_protobuf_hex"]:
                raise ValueError("Archived stage request differs on resume")
            if slot in protocol["checkpoint_slots"] and not (directory/f"{'assessment' if slot in (0,96) else 'snapshot'}-{slot:03d}.json").exists():
                if current["identity"]!=saved["snapshot"]["identity"]:
                    raise ValueError("Cannot resume missing checkpoint on a changed artifact")
                checkpoint(client,protocol,cell,directory,slot,current)
            return
        before = read(pending)["base"]
        accepted = event == "accepted"
        stage_allowed = allowed
        if cell["scope"] == "dual" and stage == "heads":
            from privoke_model.contextual_training import HEAD_NAMES
            stage_allowed = HEAD_NAMES
        changed = validate_tensor_transition(before, current, stage_allowed, accepted=accepted)
        response = None
        if accepted:
            wire = PP.FuzzerTrainingResponse.FromString(bytes.fromhex(value["response_protobuf_hex"]))
            response = MessageToDict(wire, preserving_proto_field_name=True)
            if wire.base_version != before["identity"]["model_version"] or wire.applied_version != current["identity"]["model_version"]:
                raise ValueError("Publication response/snapshot chain mismatch")
        write(path, {"slot":slot,"stage":stage,"state":event,"cycle":cycle,"request_hex":value["request_protobuf_hex"],
            "response":response,"before_identity":before["identity"],"snapshot":current,"changed_names":changed}, immutable=True)
        if cell["scope"] == "dual" and stage == "heads" and not accepted:
            write(directory/f"stage-{slot+1:03d}.json", {"slot":slot+1,"stage":"full_encoder","state":"skipped_head_rejection",
                "snapshot":current,"before_identity":current["identity"],"changed_names":[]}, immutable=True)
            if slot+1 in protocol["checkpoint_slots"]:
                checkpoint(client,protocol,cell,directory,slot+1,current)
        if slot in protocol["checkpoint_slots"]:
            import time
            time.sleep(2.1)
            checkpoint(client,protocol,cell,directory,slot,current)
    if cell["surface"] == "sparse_presence":
        from privoke_eval.accelerated_training_surfaces_presence import run_presence
        return run_presence(client, protocol, cell, directory, artifact, checkpoint)
    module.request_fuzzer_loop(config, cycles=cell["cycles"], stages=stages,
        stage_observer=observe, request_metadata={"study_gate_diagnostics":"v1"})


def offline_inputs(protocol, cell):
    entry = protocol["inputs"]["offline"][cell["surface"]]
    result = dict(entry.get("profiles",{}).get(cell["profile"],entry))
    result["source_revision"] = protocol["source_revision"]
    # Assessment paths and scores never enter the train-only adapter.
    if any(key in result for key in ("assessments", "assessment", "validation", "test")):
        raise ValueError("Offline fitter received an assessment surface")
    verify_files(result)
    expected={"sparse_presence":3832,"scratch_presence":3684}.get(cell["surface"])
    if expected is not None and len(rows(result["train"]))!=expected:
        raise ValueError("Frozen native binary TRAIN cohort size differs")
    return result


def validate_offline(result, cell):
    if result.get("schema_version") != "accelerated-offline-fit-v1" or result.get("status") != "complete" or result.get("cell_id") != cell["id"]:
        raise ValueError("Offline adapter did not complete the declared cell")
    for name in ("baseline_artifact", "final_artifact"):
        if sha(result[name]["path"]) != result[name]["sha256"]:
            raise ValueError("Offline immutable artifact mismatch")
    dose = result["dose"]
    if cell["surface"] == "sparse_presence":
        if dose["optimizer_steps"] is not None or not dose["solver_budget"]:
            raise ValueError("Native sparse fit needs explicit separate solver budget")
    elif dose["optimizer_steps"] != 96 or dose["presentations"] != 96*cell["batch_size"]:
        raise ValueError("Offline neural fixed budget changed")
    if cell["scope"] == "heads" and not result["tensor_audit"]["encoder_unchanged"]:
        raise ValueError("Offline head fit changed the encoder/representation")


def _execute(output, cell_id):
    protocol, supervisor = verify_protocol(output, execution=True)
    cell = next(c for c in protocol["cells"] if c["id"] == cell_id)
    protocol=effective_protocol(protocol,cell)
    directory = Path(output)/"cells"/cell_id
    directory.mkdir(parents=True, exist_ok=True)
    if (directory/"complete.json").exists():
        from privoke_eval.accelerated_training_surfaces_report import audit_cell
        saved=read(directory/"complete.json")
        if audit_cell(directory,cell,protocol)!=saved:raise ValueError("Completed archive changed")
        return saved
    if cell["kind"] == "offline":
        train_inputs = offline_inputs(protocol,cell)
        if cell["surface"] in ("tiny","random_control"):
            base_cell=cell | {"surface":"tiny","model_id":cell["model_id"] if cell["surface"]=="tiny" else "privoke-balanced","objective":None,"optimizer":None}
            base_path=directory/"prepared-base.json"
            prepare_base(base_cell,protocol["inputs"],base_path,protocol["source_revision"])
            train_inputs["base_artifact"]={"path":str(base_path),"sha256":sha(base_path)}
        result = offline_worker(protocol,cell,train_inputs,directory,"fit")
        validate_offline(result,cell)
        write(directory/"fit-receipt.json",result,immutable=True)
        task = "presence" if cell["surface"] in ("sparse_presence","scratch_presence") else "context"
        for slot, name in ((0,"baseline_artifact"),(96,"final_artifact")):
            item=result[name];collected={}
            for endpoint,endpoint_task,data in endpoint_specs(protocol,cell):
                evaluated=offline_worker(protocol,cell,{"snapshot":item,"rows":data,"assets":train_inputs.get("assets")},directory,f"score-{slot:03d}-{endpoint}")
                measured=normalize_offline(evaluated,data,item,endpoint_task)
                collected[endpoint]={"task":endpoint_task,"layers":{"semantic":{"predictions":measured["predictions"]}}}
            primary=collected["primary"]
            write(directory/f"assessment-{slot:03d}.json",{"slot":slot,"task":task,"identity":measured["identity"],
                "execution_mode":"offline_learned_forward_v1","snapshot_sha256":item["sha256"],
                "layers":primary["layers"],"endpoints":collected},immutable=True)
        native_serving_parity(protocol,cell,directory,result)
        from privoke_eval.accelerated_training_surfaces_report import audit_cell
        receipt=audit_cell(directory,cell,protocol)
        write(directory/"complete.json",receipt,immutable=True)
        update_supervisor(output,cell_id,sha(directory/"complete.json"))
        return receipt
    artifact = prepare_base(cell,protocol["inputs"],directory/"catalog"/(cell["model_id"]+".json"),protocol["source_revision"])
    compose, env = compose_command(protocol,cell,directory)
    log = directory/"operations.log"
    reserve_resources(compose,env,cell,directory)
    try:
        with log.open("a",encoding="utf-8") as stream:
            subprocess.run(compose+["up","-d","--no-build","--wait","--wait-timeout","180"]+(["--no-deps",*SERVICES] if any(directory.glob("pending-*.json")) else []),env=env,stdout=stream,stderr=subprocess.STDOUT,check=True)
        inspect_operations(compose,env,protocol,cell,directory)
        filesystem_probe(compose,env,directory)
        from privoke_eval.continual_fuzzer_study import RpcClient
        client=RpcClient(f"127.0.0.1:{protocol['ports']['fuzzer']}",f"127.0.0.1:{protocol['ports']['runtime']}",f"127.0.0.1:{protocol['ports']['model']}")
        try:
            run_online(client,protocol,cell,directory,artifact)
        finally:
            client.close()
    finally:
        with log.open("a",encoding="utf-8") as stream:
            subprocess.run(compose+["stop"],env=env,stdout=stream,stderr=subprocess.STDOUT,check=True)
    for service, destination in (("privoke-fuzzer","fuzzer-state"),("param-update-service","update-state")):
        container=command(compose+["ps","-aq",service],env=env).strip()
        target=directory/destination;export_receipt=directory/(destination+"-export.json")
        if target.exists():
            if not export_receipt.exists():raise ValueError("Incomplete state export requires explicit recovery; refusing overwrite")
            inventory={p.relative_to(target).as_posix():sha(p) for p in target.rglob('*') if p.is_file()}
            if read(export_receipt)!=inventory:raise ValueError("Retained state export changed")
        else:
            command(["docker","cp",f"{container}:/data",target])
            write(export_receipt,{p.relative_to(target).as_posix():sha(p) for p in target.rglob('*') if p.is_file()},immutable=True)
    from privoke_eval.accelerated_training_surfaces_report import audit_cell
    receipt=audit_cell(directory,cell,protocol)
    write(directory/"complete.json",receipt,immutable=True)
    update_supervisor(output,cell_id,sha(directory/"complete.json"))
    return receipt


def compose_command(protocol,cell,directory):
    env=dict(os.environ,AS_PROJECT=cell["project"],AS_MODEL_ID=cell["model_id"],AS_CATALOG=str((directory/"catalog").resolve()),
        AS_MODEL_IMAGE=protocol["images"]["model-streaming-service"],AS_RUNTIME_IMAGE=protocol["images"]["client-runtime"],
        AS_FUZZER_IMAGE=protocol["images"]["privoke-fuzzer"],AS_UPDATER_IMAGE=protocol["images"]["param-update-service"])
    env.update({"AS_"+key.upper()+"_PORT":str(value) for key,value in protocol["ports"].items()})
    # Effective resolved Compose settings are retained and validated before RPC.
    override={"services":{"privoke-fuzzer":{"environment":{
        "MODEL_ID":cell["model_id"],"PRESENCE_MODEL_ID":cell["model_id"] if cell["surface"]=="sparse_presence" else "privoke-presence-balanced",
        "FUZZER_ID":cell["project"],"FUZZ_TRAINING_LEARNING_RATE":str(DEFAULTS["learning_rate"]),
        "FUZZ_TRAINING_MAX_GRADIENT":str(DEFAULTS["max_gradient"]),"FUZZ_TRAINING_TRANSFORMS_PER_EXAMPLE":"1",
        "FUZZ_HELDOUT_PROMPT_COUNT":"16","FUZZ_MIN_EXACT_MATCH_RATE":"0.0"}}}}
    if cell["surface"]=="sparse_presence":
        item=protocol["inputs"]["presence_train"]
        override["services"]["privoke-fuzzer"]["volumes"]=[{"type":"bind","source":str(Path(item["path"]).resolve()),"target":"/training/presence.jsonl","read_only":True}]
        override["services"]["privoke-fuzzer"]["environment"]["FUZZ_PRESENCE_DATASET_PATH"]="/training/presence.jsonl"
    if cell["sampling"]=="curriculum":
        item=protocol["inputs"]["curriculum"]
        override["services"]["privoke-fuzzer"].update({"volumes":[{"type":"bind","source":str(Path(item["path"]).parent),"target":"/curriculum","read_only":True}],
            "environment":override["services"]["privoke-fuzzer"]["environment"]|{"FUZZ_CURRICULUM_MANIFEST_PATH":"/curriculum/manifest.json","FUZZ_CURRICULUM_STATE_PATH":"/data/curriculum.sqlite3"}})
    if cell["surface"]=="minilm":
        assets=offline_inputs(protocol,cell)["assets"]
        override["services"]["client-runtime"]={"environment":{"PRIVOKE_PRETRAINED_CONTEXT_DIR":"/assets"},
            "volumes":[{"type":"bind","source":str(Path(assets["model.onnx"]["path"]).parent),"target":"/assets","read_only":True}]}
    if cell["surface"] in ("minilm", "scratch_presence"):
        # These opt-in architectures are deliberately forbidden as latest.
        # Every scored RPC still names the experimental artifact explicitly.
        override["services"]["model-streaming-service"]={"environment":{"MODEL_LATEST_ID":"privoke-balanced"}}
    path=directory/"compose.json";write(path,override,immutable=True)
    return ["docker","compose","-p",cell["project"],"-f",str(ROOT/"evaluation/compose.accelerated-training-surfaces.yml"),"-f",str(path)],env


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    sub=parser.add_subparsers(dest="operation",required=True)
    render=sub.add_parser("render-assessment");render.add_argument("--raw",type=Path,required=True);render.add_argument("--task",choices=("context","presence"),required=True);render.add_argument("--output",type=Path,required=True)
    plan=sub.add_parser("plan");plan.add_argument("--study-id",required=True);plan.add_argument("--output",type=Path,required=True)
    prep=sub.add_parser("prepare");prep.add_argument("--study-id",required=True);prep.add_argument("--config",type=Path,required=True);prep.add_argument("--output",type=Path,required=True)
    fr=sub.add_parser("freeze");fr.add_argument("--output",type=Path,required=True);fr.add_argument("--approval",type=Path,required=True)
    ex=sub.add_parser("execute");ex.add_argument("--output",type=Path,required=True);ex.add_argument("--cell",required=True)
    for name in ("preflight","audit","report"):
        sub.add_parser(name).add_argument("--output",type=Path,required=True)
    args=parser.parse_args(argv)
    if args.operation=="render-assessment":
        receipt=render_fresh_assessment(args.raw,args.task,args.output)
        write(args.output.with_suffix('.rendition.json'),receipt,immutable=True)
    elif args.operation=="plan":write(args.output,{"schema_version":SCHEMA,"cells":matrix(args.study_id)},immutable=True)
    elif args.operation=="prepare":prepare(args.output,args.config,args.study_id)
    elif args.operation=="freeze":freeze(args.output,args.approval)
    elif args.operation=="execute":
        execute_all(args.output) if args.cell=="all" else execute(args.output,args.cell)
    elif args.operation=="preflight":preflight(args.output)
    else:
        from privoke_eval.accelerated_training_surfaces_report import report
        report(args.output,summary=args.operation=="report")
    return 0

def target_action(classification):
    path=str(ROOT/'extension/client-runtime')
    if path not in sys.path:sys.path.insert(0,path)
    from src.classification.classification_policy import _baseline_action
    from privoke_contracts.classification import Sensitivity,Visibility,Category
    return _baseline_action(Sensitivity[classification['sensitivity']],Visibility[classification['visibility']],
        [Category[v] for v in classification['categories']]).name


def bound_input_files(value):
    result={}
    def collect(node):
        if isinstance(node,dict):
            if 'path' in node and 'sha256' in node:result[node['path']]=node['sha256']
            else:
                for k,v in node.items():
                    if k not in ('ontology_manifest','length_admissibility','endpoint_ledger'):collect(v)
        elif isinstance(node,list):
            for v in node:collect(v)
    collect(value)
    return result


def verify_review_gates(protocol):
    inputs=protocol['inputs'];files=bound_input_files(inputs)
    for name in ('ontology_manifest','length_admissibility','endpoint_ledger'):
        receipt=read(inputs[name]['path'])
        if receipt.get('status')!='accepted' or receipt.get('source_files_sha256')!=digest(protocol['source_files']) or receipt.get('input_files')!=files:
            raise ValueError('Review gate lacks exact source/input commitments: '+name)
        if receipt.get('cell_ids')!=[c['id'] for c in protocol['cells']]:
            raise ValueError('Review gate does not cover the entire matrix: '+name)
    lengths=read(inputs['length_admissibility']['path'])
    if lengths.get('training_errors')!=0 or lengths.get('guard_errors')!=0 or lengths.get('primary_assessment_errors')!=0:
        raise ValueError('Tokenizer admissibility failed before fitting')
    if lengths.get('secondary_error_policy')!='fixed_denominator_error_and_qualification_veto':
        raise ValueError('Secondary overlength coverage policy must be explicit')
    if not lengths.get('tokenizer_hashes') or not lengths.get('row_length_inventory_sha256'):
        raise ValueError('Actual tokenizer/length evidence missing')
    ledger=read(inputs['endpoint_ledger']['path'])
    if set(ledger.get('routes',{}))!=set(c['id'] for c in protocol['cells']):
        raise ValueError('Missing per-route baseline/comparator/decision rule')
    for cell in protocol['cells']:
        row=ledger['routes'][cell['id']]
        if any(not row.get(key) for key in ('baseline','comparator','rule','endpoints')):
            raise ValueError('Incomplete endpoint ledger')
        expected=protocol['qualification_rules']['presence' if cell['surface'] in ('sparse_presence','scratch_presence') else 'context']
        if row['rule']!=expected:raise ValueError('Endpoint ledger uses an undeclared qualification rule')


def normalize_offline(evaluated, rows, snapshot, task):
    predictions=evaluated['predictions'] if isinstance(evaluated,dict) else evaluated
    if len(predictions)!=len(rows) or [r['id'] for r in predictions]!=[r['id'] for r in rows]:
        raise ValueError('Offline learned-forward fixed denominator/order differs')
    normalized=[];identity=None
    for row,value in zip(rows,predictions):
        record={'id':row['id'],'group_id':row.get('group_id',row.get('family_id')),
            'target':row['present'] if task=='presence' else row['classification']}
        if value.get('status')=='error':
            record.update(status='error',error=value.get('error','offline learned forward failed'))
        else:
            trace=value.get('executions',[])
            if (value.get('execution_mode')!='offline_learned_forward_v1' or value.get('executed_layers')!=['DETECTION_LAYER_SEMANTIC']
                    or value.get('snapshot_sha256')!=snapshot['sha256'] or len(trace)!=1
                    or trace[0].get('layer')!='DETECTION_LAYER_SEMANTIC' or trace[0].get('status')!='complete' or trace[0].get('forward_count')!=1):
                raise ValueError('Offline actual semantic execution evidence differs')
            if value.get('requested_model_id')!=value.get('used_model_id') or value.get('requested_version')!=value.get('used_version'):
                raise ValueError('Offline requested/used identity differs')
            observed={'model_id':value.get('used_model_id'),'model_version':value.get('used_version'),
                'artifact_checksum':value.get('snapshot_checksum') or value.get('snapshot_sha256'),'parameter_fingerprint':value.get('parameter_fingerprint')}
            if not observed or any(not observed.get(k) for k in IDENTITY) or (identity and identity!=observed):
                raise ValueError('Offline learned-forward identity differs')
            identity=observed
            record.update(value,status='ok')
            if task=='presence':record['predicted_present']=value['present'] if 'present' in value else value['classification']['sensitivity']!='S0' or bool(value['classification']['categories'])
            else:
                record['action'],record['confidence']=offline_action(value)
        if task=='context':record.update(allowed_actions=row.get('allowed_actions') or [target_action(row['classification'])],quantitative=row.get('quantitative',True))
        normalized.append(record)
    if identity is None:raise ValueError('Offline endpoint has no successful learned-forward identity')
    return {'identity':identity,'predictions':normalized}


def reserve_resources(compose,env,cell,directory):
    reservation=directory/'resource-reservation.json'
    containers=command(['docker','ps','-aq','--filter','label=com.docker.compose.project='+cell['project']]).split()
    volumes=command(['docker','volume','ls','-q','--filter','label=com.docker.compose.project='+cell['project']]).split()
    if not reservation.exists():
        if containers or volumes:raise ValueError('Fresh trajectory resources already exist')
        write(reservation,{'project':cell['project'],'compose_sha256':sha(directory/'compose.json')},immutable=True)
    elif read(reservation)!={'project':cell['project'],'compose_sha256':sha(directory/'compose.json')}:
        raise ValueError('Resource ownership commitment differs')


def inspect_operations(compose,env,protocol,cell,directory):
    ids=command(compose+['ps','-aq'],env=env).split()
    records=json.loads(command(['docker','inspect',*ids]));result={}
    for record in records:
        labels=record['Config']['Labels'];service=labels.get('com.docker.compose.service')
        if labels.get('com.docker.compose.project')!=cell['project']:raise ValueError('Container project ownership differs')
        expected=protocol['images'].get(service,protocol['images']['param-update-service'])
        if record['Image']!=expected:raise ValueError('Running image differs from freeze')
        mounts=[]
        for mount in record['Mounts']:
            if mount['Type']=='volume' and not mount['Name'].startswith(cell['project']+'-'):
                raise ValueError('Study uses nonisolated volume')
            mounts.append({k:mount.get(k) for k in ('Type','Name','Source','Destination','RW')})
        values=dict(e.split('=',1) for e in record['Config']['Env'] if '=' in e)
        if service=='param-update-service' and values.get('FUZZER_PROMPT_COUNT')!='0':raise ValueError('Unsupervised automatic training enabled')
        if service=='privoke-fuzzer':
            for key,value in {'MODEL_ID':cell['model_id'],'FUZZ_TRAINING_LEARNING_RATE':'0.03','FUZZ_TRAINING_MAX_GRADIENT':'0.05',
                'FUZZ_TRAINING_TRANSFORMS_PER_EXAMPLE':'1','FUZZ_HELDOUT_PROMPT_COUNT':'16','FUZZ_MIN_EXACT_MATCH_RATE':'0.0'}.items():
                if values.get(key)!=value:raise ValueError('Effective Fuzzer settings differ')
        result[service]={'id':record['Id'],'image':record['Image'],'mounts':mounts}
    if set(result)!=set(SERVICES)|{'storage-permissions'}:raise ValueError('Service inventory differs')
    write(directory/'operations.json',result,immutable=True)

def offline_action(value):
    path=str(ROOT/'extension/client-runtime')
    if path not in sys.path:sys.path.insert(0,path)
    from privoke_contracts.classification import initialise_unpacked,Sensitivity,Visibility,Category
    from src.classification.classification_results import ClassificationResult
    cls=value['classification'];probabilities=value['probabilities']
    confidence=round(min(max(max(probabilities['sensitivity']+probabilities['category']),0.),.999),3)
    packed=initialise_unpacked(Sensitivity[cls['sensitivity']],Visibility[cls['visibility']],[Category[v] for v in cls['categories']])
    return ClassificationResult(packed,'','',confidence=confidence).action().name,confidence


def preflight(output):
    protocol,_=verify_protocol(output)
    observed={}
    for service,image in (protocol['images']|{'offline_worker':protocol['offline_worker_image']}).items():
        info=json.loads(command(['docker','image','inspect',image]))
        if len(info)!=1 or info[0]['Id']!=image:raise ValueError('Pinned image unavailable')
        observed[service]=info[0]['Id']
    receipt={'schema_version':'accelerated-surfaces-preflight-v1','protocol_sha256':sha(Path(output)/'protocol.json'),
        'images':observed,'status':'passed','fits_run':0,'rpc_calls':0,'services_started':0}
    write(Path(output)/'preflight.json',receipt,immutable=True)
    return receipt

def native_serving_parity(protocol,cell,directory,result):
    if cell['surface']=='random_control':
        write(directory/'serving-parity.json',{'status':'unsupported','reason':'offline projection snapshot has no native runtime architecture',
            'final_sha256':result['final_artifact']['sha256']},immutable=True)
        return
    parity=directory/'serving-parity.json'
    if parity.exists():
        if read(parity)['final_sha256']!=result['final_artifact']['sha256']:raise ValueError('Serving parity artifact changed')
        return
    state=directory/'serving-parity'
    catalog=state/'catalog';catalog.mkdir(parents=True,exist_ok=True)
    artifact=read(result['final_artifact']['path'])
    serving_cell=cell|{'kind':'online','project':protocol['study_id']+'-parity-'+cell['id'],'model_id':artifact['model_id']}
    write(catalog/(artifact['model_id']+'.json'),artifact,immutable=True)
    if cell['surface'] in ('minilm','scratch_presence'):
        fallback=protocol['inputs']['base_artifacts']['privoke-balanced']
        verify_files(fallback)
        write(catalog/'privoke-balanced.json',read(fallback['path']),immutable=True)
    compose,env=compose_command(protocol,serving_cell,state)
    reserve_resources(compose,env,serving_cell,state)
    try:
        command(compose+['up','-d','--no-build','--wait','--wait-timeout','180'],env=env)
        inspect_operations(compose,env,protocol,serving_cell,state)
        from privoke_eval.continual_fuzzer_study import RpcClient
        client=RpcClient(f"127.0.0.1:{protocol['ports']['fuzzer']}",f"127.0.0.1:{protocol['ports']['runtime']}",f"127.0.0.1:{protocol['ports']['model']}")
        try:
            snapshot=client.snapshot(artifact['model_id'])
            if snapshot['parameters']!=wire_parameters(artifact):raise ValueError('Served final tensors differ')
            checkpoint(client,protocol,serving_cell,state,96,snapshot)
        finally:client.close()
    finally:command(compose+['stop'],env=env)
    direct=read(directory/'assessment-096.json')['layers']['semantic']['predictions']
    network=read(state/'assessment-096.json')['layers']['semantic']['predictions']
    if len(direct)!=len(network):raise ValueError('Serving parity denominator differs')
    for a,b in zip(direct,network):
        if a['id']!=b['id'] or a['status']!='ok' or b['status']!='ok':raise ValueError('Serving parity incomplete')
        if cell['surface'] in ('sparse_presence','scratch_presence'):
            matches=a['predicted_present']==b['predicted_present']
        else:
            matches=contextual_prediction_key(a)==contextual_prediction_key(b)
        if not matches:raise ValueError('Learned forward/native serving parity differs')
    write(parity,{'status':'passed','rows':len(direct),'execution_mode':'network_protobuf_v1',
        'final_sha256':result['final_artifact']['sha256'],'network_assessment_sha256':sha(state/'assessment-096.json')},immutable=True)

def wire_parameters(artifact):
    """Exact protobuf float32 coordinates and shapes, without changing artifacts."""
    from privoke_model.artifact import float32
    return {name:{'shape':tensor['shape'],'values':[float32(v) for v in tensor['values']]}
            for name,tensor in artifact['parameters'].items()}


def contextual_prediction_key(record):
    # Protobuf classification also carries packed bits; category order is not
    # semantic. Compare every learned label and the resulting action instead.
    value=record['classification']
    return value['sensitivity'],value['visibility'],tuple(sorted(value.get('categories',[]))),record['action']


def render_fresh_assessment(raw_path, task, destination):
    """Render supplied natural-language audience context, never gold labels."""
    raw=file_commitment(raw_path)
    authored=rows(raw);normalized=[]
    for row in authored:
        if task=='context':
            hint=row['audience_hint']
            text=row['text'] if hint is None else 'Supplied audience context: '+hint+'\nMessage: '+row['text']
            classification={k:row[k] for k in ('sensitivity','visibility','categories')}
            normalized.append({'id':row['row_id'],'group_id':row['family_id'],'text':text,
                'classification':classification,'allowed_actions':[target_action(classification)],
                'original_text':row['text'],'audience_hint':hint,'supplied_context':hint is not None,
                'label_status':'assistant_provisional','synthetic':True})
        elif task=='presence':
            if type(row['annotation_presence']) is not bool:raise ValueError('Explicit presence truth required')
            normalized.append({'id':row['row_id'],'group_id':row['family_id'],'text':row['text'],
                'present':row['annotation_presence'],'label_status':'assistant_provisional','synthetic':True})
        else:raise ValueError('Unknown assessment task')
    destination=Path(destination);destination.parent.mkdir(parents=True,exist_ok=True)
    # Compact JSONL keeps embedded newline escapes intact.
    rendered=b''.join((json.dumps(r,sort_keys=True,allow_nan=False)+'\n').encode() for r in normalized)
    with destination.open('xb') as stream:stream.write(rendered)
    return {'raw':raw,'rendered':{'path':str(destination.resolve()),'sha256':sha(destination)},'rows':len(normalized),
        'rendition':'supplied_audience_context_v1' if task=='context' else 'binary_presence_verbatim_v1'}

def effective_protocol(protocol,cell):
    index=[c['id'] for c in protocol['cells']].index(cell['id'])
    offset=(index%protocol['concurrency'])*100
    return protocol|{'ports':{k:v+offset for k,v in protocol['ports'].items()}}


@contextmanager
def exclusive_lock(path):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('x',encoding='ascii') as stream:stream.write(str(os.getpid()))
    try:yield
    finally:path.unlink()


def execute(output,cell_id):
    protocol,_=verify_protocol(output,execution=True)
    index=[c['id'] for c in protocol['cells']].index(cell_id)
    with exclusive_lock(Path(output)/f'lane-{index%protocol["concurrency"]}.lock'):
        return _execute(output,cell_id)


def execute_all(output):
    # Each deterministic lane runs serially; no two cells share ports/state.
    from concurrent.futures import ProcessPoolExecutor
    protocol,_=verify_protocol(output,execution=True)
    hardware=read(protocol['inputs']['hardware_preflight']['path'])
    if hardware.get('status')!='accepted' or hardware.get('approved_concurrency')!=protocol['concurrency']:
        raise ValueError('Hardware-only prospective concurrency acceptance required')
    lanes=[[c['id'] for i,c in enumerate(protocol['cells']) if i%protocol['concurrency']==lane] for lane in range(protocol['concurrency'])]
    with ProcessPoolExecutor(max_workers=protocol['concurrency']) as pool:
        futures=[pool.submit(execute_lane,str(output),ids) for ids in lanes]
        return [future.result() for future in futures]


def execute_lane(output,cell_ids):
    return [execute(output,cell_id)['cell_id'] for cell_id in cell_ids]


def update_supervisor(output,cell_id,receipt_sha256):
    import time
    lock=Path(output)/'supervisor.lock'
    for attempt in range(200):
        try:
            with exclusive_lock(lock):
                path=Path(output)/'supervisor.json';state=read(path)
                state['cells'][cell_id]={'status':'complete','receipt_sha256':receipt_sha256}
                write(path,state)
                return
        except FileExistsError:time.sleep(.05)
    raise RuntimeError('Supervisor receipt lock remains owned; inspect process before recovery')


def filesystem_probe(compose,env,directory):
    code="""import os,tempfile,json,pathlib
root=pathlib.Path(tempfile.mkdtemp(prefix='.as10-capability-',dir='/data'))
a=root/'source';b=root/'linked'
try:
 with a.open('xb') as f:f.write(b'as10');f.flush();os.fsync(f.fileno())
 os.link(a,b)
 descriptor=os.open(root,os.O_RDONLY)
 try:os.fsync(descriptor)
 finally:os.close(descriptor)
 assert a.read_bytes()==b.read_bytes()==b'as10'
 print(json.dumps({'status':'passed','hardlink':True,'file_fsync':True,'directory_fsync':True,'state_location':'linux_named_volume'}))
finally:
 if b.exists():b.unlink()
 if a.exists():a.unlink()
 root.rmdir()
"""
    receipt=json.loads(command(compose+['exec','-T','privoke-fuzzer','python','-c',code],env=env))
    if receipt!={'status':'passed','hardlink':True,'file_fsync':True,'directory_fsync':True,'state_location':'linux_named_volume'}:
        raise ValueError('Actual state mount lacks required atomic evidence capabilities')
    write(directory/'filesystem-preflight.json',receipt,immutable=True)

def endpoint_specs(protocol,cell):
    inputs=protocol['inputs'];binary=cell['surface'] in ('sparse_presence','scratch_presence')
    primary='presence' if binary else 'context'
    result=[('primary',primary,rows(inputs['assessments'][primary]))]
    if not binary:result.append(('annotation_transfer','presence',rows(inputs['assessments']['presence'])))
    development=[]
    for row in rows(inputs['secondary']['development']):
        development.append({'id':row['id'],'group_id':row['group_id'],'text':row['text'],'present':row['expected_has_pii']})
    result.append(('historical_annotation','presence',development))
    if not binary:
        fixtures=[]
        for row in rows(inputs['secondary']['fixtures']):
            target={'sensitivity':row.get('expected_sensitivity'),'visibility':row.get('expected_visibility'),'categories':row.get('expected_categories',[])}
            allowed=row.get('allowed_actions')
            if not allowed and row.get('minimum_action'):
                ranks=['ALLOW','WARN','BLOCK'];allowed=ranks[ranks.index(row['minimum_action']):]
            allowed=allowed or ([row['expected_action']] if row.get('expected_action') else ['ALLOW','WARN','BLOCK'])
            fixtures.append({'id':row['case_id'],'group_id':row.get('family_id',row['case_id']),'text':row['text'],
                'classification':target,'allowed_actions':allowed,'quantitative':not row['ambiguous'] and row.get('action_accuracy_eligible',True) and row.get('context_truth_eligible',True)})
        result.append(('historical_fixtures','context',fixtures))
    return result


def measure_binary_proxy(client,data,cell,identity,tag):
    from privoke_eval.continual_fuzzer_study import require_semantic_execution,LayerIsolationError
    predictions=[]
    for row in data:
        record={'id':row['id'],'group_id':row['group_id'],'target':row['present']}
        try:
            admit_network_text(row['text'],cell)
            value=client.analyze(row,cell['model_id'],'semantic',digest([tag,row['id']])[:40])
            require_semantic_execution(value['raw'])
            if not value['identities'] or any(v!=identity for v in value['identities']):raise LayerIsolationError('Binary proxy identity differs')
            record.update(status='ok',predicted_present=value['detected_sensitive'],raw=value['raw'],identity=identity,identities=value['identities'],execution_mode='network_protobuf_v1')
        except LayerIsolationError:raise
        except Exception as exc:record.update(status='error',error=str(exc))
        predictions.append(record)
    return {'semantic':{'predictions':predictions}}


def offline_worker(protocol,cell,inputs,directory,operation):
    """Separate pinned Linux process: fit has no assessment files or network."""
    image=protocol["offline_worker_image"]
    if command(["docker","image","inspect",image,"--format","{{.Id}}"] ).strip()!=image:
        raise ValueError("Offline worker image identity differs")
    directory=Path(directory).resolve();work=directory/("worker-"+operation);work.mkdir(exist_ok=True)
    mounts=[];counter=0;parents={}
    def bind(value):
        nonlocal counter
        if isinstance(value,dict):
            if "path" in value and "sha256" in value:
                path=Path(value["path"]).resolve(strict=True)
                if sha(path)!=value["sha256"]:raise ValueError("Worker input changed")
                parent=str(path.parent)
                if parent not in parents:parents[parent]=counter;counter+=1
                target=f"/inputs/{parents[parent]}/{path.name}"
                mounts.extend(["--mount",f"type=bind,source={path},target={target},readonly"])
                return value|{"path":target}
            return {k:bind(v) for k,v in value.items()}
        if isinstance(value,list):return [bind(v) for v in value]
        return value
    request={"schema_version":"accelerated-offline-worker-v1","operation":"fit" if operation=="fit" else "score", "cell":cell,"inputs":bind(inputs),"source_revision":protocol["source_revision"],"adapter_sha256":protocol["source_files"]["evaluation/privoke_eval/accelerated_training_surfaces_offline.py"]}
    if operation=="fit" and any(k in inputs for k in ("rows","assessment","assessments","test","validation")):
        raise ValueError("Fit worker received assessment input")
    request_path=work/"request.json";write(request_path,request,immutable=True)
    mounts.extend(["--mount",f"type=bind,source={request_path},target=/request.json,readonly","--mount",f"type=bind,source={work},target=/output"])
    args=["docker","run","--rm","--network","none","--read-only","--tmpfs","/tmp:rw,nosuid,size=1g",*mounts,"--entrypoint","python",image,"/study/evaluation/run-accelerated-training-surfaces-worker.py","/request.json","/output"]
    with (work/"operations.log").open("a",encoding="utf-8") as log:
        subprocess.run(args,check=True,stdout=log,stderr=subprocess.STDOUT)
    raw=read(work/"result.json")
    if raw["image_source_revision"]!=protocol["source_revision"] or raw["request_sha256"]!=sha(request_path):
        raise ValueError("Worker result commitment differs")
    def translate(value):
        if isinstance(value,dict):return {k:translate(v) for k,v in value.items()}
        if isinstance(value,list):return [translate(v) for v in value]
        if isinstance(value,str) and value.startswith("/output/"):
            relative=Path(value.removeprefix("/output/"))
            if ".." in relative.parts:raise ValueError("Worker output escaped directory")
            return str(work/relative)
        return value
    return translate(raw["result"])


def admit_network_text(text,cell):
    if cell["surface"]=="sparse_presence":return
    path=str(ROOT/"extension/client-runtime")
    if path not in sys.path:sys.path.insert(0,path)
    from src.detection.preprocessing import normalize_text
    from src.transformer_encoder import TOKEN_PATTERN
    maximum={"efficient":64,"balanced":96,"quality":128}[cell["profile"]] if cell["surface"]=="scratch_presence" else 256
    if len(TOKEN_PATTERN.findall(normalize_text(text).lower()))+1>maximum:
        raise CoverageError("Input exceeds exact native token capacity; truncation forbidden")


class CoverageError(ValueError):pass
