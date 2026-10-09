"""Bounded continual contextual training with exact, paired development evidence.

This controller does not select or promote a model. Contextual privacy signals are
compared against annotation-presence labels; that task mismatch remains explicit.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
from contextlib import ExitStack
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path
import random
import time
import subprocess

from host_environment import configure_imports

configure_imports()
import grpc
from google.protobuf.json_format import MessageToDict
from privoke.v1 import parameters_pb2 as PP, parameters_pb2_grpc as PA
from privoke.v1 import runtime_pb2 as RP, runtime_pb2_grpc as RA
from privoke_model.fingerprint import parameter_fingerprint
from privoke_model.training_data import training_text_key

PROFILES = ("privoke-efficient", "privoke-balanced", "privoke-quality")
DEVELOPMENT_SHA = "65bf02af1f9f7167a5aa5eaaa8aeac54111c90d009585ed36570d3ce0a635095"
IDENTITY_KEYS = ("model_id", "model_version", "artifact_checksum", "parameter_fingerprint")
METRICS = ("recall", "specificity", "precision", "f1", "accuracy", "balanced_accuracy")


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write_json(path, value):
    path = Path(path)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, ensure_ascii=False, allow_nan=False) + "\n", encoding="utf-8")
    temporary.replace(path)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def normalized(text):
    return training_text_key(text)


def permitted_path(path):
    path = Path(path).resolve()
    if any("final" in part.casefold() for part in path.parts):
        raise ValueError("Protected final paths are forbidden before any file access.")
    return path


def jsonl(path):
    path = permitted_path(path)
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    ids = [row.get("id") for row in rows]
    if not rows or any(not isinstance(value, str) or not value for value in ids) or len(set(ids)) != len(ids):
        raise ValueError("Rows require unique nonempty string IDs.")
    if any(not isinstance(row.get("text"), str) or not row["text"].strip() for row in rows):
        raise ValueError("Rows require nonempty text.")
    return rows


def load_inputs(dataset_file, dataset_sha256, curriculum_manifest):
    dataset_file = permitted_path(dataset_file)
    if dataset_file.name != "development.jsonl" or sha(dataset_file) != dataset_sha256:
        raise ValueError("Only the byte-pinned development.jsonl endpoint is permitted.")
    evaluation = jsonl(dataset_file)
    if any(type(row.get("expected_has_pii")) is not bool or not row.get("group_id") for row in evaluation):
        raise ValueError("Development rows require explicit boolean labels and source groups.")
    manifest_path = permitted_path(curriculum_manifest)
    manifest = read_json(manifest_path)
    if manifest.get("schema_version") != 1 or not manifest.get("curriculum_id"):
        raise ValueError("Unsupported curriculum manifest.")
    splits, inventories = {}, {}
    ids, groups, texts = set(), set(), set()
    for role in ("train", "heldout", "replay"):
        entry = manifest["splits"][role]
        path = permitted_path(manifest_path.parent / entry["path"])
        path.relative_to(manifest_path.parent)
        if sha(path) != entry["sha256"]:
            raise ValueError(f"Curriculum {role} byte commitment mismatch.")
        rows = jsonl(path)
        row_ids, row_groups, row_texts = set(), set(), set()
        for row in rows:
            meta, target = row.get("metadata", {}), row.get("classification", {})
            if (not meta.get("group_id") or not meta.get("curriculum_role")
                    or meta.get("label_status") not in {"reviewed", "provisional", "assistant_provisional"}
                    or target.get("sensitivity") not in {"S0", "S1", "S2", "S3"}
                    or target.get("visibility") not in {"P0", "P1", "P2", "P3", "P4", "PU"}
                    or not isinstance(target.get("categories"), list)):
                raise ValueError("Curriculum labels, groups and roles must be explicit.")
            row_ids.add(row["id"])
            row_groups.add(meta["group_id"])
            row_texts.add(normalized(row["text"]))
        if row_ids & ids or row_groups & groups or row_texts & texts:
            raise ValueError("Curriculum splits overlap by ID, family or normalized text.")
        if row_ids & {row["id"] for row in evaluation} or row_groups & {row["group_id"] for row in evaluation} or row_texts & {normalized(row["text"]) for row in evaluation}:
            raise ValueError("Evaluation and curriculum overlap.")
        ids.update(row_ids)
        groups.update(row_groups)
        texts.update(row_texts)
        splits[role] = rows
        inventories[role] = {"path": str(path), "sha256": entry["sha256"], "rows": len(rows), "groups": len(row_groups), "ids": sorted(row_ids)}
    return evaluation, splits, {"dataset_path": str(dataset_file), "dataset_sha256": dataset_sha256,
                               "manifest_path": str(manifest_path), "manifest_sha256": sha(manifest_path),
                               "curriculum_id": manifest["curriculum_id"], "splits": inventories}


def metrics(rows):
    good = [row for row in rows if row["status"] == "ok"]
    bad = [row for row in rows if row["status"] != "ok"]
    tp = sum(row["expected_has_pii"] and row["detected_sensitive"] for row in good)
    tn = sum(not row["expected_has_pii"] and not row["detected_sensitive"] for row in good)
    fp = sum(not row["expected_has_pii"] and row["detected_sensitive"] for row in good)
    fn = sum(row["expected_has_pii"] and not row["detected_sensitive"] for row in good)
    divide = lambda numerator, denominator: numerator / denominator if denominator else None
    recall, specificity = divide(tp, tp + fn), divide(tn, tn + fp)
    return {"true_positives": tp, "true_negatives": tn, "false_positives": fp, "false_negatives": fn,
            "recall": recall, "specificity": specificity, "precision": divide(tp, tp + fp),
            "f1": divide(2 * tp, 2 * tp + fp + fn), "accuracy": divide(tp + tn, len(good)),
            "balanced_accuracy": (recall + specificity) / 2 if recall is not None and specificity is not None else None,
            "runtime_errors": len(bad), "evaluated_samples": len(good), "loaded_samples": len(rows),
            "coverage": len(good) / len(rows) if rows else 0.0, "paper_result_valid": not bad}


def percentile(values, fraction):
    ordered = sorted(values)
    position = (len(ordered) - 1) * fraction
    low = int(position)
    high = min(low + 1, len(ordered) - 1)
    return ordered[low] + (ordered[high] - ordered[low]) * (position - low)


def paired_changes(before, after, *, iterations=2000, seed=1337):
    def keyed(rows):
        result = {row["id"]: row for row in rows}
        if len(result) != len(rows):
            raise ValueError("Duplicate paired IDs.")
        return result
    left, right = keyed(before), keyed(after)
    if left.keys() != right.keys():
        raise ValueError("Paired IDs differ.")
    pairs = [(left[key], right[key]) for key in sorted(left)]
    if any((a["expected_has_pii"], a["group_id"]) != (b["expected_has_pii"], b["group_id"]) for a, b in pairs):
        raise ValueError("Paired labels or groups differ.")
    incomplete = sum(a["status"] != "ok" or b["status"] != "ok" for a, b in pairs)
    if incomplete:
        return {"valid": False, "rows": len(pairs), "unpaired_due_to_errors": incomplete, "changes": None}
    groups = defaultdict(list)
    for index, (row, _) in enumerate(pairs):
        groups[row["group_id"]].append(index)
    def delta(indexes):
        selected = [pairs[index] for index in indexes]
        a, b = metrics([x for x, _ in selected]), metrics([y for _, y in selected])
        return {name: None if a[name] is None or b[name] is None else b[name] - a[name] for name in METRICS}
    point = delta(range(len(pairs)))
    rng, samples = random.Random(seed), {name: [] for name in METRICS}
    keys = sorted(groups)
    improved = sum(a["detected_sensitive"] != a["expected_has_pii"] and b["detected_sensitive"] == b["expected_has_pii"] for a, b in pairs)
    deteriorated = sum(a["detected_sensitive"] == a["expected_has_pii"] and b["detected_sensitive"] != b["expected_has_pii"] for a, b in pairs)
    for _ in range(iterations):
        values = delta([index for key in rng.choices(keys, k=len(keys)) for index in groups[key]])
        for name, value in values.items():
            if value is not None:
                samples[name].append(value)
    return {"valid": True, "rows": len(pairs), "groups": len(groups), "improved": improved, "deteriorated": deteriorated,
            "method": "paired group percentile bootstrap", "iterations": iterations, "seed": seed,
            "changes": {name: {"estimate": point[name], "interval_95": [percentile(samples[name], .025), percentile(samples[name], .975)] if samples[name] else None,
                               "defined_replicates": len(samples[name])} for name in METRICS}}


class RpcClient:
    def __init__(self, target, runtime_target, model_target):
        self.stack = ExitStack()
        self.fuzzer = PA.FuzzerServiceStub(self.stack.enter_context(grpc.insecure_channel(target)))
        self.runtime = RA.PrivokeRuntimeServiceStub(self.stack.enter_context(grpc.insecure_channel(runtime_target)))
        channel = self.stack.enter_context(grpc.insecure_channel(model_target, options=[("grpc.max_receive_message_length", 256 * 1024 * 1024)]))
        self.models = PA.ModelStreamingServiceStub(channel)

    def close(self):
        self.stack.close()

    def snapshot(self, model_id):
        response = self.models.GetModelParameters(PP.ModelParametersRequest(consumer_id="continual-study", model_id=model_id), timeout=120)
        parameters = {p.name: list(p.values) for p in response.parameters}
        shapes = {p.name: list(p.shape) for p in response.parameters}
        identity = {"model_id": response.model_id, "model_version": response.version,
                    "artifact_checksum": response.metadata.get("artifact_checksum", ""),
                    "parameter_fingerprint": parameter_fingerprint(parameters, shapes)}
        if response.model_id != model_id or not parameters or not all(identity.values()):
            raise ValueError("Incomplete model snapshot identity.")
        return {"identity": identity, "parameters": {p.name: {"values": list(p.values), "shape": list(p.shape)} for p in response.parameters},
                "metadata": dict(response.metadata), "generated_at_unix": response.generated_at_unix}

    def analyze(self, row, model_id, layer, request_id):
        request = RP.AnalyzePromptRequest(text=row["text"], source="continual-fuzzer-study", request_id=request_id,
                                         semantic_model_id=model_id,
                                         layers=[RP.DETECTION_LAYER_SEMANTIC if layer == "semantic" else RP.DETECTION_LAYER_RUNTIME])
        response = self.runtime.AnalyzePrompt(request, timeout=120)
        if response.request_id != request_id or response.error:
            raise ValueError(response.error or "Runtime request identity mismatch.")
        raw = MessageToDict(response, preserving_proto_field_name=True)
        if response.action not in {"ALLOW", "WARN", "BLOCK"} or response.classification.sensitivity not in {"S0", "S1", "S2", "S3"}:
            raise ValueError("Invalid runtime classification/action.")
        identities = []
        for execution in response.layers:
            if execution.status == "error":
                raise ValueError(execution.error or "Runtime layer failed.")
            if execution.layer == RP.DETECTION_LAYER_SEMANTIC and execution.status == "ok":
                for result in execution.results:
                    identities.append({key: result.metadata.get(key, "") for key in IDENTITY_KEYS})
        return {"raw": raw, "identities": identities, "detected_sensitive": response.classification.sensitivity != "S0" or bool(response.classification.categories)}

    def train(self, value):
        request = PP.FuzzerTrainingRequest(**value)
        try:
            response = self.fuzzer.RunTrainingCycle(request, timeout=300)
        except grpc.RpcError as exc:
            if exc.code() not in {grpc.StatusCode.INVALID_ARGUMENT, grpc.StatusCode.FAILED_PRECONDITION}:
                raise
            return {"accepted": False, "model_id": request.model_id, "base_version": "", "applied_version": "",
                    "prompts_generated": 0, "message": exc.details(), "metadata": {}, "rejection_code": exc.code().name}
        return {"accepted": response.accepted, "model_id": response.model_id, "base_version": response.base_version,
                "applied_version": response.applied_version, "prompts_generated": response.prompts_generated,
                "message": response.message, "metadata": dict(response.metadata)}


def measure(client, rows, model_id, identity, tag):
    reports = {}
    for layer in ("semantic", "pipeline"):
        predictions = []
        seen_identity = False
        for row in rows:
            record = {"id": row["id"], "group_id": row["group_id"], "expected_has_pii": row["expected_has_pii"]}
            request_id = "continual-probe-" + hashlib.sha256(f"{tag}:{layer}:{row['id']}".encode()).hexdigest()[:40]
            try:
                result = client.analyze(row, model_id, layer, request_id)
                if any(observed != identity for observed in result["identities"]):
                    raise ValueError("Returned semantic identity differs from pinned snapshot.")
                seen_identity |= bool(result["identities"])
                record.update(status="ok", request_id=request_id, **result)
            except (grpc.RpcError, ValueError) as exc:
                record.update(status="error", request_id=request_id, error=str(exc))
            predictions.append(record)
        if not seen_identity:
            raise ValueError(f"{layer} collection lacks independent returned semantic identity.")
        if client.snapshot(model_id)["identity"] != identity:
            raise ValueError("Model changed during checkpoint measurement.")
        reports[layer] = {"identity": identity, "predictions": predictions, "metrics": metrics(predictions)}
    return reports


def mine_training(client, rows, model_id, identity, tag):
    """Prioritize train-only provisional/reviewed targets; never inspect eval errors."""
    ordered = sorted(rows, key=lambda row: row["id"])
    selected = sorted(random.Random(1337).sample(ordered, min(128, len(ordered))), key=lambda row: row["id"])
    hard, records = [], []
    for row in selected:
        target = row["classification"]
        expected = target["sensitivity"] != "S0" or bool(target["categories"])
        request_id = "continual-mine-" + hashlib.sha256(f"{tag}:{row['id']}".encode()).hexdigest()[:40]
        record = {"id": row["id"], "group_id": row["metadata"]["group_id"], "expected_sensitive": expected,
                  "label_status": row["metadata"]["label_status"], "generator": row["metadata"].get("generator"),
                  "parent_id": row["metadata"].get("parent_id"), "request_id": request_id}
        try:
            result = client.analyze(row, model_id, "semantic", request_id)
            if any(value != identity for value in result["identities"]):
                raise ValueError("Mining identity mismatch.")
            record.update(status="ok", **result)
            if expected != result["detected_sensitive"]:
                hard.append(row["id"])
        except (grpc.RpcError, ValueError) as exc:
            record.update(status="error", error=str(exc))
        records.append(record)
    if client.snapshot(model_id)["identity"] != identity:
        raise ValueError("Model changed during train-only mining.")
    return hard[:8], records


def study_config(args, inputs):
    return {"models": [args.model_id] if args.model_id else list(PROFILES), "cycles": args.cycles, "seed": args.seed,
            "duration_seconds": args.duration_seconds, "checkpoint_interval_seconds": args.checkpoint_interval_seconds,
            "round_pause_seconds": args.round_pause_seconds, "checkpoint_only_snapshots": args.checkpoint_only_snapshots,
            "prompt_count": args.prompt_count, "checkpoints": sorted(set(args.checkpoints + [0, args.cycles])),
            "target": args.target, "runtime_target": args.runtime_target, "model_target": args.model_target,
                               "controller_sha256": sha(Path(__file__)), "mining": not args.no_mining, "bootstrap_iterations": args.bootstrap_iterations, "cache_wait_seconds": args.cache_wait_seconds, "inputs": inputs}


def verify_operations(path):
    """Check frozen Docker images and effective settings before issuing study RPCs."""
    path = permitted_path(path)
    manifest = read_json(path)
    expected = manifest["containers"]
    inspected = subprocess.run(["docker", "inspect", *expected], check=True,
                               capture_output=True, text=True)
    actual = {row["Name"].lstrip("/"): row for row in json.loads(inspected.stdout)}
    for name, pinned in expected.items():
        container = actual[name]
        environment = dict(item.split("=", 1) for item in container["Config"]["Env"] if "=" in item)
        if (container["Image"] != pinned["image_id"] or not container["State"]["Running"]
                or any(environment.get(key) != value for key, value in pinned["environment"].items())):
            raise ValueError("Live Docker image or settings differ from the frozen operational manifest.")
    return {"path": str(path), "sha256": sha(path)}


def save_checkpoint(client, evaluation, model_id, model, directory, cycle, state, args):
    key = str(cycle)
    if key in model["checkpoints"]:
        saved = model["checkpoints"][key]
        if sha(directory / saved["path"]) != saved["sha256"]:
            raise ValueError("Archived checkpoint bytes changed.")
        return
    snapshot = client.snapshot(model_id)
    if snapshot["identity"] != model["current_identity"]:
        raise ValueError("Model changed before checkpoint.")
    print(f"Measuring {model_id} checkpoint {cycle} ({len(evaluation)} rows per layer)", flush=True)
    report = measure(client, evaluation, model_id, snapshot["identity"], f"{state['run_id']}:{model_id}:{cycle}")
    if cycle:
        baseline = read_json(directory / "checkpoint-000.json")
        for layer in report:
            report[layer]["paired_vs_baseline"] = paired_changes(baseline[layer]["predictions"], report[layer]["predictions"],
                                                                iterations=args.bootstrap_iterations, seed=args.seed)
    path = directory / f"checkpoint-{cycle:03d}.json"
    write_json(path, report)
    snapshot_path = directory / f"snapshot-{cycle:03d}.json"
    write_json(snapshot_path, snapshot)
    model["checkpoints"][key] = {"path": path.name, "sha256": sha(path), "identity": snapshot["identity"],
                                "measured_at": datetime.now(timezone.utc).isoformat(),
                                "snapshot_path": snapshot_path.name, "snapshot_sha256": sha(snapshot_path)}


def save_mining(client, splits, model_id, model, directory, cycle, state):
    if str(cycle) in model.setdefault("mining", {}):
        archived = model["mining"][str(cycle)]
        if sha(directory / archived["path"]) != archived["sha256"]:
            raise ValueError("Archived mining evidence changed.")
        return
    hard, records = mine_training(client, splits["train"], model_id, model["current_identity"], f"{state['run_id']}:{model_id}:{cycle}")
    path = directory / f"mining-{cycle:03d}.json"
    write_json(path, {"identity": model["current_identity"], "hard_ids": hard, "train_only": True,
                      "pool_sampling": "fixed seed1337 sample capped128; sorted IDs", "records": records})
    model["hard_ids"] = hard
    model["mining"][str(cycle)] = {"path": path.name, "sha256": sha(path), "hard_ids": hard}


def run(args, client=None):
    evaluation, splits, inputs = load_inputs(args.dataset_file, args.dataset_sha256, args.curriculum_manifest)
    if args.operational_manifest:
        inputs["operations"] = verify_operations(args.operational_manifest)
    config = study_config(args, inputs)
    output = Path(args.output).resolve()
    if args.resume:
        state = read_json(output / "run-manifest.json")
        if state["config"] != config:
            raise ValueError("Resume configuration or input bytes differ.")
        if state["status"] == "complete":
            raise ValueError("Completed studies cannot resume.")
    else:
        output.mkdir(parents=True, exist_ok=False)
        state = {"schema_version": 1, "config": config, "status": "running", "started_at": datetime.now(timezone.utc).isoformat(),
                 "run_id": hashlib.sha256(str(output).encode()).hexdigest()[:20], "models": {},
                 "limitations": ["Contextual signal scored against annotation-presence labels: distinct tasks.",
                                 "Development comparisons are exploratory and do not establish final generalization.",
                                 "No model selection or promotion; all measured deteriorations retained."]}
    own_client = client is None
    client = client or RpcClient(args.target, args.runtime_target, args.model_target)
    manifest_path = output / "run-manifest.json"
    write_json(manifest_path, state)
    try:
        for model_id in config["models"]:
            model = state["models"].setdefault(model_id, {"rounds": [], "checkpoints": {}, "hard_ids": [], "accepted_updates": 0})
            directory = output / model_id
            directory.mkdir(exist_ok=True)
            snapshot = client.snapshot(model_id)
            if "current_identity" in model and snapshot["identity"] != model["current_identity"] and not model.get("pending"):
                raise ValueError("Resume model differs from last observed exact identity.")
            for saved in model["checkpoints"].values():
                if (sha(directory / saved["path"]) != saved["sha256"]
                        or sha(directory / saved["snapshot_path"]) != saved["snapshot_sha256"]):
                    raise ValueError("Archived checkpoint or snapshot changed before resume.")
            if "0" not in model["checkpoints"]:
                model["current_identity"] = snapshot["identity"]
                save_checkpoint(client, evaluation, model_id, model, directory, 0, state, args)
                write_json(manifest_path, state)
            completed = len(model["rounds"])
            if args.duration_seconds and "training_deadline_unix" not in model:
                model["duration_started_unix"] = time.time()
                model["training_deadline_unix"] = model["duration_started_unix"] + args.duration_seconds
                model["next_checkpoint_unix"] = model["duration_started_unix"] + args.checkpoint_interval_seconds
                write_json(manifest_path, state)
            if model.get("checkpoint_due_cycle") is not None:
                save_checkpoint(client, evaluation, model_id, model, directory, model["checkpoint_due_cycle"], state, args)
                model.pop("checkpoint_due_cycle")
                model["next_checkpoint_unix"] = time.time() + args.checkpoint_interval_seconds
                write_json(manifest_path, state)
            if completed and completed % 5 == 0 and not args.no_mining:
                save_mining(client, splits, model_id, model, directory, completed, state)
                write_json(manifest_path, state)
            if completed and completed in config["checkpoints"]:
                save_checkpoint(client, evaluation, model_id, model, directory, completed, state, args)
                write_json(manifest_path, state)
            for cycle in range(len(model["rounds"]) + 1, args.cycles + 1):
                request = model.get("pending")
                if request is None and args.duration_seconds and time.time() >= model["training_deadline_unix"]:
                    break
                if request is None:
                    request = {"request_id": f"continual-{state['run_id']}-{model_id}-{cycle:03d}", "source_id": "continual-fuzzer-study",
                               "model_id": model_id, "prompt_count": args.prompt_count, "seed": args.seed + cycle - 1,
                               "metadata": {"initiator": "continual-study-controller", "curriculum_stage": "all",
                                            "curriculum_id": inputs["curriculum_id"], "curriculum_manifest_sha256": inputs["manifest_sha256"],
                                            "curriculum_hard_ids": json.dumps(model["hard_ids"], separators=(",", ":"))}}
                    model["pending"] = request
                    write_json(manifest_path, state)
                expected_cycle = len(model["rounds"]) + 1
                if (request["seed"] != args.seed + expected_cycle - 1 or request["model_id"] != model_id
                        or request["request_id"] != f"continual-{state['run_id']}-{model_id}-{expected_cycle:03d}"):
                    raise ValueError("Pending request changed before resume.")
                started = time.monotonic()
                if args.operational_manifest:
                    if verify_operations(args.operational_manifest) != inputs["operations"]:
                        raise ValueError("Operational manifest changed during the study.")
                print(f"Training {model_id} round {cycle}/{args.cycles}, seed {request['seed']}", flush=True)
                response = client.train(request)
                response_path = directory / f"response-{cycle:03d}.json"
                if response_path.exists():
                    archived_response = read_json(response_path)
                    for key in ("accepted", "model_id", "base_version", "applied_version", "prompts_generated"):
                        if archived_response[key] != response[key]:
                            raise ValueError("Replayed acknowledgment differs from archived response.")
                    response = archived_response
                else:
                    write_json(response_path, response)
                if response["model_id"] != model_id or (not response.get("rejection_code") and response["base_version"] != model["current_identity"]["model_version"]):
                    raise ValueError("Training response identity is incomplete.")
                snapshot = client.snapshot(model_id)
                if response["accepted"]:
                    if response["metadata"].get("replayed") != "true":
                        for key, expected in (("curriculum_id", inputs["curriculum_id"]),
                                              ("curriculum_manifest_sha256", inputs["manifest_sha256"])):
                            if response["metadata"].get(key) != expected:
                                raise ValueError("Accepted training used a different curriculum commitment.")
                    if (snapshot["identity"]["model_version"] != response["applied_version"]
                            or response["applied_version"] == response["base_version"]):
                        raise ValueError("Accepted training response does not match published model.")
                    if response["prompts_generated"] != args.prompt_count:
                        raise ValueError("Accepted batch count differs from requested prompts.")
                    updated_fingerprint = parameter_fingerprint({name: parameter["values"] for name, parameter in snapshot["parameters"].items()})
                    guarded = response["metadata"].get("updated_parameter_fingerprint")
                    if guarded and guarded != updated_fingerprint:
                        raise ValueError("Published values differ from guarded training fingerprint.")
                    model["accepted_updates"] += 1
                    time.sleep(args.cache_wait_seconds)
                elif snapshot["identity"] != model["current_identity"]:
                    raise ValueError("Rejected training changed the model.")
                record = {"cycle": cycle, "request": request, "request_fingerprint": hashlib.sha256(PP.FuzzerTrainingRequest(**request).SerializeToString(deterministic=True)).hexdigest(),
                          "response": response, "identity": snapshot["identity"], "accepted_updates": model["accepted_updates"], "elapsed_seconds": time.monotonic() - started, "response_path": response_path.name, "response_sha256": sha(response_path)}
                model["rounds"].append(record)
                model["current_identity"] = snapshot["identity"]
                model.pop("pending", None)
                write_json(directory / f"round-{cycle:03d}.json", record)
                if not args.checkpoint_only_snapshots:
                    write_json(directory / f"snapshot-{cycle:03d}.json", snapshot)
                write_json(manifest_path, state)
                print(f"Round {cycle}: accepted={response['accepted']}, accepted updates={model['accepted_updates']}", flush=True)
                if cycle % 5 == 0 and not args.no_mining:
                    save_mining(client, splits, model_id, model, directory, cycle, state)
                    write_json(manifest_path, state)
                timed_checkpoint = (args.duration_seconds and args.checkpoint_interval_seconds > 0
                                    and time.time() >= model["next_checkpoint_unix"])
                if cycle in config["checkpoints"] or timed_checkpoint:
                    model["checkpoint_due_cycle"] = cycle
                    write_json(manifest_path, state)
                    save_checkpoint(client, evaluation, model_id, model, directory, cycle, state, args)
                    model.pop("checkpoint_due_cycle")
                    model["next_checkpoint_unix"] = time.time() + args.checkpoint_interval_seconds
                    write_json(manifest_path, state)
                pause = args.round_pause_seconds
                if args.duration_seconds:
                    pause = min(pause, max(0, model["training_deadline_unix"] - time.time()))
                if pause:
                    time.sleep(pause)
            if args.duration_seconds:
                elapsed = time.time() - model["duration_started_unix"]
                if elapsed < args.duration_seconds:
                    raise ValueError("Cycle cap reached before the required training duration.")
                model["timed_training_seconds"] = elapsed
                model["duration_finished_unix"] = time.time()
                model["final_cycle"] = len(model["rounds"])
                save_checkpoint(client, evaluation, model_id, model, directory, model["final_cycle"], state, args)
                write_json(manifest_path, state)
        state["status"] = "complete"
        state["finished_at"] = datetime.now(timezone.utc).isoformat()
        write_json(manifest_path, state)
        return state
    except Exception as exc:
        state["status"] = "interrupted"
        state["last_error"] = str(exc)
        write_json(manifest_path, state)
        raise
    finally:
        if own_client:
            client.close()


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--model-id", choices=PROFILES)
    result.add_argument("--cycles", type=int, default=20)
    result.add_argument("--duration-seconds", type=float, default=0, help="Required elapsed training window per model; cycles becomes a safety cap")
    result.add_argument("--checkpoint-interval-seconds", type=float, default=0)
    result.add_argument("--round-pause-seconds", type=float, default=0)
    result.add_argument("--checkpoint-only-snapshots", action="store_true", help="Archive full weights only at checkpoints; still verify every round")
    result.add_argument("--seed", type=int, default=1337)
    result.add_argument("--prompt-count", type=int, default=256)
    result.add_argument("--target", default="127.0.0.1:50053")
    result.add_argument("--runtime-target", default="127.0.0.1:50054")
    result.add_argument("--model-target", default="127.0.0.1:50051")
    result.add_argument("--dataset-file", type=Path, required=True)
    result.add_argument("--dataset-sha256", default=DEVELOPMENT_SHA)
    result.add_argument("--curriculum-manifest", type=Path, required=True)
    result.add_argument("--output", type=Path, required=True)
    result.add_argument("--checkpoints", type=lambda value: [int(part) for part in value.split(",")], default=[0, 5, 10, 20])
    result.add_argument("--bootstrap-iterations", type=int, default=2000)
    result.add_argument("--cache-wait-seconds", type=float, default=2.1)
    result.add_argument("--no-mining", action="store_true")
    result.add_argument("--resume", action="store_true")
    result.add_argument("--operational-manifest", help="Frozen Docker image/settings record, verified before RPC training")
    return result


def main(argv=None):
    command = parser()
    args = command.parse_args(argv)
    if any(not math.isfinite(value) or value < 0 for value in (args.duration_seconds, args.checkpoint_interval_seconds, args.round_pause_seconds)):
        command.error("durations and intervals must be finite nonnegative seconds")
    if args.cycles < 1 or args.prompt_count < 1 or args.seed < 0 or args.seed + args.cycles > 2**32 or args.cache_wait_seconds < 0 or args.bootstrap_iterations < 0:
        command.error("cycles/count must be positive; seed, wait and bootstrap iterations must be valid nonnegative values")
    if any(value < 0 or value > args.cycles for value in args.checkpoints):
        command.error("checkpoints must be within the planned cycles")
    state = run(args)
    print(json.dumps({"status": state["status"], "output": str(args.output), "accepted_updates": {key: value["accepted_updates"] for key, value in state["models"].items()}}))
    return 0
