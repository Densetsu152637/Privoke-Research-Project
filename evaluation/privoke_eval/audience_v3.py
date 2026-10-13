"""AU3 continuation of CURRENT EN3 packages; closed EN3/PH3 records stay immutable.

Only TRAIN/NEW VAL may be opened here. Root acceptances bind actual dataset
review, automatic pilots, probes and audits; the comparison owns FRESH access.
"""
from __future__ import annotations

import copy
import math
from pathlib import Path
import time

import torch

from . import privacy_encoder_v3 as en
from . import audience_v3_data as data

STUDY_ID = data.STUDY_ID
TIERS = en.TIERS
DATA_PIN = "41cfd9e476f3d0a17c2a4997efab2afbb6b044c5fbd55217b0614525a2571fe0"
PARENTS = {
    "efficient": "4850180c40710949c91e37f8bfad5787eb00a43992b419e23bfb8fd24e8c703e",
    "balanced": "141dcd99e58becb0d1ee463da1bfdea9d31b92b1422b619777ee65be20954318",
    "quality": "1c5a962761b0699ac1bcf5b3753525819d7d4725e499f5a9f2eff295a06dccba",
}
ORIGINALS = {tier: pins[0] for tier, pins in en.ph.INITIAL_PINS.items()}
ANCESTRY = {"efficient": (12, 19, 24), "balanced": (7, 14, 19), "quality": (4, 4, 9)}
ASSETS = {"model.safetensors": "blob", "config.json": "config", "vocab.txt": "vocab"}
OWN_SOURCES = (
    "evaluation/privoke_eval/audience_v3.py", "evaluation/run-audience-v3.py",
    "evaluation/privoke_eval/audience_v3_comparison.py",
    "evaluation/privoke_eval/audience_v3_serving.py", "evaluation/audience-v3-server.py",
    "evaluation/tests/test_audience_v3.py", "evaluation/tests/test_audience_v3_comparison.py",
    "evaluation/privoke_eval/audience_v3_data.py", "evaluation/prepare-audience-v3.py",
)
require, read, retain = en.require, en.read, en.retain
file_hash, canonical, digest = en.file_hash, en.canonical, en.ph.digest


def recipe(train_rows):
    require(type(train_rows) is int and train_rows > 64, "Invalid TRAIN size")
    updates = math.ceil(train_rows / 64)
    return dict(en.POLICY, warmup_updates=updates, total_updates=30 * updates,
                train_rows=train_rows, updates_per_epoch=updates)


def sources(root):
    """Freeze integrated executable sources, never open held-out catalog text."""
    inventory = en.sources(root)
    inventory.update({p: file_hash(Path(root) / p) for p in OWN_SOURCES})
    return dict(sorted(inventory.items()))


def check_assets(directory, expected, *, original=False):
    from privoke_model.v3_contract import validate_manifest
    directory = Path(directory)
    require(file_hash(directory / "manifest.json") == expected, "Manifest pin differs")
    manifest = validate_manifest(read(directory / "manifest.json"))
    assets = ASSETS if original else dict(ASSETS, **{"evidence.json": "evidence"})
    for filename, key in assets.items():
        require(file_hash(directory / filename) == manifest[key], "Artifact asset differs: " + filename)
    config = read(directory / "config.json")
    require(config["hidden_dropout_prob"] == .1 and config["attention_probs_dropout_prob"] == .1,
            "Native dropout recipe changed")
    require(manifest["scope"] == ("original" if original else "full_encoder"), "Wrong artifact scope")
    return manifest


def retained_acceptance(path, expected, *, required_evidence=()):
    value = read(path)
    require(value.get("status") == "accepted" and all(value.get(k) == v for k, v in expected.items()),
            "Root acceptance differs: " + str(path))
    evidence = value.get("evidence_files", {})
    require(set(required_evidence) <= set(evidence), "Missing accepted review/pilot evidence")
    for item in evidence.values():
        require(file_hash(item["path"]) == item["sha256"], "Accepted evidence bytes differ")
    return file_hash(path)


def approval(results, name):
    return retained_acceptance(Path(results) / name, {
        "study_id": STUDY_ID, "protocol_sha256": file_hash(Path(results) / "protocol.json")})


def prepare(root, results, models, data_manifest, admission):
    root = en.configure(root, "cpu", 4)
    results, models, data_manifest = (Path(p).resolve() for p in (results, models, data_manifest))
    require(file_hash(data_manifest) == DATA_PIN, "Only reviewed AU3 release-07 admitted")
    manifest, train, validation = data.validate_training_data(data_manifest, root)
    inventory = sources(root)
    closure = digest(canonical(inventory))
    accepted = retained_acceptance(admission, {
        "study_id": STUDY_ID, "dataset_manifest_sha256": DATA_PIN, "source_closure": closure},
        required_evidence=("data_review", "normal_pilot", "v3_pilot"))
    parents = {}
    for tier in TIERS:
        origin = root / "models/experiments/privacy_encoder_v3_20261013/runs/cpu-01/exports" / tier / "selected"
        parent = check_assets(origin, PARENTS[tier])
        require(parent["original"] == ORIGINALS[tier], "Wrong linguistic ORIGINAL")
        original = root / "models/experiments/pretrained_v3_20261012/initials" / tier
        check_assets(original, ORIGINALS[tier], original=True)
        for filename in ("manifest.json", *ASSETS, "evidence.json"):
            retain(models / "initials" / tier / filename, (origin / filename).read_bytes())
        for filename in ("manifest.json", *ASSETS):
            retain(models / "originals" / tier / filename, (original / filename).read_bytes())
        parents[tier] = parent
    for name in inventory:
        retain(results / "source-bytes" / name, (root / name).read_bytes())
    retain(results / "preparation-acceptance.json", Path(admission).read_bytes())
    protocol = {"schema": 1, "study_id": STUDY_ID, "policy": recipe(len(train)),
                "dataset_manifest_sha256": DATA_PIN, "dataset_files": manifest["files"],
                "data_proof": manifest["audit"], "parents": parents, "originals": ORIGINALS,
                "source_files": inventory, "source_closure": closure,
                "environment": en.environment("cpu"), "device": "cpu", "threads": 4,
                "validation_rows": len(validation), "preparation_acceptance_sha256": accepted,
                "fresh_policy": "all_three_fits_all_six_exports_native_audits_then_root_test_seal",
                "selection": "NEW_validation_only", "baseline": "CURRENT_EN3_selected"}
    retain(results / "protocol.json", protocol)
    retain(results / "bindings.json", {"repository": str(root), "models": str(models),
                                      "data_manifest": str(data_manifest)})
    return protocol


def validate(results, *, check_environment=False):
    results = Path(results)
    protocol, binding = read(results / "protocol.json"), read(results / "bindings.json")
    en.ph.configure_repository(binding["repository"])
    require(protocol["schema"] == 1 and protocol["study_id"] == STUDY_ID
            and protocol["device"] == "cpu" and protocol["threads"] == 4
            and protocol["selection"] == "NEW_validation_only", "Wrong AU3 protocol")
    require(file_hash(binding["data_manifest"]) == DATA_PIN == protocol["dataset_manifest_sha256"], "Dataset pin drift")
    manifest, train, validation = data.validate_training_data(binding["data_manifest"], binding["repository"])
    require(protocol["policy"] == recipe(len(train)) and protocol["validation_rows"] == len(validation)
            and protocol["dataset_files"] == manifest["files"] and protocol["data_proof"] == manifest["audit"],
            "Dataset/recipe drift")
    require(sources(binding["repository"]) == protocol["source_files"]
            and digest(canonical(protocol["source_files"])) == protocol["source_closure"], "Integrated source drift")
    for name, sha in protocol["source_files"].items():
        require(file_hash(results / "source-bytes" / name) == sha, "Retained source drift")
    require(file_hash(results / "preparation-acceptance.json") == protocol["preparation_acceptance_sha256"],
            "Preparation acceptance drift")
    retained_acceptance(results / "preparation-acceptance.json", {
        "study_id": STUDY_ID, "dataset_manifest_sha256": DATA_PIN, "source_closure": protocol["source_closure"]},
        required_evidence=("data_review", "normal_pilot", "v3_pilot"))
    for tier in TIERS:
        parent = check_assets(Path(binding["models"]) / "initials" / tier, PARENTS[tier])
        require(parent == protocol["parents"][tier] and parent["original"] == ORIGINALS[tier]
                and protocol["originals"] == ORIGINALS, "Parent/ORIGINAL ancestry drift")
        check_assets(Path(binding["models"]) / "originals" / tier, ORIGINALS[tier], original=True)
    if check_environment:
        require(en.environment("cpu") == protocol["environment"], "Training environment drift")
    return protocol, binding, train, validation


def identity(results, protocol, tier):
    require(tier in TIERS, "Unknown tier")
    return {"study_id": STUDY_ID, "tier": tier, "parent": PARENTS[tier], "original": ORIGINALS[tier],
            "protocol_sha256": file_hash(Path(results) / "protocol.json"), "source_closure": protocol["source_closure"]}


def component_epochs(tier, selected, completed):
    heads, joint, old_completed = ANCESTRY[tier]
    require(1 <= selected <= completed, "Invalid component epochs")
    return {"encoder": {"inherited_selected": joint, "new_selected": selected, "new_completed": completed,
                        "cumulative_selected": joint + selected},
            "pooler": {"inherited_selected": joint, "new_selected": selected, "new_completed": completed,
                       "cumulative_selected": joint + selected},
            "heads": {"inherited_selected": heads + joint, "new_selected": selected, "new_completed": completed,
                      "cumulative_selected": heads + joint + selected},
            "source_stages": {"PH3_selected_heads": heads, "EN3_selected_joint": joint,
                              "EN3_completed_joint": old_completed, "official_pretraining_epochs": None}}


def cpu_rng_state():
    # EN3's generic RNG capture initializes CUDA if present. AU3 CPU fits must
    # not allocate a context or touch another workload's accelerator.
    state = en.np.random.get_state()
    return {"python": en.random.getstate(), "numpy": (state[0], state[1].tolist(), state[2], state[3], state[4]),
            "torch": torch.get_rng_state(), "cuda": []}


def validate_cpu_rng(value):
    """Prove complete CPU RNG restoration while preserving the auditor's state."""
    require(isinstance(value, dict) and set(value) == {"python", "numpy", "torch", "cuda"}
            and value["cuda"] == [] and isinstance(value["cuda"], list), "Incomplete CPU RNG checkpoint")
    require(isinstance(value["python"], tuple) and len(value["python"]) == 3, "Invalid Python RNG")
    numpy = value["numpy"]
    require(isinstance(numpy, tuple) and len(numpy) == 5 and numpy[0] == "MT19937"
            and isinstance(numpy[1], list) and len(numpy[1]) == 624
            and all(type(n) is int and 0 <= n < 2**32 for n in numpy[1])
            and type(numpy[2]) is int and 0 <= numpy[2] <= 624 and numpy[3] in (0, 1)
            and math.isfinite(numpy[4]), "Invalid NumPy RNG")
    require(isinstance(value["torch"], torch.Tensor) and value["torch"].device.type == "cpu"
            and value["torch"].dtype == torch.uint8 and value["torch"].shape == torch.get_rng_state().shape,
            "Invalid Torch CPU RNG")
    previous = cpu_rng_state()
    try:
        en.restore_rng(value)
        restored = cpu_rng_state()
        require(restored["python"] == value["python"] and restored["numpy"] == numpy
                and torch.equal(restored["torch"], value["torch"]), "CPU RNG does not round-trip")
    except (TypeError, RuntimeError) as error:
        raise ValueError("CPU RNG cannot restore") from error
    finally:
        en.restore_rng(previous)


def validate_checkpoint(saved, model, policy, identity_value, epoch, initial_checkpoint):
    """Audit complete restorable model/AdamW/CPU RNG evidence at each boundary."""
    fields = {"identity", "epoch", "optimizer_steps", "train_exposures", "best_loss", "best_epoch", "best_model",
              "stale_epochs", "model", "optimizer", "rng", "scheduler"}
    if epoch:
        fields |= {"epoch_record", "initial_checkpoint"}
    require(set(saved) == fields and saved["identity"] == identity_value and saved["epoch"] == epoch,
            "Incomplete checkpoint schema/identity")
    updates = epoch * policy["updates_per_epoch"]
    require(saved["optimizer_steps"] == updates and saved["train_exposures"] == epoch * policy["train_rows"],
            "Checkpoint counters differ")
    initial = en.cpu_state(model)
    require(set(saved["model"]) == set(initial), "Checkpoint model keys differ")
    for name, tensor in saved["model"].items():
        require(tensor.device.type == "cpu" and tensor.shape == initial[name].shape
                and tensor.dtype == torch.float32 and bool(torch.isfinite(tensor).all()), "Invalid checkpoint model tensor")
    if epoch:
        require(saved["initial_checkpoint"] == initial_checkpoint, "Epoch-zero ancestor differs")
    else:
        require(all(torch.equal(saved["model"][k], v) for k, v in initial.items())
                and saved["best_epoch"] == 0 and saved["best_model"] == {} and saved["best_loss"] == float("inf")
                and saved["stale_epochs"] == 0
                and saved["scheduler"] == {"completed_updates": 0, "next_update": 1, "last_scale": None}, "Epoch-zero state differs")
    validate_cpu_rng(saved["rng"])
    optimizer = en.make_optimizer(model, policy)
    if updates:
        en.set_update_lr(optimizer, updates, policy)
    expected = optimizer.state_dict()
    actual = saved["optimizer"]
    require(set(actual) == {"state", "param_groups"} and actual["param_groups"] == expected["param_groups"],
            "Checkpoint AdamW group/policy binding differs")
    parameters = {pid: p for group, live in zip(actual["param_groups"], optimizer.param_groups)
                  for pid, p in zip(group["params"], live["params"])}
    require(set(actual["state"]) == (set(parameters) if epoch else set()), "Incomplete optimizer state")
    for pid, state in actual["state"].items():
        require(set(state) == {"step", "exp_avg", "exp_avg_sq"}, "Incomplete AdamW tensor state")
        step = state["step"]
        require(isinstance(step, torch.Tensor) and step.device.type == "cpu" and step.numel() == 1
                and bool(torch.isfinite(step).all()) and float(step) == updates, "Optimizer completed steps differ")
        for key in ("exp_avg", "exp_avg_sq"):
            tensor = state[key]
            require(tensor.device.type == "cpu" and tensor.shape == parameters[pid].shape
                    and tensor.dtype == torch.float32 and bool(torch.isfinite(tensor).all()), "Invalid optimizer moment")
        require(bool((state["exp_avg_sq"] >= 0).all()), "Negative second moment")
    optimizer.load_state_dict(actual)
    restored = optimizer.state_dict()
    require(restored["param_groups"] == actual["param_groups"] and set(restored["state"]) == set(actual["state"]),
            "Optimizer cannot restore")
    for pid, state in actual["state"].items():
        require(all(torch.equal(restored["state"][pid][k], v) for k, v in state.items()), "Optimizer tensors cannot round-trip")


def probe(results, tier):
    results = Path(results)
    preliminary, binding = read(results / "protocol.json"), read(results / "bindings.json")
    en.configure(binding["repository"], "cpu", preliminary["threads"])
    protocol, binding, train, validation = validate(results, check_environment=True)
    accepted = approval(results, "probe-acceptance.json")
    require(not (results / "probe" / (tier + ".json")).exists(), "Probe already completed")
    _, model = en.load_model(Path(binding["models"]) / "initials" / tier)
    before, policy = en.cpu_state(model), protocol["policy"]
    optimizer = en.make_optimizer(model, policy)
    weights = en.ph.class_weights(en.ph.targets(train))
    chosen = train[:64]
    start = time.perf_counter()
    model.train()
    optimizer.zero_grad(set_to_none=True)
    parts = en.backward_batch(model, [r["text"] for r in chosen], en.ph.targets(chosen), weights)
    gradients = en.gradient_proof(model)
    norm = torch.nn.utils.clip_grad_norm_(model.parameters(), policy["clip_norm"], error_if_nonfinite=True)
    en.set_update_lr(optimizer, 1, policy)
    optimizer.step()
    changes = en.change_proof(before, model.state_dict())
    metrics = en.validation_metrics(model, validation[:32], weights)
    directory = Path(binding["models"]) / "probes" / tier
    directory.mkdir(parents=True, exist_ok=True)
    temporary = directory / "candidate.tmp"
    try:
        tensors = model.export(temporary)
        payload = temporary.read_bytes()
    finally:
        temporary.unlink(missing_ok=True)
    parent = protocol["parents"][tier]
    header = dict(parent, parent=PARENTS[tier], blob=digest(payload), tensors=tensors,
                  evidence=digest(canonical({"purpose": "AU3_probe"})))
    retain(directory / "model.safetensors", payload)
    retain(directory / "manifest.json", header)
    for filename in ("config.json", "vocab.txt"):
        retain(directory / filename, (Path(binding["models"]) / "initials" / tier / filename).read_bytes())
    _, reloaded = en.load_model(directory)
    result = {"identity": identity(results, protocol, tier), "status": "passed",
              "probe_acceptance_sha256": accepted, "gradient_groups": gradients, "changes": changes,
              "train_rows": 64, "validation_rows": 32, "loss_parts": parts, "validation": metrics,
              "seconds": time.perf_counter() - start, "gradient_norm_before_clip": float(norm),
              "reload": en.parity(model, reloaded, [r["text"] for r in validation[:16]]),
              "environment": en.environment("cpu"), "fresh_access": False}
    retain(results / "probe" / (tier + ".json"), result)
    return result


def fit(results, tier, *, resume=False):
    results = Path(results)
    binding = read(results / "bindings.json")
    en.configure(binding["repository"], "cpu", 4)
    protocol, binding, train, validation = validate(results, check_environment=True)
    accepted = approval(results, "prefit-acceptance.json")
    probes = read(results / "prefit-acceptance.json")["probe_sha256"]
    require(set(probes) == set(TIERS), "All three probes required")
    for candidate, sha in probes.items():
        path = results / "probe" / (candidate + ".json")
        record = read(path)
        require(file_hash(path) == sha and record["status"] == "passed"
                and record["identity"] == identity(results, protocol, candidate), "Probe pin differs")
        require(record["probe_acceptance_sha256"] == approval(results, "probe-acceptance.json"), "Probe gate drift")
    policy = protocol["policy"]
    models = Path(binding["models"])
    require(not (results / "fits" / tier / "complete.json").exists(), "Completed fit cannot be overwritten")
    ident = dict(identity(results, protocol, tier), prefit_acceptance_sha256=accepted)
    with en.ph.exclusive_run(models / "fit.lock"):
        _, model = en.load_model(models / "initials" / tier)
        initial = en.cpu_state(model)
        optimizer = en.make_optimizer(model, policy)
        weights = en.ph.class_weights(en.ph.targets(train))
        directory = models / "cells" / tier / "checkpoints"
        if resume:
            state = en.ph.restore_checkpoint(directory, ident)
            receipt = read(results / "fits" / tier / "epoch-zero.json")
            initial_checkpoint = receipt["checkpoint"]
            require(receipt["identity"] == ident and receipt["epoch"] == 0, "Epoch-zero receipt drift")
            validate_checkpoint(state, model, policy, ident, state["epoch"], initial_checkpoint)
            model.load_state_dict(state["model"], strict=True)
            optimizer.load_state_dict(state["optimizer"])
            en.restore_rng(state["rng"])
            require(state["scheduler"]["completed_updates"] == state["optimizer_steps"]
                    and state["scheduler"]["next_update"] == state["optimizer_steps"] + 1, "Resume scheduler drift")
            if state["epoch"]:
                retain(results / "fits" / tier / "epochs" / f"{state['epoch']:04d}.json",
                       dict(state["epoch_record"], checkpoint=read(directory / "latest.json")["sha256"]))
            state["initial_checkpoint"] = initial_checkpoint
        else:
            require(not (directory / "latest.json").exists(), "Existing state requires explicit resume")
            retain(results / "fits" / tier / "baseline-reference.json", en.validation_metrics(model, validation, weights))
            state = {"identity": ident, "epoch": 0, "optimizer_steps": 0, "train_exposures": 0,
                     "best_loss": float("inf"), "best_epoch": 0, "best_model": {}, "stale_epochs": 0}
            state.update(model=en.cpu_state(model), optimizer=copy.deepcopy(optimizer.state_dict()), rng=cpu_rng_state(),
                         scheduler={"completed_updates": 0, "next_update": 1, "last_scale": None})
            initial_checkpoint = en.ph.save_checkpoint(directory, state)
            retain(results / "fits" / tier / "epoch-zero.json", {"identity": ident, "checkpoint": initial_checkpoint, "epoch": 0})
            state["initial_checkpoint"] = initial_checkpoint
        start = time.monotonic()
        stopped = state["epoch"] >= policy["min_epochs"] and state["stale_epochs"] >= policy["patience"]
        for epoch in range(state["epoch"] + 1, state["epoch"] + 1 if stopped else policy["max_epochs"] + 1):
            validate(results, check_environment=True)
            work = en.train_epoch(model, optimizer, train, weights, epoch, state["optimizer_steps"], policy)
            metrics = en.validation_metrics(model, validation, weights)
            selected = en.select(state, metrics["weighted_objective"], epoch, model, policy)
            state.update(epoch=epoch, optimizer_steps=work["updates"],
                         train_exposures=state["train_exposures"] + len(train), model=en.cpu_state(model),
                         optimizer=copy.deepcopy(optimizer.state_dict()), rng=cpu_rng_state(), scheduler=work["scheduler"])
            state["epoch_record"] = {"epoch": epoch, "work": work, "validation": metrics, "selected": selected,
                                     "best_epoch": state["best_epoch"], "best_loss": state["best_loss"],
                                     "stale_epochs": state["stale_epochs"], "changes": en.change_proof(initial, state["model"])}
            checkpoint = en.ph.save_checkpoint(directory, state)
            retain(results / "fits" / tier / "epochs" / f"{epoch:04d}.json", dict(state["epoch_record"], checkpoint=checkpoint))
            print(canonical({"tier": tier, "epoch": epoch, "validation": metrics["weighted_objective"],
                             "best_epoch": state["best_epoch"], "stale_epochs": state["stale_epochs"]}).decode(), flush=True)
            if epoch >= policy["min_epochs"] and state["stale_epochs"] >= policy["patience"]:
                break
        require(state["epoch"] >= policy["min_epochs"] and state["best_epoch"] >= 1, "Incomplete fit")
        summary = {k: state[k] for k in ("identity", "epoch", "best_epoch", "best_loss", "optimizer_steps", "train_exposures")}
        summary.update(checkpoint=read(directory / "latest.json")["sha256"],
                       initial_checkpoint=initial_checkpoint,
                       seconds_this_invocation=time.monotonic() - start, resumed=resume,
                       stop_reason="validation_patience" if state["stale_epochs"] >= policy["patience"] else "max_epochs",
                       components=component_epochs(tier, state["best_epoch"], state["epoch"]),
                       publication="local_research_only", fresh_access=False)
        retain(results / "fits" / tier / "complete.json", summary)
    return summary


def training_state(results, tier):
    protocol, binding, _, validation = validate(results)
    summary = read(Path(results) / "fits" / tier / "complete.json")
    expected = dict(identity(results, protocol, tier), prefit_acceptance_sha256=approval(results, "prefit-acceptance.json"))
    directory = Path(binding["models"]) / "cells" / tier / "checkpoints"
    state = en.ph.restore_checkpoint(directory, expected)
    receipt = read(Path(results) / "fits" / tier / "epoch-zero.json")
    require(summary["identity"] == expected and summary["checkpoint"] == read(directory / "latest.json")["sha256"]
            and summary["epoch"] == state["epoch"] >= protocol["policy"]["min_epochs"]
            and summary["best_epoch"] == state["best_epoch"] >= 1 and summary["best_loss"] == state["best_loss"]
            and state["initial_checkpoint"] == summary["initial_checkpoint"] == receipt["checkpoint"]
            and receipt["identity"] == expected and receipt["epoch"] == 0
            and summary["components"] == component_epochs(tier, state["best_epoch"], state["epoch"]), "Fit state drift")
    return protocol, binding, validation, summary, state


def export(results, tier):
    protocol, binding, validation, summary, state = training_state(results, tier)
    en.configure(binding["repository"], "cpu", 4)
    require(en.environment("cpu") == protocol["environment"], "Export must use training environment")
    models = Path(binding["models"])
    parent, model = en.load_model(models / "initials" / tier)
    initial, outputs = en.cpu_state(model), {}
    for kind, key, epoch in (("selected", "best_model", state["best_epoch"]), ("terminal", "model", state["epoch"])):
        model.load_state_dict(state[key], strict=True)
        model.eval()
        directory = models / "exports" / tier / kind
        directory.mkdir(parents=True, exist_ok=True)
        temporary = directory / "candidate.tmp"
        try:
            tensors = model.export(temporary)
            payload = temporary.read_bytes()
        finally:
            temporary.unlink(missing_ok=True)
        evidence = {"schema": 1, "identity": identity(results, protocol, tier), "scope": "full_encoder", "layers": [4],
                    "kind": kind, "epoch": epoch, "policy": protocol["policy"], "checkpoint": summary["checkpoint"],
                    "fit_summary_sha256": file_hash(Path(results) / "fits" / tier / "complete.json"),
                    "candidate_blob": digest(payload), "changes": en.change_proof(initial, state[key]),
                    "components": component_epochs(tier, epoch, state["epoch"]), "publication": "local_research_only"}
        manifest = dict(parent, parent=PARENTS[tier], blob=digest(payload), tensors=tensors, evidence=digest(canonical(evidence)))
        for filename, value in (("model.safetensors", payload), ("manifest.json", manifest), ("evidence.json", evidence)):
            retain(directory / filename, value)
        for filename in ("config.json", "vocab.txt"):
            retain(directory / filename, (models / "initials" / tier / filename).read_bytes())
        _, reloaded = en.load_model(directory)
        require(all(torch.equal(reloaded.state_dict()[k], v) for k, v in state[key].items()), "Export arrays differ")
        retain(directory / "cpu-reload-parity.json", en.parity(model, reloaded, [r["text"] for r in validation[:16]]))
        outputs[kind] = {"directory": str(directory), "manifest_sha256": file_hash(directory / "manifest.json"),
                         "blob": manifest["blob"], "evidence": manifest["evidence"], "epoch": epoch,
                         "cpu_parity_sha256": file_hash(directory / "cpu-reload-parity.json")}
    retain(Path(results) / "exports" / (tier + ".json"), outputs)
    return outputs


def validate_exports(results, tier):
    protocol, binding, validation, summary, state = training_state(results, tier)
    outputs = read(Path(results) / "exports" / (tier + ".json"))
    require(set(outputs) == {"selected", "terminal"}, "Both exports required")
    _, initial = en.load_model(Path(binding["models"]) / "initials" / tier)
    for kind, item in outputs.items():
        directory = Path(item["directory"])
        require(directory.resolve().is_relative_to(Path(binding["models"]).resolve()), "Export escapes model store")
        manifest = check_assets(directory, item["manifest_sha256"])
        key = "best_model" if kind == "selected" else "model"
        epoch = state["best_epoch"] if kind == "selected" else state["epoch"]
        evidence = read(directory / "evidence.json")
        expected = {"schema": 1, "identity": identity(results, protocol, tier), "scope": "full_encoder", "layers": [4],
                    "kind": kind, "epoch": epoch, "policy": protocol["policy"], "checkpoint": summary["checkpoint"],
                    "fit_summary_sha256": file_hash(Path(results) / "fits" / tier / "complete.json"),
                    "candidate_blob": manifest["blob"], "changes": en.change_proof(en.cpu_state(initial), state[key]),
                    "components": component_epochs(tier, epoch, state["epoch"]), "publication": "local_research_only"}
        require(evidence == expected and manifest["parent"] == PARENTS[tier]
                and manifest["original"] == ORIGINALS[tier] and item["epoch"] == epoch
                and item["blob"] == manifest["blob"] and item["evidence"] == manifest["evidence"], "Export provenance drift")
        require(file_hash(directory / "cpu-reload-parity.json") == item["cpu_parity_sha256"], "Reload proof drift")
        _, loaded = en.load_model(directory)
        require(all(torch.equal(loaded.state_dict()[k], v) for k, v in state[key].items()), "Export/checkpoint arrays differ")
    return protocol, binding, validation, outputs


def capture_native(results, tier):
    """Capture actual native forward/RPC values on NEW VAL16 in either host env."""
    from . import privacy_heads_v3_comparison as raw
    from . import audience_v3_comparison as comparison
    import threading
    binding = read(Path(results) / "bindings.json")
    en.configure(binding["repository"], "cpu", 4)
    from runtime_server import RuntimeServer
    protocol, _, validation, outputs = validate_exports(results, tier)
    environment = en.environment("cpu")
    require(environment["packages"]["torch"] in ("2.12.0+cu130", "2.11.0+cpu"), "Unadmitted capture environment")
    records = {}
    for kind, item in outputs.items():
        path = Path(results) / "native-captures" / tier / kind / (digest(canonical(environment)) + ".json")
        if path.exists():
            previous = read(path)
            require(previous["identity"] == identity(results, protocol, tier) and previous["kind"] == kind
                    and previous["manifest_sha256"] == item["manifest_sha256"] and previous["blob"] == item["blob"]
                    and previous["environment"] == environment
                    and [(r["id"], r["text_sha256"]) for r in previous["rows"]]
                    == [(r["id"], digest(r["text"].encode())) for r in validation[:16]], "Existing native capture differs")
            records[kind] = {"path": str(path), "sha256": file_hash(path)}
            continue
        manifest, model = en.load_model(item["directory"])
        model.eval()
        for parameter in model.parameters():
            parameter.requires_grad_(False)
        entry = {"name": "au3-" + tier + "-" + kind, "family": "v3", **item,
                 "identity": comparison.model_identity(manifest, item["manifest_sha256"])}

        class Native(RuntimeServer):
            def __init__(self):
                self.device, self.lock = "cpu", threading.RLock()
                self.cache = {entry["manifest_sha256"]: (manifest, model)}

        native = Native()
        rows = []
        for index, row in enumerate(validation[:16]):
            request = raw.request_for(entry, row, "au3-val-parity-" + str(index))
            response = native.AnalyzePrompt(request, None)
            outcome = raw.response_record(response, entry, request)
            require(outcome["status"] == "ok", "Native validation capture failed")
            with torch.no_grad():
                logits = {k: v[0].tolist() for k, v in model([row["text"]]).items()}
            rows.append({"id": row["id"], "text_sha256": digest(row["text"].encode()), "logits": logits,
                         "values": en.prediction_values(model, [row["text"]])[0],
                         "request_hex": request.SerializeToString(deterministic=True).hex(),
                         "response_hex": response.SerializeToString(deterministic=True).hex(),
                         "native_classification": outcome["classification"], "native_action": outcome["action"]})
        capture = {"identity": identity(results, protocol, tier), "kind": kind,
                   "manifest_sha256": item["manifest_sha256"], "blob": item["blob"],
                   "native_identity": entry["identity"],
                   "environment": environment, "rows": rows, "fresh_access": False}
        retain(path, capture)
        records[kind] = {"path": str(path), "sha256": file_hash(path)}
    return records


def compare_captures(a, b):
    """Compare independent raw captures; this is not same-env reload parity."""
    from . import privacy_heads_v3_comparison as raw
    from privoke.v1 import runtime_pb2
    for key in ("identity", "native_identity", "kind", "manifest_sha256", "blob"):
        require(a[key] == b[key], "Cross-version artifact identity drift")
    for item in (a, b):
        require(item["environment"]["torch_threads"] == 4 and item["environment"]["deterministic"]
                and len(item["rows"]) == 16 and item["fresh_access"] is False, "Incomplete native capture")
    require(a["environment"]["packages"]["torch"] == "2.12.0+cu130"
            and b["environment"]["packages"]["torch"] == "2.11.0+cpu", "Actual training/native versions required")
    require({k: v for k, v in a["environment"]["packages"].items() if k != "torch"}
            == {k: v for k, v in b["environment"]["packages"].items() if k != "torch"}, "Native ancillary versions differ")
    maximum = 0.
    for x, y in zip(a["rows"], b["rows"]):
        require(x["id"] == y["id"] and x["text_sha256"] == y["text_sha256"]
                and x["request_hex"] == y["request_hex"], "Native capture sample differs")
        for task in en.ph.LABELS:
            left, right = torch.tensor(x["logits"][task]), torch.tensor(y["logits"][task])
            require(left.shape == right.shape == (len(en.ph.LABELS[task]),)
                    and bool(torch.isfinite(left).all() and torch.isfinite(right).all())
                    and torch.allclose(left, right, atol=1e-5, rtol=1e-4), "Cross-version logits differ")
            maximum = max(maximum, float((left - right).abs().max()))
        for record in (x, y):
            request = runtime_pb2.AnalyzePromptRequest.FromString(bytes.fromhex(record["request_hex"]))
            response = runtime_pb2.AnalyzePromptResponse.FromString(bytes.fromhex(record["response_hex"]))
            require(list(request.layers) == [4] and not request.visibility_hint
                    and not request.HasField("semantic_presence_gate")
                    and digest(request.text.encode()) == record["text_sha256"]
                    and request.metadata.get("v3_checkpoint") == a["manifest_sha256"], "Native parity request isolation differs")
            outcome = raw.response_record(response, {"identity": a["native_identity"]}, request)
            require(outcome["status"] == "ok" and outcome["classification"] == record["native_classification"]
                    and outcome["action"] == record["native_action"]
                    and record["values"]["named"] == outcome["classification"]
                    and record["values"]["packed"] == response.classification.packed
                    and record["values"]["action"] == outcome["action"], "Raw native response differs")
        require(x["native_classification"] == y["native_classification"] and x["native_action"] == y["native_action"],
                "Cross-version native discrete/action differs")
        require({k: v for k, v in x["values"].items() if k != "confidence"}
                == {k: v for k, v in y["values"].items() if k != "confidence"}
                and abs(x["values"]["confidence"] - y["values"]["confidence"]) <= .001, "Cross-version values differ")
    return {"rows": 16, "max_abs_logit_error": maximum, "atol": 1e-5, "rtol": 1e-4,
            "confidence_atol": .001, "exact_discrete_and_action": True}


def verify_native(results, tier):
    from . import audience_v3_comparison as comparison
    protocol, _, validation, outputs = validate_exports(results, tier)
    verified = {}
    for kind, item in outputs.items():
        captures = [(p, read(p)) for p in (Path(results) / "native-captures" / tier / kind).glob("*.json")]
        by_version = {v: [(p, c) for p, c in captures if c["environment"]["packages"]["torch"] == v]
                      for v in ("2.12.0+cu130", "2.11.0+cpu")}
        require(all(len(v) == 1 for v in by_version.values()), "Exactly two independent native captures required")
        (pa, a), (pb, b) = [v[0] for v in by_version.values()]
        require(a["manifest_sha256"] == item["manifest_sha256"] and a["blob"] == item["blob"]
                and a["identity"] == identity(results, protocol, tier) and a["kind"] == kind
                and a["native_identity"] == comparison.model_identity(read(Path(item["directory"]) / "manifest.json"), item["manifest_sha256"]),
                "Capture export binding differs")
        require([(r["id"], r["text_sha256"]) for r in a["rows"]]
                == [(r["id"], digest(r["text"].encode())) for r in validation[:16]], "Capture NEW VAL sample drift")
        verified[kind] = {"proof": compare_captures(a, b), "raw": {str(pa): file_hash(pa), str(pb): file_hash(pb)}}
    result = {"identity": identity(results, protocol, tier), "status": "passed", "exports": verified}
    retain(Path(results) / "native-verification" / (tier + ".json"), result)
    return result


def audit_training(results, tier):
    protocol, binding, _, summary, state = training_state(results, tier)
    policy = protocol["policy"]
    directory = Path(binding["models"]) / "cells" / tier / "checkpoints"
    _, initial = en.load_model(Path(binding["models"]) / "initials" / tier)
    initial_state = en.cpu_state(initial)
    receipt_path = Path(results) / "fits" / tier / "epoch-zero.json"
    require(receipt_path.is_file(), "Missing epoch-zero receipt")
    receipt = read(receipt_path)
    require(receipt == {"identity": summary["identity"], "checkpoint": summary["initial_checkpoint"], "epoch": 0},
            "Epoch-zero receipt binding differs")
    zero_path = directory / (receipt["checkpoint"] + ".pt")
    require(file_hash(zero_path) == receipt["checkpoint"], "Epoch-zero checkpoint drift")
    validate_checkpoint(en.ph.load_torch(zero_path), initial, policy, summary["identity"], 0, receipt["checkpoint"])
    checkpoint_inventory = {str(receipt_path): file_hash(receipt_path), str(zero_path): receipt["checkpoint"]}
    best, best_epoch, stale, updates, exposures = float("inf"), 0, 0, 0, 0
    for epoch in range(1, state["epoch"] + 1):
        row = read(Path(results) / "fits" / tier / "epochs" / f"{epoch:04d}.json")
        checkpoint = directory / (row["checkpoint"] + ".pt")
        require(file_hash(checkpoint) == row["checkpoint"], "Epoch checkpoint drift")
        saved = en.ph.load_torch(checkpoint)
        validate_checkpoint(saved, initial, policy, summary["identity"], epoch, receipt["checkpoint"])
        checkpoint_inventory[str(checkpoint)] = row["checkpoint"]
        epoch_path = Path(results) / "fits" / tier / "epochs" / f"{epoch:04d}.json"
        checkpoint_inventory[str(epoch_path)] = file_hash(epoch_path)
        require(saved["identity"] == summary["identity"] and saved["epoch"] == epoch
                and dict(row, checkpoint=None) == dict(saved["epoch_record"], checkpoint=None), "Epoch binding differs")
        work = row["work"]
        updates += policy["updates_per_epoch"]
        exposures += policy["train_rows"]
        require(work["epoch"] == epoch and work["optimizer_steps"] == policy["updates_per_epoch"]
                and work["train_exposures"] == policy["train_rows"] and work["updates"] == updates
                and saved["optimizer_steps"] == updates and saved["train_exposures"] == exposures
                and saved["scheduler"] == work["scheduler"]
                and work["scheduler"] == {"completed_updates": updates, "next_update": updates + 1,
                                         "last_scale": en.lr_scale(updates, policy)}, "Work/scheduler drift")
        loss = row["validation"]["weighted_objective"]
        require(math.isfinite(loss), "Nonfinite validation selection")
        improved = loss < best - policy["min_delta"]
        if improved:
            best, best_epoch, stale, best_model = loss, epoch, 0, saved["model"]
        else:
            stale += 1
        require(row["selected"] == improved and row["best_epoch"] == saved["best_epoch"] == best_epoch
                and row["best_loss"] == saved["best_loss"] == best and row["stale_epochs"] == saved["stale_epochs"] == stale
                and all(torch.equal(saved["best_model"][k], v) for k, v in best_model.items()), "Selection replay differs")
        require(all(row["changes"]["groups_changed"].values())
                and set(work["gradient_groups"]) == set(row["changes"]["groups_changed"])
                and row["changes"] == en.change_proof(initial_state, saved["model"]), "Full-component evidence incomplete")
        optimizer_ids = [p for group in saved["optimizer"]["param_groups"] for p in group["params"]]
        require(len(optimizer_ids) == len(set(optimizer_ids)) == len(initial_state)
                and set(optimizer_ids) == set(saved["optimizer"]["state"])
                and all(float(v["step"]) == updates for v in saved["optimizer"]["state"].values()), "Optimizer completed work differs")
        require(not (epoch < state["epoch"] and epoch >= policy["min_epochs"] and stale >= policy["patience"]), "Ran past stop")
    require(state["epoch"] <= policy["max_epochs"] and (state["epoch"] == policy["max_epochs"] or stale >= policy["patience"])
            and summary["optimizer_steps"] == updates and summary["train_exposures"] == exposures
            and state["best_epoch"] == best_epoch and state["best_loss"] == best, "Incomplete terminal work")
    native = verify_native(results, tier)
    result = {"identity": identity(results, protocol, tier), "status": "passed", "epochs_checked": state["epoch"],
              "epoch_zero_receipt_sha256": file_hash(receipt_path), "initial_checkpoint": receipt["checkpoint"],
              "cpu_rng_boundaries_checked": state["epoch"] + 1,
              "checkpoint_inventory": checkpoint_inventory,
              "best_epoch": best_epoch, "components": summary["components"],
              "native_verification_sha256": file_hash(Path(results) / "native-verification" / (tier + ".json")),
              "exports_sha256": file_hash(Path(results) / "exports" / (tier + ".json")), "native": native}
    retain(Path(results) / "training-audit" / (tier + ".json"), result)
    return result
