"""EN3 host full-encoder continuation; PH3 evidence and sources stay immutable."""
from __future__ import annotations

import copy
import math
import os
from pathlib import Path
import random
import time

import numpy as np
import torch
from torch.nn import functional as F

from . import privacy_heads_v3 as ph

STUDY_ID = "privacy_encoder_v3_20261013"
TIERS = ph.TIERS
SELECTED_PINS = {
    "efficient": "630a319ef482a1cc82e7c1122fe36d8e13503d681cbfc402838deedc09a4070c",
    "balanced": "5dfea2eb4ace6f3bc29ffed08e23bd138e7c7fce74a05d27d022260f4525c2d0",
    "quality": "dc656b2fca3e5debd541645842c8ddd4591bf7bb97a9abf84b7d36294b61e177",
}
DATA_PIN = "9f443b0123c65caec2fbf9aa9ff213578841f28068e094e91593e3cc7de08da1"
POLICY = {
    "schema": 1, "scope": "full_encoder", "layers": [4], "seed": 42,
    "encoder_lr": 2e-5, "head_lr": 1e-4, "weight_decay": .01,
    "betas": [.9, .999], "eps": 1e-8, "clip_norm": 1.,
    "microbatch": 16, "effective_batch": 64, "warmup_updates": 98,
    "total_updates": 2940, "min_epochs": 5, "max_epochs": 30,
    "patience": 5, "min_delta": 1e-4, "dropout": .1,
    "selection": "best_trained_validation_loss_earliest_strict_delta",
    "baseline": "reference_only", "category_threshold": .5,
    "objective": ph.POLICY["objective"], "precision": "float32",
}
NEW_SOURCES = ("evaluation/privoke_eval/privacy_encoder_v3.py",
               "evaluation/run-privacy-encoder-v3.py",
               "evaluation/privoke_eval/privacy_encoder_v3_serving.py",
               "evaluation/privacy-encoder-v3-server.py",
               "evaluation/privoke_eval/privacy_encoder_v3_comparison.py")
require = ph.require
read = ph.read
retain = ph.retain
canonical = ph.canonical
file_hash = ph.file_hash


def configure(root, device="cpu", threads=4):
    root = ph.configure_repository(root)
    require(device in ("cpu", "cuda"), "Device must be cpu or cuda")
    if device == "cuda":
        require(torch.cuda.is_available(), "CUDA unavailable; do not silently fall back")
        os.environ.setdefault("CUBLAS_WORKSPACE_CONFIG", ":4096:8")
        require(os.environ["CUBLAS_WORKSPACE_CONFIG"] in (":4096:8", ":16:8"), "Invalid deterministic CUBLAS setting")
    ph.deterministic(threads)
    np.random.seed(POLICY["seed"])
    torch.backends.cuda.matmul.allow_tf32 = False
    torch.backends.cudnn.allow_tf32 = False
    torch.backends.cudnn.benchmark = False
    torch.backends.cudnn.deterministic = True
    torch.set_float32_matmul_precision("highest")
    if device == "cuda":
        torch.cuda.manual_seed_all(POLICY["seed"])
    return root


def environment(device):
    value = ph.environment()
    value.update(device=device, cuda_build=torch.version.cuda,
                 gpu=torch.cuda.get_device_name(0) if device == "cuda" else None,
                 cublas_workspace=os.getenv("CUBLAS_WORKSPACE_CONFIG"),
                 tf32=False, precision="float32")
    return value


def sources(root):
    value = ph.source_inventory(root)
    value.update({name: file_hash(Path(root)/name) for name in NEW_SOURCES})
    return dict(sorted(value.items()))


def load_model(directory, device="cpu"):
    from src.v3.model import PretrainedV3
    directory = Path(directory)
    manifest = read(directory/"manifest.json")
    model = PretrainedV3.load(manifest, directory/"model.safetensors",
                             directory/"config.json", directory/"vocab.txt", device=device)
    for parameter in model.parameters():
        parameter.requires_grad_(True)
    require(all(p.dtype == torch.float32 for p in model.parameters()), "Full float32 required")
    return manifest, model


def prepare(root, results, models, data_manifest, *, device="cpu", threads=4):
    root = configure(root, device, threads)
    results, models, data_manifest = Path(results).resolve(), Path(models).resolve(), Path(data_manifest).resolve()
    require(file_hash(data_manifest) == DATA_PIN, "Only admitted PH3 R3 data allowed")
    data, _, _ = ph.validate_training_data(data_manifest, root)
    initial = {}
    for tier in TIERS:
        origin = root/"models/experiments"/ph.STUDY_ID/"exports"/tier/"selected"
        require(file_hash(origin/"manifest.json") == SELECTED_PINS[tier], "PH3 selected pin changed")
        manifest, model = load_model(origin)
        require(manifest["scope"] == "heads" and manifest["original"] == ph.INITIAL_PINS[tier][0], "Wrong ancestry")
        for name in ("manifest.json", "model.safetensors", "config.json", "vocab.txt", "evidence.json"):
            retain(models/"initials"/tier/name, (origin/name).read_bytes())
        initial[tier] = {"manifest_sha256": SELECTED_PINS[tier], "manifest": manifest}
        del model
    inventory = sources(root)
    for name in inventory:
        retain(results/"source-bytes"/name, (root/name).read_bytes())
    protocol = {"schema": 1, "study_id": STUDY_ID, "policy": POLICY,
                "dataset_manifest_sha256": DATA_PIN, "dataset_files": data["files"],
                "initials": initial, "source_files": inventory,
                "source_closure": ph.digest(canonical(inventory)),
                "environment": environment(device), "device": device, "threads": threads,
                "development_policy": "opened_PH3_fresh_is_reused_DEVELOPMENT_no_selection"}
    retain(results/"protocol.json", protocol)
    retain(results/"bindings.json", {"repository": str(root), "models": str(models),
                                    "data_manifest": str(data_manifest)})
    return protocol


def validate(results, *, check_environment=True):
    results = Path(results)
    protocol, binding = read(results/"protocol.json"), read(results/"bindings.json")
    require(protocol["schema"] == 1 and protocol["study_id"] == STUDY_ID and protocol["policy"] == POLICY,
            "Wrong EN3 protocol/recipe")
    ph.configure_repository(binding["repository"])
    if check_environment:
        require(environment(protocol["device"]) == protocol["environment"], "Environment changed")
    require(sources(binding["repository"]) == protocol["source_files"], "Integrated source drift")
    require(ph.digest(canonical(protocol["source_files"])) == protocol["source_closure"], "Source closure changed")
    for name, sha in protocol["source_files"].items():
        require(file_hash(results/"source-bytes"/name) == sha, "Retained source changed")
    require(file_hash(binding["data_manifest"]) == DATA_PIN == protocol["dataset_manifest_sha256"], "Data pin drift")
    data, train, validation = ph.validate_training_data(binding["data_manifest"], binding["repository"])
    require(data["files"] == protocol["dataset_files"], "Data file binding drift")
    for tier in TIERS:
        path = Path(binding["models"])/"initials"/tier
        require(file_hash(path/"manifest.json") == SELECTED_PINS[tier], "Initial manifest drift")
        require(read(path/"manifest.json") == protocol["initials"][tier]["manifest"], "Initial inventory drift")
    return protocol, binding, train, validation


def approval(results, name):
    value = read(Path(results)/name)
    require(value.get("status") == "accepted" and value.get("study_id") == STUDY_ID
            and value.get("protocol_sha256") == file_hash(Path(results)/"protocol.json"), "Root acceptance required: "+name)
    return file_hash(Path(results)/name)


def lr_scale(update, policy=POLICY):
    require(type(update) is int and 1 <= update <= policy["total_updates"], "Update outside schedule")
    warmup, total = policy["warmup_updates"], policy["total_updates"]
    return update/warmup if update <= warmup else (total-update)/(total-warmup)


def make_optimizer(model, policy=POLICY):
    groups = {}
    named = dict(model.named_parameters())
    for name, parameter in named.items():
        require(parameter.requires_grad, "Frozen parameter in full fit: "+name)
        head = name.startswith("heads.")
        decay = parameter.ndim > 1 and "LayerNorm" not in name
        key = head, decay
        groups.setdefault(key, {"params": [], "names": [], "base_lr": policy["head_lr"] if head else policy["encoder_lr"],
                                "weight_decay": policy["weight_decay"] if decay else 0.})
        groups[key]["params"].append(parameter)
        groups[key]["names"].append(name)
    optimizer = torch.optim.AdamW(list(groups.values()), lr=policy["encoder_lr"],
                                  betas=tuple(policy["betas"]), eps=policy["eps"])
    actual = [id(p) for g in optimizer.param_groups for p in g["params"]]
    require(len(actual) == len(set(actual)) == len(named) and set(actual) == {id(p) for p in named.values()},
            "Optimizer coverage incomplete/duplicated")
    return optimizer


def set_update_lr(optimizer, update, policy=POLICY):
    scale = lr_scale(update, policy)
    for group in optimizer.param_groups:
        group["lr"] = group["base_lr"]*scale
    return {"completed_updates": update-1, "next_update": update, "scale": scale}


def cpu_state(model):
    return {k: v.detach().cpu().clone() for k, v in model.state_dict().items()}


def rng_state():
    state = np.random.get_state()
    return {"python": random.getstate(), "numpy": (state[0], state[1].tolist(), state[2], state[3], state[4]),
            "torch": torch.get_rng_state(), "cuda": torch.cuda.get_rng_state_all() if torch.cuda.is_available() else []}


def restore_rng(value):
    random.setstate(value["python"])
    s = value["numpy"]
    np.random.set_state((s[0], np.array(s[1], dtype=np.uint32), s[2], s[3], s[4]))
    torch.set_rng_state(value["torch"])
    if value["cuda"]:
        require(torch.cuda.is_available(), "CUDA RNG cannot restore on CPU-only host")
        torch.cuda.set_rng_state_all(value["cuda"])


def device_truth(truth, device):
    return {k: v.to(device) for k, v in truth.items()}


def loss_numerators(logits, truth, weights):
    parts = {task: F.cross_entropy(logits[task], truth[task], weight=weights[task], reduction="sum")
             for task in ("sensitivity", "visibility")}
    parts["category"] = F.binary_cross_entropy_with_logits(logits["category"], truth["category"],
                                                           pos_weight=weights["category"], reduction="sum")
    require(all(bool(torch.isfinite(v)) for v in parts.values()), "Nonfinite loss")
    return parts


def denominators(truth, weights):
    return {"sensitivity": weights["sensitivity"][truth["sensitivity"]].sum(),
            "visibility": weights["visibility"][truth["visibility"]].sum(),
            "category": truth["category"].numel()}


def backward_batch(model, texts, truth, weights, microbatch=16):
    """Global effective-batch denominators preserve weighted-CE arithmetic."""
    den = denominators(truth, weights)
    totals = {k: 0. for k in ph.LABELS}
    for begin in range(0, len(texts), microbatch):
        sub = {k: v[begin:begin+microbatch] for k, v in truth.items()}
        parts = loss_numerators(model(texts[begin:begin+microbatch]), sub, weights)
        loss = sum(parts[k]/den[k] for k in parts)
        loss.backward()
        for k, v in parts.items():
            totals[k] += float(v.detach())/float(den[k])
    return totals


def parameter_group(name):
    if name.startswith("heads."):
        return name
    if name.startswith("encoder.pooler."):
        return "pooler"
    if "encoder.layer." in name:
        return "layer."+name.split("encoder.layer.", 1)[1].split(".")[0]
    return "embeddings"


def gradient_proof(model):
    groups = {}
    for name, p in model.named_parameters():
        require(p.grad is not None and bool(torch.isfinite(p.grad).all()), "Missing/nonfinite gradient: "+name)
        key = parameter_group(name)
        groups[key] = groups.get(key, False) or bool(torch.count_nonzero(p.grad))
    require(all(groups.values()), "Entire parameter group has zero gradient")
    return groups


def change_proof(before, after):
    require(set(before) == set(after), "Model tensor keys changed")
    groups = {}
    changed = []
    for name in before:
        key = parameter_group(name)
        different = not torch.equal(before[name], after[name].detach().cpu())
        groups[key] = groups.get(key, False) or different
        if different:
            changed.append(name)
    require(all(groups.values()), "Full-model stage left an entire group unchanged")
    return {"groups_changed": groups, "changed_tensors": changed}


def train_epoch(model, optimizer, rows, weights, epoch, updates=0, policy=POLICY):
    model.train()
    order = torch.randperm(len(rows), generator=torch.Generator().manual_seed(policy["seed"]+epoch))
    norms, losses, groups = [], [], set()
    for begin in range(0, len(rows), policy["effective_batch"]):
        chosen = [rows[i] for i in order[begin:begin+policy["effective_batch"]].tolist()]
        optimizer.zero_grad(set_to_none=True)
        truth = device_truth(ph.targets(chosen), model.device_name)
        parts = backward_batch(model, [r["text"] for r in chosen], truth, weights, policy["microbatch"])
        proof = gradient_proof(model)
        groups.update(k for k, v in proof.items() if v)
        norm = torch.nn.utils.clip_grad_norm_(model.parameters(), policy["clip_norm"], error_if_nonfinite=True)
        updates += 1
        set_update_lr(optimizer, updates, policy)
        optimizer.step()
        require(all(bool(torch.isfinite(p).all()) for p in model.parameters()), "Nonfinite updated model")
        norms.append(float(norm))
        losses.append(parts)
    return {"epoch": epoch, "updates": updates, "optimizer_steps": len(losses), "train_exposures": len(rows),
            "permutation_sha256": ph.digest(order.numpy().tobytes()), "gradient_groups": sorted(groups),
            "gradient_norms_before_clip": norms, "batch_task_losses": losses,
            "scheduler": {"completed_updates": updates, "next_update": updates+1,
                          "last_scale": lr_scale(updates, policy)}}


def validation_metrics(model, rows, weights, batch=16):
    model.eval()
    truth = ph.targets(rows)
    logits = {k: [] for k in ph.LABELS}
    with torch.no_grad():
        for begin in range(0, len(rows), batch):
            value = model([r["text"] for r in rows[begin:begin+batch]])
            for k in logits:
                logits[k].append(value[k].detach().cpu())
    logits = {k: torch.cat(v) for k, v in logits.items()}
    weights = {k: v.cpu() for k, v in weights.items()}
    weighted = ph.loss_parts(logits, truth, weights)
    # Existing component scorer consumes affine features; identity features supply exact logits.
    features = torch.cat([logits[k] for k in ph.LABELS], dim=1)
    heads, offset = {}, 0
    for task, labels in ph.LABELS.items():
        heads[task+"_weight"] = torch.eye(20)[offset:offset+len(labels)]
        heads[task+"_bias"] = torch.zeros(len(labels))
        offset += len(labels)
    metrics = ph.validation_metrics(features, truth, heads, weights)
    require(abs(metrics["weighted_objective"]-sum(float(v) for v in weighted.values())) < 1e-6,
            "Validation aggregate mismatch")
    return metrics


def select(state, loss, epoch, model, policy=POLICY):
    require(epoch >= 1 and math.isfinite(loss), "Selection requires a finite trained epoch")
    if loss < state["best_loss"]-policy["min_delta"]:
        state.update(best_loss=loss, best_epoch=epoch, best_model=cpu_state(model), stale_epochs=0)
        return True
    state["stale_epochs"] += 1
    return False


def identity(results, protocol, tier):
    return {"study_id": STUDY_ID, "tier": tier, "protocol_sha256": file_hash(Path(results)/"protocol.json"),
            "initial_manifest": SELECTED_PINS[tier], "source_closure": protocol["source_closure"]}


def fit(results, tier, *, resume=False):
    results = Path(results)
    preliminary = read(results/"protocol.json")
    configure(read(results/"bindings.json")["repository"], preliminary["device"], preliminary["threads"])
    protocol, binding, train, validation = validate(results)
    accepted = approval(results, "prefit-acceptance.json")
    accepted_probes = read(results/"prefit-acceptance.json")["probe_sha256"]
    require(set(accepted_probes) == set(TIERS), "All three real probes must precede any fit")
    for candidate in TIERS:
        require(accepted_probes[candidate] == file_hash(results/"probe"/(candidate+".json")), "Other-tier probe commitment differs")
    probe = read(results/"probe"/(tier+".json"))
    require(probe["identity"] == identity(results, protocol, tier) and probe["status"] == "passed",
            "Accepted real tier probe required")
    require(read(results/"prefit-acceptance.json")["probe_sha256"][tier] == file_hash(results/"probe"/(tier+".json")),
            "Probe not bound by acceptance")
    models = Path(binding["models"])
    _, model = load_model(models/"initials"/tier, protocol["device"])
    initial = cpu_state(model)
    optimizer = make_optimizer(model)
    weights = device_truth(ph.class_weights(ph.targets(train)), protocol["device"])
    ident = dict(identity(results, protocol, tier), prefit_acceptance_sha256=accepted)
    directory = models/"cells"/tier/"checkpoints"
    complete = results/"fits"/tier/"complete.json"
    require(not complete.exists(), "Completed fit cannot be overwritten")
    with ph.exclusive_run(models/"fit.lock"):
        if resume:
            state = ph.restore_checkpoint(directory, ident)
            model.load_state_dict(state["model"], strict=True)
            optimizer.load_state_dict(state["optimizer"])
            restore_rng(state["rng"])
            require(state["scheduler"]["completed_updates"] == state["optimizer_steps"]
                    and state["scheduler"]["next_update"] == state["optimizer_steps"]+1, "Scheduler resume drift")
            if "epoch_record" in state:
                retain(results/"fits"/tier/"epochs"/f"{state['epoch']:04d}.json",
                       dict(state["epoch_record"], checkpoint=read(directory/"latest.json")["sha256"]))
        else:
            require(not (directory/"latest.json").exists(), "Existing checkpoint requires explicit resume")
            baseline = validation_metrics(model, validation, weights)
            retain(results/"fits"/tier/"baseline-reference.json", baseline)
            state = {"identity": ident, "epoch": 0, "optimizer_steps": 0, "train_exposures": 0,
                     "best_loss": float("inf"), "best_epoch": 0, "best_model": {}, "stale_epochs": 0}
        start = time.monotonic()
        stopped = state["epoch"] >= POLICY["min_epochs"] and state["stale_epochs"] >= POLICY["patience"]
        for epoch in range(state["epoch"]+1, state["epoch"]+1 if stopped else POLICY["max_epochs"]+1):
            validate(results)
            work = train_epoch(model, optimizer, train, weights, epoch, state["optimizer_steps"])
            metrics = validation_metrics(model, validation, weights)
            selected = select(state, metrics["weighted_objective"], epoch, model)
            proof = change_proof(initial, model.state_dict())
            state.update(epoch=epoch, optimizer_steps=work["updates"],
                         train_exposures=state["train_exposures"]+len(train), model=cpu_state(model),
                         optimizer=copy.deepcopy(optimizer.state_dict()), rng=rng_state(), scheduler=work["scheduler"])
            state["epoch_record"] = {"epoch": epoch, "work": work, "validation": metrics, "selected": selected,
                                     "best_epoch": state["best_epoch"], "best_loss": state["best_loss"],
                                     "stale_epochs": state["stale_epochs"], "changes": proof}
            checkpoint = ph.save_checkpoint(directory, state)
            retain(results/"fits"/tier/"epochs"/f"{epoch:04d}.json", dict(state["epoch_record"], checkpoint=checkpoint))
            print(canonical({"tier": tier, "epoch": epoch, "loss": metrics["weighted_objective"],
                             "best_epoch": state["best_epoch"], "stale_epochs": state["stale_epochs"]}).decode(), flush=True)
            if epoch >= POLICY["min_epochs"] and state["stale_epochs"] >= POLICY["patience"]:
                break
        require(state["epoch"] >= POLICY["min_epochs"] and state["best_epoch"] >= 1, "Incomplete fit")
        summary = {k: state[k] for k in ("identity", "epoch", "best_epoch", "best_loss", "optimizer_steps", "train_exposures")}
        summary.update(checkpoint=read(directory/"latest.json")["sha256"], seconds_this_invocation=time.monotonic()-start,
                       stop_reason="validation_patience" if state["stale_epochs"] >= POLICY["patience"] else "max_epochs",
                       resumed=resume, publication="research_only_no_automatic_promotion")
        retain(complete, summary)
    return summary


def prediction_values(model, texts):
    from src.classification import ClassificationResult
    return [{"packed": value.pack(), "named": value.to_dict(), "confidence": confidence,
             "action": ClassificationResult(value, text, "EN3 parity", confidence=confidence).action().name}
            for text, (value, confidence) in zip(texts, model.predictions(texts))]


def parity(reference, reloaded, texts, *, cross_device=False):
    reference.eval()
    reloaded.eval()
    maximum = 0.
    with torch.no_grad():
        a, b = reference(texts), reloaded(texts)
    for task in ph.LABELS:
        x, y = a[task].cpu(), b[task].cpu()
        require(bool(torch.isfinite(x).all() and torch.isfinite(y).all()), "Nonfinite parity logits")
        maximum = max(maximum, float((x-y).abs().max()))
        require(torch.allclose(x, y, atol=1e-5, rtol=1e-4) if cross_device else torch.equal(x, y),
                "Reload logits differ")
    a, b = prediction_values(reference, texts), prediction_values(reloaded, texts)
    for x, y in zip(a, b):
        if cross_device:
            require(abs(x["confidence"]-y["confidence"]) <= .001, "Device confidence differs")
            x, y = dict(x), dict(y)
            x.pop("confidence")
            y.pop("confidence")
        require(x == y, "Reload packed/named/confidence/action values differ")
    return {"rows": len(texts), "max_abs_logit_error": maximum,
            "cross_device": cross_device, "exact_discrete_and_action": True}


def probe(results, tier):
    """A bounded real TRAIN/validation gradient+serialization probe, never a fit."""
    results = Path(results)
    preliminary = read(results/"protocol.json")
    configure(read(results/"bindings.json")["repository"], preliminary["device"], preliminary["threads"])
    protocol, binding, train, validation = validate(results)
    accepted = approval(results, "probe-acceptance.json")
    directory = Path(binding["models"])/"initials"/tier
    _, model = load_model(directory, protocol["device"])
    before = cpu_state(model)
    optimizer = make_optimizer(model)
    weights = device_truth(ph.class_weights(ph.targets(train)), protocol["device"])
    chosen = train[:64]
    start = time.perf_counter()
    if protocol["device"] == "cuda":
        torch.cuda.reset_peak_memory_stats()
    model.train()
    optimizer.zero_grad(set_to_none=True)
    parts = backward_batch(model, [r["text"] for r in chosen],
                           device_truth(ph.targets(chosen), protocol["device"]), weights)
    gradients = gradient_proof(model)
    norm = torch.nn.utils.clip_grad_norm_(model.parameters(), POLICY["clip_norm"], error_if_nonfinite=True)
    set_update_lr(optimizer, 1)
    optimizer.step()
    changes = change_proof(before, model.state_dict())
    model.eval()
    metrics = validation_metrics(model, validation[:32], weights)
    if protocol["device"] == "cuda":
        torch.cuda.synchronize()
    elapsed = time.perf_counter()-start
    path = Path(binding["models"])/"probes"/tier
    path.mkdir(parents=True, exist_ok=True)
    temporary = path/"candidate.tmp"
    try:
        inventory = model.export(temporary)
        payload = temporary.read_bytes()
    finally:
        temporary.unlink(missing_ok=True)
    manifest = dict(read(directory/"manifest.json"), scope="full_encoder", parent=SELECTED_PINS[tier],
                    blob=ph.digest(payload), tensors=inventory, evidence=ph.digest(canonical({"purpose": "probe"})))
    retain(path/"model.safetensors", payload)
    retain(path/"manifest.json", manifest)
    for name in ("config.json", "vocab.txt"):
        retain(path/name, (directory/name).read_bytes())
    _, cpu = load_model(path)
    texts = [r["text"] for r in train[:8]+validation[:8]]
    same_device = parity(model, cpu, texts, cross_device=protocol["device"] == "cuda")
    result = {"identity": identity(results, protocol, tier), "status": "passed", "purpose": "bounded_TRAIN_validation_only",
              "probe_acceptance_sha256": accepted, "gradient_groups": gradients, "changes": changes,
              "loss_parts": parts, "validation_subset": metrics, "seconds": elapsed,
              "gradient_norm_before_clip": float(norm), "train_rows": 64, "validation_rows": 32,
              "peak_cuda_allocated": torch.cuda.max_memory_allocated() if protocol["device"] == "cuda" else None,
              "native_cpu_parity": same_device, "probe_manifest_sha256": file_hash(path/"manifest.json"),
              "environment": environment(protocol["device"]), "development_access": False}
    retain(results/"probe"/(tier+".json"), result)
    return result


def training_state(results, tier):
    results = Path(results)
    protocol, binding, _, validation = validate(results, check_environment=False)
    summary = read(results/"fits"/tier/"complete.json")
    accepted = approval(results, "prefit-acceptance.json")
    expected = dict(identity(results, protocol, tier), prefit_acceptance_sha256=accepted)
    require(summary["identity"] == expected, "Fit identity changed")
    directory = Path(binding["models"])/"cells"/tier/"checkpoints"
    state = ph.restore_checkpoint(directory, expected)
    require(summary["checkpoint"] == read(directory/"latest.json")["sha256"], "Terminal pointer drift")
    require(state["epoch"] == summary["epoch"] >= POLICY["min_epochs"] and state["best_epoch"] >= 1,
            "Incomplete trained checkpoint")
    require(state["best_epoch"] == summary["best_epoch"] and state["best_loss"] == summary["best_loss"],
            "Selected summary/checkpoint disagreement")
    return protocol, binding, validation, summary, state


def export(results, tier):
    protocol, binding, validation, summary, state = training_state(results, tier)
    models = Path(binding["models"])
    initial, reference = load_model(models/"initials"/tier)
    before = cpu_state(reference)
    outputs = {}
    for kind, key, epoch in (("selected", "best_model", state["best_epoch"]),
                             ("terminal", "model", state["epoch"])):
        reference.load_state_dict(state[key], strict=True)
        reference.eval()
        proof = change_proof(before, reference.state_dict())
        path = models/"exports"/tier/kind
        path.mkdir(parents=True, exist_ok=True)
        temporary = path/"candidate.tmp"
        try:
            inventory = reference.export(temporary)
            payload = temporary.read_bytes()
        finally:
            temporary.unlink(missing_ok=True)
        evidence = {"schema": 1, "study_id": STUDY_ID, "scope": "full_encoder", "tier": tier, "kind": kind,
                    "epoch": epoch, "layers": [4], "policy": POLICY, "changes": proof,
                    "protocol_sha256": file_hash(Path(results)/"protocol.json"),
                    "fit_summary_sha256": file_hash(Path(results)/"fits"/tier/"complete.json"),
                    "checkpoint": summary["checkpoint"], "source_closure": protocol["source_closure"],
                    "candidate_blob": ph.digest(payload), "publication": "local_research_only_no_legacy_guard_pass"}
        manifest = dict(initial, parent=SELECTED_PINS[tier], scope="full_encoder", blob=ph.digest(payload),
                        tensors=inventory, evidence=ph.digest(canonical(evidence)))
        retain(path/"model.safetensors", payload)
        retain(path/"evidence.json", evidence)
        retain(path/"manifest.json", manifest)
        for name in ("config.json", "vocab.txt"):
            retain(path/name, (models/"initials"/tier/name).read_bytes())
        _, reloaded = load_model(path)
        require(all(torch.equal(reloaded.state_dict()[k], v) for k, v in state[key].items()), "Export tensor/checkpoint mismatch")
        proof_parity = parity(reference, reloaded, [r["text"] for r in validation[:16]])
        retain(path/"cpu-reload-parity.json", proof_parity)
        if protocol["device"] == "cuda":
            require(torch.cuda.is_available(), "Actual trained CUDA/CPU export parity requires training environment")
            _, gpu = load_model(path, "cuda")
            retain(path/"cuda-cpu-parity.json", parity(gpu, reference, [r["text"] for r in validation[:16]], cross_device=True))
            del gpu
        outputs[kind] = {"directory": str(path), "manifest_sha256": file_hash(path/"manifest.json"),
                         "blob": manifest["blob"], "epoch": epoch, "evidence": manifest["evidence"],
                         "cpu_parity_sha256": file_hash(path/"cpu-reload-parity.json"),
                         "cuda_parity_sha256": file_hash(path/"cuda-cpu-parity.json") if protocol["device"] == "cuda" else None}
    retain(Path(results)/"exports"/(tier+".json"), outputs)
    return outputs


def assert_export_bindings(item, manifest, evidence, *, tier, kind, epoch, checkpoint,
                           protocol_sha, summary_sha, source_closure):
    expected = {"schema": 1, "study_id": STUDY_ID, "scope": "full_encoder", "tier": tier, "kind": kind,
                "epoch": epoch, "layers": [4], "policy": POLICY, "protocol_sha256": protocol_sha,
                "fit_summary_sha256": summary_sha, "checkpoint": checkpoint, "source_closure": source_closure,
                "candidate_blob": manifest["blob"], "publication": "local_research_only_no_legacy_guard_pass"}
    require(set(evidence) == set(expected)|{"changes"} and all(evidence.get(k) == v for k, v in expected.items()),
            "Full export sidecar binding differs")
    require(item["epoch"] == epoch and item["blob"] == manifest["blob"]
            and item["evidence"] == manifest["evidence"], "Export index history differs")


def verify_export(results, tier):
    """Run under both training and old CPU-serving environments; no inference set."""
    protocol, binding, validation, summary, state = training_state(results, tier)
    models = Path(binding["models"])
    initial, reference = load_model(models/"initials"/tier)
    outputs = read(Path(results)/"exports"/(tier+".json"))
    verified = {}
    for kind, key in (("selected", "best_model"), ("terminal", "model")):
        item = outputs[kind]
        path = Path(item["directory"])
        require(path.resolve().is_relative_to(models.resolve()), "Export path escapes model storage")
        manifest, reloaded = load_model(path)
        require(file_hash(path/"manifest.json") == item["manifest_sha256"] and manifest["blob"] == item["blob"], "Export index drift")
        require(file_hash(path/"cpu-reload-parity.json") == item["cpu_parity_sha256"], "CPU parity commitment changed")
        require(manifest["parent"] == SELECTED_PINS[tier] and manifest["original"] == initial["original"]
                and manifest["scope"] == "full_encoder", "Export lineage drift")
        evidence = read(path/"evidence.json")
        require(file_hash(path/"evidence.json") == manifest["evidence"] == item["evidence"]
                and evidence["checkpoint"] == summary["checkpoint"]
                and evidence["protocol_sha256"] == file_hash(Path(results)/"protocol.json"), "Evidence drift")
        assert_export_bindings(item, manifest, evidence, tier=tier, kind=kind,
                               epoch=state["best_epoch"] if kind == "selected" else state["epoch"],
                               checkpoint=summary["checkpoint"], protocol_sha=file_hash(Path(results)/"protocol.json"),
                               summary_sha=file_hash(Path(results)/"fits"/tier/"complete.json"),
                               source_closure=protocol["source_closure"])
        reference.load_state_dict(state[key], strict=True)
        require(all(torch.equal(reloaded.state_dict()[k], v) for k, v in state[key].items()), "Checkpoint arrays differ")
        changes = change_proof(cpu_state(load_model(models/"initials"/tier)[1]), state[key])
        require(evidence["changes"] == changes, "Recorded full-model changes differ")
        if protocol["device"] == "cuda":
            gpu_proof = read(path/"cuda-cpu-parity.json")
            require(file_hash(path/"cuda-cpu-parity.json") == item["cuda_parity_sha256"], "CUDA parity commitment changed")
            require(gpu_proof["cross_device"] and gpu_proof["rows"] == 16 and gpu_proof["exact_discrete_and_action"],
                    "Actual export GPU/CPU parity absent")
        verified[kind] = {"changes": changes,
                          "parity": parity(reference, reloaded, [r["text"] for r in validation[:16]])}
    result = {"identity": identity(results, protocol, tier), "status": "passed",
              "environment": environment("cpu"), "exports": verified, "development_access": False}
    env_hash = ph.digest(canonical(result["environment"]))
    retain(Path(results)/"export-verification"/(tier+"-"+env_hash+".json"), result)
    return result


def audit_training(results, tier):
    protocol, binding, _, summary, state = training_state(results, tier)
    directory = Path(binding["models"])/"cells"/tier/"checkpoints"
    best, best_epoch, stale, exposures, updates = float("inf"), 0, 0, 0, 0
    expected_best = None
    for epoch in range(1, state["epoch"]+1):
        record = read(Path(results)/"fits"/tier/"epochs"/f"{epoch:04d}.json")
        path = directory/(record["checkpoint"]+".pt")
        require(file_hash(path) == record["checkpoint"], "Epoch checkpoint corrupt")
        checkpoint = ph.load_torch(path)
        require(checkpoint["identity"] == summary["identity"] and checkpoint["epoch"] == epoch, "Epoch identity drift")
        require(dict(record, checkpoint=None) == dict(checkpoint["epoch_record"], checkpoint=None), "Epoch evidence mismatch")
        require(record["work"]["epoch"] == epoch and record["work"]["optimizer_steps"] == 98
                and record["work"]["train_exposures"] == 6240, "Work mismatch")
        updates += 98
        exposures += 6240
        require(checkpoint["optimizer_steps"] == updates and checkpoint["scheduler"]["completed_updates"] == updates
                and checkpoint["scheduler"]["next_update"] == updates+1, "Schedule/work drift")
        loss = record["validation"]["weighted_objective"]
        improved = loss < best-POLICY["min_delta"]
        if improved:
            best, best_epoch, stale, expected_best = loss, epoch, 0, checkpoint["model"]
        else:
            stale += 1
        require(record["selected"] == improved and checkpoint["best_epoch"] == best_epoch
                and record["best_epoch"] == best_epoch and record["best_loss"] == best
                and record["stale_epochs"] == stale, "Selection replay differs")
        require(all(torch.equal(checkpoint["best_model"][k], v) for k, v in expected_best.items()), "Best model drift")
        require(not (epoch < state["epoch"] and epoch >= POLICY["min_epochs"] and stale >= POLICY["patience"]), "Fit ran past stop")
        require(all(record["changes"]["groups_changed"].values()), "Full group change proof failed")
    require(state["best_epoch"] == summary["best_epoch"] == best_epoch and state["best_loss"] == summary["best_loss"] == best
            and summary["optimizer_steps"] == updates and summary["train_exposures"] == exposures, "Terminal summary drift")
    require(state["epoch"] == POLICY["max_epochs"] or stale >= POLICY["patience"], "Fit stopped prematurely")
    native = verify_export(results, tier)
    result = {"status": "passed", "identity": identity(results, protocol, tier), "epochs_checked": state["epoch"],
              "best_epoch": best_epoch, "native_verification": native,
              "export_index_sha256": file_hash(Path(results)/"exports"/(tier+".json"))}
    retain(Path(results)/"training-audit"/(tier+".json"), result)
    return result
