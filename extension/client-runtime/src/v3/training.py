"""Server-owned autograd fits on a frozen ordered fuzzer TRAIN stream."""
from __future__ import annotations
import time
import torch
from torch.nn import functional as F
from privoke_model.v3_contract import LABELS, validate_execution, tensor_changes
from privoke_contracts.classification import Classification
from ..classification import ClassificationResult
from ..detection.preprocessing import normalize_text
from .model import inventory

def target(row):
    if not row.has_target or row.weight != 1.0 or not row.text:
        raise ValueError("V3 fits require explicit nonempty unit-weight labeled rows.")
    value = Classification(row.target.packed)
    expected = value.to_dict()
    actual = {"sensitivity": row.target.sensitivity, "visibility": row.target.visibility, "categories": list(row.target.categories)}
    if actual != expected: raise ValueError("Named and packed training targets disagree.")
    return value

def assess(model, rows):
    predictions = []
    for offset in range(0, len(rows), 4):
        predictions.extend(model.predictions([r.text for r in rows[offset:offset + 4]]))
    results = []
    for row, (prediction, confidence) in zip(rows, predictions):
        truth = target(row)
        actual = ClassificationResult(prediction, row.text, "v3 guard", confidence=confidence).action()
        desired = ClassificationResult(truth, row.text, "explicit guard target", confidence=.999).action()
        results.append({"target": truth.pack(), "prediction": prediction.pack(), "action": actual.name,
            "confidence": confidence,
            "target_action": desired.name, "action_value": actual.value, "target_action_value": desired.value,
            "joint_correct": prediction.pack() == truth.pack() and actual == desired})
    return {"rows": results, "joint_correct": sum(r["joint_correct"] for r in results),
        "action_correct": sum(r["action"] == r["target_action"] for r in results), "examples": len(rows)}

def fit(model, request, policy, *, cancel_check=lambda: True):
    train, guard = list(request.train), list(request.guard)
    if len(train) != policy["window_batches"] * 64 or len(guard) != 16:
        raise ValueError("Frozen TRAIN window/guard counts differ.")
    train_targets = [target(r) for r in train]
    for row in guard: target(row)
    if {normalize_text(r.text) for r in train} & {normalize_text(r.text) for r in guard}:
        raise ValueError("TRAIN/guard normalized texts overlap.")
    full = request.scope == 2
    for p in model.encoder.parameters(): p.requires_grad_(full)
    model.eval()
    before = inventory(model.state_dict())
    device = model.device_name
    if device.startswith("cuda"): torch.cuda.reset_peak_memory_stats()
    base_guard = assess(model, guard)
    groups = [{"params": list(model.heads.parameters()), "lr": policy["head_lr"]}]
    if full: groups.append({"params": list(model.encoder.parameters()), "lr": policy["encoder_lr"]})
    optimizer = torch.optim.AdamW(groups, betas=tuple(policy["betas"]), eps=policy["eps"], weight_decay=0.0)
    counts = {"optimizer_steps": 0, "train_rows": 0, "microbatch_forward": 0, "microbatch_backward": 0,
              "encoder_block_forward": 0, "encoder_block_backward": 0}
    handles = []
    layers = len(model.encoder.encoder.layer)
    block_counts = {"forward": [0] * layers, "backward": [0] * layers}
    def hook(direction, index):
        def record(module, inputs, output):
            counts["encoder_block_" + direction] += 1
            block_counts[direction][index] += 1
        return record
    for index, block in enumerate(model.encoder.encoder.layer):
        handles.append(block.register_forward_hook(hook("forward", index)))
        if full: handles.append(block.register_full_backward_hook(hook("backward", index)))
    losses, gradient_trace, start = [], [], time.monotonic()
    try:
        for step in range(policy["steps"]):
            if not cancel_check(): raise ValueError("Fit cancelled; no publication attempted.")
            optimizer.zero_grad(set_to_none=True)
            offset = (step % policy["window_batches"]) * 64
            rows = train[offset:offset + 64]; truths = train_targets[offset:offset + 64]
            total_loss = 0.0
            for begin in range(0, 64, policy["microbatch"]):
                selected = truths[begin:begin + policy["microbatch"]]
                logits = model([r.text for r in rows[begin:begin + policy["microbatch"]]])
                counts["microbatch_forward"] += 1
                s = torch.tensor([LABELS["sensitivity"].index(t.sensitivity().name) for t in selected], device=device)
                v = torch.tensor([LABELS["visibility"].index(t.visibility().name) for t in selected], device=device)
                c = torch.tensor([[float(name in [item.name for item in t.categories()]) for name in LABELS["category"]] for t in selected], device=device)
                loss = (F.cross_entropy(logits["sensitivity"], s, reduction="sum") + F.cross_entropy(logits["visibility"], v, reduction="sum")
                        + F.binary_cross_entropy_with_logits(logits["category"], c, reduction="sum") / len(LABELS["category"])) / 64
                if not torch.isfinite(loss): raise ValueError("Nonfinite training loss.")
                loss.backward(); counts["microbatch_backward"] += 1
                counts["train_rows"] += len(selected); total_loss += float(loss.detach())
            parameters = [p for p in model.parameters() if p.requires_grad]
            if any(p.grad is None or not torch.isfinite(p.grad).all() for p in parameters):
                raise ValueError("Missing/nonfinite trainable gradient.")
            encoder_grad = sum(int(torch.count_nonzero(p.grad)) for p in model.encoder.parameters() if p.grad is not None)
            norm = torch.nn.utils.clip_grad_norm_(parameters, policy["clip_norm"], error_if_nonfinite=True)
            optimizer.step(); counts["optimizer_steps"] += 1
            if any(not torch.isfinite(p).all() for p in model.parameters()): raise ValueError("Nonfinite candidate parameter.")
            losses.append(total_loss); gradient_trace.append({"step": step + 1, "encoder_nonzero_gradients": encoder_grad, "norm_before_clip": float(norm)})
    finally:
        for handle in handles: handle.remove()
    candidate_guard = assess(model, guard)
    after = inventory(model.state_dict())
    changed, changes = tensor_changes(before, after, layers)
    # Both directions matter: new under-restriction and over-restriction are harms.
    harms = sum(any(max(0, direction * (b["action_value"] - b["target_action_value"])) >
                    max(0, direction * (a["action_value"] - a["target_action_value"])) for direction in (-1, 1))
                for a, b in zip(base_guard["rows"], candidate_guard["rows"]))
    evidence = {"schema": 1, "model_id": request.model_id, "tier": request.model_id.removeprefix("privoke-v3-"), "request_id": request.request_id, "base": request.base, "scope": "full_encoder" if full else "heads",
        "layers": [4], "source_commitment": request.source_commitment, "policy": policy,
        "train_wire_sha256": __import__("hashlib").sha256(b"".join(r.SerializeToString(deterministic=True) for r in train)).hexdigest(),
        "guard_wire_sha256": __import__("hashlib").sha256(b"".join(r.SerializeToString(deterministic=True) for r in guard)).hexdigest(),
        "phases": {"training": {"layer": 4, "status": "ok", "examples": counts["train_rows"]},
                   "base_heldout": {"layer": 4, "status": "ok", "examples": len(guard)},
                   "candidate_heldout": {"layer": 4, "status": "ok", "examples": len(guard)}},
        "base_guard": base_guard, "candidate_guard": candidate_guard, "action_harms": harms,
        "changes": changes, "changed_tensors": changed, "counts": counts, "block_counts": block_counts, "losses": losses, "gradient_trace": gradient_trace,
        "parameter_count": sum(p.numel() for p in model.parameters()), "trainable_count": sum(p.numel() for p in model.parameters() if p.requires_grad),
        "device": device, "torch": torch.__version__, "seconds": time.monotonic() - start,
        "cuda_peak_bytes": torch.cuda.max_memory_allocated() if device.startswith("cuda") else 0}
    return validate_execution(evidence, finalized=False)
