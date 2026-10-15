"""Isolated fixed FULL Adam; serving tensors and legacy SGD remain untouched."""
from __future__ import annotations

import hashlib
import math
import os
import numpy as np

from privoke_model.artifact import float32, updated_parameter_values
from privoke_model.fingerprint import parameter_fingerprint
from privoke_model.full_adam import (POLICY, CONFIG, CONFIG_KEY, ELIGIBILITY, ELIGIBILITY_KEY,
    EXECUTED_KEY, TRACE_KEY, SUMMARY_KEY, OBJECTIVE, canonical)
from ...model import TinyTransformerModel


def array_identity(arrays):
    digest = hashlib.sha256()
    for name in sorted(arrays):
        value = np.asarray(arrays[name], dtype="<f8")
        digest.update(name.encode() + b"\0" + value.tobytes())
    return digest.hexdigest()


def adam_step(base, shapes, delta, moment, variance, direction, step):
    """Negative globally normalized direction; prior persisted f32 delta is accumulated."""
    cap = np.float32(CONFIG["delta_cap"])
    if float(cap) > CONFIG["delta_cap"]:
        cap = np.nextafter(cap, np.float32(0))
    if set(direction) != set(base):
        raise ValueError("FULL Adam direction inventory differs from immutable base.")
    clipped = 0
    for name in sorted(base):
        g = np.asarray(direction[name], dtype=np.float64)
        if g.shape != delta[name].shape or not np.isfinite(g).all():
            raise ValueError("FULL Adam gradients must have exact finite shapes.")
        moment[name] = .9 * moment[name] + (1 - .9) * g
        variance[name] = .999 * variance[name] + (1 - .999) * g * g
        increment = .003 * (moment[name] / (1 - .9 ** step)) / (np.sqrt(variance[name] / (1 - .999 ** step)) + 1e-8)
        raw = delta[name].astype(np.float64) + increment
        if not np.isfinite(raw).all():
            raise ValueError("FULL Adam moments/increments must remain finite.")
        clipped += int(np.count_nonzero(np.abs(raw) > float(cap)))
        delta[name] = np.clip(raw, -float(cap), float(cap)).astype(np.float32)
        if np.any(np.abs(delta[name].astype(np.float64)) > .05):
            raise ValueError("FULL Adam transported delta exceeds its fixed cap.")
    cumulative = {n: tuple(float(v) for v in delta[n]) for n in sorted(delta)}
    candidate = {n: tuple(float32(v) for v in updated_parameter_values(base[n], cumulative[n])) for n in base}
    if any(not math.isfinite(v) for values in candidate.values() for v in values):
        raise ValueError("FULL Adam transported candidate must remain finite.")
    return cumulative, candidate, clipped


class FullAdamFailure(ValueError):
    def __init__(self, message, trace):
        super().__init__(message)
        self.training_metadata = {TRACE_KEY: canonical(trace), EXECUTED_KEY: POLICY,
            CONFIG_KEY: canonical(CONFIG), "full_adam_status": "partial_error"}


def preflight():
    """Reject thread configuration before cache/model access on the FULL route."""
    import torch
    if (os.getenv("OMP_NUM_THREADS") != "1" or os.getenv("MKL_NUM_THREADS") != "1"
            or torch.get_num_threads() != 1):
        raise ValueError("FULL Adam requires startup OMP_NUM_THREADS=1/MKL_NUM_THREADS=1 and actual Torch threads=1.")


def observe_numpy(model, work, phase):
    """Observe actual row/block boundaries on an isolated CPU NumPy model."""
    counts = work["phases"].setdefault(phase, {k: 0 for k in
        ("rows_attempted", "rows_completed", "blocks_attempted", "blocks_completed")})
    original_row = getattr(model, "_observed_numpy_row", model._predict_numpy)
    original_block = getattr(model, "_observed_numpy_block", model._numpy_encoder_block)
    model._observed_numpy_row, model._observed_numpy_block = original_row, original_block
    def row(*args, **kwargs):
        counts["rows_attempted"] += 1
        value = original_row(*args, **kwargs)
        counts["rows_completed"] += 1
        return value
    def block(*args, **kwargs):
        counts["blocks_attempted"] += 1
        value = original_block(*args, **kwargs)
        counts["blocks_completed"] += 1
        return value
    model._predict_numpy, model._numpy_encoder_block = row, block
    return model


def fit(model, base, shapes, examples, *, cancel_check=None, retention=None):
    """One CPU fit; actual counters are observed at helper/block/backward boundaries."""
    import torch
    from .supervised_training import supervised_last_block_deltas
    preflight()
    delta = {n: np.zeros(len(base[n]), dtype=np.float32) for n in sorted(base)}
    moment = {n: np.zeros(len(base[n]), dtype=np.float64) for n in sorted(base)}
    variance = {n: np.zeros(len(base[n]), dtype=np.float64) for n in sorted(base)}
    counts = {k: 0 for k in ("directions_attempted", "directions_completed", "microbatch_forward_attempted",
        "microbatch_forward_completed", "microbatch_backward_started", "microbatch_backward_completed",
        "torch_block_forwards_attempted", "torch_block_forwards_completed")}
    counts["train_parameter_states"] = 1
    auxiliary_counts = {k: 0 for k in ("directions_attempted", "directions_completed", "rows_attempted", "rows_completed",
        "microbatch_forward_attempted", "microbatch_forward_completed", "microbatch_backward_started",
        "microbatch_backward_completed", "torch_block_forwards_attempted", "torch_block_forwards_completed")}
    auxiliary_steps = []
    trace = {"schema": 1, "policy": POLICY, "config": CONFIG, "base": parameter_fingerprint(base, shapes),
             "final": None, "delta": None, "steps": [], "counts": counts, "train": len(examples)}
    current = base  # Zero-delta round8 transport is not an identity operation.
    current_model = TinyTransformerModel(model.config, current, shapes, device="cpu", reject_overlength=model.reject_overlength)
    try:
        for step in range(1, 65):
            if cancel_check is not None and not cancel_check():
                raise ValueError("FULL Adam cancelled between fixed steps; no update submitted.")
            original_block = current_model._torch_encoder_block
            layers = model.config.num_layers
            block_index = 0
            def block(*args, **kwargs):
                nonlocal block_index
                first, last = block_index % layers == 0, block_index % layers == layers - 1
                if first:
                    counts["microbatch_forward_attempted"] += 1
                counts["torch_block_forwards_attempted"] += 1
                value = original_block(*args, **kwargs)
                counts["torch_block_forwards_completed"] += 1
                if last:
                    counts["microbatch_forward_completed"] += 1
                    def backward_started(gradient):
                        counts["microbatch_backward_started"] += 1
                        return gradient
                    value.register_hook(backward_started)
                block_index += 1
                return value
            current_model._torch_encoder_block = block
            counts["directions_attempted"] += 1
            direction, loss = supervised_last_block_deltas(current_model, examples, set(base), objective=OBJECTIVE)
            counts["directions_completed"] += 1
            counts["microbatch_backward_completed"] = counts["microbatch_backward_started"]
            if retention is not None:
                # The main observer closes before the separately normalized auxiliary call.
                current_model._torch_encoder_block = original_block
                auxiliary_examples, margins, original_fingerprint = retention
                auxiliary_counts["directions_attempted"] += 1
                auxiliary_block_index = 0
                def auxiliary_block(*args, **kwargs):
                    nonlocal auxiliary_block_index
                    first, last = auxiliary_block_index % layers == 0, auxiliary_block_index % layers == layers - 1
                    if first:
                        auxiliary_counts["rows_attempted"] += min(32, len(auxiliary_examples) - 32 * (auxiliary_block_index // layers))
                        auxiliary_counts["microbatch_forward_attempted"] += 1
                    auxiliary_counts["torch_block_forwards_attempted"] += 1
                    value = original_block(*args, **kwargs)
                    auxiliary_counts["torch_block_forwards_completed"] += 1
                    if last:
                        auxiliary_counts["microbatch_forward_completed"] += 1
                        def auxiliary_backward(gradient):
                            auxiliary_counts["microbatch_backward_started"] += 1
                            return gradient
                        value.register_hook(auxiliary_backward)
                    auxiliary_block_index += 1
                    return value
                current_model._torch_encoder_block = auxiliary_block
                from privoke_model.sensitive_retention import HINGE_OBJECTIVE
                diagnostic = {}
                extra, hinge = supervised_last_block_deltas(current_model, auxiliary_examples, set(base),
                    objective=HINGE_OBJECTIVE, retention_margins=margins, retention_diagnostics=diagnostic)
                auxiliary_counts["directions_completed"] += 1
                auxiliary_counts["rows_completed"] += len(auxiliary_examples)
                auxiliary_counts["microbatch_backward_completed"] = auxiliary_counts["microbatch_backward_started"]
                auxiliary_steps.append({"step": step, "main_loss": loss, "auxiliary_loss": hinge,
                    "main_gradient_norm": math.hypot(*(v for values in direction.values() for v in values)),
                    "auxiliary_gradient_norm": math.hypot(*(v for values in extra.values() for v in values)),
                    "gradient_dot": math.fsum(a * b for n in direction for a, b in zip(direction[n], extra[n])),
                    "active_rows": diagnostic["active_rows"], "maximum_hinge": diagnostic["maximum_hinge"],
                    "original_state_parity_scaled_error": diagnostic["maximum_scaled_original_difference"]
                        if parameter_fingerprint(current, shapes) == original_fingerprint else None})
                direction = {n: tuple(a + b for a, b in zip(direction[n], extra[n])) for n in direction}
                loss += hinge  # Both returned directions already use their own global denominator.
            if not math.isfinite(loss) or loss < 0:
                raise ValueError("FULL Adam helper loss must remain finite and nonnegative.")
            before = parameter_fingerprint(current, shapes)
            cumulative, current, clipped = adam_step(base, shapes, delta, moment, variance, direction, step)
            after = parameter_fingerprint(current, shapes)
            counts["train_parameter_states"] += 1
            trace["steps"].append({"step": step, "before": before, "after": after, "loss": loss,
                "gradient": array_identity(direction), "moments": array_identity({**{n+":m": v for n,v in moment.items()},
                    **{n+":v": v for n,v in variance.items()}}),
                "delta": parameter_fingerprint(cumulative, shapes), "clipped": clipped})
            # Every helper call creates its own CPU float32 leaves; no graph survives.
            current_model = TinyTransformerModel(model.config, current, shapes, device="cpu", reject_overlength=model.reject_overlength)
        if cancel_check is not None and not cancel_check():
            raise ValueError("FULL Adam cancelled after optimization; no update submitted.")
    except Exception as exc:
        counts["internal_completion_work_unknown"] = counts["directions_attempted"] != counts["directions_completed"]
        counts["partial_counts_are_observed_lower_bounds"] = True
        failure = FullAdamFailure(str(exc), trace)
        if retention is not None:
            failure.training_metadata["original_train_retention_partial_work_v1"] = canonical({"counts": auxiliary_counts, "steps": auxiliary_steps})
        raise failure from exc
    trace.update(final=parameter_fingerprint(current, shapes), delta=parameter_fingerprint(cumulative, shapes))
    summary = {"schema": 1, "policy": POLICY, "trace_sha256": hashlib.sha256(canonical(trace).encode()).hexdigest(),
        "base": trace["base"], "final": trace["final"], "delta": trace["delta"], "counts": counts,
        "eligibility": ELIGIBILITY, "metric": "candidate_train_exact_match_rate"}
    return cumulative, current, current_model, {TRACE_KEY: canonical(trace), SUMMARY_KEY: canonical(summary),
        **({"original_train_retention_work_v1": canonical({"counts": auxiliary_counts, "steps": auxiliary_steps})} if retention is not None else {}),
        CONFIG_KEY: canonical(CONFIG), EXECUTED_KEY: POLICY, ELIGIBILITY_KEY: ELIGIBILITY}
