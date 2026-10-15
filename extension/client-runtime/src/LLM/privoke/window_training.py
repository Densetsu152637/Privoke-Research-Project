"""Cold local Adam with TRAIN-only exact transported checkpoint selection."""
from __future__ import annotations

import json
import math
import os
from dataclasses import replace

import numpy as np

from privoke_model import window_training as contract
from privoke_model.full_adam import canonical, OBJECTIVE
from privoke_model.fingerprint import parameter_fingerprint
from privoke_model.contextual_training import (FULL_ENCODER_STRATEGY, contextual_output_trainable_names,
                                               validate_contextual_training_contract)
from ...model import TinyTransformerModel
from ...detection.preprocessing import normalize_text
from .full_adam_training import adam_step, array_identity, preflight, observe_numpy


def component_hinge(logits, components, torch):
    """Mean bits within category, then components within row; outer caller averages rows."""
    losses = []
    for entries in components.values():
        values = []
        for entry in entries:
            value = logits[entry["task"]]
            if entry["task"] == "category":
                margin = entry["sign"] * (value[entry["index"]] - entry["offset"])
            else:
                margin = value[entry["positive"]].max(dim=0).values - value[entry["negative"]].max(dim=0).values
            values.append(torch.relu(value.new_tensor(entry["target"]) - margin))
        losses.append(torch.stack(values).mean())
    return torch.stack(losses).mean()


def _counts():
    return {k: 0 for k in ("directions_attempted", "directions_completed", "rows_attempted", "rows_completed",
        "microbatch_forward_attempted", "microbatch_forward_completed", "microbatch_backward_started",
        "microbatch_backward_completed", "torch_block_forwards_attempted", "torch_block_forwards_completed")}


def _prediction_rows(predictions):
    from .training import _classification_from_prediction
    return [[_classification_from_prediction(p).pack(), round(min(max(p.confidence, 0.), .999), 3)] for p in predictions]


def _score(model, examples, references, step, work, shapes):
    from .training import _local_training_losses
    observe_numpy(model, work, f"checkpoint_{step}_window")
    predictions = model.predict_many(tuple(e.text for e in examples))
    rows = _prediction_rows(predictions)
    work["objective_attempted"] += 1
    loss = _local_training_losses(model, examples, OBJECTIVE, predictions=predictions)[-1]
    work["objective_completed"] += 1
    observe_numpy(model, work, f"checkpoint_{step}_original_train")
    original_predictions = _prediction_rows(model.predict_many(tuple(normalize_text(source["text"]) for source, _ in references)))
    predicates = [contract.component_predicates(ref["gold"], ref["original"], ref["confidence"], *candidate)
                  for (_, ref), candidate in zip(references, original_predictions)]
    return {"step": step, "fingerprint": parameter_fingerprint({n: tuple(float(v) for v in a.ravel()) for n, a in model.parameters.items()}, shapes),
        "counts": contract.checkpoint_counts([e.target.pack() for e in examples], rows), "loss": loss,
        "predictions": rows, "original_predictions": original_predictions,
        "violations": sum(not all(p.values()) for p in predicates),
        "component_violations": {component: sum(not p[component] for p in predicates) for component in contract.COMPONENTS}}


def _guard(base_model, selected_model, examples, work):
    from .training import _safety_regression_rate
    observe_numpy(base_model, work, "base_heldout")
    before = _prediction_rows(base_model.predict_many(tuple(e.text for e in examples)))
    observe_numpy(selected_model, work, "candidate_heldout")
    after = _prediction_rows(selected_model.predict_many(tuple(e.text for e in examples)))
    from ...classification import Classification
    targets = [e.target for e in examples]
    clean = [i for i, t in enumerate(targets) if not t.is_sensitive()]
    sensitive = [i for i, t in enumerate(targets) if t.is_sensitive()]
    if not clean or not sensitive:
        raise ValueError("Unchanged guard requires both clean and sensitive rows.")
    def metrics(rows):
        return {"exact": sum(t.pack() == r[0] for t, r in zip(targets, rows)),
            "recall": sum(Classification(rows[i][0]).is_sensitive() for i in sensitive),
            "specificity": sum(not Classification(rows[i][0]).is_sensitive() for i in clean)}
    b, a = metrics(before), metrics(after)
    regression = _safety_regression_rate(targets, [Classification(r[0]) for r in before],
        [Classification(r[0]) for r in after], before_confidence=[r[1] for r in before], after_confidence=[r[1] for r in after])
    return {"before": before, "after": after, "base_counts": b, "candidate_counts": a,
        "regression_rate": regression, "passed": all(a[k] >= b[k] for k in b) and regression == 0}


def load_inputs(admission, model_id):
    """Authenticate externally pinned bytes before cache/model access."""
    window_pin = os.getenv("PRIVOKE_WINDOW_MANIFEST_SHA256")
    reference_pin = os.getenv("PRIVOKE_COMPONENT_MANIFEST_SHA256")
    if (admission["expected_window_manifest_sha256"] != window_pin
            or admission["expected_component_manifest_sha256"] != reference_pin):
        raise ValueError("Request pins differ from trusted runtime window/component configuration.")
    window = contract.validate_window(contract.read_pinned(os.getenv("PRIVOKE_WINDOW_PATH"), window_pin))
    release = contract.load_components(os.getenv("PRIVOKE_COMPONENT_BANK_PATH"), os.getenv("PRIVOKE_COMPONENT_REFERENCE_PATH"),
        os.getenv("PRIVOKE_COMPONENT_MANIFEST_PATH"), os.getenv("PRIVOKE_COMPONENT_TEACHER_PATH"),
        model_id=model_id, trusted_sha256=reference_pin,teacher_sha256=os.getenv("PRIVOKE_COMPONENT_TEACHER_SHA256"))
    return window, release


def compute(examples, *, model_id, learning_rate, max_gradient, heldout_examples, admission, cancel_check=None):
    from .training import SemanticGradientBatch, SemanticTrainingExample, _class_balanced_examples
    from .parameter_stream import ModelParameterStreamer
    from .streamed_model import GLOBAL_STREAMED_MODEL_CACHE
    from .supervised_training import supervised_last_block_deltas
    if (admission is None or admission.get("expected_training_scope") != "full_encoder"
            or learning_rate != .003 or max_gradient != .05):
        raise ValueError("Window optimizer requires explicit FULL scope/fixed rate/cap.")
    preflight()
    window, release = load_inputs(admission, model_id)
    contract.validate_request(window, examples, heldout_examples)
    runtime = GLOBAL_STREAMED_MODEL_CACHE.model_for_training(ModelParameterStreamer(model_id=model_id))
    snapshot = runtime.snapshot
    contract.validate_admission(admission, snapshot.metadata)
    c = runtime.model.config
    teacher_config = release.manifest["teacher"]["config"]
    if canonical(c.to_mapping()) != canonical(teacher_config):
        raise ValueError("CURRENT complete config/readout differs from authenticated ORIGINAL reference.")
    names = set(snapshot.parameters)
    validate_contextual_training_contract(c.__dict__, snapshot.parameters, snapshot.shapes,
        {name: name in snapshot.metadata["trainable_parameters"].split(",") for name in names}, snapshot.metadata)
    examples, weights = _class_balanced_examples(tuple(replace(e, text=normalize_text(e.text)) for e in examples))
    heldout_examples = tuple(replace(e, text=normalize_text(e.text)) for e in heldout_examples)
    references = tuple((s, r) for s, r in release.rows if r["components"])
    from ...classification import Classification
    auxiliary = tuple(SemanticTrainingExample(normalize_text(s["text"]), Classification(r["gold"]), 1.) for s, r in references)
    specs = tuple(r["components"] for _, r in references)
    base, shapes = snapshot.parameters, snapshot.shapes
    work = {"schema": 1, "backend": "numpy_cpu_float32", "phases": {}, "objective_attempted": 0, "objective_completed": 0}
    main, extra = _counts(), _counts()
    trace = {"schema": 1, "policy": contract.POLICY, "config": contract.CONFIG,
        "window_sha256": admission["expected_window_manifest_sha256"], "references_sha256": release.sha256,
        "base": parameter_fingerprint(base, shapes), "steps": [], "checkpoints": [], "work": work,
        "main": main, "auxiliary": extra, "guard": None, "weights": weights}
    def create(parameters):
        return TinyTransformerModel(c, parameters, shapes, device="cpu", reject_overlength=True)
    def active():
        if cancel_check is not None and not cancel_check():
            raise ValueError("Window training cancelled; no update submitted.")
    delta = {n: np.zeros(len(base[n]), dtype=np.float32) for n in names}
    moment = {n: np.zeros(len(base[n]), dtype=np.float64) for n in names}
    variance = {n: np.zeros(len(base[n]), dtype=np.float64) for n in names}
    current, current_model = base, create(base)
    saved = {}
    try:
        active()
        base_model = current_model
        trace["checkpoints"].append(_score(base_model, examples, references, 0, work, shapes))
        for step, block in enumerate(contract.schedule(window["seed"]), 1):
            active()
            selected_rows = examples[block * 64:(block + 1) * 64]
            main["directions_attempted"] += 1
            direction, loss = supervised_last_block_deltas(current_model, selected_rows, names, objective=OBJECTIVE,
                normalization_denominator=math.fsum(e.weight for e in examples) / 8, work_counts=main)
            main["directions_completed"] += 1
            extra["directions_attempted"] += 1
            auxiliary_direction, auxiliary_loss = supervised_last_block_deltas(current_model, auxiliary, names,
                retention_components=specs, work_counts=extra)
            extra["directions_completed"] += 1
            combined = {n: tuple(a + b for a, b in zip(direction[n], auxiliary_direction[n])) for n in names}
            before = parameter_fingerprint(current, shapes)
            cumulative, current, clipped = adam_step(base, shapes, delta, moment, variance, combined, step)
            after = parameter_fingerprint(current, shapes)
            trace["steps"].append({"step": step, "block": block, "before": before, "after": after,
                "main_loss": loss, "auxiliary_loss": auxiliary_loss, "clipped": clipped,
                "gradient": array_identity(combined), "moments": array_identity({**{n+":m": v for n,v in moment.items()},
                    **{n+":v": v for n,v in variance.items()}}), "delta": parameter_fingerprint(cumulative, shapes)})
            current_model = create(current)
            if step in contract.CONFIG["checkpoints"]:
                active()
                checkpoint = _score(current_model, examples, references, step, work, shapes)
                trace["checkpoints"].append(checkpoint)
                saved[step] = (dict(cumulative), dict(current))
        selected = contract.select(trace["checkpoints"])
        trace.update(terminal=parameter_fingerprint(current, shapes), selected_step=selected["step"],
                     selected=selected["fingerprint"], status="no_update", reason="base_selected")
        gradients, candidate = {}, base
        if selected["step"]:
            gradients, candidate = saved[selected["step"]]
            encoder = names - contextual_output_trainable_names(c.__dict__)
            if not any(candidate[n] != base[n] for n in encoder):
                trace["reason"] = "no_transported_encoder_change"
            else:
                active()
                trace["guard"] = _guard(base_model, create(candidate), heldout_examples, work)
                trace["status"] = "selected" if trace["guard"]["passed"] else "no_update"
                trace["reason"] = "guard_passed" if trace["guard"]["passed"] else "guard_failed"
        if trace["status"] == "no_update":
            gradients, candidate = {}, base
        trace["published"] = parameter_fingerprint(candidate, shapes)
        trace["selected_delta"] = parameter_fingerprint(saved[selected["step"]][0], shapes) if selected["step"] else None
        active()
    except Exception as exc:
        trace["status"] = "partial_error"
        trace["partial_counts_are_observed_lower_bounds"] = True
        failure = ValueError(str(exc))
        failure.training_metadata = {contract.TRACE_KEY: canonical(trace), "contextual_training_optimizer": contract.POLICY}
        raise failure from exc
    raw = canonical(trace)
    summary = contract.summary(trace, raw)
    metadata = {"contextual_training_optimizer": contract.POLICY, "executed_contextual_training_optimizer": contract.POLICY,
        "contextual_training_objective": OBJECTIVE, "executed_contextual_training_objective": OBJECTIVE,
        "contextual_training_strategy": FULL_ENCODER_STRATEGY, "strategy": FULL_ENCODER_STRATEGY,
        "artifact_training_strategy": FULL_ENCODER_STRATEGY, "training_scope": "full_encoder", "underlying_training_available": "true",
        "contextual_candidate_eligibility": contract.ELIGIBILITY, contract.CONFIG_KEY: canonical(contract.CONFIG),
        contract.WINDOW_KEY: trace["window_sha256"], contract.REFERENCE_KEY: release.sha256,
        contract.TRACE_KEY: raw, contract.SUMMARY_KEY: canonical(summary), "window_outcome": trace["status"],
        "base_parameter_fingerprint": trace["base"], "updated_parameter_fingerprint": trace["published"],
        "artifact_checksum": snapshot.metadata["artifact_checksum"], "architecture": snapshot.metadata.get("architecture", "privoke_tiny_transformer_v1"),
        "model_config": canonical(c.to_mapping()), "trained_parameter_names": canonical(sorted(names)),
        "trained_parameter_inventory_fingerprint": parameter_fingerprint({n: () for n in names}, shapes),
        "learning_rate": ".003", "max_gradient": ".05"}
    metrics = {"examples": 512., "candidate_train_exact_match_rate": contract.packed_exact_rate(contract.flat_rows(window),selected),
        "exact_match_rate": contract.packed_exact_rate(contract.flat_rows(window),trace["checkpoints"][0]),
        "candidate_train_objective_loss": selected["loss"], "base_train_objective_loss": trace["checkpoints"][0]["loss"]}
    return SemanticGradientBatch(model_id, snapshot.version, gradients, shapes, metrics, metadata,
                                 tuple(contract.execution_phases(trace)))
