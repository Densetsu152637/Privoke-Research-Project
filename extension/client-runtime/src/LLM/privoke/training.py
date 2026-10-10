from __future__ import annotations

import json
import math
from dataclasses import dataclass, replace
from typing import Sequence

from privoke_model.artifact import float32, updated_parameter_values
from privoke_model.pretrained_context import PRETRAINED_CONTEXT_MODEL_ID
from privoke_model.training_data import training_text_key
from privoke_model.fingerprint import parameter_fingerprint
from privoke_model.contextual_training import (STRATEGY_KEY, LAST_BLOCK_STRATEGY, FULL_ENCODER_STRATEGY, HEAD_NAMES,
    OBJECTIVE_KEY, CLASS_BALANCED_OBJECTIVES, CLASS_BALANCED_MEAN_CATEGORY_OBJECTIVE,
    CLASS_BALANCED_DECISION_MARGIN_OBJECTIVE, MEAN_CATEGORY_OBJECTIVES, validate_decision_margin_config,
    validate_contextual_training_contract, OPTIMIZER_KEY, LOCAL_SGD_STEPS,
    validate_contextual_training_optimizer)
from ...classification import Classification
from ...detection.preprocessing import normalize_text
from ...model import ModelConfig, TinyTransformerModel
from .parameter_stream import ModelParameterStreamer
from .streamed_model import GLOBAL_STREAMED_MODEL_CACHE


@dataclass(frozen=True)
class SemanticTrainingExample:
    text: str
    target: Classification | None
    weight: float


@dataclass(frozen=True)
class SemanticGradientBatch:
    model_id: str
    base_version: str
    gradients: dict[str, tuple[float, ...]]
    shapes: dict[str, tuple[int, ...]]
    metrics: dict[str, float]
    metadata: dict[str, str]
    executions: tuple[tuple[str, int], ...] = ()


def compute_semantic_gradients(
    examples: Sequence[SemanticTrainingExample],
    *,
    model_id: str,
    learning_rate: float,
    max_gradient: float,
    heldout_examples: Sequence[SemanticTrainingExample] = (),
) -> SemanticGradientBatch:
    """Legacy/head endpoint; full-capable artifacts restrict this path to heads."""
    return _compute_training_gradients(examples, model_id=model_id, learning_rate=learning_rate,
        max_gradient=max_gradient, heldout_examples=heldout_examples, full_encoder=False)


def compute_underlying_model_gradients(examples, *, model_id, learning_rate, max_gradient, heldout_examples=()):
    """Train all Tiny encoder and head tensors on an explicitly capable artifact."""
    return _compute_training_gradients(examples, model_id=model_id, learning_rate=learning_rate,
        max_gradient=max_gradient, heldout_examples=heldout_examples, full_encoder=True)


def _compute_training_gradients(examples, *, model_id, learning_rate, max_gradient,
                                heldout_examples, full_encoder):
    """Compute a bounded update with optional transported-state local SGD."""
    if model_id == PRETRAINED_CONTEXT_MODEL_ID:
        raise ValueError("Pretrained contextual online training is unsupported; use offline head fitting.")
    if not examples:
        raise ValueError("At least one training example is required.")
    if not math.isfinite(learning_rate) or learning_rate <= 0:
        raise ValueError("learning_rate must be finite and greater than zero.")
    if not math.isfinite(max_gradient) or max_gradient <= 0:
        raise ValueError("max_gradient must be finite and greater than zero.")
    if any(not math.isfinite(item.weight) or item.weight <= 0 for item in examples):
        raise ValueError("Training example weights must be finite and positive.")
    # Serving canonicalizes prompt text before the semantic layer. Candidate
    # gradients and their held-out guard must evaluate that same representation.
    examples = tuple(replace(item, text=normalize_text(item.text)) for item in examples)
    heldout_examples = tuple(replace(item, text=normalize_text(item.text))
                             for item in heldout_examples)
    if heldout_examples:
        _validate_heldout_examples(examples, heldout_examples)

    streamer = ModelParameterStreamer(model_id=model_id)
    runtime_model = GLOBAL_STREAMED_MODEL_CACHE.model_for_training(streamer)
    snapshot = runtime_model.snapshot
    trainable_names = {
        name
        for name in snapshot.metadata.get("trainable_parameters", "").split(",")
        if name
    }
    declared = snapshot.metadata.get("trainable_parameters", "").split(",")
    if len(declared) != len(set(declared)):
        raise ValueError("Contextual trainable names must be unique.")
    validate_contextual_training_contract(
        runtime_model.model.config.__dict__, snapshot.parameters, snapshot.shapes,
        {name: name in trainable_names for name in snapshot.parameters}, snapshot.metadata)
    strategy = snapshot.metadata.get(STRATEGY_KEY)
    artifact_strategy = strategy
    if artifact_strategy == FULL_ENCODER_STRATEGY:
        try:
            import torch
            with torch.inference_mode(False), torch.enable_grad():
                capability = torch.tensor(1.0, device="cpu", requires_grad=True)
                capability.square().backward()
                if capability.grad is None or capability.grad.item() != 2.0:
                    raise ValueError("CPU autograd capability check failed.")
        except ImportError as exc:
            raise ValueError("Full-capable training requires the CPU training dependency before either stage.") from exc
        checksum = snapshot.metadata.get("artifact_checksum", "")
        if not isinstance(checksum, str) or len(checksum) != 64 or any(character not in "0123456789abcdef" for character in checksum):
            raise ValueError("Full encoder training requires the streamed artifact checksum identity.")
    if full_encoder:
        if strategy != FULL_ENCODER_STRATEGY:
            raise ValueError("Underlying training requires the full Tiny encoder artifact strategy.")
    elif strategy == FULL_ENCODER_STRATEGY:
        trainable_names = set(HEAD_NAMES)
        strategy = None
    local_steps = validate_contextual_training_optimizer(snapshot.metadata)
    if local_steps is not None and any(item.target is None for item in examples):
        raise ValueError("Local SGD requires explicit contextual targets for every row.")
    if strategy in (LAST_BLOCK_STRATEGY, FULL_ENCODER_STRATEGY) and any(item.target is None for item in examples):
        raise ValueError("Encoder adaptation requires explicit contextual targets for every row.")
    if not trainable_names:
        raise ValueError("The streamed model declares no trainable parameters.")
    if not trainable_names.issubset(snapshot.parameters):
        raise ValueError("The model trainable parameter manifest is inconsistent.")

    objective = snapshot.metadata.get(OBJECTIVE_KEY)
    mean_category = objective in MEAN_CATEGORY_OBJECTIVES
    decision_margin = objective == CLASS_BALANCED_DECISION_MARGIN_OBJECTIVE
    category_count = len(runtime_model.model.config.category_labels)
    objective_metrics = {}
    weight_audit = {}
    if objective in CLASS_BALANCED_OBJECTIVES:
        examples, weight_audit = _class_balanced_examples(examples)

    gradients = {
        name: [0.0 for _ in snapshot.parameters[name]]
        for name in sorted(trainable_names)
    }
    predictions = runtime_model.model.predict_many(
        tuple(example.text for example in examples)
    )
    # Normalize the new objective before multiplication: a valid finite W can
    # still overflow intermediate loss * weight or gradient * weight sums.
    total_weight = math.fsum(item.weight for item in examples) if mean_category else 0.0
    total_loss = 0.0
    exact_matches = 0
    task_totals = {"sensitivity": 0.0, "visibility": 0.0, "category": 0.0}
    auxiliary_total = 0.0

    for example, prediction in zip(examples, predictions):
        predicted = _classification_from_prediction(prediction)
        target = example.target or predicted
        if target.pack() == predicted.pack():
            exact_matches += 1
        deltas = runtime_model.model.classification_head_deltas_from_prediction(
            prediction,
            sensitivity=target.sensitivity().name,
            visibility=target.visibility().name,
            categories=[category.name for category in target.categories()],
        )
        auxiliary = None
        if decision_margin:
            auxiliary_loss, auxiliary = _decision_margin_loss_and_head_deltas(runtime_model.model, prediction, target)
        accumulation_weight = example.weight / total_weight if mean_category else example.weight
        for name, values in deltas.items():
            if name not in gradients:
                continue
            for index, value in enumerate(values):
                if mean_category and name.startswith("head.category."):
                    value /= category_count
                if auxiliary is not None:
                    value += auxiliary[name][index]
                gradients[name][index] += value * accumulation_weight
        if decision_margin:
            auxiliary_total += auxiliary_loss * accumulation_weight
        total_loss += _classification_loss(target, predicted) * accumulation_weight
        if not mean_category:
            total_weight += example.weight
        if mean_category:
            for task, loss in _mean_category_loss_components(runtime_model.model, prediction, target).items():
                task_totals[task] += loss * accumulation_weight

    if not math.isfinite(total_weight) or not math.isfinite(total_loss):
        raise ValueError("Training totals must remain finite.")
    if weight_audit and not mean_category:
        # Match the autograd global denominator without changing legacy arithmetic.
        total_weight = math.fsum(item.weight for item in examples)
    supervised_loss = None
    if mean_category:
        objective_metrics = {f"supervised_{task}_{'bce' if task == 'category' else 'ce'}_loss": value
                             for task, value in task_totals.items()}
        if any(not math.isfinite(value) or value < 0 for value in objective_metrics.values()):
            raise ValueError("Contextual task losses must remain finite and nonnegative.")
        try:
            supervised_loss = math.fsum((*objective_metrics.values(), auxiliary_total)) if decision_margin else math.fsum(objective_metrics.values())
        except OverflowError as exc:
            raise ValueError("Contextual supervised objective must remain finite.") from exc
    if strategy in (LAST_BLOCK_STRATEGY, FULL_ENCODER_STRATEGY):
        from .supervised_training import supervised_last_block_deltas
        if mean_category:
            gradients, supervised_loss = supervised_last_block_deltas(
                runtime_model.model, examples, trainable_names, objective=objective,
                diagnostics=objective_metrics)
        else:
            gradients, supervised_loss = supervised_last_block_deltas(
                runtime_model.model, examples, trainable_names)
        # New strategy already uses the global weighted denominator.
        gradient_denominator = 1.0
    else:
        gradient_denominator = 1.0 if mean_category else total_weight
    if mean_category:
        if (not math.isfinite(supervised_loss)
                or any(not math.isfinite(value) or value < 0 for value in objective_metrics.values())
                or any(not math.isfinite(value) or not math.isfinite(value * learning_rate)
                       for values in gradients.values() for value in values)):
            raise ValueError("Contextual normalized gradients, task losses and objective must remain finite.")
    optimizer_trace = None
    if local_steps is None:
        # Full-capable scopes obey the original double request bound after
        # float32 transport; rounding the real bound outwards would exceed it.
        transport_cap = _inward_float32_bound(max_gradient) if artifact_strategy == FULL_ENCODER_STRATEGY else max_gradient
        scaled = {
            name: tuple(
                float32(_clamp(
                    (value / gradient_denominator) * learning_rate,
                    -transport_cap,
                    transport_cap,
                ))
                for value in values
            )
            for name, values in gradients.items()
        }
    else:
        scaled, optimizer_trace = _local_sgd_updates(
            runtime_model.model, snapshot.parameters, snapshot.shapes, examples,
            trainable_names, strategy, objective, snapshot.metadata[OPTIMIZER_KEY],
            learning_rate, max_gradient, gradients, gradient_denominator)
    heldout_metrics = _heldout_metrics(
        runtime_model,
        snapshot.parameters,
        heldout_examples,
    )
    candidate_parameters = {
        name: tuple(float32(value) for value in updated_parameter_values(values, scaled[name]))
        if name in scaled else tuple(float32(value) for value in values)
        for name, values in snapshot.parameters.items()
    }
    if full_encoder and not any(candidate_parameters[name] != tuple(float32(value) for value in snapshot.parameters[name])
                                for name in trainable_names - HEAD_NAMES):
        raise ValueError("Underlying training produced no transported encoder weight update.")
    heldout_metrics.update(
        {
            f"candidate_{key}": value
            for key, value in _heldout_metrics(
                runtime_model,
                candidate_parameters,
                heldout_examples,
                reference_parameters=snapshot.parameters,
            ).items()
        }
    )
    return SemanticGradientBatch(
        model_id=snapshot.model_id,
        base_version=snapshot.version,
        gradients=scaled,
        shapes={name: snapshot.shapes[name] for name in scaled},
        metrics={
            "examples": float(len(examples)),
            "average_loss": total_loss if mean_category else total_loss / total_weight,
            "exact_match_rate": exact_matches / len(examples),
            "total_weight": total_weight,
            **heldout_metrics,
            **weight_audit,
            **objective_metrics,
            **({"supervised_objective_loss": supervised_loss} if supervised_loss is not None else {}),
        },
        metadata={
            **({"contextual_optimizer_trace": optimizer_trace} if optimizer_trace is not None else {}),
            "strategy": strategy or "transformer_classification_head_finetune",
            "artifact_training_strategy": artifact_strategy or "transformer_classification_head_finetune",
            "underlying_training_available": "true" if artifact_strategy == FULL_ENCODER_STRATEGY else "false",
            "training_scope": "full_encoder" if full_encoder else ("last_block" if strategy == LAST_BLOCK_STRATEGY else "heads"),
            "trained_parameter_names": json.dumps(sorted(scaled), separators=(",", ":")),
            "trained_parameter_inventory_fingerprint": parameter_fingerprint(
                {name: () for name in scaled}, {name: snapshot.shapes[name] for name in scaled}),
            "artifact_checksum": snapshot.metadata.get("artifact_checksum", ""),
            "model_config": json.dumps(runtime_model.model.config.__dict__,
                                       sort_keys=True, separators=(",", ":"), allow_nan=False),
            "base_parameter_fingerprint": _parameter_fingerprint(snapshot.parameters),
            "updated_parameter_fingerprint": _parameter_fingerprint(candidate_parameters),
            "learning_rate": str(learning_rate),
            "max_gradient": str(max_gradient),
            "model_cache_key": snapshot.cache_key,
            "text_preprocessing": "canonical_detector_normalize_text",
            **({OBJECTIVE_KEY: objective,
                "objective_strata": "classification_is_sensitive",
                **{key: str(value) for key, value in weight_audit.items()}} if weight_audit else {}),
            **({"category_normalization": "mean_per_label",
                "category_count": str(category_count),
                "diagnostic_loss": "weighted_classification_distance",
                **{key: str(value) for key, value in objective_metrics.items()},
                "supervised_objective_loss": str(supervised_loss)} if mean_category else {}),
        },
        executions=(("training", len(examples)),) +
            ((("base_heldout", len(heldout_examples)), ("candidate_heldout", len(heldout_examples))) if heldout_examples else ()),
    )


def _inward_float32_bound(bound):
    """Largest transported magnitude no greater than the configured real bound."""
    import numpy as np
    # Bounds larger than float32 max are valid real inputs; the transport stays finite.
    maximum = float(np.finfo(np.float32).max)
    rounded = float32(min(bound, maximum))
    if rounded > bound:
        rounded = float(np.nextafter(np.float32(rounded), np.float32(0.0)))
    return rounded


def _transport_local_parameters(base, deltas):
    return {name: tuple(float32(value) for value in updated_parameter_values(values, deltas[name]))
            if name in deltas else tuple(float32(value) for value in values)
            for name, values in base.items()}


def _local_training_losses(model, examples, objective):
    """Evaluate true weighted task losses at this exact transported runtime state."""
    try:
        total = math.fsum(item.weight for item in examples)
    except OverflowError as exc:
        raise ValueError("Local SGD total weight must remain finite and positive.") from exc
    if not math.isfinite(total) or total <= 0:
        raise ValueError("Local SGD total weight must remain finite and positive.")
    losses = {"sensitivity": 0.0, "visibility": 0.0, "category": 0.0}
    count = len(model.config.category_labels)
    decision_margin = objective == CLASS_BALANCED_DECISION_MARGIN_OBJECTIVE
    if decision_margin:
        losses["decision_margin"] = 0.0
    predictions = model.predict_many(tuple(item.text for item in examples))
    for item, prediction in zip(examples, predictions):
        values = _mean_category_loss_components(model, prediction, item.target)
        if objective not in MEAN_CATEGORY_OBJECTIVES:
            values["category"] *= count
        if decision_margin:
            values["decision_margin"] = _decision_margin_loss_and_head_deltas(model, prediction, item.target)[0]
        for task, value in values.items():
            losses[task] += value * (item.weight / total)
    result = [losses[task] for task in ("sensitivity", "visibility", "category")]
    if decision_margin:
        result.append(losses["decision_margin"])
    try:
        result.append(math.fsum(result))
    except OverflowError as exc:
        raise ValueError("Local SGD task losses must remain finite and nonnegative.") from exc
    if any(not math.isfinite(value) or value < 0 for value in result):
        raise ValueError("Local SGD task losses must remain finite and nonnegative.")
    return result


def _local_sgd_direction(model, examples, names, strategy, objective):
    """Recompute the current direction, preserving each objective's operation order."""
    if strategy in (LAST_BLOCK_STRATEGY, FULL_ENCODER_STRATEGY):
        from .supervised_training import supervised_last_block_deltas
        return supervised_last_block_deltas(model, examples, names, objective=objective)[0], 1.0
    mean_category = objective in MEAN_CATEGORY_OBJECTIVES
    total = math.fsum(item.weight for item in examples) if mean_category else 0.0
    gradients = {name: [0.0] * model.parameters[name].size for name in sorted(names)}
    predictions = model.predict_many(tuple(item.text for item in examples))
    count = len(model.config.category_labels)
    for item, prediction in zip(examples, predictions):
        values = model.classification_head_deltas_from_prediction(prediction,
            sensitivity=item.target.sensitivity().name, visibility=item.target.visibility().name,
            categories=[category.name for category in item.target.categories()])
        auxiliary = (_decision_margin_loss_and_head_deltas(model, prediction, item.target)[1]
                     if objective == CLASS_BALANCED_DECISION_MARGIN_OBJECTIVE else None)
        weight = item.weight / total if mean_category else item.weight
        for name, direction in values.items():
            if name not in gradients:
                continue
            for index, value in enumerate(direction):
                if mean_category and name.startswith("head.category."):
                    value /= count
                if auxiliary is not None:
                    value += auxiliary[name][index]
                gradients[name][index] += value * weight
        if not mean_category:
            total += item.weight
    if objective in CLASS_BALANCED_OBJECTIVES and not mean_category:
        total = math.fsum(item.weight for item in examples)
    return gradients, 1.0 if mean_category else total


def _local_sgd_updates(model, base, shapes, examples, names, strategy, objective,
                       optimizer, rate, bound, initial_gradients, initial_denominator):
    """Accumulate projected local SGD relative to one immutable publication base.

    Every next direction sees T(base, accumulated transported delta), never an
    unrounded optimizer-only state. Existing batch metrics keep their initial
    meanings; the bounded trace separately records each state's true CE/BCE.
    """
    steps = LOCAL_SGD_STEPS[optimizer]
    cap = _inward_float32_bound(bound)
    accumulated = {name: tuple(0.0 for _ in base[name]) for name in sorted(names)}
    local_model = model
    direction, denominator = initial_gradients, initial_denominator
    losses, updates = [], []
    state_fingerprints = [parameter_fingerprint(base, shapes)]
    for step in range(steps):
        losses.append(_local_training_losses(local_model, examples, objective))
        if step:
            direction, denominator = _local_sgd_direction(local_model, examples, names, strategy, objective)
        if not math.isfinite(denominator) or denominator <= 0:
            raise ValueError("Local SGD gradient denominator must remain finite and positive.")
        if set(direction) != set(names):
            raise ValueError("Local SGD direction manifest is inconsistent.")
        raw_max, clipped, normalized = 0.0, 0, []
        updated = {}
        for name in sorted(names):
            if len(direction[name]) != len(base[name]):
                raise ValueError("Local SGD direction shape is inconsistent.")
            values = []
            for prior, value in zip(accumulated[name], direction[name]):
                gradient = value / denominator
                increment = gradient * rate
                raw = increment if step == 0 else prior + increment
                if not all(math.isfinite(v) for v in (gradient, increment, raw)):
                    raise ValueError("Local SGD gradients and accumulators must remain finite.")
                normalized.append(gradient)
                raw_max = max(raw_max, abs(raw))
                clipped += int(abs(raw) > cap)
                transported = float32(_clamp(raw, -cap, cap))
                if abs(transported) > bound:
                    raise ValueError("Local SGD transport exceeds the configured delta bound.")
                values.append(transported)
            updated[name] = tuple(values)
        norm = math.hypot(*normalized)
        if not math.isfinite(norm):
            raise ValueError("Local SGD gradient norm must remain finite.")
        accumulated = updated
        transported_max = max(abs(value) for values in accumulated.values() for value in values)
        updates.append([norm, raw_max, clipped, transported_max])
        parameters = _transport_local_parameters(base, accumulated)
        state_fingerprints.append(parameter_fingerprint(parameters, shapes))
        local_model = TinyTransformerModel(model.config, parameters, shapes, device=model.compute_device,
                                          reject_overlength=model.reject_overlength)
    losses.append(_local_training_losses(local_model, examples, objective))
    trace = json.dumps({"optimizer": optimizer, "steps": steps,
        "objective": objective or "legacy_sum_category", "rate": rate,
        "max_gradient": bound, "transport_cap": cap,
        "category_normalization": "mean_per_label" if objective in MEAN_CATEGORY_OBJECTIVES else "sum_labels",
        "category_count": len(model.config.category_labels),
        "loss_columns": (["sensitivity_ce", "visibility_ce", "category_bce", "decision_margin_bce", "objective"]
                         if objective == CLASS_BALANCED_DECISION_MARGIN_OBJECTIVE else
                         ["sensitivity_ce", "visibility_ce", "category_bce", "objective"]),
        **({"decision_margin_coefficient": 1.0,
            "decision_margin_rule": "max_non_s0_or_category_logit_v1"}
           if objective == CLASS_BALANCED_DECISION_MARGIN_OBJECTIVE else {}),
        "loss": losses, "state_parameter_fingerprints": state_fingerprints,
        "update_columns": ["gradient_l2", "raw_delta_max", "clipped_coordinates", "transport_delta_max"],
        "updates": updates}, separators=(",", ":"), allow_nan=False)
    if len(trace.encode("utf-8")) > 2048:
        raise ValueError("Local SGD optimizer trace exceeds its metadata byte budget.")
    return accumulated, trace


def _class_balanced_examples(examples):
    """Preserve rows and within-class weights; give each target class half the mass."""
    if not examples or any(item.target is None for item in examples):
        raise ValueError("Class-balanced training requires explicit contextual targets for every row.")
    if any(type(item.weight) not in (int, float) or not math.isfinite(item.weight)
           or item.weight <= 0 for item in examples):
        raise ValueError("Class-balanced training weights must be finite and positive.")
    strata = tuple(item.target.is_sensitive() for item in examples)
    try:
        raw = {label: math.fsum(item.weight for item, stratum in zip(examples, strata)
                               if stratum == label) for label in (False, True)}
        total = math.fsum(raw.values())
    except OverflowError as exc:
        raise ValueError("Class-balanced total weight must remain finite.") from exc
    if any(not math.isfinite(value) or value <= 0 for value in raw.values()):
        raise ValueError("Class-balanced training requires both clean and sensitive target classes.")
    if not math.isfinite(total):
        raise ValueError("Class-balanced total weight must remain finite.")
    adjusted = tuple(replace(item, weight=total * (item.weight / raw[stratum]) * 0.5)
                     for item, stratum in zip(examples, strata))
    if any(not math.isfinite(item.weight) or item.weight <= 0 for item in adjusted):
        raise ValueError("Class-balanced effective weights must remain finite and positive.")
    effective = {label: math.fsum(item.weight for item, stratum in zip(adjusted, strata)
                                 if stratum == label) for label in (False, True)}
    return adjusted, {
        "training_clean_examples": float(strata.count(False)),
        "training_sensitive_examples": float(strata.count(True)),
        "raw_clean_weight": raw[False], "raw_sensitive_weight": raw[True],
        "raw_total_weight": total,
        "effective_clean_weight": effective[False], "effective_sensitive_weight": effective[True],
        "clean_objective_mass": effective[False] / total,
        "sensitive_objective_mass": effective[True] / total,
    }


def _mean_category_loss_components(model, prediction, target):
    """True CE/BCE task losses from runtime logits; distance loss stays separate."""
    import numpy as np

    pooled = np.asarray(prediction.pooled, dtype=np.float32)
    logits = {task: pooled @ model.parameters[f"head.{task}.weight"]
              + model.parameters[f"head.{task}.bias"]
              for task in ("sensitivity", "visibility", "category")}

    def cross_entropy(values, index):
        maximum = float(max(values))
        return maximum - float(values[index]) + math.log(math.fsum(
            math.exp(float(value) - maximum) for value in values))

    categories = {category.name for category in target.categories()}
    category_loss = math.fsum(max(float(value), 0.0)
        - float(label in categories) * float(value) + math.log1p(math.exp(-abs(float(value))))
        for value, label in zip(logits["category"], model.config.category_labels)) / len(model.config.category_labels)
    components = {
        "sensitivity": cross_entropy(logits["sensitivity"], model.config.sensitivity_labels.index(target.sensitivity().name)),
        "visibility": cross_entropy(logits["visibility"], model.config.visibility_labels.index(target.visibility().name)),
        "category": category_loss,
    }
    if any(not math.isfinite(value) or value < 0 for value in components.values()):
        raise ValueError("Contextual supervised task losses must be finite and nonnegative.")
    return components


def _decision_margin_loss_and_head_deltas(model, prediction, target):
    """Differentiate union-margin BCE; exact ties choose the first configured term.

    Non-S0 severity-minus-S0 terms precede category-minus-threshold terms.
    These float32 logit margins use the artifact threshold, leaving decoding intact.
    The typed CE/BCE tasks continue to supervise severity, visibility and categories.
    """
    import numpy as np

    validate_decision_margin_config(model.config.__dict__)
    if target is None:
        raise ValueError("Decision-margin training requires explicit contextual targets.")
    pooled = np.asarray(prediction.pooled, dtype=np.float32)
    logits = {head: pooled @ model.parameters[f"head.{head}.weight"]
              + model.parameters[f"head.{head}.bias"] for head in ("sensitivity", "category")}
    if any(not np.isfinite(value).all() for value in logits.values()):
        raise ValueError("Decision-margin logits must remain finite.")
    s0 = model.config.sensitivity_labels.index("S0")
    alternatives = [i for i, label in enumerate(model.config.sensitivity_labels) if label != "S0"]
    threshold = model.config.category_threshold
    offset = np.float32(math.log(threshold) - math.log1p(-threshold))
    with np.errstate(over="ignore", invalid="ignore"):
        margins = np.concatenate((logits["sensitivity"][alternatives] - logits["sensitivity"][s0],
                                  logits["category"] - offset))
    if not np.isfinite(margins).all():
        raise ValueError("Decision-margin differences must remain finite.")
    winner = int(np.argmax(margins))
    margin = float(margins[winner])
    positive = target.is_sensitive()
    loss = max(-margin if positive else margin, 0.0) + math.log1p(math.exp(-abs(margin)))
    # Target-conditional derivative avoids 1 - sigmoid(m) cancellation for
    # confident positives while remaining exactly the mathematical y - sigmoid(m).
    signed = -margin if positive else margin
    probability = (1.0 / (1.0 + math.exp(-signed)) if signed >= 0 else
                   math.exp(signed) / (1.0 + math.exp(signed)))
    negative_error = probability if positive else -probability
    errors = {head: np.zeros(len(getattr(model.config, f"{head}_labels")), dtype=np.float32)
              for head in ("sensitivity", "visibility", "category")}
    if winner < len(alternatives):
        errors["sensitivity"][alternatives[winner]] = negative_error
        errors["sensitivity"][s0] = -negative_error
    else:
        errors["category"][winner - len(alternatives)] = negative_error
    return loss, {name: tuple(float(value) for value in values.ravel())
                  for head, error in errors.items()
                  for name, values in ((f"head.{head}.weight", np.outer(pooled, error)),
                                       (f"head.{head}.bias", error))}


def _classification_from_prediction(prediction) -> Classification:
    from ...classification import Category, Sensitivity, Visibility, initialise_unpacked

    return initialise_unpacked(
        Sensitivity[prediction.sensitivity],
        Visibility[prediction.visibility],
        [
            Category.__members__[name]
            for name in prediction.categories
        ],
    )


def _heldout_metrics(runtime_model, parameters, examples, *, reference_parameters=None):
    if not examples:
        return {}
    model = TinyTransformerModel(
        ModelConfig.from_metadata(runtime_model.snapshot.metadata),
        parameters,
        runtime_model.snapshot.shapes,
        reject_overlength=runtime_model.model.reject_overlength,
    )
    predictions = model.predict_many(tuple(example.text for example in examples))
    exact = 0
    sensitive = 0
    sensitive_correct = 0
    clean = 0
    clean_correct = 0
    for example, prediction in zip(examples, predictions):
        if example.target is None:
            continue
        target = example.target
        predicted = _classification_from_prediction(prediction)
        exact += target.pack() == predicted.pack()
        if target.is_sensitive():
            sensitive += 1
            sensitive_correct += target.is_sensitive() == predicted.is_sensitive()
        else:
            clean += 1
            clean_correct += target.is_sensitive() == predicted.is_sensitive()
    total = sensitive + clean
    metrics = {
        "heldout_examples": float(total),
        "heldout_sensitive_examples": float(sensitive),
        "heldout_clean_examples": float(clean),
        "heldout_exact_match_rate": exact / total if total else 0.0,
        "heldout_sensitive_recall": sensitive_correct / sensitive if sensitive else 1.0,
        "heldout_clean_specificity": clean_correct / clean if clean else 1.0,
    }
    if reference_parameters is not None:
        reference = TinyTransformerModel(
            ModelConfig.from_metadata(runtime_model.snapshot.metadata),
            reference_parameters,
            runtime_model.snapshot.shapes,
            reject_overlength=runtime_model.model.reject_overlength,
        ).predict_many(tuple(example.text for example in examples))
        metrics["heldout_safety_regression_rate"] = _safety_regression_rate(
            [example.target for example in examples],
            [_classification_from_prediction(item) for item in reference],
            [_classification_from_prediction(item) for item in predictions],
            before_confidence=[round(min(max(item.confidence, 0.0), 0.999), 3) for item in reference],
            after_confidence=[round(min(max(item.confidence, 0.0), 0.999), 3) for item in predictions],
        )
    return metrics


def _safety_regression_rate(targets, before, after, *, before_confidence=None, after_confidence=None):
    """Reject individual severity or policy-action losses below the target floor."""
    from ...classification import ClassificationResult

    before_confidence = before_confidence or [None] * len(targets)
    after_confidence = after_confidence or [None] * len(targets)
    regressions = 0
    for target, baseline, candidate, base_conf, candidate_conf in zip(
        targets, before, after, before_confidence, after_confidence
    ):
        target_action = ClassificationResult(target, "", "").action().value
        base_action = ClassificationResult(baseline, "", "", confidence=base_conf).action().value
        candidate_action = ClassificationResult(candidate, "", "", confidence=candidate_conf).action().value
        regressions += (
            min(candidate.sensitivity().value, target.sensitivity().value)
            < min(baseline.sensitivity().value, target.sensitivity().value)
            or min(candidate_action, target_action) < min(base_action, target_action)
        )
    return regressions / len(targets) if targets else 0.0


def _validate_heldout_examples(training, heldout):
    training_keys = {training_text_key(item.text) for item in training}
    keys = [training_text_key(item.text) for item in heldout]
    if any(not key for key in keys) or len(keys) != len(set(keys)):
        raise ValueError("Held-out examples must contain distinct non-empty texts.")
    if training_keys.intersection(keys):
        raise ValueError("Held-out examples must be separate from training texts.")
    if any(item.target is None for item in heldout):
        raise ValueError("Held-out examples require explicit target labels.")
    if any(not math.isfinite(item.weight) or item.weight <= 0 for item in heldout):
        raise ValueError("Held-out example weights must be finite and positive.")
    if {item.target.is_sensitive() for item in heldout} != {False, True}:
        raise ValueError("Held-out evaluation needs both clean and sensitive labels.")


def _classification_loss(target: Classification, predicted: Classification) -> float:
    from ...classification import Category, Visibility, visibility_rank

    sensitivity_loss = abs(
        target.sensitivity().value - predicted.sensitivity().value
    ) / 3.0
    visibility_loss = abs(
        visibility_rank(target.visibility()) - visibility_rank(predicted.visibility())
    ) / visibility_rank(Visibility.P4)
    category_loss = len(set(target.categories()) ^ set(predicted.categories())) / max(
        1,
        len(list(Category)),
    )
    return sensitivity_loss + 0.5 * visibility_loss + 0.25 * category_loss


def _parameter_fingerprint(parameters) -> str:
    return parameter_fingerprint(parameters)


def _clamp(value: float, lower: float, upper: float) -> float:
    return max(lower, min(upper, value))
