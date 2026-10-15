from __future__ import annotations

import json
import math
from dataclasses import dataclass, replace
from typing import Sequence

from privoke_model.artifact import float32, updated_parameter_values
from privoke_model.pretrained_context import PRETRAINED_CONTEXT_MODEL_ID
from privoke_model.training_data import training_text_key
from privoke_model.fingerprint import parameter_fingerprint
from privoke_model.contextual_training import (STRATEGY_KEY, LAST_BLOCK_STRATEGY, FULL_ENCODER_STRATEGY, HEAD_NAMES, contextual_output_trainable_names,
    LEGACY_OBJECTIVE, DIAGNOSTICS_POLICY_KEY, DIAGNOSTICS_KEY, EXECUTED_OBJECTIVE_KEY,
    validate_training_diagnostics_policy,
    DIAGNOSTIC_LOSS_COLUMNS, DIAGNOSTIC_ACCURACY_COLUMNS, DIAGNOSTIC_UPDATE_COLUMNS,
    validate_training_diagnostics,
    OBJECTIVE_KEY, CLASS_BALANCED_OBJECTIVES, CLASS_BALANCED_MEAN_CATEGORY_OBJECTIVE,
    CLASS_BALANCED_DECISION_MARGIN_OBJECTIVE, CLASS_BALANCED_SUM_CATEGORY_DECISION_MARGIN_OBJECTIVE,
    DECISION_MARGIN_OBJECTIVES, MEAN_CATEGORY_OBJECTIVES, training_loss_contract, validate_decision_margin_config,
    validate_contextual_training_contract, OPTIMIZER_KEY, LOCAL_SGD_STEPS,
    validate_contextual_training_optimizer)
from privoke_model.contextual_training import (BACKTRACKING_KEY, BACKTRACKING_POLICY, BACKTRACKING_PREPARATION_KEY,
    BACKTRACKING_TRACE_KEY, BACKTRACKING_TRIALS_KEY, BACKTRACKING_REJECTION, BACKTRACKING_SCALES,
    BACKTRACKING_DECREASE, validate_backtracking_policy, validate_backtracking_trace)
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
    error: str = ""


def compute_semantic_gradients(
    examples: Sequence[SemanticTrainingExample],
    *,
    model_id: str,
    learning_rate: float,
    max_gradient: float,
    heldout_examples: Sequence[SemanticTrainingExample] = (),
    admission=None,
) -> SemanticGradientBatch:
    """Legacy/head endpoint; full-capable artifacts restrict this path to heads."""
    return _compute_training_gradients(examples, model_id=model_id, learning_rate=learning_rate,
        max_gradient=max_gradient, heldout_examples=heldout_examples, full_encoder=False, admission=admission)


def compute_underlying_model_gradients(examples, *, model_id, learning_rate, max_gradient, heldout_examples=(), admission=None, cancel_check=None):
    """Train all Tiny encoder and head tensors on an explicitly capable artifact."""
    return _compute_training_gradients(examples, model_id=model_id, learning_rate=learning_rate,
        max_gradient=max_gradient, heldout_examples=heldout_examples, full_encoder=True, admission=admission, cancel_check=cancel_check)


def _compute_training_gradients(examples, *, model_id, learning_rate, max_gradient,
                                heldout_examples, full_encoder, admission=None, cancel_check=None):
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
    from privoke_model import window_training as window_contract
    if admission is not None and admission.get("expected_optimizer") == window_contract.POLICY:
        if not full_encoder:
            raise ValueError("Frozen window/checkpoint training is FULL-only.")
        from .window_training import compute
        return compute(examples, model_id=model_id, learning_rate=learning_rate, max_gradient=max_gradient,
            heldout_examples=heldout_examples, admission=admission, cancel_check=cancel_check)
    from privoke_model import sensitive_retention as retention_contract
    retention_release = None
    if admission is not None and admission.get("expected_optimizer") in retention_contract.POLICIES:
        if not full_encoder:
            raise ValueError("ORIGINAL retention is an opt-in FULL-only route.")
        from .sensitive_retention_training import load_runtime_release
        retention_release = load_runtime_release(admission, model_id)
    if admission is not None and "expected_optimizer" in admission:
        from privoke_model.full_adam import CONFIG
        if admission.get("expected_training_scope") != ("full_encoder" if full_encoder else "heads"):
            raise ValueError("FULL Adam header scope differs from the executed endpoint.")
        if full_encoder and (learning_rate != CONFIG["eta"] or max_gradient != CONFIG["delta_cap"]):
            raise ValueError("FULL Adam fixed request config differs before model access.")
        if full_encoder:
            from .full_adam_training import preflight
            preflight()
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
    from privoke_model.full_adam import validate_admission, POLICY as ADAM_POLICY, CONFIG as ADAM_CONFIG
    adam_artifact = validate_admission(admission, snapshot.metadata)
    if retention_release is not None:
        retention_contract.validate_admission(admission, snapshot.metadata)
        retention_contract.validate_release(retention_release, model_id=model_id,
            expected_sha256=snapshot.metadata[retention_contract.MANIFEST_KEY])
        from .sensitive_retention_training import validate_current_config
        validate_current_config(snapshot.metadata.get("model_config"), retention_release.manifest["teacher"]["config"])
        if len(examples) != 64 or len(heldout_examples) != 16:
            raise ValueError("Retention CURRENT config/main64/guard16 differs from fixed reference contract.")
    if adam_artifact and full_encoder and (learning_rate != ADAM_CONFIG["eta"] or max_gradient != ADAM_CONFIG["delta_cap"]):
        raise ValueError("FULL Adam request must match its fixed eta and cumulative delta cap.")
    preparation = validate_backtracking_policy(snapshot.metadata)
    backtracking = bool(full_encoder and preparation is not None)
    if admission is not None:
        if (admission.get("expected_objective") != snapshot.metadata.get(OBJECTIVE_KEY, LEGACY_OBJECTIVE)
                or admission.get("expected_diagnostics_policy") != snapshot.metadata.get(DIAGNOSTICS_POLICY_KEY)):
            raise ValueError("Actual artifact differs from pre-gradient objective admission.")
        if backtracking or "expected_backtracking_policy" in admission:
            if (not backtracking or admission.get("expected_backtracking_policy") != BACKTRACKING_POLICY
                    or admission.get("expected_backtracking_preparation_sha256") != preparation):
                raise ValueError("Actual artifact differs from pre-gradient backtracking admission.")
    elif backtracking:
        raise ValueError("FULL backtracking requires explicit matching pre-gradient admission.")
    elif snapshot.metadata.get(OBJECTIVE_KEY) == CLASS_BALANCED_SUM_CATEGORY_DECISION_MARGIN_OBJECTIVE:
        raise ValueError("Summed-category decision-margin training requires explicit objective admission.")
    if (snapshot.metadata.get(OBJECTIVE_KEY) == CLASS_BALANCED_SUM_CATEGORY_DECISION_MARGIN_OBJECTIVE
            and any(item.target is None for item in examples)):
        raise ValueError("Summed-category decision-margin training requires explicit targets.")
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
        trainable_names = set(contextual_output_trainable_names(runtime_model.model.config.__dict__))
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
    diagnostics_policy = validate_training_diagnostics_policy(snapshot.metadata)
    if diagnostics_policy and any(item.target is None for item in examples):
        raise ValueError("TRAIN diagnostics require explicit contextual targets for every row.")
    if diagnostics_policy:
        if local_steps is not None or objective in MEAN_CATEGORY_OBJECTIVES:
            raise ValueError("TRAIN process diagnostics require one legacy update with summed category BCE.")
        if {item.target.is_sensitive() for item in examples} != {False, True}:
            raise ValueError("TRAIN diagnostics require both clean and sensitive targets.")
    mean_category = objective in MEAN_CATEGORY_OBJECTIVES
    decision_margin = objective in DECISION_MARGIN_OBJECTIVES
    category_count = len(runtime_model.model.config.category_labels)
    objective_metrics = {}
    weight_audit = {}
    if objective in CLASS_BALANCED_OBJECTIVES:
        examples, weight_audit = _class_balanced_examples(examples)

    if adam_artifact and full_encoder:
        return _compute_full_adam_batch(runtime_model, examples, heldout_examples, weight_audit, cancel_check,
                                       retention_release=retention_release)

    gradients = {
        name: [0.0 for _ in snapshot.parameters[name]]
        for name in sorted(trainable_names)
    }
    predictions = runtime_model.model.predict_many(
        tuple(example.text for example in examples)
    )
    base_training_losses = (_local_training_losses(runtime_model.model, examples, objective, predictions=predictions)
                            if backtracking else None)
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
                if mean_category and (name.startswith("head.category.") or name == "readout.category.query"):
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
        if mean_category or objective == CLASS_BALANCED_SUM_CATEGORY_DECISION_MARGIN_OBJECTIVE:
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
    backtracking_result = None
    no_improvement = False
    effective_rate = learning_rate
    if backtracking:
        backtracking_result = _backtracking_trials(runtime_model, examples, gradients, gradient_denominator,
            learning_rate, max_gradient, objective, base_training_losses)
        scaled = backtracking_result["scaled"]
        effective_rate = backtracking_result["effective_rate"]
        no_improvement = backtracking_result["selected"] is None
        transport_cap = _inward_float32_bound(max_gradient)
    elif local_steps is None:
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
    heldout_metrics = {} if no_improvement else _heldout_metrics(
        runtime_model,
        snapshot.parameters,
        heldout_examples,
    )
    candidate_parameters = {
        name: tuple(float32(value) for value in updated_parameter_values(values, scaled[name]))
        if name in scaled else tuple(float32(value) for value in values)
        for name, values in snapshot.parameters.items()
    }
    if full_encoder and not no_improvement and not any(candidate_parameters[name] != tuple(float32(value) for value in snapshot.parameters[name])
                                for name in trainable_names - contextual_output_trainable_names(runtime_model.model.config.__dict__)):
        raise ValueError("Underlying training produced no transported encoder weight update.")
    if not no_improvement:
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
    diagnostics = None
    if diagnostics_policy and not no_improvement:
        if local_steps is not None or objective in MEAN_CATEGORY_OBJECTIVES:
            raise ValueError("TRAIN process diagnostics require one legacy update with summed category BCE.")
        raw = [(value / gradient_denominator) * effective_rate
               for values in gradients.values() for value in values]
        diagnostics = _training_diagnostics(runtime_model, examples, candidate_parameters,
            objective, raw, scaled, transport_cap,
            predictions=(predictions, backtracking_result["predictions"]) if backtracking else None)
    inventory = gradients if backtracking else scaled
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
            **({"gradient_fits": 1.0, "backtracking_trials": float(len(backtracking_result["trials"])),
                "backtracking_semantic_examples": float(sum(row[8] for row in backtracking_result["trials"])),
                "backtracking_forward_attempts": float(sum(row[10] > 0 for row in backtracking_result["trials"])),
                "backtracking_attempted_semantic_examples": float(sum(row[10] for row in backtracking_result["trials"]))}
               if backtracking else {}),
        },
        metadata={
            **({OPTIMIZER_KEY: ADAM_POLICY, "executed_contextual_training_optimizer": "dormant_head_v1",
                "full_projected_adam_config_v1": snapshot.metadata["full_projected_adam_config_v1"]}
               if adam_artifact else {}),
            EXECUTED_OBJECTIVE_KEY: objective or LEGACY_OBJECTIVE,
            **({DIAGNOSTICS_POLICY_KEY: diagnostics_policy} if diagnostics_policy else {}),
            **({DIAGNOSTICS_KEY: diagnostics} if diagnostics is not None else {}),
            **({BACKTRACKING_KEY: BACKTRACKING_POLICY, BACKTRACKING_PREPARATION_KEY: preparation,
                BACKTRACKING_TRACE_KEY: backtracking_result["trace"], BACKTRACKING_TRIALS_KEY: backtracking_result["trial_json"],
                **({"effective_learning_rate": str(effective_rate)} if not no_improvement else {})} if backtracking else {}),
            **({"contextual_optimizer_trace": optimizer_trace} if optimizer_trace is not None else {}),
            "strategy": strategy or "transformer_classification_head_finetune",
            "artifact_training_strategy": artifact_strategy or "transformer_classification_head_finetune",
            "underlying_training_available": "true" if artifact_strategy == FULL_ENCODER_STRATEGY else "false",
            "training_scope": "full_encoder" if full_encoder else ("last_block" if strategy == LAST_BLOCK_STRATEGY else "heads"),
            "trained_parameter_names": json.dumps(sorted(inventory), separators=(",", ":")),
            "trained_parameter_inventory_fingerprint": parameter_fingerprint(
                {name: () for name in inventory}, {name: snapshot.shapes[name] for name in inventory}),
            "artifact_checksum": snapshot.metadata.get("artifact_checksum", ""),
            "architecture": snapshot.metadata.get("architecture", "privoke_tiny_transformer_v1"),
            "model_config": json.dumps(runtime_model.model.config.to_mapping(),
                                       sort_keys=True, separators=(",", ":"), allow_nan=False),
            "base_parameter_fingerprint": _parameter_fingerprint(snapshot.parameters),
            **({"updated_parameter_fingerprint": _parameter_fingerprint(candidate_parameters)} if not no_improvement else {}),
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
            ((("base_heldout", len(heldout_examples)), ("candidate_heldout", len(heldout_examples))) if heldout_examples and not no_improvement else ()),
        error=BACKTRACKING_REJECTION if no_improvement else "",
    )


def _compute_full_adam_batch(runtime_model, examples, heldout_examples, weight_audit, cancel_check, *, retention_release=None):
    from .full_adam_training import fit, preflight, observe_numpy, FullAdamFailure
    from privoke_model.full_adam import POLICY, CONFIG, OBJECTIVE, TRACE_KEY, canonical
    preflight()
    snapshot = runtime_model.snapshot
    from privoke_model import sensitive_retention as retention_contract
    retention_policy = snapshot.metadata.get(OPTIMIZER_KEY) if retention_release is not None else None
    auxiliary = ()
    retention_fit = None
    if retention_release is not None:
        from .sensitive_retention_training import auxiliary_examples
        auxiliary = auxiliary_examples(retention_release)
        if retention_policy == retention_contract.HINGE_POLICY:
            retention_fit = (auxiliary, tuple(r["margin"] for _, r in retention_release.eligible),
                             retention_release.manifest["teacher"]["parameter_fingerprint"])
    work = {"schema": 1, "device": "cpu", "backend": "numpy", "phases": {},
            "partial_counts_are_observed_lower_bounds": True, "internal_completion_work_unknown": False,
            "capability_backwards": 1, "objective_attempted": 0, "objective_completed": 0}
    audit = {}
    base_safety = None
    try:
        # Untouched original BASE, explicitly isolated from serving device/tensors.
        base_model = observe_numpy(TinyTransformerModel(runtime_model.model.config, snapshot.parameters,
            snapshot.shapes, device="cpu", reject_overlength=runtime_model.model.reject_overlength), work, "base_train")
        base_predictions = base_model.predict_many(tuple(item.text for item in examples))
        base_exact = sum(_classification_from_prediction(p).pack() == e.target.pack()
                         for e, p in zip(examples, base_predictions)) / len(examples)
        base_safety = None
        if retention_release is not None:
            from .sensitive_retention_training import safety_rows
            observe_numpy(base_model, work, "base_original_train_safety")
            base_safety = safety_rows(retention_release, base_model.predict_many(tuple(item.text for item in auxiliary)), base_model)
        scaled, candidate, model, audit = fit(base_model, snapshot.parameters, snapshot.shapes, examples,
            cancel_check=cancel_check, **({"retention": retention_fit} if retention_fit is not None else {}))
        if not any(candidate[n] != tuple(float32(v) for v in snapshot.parameters[n]) for n in set(candidate) - contextual_output_trainable_names(runtime_model.model.config.__dict__)):
            raise ValueError("FULL Adam produced no transported encoder change.")
        observe_numpy(model, work, "candidate_train")
        final_predictions = model.predict_many(tuple(item.text for item in examples))
        candidate_exact = sum(_classification_from_prediction(p).pack() == e.target.pack()
                              for e, p in zip(examples, final_predictions)) / len(examples)
        work["objective_attempted"] += 1
        base_loss = _local_training_losses(base_model, examples, OBJECTIVE, predictions=base_predictions)[-1]
        work["objective_completed"] += 1
        work["objective_attempted"] += 1
        final_loss = _local_training_losses(model, examples, OBJECTIVE, predictions=final_predictions)[-1]
        work["objective_completed"] += 1
        guard = _heldout_metrics(runtime_model, snapshot.parameters, heldout_examples, device="cpu", numpy_work=work)
        guard.update({"candidate_"+k: v for k,v in _heldout_metrics(runtime_model, candidate, heldout_examples,
                     reference_parameters=snapshot.parameters, device="cpu", numpy_work=work).items()})
        if retention_release is not None:
            if cancel_check is not None and not cancel_check():
                raise ValueError("ORIGINAL retention cancelled before final safety execution.")
            from .sensitive_retention_training import safety_rows, finish_audit
            observe_numpy(model, work, "original_train_safety")
            safety = safety_rows(retention_release, model.predict_many(tuple(item.text for item in auxiliary)), model)
            finish_audit(audit, retention_release, retention_policy, base_safety, safety)
    except Exception as exc:
        # A raising opaque batch/loss may have done internal work beyond observed boundaries.
        work["internal_completion_work_unknown"] = True
        if isinstance(exc, FullAdamFailure):
            failure = exc
        else:
            trace = json.loads(audit[TRACE_KEY]) if TRACE_KEY in audit else {
                "schema": 1, "policy": POLICY, "config": CONFIG,
                "base": parameter_fingerprint(snapshot.parameters, snapshot.shapes), "final": None,
                "delta": None, "steps": [], "counts": {"directions_attempted": 0, "directions_completed": 0},
                "train": len(examples)}
            failure = FullAdamFailure(str(exc), trace)
            failure.training_metadata.update(audit)
            failure.training_metadata["full_adam_status"] = "postfit_error" if audit else "prefit_error"
        failure.training_metadata["full_adam_numpy_work_v1"] = canonical(work)
        if retention_release is not None:
            failure.training_metadata.update({OPTIMIZER_KEY: retention_policy,
                "executed_contextual_training_optimizer": retention_policy,
                retention_contract.MANIFEST_KEY: retention_release.sha256,
                "original_train_retention_partial_trace_v1": canonical({
                    "policy": retention_policy, "manifest_sha256": retention_release.sha256,
                    "work": work, "base_safety": base_safety,
                    "auxiliary": failure.training_metadata.get("original_train_retention_partial_work_v1"),
                    "completed_audit": audit})})
        if failure is exc:
            raise
        raise failure from exc
    metadata = {OPTIMIZER_KEY: POLICY, EXECUTED_OBJECTIVE_KEY: OBJECTIVE, **audit,
        "strategy": FULL_ENCODER_STRATEGY, "artifact_training_strategy": FULL_ENCODER_STRATEGY,
        "underlying_training_available": "true", "training_scope": "full_encoder",
        "trained_parameter_names": json.dumps(sorted(scaled), separators=(",", ":")),
        "trained_parameter_inventory_fingerprint": parameter_fingerprint({n: () for n in scaled}, snapshot.shapes),
        "artifact_checksum": snapshot.metadata["artifact_checksum"],
        "architecture": snapshot.metadata.get("architecture", "privoke_tiny_transformer_v1"),
            "model_config": json.dumps(runtime_model.model.config.to_mapping(), sort_keys=True, separators=(",", ":"), allow_nan=False),
        "base_parameter_fingerprint": parameter_fingerprint(snapshot.parameters, snapshot.shapes),
        "updated_parameter_fingerprint": parameter_fingerprint(candidate, snapshot.shapes),
        "learning_rate": str(CONFIG["eta"]), "max_gradient": str(CONFIG["delta_cap"]),
        "model_cache_key": snapshot.cache_key, "text_preprocessing": "canonical_detector_normalize_text",
        "full_adam_numpy_work_v1": canonical(work)}
    if retention_release is not None:
        metadata[EXECUTED_OBJECTIVE_KEY] = retention_contract.OBJECTIVES[retention_policy]
        metadata["contextual_training_objective"] = retention_contract.OBJECTIVES[retention_policy]
        metadata["contextual_training_strategy"] = FULL_ENCODER_STRATEGY
    return SemanticGradientBatch(snapshot.model_id, snapshot.version, scaled, snapshot.shapes,
        {"examples": float(len(examples)), "exact_match_rate": base_exact,
         "candidate_train_exact_match_rate": candidate_exact, "base_train_objective_loss": base_loss,
         "candidate_train_objective_loss": final_loss, "total_weight": math.fsum(e.weight for e in examples),
         **guard, **weight_audit}, metadata,
        (("training", len(examples)), ("base_heldout", len(heldout_examples)), ("candidate_heldout", len(heldout_examples)))
        + (tuple(retention_contract.execution_phases(metadata)) if retention_release is not None else ()))


def _backtracking_trials(runtime_model, examples, gradients, denominator, rate, bound, objective, baseline):
    """One immutable original direction; each trial reconstructs before clipping."""
    from privoke_model.artifact import ModelArtifactError
    snapshot = runtime_model.snapshot
    cap = _inward_float32_bound(bound)
    normalized = [v / denominator for values in gradients.values() for v in values]
    if any(not math.isfinite(v) for v in normalized):
        raise ValueError("Backtracking original direction must remain finite.")
    schema, columns = training_loss_contract(objective or LEGACY_OBJECTIVE)
    header = {"schema": schema, "policy": BACKTRACKING_POLICY, "objective": objective or LEGACY_OBJECTIVE,
        "base": [_parameter_fingerprint(snapshot.parameters), baseline],
        "raw": [parameter_fingerprint(gradients, snapshot.shapes),
                parameter_fingerprint({n: () for n in gradients}, {n: snapshot.shapes[n] for n in gradients}),
                len(normalized), math.hypot(*normalized), max(map(abs, normalized))],
        "selected": None, "gradient_fits": 1}
    if schema == 2:
        header["loss_columns"] = columns
    trials = []; selected_delta = {}; selected_predictions = None; selected_rate = None
    for index, scale in enumerate(BACKTRACKING_SCALES):
        actual_rate = rate * scale
        row = [actual_rate, None, None, None, None, None, None, "invalid_numeric", 0, False, 0]
        raw = [(value / denominator) * actual_rate for values in gradients.values() for value in values]
        if all(math.isfinite(value) for value in raw):
            delta = {name: tuple(float32(_clamp((v / denominator) * actual_rate, -cap, cap)) for v in values)
                     for name, values in gradients.items()}
            row[2:6] = [sum(abs(v) > cap for v in raw), max(map(abs, raw)),
                        max(abs(v) for values in delta.values() for v in values), parameter_fingerprint(delta, snapshot.shapes)]
            try:
                candidate = _transport_local_parameters(snapshot.parameters, delta)
                row[6] = _parameter_fingerprint(candidate)
                row[9] = any(candidate[n] != snapshot.parameters[n] for n in gradients.keys() - contextual_output_trainable_names(runtime_model.model.config.__dict__))
                model = TinyTransformerModel(runtime_model.model.config, candidate, snapshot.shapes,
                    device=runtime_model.model.compute_device, reject_overlength=runtime_model.model.reject_overlength)
                row[10] = len(examples)
                predictions = model.predict_many(tuple(item.text for item in examples))
                if len(predictions) != len(examples):
                    raise ValueError("Backtracking semantic forward returned incomplete rows.")
                row[8] = len(examples)
                losses = _local_training_losses(model, examples, objective, predictions=predictions)
            except (OverflowError, FloatingPointError):
                losses = None
            except ModelArtifactError as exc:
                if str(exc) not in ("Parameter is outside finite float32 range.", "Parameter must be finite."):
                    raise
                losses = None
            except ValueError as exc:
                if str(exc) not in ("Contextual supervised task losses must be finite and nonnegative.",
                                    "Local SGD task losses must remain finite and nonnegative."):
                    raise
                losses = None
            if losses is not None:
                row[1], row[7] = losses, "ok"
                if baseline[-1] - losses[-1] > BACKTRACKING_DECREASE and row[9]:
                    header["selected"] = index
                    selected_delta, selected_predictions, selected_rate = delta, predictions, actual_rate
        trials.append(row)
        if header["selected"] is not None:
            break
    trace = json.dumps(header, separators=(",", ":"), allow_nan=False)
    trial_json = json.dumps(trials, separators=(",", ":"), allow_nan=False)
    metadata = {BACKTRACKING_TRACE_KEY: trace, BACKTRACKING_TRIALS_KEY: trial_json,
        EXECUTED_OBJECTIVE_KEY: objective or LEGACY_OBJECTIVE, "base_parameter_fingerprint": header["base"][0],
        "trained_parameter_inventory_fingerprint": header["raw"][1]}
    if selected_rate is not None:
        metadata.update(effective_learning_rate=str(selected_rate), updated_parameter_fingerprint=trials[-1][6])
    validate_backtracking_trace(metadata, examples=len(examples), requested_rate=rate, rejected=selected_rate is None)
    return {"scaled": selected_delta, "predictions": selected_predictions, "effective_rate": selected_rate,
            "selected": header["selected"], "trace": trace, "trials": trials, "trial_json": trial_json}


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


def _local_training_losses(model, examples, objective, *, predictions=None):
    """Evaluate true weighted task losses at this exact transported runtime state."""
    try:
        total = math.fsum(item.weight for item in examples)
    except OverflowError as exc:
        raise ValueError("Local SGD total weight must remain finite and positive.") from exc
    if not math.isfinite(total) or total <= 0:
        raise ValueError("Local SGD total weight must remain finite and positive.")
    losses = {"sensitivity": 0.0, "visibility": 0.0, "category": 0.0}
    count = len(model.config.category_labels)
    decision_margin = objective in DECISION_MARGIN_OBJECTIVES
    if decision_margin:
        losses["decision_margin"] = 0.0
    if predictions is None:
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


def _training_diagnostics(runtime_model, examples, candidate_parameters, objective, raw, scaled, cap, *, predictions=None):
    """Passive scoring of immutable base and actual transported candidate TRAIN states."""
    clean = sum(not item.target.is_sensitive() for item in examples)
    sensitive = len(examples) - clean
    if not clean or not sensitive:
        raise ValueError("TRAIN diagnostics require both clean and sensitive targets.")
    if any(not math.isfinite(value) for value in raw):
        raise ValueError("TRAIN diagnostic raw deltas must remain finite.")
    models = (runtime_model.model, TinyTransformerModel(runtime_model.model.config, candidate_parameters,
        runtime_model.snapshot.shapes, device=runtime_model.model.compute_device,
        reject_overlength=runtime_model.model.reject_overlength))
    losses, accuracy = [], []
    for index, model in enumerate(models):
        state_predictions = predictions[index] if predictions is not None else None
        losses.append(_local_training_losses(model, examples, objective, predictions=state_predictions))
        state_predictions = state_predictions if state_predictions is not None else model.predict_many(tuple(item.text for item in examples))
        hits = [0] * 6
        for item, prediction in zip(examples, state_predictions):
            target, predicted = item.target, _classification_from_prediction(prediction)
            hits[0] += target.pack() == predicted.pack()
            hits[1] += target.sensitivity() == predicted.sensitivity()
            hits[2] += target.visibility() == predicted.visibility()
            hits[3] += set(target.categories()) == set(predicted.categories())
            hits[4] += not target.is_sensitive() and not predicted.is_sensitive()
            hits[5] += target.is_sensitive() and predicted.is_sensitive()
        accuracy.append([value / denominator for value, denominator in zip(hits, [len(examples)] * 4 + [clean, sensitive])])
    fingerprints = [_parameter_fingerprint(runtime_model.snapshot.parameters), _parameter_fingerprint(candidate_parameters)]
    schema, columns = training_loss_contract(objective or LEGACY_OBJECTIVE)
    record = {"schema": schema, "objective": objective or LEGACY_OBJECTIVE, "fingerprints": fingerprints,
        "phases": [["base_training", "semantic", "ok", len(examples)], ["candidate_training", "semantic", "ok", len(examples)]],
        "counts": [len(examples), clean, sensitive], "loss_columns": columns, "loss": losses,
        "accuracy_columns": DIAGNOSTIC_ACCURACY_COLUMNS, "accuracy": accuracy,
        "update_columns": DIAGNOSTIC_UPDATE_COLUMNS,
        "update": [len(raw), sum(abs(value) > cap for value in raw), max(map(abs, raw)),
                   max(abs(value) for values in scaled.values() for value in values)]}
    raw_record = json.dumps(record, separators=(",", ":"), allow_nan=False)
    validate_training_diagnostics(raw_record, objective=record["objective"], examples=len(examples),
        base_fingerprint=fingerprints[0], candidate_fingerprint=fingerprints[1])
    return raw_record


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
                     if objective in DECISION_MARGIN_OBJECTIVES else None)
        weight = item.weight / total if mean_category else item.weight
        for name, direction in values.items():
            if name not in gradients:
                continue
            for index, value in enumerate(direction):
                if mean_category and (name.startswith("head.category.") or name == "readout.category.query"):
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

    logits = {task: model.prediction_logits(prediction, task)
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
    logits = {head: model.prediction_logits(prediction, head) for head in ("sensitivity", "category")}
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
    return loss, model.output_deltas_from_errors(prediction, errors)


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


def _heldout_metrics(runtime_model, parameters, examples, *, reference_parameters=None, device=None, numpy_work=None):
    if not examples:
        return {}
    model = TinyTransformerModel(
        ModelConfig.from_metadata(runtime_model.snapshot.metadata),
        parameters,
        runtime_model.snapshot.shapes,
        reject_overlength=runtime_model.model.reject_overlength,
        device=device,
    )
    if numpy_work is not None:
        from .full_adam_training import observe_numpy
        observe_numpy(model, numpy_work, "candidate_heldout" if reference_parameters is not None else "base_heldout")
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
        reference_model = TinyTransformerModel(
            ModelConfig.from_metadata(runtime_model.snapshot.metadata),
            reference_parameters,
            runtime_model.snapshot.shapes,
            reject_overlength=runtime_model.model.reject_overlength,
            device=device,
        )
        if numpy_work is not None:
            observe_numpy(reference_model, numpy_work, "reference_heldout")
        reference = reference_model.predict_many(tuple(example.text for example in examples))
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
