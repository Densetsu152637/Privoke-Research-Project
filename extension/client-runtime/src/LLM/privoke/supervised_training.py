"""Isolated CPU autograd for explicitly admitted Tiny encoder training scopes."""
from __future__ import annotations

import math
import numpy as np

from privoke_model.contextual_training import (OBJECTIVE_KEY, MEAN_CATEGORY_OBJECTIVES,
    CLASS_BALANCED_DECISION_MARGIN_OBJECTIVE, DECISION_MARGIN_OBJECTIVES, validate_decision_margin_config,
    validate_contextual_training_objective)

MAX_MICROBATCH = 32


def supervised_last_block_deltas(model, examples, trainable_names, *, microbatch_size=MAX_MICROBATCH,
                                objective=None, diagnostics=None, retention_margins=None, retention_diagnostics=None,
                                retention_components=None, normalization_denominator=None, work_counts=None):
    """Return weighted SGD direction and true loss without mutating serving tensors.

    Legacy objectives use sensitivity CE + visibility CE + summed category BCE.
    The versioned mean-category objective averages category BCE over labels.
    The decision-margin objective adds union-margin BCE with coefficient one.
    Optional diagnostics receives only its typed weighted CE/BCE task components.
    Microbatches share one global weight denominator and one immutable base.
    """
    validate_contextual_training_objective({OBJECTIVE_KEY: objective} if objective is not None else {})
    mean_category = objective in MEAN_CATEGORY_OBJECTIVES
    decision_margin = objective in DECISION_MARGIN_OBJECTIVES
    if decision_margin:
        validate_decision_margin_config(model.config.__dict__)
    if type(microbatch_size) is not int or not 1 <= microbatch_size <= MAX_MICROBATCH:
        raise ValueError("Contextual microbatch size must be between one and 32.")
    if not examples or any(item.target is None for item in examples):
        raise ValueError("Encoder adaptation requires explicit contextual targets for every row.")
    if any(not math.isfinite(item.weight) or item.weight <= 0 for item in examples):
        raise ValueError("Training weights must be finite and positive.")
    total_weight = math.fsum(item.weight for item in examples)
    if normalization_denominator is not None:
        if not math.isfinite(normalization_denominator) or normalization_denominator <= 0 or retention_components is not None:
            raise ValueError("Explicit main denominator must be positive finite and independent of auxiliary normalization.")
        total_weight = normalization_denominator
    if retention_components is not None:
        if len(retention_components) != len(examples) or any(not row for row in retention_components) or retention_margins is not None:
            raise ValueError("Component auxiliary requires one nonempty frozen specification per eligible row.")
        total_weight = len(examples)
    if retention_margins is not None:
        from privoke_model.sensitive_retention import HINGE_OBJECTIVE
        if (objective != HINGE_OBJECTIVE or len(retention_margins) != len(examples)
                or any(type(v) not in (int, float) or not math.isfinite(v) for v in retention_margins)
                or any(item.weight != 1 for item in examples) or diagnostics is not None):
            raise ValueError("Retention hinge requires independent unit-weight rows and fixed finite ORIGINAL margins.")
        total_weight = len(examples)
        if retention_diagnostics is not None:
            retention_diagnostics.update(active_rows=0, maximum_hinge=0.0, maximum_scaled_original_difference=0.0)
    elif retention_diagnostics is not None:
        raise ValueError("Retention diagnostics require the independently normalized hinge route.")
    if not math.isfinite(total_weight):
        raise ValueError("Training total weight must remain finite.")
    try:
        import torch
    except ImportError as exc:
        raise ValueError("Encoder adaptation requires the opt-in CPU training dependency.") from exc
    c = model.config
    # Do not reuse cached Torch storage or inherit serving inference_mode.
    with torch.inference_mode(False), torch.enable_grad():
        p = {name: torch.tensor(value.copy(), dtype=torch.float32, device="cpu",
                                requires_grad=name in trainable_names)
             for name, value in model.parameters.items()}
        if any(not torch.isfinite(value).all() for value in p.values()):
            raise ValueError("Contextual training parameters must be finite.")
        objective_loss = 0.0
        task_totals = {"sensitivity": 0.0, "visibility": 0.0, "category": 0.0}
        for start in range(0, len(examples), microbatch_size):
            batch = examples[start:start + microbatch_size]
            if work_counts is not None:
                work_counts["rows_attempted"] += len(batch)
                work_counts["microbatch_forward_attempted"] += 1
            rows = [model.token_ids(item.text).tolist() for item in batch]
            length = max(map(len, rows))
            ids = torch.zeros((len(rows), length), dtype=torch.long)
            mask = torch.zeros_like(ids, dtype=torch.bool)
            for i, row in enumerate(rows):
                ids[i, :len(row)] = torch.tensor(row, dtype=torch.long)
                mask[i, :len(row)] = True
            hidden = p["token_embedding"][ids] + p["position_embedding"][:length]
            for layer in range(c.num_layers):
                if work_counts is not None:
                    work_counts["torch_block_forwards_attempted"] += 1
                hidden = model._torch_encoder_block(hidden, mask, model._layer_prefix(layer), torch, p)
                if work_counts is not None:
                    work_counts["torch_block_forwards_completed"] += 1
            from ...task_readout import torch_readout
            _, _, logits = torch_readout(hidden, mask, c, p, torch)
            sensitivity = torch.tensor([c.sensitivity_labels.index(item.target.sensitivity().name)
                                        for item in batch], dtype=torch.long)
            visibility = torch.tensor([c.visibility_labels.index(item.target.visibility().name)
                                       for item in batch], dtype=torch.long)
            categories = torch.tensor([[float(label in {cat.name for cat in item.target.categories()})
                                        for label in c.category_labels] for item in batch])
            weights = torch.tensor([item.weight / total_weight for item in batch], dtype=torch.float32)
            if retention_components is not None:
                from .window_training import component_hinge
                loss = sum(component_hinge({task: value[i] for task, value in logits.items()}, specs, torch)
                    for i, specs in enumerate(retention_components[start:start + len(batch)])) / total_weight
            elif mean_category or decision_margin:
                task_losses = {
                    "sensitivity": torch.nn.functional.cross_entropy(logits["sensitivity"], sensitivity, reduction="none"),
                    "visibility": torch.nn.functional.cross_entropy(logits["visibility"], visibility, reduction="none"),
                    "category": torch.nn.functional.binary_cross_entropy_with_logits(
                        logits["category"], categories, reduction="none").mean(1) if mean_category else
                        torch.nn.functional.binary_cross_entropy_with_logits(logits["category"], categories, reduction="none").sum(1),
                }
                per_row = task_losses["sensitivity"] + task_losses["visibility"] + task_losses["category"]
                if decision_margin:
                    s0 = c.sensitivity_labels.index("S0")
                    alternatives = [i for i, label in enumerate(c.sensitivity_labels) if label != "S0"]
                    offset = math.log(c.category_threshold) - math.log1p(-c.category_threshold)
                    margins = torch.cat((logits["sensitivity"][:, alternatives] - logits["sensitivity"][:, s0:s0+1],
                                         logits["category"] - offset), dim=1)
                    if not torch.isfinite(margins).all():
                        raise ValueError("Decision-margin differences must remain finite.")
                    # torch.max(dim) routes ties to its first index, matching NumPy argmax.
                    margin = margins.max(dim=1).values
                    if retention_margins is not None:
                        original = torch.tensor(retention_margins[start:start + len(batch)], dtype=torch.float32)
                        # Separate unweighted mean; no main task or main denominator enters this call.
                        per_row = torch.relu(original - margin)
                        if retention_diagnostics is not None:
                            for reference, current in zip(retention_margins[start:start + len(batch)], margin.detach().tolist()):
                                excess = max(0.0, reference - current)
                                retention_diagnostics["active_rows"] += excess > 1e-4 + 1e-4 * abs(reference)
                                retention_diagnostics["maximum_hinge"] = max(retention_diagnostics["maximum_hinge"], excess)
                                retention_diagnostics["maximum_scaled_original_difference"] = max(
                                    retention_diagnostics["maximum_scaled_original_difference"],
                                    abs(reference - current) / (1e-5 + 1e-5 * abs(reference)))
                    else:
                        positive = torch.tensor([float(item.target.is_sensitive()) for item in batch])
                        auxiliary = torch.nn.functional.softplus(torch.where(positive.bool(), -margin, margin))
                        per_row = per_row + auxiliary
                loss = (per_row * weights).sum()
                for task, values in task_losses.items():
                    task_totals[task] += float((values * weights).sum().detach())
            else:
                loss = ((torch.nn.functional.cross_entropy(logits["sensitivity"], sensitivity, reduction="none")
                         + torch.nn.functional.cross_entropy(logits["visibility"], visibility, reduction="none")
                         + torch.nn.functional.binary_cross_entropy_with_logits(
                             logits["category"], categories, reduction="none").sum(1)) * weights).sum()
            if not torch.isfinite(loss):
                raise ValueError("Contextual supervised loss must be finite.")
            objective_loss += float(loss.detach())
            if work_counts is not None:
                work_counts["microbatch_forward_completed"] += 1
                work_counts["microbatch_backward_started"] += 1
            loss.backward()
            if work_counts is not None:
                work_counts["microbatch_backward_completed"] += 1
                work_counts["rows_completed"] += len(batch)
        deltas = {}
        for name in sorted(trainable_names):
            gradient = p[name].grad
            if retention_components is not None and gradient is None:
                gradient = torch.zeros_like(p[name])
            if retention_margins is not None and gradient is None and (name.startswith("head.visibility.") or name == "readout.visibility.query"):
                # Binary margin has no visibility term; its exact contribution is zero.
                gradient = torch.zeros_like(p[name])
            if gradient is None or not torch.isfinite(gradient).all():
                raise ValueError("Contextual supervised gradients must exist and be finite.")
            deltas[name] = tuple(float(value) for value in -gradient.detach().numpy().ravel())
    if (mean_category or decision_margin) and diagnostics is not None:
        diagnostics.update({f"supervised_{task}_{'bce' if task == 'category' else 'ce'}_loss": value
                            for task, value in task_totals.items()})
    return deltas, objective_loss
