"""Isolated CPU autograd for the explicit contextual last-block strategy."""
from __future__ import annotations

import math
import numpy as np

from privoke_model.contextual_training import (OBJECTIVE_KEY, MEAN_CATEGORY_OBJECTIVES,
    CLASS_BALANCED_DECISION_MARGIN_OBJECTIVE, validate_decision_margin_config,
    validate_contextual_training_objective)

MAX_MICROBATCH = 32


def supervised_last_block_deltas(model, examples, trainable_names, *, microbatch_size=MAX_MICROBATCH,
                                objective=None, diagnostics=None):
    """Return weighted SGD direction and true loss without mutating serving tensors.

    Legacy objectives use sensitivity CE + visibility CE + summed category BCE.
    The versioned mean-category objective averages category BCE over labels.
    The decision-margin objective adds union-margin BCE with coefficient one.
    Optional diagnostics receives only its typed weighted CE/BCE task components.
    Microbatches share one global weight denominator and one immutable base.
    """
    validate_contextual_training_objective({OBJECTIVE_KEY: objective} if objective is not None else {})
    mean_category = objective in MEAN_CATEGORY_OBJECTIVES
    decision_margin = objective == CLASS_BALANCED_DECISION_MARGIN_OBJECTIVE
    if decision_margin:
        validate_decision_margin_config(model.config.__dict__)
    if type(microbatch_size) is not int or not 1 <= microbatch_size <= MAX_MICROBATCH:
        raise ValueError("Contextual microbatch size must be between one and 32.")
    if not examples or any(item.target is None for item in examples):
        raise ValueError("Encoder adaptation requires explicit contextual targets for every row.")
    if any(not math.isfinite(item.weight) or item.weight <= 0 for item in examples):
        raise ValueError("Training weights must be finite and positive.")
    total_weight = math.fsum(item.weight for item in examples)
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
            rows = [model.token_ids(item.text).tolist() for item in batch]
            length = max(map(len, rows))
            ids = torch.zeros((len(rows), length), dtype=torch.long)
            mask = torch.zeros_like(ids, dtype=torch.bool)
            for i, row in enumerate(rows):
                ids[i, :len(row)] = torch.tensor(row, dtype=torch.long)
                mask[i, :len(row)] = True
            hidden = p["token_embedding"][ids] + p["position_embedding"][:length]
            for layer in range(c.num_layers):
                hidden = model._torch_encoder_block(hidden, mask, model._layer_prefix(layer), torch, p)
            real = mask.unsqueeze(-1)
            pooled = hidden[:, 0] * 0.5 + (hidden * real).sum(1) / real.sum(1).clamp_min(1) * 0.5
            logits = {head: pooled @ p[f"head.{head}.weight"] + p[f"head.{head}.bias"]
                      for head in ("sensitivity", "visibility", "category")}
            sensitivity = torch.tensor([c.sensitivity_labels.index(item.target.sensitivity().name)
                                        for item in batch], dtype=torch.long)
            visibility = torch.tensor([c.visibility_labels.index(item.target.visibility().name)
                                       for item in batch], dtype=torch.long)
            categories = torch.tensor([[float(label in {cat.name for cat in item.target.categories()})
                                        for label in c.category_labels] for item in batch])
            weights = torch.tensor([item.weight / total_weight for item in batch], dtype=torch.float32)
            if mean_category:
                task_losses = {
                    "sensitivity": torch.nn.functional.cross_entropy(logits["sensitivity"], sensitivity, reduction="none"),
                    "visibility": torch.nn.functional.cross_entropy(logits["visibility"], visibility, reduction="none"),
                    "category": torch.nn.functional.binary_cross_entropy_with_logits(
                        logits["category"], categories, reduction="none").mean(1),
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
            loss.backward()
        deltas = {}
        for name in sorted(trainable_names):
            gradient = p[name].grad
            if gradient is None or not torch.isfinite(gradient).all():
                raise ValueError("Contextual supervised gradients must exist and be finite.")
            deltas[name] = tuple(float(value) for value in -gradient.detach().numpy().ravel())
    if mean_category and diagnostics is not None:
        diagnostics.update({f"supervised_{task}_{'bce' if task == 'category' else 'ce'}_loss": value
                            for task, value in task_totals.items()})
    return deltas, objective_loss
