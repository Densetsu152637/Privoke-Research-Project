"""The same residual task readout for serving and differentiable training."""
from __future__ import annotations

import math
import numpy as np
from privoke_model.readout import TASKS, TASK_QUERY_READOUT


def numpy_readout(hidden, config, parameters):
    mean = hidden.mean(axis=0)
    pooled = (hidden[0] * 0.5 + mean * 0.5).astype(np.float32)
    features, attention = {}, {}
    for task in TASKS:
        if config.readout == TASK_QUERY_READOUT:
            scores = hidden @ parameters[f"readout.{task}.query"] / math.sqrt(config.hidden_size)
            scores = scores - scores.max()
            alpha = np.exp(scores)
            alpha = alpha / alpha.sum()
            features[task] = pooled + (alpha @ hidden - mean)
            attention[task] = alpha
        else:
            features[task] = pooled
    logits = {task: features[task] @ parameters[f"head.{task}.weight"]
              + parameters[f"head.{task}.bias"] for task in TASKS}
    if any(not np.isfinite(value).all() for value in (*features.values(), *logits.values())):
        raise ValueError("Tiny readout produced non-finite states.")
    return pooled, features, logits, attention


def torch_readout(hidden, mask, config, parameters, torch):
    real = mask.unsqueeze(-1)
    mean = (hidden * real).sum(1) / real.sum(1).clamp_min(1)
    pooled = hidden[:, 0] * 0.5 + mean * 0.5
    features = {}
    for task in TASKS:
        if config.readout == TASK_QUERY_READOUT:
            scores = hidden @ parameters[f"readout.{task}.query"] / math.sqrt(config.hidden_size)
            scores = scores.masked_fill(~mask, -torch.inf)
            alpha = torch.softmax(scores, dim=1)
            features[task] = pooled + ((alpha.unsqueeze(-1) * hidden).sum(1) - mean)
        else:
            features[task] = pooled
    logits = {task: features[task] @ parameters[f"head.{task}.weight"]
              + parameters[f"head.{task}.bias"] for task in TASKS}
    if any(not torch.isfinite(value).all() for value in (*features.values(), *logits.values())):
        raise ValueError("Tiny readout produced non-finite states.")
    return pooled, features, logits
