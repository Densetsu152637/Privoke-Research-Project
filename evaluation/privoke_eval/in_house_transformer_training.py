"""Mechanics-only CPU autograd for the existing in-house contextual encoder.

No data loader, fitting loop, artifact publication or binary-to-contextual labels.
Torch is an explicit training dependency; serving remains unchanged.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import copy
import math
from types import MappingProxyType
from typing import Mapping, Sequence

import numpy as np
import torch
from torch.nn import functional as F

from src.detection.preprocessing import normalize_text
from src.model import ModelConfig, TinyTransformerModel

MAX_BATCH_SIZE = 32


@dataclass(frozen=True)
class ContextualTarget:
    sensitivity: str
    visibility: str
    categories: tuple[str, ...]


@dataclass(frozen=True)
class TrainingOptions:
    mode: str = "end_to_end"
    learning_rate: float = 0.001
    weight_decay: float = 0.0001
    max_gradient_norm: float = 1.0

    def validate(self) -> None:
        if self.mode not in {"head_only", "end_to_end"}:
            raise ValueError("Unknown training mode.")
        for value in (self.learning_rate, self.max_gradient_norm):
            if isinstance(value, bool) or not isinstance(value, (float, int)) or not math.isfinite(value) or value <= 0:
                raise ValueError("Training rates and norm bounds must be finite and positive.")
        if isinstance(self.weight_decay, bool) or not isinstance(self.weight_decay, (float, int)) or not math.isfinite(self.weight_decay) or self.weight_decay < 0:
            raise ValueError("Weight decay must be finite and nonnegative.")


class InHouseTransformerTrainer:
    """Own independent CPU parameters and Adam state, initialized by the caller.

    Sensitivity CE + visibility CE + mean-category BCE are optimized equally.
    Every example requires all contextual targets; unknown/pseudo labels fail.
    Parameter export returns copies and never installs or publishes an artifact.
    """

    def __init__(self, config: ModelConfig, arrays: Mapping[str, np.ndarray],
                 options: TrainingOptions = TrainingOptions()):
        options.validate()
        config = ModelConfig.from_mapping(asdict(config))
        runtime = TinyTransformerModel(config, {n: np.asarray(a).ravel() for n, a in arrays.items()},
                                       {n: np.asarray(a).shape for n, a in arrays.items()}, device="cpu")
        if set(arrays) != set(runtime._required_tensors()):
            raise ValueError("Training tensors must exactly match the encoder contract.")
        if any(not np.isfinite(a).all() for a in runtime.parameters.values()):
            raise ValueError("Training parameters must be finite.")
        self.config, self.options = config, options
        self._tokenizer = runtime
        self._parameters = {
            name: torch.nn.Parameter(torch.tensor(value.copy(), dtype=torch.float32, device="cpu"),
                                     requires_grad=options.mode == "end_to_end" or name.startswith("head."))
            for name, value in runtime.parameters.items()
        }
        self._trainable = [value for value in self._parameters.values() if value.requires_grad]
        self._optimizer = torch.optim.Adam(self._trainable, lr=options.learning_rate,
                                           weight_decay=options.weight_decay)

    @property
    def parameters(self) -> Mapping[str, torch.nn.Parameter]:
        """Named owned tensors, exposed for mechanics inspection, not serving use."""
        return MappingProxyType(self._parameters)

    def optimizer_state(self) -> dict:
        return copy.deepcopy(self._optimizer.state_dict())

    def tensor_batch(self, texts: Sequence[str]) -> tuple[torch.Tensor, torch.Tensor]:
        if isinstance(texts, (str, bytes)) or not 1 <= len(texts) <= MAX_BATCH_SIZE or any(type(t) is not str for t in texts):
            raise ValueError("Training batch requires one to 32 explicit strings.")
        rows = [self._tokenizer.token_ids(normalize_text(text)).tolist() for text in texts]
        length = max(map(len, rows))
        ids = torch.zeros((len(rows), length), dtype=torch.long)
        mask = torch.zeros_like(ids, dtype=torch.bool)
        for i, row in enumerate(rows):
            ids[i, :len(row)] = torch.tensor(row, dtype=torch.long)
            mask[i, :len(row)] = True
        return ids, mask

    def _validate_batch(self, ids: torch.Tensor, mask: torch.Tensor) -> None:
        if not isinstance(ids, torch.Tensor) or not isinstance(mask, torch.Tensor):
            raise ValueError("Token IDs and masks must be CPU tensors.")
        if (ids.device.type != "cpu" or mask.device.type != "cpu" or ids.dtype != torch.long
                or mask.dtype != torch.bool or ids.ndim != 2 or mask.shape != ids.shape
                or not 1 <= ids.shape[0] <= MAX_BATCH_SIZE
                or not 1 <= ids.shape[1] <= self.config.max_tokens):
            raise ValueError("Token batch has invalid dimensions, dtype or device.")
        if (not mask[:, 0].all() or (ids[:, 0] != 0).any()
                or ((~mask[:, :-1]) & mask[:, 1:]).any()
                or (ids[~mask] != 0).any() or (ids[:, 1:][mask[:, 1:]] == 0).any() or (ids < 0).any()
                or (ids >= self.config.vocab_size).any()):
            raise ValueError("Token batch violates the first-token or padding contract.")

    def logits(self, ids: torch.Tensor, mask: torch.Tensor) -> Mapping[str, torch.Tensor]:
        self._validate_batch(ids, mask)
        p, c = self._parameters, self.config
        if any(not torch.isfinite(value).all() for value in p.values()):
            raise ValueError("Training parameters must remain finite.")
        length = ids.shape[1]
        hidden = p["token_embedding"][ids] + p["position_embedding"][:length]
        for layer in range(c.num_layers):
            prefix = "" if c.num_layers == 1 else f"layers.{layer}."
            def split(value):
                return value.reshape(ids.shape[0], length, c.num_attention_heads,
                                     c.hidden_size // c.num_attention_heads).transpose(1, 2)
            query = split(hidden @ p[prefix + "attention.query.weight"])
            key = split(hidden @ p[prefix + "attention.key.weight"])
            value = split(hidden @ p[prefix + "attention.value.weight"])
            scores = (query @ key.transpose(2, 3)) / math.sqrt(c.hidden_size // c.num_attention_heads)
            scores = scores.masked_fill(~mask[:, None, None, :], -10000.0)
            attended = (torch.softmax(scores, -1) @ value).transpose(1, 2).reshape(hidden.shape)
            attended = attended @ p[prefix + "attention.output.weight"] + p[prefix + "attention.output.bias"]
            hidden = F.layer_norm(hidden + attended, (c.hidden_size,), eps=1e-5)
            intermediate = F.gelu(hidden @ p[prefix + "ffn.input.weight"] + p[prefix + "ffn.input.bias"], approximate="tanh")
            hidden = F.layer_norm(hidden + intermediate @ p[prefix + "ffn.output.weight"]
                                  + p[prefix + "ffn.output.bias"], (c.hidden_size,), eps=1e-5)
        real = mask.unsqueeze(-1)
        pooled = hidden[:, 0] * 0.5 + (hidden * real).sum(1) / real.sum(1).clamp_min(1) * 0.5
        return MappingProxyType({head: pooled @ p[f"head.{head}.weight"] + p[f"head.{head}.bias"]
                                 for head in ("sensitivity", "visibility", "category")})

    def loss(self, ids: torch.Tensor, mask: torch.Tensor,
             targets: Sequence[ContextualTarget]) -> torch.Tensor:
        self._validate_batch(ids, mask)
        if not isinstance(targets, (list, tuple)) or len(targets) != ids.shape[0] or any(not isinstance(t, ContextualTarget) for t in targets):
            raise ValueError("Every training row requires explicit contextual targets.")
        c = self.config
        for target in targets:
            if (type(target.sensitivity) is not str or target.sensitivity not in c.sensitivity_labels
                    or type(target.visibility) is not str or target.visibility not in c.visibility_labels
                    or not isinstance(target.categories, tuple)
                    or any(type(cat) is not str or cat not in c.category_labels for cat in target.categories)
                    or len(target.categories) != len(set(target.categories))):
                raise ValueError("Contextual targets contain unsupported or duplicate labels.")
        logits = self.logits(ids, mask)
        sensitivity = torch.tensor([c.sensitivity_labels.index(t.sensitivity) for t in targets])
        visibility = torch.tensor([c.visibility_labels.index(t.visibility) for t in targets])
        categories = torch.tensor([[float(cat in t.categories) for cat in c.category_labels] for t in targets])
        loss = (F.cross_entropy(logits["sensitivity"], sensitivity)
                + F.cross_entropy(logits["visibility"], visibility)
                + F.binary_cross_entropy_with_logits(logits["category"], categories))
        if not torch.isfinite(loss):
            raise ValueError("Training loss must be finite.")
        return loss

    def gradients(self, texts: Sequence[str], targets: Sequence[ContextualTarget]) -> tuple[float, Mapping[str, torch.Tensor]]:
        ids, mask = self.tensor_batch(texts)
        self._optimizer.zero_grad(set_to_none=True)
        loss = self.loss(ids, mask, targets)
        loss.backward()
        grads = {}
        for name, parameter in self._parameters.items():
            if parameter.requires_grad:
                if parameter.grad is None or not torch.isfinite(parameter.grad).all():
                    raise ValueError("Training gradients must exist and be finite.")
                grads[name] = parameter.grad.detach().clone()
        return float(loss.detach()), MappingProxyType(grads)

    def step(self, texts: Sequence[str], targets: Sequence[ContextualTarget]) -> Mapping[str, float]:
        loss, _ = self.gradients(texts, targets)
        norm = torch.nn.utils.clip_grad_norm_(self._trainable, self.options.max_gradient_norm,
                                             error_if_nonfinite=True)
        before = {name: parameter.detach().clone() for name, parameter in self._parameters.items()}
        state = self.optimizer_state()
        try:
            self._optimizer.step()
            if any(not torch.isfinite(p).all() for p in self._parameters.values()):
                raise ValueError("Optimizer produced non-finite parameters.")
        except Exception:
            with torch.no_grad():
                for name, value in before.items():
                    self._parameters[name].copy_(value)
            self._optimizer.load_state_dict(state)
            raise
        return MappingProxyType({"loss": loss, "gradient_norm_before_clip": float(norm)})

    def export_parameters(self) -> dict[str, np.ndarray]:
        if any(not torch.isfinite(value).all() for value in self._parameters.values()):
            raise ValueError("Export parameters must be finite.")
        return {name: value.detach().cpu().numpy().astype(np.float32, copy=True)
                for name, value in self._parameters.items()}
