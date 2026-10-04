"""Offline CPU mechanics for scratch binary annotation-presence transformers.

This module deliberately owns no data loading, fit loop, checkpoint schedule,
artifact writing, serving cache, or label conversion. It provides deterministic
paired initialization, one bounded autograd/Adam step, and validated in-memory
artifact export for synthetic mechanics checks and a later isolated fitter.
"""
from __future__ import annotations

import copy
from dataclasses import dataclass
import hashlib
import math
from types import MappingProxyType
from typing import Mapping, Sequence

import numpy as np
import torch
from torch.nn import functional as F

from privoke_model.artifact import artifact_checksum, validate_artifact
from privoke_model.fingerprint import parameter_fingerprint
from privoke_model.scratch_presence import (
    SCRATCH_PRESENCE_ARCHITECTURE,
    SCRATCH_PROFILES,
    SCRATCH_MODES,
    scratch_model_id,
    scratch_presence_tensor_shapes,
    scratch_presence_trainable_names,
    validate_scratch_artifact,
    validate_scratch_presence_config,
    validate_scratch_presence_parameters,
)
from src.detection.preprocessing import normalize_text
from src.transformer_encoder import EncoderConfig, NumpyTransformerEncoder, token_ids
from src.model import ModelConfig
from generate_baseline import (
    CATEGORIES,
    SENSITIVITIES,
    VISIBILITIES,
    initial_parameters,
)


TRAINING_SEED = 12102026
LEARNING_RATE = 0.001
WEIGHT_DECAY = 0.0001
MAX_GRAD_NORM = 1.0
_MODE_NAMES = frozenset(SCRATCH_MODES.values())


def presence_config(profile: str, training_mode: str) -> dict[str, object]:
    """Build one exact frozen profile configuration; no arbitrary dimensions."""
    if type(profile) is not str or profile not in SCRATCH_PROFILES:
        raise ValueError("Unsupported scratch profile.")
    if type(training_mode) is not str or training_mode not in _MODE_NAMES:
        raise ValueError("Unsupported scratch training mode.")
    vocab, hidden, intermediate, context, layers, heads = SCRATCH_PROFILES[profile]
    return validate_scratch_presence_config({
        "task": "annotation_presence",
        "profile": profile,
        "training_mode": training_mode,
        "vocab_size": vocab,
        "hidden_size": hidden,
        "intermediate_size": intermediate,
        "max_tokens": context,
        "num_layers": layers,
        "num_attention_heads": heads,
        "normalization": "detector_normalize_text_v1",
        "tokenizer": "legacy_sha256_bucket_tokens_v1",
        "pooling": "half_first_half_real_mean_v1",
        "arithmetic": "float32_numpy_encoder_clipped_sigmoid_v1",
        "threshold": 0.5,
    })


def _legacy_model_config(config: Mapping[str, object]) -> ModelConfig:
    return ModelConfig(
        vocab_size=config["vocab_size"],
        hidden_size=config["hidden_size"],
        intermediate_size=config["intermediate_size"],
        max_tokens=config["max_tokens"],
        sensitivity_labels=SENSITIVITIES,
        visibility_labels=VISIBILITIES,
        category_labels=CATEGORIES,
        category_threshold=0.5,
        num_layers=config["num_layers"],
        num_attention_heads=config["num_attention_heads"],
    )


def _encoder_initialization(profile: str) -> dict[str, np.ndarray]:
    """Use the original random encoder initializer, then draw one binary head."""
    if type(profile) is not str or profile not in SCRATCH_PROFILES:
        raise ValueError("Unsupported scratch profile.")
    config = presence_config(profile, "end_to_end")
    rng = np.random.default_rng(TRAINING_SEED)
    generated = initial_parameters(_legacy_model_config(config), rng)
    arrays = {
        name: np.asarray(value, dtype=np.float32).copy()
        for name, value in generated.items()
        if not name.startswith("head.")
    }
    arrays["head.presence.weight"] = rng.normal(
        0.0, 0.08, (config["hidden_size"], 1)
    ).astype(np.float32)
    arrays["head.presence.bias"] = np.zeros((1,), dtype=np.float32)
    expected = scratch_presence_tensor_shapes(config)
    if set(arrays) != set(expected) or any(arrays[name].shape != shape for name, shape in expected.items()):
        raise ValueError("Original initializer did not match the scratch encoder contract.")
    return arrays


def _fingerprint(parameters: Mapping[str, np.ndarray]) -> str:
    return parameter_fingerprint(
        {name: array.ravel().tolist() for name, array in parameters.items()},
        {name: array.shape for name, array in parameters.items()},
    )


def _validate_numpy_parameters(config: Mapping[str, object], parameters: Mapping[str, np.ndarray]) -> None:
    shapes = scratch_presence_tensor_shapes(config)
    trainable = {name: config["training_mode"] == "end_to_end" or name.startswith("head.presence.")
                 for name in shapes}
    if not isinstance(parameters, Mapping) or set(parameters) != set(shapes):
        raise ValueError("Training tensor inventory is incomplete.")
    flattened: dict[str, list[float]] = {}
    for name, shape in shapes.items():
        array = parameters[name]
        if not isinstance(array, np.ndarray) or array.shape != shape or array.dtype != np.float32:
            raise ValueError("Training tensors must have exact float32 shapes.")
        if not np.isfinite(array).all():
            raise ValueError("Training tensors must be finite.")
        flattened[name] = array.ravel().tolist()
    validate_scratch_presence_parameters(
        config, flattened, shapes, trainable
    )


def create_paired_trainers(profile: str) -> tuple["ScratchPresenceTrainer", "ScratchPresenceTrainer"]:
    """Create H/F clones from one exact initialization and independent state."""
    initialized = _encoder_initialization(profile)
    initialization_sha256 = _fingerprint(initialized)
    head = ScratchPresenceTrainer(
        presence_config(profile, "head_only"), initialized, initialization_sha256
    )
    full = ScratchPresenceTrainer(
        presence_config(profile, "end_to_end"), initialized, initialization_sha256
    )
    return head, full


def _tree_is_finite(value: object) -> bool:
    if isinstance(value, torch.Tensor):
        return bool(torch.isfinite(value).all())
    if isinstance(value, np.ndarray):
        return bool(np.isfinite(value).all())
    if isinstance(value, Mapping):
        return all(_tree_is_finite(item) for item in value.values())
    if isinstance(value, (tuple, list)):
        return all(_tree_is_finite(item) for item in value)
    if isinstance(value, bool) or value is None or isinstance(value, (str, int)):
        return True
    if isinstance(value, float):
        return math.isfinite(value)
    return False


@dataclass(frozen=True)
class StepMetrics:
    loss: float
    gradient_norm_before_clip: float
    step: int


class ScratchPresenceTrainer:
    """Independent CPU parameter/Adam owner for one offline binary arm."""

    def __init__(self, config: Mapping[str, object], parameters: Mapping[str, np.ndarray],
                 initialization_sha256: str | None = None):
        self.config = validate_scratch_presence_config(dict(config))
        _validate_numpy_parameters(self.config, parameters)
        self.model_id = scratch_model_id(self.config)
        self._arrays = {name: value.copy() for name, value in parameters.items()}
        computed_initialization = _fingerprint(self._arrays)
        canonical_initialization = _fingerprint(_encoder_initialization(self.config["profile"]))
        if computed_initialization != canonical_initialization:
            raise ValueError("Training tensors do not match the fixed random initialization.")
        if initialization_sha256 is not None and initialization_sha256 != canonical_initialization:
            raise ValueError("Initialization commitment does not match the fixed random initialization.")
        self.initialization_sha256 = canonical_initialization
        trainable = set(scratch_presence_trainable_names(self.config))
        self._parameters = {
            name: torch.nn.Parameter(torch.tensor(value.copy(), dtype=torch.float32, device="cpu"),
                                     requires_grad=name in trainable)
            for name, value in self._arrays.items()
        }
        self._trainable = [self._parameters[name] for name in sorted(trainable)]
        self._optimizer = torch.optim.Adam(
            self._trainable, lr=LEARNING_RATE, weight_decay=WEIGHT_DECAY
        )
        self._step_count = 0
        self._encoder_config = EncoderConfig.from_mapping(self.config)

    @property
    def parameters(self) -> Mapping[str, torch.nn.Parameter]:
        """Read-only mapping to owned tensors for focused mechanics inspection."""
        return MappingProxyType(self._parameters)

    @property
    def successful_steps(self) -> int:
        return self._step_count

    def optimizer_state(self) -> dict:
        return copy.deepcopy(self._optimizer.state_dict())

    def tensor_batch(self, texts: Sequence[str]) -> tuple[torch.Tensor, torch.Tensor]:
        if (isinstance(texts, (str, bytes)) or not isinstance(texts, (list, tuple))
                or not 1 <= len(texts) <= 16 or any(type(text) is not str for text in texts)):
            raise ValueError("Training batch requires one to sixteen explicit strings.")
        rows = [token_ids(normalize_text(text), self._encoder_config).tolist() for text in texts]
        width = max(len(row) for row in rows)
        ids = torch.zeros((len(rows), width), dtype=torch.long, device="cpu")
        mask = torch.zeros((len(rows), width), dtype=torch.bool, device="cpu")
        for index, row in enumerate(rows):
            ids[index, :len(row)] = torch.tensor(row, dtype=torch.long)
            mask[index, :len(row)] = True
        return ids, mask

    def _validate_batch(self, ids: torch.Tensor, mask: torch.Tensor) -> None:
        if (not isinstance(ids, torch.Tensor) or not isinstance(mask, torch.Tensor)
                or ids.device.type != "cpu" or mask.device.type != "cpu"
                or ids.dtype != torch.long or mask.dtype != torch.bool
                or ids.ndim != 2 or mask.shape != ids.shape
                or not 1 <= ids.shape[0] <= 16
                or not 1 <= ids.shape[1] <= self.config["max_tokens"]):
            raise ValueError("Token batch dimensions, dtype or device are invalid.")
        if (not bool(mask[:, 0].all()) or bool((ids[:, 0] != 0).any())
                or bool(((~mask[:, :-1]) & mask[:, 1:]).any())
                or bool((ids[~mask] != 0).any())
                or bool((ids[:, 1:][mask[:, 1:]] == 0).any())
                or bool((ids < 0).any()) or bool((ids >= self.config["vocab_size"]).any())):
            raise ValueError("Token batch violates the first-token or padding contract.")

    def logits(self, ids: torch.Tensor, mask: torch.Tensor) -> torch.Tensor:
        self._validate_batch(ids, mask)
        p = self._parameters
        if any(not bool(torch.isfinite(value).all()) for value in p.values()):
            raise ValueError("Training parameters must be finite.")
        batch, width = ids.shape
        hidden_size = self.config["hidden_size"]
        heads = self.config["num_attention_heads"]
        head_size = hidden_size // heads
        hidden = p["token_embedding"][ids] + p["position_embedding"][:width]
        for layer in range(self.config["num_layers"]):
            prefix = "" if self.config["num_layers"] == 1 else f"layers.{layer}."

            def split(value: torch.Tensor) -> torch.Tensor:
                return value.reshape(batch, width, heads, head_size).transpose(1, 2)

            query = split(hidden @ p[prefix + "attention.query.weight"])
            key = split(hidden @ p[prefix + "attention.key.weight"])
            value = split(hidden @ p[prefix + "attention.value.weight"])
            scores = (query @ key.transpose(2, 3)) / math.sqrt(head_size)
            scores = scores.masked_fill(~mask[:, None, None, :], float("-inf"))
            attended = (torch.softmax(scores, dim=-1) @ value).transpose(1, 2).reshape(hidden.shape)
            attended = attended @ p[prefix + "attention.output.weight"] + p[prefix + "attention.output.bias"]
            hidden = F.layer_norm(hidden + attended, (hidden_size,), eps=1e-5)
            intermediate = F.gelu(
                hidden @ p[prefix + "ffn.input.weight"] + p[prefix + "ffn.input.bias"],
                approximate="tanh",
            )
            hidden = F.layer_norm(
                hidden + intermediate @ p[prefix + "ffn.output.weight"] + p[prefix + "ffn.output.bias"],
                (hidden_size,), eps=1e-5,
            )
        real = mask.unsqueeze(-1)
        pooled = hidden[:, 0] * 0.5 + (hidden * real).sum(1) / real.sum(1).clamp_min(1) * 0.5
        return (pooled @ p["head.presence.weight"] + p["head.presence.bias"]).reshape(-1)

    def loss(self, ids: torch.Tensor, mask: torch.Tensor, targets: Sequence[bool]) -> torch.Tensor:
        self._validate_batch(ids, mask)
        if (not isinstance(targets, (list, tuple)) or len(targets) != ids.shape[0]
                or any(type(target) is not bool for target in targets)):
            raise ValueError("Binary training requires one explicit bool target per row.")
        logits = self.logits(ids, mask)
        labels = torch.tensor(targets, dtype=torch.float32, device="cpu")
        result = F.binary_cross_entropy_with_logits(logits, labels, reduction="mean")
        if not bool(torch.isfinite(result)):
            raise ValueError("Binary training loss must be finite.")
        return result

    def gradients(self, texts: Sequence[str], targets: Sequence[bool]) -> tuple[float, Mapping[str, torch.Tensor]]:
        ids, mask = self.tensor_batch(texts)
        self._optimizer.zero_grad(set_to_none=True)
        loss = self.loss(ids, mask, targets)
        loss.backward()
        gradients = {}
        for name, parameter in self._parameters.items():
            if parameter.requires_grad:
                if parameter.grad is None or not bool(torch.isfinite(parameter.grad).all()):
                    raise ValueError("Trainable gradients must exist and be finite.")
                gradients[name] = parameter.grad.detach().clone()
        return float(loss.detach()), MappingProxyType(gradients)

    def _parameters_finite(self) -> bool:
        return all(bool(torch.isfinite(parameter).all()) for parameter in self._parameters.values())

    def _state_finite(self) -> bool:
        return _tree_is_finite(self._optimizer.state_dict())

    def step(self, texts: Sequence[str], targets: Sequence[bool]) -> StepMetrics:
        if not self._state_finite():
            raise ValueError("Existing optimizer state must be finite before a step.")
        loss, _ = self.gradients(texts, targets)
        norm = torch.nn.utils.clip_grad_norm_(self._trainable, MAX_GRAD_NORM, error_if_nonfinite=True)
        if not bool(torch.isfinite(norm)):
            raise ValueError("Global gradient norm must be finite.")
        before = {name: parameter.detach().clone() for name, parameter in self._parameters.items()}
        state_before = self.optimizer_state()
        try:
            self._optimizer.step()
            if not self._parameters_finite():
                raise ValueError("Optimizer produced non-finite parameters.")
            if not self._state_finite():
                raise ValueError("Optimizer produced non-finite state.")
        except Exception:
            with torch.no_grad():
                for name, value in before.items():
                    self._parameters[name].copy_(value)
            self._optimizer.load_state_dict(state_before)
            raise
        self._step_count += 1
        return StepMetrics(loss, float(norm), self._step_count)

    def export_parameters(self) -> dict[str, np.ndarray]:
        if not self._parameters_finite() or not self._state_finite():
            raise ValueError("Only finite parameter and optimizer state can be exported.")
        return {
            name: parameter.detach().cpu().numpy().astype(np.float32, copy=True)
            for name, parameter in self._parameters.items()
        }

    def numpy_encoder(self) -> NumpyTransformerEncoder:
        exported = self.export_parameters()
        return NumpyTransformerEncoder(
            self._encoder_config,
            {name: value for name, value in exported.items() if not name.startswith("head.")},
        )

    def build_artifact(self, *, source_revision: str, study_plan_sha256: str,
                       prepared_manifest_sha256: str, trainer_contract_sha256: str,
                       checkpoint_epoch: int, generated_at_unix: int) -> dict[str, object]:
        """Return an independently validated artifact mapping; perform no file IO."""
        if type(checkpoint_epoch) is not int or not 1 <= checkpoint_epoch <= 10:
            raise ValueError("Checkpoint epoch must be an integer from one through ten.")
        if self._step_count <= 0 or self._step_count > 2500:
            raise ValueError("A checkpoint requires a bounded positive successful-step count.")
        if type(generated_at_unix) is not int or not 0 < generated_at_unix <= 2**63 - 1:
            raise ValueError("Artifact timestamp must be a positive int64.")
        arrays = self.export_parameters()
        shapes = scratch_presence_tensor_shapes(self.config)
        trainable_names = set(scratch_presence_trainable_names(self.config))
        parameters = {
            name: {
                "shape": list(shapes[name]),
                "values": arrays[name].ravel().tolist(),
                "trainable": name in trainable_names,
            }
            for name in sorted(arrays)
        }
        payload: dict[str, object] = {
            "schema_version": 1,
            "model_id": self.model_id,
            "version": f"v1.0.0+epoch.{checkpoint_epoch}",
            "generated_at_unix": generated_at_unix,
            "architecture": SCRATCH_PRESENCE_ARCHITECTURE,
            "config": copy.deepcopy(self.config),
            "parameters": parameters,
            "metadata": {
                "training_route": "offline_release_fit_v1",
                "source_revision": source_revision,
                "study_plan_sha256": study_plan_sha256,
                "prepared_manifest_sha256": prepared_manifest_sha256,
                "initialization_sha256": self.initialization_sha256,
                "trainer_contract_sha256": trainer_contract_sha256,
                "checkpoint_epoch": str(checkpoint_epoch),
                "training_steps": str(self._step_count),
                "training_seed": str(TRAINING_SEED),
            },
        }
        payload["checksum"] = artifact_checksum(payload)
        validate_scratch_artifact(payload)
        validate_artifact(payload)
        return payload


__all__ = [
    "LEARNING_RATE", "MAX_GRAD_NORM", "TRAINING_SEED", "WEIGHT_DECAY",
    "ScratchPresenceTrainer", "StepMetrics", "create_paired_trainers",
    "presence_config",
]
