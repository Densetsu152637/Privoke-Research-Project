"""Regenerate the deterministic, Git-storable PriVoke model family."""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from pathlib import Path

import numpy as np


REPO_ROOT = Path(__file__).resolve().parents[1]
SHARED_ROOT = REPO_ROOT / "shared/python"
if str(SHARED_ROOT) not in sys.path:
    sys.path.insert(0, str(SHARED_ROOT))

from privoke_model.artifact import ARCHITECTURE_NAME, artifact_checksum, write_artifact_atomic
from privoke_model.network import ModelConfig, TinyTransformerModel


MODEL_DIRECTORY = Path(__file__).parent
GENERATED_AT_UNIX = 1788081234
SENSITIVITIES = ("S0", "S1", "S2", "S3")
VISIBILITIES = ("P0", "P1", "P2", "P3", "P4", "PU")
CATEGORIES = (
    "HEALTH",
    "POLITICS",
    "RELIGION",
    "CRIMINAL",
    "FINANCIAL",
    "SEXUAL",
    "CHILD",
    "LOCATION",
    "IDENTITY",
    "THIRD_PARTY",
)
TRAINABLE = {
    "head.sensitivity.weight",
    "head.sensitivity.bias",
    "head.visibility.weight",
    "head.visibility.bias",
    "head.category.weight",
    "head.category.bias",
}


@dataclass(frozen=True)
class ModelProfile:
    name: str
    model_id: str
    vocab_size: int
    hidden_size: int
    intermediate_size: int
    max_tokens: int
    num_layers: int
    num_attention_heads: int
    seed: int
    training_epochs: int

    @property
    def output_path(self) -> Path:
        return MODEL_DIRECTORY / f"{self.model_id}.json"


MODEL_PROFILES = (
    # Keep the original artifact ID available to older clients.
    ModelProfile(
        "Baseline", "privoke-baseline", 512, 24, 48, 64, 1, 1, 20260830, 220
    ),
    ModelProfile(
        "Efficient", "privoke-efficient", 512, 24, 48, 64, 1, 2, 20260901, 220
    ),
    ModelProfile(
        "Balanced", "privoke-balanced", 512, 32, 64, 96, 2, 4, 20260902, 360
    ),
    ModelProfile(
        "Quality", "privoke-quality", 768, 32, 64, 128, 3, 4, 20260903, 520
    ),
)


def main() -> None:
    for profile in MODEL_PROFILES:
        write_profile(profile)


def write_profile(profile: ModelProfile) -> None:
    rng = np.random.default_rng(profile.seed)
    config = ModelConfig(
        vocab_size=profile.vocab_size,
        hidden_size=profile.hidden_size,
        intermediate_size=profile.intermediate_size,
        max_tokens=profile.max_tokens,
        sensitivity_labels=SENSITIVITIES,
        visibility_labels=VISIBILITIES,
        category_labels=CATEGORIES,
        category_threshold=0.38,
        num_layers=profile.num_layers,
        num_attention_heads=profile.num_attention_heads,
    )
    arrays = initial_parameters(config, rng)
    bootstrap_heads(config, arrays, rng, profile.training_epochs)
    payload = {
        "schema_version": 1,
        "model_id": profile.model_id,
        "version": "v0.3.0",
        "generated_at_unix": GENERATED_AT_UNIX,
        "architecture": ARCHITECTURE_NAME,
        "config": {
            "vocab_size": config.vocab_size,
            "hidden_size": config.hidden_size,
            "intermediate_size": config.intermediate_size,
            "max_tokens": config.max_tokens,
            "sensitivity_labels": list(config.sensitivity_labels),
            "visibility_labels": list(config.visibility_labels),
            "category_labels": list(config.category_labels),
            "category_threshold": config.category_threshold,
            "num_layers": config.num_layers,
            "num_attention_heads": config.num_attention_heads,
        },
        "parameters": {
            name: {
                "shape": list(array.shape),
                "trainable": name in TRAINABLE,
                "values": [round(float(value), 8) for value in array.ravel()],
            }
            for name, array in sorted(arrays.items())
        },
        "metadata": {
            "quality": profile.name.lower(),
            "release_version": "v0.3.0",
            "training_revision": "0",
            "training_strategy": "deterministic_bootstrap_head_finetune",
            "training_epochs": str(profile.training_epochs),
            "weight_format": "json-float32",
        },
    }
    payload["checksum"] = artifact_checksum(payload)
    write_artifact_atomic(profile.output_path, payload)
    print(f"wrote {profile.output_path} ({profile.output_path.stat().st_size} bytes)")


def initial_parameters(config: ModelConfig, rng: np.random.Generator) -> dict[str, np.ndarray]:
    hidden = config.hidden_size
    intermediate = config.intermediate_size

    def weight(shape: tuple[int, ...], scale: float = 0.08) -> np.ndarray:
        return rng.normal(0.0, scale, shape).astype(np.float32)

    parameters = {
        "token_embedding": weight((config.vocab_size, hidden), 0.12),
        "position_embedding": weight((config.max_tokens, hidden), 0.03),
        "head.sensitivity.weight": np.zeros((hidden, len(SENSITIVITIES)), dtype=np.float32),
        "head.sensitivity.bias": np.asarray([0.6, 0.0, 0.0, -0.1], dtype=np.float32),
        "head.visibility.weight": np.zeros((hidden, len(VISIBILITIES)), dtype=np.float32),
        "head.visibility.bias": np.asarray([0.0, 0.0, 0.0, 0.0, 0.0, 0.8], dtype=np.float32),
        "head.category.weight": np.zeros((hidden, len(CATEGORIES)), dtype=np.float32),
        "head.category.bias": np.full(len(CATEGORIES), -1.5, dtype=np.float32),
    }
    for layer_index in range(config.num_layers):
        prefix = "" if config.num_layers == 1 else f"layers.{layer_index}."
        parameters.update(
            {
                f"{prefix}attention.query.weight": weight((hidden, hidden)),
                f"{prefix}attention.key.weight": weight((hidden, hidden)),
                f"{prefix}attention.value.weight": weight((hidden, hidden)),
                f"{prefix}attention.output.weight": weight((hidden, hidden)),
                f"{prefix}attention.output.bias": np.zeros(hidden, dtype=np.float32),
                f"{prefix}ffn.input.weight": weight((hidden, intermediate)),
                f"{prefix}ffn.input.bias": np.zeros(intermediate, dtype=np.float32),
                f"{prefix}ffn.output.weight": weight((intermediate, hidden)),
                f"{prefix}ffn.output.bias": np.zeros(hidden, dtype=np.float32),
            }
        )
    return parameters


def bootstrap_heads(
    config: ModelConfig,
    arrays: dict[str, np.ndarray],
    rng: np.random.Generator,
    epochs: int,
) -> None:
    samples = training_samples()
    learning_rate = 0.025
    model = TinyTransformerModel(
        config,
        {name: array.ravel() for name, array in arrays.items()},
        {name: array.shape for name, array in arrays.items()},
    )
    for _ in range(epochs):
        for index in rng.permutation(len(samples)):
            text, sensitivity, visibility, categories = samples[int(index)]
            deltas = model.classification_head_deltas(
                text,
                sensitivity=sensitivity,
                visibility=visibility,
                categories=categories,
            )
            for name, values in deltas.items():
                arrays[name] += learning_rate * np.asarray(values, dtype=np.float32).reshape(arrays[name].shape)


def training_samples() -> list[tuple[str, str, str, tuple[str, ...]]]:
    category_phrases = {
        "HEALTH": ("my diagnosis is cancer", "my therapist prescribed medication", "I am pregnant and have anxiety"),
        "POLITICS": ("I voted for the progressive party", "my political affiliation is conservative", "I am a union activist"),
        "RELIGION": ("I worship at my local mosque", "I converted to Buddhism", "my Jewish religious community"),
        "CRIMINAL": ("I have a criminal record", "my pending court case", "I was arrested and charged"),
        "FINANCIAL": ("my bank account and mortgage debt", "my salary and credit score", "I filed a tax return"),
        "SEXUAL": ("my sexual orientation is bisexual", "I am coming out as gay", "my intimate sexual history"),
        "CHILD": ("my minor child attends daycare", "my daughter's custody schedule", "my teenager's school pickup"),
        "LOCATION": ("this is where I live near my apartment", "my private home address", "my usual commute route"),
        "IDENTITY": ("I work at a small company as the only manager", "my username identifies my profile", "my employer and job title"),
        "THIRD_PARTY": ("my patient's diagnosis", "my coworker's salary", "my friend's private address"),
    }
    sensitivity = {
        "HEALTH": "S3",
        "POLITICS": "S3",
        "RELIGION": "S3",
        "CRIMINAL": "S3",
        "FINANCIAL": "S2",
        "SEXUAL": "S3",
        "CHILD": "S3",
        "LOCATION": "S2",
        "IDENTITY": "S2",
        "THIRD_PARTY": "S2",
    }
    samples = [
        (phrase, sensitivity[category], "PU", (category,))
        for category, phrases in category_phrases.items()
        for phrase in phrases
    ]
    samples.extend(
        [
            ("my health diagnosis and bank account are private", "S3", "P4", ("HEALTH", "FINANCIAL")),
            ("my child and I live at this private address", "S3", "P4", ("CHILD", "LOCATION")),
            ("my coworker's political affiliation", "S3", "P3", ("THIRD_PARTY", "POLITICS")),
            ("this was posted publicly for everyone", "S0", "P0", ()),
            ("discussion in a public community forum", "S0", "P1", ()),
            ("the page is restricted behind login", "S0", "P2", ()),
            ("I sent this in a private group chat", "S0", "P3", ()),
            ("this is a private diary for my eyes only", "S0", "P4", ()),
            ("explain privacy using imaginary placeholders", "S0", "PU", ()),
            ("write a friendly email about tomorrow's meeting", "S0", "PU", ()),
            ("summarise this public product documentation", "S0", "P0", ()),
            ("what is the weather forecast", "S0", "PU", ()),
            ("help me format a generic travel checklist", "S0", "PU", ()),
        ]
    )
    return samples


if __name__ == "__main__":
    main()
