"""Regenerate the deterministic, Git-storable PriVoke baseline artifact."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np


REPO_ROOT = Path(__file__).resolve().parents[1]
SHARED_ROOT = REPO_ROOT / "shared/python"
if str(SHARED_ROOT) not in sys.path:
    sys.path.insert(0, str(SHARED_ROOT))

from privoke_model.artifact import ARCHITECTURE_NAME, artifact_checksum, write_artifact_atomic
from privoke_model.network import ModelConfig, TinyTransformerModel


OUTPUT_PATH = Path(__file__).with_name("privoke-baseline.json")
BASELINE_GENERATED_AT_UNIX = 1788081234
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


def main() -> None:
    rng = np.random.default_rng(20260830)
    config = ModelConfig(
        vocab_size=512,
        hidden_size=24,
        intermediate_size=48,
        max_tokens=64,
        sensitivity_labels=SENSITIVITIES,
        visibility_labels=VISIBILITIES,
        category_labels=CATEGORIES,
        category_threshold=0.38,
    )
    arrays = initial_parameters(config, rng)
    bootstrap_heads(config, arrays, rng)
    payload = {
        "schema_version": 1,
        "model_id": "privoke-baseline",
        "version": "v0.2.0",
        "generated_at_unix": BASELINE_GENERATED_AT_UNIX,
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
            "release_version": "v0.2.0",
            "training_revision": "0",
            "training_strategy": "deterministic_bootstrap_head_finetune",
            "weight_format": "json-float32",
        },
    }
    payload["checksum"] = artifact_checksum(payload)
    write_artifact_atomic(OUTPUT_PATH, payload)
    print(f"wrote {OUTPUT_PATH} ({OUTPUT_PATH.stat().st_size} bytes)")


def initial_parameters(config: ModelConfig, rng: np.random.Generator) -> dict[str, np.ndarray]:
    hidden = config.hidden_size
    intermediate = config.intermediate_size

    def weight(shape: tuple[int, ...], scale: float = 0.08) -> np.ndarray:
        return rng.normal(0.0, scale, shape).astype(np.float32)

    return {
        "token_embedding": weight((config.vocab_size, hidden), 0.12),
        "position_embedding": weight((config.max_tokens, hidden), 0.03),
        "attention.query.weight": weight((hidden, hidden)),
        "attention.key.weight": weight((hidden, hidden)),
        "attention.value.weight": weight((hidden, hidden)),
        "attention.output.weight": weight((hidden, hidden)),
        "attention.output.bias": np.zeros(hidden, dtype=np.float32),
        "ffn.input.weight": weight((hidden, intermediate)),
        "ffn.input.bias": np.zeros(intermediate, dtype=np.float32),
        "ffn.output.weight": weight((intermediate, hidden)),
        "ffn.output.bias": np.zeros(hidden, dtype=np.float32),
        "head.sensitivity.weight": np.zeros((hidden, len(SENSITIVITIES)), dtype=np.float32),
        "head.sensitivity.bias": np.asarray([0.6, 0.0, 0.0, -0.1], dtype=np.float32),
        "head.visibility.weight": np.zeros((hidden, len(VISIBILITIES)), dtype=np.float32),
        "head.visibility.bias": np.asarray([0.0, 0.0, 0.0, 0.0, 0.0, 0.8], dtype=np.float32),
        "head.category.weight": np.zeros((hidden, len(CATEGORIES)), dtype=np.float32),
        "head.category.bias": np.full(len(CATEGORIES), -1.5, dtype=np.float32),
    }


def bootstrap_heads(
    config: ModelConfig,
    arrays: dict[str, np.ndarray],
    rng: np.random.Generator,
) -> None:
    samples = training_samples()
    learning_rate = 0.025
    model = TinyTransformerModel(
        config,
        {name: array.ravel() for name, array in arrays.items()},
        {name: array.shape for name, array in arrays.items()},
    )
    for _ in range(220):
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
