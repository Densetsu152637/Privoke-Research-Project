"""Closed, offline-head-only contract for an experimental frozen MiniLM encoder."""
from __future__ import annotations

import copy
import json
import math
import re
from collections.abc import Mapping

from .artifact import ModelArtifactError, float32
from privoke_contracts.classification import Category, Sensitivity, Visibility

PRETRAINED_CONTEXT_ARCHITECTURE = "privoke_pretrained_context_v1"
PRETRAINED_CONTEXT_MODEL_ID = "privoke-pretrained-context-minilm"
BACKBONE_MODEL_ID = "sentence-transformers/all-MiniLM-L6-v2"
BACKBONE_REVISION = "1110a243fdf4706b3f48f1d95db1a4f5529b4d41"
BACKBONE_SHA256 = "6fd5d72fe4589f189f8ebc006442dbb529bb7ce38f8082112682524616046452"
TOKENIZER_SHA256 = "be50c3628f2bf5bb5e3a7f17b1f74611b2561a3a27eeab05e5aa30f411572037"
HIDDEN_SIZE = 384
MAX_TOKENS = 256
SUPPORTED_MAX_TOKENS = (256, 512)
CONFIG_CONSTANTS = {
    "task": "contextual_privacy", "backbone_model_id": BACKBONE_MODEL_ID,
    "backbone_revision": BACKBONE_REVISION, "backbone_sha256": BACKBONE_SHA256,
    "tokenizer_sha256": TOKENIZER_SHA256, "hidden_size": HIDDEN_SIZE,
    "max_tokens": MAX_TOKENS, "pooling": "masked_mean_l2_v1",
    "normalization": "detector_normalize_text_v1",
    "category_semantics": "asserted_personal_disclosure_v1",
    "arithmetic": "float32_onnx_numpy_heads_v1",
}
LABELS = {"sensitivity": tuple(Sensitivity.__members__),
          "visibility": tuple(Visibility.__members__), "category": tuple(Category.__members__)}
CONFIG_KEYS = frozenset((*CONFIG_CONSTANTS, *(task + "_labels" for task in LABELS), "category_threshold"))
ARTIFACT_KEYS = frozenset(("schema_version", "model_id", "version", "generated_at_unix",
                           "architecture", "config", "parameters", "metadata", "checksum"))
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
VERSION_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+_-]{0,127}$")


def unique_json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ModelArtifactError("Pretrained contextual JSON contains duplicate keys.")
        result[key] = value
    return result


def validate_max_tokens(max_tokens: int) -> int:
    if type(max_tokens) is not int or max_tokens not in SUPPORTED_MAX_TOKENS:
        raise ModelArtifactError("Pretrained contextual max_tokens must be exactly 256 or 512.")
    return max_tokens


def default_config(category_threshold: float = 0.5, *, max_tokens: int = MAX_TOKENS) -> dict:
    return {**CONFIG_CONSTANTS, **{task + "_labels": list(labels) for task, labels in LABELS.items()},
            "category_threshold": category_threshold, "max_tokens": validate_max_tokens(max_tokens)}


def validate_pretrained_config(config, model_id=PRETRAINED_CONTEXT_MODEL_ID) -> dict:
    if model_id != PRETRAINED_CONTEXT_MODEL_ID or not isinstance(config, dict) or set(config) != CONFIG_KEYS:
        raise ModelArtifactError("Pretrained contextual config/model ID is unsupported.")
    for name, expected in CONFIG_CONSTANTS.items():
        if name == "max_tokens":
            validate_max_tokens(config[name])
            continue
        if type(config[name]) is not type(expected) or config[name] != expected:
            raise ModelArtifactError("Pretrained contextual encoder contract does not match.")
    for task, labels in LABELS.items():
        if type(config[task + "_labels"]) is not list or config[task + "_labels"] != list(labels):
            raise ModelArtifactError("Pretrained contextual label order does not match.")
    threshold = config["category_threshold"]
    if type(threshold) not in (int, float) or not math.isfinite(threshold) or not 0 < threshold < 1:
        raise ModelArtifactError("Pretrained category threshold must be finite and between zero and one.")
    return copy.deepcopy(config)


def head_tensor_shapes() -> dict[str, tuple[int, ...]]:
    return {f"head.{task}.{part}": ((HIDDEN_SIZE, len(labels)) if part == "weight" else (len(labels),))
            for task, labels in LABELS.items() for part in ("weight", "bias")}


def validate_pretrained_parameters(parameters, shapes, trainable) -> None:
    expected = head_tensor_shapes()
    if set(parameters) != set(expected) or set(shapes) != set(expected) or set(trainable) != set(expected):
        raise ModelArtifactError("Pretrained contextual model requires exactly six head tensors.")
    for name, shape in expected.items():
        if tuple(shapes[name]) != shape or any(type(size) is not int for size in shapes[name]):
            raise ModelArtifactError("Pretrained contextual head shape does not match.")
        if trainable[name] is not False:
            raise ModelArtifactError("Pretrained contextual heads permit offline fitting only.")
        values = parameters[name]
        if len(values) != math.prod(shape):
            raise ModelArtifactError("Pretrained contextual head length does not match.")
        for value in values:
            if type(value) not in (int, float):
                raise ModelArtifactError("Pretrained contextual head values must be numeric.")
            float32(value)


def validate_pretrained_release_identity(version, generated_at_unix) -> None:
    if not isinstance(version, str) or not VERSION_PATTERN.fullmatch(version):
        raise ModelArtifactError("Pretrained contextual version is invalid.")
    if type(generated_at_unix) is not int or not 0 < generated_at_unix <= 2**63 - 1:
        raise ModelArtifactError("Pretrained contextual timestamp is invalid.")


def validate_pretrained_artifact(payload) -> None:
    if set(payload) != ARTIFACT_KEYS or payload["architecture"] != PRETRAINED_CONTEXT_ARCHITECTURE:
        raise ModelArtifactError("Pretrained contextual artifact has unsupported fields/architecture.")
    validate_pretrained_config(payload["config"], payload["model_id"])
    if type(payload["schema_version"]) is not int or payload["schema_version"] != 1:
        raise ModelArtifactError("Pretrained contextual schema is unsupported.")
    validate_pretrained_release_identity(payload["version"], payload["generated_at_unix"])
    metadata = payload["metadata"]
    if not isinstance(metadata, dict) or any(type(k) is not str or type(v) is not str for k, v in metadata.items()):
        raise ModelArtifactError("Pretrained contextual metadata must contain strings.")
    parameters = payload["parameters"]
    if not isinstance(parameters, dict) or any(not isinstance(t, dict) or set(t) != {"shape", "values", "trainable"} for t in parameters.values()):
        raise ModelArtifactError("Pretrained contextual tensor fields do not match.")
    if any(type(t["shape"]) is not list or type(t["values"]) is not list for t in parameters.values()):
        raise ModelArtifactError("Pretrained contextual shape and values must be arrays.")
    try:
        json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8", errors="strict")
    except (UnicodeError, ValueError, TypeError) as exc:
        raise ModelArtifactError("Pretrained contextual artifact contains invalid JSON values.") from exc
    validate_pretrained_parameters({n: t["values"] for n, t in parameters.items()},
                                  {n: t["shape"] for n, t in parameters.items()},
                                  {n: t["trainable"] for n, t in parameters.items()})


def validate_pretrained_stream(model_id, metadata) -> dict:
    if model_id != PRETRAINED_CONTEXT_MODEL_ID or metadata.get("architecture") != PRETRAINED_CONTEXT_ARCHITECTURE:
        raise ModelArtifactError("Pretrained contextual inference requires its exact explicit model ID.")
    if metadata.get("trainable_parameters") != "":
        raise ModelArtifactError("Pretrained contextual online updates are unsupported.")
    if not isinstance(metadata.get("artifact_checksum"), str) or not SHA256_PATTERN.fullmatch(metadata["artifact_checksum"]):
        raise ModelArtifactError("Pretrained contextual stream requires an artifact checksum.")
    try:
        config = json.loads(metadata["model_config"], object_pairs_hook=unique_json_object)
    except (KeyError, TypeError, json.JSONDecodeError) as exc:
        raise ModelArtifactError("Pretrained contextual stream config is invalid.") from exc
    return validate_pretrained_config(config, model_id)


def build_head_artifact(parameters: Mapping, *, version: str, generated_at_unix: int,
                        metadata: Mapping[str, str], category_threshold: float = 0.5,
                        max_tokens: int = MAX_TOKENS) -> dict:
    """Serialize six offline-fitted NumPy-compatible flat head arrays as float32."""
    from .artifact import artifact_checksum, validate_artifact
    shapes = head_tensor_shapes()
    if set(parameters) != set(shapes):
        raise ModelArtifactError("Offline fitter must supply exactly the six contextual heads.")
    artifact = {"schema_version": 1, "model_id": PRETRAINED_CONTEXT_MODEL_ID,
                "version": version, "generated_at_unix": generated_at_unix,
                "architecture": PRETRAINED_CONTEXT_ARCHITECTURE,
                "config": default_config(category_threshold, max_tokens=max_tokens), "metadata": dict(metadata),
                "parameters": {name: {"shape": list(shapes[name]), "trainable": False,
                                      "values": [float32(value) for value in parameters[name]]}
                               for name in shapes}}
    artifact["checksum"] = artifact_checksum(artifact)
    validate_artifact(artifact)
    return artifact
