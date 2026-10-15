"""Closed offline-only scratch transformer annotation-presence contracts."""
from __future__ import annotations

import copy
import json
import math
import re
from collections.abc import Mapping

from .artifact import ModelArtifactError, MAX_ARTIFACT_BYTES, float32

SCRATCH_PRESENCE_ARCHITECTURE = "privoke_scratch_presence_transformer_v1"
SCRATCH_PRESENCE_TASK = "annotation_presence"
SCRATCH_CONFIG_MAX_BYTES = 8192
SCRATCH_PROFILES = {
    "efficient": (512, 24, 48, 64, 1, 2),
    "balanced": (512, 32, 64, 96, 2, 4),
    "quality": (768, 32, 64, 128, 3, 4),
}
SCRATCH_MODES = {"head-only": "head_only", "full-encoder": "end_to_end"}
SCRATCH_PRESENCE_MODEL_IDS = frozenset(
    f"privoke-scratch-presence-{profile}-{suffix}"
    for profile in SCRATCH_PROFILES for suffix in SCRATCH_MODES
)
DIMENSION_KEYS = ("vocab_size", "hidden_size", "intermediate_size", "max_tokens", "num_layers", "num_attention_heads")
CONSTANT_CONFIG = {
    "task": SCRATCH_PRESENCE_TASK,
    "normalization": "detector_normalize_text_v1",
    "tokenizer": "legacy_sha256_bucket_tokens_v1",
    "pooling": "half_first_half_real_mean_v1",
    "arithmetic": "float32_numpy_encoder_clipped_sigmoid_v1",
}
CONFIG_KEYS = frozenset((*DIMENSION_KEYS, *CONSTANT_CONFIG, "profile", "training_mode", "threshold"))
ARTIFACT_KEYS = frozenset(("schema_version", "model_id", "version", "generated_at_unix", "architecture", "config", "parameters", "metadata", "checksum"))
HASH_METADATA = ("study_plan_sha256", "prepared_manifest_sha256", "initialization_sha256", "trainer_contract_sha256")
METADATA_KEYS = frozenset((*HASH_METADATA, "training_route", "source_revision", "checkpoint_epoch", "training_steps", "training_seed"))


def _fail(message: str) -> None:
    raise ModelArtifactError(message)


def _closed(value, keys, description):
    if not isinstance(value, dict) or set(value) != set(keys):
        _fail(f"Scratch {description} has missing or unknown fields.")


def validate_scratch_unicode(value) -> None:
    """Reject invalid Unicode anywhere before canonical UTF-8 serialization."""
    if isinstance(value, str):
        try:
            value.encode("utf-8", errors="strict")
        except UnicodeError:
            _fail("Scratch artifact contains invalid Unicode.")
    elif isinstance(value, Mapping):
        for key, item in value.items():
            validate_scratch_unicode(key)
            validate_scratch_unicode(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            validate_scratch_unicode(item)


def validate_scratch_presence_config(config: object, model_id: str | None = None) -> dict:
    """Validate and return an independent copy of the exact bounded config."""
    _closed(config, CONFIG_KEYS, "config")
    validate_scratch_unicode(config)
    profile = config["profile"]
    if not isinstance(profile, str) or profile not in SCRATCH_PROFILES:
        _fail("Scratch profile is unsupported.")
    if config["training_mode"] not in SCRATCH_MODES.values():
        _fail("Scratch training mode is unsupported.")
    for key, expected in zip(DIMENSION_KEYS, SCRATCH_PROFILES[profile]):
        if type(config[key]) is not int or config[key] != expected:
            _fail("Scratch profile dimensions do not match.")
    for key, expected in CONSTANT_CONFIG.items():
        if config[key] != expected:
            _fail("Scratch config contract is unsupported.")
    if type(config["threshold"]) not in (int, float) or config["threshold"] != 0.5:
        _fail("Scratch stored threshold must be 0.5.")
    if len(json.dumps(config, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")) > SCRATCH_CONFIG_MAX_BYTES:
        _fail("Scratch config exceeds 8 KiB.")
    if model_id is not None and model_id != scratch_model_id(config):
        _fail("Scratch ID does not match profile and mode.")
    return copy.deepcopy(config)


def scratch_model_id(config: Mapping) -> str:
    suffix = next(key for key, mode in SCRATCH_MODES.items() if mode == config["training_mode"])
    return f"privoke-scratch-presence-{config['profile']}-{suffix}"


def scratch_presence_tensor_shapes(config: Mapping) -> dict[str, tuple[int, ...]]:
    """Return the complete row-major inventory for a validated config."""
    config = validate_scratch_presence_config(dict(config))
    v, h, i, t, layers, _ = SCRATCH_PROFILES[config["profile"]]
    result = {"token_embedding": (v, h), "position_embedding": (t, h),
              "head.presence.weight": (h, 1), "head.presence.bias": (1,)}
    block = {
        "attention.query.weight": (h, h), "attention.key.weight": (h, h),
        "attention.value.weight": (h, h), "attention.output.weight": (h, h),
        "attention.output.bias": (h,), "ffn.input.weight": (h, i),
        "ffn.input.bias": (i,), "ffn.output.weight": (i, h), "ffn.output.bias": (h,),
    }
    for layer in range(layers):
        prefix = "" if layers == 1 else f"layers.{layer}."
        result.update({prefix + name: shape for name, shape in block.items()})
    return result


def validate_scratch_presence_parameters(config, parameters, shapes, trainable) -> None:
    """Validate the full inventory, finite float32 values and explicit offline flags."""
    config = validate_scratch_presence_config(config)
    expected = scratch_presence_tensor_shapes(config)
    for mapping in (parameters, shapes, trainable):
        if not isinstance(mapping, Mapping) or set(mapping) != set(expected):
            _fail("Scratch tensor inventory has missing or unknown tensors.")
    for name, shape in expected.items():
        actual = shapes[name]
        if not isinstance(actual, (list, tuple)) or tuple(actual) != shape or any(type(n) is not int for n in actual):
            _fail("Scratch tensor shape does not match.")
        flag = trainable[name]
        wanted = config["training_mode"] == "end_to_end" or name.startswith("head.presence.")
        if type(flag) is not bool or flag != wanted:
            _fail("Scratch trainable flags do not match its offline mode.")
        values = parameters[name]
        if not isinstance(values, (list, tuple)) or len(values) != math.prod(shape):
            _fail("Scratch tensor values do not match shape.")
        for value in values:
            if type(value) not in (int, float):
                _fail("Scratch tensor requires exact finite float32 values.")
            try:
                valid = math.isfinite(value) and float32(value) == value
            except (ValueError, OverflowError):
                valid = False
            if not valid:
                _fail("Scratch tensor requires exact finite float32 values.")


def validate_scratch_artifact(payload: object) -> None:
    """Validate schema without checking checksum (the common loader owns that)."""
    _closed(payload, ARTIFACT_KEYS, "artifact")
    validate_scratch_unicode(payload)
    if type(payload["schema_version"]) is not int or payload["schema_version"] != 1:
        _fail("Scratch schema must be integer 1.")
    timestamp = payload["generated_at_unix"]
    if type(timestamp) is not int or not 0 < timestamp <= 2**63 - 1:
        _fail("Scratch timestamp must be a positive int64.")
    if payload["architecture"] != SCRATCH_PRESENCE_ARCHITECTURE:
        _fail("Scratch ID requires the scratch architecture.")
    config = validate_scratch_presence_config(payload["config"])
    if payload["model_id"] != scratch_model_id(config):
        _fail("Scratch ID does not match profile and mode.")
    version = payload["version"]
    match = re.fullmatch(r"v1\.0\.0\+epoch\.([1-9]|10)", version) if isinstance(version, str) else None
    if match is None:
        _fail("Scratch checkpoint version is invalid.")
    validate_scratch_presence_metadata(payload["metadata"], version)
    tensors = payload["parameters"]
    if not isinstance(tensors, dict):
        _fail("Scratch parameters must be an object.")
    for tensor in tensors.values():
        _closed(tensor, ("shape", "values", "trainable"), "tensor")
    validate_scratch_presence_parameters(config, {n:t["values"] for n,t in tensors.items()},
                                {n:t["shape"] for n,t in tensors.items()}, {n:t["trainable"] for n,t in tensors.items()})
    if not isinstance(payload["checksum"], str) or not re.fullmatch(r"[0-9a-f]{64}", payload["checksum"]):
        _fail("Scratch checksum must be lowercase SHA256.")
    if len(json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")) > MAX_ARTIFACT_BYTES:
        _fail("Scratch artifact exceeds 8 MiB.")


def scratch_presence_trainable_names(config) -> tuple[str, ...]:
    config = validate_scratch_presence_config(config)
    return tuple(sorted(name for name in scratch_presence_tensor_shapes(config)
                        if config["training_mode"] == "end_to_end" or name.startswith("head.presence.")))


def validate_scratch_presence_metadata(metadata, version: str) -> None:
    """Validate closed artifact provenance and its checkpoint version."""
    match = re.fullmatch(r"v1\.0\.0\+epoch\.([1-9]|10)", version) if isinstance(version, str) else None
    if match is None:
        _fail("Scratch checkpoint version is invalid.")
    _closed(metadata, METADATA_KEYS, "metadata")
    if any(type(value) is not str or not value.isascii() for value in metadata.values()):
        _fail("Scratch metadata must be ASCII strings.")
    if metadata["training_route"] != "offline_release_fit_v1" or metadata["training_seed"] != "12102026":
        _fail("Scratch training provenance is unsupported.")
    if not re.fullmatch(r"[0-9a-f]{40}", metadata["source_revision"]):
        _fail("Scratch source revision is invalid.")
    if any(not re.fullmatch(r"[0-9a-f]{64}", metadata[key]) for key in HASH_METADATA):
        _fail("Scratch provenance digest is invalid.")
    if metadata["checkpoint_epoch"] != match[1]:
        _fail("Scratch epoch does not match version.")
    steps = metadata["training_steps"]
    if not re.fullmatch(r"[1-9][0-9]{0,3}", steps) or int(steps) > 2500:
        _fail("Scratch training steps are invalid.")


def validate_scratch_presence_stream_metadata(model_id: str, version: str, metadata) -> dict:
    """Validate first-chunk declarations before allocation; return copied config."""
    stream_keys = METADATA_KEYS | {"served_by", "consumer_id", "architecture", "model_config",
        "artifact_checksum", "artifact_file_checksum", "trainable_parameters", "task", "profile",
        "training_mode", "text_normalization", "tokenizer", "pooling", "arithmetic"}
    _closed(metadata, stream_keys, "stream metadata")
    validate_scratch_unicode(metadata)
    if any(type(v) is not str or not v.isascii() for v in metadata.values()):
        _fail("Scratch stream metadata must be ASCII strings.")
    if not isinstance(model_id, str) or model_id not in SCRATCH_PRESENCE_MODEL_IDS or metadata["architecture"] != SCRATCH_PRESENCE_ARCHITECTURE:
        _fail("Scratch stream architecture and explicit ID must match.")
    if len(metadata["model_config"].encode("utf-8")) > SCRATCH_CONFIG_MAX_BYTES:
        _fail("Scratch config exceeds 8 KiB.")
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                _fail("Scratch config contains duplicate keys.")
            result[key] = value
        return result
    try:
        config = validate_scratch_presence_config(json.loads(metadata["model_config"], object_pairs_hook=unique), model_id)
    except (ValueError, TypeError, KeyError) as exc:
        raise ModelArtifactError("Scratch stream config is invalid.") from exc
    validate_scratch_presence_metadata({key: metadata[key] for key in METADATA_KEYS}, version)
    derived = {"task": "task", "profile": "profile", "training_mode": "training_mode",
               "text_normalization": "normalization", "tokenizer": "tokenizer", "pooling": "pooling", "arithmetic": "arithmetic"}
    if any(metadata[key] != config[value] for key, value in derived.items()):
        _fail("Scratch stream derived declarations do not match config.")
    if metadata["trainable_parameters"] != ",".join(scratch_presence_trainable_names(config)):
        _fail("Scratch stream trainable manifest is not exact sorted CSV.")
    for key in ("artifact_checksum", "artifact_file_checksum"):
        if not re.fullmatch(r"[0-9a-f]{64}", metadata[key]):
            _fail("Scratch stream checksum is invalid.")
    if metadata["served_by"] != "model-streaming-service" or not metadata["consumer_id"] or len(metadata["consumer_id"]) > 128 or any(ord(c) < 32 or ord(c) == 127 for c in metadata["consumer_id"]):
        _fail("Scratch stream service metadata is invalid.")
    return config
