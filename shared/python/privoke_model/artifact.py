from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import tempfile
import time
from pathlib import Path
from typing import Any, Mapping, Sequence


ARCHITECTURE_NAME = "privoke_tiny_transformer_v1"
SCHEMA_VERSION = 1
MAX_PARAMETER_VALUES = 65_536


class ModelArtifactError(ValueError):
    pass


def load_artifact(path: str | Path) -> dict[str, Any]:
    artifact_path = Path(path)
    if artifact_path.is_symlink():
        raise ModelArtifactError("Model artifact must not be a symbolic link.")
    try:
        payload = json.loads(artifact_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ModelArtifactError(f"Could not load model artifact: {exc}") from exc
    validate_artifact(payload)
    return payload


def validate_artifact(payload: object) -> None:
    if not isinstance(payload, dict):
        raise ModelArtifactError("Model artifact must be a JSON object.")
    if payload.get("schema_version") != SCHEMA_VERSION:
        raise ModelArtifactError(f"Unsupported model schema: {payload.get('schema_version')!r}.")
    if payload.get("architecture") != ARCHITECTURE_NAME:
        raise ModelArtifactError(f"Unsupported model architecture: {payload.get('architecture')!r}.")
    for field in ("model_id", "version"):
        value = payload.get(field)
        if not isinstance(value, str) or not value or len(value) > 128:
            raise ModelArtifactError(f"{field} must contain 1 to 128 characters.")
        if any(ord(character) < 32 or ord(character) == 127 for character in value):
            raise ModelArtifactError(f"{field} contains control characters.")

    config = payload.get("config")
    if not isinstance(config, dict):
        raise ModelArtifactError("Model config must be a JSON object.")
    parameters = payload.get("parameters")
    if not isinstance(parameters, dict) or not parameters:
        raise ModelArtifactError("Model artifact must contain parameters.")

    total_values = 0
    for name, tensor in parameters.items():
        if not isinstance(name, str) or not name or len(name) > 256:
            raise ModelArtifactError("Parameter names must contain 1 to 256 characters.")
        if not isinstance(tensor, dict):
            raise ModelArtifactError(f"Parameter {name!r} must be an object.")
        shape = tensor.get("shape")
        values = tensor.get("values")
        if not isinstance(shape, list) or not shape or not all(
            isinstance(size, int) and not isinstance(size, bool) and size > 0
            for size in shape
        ):
            raise ModelArtifactError(f"Parameter {name!r} has an invalid shape.")
        if not isinstance(values, list) or not values:
            raise ModelArtifactError(f"Parameter {name!r} has no values.")
        expected = math.prod(shape)
        if expected != len(values):
            raise ModelArtifactError(
                f"Parameter {name!r} shape requires {expected} values, got {len(values)}."
            )
        if not all(
            isinstance(value, (int, float))
            and not isinstance(value, bool)
            and math.isfinite(float(value))
            for value in values
        ):
            raise ModelArtifactError(f"Parameter {name!r} contains a non-finite value.")
        total_values += len(values)
    if total_values > MAX_PARAMETER_VALUES:
        raise ModelArtifactError(
            f"Model artifact exceeds {MAX_PARAMETER_VALUES} parameter values."
        )
    checksum = payload.get("checksum")
    if not isinstance(checksum, str) or len(checksum) != 64:
        raise ModelArtifactError("Model artifact has no valid checksum.")
    expected_checksum = artifact_checksum(
        {key: value for key, value in payload.items() if key != "checksum"}
    )
    if not hmac.compare_digest(checksum, expected_checksum):
        raise ModelArtifactError("Model artifact checksum does not match its contents.")


def artifact_checksum(payload: Mapping[str, Any]) -> str:
    # Match Go's JSON encoder while keeping the canonical representation UTF-8.
    # Go always escapes the two JavaScript line separators even with HTML escaping off.
    canonical = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def apply_parameter_update(
    payload: Mapping[str, Any],
    *,
    base_version: str,
    deltas: Mapping[str, Sequence[float]],
    source_id: str,
) -> dict[str, Any]:
    validate_artifact(payload)
    if payload["version"] != base_version:
        raise ModelArtifactError(
            f"Stale base_version {base_version!r}; current version is {payload['version']!r}."
        )

    updated = json.loads(json.dumps(payload))
    parameters = updated["parameters"]
    trainable = {
        name for name, tensor in parameters.items() if bool(tensor.get("trainable", False))
    }
    if not deltas:
        raise ModelArtifactError("At least one parameter delta is required.")
    unknown = sorted(set(deltas) - set(parameters))
    if unknown:
        raise ModelArtifactError(f"Unknown parameter: {unknown[0]!r}.")
    frozen = sorted(set(deltas) - trainable)
    if frozen:
        raise ModelArtifactError(f"Parameter is not trainable: {frozen[0]!r}.")

    for name, values in deltas.items():
        stored_values = parameters[name]["values"]
        if len(values) != len(stored_values):
            raise ModelArtifactError(f"Parameter shape mismatch for {name!r}.")
        parameters[name]["values"] = [
            round(float(value) + float(values[index]), 8)
            for index, value in enumerate(stored_values)
        ]

    metadata = updated.setdefault("metadata", {})
    try:
        revision = int(metadata.get("training_revision", "0")) + 1
    except (TypeError, ValueError) as exc:
        raise ModelArtifactError("training_revision must be an integer.") from exc
    if revision <= 0:
        raise ModelArtifactError("training_revision must not be negative.")
    release_version = str(metadata.get("release_version") or base_version.split("+train.", 1)[0])
    applied_version = f"{release_version}+train.{revision}"
    metadata.update(
        {
            "release_version": release_version,
            "training_revision": str(revision),
            "last_update_source": source_id,
        }
    )
    updated["version"] = applied_version
    updated["generated_at_unix"] = int(time.time())
    updated["checksum"] = artifact_checksum({key: value for key, value in updated.items() if key != "checksum"})
    validate_artifact(updated)
    return updated


def write_artifact_atomic(path: str | Path, payload: Mapping[str, Any]) -> None:
    validate_artifact(payload)
    artifact_path = Path(path)
    artifact_path.parent.mkdir(parents=True, exist_ok=True)
    if artifact_path.exists() and artifact_path.is_symlink():
        raise ModelArtifactError("Model artifact must not be a symbolic link.")

    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=artifact_path.parent,
            prefix=f".{artifact_path.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary_name = handle.name
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary_name, 0o644)
        os.replace(temporary_name, artifact_path)
    finally:
        if temporary_name and os.path.exists(temporary_name):
            os.unlink(temporary_name)
