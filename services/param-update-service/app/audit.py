"""Append-only parameter-update auditing and health checks."""

from __future__ import annotations

import json
import os
from pathlib import Path

from privoke_model import ModelArtifactError, load_artifact


def persist_update_audit(
    storage_path: Path,
    request,
    *,
    applied_version: str,
    artifact_checksum: str,
) -> None:
    payload = {
        "source_id": request.source_id,
        "model_id": request.model_id,
        "base_version": request.base_version,
        "applied_version": applied_version,
        "artifact_checksum": artifact_checksum,
        "gradients": [
            {
                "name": gradient.name,
                "shape": list(gradient.shape),
                "values": list(gradient.values),
            }
            for gradient in request.gradients
        ],
        "metadata": dict(request.metadata),
    }
    descriptor = _open_storage_file(storage_path)
    with os.fdopen(descriptor, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, separators=(",", ":")) + "\n")


def storage_is_writable(storage_path: Path) -> bool:
    try:
        descriptor = _open_storage_file(storage_path)
    except OSError:
        return False
    os.close(descriptor)
    return True


def artifact_is_usable(model_artifact_path: Path | None) -> bool:
    if model_artifact_path is None:
        return True
    try:
        load_artifact(model_artifact_path)
    except (ModelArtifactError, OSError):
        return False
    return os.access(model_artifact_path.parent, os.W_OK)


def _open_storage_file(storage_path: Path) -> int:
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
    # Refuse symlinks where the platform exposes O_NOFOLLOW.
    flags |= getattr(os, "O_NOFOLLOW", 0)
    return os.open(storage_path, flags, 0o600)
