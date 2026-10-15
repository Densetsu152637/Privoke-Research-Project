"""Structurally framed content identities for streamed and evaluated tensors."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence


def parameter_fingerprint(
    parameters: Mapping[str, Sequence[float]],
    shapes: Mapping[str, Sequence[int]] | None = None,
) -> str:
    """Hash ordered tensor names, shapes, and values without ambiguous joins."""
    tensors = [
        [name, list(shapes.get(name, ())) if shapes is not None else None,
         [float(value) for value in parameters[name]]]
        for name in sorted(parameters)
    ]
    canonical = json.dumps(tensors, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
