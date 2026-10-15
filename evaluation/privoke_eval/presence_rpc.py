"""Small typed adapter for annotation-presence gRPC requests and responses."""
from __future__ import annotations

import math
from typing import Any, Mapping


def response_record(response: Any) -> dict:
    """Copy only typed presence response fields; do not read defaults on errors."""
    request_id = str(getattr(response, "request_id", ""))
    error = str(getattr(response, "error", ""))
    if error:
        return {"request_id": request_id, "error": error}
    return {
        "request_id": request_id,
        "model_id": str(getattr(response, "model_id", "")),
        "model_version": str(getattr(response, "model_version", "")),
        "probability": getattr(response, "probability", None),
        "threshold": getattr(response, "threshold", None),
        "predicted_label": getattr(response, "predicted_label", None),
        "artifact_checksum": str(getattr(response, "artifact_checksum", "")),
        "parameter_fingerprint": str(getattr(response, "parameter_fingerprint", "")),
        "elapsed_ms": getattr(response, "elapsed_ms", None),
        "executions": [{"layer": int(e.layer), "status": str(e.status), "error": str(e.error)}
                       for e in getattr(response, "executions", ())],
        "error": "",
    }


def validate_response(record: Mapping[str, Any], *, request_id: str,
                      expected_identity: Mapping[str, Any],
                      present_enum: int, absent_enum: int,
                      expected_probability: float | None = None) -> dict:
    """Validate exact identity, typed label and arithmetic consistency."""
    error = record.get("error")
    if error:
        raise RuntimeError(f"Runtime rejected presence request: {error}")
    validate_execution(record)
    if record.get("request_id") != request_id:
        raise ValueError("Presence RPC request ID mismatch.")
    for field in ("model_id", "model_version", "artifact_checksum", "parameter_fingerprint"):
        if record.get(field) != expected_identity[field]:
            raise ValueError(f"Presence RPC {field} mismatch.")
    probability = record.get("probability")
    threshold = record.get("threshold")
    elapsed = record.get("elapsed_ms")
    if isinstance(probability, bool) or not isinstance(probability, (int, float)) or not math.isfinite(probability) or not 0.0 <= probability <= 1.0:
        raise ValueError("Presence RPC probability is invalid.")
    if isinstance(threshold, bool) or not isinstance(threshold, (int, float)) or not math.isfinite(threshold) or threshold != expected_identity["threshold"]:
        raise ValueError("Presence RPC threshold differs from the frozen artifact.")
    if expected_probability is not None:
        if not math.isfinite(expected_probability) or not 0.0 <= expected_probability <= 1.0:
            raise ValueError("Local shared presence probability is invalid.")
        if not math.isclose(float(probability), float(expected_probability), rel_tol=0.0, abs_tol=1e-12):
            raise ValueError("Presence RPC probability differs from shared serialized-artifact inference.")
    if isinstance(elapsed, bool) or not isinstance(elapsed, (int, float)) or not math.isfinite(elapsed) or elapsed < 0.0:
        raise ValueError("Presence RPC elapsed_ms is invalid.")
    predicted = record.get("predicted_label")
    if type(predicted) is not int or predicted not in (present_enum, absent_enum):
        raise ValueError("Presence RPC enum is unspecified or unknown.")
    expected = present_enum if probability >= threshold else absent_enum
    if predicted != expected:
        raise ValueError("Presence RPC label disagrees with returned probability and threshold.")
    return {"probability": float(probability), "threshold": float(threshold),
            "predicted_label": predicted, "elapsed_ms": float(elapsed),
            "identity": {key: record[key] for key in
                         ("model_id", "model_version", "artifact_checksum", "parameter_fingerprint")}}


def validate_execution(record: Mapping[str, Any]) -> None:
    """Reject a prediction without one actual successful semantic execution."""
    executions = record.get("executions")
    if (not isinstance(executions, list) or len(executions) != 1
            or executions[0] != {"layer": 4, "status": "ok", "error": ""}):
        raise ValueError("Presence RPC requires one actual successful semantic execution.")
