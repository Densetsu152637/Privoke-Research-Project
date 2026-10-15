"""Internal ORIGINAL TRAIN reference preparation through the real semantic dispatcher.

Calling prepare_references executes models and requires a separate numerical release.
Imports, binding guards and fake-backend tests execute no teacher models.
"""
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass

from privoke_model import sensitive_retention as contract

_ACTIVE = ContextVar("privoke_original_train_reference", default=None)


@dataclass(frozen=True)
class ReferenceBinding:
    model: object
    teacher: dict
    teacher_path: str

    def validate_request(self, layers, model_id, gate):
        if self.teacher != contract.teacher_identity(self.teacher_path, self.teacher["profile"]):
            raise ValueError("ORIGINAL reference binding teacher differs from immutable accepted bytes.")
        if tuple(layers or ()) != ("semantic",) or model_id != self.teacher["model_id"] or gate is not None:
            raise ValueError("ORIGINAL reference preparation requires explicit sole semantic layer, matching teacher and no gate.")
        snapshot = self.model.snapshot
        if (snapshot.model_id != self.teacher["model_id"] or snapshot.version != self.teacher["version"]
                or snapshot.fingerprint != self.teacher["parameter_fingerprint"]
                or snapshot.metadata.get("artifact_checksum") != self.teacher["checksum"]):
            raise ValueError("ORIGINAL reference binding differs from authenticated artifact identity.")


def current_binding():
    return _ACTIVE.get()


@contextmanager
def bind_reference(binding):
    if _ACTIVE.get() is not None:
        raise ValueError("Nested ORIGINAL reference preparation is unsupported.")
    token = _ACTIVE.set(binding)
    try:
        yield binding
    finally:
        _ACTIVE.reset(token)


def prepare_references(bank_payload, teacher_path, profile, *, output):
    """One actual [4] AnalyzePrompt dispatch per TRAIN row; observe its same prediction.

    The output callback receives a durable row record before the next dispatch.
    Partial failures are observable and are never converted to eligible rows.
    """
    import json
    from .parameter_stream import ParameterSnapshot
    from .streamed_model import StreamedTransformerPrivacyModel
    from .sensitive_retention_training import margin_and_gap
    from .training import _classification_from_prediction
    from ...hosting.grpc_server import PrivokeRuntimeService
    from privoke.v1 import runtime_pb2
    bank = contract.validate_bank(bank_payload)
    teacher = contract.teacher_identity(teacher_path, profile)
    artifact = contract.load_original_artifact(teacher_path, profile)
    parameters = contract.original_effective_parameters(artifact)
    shapes = {n: tuple(t["shape"]) for n, t in artifact["parameters"].items()}
    metadata = {**artifact["metadata"], "architecture": artifact["architecture"],
        "artifact_checksum": artifact["checksum"], "model_config": json.dumps(artifact["config"], sort_keys=True, separators=(",", ":")),
        "trainable_parameters": ",".join(sorted(n for n, t in artifact["parameters"].items() if t["trainable"]))}
    captured = []
    model = StreamedTransformerPrivacyModel(ParameterSnapshot(artifact["model_id"], artifact["version"], 0,
        parameters, shapes, metadata), prediction_observer=lambda prediction: captured.append(prediction))
    binding = ReferenceBinding(model, teacher, str(teacher_path))
    service = PrivokeRuntimeService()
    rows = []
    with bind_reference(binding):
        for source in bank:
            captured.clear()
            output({"id": source["id"], "status": "attempted", "layers": [4]})
            request = runtime_pb2.AnalyzePromptRequest(text=source["text"], request_id=source["id"],
                semantic_model_id=teacher["model_id"], layers=[runtime_pb2.DETECTION_LAYER_SEMANTIC])
            response = service.AnalyzePrompt(request, None)
            if (response.error or len(response.layers) != 1 or response.layers[0].layer != 4
                    or response.layers[0].status != "ok" or response.layers[0].error or len(captured) != 1
                    or response.metadata.get("privoke.semantic.parameter_fingerprint") != teacher["parameter_fingerprint"]
                    or response.metadata.get("privoke.semantic.artifact_checksum") != teacher["checksum"]):
                output({"id": source["id"], "status": "failed", "error": response.error,
                        "observed_predictions": len(captured)})
                raise ValueError("ORIGINAL reference preparation actual semantic execution/identity assertion failed.")
            prediction = captured[0]
            margin, gap = margin_and_gap(model.model, prediction)
            classification = _classification_from_prediction(prediction)
            row = {"id": source["id"], "packed": classification.pack(),
                "confidence": round(min(max(prediction.confidence, 0.0), .999), 3),
                "margin": margin, "sensitivity_gap": gap,
                "eligible": classification.is_sensitive() and margin > contract.EPSILON and gap > contract.EPSILON}
            output({"id": source["id"], "status": "completed", "layers": [4], "reference": row,
                    "execution": {"layer": response.layers[0].layer, "status": response.layers[0].status},
                    "teacher": teacher})
            rows.append(row)
    payload = contract.canonical_bytes({"schema": 1, "teacher": teacher, "bank_sha256": contract.BANK_SHA256,
                                       "boundary": contract.BOUNDARY, "rows": rows})
    contract.validate_references(payload, bank, teacher)
    return payload, teacher
