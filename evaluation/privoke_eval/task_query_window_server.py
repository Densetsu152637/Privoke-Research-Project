"""Study server bootstrap; clients and dataset drivers run exclusively on the host.

The optional teacher servicer observes the prediction used by the existing
AnalyzePrompt handler. It serves requests; it never iterates a bank or fits a cell.
"""
from __future__ import annotations

import argparse
import base64
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import signal
import sys
import threading

ROOT = Path(__file__).resolve().parents[2]


def wire(message):
    return message.SerializeToString(deterministic=True)


def persist(path, record):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write((json.dumps(record, sort_keys=True, allow_nan=False) + "\n").encode())
        stream.flush()
        os.fsync(stream.fileno())


@dataclass(frozen=True)
class TeacherBinding:
    model: object
    teacher: dict
    teacher_path: str
    teacher_sha256: str

    def validate_request(self, layers, model_id, gate):
        from privoke_model.window_training import teacher_identity
        if (tuple(layers or ()) != ("semantic",) or gate is not None or model_id != self.teacher["model_id"]
                or teacher_identity(self.teacher_path, "balanced", self.teacher_sha256) != self.teacher):
            raise ValueError("Authenticated teacher requires explicit sole semantic execution")
        snapshot = self.model.snapshot
        if (snapshot.fingerprint != self.teacher["parameter_fingerprint"] or snapshot.version != self.teacher["version"]
                or snapshot.metadata.get("artifact_checksum") != self.teacher["checksum"]):
            raise ValueError("Teacher snapshot identity differs")


def teacher_servicer(path, accepted_sha, capture_directory):
    from privoke_model import window_training, sensitive_retention
    from src.LLM.privoke.parameter_stream import ParameterSnapshot
    from src.LLM.privoke.streamed_model import StreamedTransformerPrivacyModel
    from src.LLM.privoke.reference_preparation import bind_reference
    from src.LLM.privoke.training import _classification_from_prediction
    from src.hosting.grpc_server import PrivokeRuntimeService
    from src.task_readout import TASKS

    teacher = window_training.teacher_identity(path, "balanced", accepted_sha)
    artifact = json.loads(Path(path).read_bytes())
    metadata = {**artifact["metadata"], "architecture": artifact["architecture"], "artifact_checksum": artifact["checksum"],
        "model_config": json.dumps(artifact["config"], sort_keys=True),
        "trainable_parameters": ",".join(sorted(n for n, tensor in artifact["parameters"].items() if tensor["trainable"]))}
    observations = []
    model = StreamedTransformerPrivacyModel(ParameterSnapshot(artifact["model_id"], artifact["version"], 0,
        sensitive_retention.original_effective_parameters(artifact),
        {n: tuple(t["shape"]) for n, t in artifact["parameters"].items()}, metadata), prediction_observer=observations.append)
    binding = TeacherBinding(model, teacher, str(path), accepted_sha)

    class CapturingService(PrivokeRuntimeService):
        def __init__(self):
            super().__init__()
            self._capture_lock = threading.Lock()

        def AnalyzePrompt(self, request, context):
            with self._capture_lock:
                request_wire = wire(request)
                directory = capture_directory / hashlib.sha256(request.request_id.encode()).hexdigest()
                persist(directory / "attempted.json", {"request_id": request.request_id, "teacher": teacher,
                    "request_sha256": hashlib.sha256(request_wire).hexdigest(),
                    "request_base64": base64.b64encode(request_wire).decode(), "dispatch": "network_AnalyzePrompt"})
                observations.clear()
                # ContextVar binding belongs to this RPC thread, not server startup.
                with bind_reference(binding):
                    response = super().AnalyzePrompt(request, context)
                response_wire = wire(response)
                predictions = [{"original": _classification_from_prediction(prediction).pack(),
                    "confidence": round(min(max(prediction.confidence, 0.0), .999), 3),
                    "logits": {task: [float(v) for v in model.model.prediction_logits(prediction, task)] for task in TASKS}}
                    for prediction in observations]
                persist(directory / "observed.json", {"request_id": request.request_id, "teacher": teacher,
                    "request_sha256": hashlib.sha256(request_wire).hexdigest(),
                    "response_sha256": hashlib.sha256(response_wire).hexdigest(),
                    "response_base64": base64.b64encode(response_wire).decode(), "predictions": predictions})
                return response

    return CapturingService()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--teacher", type=Path)
    parser.add_argument("--teacher-sha256")
    parser.add_argument("--capture-directory", type=Path)
    args = parser.parse_args()
    for path in (ROOT / "shared/python", ROOT / "extension/client-runtime", ROOT / "extension/client-runtime/generated"):
        sys.path.insert(0, str(path))
    from src.config import GLOBAL_CONFIG, LLMChoice
    from src.hosting.grpc_server import create_grpc_server
    GLOBAL_CONFIG.llm_choice = LLMChoice.parse("streamed")
    configured = (args.teacher, args.teacher_sha256, args.capture_directory)
    if any(configured) and not all(configured):
        parser.error("Teacher path, accepted SHA and capture directory are required together")
    servicer = teacher_servicer(*configured) if all(configured) else None
    server = create_grpc_server(telemetry_reporter=None, servicer=servicer)
    if not server.add_insecure_port("0.0.0.0:50054"):
        raise RuntimeError("Runtime listener failed")
    stopped = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stopped.set())
    signal.signal(signal.SIGINT, lambda *_: stopped.set())
    server.start()
    try:
        stopped.wait()
    finally:
        server.stop(5).wait()


if __name__ == "__main__":
    main()
