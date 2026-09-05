from __future__ import annotations

import logging
import queue
import threading
import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING

import grpc
from privoke_service.stack_connection import grpc_channel

from privoke.v1 import telemetry_pb2, telemetry_pb2_grpc

if TYPE_CHECKING:
    from ..hosting.analyzer import PromptAnalysis


class StructuredEventEmitter:
    """Build privacy-minimal telemetry packets from current runtime results."""

    def __init__(self, source_id: str, detector_version: str = "v2"):
        self.source_id = source_id
        self.detector_version = detector_version

    def build_packet(self, analysis: "PromptAnalysis"):
        occurred_at = datetime.now(timezone.utc)
        classification = (
            analysis.result.classification
            if analysis.result is not None
            else None
        )
        sensitivity = (
            classification.sensitivity().name if classification else "S0"
        )
        visibility = (
            classification.visibility().name
            if classification
            else (
                analysis.request.visibility_hint.name
                if analysis.request.visibility_hint
                else "PU"
            )
        )
        categories = (
            [category.name for category in classification.categories()]
            if classification
            else []
        )
        risk_score = _risk_score(analysis.action.name, sensitivity)
        return telemetry_pb2.TelemetryPacket(
            event_id=str(uuid.uuid4()),
            occurred_at_unix_ms=int(occurred_at.timestamp() * 1000),
            time_bucket=occurred_at.strftime("%Y-%m-%dT%H:00:00Z"),
            source_id=self.source_id,
            request_id=analysis.request.request_id or "",
            target_app=analysis.request.target_app or "",
            action=analysis.action.name,
            sensitivity=sensitivity,
            visibility=visibility,
            categories=categories,
            text_length=len(analysis.request.text),
            elapsed_ms=analysis.elapsed_ms,
            risk_score=risk_score,
            risk_bucket=_risk_bucket(risk_score),
            detector_version=self.detector_version,
            layers=[
                telemetry_pb2.LayerTelemetry(
                    layer=execution.layer,
                    status=execution.status,
                    result_count=len(execution.results),
                    error=(
                        "detector_error"
                        if execution.status == "error"
                        else "short_circuited"
                        if execution.status == "skipped"
                        else ""
                    ),
                )
                for execution in analysis.execution.layers
            ],
        )


class TelemetryReporter:
    """Submit packets on a bounded background queue without delaying analysis."""

    _STOP = object()

    def __init__(
        self,
        target: str,
        source_id: str,
        timeout_seconds: float = 1.0,
        queue_size: int = 1024,
        detector_version: str = "v2",
    ):
        self.target = target
        self._channel = grpc_channel(target)
        self.timeout_seconds = timeout_seconds
        self.emitter = StructuredEventEmitter(source_id, detector_version)
        self._queue: queue.Queue = queue.Queue(maxsize=max(1, queue_size))
        self._thread = threading.Thread(
            target=self._run,
            name="privoke-telemetry-reporter",
            daemon=True,
        )
        self._thread.start()

    def report(self, analysis: "PromptAnalysis") -> None:
        packet = self.emitter.build_packet(analysis)
        try:
            self._queue.put_nowait(packet)
        except queue.Full:
            logging.warning("telemetry queue full; dropping event=%s", packet.event_id)

    def close(self, timeout_seconds: float = 2.0) -> None:
        try:
            self._queue.put_nowait(self._STOP)
        except queue.Full:
            return
        self._thread.join(timeout=max(0.0, timeout_seconds))

    def _run(self) -> None:
        with self._channel as channel:
            client = telemetry_pb2_grpc.TelemetryServiceStub(channel)
            while True:
                packet = self._queue.get()
                try:
                    if packet is self._STOP:
                        return
                    response = client.RecordTelemetry(
                        packet,
                        timeout=self.timeout_seconds,
                    )
                    if not response.accepted:
                        logging.warning(
                            "telemetry event rejected event=%s",
                            packet.event_id,
                        )
                except grpc.RpcError as exc:
                    logging.warning(
                        "telemetry submission failed event=%s code=%s",
                        getattr(packet, "event_id", "unknown"),
                        exc.code(),
                    )
                except Exception as exc:
                    logging.warning(
                        "telemetry reporter failed event=%s error=%s",
                        getattr(packet, "event_id", "unknown"),
                        exc.__class__.__name__,
                    )
                finally:
                    self._queue.task_done()


def _risk_score(action: str, sensitivity: str) -> float:
    action_score = {"ALLOW": 0.0, "WARN": 0.65, "BLOCK": 1.0}.get(action, 0.0)
    sensitivity_score = {"S0": 0.0, "S1": 0.25, "S2": 0.65, "S3": 1.0}.get(
        sensitivity,
        0.0,
    )
    return max(action_score, sensitivity_score)


def _risk_bucket(score: float) -> str:
    if score < 0.2:
        return "0.0-0.2"
    if score < 0.5:
        return "0.2-0.5"
    if score < 0.8:
        return "0.5-0.8"
    return "0.8-1.0"
