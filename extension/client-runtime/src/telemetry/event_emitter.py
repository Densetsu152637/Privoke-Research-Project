from __future__ import annotations

import logging
import queue
import threading
from datetime import datetime, timezone
from typing import TYPE_CHECKING

import grpc
from privoke_service.stack_connection import grpc_channel

from .privacy import (
    DAILY_EPSILON_DEFAULT,
    EVENT_EPSILON_DEFAULT,
    MECHANISM,
    DOMAINS,
    DailyPrivacyBudget,
    randomize_report,
)
from privoke.v1 import telemetry_pb2, telemetry_pb2_grpc

if TYPE_CHECKING:
    from ..hosting.analyzer import PromptAnalysis


CATEGORY_PRECEDENCE = (
    "CHILD", "HEALTH", "CRIMINAL", "SEXUAL", "FINANCIAL", "IDENTITY",
    "LOCATION", "RELIGION", "POLITICS", "THIRD_PARTY",
)


class StructuredEventEmitter:
    """Privatize a bounded categorical report locally before it leaves the runtime."""

    def build_packet(self, analysis: "PromptAnalysis", epsilon: float = EVENT_EPSILON_DEFAULT):
        now = datetime.now(timezone.utc)
        classification = analysis.result.classification if analysis.result is not None else None
        action = analysis.action.name
        sensitivity = classification.sensitivity().name if classification else "S0"
        risk_score = _risk_score(action, sensitivity)
        true_values = {
            "action": action if action in DOMAINS["action"] else "ALLOW",
            "risk_bucket": _risk_bucket(risk_score),
            "primary_category": _primary_category(classification),
            "model_version": _model_release_version(analysis.result),
            "time_bucket": _time_bucket(now),
        }
        protected = randomize_report(true_values, epsilon)
        return telemetry_pb2.TelemetryPacket(
            time_bucket=protected["time_bucket"],
            action=protected["action"],
            primary_category=protected["primary_category"],
            risk_bucket=protected["risk_bucket"],
            model_version=protected["model_version"],
            privacy_mechanism=MECHANISM,
            privacy_epsilon=epsilon,
        )


class TelemetryReporter:
    """Reserve local budget, randomize, and submit without delaying prompt analysis."""

    _STOP = object()

    def __init__(
        self,
        target: str,
        event_epsilon: float = EVENT_EPSILON_DEFAULT,
        daily_epsilon: float = DAILY_EPSILON_DEFAULT,
        ledger_path: str | None = None,
        timeout_seconds: float = 1.0,
        queue_size: int = 1024,
    ):
        from .privacy import default_ledger_path, validate_privacy_config

        validate_privacy_config(event_epsilon, daily_epsilon)
        self.target = target
        self.event_epsilon = event_epsilon
        self._budget = DailyPrivacyBudget(
            ledger_path or default_ledger_path(), daily_epsilon
        )
        self._channel = grpc_channel(target)
        self.timeout_seconds = timeout_seconds
        self.emitter = StructuredEventEmitter()
        self._queue: queue.Queue = queue.Queue(maxsize=max(1, queue_size))
        self._thread = threading.Thread(
            target=self._run,
            name="privoke-telemetry-reporter",
            daemon=True,
        )
        self._thread.start()

    def report(self, analysis: "PromptAnalysis") -> None:
        try:
            if not self._budget.reserve(self.event_epsilon):
                logging.info("telemetry daily privacy budget exhausted; report suppressed")
                return
            packet = self.emitter.build_packet(analysis, self.event_epsilon)
        except Exception as exc:
            logging.warning("telemetry privacy processing failed; report suppressed (%s)", exc.__class__.__name__)
            return
        try:
            self._queue.put_nowait(packet)
        except queue.Full:
            # A reserved privacy budget is never refunded, even when no packet is sent.
            logging.warning("telemetry queue full; report suppressed")

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
                        logging.warning("telemetry report rejected")
                except grpc.RpcError as exc:
                    logging.warning(
                        "telemetry submission failed event=%s code=%s",
                        "protected-report",
                        exc.code(),
                    )
                except Exception as exc:
                    logging.warning(
                        "telemetry reporter failed event=%s error=%s",
                        "protected-report",
                        exc.__class__.__name__,
                    )
                finally:
                    self._queue.task_done()


def _primary_category(classification) -> str:
    if classification is None:
        return "NONE"
    categories = {category.name for category in classification.categories()}
    return next((name for name in CATEGORY_PRECEDENCE if name in categories), "NONE")


def _model_release_version(result) -> str:
    if result is None:
        return "OTHER"
    metadata = getattr(result, "metadata", {}) or {}
    version = str(metadata.get("model_version", ""))
    # Training revisions retain the public release channel but not an unbounded
    # per-update identifier in telemetry.
    release_version = version.split("+train.", 1)[0]
    return release_version if release_version in DOMAINS["model_version"] else "OTHER"


def _time_bucket(occurred_at: datetime) -> str:
    start_hour = (occurred_at.hour // 4) * 4
    end_hour = start_hour + 4
    return f"{start_hour:02d}-{end_hour:02d}_UTC"


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
