"""Reliable client for reconstructing streamed model snapshots."""

from __future__ import annotations

import logging
import time

import grpc
from config import FuzzerConfig
from privoke.v1 import parameters_pb2, parameters_pb2_grpc
from training.protocols import StreamedParameterSnapshot

MAX_SNAPSHOT_BYTES = 8 * 1024 * 1024
RETRYABLE_STATUS_CODES = frozenset(
    {grpc.StatusCode.UNAVAILABLE, grpc.StatusCode.DEADLINE_EXCEEDED}
)
LOGGER = logging.getLogger(__name__)


class ModelSnapshotUnavailable(RuntimeError):
    pass


def fetch_snapshot(config: FuzzerConfig, model_id: str) -> StreamedParameterSnapshot:
    """Fetch a snapshot with bounded exponential retry for transient failures."""
    attempts = max(1, int(config.model_streaming_fetch_max_attempts))
    last_error_message = "unknown error"

    for attempt in range(1, attempts + 1):
        try:
            return _fetch_snapshot_once(config, model_id)
        except grpc.FutureTimeoutError as exc:
            last_error_message = _snapshot_error_message(exc, config)
        except grpc.RpcError as exc:
            if not _is_retryable_rpc_error(exc):
                raise
            last_error_message = _snapshot_error_message(exc, config)

        if attempt < attempts:
            _wait_before_retry(config, attempt, attempts, last_error_message)

    raise ModelSnapshotUnavailable(
        "model-streaming-service was unavailable after "
        f"{attempts} attempts at {config.model_streaming_target}: "
        f"{last_error_message}"
    )


def _fetch_snapshot_once(
    config: FuzzerConfig,
    model_id: str,
) -> StreamedParameterSnapshot:
    with grpc.insecure_channel(
        config.model_streaming_target,
        options=(("grpc.max_receive_message_length", MAX_SNAPSHOT_BYTES),),
    ) as channel:
        grpc.channel_ready_future(channel).result(
            timeout=max(0.1, config.model_streaming_connect_timeout_seconds)
        )
        chunks = parameters_pb2_grpc.ModelStreamingServiceStub(
            channel
        ).StreamModelParameters(
            parameters_pb2.ModelParametersRequest(
                consumer_id=config.fuzzer_id,
                model_id=model_id,
            ),
            timeout=config.timeout_seconds,
        )
        snapshot = assemble_parameter_stream(chunks)

    if snapshot.model_id != model_id:
        raise ModelSnapshotUnavailable(
            "model-streaming-service returned model "
            f"'{snapshot.model_id}' for requested model '{model_id}'."
        )
    return snapshot


def assemble_parameter_stream(chunks) -> StreamedParameterSnapshot:
    """Reassemble ordered chunks while rejecting a mixed or partial snapshot."""
    snapshot = _SnapshotBuilder()
    for chunk in chunks:
        snapshot.add(chunk)
    return snapshot.build()


class _SnapshotBuilder:
    def __init__(self) -> None:
        self.model_id = ""
        self.version = ""
        self.generated_at_unix = 0
        self.expected_chunks: int | None = None
        self.received_chunks = 0
        self.metadata: dict[str, str] = {}
        self.values_by_name: dict[str, list[float]] = {}
        self.shapes_by_name: dict[str, tuple[int, ...]] = {}

    def add(self, chunk) -> None:
        if int(chunk.chunk_index) != self.received_chunks:
            raise ModelSnapshotUnavailable("Model parameter stream is out of order.")
        if self.expected_chunks is None:
            self._set_identity(chunk)
        elif not self._matches_identity(chunk):
            raise ModelSnapshotUnavailable(
                "Model parameter stream changed snapshot mid-stream."
            )

        self._add_parameter_chunk(chunk.parameter)
        self.metadata.update(dict(chunk.metadata))
        self.received_chunks += 1

    def _set_identity(self, chunk) -> None:
        self.expected_chunks = int(chunk.total_chunks)
        self.model_id = chunk.model_id
        self.version = chunk.version
        self.generated_at_unix = int(chunk.generated_at_unix)

    def _matches_identity(self, chunk) -> bool:
        return (
            chunk.model_id == self.model_id
            and chunk.version == self.version
            and int(chunk.generated_at_unix) == self.generated_at_unix
            and int(chunk.total_chunks) == self.expected_chunks
        )

    def _add_parameter_chunk(self, parameter) -> None:
        shape = tuple(int(size) for size in parameter.shape)
        values = self.values_by_name.setdefault(parameter.name, [])
        previous_shape = self.shapes_by_name.get(parameter.name)
        if previous_shape is not None and previous_shape != shape:
            raise ModelSnapshotUnavailable("Model tensor shape changed mid-stream.")
        if int(parameter.value_offset) != len(values):
            raise ModelSnapshotUnavailable(
                "Model tensor stream has a discontinuous offset."
            )
        self.shapes_by_name[parameter.name] = shape
        values.extend(float(value) for value in parameter.values)

    def build(self) -> StreamedParameterSnapshot:
        if self.expected_chunks is None or self.received_chunks != self.expected_chunks:
            raise ModelSnapshotUnavailable("Model parameter stream ended early.")
        if not self.model_id or not self.version or self.generated_at_unix <= 0:
            raise ModelSnapshotUnavailable(
                "Model parameter stream metadata is invalid."
            )
        return parameters_pb2.ModelParametersResponse(
            model_id=self.model_id,
            version=self.version,
            generated_at_unix=self.generated_at_unix,
            parameters=[
                parameters_pb2.Parameter(
                    name=name,
                    shape=self.shapes_by_name[name],
                    values=values,
                )
                for name, values in self.values_by_name.items()
            ],
            metadata=self.metadata,
        )


def _wait_before_retry(
    config: FuzzerConfig,
    failed_attempt: int,
    total_attempts: int,
    error_message: str,
) -> None:
    delay_seconds = _retry_delay(config, failed_attempt)
    LOGGER.warning(
        "model snapshot fetch failed attempt=%s/%s target=%s: %s; retrying in %.1fs",
        failed_attempt,
        total_attempts,
        config.model_streaming_target,
        error_message,
        delay_seconds,
    )
    time.sleep(delay_seconds)


def _is_retryable_rpc_error(exc: grpc.RpcError) -> bool:
    try:
        return exc.code() in RETRYABLE_STATUS_CODES
    except AttributeError:
        return False


def _snapshot_error_message(exc: Exception, config: FuzzerConfig) -> str:
    if isinstance(exc, grpc.FutureTimeoutError):
        return (
            "channel was not ready within "
            f"{config.model_streaming_connect_timeout_seconds:.1f}s"
        )
    if not isinstance(exc, grpc.RpcError):
        return str(exc) or exc.__class__.__name__

    code = exc.code() if hasattr(exc, "code") else None
    details = exc.details() if hasattr(exc, "details") else None
    return f"{code}: {details}" if details else str(code)


def _retry_delay(config: FuzzerConfig, failed_attempt: int) -> float:
    initial = max(0.1, config.model_streaming_retry_initial_seconds)
    maximum = max(initial, config.model_streaming_retry_max_seconds)
    return min(maximum, initial * (2 ** (failed_attempt - 1)))
