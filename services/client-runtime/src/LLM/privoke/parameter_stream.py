from __future__ import annotations

import hashlib
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Tuple

from ...env import env_float


@dataclass(frozen=True)
class ParameterSnapshot:
    """A streamed model-parameter snapshot from model-streaming-service."""

    model_id: str
    version: str
    generated_at_unix: int
    parameters: Dict[str, Tuple[float, ...]]
    metadata: Dict[str, str]

    @property
    def parameter_count(self) -> int:
        return len(self.parameters)

    @property
    def fingerprint(self) -> str:
        digest = hashlib.sha256()
        for name in sorted(self.parameters):
            digest.update(name.encode("utf-8"))
            for value in self.parameters[name]:
                digest.update(repr(float(value)).encode("utf-8"))
        return digest.hexdigest()[:16]

    @property
    def cache_key(self) -> str:
        return f"{self.model_id}:{self.version}:{self.fingerprint}"

    def flat_values(self) -> Tuple[float, ...]:
        values = []
        for name in sorted(self.parameters):
            values.extend(self.parameters[name])
        return tuple(values)


class ModelParameterStreamer:
    """
    Lazy client for model-streaming-service.

    The generated protobuf package is created by the client-runtime Dockerfile
    and dev-compose command. Imports stay inside fetch() so instantiating a
    classifier never streams parameters or requires generated files.
    """

    DEFAULT_TARGET = "model-streaming-service:50051"
    DEFAULT_CONSUMER_ID = "client-runtime"
    DEFAULT_MODEL_ID = "privoke-baseline"
    DEFAULT_TIMEOUT_SECONDS = 10.0

    def __init__(
        self,
        target: str | None = None,
        model_id: str | None = None,
        consumer_id: str | None = None,
        timeout_seconds: float | None = None,
    ):
        self.target = target or os.getenv(
            "MODEL_STREAMING_TARGET",
            self.DEFAULT_TARGET,
        )
        self.model_id = model_id or os.getenv("MODEL_ID", self.DEFAULT_MODEL_ID)
        self.consumer_id = consumer_id or os.getenv(
            "MODEL_STREAMING_CONSUMER_ID",
            self.DEFAULT_CONSUMER_ID,
        )
        self.timeout_seconds = (
            timeout_seconds
            if timeout_seconds is not None
            else env_float(
                "MODEL_STREAMING_TIMEOUT_SECONDS",
                self.DEFAULT_TIMEOUT_SECONDS,
            )
        )
        if self.timeout_seconds <= 0:
            raise ValueError("MODEL_STREAMING_TIMEOUT_SECONDS must be greater than zero.")

    def fetch(self) -> ParameterSnapshot:
        grpc, parameters_pb2, parameters_pb2_grpc = _load_generated_grpc_modules()

        with grpc.insecure_channel(self.target) as channel:
            client = parameters_pb2_grpc.ModelStreamingServiceStub(channel)
            snapshot = client.GetModelParameters(
                parameters_pb2.ModelParametersRequest(
                    consumer_id=self.consumer_id,
                    model_id=self.model_id,
                ),
                timeout=self.timeout_seconds,
            )

        return ParameterSnapshot(
            model_id=snapshot.model_id,
            version=snapshot.version,
            generated_at_unix=snapshot.generated_at_unix,
            parameters={
                parameter.name: tuple(float(value) for value in parameter.values)
                for parameter in snapshot.parameters
            },
            metadata=dict(snapshot.metadata),
        )


def _load_generated_grpc_modules():
    generated_dir = Path(__file__).resolve().parents[3] / "generated"
    if str(generated_dir) not in sys.path:
        sys.path.insert(0, str(generated_dir))

    try:
        import grpc
    except ModuleNotFoundError as exc:
        raise RuntimeError(
            "grpcio is required for streamed PriVoke classification. "
            "Install services/client-runtime/requirements.txt."
        ) from exc

    try:
        from privoke.v1 import parameters_pb2, parameters_pb2_grpc
    except ModuleNotFoundError as exc:
        raise RuntimeError(
            "Generated gRPC stubs are missing. Run the client-runtime Dockerfile "
            "or generate shared/proto/privoke/v1/parameters.proto into "
            f"{generated_dir}."
        ) from exc

    return grpc, parameters_pb2, parameters_pb2_grpc
