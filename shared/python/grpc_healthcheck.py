"""Lightweight gRPC health probe shared by the Python services."""

from __future__ import annotations

import argparse
import importlib
import sys
from dataclasses import dataclass
from pathlib import Path

import grpc


@dataclass(frozen=True)
class HealthSpec:
    protobuf_module: str
    grpc_module: str
    stub_name: str
    request_name: str


HEALTH_SPECS = {
    "param-update-service": HealthSpec(
        "privoke.v1.parameters_pb2",
        "privoke.v1.parameters_pb2_grpc",
        "ParamUpdateServiceStub",
        "HealthRequest",
    ),
    "privoke-fuzzer": HealthSpec(
        "privoke.v1.parameters_pb2",
        "privoke.v1.parameters_pb2_grpc",
        "FuzzerServiceStub",
        "HealthRequest",
    ),
    "client-runtime": HealthSpec(
        "privoke.v1.runtime_pb2",
        "privoke.v1.runtime_pb2_grpc",
        "PrivokeRuntimeServiceStub",
        "RuntimeHealthRequest",
    ),
    "telemetry-service": HealthSpec(
        "privoke.v1.telemetry_pb2",
        "privoke.v1.telemetry_pb2_grpc",
        "TelemetryServiceStub",
        "TelemetryHealthRequest",
    ),
}


def check_health(
    service: str,
    target: str,
    generated_dir: str | Path,
    timeout_seconds: float = 1.0,
) -> None:
    spec = HEALTH_SPECS[service]
    generated_path = str(Path(generated_dir).resolve())
    if generated_path not in sys.path:
        sys.path.insert(0, generated_path)

    protobuf_module = importlib.import_module(spec.protobuf_module)
    grpc_module = importlib.import_module(spec.grpc_module)
    request = getattr(protobuf_module, spec.request_name)()
    stub_type = getattr(grpc_module, spec.stub_name)

    with grpc.insecure_channel(target) as channel:
        response = stub_type(channel).Health(request, timeout=timeout_seconds)

    if response.service != service or response.status != "SERVING":
        raise RuntimeError(
            f"{target} returned service={response.service!r} "
            f"status={response.status!r}"
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("service", choices=sorted(HEALTH_SPECS))
    parser.add_argument("target")
    parser.add_argument("generated_dir")
    parser.add_argument("--timeout", type=float, default=1.0)
    args = parser.parse_args()

    try:
        check_health(
            args.service,
            args.target,
            args.generated_dir,
            args.timeout,
        )
    except Exception as exc:
        print(f"healthcheck failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
