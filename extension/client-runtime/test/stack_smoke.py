"""Exercise the running Compose topology through its public gRPC contracts.

Run this from the production client-runtime container so that the test uses
the same Docker network and generated protobuf bindings as the deployed
runtime:

    docker compose exec -T client-runtime python test/stack_smoke.py
"""

from __future__ import annotations

import argparse
import os
import sys
import time
import uuid
from pathlib import Path

import grpc


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
GENERATED_DIR = PACKAGE_ROOT / "generated"
if str(GENERATED_DIR) not in sys.path:
    sys.path.insert(0, str(GENERATED_DIR))

from privoke.v1 import (  # noqa: E402
    parameters_pb2,
    parameters_pb2_grpc,
    runtime_pb2,
    runtime_pb2_grpc,
    telemetry_pb2,
    telemetry_pb2_grpc,
)


RPC_TIMEOUT_SECONDS = float(os.getenv("CI_RPC_TIMEOUT_SECONDS", "15"))
MODEL_ID = os.getenv("MODEL_ID", "privoke-baseline")
TARGETS = {
    "model": os.getenv("MODEL_STREAMING_TARGET", "model-streaming-service:50051"),
    "updates": os.getenv("PARAM_UPDATE_TARGET", "param-update-service:50052"),
    "fuzzer": os.getenv("FUZZER_TARGET", "privoke-fuzzer:50053"),
    "runtime": os.getenv("PRIVOKE_RUNTIME_TARGET", "client-runtime:50054"),
    "telemetry": os.getenv("TELEMETRY_TARGET", "telemetry-service:50055"),
}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--skip-training",
        action="store_true",
        help="Skip the fuzzer cycle while retaining health/runtime/telemetry checks.",
    )
    args = parser.parse_args()

    check_health_endpoints()
    check_model_snapshot()
    request_id = check_runtime_analysis()
    check_runtime_telemetry(request_id)
    if not args.skip_training:
        check_fuzzer_training_cycle()
    check_health_endpoints(rounds=3)
    print("Live stack smoke test passed.", flush=True)


def check_health_endpoints(rounds: int = 1) -> None:
    checks = (
        (
            "model-streaming-service",
            TARGETS["model"],
            parameters_pb2_grpc.ModelStreamingServiceStub,
            parameters_pb2.HealthRequest,
        ),
        (
            "param-update-service",
            TARGETS["updates"],
            parameters_pb2_grpc.ParamUpdateServiceStub,
            parameters_pb2.HealthRequest,
        ),
        (
            "privoke-fuzzer",
            TARGETS["fuzzer"],
            parameters_pb2_grpc.FuzzerServiceStub,
            parameters_pb2.HealthRequest,
        ),
        (
            "client-runtime",
            TARGETS["runtime"],
            runtime_pb2_grpc.PrivokeRuntimeServiceStub,
            runtime_pb2.RuntimeHealthRequest,
        ),
        (
            "telemetry-service",
            TARGETS["telemetry"],
            telemetry_pb2_grpc.TelemetryServiceStub,
            telemetry_pb2.TelemetryHealthRequest,
        ),
    )
    for _ in range(rounds):
        for expected_service, target, stub_type, request_type in checks:
            with grpc.insecure_channel(target) as channel:
                response = stub_type(channel).Health(
                    request_type(),
                    timeout=RPC_TIMEOUT_SECONDS,
                )
            require(response.status == "SERVING", f"{target} is not SERVING")
            require(
                response.service == expected_service,
                f"{target} returned unexpected service name {response.service!r}",
            )
        time.sleep(0.2)
    print(f"Health RPCs passed for all services ({rounds} round(s)).", flush=True)


def check_model_snapshot() -> None:
    with grpc.insecure_channel(TARGETS["model"]) as channel:
        chunks = list(parameters_pb2_grpc.ModelStreamingServiceStub(
            channel
        ).StreamModelParameters(
            parameters_pb2.ModelParametersRequest(
                consumer_id="github-actions-smoke-test",
                model_id=MODEL_ID,
            ),
            timeout=RPC_TIMEOUT_SECONDS,
        ))
    require(bool(chunks), "model parameter stream was empty")
    require(chunks[0].model_id == MODEL_ID, "model snapshot ID did not match")
    require(bool(chunks[0].version), "model snapshot has no version")
    require(
        all(chunk.chunk_index == index for index, chunk in enumerate(chunks)),
        "model parameter chunks were out of order",
    )
    require(
        chunks[0].total_chunks == len(chunks),
        "model parameter stream was incomplete",
    )
    require(
        all(chunk.parameter.name and chunk.parameter.shape for chunk in chunks),
        "model parameter chunks did not include tensor shapes",
    )
    require(
        chunks[0].metadata.get("served_by") == "model-streaming-service",
        "model snapshot provenance metadata is missing",
    )
    print("Parameter streaming check passed.", flush=True)


def check_runtime_analysis() -> str:
    request_id = f"ci-runtime-{uuid.uuid4().hex}"
    with grpc.insecure_channel(TARGETS["runtime"]) as channel:
        response = runtime_pb2_grpc.PrivokeRuntimeServiceStub(channel).AnalyzePrompt(
            runtime_pb2.AnalyzePromptRequest(
                text="I was diagnosed with cancer and take prescription medication.",
                source="github-actions",
                target_app="simulated-client",
                request_id=request_id,
                layers=[runtime_pb2.DETECTION_LAYER_SEMANTIC],
                semantic_model_id=MODEL_ID,
            ),
            timeout=RPC_TIMEOUT_SECONDS,
        )
    require(not response.error, f"runtime analysis failed: {response.error}")
    require(response.request_id == request_id, "runtime request ID was not preserved")
    require(response.action in {"WARN", "BLOCK"}, "sensitive prompt was not protected")
    require(len(response.layers) == 1, "runtime did not return one semantic layer")
    require(response.layers[0].status == "ok", "semantic layer did not complete")
    require(bool(response.layers[0].results), "semantic layer returned no evidence")
    evidence = response.layers[0].results[0]
    require(
        evidence.metadata.get("model_id") == MODEL_ID,
        "runtime did not use the streamed model snapshot",
    )
    print(f"Simulated client-runtime request returned {response.action}.", flush=True)
    return request_id


def check_runtime_telemetry(request_id: str) -> None:
    deadline = time.monotonic() + RPC_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        with grpc.insecure_channel(TARGETS["telemetry"]) as channel:
            response = telemetry_pb2_grpc.TelemetryServiceStub(channel).ListTelemetry(
                telemetry_pb2.ListTelemetryRequest(limit=100),
                timeout=RPC_TIMEOUT_SECONDS,
            )
        matching = [
            stored.packet
            for stored in response.packets
            if stored.packet.request_id == request_id
        ]
        if matching:
            packet = matching[0]
            require(packet.source_id == "server-client-runtime", "wrong telemetry source")
            require(packet.target_app == "simulated-client", "wrong telemetry target")
            require(packet.text_length > 0, "telemetry text length was not recorded")
            print("Runtime-to-telemetry check passed.", flush=True)
            return
        time.sleep(0.25)
    raise AssertionError(f"telemetry event for {request_id} was not persisted")


def check_fuzzer_training_cycle() -> None:
    request = parameters_pb2.FuzzerTrainingRequest(
        request_id=f"ci-fuzzer-{uuid.uuid4().hex}",
        source_id="github-actions-smoke-test",
        model_id=MODEL_ID,
        prompt_count=2,
        seed=2026,
        metadata={"purpose": "cross-service-integration"},
    )
    deadline = time.monotonic() + max(60.0, RPC_TIMEOUT_SECONDS * 4)
    while True:
        try:
            with grpc.insecure_channel(TARGETS["fuzzer"]) as channel:
                response = parameters_pb2_grpc.FuzzerServiceStub(
                    channel
                ).RunTrainingCycle(
                    request,
                    timeout=max(60.0, RPC_TIMEOUT_SECONDS * 4),
                )
            break
        except grpc.RpcError as exc:
            if (
                exc.code() == grpc.StatusCode.RESOURCE_EXHAUSTED
                and time.monotonic() < deadline
            ):
                time.sleep(1)
                continue
            raise
    require(response.accepted, f"fuzzer cycle was rejected: {response.message}")
    require(response.model_id == MODEL_ID, "fuzzer used an unexpected model")
    require(response.prompts_generated == 2, "fuzzer generated an unexpected prompt count")
    require(bool(response.base_version), "fuzzer response has no base version")
    require(bool(response.applied_version), "parameter update was not applied")
    print("Fuzzer cross-service training cycle passed.", flush=True)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


if __name__ == "__main__":
    main()
