"""Exercise running localhost services through their public gRPC contracts.

    python evaluation/run-component-tests.py stack-smoke --skip-training

Explicit *_TARGET variables also support the production CI container network.
"""

from __future__ import annotations

import argparse
import math
import os
import random
import sys
import time
import uuid
from pathlib import Path

import grpc


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
GENERATED_DIR = PACKAGE_ROOT / "generated"
REPO_ROOT = PACKAGE_ROOT.parents[1]
for import_path in (REPO_ROOT / "shared/python", PACKAGE_ROOT, GENERATED_DIR):
    if str(import_path) not in sys.path:
        sys.path.insert(0, str(import_path))

from privoke.v1 import (  # noqa: E402
    parameters_pb2,
    parameters_pb2_grpc,
    runtime_pb2,
    runtime_pb2_grpc,
    telemetry_pb2,
    telemetry_pb2_grpc,
)
from src.telemetry.privacy import DOMAINS, DIMENSIONS, MECHANISM, randomize_report  # noqa: E402


RPC_TIMEOUT_SECONDS = float(os.getenv("CI_RPC_TIMEOUT_SECONDS", "15"))
# Runtime MODEL_ID may be the "latest" alias; training and identity assertions
# need the concrete artifact configured on the fuzzer/update services.
MODEL_ID = os.getenv("SMOKE_MODEL_ID", "privoke-balanced")
TARGETS = {
    "model": os.getenv("MODEL_STREAMING_TARGET", "127.0.0.1:50051"),
    "updates": os.getenv("PARAM_UPDATE_TARGET", "127.0.0.1:50052"),
    "fuzzer": os.getenv("FUZZER_TARGET", "127.0.0.1:50053"),
    "runtime": os.getenv("PRIVOKE_RUNTIME_TARGET", "127.0.0.1:50054"),
    "telemetry": os.getenv("TELEMETRY_TARGET", "127.0.0.1:50055"),
}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--skip-training",
        action="store_true",
        help="Skip the fuzzer cycle while retaining health/runtime/telemetry checks.",
    )
    parser.add_argument("--training-request-id", default=None)
    parser.add_argument("--replay-training", action="store_true")
    args = parser.parse_args()

    check_health_endpoints()
    check_model_snapshot()
    check_runtime_analysis()
    check_runtime_telemetry()
    if not args.skip_training:
        check_fuzzer_training_cycle(args.training_request_id, args.replay_training)
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


def check_model_snapshot():
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
    return chunks


def check_runtime_analysis() -> None:
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


def check_runtime_telemetry() -> None:
    """Exercise protected telemetry aggregation with one controlled synthetic report.

    This deliberately does not correlate a telemetry record to the preceding
    runtime request: reports carry no request IDs, and the client's persistent
    privacy budget may suppress an analysis event.
    """
    true_values = {
        "action": "WARN",
        "risk_bucket": "0.5-0.8",
        "primary_category": "HEALTH",
        "model_version": "v0.3.0",
        "time_bucket": "12-16_UTC",
    }
    epsilon = 1.0
    protected = randomize_report(true_values, epsilon, rng=random.Random(2026))
    packet = telemetry_pb2.TelemetryPacket(
        **protected,
        privacy_mechanism=MECHANISM,
        privacy_epsilon=epsilon,
    )
    with grpc.insecure_channel(TARGETS["telemetry"]) as channel:
        stub = telemetry_pb2_grpc.TelemetryServiceStub(channel)
        before = stub.GetTelemetrySummary(
            telemetry_pb2.GetTelemetrySummaryRequest(),
            timeout=RPC_TIMEOUT_SECONDS,
        )
        result = stub.RecordTelemetry(packet, timeout=RPC_TIMEOUT_SECONDS)
        require(result.accepted, f"protected synthetic report was rejected: {result.message}")
        after = stub.GetTelemetrySummary(
            telemetry_pb2.GetTelemetrySummaryRequest(),
            timeout=RPC_TIMEOUT_SECONDS,
        )

    require(
        after.sample_count >= before.sample_count + 1,
        "aggregate sample count did not include the synthetic report",
    )
    before_counts = _observed_summary_counts(before)
    after_counts = _observed_summary_counts(after)
    require(set(after_counts) == set(DIMENSIONS), "summary dimensions do not match the protected report")
    for dimension in DIMENSIONS:
        require(
            set(after_counts[dimension]) == set(DOMAINS[dimension]),
            f"summary domain changed for {dimension}",
        )
        require(
            after_counts[dimension][protected[dimension]]
            >= before_counts[dimension].get(protected[dimension], 0) + 1,
            f"summary did not count the synthetic noisy {dimension} value",
        )
    for dimension in after.dimensions:
        for value in dimension.values:
            require(
                math.isfinite(value.estimated_count)
                and 0 <= value.estimated_count <= after.sample_count,
                f"summary estimate is outside its possible range for {dimension.dimension}",
            )
    print(
        "Synthetic locally randomized report Record->Summary check passed; "
        "the report was not correlated with the runtime analysis request.",
        flush=True,
    )


def _observed_summary_counts(response) -> dict[str, dict[str, int]]:
    return {
        dimension.dimension: {
            value.value: value.observed_noisy_count
            for value in dimension.values
        }
        for dimension in response.dimensions
    }


def check_fuzzer_training_cycle(request_id=None, replay_only=False) -> None:
    before = check_model_snapshot()
    request = parameters_pb2.FuzzerTrainingRequest(
        request_id=request_id or f"ci-fuzzer-{uuid.uuid4().hex}",
        source_id="github-actions-smoke-test",
        model_id=MODEL_ID,
        prompt_count=32,
        seed=1,
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
    require(response.prompts_generated == 32, "fuzzer generated an unexpected prompt count")
    require(bool(response.base_version), "fuzzer response has no base version")
    require(bool(response.applied_version), "parameter update was not applied")
    after = check_model_snapshot()
    if replay_only:
        require(response.metadata.get("replayed") == "true", "restart lost the committed request")
        require(after[0].version == response.applied_version, "restart replay changed the version")
        require(
            [chunk.SerializeToString(deterministic=True) for chunk in before]
            == [chunk.SerializeToString(deterministic=True) for chunk in after],
            "restart replay mutated the streamed model",
        )
        print("Durable fuzzer replay after service restart passed.", flush=True)
        return
    require(response.base_version == before[0].version, "training did not use the current snapshot")
    require(after[0].version == response.applied_version, "updated version was not streamed")
    require(
        [tuple(chunk.parameter.values) for chunk in before]
        != [tuple(chunk.parameter.values) for chunk in after],
        "training did not change any streamed weights",
    )
    with grpc.insecure_channel(TARGETS["fuzzer"]) as channel:
        replay = parameters_pb2_grpc.FuzzerServiceStub(channel).RunTrainingCycle(
            request, timeout=RPC_TIMEOUT_SECONDS,
        )
    require(replay.accepted and replay.metadata.get("replayed") == "true", "committed request was not replayed")
    require(replay.applied_version == response.applied_version, "retry changed the committed outcome")
    repeated = check_model_snapshot()
    require(
        [chunk.SerializeToString(deterministic=True) for chunk in after]
        == [chunk.SerializeToString(deterministic=True) for chunk in repeated],
        "retry mutated the streamed model",
    )
    print("Fuzzer training publication and idempotent replay passed.", flush=True)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


if __name__ == "__main__":
    main()
