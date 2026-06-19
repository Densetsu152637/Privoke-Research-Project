from __future__ import annotations

import logging
import os
import signal
import sys
import time
from concurrent import futures
from pathlib import Path

import grpc

from prompt_generation import generate_training_prompts
from training import BatchTrainingConfig, emit_training_update, train_parameter_batch


GENERATED_DIR = Path(__file__).resolve().parents[1] / "generated"
if str(GENERATED_DIR) not in sys.path:
    sys.path.insert(0, str(GENERATED_DIR))

from privoke.v1 import parameters_pb2, parameters_pb2_grpc


logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

_SHOULD_STOP = False


class FuzzerTrainingService(parameters_pb2_grpc.FuzzerServiceServicer):
    def __init__(self, config: "FuzzerConfig"):
        self.config = config

    def RunTrainingCycle(self, request, context):
        prompt_count = int(request.prompt_count)
        if prompt_count <= 0:
            context.abort(
                grpc.StatusCode.INVALID_ARGUMENT,
                "prompt_count must be greater than zero.",
            )
        if prompt_count > self.config.max_prompt_count:
            context.abort(
                grpc.StatusCode.INVALID_ARGUMENT,
                f"prompt_count must be <= {self.config.max_prompt_count}.",
            )

        model_id = request.model_id or self.config.model_id
        seed = int(request.seed) if request.seed else self.config.seed
        logging.info(
            "received training request id=%s source=%s model=%s prompts=%s",
            request.request_id,
            request.source_id,
            model_id,
            prompt_count,
        )

        snapshot = fetch_snapshot(self.config, model_id=model_id)
        examples = generate_training_prompts(
            count=prompt_count,
            seed=seed,
            dataset_path=self.config.prompt_dataset_path,
        )
        update = train_parameter_batch(
            snapshot=snapshot,
            new_examples=examples,
            config=self.config.batch_training_config(seed),
        )
        ack = emit_training_update(
            target=self.config.param_update_target,
            source_id=self.config.fuzzer_id,
            update=update,
            extra_metadata={
                "request_id": request.request_id,
                "request_source_id": request.source_id,
                "requested_prompt_count": str(prompt_count),
                "generated_prompt_count": str(len(examples)),
                "training_pipeline": "streamed_llm_only",
            },
            timeout_seconds=self.config.timeout_seconds,
        )

        logging.info(
            "completed training request id=%s accepted=%s version=%s prompts=%s",
            request.request_id,
            ack.accepted,
            ack.applied_version,
            len(examples),
        )

        response_metadata = dict(update.metadata)
        response_metadata.update(
            {
                key: str(value)
                for key, value in update.metrics.items()
            }
        )
        return parameters_pb2.FuzzerTrainingResponse(
            accepted=ack.accepted,
            model_id=ack.model_id,
            base_version=update.base_version,
            applied_version=ack.applied_version,
            prompts_generated=len(examples),
            message=ack.message,
            metadata=response_metadata,
        )

    def Health(self, request, context):
        return parameters_pb2.HealthResponse(
            service="privoke-fuzzer",
            status="SERVING",
        )


class FuzzerConfig:
    def __init__(
        self,
        model_streaming_target: str,
        param_update_target: str,
        model_id: str,
        fuzzer_id: str,
        port: int,
        timeout_seconds: float,
        seed: int,
        max_prompt_count: int,
        prompt_dataset_path: str | None,
        training_learning_rate: float,
        training_max_gradient: float,
        training_transformations_per_example: int,
    ):
        self.model_streaming_target = model_streaming_target
        self.param_update_target = param_update_target
        self.model_id = model_id
        self.fuzzer_id = fuzzer_id
        self.port = port
        self.timeout_seconds = timeout_seconds
        self.seed = seed
        self.max_prompt_count = max_prompt_count
        self.prompt_dataset_path = prompt_dataset_path
        self.training_learning_rate = training_learning_rate
        self.training_max_gradient = training_max_gradient
        self.training_transformations_per_example = (
            training_transformations_per_example
        )

    @classmethod
    def from_env(cls) -> "FuzzerConfig":
        return cls(
            model_streaming_target=os.getenv(
                "MODEL_STREAMING_TARGET",
                "model-streaming-service:50051",
            ),
            param_update_target=os.getenv(
                "PARAM_UPDATE_TARGET",
                "param-update-service:50052",
            ),
            model_id=os.getenv("MODEL_ID", "privoke-baseline"),
            fuzzer_id=os.getenv("FUZZER_ID", "privoke-fuzzer"),
            port=_env_int("FUZZER_PORT", 50053),
            timeout_seconds=_env_float("FUZZ_TIMEOUT_SECONDS", 10.0),
            seed=_env_int("FUZZ_SEED", 1337),
            max_prompt_count=_env_int("FUZZ_MAX_PROMPT_COUNT", 256),
            prompt_dataset_path=os.getenv("FUZZ_PROMPT_DATASET_PATH"),
            training_learning_rate=_env_float("FUZZ_TRAINING_LEARNING_RATE", 0.03),
            training_max_gradient=_env_float("FUZZ_TRAINING_MAX_GRADIENT", 0.05),
            training_transformations_per_example=_env_int(
                "FUZZ_TRAINING_TRANSFORMS_PER_EXAMPLE",
                1,
            ),
        )

    def batch_training_config(self, seed: int) -> BatchTrainingConfig:
        return BatchTrainingConfig(
            learning_rate=self.training_learning_rate,
            max_gradient=self.training_max_gradient,
            transformations_per_example=self.training_transformations_per_example,
            seed=seed,
        )


def main() -> None:
    global _SHOULD_STOP

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)

    config = FuzzerConfig.from_env()
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=8))
    parameters_pb2_grpc.add_FuzzerServiceServicer_to_server(
        FuzzerTrainingService(config),
        server,
    )
    server.add_insecure_port(f"[::]:{config.port}")
    server.start()
    logging.info(
        "privoke-fuzzer awaiting training requests port=%s model=%s",
        config.port,
        config.model_id,
    )

    try:
        while not _SHOULD_STOP:
            time.sleep(0.25)
    finally:
        server.stop(5).wait()


def fetch_snapshot(config: FuzzerConfig, model_id: str):
    with grpc.insecure_channel(config.model_streaming_target) as channel:
        client = parameters_pb2_grpc.ModelStreamingServiceStub(channel)
        return client.GetModelParameters(
            parameters_pb2.ModelParametersRequest(
                consumer_id=config.fuzzer_id,
                model_id=model_id,
            ),
            timeout=config.timeout_seconds,
        )


def _stop(signum, frame) -> None:
    global _SHOULD_STOP
    _SHOULD_STOP = True


def _env_float(name: str, default: float) -> float:
    raw_value = os.getenv(name)
    if raw_value is None:
        return default
    try:
        return float(raw_value)
    except ValueError as exc:
        raise ValueError(f"{name} must be a number.") from exc


def _env_int(name: str, default: int) -> int:
    raw_value = os.getenv(name)
    if raw_value is None:
        return default
    try:
        return int(raw_value)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer.") from exc


if __name__ == "__main__":
    main()
