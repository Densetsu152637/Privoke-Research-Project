from __future__ import annotations

import logging
import time

import grpc

from config import FuzzerConfig
from prompt_generation import generate_training_prompts
from training import emit_training_update, train_parameter_batch
from training.protocols import StreamedParameterSnapshot
from training.types import BatchTrainingUpdate
from runtime_client import PrivokeRuntimeClient

from privoke.v1 import parameters_pb2, parameters_pb2_grpc


class ModelSnapshotUnavailable(RuntimeError):
    pass


class FuzzerTrainingService(parameters_pb2_grpc.FuzzerServiceServicer):
    def __init__(self, config: FuzzerConfig):
        self.config = config

    def RunTrainingCycle(self, request, context):
        requested_prompt_count = int(request.prompt_count)
        if requested_prompt_count <= 0:
            context.abort(
                grpc.StatusCode.INVALID_ARGUMENT,
                "prompt_count must be greater than zero.",
            )
        prompt_count = min(requested_prompt_count, self.config.max_prompt_count)
        if prompt_count < requested_prompt_count:
            logging.info(
                "capped training prompt count requested=%s max=%s",
                requested_prompt_count,
                self.config.max_prompt_count,
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

        try:
            snapshot = fetch_snapshot(self.config, model_id=model_id)
        except ModelSnapshotUnavailable as exc:
            context.abort(grpc.StatusCode.UNAVAILABLE, str(exc))

        examples = generate_training_prompts(
            count=prompt_count,
            seed=seed,
            dataset_path=self.config.prompt_dataset_path,
        )
        update = train_parameter_batch(
            snapshot=snapshot,
            new_examples=examples,
            config=self.config.batch_training_config(seed),
            runtime_client=PrivokeRuntimeClient(
                self.config.privoke_runtime_target,
                timeout_seconds=self.config.timeout_seconds,
            ),
        )
        ack = emit_training_update(
            target=self.config.param_update_target,
            source_id=self.config.fuzzer_id,
            update=update,
            extra_metadata={
                "request_id": request.request_id,
                "request_source_id": request.source_id,
                "requested_prompt_count": str(requested_prompt_count),
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
        return build_training_response(ack, update, len(examples))

    def Health(self, request, context):
        return parameters_pb2.HealthResponse(
            service="privoke-fuzzer",
            status="SERVING",
        )


def fetch_snapshot(config: FuzzerConfig, model_id: str) -> StreamedParameterSnapshot:
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

        if attempt >= attempts:
            break

        delay_seconds = _retry_delay(config, attempt)
        logging.warning(
            "model snapshot fetch failed attempt=%s/%s target=%s: %s; "
            "retrying in %.1fs",
            attempt,
            attempts,
            config.model_streaming_target,
            last_error_message,
            delay_seconds,
        )
        time.sleep(delay_seconds)

    raise ModelSnapshotUnavailable(
        "model-streaming-service was unavailable after "
        f"{attempts} attempts at {config.model_streaming_target}: "
        f"{last_error_message}"
    )


def _fetch_snapshot_once(
    config: FuzzerConfig,
    model_id: str,
) -> StreamedParameterSnapshot:
    with grpc.insecure_channel(config.model_streaming_target) as channel:
        grpc.channel_ready_future(channel).result(
            timeout=max(0.1, config.model_streaming_connect_timeout_seconds)
        )
        client = parameters_pb2_grpc.ModelStreamingServiceStub(channel)
        return client.GetModelParameters(
            parameters_pb2.ModelParametersRequest(
                consumer_id=config.fuzzer_id,
                model_id=model_id,
            ),
            timeout=config.timeout_seconds,
        )


def _is_retryable_rpc_error(exc: grpc.RpcError) -> bool:
    try:
        code = exc.code()
    except AttributeError:
        return False

    return code in {
        grpc.StatusCode.UNAVAILABLE,
        grpc.StatusCode.DEADLINE_EXCEEDED,
    }


def _snapshot_error_message(exc: Exception, config: FuzzerConfig) -> str:
    if isinstance(exc, grpc.FutureTimeoutError):
        return (
            "channel was not ready within "
            f"{config.model_streaming_connect_timeout_seconds:.1f}s"
        )

    if isinstance(exc, grpc.RpcError):
        try:
            code = exc.code()
        except AttributeError:
            code = None
        try:
            details = exc.details()
        except AttributeError:
            details = None
        if details:
            return f"{code}: {details}"
        return str(code)

    return str(exc) or exc.__class__.__name__


def _retry_delay(config: FuzzerConfig, failed_attempt: int) -> float:
    initial = max(0.1, config.model_streaming_retry_initial_seconds)
    maximum = max(initial, config.model_streaming_retry_max_seconds)
    return min(maximum, initial * (2 ** (failed_attempt - 1)))


def build_training_response(
    ack,
    update: BatchTrainingUpdate,
    prompts_generated: int,
):
    response_metadata = dict(update.metadata)
    response_metadata.update({key: str(value) for key, value in update.metrics.items()})
    return parameters_pb2.FuzzerTrainingResponse(
        accepted=ack.accepted,
        model_id=ack.model_id,
        base_version=update.base_version,
        applied_version=ack.applied_version,
        prompts_generated=prompts_generated,
        message=ack.message,
        metadata=response_metadata,
    )
