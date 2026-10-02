"""gRPC orchestration for one bounded fuzzer training cycle."""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass

import grpc
from config import FuzzerConfig
from privoke.v1 import parameters_pb2, parameters_pb2_grpc
from privoke_service import validate_text
from prompt_generation import generate_training_prompts
from runtime_client import PrivokeRuntimeClient, RuntimeAnalysisError
from training import emit_training_update, train_parameter_batch
from training.types import BatchTrainingUpdate

LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class TrainingCycle:
    requested_prompt_count: int
    prompt_count: int
    model_id: str
    seed: int


class FuzzerTrainingService(parameters_pb2_grpc.FuzzerServiceServicer):
    def __init__(self, config: FuzzerConfig):
        self.config = config
        self._cycle_slots = threading.BoundedSemaphore(
            value=config.max_concurrent_cycles
        )

    def RunTrainingCycle(self, request, context):
        try:
            validate_training_request(request, self.config.model_id)
        except ValueError as exc:
            context.abort(grpc.StatusCode.INVALID_ARGUMENT, str(exc))
        if not self._cycle_slots.acquire(blocking=False):
            context.abort(
                grpc.StatusCode.RESOURCE_EXHAUSTED,
                "The maximum number of concurrent training cycles is already running.",
            )
        try:
            return self._run_training_cycle(request, context)
        finally:
            self._cycle_slots.release()

    def _run_training_cycle(self, request, context):
        cycle = _resolve_cycle(request, self.config)
        _log_cycle_started(request, cycle)
        examples = generate_training_prompts(
            count=cycle.prompt_count,
            seed=cycle.seed,
            dataset_path=self.config.prompt_dataset_path,
        )
        update = self._train(cycle.model_id, examples, cycle.seed, context)
        if not context.is_active():
            context.abort(
                grpc.StatusCode.CANCELLED,
                "Training request was cancelled before update submission.",
            )
        ack = self._submit_update(request, cycle, update, len(examples), context)
        LOGGER.info(
            "completed training request id=%r accepted=%s version=%r prompts=%s",
            request.request_id,
            ack.accepted,
            ack.applied_version,
            len(examples),
        )
        return build_training_response(ack, update, len(examples))

    def _train(self, model_id, examples, seed: int, context) -> BatchTrainingUpdate:
        try:
            return train_parameter_batch(
                model_id=model_id,
                new_examples=examples,
                config=self.config.batch_training_config(seed),
                runtime_client=PrivokeRuntimeClient(
                    self.config.privoke_runtime_target,
                    timeout_seconds=self.config.timeout_seconds,
                ),
            )
        except (RuntimeAnalysisError, grpc.RpcError) as exc:
            LOGGER.warning("client runtime semantic training failed: %s", exc)
            context.abort(
                grpc.StatusCode.UNAVAILABLE,
                "Client runtime training evaluation is unavailable.",
            )

    def _submit_update(
        self,
        request,
        cycle: TrainingCycle,
        update: BatchTrainingUpdate,
        generated_count: int,
        context,
    ):
        try:
            return emit_training_update(
                target=self.config.param_update_target,
                source_id=self.config.fuzzer_id,
                update=update,
                extra_metadata={
                    "request_id": request.request_id,
                    "request_source_id": request.source_id,
                    "requested_prompt_count": str(cycle.requested_prompt_count),
                    "generated_prompt_count": str(generated_count),
                    "training_pipeline": "client_runtime_semantic_gradients",
                },
                timeout_seconds=self.config.timeout_seconds,
            )
        except grpc.RpcError as exc:
            LOGGER.warning(
                "parameter update submission failed code=%s",
                exc.code(),
            )
            context.abort(
                grpc.StatusCode.UNAVAILABLE,
                "Parameter update service is unavailable.",
            )

    def Health(self, request, context):
        return parameters_pb2.HealthResponse(
            service="privoke-fuzzer",
            status="SERVING",
        )


def validate_training_request(request, expected_model_id: str) -> None:
    validate_text(request.request_id, "request_id", required=True)
    validate_text(request.source_id, "source_id", required=True)
    validate_text(request.model_id, "model_id", required=False)
    if request.model_id and request.model_id != expected_model_id:
        raise ValueError(f"model_id must be {expected_model_id!r}.")
    if request.prompt_count <= 0:
        raise ValueError("prompt_count must be greater than zero.")
    if len(request.metadata) > 64:
        raise ValueError("metadata may contain at most 64 entries.")
    for key, value in request.metadata.items():
        validate_text(key, "metadata key", required=True, limit=128)
        validate_text(value, "metadata value", required=False, limit=2_048)


def _resolve_cycle(request, config: FuzzerConfig) -> TrainingCycle:
    requested_count = int(request.prompt_count)
    prompt_count = min(requested_count, config.max_prompt_count)
    if prompt_count < requested_count:
        LOGGER.info(
            "capped training prompt count requested=%s max=%s",
            requested_count,
            config.max_prompt_count,
        )
    return TrainingCycle(
        requested_prompt_count=requested_count,
        prompt_count=prompt_count,
        model_id=request.model_id or config.model_id,
        seed=int(request.seed) if request.seed else config.seed,
    )


def _log_cycle_started(request, cycle: TrainingCycle) -> None:
    LOGGER.info(
        "received training request id=%r source=%r model=%r prompts=%s",
        request.request_id,
        request.source_id,
        cycle.model_id,
        cycle.prompt_count,
    )


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
