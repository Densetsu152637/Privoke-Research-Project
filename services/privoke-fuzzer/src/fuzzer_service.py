from __future__ import annotations

import logging

import grpc

from config import FuzzerConfig
from prompt_generation import generate_training_prompts
from training import emit_training_update, train_parameter_batch

from privoke.v1 import parameters_pb2, parameters_pb2_grpc


class FuzzerTrainingService(parameters_pb2_grpc.FuzzerServiceServicer):
    def __init__(self, config: FuzzerConfig):
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
        return build_training_response(ack, update, len(examples))

    def Health(self, request, context):
        return parameters_pb2.HealthResponse(
            service="privoke-fuzzer",
            status="SERVING",
        )


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


def build_training_response(ack, update, prompts_generated: int):
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
