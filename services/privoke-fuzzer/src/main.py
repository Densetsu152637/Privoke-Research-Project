import logging
import os
import random
import sys
import time
from pathlib import Path

import grpc

GENERATED_DIR = Path(__file__).resolve().parents[1] / "generated"
if str(GENERATED_DIR) not in sys.path:
    sys.path.insert(0, str(GENERATED_DIR))

from privoke.v1 import parameters_pb2, parameters_pb2_grpc


logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")


def jitter(values):
    return [round(value + random.uniform(-0.05, 0.05), 6) for value in values]


def run() -> None:
    streaming_target = os.getenv("MODEL_STREAMING_TARGET", "model-streaming-service:50051")
    update_target = os.getenv("PARAM_UPDATE_TARGET", "param-update-service:50052")
    model_id = os.getenv("MODEL_ID", "privoke-baseline")
    fuzzer_id = os.getenv("FUZZER_ID", "server-fuzzer")
    interval = int(os.getenv("FUZZ_INTERVAL_SECONDS", "15"))

    while True:
        try:
            with grpc.insecure_channel(streaming_target) as streaming_channel:
                streaming_client = parameters_pb2_grpc.ModelStreamingServiceStub(streaming_channel)
                snapshot = streaming_client.GetModelParameters(
                    parameters_pb2.ModelParametersRequest(
                        consumer_id=fuzzer_id,
                        model_id=model_id,
                    ),
                    timeout=10,
                )

            gradients = [
                parameters_pb2.Parameter(name=parameter.name, values=jitter(parameter.values))
                for parameter in snapshot.parameters
            ]

            with grpc.insecure_channel(update_target) as update_channel:
                update_client = parameters_pb2_grpc.ParamUpdateServiceStub(update_channel)
                ack = update_client.SubmitParameterUpdate(
                    parameters_pb2.ParameterUpdateRequest(
                        source_id=fuzzer_id,
                        model_id=snapshot.model_id,
                        base_version=snapshot.version,
                        gradients=gradients,
                        metadata={"origin": "privoke-fuzzer"},
                    ),
                    timeout=10,
                )

            logging.info(
                "submitted fuzz update accepted=%s model=%s version=%s",
                ack.accepted,
                ack.model_id,
                ack.applied_version,
            )
        except grpc.RpcError as exc:
            logging.warning("grpc error during fuzz cycle: %s", exc)

        time.sleep(interval)


if __name__ == "__main__":
    run()
