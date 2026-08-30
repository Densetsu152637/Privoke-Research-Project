import argparse
import json
import sys
import time
import uuid
from pathlib import Path

GENERATED_DIR = Path(__file__).resolve().parents[1] / "generated"
if str(GENERATED_DIR) not in sys.path:
    sys.path.insert(0, str(GENERATED_DIR))

from prompt_testing import add_test_prompt_args, run_prompt_tests

def fetch_parameters(args) -> None:
    import grpc

    from privoke.v1 import parameters_pb2, parameters_pb2_grpc

    with grpc.insecure_channel(
        args.target,
        options=(("grpc.max_receive_message_length", 8 * 1024 * 1024),),
    ) as channel:
        client = parameters_pb2_grpc.ModelStreamingServiceStub(channel)
        snapshot = client.GetModelParameters(
            parameters_pb2.ModelParametersRequest(
                consumer_id=args.consumer_id,
                model_id=args.model_id,
            ),
            timeout=args.timeout,
        )

    payload = {
        "model_id": snapshot.model_id,
        "version": snapshot.version,
        "generated_at_unix": snapshot.generated_at_unix,
        "parameter_count": len(snapshot.parameters),
        "parameters": [
            {
                "name": parameter.name,
                "shape": list(parameter.shape),
                "values": list(parameter.values),
            }
            for parameter in snapshot.parameters
        ],
        "metadata": dict(snapshot.metadata),
    }
    print(json.dumps(payload, indent=2))


def run_training_cycle(args) -> None:
    import grpc

    from privoke.v1 import parameters_pb2, parameters_pb2_grpc

    request_id = args.request_id or f"privoke-cli-{int(time.time())}-{uuid.uuid4().hex[:8]}"
    with grpc.insecure_channel(args.target) as channel:
        response = parameters_pb2_grpc.FuzzerServiceStub(channel).RunTrainingCycle(
            parameters_pb2.FuzzerTrainingRequest(
                request_id=request_id,
                source_id=args.source_id,
                model_id=args.model_id,
                prompt_count=args.prompt_count,
                seed=args.seed,
                metadata={"initiator": "privoke-fuzzer-cli"},
            ),
            timeout=args.timeout,
        )
    print(
        json.dumps(
            {
                "accepted": response.accepted,
                "model_id": response.model_id,
                "base_version": response.base_version,
                "applied_version": response.applied_version,
                "prompts_generated": response.prompts_generated,
                "message": response.message,
                "metadata": dict(response.metadata),
            },
            indent=2,
            sort_keys=True,
        )
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="PriVoke fuzzer CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    params_parser = subparsers.add_parser(
        "fetch-params",
        help="Fetch model parameters from the model-streaming-service over gRPC.",
    )
    params_parser.add_argument("--target", default="model-streaming-service:50051")
    params_parser.add_argument("--consumer-id", default="privoke-fuzzer")
    params_parser.add_argument("--model-id", default="privoke-baseline")
    params_parser.add_argument("--timeout", type=int, default=10)
    params_parser.set_defaults(handler=fetch_parameters)

    train_parser = subparsers.add_parser(
        "train",
        help="Request a fuzzer training cycle and persist the resulting model version.",
    )
    train_parser.add_argument("--target", default="privoke-fuzzer:50053")
    train_parser.add_argument("--model-id", default="privoke-baseline")
    train_parser.add_argument("--source-id", default="privoke-fuzzer-cli")
    train_parser.add_argument("--request-id")
    train_parser.add_argument("--prompt-count", type=int, default=8)
    train_parser.add_argument("--seed", type=int, default=1337)
    train_parser.add_argument("--timeout", type=float, default=60.0)
    train_parser.set_defaults(handler=run_training_cycle)

    test_parser = subparsers.add_parser(
        "test-prompts",
        help="Run prompt tests against selected detection layers.",
    )
    add_test_prompt_args(test_parser)
    test_parser.set_defaults(handler=run_prompt_tests)

    args = parser.parse_args()
    args.handler(args)


if __name__ == "__main__":
    main()
