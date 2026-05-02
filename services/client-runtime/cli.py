import argparse
import json
import sys
from pathlib import Path

import grpc

from main import run_full_pipeline

GENERATED_DIR = Path(__file__).resolve().parent / "generated"
if str(GENERATED_DIR) not in sys.path:
    sys.path.insert(0, str(GENERATED_DIR))

from privoke.v1 import parameters_pb2, parameters_pb2_grpc

def fetch_parameters(args) -> None:
    with grpc.insecure_channel(args.target) as channel:
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
            {"name": parameter.name, "values": list(parameter.values)}
            for parameter in snapshot.parameters
        ],
        "metadata": dict(snapshot.metadata),
    }
    print(json.dumps(payload, indent=2))


def main() -> None:
    parser = argparse.ArgumentParser(description="PriVoke client runtime CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    pipeline_parser = subparsers.add_parser("pipeline", help="Run the privacy pipeline sample.")
    pipeline_parser.set_defaults(handler=lambda args: run_full_pipeline())

    params_parser = subparsers.add_parser(
        "fetch-params",
        help="Fetch model parameters from the model-streaming-service over gRPC.",
    )
    params_parser.add_argument("--target", default="model-streaming-service:50051")
    params_parser.add_argument("--consumer-id", default="client-runtime")
    params_parser.add_argument("--model-id", default="privoke-baseline")
    params_parser.add_argument("--timeout", type=int, default=10)
    params_parser.set_defaults(handler=fetch_parameters)

    args = parser.parse_args()
    args.handler(args)


if __name__ == "__main__":
    main()
