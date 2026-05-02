import json
import logging
import os
import sys
from concurrent import futures
from pathlib import Path

import grpc

GENERATED_DIR = Path(__file__).resolve().parents[1] / "generated"
if str(GENERATED_DIR) not in sys.path:
    sys.path.insert(0, str(GENERATED_DIR))

from privoke.v1 import parameters_pb2, parameters_pb2_grpc

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

class ParamUpdateService(parameters_pb2_grpc.ParamUpdateServiceServicer):
    def __init__(self, storage_path: Path):
        self.storage_path = storage_path
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)

    def submitParameterUpdate(self, request, context):
        payload = {
            "source_id": request.source_id,
            "model_id": request.model_id,
            "base_version": request.base_version,
            "gradients": [
                {"name": gradient.name, "values": list(gradient.values)}
                for gradient in request.gradients
            ],
            "metadata": dict(request.metadata),
        }

        with self.storage_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload) + "\n")

        logging.info(
            "accepted parameter update source=%s model=%s gradients=%d",
            request.source_id,
            request.model_id,
            len(request.gradients),
        )

        return parameters_pb2.ParameterUpdateAck(
            accepted=True,
            model_id=request.model_id,
            applied_version=f"{request.base_version}-updated",
            message="Parameter update persisted for downstream training.",
        )

    def health(self, request, context):
        return parameters_pb2.HealthResponse(
            service="param-update-service",
            status="SERVING",
        )


def serve() -> None:
    port = os.getenv("PARAM_UPDATE_PORT", "50052")
    storage_path = Path(os.getenv("PARAM_UPDATE_STORAGE_PATH", "/tmp/updates.jsonl"))

    server = grpc.server(futures.ThreadPoolExecutor(max_workers=8))
    parameters_pb2_grpc.add_ParamUpdateServiceServicer_to_server(
        ParamUpdateService(storage_path), server
    )
    server.add_insecure_port(f"[::]:{port}")
    server.start()
    logging.info("param-update-service listening on %s", port)
    server.wait_for_termination()


if __name__ == "__main__":
    serve()
