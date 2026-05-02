FROM python:3.11-slim

WORKDIR /workspace

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

COPY shared/proto /workspace/shared/proto
COPY services/client-runtime /workspace/services/client-runtime

WORKDIR /workspace/services/client-runtime

RUN pip install --no-cache-dir -r requirements.txt \
    && mkdir -p generated \
    && python -m grpc_tools.protoc \
      -I /workspace/shared/proto \
      --python_out=/workspace/services/client-runtime/generated \
      --grpc_python_out=/workspace/services/client-runtime/generated \
      /workspace/shared/proto/privoke/v1/parameters.proto

CMD ["python", "cli.py", "pipeline"]
