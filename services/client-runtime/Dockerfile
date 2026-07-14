FROM python:3.11-slim

WORKDIR /workspace

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

COPY shared /workspace/shared
COPY services/client-runtime /workspace/services/client-runtime

WORKDIR /workspace/services/client-runtime

RUN pip install --no-cache-dir -r requirements.txt /workspace/shared/python \
    && mkdir -p generated \
    && python -m grpc_tools.protoc \
      -I /workspace/shared/proto \
      --python_out=/workspace/services/client-runtime/generated \
      --grpc_python_out=/workspace/services/client-runtime/generated \
      /workspace/shared/proto/privoke/v1/parameters.proto \
      /workspace/shared/proto/privoke/v1/runtime.proto \
      /workspace/shared/proto/privoke/v1/telemetry.proto

EXPOSE 50054

CMD ["python", "src/grpc_main.py"]
