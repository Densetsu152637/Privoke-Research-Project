FROM python:3.11-slim

WORKDIR /workspace

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

COPY shared /workspace/shared
COPY extension/client-runtime /workspace/extension/client-runtime

WORKDIR /workspace/extension/client-runtime

ENV PRIVOKE_GRPC_HOST=0.0.0.0

RUN pip install --no-cache-dir -r requirements.txt /workspace/shared/python \
    && mkdir -p generated \
    && python -m grpc_tools.protoc \
      -I /workspace/shared/proto \
      --python_out=/workspace/extension/client-runtime/generated \
      --grpc_python_out=/workspace/extension/client-runtime/generated \
      /workspace/shared/proto/privoke/v1/parameters.proto \
      /workspace/shared/proto/privoke/v1/runtime.proto \
      /workspace/shared/proto/privoke/v1/telemetry.proto

EXPOSE 50054

CMD ["python", "src/grpc_main.py"]
