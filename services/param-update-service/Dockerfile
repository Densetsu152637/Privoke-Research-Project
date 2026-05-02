FROM python:3.11-slim

WORKDIR /workspace

RUN apt-get update \
    && apt-get install -y --no-install-recommends protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

COPY shared/proto /workspace/shared/proto
COPY services/param-update-service /workspace/services/param-update-service

WORKDIR /workspace/services/param-update-service

RUN pip install --no-cache-dir -r requirements.txt \
    && mkdir -p generated \
    && python -m grpc_tools.protoc \
      -I /workspace/shared/proto \
      --python_out=/workspace/services/param-update-service/generated \
      --grpc_python_out=/workspace/services/param-update-service/generated \
      /workspace/shared/proto/privoke/v1/parameters.proto

EXPOSE 50052

CMD ["python", "app/server.py"]
