FROM python:3.11-slim

WORKDIR /workspace

COPY shared/proto /workspace/shared/proto
COPY services/telemetry-service /workspace/services/telemetry-service

WORKDIR /workspace/services/telemetry-service

RUN pip install --no-cache-dir -r requirements.txt \
    && mkdir -p generated \
    && python -m grpc_tools.protoc \
      -I /workspace/shared/proto \
      --python_out=/workspace/services/telemetry-service/generated \
      --grpc_python_out=/workspace/services/telemetry-service/generated \
      /workspace/shared/proto/privoke/v1/telemetry.proto

EXPOSE 50055

CMD ["python", "app/server.py"]
