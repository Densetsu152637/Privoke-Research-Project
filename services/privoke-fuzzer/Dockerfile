FROM python:3.11-slim

WORKDIR /workspace

COPY shared/proto /workspace/shared/proto
COPY services/privoke-fuzzer /workspace/services/privoke-fuzzer

WORKDIR /workspace/services/privoke-fuzzer

RUN pip install --no-cache-dir -r requirements.txt \
    && mkdir -p generated \
    && python -m grpc_tools.protoc \
      -I /workspace/shared/proto \
      --python_out=/workspace/services/privoke-fuzzer/generated \
      --grpc_python_out=/workspace/services/privoke-fuzzer/generated \
      /workspace/shared/proto/privoke/v1/parameters.proto

CMD ["python", "app/main.py"]
