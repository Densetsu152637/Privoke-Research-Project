FROM python:3.11-slim

WORKDIR /workspace

COPY shared /workspace/shared
COPY services/privoke-fuzzer /workspace/services/privoke-fuzzer

WORKDIR /workspace/services/privoke-fuzzer

ENV PRIVOKE_FUZZER_DUMP_DIR=/workspace/dumps/privoke-fuzzer

RUN pip install --no-cache-dir -r requirements.txt /workspace/shared/python \
    && mkdir -p /workspace/dumps/privoke-fuzzer \
    && mkdir -p generated \
    && python -m grpc_tools.protoc \
      -I /workspace/shared/proto \
      --python_out=/workspace/services/privoke-fuzzer/generated \
      --grpc_python_out=/workspace/services/privoke-fuzzer/generated \
      /workspace/shared/proto/privoke/v1/parameters.proto \
      /workspace/shared/proto/privoke/v1/runtime.proto

EXPOSE 50053

CMD ["python", "src/main.py"]
