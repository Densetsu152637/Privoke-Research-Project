# PriVoke Runtime Supervisor

This package is the workstation-local control process used by the browser extension. It is deliberately separate from `../client-runtime`, which contains the detector and prompt-analysis implementation.

The supervisor stays running on port `50056` while it starts and stops the detector child on port `50054`. It implements:

- `SetRuntimeEnabled` to start or stop the detector process;
- `Status` to report the detector process state and PID;
- `ModelStreamingHealth` to check the configured parameter-streaming endpoint on demand when the extension enables its LLM layer.

The supervisor and detector start without contacting `model-streaming-service`. The detector is launched from `../client-runtime/src/grpc_main.py` with the supervisor's Python interpreter and inherited environment.

## Local setup

First prepare `../client-runtime` as described in its README. Then, from this directory, install the lightweight control-plane dependencies and generate this process's protobuf bindings:

```bash
cd extension/runtime-supervisor
pip install -r requirements.txt
mkdir generated  # omit when it already exists
python -m grpc_tools.protoc \
  -I ../../shared/proto \
  --python_out=generated \
  --grpc_python_out=generated \
  ../../shared/proto/privoke/v1/parameters.proto \
  ../../shared/proto/privoke/v1/runtime.proto
python src/main.py
```

The process uses these environment variables:

- `PRIVOKE_CONTROL_GRPC_HOST`, default `127.0.0.1`
- `PRIVOKE_CONTROL_GRPC_PORT`, default `50056`
- `PRIVOKE_GRPC_PORT`, detector child port, default `50054`
- `PRIVOKE_RUNTIME_START_ENABLED`, default `true`
- `PRIVOKE_RUNTIME_START_TIMEOUT_SECONDS`, default `30`
- `PRIVOKE_RUNTIME_STOP_TIMEOUT_SECONDS`, default `10`
- `MODEL_STREAMING_TARGET`, default `127.0.0.1:50051`
- `MODEL_STREAMING_HEALTH_TIMEOUT_SECONDS`, default `3`

## Verification

After generating bindings:

```bash
python -m unittest discover -s test -v
```

These tests cover process lifecycle behavior, lazy health checking, successful model-service health responses, and unavailable model-service responses.
