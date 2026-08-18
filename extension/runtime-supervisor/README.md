# PriVoke Runtime Supervisor

This package is the workstation-local control process used by the browser extension. It is deliberately separate from `../client-runtime`, which contains the detector and prompt-analysis implementation.

The supervisor stays running on port `50056` while it starts and stops the detector child on port `50054`. It implements:

- `SetRuntimeEnabled` to start or stop the detector process;
- `Status` to report the detector process state and PID;
- `ModelStreamingHealth` to check the configured parameter-streaming endpoint on demand when the extension enables its LLM layer.

The supervisor and detector start without contacting `model-streaming-service`. The detector is launched from `../client-runtime/src/grpc_main.py` with the supervisor's Python interpreter and inherited environment. The portable WebExtension can start the supervisor through the fixed-purpose native messaging launcher in `src/native_messaging_host.py`.

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

## Extension-initiated startup

WebExtensions cannot directly create operating-system processes. PriVoke uses the browser-standard Native Messaging boundary and supplies installers that generate the browser-family-specific host manifest.

Windows, with automatic default-browser detection:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\install-native-host.ps1 -Browser Auto
```

Use `-Browser OperaGX` for an explicit Opera GX registration. Other values are `Chrome`, `Edge`, `Chromium`, `Firefox`, and `All`.

Linux or macOS:

```bash
sh ./scripts/install-native-host.sh auto
```

The Windows installer places a compiled binary stream proxy and host files under `%LOCALAPPDATA%\PriVoke\NativeHost`. The POSIX installer uses the selected browser's per-user native-manifest directory. Chromium-family browsers use `allowed_origins`; Firefox uses `allowed_extensions`. Stable extension identities are read from `../extension-identities.json`, so no manually copied development ID is required. The host accepts only `ensure_supervisor`; it cannot run caller-supplied commands.

The extension probes `Status` first. Only when that fails does it ask the native host to start `src/main.py`. The native launcher sets `PRIVOKE_RUNTIME_START_ENABLED=false`, waits for the bridge on `127.0.0.1:8080`, and returns. The extension then invokes `SetRuntimeEnabled(true)` to start the detector on `50054`.

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
