# PriVoke Chromium Extension

The extension checks prompts before supported AI websites send their network request. Its popup has a master power toggle, three protection-layer toggles, an optional manual prompt check, and a settings drawer.

## Behavior

- The master toggle starts or stops the client-runtime detector process through `PrivokeRuntimeControlService`. The lightweight supervisor stays online so an off runtime can be started again.
- **Regex**, **NER**, and **LLM (streamed)** can be enabled independently. Regex and NER start enabled; the streamed LLM starts disabled.
- Enabling LLM asks the local Python supervisor to check `ModelStreamingService.Health`. If the service does not return `SERVING`, LLM remains off and the popup says that the PriVoke servers are offline.
- Startup never contacts `model-streaming-service`. Regex and NER remain available when that service is absent; only explicitly enabling or using the streamed LLM layer needs it.
- Manual analysis reports a compact `PASS`, `WARN`, or `ERROR` badge beside the **Analyse prompt** button. `BLOCK` maps to `ERROR` in this compact UI.
- Website notifications are shown only for `WARN` and `BLOCK`. The detected evidence span is rendered in red; `ALLOW` stays silent.
- A warning allows the original web request to continue. A block cancels it before it is sent.
- Settings persist in `chrome.storage.local`. **Wait for regex** selects first/short-circuit versus parallel execution, and **PriVoke model** supplies the streamed model ID for each analysis.
- Every analysis request names the concrete enabled layers; the extension never relies on the runtime's omitted-layer default.

The page-network hook currently recognises prompt POSTs for:

- ChatGPT (`chatgpt.com` and the legacy `chat.openai.com` host),
- Claude,
- Gemini,
- Microsoft Copilot,
- OpenAI Chat Completions and Responses API requests made from a matching browser page.

Both `fetch` and `XMLHttpRequest` are intercepted at `document_start`. If the extension bridge or runtime is unavailable, website requests fail open and no page notification is shown. This avoids presenting an infrastructure failure as a privacy classification.

## Request path

```text
supported AI page fetch/XHR  ─┐
extension popup manual check ─┴─> MV3 background worker
                                  -> gRPC-Web http://127.0.0.1:8080
                                  -> Envoy development bridge
                                  -> supervisor control gRPC :50056 (power toggle)
                                  -> detector runtime gRPC :50054 (analysis)
                                  -> selected regex / NER / semantic layers
```

The LLM toggle health check goes through the Python supervisor's `ModelStreamingHealth` RPC. The browser bridge never routes directly to the parameter-streaming service; the supervisor performs the native gRPC health call on demand. Model parameters also flow only from that endpoint to the Python runtime. The checked-in configuration is a loopback development configuration, so a remote deployment must supply a secure local forward or an equivalent machine-local bridge configuration.

The supervisor is intentionally separate from the detector runtime. A shutdown method hosted by the detector itself could stop the process, but could not receive the later start request. The supervisor owns the child process, waits for port `50054` on startup, terminates it on shutdown, and also stops it when the supervisor process is terminated.

Browsers cannot call a native gRPC HTTP/2 endpoint directly. The bridge translates gRPC-Web frames while keeping the shared protobuf files as the request and response contracts.

## Run locally

The extension itself is not deployed with Docker. Before loading it, start the Python runtime supervisor and local Envoy bridge. A parameter-streaming endpoint is optional unless the LLM layer is enabled.

1. To use the LLM layer, make `model-streaming-service` reachable on workstation loopback port `50051`. Skip this step for offline regex/NER operation. For local streamed-model testing, run:

```bash
docker compose -f docker-compose.yml -f docker-compose.dev.yml up --build model-streaming-service
```

2. Prepare the detector and supervisor. The commands below use one virtual environment, but each process keeps its own source and generated protobuf bindings:

```bash
cd extension/client-runtime
python -m venv .venv
source .venv/bin/activate  # Windows PowerShell: .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt ../../shared/python
mkdir generated  # omit this line when the directory already exists
python -m grpc_tools.protoc \
  -I ../../shared/proto \
  --python_out=generated \
  --grpc_python_out=generated \
  ../../shared/proto/privoke/v1/parameters.proto \
  ../../shared/proto/privoke/v1/runtime.proto \
  ../../shared/proto/privoke/v1/telemetry.proto
cd ../runtime-supervisor
pip install -r requirements.txt
mkdir generated  # omit this line when the directory already exists
python -m grpc_tools.protoc \
  -I ../../shared/proto \
  --python_out=generated \
  --grpc_python_out=generated \
  ../../shared/proto/privoke/v1/parameters.proto \
  ../../shared/proto/privoke/v1/runtime.proto
python src/main.py
```

The supervisor and detector bind to loopback by default. `MODEL_STREAMING_TARGET` defaults to `127.0.0.1:50051` for this workstation path; server Compose overrides it with the internal service name.

3. With Envoy installed on the workstation, start the gRPC-Web bridge from the repository root:

```bash
envoy -c extension/envoy.yaml
```

The repository does not include a separate extension Compose file or a packaged companion installer. If Envoy or the supervisor is not running, intercepted website requests fail open and manual analysis reports an error.

4. Build and test the normal Chromium extension:

```bash
cd extension
npm install
npm test
npm run build
```

Then open the Chromium extensions page, enable developer mode, choose **Load unpacked**, and select `extension/dist`. Reload supported AI tabs after loading or rebuilding the extension so the early network hook is installed.

The extension expects its workstation-local PriVoke control/bridge endpoint at `127.0.0.1:8080`. The extension, supervisor, and bridge remain separate from the production and development server Compose deployments.

For incremental builds, run `npm run dev` and reload the unpacked extension plus any supported website tabs after a change.

## Local boundaries

- The runtime bridge permission is limited to HTTP loopback hosts. Chrome host match patterns cannot scope this to only port `8080`, although the client endpoint is fixed to that port.
- Website access is limited in the manifest to the supported AI hosts listed above.
- Envoy binds only to `127.0.0.1`, routes runtime analysis and lifecycle control, and limits CORS to local pages and extension origins. It has no route to `model-streaming-service`.
- Prompt text is sent to the local bridge and runtime. Runtime telemetry remains metadata-only and excludes prompt text.
- The browser bridge is local extension infrastructure and is deliberately absent from the server Docker deployments.

## Layout

- `manifest.json`, `popup.html`, `popup.css`: extension shell and permissions.
- `src/page-interceptor.js`: main-world `fetch`/XHR gate.
- `src/content-script.js`: isolated-world runtime bridge and WARN/BLOCK notice.
- `src/background.js`: analysis, health, and settings message handling.
- `src/prompt-interception.js`: supported endpoints and prompt extraction.
- `src/runtime-client.js`: protobuf encoding plus analysis, lifecycle, and supervisor-mediated health gRPC-Web calls.
- `src/analysis-request.js`: enforces explicit concrete layers on every outgoing analysis RPC.
- `src/settings.js`: defaults, validation, and persisted settings.
- `scripts/build.mjs`: esbuild bundles and static-file assembly into `dist`.
- `envoy.yaml`: gRPC-Web routes to runtime analysis and lifecycle control.
- `client-runtime`: Python inspection runtime and detector layers.
- `runtime-supervisor`: separate Python lifecycle and model-health control process.

The two Python processes are documented in `client-runtime/README.md` and `runtime-supervisor/README.md`.
