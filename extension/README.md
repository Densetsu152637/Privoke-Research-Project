# PriVoke Portable WebExtension

The extension checks prompts before supported AI websites send their network request. Its popup has a master power toggle, three protection-layer toggles, an optional manual prompt check, and a settings drawer.

## Deployment boundary

The extension has its own workstation runtime process. Although that process and the server Compose `client-runtime` are built from the same `client-runtime` package, they are independent instances:

- the extension reaches only its supervisor-owned bridge at `127.0.0.1:8080`;
- the supervisor controls only its child detector on `127.0.0.1:50057`;
- the Compose detector remains at `client-runtime:50054` for the fuzzer and evaluation tooling; and
- neither deployment discovers, controls, or falls back to the other.

Docker is optional for the extension's regex and NER layers. It is used only when a developer chooses to provide `model-streaming-service` on `127.0.0.1:50051` for the streamed LLM layer.

## Behavior

- The master toggle starts or stops the client-runtime detector process through `PrivokeRuntimeControlService`. The lightweight supervisor stays online so an off runtime can be started again.
- **Regex**, **NER**, and **LLM (streamed)** can be enabled independently. Regex and NER start enabled; the streamed LLM starts disabled.
- Enabling LLM asks the local Python supervisor to check `ModelStreamingService.Health`. If the service does not return `SERVING`, LLM remains off and the popup says that the PriVoke servers are offline.
- Startup never contacts `model-streaming-service`. Regex and NER remain available when that service is absent; only explicitly enabling or using the streamed LLM layer needs it.
- Manual analysis reports a compact `PASS`, `WARN`, or `ERROR` badge beside the **Analyse prompt** button. `BLOCK` maps to `ERROR` in this compact UI.
- Website notifications are shown only for `WARN` and `BLOCK`. The detected evidence span is rendered in red; `ALLOW` stays silent.
- A warning allows the original web request to continue. A block cancels it before it is sent.
- Settings persist in the standard WebExtensions local-storage API. **Wait for regex** selects first/short-circuit versus parallel execution, and **PriVoke model** supplies the streamed model ID for each analysis.
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
extension popup manual check ─┴─> MV3 background worker or event page
                                  -> gRPC-Web http://127.0.0.1:8080
                                  -> supervisor-hosted loopback bridge
                                      |-> lifecycle/model health -> control gRPC :50056
                                      `-> prompt analysis -> detector gRPC :50057
                                                            -> regex / NER / semantic layers
```

The LLM toggle health check goes through the Python supervisor's `ModelStreamingHealth` RPC. The browser bridge never routes directly to the parameter-streaming service; the supervisor performs the native gRPC health call on demand. Model parameters flow from that endpoint to the extension-local detector only when its streamed semantic layer is requested. The bridge, control service, and detector are forced to loopback and are not a remote deployment path.

The supervisor is intentionally separate from the detector runtime. A shutdown method hosted by the detector itself could stop the process, but could not receive the later start request. The supervisor owns the child process, waits for extension-local port `50057` on startup, terminates it on shutdown, and also stops it when the supervisor process is terminated. Port `50057` is deliberately distinct from the development Compose runtime published on `50054`, so the browser extension and server simulation can run together. The supervisor also hosts the loopback gRPC-Web bridge on port `8080`, so the normal workstation path does not require a separate proxy process.

Browsers cannot call a native gRPC HTTP/2 endpoint directly. The bridge translates gRPC-Web frames while keeping the shared protobuf files as the request and response contracts.

## Run locally

The extension itself is not deployed with Docker. Install its native messaging launcher once so Opera GX, Firefox, or another supported WebExtensions browser can start the Python supervisor on demand. A parameter-streaming endpoint is optional unless the LLM layer is enabled.

1. To use the LLM layer, make `model-streaming-service` reachable on workstation loopback port `50051`. Skip this step for offline regex/NER operation. For local streamed-model testing, start only that server-side dependency; do not use the Compose `client-runtime` for extension analysis:

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
```

The bridge, control service, and detector are forced to loopback. The supervisor prefers `client-runtime/.venv` for the detector process (or `PRIVOKE_RUNTIME_PYTHON` when explicitly set) and refuses to start it unless Presidio and the `en_core_web_sm` spaCy model load successfully. `MODEL_STREAMING_TARGET` defaults to `127.0.0.1:50051` for this workstation path; the separate Compose detector uses the internal service name. Streaming-service health is intentionally not part of the local dependency preflight.

3. Build the portable extension:

```powershell
cd extension
npm install
npm test
npm run build
```

The default build targets Chromium-family browsers and writes `dist`. For Firefox,
run `npm run build:firefox` instead; its Firefox-specific Manifest V3 build is
written to `dist-firefox`.

The manifest contains stable identities for both browser families: `hmlhjfklebbbhpjdjodegbjnbamlkonp` for Opera GX/Chrome/Edge/Chromium and `privoke-local@privoke` for Firefox. Rebuilding or moving the unpacked extension therefore does not invalidate native-host permissions.

4. Register the native host for the target browser. On Windows, `Auto` detects the default browser; `OperaGX`, `Chrome`, `Edge`, `Chromium`, `Firefox`, and `All` are also accepted:

```powershell
cd extension\runtime-supervisor
powershell -ExecutionPolicy Bypass -File .\scripts\install-native-host.ps1 -Browser OperaGX
```

On Linux or macOS:

```bash
cd extension/runtime-supervisor
sh ./scripts/install-native-host.sh opera
```

The installers generate the correct `allowed_origins` or `allowed_extensions` manifest and register it in the selected browser's native-messaging location. Opera GX uses its documented Chrome-compatible Windows registry location. The host accepts only the fixed `ensure_supervisor` action.

When PriVoke is configured on, the background worker restores that state when it is loaded, installed, or notified of browser startup. Opening the popup also repairs a stopped supervisor/runtime instead of only reporting it. If the loopback bridge is unavailable, the worker invokes the native launcher, waits for the supervisor and bridge, and then asks the supervisor to start the detector. The launcher starts the supervisor with `PRIVOKE_RUNTIME_START_ENABLED=false` so these are two explicit stages. The supervisor and detector are operating-system processes independent of the popup lifecycle, so closing or minimising the popup does not stop them. Supervisor output is written to `%TEMP%\PriVoke\runtime-supervisor.log`.

For development without native messaging, start the supervisor manually from `extension/runtime-supervisor`:

```bash
../client-runtime/.venv/bin/python src/main.py
```

The repository does not include a separate extension Compose file. If neither the registered native launcher nor a manually started supervisor is available, intercepted website requests fail open and the popup reports that the native messaging host must be installed.

5. Load `extension/dist` using the target browser's development-extension page:

- Opera GX: `opera://extensions`
- Chrome: `chrome://extensions`
- Edge: `edge://extensions`
- Firefox: `about:debugging#/runtime/this-firefox`, then **Load Temporary Add-on** and select `dist-firefox/manifest.json`

Enable developer mode where required, load the unpacked `extension/dist` directory, and reload supported AI tabs so the early network hook is installed. Fully restart the browser after changing native-host registration.

After changing the extension, rebuild it:

```bash
cd extension
npm install
npm test
npm run build
```

The extension expects its single workstation-local HTTP endpoint at `127.0.0.1:8080`. The bridge routes internally to the supervisor control service and its detector child. The extension, supervisor, bridge, and detector process remain separate from both server Compose deployments.

For incremental builds, run `npm run dev` and reload the unpacked extension plus any supported website tabs after a change.

## Local boundaries

- The runtime bridge permission is limited to HTTP loopback hosts. WebExtension host match patterns cannot scope this to only port `8080`, although the client endpoint is fixed to that port.
- Website access is limited in the manifest to the supported AI hosts listed above.
- The supervisor-hosted bridge binds only to `127.0.0.1`, routes runtime analysis and lifecycle control, and limits browser CORS to local pages and extension origins. It has no route to `model-streaming-service`.
- Loopback binding prevents remote-network access, but CORS is not local-process authentication. Another application on the workstation can construct requests to these local services.
- Prompt text is sent to the local bridge and runtime. Runtime telemetry remains metadata-only and excludes prompt text.
- The browser bridge is local extension infrastructure and is deliberately absent from the server Docker deployments.

## Layout

- `manifest.json`, `popup.html`, `popup.css`: extension shell and permissions.
- `src/page-interceptor.js`: main-world `fetch`/XHR gate.
- `src/content-script.js`: isolated-world extension messaging relay and WARN/BLOCK notice.
- `src/background.js`: analysis, health, and settings message handling.
- `src/prompt-interception.js`: supported endpoints and prompt extraction.
- `src/runtime-client.js`: protobuf encoding plus analysis, lifecycle, and supervisor-mediated health gRPC-Web calls.
- `src/analysis-request.js`: enforces explicit concrete layers on every outgoing analysis RPC.
- `src/settings.js`: defaults, validation, and persisted settings.
- `src/webextension-api.js`: promise/callback and `browser`/`chrome` namespace portability adapter.
- `scripts/build.mjs`: esbuild bundles and static-file assembly into `dist`.
- `client-runtime`: Python inspection runtime and detector layers.
- `runtime-supervisor`: separate Python lifecycle process that owns the loopback gRPC-Web bridge, detector child, and model-health control RPC.

The two Python processes are documented in `client-runtime/README.md` and `runtime-supervisor/README.md`.
