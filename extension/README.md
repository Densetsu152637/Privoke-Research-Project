# PriVoke Chromium Extension

The extension checks prompts before supported AI websites send their network request. Its popup has a master power toggle, three protection-layer toggles, an optional manual prompt check, and a settings drawer.

## Behavior

- The master toggle starts or stops the client-runtime detector process through `PrivokeRuntimeControlService`. The lightweight supervisor stays online so an off runtime can be started again.
- **Regex**, **NER**, and **LLM (streamed)** can be enabled independently. Regex and NER start enabled; the streamed LLM starts disabled.
- Enabling LLM first calls `ModelStreamingService.Health`. If the service does not return `SERVING`, LLM remains off and the popup says that the PriVoke servers are offline.
- Manual analysis reports a compact `PASS`, `WARN`, or `ERROR` badge beside the **Analyse prompt** button. `BLOCK` maps to `ERROR` in this compact UI.
- Website notifications are shown only for `WARN` and `BLOCK`. The detected evidence span is rendered in red; `ALLOW` stays silent.
- A warning allows the original web request to continue. A block cancels it before it is sent.
- Settings persist in `chrome.storage.local`. **Wait for regex** selects first/short-circuit versus parallel execution, and **PriVoke model** supplies the streamed model ID for each analysis.

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

The LLM toggle health check follows a separate Envoy route to the parameter-streaming endpoint on `127.0.0.1:50051`. Only its `Health` RPC is exposed through the browser bridge; model parameters continue to flow from that endpoint to the Python runtime over native gRPC. The checked-in configuration is a loopback development configuration, so a remote deployment must supply a secure local forward or an equivalent machine-local bridge configuration.

The supervisor is intentionally separate from the detector runtime. A shutdown method hosted by the detector itself could stop the process, but could not receive the later start request. The supervisor owns the child process, waits for port `50054` on startup, terminates it on shutdown, and also stops it when the supervisor process is terminated.

Browsers cannot call a native gRPC HTTP/2 endpoint directly. The bridge translates gRPC-Web frames while keeping the shared protobuf files as the request and response contracts.

## Run locally

The extension itself is not deployed with Docker. Before loading it, start three independent companion pieces: a parameter-streaming endpoint, the Python runtime supervisor, and the local Envoy bridge.

1. Make `model-streaming-service` reachable on workstation loopback port `50051`. For local testing, start only that server component from the repository root:

```bash
docker compose -f docker-compose.yml -f docker-compose.dev.yml up --build model-streaming-service
```

2. In another terminal, prepare and start the local runtime supervisor:

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
python src/supervisor_main.py
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
- Envoy binds only to `127.0.0.1`, routes runtime analysis, runtime lifecycle control, and the model-streaming health RPC, and limits CORS to local pages and extension origins.
- Prompt text is sent to the local bridge and runtime. Runtime telemetry remains metadata-only and excludes prompt text.
- The browser bridge is local extension infrastructure and is deliberately absent from the server Docker deployments.

## Layout

- `manifest.json`, `popup.html`, `popup.css`: extension shell and permissions.
- `src/page-interceptor.js`: main-world `fetch`/XHR gate.
- `src/content-script.js`: isolated-world runtime bridge and WARN/BLOCK notice.
- `src/background.js`: analysis, health, and settings message handling.
- `src/prompt-interception.js`: supported endpoints and prompt extraction.
- `src/runtime-client.js`: protobuf encoding plus analysis, lifecycle, and health gRPC-Web calls.
- `src/settings.js`: defaults, validation, and persisted settings.
- `scripts/build.mjs`: esbuild bundles and static-file assembly into `dist`.
- `envoy.yaml`: gRPC-Web routes to runtime analysis, lifecycle control, and streaming health.
- `client-runtime`: Python inspection runtime and detector layers.

The runtime's setup and detector behavior are documented in `client-runtime/README.md`.
