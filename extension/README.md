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

The LLM toggle health check follows a separate Envoy route to `model-streaming-service:50051`. Only its `Health` RPC is exposed through the browser bridge; model parameters continue to flow from that service to the Python runtime over native gRPC.

The supervisor is intentionally separate from the detector runtime. A shutdown method hosted by the detector itself could stop the process, but could not receive the later start request. The supervisor owns the child process, waits for port `50054` on startup, terminates it on shutdown, and also stops it when the supervisor terminal or container is terminated.

Browsers cannot call a native gRPC HTTP/2 endpoint directly. The bridge translates gRPC-Web frames while keeping the shared protobuf files as the request and response contracts.

## Run locally

From the repository root, start the development stack (the baseline Compose file does not expose the browser bridge):

```bash
docker compose -f docker-compose.yml -f docker-compose.dev.yml up --build
```

Build and test the extension:

```bash
cd extension
npm install
npm test
npm run build
```

Then open the Chromium extensions page, enable developer mode, choose **Load unpacked**, and select `extension/dist`. Reload supported AI tabs after loading or rebuilding the extension so the early network hook is installed.

For incremental builds, run `npm run dev` and reload the unpacked extension plus any supported website tabs after a change.

## Local boundaries

- The runtime bridge permission is limited to HTTP loopback hosts. Chrome host match patterns cannot scope this to only port `8080`, although the client endpoint is fixed to that port.
- Website access is limited in the manifest to the supported AI hosts listed above.
- Envoy only routes runtime analysis, runtime lifecycle control, and the model-streaming health RPC, and limits CORS to local pages and extension origins.
- Prompt text is sent to the local bridge and runtime. Runtime telemetry remains metadata-only and excludes prompt text.
- The bridge is part of `docker-compose.dev.yml` because it is a browser adapter rather than a new service contract.

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
