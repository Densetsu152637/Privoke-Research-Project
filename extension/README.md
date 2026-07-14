# PriVoke Local Extension

This directory owns the client-side PriVoke components:

- a Chromium Manifest V3 popup that submits prompts for local inspection,
- an Envoy gRPC-Web bridge for browser-to-gRPC translation,
- `client-runtime`, the moved Python detector runtime.

The first extension slice is intentionally explicit: users paste a prompt into the popup and choose **Inspect locally**. It does not yet read or modify text on arbitrary websites.

## Request path

```text
extension popup
  -> gRPC-Web http://127.0.0.1:8080
  -> Envoy development bridge
  -> native gRPC privoke-runtime:50054
  -> regex / NER / semantic detector pipeline
```

Browsers cannot call a native gRPC HTTP/2 endpoint directly. The bridge translates gRPC-Web frames while keeping `shared/proto/privoke/v1/runtime.proto` as the request and response contract. The browser build imports that shared proto at build time; no duplicate JSON API or checked-in generated stub is maintained.

## Run locally

From the repository root, start the development stack (the baseline Compose file does not expose the browser bridge):

```bash
docker compose -f docker-compose.yml -f docker-compose.dev.yml up --build
```

Build the extension:

```bash
cd extension
npm install
npm run build
```

Then open the Chromium extensions page, enable developer mode, choose **Load unpacked**, and select `extension/dist`. Open the PriVoke toolbar popup and inspect a prompt. The popup displays the runtime action, reason, classification, and elapsed time.

For incremental browser-client builds, use `npm run dev` and reload the unpacked extension after a change. `npm test` verifies the gRPC-Web framing code.

## Local boundaries

- The extension host permission is limited to HTTP loopback hosts (`127.0.0.1` and `localhost`); Chrome host match patterns do not scope permissions to one port. The client endpoint itself is fixed to port `8080`.
- Envoy only routes `PrivokeRuntimeService` RPC paths and only accepts local-extension/local-page CORS origins.
- Prompt text is sent to the local bridge and runtime. Existing runtime telemetry remains metadata-only and excludes prompt text.
- The bridge is part of `docker-compose.dev.yml` because it is a browser development adapter, not a new service contract.

## Layout

- `manifest.json`, `popup.html`, `popup.css`: unpacked-extension shell.
- `src/runtime-client.js`: protobuf encoding and unary `AnalyzePrompt` call.
- `src/grpc-web.js`: gRPC-Web frame encoding/decoding.
- `scripts/build.mjs`: esbuild bundle and static-file assembly into `dist`.
- `envoy.yaml`: gRPC-Web-to-native-gRPC proxy configuration.
- `client-runtime`: Python local inspection runtime and detector layers.

The runtime's own setup and configuration are documented in `client-runtime/README.md`.
