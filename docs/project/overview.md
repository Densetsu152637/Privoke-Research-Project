# PriVoke Research Project

> Source area: `.`. Commands retain their original working-directory assumptions; follow explicit directory instructions, or use this source area for component-local commands.

PriVoke is a research prototype for client-side privacy protection around LLM prompts. The current implementation centers on a Python runtime that can run as a workstation-local extension companion or as a separate workstation detector deployment; no server container runs it. It inspects prompt text, produces structured `ClassificationResult` evidence, and derives a `PriVokeAction`; the extension uses that decision before an intercepted browser request is sent onward.

Docker Compose runs the Rust `model-streaming-service` and `telemetry-service`. The opt-in `v3-training` profile adds `param-update-service`, `v3-fuzzer` and `v3-runtime`, which retrain all three standard V3 tiers (drift, guard and retention gates, then Ed25519-signed publication; see [parameter updates](../services/parameter-updates.md)). V1 models are served for detection only: V1 training and the `SubmitParameterUpdate` RPC were removed in stage V3-R8b. The server runs no detector pipeline; `v3-fuzzer` requests semantic-only fits from `v3-runtime`.

Reference context: https://arxiv.org/abs/2408.07004

## Current Runtime Path

`extension/client-runtime` contains detector implementation code reused in two independent deployments. Reuse stops at the source boundary: the two runtime processes do not discover, call, control, or share lifecycle state with each other.

| Deployment | Process owner | Runtime endpoint | Consumer |
| --- | --- | --- | --- |
| Browser extension | Workstation supervisor | `127.0.0.1:50057`, reached by the extension through the supervisor-owned bridge on `127.0.0.1:8080` | The local WebExtension only |

The workstation supervisor exposes its lifecycle control service on `127.0.0.1:50056`. Docker Compose never starts that supervisor or bridge, and the extension has no server-side detector to fall back on.

```text
gRPC request or local HTTP POST /analyze
  -> request validation and optional visibility-hint parsing
  -> TextNormalizer
  -> RuleDetector
  -> EntityNERDetector
  -> selected semantic classifier
  -> combined classification and original-text primary evidence
  -> HTTP or gRPC response serialization
```

Current behavior is deliberately simple:

- Callers can request the full runtime or any subset of regex, NER, and semantic detection.
- Regex rules run first by default. If they produce a `BLOCK`, the runtime marks the remaining requested layers as skipped. Callers can instead request parallel regex execution.
- Detector failures are returned as aggregate and per-layer errors without discarding successful layer results.
- The runtime preserves `ALLOW` evidence and combines strongest sensitivity/known visibility with the category union. Confidence moderation remains tied to the most sensitive contributors, and individual decisions are never weakened.
- Visibility hints can promote retained identity/location evidence; they cannot lower an existing failure `BLOCK`. Layer and primary evidence spans address the original prompt, including Unicode and whitespace.

## Classification Contract

Detector output is represented by `extension/client-runtime/src/classification`.

- `Sensitivity`: `S0`, `S1`, `S2`, `S3`
- `Visibility`: `P0`, `P1`, `P2`, `P3`, `P4`, `PU`
- `Category`: `HEALTH`, `POLITICS`, `RELIGION`, `CRIMINAL`, `FINANCIAL`, `SEXUAL`, `CHILD`, `LOCATION`, `IDENTITY`, `THIRD_PARTY`

`Classification` packs those dimensions into a 16-bit integer. `ClassificationResult` wraps the classification with span, confidence, reasoning, and metadata.

`PriVokeAction` is derived from each `ClassificationResult`:

- `BLOCK`: high-confidence `S3`.
- `WARN`: `S2`.
- `WARN`: `IDENTITY` or `LOCATION` combined with restricted/private visibility, or with each other.
- `ALLOW`: `S0`/`S1` context that does not trigger a warning or block.
- Low-confidence `S3` downgrades to `WARN`; low-confidence non-identifying `S2` can become `ALLOW`.

## Repository Layout

- `extension`: Manifest V3 browser client, the supervisor-hosted loopback gRPC-Web bridge, the Python prompt inspection runtime under `extension/client-runtime`, and its separate workstation control process under `extension/runtime-supervisor`.
- `rust/services`: the deployed Rust services: `model-streaming`, `telemetry`, `param-update` (V3 checkpoint store and routine scheduler), `v3-fuzzer`, `v3-runtime`, plus the workstation `runtime-supervisor` and the not-deployed `analysis`. `rust/crates/privoke-transport` provides their in-service mutual TLS and role policy.
- `services/model-streaming-service`, `services/param-update-service`, `services/telemetry-service`: the retired Go and Python implementations, kept as parity oracles.
- `services/privoke-fuzzer`: the frozen Python fuzzer and CLI, used by the historical studies and not deployed.
- `shared/proto`: Shared protobuf contracts used by the gRPC services and streamed semantic backend.
- `paper`: Research figures and experiment artifacts.

## Server Compose Service Ports

- `model-streaming-service`: gRPC on `50051`.
- `param-update-service`: gRPC on `50052` (`v3-training` profile only).
- `telemetry-service`: gRPC on `50055`.
- `v3-runtime`: gRPC on `50171` (`v3-training` profile only).
- `v3-fuzzer`: gRPC on `50172` (`v3-training` profile only).

Production Compose (the Rust stack) keeps every internal listener (`50051`, `50052`, `50055`, `50171`, `50172`) inside its service network and publishes only the two mutual-TLS public listeners of the model and telemetry services, on loopback unless the deployment says otherwise. The default stack publishes the internal listeners on host loopback (`127.0.0.1`) for Python evaluation and integration scripts; every listener is mutual TLS, so those clients present a test certificate. The earlier Python and Go stack that the historical studies layer over is `docker-compose.legacy.yml`. See [host test setup](../../evaluation/README.md). A real external endpoint is a service's own mutual-TLS listener, never a published plaintext gRPC port.

The extension-local ports `8080`, `50056`, and `50057` are not Compose service ports. They are owned by the workstation supervisor and remain bound to loopback.

## Development Commands

Run the default host-test stack (the production Rust images with the internal listeners published on loopback). Without profiles it starts `model-seed`, `model-streaming-service` and `telemetry-service`; add `--profile v3-training` for `param-update-service`, `v3-fuzzer` and `v3-runtime`, which `docker-compose.prod.yml` gates the same way. It has the same topology as the production deployment; it does not run the WebExtension or its local supervisor/bridge:

```bash
docker compose up --build
```

The default file extends the shared service definitions in `docker-compose.prod.yml`; there is no separate development image. All service healthchecks call their public gRPC `Health` methods. The former `docker-compose.dev.yml` override has been removed; use the default file directly.

Run the production-style server deployment:

```bash
docker compose -f docker-compose.prod.yml up -d --build
```

## Continuous Integration

`.github/workflows/service-stack-ci.yml` runs for pull requests to `main` and
`feat/dev-testing`, pushes to `feat/dev-testing`, and manual runs. The Compute Engine
deployment calls it for pushes to `main` before publishing images. It:

- tests and builds the unpacked browser extension,
- regenerates the Go protobuf bindings and runs the model service tests with
  race detection,
- validates both Compose configurations and builds every production service
  image,
- runs each Python service's unit tests inside its production image,
- starts the production topology and waits for every health check,
- verifies non-root/read-only container controls and loopback-only test port mappings,
- runs host Python scripts to simulate a client-runtime request and verify parameter streaming and
  telemetry persistence,
- restarts the model service and confirms that the stack recovers.

Its deployment-configuration job renders every Compose file, including the `v3-training` profile, and the Compose files default `FUZZER_PROMPT_COUNT` to the 256-prompt routine budget, active only under the `v3-training` profile; set it to `0` to disable the scheduler. The semantic-training jobs run the retired Python stack from `docker-compose.legacy.yml`.

Run the optional standalone HTTP harness (this is neither managed runtime deployment):

```bash
cd extension/client-runtime
pip install -r requirements.txt
python src/main.py --port 8765 --llm-choice streamed
```

For streamed classification outside Docker, install `shared/python` and generate Python bindings for `parameters.proto`, `runtime.proto`, and `telemetry.proto` into `extension/client-runtime/generated`. The Rust services use their generated contracts from `shared/proto`.

Build the unpacked browser extension:

```bash
cd extension
npm install
npm run build
```

Load `extension/dist` in Chromium-family browsers, or build the Firefox target and load `extension/dist-firefox`, using the browser's development-extension page. The extension itself is never run by Compose. Register the browser-specific native messaging launcher described in [Browser extension](../runtime/browser-extension.md); the extension can then start the workstation supervisor on demand. The supervisor hosts the gRPC-Web bridge on `8080`, its control service on `50056`, and its extension-local detector on `50057`. No server Compose detector exists, so there is no port conflict with the stack. Port `50051` is contacted by Python only when streamed LLM health or parameters are requested.

Run paper figure scripts:

```bash
pip install -r paper/requirements.txt
python paper/fig1.py
```

Reconfigure the local client-runtime semantic backend when running its local HTTP harness:

```bash
curl -X POST http://127.0.0.1:8765/config/llm \
  -H "Content-Type: application/json" \
  -d '{"choice":"streamed"}'

curl -X POST http://127.0.0.1:8765/config/llm \
  -H "Content-Type: application/json" \
  -d '{"choice":"local","local":{"base_url":"http://host.docker.internal:1234/v1","model":"your-lm-studio-model"}}'

curl -X POST http://127.0.0.1:8765/config/llm \
  -H "Content-Type: application/json" \
  -d '{"choice":"openai","openai":{"api_key":"sk-...","model":"gpt-4o-mini"}}'
```

Run prompt tests through the frozen Python fuzzer (it is not deployed; these commands need the retired stack of `docker-compose.legacy.yml` and its `legacy-training` profile):

```bash
docker compose -f docker-compose.legacy.yml exec privoke-fuzzer \
  python src/cli.py test-prompts \
  --layer runtime \
  --prompt "My email is alex@example.com"
```

Run layer probes:

```bash
docker compose -f docker-compose.legacy.yml exec privoke-fuzzer \
  python src/cli.py test-prompts \
  --layer regex \
  --layer ner \
  --layer semantic \
  --regex-first \
  --generated-count 8
```

In the legacy stack, fuzzer prompt-test dumps live in its `fuzzer-dumps` volume (`docker-compose.legacy.yml`). The Rust Compose files have no such volume.

## Current Prototype Boundaries

- `model-streaming-service` serves the configured, versioned model artifacts and the signed V3 packages to registered installations.
- `param-update-service` stores V3 checkpoints and publishes a candidate only after the drift, guard and retention gates, under an Ed25519-signed statement; commits are durable, idempotent receipts. The V1 gradient update path no longer exists.
- Training reserves distinct labeled clean/sensitive held-out examples before sampling training data. Runtime evaluation checks the exact clipped candidate; publication requires finite quality metrics and no held-out regression. This is an experiment guard, not a public accuracy guarantee.
- Compose files default `FUZZER_PROMPT_COUNT` to `256`, active only under the opt-in `v3-training` profile (V3 tiers); set `0` to disable the scheduler. The store and signed tree persist in `v3-store` and `v3-published`; seeded V1 artifacts sit in `model-data`.
- Production containers run as an unprivileged user with a read-only root filesystem, all Linux capabilities dropped, and `no-new-privileges`. A one-shot `model-seed` copies the shipped artifacts into an empty `model-data` volume.
- The unpacked extension requires the workstation supervisor, which owns both the local detector process and its loopback gRPC-Web bridge. The repository does not ship a separate extension Compose deployment.
- The optional HTTP harness on `127.0.0.1:8765` exists for evaluation and local integration; server Compose and the browser extension use gRPC paths instead.
- Every service listener is mutual TLS with a per-RPC role policy (`rust/crates/privoke-transport`). Internal listeners are never published by the production files, and the training services sit on an `internal: true` network.

## Cross-Service Contract

`shared/proto/privoke/v1/parameters.proto` defines:

- `ModelStreamingService.StreamModelParameters` and unary `GetModelParameters`
- `ParamUpdateService.GetParameterUpdateStatus` and `Health`; `SubmitParameterUpdate` stays in the proto and answers `UNIMPLEMENTED`
- the V1 `FuzzerService`, implemented only by the frozen Python fuzzer

`shared/proto/privoke/experimental/v3.proto` defines `CheckpointService`, `TrainingService` and `V3FuzzerService`, the routine-training contracts.

`shared/proto/privoke/v1/runtime.proto` defines `PrivokeRuntimeService`, including prompt analysis and bounded semantic-gradient calls, plus the workstation-local `PrivokeRuntimeControlService` and its on-demand model-streaming health proxy. Server Compose runs no detector runtime (`v3-runtime` serves only semantic-only `AnalyzePrompt`, and the gradient calls were removed in stage V3-R8a); `extension/runtime-supervisor` hosts the control service.

`shared/proto/privoke/v1/telemetry.proto` defines bounded randomized event recording and aggregate summary retrieval. Compose persists epsilon-stratified marginal counts in the `telemetry-data` SQLite volume; the client privacy ledger persists separately.

The default development Compose file regenerates Python and Go protobuf bindings into each service-local `generated` or `gen` directory before starting the service.

## Subagent Work Model

- Browser integration and detection behavior belong in `extension`; the Python detector implementation remains isolated in `extension/client-runtime`.
- gRPC contract changes start in `shared/proto`, followed by regenerated bindings and README updates.
- V3 curriculum sampling and fit orchestration belong in `rust/services/v3-fuzzer`, and candidate fitting in `rust/services/v3-runtime`.
- The checkpoint store, gates, signed publication and the routine scheduler belong in `rust/services/param-update`.
- Snapshot serving belongs in `services/model-streaming-service`.

Avoid reintroducing string-only severity/category flow. Preserve `Classification`, `ClassificationResult`, `PriVokeAction`, and protobuf boundaries where they are already used.

See the [feature completion matrix](../feature-completion.md) for contract coverage and release validation still required.
