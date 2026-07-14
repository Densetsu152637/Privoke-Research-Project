# PriVoke Research Project

PriVoke is a research prototype for client-side privacy protection around LLM prompts. The current implementation centers on a Python runtime service intended to run on a user's local computer. It inspects prompt text, produces structured `ClassificationResult` evidence, derives a `PriVokeAction`, and can return a local decision before text is sent onward.

Docker Compose runs an always-on server `client-runtime` alongside parameter streaming, fuzzer-driven adaptive experiments, telemetry, and update capture. The fuzzer queries that runtime for all detector execution; it does not install or import runtime implementation code.

Reference context: https://arxiv.org/abs/2408.07004

## Current Runtime Path

`extension/client-runtime` contains the prompt inspection implementation shared by two execution contexts. Server Docker deployments run it directly as the always-on `client-runtime` gRPC service on `50054`. The unpacked Chrome extension is built separately and uses its workstation-local lifecycle supervisor; it is not deployed by either server Compose file.

```text
local request or local HTTP POST /analyze
  -> request validation and optional visibility-hint parsing
  -> TextNormalizer
  -> RuleDetector
  -> EntityNERDetector
  -> selected semantic classifier
  -> strongest ClassificationResult action
  -> HTTP response serialization
```

Current behavior is deliberately simple:

- Callers can request the full runtime or any subset of regex, NER, and semantic detection.
- Regex rules run first by default. If they produce a `BLOCK`, the runtime marks the remaining requested layers as skipped. Callers can instead request parallel regex execution.
- Detector failures are returned as aggregate and per-layer errors without discarding successful layer results.
- The runtime does not merge all detector evidence into one combined classification. It selects the first result that raises the strongest action above `ALLOW`.
- Visibility hints are applied by the hosting layer after pipeline analysis.

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

- `extension`: Manifest V3 browser client, local gRPC-Web bridge configuration, and the Python prompt inspection runtime under `extension/client-runtime`.
- `services/model-streaming-service`: Go gRPC service that returns the current model parameter snapshot.
- `services/param-update-service`: Python gRPC service that accepts parameter update payloads and can request fuzzer training cycles.
- `services/privoke-fuzzer`: Python gRPC worker and CLI for prompt generation, layer probes, streamed semantic-model evaluation, and update submission.
- `services/telemetry-service`: Python gRPC metadata collector backed by SQLite.
- `shared/proto`: Shared protobuf contracts used by the gRPC services and streamed semantic backend.
- `paper`: Research figures and experiment artifacts.

## Service Ports

- `model-streaming-service`: gRPC on `50051`.
- `param-update-service`: gRPC on `50052`.
- `privoke-fuzzer`: gRPC on `50053`.
- `client-runtime`: always-on server detector gRPC on `50054`.
- `telemetry-service`: gRPC on `50055`.

## Development Commands

Run the development server simulation with bind-mounted sources and generated stubs:

```bash
docker compose -f docker-compose.yml -f docker-compose.dev.yml up --build
```

Run the production-style server deployment:

```bash
docker compose up -d --build
```

Run the client runtime directly:

```bash
cd extension/client-runtime
pip install -r requirements.txt
python src/main.py --port 8765 --llm-choice streamed
```

For streamed classification outside Docker, generate the Python bindings for both `parameters.proto` and `runtime.proto` into `extension/client-runtime/generated`. The runtime and fuzzer Docker images generate only their own bindings.

Build the unpacked browser extension:

```bash
cd extension
npm install
npm run build
```

With the development Compose stack running, load `extension/dist` from the browser's unpacked-extension page. See `extension/README.md` for the request boundary and development workflow.

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

Run prompt tests through the deployed runtime gRPC service:

```bash
docker compose -f docker-compose.yml -f docker-compose.dev.yml exec privoke-fuzzer \
  python src/cli.py test-prompts \
  --layer runtime \
  --prompt "My email is alex@example.com"
```

Run layer probes:

```bash
docker compose -f docker-compose.yml -f docker-compose.dev.yml exec privoke-fuzzer \
  python src/cli.py test-prompts \
  --layer regex \
  --layer ner \
  --layer semantic \
  --regex-first \
  --generated-count 8
```

In dev mode fuzzer prompt-test dumps are bind-mounted to `./dumps/privoke-fuzzer`. In the baseline stack they stay inside the fuzzer container at `/workspace/dumps/privoke-fuzzer`.

## Cross-Service Contract

`shared/proto/privoke/v1/parameters.proto` defines:

- `ModelStreamingService.GetModelParameters`
- `ParamUpdateService.SubmitParameterUpdate`
- `FuzzerService.RunTrainingCycle`
- `Health` RPCs for the parameter, update, and fuzzer services

`shared/proto/privoke/v1/runtime.proto` defines `PrivokeRuntimeService`, requested detector layers, regex execution order, and per-layer results/errors.

`shared/proto/privoke/v1/telemetry.proto` defines privacy-minimal event recording and paginated retrieval. Compose persists these packets in the `telemetry-data` SQLite volume.

The dev Compose override regenerates Python and Go protobuf bindings into each service-local `generated` or `gen` directory before starting the service.

## Subagent Work Model

- Browser integration and detection behavior belong in `extension`; the Python detector implementation remains isolated in `extension/client-runtime`.
- gRPC contract changes start in `shared/proto`, followed by regenerated bindings and README updates.
- Prompt generation, prompt tests, and streamed semantic training experiments belong in `services/privoke-fuzzer`.
- Fuzzer request initiation and update persistence belong in `services/param-update-service`.
- Snapshot serving belongs in `services/model-streaming-service`.

Avoid reintroducing string-only severity/category flow. Preserve `Classification`, `ClassificationResult`, `PriVokeAction`, and protobuf boundaries where they are already used.
