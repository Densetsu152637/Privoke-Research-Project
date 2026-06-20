# Services

This directory contains PriVoke's local client runtime code and research-support services. The Docker Compose stack deploys three gRPC services for parameter streaming, fuzzer training requests, and update ingestion. The prompt inspection runtime is client-local code, not a server-side microservice.

## Service Map

- `client-runtime`: Python package for local prompt privacy inspection. It owns the detector pipeline and includes an optional local HTTP harness for client-side development.
- `model-streaming-service`: Go gRPC server that returns the current parameter snapshot used by the streamed semantic backend.
- `param-update-service`: Python gRPC server that appends parameter updates to JSONL storage and can request fuzzer training cycles after startup.
- `privoke-fuzzer`: Python gRPC worker plus CLI for prompt generation, layer probes, streamed semantic-model evaluation, and update submission.

## Runtime Detection Path

Prompt inspection happens in `client-runtime` code, either embedded locally or through its optional local HTTP harness:

```text
prompt
  -> normalization
  -> regex/rule detector
  -> NER/entity detector
  -> semantic classifier backend
  -> strongest result/action selection
  -> local response serialization
```

The runtime chooses one semantic backend at a time:

- `streamed`: fetches parameters from `model-streaming-service` and applies the local parameter-backed semantic model.
- `local`: calls an OpenAI-compatible local API such as LM Studio.
- `openai`: calls the OpenAI SDK.

The Compose services are experiment infrastructure. They should not become server-side dependencies of the prompt decision path unless the architecture is explicitly changed. The fuzzer imports `client-runtime` directly for prompt tests and streamed-only training experiments.

## gRPC Service Contracts

Cross-service APIs live in `shared/proto/privoke/v1/parameters.proto`.

- `ModelStreamingService.GetModelParameters(ModelParametersRequest) -> ModelParametersResponse`
- `ParamUpdateService.SubmitParameterUpdate(ParameterUpdateRequest) -> ParameterUpdateAck`
- `FuzzerService.RunTrainingCycle(FuzzerTrainingRequest) -> FuzzerTrainingResponse`
- Each gRPC service also implements `Health(HealthRequest) -> HealthResponse`

Do not create ad hoc JSON contracts between services when a protobuf boundary exists.

## Compose Wiring

Default ports:

- `model-streaming-service`: `50051`
- `param-update-service`: `50052`
- `privoke-fuzzer`: `50053`

`docker-compose.dev.yml` bind-mounts the service source trees and regenerates protobuf bindings before startup. It also bind-mounts `services/client-runtime` into the fuzzer container because fuzzer prompt tests import it directly, and it bind-mounts fuzzer prompt-test dumps to `./dumps/privoke-fuzzer`.

## Documentation Scope

Each service README should describe:

- current purpose and non-purpose,
- runtime inputs and outputs,
- ports and environment variables,
- how it participates in the stack,
- known prototype limitations that matter for future rewrites.

## Subagent Guidance

- Keep detector changes in `client-runtime`.
- Keep shared API changes in `shared/proto` and regenerate affected bindings.
- Keep prompt generation, layer testing, and streamed semantic training in `privoke-fuzzer`.
- Keep update persistence and fuzzer request initiation in `param-update-service`.
- Keep parameter snapshot serving in `model-streaming-service`.
