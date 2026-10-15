# PriVoke Research Project

PriVoke inspects LLM prompts in a workstation runtime used by a browser extension. Its server stack provides model streaming, telemetry, parameter updates, and fuzzer experiments.

Start with the [documentation index](docs/README.md), the [project architecture](docs/project/overview.md), or the [Google Cloud deployment guide](docs/deployment/google-cloud.md).

## Local development

```bash
docker compose -f docker-compose.yml -f docker-compose.dev.yml up --build
```

Follow the [browser extension setup](docs/runtime/browser-extension.md) and [client configuration guide](docs/runtime/client-configuration.md). The extension's supervisor owns its local detector on `127.0.0.1:50057` and bridge on `127.0.0.1:8080`. In the popup, **Ctrl+Shift+D** reveals the hidden **Use local development servers** setting; it switches model and telemetry connections and restarts the workstation runtime.

Evaluation and integration tests run as [host Python scripts](evaluation/README.md).
The development stack publishes the fuzzer on `127.0.0.1:50053` and the server
runtime on `127.0.0.1:50054` for those scripts.

## Compute Engine deployment

After the one-time Google Cloud and GitHub setup, pushes to `main` run the full service CI, publish five commit-tagged images to Artifact Registry, and deploy them to a Compute Engine VM through IAP. A TLS ingress requires an installation-specific client certificate. The VM retains model artifacts and service data across releases.

Copy [.env.example](.env.example) for the complete list of GitHub secret names. Runtime credentials have a separate [client template](extension/client-runtime/.env.example) and VM configuration has a [deployment template](deploy/gce/.env.example). Actual `.env` files and private keys are ignored and excluded from image builds.

This repository supplies deployment configuration; the [deployment guide](docs/deployment/google-cloud.md) covers provisioning, certificates, rollout, backups, and rollback.

Implementation contracts, regression coverage, and pending release checks are recorded in the [feature completion matrix](docs/feature-completion.md).

LLM training and evaluation tests isolate the semantic layer and validate actual
returned execution. The versioned curriculum/sampler/representation study preserves
fifteen archived semantic views and runs forty-eight fresh semantic-only cells;
see [the amended study protocol](docs/fuzzer-curriculum-improvement-process-20261009.md).
Historical combined-detector results remain separate.
