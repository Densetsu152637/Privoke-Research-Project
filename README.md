# PriVoke Research Project

PriVoke inspects LLM prompts in a workstation runtime used by a browser extension. Its server stack is Rust and provides model streaming and telemetry, plus an opt-in routine-training stack that retrains and signs the three standard V3 tiers.

Start with the [documentation index](docs/README.md), the [project architecture](docs/project/overview.md), or the [Google Cloud deployment guide](docs/deployment/google-cloud.md).

## Local development

```bash
python models/prepare_standard_releases.py
docker compose up --build
```

The default `docker-compose.yml` runs the same Rust images as production with
the internal listeners also published on loopback. For the production file with internal-only service ports, use
`docker compose -f docker-compose.prod.yml up -d --build`.

The standard `latest` profile is the selected AU3 V3 balanced package. Preparation
verifies existing local exports and copies their original bytes into an ignored,
read-only distribution store; it does not train or download models. All three V3
tiers use native CPU inference. Explicit older V1 profiles remain available.
Routine training of the three V3 tiers requires the opt-in `v3-training` Compose profile
(`param-update-service`, `v3-fuzzer`, `v3-runtime`); V1 models are served for detection only and are no longer trained. See [model streaming](docs/services/model-streaming.md)
for package pins, missing-asset behavior, cache and deployment staging requirements.

Follow the [browser extension setup](docs/runtime/browser-extension.md) and [client configuration guide](docs/runtime/client-configuration.md). The extension's supervisor owns its local detector on `127.0.0.1:50057` and bridge on `127.0.0.1:8080`. In the popup, **Ctrl+Shift+D** reveals the hidden **Use local development servers** setting; it switches model and telemetry connections and restarts the workstation runtime.

Evaluation and integration tests run as [host Python scripts](evaluation/README.md).
With the `v3-training` profile, the default stack publishes the V3 fuzzer on `127.0.0.1:50172` and the V3 runtime on
`127.0.0.1:50171` for those scripts.

## Compute Engine deployment

After the one-time Google Cloud and GitHub setup, pushes to `main` run the full service CI, publish five commit-tagged images to Artifact Registry, and deploy them to a Compute Engine VM through IAP (once the repository variable `GCP_DEPLOY_ENABLED` is set; the workflow is inert before that). The Rust model and telemetry services terminate mutual TLS themselves, with an installation-specific client certificate. The VM retains model artifacts and service data across releases.

Copy [.env.example](.env.example) for the complete list of GitHub secret names. Runtime credentials have a separate [client template](extension/client-runtime/.env.example) and VM configuration has a [deployment template](deploy/gce/.env.example). Actual `.env` files and private keys are ignored and excluded from image builds.

This repository supplies deployment configuration; the [deployment guide](docs/deployment/google-cloud.md) covers provisioning, certificates, rollout, backups, and rollback.

Implementation contracts, regression coverage, and pending release checks are recorded in the [feature completion matrix](docs/feature-completion.md).

LLM training and evaluation tests isolate the semantic layer and validate actual
returned execution. The versioned curriculum/sampler/representation study preserves
fifteen archived semantic views and runs forty-eight fresh semantic-only cells;
see [the amended study protocol](docs/fuzzer-curriculum-improvement-process-20261009.md).
Historical combined-detector results remain separate.
