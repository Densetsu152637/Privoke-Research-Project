# PriVoke Research Project

PriVoke inspects LLM prompts in a workstation runtime used by a browser extension. Its server stack provides model streaming, telemetry, parameter updates, and fuzzer experiments.

Start with the [documentation index](documents/README.md), the [project architecture](documents/README.Project.md), or the [Google Cloud deployment guide](documents/README.Google-cloud-deployment.md).

## Local development

```bash
docker compose -f docker-compose.yml -f docker-compose.dev.yml up --build
```

Follow the [browser extension setup](documents/README.Browser-extension.md) and [client configuration guide](documents/README.Client-configuration.md). The extension's supervisor owns its local detector on `127.0.0.1:50057` and bridge on `127.0.0.1:8080`. In the popup, **Ctrl+Shift+D** reveals the hidden **Use local development servers** setting; it switches model and telemetry connections and restarts the workstation runtime.

## Compute Engine deployment

After the one-time Google Cloud and GitHub setup, pushes to `main` run the full service CI, publish five commit-tagged images to Artifact Registry, and deploy them to a Compute Engine VM through IAP. A TLS ingress requires an installation-specific client certificate. The VM retains model artifacts and service data across releases.

Copy [.env.example](.env.example) for the complete list of GitHub secret names. Runtime credentials have a separate [client template](extension/client-runtime/.env.example) and VM configuration has a [deployment template](deploy/gce/.env.example). Actual `.env` files and private keys are ignored and excluded from image builds.

This repository supplies deployment configuration; the [deployment guide](documents/README.Google-cloud-deployment.md) covers provisioning, certificates, rollout, backups, and rollback.
