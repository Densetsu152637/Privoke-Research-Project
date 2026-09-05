# Client configuration and hidden developer settings

The browser extension always calls its workstation supervisor and detector over loopback. The selected server stack provides model parameters and receives telemetry when enabled. The Compose detector is a separate server process used for experiments.

## Configure an installation

From the repository root:

```bash
cp extension/client-runtime/.env.example extension/client-runtime/.env
```

If a `.env` already exists, edit it instead of replacing it. The runtime and supervisor load this exact file before reading configuration, regardless of their launch directory. Process environment variables take precedence. For an installed package or read-only application directory, set `PRIVOKE_ENV_FILE` to an absolute path in the user's private application-data directory. Certificate paths inside it are relative to that file. Restart the supervisor after editing credentials or the cloud hostname.

| Variable | Purpose |
| --- | --- |
| `PRIVOKE_CLOUD_TARGET` | Cloud DNS name and port, such as `stack.example.com:443`; no URL scheme |
| `PRIVOKE_TLS_CERT_FILE` | PEM client certificate chain issued for this installation |
| `PRIVOKE_TLS_KEY_FILE` | PEM private key belonging to that client certificate |
| `PRIVOKE_TLS_CA_FILE` | Optional private CA for the **server** certificate; empty uses gRPC's default trust roots |
| `PRIVOKE_USE_LOCAL_STACK` | Standalone runtime's hidden developer switch; defaults to `false` |
| `TELEMETRY_ENABLED` | Defaults to `false` for workstation installations |
| `OPENAI_API_KEY` | Optional installation/user-owned credential for the OpenAI classifier |
| `LM_STUDIO_API_KEY` | Optional installation/user-owned local inference credential |

Ship `.env.example` and the shared Python package with the workstation application, then create its private `.env` at installation. Restrict it and its private key to the installation's user (mode `0600` on Unix, or a user-only Windows ACL). Provision a unique client key/certificate separately for each installation; do not put a universal private key, Google service-account credential or operator OpenAI key into a distributable. Files shipped to a user can be read by that user. The browser bundle contains no secrets and never reads `.env`.

All `.env` files, `secrets/` folders, `.key`, `.pem`, and `.p12` files are ignored by Git and excluded from Docker build contexts. The root `.env.example` lists deployment identities; it is not the client configuration. An actual value cannot be supplied by this repository until an operator provisions it.

## Reveal the hidden toggle

1. Start the local stack with `docker compose -f docker-compose.yml -f docker-compose.dev.yml up --build`.
2. Focus the extension popup and press **Ctrl+Shift+D** to reveal developer settings.
3. Turn on **Use local development servers**. Model streaming connects to `127.0.0.1:50051`; telemetry connects to `127.0.0.1:50055`. Local connections need no cloud certificate.
4. Turn it off to return to `PRIVOKE_CLOUD_TARGET` with authenticated TLS.

The switch is saved in browser-local extension storage, survives browser restarts, and is reapplied whenever the runtime starts. It restarts an enabled runtime to discard cached model parameters, open channels, and queued telemetry from the previous stack. Requests in progress may fail during this restart. When PriVoke is disabled, the choice is saved for its next start. Pressing the shortcut again hides the panel without changing the saved selection.

The extension's saved setting takes precedence over `PRIVOKE_USE_LOCAL_STACK` in the managed child. A directly launched runtime uses the environment variable. Cloud is the default; an absent endpoint or unavailable cloud service does not silently select localhost. Regex and NER remain usable without a cloud connection when telemetry is disabled. Streamed-LLM health checks use the same destination and certificate as downloads.

`PRIVOKE_STACK_MODE=internal` is set explicitly by Compose for the server detector. Only this mode uses `MODEL_STREAMING_TARGET` and `TELEMETRY_TARGET` to contact internal Docker service names. Do not set it in a workstation package. The toggle does not change the local LLM classifier backend (`LM Studio`), supervisor ports, or detector ownership.

## Build after changing the protobuf contract

`SetRuntimeEnabledRequest.use_local_stack` is optional, so older callers can omit it. Rebuild the extension with `npm run build` in `extension`, and regenerate Python bindings for both runtime packages using the commands in their setup guides. Install the supervisor requirements, which now include `python-dotenv`. Include `shared/python` in every distributed workstation installation.
