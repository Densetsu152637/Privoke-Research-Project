# Privoke-Research-Project

## Repository Layout

- `services/client-runtime`: Python CLI runtime for the privacy pipeline and parameter fetch client.
- `services/model-streaming-service`: Go gRPC service for serving model parameter snapshots.
- `services/param-update-service`: Python gRPC service for receiving protobuf parameter updates.
- `services/privoke-fuzzer`: Python server-side worker that polls parameters and submits updates.
- `shared/proto`: Shared protobuf contracts used across all services.

## Docker

Development stack:

```bash
docker compose -f docker-compose.yml -f docker-compose.dev.yml up --build
```

Baseline stack:

```bash
docker compose up --build
```
