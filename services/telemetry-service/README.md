# telemetry-service

`telemetry-service` is a Python gRPC collector backed by SQLite. Python keeps the service consistent with the runtime protobuf tooling, while SQLite provides a durable, low-operations database suitable for the current single-node local research stack.

The service never receives raw prompt text, spans, detector reasoning, request metadata, or model parameters. A packet contains only identifiers, an hourly time bucket, action/classification labels, text length, elapsed time, a coarse risk score/bucket, detector version, and per-layer status/counts. Layer failures use generic codes rather than exception messages.

## API

Defined in `shared/proto/privoke/v1/telemetry.proto`:

- `RecordTelemetry(TelemetryPacket) -> RecordTelemetryResponse`
- `ListTelemetry(ListTelemetryRequest) -> ListTelemetryResponse`
- `Health(TelemetryHealthRequest) -> TelemetryHealthResponse`

`ListTelemetry` returns newest packets first. `limit` defaults to `100` and is capped at `1000`; pass the last returned sequence as `before_sequence` to retrieve the next page.

Incoming packets are validated against bounded identifier, category, layer, timing, score, and text-length fields. Non-finite numbers, detailed layer exceptions, unknown enum-like values, and oversized gRPC messages are rejected before persistence.

## Storage

The SQLite schema is created automatically. Compose stores it in the named `telemetry-data` volume at `/data/telemetry.db`. Events are idempotent by `event_id`, indexed by occurrence time, and use SQLite WAL mode for concurrent readers and writers.

The `Health` RPC returns `SERVING` only when SQLite can open an immediate write transaction against the configured database.

Environment variables:

- `TELEMETRY_PORT`, default `50055`
- `TELEMETRY_DB_PATH`, default `/data/telemetry.db`
- `TELEMETRY_MAX_MESSAGE_BYTES`, default `131072`

Run through Compose:

```bash
docker compose up --build telemetry-service client-runtime
```
