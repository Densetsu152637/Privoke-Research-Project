# telemetry-service

> Source area: `services/telemetry-service`. Commands retain their original working-directory assumptions; follow explicit directory instructions, or use this source area for component-local commands.

`telemetry-service` accepts categorical reports marked as randomized by the client runtime. It validates the mechanism marker, epsilon, and fixed domains, but cannot independently prove that a client applied randomization. The guarantee assumes the official trusted client runtime. The service stores only marginal aggregate counts by epsilon stratum, not individual packets. It never receives prompt text, exact event timestamps, source/request identifiers, target app names, raw scores, detector timings, or per-layer results.

## Local privacy mechanism

The runtime applies independent k-ary generalized randomized response (GRR) to five bounded values before enqueueing a packet:

- action: `ALLOW`, `WARN`, or `BLOCK`
- risk bucket: `0.0-0.2`, `0.2-0.5`, `0.5-0.8`, or `0.8-1.0`
- primary category: `NONE` plus the ten classification categories
- model release: `v0.3.0` or `OTHER`; training revision suffixes are removed
- UTC time of day: one of six fixed four-hour bins, without a calendar date

When multiple categories are present, the emitter selects one using the fixed precedence `CHILD`, `HEALTH`, `CRIMINAL`, `SEXUAL`, `FINANCIAL`, `IDENTITY`, `LOCATION`, `RELIGION`, `POLITICS`, `THIRD_PARTY`. This is a reporting convention, not a claim that unrelated categories have an objective severity order.

For a field with public domain size `K`, GRR reports the true value with probability `p = exp(epsilon_i) / (exp(epsilon_i) + K - 1)` and each other value with probability `q = 1 / (exp(epsilon_i) + K - 1)`. The per-event budget is split equally across the five fields (`epsilon_i = epsilon_event / 5`). Basic composition gives pure event-level `epsilon_event`-LDP (`delta = 0`) for the released tuple. The default is `epsilon_event = 1`; accepted configuration is `0.5 <= epsilon_event <= 2`.

The runtime reserves budget in a durable, installation-local SQLite ledger before randomization and enqueueing. The daily total defaults to `epsilon = 8`, is configurable from the event epsilon up to 8, and is never refunded after reservation. At default settings, at most eight reports are released per UTC day. The ledger uses an atomic SQLite write transaction, fails closed on corruption or write errors, and rejects a backwards UTC date. Native installs use the user's stable local state directory by default; set `TELEMETRY_PRIVACY_LEDGER_PATH` if that location is not persistent or writable. The runtime image stores its ledger under `/var/lib/privoke` and declares that directory as a volume; use a named mount when replacing containers so the ledger carries across replacement. Root, development, and GCE Compose configurations mount persistent named volumes. The daily limit assumes the ledger is retained; deleting it or changing the clock is outside the mechanism's protection.

The guarantee protects the categorical values in one report, conditional on a report being sent. It is event-level, not user-level; multiple reports compose, and this ledger bounds reports per runtime installation rather than identifying a person. It does not hide whether a report exists or its network-level arrival time, source IP, or other transport metadata. The exact `sample_count` returned by the summary API is also not private. No raw prompt, event ID, or client-provided identifier is included in the telemetry payload.

## Aggregate API

Defined in `shared/proto/privoke/v1/telemetry.proto`:

- `RecordTelemetry(TelemetryPacket) -> RecordTelemetryResponse` rejects packets missing the known local mechanism marker, supported epsilon, or fixed-domain values.
- `GetTelemetrySummary(GetTelemetrySummaryRequest) -> GetTelemetrySummaryResponse` returns exact sample count and per-domain observed noisy counts plus debiased estimated counts. It does not return individual packets.
- `Health(TelemetryHealthRequest) -> TelemetryHealthResponse` reports whether the configured SQLite store is writable.

For each domain value, the service estimates its true count within each epsilon stratum as `(observed_noisy_count - n*q) / (p - q)`, where `n` is the number of reports in that stratum, then sums stratum estimates. It clips estimates to `[0, sample_count]`; this is post-processing that introduces bias. GRR estimates can have substantial variance, especially for larger domains at low epsilon, so useful estimates require adequate report volume. The API does not claim a confidence interval or a formal guarantee for exact report counts.

## Storage and migration

Compose stores protected marginal counts in the named `telemetry-data` volume at `/data/telemetry-ldp-v1.sqlite3`. The old `/data/telemetry.db` file is not imported, read, or exposed by the new API and is left untouched. It may contain historical unprotected telemetry; operators should handle that file under their data-retention policy. Pointing `TELEMETRY_DB_PATH` at an old-schema database fails closed with a migration explanation rather than mixing legacy rows with protected reports.

Environment variables:

- `TELEMETRY_PORT`, default `50055`
- `TELEMETRY_DB_PATH`, default `/data/telemetry-ldp-v1.sqlite3`
- `TELEMETRY_MAX_MESSAGE_BYTES`, default `131072`
- `TELEMETRY_LDP_EPSILON`, default `1`; allowed range `0.5` to `2`
- `TELEMETRY_LDP_DAILY_EPSILON`, default `8`; must be at least the event epsilon and no more than `8`
- `TELEMETRY_PRIVACY_LEDGER_PATH`, optional stable client-side budget database path

Run through Compose:

```bash
docker compose up --build telemetry-service client-runtime
```
