# Rust parameter-update service and scheduler (stage 5 of docs/plans/rust-server-rewrite.md). Build from the repository root:
#
#   docker build -f rust/services/param-update/Dockerfile -t privoke-param-update-rust:<tag> .
#
# The Python image (services/param-update-service/Dockerfile) stays in place as the parity oracle until the stage 9
# retirement. This image has no plaintext mode: it refuses to start without --cert, --key, --client-ca, --crl and
# --registry, and it serves only registered publisher and trainer services. It reads and writes the same artifact,
# receipt and journal formats as the Python service, so an existing /data and model volume work unchanged.
FROM rust:1.99.1-slim-bookworm AS builder

WORKDIR /workspace
COPY rust /workspace/rust
COPY shared/proto /workspace/shared/proto
# The V3 checkpoint store links privoke-semantic and so privoke-rules, which embeds this rule file at compile time.
COPY extension/client-runtime/src/regex/external_rules /workspace/extension/client-runtime/src/regex/external_rules

WORKDIR /workspace/rust
# The cloud build enables no cargo feature: `workstation-loopback` is never compiled in. SQLite is compiled in.
RUN cargo build --release --locked -p privoke-param-update --bin param-update-service \
    && mkdir /data-skeleton /models-skeleton /v3-store-skeleton /v3-published-skeleton

FROM gcr.io/distroless/cc-debian12:nonroot AS runtime

COPY --from=builder /workspace/rust/target/release/param-update-service /param-update-service
# The drift bounds of the V3 publication gate (V3_DRIFT_BOUNDS), the frozen routine policy (V3_POLICY_FILE) and the three V3
# retention reference releases (V3_RETENTION_ROOT; ids and numbers, no prompt text). The publication key is a mounted secret,
# never part of the image, and so is the approved retention bank.
COPY --from=builder /workspace/rust/services/param-update/config /config
# Volumes mounted here inherit this ownership, so the non-root user can write the audit file, the receipt database, the
# training-cycle journal and (in the model directory) the temporary file of an atomic publication.
COPY --from=builder --chown=nonroot:nonroot /data-skeleton /data
COPY --from=builder --chown=nonroot:nonroot /models-skeleton /models
# The V3 checkpoint store (SQLite catalog and blobs) and the published tree; model-streaming shares both volumes.
COPY --from=builder --chown=nonroot:nonroot /v3-store-skeleton /v3-store
COPY --from=builder --chown=nonroot:nonroot /v3-published-skeleton /v3-published

ENV PARAM_UPDATE_PORT=50052 \
    PARAM_UPDATE_STORAGE_PATH=/data/updates.jsonl \
    FUZZER_CYCLE_STATE_PATH=/data/training-cycles.sqlite3 \
    MODEL_ARTIFACT_PATH=/models/privoke-baseline.json

# 50052: the update listener (mutual TLS, registered services only). Keep it on the internal network.
EXPOSE 50052
VOLUME ["/data"]

USER nonroot:nonroot

ENTRYPOINT ["/param-update-service"]
