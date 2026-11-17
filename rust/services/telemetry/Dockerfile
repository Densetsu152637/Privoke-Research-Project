# Rust telemetry service (stage 4 of docs/plans/rust-server-rewrite.md). Build from the repository root:
#
#   docker build -f rust/services/telemetry/Dockerfile -t privoke-telemetry-rust:<tag> .
#
# The Python image (services/telemetry-service/Dockerfile) stays in place until the stage 9 retirement. This image has no
# plaintext mode: it refuses to start without --cert, --key, --client-ca, --crl and --registry. It reads and writes the
# same SQLite schema as the Python service, so an existing /data volume works unchanged.
FROM rust:1.99.1-slim-bookworm AS builder

WORKDIR /workspace
COPY rust /workspace/rust
COPY shared/proto /workspace/shared/proto

WORKDIR /workspace/rust
# The cloud build enables no cargo feature: `workstation-loopback` is never compiled in. SQLite is compiled in.
RUN cargo build --release --locked -p privoke-telemetry --bin telemetry-service \
    && mkdir /data-skeleton

FROM gcr.io/distroless/cc-debian12:nonroot AS runtime

COPY --from=builder /workspace/rust/target/release/telemetry-service /telemetry-service
# A volume mounted here inherits this ownership, so the non-root user can write the database.
COPY --from=builder --chown=nonroot:nonroot /data-skeleton /data

ENV TELEMETRY_DB_PATH=/data/telemetry-ldp-v1.sqlite3 \
    TELEMETRY_PORT=50055 \
    TELEMETRY_PUBLIC_PORT=58443

# 58443: public listener (the shared reporter credential). 50055: internal listener (services). Both require mutual TLS.
EXPOSE 58443 50055
VOLUME ["/data"]

USER nonroot:nonroot

ENTRYPOINT ["/telemetry-service"]
