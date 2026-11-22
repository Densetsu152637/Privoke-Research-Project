# Rust V3 runtime service (stage 22 of docs/plans/rust-server-rewrite.md). Build from the repository root:
#
#   docker build -f rust/services/v3-runtime/Dockerfile -t privoke-v3-runtime-rust:<tag> .
#
# The Python image (evaluation/Dockerfile.pretrained-v3, `runtime_server.py`) stays in place as the parity oracle and for the
# historical study runners. This image has no plaintext mode: it refuses to start without --cert, --key, --client-ca, --crl
# and --registry, and it presents a registered service certificate to the checkpoint service. It runs on the CPU only
# (V3_DEVICE other than `cpu` is refused). The Python source closure that the evidence commits to is not in the image: mount
# a checkout read-only and name it with V3_SOURCE_ROOT.
FROM rust:1.99.1-slim-bookworm AS builder

WORKDIR /workspace
COPY rust /workspace/rust
COPY shared/proto /workspace/shared/proto

WORKDIR /workspace/rust
# SQLite is compiled in. No cargo feature is enabled.
RUN cargo build --release --locked -p privoke-v3-runtime --bin v3-runtime-service \
    && mkdir /state-skeleton

FROM gcr.io/distroless/cc-debian12:nonroot AS runtime

COPY --from=builder /workspace/rust/target/release/v3-runtime-service /v3-runtime-service
# The durable fit ledger, the asset cache and the work directories live here; a mounted volume inherits this ownership.
COPY --from=builder --chown=nonroot:nonroot /state-skeleton /state

ENV V3_PORT=50171 \
    V3_BIND=0.0.0.0 \
    V3_RUNTIME_STATE=/state

# 50171: the runtime listener (mutual TLS, registered publisher, trainer and runtime services). Keep it on the internal network.
EXPOSE 50171
VOLUME ["/state"]

USER nonroot:nonroot

ENTRYPOINT ["/v3-runtime-service"]
