# Rust model-streaming service (stage 3 of docs/plans/rust-server-rewrite.md). Build from the repository root:
#
#   docker build -f rust/services/model-streaming/Dockerfile -t privoke-model-streaming-rust:<tag> .
#
# The Go image (services/model-streaming-service/Dockerfile) stays in place until the stage 9 retirement. This image
# has no plaintext mode: it refuses to start without --cert, --key, --client-ca, --crl and --registry.
FROM rust:1.99.1-slim-bookworm AS builder

WORKDIR /workspace
COPY rust /workspace/rust
COPY shared/proto /workspace/shared/proto

WORKDIR /workspace/rust
# The cloud build enables no cargo feature: `workstation-loopback` is never compiled in.
RUN cargo build --release --locked -p privoke-model-streaming --bin model-streaming-service

FROM gcr.io/distroless/cc-debian12:nonroot AS runtime

COPY --from=builder /workspace/rust/target/release/model-streaming-service /model-streaming-service
COPY --chown=nonroot:nonroot models/privoke-*.json /models/

ENV MODEL_ARTIFACT_DIR=/models \
    MODEL_RELEASE_DIR=/model-releases \
    MODEL_STREAMING_PORT=50051 \
    MODEL_STREAMING_PUBLIC_PORT=50443

# 50443: public listener (consumers). 50051: internal listener (services). Both require mutual TLS.
EXPOSE 50443 50051

USER nonroot:nonroot

ENTRYPOINT ["/model-streaming-service"]
