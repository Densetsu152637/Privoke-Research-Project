# Quarantined analysis service (stage W3 of docs/plans/rust-server-rewrite.md). Build from the repository root:
#
#   docker build -f extension/client-runtime/Dockerfile --target runtime -t privoke-client-runtime-base:w3 .
#   docker build -f rust/services/analysis/Dockerfile --build-arg PYTHON_RUNTIME_IMAGE=privoke-client-runtime-base:w3 \
#       -t privoke-analysis:w3 .
#
# The Python side is the existing client-runtime image (Python 3.11, the /opt/venv with torch, spaCy and the other
# pinned requirements, a non-root user), so the worker runs on the same dependency set as the gRPC runtime it replaces.
# This file adds the Rust binary, the pool-framing shim, and the current worker sources and protobuf stubs on top.
# The image has no plaintext mode: it refuses to start without --cert, --key, --client-ca, --crl and --registry.
ARG PYTHON_RUNTIME_IMAGE=privoke-research-project-client-runtime:latest

FROM rust:1.99.1-slim-bookworm AS builder
WORKDIR /workspace
COPY rust /workspace/rust
COPY shared/proto /workspace/shared/proto
WORKDIR /workspace/rust
RUN cargo build --release --locked -p privoke-analysis --bin analysis-service

# Protobuf stubs from the proto sources in this checkout, with the versions the runtime pins.
FROM python:3.11-slim-bookworm AS protos
RUN pip install --no-cache-dir grpcio-tools==1.82.1 protobuf==7.35.1
COPY shared/proto /proto
RUN mkdir /generated \
    && python -m grpc_tools.protoc -I /proto --python_out=/generated --grpc_python_out=/generated \
       /proto/privoke/v1/parameters.proto /proto/privoke/v1/runtime.proto /proto/privoke/v1/telemetry.proto

FROM ${PYTHON_RUNTIME_IMAGE} AS runtime
USER root
# Everything the worker imports is owned by root and read-only to the service user.
COPY --from=protos --chown=root:root /generated /workspace/extension/client-runtime/generated
COPY --chown=root:root shared/python /workspace/shared/python
COPY --chown=root:root extension/client-runtime/src /workspace/extension/client-runtime/src
COPY --from=builder /workspace/rust/target/release/analysis-service /usr/local/bin/analysis-service
COPY --chown=root:root rust/services/analysis/python/worker_shim.py /opt/privoke-analysis/worker_shim.py
RUN find /workspace /opt/privoke-analysis -type d -exec chmod 0555 {} + \
    && find /workspace /opt/privoke-analysis -type f -exec chmod a-w,a+r {} + \
    && mkdir -p /var/cache/privoke-models && chown 10001:10001 /var/cache/privoke-models

ENV ANALYSIS_PORT=50054 \
    ANALYSIS_RUNTIME_ROOT=/workspace/extension/client-runtime \
    ANALYSIS_WORKER_SHIM=/opt/privoke-analysis/worker_shim.py \
    ANALYSIS_WORKER_PYTHON=/opt/venv/bin/python \
    ANALYSIS_CACHE_DIR=/var/cache/privoke-models \
    PYTHONDONTWRITEBYTECODE=1

# The cache volume is the only place the service writes besides tmpfs.
VOLUME ["/var/cache/privoke-models"]
EXPOSE 50054
USER 10001:10001
WORKDIR /workspace/extension/client-runtime
ENTRYPOINT ["/usr/local/bin/analysis-service"]
