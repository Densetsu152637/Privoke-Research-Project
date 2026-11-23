# Rust V3 fuzzer service (stage 21 of docs/plans/rust-server-rewrite.md; routine mode of stage V3-R5). Build from the repository root:
#
#   docker build -f rust/services/v3-fuzzer/Dockerfile -t privoke-v3-fuzzer-rust:<tag> .
#
# The Python fuzzer (`services/pretrained-v3/src/fuzzer_server.py`) stays in place as the parity oracle and for the historical
# study runners. This image has no plaintext mode: it refuses to start without --cert, --key, --client-ca, --crl and --registry, it
# serves only registered publisher and trainer services, and it presents a registered service certificate to the V3 runtime and to
# the checkpoint service. The sources the evidence commits to (the Python closure and the pinned BC01 inputs) are not in the image:
# mount the staged source directory read-only and name it with V3_SOURCE_ROOT. The frozen routine policy is in the image.
FROM rust:1.99.1-slim-bookworm AS builder

WORKDIR /workspace
COPY rust /workspace/rust
COPY shared/proto /workspace/shared/proto
# privoke-training links privoke-rules, which embeds this rule file at compile time.
COPY extension/client-runtime/src/regex/external_rules /workspace/extension/client-runtime/src/regex/external_rules

WORKDIR /workspace/rust
# No cargo feature is enabled.
RUN cargo build --release --locked -p privoke-v3-fuzzer --bin v3-fuzzer-service \
    && mkdir /state-skeleton

FROM gcr.io/distroless/cc-debian12:nonroot AS runtime

COPY --from=builder /workspace/rust/target/release/v3-fuzzer-service /v3-fuzzer-service
# The same frozen policy file the scheduler hashes into every routine request (V3_POLICY_FILE).
COPY --from=builder /workspace/rust/services/param-update/config/v3-policy.json /config/v3-policy.json
# The durable cycles table and the work directories live here; a mounted volume inherits this ownership.
COPY --from=builder --chown=nonroot:nonroot /state-skeleton /state

ENV V3_PORT=50172 \
    V3_BIND=0.0.0.0 \
    V3_MODE=routine \
    V3_FUZZER_STATE=/state \
    V3_POLICY_FILE=/config/v3-policy.json

# 50172: the fuzzer listener (mutual TLS, registered publisher and trainer services). Keep it on the internal network.
EXPOSE 50172
VOLUME ["/state"]

USER nonroot:nonroot

ENTRYPOINT ["/v3-fuzzer-service"]
