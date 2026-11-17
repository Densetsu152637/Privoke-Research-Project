# Rust fuzzer service (stage 21 of docs/plans/rust-server-rewrite.md). Build from the repository root:
#
#   docker build -f rust/services/fuzzer/Dockerfile -t privoke-fuzzer-rust:<tag> .
#
# The Python image (services/privoke-fuzzer/Dockerfile) stays in place as the parity oracle and for the historical study
# runners. This image has no plaintext mode: it refuses to start without --cert, --key, --client-ca, --crl and --registry,
# and it presents a registered service certificate to the runtime and the parameter-update service. The legacy random,
# contextual role-quota and fixed-curriculum samplers need no data file (the legacy prompt set is compiled in).
FROM rust:1.99.1-slim-bookworm AS builder

WORKDIR /workspace
COPY rust /workspace/rust
COPY shared/proto /workspace/shared/proto

WORKDIR /workspace/rust
# The cloud build enables no cargo feature: `workstation-loopback` is never compiled in. SQLite is compiled in.
RUN cargo build --release --locked -p privoke-fuzzer --bin fuzzer-service \
    && mkdir /dump-skeleton

FROM gcr.io/distroless/cc-debian12:nonroot AS runtime

COPY --from=builder /workspace/rust/target/release/fuzzer-service /fuzzer-service
# The durable evidence, reservation and curriculum state live here; a mounted volume inherits this ownership.
COPY --from=builder --chown=nonroot:nonroot /dump-skeleton /state

ENV FUZZER_PORT=50053 \
    PRIVOKE_FUZZER_DUMP_DIR=/state/dump \
    FUZZ_CURRICULUM_STATE_PATH=/state/curriculum.sqlite3 \
    FUZZ_CONTEXTUAL_SAMPLING_STRATEGY=legacy_random_v1

# 50053: the fuzzer listener (mutual TLS, registered publisher and trainer services). Keep it on the internal network.
EXPOSE 50053
VOLUME ["/state"]

USER nonroot:nonroot

ENTRYPOINT ["/fuzzer-service"]
