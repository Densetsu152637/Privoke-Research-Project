# Plan: Rust server rewrite and nginx removal

Revision: 2026-11-16 r3 (planning only; base `7384ec7` on `feat/nick-branch`, branch `plan/rust-rewrite`; r2 applied the plan-gate critique, r3 the round-2 critique and root's settlements)

**User instruction (16 November 2026).** "Because we use microservices, we do not need nginx. Also, plan to rewrite most of the server architecture in rust, the only exceptions being where model inference and training occur, as python is a good language for them. However, if they can be rewritten in rust, let me know and then I will decide whether it happens or not."

**Follow-up user decisions (16 November 2026).**
- "Because spaCy NER runs a model, make an equivalent rust harness in a separate repo, make it importable through crate and then use it. D1-D10 can be ported."
- The user then decided: "Use PyO3". spaCy is called through PyO3 in a supervised worker pool (stage 11), and the separate-repository plan was dropped.

**Status.** This is a plan. No code is changed by it. Every stage is `pending`.
- Stages 0 to 10 cover the server rewrite.
- Stages 11 to 22 cover the [approved inference and training ports](#approved-inference-and-training-ports-stages-11-to-22), D1 to D10.
- D11 (model fetch in Rust) is approved as networking work and is part of stage 17.

## Goals

Each goal is boolean and names its check. Commands run from the repository root on the host.

- **G1. nginx is gone from every deployment path.** `git grep -n -i nginx -- deploy .github docker-compose.yml docker-compose.prod.yml docker-compose.gpu.yml` prints nothing, and `deploy/gce/nginx.conf` does not exist. This holds only after stage 8b; until then nginx is the rollback path.
- **G2. Authentication is enforced inside each server, fail-closed, before nginx is removed.** Every non-loopback listener of a server rejects a peer without a valid client certificate.
  - A cloud build cannot start without a client-certificate verifier, and it has no plaintext or insecure flag.
  - Stage 8a has stages 3 to 6 as dependencies, and it is gated on the stage 3 to 5 negative rows passing against the real containers.
  - Check: the new UPDSEC record (stage 9) has rows A1, A3, T1, T3, T8, T12, T14 and R7 `rejected` with model unchanged, and the new static rows (replacing ST1 to ST3) hold. Startup check: each cloud binary, started without `--client-ca`, exits non-zero (`cargo test -p privoke-transport fail_closed`).
- **G3. Each UPDSEC-20261116 gap is closed or kept, and each has a negative test.** In the new record, the gap table lists all eight gaps. Each is `met`, `kept`, or `kept (telemetry)` with a reason, and each links at least one row that ran. Check: `python evaluation/update_security_report.py` followed by `python -m unittest discover -s evaluation/tests -p test_update_security.py`.
- **G4. The Rust services pass their host tests.** `cargo test --workspace --locked --manifest-path rust/Cargo.toml` exits 0 on the host.
- **G5. The Rust services behave like the services they replace.** Check: `cargo test -p privoke-conformance --manifest-path rust/Cargo.toml`. It replays the stage 0 corpus and compares outputs under the rules in `tests/conformance/normalization.toml`:
  - **Byte equality, no normalisation:**
    - artifacts
    - canonical JSON
    - fingerprints
    - streamed chunk sequences
    - V3 manifests and assets
    - native-messaging and gRPC-Web payloads
  - **Receipts and audit lines:** byte equality after normalisation. Wall-clock timestamps (fields ending in `_at`, `timestamp`, `time`) become `<TS>`. Server-generated identifiers (UUIDs not supplied by the request) become `<ID:n>`, numbered by first appearance, so that equality of reuse is still checked. Client-supplied `request_id`, `base_version`, digests and versions are never normalised.
  - **Telemetry:** integer counts and stored marginals are exact. Floating-point estimator outputs agree within 4 ULP. They come from the same IEEE operations, so the expected difference is 0; the tolerance only covers reordering of `log` and `exp` in libm.
- **G6. Python inference and training code does not change unless a stage owns the change.** The check is a single command, with no brace expansion, that works in PowerShell and Git Bash:
  ```
  git diff --exit-code asiaccs-2027-submission -- extension/client-runtime/src/LLM extension/client-runtime/src/NER extension/client-runtime/src/regex extension/client-runtime/src/detection extension/client-runtime/src/classification extension/client-runtime/src/v3 extension/client-runtime/src/pipeline.py extension/client-runtime/src/model.py extension/client-runtime/src/telemetry/privacy.py services/privoke-fuzzer/src/prompt_generation services/privoke-fuzzer/src/training services/pretrained-v3/src/runtime_server.py services/pretrained-v3/src/fuzzer_training.py services/pretrained-v3/src/audience_schedule.py shared/python/privoke_model
  ```
  It must exit 0. The tag name is set in stage 0. Stage 6 changes only the transport files it lists, which are outside these paths.
- **G7. Recorded evidence is not invalidated silently.** Check: `python evaluation/check_revalidation.py --plan docs/plans/rust-server-rewrite.md --base asiaccs-2027-submission`, written in stage 9, exits 0. It asserts the following:
  1. Every row of the [revalidation table](#research-evidence-and-revalidation) has a status from {`revalidated (<record path>)`, `historical (unchanged path)`, `not claimed for the Rust build`}, and every cited record exists.
  2. `git diff --diff-filter=MD --name-only asiaccs-2027-submission -- paper/research docs/experiments` is empty, so existing evidence was only added to, never modified or deleted.
  3. `paper/research/update-security-20261116.md` and its JSON are byte-identical to the tag.

  Until the script exists, the same three items are a manual checklist in the stage 9 handoff.
- **G8. Cloud clients can fetch the default V3 package. This is a deliberate behaviour change.** `GetModelPackage` and `StreamModelAsset` become public RPCs on the authenticated model listener. Today nginx does not route them. Check: the stage 8a smoke test fetches `privoke-v3-balanced` over mutual TLS and verifies its pin. Each new public RPC also has its negative rows (R7, R8).

## Scope and non-goals

**In scope:**
- Moving server and infrastructure code to Rust.
- Porting the approved inference and training components D1 to D10 to Rust. NER uses the unchanged spaCy, called through PyO3 (stage 11).
- Removing nginx and replacing it with in-service mutual TLS and authorisation.
- PKI and identity design.
- Compose, deployment and CI changes.
- Conformance and security revalidation.
- Sequencing against the paper deadline.

**Non-goals:**
- Changing the Python inference and training code. The approved Rust ports (stages 11 to 22) are new code, and the Python implementation stays unchanged as the oracle and as the measured system the paper describes (G6).
- Changing the protobuf contracts in `shared/proto/`, except for additions that a stage justifies.
- Changing the browser extension's gRPC-Web wire format.
- Changing the native-messaging protocol.
- Editing the paper.
- Pushing.

Before the deadline, only stage 0 and stage 1 may run in this repository (see [sequencing](#sequencing-against-the-11-december-2026-deadline)). Stage 11 now lives in this repository, not a separate one. Root's earlier permission to start it before the deadline was based on the separate repository, so root needs to re-confirm it for the PyO3 stage. Until then it follows the rule above.

## Assumptions

- The ASIACCS deadline is 11 December 2026 ([revision plan](asiaccs-2027-revision.md)).
- The submitted paper and the anonymous artifact describe the current Python, Go and nginx build.
- The host has Rust 1.99.1 (`cargo --version` on 2026-11-16). Go is not on the host: UPDSEC ran the Go service in Docker.
- The protobuf contracts stay the interface between components. These clients keep their current transports:
  - The extension uses gRPC-Web to a loopback bridge, and native messaging to the supervisor.
  - The Python runtime, fuzzer and pretrained-v3 servers use gRPC.
- Model packages are non-secret released artifacts. Authentication on retrieval is for admission and accounting, not confidentiality.
- Effort sizes (S up to about 1 week, M 1 to 4 weeks, L over 4 weeks, one engineer) are estimates and have not been measured.

## Relevant paths

- Servers:
  - `services/model-streaming-service/` (Go)
  - `services/param-update-service/`
  - `services/telemetry-service/`
  - `services/privoke-fuzzer/`
  - `services/pretrained-v3/`
- Workstation:
  - `extension/runtime-supervisor/`
  - `extension/client-runtime/`
  - `extension/src/runtime-client.js` (gRPC-Web caller)
- Shared:
  - `shared/proto/privoke/{v1,experimental}/`
  - `shared/python/privoke_model/`
  - `shared/python/privoke_service/`
  - `shared/python/grpc_healthcheck.py`
- Deployment:
  - `docker-compose.yml`
  - `docker-compose.prod.yml`
  - `docker-compose.gpu.yml`
  - `deploy/gce/{compose.yml,nginx.conf,deploy.sh,bootstrap.sh,tests/smoke.py}`
  - `.github/workflows/{service-stack-ci.yml,deploy-gce.yml}`
  - `evaluation/compose.*.yml` (study stacks)
- Security harness:
  - `evaluation/update_security.py`
  - `evaluation/update_security_pki.py`
  - `evaluation/update_security_report.py`
  - `evaluation/tests/test_update_security.py`
- NER reference: `extension/client-runtime/src/NER/`, `evaluation/.venv-v1-v3-pipeline` (spaCy 3.7.5, thinc 8.2.5, `en_core_web_sm` 3.7.1, `en_core_web_lg` 3.7.1).
- Proposed new paths:
  - `rust/` (Cargo workspace)
  - `tests/conformance/` (golden corpus captured in stage 0)
  - `rust/crates/privoke-spacy/` and `rust/services/spacy-worker/` (stage 11, PyO3 spaCy worker); no separate NER repository

## Related docs

When documents conflict, the first one listed wins. Later documents defer to earlier ones.

1. Repository `AGENTS.md`: the host Python test workflow, Compose usage, and LLM-layer isolation.
2. [ASIACCS 2027 revision plan](asiaccs-2027-revision.md): it governs everything before the deadline.
3. [UPDSEC-20261116](../../paper/research/update-security-20261116.md): gap definitions and attack rows.
4. [Google Cloud deployment](../deployment/google-cloud.md), especially the [ingress routing](../deployment/google-cloud.md#ingress-routing) section and section 4 on credentials.
5. [Claim ledger](../../paper/research/claims.md).
6. This plan.

## Current architecture (from source at `7384ec7`)

The current trust boundaries are as follows:
- nginx (`deploy/gce/nginx.conf`) terminates TLS 1.2/1.3 and requires a client certificate from one client CA (`ssl_verify_client on`). It also does the following:
  - It rate-limits per IP (20 r/s, burst 40, 20 connections).
  - It caps request bodies at 1 MB.
  - It applies 60 s gRPC timeouts.
  - It routes only `ModelStreamingService/{Health,StreamModelParameters}` and `TelemetryService/RecordTelemetry` to plaintext upstreams, and returns 404 for every other path.
- Every service opens a plaintext gRPC port with no credential checks (UPDSEC ST1 to ST3).
- Clients use one `PRIVOKE_CLOUD_TARGET` for both cloud services (`shared/python/privoke_service/stack_connection.py`). This works today only because nginx multiplexes the two services by path.

## Component inventory and classification

Classes:
- **(a) Server/infra → Rust.**
- **(b) Inference/training → stays Python during the server rewrite (stages 0 to 10).** The approved ports (stages 11 to 22) then add Rust equivalents, and the Python code stays unchanged as the oracle.
- **(a/b) Mixed:** the component is split.

| Component | Path | Language now | What it does | Class | Plan |
| --- | --- | --- | --- | --- | --- |
| Model streaming service | `services/model-streaming-service/cmd/server/*.go` | Go | Catalog. Legacy JSON Tiny artifact snapshot streaming. Standard V3 manifests and assets (`standard_v3.go`). Validation of training-contract metadata, which must equal Python canonical JSON byte for byte (`contextual_training.go`, `scratch_presence.go`, `pretrained_context.go`). Health subcommand. | a | Rust, stage 3 |
| Param update service | `services/param-update-service/app/{server,validation,receipts,audit,bootstrap,config}.py` | Python | Validates updates (model, base version, tensors, shapes, finite values, per-coordinate bound). Compare-and-swap publication with atomic rename. Durable receipts in SQLite. Audit log. Bootstrap. No backpropagation. | a | Rust, stage 5 |
| Training-cycle scheduler | `services/param-update-service/app/{fuzzer_requests,training_cycles}.py` | Python | Timed, persistent requests to the fuzzer (SQLite state, retries, seeds). This is orchestration, not training. | a | Rust, stage 5 |
| Telemetry collector | `services/telemetry-service/app/{server,validation,storage,config}.py` | Python | Validates LDP packets. Stores lifetime marginals in SQLite. Summary uses nominal inversion and clipping. | a | Rust, stage 4. The estimator is ported with the Python code kept as a parity oracle, because claims C7 and C34 cite it. The client randomizer port is D8 (stage 18; see [assessment D8](#d8-telemetry-ldp-randomizer-and-estimator)). |
| Fuzzer service (legacy) | `services/privoke-fuzzer/src/{fuzzer_service,main,cli,config,runtime_client,json_records}.py` | Python | gRPC `FuzzerService`, cycle control, calls to the runtime for gradients, dumps. | b (kept whole) | Stays Python. `fuzzer_service.py` imports `prompt_generation` and `training` and runs them in-process (sampling, batch training, evidence persistence), so its orchestration is inseparable from the training loop. Stage 6 adds mutual TLS only. Approved Rust port: D6 (stage 21). |
| Fuzzer prompt generation | `services/privoke-fuzzer/src/prompt_generation/*` | Python | Seeded synthetic training curricula (Python `random`, MT19937). | b | Stays. Approved Rust port: D5 (stage 20). |
| Fuzzer training and update aggregation | `services/privoke-fuzzer/src/training/*` | Python | Batches, transforms, gradient aggregation into update deltas, retention evidence. | b | Stays. Approved Rust port: D5 (stage 20). |
| Pretrained-v3 checkpoint server | `services/pretrained-v3/src/{checkpoint_server,checkpoint_store,common}.py` | Python | Experimental content-addressed checkpoint store and publication receipts (`CheckpointService`). | a (experimental) | Deferred. Stage 10 is optional and runs only if V3 training graduates from experimental. |
| Pretrained-v3 fuzzer server | `services/pretrained-v3/src/fuzzer_server.py` | Python | Experimental `V3FuzzerService` orchestration. | b (experimental) | Stays Python, for the same reason as the legacy fuzzer: it imports `fuzzer_training.schedule` in-process to produce the frozen sampling stream. It is not part of stage 10. A Rust replacement is part of D6 (stage 21). |
| Pretrained-v3 runtime and training | `services/pretrained-v3/src/{runtime_server,fuzzer_training,audience_schedule}.py` | Python (torch) | V3 semantic inference and physical training (`TrainingService`). Frozen AU3/BC01 sampling schedules. | b | Stays. Approved Rust port: D3 (stage 14); D4 (stage 19); D5 (stage 20). |
| Client runtime: gRPC shell | `extension/client-runtime/src/grpc_main.py`, `hosting/{grpc_server,serialization,runtime_config,analyzer,models}.py`, `env.py`, `config.py`, `dependency_check.py` | Python | `PrivokeRuntimeService` server (image `CMD`), request and response serialisation, runtime configuration. | a, held in Python | Stays in the Python worker. Reason: it is the in-process host of inference and gradients. Each RPC calls into the torch, spaCy and pipeline objects in the same interpreter. A Rust replacement would need either PyO3 (rejected, see [boundary](#pythonrust-boundary)) or a second Python-side server, so the same shell would still exist. The Rust supervisor becomes the external edge in front of it instead. Stage 6 changes listener security only. |
| Client runtime: HTTP JSON shell | `extension/client-runtime/src/main.py`, `hosting/server.py` | Python | Alternative `ThreadingHTTPServer` JSON host of the same analyzer; not used by the container images, which run `grpc_main.py`. | a, held in Python | Not ported. Same in-process reason as the gRPC shell. Deprecating it is a separate decision for root, because evaluation scripts may use it. |
| Client runtime: model fetch | `extension/client-runtime/src/LLM/privoke/{v3_package,parameter_stream}.py` | Python | Downloads V3 packages and legacy tensor streams from the model service, verifies pins, shapes and finite values, and writes the cache that inference loads. | a, held in Python | Stays in Python. Reason: verification is coupled to the loader that builds the torch model, and the installed-client evidence (C42, V3 timing) measured this path. Moving download and pin checking to Rust is D11, which root has approved as networking work. It is done in stage 17. It is listed with the ports because it changes an evidence path, even though it is not inference. |
| Client runtime: detection pipeline | `extension/client-runtime/src/{pipeline,model,detection/*,classification/*,task_readout,pretrained_context,transformer_encoder,util}.py` | Python | Normalisation, layer selection, policy aggregation, semantic readout. | b | Stays. Normalisation and aggregation fix the recorded detector results. |
| Regex layer | `extension/client-runtime/src/regex/*` | Python (`regex`, Presidio recognisers) | Deterministic rules, validators, Presidio imports. | b (detector) | Stays. Approved Rust port: D2 (stage 12). |
| NER layer | `extension/client-runtime/src/NER/*` | Python (spaCy, optional GLiNER) | spaCy `en_core_web_sm`, post-filter, pattern entities. | b | Stays. Approved Rust port: D1 (stages 11 and 13); D9 (stage 15). |
| Semantic classifiers | `extension/client-runtime/src/LLM/{local_classifier,privoke_classifier,abs_classifier,prompt}.py`, `LLM/privoke/{streamed_model,presence_model,scratch_presence_model,pretrained_context_model}.py`, `v3/model.py` | Python (torch, transformers, tokenizers, safetensors) | V3 encoder and heads, legacy Tiny model, presence models. | b | Stays. Approved Rust port: D3 (stage 14). |
| External LLM classifier | `extension/client-runtime/src/LLM/open_classifier.py` | Python (`openai`) | Remote API classifier. | b | Stays. Approved Rust port: D10 (stage 16). |
| Gradient and local training | `extension/client-runtime/src/LLM/privoke/{training,full_adam_training,window_training,supervised_training,presence_training,sensitive_retention_training,reference_preparation}.py`, `v3/training.py` | Python (torch) | `ComputeSemanticGradients`, `ComputeUnderlyingModelGradients` and `ComputePresenceGradients`. Local SGD and FULL projected Adam. | b | Stays. Approved Rust port: D4 (stage 19). |
| Telemetry reporter (client) | `extension/client-runtime/src/telemetry/{privacy,event_emitter}.py` | Python | Randomised response, persistent budget ledger, delivery. | a (infra), held | Stays in Python. The audited finite kernel (C34) is `privacy.py`, and it must stay byte-identical (G6). Stage 6 changes only the delivery channel in `event_emitter.py`, so that it can use the telemetry credential. Approved Rust port: D8 (stage 18). |
| Runtime supervisor | `extension/runtime-supervisor/src/{main,runtime_supervisor,grpc_web_bridge,native_messaging_host}.py` | Python | Native-messaging host (length-prefixed JSON on stdio). Launches the supervisor and the fixed-argv runtime child. gRPC-Web to gRPC bridge with an origin allowlist and 30/35 s timeouts. `PrivokeRuntimeControlService`. | a | Rust, stage 7 |
| Shared model contracts | `shared/python/privoke_model/{artifact,fingerprint,readout,v3_contract,standard_v3,full_adam,contextual_training,sensitive_retention,window_training,scratch_presence,pretrained_context}.py` | Python | Artifact codec and checksum. Two canonical-JSON variants (`full_adam.canonical`: ASCII-escaped; `sensitive_retention.canonical_bytes`: UTF-8 plus LF). Tensor fingerprints. V3 manifest rules. | a/b | A Rust port in `rust/crates/privoke-contracts` serves the Rust servers (stage 1). The Python originals stay authoritative for training, and the conformance corpus binds the two. |
| Shared training contracts | `shared/python/privoke_model/{presence,training_data,window_training}.py` | Python | Lexical presence inference. Train/eval text keys. Window training. | b | Stays. |
| Service helpers | `shared/python/privoke_service/{environment,logging,validation,stack_connection}.py`, `shared/python/grpc_healthcheck.py` | Python | Environment parsing. Stack selection and the mutual-TLS client channel. Health probe. | a (Python consumers stay) | Stays for the Python processes. Stage 6 adds server credentials and per-service cloud targets. Rust equivalents live in `rust/crates/privoke-transport`. |
| Contracts | `shared/proto/privoke/v1/{parameters,runtime,telemetry}.proto`, `shared/proto/privoke/experimental/v3.proto` | protobuf | Service interfaces. | interface | Unchanged. Rust uses `tonic-build`, with `protox` so that `protoc` is not needed on Windows. |
| Compose stacks | `docker-compose.yml`, `docker-compose.prod.yml`, `docker-compose.gpu.yml`, `evaluation/compose.*.yml` | YAML | Development, production and study stacks. | a | Stage 8a switches the service images. Study compose files stay pinned to their recorded revisions (see revalidation). |
| Cloud deployment | `deploy/gce/{compose.yml,nginx.conf,deploy.sh,bootstrap.sh,tests/smoke.py}`, `.github/workflows/deploy-gce.yml` | YAML, shell, nginx, Python | VM stack and ingress. | a | Stage 8a cuts over with nginx kept as rollback; stage 8b removes nginx. |

## Python↔Rust boundary

The decision is a **separate process over gRPC**, using the existing contracts. The Rust processes are the network-facing servers. The Python processes are workers that the Rust side reaches through the gRPC services in `shared/proto` that they already implement:
- `PrivokeRuntimeService` on the client runtime
- `FuzzerService` on the fuzzer
- `TrainingService` and `V3FuzzerService` on pretrained-v3

How the workers are reached:
- **Workstation:** the Rust supervisor launches the Python runtime as a child, as the Python supervisor does today, and connects to it on loopback.
- **Server:** the Python workers run on the internal Compose network with mutual TLS (stage 6).

Alternatives considered against the same requirements: keep the Python evidence path unchanged, isolate crashes, ship on Windows and Linux, and keep the host test workflow.

| Option | Verdict | Reasons |
| --- | --- | --- |
| **Process boundary over gRPC (chosen)** | Accept | <ul><li>The contracts already exist and are tested.</li><li>The Python worker runs the same code and interpreter that produced the recorded evidence.</li><li>The GIL and torch thread pools stay out of the Rust async runtime.</li><li>A crash or OOM in inference cannot take the network edge down.</li><li>Independent toolchains: torch wheels on one side, a static Rust binary on the other.</li><li>Python tests keep running on the host exactly as `AGENTS.md` prescribes.</li></ul> Cost: one extra loopback hop on the workstation. The bridge already adds a hop today, so the stage 7 check is that the end-to-end median does not regress. This is an estimate and must be measured. |
| PyO3, Rust embedding CPython (whole runtime) | Reject (for spaCy alone, the user chose PyO3 in an out-of-process worker pool; see stage 11) | <ul><li>It links CPython, torch and spaCy into the Rust binary, which is fragile with Windows DLLs and virtual environments.</li><li>The GIL serialises calls.</li><li>A Python fault kills the server.</li><li>The inference code is still Python, so nothing is gained.</li></ul> |
| PyO3, Python importing a Rust extension (`privoke_contracts_rs`) | Reject for now; revisit | It would remove the duplicate contract code. However, it changes the code path behind recorded training evidence. Revisit after the deadline, once the conformance corpus shows byte equality and the user wants a single contract implementation. |
| Keep Python and Go servers; add mutual TLS only | Reject | It does not satisfy the user's instruction. It remains the fallback if a stage fails its parity gate. |

## nginx replacement design

nginx is removed only after every function it performs has an in-service replacement:

| nginx function | Replacement in each Rust server | Stage |
| --- | --- | --- |
| TLS termination (1.2/1.3) | `tonic` with `rustls`. The server config is built directly so that the client verifier can be set. | 1, 3, 4, 5 |
| Client certificate required, one CA, depth 2 | `rustls::server::WebPkiClientVerifier`, with roots from the client CA, CRLs loaded, and anonymous clients refused. | 1 |
| Method allowlist with 404 default | A **public listener** serves only the public RPCs. Private RPCs go on a separate **internal listener**. An authorisation interceptor maps (role, RPC) to allow, and returns `PERMISSION_DENIED` otherwise. | 3 to 5 |
| Rate limits per IP, 20 connections | `tower` `ConcurrencyLimit`, plus a per-peer limiter (`tower_governor`), plus a connection cap. The limiter key depends on the service:<br>• **Model service:** keyed by the installation identity from the certificate.<br>• **Telemetry service:** keyed by source IP, because every reporter shares one certificate (see the telemetry notes below), so a certificate key would put all clients in one bucket. | 1 |
| 1 MB body, 60 s timeouts | `max_decoding_message_size` and `tower::timeout` per service. Streaming RPCs keep their existing per-message limits. | 1 |
| One `:443` shared by two services | Model on `:443`, telemetry on `:8443` (see the [port decision](#port-decision)). The client gets `PRIVOKE_CLOUD_MODEL_TARGET` and `PRIVOKE_CLOUD_TELEMETRY_TARGET`; an unset value falls back to `PRIVOKE_CLOUD_TARGET`, for model only. The firewall rule in section 3 of the deployment guide changes to match, at the end of the stage 8a cutover. | 6, 8 |
| `/healthz` on 127.0.0.1:8081 | Each Rust binary has a `healthcheck` subcommand, as the Go service has now, and the gRPC `Health` RPC on the internal listener. | 3 to 5 |
| Re-resolve upstreams after recreate | Not needed: there is no proxy hop. | — |

**Fail-closed construction.**
- `privoke-transport` builds a server only from a `ServerTlsConfig`, and that type cannot be constructed without a client-CA root store and a CRL path. There is no plaintext constructor in the cloud build.
- Plaintext loopback is available only behind the cargo feature `workstation-loopback`. That feature is enabled only for `runtime-supervisor` and for tests.
- The cloud Dockerfiles build with `--no-default-features`. A CI or host test asserts that the release binaries do not contain the loopback code path (`cargo tree -e features` shows no `workstation-loopback`).
- A cloud binary started without `--client-ca`, `--crl`, `--registry`, `--cert` or `--key` exits non-zero before it binds.

**Identity (stage 2).** Every principal holds an X.509 certificate from the private client CA. The identity is carried in the certificate's URI SAN:
- `urn:privoke:installation:<uuid>`, role `consumer`
- `urn:privoke:service:<name>`, role `publisher`, `trainer` or `runtime`
- `urn:privoke:reporter`, the shared telemetry credential

How services use the identity:
- Services derive `consumer_id` and `source_id` from the peer certificate (`Request::peer_certs`, parsed with `x509-parser`).
- A request field that disagrees with the certificate identity is rejected.
- A registry file (`installations.toml` and `services.toml`) authorises identities individually.

**Enrolment and renewal of per-installation certificates (stage 2 acceptance).** This is operator-mediated, which suits the deployment's scale (a private research installation; section 4 of the deployment guide already issues certificates by hand). The CA key stays offline. No online issuing endpoint is added, so no new RPC or contract is needed.

1. **Who enrols.** The operator, holding the offline client-CA key, is the only issuer. The user installs the extension, then runs `privoke-supervisor enrol`. This generates the key pair locally (the private key never leaves the machine, file mode 0600 or user-only ACL) and writes a CSR whose SAN carries a fresh installation UUID.
2. **How the desktop receives its certificate.** The user sends the CSR, which is public, to the operator by any channel. The operator verifies the request out of band (the user and a fingerprint confirmed in person or by a known contact), then runs `privoke-pki sign --installation <uuid> --days 180`, adds the UUID to `installations.toml` and publishes the registry. The operator returns `client.crt` and the server CA. `privoke-supervisor install-cert` checks that the certificate matches the local key and SAN before storing it.
3. **Renewal, including offline periods.** Certificates are valid for 180 days. Inside `privoke-supervisor`, `status` warns from 30 days before expiry, and `renew` creates a new key and CSR under the same UUID. The operator signs it by the same manual path, so no network renewal service exists.
4. **Expiry while offline is safe.** An installation that stays offline past expiry loses only cloud model refresh and telemetry delivery. Local inspection keeps using the cached, pin-verified package in `MODEL_PACKAGE_CACHE_DIR`. The next contact fails closed at the handshake until the user renews, and the supervisor's status reports this.
5. **Revocation.** The operator adds the UUID to the registry deny list (immediate) and issues a CRL (applied at the handshake; see CRL hot reload below).

Limitation, stated rather than hidden: renewal needs a human at both ends, so this does not scale beyond a small cohort. Automatic renewal would need an online issuer, and that is out of scope. Revisit if the installation count grows beyond what the operator can serve by hand. On this basis the plan closes GAP-NO-CREDENTIAL-MECHANISM and GAP-NO-PER-INSTALLATION-AUTHZ for model retrieval and keeps the latter for telemetry.

**CRL and registry hot reload (stage 1, tested by X13 in stage 9).**
- Each listener accepts TCP itself and runs a `tokio-rustls` `TlsAcceptor`. The acceptor is built per connection from an `ArcSwap<Arc<rustls::ServerConfig>>`, and tonic serves the result with `serve_with_incoming`. tonic's built-in TLS cannot swap configs, which is why the acceptor is separate.
- A reloader watches the CRL and registry files (`notify`, plus a 60 s poll as a fallback). It parses the new CRL and checks its signature against the client CA and that `nextUpdate` is in the future. It then builds a new `WebPkiClientVerifier` and `ServerConfig` and stores them atomically, so new handshakes use the new config.
- A malformed or stale CRL is refused. The old config stays active, and an error is logged and exposed in `Health`.
- Existing connections were authenticated under the old config. A maximum connection age (10 min, with graceful drain) bounds how long a revoked peer can keep a stream open. The registry deny list is checked on every RPC, so it takes effect immediately even on open connections.
- Tests:
  - Revoke one installation, replace the CRL file, and within the poll interval a new handshake fails while a control installation still connects.
  - A corrupt CRL keeps the previous config.
  - A deny-listed UUID gets `PERMISSION_DENIED` on an open connection.

<a id="port-decision"></a>**Port decision (separate hostname on 443 versus port 8443).** Without a proxy, two TLS servers cannot share one IP and port. SNI routing is a proxy function.
- **A separate hostname on 443** therefore needs a second external IP routed to the VM (GCE protocol forwarding or a second NIC). Each container then publishes `<ip>:443`. It works on networks that allow only 443, but it adds a reserved static IP, guest routing configuration and a second DNS name and server certificate.
- **Port 8443 for telemetry** needs nothing extra, but restrictive networks that allow only 443 will block it.

Decision: **8443 for telemetry, 443 for model.** Reasons:
- Model retrieval, the path whose failure matters, stays on 443.
- Telemetry is best-effort by design. Blocked delivery is already handled as an outage: the budget is reserved and not refunded, which is the privacy-safe direction, and inspection is unaffected.
- The single-IP VM layout and costs stay unchanged.

Revisit (switch to a second IP on 443) if stage 9 or field reports show material telemetry loss from blocked 8443. The client configuration already supports separate targets, so the switch is configuration-only.

**Telemetry credential, abuse and poisoning.**
- Per-installation certificates would make telemetry reports linkable to an installation at the transport. The collector therefore accepts the shared `urn:privoke:reporter` credential. It is delivered to installations at enrolment as a second key pair (`PRIVOKE_TELEMETRY_TLS_CERT_FILE` / `PRIVOKE_TELEMETRY_TLS_KEY_FILE`, loaded by `stack_connection`) and never persists or logs the peer identity.
- Consequence: GAP-NO-PER-INSTALLATION-AUTHZ and GAP-IDENTITY-SELF-ASSERTED are `kept (telemetry)`. Revoking the reporter credential revokes every reporter, and recovery means rotating it at the next enrolment or renewal of each installation.
- Abuse and poisoning: anyone holding the shared key can submit arbitrary well-formed packets. They could extract it from any installation, since it is on every client. LDP reports cannot be checked for truthfulness by construction, so a holder can bias the collected marginals (a known class of poisoning attacks on LDP frequency estimation).
- Mitigations:
  - a per-source-IP rate and daily cap
  - the message-size and field-domain validation that already exists
  - a per-IP daily acceptance counter, which records only counts by day and not identities, for detecting anomalies
- Residual risk, to be stated wherever telemetry results are used: aggregates are not robust to a motivated key holder, and the paper's telemetry claims (C7, C34) concern privacy of honest reports, not integrity of aggregates.

## UPDSEC gap closure map

Every gap from [UPDSEC-20261116](../../paper/research/update-security-20261116.md#unmet-properties-gaps) appears below. The new record extends `evaluation/update_security.py` against the Rust services in stage 9. Rows keep their IDs; new rows use the `R` prefix.

| Gap | Decision | Mechanism | Negative test (must be rejected, model unchanged) |
| --- | --- | --- | --- |
| GAP-NO-PUBLISHER-AUTH | Close (stage 5) | `ParamUpdateService` serves only on the internal listener. It requires mutual TLS and the `publisher` role for `SubmitParameterUpdate`, and `publisher` or `trainer` for `GetParameterUpdateStatus`. | A1 and T14 rerun. Add R1: a valid `consumer` installation certificate submits an update and gets `PERMISSION_DENIED`. |
| GAP-IDENTITY-SELF-ASSERTED | Close for update and model retrieval (stages 3 and 5). `kept (telemetry)`: reports carry no identity field, and the shared reporter credential is deliberately not individual. | `source_id` and `consumer_id` come from the certificate SAN. A mismatching field is rejected with `PERMISSION_DENIED`. | A2 and T2 rerun. Add R2: a publisher certificate for `service:test-trainer` claims `source_id=server-fuzzer`. The telemetry row is static: no identity is stored. |
| GAP-NO-CREDENTIAL-MECHANISM | Close (stage 2). The mechanism is client certificates with 180-day validity, checked in-service, issued and renewed through the operator-mediated enrolment above. There are no bearer tokens. | Expiry and not-before are checked by `rustls` at the handshake. Registry entries carry an expiry. | A3 rerun: the bogus token is ignored and the request still fails for lack of a certificate. Add R3: an expired certificate, a not-yet-valid certificate, and a certificate without client-auth EKU are each rejected at the handshake by the real service, not a stand-in. |
| GAP-NO-RETRIEVAL-AUTH | Close (stage 3) | Every model RPC except `Health` requires the `consumer` role. `GetModelPackage` and `StreamModelAsset` become publicly reachable, a behaviour change (G8). | T1, T3, T8 and T12 rerun without a certificate. Add R4: a certificate from a foreign CA with a valid subject. Add R7 (new public `GetModelPackage`): no certificate, an unregistered installation, the reporter credential, and a path-traversal or unknown model id, all through the public listener. Add R8 (new public `StreamModelAsset`): the same identities, plus a wrong pin and a non-allowlisted asset name (as T9 to T11), through the public listener. Add R9: `GetModelParameters` and `ParamUpdateService` methods on the public listener return `UNIMPLEMENTED`. |
| GAP-NO-PER-INSTALLATION-AUTHZ | Close for model retrieval (stage 2 registry, enforced in stage 3). `kept (telemetry)`: the shared reporter credential avoids making reports linkable, and revoking it is all-or-nothing. | Installation IDs in the registry; unknown IDs are refused. | X8 changes: a second certificate from the same CA whose installation ID is not registered gets `PERMISSION_DENIED`. A registered one is accepted (positive control). The telemetry row records the kept property with an installation certificate (accepted only if it is the reporter credential). |
| GAP-NO-REVOCATION | Close (stages 1 and 2) | CRL in `WebPkiClientVerifier`, hot-reloaded by an atomic `ServerConfig` swap, plus the registry deny list and a maximum connection age. | X13 changes from `not_applicable` to a live run, as in the CRL hot reload tests above: a revoked installation's new handshake fails without a restart, a corrupt CRL keeps the old config, and a deny-listed ID gets `PERMISSION_DENIED` on an open connection. |
| GAP-NO-CUMULATIVE-BOUND | Close as configurable policy (stage 5). The default is chosen in stage 5 from replayed recorded update sequences. | Two new checks on top of the per-coordinate bound: a per-update L2 bound, and a rolling cumulative L2 drift budget measured from the anchored release. Both are recorded in the receipt. | E6 and E7 rerun and are rejected once the budget is exceeded. Add R5: drift spread across many small updates, each under the per-update bound, is rejected at the budget. |
| GAP-LOOPBACK-PLAINTEXT-POLICY | Split. **Close** for internal Compose mode: the Python and Rust servers on the Compose network use mutual TLS (stage 6). **Keep** for workstation loopback (supervisor to Python worker, bridge to supervisor). | Reason for keeping: traffic never leaves the host, and any local process can already reach the loopback gRPC-Web bridge, so TLS adds no boundary there. Optional hardening (revisit item): a per-launch secret that the supervisor passes to the worker on stdin and checks in metadata. | X16 changes: in internal mode with a non-loopback target, plaintext is refused. Add R6: a Compose-network plaintext call to `param-update` or `client-runtime` is refused. Loopback stays a documented `kept` row. |

The static rows ST1 to ST10 become new static rows that check the Rust configuration instead of `nginx.conf`. The existing static checks parse `nginx.conf` (`evaluation/update_security.py`, around lines 1111 to 1133), so they must be rewritten in the same stage that deletes the file.

## Research evidence and revalidation

Recorded results remain historical measurements of the Python and Go build that produced them. They are never edited to describe the Rust build. Where the Rust build is claimed to behave identically, new records establish it. A server-only rewrite does not touch inference or training, so most detector and model claims stay valid as-is: the Python worker that produced them is unchanged and still produces them. Only claims about the replaced servers need new evidence.

Before the paper deadline, the Python, Go and nginx build being assessed has to stay intact, so nothing on this list may be done before submission. Each of these surfaces needs a new record:

| Claim or record | Why it is affected | Stage that revalidates |
| --- | --- | --- |
| UPDSEC-20261116. Paper G2, G7, the threats table and the guarded-update text (`paper/main.tex` around lines 101, 106, 125 and 241, which say update-path authentication is pending and the cumulative change is unbounded). | The services and their authentication change. Closing gaps makes those paper sentences out of date. | 9: new record `UPDSEC-<date>`. The paper changes only under its own scope authorisation. |
| Legacy guarded-update mechanism (paper section "Guarded Detector Updates"). C4, C10 and C16 used Python `param-update`. | Validation, compare-and-swap and receipts are reimplemented. | 5: byte equality of published artifacts on the stage 0 sequences keeps the historical results applicable. A new cumulative bound is a behaviour change and is disclosed. |
| Standard V3 serving (paper path table). Package pins. | The Go service is replaced. | 3: byte equality of manifests and assets. |
| Ingress claim of three routed RPCs: UPDSEC ST5 and ST6, the paper threats row "Client certificates on streaming and telemetry routes" (`main.tex`, around line 125), and the [ingress routing](../deployment/google-cloud.md#ingress-routing) section of the deployment guide. | Behaviour change. The public surface grows from three RPCs to `Health`, `StreamModelParameters`, `GetModelPackage` and `StreamModelAsset` on the model service, plus `RecordTelemetry`. Authentication moves from nginx into each service. | 9: new static rows and R7 to R9 in the new UPDSEC record. The historical record keeps its three-RPC statement unchanged. The paper statement is `not claimed for the Rust build` until edited under its own authorisation. |
| C1 (component suites pass). | The suites change. | 3 to 7: new suite counts in a new record. |
| C5, C6, C42 (B14 installed client). V3 installed timing (`main.tex`, around line 327). Paper around line 325 ("supervisor, bridge"). | The supervisor, bridge and native host are rewritten. Bridge timeouts set the silent-broker timing (about 32 s). | 7: rerun the installed-browser protocol (`paper/research/installed-browser-protocol.md`) only if the paper or artifact is to describe the Rust build. Otherwise mark `not claimed for the Rust build`. |
| C7, C34 and the telemetry audit (collector inversion and clipping). | The collector estimator is reimplemented. | 4: exact estimator parity on the corpus. The client kernel is unchanged unless the user chooses D8. |
| Anonymous artifact (ASIACCS-S8) and reproduction capsules (C41, RP14). | The artifact pins the current build. | Tag the submission revision in stage 0. The artifact is never rebuilt from the Rust tree. |
| Study compose files (`evaluation/compose.*.yml`), whose results cite Go and Python images. | The images change. | Recorded studies stay reproducible from their own revisions. Stage 8a does not edit historical study stacks. |
| Approved ports D1 to D10 (stages 11 to 22). | They change the inference and training implementation. | Each stage's parity criterion and revalidated claims are in the [port table](#approved-inference-and-training-ports-stages-11-to-22). Together they cover most of C2 to C56. Until a stage's record exists, those claims stay `not claimed for the Rust build`. |

## Sequencing against the 11 December 2026 deadline

- **Before 11 December 2026:** run stage 0 (tag, conformance capture) and, optionally, stage 1 (Rust workspace and contract crate) on `plan/rust-rewrite` or a successor branch. Do not merge into the branch the submission and artifact are built from. Make no change to `services/`, `extension/`, `deploy/`, `shared/python/`, `paper/` or `.github/`. In particular, no CI workflow changes before the deadline: the Rust tests run on the host only (`cargo test`).
- **After submission:** stages 2 to 9 in order. The artifact-evaluation and camera-ready builds use the submission tag. If the paper is to describe the Rust build, stage 9 and the revalidation rows run before camera-ready, and the paper is edited under its own authorisation.
- **Approved ports (stages 11 to 22, D1 to D10):**
  - They run on a non-submission branch and never change the submission build or the evidence it reports.
  - Runtime integration (stage 17 onward) starts only after stage 9, so that server and model changes are never confounded in one revalidation.
  - The paper keeps describing the measured Python system until a revalidated rerun exists.
- **D11:** approved by root as networking work, and done within stage 17.

## Rust and host test workflow

- **Workspace:** `rust/Cargo.toml` with crates:
  - `privoke-proto` (`tonic-build` and `protox` over `shared/proto`)
  - `privoke-contracts` (canonical JSON in both Python variants, Python-compatible float `repr`, artifact codec, fingerprints, V3 manifest rules)
  - `privoke-transport` (rustls server and client config, verifier, authorisation interceptor, limits, registry)
  - `privoke-conformance` (corpus replay)
  - `services/{model-streaming,param-update,telemetry,runtime-supervisor}`
  - `tools/privoke-pki`
- Main dependencies:
  - `tokio`, `tonic`, `tonic-web`, `prost`
  - `rustls`, `x509-parser`, `rcgen`
  - `tower` and `tower_governor`
  - `rusqlite` (opens the existing SQLite files and schemas)
  - `serde_json` (only behind the canonical writer), `sha2`, `hmac`
- **Gotcha: float formatting.** Python `json.dumps` writes floats with `repr` (for example `1e-08`), while `serde_json` and `ryu` write `1e-8`. The Go code depends on lexical equality with Python `canonical(CONFIG)` (`contextual_training.go`, `contextualFullAdamConfig`). The contract crate must reproduce Python's float `repr` and `ensure_ascii` behaviour, and the corpus tests it.
- **Host tests:** `cargo test --workspace --locked` on the host. This covers unit, parity and in-process TLS tests (`rcgen` makes synthetic certificates per test).
- **Cross-language tests:** they follow `AGENTS.md`. The Rust servers run as host processes, or Docker Compose hosts them on loopback ports. The Python test clients run in the host Python environment:
  - generate the clients with `evaluation/setup-host.py`
  - then run `evaluation/update_security.py` and `evaluation/run-component-tests.py`
  - Never use `docker compose run` or a test-driver container for test cases.
- **LLM-layer isolation:** any check of the Python worker after the transport changes sends an explicit semantic-only layer selection and asserts the returned layer execution. A product end-to-end check is a separate, labelled run.
- **CI:** after the deadline, stage 2 adds a Rust job to `service-stack-ci.yml` (`cargo fmt --check`, `cargo clippy -D warnings`, `cargo test`, and the `fail_closed` and feature checks). No workflow file changes before 11 December 2026, on any branch. The Go job stays until stage 9 retires the Go service from deployment.

## Stage 0: Reference tag and conformance corpus

- Objective:
  - Tag the submission revision (`asiaccs-2027-submission`; the tag name is root's decision).
  - Capture a golden corpus from the current Python and Go services into `tests/conformance/`:
    - artifacts before and after a fixed update sequence
    - receipts
    - canonical JSON of every contract config
    - fingerprints
    - streamed chunk sequences
    - V3 manifests and asset bytes (as hashes)
    - telemetry packets and summaries
    - native-messaging and gRPC-Web request/response transcripts
- Depends on: none
- Owned paths:
  - `tests/conformance/`
  - `evaluation/capture_conformance.py`
- Acceptance checks:
  - Capture is deterministic: running it twice gives an identical corpus (`git diff --exit-code tests/conformance`).
  - No file outside the owned paths changes.
  - Large binaries are stored as hashes.
- Status: pending
- Outcome:
- Handoff notes: allowed before the deadline. Capture uses host processes, and the Go service runs in Docker as in UPDSEC.

## Stage 1: Rust workspace, contracts and transport crates

- Objective: create the workspace, proto bindings, `privoke-contracts` and `privoke-transport` (TLS server and client config, verifier with CRL, authorisation interceptor, limits).
- Depends on: stage 0
- Owned paths: `rust/` (no `.github/` changes in this stage)
- Acceptance checks:
  - `cargo test --workspace --locked` exits 0 on the host.
  - The contract crate reproduces every stage 0 canonical-JSON, checksum and fingerprint fixture byte for byte.
  - The verifier rejects each of the following in tests: no certificate, foreign CA, expired, not yet valid, missing EKU, revoked.
  - The CRL hot-reload tests and the `fail_closed` startup test pass.
- Status: pending
- Outcome:
- Handoff notes: allowed before the deadline on a non-submission branch, without CI.

## Stage 2: PKI, identities and authorisation policy

- Objective:
  - Certificate profile with URI SANs and roles.
  - `privoke-pki` issuance and CRL tool.
  - Registry format.
  - Telemetry reporter-credential decision.
  - Public port assignment.
  - Rewritten section 4 of the deployment guide.
- Depends on: stage 1
- Owned paths:
  - `rust/tools/privoke-pki/`
  - `rust/crates/privoke-transport/src/registry*`
  - `docs/deployment/google-cloud.md` (section 4)
  - Rust job in `.github/workflows/service-stack-ci.yml` (after the deadline)
- Acceptance checks:
  - **Enrolment is specified and tested:** a host test runs `enrol` → `privoke-pki sign` → `install-cert` → mutual-TLS call accepted.
  - **Renewal is specified and tested:** `renew` under the same UUID → old and new certificates both valid until the old one expires.
  - **Offline expiry is specified and tested:** an expired certificate is refused, and local inspection still works from the cached package.
  - **Revocation is specified and tested:** deny list plus CRL, as in the enrolment design above.
  - The documentation names who enrols (the operator with the offline CA), how the desktop receives the certificate (an out-of-band CSR and certificate exchange), and how renewal works offline (manual, 180-day validity, 30-day warning, fail-closed with local inspection unaffected).
  - The reporter credential is issued and delivered with enrolment.
  - The registry hot-reload test passes.
  - The documentation names every secret file.
- Status: pending
- Outcome:
- Handoff notes: if the operator-mediated enrolment is not acceptable to the user, mark GAP-NO-CREDENTIAL-MECHANISM and GAP-NO-PER-INSTALLATION-AUTHZ `kept`, with the reason "no enrolment process", and fall back to CA-wide access as today.

## Stage 3: Rust model-streaming service

- Objective:
  - Replace the Go service with full RPC parity: catalog, legacy streaming, V3 packages, metadata contract validation, health subcommand.
  - Public listener: `Health`, `StreamModelParameters`, `GetModelPackage`, `StreamModelAsset`. Exposing the last two is a behaviour change (G8).
  - Internal listener: `GetModelParameters` and `Health`.
  - Fail-closed startup.
- Depends on: stages 1 and 2
- Owned paths:
  - `rust/services/model-streaming/`
  - its Dockerfile, a new file (the Go Dockerfile stays)
- Acceptance checks:
  - Every Go test case (`cmd/server/*_test.go`) is ported or explicitly mapped.
  - Streamed bytes match the stage 0 corpus for every catalog model.
  - The following negative rows pass against the built container on loopback: T1 to T12, R3, R4, R7, R8, R9 and the X8 variant.
- Status: pending
- Outcome:
- Handoff notes: the Go source and Dockerfile stay in place (see the stage 9 retirement scope).

## Stage 4: Rust telemetry service

- Objective:
  - Port ingestion, validation, SQLite storage (it opens existing databases) and the summary estimator.
  - Mutual TLS with the shared reporter credential.
  - A rate limiter and a daily cap, both keyed by source IP.
  - The peer identity is never persisted.
  - Fail-closed startup.
- Depends on: stages 1 and 2
- Owned paths:
  - `rust/services/telemetry/`
  - its Dockerfile
- Acceptance checks:
  - The estimator output matches the Python output under the G5 rules, on the corpus and on the telemetry-audit fixtures.
  - The malformed-packet tests are ported.
  - A test asserts that no identity column or identity log line exists.
  - A test asserts that two clients holding the same reporter certificate, at different source IPs, are limited independently.
  - Against the container, a request without a certificate and a request with an installation (non-reporter) certificate are both rejected (R10).
- Status: pending
- Outcome:
- Handoff notes: `services/telemetry-service/app/storage.py` stays in place as the parity oracle.

## Stage 5: Rust param-update service and scheduler

- Objective:
  - Port validation, compare-and-swap publication, receipts (existing SQLite and JSONL formats), audit and bootstrap.
  - Port the training-cycle scheduler, which calls the Python fuzzer over mutual TLS.
  - Add publisher authorisation, identity binding and the configurable cumulative bound.
  - Fail-closed startup.
- Depends on: stages 1, 2 and 6. Stage 6 gives the Python fuzzer its mutual-TLS listener and publisher client. Its only prerequisite is stage 2, so it is scheduled before this stage.
- Owned paths:
  - `rust/services/param-update/`
  - its Dockerfile
- Acceptance checks:
  - The published artifact bytes equal the Python service's on the stage 0 update sequences (G5 rules for receipts).
  - The ported `test_security_validation.py` and `test_update_receipts.py` cases pass, including the injected crash windows.
  - Against the container, the following behave as in the gap map: A1 to A3, E1 to E7, T14, R1, R2 and R5.
  - The scheduler completes one cycle against the stage 6 Python fuzzer over mutual TLS, and is refused when the fuzzer certificate is not registered.
- Status: pending
- Outcome:
- Handoff notes: choose the default cumulative budget by replaying the recorded accepted sequences (C4, C10, C16). The bound must not reject any historical accepted update unless this is disclosed.

## Stage 6: Mutual TLS for the remaining Python servers, telemetry credential and split cloud targets

- Objective:
  - Add server credentials and client-identity checks in `privoke_service` for the client-runtime gRPC server, the legacy fuzzer and pretrained-v3. Internal Compose mode uses mutual TLS.
  - The fuzzer's publisher client uses its service certificate.
  - Add `PRIVOKE_CLOUD_MODEL_TARGET` and `PRIVOKE_CLOUD_TELEMETRY_TARGET`.
  - Deliver the reporter credential to the telemetry emitter through `PRIVOKE_TELEMETRY_TLS_CERT_FILE` and `PRIVOKE_TELEMETRY_TLS_KEY_FILE`.
- Depends on: stage 2
- Owned paths:
  - `shared/python/privoke_service/stack_connection.py` (server credentials, per-service targets, loading the telemetry credential env)
  - `shared/python/grpc_healthcheck.py`
  - `extension/client-runtime/src/grpc_main.py`
  - `extension/client-runtime/src/telemetry/event_emitter.py` (channel construction only)
  - `extension/client-runtime/src/telemetry/__init__.py` (only if exports change)
  - `services/privoke-fuzzer/src/main.py`
  - `services/pretrained-v3/src/common.py`
  - `docs/runtime/client-configuration.md`
  - the installer scripts that write the client `.env` (`extension/runtime-supervisor/scripts/install-native-host.{sh,ps1}`)
  - shared tests
  - Not owned: `extension/client-runtime/src/telemetry/privacy.py` stays byte-identical, and G6 includes it.
- Acceptance checks:
  - `python evaluation/run-component-tests.py shared` and the runtime telemetry tests pass.
  - R6 and X16 behave as in the gap map.
  - A semantic-only `AnalyzePrompt` gives byte-identical responses before and after on the stage 0 inputs. The request uses an explicit semantic-only layer list, and the returned layer execution is asserted.
  - The emitter delivers a packet over mutual TLS with the reporter credential to the stage 4 service.
  - The G6 command exits 0.
- Status: pending
- Outcome:
- Handoff notes: transport-only change.

## Stage 7: Rust runtime supervisor

- Objective:
  - Replace the native-messaging host, the process supervisor, the gRPC-Web bridge and `PrivokeRuntimeControlService`. The bridge uses `tonic-web` and keeps the same origin allowlist, the 30/35 s timeouts and the same paths.
  - The Python client runtime stays as the child worker.
  - Add the `enrol`, `install-cert`, `renew` and `status` commands from stage 2.
- Depends on: stages 1 and 2
- Owned paths:
  - `rust/services/runtime-supervisor/`
  - the native-host manifest templates in `extension/runtime-supervisor/scripts/` (paths only)
- Acceptance checks:
  - The stage 0 native-messaging and gRPC-Web transcripts replay identically.
  - `npm test` in `extension/` passes against the Rust bridge.
  - The `python evaluation/run-component-tests.py supervisor` cases are ported.
  - Measured end-to-end median latency does not regress beyond the run-to-run spread.
- Status: pending
- Outcome:
- Handoff notes: the installed-client claims (C5, C6, C42) are not claimed for this build unless the installed-browser protocol is rerun.

## Stage 8a: Fail-closed cutover with nginx rollback retained

- Objective: cut over from the nginx-fronted services to the Rust services without ever exposing an unauthenticated or untested listener. The order is fixed:
  1. **Stage the containers.** Deploy a release that runs the Rust containers alongside the current nginx release. The Rust public ports are published on `127.0.0.1` only (for example `127.0.0.1:50443` and `127.0.0.1:58443`). The firewall is unchanged, and nginx keeps serving `:443`.
  2. **Negative gate.** From the host Python harness, over an SSH tunnel to those loopback ports, run the stage 3 to 5 negative rows against the real containers on the VM: T1 to T14, A1 to A3, E6, E7, R1 to R10, X8 and X13. Any unexpected accept stops the cutover.
  3. **Smoke on loopback.** The rewritten `deploy/gce/tests/smoke.py` asserts the following:
     - mutual TLS is required
     - private RPCs are denied (R9)
     - the V3 fetch works (G8)
     - telemetry is accepted with the reporter credential
     - a container started without a CA or CRL fails to start
  4. **Switch.** Publish the Rust ports on `0.0.0.0:443` and `:8443` and stop the nginx container. Only then open the firewall for `8443`; 443 is already open.
  5. **External smoke.** Rerun the smoke test from outside the VM against the public endpoints.
  6. **Rollback until step 5 passes.** If anything fails, `deploy.sh` redeploys the previous release directory, which contains `nginx.conf` and the `ingress` service, and closes `8443` again.
  - Until step 4, the existing UPDSEC row set, with its three routed RPCs, still describes production.
- Depends on: stages 3, 4, 5 and 6. Stage 7 is needed only by workstation clients and is not a dependency of the cloud cutover.
- Owned paths:
  - `docker-compose.yml`
  - `docker-compose.prod.yml`
  - `docker-compose.gpu.yml`
  - `deploy/gce/compose.yml`
  - `deploy/gce/deploy.sh`
  - `deploy/gce/tests/smoke.py`
  - `.github/workflows/deploy-gce.yml`
  - `.github/workflows/service-stack-ci.yml`
  - `docs/deployment/google-cloud.md`
  - `docs/services/`
- Acceptance checks:
  - The step 2 negative gate passed against the containers.
  - The external smoke test (step 5) passes.
  - `docker compose -f deploy/gce/compose.yml config --quiet` passes.
  - `python -m unittest discover -s evaluation/tests -p test_compose_defaults.py` passes.
- Status: pending
- Outcome:
- Handoff notes:
  - `nginx.conf` and the `ingress` service stay in the repository and in the previous release directory until stage 8b.
  - Do not edit the historical study stacks in `evaluation/compose.*.yml`.

## Stage 8b: Remove nginx

- Objective: delete the `ingress` service, `deploy/gce/nginx.conf`, the `nginx -t` step in `deploy.sh`, `nginx.conf` from the `deploy-gce.yml` tarball, and the nginx text in the documentation.
- Depends on: stage 8a passing its external smoke test on the production VM, plus one full deployment cycle without a rollback.
- Owned paths:
  - `deploy/gce/`
  - `.github/workflows/deploy-gce.yml`
  - `docs/deployment/google-cloud.md`
- Acceptance checks: G1.
- Status: pending
- Outcome:
- Handoff notes: after 8b, rolling back to nginx means redeploying an earlier release from the tag.

## Stage 9: Security revalidation, retirement from deployment and records

- Objective:
  - Extend `evaluation/update_security.py` with a `--target rust` mode: the R rows, new static checks against the Rust configuration, and the X8 and X13 changes. Run it against the Rust services as host processes.
  - Keep the existing legacy mode (the nginx static checks ST4 to ST7, and the Go and Python targets), so that UPDSEC-20261116 stays reproducible at its tag.
  - Write a new UPDSEC record. Do not overwrite UPDSEC-20261116.
  - Write `evaluation/check_revalidation.py` (G7) and fill in the revalidation table.
  - Retire the replaced services from deployment only, as listed below.
- Depends on: stages 8a and 8b
- Owned paths:
  - `evaluation/update_security.py`
  - `evaluation/update_security_pki.py`
  - `evaluation/update_security_report.py`
  - `evaluation/tests/test_update_security.py`
  - `evaluation/check_revalidation.py`
  - `paper/research/update-security-<date>.md` and its `.json`
  - `docs/experiments/`
  - the `README` notes in the retired directories
- Acceptance checks: G2, G3, G5 and G7.
- Status: pending
- Outcome:
- Handoff notes: paper text changes need their own `REWRITE_SCOPE` authorisation.

**Retirement scope.** Retirement here means removal from deployment, not deletion. Fifty-five files in `evaluation/` refer to the replaced service directories, so this plan moves and deletes no service source directory. The Python and Go sources stay at their current paths as the parity oracle and for historical reproduction. A separate `tests/oracle/` copy is therefore unnecessary, and no reference breaks. Each retired directory gets one README line: "Retired from deployment by stage 8a; kept as conformance oracle and for historical reproduction; do not deploy."

| Reference | Retirement action |
| --- | --- |
| `services/param-update-service/`, `services/telemetry-service/`, `services/model-streaming-service/` (Go), `extension/runtime-supervisor/src/` | Kept in place and no longer built by the default or production Compose files. Their tests keep running in `run-component-tests.py` as oracle tests. The CI Go job stays as an oracle build until root decides otherwise. |
| `evaluation/update_security.py`, `update_security_pki.py`, `update_security_report.py` | Extended with `--target rust`. The legacy target, which hosts `services/param-update-service/app/server.py` on the host and uses the Go image, is unchanged. |
| `evaluation/privoke_eval/task_query_window_study.py` (TW01) | Unchanged. It inventories, builds and runs `services/param-update-service` and `services/model-streaming-service/Dockerfile` at its pinned sources, and it keeps working because those paths remain. |
| `evaluation/analysis/audit-telemetry-mechanism.py` (T2 audit) | Unchanged. It reads `services/telemetry-service/app/{storage,validation}.py`, which stay as the audited oracle. A Rust collector audit would be a new script. |
| `evaluation/compose.*.yml`, `evaluation/Dockerfile*` (study stacks) | Unchanged. They pin the historical Python and Go services. |
| `evaluation/run-*.py` study runners, `evaluation/run-component-tests.py` | Unchanged. `run-component-tests.py` gains Rust targets only if root asks, because the Rust tests run through `cargo test`. |

Deleting any of these directories is a separate future decision. Before it, every reference above must be migrated or explicitly frozen.

## Stage 10 (optional): Experimental pretrained-v3 checkpoint server

- Objective:
  - Port `checkpoint_server.py` and `checkpoint_store.py` to Rust, behind the same transport crate.
  - The following stay Python:
    - `fuzzer_server.py`, which imports the frozen schedule in-process (a Rust shell is part of D6)
    - `runtime_server.py`
    - `fuzzer_training.py`
    - `audience_schedule.py`
- Depends on: stage 9, and a decision that V3 training graduates from experimental
- Owned paths: `rust/services/v3-checkpoint/`
- Acceptance checks: the content-addressed store and its receipts match the Python store on the corpus.
- Status: pending (not scheduled)
- Outcome:
- Handoff notes: skip if the experimental path is retired instead.

## Approved inference and training ports (stages 11 to 22)

**User decision (16 November 2026), verbatim:** "Because spaCy NER runs a model, make an equivalent rust harness in a separate repo, make it importable through crate and then use it. D1-D10 can be ported." This was then superseded for NER by the user's "Use PyO3" decision (stage 11).

Root settled the following:
- D1 to D10 are approved for porting.
- D1 is resolved by the PyO3 binding (the user's decision of 16 November 2026): spaCy is called unchanged in a supervised worker pool (stage 11) and is not ported. The separate `privoke-ner` repository is not created.
- D11 (model fetch) was added in r2. Root approved it as networking work, and it is done in stage 17.
- Stage 17 (pipeline and policy aggregation) is within the approval, because it is server logic.
- Stage 11 is now in this repository. Root needs to re-confirm whether it may start before the deadline.

The assessments in [port assessments](#port-assessments-d1-to-d11) give the Rust options, what each port loses, effort and risk. These stages turn D1 to D10 into dependency-ordered work.

**Rules that apply to every port stage:**
- **No Python edits.** The Python implementation stays unchanged, and G6 still holds. It remains both the parity oracle and the system the paper describes.
- **The paper is unchanged.** It keeps describing the measured Python system until a revalidated rerun of the Rust build exists, and paper edits need their own `REWRITE_SCOPE` authorisation.
- **Revalidation means new records.** Every claim a stage revalidates gets a new record. Historical records are never edited (G7).
- **Branch.** All work happens on a non-submission branch and never enters the 11 December submission build or its artifact.
- **Scheduling.** The schedule is unchanged:
  - In the Privoke repository, nothing beyond stages 0 and 1 happens before the deadline.
  - Runtime integration (stage 17 onward) starts only after stage 9, so that server changes and model changes are never confounded in one revalidation.
  - Stage 11 (PyO3 spaCy worker) is in this repository on a non-submission branch. Root needs to re-confirm whether it may start before the deadline.
- **LLM-layer isolation.** Semantic parity runs use an explicit semantic-only layer selection and assert the returned layer execution, as the repository `AGENTS.md` requires. Product end-to-end reruns are separate, labelled runs.

**Dependency order:**

```
11 (spaCy PyO3 worker) ─────────┐
12 (D2 rules + preprocessing) ────┼─> 13 (D1 NER layer + post-filter) ─> 15 (D9 GLiNER)
14 (D3 semantic inference) ───────┴─> 16 (D10 external classifier)
                                      17 (Rust analysis runtime; needs 12, 13, 14, 16) ─> 18 (D8 reporter)
14 ─> 19 (D4 gradients and training) ─┐
20 (D5 curricula, aggregation) ───────┴─> 21 (D6 fuzzer orchestration) ─> 22 (D7 pretrained-v3 runtime)
```

| Stage | Item | Parity criterion (on the stage 0 corpus plus every recorded evaluation set it names) | Revalidates (new records) |
| --- | --- | --- | --- |
| 11 | D1 engine: spaCy through PyO3 | NER smoke test: worker output byte-identical to direct Python spaCy on a small corpus (identical by construction) | none (spaCy unchanged) |
| 12 | D2 | Identical rule hits (rule, span, signal, severity) and identical normalised text and offset maps on all recorded detector sets | C2, C10, C38, C44 to C47, C54, C55 (regex part) |
| 13 | D1 | Identical post-filter decisions and NER-layer results, for the default and caseless gate settings | C2, C44 to C55, the installed probes, NER paper text |
| 14 | D3 | Golden logits within the stated tolerance, and identical decisions (sensitivity, category, visibility, action) on recorded sets, semantic-only | C12, C13, C27, C31, C35, C37, C41, C47, V1/V3 comparisons, latency tables |
| 15 | D9 | Identical GLiNER spans at the frozen threshold on the C53 sets | C53 (GLiNER comparator) |
| 16 | D10 | Byte-identical request bodies (prompt construction) and identical parsing of recorded responses | none (no recorded claim) |
| 17 | Integration and D11 | Identical decisions for every layer selection. Floats are equal after rounding to 6 decimal places. Responses are byte-identical only for regex-only and NER-only selections. D11 produces an identical package cache. | C1, C5, C6, C42, V3 installed timing (only if claimed for this build) |
| 18 | D8 | Identical ledger behaviour. A new finite-epsilon audit of the Rust kernel replaces C34 for this build. | C7, C34 (T2 rerun) |
| 19 | D4 | Gradients and updates within the stated tolerance. Identical accepted and rejected guard outcomes on recorded runs. Artifact bytes are identical only where the gradients are bitwise equal; otherwise artifacts are compared with a tolerance. | C39, RQ2, the local SGD, FULL Adam, window and retention studies |
| 20 | D5 | Identical sample streams (schedule digests equal) for every recorded seed | C4, C16, the 2026-10 fuzzer study series, AU3 and BC01 schedules |
| 21 | D6 | Identical cycle records and dumps after normalisation (G5 rules) | the fuzzer study series (cycle mechanics) |
| 22 | D7 | As 14 and 19, for the `TrainingService` and runtime RPCs | the pretrained-v3 study records |

## Stage 11: spaCy through PyO3 in a supervised worker pool (D1 engine)

**User decision (16 November 2026): "Use PyO3".** spaCy is not ported. No `Privoke-NER` repository is created, and no model weights are exported. The Rust pipeline calls the unchanged Python spaCy 3.7.5 running `en_core_web_sm` 3.7.1.

- **Objective.** Give the Rust NER layer (stage 13) spaCy's exact output through a small, supervised spaCy worker.
- **Choice: a pool of supervised worker processes, not a dedicated interpreter thread.**
  - Each worker is a small Rust binary, `privoke-spacy-worker`. It embeds CPython through PyO3, calls `spacy.load("en_core_web_sm")` once at start-up, and serves requests over a local length-prefixed protocol on stdin/stdout pipes.
  - The Rust runtime (stage 17) owns the pool. It starts N workers (default 1 on the workstation, configurable on the server), restarts a worker that exits, crashes or misses its deadline, and routes each request to an idle worker.
  - **Why processes rather than a thread:**
    - **Crash isolation.** A segfault, OOM or deadlock in spaCy, thinc or NumPy, or a GIL held forever, kills or stalls only that worker. With a thread inside the runtime it would kill or stall the runtime, and with it the extension's inspection path.
    - **Throughput.** It scales past the single-GIL limit by adding processes. spaCy's C extensions do not support sub-interpreters, so a thread design can never exceed one document at a time.
    - **Memory.** Each worker's memory is bounded and reclaimed on restart.
  - The cost is one local pipe hop per document. It is measured in stage 17 against the current in-process Python call, and it should be small next to the measured NER-layer cost (C55, about 27 ms combined median). That figure is an estimate until measured.
- **Worker protocol.**
  - Request: text, plus a pipe selection — full pipeline, or the post-filter's tagger-only sub-pipeline (`select_pipes(enable=tok2vec, tagger, attribute_ruler, lemmatizer)`) on lowercased phrases.
  - Response, per token: `text`, `idx`, `whitespace_`, `is_alpha`, `lower_`, `tag_`, `pos_`, `lemma_`, `dep_`, `head.i`. Plus the entities (`start_char`, `end_char`, `label_`).
  - A one-time `lemma_index` word-list request, for the post-filter's lexicon.
  - Python objects never leave the worker.
  - The caseless gate and the post-filter are Rust logic (stage 13). GLiNER (stage 15) uses the same worker with `ner` disabled.
- **Back-pressure and limits.**
  - A bounded queue, returning `RESOURCE_EXHAUSTED` when full.
  - A per-request deadline below the bridge's 30 s.
  - A maximum text length equal to the runtime's current limit.
  - A worker that times out is killed and restarted, and the request returns `UNAVAILABLE`.
  - A failed NER layer then blocks an otherwise ALLOW decision, as the Python pipeline does today.
  - **Poisoned input (P3).** A request whose worker crashed is never retried on another worker; it returns `UNAVAILABLE`, which blocks an ALLOW as above.
  - **Crash-loop backoff (P3).** Restarts back off exponentially, from 100 ms up to a 30 s cap.
  - **Readiness (P3).** A worker is not ready until `spacy.load` completes. Requests arriving while no worker is ready return `UNAVAILABLE`.
- **Framing and offsets (P4).**
  - The protocol uses a dedicated pipe file descriptor, not stdout. Inside the worker, `sys.stdout` is redirected to stderr, so a stray print or C-library warning cannot corrupt the frames.
  - spaCy character offsets are Python code points. The Rust client converts them to UTF-8 byte offsets internally, and to UTF-16 code units at the extension boundary, matching today's behaviour.
- **Packaging (bundled venv).**
  - A relocatable CPython 3.11 runtime and a venv, shipped beside the runtime binary in the Docker images and the workstation installer.
  - The venv is built from a new hash-locked file, `rust/services/spacy-worker/bundle.lock.txt`, installed with `pip install --require-hashes`. `extension/client-runtime/requirements.txt` only gives a range (`spacy>=3.7.2,<3.8.0`), has no `thinc` pin, and has no hash for the model wheel, so it cannot serve as the pin source (P1).
  - The lock pins exact versions and SHA-256 hashes for spaCy, thinc, blis, numpy, cymem, preshed, murmurhash, srsly, wasabi, catalogue, confection and the `en_core_web_sm` 3.7.1 wheel.
  - These versions are taken from the reference `evaluation/.venv-v1-v3-pipeline` (`pip freeze`), along with that venv's CPython 3.11 patch version.
  - It is built from wheels, not copied from a developer venv.
  - PyO3 builds against that exact interpreter (no `abi3`, because spaCy's compiled extensions pin the minor version).
  - The worker sets `PYTHONHOME`, `sys.path` and, on Windows, the DLL search path explicitly, and ignores the user's Python environment.
- **Licensing.** spaCy, thinc and the model are bundled unchanged, with their own `LICENSE` files and the model's `LICENSES_SOURCES`. The model's `meta.json` declares MIT, with the sources OntoNotes 5, ClearNLP and WordNet 3.0. The bundle build fails if these files are missing.
- **Workspace isolation (N7).**
  - Stage 11 writes only on the non-submission branch of this plan's worktree (or its successor branch). It writes nothing in the submission worktree or the main checkout (`D:/Git Repositories/Privoke-Research-Project`).
  - Its access to `evaluation/.venv-v1-v3-pipeline` (the reference for the smoke test) and to the stage 0 hashes is read-only.
  - Golden output derived from recorded sets is generated locally into an ignored directory and is not committed.
- Depends on: stage 1
- Owned paths:
  - `rust/crates/privoke-spacy/`, the client used by stage 13
  - `rust/services/spacy-worker/`
  - the bundled-venv build script and its pin file
- Acceptance checks:
  - **NER smoke test.** On a small declared corpus (about 200 documents: a sample of the recorded NER sets, read-only by hash, plus a synthetic stress set of URLs, emoji, CJK, zero-width characters and all-caps or all-lowercase text), the worker's output (tokens, all fields above, and entities) is byte-identical to direct Python spaCy in `evaluation/.venv-v1-v3-pipeline`, for both the full and tagger-only selections. Identity is expected by construction; a mismatch indicates a packaging or version fault. This 200-document check is the quick check only.
  - **Full NER parity gate (P2).** Every recorded NER set (read-only, by hash) is run through both the bundle and the reference venv, with both selections. The gate is 100% byte-identical output, and any mismatch blocks the stage.
  - At start-up the bundle compares its installed packages and the CPython patch version against the whole `bundle.lock.txt`, and the runtime refuses to start on any difference (P1).
  - The worker-protocol tests each have a case that must pass:
    - **P3, poisoned input:** a deliberate crash input returns `UNAVAILABLE` without being retried.
    - **P3, crash loop:** restarts back off.
    - **P3, readiness:** a request during `spacy.load` returns `UNAVAILABLE`.
    - **P4, framing:** a deliberate `print` inside the worker leaves the framing intact.
    - **P4, offsets:** emoji, combining-mark and CJK text map to correct UTF-8 and UTF-16 offsets.
  - The runtime starts from the bundle with no system Python on `PATH`, on Windows and Linux.
  - Killing a worker in the middle of a request gives `UNAVAILABLE` for that request, and the pool recovers.
  - The queue-full and deadline paths are tested.
- Status: pending
- Outcome:
- Handoff notes:
  - The runtime keeps a Python dependency for spaCy only; every other analysis component is Rust after stage 17.
  - The earlier rejection of embedding CPython (see the [boundary](#pythonrust-boundary) table) remains for torch and the whole runtime. For spaCy alone, the out-of-process pool answers its crash and GIL objections. The remaining objection, packaging, is handled by the bundled venv.
  - `en_core_web_lg` or `trf` would only be a pin change in the bundle; the default is unchanged.

## Stage 12: Regex rules and preprocessing in Rust (D2)

- Objective: build the `privoke-rules` crate. It ports `extension/client-runtime/src/regex/*` (including the Presidio recognisers and validators, ported by hand from the `presidio-analyzer` 2.2.363 sources) and `detection/preprocessing.py` (normalisation with offset maps).
- Depends on: stages 0 and 1
- Owned paths: `rust/crates/privoke-rules/`
- Acceptance checks:
  - Rule hits (rule name, span, signal, severity) and normalised text with offset maps are identical on the corpus and on all recorded detector sets. The pinned Unicode version is stated.
  - Each pattern needing `fancy-regex` or `pcre2` is listed with the reason.
- Status: pending
- Outcome:
- Handoff notes: the golden output comes from the Python layer with an explicit `regex`-only layer selection.

## Stage 13: NER layer and post-filter in Rust (D1)

- Objective: build `privoke-ner-layer` in the Privoke workspace, using the stage 11 spaCy worker. It ports:
  - `NER/ner_detector.py`, including the caseless gate (`has_case_signal`, `fold_case`, `CASELESS_DISABLED_RULES`)
  - `NER/ner_postfilter.py` (both stages and all rules, including `_english_lexicon` from `lemma_index`)
  - `NER/pattern_entity_detector.py`
  - `NER/use_cases.py`
  - the default-off robustness flags
- Depends on: stages 11 and 12
- Owned paths: `rust/crates/privoke-ner-layer/`
- Acceptance checks:
  - Identical NER-layer results, and identical post-filter decision logs (rule, candidate, outcome), on all recorded NER sets, for the default and caseless settings and each robustness flag.
  - Golden data derived from recorded sets is generated locally into an ignored directory and is not committed.
  - The golden output comes from Python with an explicit NER-only layer selection.
- Status: pending
- Outcome:
- Handoff notes: C55 latency, if rerun, is a new record for the Rust build.

## Stage 14: Semantic inference in Rust (D3)

- Objective: build `privoke-semantic`.
  - V3 encoder and heads come first. Loading the V3 packages (safetensors and tokenizer) is unchanged.
  - Then the legacy Tiny streamed model, the presence models (including the pure-Python `privoke_model/presence.py`), and the experimental scratch-presence and pretrained-context models.
  - The backend is chosen by a measured spike over `tch-rs` (same libtorch, closest numerics), `candle` and `ort`. The default is `tch-rs` if it reaches decision parity; otherwise the best of the others, with the reason recorded.
- Depends on: stage 1
- Owned paths: `rust/crates/privoke-semantic/`
- Acceptance checks:
  - Tokenisation is identical.
  - Logits are within an absolute 1e-5 of torch CPU float32 (a backend that cannot meet this states its own tolerance and justification).
  - Decisions are identical on every recorded semantic set, semantic-only.
- Status: pending
- Outcome:
- Handoff notes: report backend, version and thread settings, because the paper names Torch 2.11 CPU with four threads.

## Stage 15: GLiNER backend (D9)

- Objective: port `NER/gliner_detector.py` as an optional backend. It uses `gline-rs` or `ort` for the model and the stage 11 spaCy worker (with `ner` disabled) for the spaCy tokens and parse it reads.
- Depends on: stages 11 and 13
- Owned paths: `rust/crates/privoke-ner-layer/src/gliner*`
- Acceptance checks: identical spans at the frozen label preset and threshold on the C53 sets.
- Status: pending
- Outcome:
- Handoff notes: not shipped by default, as in the Python build.

## Stage 16: External classifier client (D10)

- Objective: port `LLM/open_classifier.py` and `LLM/prompt.py` with `reqwest`.
- Depends on: stage 14, for the shared classifier trait
- Owned paths: `rust/crates/privoke-semantic/src/open*`
- Acceptance checks:
  - Request bodies are byte-identical for the corpus prompts.
  - Recorded responses parse identically.
  - Tests use no live API calls.
- Status: pending
- Outcome:
- Handoff notes: an API key is supplied by the user only at run time and is never recorded.

## Stage 17: Rust analysis runtime (integrates D1 to D3, D9, D10)

- Objective: implement `PrivokeRuntimeService` analysis RPCs (`AnalyzePrompt`, `DetectAnnotationPresence`, `Health`) in Rust. This covers the `pipeline.py`, `model.py`, `classification/*` and `task_readout.py` logic, and it runs as the supervisor's child process instead of the Python worker.
  - Root settled that the pipeline and policy aggregation are within the user's approval, because they are server logic.
  - It also includes D11: model package and legacy stream fetch, with pin, shape and finite checks, into the same cache layout. Root approved this as networking work.
  - The gradient RPCs stay on the Python worker until stage 19. The supervisor routes each RPC by path to the Rust or Python worker.
- Depends on: stages 7, 9, 12, 13, 14 and 16
- Owned paths:
  - `rust/services/runtime/`
  - the supervisor routing in `rust/services/runtime-supervisor/`
- Acceptance checks:
  - **Decisions must be identical.** For each explicit layer selection (regex, NER, semantic, regex+NER, full) on the corpus, these are identical to the Python worker: action, sensitivity, severity, category, visibility, and the per-layer findings (layer, span, label, rule or signal).
  - **Floating-point fields** (confidences, scores, probabilities) are compared after rounding to 6 decimal places, or within an absolute 1e-5, which is consistent with the stage 14 logit tolerance. The rule is declared in `tests/conformance/normalization.toml`.
  - **Byte equality** of the serialised `AnalyzePromptResponse` is required only for regex-only and NER-only selections, which involve no model floats beyond spaCy parity.
  - LLM-only (semantic-only) results are reported separately from product results.
  - D11: the Rust fetch writes a package cache byte-identical to the Python fetch's, and it rejects the same pin, shape and finite-value violations.
  - Extension tests pass.
- Status: pending
- Outcome:
- Handoff notes: the installed-client claims are revalidated only if the installed-browser protocol is rerun on this build.

## Stage 18: Telemetry reporter in Rust (D8)

- Objective: port `telemetry/privacy.py` (53-bit draw, binary64 thresholds, rejection sampling, SQLite ledger) and `event_emitter.py` into the Rust runtime.
- Depends on: stages 4 and 17
- Owned paths: `rust/crates/privoke-telemetry-client/`
- Acceptance checks:
  - Ledger behaviour is identical on the controlled fixtures (caps, persistence, ordering, outage and recovery).
  - A new exact finite-epsilon audit of the Rust kernel's actual thresholds, using a new audit script, is a new T2 record. C34's values are not reused.
- Status: pending
- Outcome:
- Handoff notes: until that record exists, the C34 values apply to the Python kernel only.

## Stage 19: Gradients and local training in Rust (D4)

- Objective: port the gradient RPCs and the local training paths to Rust (`tch-rs` recommended for parity):
  - `ComputeSemanticGradients`, `ComputeUnderlyingModelGradients`, `ComputePresenceGradients`
  - `training.py`, `full_adam_training.py`, `window_training.py`, `supervised_training.py`, `presence_training.py`, `sensitive_retention_training.py`, `reference_preparation.py`, `v3/training.py`
  - The FULL Adam contract (float64 moments, `cpu_threads: 1`) is binding.
- Depends on: stage 14
- Owned paths: `rust/crates/privoke-training/`
- Acceptance checks:
  - Gradients and parameter deltas are within an absolute 1e-6 relative to the Python output under the same seed and threads. Bitwise equality is reported where achieved.
  - Accepted and rejected guard outcomes are identical on replayed recorded runs.
  - **Byte equality of published artifacts** is required only for runs where the gradients themselves were bitwise equal to the Python output.
  - **Every other run** compares artifacts with a tolerance: same version, tensor inventory and shapes; per-coordinate parameter values within 1e-6 absolute; same canonical metadata.
  - The report counts runs in each category.
- Status: pending
- Outcome:
- Handoff notes: CUDA parity is out of scope unless requested.

## Stage 20: Curricula, schedules and update aggregation in Rust (D5)

- Objective: port `services/privoke-fuzzer/src/prompt_generation/*` and `training/*` aggregation, and `pretrained-v3/src/{fuzzer_training,audience_schedule}.py`.
  - This includes an exact reimplementation of CPython `random`: MT19937 seeding from int, `random()`, `getrandbits`, `_randbelow`, `choice`, `shuffle`, `sample`, `randrange`, `uniform`, `choices` with cumulative weights.
- Depends on: stage 1
- Owned paths: `rust/crates/privoke-curriculum/`
- Acceptance checks:
  - Every recorded schedule and curriculum digest, for every recorded seed, is reproduced exactly.
  - A per-call test against CPython `random` covers 10^6 draws per method.
- Status: pending
- Outcome:
- Handoff notes: any digest mismatch blocks the stage. Approximate parity is not acceptable for frozen schedules.

## Stage 21: Fuzzer orchestration in Rust (D6)

- Objective: replace `services/privoke-fuzzer/src/{fuzzer_service,runtime_client,main,cli,config,json_records}.py` and `services/pretrained-v3/src/fuzzer_server.py` with Rust services that use stages 19 and 20 in-process, with stage 1 transport.
- Depends on: stages 19 and 20, and stage 10 if it ran
- Owned paths: `rust/services/fuzzer/`, `rust/services/v3-fuzzer/`
- Acceptance checks:
  - Cycle records and dumps are identical under the G5 normalisation on replayed recorded cycles.
  - The stage 5 scheduler interoperates over mutual TLS.
- Status: pending
- Outcome:
- Handoff notes: historical study runners keep pointing at the Python fuzzer.

## Stage 22: Pretrained-v3 runtime and training server in Rust (D7)

- Objective: replace `services/pretrained-v3/src/runtime_server.py` (V3 inference and `TrainingService`), using stages 14 and 19.
- Depends on: stages 14, 19 and 21
- Owned paths: `rust/services/v3-runtime/`
- Acceptance checks: the parity criteria of stages 14 and 19 hold on the pretrained-v3 recorded fits and snapshots.
- Status: pending
- Outcome:
- Handoff notes: after this stage the process boundary has no Python worker left. The Python code stays in place as the oracle (stage 9 retirement scope).

## Port assessments (D1 to D11)

These assessments informed the user's decision. D1 to D10 are approved and staged above. D11 is approved by root as networking work and is done in stage 17.

"Lost" lists what a port invalidates or gives up until its stage revalidates it. Effort is S, M or L, and risk refers to the risk of not reaching parity.

### D1. spaCy NER layer (resolved by PyO3 binding, user decision 16 Nov)

- **Code:** `extension/client-runtime/src/NER/{ner_detector,ner_postfilter,pattern_entity_detector,use_cases}.py` with `en_core_web_sm` 3.7.1.
- **Feasibility:** there is no Rust spaCy, so no off-the-shelf port exists. The post-filter depends on the tagger's lowercased-token reading, the parser's dependencies and the model's word list.
- **Rust options:**
  - (a) A different token-classification model through `ort` (ONNX Runtime) or `candle`, with the `tokenizers` crate. Ready-made pipelines exist, such as `rust-bert` NER on `tch-rs`.
  - (b) A hand-built gazetteer and rules engine.
  - Both are new detectors, not ports.
- **Resolved by the user (16 November 2026), "Use PyO3":** spaCy is called unchanged through PyO3 in a supervised worker pool (stage 11). It is not reimplemented, so detector parity is preserved by construction. The earlier choice of a separate-repository reimplementation was withdrawn. Effort for the engine: S to M.
- **Lost:** detector parity. All regex+NER evidence is measured with spaCy: C2, C44 to C55, the installed probes, the Presidio comparison context, and the paper text describing spaCy and the post-filter.
- **Effort:** L. **Risk:** high.

### D2. Regex rule layer and preprocessing

- **Code:**
  - `extension/client-runtime/src/regex/*`, which uses the Python `regex` module, Presidio recognisers through `rules_presidio.py` and `import_presidio.py`, and checksum validators
  - `detection/preprocessing.py`, which uses NFKC through `unicodedata` and keeps offsets
- **Feasibility:** the most feasible item. Rules are deterministic, so parity can be checked exactly (identical spans and decisions on all recorded corpora).
- **Rust options:**
  - `regex`: linear time, but no look-around and no backreferences.
  - `fancy-regex`: look-around and backtracking.
  - `pcre2`.
  - `unicode-normalization`.
  - Presidio recognisers and validators must be hand-ported.
- **Pitfalls:**
  - The Python `regex` module's Unicode classes, case folding, and possessive and variable look-behind differ from all three crates.
  - The Unicode version in `unicodedata` differs from the crate's.
- **Lost:** none, if exact parity is shown on every recorded set. Any mismatch reopens C2, C10, C38, C44 to C47, C54 and C55. The rule layer would no longer share code with the Presidio baseline used in evaluation.
- **Effort:** M. **Risk:** medium.

### D3. Semantic classifiers (V3 encoder and heads, legacy Tiny, presence and experimental models)

- **Code:**
  - `extension/client-runtime/src/{transformer_encoder,model}.py`
  - `v3/model.py`
  - `LLM/privoke/*_model.py`
  - `LLM/local_classifier.py`
  - `pretrained-v3/src/runtime_server.py` (inference half)
  - `shared/python/privoke_model/presence.py` (pure-Python lexical)
- **Feasibility:** good for inference.
  - V3 packages are safetensors with a HuggingFace tokenizer, and the Python `tokenizers` package is a binding of the Rust `tokenizers` crate, so tokenisation parity is likely.
  - BERT-style encoders exist in `candle-transformers` and `burn`.
  - `ort` runs an ONNX export; `onnxruntime` 1.23.2 is already a dependency.
  - `tch-rs` uses libtorch kernels and gives the closest numbers.
- **Numerics:** logits will differ at float tolerance from torch CPU (except possibly `tch-rs` with the same libtorch version). Decisions near thresholds can flip. The check is golden logits within a tolerance plus identical decisions on the recorded sets.
- **Lost:**
  - Exact reproduction of every semantic and product result: C12, C13, C27, C31, C35, C37, C41, C47, the V1/V3 comparisons and the latency tables.
  - The "Torch 2.11 CPU" execution statements in the paper.
- **Effort:** M for V3 inference only; L including the legacy and experimental model families. **Risk:** medium (V3 only) to high (all models).

### D4. Gradient computation and local training (local SGD, FULL projected Adam, window, retention and supervised training; V3 physical training)

- **Code:**
  - `extension/client-runtime/src/LLM/privoke/{training,full_adam_training,window_training,supervised_training,presence_training,sensitive_retention_training}.py`
  - `v3/training.py`
  - `pretrained-v3/src/runtime_server.py` (`TrainingService`)
- **Feasibility:** possible but costly.
  - `tch-rs` (libtorch autograd and optimisers) can approach bitwise parity if the libtorch version and thread settings match. The FULL Adam contract fixes float64 moments and `cpu_threads: 1`.
  - `candle` and `burn` have autodiff and AdamW, but different kernels, so bitwise parity is not expected.
  - The canonical training contracts stay unchanged either way.
- **Lost:**
  - Reproducibility of all recorded training studies: local SGD, FULL Adam, window, retention, the accelerated and continual fuzzer studies, C39 and RQ2.
  - The paper's training-environment statements (Python 3.11, Torch 2.12, CUDA 13.0, Transformers 4.57.6).
  - Torch and Transformers ecosystem tooling (optimisers, CUDA support).
- **Effort:** L. **Risk:** high.

### D5. Fuzzer curricula, sampling schedules and update aggregation

- **Code:**
  - `services/privoke-fuzzer/src/{prompt_generation,training}/*`
  - `services/pretrained-v3/src/{fuzzer_training,audience_schedule}.py`
- **Feasibility:** feasible, because it is pure Python. The difficulty is that recorded curricula and the frozen AU3 and BC01 schedules are defined by Python `random` (MT19937) call sequences:
  - `rand_mt` gives MT19937.
  - `random.choice`, `shuffle`, `sample`, `randrange` and `getrandbits` must be reimplemented exactly to reproduce the streams.
  - Schedule digests make parity checkable.
- **Lost:** none, if the stream digests match. Otherwise, regenerated curricula invalidate every fuzzer study (C4, C16 and the 2026-10 study series) and make the frozen schedules non-reproducible from the new code.
- **Effort:** M to L. **Risk:** medium to high.

### D6. Fuzzer service orchestration

- **Code:**
  - `services/privoke-fuzzer/src/{fuzzer_service,runtime_client,main,cli,config,json_records}.py`
  - `services/pretrained-v3/src/fuzzer_server.py`
- **Classification:** both are class b in the inventory, because each imports its sampler and training code in-process. They are not part of stage 10.
- **Feasibility:** straightforward with `tonic` once D5 is in Rust, which is why stage 21 depends on stage 20. Without D5, it would need a Rust process calling a Python curriculum worker, which adds a hop.
- **Lost:** the single-process debugging and dump format, unless preserved.
- **Effort:** S to M. **Risk:** low.

### D7. Pretrained-v3 runtime server orchestration

- The checkpoint server and store are already stage 10. The experimental fuzzer server belongs to D6.
- The `runtime_server.py` gRPC shell around torch could only move with D3 and D4, or as a Rust front end to a Python worker.
- **Effort:** S as a front end. **Risk:** low. It gives little benefit while the service is experimental.

### D8. Telemetry LDP randomizer and estimator

- **Code:**
  - Client randomizer and ledger: `extension/client-runtime/src/telemetry/privacy.py`, with a 53-bit uniform draw, a binary64 threshold, rejection sampling and a SQLite ledger.
  - Collector estimator: `services/telemetry-service/app/storage.py`. It moves to Rust in stage 4 with exact parity required.
- **Feasibility:** high. `rand` plus `getrandom` give the same 53-bit construction, and `rusqlite` handles the ledger. The thresholds depend on `exp` from the platform libm, which can differ from CPython's in the last bit.
- **Lost:** the audited finite-epsilon values (C34, the T2 record) apply only to the audited CPython kernel. A Rust randomizer would need the finite audit recomputed (exact arithmetic over its actual thresholds), and the C7 trusted-emitter tests would need to be ported.
- **Effort:** S. **Risk:** low technically, medium for claims.

### D9. GLiNER detector (optional, not shipped)

- **Code:** `extension/client-runtime/src/NER/gliner_detector.py`
- **Rust options:** `gline-rs` (ONNX through `ort`).
- **Lost:** C53 compared it under Python; it was dropped and not shipped.
- **Effort:** S. **Risk:** low. Relevance is also low.

### D10. External LLM classifier client

- **Code:** `extension/client-runtime/src/LLM/open_classifier.py`
- **What it is:** a remote API call; the inference itself is remote.
- **Rust options:** an HTTP client (`reqwest`) or an OpenAI-compatible crate.
- **Lost:** nothing measurable. The prompt construction in `LLM/prompt.py` must be byte-identical.
- **Effort:** S. **Risk:** low.

### D11. Model package fetch in Rust (added in r2; approved by root as networking work, done in stage 17)

- **Code:** `extension/client-runtime/src/LLM/privoke/{v3_package,parameter_stream}.py`
- **What it is:** not inference. It is listed here because it changes an evidence path: the installed-client probes and the V3 timing measured the Python fetch.
- **Rust options:** a `tonic` client in the supervisor (or in the stage 17 runtime). It writes the same cache layout and performs the same pin, shape and finite-value checks.
- **Lost:** nothing, if the cache bytes and the rejection behaviour are identical. The installed-client claims need a rerun to be claimed for the new path.
- **Effort:** S to M. **Risk:** low.
- **Note:** this is done in stage 17.

## Rejected alternatives and revisit conditions

- **Rust edge gateway replacing nginx** (one Rust proxy in front of the plaintext services). Rejected: it recreates the single compensating control that the user's microservice argument removes, and it leaves the in-service gaps open.
  - Revisit if per-service public ports are not acceptable operationally.
- **Bearer tokens or JWT in place of client certificates.** Rejected: the clients already carry mutual-TLS material (`PRIVOKE_TLS_*`). Tokens would add an issuer, refresh and storage without closing more gaps.
  - Revisit if browser-originated cloud calls are ever needed.
- **Rewrite before the deadline.** Rejected: it would change the system the paper and artifact describe while they are being finalised.
- **Revisit triggers for the boundary:**
  - Loopback hop latency exceeds the run-to-run spread.
  - Stages 17 to 22 complete (the approved D ports). The Python runtime worker then disappears, and only the PyO3 spaCy worker pool (stage 11) remains Python.
