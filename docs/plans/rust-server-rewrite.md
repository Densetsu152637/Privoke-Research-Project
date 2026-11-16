# Plan: Rust server rewrite and nginx removal

Revision: 2026-11-16 (planning only; base `7384ec7` on `feat/nick-branch`, branch `plan/rust-rewrite`)

**User instruction (16 November 2026).** "Because we use microservices, we do not need nginx. Also, plan to rewrite most of the server architecture in rust, the only exceptions being where model inference and training occur, as python is a good language for them. However, if they can be rewritten in rust, let me know and then I will decide whether it happens or not."

**Status.** This is a plan. No code is changed by it. Every stage is `pending`. The [user-decision section](#inference-and-training-components-that-could-be-rewritten-in-rust-for-the-users-decision) lists options only; nothing there is scheduled.

## Goals

Each goal is boolean and names its check. Commands run from the repository root on the host.

- **G1. nginx is gone from every deployment path.** `git grep -n -i nginx -- deploy .github docker-compose*.yml` prints nothing, and `deploy/gce/nginx.conf` does not exist.
- **G2. Authentication is enforced inside each server, before nginx is removed.** Stage 8 (removal) has stages 3 to 6 as dependencies. Every non-loopback listener of a server rejects a peer without a valid client certificate. Check: the new UPDSEC record (stage 9) has rows A1, A3, T1, T3, T8, T12 and T14 `rejected` with model unchanged, and the new static rows (replacing ST1 to ST3) hold.
- **G3. Each UPDSEC-20261116 gap is closed or kept, and each has a negative test.** In the new record, the gap table lists all eight gaps. Each is `met`, or `kept` with a reason, and each links at least one row that ran. Check: `python evaluation/update_security_report.py` followed by `python -m unittest discover -s evaluation/tests -p test_update_security.py`.
- **G4. The Rust services pass their host tests.** `cargo test --workspace --locked --manifest-path rust/Cargo.toml` exits 0 on the host.
- **G5. The Rust services behave like the services they replace.** Check: `cargo test -p privoke-conformance --manifest-path rust/Cargo.toml`. It replays the stage 0 corpus and requires byte equality for artifacts, canonical JSON, fingerprints, streamed chunks, V3 package bytes and receipts. Telemetry estimates must also match exactly.
- **G6. Python inference and training code does not change unless a stage owns the change.** `git diff <S0 tag> -- extension/client-runtime/src/{LLM,NER,regex,detection,classification,v3} extension/client-runtime/src/pipeline.py extension/client-runtime/src/model.py services/privoke-fuzzer/src/{prompt_generation,training} services/pretrained-v3/src/{runtime_server,fuzzer_training,audience_schedule}.py shared/python/privoke_model` shows nothing. Stage 6 may change transport-only files, and it lists them.
- **G7. Recorded evidence is not invalidated silently.** Every row in the [revalidation table](#research-evidence-and-revalidation) is `revalidated (record)`, `historical (unchanged path)`, or `not claimed for the Rust build`. No existing evidence file is edited to describe the Rust build. Check: review the table against `git log -- paper/research docs/experiments`.
- **G8. Cloud clients can fetch the default V3 package.** `GetModelPackage` and `StreamModelAsset` are public RPCs on the authenticated model listener. Check: the stage 8 smoke test fetches `privoke-v3-balanced` over mutual TLS and verifies its pin.

## Scope and non-goals

**In scope:**
- Moving server and infrastructure code to Rust.
- Removing nginx and replacing it with in-service mutual TLS and authorisation.
- PKI and identity design.
- Compose, deployment and CI changes.
- Conformance and security revalidation.
- Sequencing against the paper deadline.

**Non-goals:**
- Rewriting any model inference or training code. The user decides that separately.
- Changing the protobuf contracts in `shared/proto/`, except for additions that a stage justifies.
- Changing the browser extension's gRPC-Web wire format.
- Changing the native-messaging protocol.
- Editing the paper.
- Pushing.

Before the deadline, only stage 0 and stage 1 may run (see [sequencing](#sequencing-against-the-11-december-2026-deadline)).

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
- Proposed new paths:
  - `rust/` (Cargo workspace)
  - `tests/conformance/` (golden corpus captured in stage 0)

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
- **(b) Inference/training → stays Python.**
- **(a/b) Mixed:** the component is split.

| Component | Path | Language now | What it does | Class | Plan |
| --- | --- | --- | --- | --- | --- |
| Model streaming service | `services/model-streaming-service/cmd/server/*.go` | Go | Catalog. Legacy JSON Tiny artifact snapshot streaming. Standard V3 manifests and assets (`standard_v3.go`). Validation of training-contract metadata, which must equal Python canonical JSON byte for byte (`contextual_training.go`, `scratch_presence.go`, `pretrained_context.go`). Health subcommand. | a | Rust, stage 3 |
| Param update service | `services/param-update-service/app/{server,validation,receipts,audit,bootstrap,config}.py` | Python | Validates updates (model, base version, tensors, shapes, finite values, per-coordinate bound). Compare-and-swap publication with atomic rename. Durable receipts in SQLite. Audit log. Bootstrap. No backpropagation. | a | Rust, stage 5 |
| Training-cycle scheduler | `services/param-update-service/app/{fuzzer_requests,training_cycles}.py` | Python | Timed, persistent requests to the fuzzer (SQLite state, retries, seeds). This is orchestration, not training. | a | Rust, stage 5 |
| Telemetry collector | `services/telemetry-service/app/{server,validation,storage,config}.py` | Python | Validates LDP packets. Stores lifetime marginals in SQLite. Summary uses nominal inversion and clipping. | a | Rust, stage 4. The estimator is ported with the Python code kept as a parity oracle, because claims C7 and C34 cite it. See [decision item D8](#d8-telemetry-ldp-randomizer-and-estimator). |
| Fuzzer service | `services/privoke-fuzzer/src/{fuzzer_service,main,cli,config,runtime_client,json_records}.py` | Python | gRPC `FuzzerService`, cycle control, calls to the runtime for gradients, dumps. | b (kept whole) | Stays Python. The orchestration is thin (`fuzzer_service.py` plus `runtime_client.py`) and tied to the training loop it drives. Splitting it would add a process hop and gain nothing. Stage 6 adds mutual TLS only. |
| Fuzzer prompt generation | `services/privoke-fuzzer/src/prompt_generation/*` | Python | Seeded synthetic training curricula (Python `random`, MT19937). | b | Stays. Decision item D5. |
| Fuzzer training and update aggregation | `services/privoke-fuzzer/src/training/*` | Python | Batches, transforms, gradient aggregation into update deltas, retention evidence. | b | Stays. Decision item D5. |
| Pretrained-v3 checkpoint server | `services/pretrained-v3/src/{checkpoint_server,checkpoint_store,common}.py` | Python | Experimental content-addressed checkpoint store and publication receipts (`CheckpointService`). | a (experimental) | Deferred. Stage 10 is optional and runs only if V3 training graduates from experimental. |
| Pretrained-v3 fuzzer server | `services/pretrained-v3/src/fuzzer_server.py` | Python | Experimental `V3FuzzerService` orchestration. | a (experimental) | Deferred to stage 10. |
| Pretrained-v3 runtime and training | `services/pretrained-v3/src/{runtime_server,fuzzer_training,audience_schedule}.py` | Python (torch) | V3 semantic inference and physical training (`TrainingService`). Frozen AU3/BC01 sampling schedules. | b | Stays. Decision items D3, D4, D5. |
| Client runtime: transport and hosting | `extension/client-runtime/src/{grpc_main.py,hosting/*,env.py,config.py,dependency_check.py}` | Python | gRPC `PrivokeRuntimeService` server. HTTP JSON server (`hosting/server.py`). Serialisation. | a/b | Stays in the Python worker process, behind the Rust supervisor (see [boundary](#pythonrust-boundary)). Stage 6 changes the listener security only. |
| Client runtime: model fetch | `extension/client-runtime/src/LLM/privoke/{v3_package,parameter_stream}.py` | Python | Downloads and verifies V3 packages and legacy streams into the cache. | a | Stays in Python for now. Moving the download and pin check into the Rust supervisor is a revisit item: it would change the path the installed-client evidence measured. |
| Client runtime: detection pipeline | `extension/client-runtime/src/{pipeline,model,detection/*,classification/*,task_readout,pretrained_context,transformer_encoder,util}.py` | Python | Normalisation, layer selection, policy aggregation, semantic readout. | b | Stays. Normalisation and aggregation fix the recorded detector results. |
| Regex layer | `extension/client-runtime/src/regex/*` | Python (`regex`, Presidio recognisers) | Deterministic rules, validators, Presidio imports. | b (detector) | Stays. Decision item D2. |
| NER layer | `extension/client-runtime/src/NER/*` | Python (spaCy, optional GLiNER) | spaCy `en_core_web_sm`, post-filter, pattern entities. | b | Stays. Decision items D1 and D9. |
| Semantic classifiers | `extension/client-runtime/src/LLM/{local_classifier,privoke_classifier,abs_classifier,prompt}.py`, `LLM/privoke/{streamed_model,presence_model,scratch_presence_model,pretrained_context_model}.py`, `v3/model.py` | Python (torch, transformers, tokenizers, safetensors) | V3 encoder and heads, legacy Tiny model, presence models. | b | Stays. Decision item D3. |
| External LLM classifier | `extension/client-runtime/src/LLM/open_classifier.py` | Python (`openai`) | Remote API classifier. | b | Stays. Decision item D10. |
| Gradient and local training | `extension/client-runtime/src/LLM/privoke/{training,full_adam_training,window_training,supervised_training,presence_training,sensitive_retention_training,reference_preparation}.py`, `v3/training.py` | Python (torch) | `ComputeSemanticGradients`, `ComputeUnderlyingModelGradients` and `ComputePresenceGradients`. Local SGD and FULL projected Adam. | b | Stays. Decision item D4. |
| Telemetry reporter (client) | `extension/client-runtime/src/telemetry/{privacy,event_emitter}.py` | Python | Randomised response, persistent budget ledger, delivery. | a (infra), held | Stays in Python. The audited finite kernel (C34) is this code. Decision item D8. |
| Runtime supervisor | `extension/runtime-supervisor/src/{main,runtime_supervisor,grpc_web_bridge,native_messaging_host}.py` | Python | Native-messaging host (length-prefixed JSON on stdio). Launches the supervisor and the fixed-argv runtime child. gRPC-Web to gRPC bridge with an origin allowlist and 30/35 s timeouts. `PrivokeRuntimeControlService`. | a | Rust, stage 7 |
| Shared model contracts | `shared/python/privoke_model/{artifact,fingerprint,readout,v3_contract,standard_v3,full_adam,contextual_training,sensitive_retention,window_training,scratch_presence,pretrained_context}.py` | Python | Artifact codec and checksum. Two canonical-JSON variants (`full_adam.canonical`: ASCII-escaped; `sensitive_retention.canonical_bytes`: UTF-8 plus LF). Tensor fingerprints. V3 manifest rules. | a/b | A Rust port in `rust/crates/privoke-contracts` serves the Rust servers (stage 1). The Python originals stay authoritative for training, and the conformance corpus binds the two. |
| Shared training contracts | `shared/python/privoke_model/{presence,training_data,window_training}.py` | Python | Lexical presence inference. Train/eval text keys. Window training. | b | Stays. |
| Service helpers | `shared/python/privoke_service/{environment,logging,validation,stack_connection}.py`, `shared/python/grpc_healthcheck.py` | Python | Environment parsing. Stack selection and the mutual-TLS client channel. Health probe. | a (Python consumers stay) | Stays for the Python processes. Stage 6 adds server credentials and per-service cloud targets. Rust equivalents live in `rust/crates/privoke-transport`. |
| Contracts | `shared/proto/privoke/v1/{parameters,runtime,telemetry}.proto`, `shared/proto/privoke/experimental/v3.proto` | protobuf | Service interfaces. | interface | Unchanged. Rust uses `tonic-build`, with `protox` so that `protoc` is not needed on Windows. |
| Compose stacks | `docker-compose.yml`, `docker-compose.prod.yml`, `docker-compose.gpu.yml`, `evaluation/compose.*.yml` | YAML | Development, production and study stacks. | a | Stage 8 switches the service images. Study compose files stay pinned to their recorded revisions (see revalidation). |
| Cloud deployment | `deploy/gce/{compose.yml,nginx.conf,deploy.sh,bootstrap.sh,tests/smoke.py}`, `.github/workflows/deploy-gce.yml` | YAML, shell, nginx, Python | VM stack and ingress. | a | Stage 8 removes nginx and rewrites the smoke test. |

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
| PyO3, Rust embedding CPython | Reject | <ul><li>It links CPython, torch and spaCy into the Rust binary, which is fragile with Windows DLLs and virtual environments.</li><li>The GIL serialises calls.</li><li>A Python fault kills the server.</li><li>The inference code is still Python, so nothing is gained.</li></ul> |
| PyO3, Python importing a Rust extension (`privoke_contracts_rs`) | Reject for now; revisit | It would remove the duplicate contract code. However, it changes the code path behind recorded training evidence. Revisit after the deadline, once the conformance corpus shows byte equality and the user wants a single contract implementation. |
| Keep Python and Go servers; add mutual TLS only | Reject | It does not satisfy the user's instruction. It remains the fallback if a stage fails its parity gate. |

## nginx replacement design

nginx is removed only after every function it performs has an in-service replacement:

| nginx function | Replacement in each Rust server | Stage |
| --- | --- | --- |
| TLS termination (1.2/1.3) | `tonic` with `rustls`. The server config is built directly so that the client verifier can be set. | 1, 3, 4, 5 |
| Client certificate required, one CA, depth 2 | `rustls::server::WebPkiClientVerifier`, with roots from the client CA, CRLs loaded, and anonymous clients refused. | 1 |
| Method allowlist with 404 default | A **public listener** serves only the public RPCs. Private RPCs go on a separate **internal listener**. An authorisation interceptor maps (role, RPC) to allow, and returns `PERMISSION_DENIED` otherwise. | 3 to 5 |
| Rate limits per IP, 20 connections | `tower` `ConcurrencyLimit`, plus a per-peer limiter (`tower_governor`, keyed by certificate identity and falling back to IP), plus a connection cap. | 1 |
| 1 MB body, 60 s timeouts | `max_decoding_message_size` and `tower::timeout` per service. Streaming RPCs keep their existing per-message limits. | 1 |
| One `:443` shared by two services | Each public service gets its own port. The plan uses model `:443` and telemetry `:8443`; the actual ports are a stage 2 decision. The client gets `PRIVOKE_CLOUD_MODEL_TARGET` and `PRIVOKE_CLOUD_TELEMETRY_TARGET`, and an unset value falls back to `PRIVOKE_CLOUD_TARGET` for model only. The firewall rule in section 3 of the deployment guide changes to match. | 6, 8 |
| `/healthz` on 127.0.0.1:8081 | Each Rust binary has a `healthcheck` subcommand, as the Go service has now, and the gRPC `Health` RPC on the internal listener. | 3 to 5 |
| Re-resolve upstreams after recreate | Not needed: there is no proxy hop. | — |

**Identity (stage 2).** Every principal holds a short-lived X.509 certificate from the private CA. The identity is carried in the certificate's URI SAN:
- `urn:privoke:installation:<uuid>`, role `consumer`
- `urn:privoke:service:<name>`, role `publisher`, `trainer` or `runtime`

How services use the identity:
- Services derive `consumer_id` and `source_id` from the peer certificate (`Request::peer_certs`, parsed with `x509-parser`).
- A request field that disagrees with the certificate identity is rejected.
- A registry file (`installations.toml` and `services.toml`, hot-reloaded) authorises identities individually.

Revocation:
- A CRL is loaded by `rustls`, so revocation takes effect at the handshake.
- The registry deny list provides immediate revocation without reissuing the CRL.
- Issuance and CRLs use a Rust CLI (`rust/tools/privoke-pki`, built on `rcgen`) that replaces the manual OpenSSL steps in section 4 of the deployment guide.

**Telemetry privacy constraint.** Per-installation certificates make telemetry reports linkable to an installation at the transport. The paper already lists source IP and report presence as observable. Even so, the collector must not persist or log the peer identity next to packet content.

Two options for stage 2 to choose between:
1. A shared `reporter` role certificate for telemetry only.
2. Per-installation certificates, with the linkability documented.

Recommendation: option 1 for telemetry, per-installation certificates for model retrieval. The gap table below records this as a deliberate scope limit for telemetry.

## UPDSEC gap closure map

Every gap from [UPDSEC-20261116](../../paper/research/update-security-20261116.md#unmet-properties-gaps) appears below. The new record extends `evaluation/update_security.py` against the Rust services in stage 9. Rows keep their IDs; new rows use the `R` prefix.

| Gap | Decision | Mechanism | Negative test (must be rejected, model unchanged) |
| --- | --- | --- | --- |
| GAP-NO-PUBLISHER-AUTH | Close (stage 5) | `ParamUpdateService` serves only on the internal listener. It requires mutual TLS and the `publisher` role for `SubmitParameterUpdate`, and `publisher` or `trainer` for `GetParameterUpdateStatus`. | A1 and T14 rerun. Add R1: a valid `consumer` installation certificate submits an update and gets `PERMISSION_DENIED`. |
| GAP-IDENTITY-SELF-ASSERTED | Close (stages 3 and 5) | `source_id` and `consumer_id` come from the certificate SAN. A mismatching field is rejected with `PERMISSION_DENIED`. | A2 and T2 rerun. Add R2: a publisher certificate for `service:test-trainer` claims `source_id=server-fuzzer`. |
| GAP-NO-CREDENTIAL-MECHANISM | Close (stage 2). The mechanism is short-lived client certificates checked in-service, with no bearer tokens. | Expiry and not-before are checked by `rustls` at the handshake. Registry entries carry an expiry. | A3 rerun: the bogus token is ignored and the request still fails for lack of a certificate. Add R3: an expired certificate, a not-yet-valid certificate, and a certificate without client-auth EKU are each rejected at the handshake by the real service, not a stand-in. |
| GAP-NO-RETRIEVAL-AUTH | Close (stage 3) | Every model RPC except `Health` requires the `consumer` role. `GetModelPackage` and `StreamModelAsset` are now reachable (G8). | T1, T3, T8 and T12 rerun without a certificate. Add R4: a certificate from a foreign CA with a valid subject. |
| GAP-NO-PER-INSTALLATION-AUTHZ | Close (stage 2 registry, enforced in stages 3 and 4) | Installation IDs in the registry; unknown IDs are refused. | X8 changes: a second certificate from the same CA whose installation ID is not registered gets `PERMISSION_DENIED`. A registered one is accepted (positive control). |
| GAP-NO-REVOCATION | Close (stage 2) | CRL in `WebPkiClientVerifier`, plus the registry deny list. | X13 changes from `not_applicable` to a live run: revoke one installation and its handshake fails. A deny-listed ID gets `PERMISSION_DENIED` without a restart. |
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
| C1 (component suites pass). | The suites change. | 3 to 7: new suite counts in a new record. |
| C5, C6, C42 (B14 installed client). V3 installed timing (`main.tex`, around line 327). Paper around line 325 ("supervisor, bridge"). | The supervisor, bridge and native host are rewritten. Bridge timeouts set the silent-broker timing (about 32 s). | 7: rerun the installed-browser protocol (`paper/research/installed-browser-protocol.md`) only if the paper or artifact is to describe the Rust build. Otherwise mark `not claimed for the Rust build`. |
| C7, C34 and the telemetry audit (collector inversion and clipping). | The collector estimator is reimplemented. | 4: exact estimator parity on the corpus. The client kernel is unchanged unless the user chooses D8. |
| Anonymous artifact (ASIACCS-S8) and reproduction capsules (C41, RP14). | The artifact pins the current build. | Tag the submission revision in stage 0. The artifact is never rebuilt from the Rust tree. |
| Study compose files (`evaluation/compose.*.yml`), whose results cite Go and Python images. | The images change. | Recorded studies stay reproducible from their own revisions. Stage 8 does not edit historical study stacks. |
| Any item in the user-decision list (D1 to D10). | It changes inference or training numerics. | See each item. It affects most of C2 to C56. |

## Sequencing against the 11 December 2026 deadline

- **Before 11 December 2026:** run stage 0 (tag, conformance capture) and, optionally, stage 1 (Rust workspace and contract crate) on `plan/rust-rewrite` or a successor branch. Do not merge into the branch the submission and artifact are built from. Make no change to `services/`, `extension/`, `deploy/`, `shared/python/` or `paper/`.
- **After submission:** stages 2 to 9 in order. The artifact-evaluation and camera-ready builds use the submission tag. If the paper is to describe the Rust build, stage 9 and the revalidation rows run before camera-ready, and the paper is edited under its own authorisation.
- **User-decision items (D1 to D10):** none is scheduled. If any is chosen, it should start only after stage 9, so that server and model changes are never confounded in one revalidation.

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
- **CI:** `service-stack-ci.yml` gains a Rust job (`cargo fmt --check`, `cargo clippy -D warnings`, `cargo test`). The Go job stays until stage 9 retires the Go service.

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
- Owned paths:
  - `rust/`
  - Rust job in `.github/workflows/service-stack-ci.yml`
- Acceptance checks:
  - `cargo test --workspace --locked` exits 0.
  - The contract crate reproduces every stage 0 canonical-JSON, checksum and fingerprint fixture byte for byte.
  - The verifier rejects each of the following in tests: no certificate, foreign CA, expired, not yet valid, missing EKU, revoked.
- Status: pending
- Outcome:
- Handoff notes: allowed before the deadline on a non-submission branch.

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
- Acceptance checks:
  - The tool issues, rotates and revokes certificates in a host test.
  - The registry hot-reload test passes.
  - The documentation names every secret file.
- Status: pending
- Outcome:
- Handoff notes: decide shared reporter certificate versus per-installation certificates for telemetry (recommendation: shared).

## Stage 3: Rust model-streaming service

- Objective:
  - Replace the Go service with full RPC parity (catalog, legacy streaming, V3 packages, metadata contract validation, health subcommand).
  - Public listener: `Health`, `StreamModelParameters`, `GetModelPackage`, `StreamModelAsset`.
  - Internal listener: `GetModelParameters` and `Health`.
- Depends on: stages 1 and 2
- Owned paths:
  - `rust/services/model-streaming/`
  - `services/model-streaming-service/Dockerfile` (replaced) or a new Dockerfile
- Acceptance checks:
  - Every Go test case (`cmd/server/*_test.go`) is ported or explicitly mapped.
  - Streamed bytes match the stage 0 corpus for every catalog model.
  - T1 to T12, R4 and the X8 variant behave as in the gap map.
- Status: pending
- Outcome:
- Handoff notes: keep the Go source until stage 9.

## Stage 4: Rust telemetry service

- Objective:
  - Port ingestion, validation, SQLite storage (opens existing databases) and the summary estimator.
  - Mutual TLS with the reporter credential.
  - The peer identity is never persisted.
- Depends on: stages 1 and 2
- Owned paths: `rust/services/telemetry/`
- Acceptance checks:
  - The estimator output equals the Python output on the corpus and on the telemetry-audit fixtures.
  - Malformed-packet tests are ported.
  - A test asserts that no identity column or log line exists.
- Status: pending
- Outcome:
- Handoff notes: the Python `storage.py` stays as the parity oracle in tests.

## Stage 5: Rust param-update service and scheduler

- Objective:
  - Port validation, compare-and-swap publication, receipts (existing SQLite and JSONL formats), audit, bootstrap and the training-cycle scheduler, which calls the Python fuzzer over mutual TLS.
  - Add publisher authorisation, identity binding and the configurable cumulative bound.
- Depends on: stages 1 and 2. Stage 6 is needed for the fuzzer side of the mutual-TLS link.
- Owned paths: `rust/services/param-update/`
- Acceptance checks:
  - The published artifact bytes equal the Python service's on the stage 0 update sequences.
  - The ported `test_security_validation.py` and `test_update_receipts.py` cases pass, including the injected crash windows.
  - A1 to A3, E1 to E7, T14, R1, R2 and R5 behave as in the gap map.
- Status: pending
- Outcome:
- Handoff notes: choose the default cumulative budget by replaying recorded accepted sequences (C4, C10, C16), so that the bound would not have rejected any historical accepted update unless that is disclosed.

## Stage 6: Mutual TLS for the remaining Python servers and split cloud targets

- Objective:
  - Add server credentials and client-identity checks to `privoke_service` for the client-runtime gRPC server, the fuzzer and pretrained-v3.
  - Internal Compose mode uses mutual TLS.
  - Add `PRIVOKE_CLOUD_MODEL_TARGET` and `PRIVOKE_CLOUD_TELEMETRY_TARGET`.
- Depends on: stage 2
- Owned paths:
  - `shared/python/privoke_service/stack_connection.py`
  - `extension/client-runtime/src/grpc_main.py`
  - `services/privoke-fuzzer/src/main.py`
  - `services/pretrained-v3/src/common.py`
  - `shared/python/grpc_healthcheck.py`
  - shared tests
- Acceptance checks:
  - `python evaluation/run-component-tests.py shared` passes.
  - R6 and X16 behave as in the gap map.
  - A semantic-only `AnalyzePrompt` gives byte-identical responses before and after on the stage 0 inputs (explicit semantic-only layer list, with the returned layer execution asserted).
- Status: pending
- Outcome:
- Handoff notes: transport-only change. The G6 diff check lists exactly these files.

## Stage 7: Rust runtime supervisor

- Objective:
  - Replace the native-messaging host, process supervisor, gRPC-Web bridge (`tonic-web`, same origin allowlist, 30/35 s timeouts, same paths) and `PrivokeRuntimeControlService`.
  - The Python client runtime stays as the child worker.
- Depends on: stage 1
- Owned paths:
  - `rust/services/runtime-supervisor/`
  - native-host manifest templates in `extension/runtime-supervisor/scripts/` (paths only)
- Acceptance checks:
  - The stage 0 native-messaging and gRPC-Web transcripts replay identically.
  - `npm test` in `extension/` passes against the Rust bridge.
  - `python evaluation/run-component-tests.py supervisor` cases are ported.
  - Measured end-to-end median latency does not regress beyond the run-to-run spread.
- Status: pending
- Outcome:
- Handoff notes:
  - The installed-client claims (C5, C6, C42) are not claimed for this build unless the installed-browser protocol is rerun.
  - Revisit: move the V3 package download and pin check into the supervisor.

## Stage 8: Compose and deployment cutover; remove nginx

- Objective:
  - Switch `docker-compose*.yml` and `deploy/gce/compose.yml` to the Rust images.
  - Delete the `ingress` service and `deploy/gce/nginx.conf`.
  - Publish model `:443` and telemetry `:8443` directly.
  - Update `deploy.sh` (drop `nginx -t`) and `deploy-gce.yml` (drop `nginx.conf` from the tarball).
  - Rewrite `deploy/gce/tests/smoke.py` to assert in-service mutual TLS, the private-RPC denial and the V3 fetch.
  - Update the firewall and ingress-routing documentation.
- Depends on: stages 3, 4, 5 and 6. Authentication must be enforced before nginx goes.
- Owned paths:
  - `docker-compose*.yml`
  - `deploy/gce/`
  - `.github/workflows/deploy-gce.yml`
  - `.github/workflows/service-stack-ci.yml`
  - `docs/deployment/google-cloud.md`
  - `docs/services/`
- Acceptance checks:
  - G1, and G8 through the smoke test.
  - `docker compose -f deploy/gce/compose.yml config --quiet` passes.
  - `python -m unittest discover -s evaluation/tests -p test_compose_defaults.py` passes.
- Status: pending
- Outcome:
- Handoff notes: do not edit `evaluation/compose.*.yml` historical study stacks.

## Stage 9: Security revalidation, retirement and records

- Objective:
  - Extend `evaluation/update_security.py` with the R rows and the new static checks, and run it against the Rust services as host processes.
  - Write a new UPDSEC record. Do not overwrite UPDSEC-20261116.
  - Fill in the revalidation table.
  - Retire the Go service and the Python `param-update`, `telemetry` and `runtime-supervisor` sources (history is preserved by the tag).
- Depends on: stage 8, and stage 7 for the supervisor retirement
- Owned paths:
  - `evaluation/update_security*.py`
  - `evaluation/tests/test_update_security.py`
  - `paper/research/update-security-<date>.md` and its `.json`
  - `docs/experiments/`
  - retired service directories
- Acceptance checks: G2, G3, G5 and G7.
- Status: pending
- Outcome:
- Handoff notes: paper text changes need their own `REWRITE_SCOPE` authorisation.

## Stage 10 (optional): Experimental pretrained-v3 servers

- Objective: port `checkpoint_server` and `checkpoint_store` and the `fuzzer_server` orchestration to Rust, behind the same transport crate. `runtime_server`, `fuzzer_training` and `audience_schedule` stay Python.
- Depends on: stage 9, and a decision that V3 training graduates from experimental
- Owned paths: `rust/services/v3-checkpoint/`, `rust/services/v3-fuzzer/`
- Acceptance checks: content-addressed store and receipt parity with the Python store on the corpus.
- Status: pending (not scheduled)
- Outcome:
- Handoff notes: skip if the experimental path is retired instead.

## Inference and training components that could be rewritten in Rust (for the user's decision)

These are options, not recommendations. Each item can be chosen independently, but none should start before stage 9 (see sequencing).

"Lost" lists what a rewrite would invalidate or give up. Effort is S, M or L, and risk refers to the risk of not reaching parity.

### D1. spaCy NER layer

- **Code:** `extension/client-runtime/src/NER/{ner_detector,ner_postfilter,pattern_entity_detector,use_cases}.py` with `en_core_web_sm` 3.7.1.
- **Feasibility:** low for parity. There is no Rust spaCy. The small model's CNN tok2vec, tokenizer exceptions and tagger cannot be ported directly. The post-filter depends on the tagger's lowercased-token reading and the model's word list.
- **Rust options:**
  - (a) A different token-classification model through `ort` (ONNX Runtime) or `candle`, with the `tokenizers` crate. Ready-made pipelines exist, such as `rust-bert` NER on `tch-rs`.
  - (b) A hand-built gazetteer and rules engine.
  - Both are new detectors, not ports.
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

- **Code:** `services/privoke-fuzzer/src/{fuzzer_service,runtime_client,main,cli,config,json_records}.py`
- **Classification:** this plan keeps it in Python as part of training.
- **Feasibility:** straightforward with `tonic` once D5 stays in Python. It would need a Rust process calling a Python curriculum worker, which adds a hop.
- **Lost:** the single-process debugging and dump format, unless preserved.
- **Effort:** S to M. **Risk:** low.

### D7. Pretrained-v3 runtime server orchestration

- The checkpoint, store and fuzzer parts are already stage 10.
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

## Rejected alternatives and revisit conditions

- **Rust edge gateway replacing nginx** (one Rust proxy in front of the plaintext services). Rejected: it recreates the single compensating control that the user's microservice argument removes, and it leaves the in-service gaps open.
  - Revisit if per-service public ports are not acceptable operationally.
- **Bearer tokens or JWT in place of client certificates.** Rejected: the clients already carry mutual-TLS material (`PRIVOKE_TLS_*`). Tokens would add an issuer, refresh and storage without closing more gaps.
  - Revisit if browser-originated cloud calls are ever needed.
- **Rewrite before the deadline.** Rejected: it would change the system the paper and artifact describe while they are being finalised.
- **Revisit triggers for the boundary:**
  - Loopback hop latency exceeds the run-to-run spread.
  - The user chooses D3 or D4, which would let the Python worker disappear on that path.
