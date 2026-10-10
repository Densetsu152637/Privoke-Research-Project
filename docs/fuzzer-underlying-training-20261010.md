# Full Tiny encoder training through the fuzzer

The fuzzer now has separate head and underlying Tiny encoder-and-head training endpoints. The automatic requester sequences both on the same selected model, and both require explicit semantic-only runtime execution. This is supervised contextual classification training. It does not perform general language-model pretraining, train on browser traffic or establish improved detection quality.

Research ID: `RQ-FUZZER-FULL-ENCODER-20261010`. The authoritative active goal, retained from the goal tool rather than reconstructed as a conversation quotation, is:

> Refactor the fuzzer service to also be able to train the underlying language model as well. This can have a separate endpoint than the head training but during the automated training batches it should also query that endpoint or start the pipeline. Also ensure that with the fuzzer training only the LLM layer is active for both pipelines so that the models can be accurately updated.

The earlier exact research prompt was “Use the research workflow to acclaim whether the fuzzer does periodic training on procedurally generated prompts rather than an existing dataset”. The later token steering was “you can also increase the token limit”, clarified as “Model input length”.

The full-Tiny contract is committed at `d19ec2e09fcf052af408387b36f4ff033d17913a`, orchestration at `3d2490dfb773fc32824afd604c882e3eca2db68b`, and the runtime/fuzzer publication repair at `98a59eebf9e897b656a392551ffa0a3913e715e3`. The accepted local four-service execution used those final runtime/fuzzer images with the unchanged model/updater source from `3d2490d` and the committed read-only helper at `b509f0e355e98338c2c1730cf5a58a261623318d`. It verified two actual publications on one synthetic logical cycle. The subsequent CI separation is committed at `c7d8015447fcbade3cc20b2c2c26c2cc88622985`; hosted CI has not run at this record checkpoint. Mechanical success is separate from quality evaluation or cloud deployment.

## Questions and evidence boundaries

| Question | Current answer and evidence |
|---|---|
| Does periodic training use procedural prompts? | The existing default fuzzer generates labeled prompts procedurally. An explicitly configured curriculum instead supplies prepared training/replay rows and a held-out guard. Periodicity comes from the updater requester, not from a new dataset or browser traffic. These modes must not be conflated. |
| Can it train the underlying model? | `RunUnderlyingTrainingCycle` calls `ComputeUnderlyingModelGradients` for the explicit `contextual_full_encoder_sgd_v1` strategy. Token/position embeddings, every encoder block and the task heads are trainable. The head endpoint keeps its six-head scope on the same prepared artifact. |
| Are both paths semantic-only? | Both runtime RPCs require exactly `[DETECTION_LAYER_SEMANTIC]`, nonempty held-out data and explicit targets for encoder training. The fuzzer verifies returned phase/layer/status/count records and model/tensor identity before publication. |
| Does automation run both safely across retries? | The requester persists separate head/full stage identities and sequences head then full with the acknowledged head version as expected base. Publications are independently guarded and committed, not one atomic pair. Actual image/network checks verified two publications and completed-cycle restart/replay. A crash during a pending full stage remains unit-test coverage only. |
| What does the larger input limit establish? | Prepared Tiny releases default to 256 total tokens, including one start token. Existing coordinates are preserved and appended positions have deterministic initialization. Boundary mechanics do not establish long-input accuracy. |

## Runtime and publication contracts

The [fuzzer](services/fuzzer.md) orchestrates generation, execution and publication without downloading model weights. The runtime computes supervised gradients on CPU, evaluates the exact clipped/float32 candidate on held-out examples and returns bounded deltas. It does not mutate its serving snapshot during candidate evaluation. Both stages retain the existing finite-metric, held-out class, nonregression and casewise severity/action guards; a computed gradient is not permission to publish.

The head/full runtime responses contain actual `training`, `base_heldout` and `candidate_heldout` semantic execution records. These identify direct Tiny model execution, not an `AnalyzePrompt` product-pipeline trace. Empty or mixed layer lists, failed or missing phases, wrong example counts, mismatched request/model/base identity, invalid checksum, incorrect tensor inventory/shapes, nonfinite values or out-of-bound deltas prevent publication. No regex or NER execution is used to justify a semantic update.

The full strategy uses exact validated tensor shapes, at most 24,576 values in one tensor and 65,536 values in total. Legacy per-tensor limits remain 4,096. The updater rechecks the artifact and shapes under its writer lock and publishes a complete bounded candidate atomically. It does not publish embedding fragments independently. Model identity and checksum change with each committed update; streaming/cache refresh exposes that committed artifact to subsequent inference.

The maintained Linux runtime image installs `torch==2.10.0+cpu` through [requirements-training-cpu.txt](../extension/client-runtime/requirements-training-cpu.txt). `PRIVOKE_REQUIRE_TRAINING_CPU=true` probes CPU autograd before readiness. A dual-stage request additionally checks full-model capability before allowing its head stage to publish. Host mechanics tests used Torch 2.12; they do not substitute for testing the maintained image's pinned version.

Frozen pretrained MiniLM remains a separate architecture with offline-fitted heads and explicitly rejected online updates. Its 256/512-token profiles, failed quality qualification and historical receipts are unchanged. Neither Tiny path consumes the conversational classification prompt; its compatibility tests remain separate from unmeasured conversational accuracy.

## Automatic stages, retries and persistence

The updater defaults to 32 prompts per stage, an initial two-second delay, up to three attempts per pass with two-second retry waits, a 30-second RPC timeout, and a one-hour interval after a cycle. `FUZZER_TRAIN_UNDERLYING=true` selects head then full; `false` selects only heads. `FUZZER_PROMPT_COUNT=0` disables automatic training. `FUZZER_REQUEST_INTERVAL_SECONDS=0` selects a one-shot cycle. Controlled quality-study and general product-smoke overrides disable background training; the dedicated semantic-training CI job deliberately enables one cycle on isolated fixed-fixture state.

`FUZZER_CYCLE_STATE_PATH` defaults to `/data/training-cycles.sqlite3` in the persistent updater volume. The journal retains each cycle's seed, training settings fingerprint, stage request IDs, serialized responses and committed versions. Accepted stages are not repeated on restart. Transport uncertainty preserves the pending stage identity; exhausting its bounded retries does not turn an unknown outcome into a rejection. A later interval or restart can resume it. Changed training settings while pending fail closed. A completed one-shot with unchanged settings remains complete after restart.

A definite head rejection stops the cycle. A definite full-stage rejection records a partial outcome and leaves the accepted head update installed. A later periodic cycle receives a new identity/seed. The full stage must use the first stage's acknowledged version; an intervening update fails expected-base or updater compare-and-swap checks. Durable updater receipts recover lost acknowledgments without republishing. Thus the two publications are sequential and independently recoverable, not transactionally all-or-nothing.

The fuzzer's local evidence retains synthetic request/response protobufs and semantic execution records under `PRIVOKE_FUZZER_DUMP_DIR/training-cycles/`; the submitted update metadata does not contain raw prompt text. Back up the fuzzer reservation/evidence state, automatic-cycle journal, update receipts and model volume together. The underlying stage has a separate replay namespace from the head and binary annotation-presence objectives.

## Context preparation and deployment migration

[prepare-underlying-training-model.py](../evaluation/prepare-underlying-training-model.py) creates a separate artifact without fitting or installing it. It requires a distinct version, positive timestamp and exact source revision, refuses an existing output path and refuses an uncleared recovery receipt. The CLI defaults to 256 total tokens: 255 content tokens plus one start token. Full-training releases reject overlength input; historical artifact behavior is unchanged.

Preparation preserves the original position-embedding prefix and all other weight coordinates. Added coordinates are float32 values in `[-0.03, 0.03]`, derived from the versioned `privoke_position_sha256_v1` coordinate hash. Configuration, version and checksum change, and provenance binds the source model. Extra positional capacity is not pretrained knowledge or a quality result.

Base, development and Compute Engine Compose use a mutable named `model-data` volume. Before serving, bootstrap validates the selected model ID under the receipt writer lock, checkpoints and reloads receipt state, then migrates the **current learned artifact** to the full strategy with at least 256 total tokens. It preserves learned coordinates rather than reseeding from tracked historical model bytes. A valid full-capability artifact with sufficient context is reused unchanged. A volume initialization marker does not bypass this capability check. Do not delete the volume to force migration. These source changes do not prove a cloud deployment occurred.

## Validation status and limits

Retained local evidence is under `evaluation/results/fuzzer_underlying_training_20261010/`. `ft3-result.json`, `ft3-review-r1.json`, `ft4-result.json` and `ft4-review.json` bind the implementation/test artifacts. The FT3 checks include finite-difference gradients, serialized candidate application, head-only encoder preservation, exact shape/strategy admission, 97/256-token acceptance and 257-token rejection, and preparation overwrite refusal. FT4 reports 80 fuzzer, 37 updater and seven runtime tests passing, plus base/development/GCE wiring checks. These are focused mechanics checks, not independent quality scores or actual VM deployment. The later accepted image/network evidence below separately establishes a completed live dual-stage publication.

### Accepted image/network execution

The maintained Linux image ran Torch `2.10.0+cpu`, one thread, with CUDA unavailable. The smoke used 16 fixed synthetic templates, eight training rows and four held-out rows, seed 1, no transformations, learning rate 0.003 and maximum delta 0.00001. It exercised a supported fixed-dataset path, not a sample of procedural prompt quality. The positive exact-match floor was 0; a separate fresh negative run set it to 1. Existing guards and the fixture were not weakened after observing failures.

| Check | Observed outcome |
|---|---|
| Sequential publication | One logical cycle committed HEAD `smoke-synthetic-256+train.1` then FULL `smoke-synthetic-256+train.2` on the same model ID. FULL's actual base matched the head publication. |
| Model effects | HEAD changed heads and preserved every encoder coordinate. FULL changed token/position embeddings, an earlier encoder block and heads. Published final state matched the exact bounded float32 candidate. |
| Identity evidence | Initial S0 and final S2 were streamed online. Intermediate S1 was reconstructed from actual HEAD deltas, not independently captured online; FULL's observed base version/checksum matched it. |
| Semantic isolation | Actual training/base-heldout/candidate-heldout records selected only SEMANTIC; semantic inference likewise returned one semantic execution, without a presence gate or product detector. |
| Replay and admission | Four successful committed-stage replays across before/after restart plus two deliberate stale/conflicting submissions preserved model/audit state. |
| Boundary matrix | Nine final RPC records: 97 and 256 total tokens accepted and 257 rejected for both gradient endpoints and semantic inference. Boundary checks did not publish updates. |
| Restart | All four services restarted; the same terminal cycle/stage IDs and accepted trace/model/audit/receipt bytes persisted, with no new gradient execution or publication. |
| Strict negative | On fresh state, HEAD candidate exact match 0.5 failed the strict floor of 1; no FULL call, acknowledgment, update audit or publication followed. |

There were two accepted publications, but three positive gradient computations: HEAD ran twice because its first publication failed, and FULL ran once. The separate negative HEAD ran once. Seven boundary gradient attempts include four supported successes, two expected 257-token errors and one earlier malformed 97-token request. Total gradient RPC attempts were therefore 11. Seven semantic `AnalyzePrompt` attempts yielded six successes and one expected 257-token error. Health/snapshot calls were not globally counted; no overall RPC total is inferred from these counts. The final harness test receipt reports 15 passing tests.

### Retained failed attempts and recovery limits

1. An unquoted tmpfs entry in the isolated overlay parsed as multiple mounts and failed before service execution. The overlay was corrected without changing the fixture or training guards.
2. The first actual HEAD computation and semantic guards succeeded, but publication failed because pretty-printed model-config JSON contained control characters rejected by existing metadata validation. Source `98a59ee` canonicalizes the validated config to compact JSON and preserves definitive updater rejection statuses. The original pending stage identity was resumed; HEAD was computed again before the two successful publications.
3. After both stages were accepted, the scheduler's aggregate terminal SQLite commit failed with disk I/O and left a rollback journal. The precipitating cause is unproven. Standard SQLite recovery in Linux-local writable storage passed integrity checks and preserved model, audit and accepted receipt bytes. Restart then marked that same aggregate cycle complete without retraining. This was an accepted-HEAD-and-FULL/aggregate-pending recovery, not a live crash during a pending FULL stage; the latter remains unit-only evidence.
4. A root-UID one-off could not read private trace files under dropped capabilities. Running as the recorded owner UID/GID `10001:10001` resolved this without relaxing file permissions. A harness mismatch between shape-bound and training-wire fingerprint domains was corrected while retaining the actual hashes.
5. An early 97-token boundary request omitted packed labels and failed guard validation. Its log is retained, but the original raw error response is missing and is not reconstructed. Corrected requests used the authoritative packed labels; subsequent raw responses were retained before assertions.

The accepted result is `FT5E/FT5E-result.json`, SHA-256 `07b3792fb83adc3f1911796ab1a5e46e1cf32ed2e3ba385699f67e63edf2c844`. Its 142-file evidence manifest is `FT5E/FT5E-evidence-manifest.json`, SHA-256 `264af4759a2da599ff4d5bbd3f4399cc49f24646900e363c32306568fdd5bd64`, under the local evidence directory above. The command record is `FT5E/FT5E-commands.json`. These receipts bind the observed revisions, image identities, attempts and limitations; a hash does not substitute for unavailable raw evidence. Task service cleanup is managed separately and is not inferred from these execution receipts.

### Reproduction and CI scope

Use the standalone [four-service overlay](../evaluation/compose.underlying-training-smoke.yml), an isolated Compose project and fresh Linux-owned task state. The maintained [semantic-training CI job](../.github/workflows/service-stack-ci.yml) supplies the full prepare/capture/start/verify/replay/admission/boundary/restart/negative sequence. Run the client helper inside the runtime image as UID/GID `10001:10001`, mount the task state at `/state` and the repository's model seeds read-only at `/workspace/models`, and use internal service names:

```bash
docker compose run --rm --no-deps --user 10001:10001 --entrypoint python \
  -v "${FT5_STATE_DIR}:/state" -v "$PWD/models:/workspace/models:ro" \
  -e MODEL_STREAMING_TARGET=model-streaming-service:50051 \
  -e PARAM_UPDATE_TARGET=param-update-service:50052 \
  -e FUZZER_TARGET=privoke-fuzzer:50053 \
  -e PRIVOKE_RUNTIME_TARGET=client-runtime:50054 \
  client-runtime /workspace/evaluation/run-component-tests.py stack-smoke \
  --semantic-training-only --training-state-dir /state \
  --training-action verify --training-output /state/verify.json
```

This example assumes `COMPOSE_FILE=evaluation/compose.underlying-training-smoke.yml`, an isolated `COMPOSE_PROJECT_NAME`, an absolute `FT5_STATE_DIR`, built images and the preceding preparation/capture/start phases. Use a fresh output path. Keep live SQLite access inside the Linux container/storage boundary; inspect closed snapshots rather than opening a live Windows bind-mounted database from the host. The tested recovery does not establish a general cross-OS filesystem failure cause.

Automatic push/PR CI now runs the dedicated semantic-training job; the full product `docker-stack` job requires `allow_product_pipeline=true`, whose workflow-dispatch/call default is false. The deployment workflow explicitly opts in for its separate product/deployment purpose. Component unit/configuration jobs remain distinct from detector-pipeline scoring. Local static/configuration and Linux preparation checks passed for this workflow change, but a hosted CI run remains pending. None of this claims a cloud deployment, quality qualification or protected-final evaluation.

The prior [accelerated fuzzer study](accelerated-fuzzer-study-20261010.md), [curriculum comparison](fuzzer-curriculum-improvement-process-20261009.md) and [frozen pretrained study](semantic-pretrained-context-study-20261010.md) retain their original methods, hashes and negative/tradeoff outcomes. Adding online full-Tiny mechanics does not revise those measurements, prove sustained improvement, satisfy reviewed-label/data requirements or authorize protected-final scoring. A new quality claim needs a separately frozen supervised evaluation and casewise regression checks. No new external research source was needed for this repository implementation record.
