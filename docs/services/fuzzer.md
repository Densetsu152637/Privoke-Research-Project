# privoke-fuzzer

> Source area: `services/privoke-fuzzer`. Commands retain their original working-directory assumptions; follow explicit directory instructions, or use this source area for component-local commands.

`privoke-fuzzer` is a Python gRPC worker and CLI for PriVoke research experiments. It generates labeled prompts, asks `client-runtime` to execute a bounded semantic training batch, submits the returned head-only or full-Tiny encoder-and-head deltas to `param-update-service`, and runs ad hoc prompt tests through the same runtime service.

It is not in the hosted prompt decision path. Training cycles deliberately target the streamed semantic model path rather than the full regex + NER + semantic pipeline.

For LLM study comparisons, use the semantic-only curriculum-improvement runner. Older combined-protocol study commands require `--allow-product-pipeline` solely for separately authorized product/detector analysis; their pipeline selection rules and historical scores retain that scope. See the [evaluation entrypoint policy](../../evaluation/README.md).

Normal deployments enable the updater's automatic requester by default: 32
prompts per stage at startup and another cycle every hour after completion.
Its default random source now uses the shipped, pinned AU3 audience coverage
release, with all six audiences and all ten primary categories represented in
each 32-original cycle. Explicit legacy datasets and fixed named study protocols
retain their selected source. See [audience coverage](../audience-v3-data.md) for
quotas, source pins, deployment controls and evidence boundaries.
Each cycle runs head training followed by full Tiny encoder-and-head training on
the same model ID, with a different seed for each new cycle and the same seed
and stage IDs on retries. The stages publish independently; a full-stage
rejection does not roll back an accepted head update. Set `FUZZER_PROMPT_COUNT=0` on the updater
to disable it. Controlled quality studies and general product smoke overrides
do this explicitly. The dedicated semantic-training CI job instead enables one
automatic cycle on an isolated fixed fixture. See
[requester configuration](parameter-updates.md#fuzzer-requests).

## gRPC Worker

Defined in `shared/proto/privoke/v1/parameters.proto`:

- `RunTrainingCycle(FuzzerTrainingRequest) -> FuzzerTrainingResponse`
- `RunUnderlyingTrainingCycle(FuzzerTrainingRequest) -> FuzzerTrainingResponse`
- `RunPresenceTrainingCycle(FuzzerTrainingRequest) -> FuzzerTrainingResponse`
- `Health(HealthRequest) -> HealthResponse`

Default port: `50053`

Startup:

```bash
python src/main.py
```

On `RunTrainingCycle`, the service:

1. validates `prompt_count > 0`,
2. caps prompt counts above `FUZZ_MAX_PROMPT_COUNT`,
3. checks durable update status for the same source/request identity and returns an existing committed outcome on replay,
4. reserves distinct labeled clean and sensitive held-out examples, then samples training prompts excluding their normalized texts and any declared held-out source groups,
5. sends bounded training and held-out batches through `ComputeSemanticGradients`,
6. receives deltas and before/candidate metrics tied to the exact model version; rejects missing, non-finite, invalid or regressing quality evidence,
7. submits accepted deltas through `SubmitParameterUpdate` with replay identity and request fingerprint,
8. returns the committed acknowledgment and training metadata to the requester.

The fuzzer does not connect to `model-streaming-service`. Fetching, validation, caching, model execution, and gradient descent all occur inside `client-runtime`.

`RunPresenceTrainingCycle` is a separate binary annotation-presence objective. It requires an explicit `model_id` matching `PRESENCE_MODEL_ID`, and loads a prepared JSONL curriculum from `FUZZ_PRESENCE_DATASET_PATH`. Each row has a unique string `id`, nonempty `text`, strict boolean `sensitive`, and nonempty `group_id`. Sampling is deterministic, holds out both labels, and excludes normalized text and source groups across the two partitions. It sends explicit absent/present enum labels to `ComputePresenceGradients`; no contextual classifications are synthesized and no text transforms are applied. Runtime returns gradients and before/candidate metrics for the frozen representation, and only presence-head gradients are submitted. The presence quality gate requires finite metrics, positive consistent held-out counts for both labels, and no decrease in held-out exact match, present recall, or absent specificity. Presence requests use a task-specific durable fingerprint namespace so request IDs cannot replay a contextual update.

Both dedicated presence RPCs require exactly `layers=[DETECTION_LAYER_SEMANTIC]`; omitted, mixed or duplicate selections fail before model access. Inference returns exactly one successful semantic `RuntimeLayerExecution`. Training requires a nonempty disjoint binary guard and returns actual `training`, `base_heldout` and `candidate_heldout` `SemanticTrainingExecution` records with exact nonzero example counts. Callers reject missing or failed traces before accepting predictions or publishing updates. These records identify semantic computation of the binary task, not contextual classifications. Regenerate protobuf bindings for this stricter admission contract; older responses without execution evidence are rejected. Historical measurements are unchanged.


## Experimental pretrained v3 study controller

The [v3 protocol](../pretrained-v3-study.md) uses separate experimental Python
fuzzer, runtime and checkpoint servers. Host Python drives the controller and
dataset loops; the runtime performs physical HEADS or FULL fitting. The fuzzer
validates explicit semantic execution, ordered TRAIN/guard commitments, actual
work and candidate identity before requesting publication. Immutable raw terminal
candidates remain scientific endpoints even when their guard rejects publication.
CAS receipts, exact replay and status reconciliation preserve unknown outcomes
without replacement fits. This opt-in route does not change the automatic Tiny
requester or its independently published stages.

## Training Semantics

`RunTrainingCycle` updates the six sensitivity, visibility and category head tensors on a full-capability Tiny artifact. `RunUnderlyingTrainingCycle` instead calls `ComputeUnderlyingModelGradients` to update token/position embeddings, every attention/feed-forward block and those heads. It requires the versioned `contextual_full_encoder_sgd_v1` artifact strategy and explicit contextual targets. Existing declared last-block research artifacts retain their scoped behavior. This is supervised task-specific classification training, not general language-model pretraining. Frozen MiniLM online updates still fail explicitly.

Both runtime training RPCs require exactly `[DETECTION_LAYER_SEMANTIC]` and nonempty held-out examples; empty or mixed layer lists fail. The fuzzer checks returned `training`, `base_heldout` and `candidate_heldout` records for the semantic layer, successful status and exact example counts. These are direct Tiny execution records, not an `AnalyzePrompt` product-pipeline trace. It also validates request/model/base identity, artifact checksum, declared strategy, exact tensor shapes/inventory, fingerprints and bounded finite deltas before publication.
Training and held-out execution use the same canonical text normalization as
serving, so Unicode compatibility forms, obfuscated email separators and spaced
digits have a consistent semantic representation in candidate quality checks.

`train_parameter_batch`:

- generates optional transformed variants per new example and rejects overlap with held-out normalized texts,
- delegates the complete model-dependent batch to `client-runtime`,
- receives bounded tensor deltas, metrics, fingerprints, and the exact base version,
- packages those values for `param-update-service` without receiving model weights.

Only the selected strategy's tensor deltas are sent to `param-update-service`; raw prompt text is not included in that update. The fuzzer's local training evidence does retain the synthetic request/response protobufs and execution records under `PRIVOKE_FUZZER_DUMP_DIR/training-cycles/`, so those evidence files need separate handling from the bounded update metadata. Runtime quality evaluation compares the base model and exact clipped/float32 candidate on distinct held-out labels without mutating its serving cache. Publication requires training exact-match rate strictly above `FUZZ_MIN_EXACT_MATCH_RATE`, both held-out strata present, and no decrease in held-out exact-match rate, sensitive recall, or clean specificity. `candidate_heldout_safety_regression_rate` must also be zero: each example preserves at least the lesser of its target and baseline severity and policy action, including confidence-based action thresholds. Missing/invalid metrics fail the cycle. This synthetic held-out guard does not establish generalization to public benchmarks.

The update service checks the base version, atomically applies accepted deltas, increments `+train.N`, and streaming makes that artifact available on the next request. Runtime caches refresh after their configured interval. A retry after a lost acknowledgment queries durable status before generating or training new data; conflicting request reuse is rejected, and unavailable status storage prevents a new cycle.

For explicitly admitted `full_projected_adam64_v1` FULL execution, the same
strict configured floor applies to `candidate_train_exact_match_rate` under
`candidate_train_exact_eligibility_v1`; original pre-update `exact_match_rate`
remains separate. HEAD/default eligibility and every held-out predicate above
retain their behavior. Gate diagnostics share the authenticated metric selector
and record the versioned selected metric, strict threshold and guard predicates.
The bound `full_adam_gate_v1` summary is retained with the complete cycle and
publication identity. Equality with the floor rejects.

The experimental FULL RPC deadline is 180 seconds; default RPCs retain ten
seconds. A durable reservation precedes each physical attempt. Reservation
rejection records zero RPC calls, while a started request without a response
retains an unknown outcome and cannot be replayed. Raw responses are persisted
immutably before admission. Publication validates raw request/header/response,
trace, exact delta, identities and the retained gate, then removes only the
validated detailed trace from its outgoing copy. Nine weight fields are packed
losslessly as their exact string values into `full_adam_weight_audit_v1`.
Sampling counts, config, identities, compact work/trace summaries and gate
policy remain retained under the unchanged 64-entry/2,048-byte value limits.
Only this FULL policy with `contextual_sampling_strategy=taxonomy_coverage_v1`
also packs the exact fourteen taxonomy sampling fields losslessly into
`full_adam_taxonomy_audit_v1` (`schema=1`, `fields` maps names to original string
values). Strategy and `taxonomy_dataset_sha256` stay explicit. Missing or unknown
sampling fields and a preexisting summary key reject publication. The complete
cycle metadata and publication evidence digest bind the unprojected fields.
Consumers of this policy must read weight fields from
`full_adam_weight_audit_v1.fields` and taxonomy sampling fields from
`full_adam_taxonomy_audit_v1.fields`; JSON count-map strings inside those fields
remain strings and may be parsed separately. Default and HEAD consumers retain
their existing keys. The fourteen taxonomy fields comprise training rows/unique
texts/groups, guard rows/groups, sensitivity/sensitive-visibility/category count
maps, training-ID/training-group/guard-group SHA256 values, and expanded
rows/unique-texts/ID SHA256 values.
The raw trace stays in durable evidence. This mechanics policy is experimental
and supplies no held-out improvement or model qualification claim.

The full endpoint uses a separate replay namespace from head and annotation-presence training. Before automatic head publication, the dual-stage path checks that the model supports full training and CPU autograd is usable. The full stage requires the head stage's acknowledged applied version; an intervening publication fails the expected-base/CAS checks. Retry recovery queries durable outcomes before generating or training again. See the [underlying-training record](../fuzzer-underlying-training-20261010.md) for scope, validation and remaining limits.

## Prompt Generation

Default prompt seeds cover financial, health, third-party, identity/location, public, beliefs, criminal, and location cases.

Custom prompt datasets can be JSON arrays, JSON objects with `prompts`, `examples`, or `data`, or JSONL. Entries must include `template`, `text`, or `prompt`, plus either `packed_classification` or a classification object/components.

Example:

```json
{
  "template": "My {account} is behind login.",
  "packed_classification": 526,
  "metadata": {
    "dataset": "custom_financial"
  }
}
```

Templates use vocabulary slots from `src/prompt_generation/vocabulary.py`.
For document-derived curricula, supply `metadata.group_id`. The held-out sampler
reserves distinct declared groups and keeps their metadata; all siblings from
those groups are excluded from training. Insufficient groups fail the cycle.
Datasets without group metadata retain normalized-text disjointness.

## Opt-in taxonomy coverage

`FuzzerTrainingRequest.metadata["contextual_sampling_strategy"]="taxonomy_coverage_v1"`
selects a separately prepared historical TRAIN-only release. Set
`FUZZ_PROMPT_DATASET_PATH` to that release, retain 32 requested originals,
`FUZZ_HELDOUT_PROMPT_COUNT=16` and `FUZZ_TRAINING_TRANSFORMS_PER_EXAMPLE=1`,
and configure a writable durable `PRIVOKE_FUZZER_DUMP_DIR`. The mode rejects
a simultaneous curriculum manifest, missing durability, unsupported release,
or insufficient slots before reservation/receipt lookup or runtime execution.
An optional request `taxonomy_dataset_sha256` must match the loaded release.
There is no automatic fallback to the default dataset.

Preparation uses `evaluation/prepare-taxonomy-coverage.py`: it accepts the pinned
640-row historical `prepared-v3/train.jsonl` and reviewed renderer, verifies
protected exclusions, and consumes existing opaque assessment/safety keys.
Only the explicitly named, pinned development-validation file is opened for
membership checks. Assessment and safety paths embedded in metadata are never
dereferenced. The command creates a new canonical JSON release and provenance
with `fit_release=false`; a new experiment needs its own source/data/protocol
acceptance. See the [iterative record](../iterative-fuzzer-training-20261011.md)
for exact source/release identities and the accepted plan.

For each of ten primary categories, sort its four source-family IDs: the first
two permanently supply TRAIN and the other two permanently supply the guard.
The seed chooses one TRAIN family per category. Twenty actual-disclosure
audience slots, eight fiction controls and four mild controls yield 32 distinct
original texts from ten correlated families. Original sensitivity counts are
S0=8, S1=4, S2=6 and S3=14; sensitive visibility has four rows each for
P0/P1/P2/P3/P4/PU. Every category has at least two positive labels. Full source
category sets are preserved: FINANCIAL has four labels, THIRD_PARTY has four
or six depending on the SEXUAL family, and other categories have two.
The alternating guard uses sixteen distinct guard-only families: eight S0,
two S1, two S2 and four S3, with all six sensitive visibility labels present.
Eight sensitive guard rows do not guarantee all-category guard coverage.

One unchanged invariance transformation per original produces 64 actual rows;
identity duplicates are allowed and the actual unique-text count is reported.
Immediately before the semantic training RPC, the trainer audits the actual
expanded list against its source snapshot, exact slots, doubled actual targets,
weights and permanent source/text isolation. Prompt-free counts and ID/group
digests travel through existing update metadata/evidence. Both HEAD and FULL
bind the same snapshotted dataset bytes, versioned slot/partition plan, resolved
request, effective trainer settings (including the applicable FULL rate), guard
and semantic execution contract before durable reservation and terminal lookup.
Identical terminal retries perform no sampling, fitting or publication; changed
settings/data under a reserved identity fail closed. Actual successful semantic
training/base-guard/candidate-guard execution checks remain mandatory.

The default sampler, legacy receipt fingerprints and contextual 256-row role
quota mode retain their prior behavior. This is an unmeasured training-method
feature, not a demonstrated quality gain. Source labels remain provisional;
the guard families were historical TRAIN in another study and are not globally
untouched evaluation. The baseline bootstrap already exposed all ten categories;
the missing positive exposure motivating this mode concerns the current bundled
fuzzer dataset.

## Opt-in training policy admission and passive diagnostics

`evaluation/prepare-training-policy.py` prepares a new artifact and separate
provenance from an existing artifact and frozen protocol/settings file. Select
`--objective legacy_sum_category` (objective metadata omitted) or
`--objective class_balanced_contextual_v1` or
`--objective class_balanced_contextual_sum_category_decision_margin_v1`, and independently select
`--diagnostics train_before_candidate_v1` or `off`. Preparation preserves model
weights, version and trainability, requires absent optimizer metadata, and binds
the actual baseline parameter fingerprint, source/prepared checksums, policy,
helper source and protocol bytes. It grants no fitting or promotion authority.

Optional `FuzzerTrainingRequest.metadata` fields
`expected_contextual_training_objective` and
`expected_contextual_training_diagnostics_policy` admit the actual runtime
artifact policy; they do not override it. The controlled process supports legacy,
class-balanced summed-category, and the separately named summed-category union-margin
objective below. Opt-in requests require durable `PRIVOKE_FUZZER_DUMP_DIR`; expectations,
resolved identity and effective settings are bound before reservation and terminal
receipt lookup for both HEAD and FULL. Identical committed retries return the
historical outcome without sampling or computation. Runtime reports the actual
snapshot's executed objective and diagnostic policy; mismatches prevent
publication. Each stage uses its actual base checksum/fingerprints, rather than
requiring the original prepared checksum after weights have changed. This is a
frozen single-writer experiment contract; it does not atomically exclude a
concurrent metadata-only artifact replacement through updater base-version CAS.

The diagnostics artifact flag requires explicit TRAIN targets, both clean and
sensitive target strata, absent optimizer metadata and summed category BCE;
these prerequisites fail before prediction/gradient computation. With the flag
absent, legacy one-class behavior remains available. Diagnostics score normalized
actual TRAIN rows before the update and at the exact existing clipped float32
transported candidate. A bounded versioned JSON record reports weighted
sensitivity/visibility CE, summed category BCE and total; unweighted joint and
per-head/category-set exactness, clean specificity and sensitive recall; explicit
counts, fingerprints and successful semantic TRAIN diagnostic phases; and strict
raw clipping counts/maxima. Runtime-state loss diagnostics do not measure per-task
gradient contributions. They leave update mathematics and publication gates
unchanged. The three existing successful semantic training/base-guard/candidate-
guard records and exact counts remain mandatory. No protobuf schema changes are
needed.

Opt-in physical attempts are retained immutably under
`PRIVOKE_FUZZER_DUMP_DIR/policy-attempts/`, including actual serialized requests and
responses before an admission rejection. An RPC transport failure retains the
request with an unknown computation outcome, rather than claiming zero fits.
These raw evidence files contain synthetic prompt payloads and require the same
handling as existing cycle evidence. The new diagnostic record itself is
prompt-free and limited to 2048 bytes.

If the actual outgoing publication union exceeds the unchanged 64-entry limit,
the diagnostics opt-in compacts secondary sampling/weight audit fields into
`training_audit_v1`, preserving their exact values. Complete unprojected cycle
metadata, metrics and actual execution evidence must already exist durably and
match before this projection. `training_evidence_sha256` binds their canonical
JSON, excluding the later mutable acknowledgment. Gate, receipt, identity and
policy fields remain explicit. Every final value must fit 2048 bytes; no updater
limit is relaxed. Offline actual 64/16/16 fixtures demonstrated 70→48 HEAD and
71→49 FULL entries, with a maximum value of 1356 bytes. These are mechanical
checks of an unmeasured method, not model-quality evidence.

## Environment Variables

- `PARAM_UPDATE_TARGET`, default `param-update-service:50052`
- `PRIVOKE_RUNTIME_TARGET`, default `client-runtime:50054`
- `MODEL_ID`, default `privoke-baseline`
- `FUZZER_ID`, default `privoke-fuzzer`
- `FUZZER_PORT`, default `50053`
- `FUZZ_TIMEOUT_SECONDS`, default `10.0`
- `FUZZ_SEED`, default `1337`
- `FUZZ_MAX_PROMPT_COUNT`, default `256`
- `FUZZ_MAX_CONCURRENT_CYCLES`, default `1`; additional simultaneous requests receive `RESOURCE_EXHAUSTED`
- `FUZZ_PROMPT_DATASET_PATH`
- `PRESENCE_MODEL_ID`, default `privoke-presence-balanced`; presence-cycle requests must name this model explicitly
- `FUZZ_PRESENCE_DATASET_PATH`; required dedicated presence JSONL curriculum
- `FUZZ_TRAINING_LEARNING_RATE`, default `0.03`
- `FUZZ_UNDERLYING_TRAINING_LEARNING_RATE`, optional finite positive rate for the FULL contextual encoder-and-head endpoint; when unset, uses `FUZZ_TRAINING_LEARNING_RATE`. HEAD and annotation-presence training keep the existing rate. The runtime applies the selected rate before the unchanged float32/clipping path.
- `FUZZ_TRAINING_MAX_GRADIENT`, default `0.05`
- `FUZZ_TRAINING_TRANSFORMS_PER_EXAMPLE`, default `1`
- `FUZZ_MIN_EXACT_MATCH_RATE`, default `0.0`, finite in `[0,1]`; training rate must be strictly greater
- `FUZZ_HELDOUT_PROMPT_COUNT`, default `16`, allowed range `2` to `256`; requires distinct clean and sensitive examples
- `PRIVOKE_FUZZER_DUMP_DIR`, default `/workspace/dumps/privoke-fuzzer`

For a controlled FULL-rate comparison, set `FUZZ_TRAINING_LEARNING_RATE=0.03`
and `FUZZ_UNDERLYING_TRAINING_LEARNING_RATE=0.003` in the fuzzer service process,
keeping `FUZZ_TRAINING_MAX_GRADIENT=0.05` and the publication gates fixed.
Compose overrides must explicitly forward these variables into the service;
setting them only in the host shell does not configure the container.
This controls the whole FULL stage, including its task heads, rather than only
the encoder. A smaller rate is an unproven quality hypothesis.

FULL effective settings already enter curriculum and procedural request
fingerprints before durable reservation and receipt lookup. Unset or explicitly
equal FULL rates preserve existing fingerprints; changing the effective rate
under the same request identity fails before training or receipt recovery.
Use a fresh request identity for a new arm and retain the original configuration
when recovering an uncertain request. Runtime metadata and retained protobuf
execution evidence record the selected rate; transported deltas are never
rescaled by the fuzzer. See the [iterative training record](../iterative-fuzzer-training-20261011.md).

## Runtime Boundary

The fuzzer has no source dependency on `extension/client-runtime`. Production and development Compose both deploy that code as the `client-runtime:50054` service, and the fuzzer waits for it to become healthy. It never calls `model-streaming-service`, the extension bridge on `8080`, its control plane on `50056`, or its workstation detector on `50057`. Prompt tests use `AnalyzePrompt`; contextual training uses `ComputeSemanticGradients`; annotation-presence training uses `ComputePresenceGradients`. Model selection, fetching, validation, caching, execution, descent, and model-version selection remain inside the runtime.

## CLI

Run raw host Python scripts from the repository root after the
[host setup](../../evaluation/README.md). The development or research-test stack
publishes the fuzzer on `127.0.0.1:50053`; prompt probes connect to the runtime
on `127.0.0.1:50054`. The fuzzer retains the training loop on the server.

Check fuzzer health, then train and persist a new model version:

```bash
python evaluation/run-fuzzer-tests.py health
python evaluation/run-fuzzer-tests.py train \
  --target 127.0.0.1:50053 \
  --model-id privoke-balanced \
  --prompt-count 32
```

Test the LLM layer through the runtime gRPC service:

```bash
python evaluation/run-fuzzer-tests.py test-prompts \
  --layer semantic \
  --prompt "My email is alex@example.com"
```

For an explicitly requested product end-to-end test or detector ablation, select
the full runtime or multiple layers. Keep these results separate from LLM tests:

```bash
python evaluation/run-fuzzer-tests.py test-prompts \
  --layer regex \
  --layer ner \
  --layer semantic \
  --model-id privoke-balanced \
  --regex-parallel \
  --generated-count 8
```

Available test layers:

- `runtime`: asks the runtime to run its complete configured detector set.
- `regex`: asks the runtime to isolate regex detection.
- `ner`: asks the runtime to isolate NER detection.
- `semantic`: asks the runtime to isolate its configured semantic backend.

Without `--layer`, prompt tests send only `semantic` and require exactly one successful semantic execution in the response. Empty or unknown selections fail. Repeat `--layer` to send an explicitly selected set in one RPC for product tests. `--regex-first` and `--regex-parallel` override the runtime's default ordering for that request. `--model-id` selects the streamed semantic model and defaults to `MODEL_ID` when set. Detector failures are written to the report from the runtime's per-layer response and cause the CLI to exit with status `1`; layers intentionally skipped after a regex `BLOCK` in an explicit product test are counted separately and are not failures. Historical full-runtime scores are not LLM-only evidence.

Prompt files can be JSON, JSONL, or text. JSON entries may be strings or objects with `text`/`prompt` fields.

The CLI writes a JSON dump for each prompt-test run and prints the full per-prompt JSON report. Each prompt entry includes the request text, optional expected classification, and each selected layer's elapsed runtime time plus observed classification/action/results. If any layer run fails, it exits with status `1`.

The host script writes dumps to `./dumps/privoke-fuzzer`. In Docker dev mode,
dumps use the same host directory through a bind mount. In the production stack,
`/workspace/dumps/privoke-fuzzer` is backed by the `fuzzer-dumps` named volume.
The service-local `src/cli.py` remains available inside containers with explicit
service-DNS targets. Rejected training requests exit with status `1`.

## Durable synthetic curriculum

An optional prepared curriculum enables grammar prompts, offline teacher
paraphrases, and fact-preserving evolution. Prepare it with
`evaluation/prepare-synthetic-curriculum.py`; inputs are checked against an opaque
protected-key index and a byte-pinned development endpoint. The final corpus is
never needed. Assistant-authored targets remain `assistant_provisional`.

Set `FUZZ_CURRICULUM_MANIFEST_PATH`, `FUZZ_CURRICULUM_STATE_PATH` and optionally
`FUZZ_CURRICULUM_REPLAY_FRACTION` (default 0.25). Split files are bound by SHA-256,
with globally distinct IDs, canonical text and parent families. The fixed
publication guard contains exactly 16 rows, and the replay pool at least 64.
Curriculum batches balance roles and clean/sensitive targets. Total requested
prompt count includes replay. `FUZZ_TRAINING_REPLAY_WEIGHT` sets its relative
example weight (default 0.35; finite values in (0,1]), separately from the row
fraction. Effective trainer settings are included in receipt fingerprints.

SQLite reservations retain batch IDs and per-model cursors across restarts;
retrying the same request reuses its batch, and a new request advances the cursor
even if its candidate was rejected. Receipt fingerprints include the manifest
digest. `curriculum_stage` selects `all`, `grammar`, `teacher`, or `evolved`;
`curriculum_hard_ids` is a JSON array of up to eight eligible TRAIN IDs. Guard and
replay IDs cannot be mined. Publication quality checks remain mandatory.

The default `curriculum_sampler_policy=deterministic_v1` preserves existing
allocation and requires `curriculum_sampler_seed=0`. Set request metadata
`curriculum_sampler_policy=seeded_family_v1` and `curriculum_sampler_seed` to an
unsigned 32-bit integer for seeded family/descendant permutations per epoch.
Keep this sampler seed stable across cycles; the trainer seed may change.
Seeded cursors have separate policy/seed namespaces and survive retries and
restart. Audits record sampler settings, positions/epochs, replay weight and
train/replay ID digests. Role/class quotas and within-batch uniqueness are retained.

The versioned resource `evaluation/datasets/synthetic-teacher-templates-v2.json`
uses complete authored evolved renderings and contextual contrasts at the same
row budget. Optional preparation `--assessment-resource` writes a separate
contextual endpoint outside all training, replay and publication-guard splits.
See the [audited improvement process and results](../fuzzer-curriculum-improvement-process-20261009.md)
for exposure distributions, provisional-label limits and controlled comparisons.

Automatic augmentation retains labels only for conservative transformations;
redaction and phone replacement are available explicitly, but are no longer
randomly applied while retaining an unchanged contextual label.

See the [continual-study instructions](../../evaluation/README.md#continual-synthetic-fuzzer-study)
for isolated Docker execution and before/after measurement.

## Subagent Tasks

Subagents working here should:

- add deterministic experiment fixtures,
- improve generated prompt coverage,
- add training-cycle integration tests with streaming and update services,
- keep gradient bounds explicit,
- preserve metadata needed to trace updates back to request IDs and training config,
- preserve the runtime RPC boundary for all detector execution.

The default dataset mixes challenging compound templates with independently labeled calibration phrases also used by model bootstrap training. The held-out split is disjoint within each adaptive cycle; this calibration overlap cannot establish generalization to unseen data.

## Periodic sampler configuration

To opt an existing curriculum deployment into seeded allocation, set the updater's
`FUZZER_CURRICULUM_SAMPLER_POLICY=seeded_family_v1` and
`FUZZER_CURRICULUM_SAMPLER_SEED=42` through base Compose or the service environment.
The sampler seed stays fixed across periodic cycles and retries, while
`FUZZER_REQUEST_SEED` continues to advance for new trainer cycles. The defaults
remain `deterministic_v1` with sampler seed 0; a nonzero deterministic seed is
rejected. Explicit seeded metadata is included in the durable request commitment.
`FUZZ_TRAINING_REPLAY_WEIGHT` is forwarded by base Compose and defaults to 0.35.
These controls require the existing curriculum manifest and durable state paths;
they do not install a curriculum or promote a model automatically.

Presence runtime attempts under `PRIVOKE_FUZZER_DUMP_DIR/presence-runtime` retain serialized actual requests/responses, request hashes, base identities and execution-validation status, including rejected and transport-unknown calls. Presence publication evidence also keeps immutable attempt copies beside its canonical logical-request trace, numeric guard diagnostics, and acknowledgments. Physical attempt copies are not additional logical training rounds.


## Opt-in FULL TRAIN backtracking

Add `--backtracking full_train_backtracking_v1` to the preparation command above,
with `--diagnostics train_before_candidate_v1` and any supported objective.
The source must already be FULL-capable. Preparation preserves weights, version
and trainability, changes the artifact checksum intentionally, and writes a
bounded preparation record binding the actual baseline checksum/fingerprint,
protocol bytes and helper source. Its SHA-256 is
`backtracking_preparation_sha256` in the separate provenance file. Preparation
still grants no fitting authority.

For an explicit FULL request, supply the existing objective/diagnostics
expectations plus `expected_contextual_training_backtracking_policy` equal to
`full_train_backtracking_v1` and
`expected_contextual_training_backtracking_preparation_sha256` from provenance.
The client sends these exact expectations in the versioned gRPC invocation
header `x-privoke-training-admission-v1`; the original header is bound into durable
request identity before reservation or committed-receipt lookup. Missing,
unsupported, duplicate or conflicting admission fails before the gradient.
The actual FULL artifact requires matching admission. Its flag is dormant for
HEAD, and an explicit HEAD backtracking expectation is rejected. Without the
artifact/header opt-in, existing defaults and candidate construction are retained.
The frozen single-writer assumption still applies.

One original raw gradient is computed. From that immutable direction, candidates
use the requested FULL learning rate multiplied in order by 1, 1/4, 1/16, 1/64
and 1/256. Each candidate is reconstructed before clipping, round-to-eight-decimal
update arithmetic and float32 transport; a previously clipped delta is never
rescaled. The first finite candidate whose TRAIN objective decreases strictly by
more than 0.00002 and changes an encoder coordinate is selected. This fixed
threshold exceeds the observed two-case serving/Torch loss discrepancy by over
12 times; it is not a global numerical-error bound. The guard is evaluated only
after selection, with the existing TRAIN exact-match floor and all guard and
publication gates unchanged. No guard-guided fallback occurs.

Returned `gradients` contain the selected transported delta. `learning_rate`
remains the requested rate, while `effective_learning_rate` identifies the
selected trial; the fuzzer publishes the returned values without multiplying by
either rate. Two bounded JSON values retain the original raw direction SHA-256,
shape-inventory fingerprint, coordinate count/norm/maximum, base loss and all
attempted trial rates/losses/clipping/fingerprints. `gradient_fits=1` counts the
single gradient separately from `backtracking_trials` and
`backtracking_semantic_examples` (completed rows).
`backtracking_forward_attempts` and `backtracking_attempted_semantic_examples`
retain attempted work separately: a failed forward never claims completed rows
or zero attempted model work. Structural errors propagate instead of being
relabelled as numeric no-improvement. For N TRAIN rows and t valid trials, serving
work comprises N baseline rows plus t*N trial rows, with guard work separate.
Selected diagnostics reuse these same predictions.

If all five trials fail, the typed runtime error
`TRAIN_BACKTRACKING_NO_IMPROVEMENT_V1` carries one gradient fit and the actual
TRAIN trial audit, no selected delta and no guard execution claim. The client
validates it and raises a known training rejection; no publication occurs.
Under `PRIVOKE_FUZZER_DUMP_DIR/backtracking-attempts/`, one immutable raw physical
attempt stores serialized request, original invocation header and response BEFORE
local admission; a separate linked verdict records acceptance, known rejection
or unadmitted evidence. Transport failure retains the request/error type with
unknown fit count. Persistence failure also prevents submission. A committed
retry returns its historical updater receipt without sampling or fitting; this
feature adds no automatic retry for rejected or unknown attempts.

Complete unprojected execution/cycle evidence remains durable before the existing
limited audit projection. Publication retains every gate, receipt, identity and
policy field under the unchanged 64-entry/2048-byte value limits. This feature is
an unmeasured training-method hypothesis motivated by two captured FULL
overshoots; it does not resolve the quality model's separate TRAIN-exact floor or
establish disclosure gains.

## Opt-in summed-category union decision margin

`class_balanced_contextual_sum_category_decision_margin_v1` supports HEAD and FULL.
It retains the existing class-balanced weights and summed category BCE, adding
one coefficient-1 BCE term for the maximum of non-S0-minus-S0 severity logits
and category logits minus the logit of the artifact's category threshold. Its
binary target is the contextual target's sensitive decision. Exact maximum ties
use the first configured term. This threshold-aligned surrogate leaves the
decoder unchanged; severity ties, inclusive category thresholds and float32
boundaries can differ from its binary margin decision. The existing mean-category
decision-margin objective remains a distinct method.

Preparation requires absent optimizer metadata. Explicit targets and matching
objective admission are required before model work, including when passive
diagnostics are off. Without FULL backtracking, the original invocation header
uses schema 2 with exactly `schema`, `expected_objective` and
`expected_diagnostics_policy`; the latter must explicitly be the known diagnostics
policy or JSON null, meaning diagnostics are actually absent. FULL backtracking
uses its existing schema-1 admission with the new objective identifier. A HEAD
artifact's backtracking flag remains dormant; its objective-only header contains
no backtracking fields. Exact original header bytes enter durable request identity
before reservation or receipt lookup. A backtracking exhaustion error on an
objective-only call is unadmitted evidence, rather than a known one-fit rejection.

New-objective diagnostics and backtracking audits use objective-specific schema 2
with five loss columns: sensitivity CE, visibility CE, summed category BCE,
decision-margin BCE and their total. Existing schema-1 four-column contracts remain
strict. Full unprojected evidence is durable before the bounded publication audit.
The selected transport arithmetic, five-rate search, strict decrease tolerance,
base TRAIN exact-match floor, guard gates and publication limits are unchanged.
The three-fixture TRAIN-only pilot found no feasible candidate among its 15 fixed
rate trials, with zero sensitive joint exactness throughout. Mechanical validation
does not reverse that negative result or resolve a zero base TRAIN exact-match
floor. See the separately retained pilot and limitations in
`evaluation/results/iterative_fuzzer_20261011/sum-margin-objective/result.md`.

## Opt-in ordinary-benign TRAIN coverage

`taxonomy_benign_coverage_v1` calls the legacy taxonomy generator first, then
replaces four fiction S0 rows in place: HEALTH/P0, POLITICS/P1, RELIGION/P2 and
CRIMINAL/P3. An independent deterministic RNG selects one independently authored
ordinary task per visibility from a pinned positive TRAIN pool. The batch keeps
32 originals, 64 approved presentations, sensitivity counts 8/4/6/14, raw unit
weights, all sensitive/category exposure, four fiction controls and the exact
ordered legacy 16-row guard. Ordinary rows have their own TRAIN IDs, groups,
provenance, explicit S0 targets and empty category targets.

Configure `FUZZ_BENIGN_POOL_PATH`, `FUZZ_BENIGN_MANIFEST_PATH` and
`FUZZ_BENIGN_EXCLUSION_PROOF_PATH`; requests must pin `taxonomy_dataset_sha256`,
`benign_pool_sha256`, `benign_manifest_sha256` and
`benign_exclusion_proof_sha256`. This strategy requires the authenticated FULL
64-step Adam policy and rejects incompatible policies, orphan/missing pins and
snapshot tampering before durable reservation or receipt lookup. Default
taxonomy and anchor-rehearsal behavior remain unchanged.

The new manifest also binds an independently pinned full-content commitment for
all 640 ordered legacy rows: exact text, full and packed targets, raw weights,
complete metadata, partitions and exclusion metadata. A supplied in-memory
dataset must match that accepted content before selection, auditing or direct
trainer execution; retaining the dataset hash while altering rows cannot pass.

`evaluation/prepare-benign-coverage.py` admits the independently reviewed pool
and proves exclusion for every approved transform using the existing opaque
endpoint commitments and the authorized frozen development membership route.
It also checks all legacy TRAIN/guard source variants. It does not regenerate
endpoint keys or read protected payloads. Preparation records retain
`fit_release: false`; a future finite schedule must separately prove its actual
ordered expanded membership, targets, raw weights and unchanged guard bytes.

The initial pool has 32 unique source groups from one authored collection, eight
per visibility. Its explicit English audience cues, repeated visibility terms
and topics that are not crossed across audiences limit diversity claims.
Retained raw audits bind source, target, weight and ordered wire commitments.
The separate lossless `full_adam_benign_audit_v1` publication summary preserves
the existing 64-entry/2048-byte limits. The guard wire commitment follows the
existing packed-only runtime request. Update mathematics, admission gates,
runtime schema and semantic-only execution remain unchanged. Nonmodel constructor
checks establish contracts; numerical readiness and model benefit remain untested.

## Opt-in ORIGINAL TRAIN sensitivity retention

SR01 adds `full_projected_adam64_original_train_gate_v1` and
`full_projected_adam64_original_train_hinge_v1`. Both retain the main 64
presentations and the same CURRENT-relative 16-row guard. They additionally
require every eligible ORIGINAL TRAIN row to remain sensitive, with sensitivity
severity and rounded-confidence action at least the lesser of the gold and
ORIGINAL values. Existing classification and action-policy helpers define these
comparisons; a positive binary margin cannot substitute for the per-row checks.

The hinge policy adds coefficient one times a separately normalized, unweighted
mean of `max(0, ORIGINAL_margin - CURRENT_margin)` to the existing main objective.
The decoder-aligned margin is the maximum of the non-S0-versus-S0 sensitivity
logit differences and category logits minus the log-odds of the configured
category probability threshold. The
gate-only policy has no auxiliary backward work. Both policies retain cold FULL
64-step Adam, learning rate 0.003 and the CURRENT-base cumulative radius 0.05;
old policy/objective combinations and schema3 remain valid and unchanged.

The fixed positive TRAIN bank contains 200 independently reviewed rows in twenty
groups. Eligibility requires gold non-S0, an ORIGINAL sensitive prediction,
margin greater than `1e-6` and sensitivity top-two gap greater than `1e-6`.
Every group must be represented for each profile; no backfill or endpoint tuning
is permitted. The bank content, accepted ORIGINAL artifact bytes and identity,
eligible rows, packed targets and baselines are committed by canonical JSON
with one actual trailing LF byte. SR01's ORIGINAL parameter fingerprint and
teacher snapshot use the effective float32 values evaluated by Tiny and carried
by protobuf repeated floats. The independently authenticated raw artifact bytes,
SHA and checksum remain unchanged. A pure actual-protobuf roundtrip demonstrated
identity agreement for all three profiles; this establishes parity-branch
reachability, not measured NumPy/Torch margin parity. Earlier raw-identity
manufactured manifests remain historical; fresh actual references still need
separate root approval and trusted-pin installation. BC01's full 640-row content binding remains
enforced. These labels and authored collection do not establish generalization.

Configure `FUZZ_RETENTION_BANK_PATH`, `FUZZ_RETENTION_REFERENCE_PATH`,
`FUZZ_RETENTION_MANIFEST_PATH`, `FUZZ_RETENTION_TEACHER_PATH` and the independently
trusted `FUZZ_RETENTION_MANIFEST_SHA256`; the runtime uses the corresponding
`PRIVOKE_RETENTION_` names. The trusted hash must come from root-accepted actual
reference preparation, separately from request self-pins. Fuzzer, direct trainer
and runtime authenticate immutable sidecars before reservation, receipt recovery
or model access; runtime also binds the active artifact. Schema4 carries the new
policy/objective and manifest commitment, without a public RPC/protobuf change.

The in-process reference helper routes actual `AnalyzePrompt` requests with
explicit layers `[4]`, asserts the returned sole execution and ORIGINAL artifact
identity, and observes logits from that same prediction. Its scoped binding is
explicitly passed into the threadpool closure and reset on failure; ordinary
calls retain their existing behavior. Teacher work is distinct from CURRENT
work, including when CURRENT initially equals ORIGINAL. The parity diagnostic
uses an already required CURRENT auxiliary Torch call only when its parameter
fingerprint equals ORIGINAL; it adds no teacher forward. A successful fit records
BASE/FINAL main NumPy rows (64 each), the three existing guard passes (16 each),
BASE/FINAL auxiliary safety rows, main gradient work and hinge-only auxiliary
gradient work. Partial work remains observed lower bounds with unknown work
explicit; control fits are not padded to match hinge compute.

Immutable raw schema4 traces precede admission and publication. Separate main
and auxiliary losses and normalized gradient norms remain in raw step evidence;
the publisher recognizes both new policies, validates complete retained bindings,
and emits a bounded lossless summary alongside BC01/AR01 fields. Manufactured
constructor checks for both policies produced 61 entries, maximum 1,405 UTF8
bytes per value, with exact restoration and artifact/receipt consumer checks.
These zero-delta/full-tensor fixtures are not real teacher predictions, measured
losses, accepted encoder-changing updates or numerical canaries. Actual reference
generation, numerical pilot and model-quality claims remain unreleased pending
separate root acceptance and a TRAIN-only protocol.

## Opt-in fixed gold-target TRAIN anchor rehearsal

`taxonomy_anchor_rehearsal_v1` requires authenticated FULL Adam and an explicit
`FUZZ_REHEARSAL_MANIFEST_PATH`. Its request supplies `contextual_sampling_strategy`
and all three mandatory SHA pins: `taxonomy_dataset_sha256`,
`rehearsal_bank_sha256`, and `rehearsal_manifest_sha256`. Prepare the separate
canonical manifest with `evaluation/prepare-train-anchor-rehearsal.py --dataset
PATH --output PATH`; preparation never opens evaluation endpoints and always
records `fit_release=false`. The server validates the same manifest bytes,
positive permanent-TRAIN membership, fixed table and effective configuration
before reservation or receipt recovery. HEAD, curriculum, extra golden replay,
missing/orphan pins and policy mixtures fail closed.

The bank fixes sixteen gold-target anchors from the first sorted TRAIN family
per category and sixteen complements from the second. Each half contains
4/2/3/7 S0/S1/S2/S3 rows, four clean and twelve sensitive rows, and two sensitive
rows per visibility. All twenty TRAIN families and complete source category sets
are represented. Membership stays fixed; the seed changes order and the unchanged
legacy one-transform expansion. Thirty-two normalized-unique originals become
64 presentations, which may repeat same-parent inputs. Cross-original possible
transform collisions are rejected and actual expanded uniqueness is recorded.
The same-seed sixteen-row v1 guard, unit raw weights, runtime class balancing,
64-step Adam, strict candidate TRAIN floor and heldout predicates remain fixed.

The full manifest and sampling audit are retained immutably before compute.
Actual ordered protobuf training fields have a commitment checked at publication.
`full_adam_rehearsal_audit_v1` restores exact outgoing sampling strings; explicit
strategy/dataset/bank/manifest pins remain visible. The actual constructed map
must satisfy the existing 64-entry/2048-byte value limits. This route leaves v1,
default sampling, HEAD and the semantic-only execution contract unchanged.

This unmeasured feature changes family and audience coverage; it does not isolate
temporal forgetting. Existing TC02 exclusion commitments remain historical.
Before fitting, the future manager must prove actual v2 outputs are a subset of
the byte-pinned TC02 source-row/legacy-transform superset already validated
against opaque exclusions and development validation64. Preserve that proof's
endpoint commitments and verify source/target/transform identity; old seed-specific
batch hashes cannot identify new v2 batches. Do not open endpoints, regenerate
keys or substitute unrelated validation968 indices. A
separate preregistration must fix common warm-up, paired arm states, update slots
and budgets. Compare joint and visibility retention on the same sixteen anchors
(four clean/twelve sensitive) from their shared attained state; failure to reduce
retention loss rejects the mechanism, and failure to attain accuracy is
inconclusive. Retention success still requires unchanged development qualification.
AR01 adds no fit, assessment, quality gain or convergence claim.
# Frozen TRAIN window and component retention (opt-in)

`full_projected_adam64_window_checkpoint_v1` is a separate FULL-only policy. It uses `taxonomy_benign_train_window_v1`, eight authenticated BC01 blocks (256 original occurrences, 512 actual transformed wire rows), and eight deterministic block permutations. The bounded 64-candidate seed search must cover all 20 permanent TRAIN families. Repeated source IDs/texts are counted explicitly; 512 occurrences are not claimed to be 512 independent examples. The permanent 16-row guard remains outside the window. Preparation, optimization and checkpoint selection read no development/final inputs.

`evaluation/prepare-train-window.py` freezes the actual ordered texts, targets, raw weights, provenance and block membership from existing accepted taxonomy/benign releases. `evaluation/prepare-component-retention.py` authenticates an already-produced full ORIGINAL task-logit record against the fixed approved TRAIN bank and a separately supplied accepted teacher-file SHA. It performs zero teacher/model calls. Preparation emits hashes and `fit_release: false`; emitted hashes do not approve themselves. The accepted component manifest SHA and teacher-file SHA must be configured independently on both fuzzer and runtime. The complete teacher/CURRENT configuration, including v1/v2 readout and every dimension/label/threshold, must agree. Historical v1 references and fixed teacher pins retain their old semantics.

Prepare an optimizer-free FULL summed-margin artifact with `evaluation/prepare-training-policy.py --optimizer full_projected_adam64_window_checkpoint_v1 --objective class_balanced_contextual_sum_category_decision_margin_v1 --diagnostics off --window-manifest-sha256 ACCEPTED_WINDOW_SHA --component-manifest-sha256 ACCEPTED_COMPONENT_SHA`, together with its required source/protocol/output/provenance arguments. This changes policy metadata/checksum; it does not fit or promote a model. `evaluation/compose.train-window.yml` provides explicit read-only release mounts and fuzzer/runtime environment wiring for a separately prepared research model store. It disables automatic legacy cycles. All paths and accepted pins are required; no ambient fallback chooses a release.

Invoke the existing CLI explicitly, substituting the prepared frozen seed and accepted pins:

```text
python src/cli.py train --underlying --model-id privoke-balanced --prompt-count 256 --seed FROZEN_SEED --training-policy full_projected_adam64_window_checkpoint_v1 --window-manifest-sha256 ACCEPTED_WINDOW_SHA --component-manifest-sha256 ACCEPTED_COMPONENT_SHA
```

The window source and transformed rows are rederived before reservation and receipt lookup. Schema-5 admission binds effective policy/config/window/component pins. Compute sends semantic `[4]` explicitly and validates every returned semantic execution phase/count. One cold local Adam trajectory executes 64 main directions (4096 row presentations, 128 microbatches) plus independently counted component auxiliary directions. Main class balancing occurs once over the complete window; a block uses eight times its weighted sum divided by frozen window weight. Unequal block masses therefore do not silently change the intended objective.

Component retention averages eligible category-bit hinges, then eligible components within a row, then eligible ORIGINAL-sensitive rows, coefficient one. It preserves positive non-S0, target-capped ordinal severity, gold-correct category bits including negatives, and gold-correct visibility margins. Saved positive teacher margins are capped at 1.0; ties/nonpositive margins are excluded. Exact per-row sensitivity/severity/category/visibility/action gates remain separate. The rounded-confidence production action predicate is authoritative; the margin losses are surrogates and do not claim to differentiate action.

BASE and exact transported checkpoints 8/16/…/64 are scored on TRAIN window plus ORIGINAL TRAIN only. Independent clean/sensitive/component nonregression constraints precede ranking by sensitive joint, ordered sensitive component counts, all-row joint, loss, earliest step. Publication requires strict sensitive joint/component progress and the configured strict selected TRAIN packed-label exact floor; rounded-confidence action correctness remains independently gated and ranked. The preserved FULL gate also requires an actual transported encoder change: head/query-only changes produce `no_transported_encoder_change` without guard execution. The guard executes only for the single selected nonBASE candidate (one BASE comparison and one selected comparison). Guard failure does not search another candidate. BASE fallback or floor/guard failure records a durable known `no_update`, retains the original version and performs no publication. The selected delta/state are distinct from the terminal step-64 state. Unknown physical outcomes cannot replay; identical known no-update receipts return without another fit.

Full source, recurrence, checkpoint predictions, partial-work counters, raw RPCs and admission evidence remain durable. Publication drops the detailed trace only after validating it against independent pins and the retained cycle. Compact winner/terminal evidence stays within 64 metadata entries and 2048 bytes per value. The updater independently checks policy/pins, full tensor shapes, selected delta and reconstructed selected state; this is mechanical provenance, not a model-quality claim.
