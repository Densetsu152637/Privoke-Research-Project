# privoke-fuzzer

> Source area: `services/privoke-fuzzer`. Commands retain their original working-directory assumptions; follow explicit directory instructions, or use this source area for component-local commands.

`privoke-fuzzer` is a Python gRPC worker and CLI for PriVoke research experiments. It generates labeled prompts, asks `client-runtime` to execute a bounded semantic training batch, submits the returned classification-head gradients to `param-update-service`, and runs ad hoc prompt tests through the same runtime service.

It is not in the hosted prompt decision path. Training cycles deliberately target the streamed semantic model path rather than the full regex + NER + semantic pipeline.

For LLM study comparisons, use the semantic-only curriculum-improvement runner. Older combined-protocol study commands require `--allow-product-pipeline` solely for separately authorized product/detector analysis; their pipeline selection rules and historical scores retain that scope. See the [evaluation entrypoint policy](../../evaluation/README.md).

Normal deployments enable the updater's automatic requester by default: 32
prompts at startup and another cycle every hour, with a different seed for each
new cycle and the same seed on retries. Set `FUZZER_PROMPT_COUNT=0` on the updater
to disable it. Controlled research and CI overrides do this explicitly. See
[requester configuration](parameter-updates.md#fuzzer-requests).

## gRPC Worker

Defined in `shared/proto/privoke/v1/parameters.proto`:

- `RunTrainingCycle(FuzzerTrainingRequest) -> FuzzerTrainingResponse`
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

## Training Semantics

The training cycle fine-tunes the sensitivity, visibility, and multi-label category heads of the streamed transformer. The encoder remains frozen in this first architecture revision, which keeps updates small and makes online experiments repeatable.
Training and held-out execution use the same canonical text normalization as
serving, so Unicode compatibility forms, obfuscated email separators and spaced
digits have a consistent semantic representation in candidate quality checks.

`train_parameter_batch`:

- generates optional transformed variants per new example and rejects overlap with held-out normalized texts,
- delegates the complete model-dependent batch to `client-runtime`,
- receives bounded tensor deltas, metrics, fingerprints, and the exact base version,
- packages those values for `param-update-service` without receiving model weights.

Only trainable-head deltas are sent to `param-update-service`; raw prompt text is not included. Runtime quality evaluation compares the base model and exact clipped/float32 candidate on distinct held-out labels without mutating its serving cache. Publication requires training exact-match rate strictly above `FUZZ_MIN_EXACT_MATCH_RATE`, both held-out strata present, and no decrease in held-out exact-match rate, sensitive recall, or clean specificity. `candidate_heldout_safety_regression_rate` must also be zero: each example preserves at least the lesser of its target and baseline severity and policy action, including confidence-based action thresholds. Missing/invalid metrics fail the cycle. This synthetic held-out guard does not establish generalization to public benchmarks.

The update service checks the base version, atomically applies accepted deltas, increments `+train.N`, and streaming makes that artifact available on the next request. Runtime caches refresh after their configured interval. A retry after a lost acknowledgment queries durable status before generating or training new data; conflicting request reuse is rejected, and unavailable status storage prevents a new cycle.

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
- `FUZZ_TRAINING_MAX_GRADIENT`, default `0.05`
- `FUZZ_TRAINING_TRANSFORMS_PER_EXAMPLE`, default `1`
- `FUZZ_MIN_EXACT_MATCH_RATE`, default `0.0`, finite in `[0,1]`; training rate must be strictly greater
- `FUZZ_HELDOUT_PROMPT_COUNT`, default `16`, allowed range `2` to `256`; requires distinct clean and sensitive examples
- `PRIVOKE_FUZZER_DUMP_DIR`, default `/workspace/dumps/privoke-fuzzer`

## Runtime Boundary

The fuzzer has no source dependency on `extension/client-runtime`. Production and development Compose both deploy that code as the `client-runtime:50054` service, and the fuzzer waits for it to become healthy. It never calls `model-streaming-service`, the extension bridge on `8080`, its control plane on `50056`, or its workstation detector on `50057`. Prompt tests use `AnalyzePrompt`; contextual training uses `ComputeSemanticGradients`; annotation-presence training uses `ComputePresenceGradients`. Model selection, fetching, validation, caching, execution, descent, and model-version selection remain inside the runtime.

## CLI

Run host Python scripts from the repository root after the
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
