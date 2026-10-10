# Accelerated training across model surfaces

This prospective study measures before and fixed-final quality after accelerated training across the maintained model and training interfaces. It uses separate trajectories for different objectives and architectures. It does not promote a model or attribute Tiny training results to a conversational prompt revision.

The active goal objective is: “Now that these things have been refactored, run accelerated fuzzer training rounds on all models and then test them to see how they have improved. This should cover all training surfaces.” This records the active goal, rather than claiming a verified verbatim user message.

## Fixed matrix and dose

The maintained entrypoint is `evaluation/run-accelerated-training-surfaces-study.py`. Its `plan` operation enumerates 168 trajectories, each with seeds 42, 43 and 44 represented explicitly.

| Cohort | Configurations per seed | Trajectories |
| --- | ---: | ---: |
| Four Tiny models with HEAD, LAST BLOCK, FULL and actual automatic HEAD then FULL | 16 | 48 |
| Balanced Tiny with three contextual objectives across three scopes, plus two local optimizers across three scopes at the mean category objective | 15 | 45 |
| Balanced curriculum HEAD, FULL and automatic dual | 3 | 9 |
| Four offline Tiny profiles with head only and full encoder Adam | 8 | 24 |
| Three sparse presence profiles, separately online and offline | 6 | 18 |
| Six scratch presence profile and scope variants | 6 | 18 |
| Frozen MiniLM heads and matched projected random representation control | 2 | 6 |
| Total | 56 | 168 |

There are 111 online trajectories and 57 offline trajectories. Online trajectories have 96 stage opportunities with 32 generated prompts per attempted stage. Automatic dual trajectories have 48 logical cycles. A definite rejected head consumes its full opportunity as an explicit skipped FULL stage; it is not replaced. HEAD and FULL remain independently guarded publications. A rejected FULL retains the acknowledged intermediate head publication.

Current procedural Fuzzer defaults are frozen prospectively: learning rate 0.03, transported clamp 0.05, one transformation per generated example, 16 held-out guard examples and a strict training exact-match floor of zero. Consequently, 32 generated prompts normally produce 64 contextual training examples. Sparse online presence has no contextual augmentation. Local SGD 4 applies four internal steps; legacy SGD and local SGD 1 remain distinct settings. Generated prompts, expanded training examples, guard examples, internal optimizer steps, skipped stages and physical RPC attempts have separate counters.

Offline neural trajectories use 96 optimizer steps. Tiny and frozen representation arms use batch 32; native scratch presence retains batch 16 and fixed initialization seed 12102026, with study seeds controlling batch order. Sparse offline fitting instead uses native `lbfgs`, maximum 1000 iterations, tolerance 0.0001, C 1.0 and balanced class weights, with threshold 0.5. Its solver iterations and convergence are retained separately; they are not minibatch equivalents. Identical deterministic sparse fits are disclosed and cannot provide independent stochastic corroboration. A zero coefficient head at probability 0.5 predicts positive under the maintained greater-than-or-equal threshold rule, leaving obvious specificity headroom.

The maximum online opportunity count is 10,656, with 340,992 generated prompts. Without skipped stages, contextual augmentation and sparse training produce at most 654,336 online training examples. Offline neural fitting adds 119,808 presentations, including 27,648 scratch presentations. Native sparse solver work is additional and has no fictitious equivalent presentation count. These totals describe planned exposure, not accepted updates.

## Baselines and assessment isolation

All Tiny before and after measurements use a deterministic prepared 256-token capacity. HEAD uses six classification tensors; LAST BLOCK permits the final block and heads; FULL permits the bounded Tiny encoder and heads. Trainable inventories differ without changing the matched initial weight coordinates. No parameter cap is increased.

Sparse offline baselines use train-only fitted vocabulary and IDF with a zero coefficient head. Scratch baselines use an honest zero-step initialization snapshot rather than falsely labeling initialization as a trained release. Frozen MiniLM and projected random controls share head initialization and order. The random control uses a fixed Gaussian projection of frozen Tiny pooled features into 384 dimensions and the same normalization as the official representation. It is a representation-package comparison, not an isolated causal test of pretraining or model size.

Fresh assistant-provisional contextual and binary annotation-presence sets each contain 320 rows. They are newly authored primary transfer assessments. Exact overlap and source-family limitations are checked and disclosed through the preregistered admission process; exact-text hashes do not establish statistical or mechanism independence. Contextual targets describe asserted disclosure, whereas default procedural training retains template and topic conventions; every cohort therefore requires its own reviewed target-ontology manifest. Existing 502-row annotation development data and 48 contextual fixtures remain secondary. Seven ambiguous fixtures remain descriptive; the 41 eligible cases supply casewise harm checks.

The `render-assessment` operation preserves original text and audience hint while rendering a supplied natural-language hint into model input as `Supplied audience context: ...` followed by `Message: ...`. Gold enums, rationales and labels never enter model input. Raw and rendered bytes have separate hashes. The same rendition reaches every before and after route. Fresh authoring alone does not test long-context quality; 256-token preparation mechanics and natural short-text quality are separate evidence.

Actual token lengths must be reviewed before fitting for every generated training example, transformation, guard and assessment input. Tiny includes its start token; MiniLM uses the pinned tokenizer including special tokens; scratch keeps native 64, 96 and 128 capacities. Training, guard or primary assessment inadmissibility prevents execution. Historical secondary overlength cases retain their fixed denominators as coverage errors and veto qualification. No silent truncation, filtering or after-baseline shortening is permitted.

## Execution and evidence contracts

`prepare` requires committed computation sources, immutable four-service image IDs, input hash references, reviewed fresh assessments and unique localhost ports. `freeze` binds an immutable internal root acceptance receipt to the exact protocol and assessments. This is a research acceptance record; it does not request another human confirmation. No fitting or baseline scoring is performed by `plan`, `render-assessment`, `prepare`, `preflight` or `freeze`.

Source-compatible image attestation, ontology manifests, actual tokenizer-length inventories and a per-route baseline/comparator/decision/endpoint ledger are execution gates. Receipt status alone is insufficient: source and input hashes and the complete matrix must match. Native runtime and generated protobuf contracts must be integrated and checked before any study execution.

Online requests use the actual public journaled requester with optional bounded controls. Ordinary daemon defaults remain unchanged. Pending deterministic request bytes are persisted before RPC, uncertain outcomes resume the same request, and definite rejections consume their opportunity. Stage observers capture the exact acknowledged S1 tensors before FULL begins. Missing checkpoint collection cannot be repaired by measuring a later publication.

Contextual and presence RPCs send an explicit semantic layer selection and assert actual execution, counts and model identity. Successful streamed contextual executions publish reserved `privoke.semantic.*` response metadata from the exact classified snapshot, including clean S0/PU outputs with no finding. Caller metadata cannot supply this identity; clean findings and enforcement actions are unchanged. Offline adapters receive only TRAIN, optional legitimate base artifacts, pinned assets and source revision. Their baseline and final learned-forward evaluations use explicit semantic selection and genuine per-row execution traces after fitting under a blind immutable-baseline contract. Their execution mode is recorded as `offline_learned_forward_v1`, distinct from `network_protobuf_v1`. Assessment scores never return to the fitter.

Supported native final artifacts additionally require learned-forward versus actual runtime-serving parity. Contextual parity compares sensitivity, visibility, the category set and action; transport-only packed bits do not change label equality. Experimental MiniLM and scratch artifacts are explicitly requested by model ID; their isolated catalogs also contain the frozen balanced release solely to satisfy the service's nonexperimental latest-model requirement. The projected random control has no native runtime architecture; it explicitly records unsupported runtime serving and remains direct learned-forward evidence.

Each trajectory owns isolated Compose projects, named Linux state volumes, ports and model catalogs. Catalog mounts disable image copy-up so the prepared baseline alone initializes the fresh volume; initialization refuses an existing catalog with different bytes. The runtime constructs its direct gRPC server without initializing the product detector stack. A mounted-volume hardlink and file/directory fsync probe precedes training. SQLite updater/Fuzzer state is exported after stopping services; the host does not read live Linux SQLite over a Windows bind mount. The supervisor journal is a native host SQLite file, not a host view of the mounted Linux database.

The initial concurrency is two deterministic lanes with separate ports and process ownership locks, contingent on prospectively accepted hardware checks. Only hardware and storage readiness can change concurrency before execution; outcomes cannot change budgets. Each trajectory permits two transport recovery retries with the original pending bytes. Exhausted uncertain transport preserves pending state and requires diagnosis.

## Commands and required configuration

Run from the repository root with the configured evaluation interpreter and generated protobuf import paths:

```text
python -B evaluation/run-accelerated-training-surfaces-study.py plan --study-id privoke-all-surfaces-20261010 --output evaluation/results/accelerated_all_surfaces_20261010/plan.json
python -B evaluation/run-accelerated-training-surfaces-study.py render-assessment --raw AUTHORED_CONTEXT_JSONL --task context --output RENDERED_CONTEXT_JSONL
python -B evaluation/run-accelerated-training-surfaces-study.py prepare --study-id privoke-all-surfaces-20261010 --config REVIEWED_CONFIG_JSON --output FRESH_STUDY_DIRECTORY
python -B evaluation/run-accelerated-training-surfaces-study.py preflight --output STUDY_DIRECTORY
python -B evaluation/run-accelerated-training-surfaces-study.py freeze --output STUDY_DIRECTORY --approval ROOT_ACCEPTANCE_JSON
python -B evaluation/run-accelerated-training-surfaces-study.py execute --output STUDY_DIRECTORY --cell CELL_ID
python -B evaluation/run-accelerated-training-surfaces-study.py execute --output STUDY_DIRECTORY --cell all
python -B evaluation/run-accelerated-training-surfaces-study.py audit --output STUDY_DIRECTORY
python -B evaluation/run-accelerated-training-surfaces-study.py report --output STUDY_DIRECTORY
```

Uppercase paths and `CELL_ID` are explicit placeholders. The config contains `images` for model streaming, updater, runtime and Fuzzer; `image_attestation`; four `ports` named model, updater, runtime and fuzzer; and `inputs`. Input references contain `path` and `sha256`. Inputs include model base artifacts, offline TRAIN/assets by surface and profile, primary assessments, secondary development/fixtures, a curriculum manifest, assessment review, ontology, length, endpoint-ledger and hardware-preflight commitments. Offline sparse and online fitted sparse cohorts have independent baseline identities.

The complete matrix must be reviewed before freeze. The endpoint ledger specifies every comparator and qualification rule; the report includes final metric differences, differences in changes, paired source-group/family descriptive uncertainty, disclosure components, exact prediction-change counts, errors, rejection predicates and casewise harms. Final opportunity 96 is the decision endpoint; snapshots 32 and 64 retain tensors without quality scoring. No global improvement claim is available unless every eligible configuration qualifies, and qualification never authorizes promotion.

## Validation and current limits

Focused synthetic tests cover the complete matrix, native budget exceptions, strict input and execution gates, exact dual stage ordering, rejected-head skips, partial publications, immutable snapshots, pending transport recovery and legacy default behavior. Host mechanics checks are not evidence of pinned Linux Torch, MiniLM dependencies, native filesystem durability or network contract integration. Those checks remain required before fitting. The earlier 519-second head benchmark is only a rough reference: the new defaults, encoder backpropagation, endpoints and solver work differ, so it is not a runtime prediction for this matrix.

Offline fits run in the immutable `offline_worker_image`, never the host supervisor. Prepare also records `offline_worker_attestation`, binding source files, pinned Linux dependencies and passed adapter tests. Fit containers mount TRAIN, assets and the initial baseline only, with networking disabled. Separate score containers receive assessment rows after the fit. Root acceptance binds exact protocol and labels; the sequence is prepare, preflight review, freeze, execute, audit, report. Primary presence-client regeneration and host contract tests have passed; pinned Linux adapter and runtime integration remain pending.

Qualification follows the retained prospective rule: contextual gains of at least 16/160 non-S0 joint matches and 12/120 serious joint matches occur together in at least two seeds. Every seed respects union-recall loss limits of 3/160 and 2/120, S0 union-specificity loss of at most 3/160, zero errors, no newly incorrect action and no serious underaction worsening. Secondary union recall may decline by at most two percentage points; eligible fixture action harms veto. Presence requires at least eight extra true negatives out of 160 in two seeds, with all seeds retaining fresh recall of at least 144/160 without decline; historical annotation recall stays at least 90% without decline and specificity does not decline. Component accuracies remain descriptive. Deterministic sparse solver repetitions do not constitute independent seed corroboration. Historical fixtures use explicitly frozen text-only replay uniformly before and after; stored visibility hints are not model input, and their action targets are transfer targets.

The current source tests establish orchestration behavior; they do not establish Linux adapter, mounted-filesystem, tokenizer or network execution success. The dedicated worker recipe and its dependency installation are described below; actual MiniLM mechanics remain an acceptance gate.

The worker builds from an explicitly supplied immutable Linux x86_64 Python3.11 parent using `evaluation/requirements-accelerated-training-surfaces.txt`. The dedicated closure retains the maintained hashed Torch2.10.0 CPU wheel and sparse solver pins while selecting MiniLM-compatible NumPy2.2.6; it does not include the contradictory NumPy1.26.4 requirements. Direct pins are not a transitive hash lock. Freeze requires recipe and requirements hashes, the effective pip-freeze commitment, passed pip check and Linux adapter tests, and the final immutable worker image ID. No dependency installation occurred during source authoring.

The worker includes the evaluation environment helper and updater requester modules and generates its protobuf clients from the committed schemas using pinned grpcio-tools. Build `evaluation/Dockerfile.accelerated-training-surfaces-worker` with `--target worker` for fitting or `--target runtime` for isolated semantic serving. The runtime derives from the same named worker stage, retaining its numerical and pretrained inference dependencies without requiring a local worker image to resolve through a registry. It supplies the workspace paths, unprivileged user and state directory required by the isolated Compose contract. Production runtime recipes remain unchanged. Actual image builds and import, tokenizer, transport and parity checks are required; recipe contents alone do not establish their success.

Sparse offline fits use the full3832-row native binary TRAIN cohort. Scratch uses the shared3684-row cohort admitted at the strictest native64-token capacity; per-profile input references bind that cohort explicitly. These are different training cohorts, and comparisons must disclose this difference. Fresh annotation-transfer rates remain descriptive; the contextual secondary recall veto applies specifically to the reused502-row historical annotation endpoint. Qualification groups include architecture/surface and require exactly one42/43/44 seed set. Deterministic sparse solver repetitions use a separate all-run rule, without stochastic corroboration; the global eligible-configuration decision aggregates configuration decisions rather than individual seeds.

For stochastic configurations, gain eligibility requires at least two seeds with sufficient gain headroom. Qualification requires the same two or more seeds to pass both gain thresholds while all three clear the explicit vetoes. A third seed without gain headroom does not veto qualification; its per-seed headroom remains descriptive. Deterministic sparse repetitions retain their separate all-run criterion.
