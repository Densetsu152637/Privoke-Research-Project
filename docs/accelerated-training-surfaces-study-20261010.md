# Accelerated training across model surfaces

This study measures before and fixed-final quality after accelerated training across the maintained model and training interfaces. It uses separate trajectories for different objectives and architectures. It does not promote a model or attribute Tiny training results to a conversational prompt revision.

The active goal objective is: “Now that these things have been refactored, run accelerated fuzzer training rounds on all models and then test them to see how they have improved. This should cover all training surfaces.” This records the active goal, rather than claiming a verified verbatim user message.

Research record `RQ-FUZZER-ALL-SURFACES-20261010` asks which supported training configurations improve their matched fixed-final endpoints under the frozen gain and harm rules. It separates execution coverage, descriptive metric changes and qualification; none alone establishes deployment readiness.

## Results

Both maintained raw audit and report commands passed, producing byte-identical aggregate SHA-256 `ec530e92d01f5f1f6747549c84a7315db521cf8fdcb99be794ea311f0abe9b63`. Independent count reconciliation passed for all 168 trajectories, 56 configuration decisions and 600 primary/secondary endpoint pairs. The [public evidence package](evidence/all-surfaces-20261010/README.md) binds eight accepted raw inputs and provides reproducible aggregate projections.

All 168 trajectories completed. **None of the 56 configurations qualified** under the frozen gain and harm rules. Fifty configurations had sufficient gain headroom; all six scratch configurations were ineligible because their initial specificity left fewer than eight additional correct negatives available. No individual realization passed its complete qualification rule. Online training published 3,758 candidates, rejected 6,715 and consumed 183 skipped opportunities after rejected heads. Rejected attempts still consumed training work.

| Training surface | Configurations | Gain-eligible | Qualified |
| --- | ---: | ---: | ---: |
| Online Tiny: scopes, objectives, optimizers and curriculum | 34 | 34 | 0 |
| Offline Tiny HEAD/FULL | 8 | 8 | 0 |
| Online sparse presence | 3 | 3 | 0 |
| Offline sparse presence | 3 | 3 | 0 |
| Offline scratch presence HEAD/FULL | 6 | 0 | 0 |
| Frozen MiniLM heads | 1 | 1 | 0 |
| Projected random-representation control | 1 | 1 | 0 |
| Total | 56 | 50 | 0 |

All 132 contextual baselines had zero joint sensitivity/visibility/category-set matches on the 160 non-S0 disclosure rows, including zero on the 120 serious rows. At the fixed final endpoint, 131 trajectories still had zero; offline quality FULL seed 43 reached one match in each subgroup. Thus overall joint gains predominantly came from S0 controls, not disclosure exactness. For example, MiniLM reached 78–79 overall joint matches out of 320, all on S0 rows, while adding 57–67 incorrect actions and 38–73 serious underaction worsenings per realization. These overlapping harm counts use provisional targets and are not counts of independent harms across seeds. Every default procedural main-arm LAST/FULL attempt was rejected (2,304 total); their unchanged endpoints do not establish the quality of 96 accepted encoder updates.

Offline sparse presence gained 68, 107 and 110 correct negatives out of 160 for efficient, balanced and quality respectively, but recall fell from 160/160 to 115/160, 84/160 and 83/160. Each profile's three solver runs produced identical final parameter fingerprints; these are deterministic repetitions. Online efficient and quality presence endpoints were unchanged, while balanced lost two correct negatives without recall gain. Scratch FULL training increased recall from zero to 118–140 correct positives out of 160 across profiles/seeds, while specificity fell to 16–42 correct negatives out of 160; these changes are descriptive tradeoffs, not qualified improvements.

There were zero primary, annotation-transfer or fixture errors. The reused historical annotation endpoint retained **714 overlength error observations across 18 unique case IDs**, repeated across models, seeds and before/after endpoints: 252 Tiny, six projected-control, twelve MiniLM and 216/132/96 scratch efficient/balanced/quality observations. Tiny and projected controls each had one overlength case per endpoint, MiniLM two, and scratch 18/11/8 at native 64/96/128 capacities. These remain fixed-denominator errors and qualification vetoes. Some legacy offline messages say “TRAIN” even when raised by a secondary scoring input; they do not indicate failed training admission.

The [aggregate evidence](evidence/all-surfaces-20261010/README.md) preserves every configuration, component, harm count, error bound and descriptive paired interval. The actual ledger declares no cross-cell reference IDs, so `controlled_contrasts` is empty. Cross-configuration package summaries are descriptive. This study does not establish a beneficial conversational-prompt effect, a causal representation/variance effect, convergence at larger doses, independent human-label validity, long-context accuracy or deployment readiness. No model was promoted and protected final data were not scored.

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

There are 111 online trajectories and 57 offline trajectories. Online trajectories have 96 stage opportunities with 32 prompt allocations per attempted stage. Automatic dual trajectories have 48 logical cycles. A definite rejected head consumes its full opportunity as an explicit skipped FULL stage; it is not replaced. HEAD and FULL remain independently guarded publications. A rejected FULL retains the acknowledged intermediate head publication.

Current procedural contextual Fuzzer defaults are frozen prospectively: learning rate 0.03, transported clamp 0.05, one transformation per generated example, 16 held-out guard examples and a strict training exact-match floor of zero. Consequently, 32 generated prompts normally produce 64 contextual training examples. Dataset-sampled sparse online presence has no contextual augmentation. Local SGD 4 applies four internal steps; legacy SGD and local SGD 1 remain distinct settings. Prompt allocations, expanded training examples, guard examples, internal optimizer steps, skipped stages and physical RPC attempts have separate counters. The offset seed plans share substantial procedural-pool membership across realizations; the two-of-three qualification rule is an engineering rule, and scenario bootstrap intervals do not estimate independent seed uncertainty.

Offline neural trajectories use 96 optimizer steps. Tiny and frozen representation arms use batch 32; native scratch presence retains batch 16 and fixed initialization seed 12102026, with study seeds controlling batch order. Sparse offline fitting instead uses native `lbfgs`, maximum 1000 iterations, tolerance 0.0001, C 1.0 and balanced class weights, with threshold 0.5. Its solver iterations and convergence are retained separately; they are not minibatch equivalents. Identical deterministic sparse fits are disclosed and cannot provide independent stochastic corroboration. A zero coefficient head at probability 0.5 predicts positive under the maintained greater-than-or-equal threshold rule, leaving obvious specificity headroom.

The maximum online opportunity count is 10,656, with 340,992 prompt allocations. Without skipped stages, contextual augmentation and sparse training produce at most 654,336 online training examples. Offline neural fitting adds 119,808 presentations, including 27,648 scratch presentations. Native sparse solver work is additional and has no fictitious equivalent presentation count. These totals describe planned exposure, not accepted updates.

All 168 trajectories completed fitting and scoring. Actual online exposure comprised 10,656 opportunities, 10,473 attempted stages, 183 consumed skips, 335,136 prompt allocations, 636,112 TRAIN payload-row allocations, 167,568 guard examples and 13,065 internal optimizer steps. There were 10,473 physical RPC attempts. Attempts and optimizer work include rejected candidates; neither count establishes publication or quality improvement. TRAIN row allocations do not multiply repeated internal SGD steps; row counts, optimizer steps and accepted publication exposure are separate doses. Equal opportunity budgets therefore do not mean equal accepted exposure or compute. The generic `generated_prompts` counter records allocations: procedural contextual generation, finite curriculum selections and dataset-sampled presence examples must remain distinct, and the counter does not establish novelty.

## Baselines and assessment isolation

All Tiny before and after measurements use a deterministic prepared 256-token capacity. This expands the experimental input length while retaining matched baseline and endpoint capacity; it does not change shipped defaults or establish long-context accuracy. HEAD uses six classification tensors; LAST BLOCK permits the final block and heads; FULL permits the bounded Tiny encoder and heads. Trainable inventories differ without changing the matched initial weight coordinates. No parameter cap is increased.

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

Each trajectory owns isolated Compose projects, named Linux state volumes, ports and model catalogs. Baseline and serving tensor checks compare the complete tensor inventory, exact shapes and canonical protobuf float32 coordinates, preserving the original JSON artifacts rather than comparing their decimal Python-float representation to the wire. Catalog mounts disable image copy-up so the prepared baseline alone initializes the fresh volume; initialization refuses an existing catalog with different bytes. The runtime constructs its direct gRPC server without initializing the product detector stack. A mounted-volume hardlink and file/directory fsync probe precedes training. SQLite updater/Fuzzer state is exported after stopping services; the host does not read live Linux SQLite over a Windows bind mount. The supervisor journal is a native host SQLite file, not a host view of the mounted Linux database.

The initial concurrency is two deterministic lanes with separate ports and process ownership locks, contingent on prospectively accepted hardware checks. Only hardware and storage readiness can change concurrency before execution; outcomes cannot change budgets. Each trajectory permits two transport recovery retries with the original pending bytes. Exhausted uncertain transport preserves pending state and requires diagnosis.

Independent candidate reconstruction applies the publisher's exact arithmetic: round the sum of float32 base and delta to eight decimal places, then convert the durable value to float32 for the runtime commitment and serving comparison. Omitting the decimal rounding produces a different candidate commitment. The audit checks every transported candidate, including rejected updates, and requires accepted publications to match its complete reconstructed tensor inventory. Archived contextual traces bind the complete reserved server identity plus any finding identities; clean predictions need no fabricated finding. Saved actions must match the trace, and protobuf-omitted category lists mean the empty set in qualification calculations.

The request clamp remains exactly 0.05. Legacy HEAD/LAST BLOCK and sparse interfaces transport its float32-rounded boundary; FULL-capable artifacts retain the stricter inward double-request boundary, including their HEAD stages. The auditor selects the stricter rule when either the archived base or response declares FULL capability and rejects values above the applicable transported limit.

An `audit-source-amendment.json` sidecar permits a narrowly reviewed auditor correction without changing a frozen protocol or rerunning completed fits. It binds `status: accepted`, `scope: audit_only`, the original `protocol_sha256` and `frozen_source_revision`, plus the current `source_revision` and complete `source_files` inventory. Only the candidate-audit function, source-verification functions and focused study tests may differ. AST comparisons preserve every other computation, including fitting, qualification, matrix and budgets; source additions or changes elsewhere are refused. Root records the diagnosis, checks, recovery decision and amended auditor revision separately. Original training/runtime images and their source binding remain frozen. This is internal evidence acceptance within the authorized study, not model promotion.

A subsequent `worker-environment-amendment.json` may chain to that unchanged audit receipt to repair the missing models import path. It binds the original protocol, prior auditor revision/inventory and receipt hash, current supervisor revision/inventory, original worker image, and exact old/new `PYTHONPATH`. The only executable change permitted is the worker invocation's explicit `/study/models` path; the recipe also adds `/study/models` and `/workspace/models` for future builds. AST comparison removes only that exact argument pair before comparing all other computation; recipe comparison removes only those two exact environment additions. The study continues using its original images, fitting adapter, inputs, seeds and budgets. The two initial scratch attempts failed before trainer creation or optimizer steps; completed trajectories are retained. This repairs the execution environment without resetting the supervisor recovery allowance.

## Commands and required configuration

Projected random-control snapshots retain a hash-bound reference to their prepared fit baseline. Separate scoring workers mount that same baseline read-only at its recorded container path, after checking the snapshot hash, fit request, cell identity, path shape and baseline hash. Fits receive no additional mounts or assessment inputs. A `score-dependency-amendment.json` may chain to the unchanged environment receipt; it binds the original protocol/image and both source inventories. Its source check admits only this exact scoring helper and invocation, then compares every other computation against the prior source. This repairs missing score-worker dependency mounts while retaining completed fits, original requests and failure logs, without resetting the recovery allowance.

Both first bulk audits checked all 168 cell archives, then failed during aggregate assembly because the reporter treated the ledger's dictionary endpoint descriptors as cell-ID strings. A `report-ledger-amendment.json` chains to the unchanged scoring receipt and admits only the exact comparator-resolution helper and two report-loop statements. It validates fixed-final descriptor kinds and distinguishes own-baseline endpoints from explicitly declared cross-cell references. All other report arithmetic, cell auditing, fitting and qualification remain protected by AST comparison. The actual frozen ledger contains own-baseline-to-final descriptors for all trajectories and no cross-cell reference IDs: its `controlled_contrasts` output is therefore empty. Cross-configuration summaries remain descriptive; no post-fit references are inserted into the frozen ledger.

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

The complete matrix must be reviewed before freeze. The endpoint ledger specifies every comparator and qualification rule; the report includes paired source-group/family descriptive uncertainty, disclosure components, exact prediction-change counts, errors, rejection predicates and casewise harms. Explicit cross-cell references, when declared, additionally produce final metric differences and differences in changes; none were declared in this execution's ledger. Final opportunity 96 is the decision endpoint; snapshots 32 and 64 retain tensors without quality scoring. No global improvement claim is available unless every eligible configuration qualifies, and qualification never authorizes promotion.

## Validation and current limits

The report-ledger schema repair passed 49 focused host tests and five active hosted CI jobs at `ad9241a86ba39e4d594b17eda67137807b7f632f` ([run 38075810690](https://github.com/Densetsu152637/Privoke-Research-Project/actions/runs/38075810690)); the product job was skipped. Both final maintained commands then recomputed all raw cell audits successfully and agreed byte for byte. The independent checker separately reconciled all 600 endpoint pairs and the frozen decisions. These host/report checks are separate from the earlier Linux worker and network validation below.

Focused synthetic tests cover the complete matrix, native budget exceptions, strict input and execution gates, exact dual stage ordering, rejected-head skips, partial publications, immutable snapshots, pending transport recovery and legacy default behavior. The final scoring repair passed 61 focused tests in the original pinned Linux image with the accepted current supervisor and precision auditor mounted; a four-input synthetic probe verified the dependency mount and actual semantic-only execution without retraining. Five active hosted CI jobs passed at `236328d04a1673902375d91b0624265d2aa36f05`, including semantic-only HEAD/FULL integration; the product job was skipped. Host mechanics alone would not establish Linux dependencies, filesystem durability or network integration. The earlier 519-second head benchmark remains a rough historical reference, not a runtime prediction for this matrix.

Offline fits ran in the immutable `offline_worker_image`, never the host supervisor. Prepare records `offline_worker_attestation`, binding source files, pinned Linux dependencies and passed adapter tests. Fit containers mounted TRAIN, assets and the initial baseline only, with networking disabled. Separate score containers received assessment rows after the fit. Root acceptance binds exact protocol and labels; the sequence is prepare, preflight review, freeze, execute, audit and report. Execution covered 111 online network trajectories, 54 offline fits with native runtime parity and three direct-only projected controls. Each offline parity comparison covered 320 primary labels and contextual actions where applicable; additional network secondary endpoints were collected without a direct offline parity comparison. The controls have no native serving architecture. This is 165 native-serving-supported trajectories, not 165 separate offline parity files.

Qualification follows the retained prospective rule: contextual gains of at least 16/160 non-S0 joint matches and 12/120 serious joint matches occur together in at least two seeds. Every seed respects union-recall loss limits of 3/160 and 2/120, S0 union-specificity loss of at most 3/160, zero errors, no newly incorrect action and no serious underaction worsening. Secondary union recall may decline by at most two percentage points; eligible fixture action harms veto. Presence requires at least eight extra true negatives out of 160 in two seeds, with all seeds retaining fresh recall of at least 144/160 without decline; historical annotation recall stays at least 90% without decline and specificity does not decline. Component accuracies remain descriptive. Deterministic sparse solver repetitions do not constitute independent seed corroboration. Historical fixtures use explicitly frozen text-only replay uniformly before and after; stored visibility hints are not model input, and their action targets are transfer targets.

Source tests alone do not establish mounted-filesystem, tokenizer or network execution success. This execution also retained pinned Linux dependency checks, native state-filesystem probes, tokenizer inventories, actual MiniLM fits and native parity evidence. Raw archive audit and independent numerical reconciliation remain distinct from those mechanics checks.

The worker builds from an explicitly supplied immutable Linux x86_64 Python3.11 parent using `evaluation/requirements-accelerated-training-surfaces.txt`. The dedicated closure retains the maintained hashed Torch2.10.0 CPU wheel and sparse solver pins while selecting MiniLM-compatible NumPy2.2.6; it does not include the contradictory NumPy1.26.4 requirements. Direct pins are not a transitive hash lock. Freeze requires recipe and requirements hashes, the effective pip-freeze commitment, passed pip check and Linux adapter tests, and the final immutable worker image ID. No dependency installation occurred during source authoring.

The worker includes the evaluation environment helper and updater requester modules and generates its protobuf clients from the committed schemas using pinned grpcio-tools. Its source revision is stamped after dependency installation and source copying so a source-only rebuild can reuse the dependency layer. Build `evaluation/Dockerfile.accelerated-training-surfaces-worker` with `--target worker` for fitting or `--target runtime` for isolated semantic serving. The runtime derives from the same named worker stage, retaining its numerical and pretrained inference dependencies without requiring a local worker image to resolve through a registry. It supplies the workspace paths, unprivileged user and state directory required by the isolated Compose contract. Production runtime recipes remain unchanged. Actual image builds and import, tokenizer, transport and parity checks are required; recipe contents alone do not establish their success.

Sparse offline fits use the full3832-row native binary TRAIN cohort. Scratch uses the shared3684-row cohort admitted at the strictest native64-token capacity; per-profile input references bind that cohort explicitly. These are different training cohorts, and comparisons must disclose this difference. Fresh annotation-transfer rates remain descriptive; the contextual secondary recall veto applies specifically to the reused502-row historical annotation endpoint. Qualification groups include architecture/surface and require exactly one42/43/44 seed set. Deterministic sparse solver repetitions use a separate all-run rule, without stochastic corroboration; the global eligible-configuration decision aggregates configuration decisions rather than individual seeds.

For stochastic configurations, gain eligibility requires at least two seeds with sufficient gain headroom. Qualification requires the same two or more seeds to pass both gain thresholds while all three clear the explicit vetoes. A third seed without gain headroom does not veto qualification; its per-seed headroom remains descriptive. Deterministic sparse repetitions retain their separate all-run criterion.

## Every frozen configuration

Counts within brackets follow seeds 42, 43 and 44. N/S are gains in joint matches on 160 non-S0 and 120 serious rows; TN is the gain in correct negatives out of 160. TP shows before → after correct positives out of 160. Eligibility and veto are configuration decisions; all configurations failed qualification. Complete components and descriptive uncertainty remain in the aggregate JSON.

| Configuration (seed suffix omitted) | N/S gain counts | TN gain counts | TP before → after | Eligible | Any veto |
| --- | --- | --- | --- | --- | --- |
| `offline-presence-balanced-heads` | — | [107, 107, 107] | [160, 160, 160] → [84, 84, 84] | Yes | Yes |
| `offline-presence-efficient-heads` | — | [68, 68, 68] | [160, 160, 160] → [115, 115, 115] | Yes | Yes |
| `offline-presence-quality-heads` | — | [110, 110, 110] | [160, 160, 160] → [83, 83, 83] | Yes | Yes |
| `offline-representation-balanced-minilm` | [0, 0, 0] / [0, 0, 0] | — | — | Yes | Yes |
| `offline-representation-balanced-random_control` | [0, 0, 0] / [0, 0, 0] | — | — | Yes | Yes |
| `offline-scratch-balanced-full_encoder` | — | [-126, -121, -141] | [0, 0, 0] → [128, 119, 133] | No | Yes |
| `offline-scratch-balanced-heads` | — | [-83, -36, -3] | [0, 0, 0] → [59, 31, 2] | No | Yes |
| `offline-scratch-efficient-full_encoder` | — | [-142, -141, -141] | [0, 0, 0] → [140, 140, 140] | No | Yes |
| `offline-scratch-efficient-heads` | — | [-12, -1, 0] | [0, 0, 0] → [18, 3, 0] | No | Yes |
| `offline-scratch-quality-full_encoder` | — | [-118, -120, -128] | [0, 0, 0] → [118, 122, 135] | No | Yes |
| `offline-scratch-quality-heads` | — | [-90, -28, -4] | [0, 0, 0] → [76, 22, 0] | No | Yes |
| `offline-tiny-balanced-full_encoder` | [0, 0, 0] / [0, 0, 0] | — | — | Yes | Yes |
| `offline-tiny-balanced-heads` | [0, 0, 0] / [0, 0, 0] | — | — | Yes | Yes |
| `offline-tiny-baseline-full_encoder` | [0, 0, 0] / [0, 0, 0] | — | — | Yes | Yes |
| `offline-tiny-baseline-heads` | [0, 0, 0] / [0, 0, 0] | — | — | Yes | Yes |
| `offline-tiny-efficient-full_encoder` | [0, 0, 0] / [0, 0, 0] | — | — | Yes | Yes |
| `offline-tiny-efficient-heads` | [0, 0, 0] / [0, 0, 0] | — | — | Yes | Yes |
| `offline-tiny-quality-full_encoder` | [0, 1, 0] / [0, 1, 0] | — | — | Yes | Yes |
| `offline-tiny-quality-heads` | [0, 0, 0] / [0, 0, 0] | — | — | Yes | Yes |
| `curriculum-balanced-dual` | [0, 0, 0] / [0, 0, 0] | — | — | Yes | Yes |
| `curriculum-balanced-full_encoder` | [0, 0, 0] / [0, 0, 0] | — | — | Yes | Yes |
| `curriculum-balanced-heads` | [0, 0, 0] / [0, 0, 0] | — | — | Yes | Yes |
| `main-balanced-dual` | [0, 0, 0] / [0, 0, 0] | — | — | Yes | Yes |
| `main-balanced-full_encoder` | [0, 0, 0] / [0, 0, 0] | — | — | Yes | Yes |
| `main-balanced-heads` | [0, 0, 0] / [0, 0, 0] | — | — | Yes | Yes |
| `main-balanced-last_block` | [0, 0, 0] / [0, 0, 0] | — | — | Yes | Yes |
| `main-baseline-dual` | [0, 0, 0] / [0, 0, 0] | — | — | Yes | Yes |
| `main-baseline-full_encoder` | [0, 0, 0] / [0, 0, 0] | — | — | Yes | Yes |
| `main-baseline-heads` | [0, 0, 0] / [0, 0, 0] | — | — | Yes | Yes |
| `main-baseline-last_block` | [0, 0, 0] / [0, 0, 0] | — | — | Yes | Yes |
| `main-efficient-dual` | [0, 0, 0] / [0, 0, 0] | — | — | Yes | Yes |
| `main-efficient-full_encoder` | [0, 0, 0] / [0, 0, 0] | — | — | Yes | Yes |
| `main-efficient-heads` | [0, 0, 0] / [0, 0, 0] | — | — | Yes | Yes |
| `main-efficient-last_block` | [0, 0, 0] / [0, 0, 0] | — | — | Yes | Yes |
| `main-quality-dual` | [0, 0, 0] / [0, 0, 0] | — | — | Yes | Yes |
| `main-quality-full_encoder` | [0, 0, 0] / [0, 0, 0] | — | — | Yes | Yes |
| `main-quality-heads` | [0, 0, 0] / [0, 0, 0] | — | — | Yes | Yes |
| `main-quality-last_block` | [0, 0, 0] / [0, 0, 0] | — | — | Yes | Yes |
| `objective-balanced-full_encoder-o2` | [0, 0, 0] / [0, 0, 0] | — | — | Yes | Yes |
| `objective-balanced-full_encoder-o1` | [0, 0, 0] / [0, 0, 0] | — | — | Yes | Yes |
| `objective-balanced-full_encoder-o0` | [0, 0, 0] / [0, 0, 0] | — | — | Yes | Yes |
| `objective-balanced-heads-o2` | [0, 0, 0] / [0, 0, 0] | — | — | Yes | Yes |
| `objective-balanced-heads-o1` | [0, 0, 0] / [0, 0, 0] | — | — | Yes | Yes |
| `objective-balanced-heads-o0` | [0, 0, 0] / [0, 0, 0] | — | — | Yes | Yes |
| `objective-balanced-last_block-o2` | [0, 0, 0] / [0, 0, 0] | — | — | Yes | Yes |
| `objective-balanced-last_block-o1` | [0, 0, 0] / [0, 0, 0] | — | — | Yes | Yes |
| `objective-balanced-last_block-o0` | [0, 0, 0] / [0, 0, 0] | — | — | Yes | Yes |
| `online-presence-balanced-heads` | — | [-2, -2, -2] | [122, 122, 122] → [122, 122, 122] | Yes | Yes |
| `online-presence-efficient-heads` | — | [0, 0, 0] | [151, 151, 151] → [151, 151, 151] | Yes | No |
| `online-presence-quality-heads` | — | [0, 0, 0] | [103, 103, 103] → [103, 103, 103] | Yes | Yes |
| `optimizer-balanced-full_encoder-p0` | [0, 0, 0] / [0, 0, 0] | — | — | Yes | Yes |
| `optimizer-balanced-full_encoder-p1` | [0, 0, 0] / [0, 0, 0] | — | — | Yes | Yes |
| `optimizer-balanced-heads-p0` | [0, 0, 0] / [0, 0, 0] | — | — | Yes | Yes |
| `optimizer-balanced-heads-p1` | [0, 0, 0] / [0, 0, 0] | — | — | Yes | Yes |
| `optimizer-balanced-last_block-p0` | [0, 0, 0] / [0, 0, 0] | — | — | Yes | Yes |
| `optimizer-balanced-last_block-p1` | [0, 0, 0] / [0, 0, 0] | — | — | Yes | Yes |
