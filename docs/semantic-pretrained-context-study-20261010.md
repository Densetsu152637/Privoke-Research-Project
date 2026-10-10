# Frozen pretrained contextual head study

This prospective engineering study compares fresh contextual classification heads on a frozen MiniLM representation package with fresh heads on the existing frozen balanced random encoder. Earlier semantic-only curriculum studies produced no qualifying candidate; the category diagnostic motivated testing a representation change. This experiment has not fitted heads or produced assessment predictions. It does not promote a model.

The comparison changes pretraining, tokenizer, dimension, pooling and feature scale together. It cannot isolate a causal effect of language pretraining. Both arms receive the same authored TRAIN rows, paired minibatch orders, head initialization rule, objective, optimizer and step budget.

## Targets and authored scenarios

The versioned experimental convention is `asserted_personal_disclosure_v1`. Categories label supported actual personal disclosure facts within each synthetic scenario. Pure topics and fully invented passages have empty category sets. The primary category selects a sampling stratum; the complete target can contain additional categories. CHILD disclosures about another child include THIRD_PARTY. Actual sexual relationships and history involving other adults include THIRD_PARTY where supported. Third-party financial disclosures include FINANCIAL and THIRD_PARTY.

This convention differs from the historical 48-case fixture's topic-tag categories. That fixture can provide separate sensitivity/action guards; its category exact-match scores are not comparable truth for the new convention. All new targets are `assistant_provisional`. Independent assistant critique does not replace blinded human annotation or establish validated contextual accuracy.

The fixed resource is [contextual-head-study-20261010.json](../evaluation/datasets/contextual-head-study-20261010.json). It contains 60 offline-authored families across ten sampling strata. Each stratum contributes four TRAIN families, one VALIDATION family and one ASSESSMENT family. Every family renders 16 rows, yielding 640/160/160 rows. A complete family stays in one split. Split-specific audience and framing templates and entity-value inventories are checked before fitting.

Slots 0–5 assert an actual serious personal fact at each of P0/P1/P2/P3/P4/PU. Slots 6–11 place the identical fact in an explicitly invented story at the same message visibility. Slot 12 combines an imaginary surrounding passage with a separately actual personal fact. Slot 13 supplies a hypothetical discussion with an actual personal premise in an unshared note. Slots 14–15 assert a mild ordinary preference at PU and P1. Visibility describes the current message's audience, including when its content is fiction.

Each assessment has 60 S0, 20 S1, 24 S2 and 56 S3 rows. Visibility counts are 20/30/20/20/30/40 in P0/P1/P2/P3/P4/PU order. After the prefit completeness correction, its category sets comprise 56 single-category, 24 double-category and 80 empty-category rows. Category support is eight each for HEALTH, POLITICS, RELIGION, CRIMINAL, SEXUAL, CHILD, LOCATION and IDENTITY, 16 for FINANCIAL and 24 for THIRD_PARTY. Sixteen descendants of a family are correlated observations, not sixteen independent situations.

## Eligibility and exclusions

Preparation checks schema, enums, provisional provenance, per-dimension rationales, evidence spans, category completeness metadata, duplicate IDs and normalized text, permanent family splits, distinct frame banks and cross-split entity-value reuse. It rejects overlapping opaque protected ID/group/text keys using the existing exclusion-index schema and union digest, without opening protected final content.

Prior public exclusion coverage is bounded to the rendered original and revised synthetic curricula, their guard/replay rows, the prior 64-row contextual assessment, the byte-pinned 502-row public development endpoint and the separate historical 48-case fixture. The opaque index additionally covers its recorded protected union. This does not establish overlap checks against every historical public corpus. Prepared records retain exact input and normalized-key commitments.

Both actual serving tokenizers must admit every rendered row without truncation. The current corrected preparation observes at most 45 tokens including CLS for the 96-token random model, and 50 tokens including special tokens for the 256-token pretrained model. Preparation uses tokenization only and computes no assessment features. The first preparation is preserved at `evaluation/results/semantic_pretrained_20261010/`, and the category correction at `prepared-v2/`. The current package is `evaluation/results/semantic_pretrained_20261010/prepared-v3/`, which additionally expands sensitivity evidence spans to include decisive fictional or actual-premise framing. No prompt texts, targets or settings changed in that last amendment.

The pinned MiniLM revision, ONNX/tokenizer hashes, graph contract, CPU provider and dependency versions belong to the [experimental runtime contract](detectors/semantic-classifiers.md). The study uses the dedicated ignored asset virtual environment. Its NumPy 2.2.6 requirement conflicts with the ordinary evaluation environment's NumPy constraint, so the environments remain separate.

## Frozen fitting procedure

The fitter accepts a freeze only after the root supplies an independent acceptance receipt for all 60 concrete families, protocol and eligibility hashes. Freeze also requires committed source contents and documentation, records the exact working-byte source inventory, and checks that resource bytes equal the committed Git blob. This accommodates Windows CRLF source checkouts without weakening the resource byte pin. It records the source revision, file hashes, review receipt and fixed settings. Preparation never starts fitting automatically.

Random features are exactly `TinyTransformerModel.encode` on detector-normalized text, with no additional normalization. Pretrained features use official masked mean pooling and L2 normalization on detector-normalized text. Fresh heads use `PCG64(seed)` with C-order Normal(0, 0.02) weights and zero biases, drawing sensitivity, visibility and category weights in that order. Existing head weights never initialize a fit. The same distribution rule applies to different 32- and 384-dimensional feature spaces.

Seeds 42, 43 and 44 each supply one paired order sequence. Every arm runs 100 epochs of 20 minibatches of 32, exactly 2,000 steps. The loss is mean sensitivity cross-entropy plus mean visibility cross-entropy plus multilabel BCE averaged over all rows and ten categories. NumPy computes optimizer state in float64; exports are float32. The fixed Adam learning rate is 0.01, coupled weight decay 0.0001, betas 0.9/0.999 and epsilon 1e-8. Data gradients are globally norm-clipped at 1 before coupled L2 is added; bias-corrected Adam then updates all six head tensors, including bias decay. This exact order is covered by an independent scalar oracle and finite-difference loss checks.

Checkpoints at epochs 25/50/75/100 are ranked by VALIDATION exact sensitivity+visibility+category-set joint count on non-S0 rows, then overall joint count, then earlier epoch. Selection uses exported float32 heads. All six selection receipts and selected artifact hashes must be committed to a local selection manifest before assessment rows are loaded by the scorer. The fitter does not load assessment rows or compute their features. Assessment is scored once for each selected arm/seed, and failed attempts remain recorded.

## Runtime and operational evidence

Every actual evaluation request specifies its exact model ID and `layers=[DETECTION_LAYER_SEMANTIC]`. Responses must contain exactly one successful semantic execution, no errors and no semantic presence gate. Model-streaming snapshots bind identity before and after every request, including clean empty results. Each returned finding must match the selected artifact identity. The pretrained response additionally binds the identity actually used, including backbone and tokenizer hashes, even when no finding is returned. The legacy random arm uses its before/after snapshots and findings under an isolated catalog without concurrent publication.

Expected parameter fingerprints use float32 wire values, matching protobuf unary/streamed tensors and reconstructed runtime snapshots. The original balanced artifact's higher-precision JSON decimals are converted for this wire fingerprint only; its exact artifact checksum and version remain separate unchanged identity fields. A regression constructs and serializes protobuf tensors from the original artifact to exercise this precision boundary.

Direct offline-versus-reconstructed serialized probabilities must agree within 1e-5 using the same encoder. RPC labels and actions must match the actual semantic wrapper, including its rounded/clipped confidence and existing policy. RPC category-probability metadata is rounded to four decimals and is checked within 0.00005001. Artificial confidence of one is never substituted.

The tool does not start services or install artifacts. The integration owner supplies an isolated serving catalog and a server manifest with source revision, runtime/model targets, runtime PID, named CPU, CPU device, one encoder thread and disabled automatic/concurrent training. On Windows the controller checks that the PID owns the runtime listener. Every selected candidate must already be served at its exact frozen identity.

Operational checks send 200 fixed short TRAIN inputs through actual loopback gRPC after one warmup. They exclude snapshot requests from prompt latency, retain individual durations and measure the runtime process's RSS/peak RSS. The operational gate requires warm p95 at most 500 ms and peak RSS at most 1 GiB on the named CPU. Separate local cold model construction is reported explicitly; it does not measure server startup or cold network latency. Synthetic wrapper fixtures and direct-handler tests do not count as operational RPC evidence.

## Engineering qualification and limits

The same at least two of three paired seeds must gain at least ten percentage points in both non-S0 joint accuracy (at least 10 of 100 cases) and S2/S3 joint accuracy (at least eight of 80 cases). Every seed pair must lose at most two percentage points of non-S0 union detection recall, serious union detection recall and S0 union specificity: this permits respectively two, one and one fewer correct cases. Union detection means non-S0 sensitivity or a nonempty category set; sensitivity-only recall is reported separately.

For every serious case, the candidate must not reduce `min(actual action rank, required action rank)` against its paired random control. ALLOW/WARN/BLOCK ranks are 0/1/2. Reports retain all serious harms and a separate P2/P3/P4 harm list, including empty lists. The veto applies equally to public and unknown-visibility serious cases. Category TP/FP/FN, cardinality, denominators, checkpoint choices, all runs and operational failures remain visible. Errors, skips, identity violations and label/action parity mismatches prevent qualification. No qualification automatically promotes a candidate.

The resource contains unusually explicit actual, invented and private status cues. Its mild rows consistently say “ordinary non-identifying preference.” Split-specific synonyms do not remove this shared easy lexical envelope. A successful result would establish learning on this bounded authored family-transfer task, not naturalistic conversational or human generalization. Subsequent label or protocol changes after fitting require a newly scoped study, preserving this run's outcomes.

The original deployed balanced model, the reused 502-row development endpoint and the historical 48-case fixture remain separate secondary regression measurements. They are not a fresh TEST set and do not substitute for the prospective assessment. The `secondary` phase measures the deployed baseline once and each selected arm/seed separately, preserving development presence metrics and fixture sensitivity/action guards. Historical fixture category exact-match is excluded. Longer public-development inputs can exceed MiniLM's 256-token contract even though the short prospective rows pass; such runtime errors and coverage remain visible and prevent a passing secondary guard. No input is skipped or silently truncated to hide that difference. Protected final data remain untouched.

## Commands and current status

The maintained entry point is `evaluation/run-pretrained-context-study.py`; its phases are `prepare`, `freeze`, `fit`, `evaluate`, `operational`, `secondary` and `report`. Run with the dedicated interpreter, `PRIVOKE_MODEL_DEVICE=cpu`, and TEMP/TMP set to `evaluation/results/semantic_improvement_20261010_assets/tmp`. Preparation takes a fresh output directory. The default currently selects the corrected `prepared-v3` directory, which already exists; use its frozen receipts for later phases rather than rerunning preparation over it.

```powershell
& evaluation/results/semantic_improvement_20261010_assets/.venv/Scripts/python.exe evaluation/run-component-tests.py evaluator -p 'test_pretrained_context*.py'
& evaluation/results/semantic_improvement_20261010_assets/.venv/Scripts/python.exe evaluation/run-pretrained-context-study.py --help
```

For a new preparation, pass `--output` before the phase name. `freeze --review-receipt PATH` is a distinct operation requiring the root's concrete accepted receipt. `fit` remains unauthorized until root release. `evaluate --arm ARM --seed SEED --server-manifest PATH`, `secondary` and `operational` require separately authorized services and already installed selected artifacts. Secondary accepts `--arm baseline` or a selected arm/seed. Operational additionally requires `--runtime-pid PID --cpu-name NAME`. `report` refuses incomplete primary endpoints and reports an unpassed operational gate when measurements are missing; it also exposes secondary completion separately.

Preparation and focused synthetic mechanics checks have run. Fitting, actual network runtime scoring, secondary regression measurements and operational qualification have not run. Review and source freezing precede those measurements.
