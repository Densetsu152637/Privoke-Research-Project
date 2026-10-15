# Frozen pretrained contextual head study

Fresh heads on a frozen MiniLM representation improved the authored contextual assessment over matched heads on the frozen balanced random encoder, but failed the prespecified action-harm veto. All three candidates improved serious-disclosure joint correctness from 0/80 to 19/80 while worsening the same required-BLOCK case from WARN to ALLOW. Separate historical checks exposed poor clean specificity and another action regression. No candidate was promoted. A later explicit 512-token profile passed bounded execution checks; it does not change the original 256-token study results.

Research ID: `RQ-SEM-PRETRAINED-CONTEXT-20261010`. The exact user request was “Can you improve the LLM layer in which ever way you can find through research and potential gaps you can identify?” Subsequent steering was “Along with this goal continue working on the previous prompt as well” and “you can also increase the token limit”. This record retains the frozen methods, measured outcomes and separate functional extension. The original prospective document remains committed at `1064a9518b497186f6031698f43c47d6ea38a3be` and bound by the unchanged local freeze.

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

The maintained entry point is `evaluation/run-pretrained-context-study.py`; its phases are `prepare`, `freeze`, `fit`, `evaluate`, `operational`, `secondary` and `report`. Recreate a dedicated Python 3.13.2 environment from `extension/client-runtime/requirements-pretrained-context.txt` when needed; the ignored study virtual environment is disposable. Do not combine its NumPy 2.2.6 requirements with ordinary host evaluation requirements. Use `PRIVOKE_MODEL_DEVICE=cpu` and a task-owned TEMP/TMP directory. Preparation takes a fresh output directory. The default selects the corrected `prepared-v3` directory, which already exists; preserve those frozen receipts rather than preparing or fitting over them.

```powershell
& evaluation/results/semantic_improvement_20261010_assets/.venv/Scripts/python.exe evaluation/run-component-tests.py evaluator -p 'test_pretrained_context*.py'
& evaluation/results/semantic_improvement_20261010_assets/.venv/Scripts/python.exe evaluation/run-pretrained-context-study.py --help
```

For a separately authorized new study, pass a fresh `--output` before the phase name. `freeze --review-receipt PATH` requires an accepted concrete receipt. `evaluate --arm ARM --seed SEED --server-manifest PATH`, `secondary` and `operational` require isolated services and already installed selected artifacts. Secondary accepts `--arm baseline` or a selected arm/seed. Operational additionally requires `--runtime-pid PID --cpu-name NAME`. `report` refuses incomplete primary endpoints and reports an unpassed operational gate when measurements are missing. The completed original summary remains immutable; the amended secondary results are a separate record.

All six fits, primary assessments and operational runs completed at source `1064a9518b497186f6031698f43c47d6ea38a3be`. All selected epoch 25 after the fixed 2,000-step budgets. The six-fit phase took 22.2899823 seconds, excluding preparation, service execution and the rest of this research task. Secondary controller revision `8227218ef1846e10c4950fce8646483c59e49e04` repaired only historical null-action scoring while preserving the frozen runtime and primary evidence. The later context-limit implementation is `fd0b507ddddd82ee88fb45e1249711738cc8f0c2`.

## Research decisions and evidence

The research question was whether a frozen pretrained representation package improves contextual disclosure classification over matched fresh heads on the existing random encoder without introducing action harm. Seed variation and longer random-encoder training had already produced negative or mixed outcomes in the [accelerated study](accelerated-fuzzer-study-20261010.md) and [curriculum comparison](fuzzer-curriculum-improvement-process-20261009.md). They motivated a distinct representation hypothesis, not a claim that optimization or labels were ruled out as explanations.

| Question | Evidence and decision | Interpretation |
| --- | --- | --- |
| Is the current representation pretrained? | Tiny uses seeded random encoder tensors and a hashed vocabulary; the selected MiniLM package supplies pretrained 384-dimensional language features. | Actual implementation difference, with tokenizer, pooling, scale and capacity confounds. |
| Must the first intervention tune the encoder? | SetFit trains a pretrained sentence encoder contrastively before its head. This experiment instead freezes the encoder and fits only three contextual heads. | SetFit is a research alternative, not the implemented algorithm. |
| Could category decisions explain failure? | Existing sigmoid heads already support multiple labels; the new primary fixes threshold 0.5. Asymmetric-loss and thresholding literature motivated alternatives but were not treatments. | Assessment-driven threshold or loss changes would require a new experiment. |
| Does the package meet the frozen criterion? | Primary gains and operational limits pass; one repeated serious-case action regression fails the veto. | Measured synthetic improvement, failed qualification. |
| Does the historical secondary support deployment? | Six long-input errors, low successful-only specificity and one repeated credential action regression remain. | No passing regression guard or promotion. |
| Does 512-token execution repair the two length failures? | Nine separate functional RPCs include successful replays of both previous failures and explicit over-limit rejection. | Execution capacity only; no new assessment accuracy or latency qualification. |

The [public evidence](evidence/semantic-pretrained-20261010/README.md) includes privacy-safe projections and a standard-library arithmetic reproducer. Raw primary summary SHA256 is `2d673c73234b9d96a126847f3aa29fb971fae17c110ecf4a77f2d0126a1b7668`; the secondary aggregate SHA256 is `451f72a6cf75710fa8750ddb02b1d65b851dca24879e21f6b7ade20a696c0c65`. [Provenance](evidence/semantic-pretrained-20261010/provenance.json) binds the original receipts and independent audits; the [publication manifest](evidence/semantic-pretrained-20261010/publication-hashes.json) binds the projections without substituting them for raw evidence.

## Primary assessment results

Each arm and seed scored the same 160 rows using only the semantic layer, totaling 960 observations. The 100 non-S0 rows include 20 mild S1 cases; the 80 S2/S3 rows are reported independently so mild cases cannot drive the primary conclusion.

| Seed | Non-S0 joint random → pretrained /100 | S2/S3 joint /80 | S2/S3 union detected /80 | S0 correctly clean /60 |
| --- | --- | --- | --- | --- |
| 42 | 14 → 30 | 0 → 19 | 53 → 75 | 5 → 50 |
| 43 | 15 → 30 | 0 → 19 | 52 → 75 | 7 → 50 |
| 44 | 15 → 30 | 0 → 19 | 45 → 75 | 11 → 50 |

Every pair passes both gain thresholds: 15–16 percentage points for non-S0 joint and 23.75 points for serious joint. Pretrained serious detection recall is 93.75% and S0 specificity is 83.33%; neither is complete contextual agreement, which remains 19/80 for serious disclosures. LOCATION and IDENTITY each have zero recovered category labels out of eight supported labels in every pretrained assessment. Full per-category counts, cardinality results and paired outcomes remain in [primary.json](evidence/semantic-pretrained-20261010/primary.json).

The required-BLOCK case `contextual-head-20261010/child_overnightcare/12` changes from WARN to ALLOW in every pair. This is one synthetic case repeated across three realizations, not three independent scenarios. Its target visibility is PU, so the P2/P3/P4-specific harm list is empty while the all-serious veto fails. `engineering_qualified` is false. No thresholds, labels or checkpoint selections were changed after this result.

All six operational runs pass the frozen 500 ms / 1 GiB limits. Pretrained warm p95 is 21.91–32.16 ms and peak process RSS is 348,991,488–349,110,272 bytes on the Windows i7-13700KF with one encoder thread. Each run uses 200 short TRAIN prompts after one warmup; snapshot requests are excluded from latency. Local cold model construction takes 240.75–260.65 ms, not server startup or cold RPC time. These observations do not establish browser latency or a causal architecture speedup.

## Secondary regressions and scoring amendment

Seven comparisons cover the original balanced artifact and all six selected heads. The amended run issued 3,348 new requests and reused the 502 already-complete random-42 development predictions, representing 3,850 endpoint observations. It retained six runtime errors, all from the pretrained arms: the same 381- and 286-token inputs exceed the original 256-token contract. Each has one positive-labelled and one negative-labelled error; neither error becomes a negative prediction.

| Model | TP | TN | FP | FN | Successful / attempted development rows | Historical action correct /41 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Original balanced | 169 | 60 | 178 | 95 | 502/502 | 27 |
| Random 42 | 189 | 55 | 183 | 75 | 502/502 | 12 |
| Random 43 | 186 | 59 | 179 | 78 | 502/502 | 12 |
| Random 44 | 173 | 71 | 167 | 91 | 502/502 | 12 |
| Pretrained 42, 43 and 44, each | 233 | 14 | 223 | 30 | 500/502 | 28 |

Pretrained development recall 88.59% and specificity 5.91% describe only the 500 successful rows (263 positive, 237 negative), with 99.60% coverage. They are not complete-endpoint success or a passing guard. Historical fixture requests all execute (336/336); seven ambiguous rows per comparison retain null scores, leaving 41 quantitative cases. Aggregate action agreement conceals a repeated regression on `cc-credentials-03`: required BLOCK, original WARN and paired random BLOCK, but pretrained ALLOW in all three seeds. This is a second observed scenario, distinct from the primary child case; it has no omitted visibility hint.

Historical fixture replay is text-only: the controller did not forward four stored `visibility_hint` fields (`cc-visibility_hints-01` through `-04`). In `-03`, text has PU while the stored hint specifies P4. Private grouping uses expected visibility; no visibility accuracy or exact reproduction of the historical hinted request is claimed. Historical category exact-match is excluded because topic-tag labels differ from the new disclosure convention.

The first secondary scorer stopped on a null expected action after random-42 development scoring and a partial fixture pass. The failed receipt remains SHA256 `e3c8aeadaed552f4076200b0739cbcc38d2aa2085b36718ea29d50cfdceee48a`. A separately accepted amendment (`f850346598b6e8433e162bcf4bae754d7637771acf9ce3485eb8f557d3e7dd6f`) repairs only secondary scoring, preserves the successful development predictions and allows null scores for ambiguous rows. It changes no fit, primary assessment, selection or runtime. The independent secondary audit is SHA256 `992838a01f8f5fa5387ea12e649837ed9230ec976f32009c9f7248cbdb3928f5`; arithmetic validity does not convert the negative regression outcome into a pass.

## Separate 512 token functional extension

At the user's request, a later explicit artifact profile permits 512 tokens including special tokens. Builder/offline defaults remain 256 for reproduction; selecting 512 requires a new version/checksum using the same six head tensors. Encoder caches distinguish limits, model/config mismatches fail, and neither profile silently truncates. The pinned upstream model config has 512 positions, while the sentence encoder config defaults to 256 and its model card describes fine-tuning at 128 tokens. Positional capacity is not evidence of long-input quality.

Nine semantic-only RPCs verify seven successes and two expected errors: the legacy profile rejects 257; the 512 profile admits 256/257/512 and rejects 513; both prior 381/286-token errors now execute, and a short TRAIN row agrees across profiles. [context512.json](evidence/semantic-pretrained-20261010/context512.json) retains counts and outcomes without public-development text. Original 256-token errors and scores remain unchanged. This is not a rerun of all 502 rows, a new accuracy result, retraining, promotion or latency qualification at 512.

Two harness failures remain recorded separately from model errors. An unsupported assertion expected an actual input-count substring in a valid 256-limit error; its narrow repair reused two already-returned responses without another RPC. A UTF-8 reader failure occurred before the first 512 RPC and was corrected before the remaining seven requests. The functional aggregate SHA256 is `5f807c27b8fa1954c096cbf3a3aab95ae4bed791f8c7397f346d659ed3048954`. Explicit final cleanup confirms no remaining task listeners; retained launchers and receipts do not imply services are still running.

## Related changes and next research question

The procedural fuzzer still computes bounded online updates for supported Tiny heads; successful publication is not general language-model pretraining or evidence of monotonic improvement. Its earlier negative/tradeoff studies remain unchanged. The CPU bootstrap fix `2e6146d` ensures in-place head updates are visible regardless of accelerator settings; component checks validate mechanics, not accuracy. The conversational prompt change `f826d92` requires all supported categories, including THIRD_PARTY where warranted; eleven mocked compatibility checks do not measure conversational-model accuracy. Neither Tiny nor frozen MiniLM inference consumes that prompt. The 21 guides reorganized at `2d0a708` are discoverable through the [documentation index](README.md); historical hash-pinned compatibility pointers remain.

The next useful question is whether reviewed supervision and category calibration or encoder adaptation improve less formulaic contextual cases without casewise action losses. Representation, category omissions and calibration remain competing explanations. A new study must freeze its own calibration and assessment families before fitting; it cannot repair this study's child/credential cases or tune thresholds on these observed assessment rows and call the result independent. This package changes tokenization, feature scale, pooling and capacity together, while ten assessment families and explicit framing limit generalization. Protected final data remain untouched.

## Primary source ledger

Sources were opened and checked on 10 October 2026. Stable bibliography keys below are retained in [paper/ref.bib](../paper/ref.bib). Documentation without a publication date has no invented year. Model/config links pin revision `1110a243fdf4706b3f48f1d95db1a4f5529b4d41`.

| Key | Source and role |
| --- | --- |
| `tunstall2022setfit` | [Tunstall et al., Efficient Few-Shot Learning Without Prompts, arXiv:2209.11055v1](https://arxiv.org/html/2209.11055v1), 2022; contrastive alternative, not the implemented method. |
| `benbaruch2021asymmetric` | [Ben-Baruch et al., Asymmetric Loss For Multi-Label Classification, arXiv:2009.14119v4](https://arxiv.org/abs/2009.14119v4), 2021 revision; image-domain imbalance evidence, not a privacy result. |
| `lipton2014thresholding` | [Lipton, Elkan and Narayanaswamy, Thresholding Classifiers to Maximize F1 Score, arXiv:1402.1892v2](https://arxiv.org/abs/1402.1892v2), 2014; decision-threshold caution. |
| `sentenceTransformersMiniLML6v2` | [Pinned MiniLM model card](https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2/blob/1110a243fdf4706b3f48f1d95db1a4f5529b4d41/README.md); dimensions, intended use, pooling, training length and Apache-2.0 declaration. |
| `sentenceTransformersMiniLMOnnx` | [Pinned ONNX artifact](https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2/blob/1110a243fdf4706b3f48f1d95db1a4f5529b4d41/onnx/model.onnx); artifact size/hash. |
| `sentenceTransformersEfficiency` | [Sentence Transformers inference documentation](https://www.sbert.net/docs/sentence_transformer/usage/efficiency.html); ONNX token outputs require pooling/normalization. |
| `onnxruntimePythonAPI` | [Microsoft ONNX Runtime Python API](https://onnxruntime.ai/docs/api/python/api_summary.html); local session and graph metadata contract. |
| `huggingfaceTokenizersAPI` | [Hugging Face Tokenizer API](https://huggingface.co/docs/tokenizers/api/tokenizer); tokenizer interface, with actual installed loader verified by implementation checks. |
| `onnxruntimeLicense` | [ONNX Runtime license](https://github.com/microsoft/onnxruntime/blob/main/LICENSE), MIT. |
| `huggingfaceTokenizersLicense` | [Tokenizers license](https://github.com/huggingface/tokenizers/blob/main/LICENSE), Apache-2.0. |
| `huggingfaceSetfitLicense` | [SetFit license](https://github.com/huggingface/setfit/blob/main/LICENSE), Apache-2.0; considered alternative, not a runtime dependency. |
| `sentenceTransformersMiniLMConfig` | [Pinned model config](https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2/blob/1110a243fdf4706b3f48f1d95db1a4f5529b4d41/config.json); 512 positional embeddings, independently matched to retained local bytes. |
| `sentenceTransformersMiniLMSentenceConfig` | [Pinned sentence config](https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2/blob/1110a243fdf4706b3f48f1d95db1a4f5529b4d41/sentence_bert_config.json); default 256-token limit, independently matched to retained local bytes. |
