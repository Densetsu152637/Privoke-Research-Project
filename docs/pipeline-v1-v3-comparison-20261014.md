# Native V1/V3 product cascade comparison (PIPE3)

Status: all six package runs and the independent all-pass evidence review completed. Results describe the reused synthetic product workload; no model promotion is claimed.

This study compares the AU3-selected V3 efficient, balanced and quality packages with the original V1 packages at the same tiers through the native **REGEX → NER → SEMANTIC** product path. This is a full detector-pipeline comparison, not an LLM-only score or a detector ablation. Execution followed V3 efficient/balanced/quality, then V1 efficient/balanced/quality, with one model loaded at a time. Every model received three passes over the same 1,560 cases: 28,080 accuracy RPCs in total. First-pass same-case accuracy is primary; later passes measure repeatability and descriptive cost and do not create new independent examples.

## Fixed workload and execution

The inputs are release-07 AU3 FRESH, previously opened in the [AU3 semantic-only study](audience-v3-training.md). They are therefore a **reused benchmark** here, with assistant-provisional labels, 35 dependent scenario families and 24 audience-expression groups. The release contains 810 contextually sensitive and 750 clean cases, with 260 true cases for each audience P0–P4 and PU. Its manifest SHA256 is `41cfd9e476f3d0a17c2a4997efab2afbb6b044c5fbd55217b0614525a2571fe0`; the pinned FRESH payload SHA256 is `e965c21a0d43babc0984f46eb70785c8d66d878e00e647eefb9565f219b2da0c`. Case IDs, text, truth and allowed action sets are fixed before scoring. Truth and audience labels are not forwarded as hints.

Every request explicitly selects nonempty protobuf layers `[2,3,4]`, sets regex execution order to FIRST (`1`), leaves the visibility/audience hint empty and disables the semantic presence gate. The common native product handler runs regex first and may legitimately skip NER and semantic after a regex BLOCK. The actual `ok`, `skipped` and `error` counts for all three returned layer records appear below; an explicitly requested semantic layer does not mean the classifier executed on a skipped case. Errors count incorrect, including fail-closed BLOCK responses. The V3 package enters the maintained product handler through a narrow inference-only adapter; the earlier V3 semantic-only server cannot serve this full layer list. Product normalization, regex/NER findings, aggregation, action selection and response serialization follow the native path. No forced all-detectors-run comparison is included.

The six packages keep their native tokenization and thresholds. V1 uses deterministic bootstrap Tiny encoders with caps of 64, 96 and 128 tokens including the start token, plus a category threshold of 0.38. V3 uses its own WordPiece tokenizer, 512-token cap and category threshold of 0.5. The length audit identifies three release rows above the V1 efficient cap (maximum 67 Tiny tokens), while all V3 rows fit (maximum 73 WordPieces). Of these three, one received a regex BLOCK before semantic execution; the other two reached V1 efficient semantic with truncation. Their IDs are recorded below. No row is removed or text shortened to force a shared cap. Differences in representations, model capacity, training data/history, native thresholds and token windows prevent a causal architecture ranking from this package comparison.

## Selected package lineage

The V3 packages are the independently pinned AU3 **selected**, not terminal, exports. PH3 selected 12, 7 and 4 head-only epochs for efficient, balanced and quality. EN3 then selected 19, 14 and 4 joint encoder, pooler and head epochs; AU3 selected 11, 6 and 4 more. The selected cumulative encoder and pooler counts are 30, 20 and 8 epochs, and the selected cumulative head counts are 42, 27 and 12. AU3 actually completed 16, 11 and 9 epochs before choosing those checkpoints; the discarded later work is not part of the selected package's ancestry. Upstream linguistic-pretraining epochs and steps are unknown. See the [AU3 training record](audience-v3-training.md) for the retained fit, export and native parity audits.

The V3 ancestry retains each pretrained BERT encoder and pooler. Task heads were zero-initialized before PH3, then trained through the selected PH3, EN3 and AU3 stages above. The upstream pretrained checkpoint identities and architectural sizes differ by tier; upstream linguistic-pretraining counts are unavailable.

| Tier | Pretrained base identity and revision | Transformer blocks / hidden size / attention heads |
| --- | --- | ---: |
| Efficient | `google/bert_uncased_L-4_H-128_A-2` @ `c29bee83fc7f003ac8c5e6e135529da4ecddb7c3` | 4 / 128 / 2 |
| Balanced | `google/bert_uncased_L-2_H-256_A-4` @ `4e937a8675e5afd9a4836735c186ec01695bc3ea` | 2 / 256 / 4 |
| Quality | `google/bert_uncased_L-12_H-256_A-4` @ `2ab9a0f41435a4d23d4cbc11cc3e7c922545f13d` | 12 / 256 / 4 |

| Tier | V3 selected manifest SHA256 | V3 parameters | Selected encoder / pooler epochs | Selected head epochs | AU3 completed / selected epochs |
| --- | --- | ---: | ---: | ---: | ---: |
| Efficient | `1f45a21bd7bd0c931dad215f823008193e7af7359bc68527c1f5dd4e7fbbeffd` | 4,785,044 | 30 / 30 | 42 | 16 / 11 |
| Balanced | `99b36171056bb0398584a0b0556d9d7ff2640d0acac4b124a126327451a80589` | 9,596,180 | 20 / 20 | 27 | 11 / 6 |
| Quality | `bb17d355fe1ad13c7052e922fb6de607d82cdafb1f4440fee1a47f35d42caf39` | 17,493,780 | 8 / 8 | 12 | 9 / 4 |

The original V1 packages use seeded bootstrap encoder weights with **zero optimizer-trained encoder epochs**; their heads received 220, 360 and 520 synthetic bootstrap epochs. This is not linguistic pretraining, and those epochs do not represent the same training dose as AU3 epochs. V1 has no corresponding trained BERT pooler stage.

| Tier | V1 source file SHA256 | V1 parameters | Native token cap | Bootstrap head epochs |
| --- | --- | ---: | ---: | ---: |
| Efficient | `c8992bda8a75f5ee7165a3debabaef1a229c4f661be2f5792de65c0aefcf9a5b` | 19,028 | 64 | 220 |
| Balanced | `dcacb490bf19cf771fe4084e7f3484d83daee040609c496c1aef04f0da779b51` | 36,756 | 96 | 360 |
| Quality | `c3126ae0ae238d3967226b6c616491fb90e9b766a3fbb6e066203cb92f2ed8c8` | 54,292 | 128 | 520 |

## Frozen implementation and host provenance

The [run protocol](../evaluation/results/pipeline_v1_v3_20261014/runs/cpu-01/protocol.json), SHA256 `938f626bec9b5810a34e6e9f33d1d28f0070fbc10ac6a570e568b41c39346ed7`, pins the six package identities, case order, three repeats, regex-first policy, model order, warmups, source and environment. The harness was committed at `663746814bfd3624b780ad32de184301122d49c2`. Its **actual source closure** SHA256 is `bf022fc18b16aebfdbcc75e68ef92e28ffb4f4765015c74fc56e95e1047864fa`: retained working-tree bytes include pre-existing dirty transitive dependencies, so the harness commit alone does not reproduce the full run. The AU3 selected registry SHA256 is `cb0529d59261d9bcc0d8450a0f6739f66ffeabde0fd1ad20bbae1cd0bef67a37`. The effective 297-rule regex inventory SHA256 is `9b4dc9c1598e0e6be59bb8e96e6959f12be8f862155fd9de763e082c3c0d6e1b`.

The [isolated host environment](../evaluation/results/pipeline_v1_v3_20261014/environment/environment-provenance.json) is Python 3.11.9 on CPU with four model threads, PyTorch 2.11.0+cpu, NumPy 1.26.4, spaCy 3.7.5, `en_core_web_sm` 3.7.1, Presidio Analyzer 2.2.363, regex 2026.6.28 and grpcio 1.82.1. Its 28 NER package assets have canonical SHA256 `4141104a7a6be9acbabf1f8e16072d236ab00c10b7eb41e7f54954f8c1eba2b2`. Regex and NER are actual installed detectors, rather than stubs or empty fallbacks. The [final implementation review](../evaluation/results/pipeline_v1_v3_20261014/integration/code-review-03.md) passed 17 focused isolated tests after host protobuf client generation. A subsequent [real preflight review](../evaluation/results/pipeline_v1_v3_20261014/planning/preflight-review-01.json) accepted the six asset pins, 16 retained V3 adapter parity captures, and two native product traces: one regex BLOCK with later layers skipped, and one input reaching all three detectors. Those bounded checks establish readiness and path behavior, not benchmark accuracy.

## First-pass product results and same-case changes

[Independent final review](../evaluation/results/pipeline_v1_v3_20261014/planning/results-review-final-01.json), SHA256 `7739f7f2e6d9ad907775606353e84cad42556c8915820f420f3d5302717790f0`, recomputed the first-pass counts and paired changes from the retained raw protobuf journal. Full joint correctness requires exact sensitivity, audience and category labels **and** an allowed final action on the same case; the packed-exact field agreed with joint throughout. An error would score incorrect. All entries below have denominator 1,560. V3 minus V1 is a paired change in correct cases, not a percentage or an independent-sample test.

| Tier | V1 joint → V3 joint | Paired joint improved / regressed | V1 allowed action → V3 | Paired action improved / regressed | Sensitivity exact V1 → V3 | Audience exact V1 → V3 | Category exact V1 → V3 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Efficient | 266 → 693 (+427) | 484 / 57 | 1,029 → 1,415 (+386) | 389 / 3 | 803 → 1,319 | 641 → 1,089 | 743 → 885 |
| Balanced | 160 → 717 (+557) | 573 / 16 | 1,026 → 1,409 (+383) | 389 / 6 | 597 → 1,321 | 654 → 1,092 | 743 → 914 |
| Quality | 226 → 879 (+653) | 671 / 18 | 1,073 → 1,421 (+348) | 348 / 0 | 715 → 1,344 | 654 → 1,217 | 675 → 979 |

The quality package has the highest V3 joint score of these three (879); this does not establish a universal tier ranking. V1 balanced scores below V1 efficient on joint correctness: the independent [component review](../evaluation/results/pipeline_v1_v3_20261014/planning/v1-tier-component-review-01.json) found 21 gained and 127 lost joint cases for balanced minus efficient. All 127 losses failed sensitivity, 92 also failed action, and 126 had S0 truth. The observed V1 balanced clean sensitivity predictions shifted from 494 S0 / 7 S2 / 249 S3 with efficient to 318 / 291 / 141. These are descriptive predictions on this fixture, not an architectural explanation.

The table below separates contextual detection from exact four-class sensitivity. Contextual sensitive recall counts correct sensitive-versus-clean decisions among 810 positive cases; clean specificity counts correct decisions among 750 clean cases. Category-bearing and multilabel joint scores use 720 and 456 cases respectively. Macro F1 averages ten category F1 values; micro F1 pools category true positives, false positives and false negatives. A correct action can coexist with an incorrect classification.

| Package | Sensitive recall / 810 | Clean specificity / 750 | Category-bearing joint / 720 | Multilabel joint / 456 | Category macro F1 | Category micro F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| V1 efficient | 544 | 494 | 5 | 0 | 0.214 | 0.280 |
| V3 efficient | 808 | 629 | 138 | 51 | 0.664 | 0.663 |
| V1 balanced | 771 | 318 | 4 | 0 | 0.214 | 0.280 |
| V3 balanced | 802 | 631 | 149 | 69 | 0.703 | 0.701 |
| V1 quality | 598 | 468 | 4 | 0 | 0.229 | 0.281 |
| V3 quality | 810 | 641 | 237 | 125 | 0.761 | 0.747 |

The V3 clean false-positive counts are 121, 119 and 109 for efficient, balanced and quality. They remain material despite the paired gain. Among sensitive cases, V3 joint correctness improved by 188, 199 and 291; among category-bearing disclosures it improved by 133, 145 and 233. The [analysis](../evaluation/results/pipeline_v1_v3_20261014/runs/cpu-01/analysis.json) retains all task and slice denominators, exact confusion matrices, per-category precision/recall/F1/support, and family- and expression-cluster sensitivity intervals. The 294 independently recomputed intervals are descriptive uncertainty checks for dependent synthetic clusters; neither family nor expression resampling creates independent external validation.

### Audience and category slices

Every audience has 260 true cases. Each entry is exact audience correct for V1 → V3; P0–P4 are explicit audiences and PU is unspecified. The efficient and balanced V3 packages **lose** 56 and 65 correct PU labels versus V1, while quality loses 21, even as their overall audience exact counts rise. The paired joint PU changes are −4, +36 and +69 respectively; efficient PU joint correctness falls from 102 to 98.

| True audience | Efficient V1 → V3 | Balanced V1 → V3 | Quality V1 → V3 |
| --- | ---: | ---: | ---: |
| P0 | 104 → 138 | 113 → 135 | 113 → 173 |
| P1 | 225 → 225 | 225 → 225 | 225 → 225 |
| P2 | 89 → 222 | 91 → 185 | 91 → 228 |
| P3 | 0 → 167 | 0 → 190 | 0 → 180 |
| P4 | 0 → 170 | 0 → 197 | 0 → 207 |
| PU | 223 → 167 | 225 → 160 | 225 → 204 |

Category F1 below is V1 → V3, rounded to three decimals. Supports include every true label occurrence and therefore sum above the number of category-bearing cases for multilabel rows. The exact precision, recall, true-positive, false-positive and false-negative values for **each** package and category are in its [first-pass summary directory](../evaluation/results/pipeline_v1_v3_20261014/runs/cpu-01/models/); zero F1 can include undefined precision when no positive prediction was made.

| Category (support) | Efficient F1 | Balanced F1 | Quality F1 |
| --- | ---: | ---: | ---: |
| CHILD (108) | .797 → .797 | .797 → .791 | .797 → .788 |
| CRIMINAL (108) | .727 → .745 | .727 → .797 | .727 → .802 |
| FINANCIAL (144) | 0 → .698 | 0 → .678 | 0 → .785 |
| HEALTH (240) | 0 → .715 | 0 → .797 | 0 → .855 |
| IDENTITY (108) | .113 → .360 | .113 → .393 | .113 → .401 |
| LOCATION (108) | 0 → .695 | 0 → .671 | .150 → .921 |
| POLITICS (108) | 0 → .737 | 0 → .804 | 0 → .753 |
| RELIGION (108) | 0 → .287 | 0 → .436 | 0 → .611 |
| SEXUAL (108) | 0 → .790 | 0 → .800 | 0 → .851 |
| THIRD_PARTY (204) | .498 → .817 | .498 → .865 | .498 → .846 |

The full [raw inventory](../evaluation/results/pipeline_v1_v3_20261014/runs/cpu-01/raw-inventory.json), SHA256 `d68f9cb08b4d3f16db396a4f3fea4c5c8764803c3a387ff87719f637e7184da7`, pins each pass summary and wire journal. The first-pass sensitivity confusion for V1 efficient, for example, has true S0 predicted S0/S1/S2/S3 = 494/0/7/249; V3 efficient has 641/0/0/109. V3 efficient's 641 S0 severity predictions include 12 category false positives, leaving 629 contextually clean decisions; the contextual metric also considers categories. The full four-by-four matrices, audience confusion and category PRF1 are retained in those linked pass summaries, rather than collapsed into the main outcome.

## Cascade execution, actions and errors

Each package executed regex on all 1,560 cases. Regex issued 289 early BLOCK decisions, so NER and semantic both report 1,271 `ok`, 289 `skipped` and zero `error` records per pass. The model comparison therefore tests semantic behavior on the same 1,271 reached cases and the **merged product** outcome on all 1,560. Each pass contains 1,364 regex findings. The loaded spaCy NER component ran on reached cases but produced zero **converted PriVoke NER findings** after supported-label filtering; this does not claim zero raw spaCy entities or an absent backend. The independent [NER observation review](../evaluation/results/pipeline_v1_v3_20261014/planning/ner-observation-review-01.json) checks that distinction.

| Package | Semantic findings | Final ALLOW / WARN / BLOCK | Regex early BLOCK | Under-enforcement distance (cases) | Over-enforcement distance (cases) |
| --- | ---: | ---: | ---: | ---: | ---: |
| V1 efficient | 443 | 777 / 253 / 530 | 289 | 234 (234) | 503 (297) |
| V3 efficient | 1,197 | 707 / 124 / 729 | 289 | 6 (6) | 248 (139) |
| V1 balanced | 883 | 564 / 585 / 411 | 289 | 129 (129) | 545 (405) |
| V3 balanced | 1,207 | 713 / 103 / 744 | 289 | 12 (12) | 248 (139) |
| V1 quality | 505 | 825 / 442 / 293 | 289 | 236 (236) | 364 (251) |
| V3 quality | 1,182 | 701 / 103 / 756 | 289 | 0 (0) | 248 (139) |

Action distance is ordinal deviation from an allowed action: under means less restrictive and over means more restrictive. Distances need not equal affected-case counts. Comparing each V3 package with its V1 tier, over-enforcement falls by 255, 297 and 116 distance units and under-enforcement by 228, 117 and 236 units. The paired first-pass audit still finds **new under-enforcement on 3 efficient and 6 balanced cases**; quality has none. Zero action regression for quality does not mean zero joint regression: it has 18 joint regressions.

All three V3 packages over-enforce the **same 139 case IDs**, totaling 248 distance units each. The independent [common-case review](../evaluation/results/pipeline_v1_v3_20261014/planning/common-over-enforcement-review-01.json), SHA256 `3ead52263ada5164d52ed731ad39e5e6a52b9abc69aeb154f7f5a5cf86bfe537`, checked the IDs against first-pass raw wires. For each, the maximum final action equals an individual regex finding. Of these, 109 S0/ALLOW controls produce regex BLOCK and skip NER/semantic; 30 S1/ALLOW controls produce regex WARN. For example, `AU3/fresh_eval/child/09/P0/1/0` has an assistant-provisional S0/ALLOW target for an unfilled form, while a `child` regex finding produces S3/BLOCK. This is observed provenance in the normal cascade, not an ablation or a counterfactual causal estimate.

There were zero failed accuracy RPCs and zero layer errors in 28,080 accuracy requests. Each package had four warmups, 24 total, plus 12 separate synthetic product preflight calls. All three passes of each package gave identical classifications, final actions, evidence fields, masks and layer traces for every case. That is within-run repeatability on unchanged inputs, not independent test-set replication. The [execution handoff](../evaluation/results/pipeline_v1_v3_20261014/runs/cpu-01/execution-handoff-01.json), SHA256 `441def13577d00bad596d5d0a587f894346782b78b194ebfa3e62212bad38d8c`, records completion and server cleanup; all six owned server processes were stopped.

The three over-cap V1 efficient IDs are `AU3/fresh_eval/child/11/P1/3/1`, `AU3/fresh_eval/identity/09/P1/3/0` and `AU3/fresh_eval/third_party/09/P1/3/0`. The first skipped semantic after regex BLOCK; the latter two executed with native truncation. No V1 balanced/quality or V3 package exceeded its own cap. The comparison retains these cases and their native behavior.

## Descriptive execution cost

The table gives first-pass **host RPC** latency after model and real NER preload and four warmups per package. Quantiles cover 1,560 successful RPCs each; they are not model-only times or a service-level objective. The reported post-warmup-to-end duration uses two monotonic process-resource snapshots and includes three accuracy passes plus nearby bookkeeping; it excludes process load and initial warmups. Load/parity time is separately recorded at server readiness. Peak RSS is the Windows process counter across that server process. These scopes must not be added into a purported controlled speedup.

| Package | Load/parity ms | Host RPC median / p95 / p99 ms | Post-warmup-to-end s | Peak RSS MiB |
| --- | ---: | ---: | ---: | ---: |
| V1 efficient | 4,202 | 55.20 / 70.08 / 76.90 | 409.40 | 389.4 |
| V3 efficient | 5,577 | 43.71 / 50.12 / 54.32 | 465.30 | 466.8 |
| V1 balanced | 5,196 | 65.87 / 85.65 / 97.52 | 465.52 | 389.8 |
| V3 balanced | 4,931 | 42.73 / 47.82 / 53.64 | 494.38 | 506.4 |
| V1 quality | 4,533 | 59.58 / 90.08 / 102.41 | 416.88 | 391.8 |
| V3 quality | 6,162 | 50.02 / 59.48 / 66.81 | 463.52 | 523.4 |

Server-side elapsed medians in the same order are 53.92, 42.55, 64.59, 41.54, 58.52 and 48.88 ms. Host time includes transport and client overhead; server elapsed covers request handling. The counter snapshots show larger observed V3 process memory and cumulative process CPU seconds over the three-pass window, while first-pass host median is lower for V3 in this particular run. The fixed V3-first order, runtime differences (Torch versus NumPy), regex shortcuts, process warming and host load prevent a controlled latency or throughput claim. Raw pass summaries retain p90, maxima, totals, server quantiles and resource snapshots for all 18 passes.

## Reproduction and limits

The frozen [protocol](../evaluation/results/pipeline_v1_v3_20261014/runs/cpu-01/protocol.json) and [analysis](../evaluation/results/pipeline_v1_v3_20261014/runs/cpu-01/analysis.json), SHA256 `2d9190cc26003e9916719c96127791b6b348e1a0683a30b11891a058a96a302f`, are local ignored evidence, as are raw protobuf journals, snapshots and model artifacts. Preserve them with the cited hashes to reproduce the numerical audit; a clean checkout of commit `6637468` alone lacks the dirty source-closure bytes and ignored assets. The host audit command is:

```powershell
evaluation/.venv-v1-v3-pipeline/Scripts/python.exe evaluation/run-pipeline-v1-v3.py audit --results evaluation/results/pipeline_v1_v3_20261014/runs/cpu-01
```

To regenerate rather than audit, first restore the pinned source closure, six package assets, release-07 payload and host environment, then use `evaluation/run-pipeline-v1-v3.py prepare` and the `preflight`/`evaluate` actions with the matching named server and ready file according to the protocol. Host protobuf clients are generated with `evaluation/setup-host.py`; focused harness tests use `evaluation/.venv-v1-v3-pipeline/Scripts/python.exe -m unittest discover -s evaluation/tests -p test_pipeline_v1_v3.py -v`. Do not substitute an empty layer list: it selects the whole product pipeline implicitly and would lose the explicit protocol assertion. This run deliberately selected the full product path; it must not be described as an isolated LLM-layer evaluation.

The workload is reused and assistant-provisional, with 35 related families and 24 audience-expression groups. Same-case pairing removes case-mix differences but does not create a fresh independent evaluation, prove causes for package differences, or measure real-world safety. Regex shortcuts leave 289 cases per pass without semantic execution. Native thresholds, tokenizers, training histories and token windows differ. Category and audience errors, 139 shared V3 over-enforcement cases, and the new paired regressions above remain material. No deployment, production-readiness, causal architecture, detector-ablation or controlled speedup conclusion follows from these observations.
