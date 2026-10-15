# Controlled detector and adaptation studies, 14 October 2026

Status: AB14 and AD14 main experiments completed and accepted by root after independent raw-wire, tensor, exposure and numerical review; root and peer accepted the AD14 resource pilot before the main fits. No protected-final contents were accessed, no model was promoted, and no existing dirty training source was changed by this stream.

## Request and questions

Root's exact retained goal was: "get data and rewrite paper for ALL unfinished work obtainable autonomously; first concrete workflow-based implementation plan then execute". This delegated stream implements separately authorized product detector ablation and bounded matched adaptation/resource evidence. Root owns manuscript and claim-ledger integration. The research questions are whether the shared 139 over-enforced cases change under actual detector removal, what protections are lost by that change, and whether updating a fixed pretrained encoder changes outcomes relative to matched head training and an unchanged control.

## AB14 protocol and amendments

One unchanged AU3-selected balanced V3 package (`99b36171056bb0398584a0b0556d9d7ff2640d0acac4b124a126327451a80589`) was evaluated on the same already opened 1,560 assistant-provisional AU3 FRESH cases. Package, tokenizer, native rules/NER/policy, ordered texts/targets, actual dirty source closure, dependencies and harness were frozen before requests. All Python clients ran on the Windows host. A dedicated inference-only native server used loopback port 50191. Every call had explicit nonempty detector layers, regex FIRST, no visibility hints and no presence gate; raw requests and responses have immutable reservation/terminal hash-chained journals.

The original five-configuration freeze (`ablation-01`) was retained without requests. Peer review identified that individual detector-removal effects require `[3,4]` and `[2,4]`; root approved both prospectively. The executed `ablation-02` protocol SHA256 is `d3badb10c83254dfb2eb7b6aac256296ca459b81f57091053b5d99d4ca5c420b`. Actual runtime source closure is `bf022fc18b16aebfdbcc75e68ef92e28ffb4f4765015c74fc56e95e1047864fa`, matching the historical PIPE3 closure. This includes pre-existing dirty dependencies; a clean Git commit does not substitute for that captured source closure.

The frozen scorer used `family_id` and `group_id`, but AU3 stores the same family identity in both. This was discovered during inference. Frozen inference and original analysis were preserved; a separately hashed post-hoc scorer uses actual `metadata.audience_expression_group_id`. Only that corrected artifact supplies expression sensitivity. Both analyses use 2,000 paired cluster draws, seed 42 and linear percentile 95% intervals. Family and expression results are separate dependence sensitivities and do not establish crossed independence. This correction required no repeated inference.

## AB14 observed results

All 10,920 requests completed with valid traces, zero runtime/transport errors and full 1,560-case correctness denominators for every configuration. Requested sole semantic `[4]` executed successfully on all cases. In the full product, regex executed on all 1,560 and later requested NER/semantic layers legitimately skipped after regex BLOCK on 289; each later detector executed on 1,271. The scorer validates exact returned layer order, immutable executed semantic identity, and skip provenance rather than counting skips as executions.

| Configuration | Requested layers | Binary correct | Allowed action | Joint correct | Under / over-enforced |
| --- | --- | ---: | ---: | ---: | ---: |
| Regex | `[2]` | 1,001 | 1,031 | 295 | 390 / 139 |
| NER | `[3]` | 750 | 840 | 125 | 720 / 0 |
| Semantic | `[4]` | 1,534 | 1,530 | 972 | 30 / 0 |
| Nonsemantic | `[2,3]` | 1,001 | 1,031 | 295 | 390 / 139 |
| Remove regex | `[3,4]` | 1,534 | 1,530 | 972 | 30 / 0 |
| Remove NER | `[2,4]` | 1,433 | 1,409 | 717 | 12 / 139 |
| Full product | `[2,3,4]` | 1,433 | 1,409 | 717 | 12 / 139 |

Binary positivity is non-S0 or a nonempty category set. Joint correctness requires exact sensitivity, visibility and category set plus an allowed policy action. Under/over-enforcement counts use distance from the allowed-action set; errors would remain incorrect in full correctness denominators and would have a separately reported paired-success denominator for distance contrasts. Actual paired-success denominators are all 1,560.

Removing regex while retaining NER and semantic detection improved 139 allowed actions and regressed 18 (net +121/1,560); binary improved/regressed 109/8 (net +101), and joint improved/regressed 260/5 (net +255). Under-enforcement increased from 12 to 30 cases while over-enforcement fell from 139 to zero. The corrected paired action-rate intervals are [0.03461, 0.12696] by 35 families and [0.05962, 0.09231] by 24 audience expressions. Joint-rate intervals are [0.12037, 0.21592] and [0.13910, 0.18720] respectively. These descriptive intervals do not justify disabling regex in deployment.

The post-hoc audit independently reconstructs the shared 139-case over-enforcement intersection from all three historical V3 first-pass raw journals. All 139 have an allowed action under semantic and remove-regex configurations, while all remain over-enforced under regex, nonsemantic, remove-NER and full product. Current balanced full-product classifications/actions/statuses exactly match historical balanced first-pass outcomes on all 1,560. Removal of NER yields identical full-product outcomes here, consistent with zero converted NER findings on this bounded fixture; this does not establish that NER is unnecessary on other data.

Raw evidence remains ignored under `evaluation/results/controlled_studies_20261014/ablation-02/`. The original analysis hash is `640a7da4a92e3657f2a9c2c52ee2032d8a44a781c05d8ad671bbc65f9bf5511d`; corrected grouping/cohort analysis is `f6bba29b524a4e261c990ae13f6e9ec00ff31800ad9caa1e329cba3f8bf1f67a`. No raw prompts, case identifiers, fitted vocabulary or weights are committed.

## AD14 prior evidence and prospective design

The completed V3-R1 study already contains 18 matched HEADS/FULL cells across three package tiers and seeds 42/43/44, plus unchanged ORIGINAL controls. All terminal candidates were scored, including eight guard-rejected fits whose effective outcome remained ORIGINAL. Every main cell completed 256 steps/16,384 repeated TRAIN exposures. Existing paired contrasts show both gains and regressions; ORIGINAL has zero affine heads and is a weak task baseline. That experiment does not isolate pretraining or architecture effects. This work preserves it rather than relabeling its historical scores.

The new bounded experiment changes the TRAIN domain to the maintained AU3 sampler and starts each treatment from the same independently pinned, intact official pretrained balanced encoder/pooler and deterministic zero task-head bytes. Its ORIGINAL manifest is `81b3d20e1c695b81a159ec23b3b06567e548a84909f5de21fe8936966ec13fff`, blob `bfb59899774b9858292010b4cddc4e79cc4010e61b3c0216b896482c70626d15`; it has no PriVoke optimizer-training ancestry. No random model initialization occurs.

Initial preparation deliberately refused the overlap between the maintained guard and AU3 validation scenarios; no fit occurred in that failed attempt. Fresh `adaptation-02` preparation excludes complete TRAIN/guard scenario-group and normalized-text unions across all predeclared schedules before any predictions. This removes 480 validation rows in ten guard groups, leaving 1,080 rows in 25 assessment groups. Actual generated TRAIN, invariant-transform exposures and guard wires have zero assessment group/text overlap for all admitted schedules. The existing AU3 exclusion proof is retained; this does not manufacture independent human truth or make the reused validation endpoint fresh confirmation.

The prospective main design is balanced HEADS/FULL x seeds 42/43/44, 64 optimizer steps each and 4,096 repeated TRAIN exposures, plus one unchanged ORIGINAL assessment. Paired treatments share byte-identical bases/heads, exact TRAIN order/targets/guard, head AdamW settings, objective, clipping policy, microbatch size, dropout-off execution and step budget. FULL alone enables encoder gradients and adds the fixed encoder learning-rate optimizer group; consequent joint-gradient clipping changes belong to this treatment. Only terminal candidates are scored, with all guard outcomes retained and no tuning, checkpoint selection or promotion.

Protocol SHA256: `98c1d0fbd8c1342c99e993d5257d75c99f8918510c0719ba363f43f8d147afe3`; actual source closure: `302ddc423abe7897e7c23c37d2d330d1d41c9f2a09f372dd65c256eb0a8819d7`. Host environment is Python 3.11, Torch 2.12 CUDA 13.0 and Transformers 4.57.6 on RTX 5080. Every direct host-Torch fit selects `[4]` and asserts actual successful semantic training evidence; assessment calls the in-process native protobuf handler with `[4]` and exact returned sole-layer/identity assertions. Resource-only pilots score no assessment rows.

## AD14 resource pilot

The reviewed two-step seed-42 HEADS and FULL pilots each completed exactly 128 TRAIN occurrences and 32 forward/backward microbatches. HEADS left all encoder bytes unchanged with zero encoder backward blocks. FULL changed 39 encoder tensors (16 per block, five embedding and two pooler tensors), recorded 64 block backwards, and recorded 1,770,496 nonzero encoder-gradient elements on step two after the expected zero-gradient first step from zero heads. Both reload/guard-parity checks passed, losses and parameters remained finite, and guard action harms were zero. These are execution/readiness observations, not useful-improvement evidence or a speed ranking.

| Pilot | Fit seconds | CUDA peak allocated bytes | Evidence SHA256 |
| --- | ---: | ---: | --- |
| HEADS | 2.891 | 160,674,304 | `a5ddb408cb7ee62914cee5006d578e317b86a6ffb4e21179edadeccdce4d0246` |
| FULL | 1.312 | 292,005,376 | `10c7cb83241013645f54c746b9a1adcbc602e93cbc3290b51aee433ec247e284` |

Both meet the prospectively declared 120-second/8-GiB allocated-tensor limits. Fixed order and cold kernels prevent interpreting the two-step times as comparative training speed. Raw evidence and independent ORIGINAL/per-cell initial catalogs/candidates remain durable and ignored under `models/experiments/controlled_studies_20261014/adaptation-02/`; result/source captures are under the matching `evaluation/results` directory. Failed attempt records and unused freezes are retained. All main fits and assessment calls subsequently completed and were accepted as recorded below.

## Reproduction and verification

Owned entry points are `evaluation/run-controlled-product-ablation.py`, `evaluation/run-controlled-adaptation.py` and `evaluation/analyze-controlled-studies.py`. Product commands require `--allow-product-pipeline`; this flag is confined to the separately authorized product ablation. Adaptation never calls the product pipeline. Eight host behavior checks cover exact layer order, semantic-only skip refusal, legitimate regex suffix skips, immutable semantic identity, error-inclusive correctness and directional action distance. Real resource-pilot checks cover training execution, encoder tensor/gradient behavior and serialized parity.

Root owns manuscript integration and discoverability links, acceptance, commits on the primary branch, and managed-worktree cleanup. This stream owns only its new scripts/tests and this controlled-study record. Scientific limits remain reused provisional synthetic labels, native-package specificity, finite scenario/expression groups, a weak zero-head ORIGINAL baseline, dependent repeated-seed outcomes, host-specific resources and no deployment/generalization/pretraining-causal claim.

## AD14 fixed main outcomes

Root acceptance of the resource pilot is retained at `adaptation-02/pilot-accepted.json`, SHA256 `7492dc3b94c644b6f68fe0b4553eafe86463c77ec2e8f9c297f0bf1199480aea`. All six fixed 64-step cells completed, each with 4,096 repeated TRAIN exposures, 1,024 forward/backward microbatches and finite losses/parameters. An independent reviewer decoded actual fit requests, checked paired TRAIN/guard protobuf hashes, verified candidate/manifest/evidence/terminal hash joins, loaded actual safetensors through NumPy and compared every tensor to ORIGINAL. HEADS changed zero encoder and six head tensors in every seed; FULL changed 39 encoder and six head tensors in every seed, with actual later nonzero encoder gradients and 2,048 encoder-block backwards. Reloaded guard parity passed throughout.

The seven snapshots were then scored on the same frozen 1,080-row assessment (570 sensitive, 510 clean provisional cases). All 7,560 in-process host-CUDA calls to the unchanged native protobuf handler returned exactly successful `[4]` with immutable snapshot identity and zero handler errors. These calls serialized requests/responses for audit but exercised no network transport or deployed gRPC service; their results establish no RPC or deployment latency. Every terminal candidate was scored, including guard-rejected candidates. No assessment feedback changed any fit, threshold, source, checkpoint or selection.

| Snapshot | Joint correct / 1,080 | Allowed action / 1,080 | Binary correct / 1,080 | Fit seconds | CUDA peak allocated bytes |
| --- | ---: | ---: | ---: | ---: | ---: |
| Unchanged ORIGINAL | 0 | 480 | 570 | -- | -- |
| HEADS 42 | 192 | 908 | 947 | 17.969 | 160,674,304 |
| FULL 42 | 257 | 993 | 1,014 | 9.188 | 292,005,376 |
| HEADS 43 | 204 | 906 | 939 | 4.766 | 160,674,304 |
| FULL 43 | 247 | 989 | 995 | 8.609 | 292,005,376 |
| HEADS 44 | 198 | 912 | 966 | 5.688 | 160,674,304 |
| FULL 44 | 268 | 1,003 | 1,027 | 12.375 | 292,005,376 |

| FULL minus matched HEADS | Joint improved / regressed; net | Action improved / regressed; net | Binary improved / regressed; net | Under / over distance increased |
| --- | ---: | ---: | ---: | ---: |
| Seed 42 | 79 / 14; +65 | 123 / 38; +85 | 93 / 26; +67 | 33 / 17 |
| Seed 43 | 69 / 26; +43 | 124 / 41; +83 | 99 / 43; +56 | 37 / 13 |
| Seed 44 | 90 / 20; +70 | 110 / 19; +91 | 80 / 19; +61 | 15 / 17 |

Each contrast has 1,080 paired successful outcomes. Under and over changes are separate directional distances to the allowed-action set; these counts are not a mutually exclusive harm union. All seeds reuse the same assessment cases and do not create 3,240 independent situations. The corrected analysis reports per-seed 2,000-draw seed-42 paired intervals separately over 25 family groups and 24 actual audience-expression groups. The original duplicated-family interval fields remain preserved and are not evidence of expression uncertainty.

The existing training guard reported action harms HEADS 0/1/0 and FULL 1/1/1 for seeds 42/43/44. Under its fixed rule (joint guard improvement and zero action harms), only HEADS 42 and 44 would retain their candidate; HEADS 43 and every FULL cell map to unchanged ORIGINAL. Immutable per-cell `effective-catalog.json` files preserve this hypothetical mapping, the independent ORIGINAL and every raw candidate. No publication or promotion occurred. The guard covers 16 fixed rows through the maintained prediction primitive; assessment uses the unchanged native runtime on 1,080 different rows. The native no-finding case is exactly S0/empty categories/PU and its fallback preserves that classification. A guard pass is a bounded regression decision, not a certificate for the broader assessment or deployment safety.

These fixed-base results support a bounded treatment contrast under the stated optimizer and clipping policy: FULL improves aggregate correctness here, yet incurs casewise regressions and guard harms. They do not isolate pretraining, architecture or deployment benefit. The zero-head ORIGINAL is a deliberately weak task baseline. The ordered times, especially cold HEADS seed 42, do not support a general training-speed ratio. Peak values are allocated CUDA tensor bytes, not whole-process/driver VRAM or total study cost.

Final adaptation raw analysis SHA256 is `a1b5f1091b859d4b5460e59987b1c3a364eb724c213a00f15ed4c937d8d32af1`; corrected grouping/effective-catalog analysis is `ad1e172bca18f97f9edf31e9a8688e183d884c126826cbd1f8e2ee5606df5823`. The supplementary generated-protobuf/scoring closure is `f6af3881b83c68e3a9fd2806c5f7fb6a5de65e8e1d8ca5067cc34f0bf467bb26`; all ten actual files match byte-for-byte the earlier prospective AB14 source capture. Frozen own harnesses, the original AB14 post-hoc scorer and the adaptation post-hoc scorer are retained by exact bytes alongside ignored evidence. The prompt-free tracked [aggregate](controlled-studies-20261014.json) contains the complete counts, corrected intervals, guard mappings and provenance hashes.


Independent acceptance verified all 10,920 AB14 raw protobuf pairs and journal chains, all 7,560 AD14 raw protobuf pairs and case joins, all six actual candidate tensor changes and paired fit wires, and all 54 corrected AD14 per-seed family/expression intervals to numerical tolerance 1e-14. Root accepted point/cohort claims and the fixed adaptation results while retaining the directional harms, guard rejections and provisional-label limits. All six AB14 remove-regex family/expression intervals were additionally independently recomputed from verified raw records and matched to tolerance 1e-14; other AB14 contrast intervals remain descriptive outputs without separate numerical recomputation. All owned servers and assessment processes terminated; the verified AB14 PID/create-time/port cessation receipt is retained. Port 50192 was never opened by this stream.


The exact executed harness bytes are preserved under the primary ignored result directory's `execution-harness/` and frozen source captures. Tracked delivery projections remove trailing blank EOF lines and are subject to Git newline conversion; the normalization manifest verifies equivalence after line-ending and trailing-blank normalization. Existing frozen protocols must be audited with their exact captured harness bytes, rather than claiming a normalized checkout file has the same byte hash.
