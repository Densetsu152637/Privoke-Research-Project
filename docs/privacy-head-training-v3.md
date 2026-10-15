# Privacy-head training and fresh v1 comparison (PH3-R1)

Status: all three head fits, all six selected/terminal exports and the fresh six-model comparison completed and passed independent audit. All three trained V3 packages improve joint correctness over their same-tier V1 baselines on this synthetic workload, with the recall/specificity regressions reported below. Study ID: `privacy_heads_v3_20261013`, 13 October 2026, Sydney. No production promotion or independently validated human labels are claimed.

Exact user request: “Can you then train V3s heads for privacy? This can be a lengthy training session. Once this is done run a fresh eval comparing them with V1”.

The prior [V123-D1 diagnostic](model-generation-comparison-20261013.md#follow-up-why-v1-balanced-appears-stronger-v123-d1) found category collapse on sensitive disclosures. New head training therefore needs direct complete category supervision, meaningful sensitivity and visibility labels, and a genuinely new authored comparison. That observation does not establish which training or architecture choice caused the earlier failure.

The follow-up reporting requirement covers epochs for each model's base, encoder, pooler and task heads. Those stages have different histories; a head epoch does not train a frozen encoder, and upstream language-model pretraining is separate from privacy-head fitting.

## Epoch and stage history (PH3-EPOCHS-R1)

The [retained epoch-history extraction](../evaluation/results/privacy_heads_v3_20261013/planning/epoch-history.md), SHA256 `40643cb3e65a6d2eae7d9643cded24abd21d47d06e3a2f2c0e94e99b48cfd695`, records the local artifact fields and source hashes supporting this table. Unknown means trustworthy epoch/step evidence is unavailable; counts are not inferred from row exposures.

The [upstream provenance check](../evaluation/results/privacy_heads_v3_20261013/planning/upstream-training-history.md), SHA256 `45f18421c6fca0d77f1c8a14ab490fccec902ca4e16c6d64475fd581f82ff063`, also found no checkpoint-specific pretraining epoch/step counts in the inspected publisher material and associated [Turc et al. paper](https://arxiv.org/abs/1908.08962). Exact pinned README retrieval was unavailable; local manifests still establish the pinned lineage. The model-card figure of four epochs concerns downstream GLUE fine-tuning, not base pretraining, and is not used as a substitute.

| Model / artifact | Base linguistic pretraining | Encoder and pooler privacy training | Task-head training |
| --- | --- | --- | --- |
| V1 efficient | None in this repository path; seeded random Tiny initialization | 0 epochs/steps after initialization; frozen during bootstrap | **220 bootstrap epochs**, revision 0 |
| V1 balanced | None in this repository path; seeded random Tiny initialization | 0 epochs/steps after initialization; frozen during bootstrap | **360 bootstrap epochs**, revision 0 |
| V1 quality | None in this repository path; seeded random Tiny initialization | 0 epochs/steps after initialization; frozen during bootstrap | **520 bootstrap epochs**, revision 0 |
| V2 balanced `v2-original`, `v2-window-42`, `v2-window-43` | Inherited V1 base; no linguistic pretraining in this Tiny lineage | **0 additional applied V2 updates**; ORIGINAL is BASE, windows 42/43 retain BASE | Inherit 360 bootstrap epochs; **0 additional applied head updates**; configured 8 window epochs are not applied training |
| V2 balanced `v2-legacy-42`, `v2-legacy-43`, `v2-legacy-44` | Inherited V1 base; no linguistic pretraining | Each applies **64 full-encoder projected-Adam directions**; actual V2 epochs **unknown** | Inherit 360 bootstrap epochs, plus the same joint 64-direction update; no separate head-only stage |
| V2 balanced `v2-window-44` | Inherited V1 base; no linguistic pretraining | **64 applied full-encoder optimizer steps**, selected step 64; actual V2 epochs **unknown** | Inherits 360 bootstrap epochs plus the same joint 64-step update; no separate head-only stage |
| Previous V3 efficient FULL42 candidate, 12 October | Pinned upstream Google BERT; upstream epochs/steps **unknown** locally | 32 recorded passes through the frozen 512-occurrence window, 256 full-model optimizer steps and 16,384 repeated TRAIN exposures | Included in the same 32 full-model window passes; no separate head-only stage |
| Previous V3 balanced FULL42 candidate, 12 October | Pinned upstream Google BERT; upstream epochs/steps **unknown** locally | 32 recorded window passes / 256 full-model steps / 16,384 repeated exposures | Included in the same full-model optimization |
| Previous V3 quality FULL42 raw candidate, 12 October | Pinned upstream Google BERT; upstream epochs/steps **unknown** locally | 32 recorded window passes / 256 full-model steps / 16,384 repeated exposures; candidate was guard-rejected | Included in the same full-model optimization; no inherited guard-pass claim |
| Historical V3 quality ORIGINAL control | Pinned upstream Google BERT; upstream epochs/steps **unknown** | **0 additional task encoder/pooler epochs/steps** | Deterministic zero heads; **0 task-head fit epochs/steps**; no FULL42 inheritance |
| Current V3 efficient PH3 heads | Pinned linguistic ORIGINAL; upstream epochs/steps **unknown** locally; 0 additional PH3 linguistic-training epochs | **0 additional PH3 encoder/pooler epochs/steps**; both serialized exports independently match ORIGINAL encoder/pooler tensors | **32 completed head epochs; selected epoch 12** |
| Current V3 balanced PH3 heads | Pinned linguistic ORIGINAL; upstream epochs/steps **unknown** locally; 0 additional PH3 linguistic-training epochs | **0 additional PH3 encoder/pooler epochs/steps**; both serialized exports independently match ORIGINAL encoder/pooler tensors | **30 completed head epochs; selected epoch 7** |
| Current V3 quality PH3 heads | Pinned linguistic ORIGINAL; upstream epochs/steps **unknown** locally; 0 additional PH3 linguistic-training epochs | **0 additional PH3 encoder/pooler epochs/steps**; both serialized exports independently match ORIGINAL encoder/pooler tensors | **30 completed head epochs; selected epoch 4** |

V1 counts come from each pinned artifact's `metadata.training_epochs`, `training_strategy=deterministic_bootstrap_head_finetune` and `training_revision=0`, checked against `models/generate_baseline.py` and its six head-only trainable tensors. A V1 epoch is a pass through the generator's synthetic training phrases, not language-model pretraining. The [seven-snapshot V2 inventory](../evaluation/results/privacy_heads_v3_20261013/planning/epoch-history-v2-inventory-01.md), SHA256 `d22eb0353640864dddf381137bffaa2f948c63f2f57668e0f949cd2b9a48b365`, and [independent source check](../evaluation/results/privacy_heads_v3_20261013/planning/epoch-history-v2-review-01.md), SHA256 `2352b19d1e84eff1948de1c12d3ef38f2ee56305926c0c2e2d07eb722b753e76`, distinguish three unchanged BASE snapshots from four applied contextual updates. The independent check corrects the inventory's window-43 fit-response hash transcription; its actual SHA256 is `8131e07f1537b850f40b7c592bea6992e19c5b926f245e8f705bed5d134bdde5`. All seven carry inherited `metadata.training_epochs=360`; it does not count new V2 updates. These rows cover all fourteen historical comparison snapshots (three V1, seven V2, three FULL42 and one quality ORIGINAL) separately from the three new PH3 fits.

The [append-only historical epoch addendum](../evaluation/results/privacy_heads_v3_20261013/planning/epoch-history-addendum-01.md), SHA256 `50ed3d9ee2ba436b98b9272df85e3baec000123ef7cfef32099a9afb30c922a0`, corrects the earlier ledger: each FULL42 `training-evidence.json` explicitly records `policy.epochs=32`, `policy.window_batches=8`, `source.train_rows=512`, `counts.optimizer_steps=256`, `counts.train_rows=16384`, `source.seed=42` and scope `full_encoder`. Thus the historical epoch unit is a pass through that frozen 512-occurrence window, jointly updating encoder, pooler and heads, with no separate head-only stage. They do not belong to the current PH3 lineage: each current tier starts again from its independently pinned linguistic ORIGINAL, not the old FULL42 export. Current completed and selected counts come from the actual execution records below; its configured minimum/maximum are not substituted for those counts.

## Completed PH3 head fits (PH3-FIT-R1)

All three fit commands completed with exit 0 and `stop_reason=validation_patience`. The [actual epoch-history record](../evaluation/results/privacy_heads_v3_20261013/implementation/full-fit-01/epoch-history-01.json), SHA256 `ba39ad9d5c1f07a8383d1a85f1510f03f4a6513aed68a0ae3326ef7f6dbd3d21`, retains completed work and independently read selected-checkpoint counts. The per-tier summaries supply `epoch`, `best_epoch`, `optimizer_steps`, `train_exposures` and `seconds_this_invocation`.

| Model | Completed epochs | Selected epoch | Completed / selected optimizer steps | Completed / selected TRAIN exposures | Core fit seconds |
| --- | ---: | ---: | ---: | ---: | ---: |
| [V3 efficient](../evaluation/results/privacy_heads_v3_20261013/fits/efficient/complete.json) | 32 | 12 | 3,136 / 1,176 | 199,680 / 74,880 | 18.797 |
| [V3 balanced](../evaluation/results/privacy_heads_v3_20261013/fits/balanced/complete.json) | 30 | 7 | 2,940 / 686 | 187,200 / 43,680 | 18.328 |
| [V3 quality](../evaluation/results/privacy_heads_v3_20261013/fits/quality/complete.json) | 30 | 4 | 2,940 / 392 | 187,200 / 24,960 | 19.375 |

Completed work includes the later epochs needed to satisfy minimum training and patience; selected work describes the earlier validation-selected checkpoint intended for the comparison. Selection before epoch 30 does not mean the run stopped before its 30-epoch minimum. Exposures are repeated visits to the same 6,240 unique TRAIN rows, not new examples. No new base-language, encoder or pooler training occurred: the current PH3 stage adds **0 epochs/steps** to those frozen stages, while their upstream linguistic-pretraining counts remain unknown.

The fits were short because optimization used cached frozen-encoder features and only 2,580/5,140/5,140 affine head parameters for efficient/balanced/quality. The measured 18–20 seconds per tier are actual core fit durations; they exclude cache extraction, model loading, export, audits and fresh evaluation. All three fixed recipes ran to their declared stopping criterion without evaluation-based tuning.

The complete-summary SHA256 values are `4ecc9ce1112acdcb3751a3aba187a46e61591ca5e714d7dc9bc783dccadc83ea` (efficient), `113576ef6fb07efdfd1808d6582636fb602a3ceaf57d76ef0134031fb5b274d7` (balanced), and `e942e0d96fe614b564ec6c1cb3d7b7be2ea60ee143c3d36de2f7c7a53c8189ca` (quality). Export admission subsequently passed; the separately audited fresh comparison is reported below.

## Export failure and bounded recovery

All three original export commands failed at the serialization parity check before export indexes and terminal exports were published. The check compared lists containing `Classification` objects without value equality, so equal classifications from separately loaded models compared unequal by object identity. The [retained diagnosis](../evaluation/results/privacy_heads_v3_20261013/implementation/full-fit-01/export-parity-diagnosis-01.json), SHA256 `5db28ea4e241835c9707eef3c1c191fd032e488b2a0abafc996eaad59cfc477c`, confirms exact task logits, packed/named classifications, confidence and action values on eight validation samples per tier; serialized heads equal the selected checkpoints and encoder inventories remain unchanged.

Partial selected assets and original failure logs are retained. The separately reviewed [export finalizer](../evaluation/finalize-privacy-heads-v3-exports.py), committed in `04f5c7d5fd75fcb99db4814ef5bdb2eb8876a791`, compares actual values instead of object identity. It sits outside the frozen 159-file training closure and is bound separately by source SHA256 `3196bcacd5150f3ac1f4db0600eda74cebb8f4540e1ccb104ff0b9453b84fb67`, the [corrective record](../evaluation/results/privacy_heads_v3_20261013/corrections/export-value-parity-r1.json), eight regression tests and [root correction acceptance](../evaluation/results/privacy_heads_v3_20261013/export-correction-acceptance.json). The [independent finalizer review](../evaluation/results/privacy_heads_v3_20261013/planning/export-finalizer-review.md), SHA256 `459692bd0f058e60fdfa99d46b46f136964f40d1d88cb429b3f2058351f0bafa`, accepted the bounded correction before index publication. No completed fit, selection, model weight, threshold or old source/protocol byte changed.

For reproduction after fitting, the correction record and protocol-bound root acceptance precede `finalize-privacy-heads-v3-exports.py finalize --results <assigned-results> --tier <tier>`, followed by the unchanged `run-privacy-heads-v3.py audit-training` phase for each tier. The finalizer's `record --test-proof` phase binds its exact regression evidence; an old acceptance cannot authorize changed sources. Use fresh assigned result/model directories rather than overwrite these retained runs.

## Completed exports and post-fit admission (PH3-EXPORT-R1)

All three corrective finalizations and all three unchanged training audits exited 0. The [execution handoff](../evaluation/results/privacy_heads_v3_20261013/implementation/full-fit-01/result.json), SHA256 `ffac1a14fd358f46033e42a1e909e95809bc18c7bdb6ebcbb453f5fcb72a6bb5`, binds all indexes, selected/terminal assets, corrective proofs and failed original-export records. The [independent post-fit review](../evaluation/results/privacy_heads_v3_20261013/planning/postfit-review.md) then loaded all six actual safetensors exports and persisted checkpoints without model inference. It reconciled every one of the 92 epoch records, selection/patience/work counts and exact chosen head arrays.

Both exports for every tier preserve all encoder and pooler tensors byte-identically to their independently pinned ORIGINALs: 71/39/199 tensors for efficient/balanced/quality. Exactly the six task-head tensors change. Selected arrays equal `best_heads` and the recorded selected epoch's actual checkpoint; terminal arrays equal terminal checkpoint heads. All 15 selected partial-asset hashes from the failed export attempts remain unchanged. The retained validation reload checks have exact finite task logits and packed/named/confidence/action parity for both kinds.

| Tier | Selected manifest SHA256 | Terminal manifest SHA256 |
| --- | --- | --- |
| Efficient | `630a319ef482a1cc82e7c1122fe36d8e13503d681cbfc402838deedc09a4070c` | `3c23bd783d66d35e28dccaf9efd6eb070190c326f0567e806e11563dbc7dbd0f` |
| Balanced | `5dfea2eb4ace6f3bc29ffed08e23bd138e7c7fce74a05d27d022260f4525c2d0` | `98c74393b36f95b6831cb4a877c2fafa8b7ef068ed4985fd15fd63fedd7c1247` |
| Quality | `dc656b2fca3e5debd541645842c8ddd4591bf7bb97a9abf84b7d36294b61e177` | `b9e45509204157bd969e8aa51fa9d091a58f3bc33421d4c8a92dca7bbdab25f7` |

Weights, configs, vocabularies and evidence remain under `models/experiments/privacy_heads_v3_20261013/exports/<tier>/<selected|terminal>/`. The selected packages are admitted for the predeclared fresh comparison, while terminal packages remain retained evidence. This establishes fitted artifact identity and frozen-state preservation, not superiority, a legacy guard pass or production promotion.

## Prospective scope and boundaries

Train privacy heads for all three v3 tiers with the encoder and pooler frozen, then freeze all three selected and terminal exports before accessing fresh-evaluation predictions or computing evaluation features. The [host controller](../evaluation/run-privacy-heads-v3.py) and [native serving adapter](../evaluation/privoke_eval/privacy_heads_v3_serving.py) implement a separate PH3 contract. The planned fresh comparison covers all three immutable v1 tiers and all three new selected v3 exports on identical wire texts with explicit protobuf semantic layers `[4]` and actual returned-layer assertions. Native category threshold remains 0.5; visibility hints remain empty. No historical final payload is opened, and no checkpoint is selected using fresh comparison outcomes.

The [new authored resource](../evaluation/datasets/privacy-heads-v3-scenarios-v1.json), [fuzzer adapter](../services/privoke-fuzzer/src/prompt_generation/privacy_heads_curriculum.py), and [host preparer](../evaluation/prepare-privacy-heads-v3.py) form the data source. They leave old frozen study modules unchanged. The adapter uses the maintained `PromptSeed` loader and explicit classification packing, shuffles only permanent TRAIN rows, and refuses replacement when the requested unique pool is exhausted. Repeated epochs are exposures, never new data. Fit consumes original rows; maintained invariant transformations are audited for leakage without silently adding training rows.

## Frozen fitting method and verified preparation

The [PH3 protocol](../evaluation/results/privacy_heads_v3_20261013/protocol.json), SHA256 `230ec5a5f6f2330e3076523e0a8b30e682f76bc87f3d4a72ea2bdd4c36a833f6`, binds final R3 data, independently copied ORIGINALs, 159 integrated source files and the host environment. Its source-closure SHA256 is `f2a46c0095aba3346154480df25a18024dd02cdb39bf0b2e9e8e244291f8a297`. Preparation used host Python 3.11.9, Torch 2.11.0+cpu, Transformers 4.57.6, float32 features, four Torch threads and feature batch 16. GPU hardware availability is not used as evidence of CUDA training.

The fixed recipe trains only the six affine head tensors, with deterministic seed 42 and dropout disabled. AdamW uses learning rate 0.001, betas (0.9, 0.999), epsilon 1e-8, zero weight decay and gradient clipping at 1.0. Every epoch visits all 6,240 TRAIN rows in a deterministic new permutation: batch 64, 98 optimizer steps, and a final batch of 32 rows. The declared budget is **minimum 30 / maximum 200 head epochs**, with patience 20. Validation-loss improvement must exceed 0.0001 to replace the selected checkpoint and reset patience; smaller changes retain the earlier selection. These are planned limits, not completed epochs.

Sensitivity and visibility class weights are inverse square roots of TRAIN frequencies, divided by their mean and clipped to [0.5, 4]. Category positive weights are square roots of TRAIN negative/positive counts, clipped to [1, 8]. The objective sums two weighted cross-entropies and category BCE: each CE sums weighted losses then divides by the selected target-weight sum; BCE averages over actual batch rows times ten categories. Validation uses those TRAIN-derived weights, with no evaluation-based calibration or checkpoint selection.

All three [cache completion records](../evaluation/results/privacy_heads_v3_20261013/cache/) exist and bind only TRAIN and validation feature tensors to the protocol, data commitments and exact encoder inventory. Extraction recorded 3.516 seconds for efficient, 4.172 for balanced and 17.078 for quality; these are feature-cache costs, not head-training time. Every cache has finite pooled features and an unchanged encoder inventory (71/39/199 encoder tensors for efficient/balanced/quality). Fresh-evaluation file metadata is committed, but no evaluation features are included.

The [independent trainer review](../evaluation/results/privacy_heads_v3_20261013/planning/prefit-trainer-review-01.md) reproduced 20 synthetic mechanics tests; actual export execution later exposed the object-equality defect described above. Its batch-one parity gap was resolved by bounded operational probes on 16 TRAIN and 16 validation examples per tier: cached batch-16 features versus native batch-one inference, original and synthetic nonzero heads, with exact sampled classifications/confidences/actions and restored ORIGINAL tensors. See the [R3 TRAIN probe](../evaluation/results/privacy_heads_v3_20261013/implementation/integrated-preflight-01/batch16-native1-parity-r3-result.json) and [validation probe](../evaluation/results/privacy_heads_v3_20261013/implementation/integrated-preflight-01/batch16-native1-validation-parity-result.json). These are mechanics checks, not trained-model quality scores. The separate native smoke used explicitly substituted ORIGINAL/synthetic fixtures; it is not admission or evaluation of completed PH3 exports.

The [root resource acceptance](../evaluation/results/privacy_heads_v3_20261013/resource-acceptance.json) authorized TRAIN/validation cache extraction against that exact protocol. The subsequent [prefit acceptance](../evaluation/results/privacy_heads_v3_20261013/prefit-acceptance.json) records independent reconciliation of actual cache hashes/shapes/targets/weights, ORIGINALs, all 159 live/retained sources, frozen inventories, native parity and 24 mechanical RPCs, then authorizes the three fixed fits. Selected and terminal checkpoints, epoch records, optimizer/RNG state, serialized exports and final frozen-encoder proofs are retained; the completed independent post-fit audit is described above.

## Data allocation and labels

Permanent scenario/template/entity/audience-frame allocation precedes rendering. There are 180 new category scenario families, allocated 120 TRAIN / 30 validation / 30 fresh evaluation, balanced over ten primary categories. Thirty auxiliary families allocate 20/5/5. Every category family renders six audiences, four narrative variants, and paired actual/control states (48 rows). Every auxiliary family renders six audiences and four variants (24 rows), of which three assert mild personal preferences/routines and one is a generic control.

| Split | Category-bearing disclosures | Matched contextual controls | Mild-personal S1, empty categories | Auxiliary S0 controls | Total / families |
| --- | --- | --- | --- | --- | --- |
| TRAIN | 2880 | 2880 | 360 | 120 | 6240 /140 |
| Validation | 720 | 720 | 90 | 30 | 1560 /35 |
| Fresh evaluation | 720 | 720 | 90 | 30 | 1560 /35 |

This prospectively amends the initial proposal that called all auxiliary rows ordinary negatives. Mild personal facts provide valid S1 coverage without downgrading genuinely sensitive categories. Report category-bearing disclosure metrics separately from all sensitive cases, which also include these S1 rows. Otherwise successful mild classification could conceal continued category failure.

Sensitivity follows the explicit provisional rubric: S0 means no actual personal disclosure; S1 covers ordinary personal preferences/routines; S2 covers personal finances, precise whereabouts and nonmedical circumstances of another minor; S3 covers actual health, identity identifiers, political/religious affiliation, criminal history or sexual information. All ten categories use complete sets. The authored child cases concern someone else's child, so include THIRD_PARTY; the authored THIRD_PARTY cases assert an adult's health, so include HEALTH. These are particular scenario facts, not universal category implications. Medical child conditions additionally include HEALTH. Each category family has a separate explicit secondary fact component with its own severity, complete categories, rationale and lineage. Secondary domain pairings vary by primary category, and slot assignment rotates across families, audiences and narrative variants. Complete valid closure takes precedence over an arbitrary50% single-label quota. Actual counts and at least15 category-set combinations per split are audited.

P0 unrestricted readership, P1 semi-public community, P2 authenticated access, P3 closed private group, P4 unshared self-only and PU unknown audience are expressed through meaningful split-specific prose. Public sensitive disclosures retain their categories/severity. The title/entity vocabulary is split-disjoint; no explicit target tokens or protobuf visibility hints enter input. Clean controls cover generic instruction, unfilled form, invented scene and absent record. Their domain mentions remain empty-category controls for this disclosure task; topic classification is a different target.

Labels are **assistant-provisional synthetic truth**, not professor confirmation or independently adjudicated human gold. The source policy is [the provisional contextual rubric](../paper/research/contextual-cascade-rubric.md), together with the prior fact-contrast labeling convention and maintained classification/action contracts. Non-sensitive controls and mild preferences allow ALLOW; category-bearing disclosures allow WARN or BLOCK under the rubric. This allowed-action set is distinct from deterministic severity-policy mapping. Three predeclared ambiguous concepts (uncertain actual record, unspecified minor age, conflicting audience) are excluded before rendering, retained in `author-review.json`, and contribute no fabricated labels or correctness denominator. No ambiguous rows are included.

## Reproduction and admission

Run in the host Python environment with Transformers/tokenizers installed:

```powershell
evaluation/.venv-v3-study/Scripts/python.exe evaluation/prepare-privacy-heads-v3.py --output evaluation/results/privacy_heads_v3_20261013/data/release-03
evaluation/.venv-v3-study/Scripts/python.exe -m unittest discover -s evaluation/tests -p test_privacy_heads_data.py
```

Exact replay uses the protocol's 159-file working-tree source closure and retained `source-bytes`, not Git HEAD alone. Pre-existing dirty implementation was preserved and excluded from the scoped task commits, so a clean clone at HEAD is not by itself the complete tested source.

The preparer refuses existing outputs, including partial failed attempts. Preserve them and choose a new immutable release directory when sources change. The manifest uses schema1 and `files.train`, `files.validation`, `files.fresh_eval`, with relative filenames, byte hashes, rows and groups. Each row includes explicit partition, text, classification, packed integer, allowed actions and complete metadata rationales/lineage. `source_files` binds generator, resource, loader, normalizer, native tokenizer logic and rubric source bytes. `audit.json` records structural coverage, exclusion membership, native lengths and deterministic regeneration. `author-review.json` records all210family rules and representative cases for independent review.

Admission fails on missing/unknown targets, packed/named disagreement, wrong lineage or source rendering, duplicate/NFKC-normalized text, cross-split entity/templates/skeletons, shared primary/secondary assertion components or coarse situation groups, native overlength or exhaustion. The fitting wrapper requires complete named targets and agreement with both packed integers before invoking the maintained loader; its permissive defaults cannot silently fill absent labels. Length checks use actual native preprocessing, the v1 efficient64-token window including start token, and all three native BERT tokenizers including both special tokens. No labeled text is truncated. No inference is performed during this audit.

Historical exclusions use an explicit authorized inventory of TRAIN/guard/development captures, both old teacher-template renderings, all three old v3 frozen streams and the pinned opaque protected union. Historical final payloads are never dereferenced. Original and every allowed invariant transform are checked. Individual primary and secondary components additionally undergo exact/normalized/entity-and-amount-skeleton historical substring checks; a new whole-row prefix cannot hide a reused assertion. Exact and skeleton checks cannot establish universal semantic novelty; independent review must inspect new family predicates, coarse situations and framing against historical authorized resource descriptions before fit. This is a new sealed synthetic short disclosure/control workload with shared general privacy concepts. It does not claim that every semantic concept is unseen or establish indirect/adversarial robustness. Structural audit `passed` alone does not replace independent admission; R3's accepted review is recorded below.

## R1 rejection and R2 prospective repairs

The first release was rejected before any fitting because its shared debt/asthma secondary assertions crossed splits, some source labels omitted health/financial closure or used ambiguous monastic study, six TRAIN primary facts repeated historical assertion substrings, and loan-record variants crossed coarse scenario boundaries. R1 bytes remain immutable in `data/`; its original source captures and failure record remain in `planning/data-build/failed-candidate-01/`.

R2 has390 explicit assertion components (180 primary,180 secondary,30 mild auxiliary) and complete split lineage. Paid political donations/funding/dues include FINANCIAL. Sexual-interest/orientation and child family-contact cases now explicitly assert nonmedical facts instead of ambiguous counselling, and religious vows explicitly assert adherence. Six historical TRAIN components were rewritten. Validation/evaluation financial loan, wage and retirement variants were replaced by distinct inheritance, policy surrender, spousal maintenance, gambling loss, insolvency and claim-payout situations. Borrowing/loan-credit obligations and employment-pay records are explicitly grouped as coarse mechanisms within TRAIN. General category concepts remain shared and are not described as novel categories.

R2 was also withheld from fitting because two secondary predicates ambiguously added a criminal fine or dental service without additional categories. R3 removes the fine from the conviction and uses a nonmedical boiler-repair debt. Allocations and labels remain unchanged; R2 data and source captures are retained under `data/release-02/` and `planning/data-build/failed-candidate-02/`.

The current [R3 manifest](../evaluation/results/privacy_heads_v3_20261013/data/release-03/manifest.json) has SHA256 `9f443b0123c65caec2fbf9aa9ff213578841f28068e094e91593e3cc7de08da1`; controllers bind that exact path and hash. The [independent R3 delta review](../evaluation/results/privacy_heads_v3_20261013/planning/prefit-data-review-03.md), SHA256 `2b00a61a248e27cfa4e96fafe0f1f98fa2bc313e453fb8170b77b14bea0f9f77`, admitted the agreed synthetic data scope, and root accepted it. Admission establishes the reviewed labels, isolation and provenance; it does not establish training completion or model quality.

Root owns the independent review, final training protocol, fitted-export freeze, fresh scoring, integration and publication. Report native errors as incorrect, sensitivity/visibility/category/packed/action/joint metrics, category micro/macro precision/recall/F1 and every category's support. Show category-positive sensitive disclosure successes and clean specificity separately, paired casewise improvements/regressions and action harms. Different historical V1 training and native packages preclude causal generation claims; synthetic fresh results alone do not establish production privacy safety.

## Fresh six-model comparison (PH3-FRESH-R1)

The [accepted analysis](../evaluation/results/privacy_heads_v3_20261013/comparison/analysis.json), SHA256 `98edb4166bf97742d9c766456ffc14b5d8af20bf205f00486fa54584183699ce`, and [independent raw audit](../evaluation/results/privacy_heads_v3_20261013/planning/fresh-audit/final.json), SHA256 `57bf0abb7e8262406784572d2b4c7bd27b3656c0b8b460d0bfde1dc797f6f4ce`, reconcile all 9,360 fresh requests, 24 separate TRAIN warmups and 37,440 fresh case files. Every model scored the same 1,560 rows from 35 families, with exact native identities, actual semantic layer `[4]`, empty wire hints and **zero runtime/transport errors**. The raw-inventory SHA256 is `020d560fb205f2622bb6ab3187a981daffcf62d70b0d3b4545a5d055e88681a2`. These are six repeated evaluations of one fixture, not 9,360 independent cases.

J is exact sensitivity/category-set/visibility plus allowed-action agreement. Category J and category exact use the 720 category-bearing disclosures. Recall uses all 810 contextually sensitive cases, including 90 mild S1 rows with empty categories; specificity uses 750 clean S0 controls. F1 is a proportion, with all ten categories supported. Base/encoder histories remain in the stage table above; the head column explicitly identifies the compared checkpoint.

| Model | Head epochs | J /1560 | Category J /720 | Category exact /720 | Macro / micro F1 | Sensitive recall /810 | Clean specificity /750 |
| --- | --- | ---: | ---: | ---: | --- | ---: | ---: |
| v1-efficient | 220 bootstrap | 51 | 0 | 0 | 0.0000 / 0.0000 | 605 | 360 |
| v3-efficient | 12 selected / 32 completed | 358 | 64 | 173 | 0.5316 / 0.5669 | 763 | 564 |
| v1-balanced | 360 bootstrap | 105 | 0 | 0 | 0.0000 / 0.0000 | 634 | 674 |
| v3-balanced | 7 selected / 30 completed | 396 | 77 | 207 | 0.5967 / 0.5924 | 757 | 520 |
| v1-quality | 520 bootstrap | 22 | 0 | 5 | 0.0149 / 0.0178 | 709 | 82 |
| v3-quality | 4 selected / 30 completed | 360 | 48 | 124 | 0.4443 / 0.4539 | 663 | 494 |

Joint correctness improves by **307/291/338 cases** for efficient/balanced/quality. Category-bearing joint correctness rises from zero for every V1 tier to **64/77/48 out of 720**; the category bottleneck is reduced but persists. The balanced V3 package has the highest joint count (396), ahead of quality (360) and efficient (358): larger capacity does not produce a monotonic gain here. Even the best category-bearing joint rate is only 77/720 (10.69%).

The gains have material costs. **Balanced clean specificity falls from 674 to 520/750** (89.87% to 69.33%), despite its higher sensitive recall. **Quality sensitive recall falls from 709 to 663/810** (87.53% to 81.85%), including category-bearing detection declining from 627 to 598/720. More total/joint correct cases therefore does not mean every privacy outcome improves.

| Model | Sensitivity /1560 | Visibility /1560 | Allowed action /1560 | Under / over restriction distance | RPC p50 / p95 ms |
| --- | ---: | ---: | ---: | --- | --- |
| v1-efficient | 725 | 211 | 924 | 218 / 747 | 12.489 / 13.441 |
| v3-efficient | 1224 | 721 | 1315 | 62 / 325 | 4.116 / 5.658 |
| v1-balanced | 911 | 243 | 1141 | 293 / 148 | 13.601 / 24.074 |
| v3-balanced | 1171 | 735 | 1254 | 96 / 349 | 3.835 / 5.119 |
| v1-quality | 284 | 258 | 695 | 153 / 736 | 35.767 / 55.189 |
| v3-quality | 1032 | 759 | 1211 | 144 / 365 | 10.095 / 13.024 |

These latency figures are descriptive full host RPC timings during a batch-one, concurrency-one accuracy loop on the admitted CPU packages; they are not a controlled SLA or a causal backend/architecture comparison. Under/over entries sum distance to the allowed-action set, with all 1,560 successful cases comparable. Full sensitivity and visibility confusion matrices, including explicit ERROR columns and class supports, are retained as `results.<model>.confusion` in the accepted analysis; each visibility truth class has 260 cases and sensitivity supports are S0/S1/S2/S3 = 750/90/144/576.

### Category precision, recall and F1

Each cell is precision / recall / F1, rounded to three decimals. Supports are the same for all six models. Full integer TP/FP/FN and unrounded values are retained under `results.<model>.categories.per_category` in the accepted analysis.

| Category | Support | V3 efficient P/R/F1 | V3 balanced P/R/F1 | V3 quality P/R/F1 |
| --- | ---: | --- | --- | --- |
| HEALTH | 180 | 0.541 / 0.778 / 0.638 | 0.704 / 0.633 / 0.667 | 0.667 / 0.267 / 0.381 |
| POLITICS | 144 | 0.509 / 0.792 / 0.620 | 0.730 / 0.375 / 0.495 | 0.709 / 0.660 / 0.683 |
| RELIGION | 108 | 0.423 / 0.556 / 0.480 | 0.632 / 0.620 / 0.626 | 0.321 / 0.491 / 0.388 |
| CRIMINAL | 108 | 0.842 / 0.444 / 0.582 | 0.622 / 0.472 / 0.537 | 0.252 / 0.593 / 0.354 |
| FINANCIAL | 108 | 0.619 / 0.120 / 0.202 | 0.716 / 0.676 / 0.695 | 0.512 / 0.611 / 0.557 |
| SEXUAL | 108 | 0.327 / 0.315 / 0.321 | 0.510 / 0.694 / 0.588 | 0.810 / 0.157 / 0.264 |
| CHILD | 108 | 0.366 / 0.546 / 0.439 | 0.394 / 0.722 / 0.510 | 0.500 / 0.148 / 0.229 |
| LOCATION | 108 | 0.568 / 0.769 / 0.654 | 0.598 / 0.593 / 0.595 | 0.756 / 0.546 / 0.634 |
| IDENTITY | 108 | 0.777 / 0.676 / 0.723 | 0.667 / 0.722 / 0.693 | 0.537 / 0.741 / 0.623 |
| THIRD_PARTY | 216 | 0.556 / 0.810 / 0.659 | 0.435 / 0.787 / 0.560 | 0.613 / 0.227 / 0.331 |

V1 efficient and balanced have zero true positives, recall and F1 for every category. Precision is undefined when no positives are predicted; their only defined precisions are zero for efficient POLITICS (7 false positives) and balanced LOCATION (2 false positives). V1 quality has the following nonzero category results; all remaining categories have zero recall/F1, with precision undefined except IDENTITY precision zero (2 false positives).

| V1 quality category | Support | P/R/F1 |
| --- | ---: | --- |
| FINANCIAL | 108 | 0.231 / 0.028 / 0.050 |
| LOCATION | 108 | 0.057 / 0.074 / 0.064 |
| RELIGION | 108 | 0.400 / 0.019 / 0.035 |

### Paired improvements and regressions

Direction is selected V3 minus same-tier V1 on identical cases. I/R are improved/regressed correctness; under/over worsenings count cases whose action-distance component increases, not a unique-case union. All action comparisons have denominator 1,560 and zero error pairs. Full per-component and category-bearing/S1-inclusive paired tables remain in `paired_v3_minus_v1` in the accepted analysis.

| Tier | Joint I/R; net | Category J I/R; net | Action I/R; net | Under / over worsenings |
| --- | --- | --- | --- | --- |
| efficient | 318/11; +307 | 64/0; +64 | 504/113; +391 | 43 / 84 |
| balanced | 313/22; +291 | 77/0; +77 | 356/243; +113 | 71 / 182 |
| quality | 348/10; +338 | 48/0; +48 | 633/117; +516 | 105 / 161 |

Every tier improves net joint correctness while regressing individual joint cases and actions. No confidence interval or significance claim is inferred from the repeated renditions. The newly sealed fixture remains assistant-provisional short synthetic disclosure/control data; these native packages have different training histories, capacities, tokenization and backends. Results establish neither a causal generation/pretraining effect nor independently validated real-world privacy safety. Historical V123 DEVELOPMENT scores retain their separate scope and are not pooled with this fresh fixture.

## Retained evidence and reproducibility

Local ignored records are retained under `evaluation/results/privacy_heads_v3_20261013/data/` and `planning/`. No model weights are generated by data preparation. Trained weights, independently pinned ORIGINALs, checkpoints and export provenance are retained under `models/experiments/privacy_heads_v3_20261013/`.

R3 data admission, prefit acceptance, all three caches/fits, all six selected/terminal exports, the complete fresh six-model comparison and independent raw-response reconciliation are complete. Comparison servers were stopped and port 50371 was verified free by the execution owner. Original study records, failed starts, the three original export failures, partial selected assets and corrective proofs remain retained; no model was promoted.
