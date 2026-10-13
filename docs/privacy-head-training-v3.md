# Privacy-head training and fresh v1 comparison (PH3-R1)

Status: prospective protocol and R2 data preparation; training and comparison results **PENDING**. This record does not claim trained models, superiority, independent human labels or promotion. Study ID: `privacy_heads_v3_20261013`, 13 October 2026, Sydney.

Exact user request: “Can you then train V3s heads for privacy? This can be a lengthy training session. Once this is done run a fresh eval comparing them with V1”.

The prior [V123-D1 diagnostic](model-generation-comparison-20261013.md#follow-up-why-v1-balanced-appears-stronger-v123-d1) found category collapse on sensitive disclosures. New head training therefore needs direct complete category supervision, meaningful sensitivity and visibility labels, and a genuinely new authored comparison. That observation does not establish which training or architecture choice caused the earlier failure.

## Prospective scope and boundaries

Train privacy heads for all three v3 tiers with the encoder and pooler frozen, then freeze every terminal export before accessing fresh-evaluation predictions or computing evaluation features. The host trainer and native serving adapter are separate implementation work. The planned fresh comparison covers all three immutable v1 tiers and all three new v3 exports on identical wire texts with explicit protobuf semantic layers `[4]` and actual returned-layer assertions. Native threshold remains0.5; visibility hints remain empty. No historical final payload is opened, and no checkpoint is selected using fresh comparison outcomes.

The [new authored resource](../evaluation/datasets/privacy-heads-v3-scenarios-v1.json), [fuzzer adapter](../services/privoke-fuzzer/src/prompt_generation/privacy_heads_curriculum.py), and [host preparer](../evaluation/prepare-privacy-heads-v3.py) form the data source. They leave old frozen study modules unchanged. The adapter uses the maintained `PromptSeed` loader and explicit classification packing, shuffles only permanent TRAIN rows, and refuses replacement when the requested unique pool is exhausted. Repeated epochs are exposures, never new data. Fit consumes original rows; maintained invariant transformations are audited for leakage without silently adding training rows.

## Data allocation and labels

Permanent scenario/template/entity/audience-frame allocation precedes rendering. There are180 new category scenario families,120TRAIN/30validation/30fresh-evaluation, balanced over ten primary categories. Thirty auxiliary families allocate20/5/5. Every category family renders six audiences, four narrative variants, and paired actual/control states (48rows). Every auxiliary family renders six audiences and four variants (24rows), of which three assert mild personal preferences/routines and one is a generic control.

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
evaluation/.venv-v3-study/Scripts/python.exe evaluation/prepare-privacy-heads-v3.py --output evaluation/results/privacy_heads_v3_20261013/data/release-02
evaluation/.venv-v3-study/Scripts/python.exe -m unittest discover -s evaluation/tests -p test_privacy_heads_data.py
```

The preparer refuses existing outputs, including partial failed attempts. Preserve them and choose a new immutable release directory when sources change. The manifest uses schema1 and `files.train`, `files.validation`, `files.fresh_eval`, with relative filenames, byte hashes, rows and groups. Each row includes explicit partition, text, classification, packed integer, allowed actions and complete metadata rationales/lineage. `source_files` binds generator, resource, loader, normalizer, native tokenizer logic and rubric source bytes. `audit.json` records structural coverage, exclusion membership, native lengths and deterministic regeneration. `author-review.json` records all210family rules and representative cases for independent review.

Admission fails on missing/unknown targets, packed/named disagreement, wrong lineage or source rendering, duplicate/NFKC-normalized text, cross-split entity/templates/skeletons, shared primary/secondary assertion components or coarse situation groups, native overlength or exhaustion. The fitting wrapper requires complete named targets and agreement with both packed integers before invoking the maintained loader; its permissive defaults cannot silently fill absent labels. Length checks use actual native preprocessing, the v1 efficient64-token window including start token, and all three native BERT tokenizers including both special tokens. No labeled text is truncated. No inference is performed during this audit.

Historical exclusions use an explicit authorized inventory of TRAIN/guard/development captures, both old teacher-template renderings, all three old v3 frozen streams and the pinned opaque protected union. Historical final payloads are never dereferenced. Original and every allowed invariant transform are checked. Individual primary and secondary components additionally undergo exact/normalized/entity-and-amount-skeleton historical substring checks; a new whole-row prefix cannot hide a reused assertion. Exact and skeleton checks cannot establish universal semantic novelty; independent review must inspect new family predicates, coarse situations and framing against historical authorized resource descriptions before fit. This is a new sealed synthetic short disclosure/control workload with shared general privacy concepts. It does not claim that every semantic concept is unseen or establish indirect/adversarial robustness. Structural audit `passed` explicitly leaves independent admission pending.

## R1 rejection and R2 prospective repairs

The first release was rejected before any fitting because its shared debt/asthma secondary assertions crossed splits, some source labels omitted health/financial closure or used ambiguous monastic study, six TRAIN primary facts repeated historical assertion substrings, and loan-record variants crossed coarse scenario boundaries. R1 bytes remain immutable in `data/`; its original source captures and failure record remain in `planning/data-build/failed-candidate-01/`.

R2 has390 explicit assertion components (180 primary,180 secondary,30 mild auxiliary) and complete split lineage. Paid political donations/funding/dues include FINANCIAL. Sexual-interest/orientation and child family-contact cases now explicitly assert nonmedical facts instead of ambiguous counselling, and religious vows explicitly assert adherence. Six historical TRAIN components were rewritten. Validation/evaluation financial loan, wage and retirement variants were replaced by distinct inheritance, policy surrender, spousal maintenance, gambling loss, insolvency and claim-payout situations. Borrowing/loan-credit obligations and employment-pay records are explicitly grouped as coarse mechanisms within TRAIN. General category concepts remain shared and are not described as novel categories.

The R2 manifest is `data/release-02/manifest.json`; controllers must bind that exact path and hash, rather than the rejected R1 manifest. Independent review and root admission remain required before fitting.

Root owns the independent review, final training protocol, fitted-export freeze, fresh scoring, integration and publication. Report native errors as incorrect, sensitivity/visibility/category/packed/action/joint metrics, category micro/macro precision/recall/F1 and every category's support. Show category-positive sensitive disclosure successes and clean specificity separately, paired casewise improvements/regressions and action harms. Different historical V1 training and native packages preclude causal generation claims; synthetic fresh results alone do not establish production privacy safety.

## Retained evidence and pending work

Local ignored records are retained under `evaluation/results/privacy_heads_v3_20261013/data/` and `planning/`. No model weights are generated by data preparation. Preserve future weights and independently pinned originals under `models/experiments/privacy_heads_v3_20261013/`.

Data authoring/admission: structural checks available; independent review pending. Three v3 fits: pending. Frozen exports: pending. Fresh all-six-model comparison: pending. Final result and limitations will be recorded here after actual execution.
