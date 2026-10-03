# Prospective training-data expansion protocol

## Question and scope

Test whether adding official training-split PII examples improves the frozen annotation-presence profiles' coverage while preserving their clean-prompt specificity. The target remains **annotated PII presence**. This experiment does not train or evaluate contextual sensitivity, severity, visibility, categories, or policy action, and it does not replace the original semantic classifier.

Use only official training splits from pinned Nemotron-PII and core Meddies English, after the audits below. Do not add PIIMB benchmark-test rows. PIIMB's card explicitly tells users to avoid fine-tuning on test data. Existing PIIMB-test-derived fitting is exploratory within-corpus evidence and must not be reported as an independent benchmark result. Keep PIIMB only for creating an opaque exclusion index from the original protected selection and for the already approved fixed training/validation controls.

No dataset download, preprocessing run, or fit is authorized by this protocol document alone. First obtain review of the protected-index derivation and source manifest; then implement under the approved scope. Do not read the locked development or final JSONL files during preparation, fitting, validation selection, or internal checks.

## Preflight gates

Before reading candidate rows, write a manifest that freezes each source's repository ID, exact commit SHA, original split/config, license text and attribution obligations, schema, annotation definition, documented size, source ID and group fields, expected language/domain, and inclusion rationale. Read the card/license at the exact commit, not only its mutable default branch. Confirm the selected Nemotron revision really contains an official `train` split and that the pinned Meddies revision's core English `train` view is not a derived MIX/BIOES view containing Nemotron or AI4Privacy. Preserve any noncommercial, attribution, redistribution, and derivative-use restrictions in the run record and resulting artifacts.

Fail closed if a pin is unavailable, the field mapping differs from the manifest, the canonical source ID/group mapping cannot be checked against protected rows and existing training/validation/bootstrap exclusions, labels are not parseable without guessing, or a license term conflicts with intended handling. Do not silently switch revisions, splits, or label meanings. Record a blocker and stop before row serialization. Distinguish known source-document grouping from unverified template independence; do not claim the latter.

## Protected 1,000-row exclusion index

Reproduce only the original protected-row selection from the pinned PIIMB source using the exact balanced full-scan loader and original seed `3102026`. This is a one-time source-key derivation, not a training or scoring pass. Do not branch on development/final assignment and do not open any file under `evaluation/results/locked-public/`, including `final.jsonl`.

The derivation emits exactly 1,000 opaque records' keys and aggregate bookkeeping: SHA-256 digests with domain-separated prefixes for source ID, source group ID, and normalized text key; source revision/seed/algorithm identifiers; aggregate counts; and a digest over the sorted key set. It must not emit selected text, raw IDs, labels, categories, predictions, probabilities, or scores. Protect the full 1,000-row selection, regardless of later partition. Keep the key index in a restricted preparation location outside model artifacts, scorer outputs, and public reports. Do not log candidate raw text while comparing keys.

Before candidate rows are eligible, verify the selection count is exactly 1,000, all three key families are present where source provenance permits, and rerunning the pinned selection yields an identical digest. If the original sampler cannot be reproduced from the documented source/seed alone without consulting a locked partition, stop and request a reviewed alternative; never recover it by parsing the locked files.

## Candidate loading, filtering, and units

Load only:

- Nemotron-PII's official pinned `train` split, preserving `uid`, `domain`, `document_type`, `document_format`, `locale`, `text`, and the original spans and text tags.
- Core Meddies `english` configuration, official pinned `train` split, preserving `id`, `raw`, original JSON label mapping, language, document type, and format. Exclude any merged/derived view whose upstream composition includes Nemotron or AI4Privacy.

For every candidate, construct domain-separated ID, group, and normalized-text keys. Exclude any row whose source ID, group, or normalized text matches the protected selection, unchanged current train (3,832 rows), unchanged validation (968 rows), or the 43-row bootstrap exclusion. Also remove duplicate normalized text and exclude all rows for an ambiguous source ID that maps to multiple distinct normalized texts. Preserve source, revision, original split, annotations, and source family. Report exclusions by reason and source as counts only. Neither locked partition may be read to build these exclusions.

For Nemotron, canonicalize each 32-hex-digit `uid` to group key `nemotron-pii:<lowercase-uid>`. This must match the PIIMB loader's parent group convention and exclude every sentence from a parent document if one sentence was protected. PIIMB source IDs take the form `piimb:nemotron-pii:<uid>_s15`; check known ID aliases as well as canonical group and normalized-text hashes. Do not namespace the same parent UID differently by dataset name. For Meddies, group by verified source document ID; when the only stable lineage available is a template signature, use the complete tuple `(document_type, document_label, text_format, edge_case)` as a conservative group key. Do not substitute row order or synthetic row index. If Meddies source-document identity is missing, stop. Group checks establish known document separation, not semantic template independence.

### Annotation rules

Use whole source documents only. A row with one or more valid annotated spans is a positive example for annotated PII presence. Rows with empty, missing, or ambiguous annotations are unknown and excluded from added-source binary fitting. Do not create negative examples or chunks in this first experiment. Retain existing PIIMB-derived clean rows as the clean reference, while candidly reporting that this reference comes from a within-corpus benchmark-test source and is not an independent external clean set.

Sentence/paragraph chunking is out of scope and requires a separate reviewed protocol. Never label unannotated chunks from a positive document as clean negatives.

Meddies' current adapter is positive-only and maps entity-valued JSON labels to positive. Target 3,000 explicit positive English training rows plus 1,000 group-held-out Meddies diagnostic rows, if exact-pin audit verifies enough eligible examples and groups. The diagnostic is positive-only; specificity is not estimable. These are targets, not observed counts. Never fill missing labels with `false` or synthesize negatives from absent JSON entities.

## Sampling and fit plan

Freeze these sizes and seeds before preprocessing or fitting: a 20,000-row training cap = unchanged 3,832-row existing train reference + up to 13,168 Nemotron positive whole documents + up to 3,000 Meddies positive whole documents. Hold out 1,000 Nemotron groups and 1,000 Meddies groups separately for source diagnostics; those are outside the training cap. Use sampling seed `8102026`, heldout-group seed `9102026`, and existing fitter seed `7102026`. If audited supply is smaller, record pre-fit availability/exclusion reasons and use fewer rows; never duplicate or paraphrase to fill a cap. Record counts by source, language, domain, label, and format.

Make group-disjoint training and internal-heldout partitions independently within each source. The unchanged 968-row validation partition is the only C/threshold selection control and must remain byte-for-byte unchanged. The 1,000 Nemotron and 1,000 Meddies rows are report-only source diagnostics; neither selects C or threshold. No candidate-source development tuning is allowed.

Use the same three frozen profile families (efficient, balanced, quality), feature/vectorizer and artifact contracts as the current sparse presence path. Fit only C `{1, 10}` for each profile with `class_weight="balanced"` and fitter seed `7102026`, adding only verified positive whole-document examples to the existing train set. Select C on the unchanged 968-row validation under recall floor `0.90`; rank eligible candidates by balanced accuracy, specificity, recall, then lower C. Select threshold by maximum specificity subject to recall at least `0.90`, then higher recall and threshold as fixed tie-breaks. Freeze each profile, threshold, artifact, and manifest before development scoring. New source diagnostics are report-only. Do not add C values, change policy after development, or run fuzzer updates. Compare each candidate profile with the corresponding current-profile control on matched validation rows using the same metric implementation.

Keep source-stratum metrics separate: report examples, positive and verified-negative denominators, exact-match accuracy, recall, and specificity for the fixed validation control, Nemotron heldout, and Meddies heldout. Meddies has positives only; specificity is not estimable. Nemotron empty-span rows remain unknown and cannot enter negative metrics without separate exhaustive-label evidence. Report confidence intervals and group counts where supported; explain synthetic-source and label-taxonomy limits. Do not pool rates into one generalization claim.

## Integrity checks and stop criteria

Before fitting, require all of the following:

1. Exact source revision/split/license/schema match to the reviewed manifest.
2. Exactly 1,000 protected source-selection keys, with reproducible digest and no access to locked partition files.
3. Zero candidate overlap with protected source IDs, groups, and normalized text; zero duplicate normalized-text keys across train and heldout; zero group overlap across partitions.
4. Positive labels trace to nonempty validated annotations. Negative labels trace to explicit clean truth or documented exhaustive annotation plus the approved audit; unknown labels are excluded.
5. All profile sampling, C values, training seed, thresholds/selection rules, per-source caps, and reporting strata frozen before development inference.
6. No raw clinical or PII-bearing text in logs, manifests, model artifacts, or shareable results. Retained prediction evidence may contain opaque IDs, labels, probabilities, denominator counts, and verified annotation offsets only. Keep any unavoidable raw RPC evidence in restricted ignored storage and out of shareable reports.

Stop without fitting if protected-index generation cannot be reproduced, a source's official train split cannot be validated, overlap or grouping is unresolved, label exhaustiveness cannot be established for a negative, or licenses prohibit the intended use. Retain a count-only audit record that does not expose raw text or locked data. Any plan to use locked development or final data is a separately gated evaluation after the model and analysis are frozen.

## Primary sources and project contracts

- PIIMB benchmark composition and explicit test-use guidance: [PIIMB dataset card](https://huggingface.co/datasets/piimb/pii-masking-benchmark).
- Nemotron source card and split metadata (verify the exact repository pin before use): [Nemotron-PII](https://huggingface.co/datasets/nvidia/Nemotron-PII).
- Meddies source card: [Meddies PII](https://huggingface.co/datasets/Meddies/meddies-pii); paper, submitted 2026-09-11: [Meddies-PII: A Multilingual Framework for Personally Identifiable Information Extraction in Clinical De-identification](https://arxiv.org/abs/2609.12544).
- Repository source pins and adapters: [datasets.py](../../evaluation/privoke_eval/datasets.py).
- Current locked-reading preparation implementation (read for behavior only; do not execute for this protocol): [prepare-representation-study.py](../../evaluation/prepare-representation-study.py).
- Frozen profile fitting behavior: [fit-presence-profiles.py](../../evaluation/fit-presence-profiles.py).
- Label and split limitations: [Evaluation README](../../docs/README.Evaluation.md), [representation protocol](representation-protocol.md), [model-refactor protocol](model-refactor-protocol.md).
