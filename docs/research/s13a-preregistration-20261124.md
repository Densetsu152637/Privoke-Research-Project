# Stage 13a pre-registration (template, 24 November 2026)

Status: **template, not yet filled.** Root commits the filled version together with `docs/research/s13a/set_manifest.json` in 13a-3, before any sheet is sent. Values marked *provisional* follow the defaults of the Stage 13 plan while the user's answers to D1, D2, D4 and D12 are outstanding.

## Question

Does PriVoke's accuracy hold against ground truth that no developer label influenced? Scope label of the human labels: `human ground truth`. The record claims agreement at the reported rate with adjudicated labels from N annotators, and never "validated".

## Fixed before annotation

| Item | Value |
| --- | --- |
| Set | the frozen fresh set; `sha256_jsonl` and `n` in `set_manifest.json`; source kind: writers (provisional, D1) |
| Sizes | 360 main items plus a 30-item pilot (D3) |
| Sampling | `sample_annotation.py --stratify-by quota_cell --fail-on-marker`; per-cell floor 1; main and pilot disjoint |
| Seed | `20261024` (the sampler default; the user confirms or replaces it before 13a-3) |
| Annotators | 2 annotators and 1 adjudicator, none of whom wrote PriVoke labels or rubrics (provisional, D2); agreement per pair by Cohen's kappa, Fleiss' kappa if three or more |
| Fields | `sensitive`, `subject`, `audience`, `categories`, `action` (schema v2, guideline v2 dated 2026-11-24 or later) |
| Pilot gate | kappa at least 0.6 for `sensitive`, `audience` and `action`; one revision and one repeat if not (`compute_iaa.py --min-kappa 0.6 --fields sensitive,audience,action`) |
| Adjudication | a human decides every disagreement; `compute_iaa.py --check-adjudication` must exit 0 |
| Freeze | label-only files and `iaa.json` are committed before any PriVoke run on these items |

## Arms and metrics

| Arm | Layers | Scope label |
| --- | --- | --- |
| `product` | regex, NER, semantic (V3 balanced, shipped defaults) | `product pipeline (in-process)` |
| `semantic_only` | semantic | `LLM-only (semantic)` |

Each request names its layers explicitly and the scorer asserts the executed layers; a layer error aborts the arm. Positive class: `sensitive = yes`; predicted positive: action WARN or BLOCK. Metrics: precision, recall, specificity, F1, under-enforcement and over-enforcement (a PriVoke action less or more strict than the reference `action`). Both enforcement rates are reported with two denominators: over **all scored items**, and conditionally, **under-enforcement among items whose reference action is WARN or BLOCK** and **over-enforcement among items whose reference action is ALLOW**. Each metric carries a Wilson interval and a cluster bootstrap over quota cells (1,000 replicates, seed 20261124; F1 has the bootstrap interval only). Per-category recall and per-audience recall and specificity are reported.

## Analysis order

1. Validate every returned sheet (`annotation_schema.py --validate <sheet> --schema 2`).
2. Pilot agreement, then the guideline revision if the gate fails.
3. Main-round agreement (`compute_iaa.py --schema 2`) and adjudication.
4. Freeze commit with `human_eval_report.py freeze`.
5. Run `score_privoke.py --smoke` once, then score both arms with `score_privoke.py`, under the host lock.
6. Build and check the record (`human_eval_report.py build`, then `--check`), then `check_order.py`.

## Not tuned against PriVoke

No template, brief, guideline, threshold or metric changes after any PriVoke output on these items has been seen.

## To be filled by the user

- Seed confirmation: ____________
- Names of the annotators and adjudicator are kept outside the repository; the count goes in the record.
- Ethics (D4) status: ____________
- Examples (D12) status: ____________
