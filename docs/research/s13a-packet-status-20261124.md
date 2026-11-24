# Stage 13a packet status, 24 November 2026

Status: **tooling and drafts ready; no prompt, label or annotation exists, and no agent produced any.** This note records what 13a-0 and 13a-1 built, which decisions are provisional, and what only the user can do.

## What exists

| Item | Location |
| --- | --- |
| Marker decision (`fresh_eval-folio-NN`) | `docs/research/annotation-marker-decision-20261124.md` |
| Writer brief (draft, no examples) | `docs/research/s13a-writer-brief-20261124.md` |
| Guideline v2 (draft, **no worked examples**) | `docs/research/annotation-guideline-v2-20261124.md` |
| Pre-registration template | `docs/research/s13a-preregistration-20261124.md` |
| Freeze of the fresh set | `evaluation/annotation/fresh_set.py` (`--dry-run`, `--check-quotas`) |
| Schema v2 and validator | `evaluation/annotation/annotation_schema.py` (`--validate <sheet> --schema 2`) |
| Sampler, quota cells, packet manifest, verification | `evaluation/annotation/sample_annotation.py` (`--stratify-by quota_cell`, `--fail-on-marker`, `--verify-against`) |
| Agreement | `evaluation/annotation/compute_iaa.py` (`--schema 2`, Fleiss, `--min-kappa --fields`, `--check-adjudication`) |
| Scoring (refuses without a freeze) | `evaluation/annotation/score_privoke.py` |
| Record, freeze summary, re-derivation | `evaluation/annotation/human_eval_report.py` |
| Commit-order proof | `evaluation/annotation/check_order.py` |

## Provisional decisions

The plan's defaults are applied and marked provisional until the user answers: D1 (writers), D2 (two annotators and one adjudicator), D4 (ethics), D9 and D12. D3 (360 + 30), D5 and D6 use their defaults.

## Worked examples

**Not written.** The guideline ships with a marked placeholder (decision D12). The pilot cannot start until the user supplies the examples and their labels, or states "no examples".

## Quota rules as implemented

`fresh_set.py --check-quotas` enforces: at least 390 usable prompts, at least 45% declared sensitive, at least 20 prompts for each of the ten categories. It reports the counts per category, audience and cell, and enforces no per-cell minimum.

## Remains user-only

D1, D2, D4, D9 and D12; recruiting and briefing writers and annotators; the declarations; collecting prompts into the Git-ignored `evaluation/results/s13a/raw/`; all labelling and adjudication; dated guideline revisions.
