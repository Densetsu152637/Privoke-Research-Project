# Results figures integration — 8 October 2026

The author requested Python-generated diagrams in the existing script/figure folders and references in `main.tex`. Root wrote `paper/scripts/plot_paper_results.py` and its README, generated four 450-dpi PNG/SVG pairs in `paper/figures`, added four figure environments and a Discussion section, and preserved all six existing results tables and the entire Introduction.

Input branch/base: `feat/dev-testing`, `c25b6250a388a563694b95d2e9670ca221988e4f`. Final manuscript SHA-256: `08aaf422e82ca430e558c3379b6144e31bfc437d35713dc37eaba828401f69ff`. Plotting script SHA-256: `1a838ad7f8e38df7a2e6d2537f8df68f32712631f262ed7fbcb0f96ad2218067`.

## Questions and evidence

| Question | Figure | Source and interpretation boundary |
| --- | --- | --- |
| How do layers trade recall for specificity? | `results-layer-ablation` | Frozen original balanced/rule comparison in `development-results.md`, 502 prompts, 264 positive/238 negative. Binary annotation presence, not action accuracy. |
| Does publication establish a useful update? | `results-update-outcomes` | Six contextual grids in the study index and initial-grid report: 67 rejected, 44 accepted-ineligible and 15 eligible, with zero retained. Eligibility is nested inside acceptance; historical and separate presence updates are excluded. |
| What does cascade gating cost? | `results-cascade-errors` | Original balanced control with revised rules, `docs/contextual-cascade-results.md`: FP 185 to 63/69/79 and FN 17 to 22. Panel scales differ and are disclosed; paired uncertainty remains uncomputed and safe actions are unestablished. |
| Does expanded data consistently improve specificity? | `results-external-specificity` | `docs/PII-dataset-analysis.md`: count-derived differences and reported 95% source-group intervals on reused validation. Model/threshold selection conditions the comparison; these are descriptive, not final or causal estimates. |

`paper/figures/results-figure-manifest.json` retains the exact plotted inputs, five normalized-LF source hashes, all eight output hashes, bootstrap scope, script hash and Matplotlib version. The script opens only these named aggregate Markdown reports and does not access raw examples, predictions, model files or protected final data. Existing hypothetical-trend figures and scripts remain intact and unreferenced as measured evidence.

## Acceptance and checks

- `python paper/scripts/plot_paper_results.py --validate-only` passed; generation and explicit regeneration passed on Python 3.13 / Matplotlib 3.10.9. The initial table selector encountered two cascade tables headed `Profile`; selection was repaired to require the development table's specific loss-column header before any outputs were written.
- Root independently verified all five source hashes and eight output hashes, image dimensions, original-table/Introduction preservation, figure-path existence, unique/resolved LaTeX labels, balanced braces/environments and `git diff --check`.
- Root inspected all four actual PNGs. Initial hatched-bar labels interfered with hatch marks; text backgrounds were added, the chart was regenerated and the corrected pixels reinspected. Current plots have readable labels and no observed clipping/overlap. Three plots are designed for one column; the cascade is a two-column figure.
- Research critic `FIGURES-RESEARCH-REVIEW-20261008` reviewed the stable manuscript/script hashes above and reported no consequential findings. Numerical, provenance and caption/discussion scope checks passed. Root accepts that review; pixel inspection was a separate root check.
- Built-in LaTeX compilation again failed during preview preparation with `windows sandbox: helper_unknown_error: setup refresh had errors`. Final typeset page placement remains unverified; no compilation success is claimed.

The pre-existing user edit to `paper/reference.tex` is preserved at SHA-256 `22c7172536c08d2a1afdaab9977cf746be59c796576d6c040e5f352ee0a238cc`. No experiments, dataset/model changes or commits occurred. Updated custom-workflow instructions and project instructions were read; applicable companion files were identical. Exact cumulative session/worker token telemetry was unavailable.
