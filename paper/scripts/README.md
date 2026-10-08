# Paper figures

Run from the repository root with Python and the dependencies in `paper/requirements.txt`:

```powershell
python paper/scripts/plot_paper_results.py --validate-only
python paper/scripts/plot_paper_results.py --overwrite
```

The first command checks the tracked aggregate reports without producing files. The second generates four 450-dpi PNGs, matching editable SVGs and `paper/figures/results-figure-manifest.json`. The PNGs are referenced by `paper/main.tex`; outputs go alongside the existing figures. Without `--overwrite`, the script refuses to replace its existing named outputs. Other files in the directory are preserved.

| Output stem | Evidence | Plot scope |
| --- | --- | --- |
| `results-layer-ablation` | `paper/research/development-results.md` | Frozen original rules/balanced model, 502 development prompts; recall/specificity derived from counts. |
| `results-update-outcomes` | `docs/model-quality-study-index-20261006.md`, `docs/fuzzer-model-results-20261006.md` | Six contextual grids, 126 attempts. Rejected, accepted-ineligible and eligible outcomes are mutually exclusive; 15 eligible attempts are a subset of 59 accepted updates. No candidate retained. |
| `results-cascade-errors` | `docs/contextual-cascade-results.md` | Original balanced control with revised rules, 502 development prompts; additional misses accompany fewer annotation-negative detections. Panels use different count scales and disclose both class denominators. |
| `results-external-specificity` | `docs/PII-dataset-analysis.md` | Expanded sparse models minus matched fitted controls on reused validation; reported descriptive 95% source-group intervals. |

The generator parses only these named aggregate Markdown documents. It does not open raw prompts, predictions, model artifacts, or the protected final partition. It recomputes rates and checks reported percentages, class denominators, nested counts and interval consistency before writing. The manifest preserves plotted counts, source hashes normalized to LF, output hashes and the plotting-script/Matplotlib version. A changed source report changes the manifest; it does not silently become final-test evidence.

Layer and cascade uncertainty is not invented; cascade paired intervals remain uncomputed. External intervals are selection-conditioned, using 2,000 paired source-group bootstrap resamples over 714 groups, seed 10102026. The script plots the report's rounded interval endpoints and recomputes point changes from counts; it does not recompute bootstrap intervals or claim significance.

`fig1.py` and `fig2.py` draw hypothetical accuracy/runtime trends. Their existing outputs are retained but are not used as measured evidence in the main paper. `plot_external_pii_results.py` remains available for its separate hash-bound external aggregate-JSON comparison; its fresh-directory workflow is unchanged.
