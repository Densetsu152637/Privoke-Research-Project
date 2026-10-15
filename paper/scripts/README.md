# Paper figures

## Current native product and recognizer comparison (14 October 2026)

```powershell
python paper/scripts/plot_pipeline_comparison.py --validate-only
python paper/scripts/plot_pipeline_comparison.py --overwrite
```

This generator reads only the tracked compact aggregate
`paper/research/pipeline-comparison-20261014.json`. It requires no model, raw
prompt, ignored study directory, service or protected-final data, so a clean
checkout can reproduce the publication figures. Source analysis, protocol and
independent review commitments are retained in the aggregate and explained in
`paper/research/pipeline-comparison-20261014.md`.

It validates six-package denominators, binary confusion counts, paired
improvements/regressions, action-case accounting, zero-error coverage and
actual product execution scope. Outputs are 450-dpi PNG plus vector SVG/PDF:

| Output stem | Meaning |
| --- | --- |
| `results-pipeline-v1-v3` | First-pass joint/action correctness and under/over-enforced case counts on 1,560 reused contextual cases. Native packages differ; this is a full product comparison. |
| `results-pipeline-v1-v3-cost` | Descriptive first-pass host RPC median/p95 and server-process peak RSS. Fixed ordering, native backends and regex skips prevent a controlled speed claim. |
| `results-pipeline-presidio-reference` | All six product packages and configured Presidio on the same 810 contextual-sensitive/750 clean targets. Entity versus contextual ontology remains deliberately different; unsupported joint/action/audience/category tasks are unmeasured. |

`results-pipeline-comparison-manifest.json` pins the aggregate, generator,
Matplotlib/NumPy versions and all output hashes. Presidio direct-analyzer timing
is excluded from the product-cost chart. No published sanitization score or
historical 502-row annotation-presence score shares these axes. The external
paper context table retains each work's own metric and population. Older
generators and measured/hypothetical distinctions below remain unchanged.

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

## Six hour fuzzer trajectories

Run from the repository root with Python and Matplotlib from
`paper/requirements.txt`:

```powershell
python paper/scripts/plot_long_fuzzer_trajectories.py --validate-only
python paper/scripts/plot_long_fuzzer_trajectories.py --overwrite
```

The plot reads only the tracked aggregate evidence in
`docs/evidence/long-fuzzer-20261009/`: `summary.json` supplies checkpoint
counts and rates, and `provenance.json` supplies actual checkpoint times and
archive commitments. The validator checks the independent audit, source hashes,
endpoint denominators, confusion-count arithmetic and per-profile timing before
plotting. It does not read the source dataset, per-example predictions, training
prompts, row IDs or model weights.

The script writes `paper/figures/results-long-fuzzer-trajectories.png`, its
editable SVG counterpart and
`paper/figures/results-long-fuzzer-trajectories-manifest.json`. The four panels
show semantic recall, semantic specificity, pipeline recall and pipeline
specificity for the three profiles. The x-axis uses measured checkpoint times
relative to a baseline measured just before each profile's window. The final
measurements occur after 120 minutes because checkpoint evaluation finished
after the elapsed windows. Without `--overwrite`, the script refuses to replace
its named outputs.
