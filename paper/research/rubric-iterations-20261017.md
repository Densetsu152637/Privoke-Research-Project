# Rubric-guided paper iterations — 17 October 2026

**Goal:** “In a loop, iterate by improving the paper by applying suggested feedback from the rubric evaluation, and then editing the rubric evaluation to reflect the new state of the paper. Use the astra subagent to do this and stop when the weekly usage hits 20% (you have 31% currently)”.

The user's threshold is **20% remaining**, equivalent to **80% used** in the exposed weekly quota. Quota is shared across the account, not a token budget for this manuscript or agent. Read `get_usage_limits` at milestones; notify root at 79% used/21% remaining and stop substantive work immediately at 80% used/20% remaining. Preserve written work and report the actual checkpoint. This is a polling-based control, not a hard runtime cap. Do not consume allowance for its own sake or repeat edits that do not materially improve the paper. Root reviews each stable iteration before authorizing the next.

The sole writer remains the user-requested GPT-6 Astra agent at high reasoning. No descendants, new studies, inference, fitting, scoring, protected-data access or external-source research are authorized. [REWRITE_SCOPE.md](../REWRITE_SCOPE.md) fixes the seven evidence units, all retained arms and adverse findings. The supplied journal template and custom features, exact RQs, normal typography, ten-page complete-paper limit and prohibition on appendices remain binding. The user's untracked template is preserved unchanged. Root owns Git finalization; the writer does not commit or push.

## Iteration 1 — Contribution mapping and bounded implications

**Input:** `docs/paper` at `a70be124bda089752a77cf8a1ce7e14c08184a7d`, tracked clean, user template untracked. Baseline source SHA-256 `df437e6c074fda23882040487268adb3db66a368fe75d0e9efdca32b94c4a7cb`; PDF `407b51a91dbed06a8db87c0636f560ae30a79f3794272f62c16ff2585ba155c4`. The current [rubric evaluation](../rubric-evaluation.md) selected former **Priority 1** (explicit design implications) and **Priority 5** (contributions linked to RQs and prior work). This bounded iteration excludes the other four recommendations until root reviews the result.

### Changes and reasoning

Six paragraphs were replaced, adding a net 118 whitespace-counted words while keeping the established connected explanatory style:

- **Introduction:** replaced generic lifecycle contribution wording with the three decisions and their evidence outputs; after the unchanged RQs, identified the connected prediction/enforcement account, matched retention evidence and separation of report privacy from estimation/selection error.
- **Related Work:** replaced the general closing summary with an explicit RQ-to-strand mapping: local sanitization/request consequences for RQ1, negative flips/version-bound acceptance for RQ2, repeated reporting/finite privacy/estimation/admission for RQ3. Established primitives are not claimed as new and incompatible measures do not support superiority.
- **Discussion VIII-A:** used the retained 139 corrected unnecessary restrictions and eighteen lost correct actions to explain why early rules should be assessed by both restriction and protection costs. The provisional policy and tested fixture bound that inference.
- **Discussion VIII-C:** explained why the configured casewise guard remains a publication veto despite aggregate improvement. No candidate was published; the small guard and weak zero-head control still limit what passing would establish.
- **Discussion VIII-D:** explained why a functioning budget cap cannot certify useful monitoring, given estimator error and admission-order effects. Privacy, estimation and representativeness require separate justification; no deployment threshold or validation is invented.

Existing named primary sources and their already verified interpretations were reused. No citation key or bibliography entry was added, removed or altered. Methods and Results were not rewritten to make the findings look stronger. These implications describe bounded engineering decisions, not validated new algorithms, a general recommendation to remove detectors, or new evidence of user benefit.

### Artifact checks

The PDF skill marker ran once for one edited PDF. Installed MiKTeX compiled into the new ignored directory `evaluation/results/rubric_iteration_20261017/iteration-01`, using `--disable-installer --no-shell-escape --interaction=nonstopmode --halt-on-error`; BibTeX used `--disable-installer`. Narrow configuration access was approved. One initial LaTeX pass, BibTeX and two resolving LaTeX passes completed with exit status zero. Final **pass3** produced ten pages including references, without layout reductions or content cuts.

All ten final pages were rendered with Poppler at 120 dpi and visually inspected anew. The journal title/author footnotes, overview, six tables, two equations and references are legible without clipping or overlap. Discussion now spans pp. 9–10; Conclusion, AI Assistance and references are on p. 10. All twenty font resources are embedded. No overfull boxes, undefined/multiply-defined references or missing-glyph diagnostics occur. Known underfull horizontal boxes and the disabled-shell-escape warning remain non-blocking after visual inspection.

Against the input commit, all six complete table environments, both equations, the overview figure, label and citation-key sequences and all three RQ strings are identical. Table data preserve 109 numeric tokens including the question map (99 across the five result tables). Design through the end of Results is identical, as is Conclusion through the end of the source, including the AI statement and bibliography configuration. Local references and all twenty citation keys resolve. The main source and extracted PDF contain no appendix/supplement/supporting-detail dependency. The delivered PDF is byte-identical to the final build. Logs, text, renders and `source-and-pdf-checks.json` remain in that new build directory as evidence.

| Final artifact | SHA-256 |
| --- | --- |
| `paper/main.tex` | `76ce61ba7c4f014be8c0938b1e122832ef0f54df165ae4266aec5fe88f22e503` |
| `paper/main.pdf` | `08bf596d531d046ee0f912526774fcf93b45ab2cf4a686028c54f53ff456ec96` |
| `paper/template.tex`, unchanged user input | `e4ea281c35acf1028e726f0777f2b75817478824a6b6fa723bd8b85ae8d9c056` |

### Reassessment after the completed artifact

The rubric review was updated only after the new PDF was built and inspected. Former Priorities 1 and 5 moved to the resolved table with actual locations and bounded evidence. They are no longer presented as missing work. The four remaining opportunities retain their identifiers: **2** illustrative policy traversal; **3** clearer ablation tradeoff presentation; **4** artifact/configuration availability; **6** bias–mitigation–residual synthesis. Current source/PDF bindings and physical-page locators were updated.

The category judgments remain D-defensible/plausible, with observed D–HD presentation features; completing two recommendations does not mechanically establish HD or an unsupported numerical uplift. The contribution-to-prior-work chain is stronger, and the discussion now draws decisions rather than only listing limits. Reproducibility, accessible comparison and residual-bias synthesis remain opportunities. Provisional contextual truth, source dependence, package confounding, poor final specificity, small guard/weak base, no incremental semantic cost and no demonstrated human/deployment utility remain scientific limits. No positive-outcome requirement or additional study was invented to earn marks.

### Weekly quota checkpoints and handoff

| Checkpoint | Weekly used | Remaining | Meaning |
| --- | --- | --- | --- |
| Before iteration 1 | 69% | 31% | Account-wide 10,080-minute window; matches the user's starting allowance. |
| After six source paragraph edits | 70% | 30% | Below warning/stop thresholds. |
| After compilation | 70% | 30% | Three LaTeX passes and bibliography completed. |
| After PDF validation and rubric reassessment | 70% | 30% | Same exposed weekly checkpoint; not an exact agent token measure. |

Root independently read and accepted all six paragraph diffs as material, bounded improvements, with qualifications visible and no scope problem. Root also independently viewed the changed final pages 1, 2, 9 and 10 at full size and accepted their fit and readability without clipping or overlap; this is focused independent coverage, alongside the writer's complete ten-page inspection. Final hash/record acceptance remains root's next step. The writer stops here rather than starting iteration 2 without that review. Four owned paths are ready: manuscript source, delivered PDF, current rubric review and this record. No scratch cleanup or active process is pending; ignored build evidence is retained. No Git mutation or push was performed.
