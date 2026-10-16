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


## Iteration 2 — Policy traversal and targeted ablation presentation

**Input:** `docs/paper` at `d1778e349cf5004f55de03cb15c2193be67c144e`, root's accepted iteration-1 commit. Root completed the preceding source, focused-render, binding/table and document checks before this iteration. Tracked files were clean; the unchanged user template remained untracked. Only former **Priority 2** (policy traversal) and **Priority 3** (ablation presentation) were assigned. The current four-file ownership and all goal constraints remain unchanged.

### Changes, source and preservation

Section III-B now includes a hypothetical traversal: assumed S2/HEALTH/confidence 0.7 with no prior restriction produces WARN and original-body transmission without acknowledgement; an earlier rule BLOCK cancels before semantics. It explicitly does not claim an observed model prediction, independent labelling or another test. No prompt example, protected row or additional study was introduced.

Section V-A now uses **Table III** to compare the same three approved ablation configurations. The existing aggregate source is [controlled-studies-20261014.md](controlled-studies-20261014.md), **AB14 observed results**, specifically the `Full product`, `Remove regex` and `Remove NER` rows and the following paired-contrast paragraphs. That record reports executed protocol hash `d3badb10c83254dfb2eb7b6aac256296ca459b81f57091053b5d99d4ca5c420b`, frozen balanced package `99b36171056bb0398584a0b0556d9d7ff2640d0acac4b124a126327451a80589` and corrected grouping/cohort analysis hash `f6bba29b524a4e261c990ae13f6e9ec00ff31800ad9caa1e329cba3f8bf1f67a`. Only its already reported aggregates were read; no raw study rows or rerun were needed.

| Contrast | Requested layers | Allowed action | Label-and-action joint | Under | Over |
| --- | --- | ---: | ---: | ---: | ---: |
| Full | `[2,3,4]` | 1409 | 717 | 12 | 139 |
| No rules | `[3,4]` | 1530 | 972 | 30 | 0 |
| No NER | `[2,4]` | 1409 | 717 | 12 | 139 |

The new table promotes **twelve existing outcome counts** and carries **seven layer-ID digits**. These mechanical token counts are not new measurements or independent cases. All configurations retain the 1,560-case denominator. Adjacent prose retains 139 corrected unnecessary restrictions, eighteen lost correct actions, net 121, family interval 3.46–12.70 percentage points and audience-expression interval 5.96–9.23. It preserves the descriptive dependence qualification, actual-execution check and fixture-specific zero-converted-finding explanation for no-NER equality. Full comparison counts were removed from that prose because the table now presents them.

All six original table environments are unchanged, preserving their 109 data-row numeric tokens including the question map (99 in the five original result tables). Both equations, the overview, existing labels, citation-key sequences and exact RQs are unchanged; only the new table label/callout is added. The new table uses the same `\small` table text as the existing tables, which is larger than IEEEtran's default table text; no typography reduction or width scaling was used. No source outside the policy illustration and targeted ablation presentation was substantively changed.

### Build, visual checks and reassessment

The PDF marker ran once for one edit output. Installed MiKTeX/BibTeX built in `evaluation/results/rubric_iteration_20261017/iteration-02`, with package installation and shell escape disabled and narrow configuration access approved. The first complete build reached eleven pages, with only the final reference on page eleven. Tightening the newly added illustration, caption and ablation prose restored ten pages. No other section, result or caveat was cut. A final wording check distinguished policy selection from semantic labels, and the new table's font setting was matched to the existing tables.

All six LaTeX pass1–pass6 invocations, the final **pass7** and BibTeX completed successfully. All pass6 pages were rendered and visually inspected. Pass7 changed only page 7; this was verified by PNG byte hashes, and page 7 was inspected again at full-page view. Pages 8–10 were also re-inspected; the other nine final images are byte-identical to inspected pass6 images. This establishes complete final-page coverage without attributing old-version acceptance to changed pixels.

The delivered PDF has **ten pages including twenty references, seven tables, one overview and two equations**. Table III is the new ablation; the final semantic table is IV, matched continuation V, browser cost VI and telemetry utility VII. The policy traversal is on p. 3, ablation text on pp. 6–7/table on p. 7, and the expanded Design ends on p. 5. Tables and surrounding text are readable with no clipping or overlap. All twenty font resources are embedded; labels and all twenty citation keys resolve. The final log has no overflow, undefined/multiply-defined reference or missing-glyph diagnostics. Known underfull horizontal boxes and the disabled-shell-escape warning remain visually non-blocking. No appendix/supplement/supporting-detail dependency appears in source or extracted PDF.

The final PDF was copied to the deliverable and is byte-identical to the build. New logs, extraction, final renders, preservation checks and `source-and-pdf-checks.json` remain under the iteration-02 directory. Earlier iteration evidence is preserved.

| Final artifact | SHA-256 |
| --- | --- |
| `paper/main.tex` | `cd199b7dc129ac03957696d14c6a1f84280a6a91e37bbeedbea095a00e3b665a` |
| `paper/main.pdf` | `3ce5612fba9fd51f0c6a476d5804934d6a3752002a03075edebc48406e934d1c` |
| `paper/template.tex`, unchanged user input | `e4ea281c35acf1028e726f0777f2b75817478824a6b6fa723bd8b85ae8d9c056` |

The review was reassessed after this final artifact. Priorities 2 and 3 moved to the resolved table with locations and acceptance evidence; only **4 (artifact availability)** and **6 (bias–mitigation–residual synthesis)** remain in the priority list. Table numbering, page locators and source/PDF bindings were updated. The table improves comparison and the example improves interpretation, but neither validates provisional labels, eliminates the observed harm or supplies new empirical evidence. Category bands remain candid rather than advancing automatically to HD. All scientific limits and the seven-unit scope remain.

### Weekly quota and handoff

| Checkpoint | Weekly used | Remaining |
| --- | --- | --- |
| Iteration-2 preflight | 71% | 29% |
| After source edit | 71% | 29% |
| After initial and page-fit compilation checks | 71% | 29% |
| After final PDF validation and rubric update | 72% | 28% |

These are account-wide 10,080-minute-window snapshots, not per-agent token costs. The stop threshold has not been reached. Root independently read the complete source diff and AB14 aggregate rows and accepted the hypothetical traversal, table values and scope. Root independently inspected final iteration-02 pages 3, 4, 7, 8 and 10 and accepted their fit/readability and the complete source diff. Final binding/record acceptance remains root's next step. The writer stops at this stable iteration-2 milestone; iteration 3 requires root's next assignment. No pending process, disposable scratch, Git mutation or push remains; the four owned files are the source/PDF, current review and this ledger.
