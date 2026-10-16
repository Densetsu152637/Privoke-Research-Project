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


## Iteration 3 — Artifact availability and mitigation–residual synthesis

**Input:** `docs/paper` at `d085e97b8ef881a6b4f356734649950b583fa613`, root's accepted iteration-2 commit. Tracked files were clean; the user template remained unchanged and untracked. Only former **Priority 4** (precise reproducibility/artifact availability) and **Priority 6** (bias–mitigation–residual synthesis) were assigned. The four-file ownership, template, seven-unit scope and quota controls above remain binding.

### Changes and provenance

IV-B now records the historical matched-fit environment: Python 3.11, Torch 2.12/CUDA 13.0, Transformers 4.57.6 and RTX 5080. IV-C adds a compact availability paragraph distinguishing tracked recipes and dated aggregate/provenance records from run-specific checkpoints and raw artifacts that remain local and ignored. It names the product/ablation, matched continuation, final semantics, pinned Linux client and telemetry configuration boundaries without an unexplained hash catalogue. It explicitly acknowledges historical uncommitted dependencies, rejects Git-only exact reproduction and leaves public distribution of pinned assets unestablished.

Only existing non-protected records were read:

| Existing record | Used evidence |
| --- | --- |
| [pipeline-comparison-20261014.json](pipeline-comparison-20261014.json) and [pipeline-comparison-20261014.md](pipeline-comparison-20261014.md) | PIPE3 product source/protocol/data fingerprints and compact aggregate availability. Source closure `bf022fc18b16aebfdbcc75e68ef92e28ffb4f4765015c74fc56e95e1047864fa`. |
| [controlled-studies-20261014.md](controlled-studies-20261014.md) | AB14 historical uncommitted-dependency closure; AD14 historical fit environment and matched configuration. AD14 protocol `98c1d0fbd8c1342c99e993d5257d75c99f8918510c0719ba363f43f8d147afe3`, source closure `302ddc423abe7897e7c23c37d2d330d1d41c9f2a09f372dd65c256eb0a8819d7`. |
| [final-semantic-evidence-20261014.json](final-semantic-evidence-20261014.json) and [final-semantic-audit-20261014.json](final-semantic-audit-20261014.json) | Frozen endpoint, aggregate scope and audit provenance, without opening protected rows. Freeze hash `655798df22d0dd817873b0554d5b4de084dec669354ae2c616f7dd06eaceda00`. |
| [installed-client-evidence-20261014.md](installed-client-evidence-20261014.md) | Pinned historical Linux client capture and local raw-receipt boundary. |
| [telemetry-evidence-20261014.md](telemetry-evidence-20261014.md) | Existing protocol/environment receipts, compact tracked summaries and local raw-array boundary. |

Tracked-file and ignore-rule inspection confirmed recipes/aggregates are tracked while experiment weights and run results are ignored. No inference, fitting, scoring, resampling, protected raw access, external research, asset redistribution or new reproduction study was performed. These provenance statements identify the historical evidence; they do not certify current dependency compatibility or complete public availability.

VIII-B/C/D replaces repeated caveats with connected explanations: endpoint freezing limits post-selection on its distinct target; exclusions/clustering address declared grouping without proving template/pretraining independence; fixed-base continuation limits its configuration confounding without isolating the earlier package comparison; request/window records bound whole-container measurement without supplying an unprotected or semantic baseline. Telemetry accounting still cannot remove estimator error or admission selection. All residual target, source, weak-base/small-guard and deployment/utility limitations remain. The first opening of the frozen endpoint is stated explicitly, avoiding ambiguity with product release.

### Build and preservation checks

The PDF marker ran once for one edited PDF. Installed MiKTeX/BibTeX compiled into the new ignored directory `evaluation/results/rubric_iteration_20261017/iteration-03`, with package installation and shell escape disabled and narrowly approved configuration access. All seven LaTeX passes and BibTeX completed successfully. Early complete builds reached eleven pages; tightening only the newly revised availability/discussion prose and its repetition restored **ten pages** in pass6 and final **pass7**, without typography reduction or removal of findings.

All ten final pass7 pages were rendered with Poppler at 120 dpi and visually inspected anew. The final paper retains seven tables, two displayed equations, one overview and twenty references, with normal readable typography and no clipping or overlap. All twenty font resources are embedded. No overfull, undefined/multiply-defined reference or missing-glyph diagnostics occur; existing underfull boxes and the disabled-shell-escape warning are visually non-blocking. No appendix/supplement/supporting-detail dependency occurs in source or extracted PDF.

Against the input commit, **all seven complete table environments, both equations, the overview, all 25 label occurrences, citation-key sequences and all three RQs are identical**. All Results sections and Conclusion through the end are unchanged. All local references and twenty citation keys resolve. The new version/hardware numerals describe the verified historical environment, not new outcome measurements. The delivered PDF was copied from pass7 and is byte-identical to the build. Logs, extraction, renders and `source-and-pdf-checks.json` remain in the new ignored directory.

| Final artifact | SHA-256 |
| --- | --- |
| `paper/main.tex` | `0442c8b03e243ee095cf560f53897d3d3b1c3c924e0b19094ac56de83b078acf` |
| `paper/main.pdf` | `f795578809c633414b1734b2338f979347df9530e2dfd2a956f2ccd92477caf0` |
| `paper/template.tex`, unchanged user input | `e4ea281c35acf1028e726f0777f2b75817478824a6b6fa723bd8b85ae8d9c056` |

### Reassessment, quota and handoff

The current rubric review was updated after the completed PDF. Priorities 4 and 6 moved to resolved with their actual page/section evidence. **All six initial editorial recommendations are now addressed.** No further material editorial defect was identified in this bounded reassessment; this is not exhaustive certification or an automatic HD. Existing category judgments remain candid: improved transparency does not supply independent contextual truth, remove dependence/package confounding, strengthen the weak base/guard, measure incremental semantic cost or establish public reproduction, human benefit or useful deployment. No new study is recommended as an automatic scope expansion, and quota consumption is not a reason to invent further edits.

| Checkpoint | Weekly used | Remaining |
| --- | --- | --- |
| Iteration-3 preflight | 72% | 28% |
| After source edits | 73% | 27% |
| After initial and final compilation | 73% | 27% |
| After final PDF validation and completed rubric reassessment | 74% | 26% |

These are shared account snapshots, not per-agent token accounting. Neither warning nor stop threshold was reached. Root independently reviewed the complete source diff, spot-verified PIPE3's historical closure and AD14's fit versions, and accepted the final wording. Root independently inspected final pages **5, 6, 9 and 10** and accepted normal readable layout, availability text and all references; the writer's separate visual inspection covers all ten pages. Final source/PDF/build hash bindings, local document links, six-priority coverage and whitespace checks pass; the template remains byte-identical and untracked. Final independent binding/document acceptance remains root's next step.

The writer stops at the stable iteration-3 milestone and awaits root's decision. Only the manuscript source/PDF, current rubric review and this ledger are owned changes. No active process or disposable scratch is pending; ignored build evidence is retained. The user template remains unchanged and untracked. No Git mutation or push was performed.


## Iteration 4 — Full descriptor and section audit, with reference corrections

**Follow-up objective:** root conveyed the user's stronger completion standard: continue iterating toward a supported D or possible HD assessment for every section, still stopping at 20% weekly allowance remaining. A guaranteed grade is not attainable from an assistant review; the operational goal is an evidence-based audit against the actual descriptors, with concrete remaining defects repaired. Root explicitly warned that completing six recommendations did not prove completion of all rubric dimensions.

**Input:** `docs/paper` at `15318ea31e6da731c0cae26b0fd2b349b9deac22`, tracked clean, template unchanged/untracked; quota 74% used/26% remaining. The assignment was to reread the actual rubric and current paper, build a matrix for all fifteen dimensions and every section, repair warranted gaps without changing the seven studies, and return one stable iteration. No descendants, experiments, inference, fitting, protected raw access or resampling were authorized. Root retained Git ownership.

### Audit method and substantive conclusion

The complete four-page rubric and current manuscript were reread. Its dimensions divide **4/5/3/3** across the **30/50/10/10%** categories. D explicitly exceeds all Acceptable criteria and meets most HD criteria; it is a category descriptor, not a numeric cutoff or formal section grade. The updated review tests each P-to-HD distinction against concrete current evidence and separately covers **25 section/subsection groups**, with page locators, relevant rubric IDs, readiness and residual boundaries.

The audit examined literature relevance/critical synthesis, originality, appropriateness of the bounded methods, paired and uncertainty-aware interpretation, usefulness of failed outcomes, all Discussion connections, structure, every visual, wording and references. It did not classify weak labels, a weak base or negative outcomes as automatic rubric failures. Instead, it checked whether their limits are explicit and the claims are appropriate. Integration and original empirical findings can satisfy the stated originality descriptor without inventing new primitives. Current/seminal coverage is judged for concise relevance, not against an unstated exhaustive-search requirement.

The resulting judgment supports **D readiness / possible HD in all four categories**, with no identified under-supported dimension after the corrections below. Literature selection and the weight given to the engineering advancement remain judgment-dependent; perfect typo-freedom and an unavailable institutional declaration format cannot be guaranteed. This is a fuller evidence basis than iteration 3's shorthand verdict, not a claim that a few bibliography edits automatically improved scientific performance. All scientific limits remain.

### Concrete findings and bounded repairs

- **IV-A endpoint wording:** replaced “frozen before release” with “frozen before opening,” consistent with VIII-B and the final endpoint's provenance. No protocol changed.
- **Rendered references:** protected LLMs, ChatGPT, AI, HaS, PromptShield/DLP/AI and CPU capitalization in the affected existing entries. IEEEtran had lowercased these proper acronyms, including the visible “cPU” defect.
- **Gupta2024 metadata:** replaced the repeated `109215-109215` range with the single article identifier `109215`. Publisher-deposited DOI metadata also showed that Akshat Gaurav and Wadee Alhalabi had reversed given/family names and that the journal publication month was May 2024, not February; those fields were corrected.

Root approved expanding the four owned paths to include only the affected entries in [ref.bib](../ref.bib) and [manuscript-completion-sources-20261014.bib](../manuscript-completion-sources-20261014.bib), then separately approved the verified author/month corrections. No citation key or scientific source was added or removed. Other entries were untouched. IEEEtran.bst's `format.pages` has no article-eid handling and prints a single value as `p. 109215`; the identifier is retained without fabricating a page extent or modifying the style.

### Narrow source-verification record: ITER04-REF1

**Question:** verify the existing Gupta2024 article identifier and the bibliography style's rendering, not investigate new scientific claims. Existing key `Gupta2024` remains the source's BibTeX record.

Exact web search queries were:

1. `site.sciencedirect.com/science/article/pii/S0045790624001435 109215 confidentiality`
2. `site.doi.org 10.1016/j.compeleceng.2024.109215`
3. `"Enhancing user prompt confidentiality" "109215"`

Direct opens of the [publisher article](https://www.sciencedirect.com/science/article/pii/S0045790624001435), its DOI and the indexed publisher URL with `?dgcid=rss_sd_all` failed/returned HTTP 403. The first searches were not useful for the article; the third returned the indexed publisher title, volume 116, May 2024 and 109215, treated as a lead rather than sufficient opened-source evidence. Other returned sources were not used for claims.

An unauthenticated request to the [Crossref DOI metadata endpoint](https://api.crossref.org/works/10.1016/j.compeleceng.2024.109215) succeeded. The publisher-deposited result identifies Elsevier, volume 116, page/article-number 109215, publication date `[2024,5]`, and author pairs `(Brij B., Gupta)`, `(Akshat, Gaurav)`, `(Varsha, Arya)`, `(Wadee, Alhalabi)`, `(Dheyaaldin, Alsalman)`, `(P., Vijayakumar)`. This authoritative metadata, not an unseen article body or a secondary paraphrase, supports the corrections. The exact response is retained at `evaluation/results/rubric_iteration_20261017/iteration-04/gupta-crossref-metadata.json`, SHA-256 `08b08ee2a95f8ca327fec4cca1dcb61a609b85e3991429bab905821ed3874a46`. Installed `IEEEtran.bst`, `format.pages`, was read to verify its single-value behavior. No scientific interpretation of the Gupta paper was added.

### Artifact validation and bindings

The PDF skill marker ran exactly once for one edited output. Installed MiKTeX/BibTeX built in the new ignored `evaluation/results/rubric_iteration_20261017/iteration-04`, with installation and shell escape disabled and narrow configuration access approved. Three LaTeX passes and BibTeX exited successfully; final **pass3** is ten complete pages including references. No page-fit prose cuts, font/margin reductions or scope changes were needed.

All ten final pages were rendered at 110 dpi with Poppler and visually inspected anew. All twenty font resources are embedded; seven tables, two equations, one overview and twenty references are retained. No overfull, undefined/multiply-defined reference or missing-glyph diagnostics occur. Source/PDF contain no appendix/supplement/supporting-detail dependency. Root independently inspected changed pages **5 and 10**, accepted the complete source/bibliography diff, and verified the deposited metadata corrections.

A whole-source comparison confirms the **only manuscript-source delta is release→opening** in the named sentence. Thus every numerical finding, table, equation, figure, RQ, citation-key sequence, label and Results paragraph is preserved. Bibliography changes are confined to seven existing entries in ref.bib and one existing entry in manuscript-completion-sources-20261014.bib, eight entries in total across the two approved files. The final PDF was copied to the deliverable and is byte-identical to the build. `source-and-pdf-checks.json`, the exact metadata response, compile logs, extracted text and all renders remain in the ignored iteration directory.

| Final artifact | SHA-256 |
| --- | --- |
| `paper/main.tex` | `5deaa4009f792771ec20ba432729073f594f3e811dc7307902a6875aef9aa3d4` |
| `paper/main.pdf` | `5bab5f0212047bff2daeb4d888695ad4ec901561fb2222a9b6e7175d2c786617` |
| `paper/ref.bib` | `dca09ce2dca7ed4183275661782032cb3066d2d435951f7befd8356d22aa7e4c` |
| `paper/manuscript-completion-sources-20261014.bib` | `ee089293ce8d3a9fd9317e068952de807844bad03b34482249940b0bb18e847b` |
| Unchanged user `paper/template.tex` | `e4ea281c35acf1028e726f0777f2b75817478824a6b6fa723bd8b85ae8d9c056` |

### Quota and handoff

| Checkpoint | Weekly used | Remaining |
| --- | --- | --- |
| Iteration-4 preflight | 74% | 26% |
| After source/bibliography edits | 75% | 25% |
| After final compilation and all-page QA | 75% | 25% |
| After full descriptor and section reassessment | 76% | 24% |

These are shared account snapshots; no per-agent token total is inferred. Warning/stop thresholds remain 79%/80% used. The writer returns this stable iteration for root's review rather than beginning another cycle. Six owned files are the source/PDF, both approved bibliographies, current rubric review and this ledger. The user template remains unchanged/untracked; no Git mutation, push, active process or disposable scratch is pending. The final rubric audit identifies no additional material within-scope remedy, but root remains responsible for accepting the completion evidence and deciding the next step.
