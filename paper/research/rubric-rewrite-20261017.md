# Sequential rubric-led manuscript rewrite

**Record ID:** RUBRIC-REWRITE-20261017. **Date:** 17 October 2026 (Australia/Sydney). **Current checkpoint:** substantive rewrite and final two-document layout accepted by root after independent source and all-page visual review. Main paper: ten complete pages including references; supporting detail: seven pages. Writer has ceased edits; root owns Git finalization. **Input revision:** `017ad37e291a6574c94b9df4e3b02e9381db5f85`, branch `docs/paper`, `D:/Git Repositories/Privoke-Research-Project`.

## Objective and boundaries

Exact user objective supplied by the coordinating root:

> use the same astra model to rewrite each section in the style of the previous introduction so that it meets the criteria of the very high in each section of the rubric. Use the agent to do this sequentially.

The continuing writer is the same explicitly selected Astra agent (`gpt-6-astra`, high reasoning). The task is a sequential whole-paper rewrite against [the rubric evaluation](../rubric-evaluation.md) and [the supplied rubric](../Final_Paper_Rubric.pdf). The highest rubric band is HD; revision can improve alignment with its descriptors but cannot guarantee marks or supply missing empirical evidence through wording.

The first assigned milestone is **Introduction and Related Work only**, followed by root review before further manuscript sections. Root owns Git operations and final integration. No descendants, commits or pushes are performed by this writer. All quantitative facts, adverse evidence, equations, tables, figures and labels are to remain available. No training, detector execution, service startup, protected raw data or study scoring is authorized. The ultimate layout target is a complete ten-page PDF under the conservative rubric interpretation; later restructuring may preserve full appendices in a separate supplement, but this first milestone moves or deletes no appendix. Template/page exemptions remain unverified.

## Instruction and style checkpoint

The writer retained the complete unchanged shared, leaf, research, vision, validation, coordination, Git and PDF instruction owners loaded in the preceding review. Newly loaded for authoring: `profiles/AGENTS.implementer.md`, `guides/coding-standards.md` under `D:/Git Repositories/Agent-Custom-Workflow/`, and the `write-like-me` skill at `C:/Users/Nicholas/.codex/plugins/cache/openai-curated-remote/write-like-me/0.1.1/skills/write-like-me/SKILL.md`. The user's selected historical text supplies the style reference; no unrelated personal-writing search was needed.

Style inputs, read directly with `git show`, are the Introduction at `2b5cf75149d146d73a8ba1227c936c444b75c9f9:paper/main.tex` and the Introduction/Background at `d72075b35240b96a16cd062d5d3d91b0189d6f74:paper/main.tex`. Those passages inform explanatory flow and degree of development, not scientific authority. Current results, supported-path restrictions, no automatic WARN acknowledgement, separate telemetry and training, and the professor's exact three RQs remain authoritative. Earlier claims about deployment, universal benefit or other unsupported capabilities are not restored.

## Question map and first-milestone decisions

| Question | Revision decision | Evidence and boundary |
| --- | --- | --- |
| How can the introduction explain the problem naturally? | Develop useful prompt context, possible outgoing disclosure, contextual interpretation and actual intervention before describing the maintenance/reporting paths. | Existing manuscript motivation; historical style references. The illustrative report scenario is explanatory, not an experimental observation. |
| Why do the three RQs follow from prior work? | Connect local protection to observed request effects, model revision to retained behavior, and random reporting to privacy/accounting/utility. | Existing supplied system papers plus the three primary-source additions below. |
| What is the defensible contribution? | An implemented and evaluated lifecycle connecting enforcement, version-bound guarded revision and separate randomized reporting. | Current mechanism/results sections are unchanged. No first-ever locality, training, regression-analysis or randomization claim. |
| What empirical limits must survive improved prose? | Labels do not independently establish authorization; guards cover declared cases; reporting excludes participation/network metadata; no matched end-to-end superiority claim. | Current methods, results, discussion and [claims ledger](claims.md). |

## Primary-source research ledger

**Bounded research goal:** add foundational support for contextual disclosure, casewise model-update regressions and locally randomized operational reporting, without expanding into a new literature survey or experiment.

Exact web search queries used on 17 October 2026:

1. `site.openaccess.thecvf.com Positive-Congruent Training Towards Regression-Free Model Updates 2021`
2. `site.research.google RAPPOR Randomized Aggregatable Privacy-Preserving Ordinal Response Erlingsson Pihur Korolova 2014`
3. `site.cis.upenn.edu nissim contextual integrity privacy information flow Nissenbaum 2004`
4. `site.digitalcommons.law.uw.edu "Privacy as Contextual Integrity" 2004 79`

Search results were discovery aids. The source pages/PDFs below were opened before use. Only the narrow supported claims were carried into the manuscript. Relevant BibTeX entries were added to the existing [bibliography](../ref.bib); no separate disconnected bibliography was introduced.

| Evidence ID / citation key | Primary source and inspected locator | Result and use | Limits/access issues |
| --- | --- | --- | --- |
| RW17-CI / `NissenbaumContextualIntegrity2004` | [Published journal record](https://digitalcommons.law.uw.edu/wlr/vol79/iss1/10/); [author-hosted published PDF](https://nissenbaum.tech.cornell.edu/papers/H.%20Nissenbaum%2C%20_Privacy%20as%20Contextual%20Integrity.pdf), title/abstract and Section III, especially appropriateness/distribution at PDF pp. 20-24. | Supports contextual information-flow framing in the Introduction. Metadata: Helen Nissenbaum, Washington Law Review 79(1), 2004, starting p. 119. | The earlier [Stanford project record](https://crypto.stanford.edu/portia/pubs/articles/N1301112078.html) has inconsistent volume/pagination and links a draft; the published journal/author PDF controls. The manuscript does not claim to implement or validate the full contextual-integrity framework. |
| RW17-PC / `YanPositiveCongruent2021` | [CVPR primary record](https://openaccess.thecvf.com/content/CVPR2021/html/Yan_Positive-Congruent_Training_Towards_Regression-Free_Model_Updates_CVPR_2021_paper.html); [author preprint v3](https://arxiv.org/pdf/2011.09161), 17 May 2021, abstract and Sections 1-4. | Supports the distinction between average accuracy and newly incorrect cases, and acknowledges established regression-aware training. | Direct CVF HTML/PDF open returned HTTP 403. Search returned the primary proceedings metadata; the complete arXiv author version was accessible and read for the scientific claim. Image-classifier evidence is not transferred into a privacy-accuracy guarantee, and PriVoke is not claimed to implement focal distillation. |
| RW17-RR / `ErlingssonRappor2014` | [Google Research publication record](https://research.google/pubs/rappor-randomized-aggregatable-privacy-preserving-ordinal-response/), its [linked author paper](https://arxiv.org/pdf/1407.6981), abstract and Sections 1-3. | Establishes prior randomized client reporting and the need to account for repeated contributions. | PriVoke's event randomizer/ledger is explicitly distinguished from RAPPOR's memoization. No RAPPOR utility or longitudinal guarantee is assigned to PriVoke. DOI verified in the paper's first-page publication notice. |

The supplied local primary papers were also reopened with `pypdf`: [Casper v1](../sources/main/Casper.pdf), particularly design/implementation pp. 5-9; [Hide and Seek](../sources/main/Hide%20and%20Seek.pdf), abstract and Sections 3-3.2 on pp. 2-3; [ProSan](../sources/main/ProSan.pdf), abstract and lightweight implementation/framework on pp. 8-9. Existing `CasperPreprintV12024`, `HaS2024` and `ProSan2024` keys are retained. These checks support their different request/transformation/recovery contracts. Existing PromptShield and Presidio references retain their previous narrow descriptions; no new claim about their uninspected functions was added. Version-qualified external metric details remain unchanged in Appendix D.

The first local PDF extraction attempt hit Windows console `UnicodeEncodeError`; rerunning the same read-only extraction with UTF-8 stdout succeeded. This was a tooling failure, not missing source evidence. No source PDFs were edited or downloaded into the project.

## Checkpoint 1: changed sections and scientific preservation

**Changed files:** `paper/main.tex`, `paper/ref.bib`, and this record.

**Introduction:** restored connected motivation-to-mechanism explanation; added a sourced contextual-flow basis; distinguished classification from request consequences; explained why model maintenance and reporting create separate evaluation questions; made the lifecycle contribution explicit. All three professor-specified RQs are byte-for-byte unchanged. Current limits replace unsupported implications that might otherwise be inherited from older prose.

**Related Work and Contribution:** organized the argument into local/contextual intervention, retained behavior during revision, operational reporting and the bounded combined contribution. Acknowledged prior configurable local models, trained sanitization and regression-aware learning. Explained why request outcomes, retained behavior and reporting costs need separate evidence. Preserved the lack of automatic masking/recovery, mismatched external metric targets, component-reference status of Presidio, and absence of demonstrated general system superiority.

**Bibliography:** added exactly `NissenbaumContextualIntegrity2004`, `YanPositiveCongruent2021` and `ErlingssonRappor2014`. Existing entries and keys remain unchanged. Broad introductory provider-policy citations were removed from that passage because the revised sentence makes only the logical distinction between initial transfer and subsequent handling; no current provider-policy claim is made.

## Checkpoint 1 validation

Read-only checks against input Git revision `017ad37` passed:

- The manuscript prefix before `\\section{Introduction}` is unchanged, including title, author block, abstract and keywords.
- The manuscript suffix starting at `\\section{System Design and Privacy Boundary}` is unchanged, including every result, table, figure, equation, appendix, adverse finding and bibliography command.
- All three RQ strings are exact matches; the complete sequence of `\\label{...}` identifiers is unchanged.
- All manuscript citation keys resolve across the four existing bibliography inputs; no duplicate bibliography keys were found.
- `git diff --check` passed. Git warns that LF in `main.tex` will be converted to CRLF when it next touches the file; this is not a content change.
- Simple whitespace-token counts, which are not a LaTeX word-count standard: Introduction 528 to 634; Related Work 374 to 634. The additional literature argument adds 366 tokens by this measure. Whole-paper compression/layout remains a later checkpoint.

First-milestone source SHA-256: `280892adda44e0da63cb2e80f01f1d5c814833b7f9860c5f11a2d0a52215da5a`.

First-milestone `ref.bib` SHA-256: `2c142f0f7a1d932bdf4eae9d3d8903c3f9fe7f80a477d34a7f65dfdf94eb72c1`.

`main.pdf` remains the previous 16-page artifact, SHA-256 `d9ee4bd5ba74b28853c3cf7fffdf5a715f71c5e5f218800d178e08de4fd26027`. It does **not** yet render these source revisions. No PDF-build, final page-limit, visual-layout or updated bibliography-rendering acceptance is claimed at this source-only milestone. The root owns the subsequent multi-file LaTeX build/approval path.

## Remaining sequential work and empirical limits

Proceed through the remaining assigned sections in order, keeping a checkpoint after each requested milestone. Results must retain the quantitative facts while making their implications clear; Discussion/Conclusion must connect the findings to the literature strands. Abstract and final layout/appendix placement should be reconciled with the accepted whole-paper argument, followed by the complete PDF build and all-page review.

Independent contextual adjudication, new protected generalization evidence, useful retention from a meaningful trained base, baseline-relative semantic cost, and user/task benefit remain empirically unresolved. This writing milestone neither performs those studies nor upgrades the corresponding claims. Correct AI acknowledgement, confirmed template/page rules, integrated figure/table callouts and a compliant final PDF remain explicit later acceptance items.

## Checkpoint 2: System Design, followed by Evaluation Method

Root accepted checkpoint 1 after reviewing its diff and source records. The next exact section assignment was: “rewrite System Design and Privacy Boundary, then Evaluation Method, in that order.” The writer revised the complete System Design prose first and Evaluation Method second, retaining the first checkpoint's accepted Introduction and Related Work. No Results or later section was edited.

Instruction delta: the previous authoring owners remained loaded; `workflows/AGENTS.architecture.md` was additionally read for describing boundaries, contracts and failure paths. This is a manuscript explanation of the existing architecture, not a new architecture decision or implementation change.

### Explanation and evidence decisions

| Area | Revised explanation | Evidence and preserved boundary |
| --- | --- | --- |
| Trust and data flow | Follow the supported outgoing request and distinguish the prompt, supplied training example and randomized-event paths. | Existing architecture/text and Figures 1-3 remain unchanged in substance; unsupported transports, malicious/compromised components, disabled protection and hosted inference retain their exclusions. |
| Detector policy | Define sensitivity S0-S3, audience/implementation visibility P0-P4/PU, multilabel categories and the confidence threshold in the main text. | Existing Appendix A supplies the definitions and exact mapping. The returned head score is not a calibrated probability of full correctness or authorization. |
| Cascade and failure | Explain why early rule BLOCK prevents later execution, strongest-action aggregation prevents semantic reversal, and stream fallback differs from unavailable analysis. | Existing mechanism and installed-client findings; no new coverage or runtime test. |
| Guarded update | Explain separately candidate identity, artifact checks, retention, exact-base publication, replay and client refresh. | Existing mechanism/guard evidence; a later rejected underlying-model stage does not undo an earlier accepted head publication. No inference from service implementation to cloud deployment. |
| Telemetry privacy | Define the event-content comparison at a fixed reporting opportunity and common public configuration before the existing probability equation. | Existing finite audit and ledger scope plus the supplied Dwork/Roth foundation below. Ideal composition is not a claim that the finite implementation meets the exact nominal bound. Participation, delivery and metadata remain excluded. |
| Metric names | Define label-joint agreement separately from label-and-action joint agreement; identify the product and semantic-only matched-continuation study as action-inclusive. | Existing Appendix B explicitly describes the matched-continuation metric. This clarifies an ambiguity without changing any scorer, count or result. Later Results terminology needs to be aligned at its own milestone. |
| Cases and uncertainty | Explain provisional labels, reuse, paired product cluster resampling, frozen final endpoint and the distinct source-category projection. | Existing method/appendix records; 2,000 draws, seed 42 and linear 95% ranges apply specifically to contextual product binary measures, not to every study. No independent population claim. |
| Comparisons | Promote native input-window/threshold differences and distinguish contextual Presidio from the restricted external-category configuration. | Existing Appendix B. All original model/data counts retained; no new benchmark, tuning or causal attribution. |
| Retention assessment | State matched exposures, shared weak base, distinct 16-case guard versus 1,080-case assessment, and hypothetical retained artifacts. | Existing study record and Results. No matched-study candidate was published. |
| Systems/telemetry measurement | Explain receiver observations, rules/NER-only cost windows, profile clustering, whole-container accounting and fixed-contributor simulations. | Existing browser/telemetry appendices; 180 cells and 10,000 repetitions are existing evidence, not new execution. No semantic-cost, incremental-overhead or deployed-monitoring claim. |

### Additional primary source: RW17-DP

Bounded source question: “Verify the supplied foundational source for randomized response, composition and the local privacy model before explaining the event-content guarantee.”

Read the existing [The Algorithmic Foundations of Differential Privacy PDF](../sources/background/The%20Algorithmic%20Foundations.pdf) by Cynthia Dwork and Aaron Roth. Its title page supplies year 2014, Foundations and Trends in Theoretical Computer Science 9(3-4), pp. 211-407 and DOI `10.1561/0400000042`. Relevant text inspected: Section 3.2, printed pp. 29-30 (PDF pp. 33-34); composition, printed p. 43 (PDF p. 47); local model, printed pp. 232-233 (PDF pp. 236-237). The supplied file has 281 physical pages, so physical locators are retained separately from its title-page publication metadata.

Result: the source supports local randomization and additive composition as foundations for the intended ideal bound. It does not certify PriVoke's finite sampler, ledger integrity or omitted reporting channels. Added `DworkRothFoundations2014` to the existing bibliography and cited it only for the conceptual definition/composition explanation. No external search, PDF download or new mathematical guarantee was introduced at this checkpoint.

### Checkpoint 2 preservation and validation

Before editing, the writer recorded normalized-source fingerprints for the accepted first-stage prefix, the complete Results-onward suffix, every figure/table/equation environment, all labels and the three RQs. Comparison after editing passed for all of them:

- Accepted content before System Design is unchanged: normalized UTF-8 SHA-256 `e49747f520bbae053b61f5f047a457cced589c1d6b3dab7a7a8d1addfeb7dae8`.
- The complete content after the RQ1 section heading is unchanged: `4af6d6485a918f662ec5d1706d956468e9aef42441799c49a76f77a8b4666ef1`.
- All sixteen existing figure/table/equation environments, including their captions, are unchanged; all labels and RQ strings are unchanged. The evidence-unit table is retained verbatim.
- Appendix definitions were selectively promoted into explanatory main-text prose; no supporting appendix content was removed.
- Simple whitespace-token counts: System Design 1,350 to 1,399; Evaluation Method 1,020 to 1,218. This checkpoint adds 247 tokens by that measure; whole-paper layout/compression is still pending.

Checkpoint 2 manuscript SHA-256: `de796456ef5ab8e71675d304e0c6e9c5ccbef468bc763779ef90224e9e8b34bd`.

Checkpoint 2 bibliography SHA-256: `1dd611b00ca0a61947c3f557e50fc84b1e9019f2dccc2f55eed56129cb0b3a4d`.

The existing `main.pdf` remains unchanged and does not render either writing checkpoint. Compilation, updated citation rendering, complete page count and visual acceptance remain pending. No detector tests, model inference, training, protected data or study scoring were run. The writer stops at this stable source milestone for root review before revising Results.

## Checkpoint 3: RQ1, RQ2 and RQ3 in sequence

Root accepted checkpoint 2 and assigned: “Proceed next milestone RQ1 then RQ2 then RQ3, sequentially; report per-section completion but can continue through three without stopping, then stable handoff for root review.” Each section was rewritten in that order, with completion messages after RQ1 and RQ2. Root reviewed and accepted the RQ1 interpretation before the final checkpoint. Discussion onward remains untouched for its subsequent stage.

After context compaction, the writer reloaded the exact shared/leaf/research owners, implementer profile, validation/coding/coordination/Git guides, result schema and writing-style skill listed above. No new activity-specific owner was needed: this stage interprets existing reported results, with no new experiment, resampling, runtime execution or protected raw-data access. Root retains sole Git finalization authority in the shared checkout.

| Section | Revised argument and evidence | Additional values / source locator |
| --- | --- | --- |
| RQ1 | Explain aggregate gains through paired losses, cascade-caused restriction, controlled detector removal, transfer across different targets and receiver-observed enforcement. Use explicit label-and-action joint naming in prose and the table caption; add direct callouts to both detailed result figures. | Existing AB14 action-rate sensitivity ranges, converted from proportions to percentage points: 3.46–12.70 by family and 5.96–9.23 by audience expression. Source: [controlled study record](controlled-studies-20261014.md), AB14 observed results, lines 31–35. No new interval calculation; only unit conversion and rounding. |
| RQ2 | Explain mechanism success separately from qualifying improvement, treatment verification, paired benefit/harm and the different candidate-to-base guard comparison. Clarify action-inclusive semantic-only joint agreement and hypothetical effective artifacts. | Existing paired joint gains 79/69/90 and action gains 123/124/110 accompany the already reported losses. Source: [controlled study record](controlled-studies-20261014.md), completed AD14 results, lines 74–94. All original table counts remain unchanged. |
| RQ3 | Explain what the latency and container resource measurements include; distinguish elapsed time, CPU-seconds and sampled charged memory. Develop the separate consequences of finite privacy loss, estimator error and report selection. | No additional numerical results. Existing cost and telemetry results and their appendix definitions remain authoritative. |

The manuscript's product joint definition was checked against the AB14 protocol text (exact labels plus allowed action), and the matched-continuation definition against the accepted method/appendix and AD14 results. No new scholarly claim or bibliography entry was added. Some historical appendix terminology remains to be aligned when that content is authorized for revision; it was not changed through the Discussion-onward preservation boundary.

Validation at manuscript SHA-256 `e741ce94a5395077a0ac51d7845610cc335d65004b6e5d5634934f61c5f2496a`:

- The entire prefix before RQ1 and the entire suffix beginning at Discussion are identical to accepted checkpoint 2.
- All numerical table bodies, figures, equations and labels are unchanged. Every original numeric token in the three result sections is retained; additional values are identified above. Only the two result-table captions/headers were clarified.
- All citation keys resolve across the four bibliography inputs declared by the manuscript, with no duplicate keys; all cross-referenced labels resolve. An initial check scanning only top-level bibliography files missed two existing nested-file entries; the corrected check uses the actual declared inputs and passes.
- `git diff --check` passes; Git reports its existing LF-to-CRLF conversion advisory. Only the expected manuscript, bibliography and revision record are modified/untracked.
- Whitespace-token counts are RQ1 1,026 to 1,131; RQ2 530 to 629; RQ3 551 to 653. This stage adds 306 tokens. The developed prose remains subject to the final ten-page layout target; compact table-header width, duplicate presentation and supplemental structure need visual review during integration.

No new runtime tests, study execution, external research, temporary files or processes were introduced. `main.pdf` remains stale. Independent ground truth, useful retained adaptation, baseline-relative semantic cost and human/deployment benefit remain empirically unresolved. Writes stop for root review; root owns the next section assignment and eventual integrated build.

## Checkpoint 4: Discussion through appendices, then abstract

Root accepted the complete results rewrite and assigned the remaining prose in this order: Discussion subsections, Conclusion, appendices A–I, and abstract/keywords last. All were revised in that sequence. The accepted Introduction through RQ3 remains unchanged.

Discussion now develops the implications of connected decisions, contextual targets, casewise update regressions, availability and observation boundaries. It uses the already verified Nissenbaum, Yan, RAPPOR and local sanitization references to explain those implications, without a new literature search or new empirical claim. Conclusion answers the original scope through bounded achievements and unresolved effectiveness. Appendix prose retains every supporting protocol, adverse result, quantitative table body, figure, equation, citation and label; AU3 label-joint and product/matched label-and-action joint meanings are made explicit. Historical guard/disclosure metric names are retained where their protocol-specific meaning should not be silently reassigned. Related-system tables now have direct narrative callouts.

The abstract was rewritten last to reflect provisional contextual targets, bounded receiver verification, rejected candidates, unisolated incremental overhead and telemetry limitations. Keywords now include model regression and randomized telemetry. The AI Assistance section identifies the observed uses: provisional contextual labels and manuscript drafting, plus GPT-6 Astra review/rewriting. It states author responsibility without claiming unobserved independent human validation. The institution's required declaration format is unavailable, so this is a truthful manuscript disclosure rather than a claim of confirmed administrative compliance.

Preservation checks confirm unchanged Introduction-through-RQ3, all nine numerical table bodies, both displayed equations, every figure asset reference, every label and all three RQs. All citations resolve across the four declared bibliography inputs, with no duplicate keys; all cross-references resolve. The detailed product figure caption alone gains an explicit action-inclusive joint definition. Whole-source whitespace tokens changed from 11,391 to 11,384 at this checkpoint. No template typography, data, figures or experimental records were changed. `git diff --check` passes with the existing newline-conversion advisory. The PDF remains unchanged and stale, and no runtime tests or experiments were run. Final source SHA-256: `bb71e11fc410654d518be0c3ad2772d8f92d78a8e1267dd7a59b6ee634cc0fb6`.

### Proposed layout plan for root approval

The full source is ready for review before restructuring. A ten-page complete main paper including references is the target; no course acceptance of a separate supplement is assumed.

1. Keep the complete argument, essential policy legend and study definitions, all three RQs, adverse results, four main tables, Discussion, Conclusion, AI acknowledgement and main bibliography in `main.tex`.
2. Preserve rewritten appendices A–I verbatim in an independently buildable `supplement.tex`, with a clear supporting-detail title and its own cited bibliography. Retain their labels, quantitative tables, figures and finite-kernel equation. No evidence is discarded.
3. Keep the architecture overview in the main paper. Move the two detailed enforcement/update diagrams to the supplement, where their mechanisms remain fully preserved; their essential explanations stay in main System Design. This removes repeated visual detail before cutting explanatory prose. Detailed result plots remain in the supplement with direct main-text callouts.
4. Use explicit named supplementary callouts linking to `supplement.pdf` and stable section/figure identifiers. Keep within-document references automatic. This avoids undefined references, cross-document auxiliary-file dependencies and fragile build ordering. Both documents retain IEEE typography; neither the style nor font sizes are compressed.
5. Root compiles both documents and checks page count, references, float placement and legibility. If the main paper still exceeds ten pages, shorten repeated explanations while preserving essential methods, failures and effect sizes; do not claim success before the rendered result passes. The supplement remains clearly additional supporting material, not an asserted rubric exemption.

No layout split has been performed at this checkpoint. Root owns approval of this plan, the integrated build and Git finalization.

## Checkpoint 5: approved layout and verified PDFs

Root accepted checkpoint 4 and approved the preceding plan, authorizing source restructuring and the installed multi-file LaTeX toolchain. The new `paper/supplement.tex` (historical supporting source at `075a0cd6`) preserves rewritten appendices A–I and the detailed enforcement/update diagrams; its title identifies it as supporting detail. The [main source](../main.tex) retains the overview, essential definitions and study units, all four main tables, numerical and adverse findings, primary-source argument, AI acknowledgement and references. Explicit named links connect the PDFs without external auxiliary-file dependencies. Supplementary figures use S1–S4, tables SI–SV and the finite equation S1. All original labels remain in their owning document.

The first complete build produced eleven main pages and seven supporting pages. The eleventh main page contained only references 14–22. Root approved removing repeated explanations while retaining developed prose and qualifications. Reducing the Discussion from 888 to 692 whitespace tokens was sufficient: no layout compression of the Introduction, Design, Methods or Results was needed. The source retains the same IEEEtran conference class, font settings, margins and US Letter page size. The final main PDF has ten complete pages, including its references. This meets the conservative length target for that file, without establishing whether the course accepts the separate supplement or whether IEEEtran is the prescribed template.

### Build procedure and tool limits

The PDF skill operation marker completed successfully exactly once, before restructuring/building, with `--operation-kind edit --expected-output-count 2 --output-format pdf`. The existing multi-file LaTeX project was compiled with installed MiKTeX, not converted through a standalone document compiler. From `paper/`, the compilation sequence used:

```text
pdflatex --disable-installer --no-shell-escape --interaction=nonstopmode --halt-on-error --output-directory=<build-directory> main.tex
bibtex --disable-installer <build-directory>/main
pdflatex --disable-installer --no-shell-escape --interaction=nonstopmode --halt-on-error --output-directory=<build-directory> main.tex
pdflatex --disable-installer --no-shell-escape --interaction=nonstopmode --halt-on-error --output-directory=<build-directory> main.tex
```

The same sequence built `supplement.tex`. Here `<build-directory>` is the repository-owned `evaluation/results/rubric_rewrite_20261017`. Two further main passes followed the repetition-only edit. Every completed compiler/BibTeX pass exited zero. The initial sandbox attempt could not read MiKTeX registry/configuration; narrow automatic approval for local compilation succeeded, with package installation and shell escape disabled throughout. No package was installed and no application/runtime service was started. The shell-escape warning is expected because embedded figures are already PDFs.

Bundled Poppler `pdftoppm` rendered every final page at 120 dpi into the build directory's `renders/`. The bundled `pdffonts` executable was unavailable, so font embedding was verified directly from PDF font descriptors with `pypdf`, including Type0 descendant fonts and Type3 embedded glyphs. A first descriptor-only check falsely flagged two existing diagram fonts; the recursive check confirms all fonts are embedded in both documents. Read-only text checks that initially used Windows' default encoding were rerun with explicit UTF-8. These tooling corrections changed no research data or outcomes.

### Acceptance evidence and preservation

The new [source/PDF check record](../../evaluation/results/rubric_rewrite_20261017/source-and-pdf-checks.json), compiler logs and seventeen page renders retain current-artifact evidence. Earlier validation records were not overwritten. Every main page 1–10 and supporting page 1–7 was visually inspected: text, citations, tables, equations and figures are legible, with no clipping, overlap, missing glyphs or blank pages. Table headers fit their columns, supplementary table order is SI–SV, and the main reference list ends within page ten. Final logs contain no overfull boxes or undefined references/citations; residual underfull spacing warnings were checked visually.

Checks against input Git revision `017ad37` confirm that all nine numerical table bodies are identical, both displayed equations are byte-identical, all original labels remain, and all five figure asset references are preserved. All three professor-specified RQs remain unchanged. The source citation audit identifies the three already documented checkpoint-1 removals with the replaced broad provider-policy sentence: `Athey2017`, `King2025` and `barbera2025ai`. Their existing BibTeX entries remain unchanged, and no new claim relies on them. Other original cited keys are retained across the two documents. Four verified foundational entries were added during checkpoints 1–2; no new sources were introduced during the later rewrite/layout stages.

Twenty main-to-supplement PDF links and one return link are encoded as relative file links. Both PDFs are colocated so these references have a portable target; within-document references resolve independently. Reader-specific handling of external PDF links is outside the compile check. Final build PDFs were copied to [the main PDF](../main.pdf) and `paper/supplement.pdf` (historical supporting PDF at `075a0cd6`), with matching bytes.

| Artifact | SHA-256 |
| --- | --- |
| `paper/main.tex` | `d992ff45401121215f27120ff2abc421eaf5ef2c5169168b4b7fe54a10d77d30` |
| `paper/main.pdf` | `b70625330ed4a7709383a665f997e7d2d61af3c17139fac254ad94d42836bf92` |
| `paper/supplement.tex` | `51596da20e73143fb805850836e6c3e80fd210c21f92138dee1ce62e8b3fb9c7` |
| `paper/supplement.pdf` | `ea54656536eac8af24ccfd061e64766027c739ca87f5f9e5df72f167fe79d5d8` |

All work remains document-only: no inference, training, Python test suites, scoring, resampling or protected raw-data access occurred. Independently adjudicated contextual accuracy, useful retained adaptation, baseline-relative semantic cost and user/deployment benefit remain unresolved; the prose does not claim otherwise. The exact institutional AI declaration format, prescribed template and treatment of supplementary material remain unverified. Build logs and renders are deliberately retained as local validation evidence in the ignored results directory; no disposable scratch directory or live process remains. The writer stops at this stable checkpoint, with root responsible for independent acceptance and Git finalization.

### Root acceptance and final rubric alignment

Root independently inspected all seventeen final rendered pages and accepted the substantive rewrite, style and layout. Its separate original-versus-main-plus-supplement audit confirmed identical numerical table sequences, preserved labels and five figure assets, and both equations. Root found readable normal IEEE typography, no overlap/clipping and agreement between source/PDF structure and page counts. Compilation was performed by the Astra writer with root's explicit approval and narrow host approval for MiKTeX configuration access; root then performed independent acceptance. The earlier proposed allocation of compilation to root was superseded by that authorization.

| Rubric category | Final revision contribution | Remaining limit |
| --- | --- | --- |
| Background/context/literature, 30% | Developed motivation and gap-to-contribution argument across enforcement, retained behavior and reporting; verified foundational sources and version-qualified related-system distinctions. | No matched end-to-end superiority claim or invented novelty; the literature comparison remains bounded by reviewed versions. |
| Scientific/engineering work, 50% | Explicit policy/execution boundaries, study units and metric definitions; paired gains/harms, correct uncertainty scopes, guard versus assessment distinction and direct answers to all three unchanged RQs. | Editorial improvement does not create independent ground truth, generalization, useful retained adaptation, incremental semantic overhead or human benefit. Negative evidence remains visible. |
| Structure/presentation, 10% | Ten-page complete main paper, separately labelled seven-page supporting detail, resolved callouts and independently reviewed tables/figures/equations. | Official template requirements and acceptance of supplementary material are unverified. No font, margin or page-size reduction was used. |
| Clarity/referencing, 10% | Consistent explanatory prose, explicit joint-metric meanings, verified added sources, complete references and truthful AI assistance acknowledgement. | Institution-specific AI declaration format remains unavailable. No grade or highest-band outcome is guaranteed. |

Final owned deliverables are `paper/main.tex`, `paper/main.pdf`, `paper/supplement.tex`, `paper/supplement.pdf`, `paper/ref.bib` and this record. No further writer mutation, commit or push is planned. Root owns the scoped commit; the prior automatic approval rejection still prevents treating a push as authorized or completed without the required new user authorization.

## NOAPPX17: self-contained paper with a reduced evidence set

**New user request, verbatim:**

> The paper is not allowed to have an appendix. Given this, rewrite the sections that rely on the appendix, reducing the coverage of tests conducted to only the meaningful ones that link back to the research questions. Use the same astra subagent to do this work

**Status:** selection plan ready for root review; no manuscript/PDF restructuring or supplement deletion has yet occurred for this revision. The same Astra writer continues sequentially, with root retaining Git ownership. Input is clean `docs/paper` at `075a0cd6deb7c7a57b4de4994ebe5bbaa9bbb5a0`. The current source hashes still match the accepted ten-page main and seven-page supplement above. The no-appendix instruction supersedes the previous two-document submission plan and the requirement to reproduce every study in the submission. Earlier records remain historical evidence, not the current delivery specification.

### Instruction delta and selection principle

Shared/leaf/implementer/research/vision/validation/Git/coordination/PDF/writing-style instructions remain loaded from the preceding work; architecture and critic owners were reloaded for the revised claim/evidence boundary. Read-only review used the current manuscript and supplement, relevant rubric-evaluation sections and the compact evidence records below. No protected row data, runtime, inference, fitting, test suite, scoring or resampling was accessed or executed. Only this new revision section is written before root selection approval.

The submission will tell one coherent story: whether the implemented request policy works on its declared targets and supported paths, whether matched model continuation retains protected behavior, and what processing/reporting costs are actually measured. A study is retained when it answers a distinct part of those questions or exposes a necessary counterexample. Repeated evidence, incompatible rankings and engineering validation that does not directly answer an RQ can leave the submission without being erased from the research record. The selection is made by inferential role, not whether an outcome is favourable.

### Proposed retain map and required main-text detail

| Retained unit | RQ and reason | Main-text methods/definitions to preserve or promote | Decisive findings that must remain |
| --- | --- | --- | --- |
| Historical versus updated full-product contextual comparison, all three package tiers | RQ1: directly assesses the implemented label/action policy. Keep all tiers rather than choose the most favourable one. | 1,560 authored provisional cases: 810 sensitive, 750 clean, 260 per audience; 35 families/24 expression groups; prior sealing then reuse; no independent human adjudication. Explicit rules/NER/semantic request and actual skips; label-and-action joint and allowed-action metrics. Native windows 64/96/128 versus 512, thresholds .38 versus .5, package capacity/training confounding and validation-selected artifact lineage at a compact level. First-pass outcomes; repeat calls are not new cases. | Existing full-product table and paired gains/losses, including quality's label/action distinction and the 139 shared unnecessary restrictions. Zero errors stays a table note rather than a separate result. No promotion or general privacy superiority. |
| Targeted balanced-package detector removal | RQ1: explains the shared cascade restriction and the protection lost when rules are removed. | Same package, cases and policy; report the relevant full `[2,3,4]`, no-regex `[3,4]` and no-NER `[2,4]` contrasts, each with verified actual execution. The remaining four executed configurations need not become additional reported tests. Define under/over-restriction and preserve separate paired family/expression resampling assumptions (2,000 draws, seed 42, linear 95% ranges; corrected expression grouping). | Action 1,409 to 1,530; 139 improvements and 18 losses; joint 717 to 972; under-restriction 12 to 30. Existing action-gain ranges 3.46–12.70 and 5.96–9.23 percentage points. No-NER equality is bounded by zero converted findings on this fixture, not a recommendation to disable NER universally. |
| Frozen final annotation-presence endpoint, all six semantic-only arms | RQ1: the strongest distinct-target negative check, with frozen selection and no post-release tuning. | 498 PIIMB rows at revision `4a13e9f`, 236 positive/262 negative; nonzero sensitivity/category prediction proxy, distinct from contextual authorization and official character/F2 evaluation. Explicit sole-semantic requested and returned execution. 464 observed source groups; 2,000 paired whole-cluster row-weighted draws, seed 42, linear percentile ranges; descriptive/unadjusted and not proof of template independence. Preserve source imbalance and the need for a new protected successor. | Full TP/TN/FP/FN table; updated specificity 13.36–21.76% despite recall gains; original paired accuracy ranges and uncertainty on quality specificity. Do not present this as a same-target continuation of the full-product score. The separate AU3 semantic clean-specificity comparison can be omitted with its extra experimental endpoint. |
| Installed receiver-enforcement probes | RQ1: distinguishes a classification/action from actual transmission. | 33 synthetic probes in installed unpacked Linux Chromium with standard native launch, historical balanced detector and local HTTPS receiver; byte-preserving sends, zero-send outcomes, late-arrival checks and actual full/sole-semantic execution. Separate these probes from cost windows. | 18 unchanged-body sends/15 zero-send outcomes; WARN forwards; analysis failure versus semantic-stream fallback; disabled protection bypass; recovery. Keep failed captures unpooled, and no real-provider/platform/usability generalization. |
| Fixed-base matched HEADS/FULL continuation plus retention guard | RQ2: directly tests aggregate improvement against casewise losses and acceptance. This is the only reported adaptation experiment. | Three seeds 42/43/44; byte-identical intact pretrained balanced base with zero heads; 4,096 matched exposures/64 steps; objective, AdamW learning rates, micro/effective batch, disabled dropout and changed gradient-clipping scope. TRAIN/guard group/text exclusions leave 1,080 reused cases; 16 separate guard rows. Distinguish action-inclusive assessment from the guard's single derived target action, all terminal candidates from effective artifacts, and in-process semantic-only assessment from deployment. | Existing six-candidate joint/action/guard table; paired gains and losses; directional harms not summed; all FULL candidates fail, HEADS 42/44 pass and 43 fails. No candidate published; weak base and small guard limit inference. Do not retain an empirical publication/client-refresh success claim whose separate supporting test is dropped. |
| Installed rules/NER browser cost | RQ3: measures a declared processing configuration without inventing semantic or baseline-relative overhead. | Twelve fresh profiles, two per fetch/XHR/action cell; first decision, five warmups and thirty measured requests per profile. 360 measured decisions, actual 240 dual-layer versus 120 rules-only BLOCK paths. Page analysis-request/result latency; two profile clusters per cell. Whole-container CPU/charged memory, included observer/infrastructure/cache, 100-ms requested sampling and actual gaps; no unprotected baseline or semantic cost. | Six-cell descriptive latency table (p50/p95/observed maximum), CPU 193.29 CPU-seconds over 126.40 seconds, observer 0.69 and memory 1,267.91 MiB; maximum sampling gap 622.84 ms. Exclude separate startup-interval and host-RPC/training-speed catalogues. |
| Telemetry finite-content privacy, estimator error and accounting/selection | RQ3: privacy cost cannot be interpreted without both the implemented kernel and the usefulness/selection limits of its reports. Treat these as three properties of one reporting mechanism. | Five domains `K=3,4,11,2,6`, equal budget split, ideal and finite equations, binary64 threshold/53-bit truth draw/rejection sampling, fingerprinted Windows CPython 3.11.9 and independent uniform-entropy assumption. Three audited budgets .5/1/2, nominal ledger cap eight/day. Explain inverse-response estimator and clipping; 180 fixed-truth cells/10,000 repetitions, budget/contributor/domain/truth-shape sweep and fixed-contributor estimand. | Retain all three tiny nominal-bound excesses and eight-event composition. Show existing balanced-category examples at `n=80/8000` (truth 7/727, bias +22.84/+237.50, RMSE 42.32/1028.47, clipping and incoherent totals), explicitly illustrative reported cells rather than deployment-utility success. Retain cap/reopen/rollover/concurrency/failure accounting and the 32-event order reversal, 25% overall BLOCK versus 100%/0% contributors. Content privacy excludes participation/delivery/metadata. |

### Proposed drop map

| Remove from the submission | Reason and safeguard |
| --- | --- |
| Small/large Presidio contextual comparisons and restricted five-type external reference | They compare entity-finding targets/configurations with a contextual policy and do not test matched end-to-end protection. Remove both favourable and unfavourable scores, without implying competitive superiority. Related-work discussion remains qualitative and version-qualified. |
| AdvPIIBench 2,000-row category experiment | It adds a second mismatched target and a different any-finding proxy. The final annotation-presence endpoint already supplies a stronger frozen distinct-target check. Remove its poor specificity and high recall together; retain the final endpoint's poor specificity prominently. |
| Historical 502-row development comparison and historical adaptation grids/curricula/accelerated studies | These heterogeneous protocols do not improve the interpretation of the retained controlled tests. Remove failed-attempt budget catalogues and favourable supervised-stage gains together. RQ2's all-FULL rejection remains the central negative outcome. |
| Separate EN3-to-AU3 semantic comparison and full selected-epoch ancestry table | The paper need not report a second supervised package-effect experiment. Retain only the artifact lineage and native configuration differences needed to interpret the full-product comparison; do not rebrand those package differences as causal adaptation. |
| Detailed per-label subgroup catalogue and repeated-call totals | The main paired outcomes and controlled ablation answer the causal/mechanistic question more directly. Keep denominators and repetition/dependence limits; repetitions do not become extra samples. |
| Host-RPC medians/RSS, training timings/CUDA peaks and browser-startup interval catalogue | Different scopes and fixed ordering cannot answer incremental or semantic overhead. Retain the coherent browser decision/cgroup cost study and its explicit unresolved overhead claim. |
| Local 195-pin reconstruction/24-probe capsule and 53 synthetic client-event tests | These validate reconstruction or a diagnostic contract, not contextual effectiveness, retained protection or measured overhead. Remove them from methods/results/discussion; keep the lack of measured human/task utility. |
| External systems' numerical outcome table and detailed function table | Incompatible outcome definitions and denominators preclude a ranking. Retain the literature synthesis needed for motivation, gap and the distinction between sanitization/recovery and request actions. |
| Supplementary duplicate result plots and detailed enforcement/update diagrams | Their essential mechanisms and results are stated in the main text and tables. Keep the single overview figure; preserve reusable figure files in the repository, with no manuscript pointer to excluded material. |

The existing research/aggregate records, source assets and historical Git revisions remain intact. Once the self-contained main is complete, delete only the task-created `paper/supplement.tex` and `paper/supplement.pdf`. The manuscript must contain no appendix, renamed appendix, companion document, supporting-detail pointer or unresolved transferred label.

### Promoted definitions and presentation plan

System Design will contain the complete compact S0–S3/P0–P4/PU legend, ten category names, deterministic exceptions and low-confidence action mapping; the confidence score remains uncalibrated. Exact-base checks, staged publication/replay and local-versus-hosted boundaries stay explicit. The two telemetry equations belong next to their ideal/finite assumptions in the main text.

Methods will identify the retained evidence units and the target, sample, detector scope, comparator and uncertainty appropriate to each. All interpretive qualifications needed to understand a result stay with its first use. Six compact tables are provisionally appropriate: study map, full-product comparison, final confusion counts, matched continuation/guard, browser latency and two telemetry utility examples. The targeted ablation and receiver outcomes can remain short, numerical explanatory paragraphs. The existing overview figure carries the architecture; no new graphic is necessary. The exact three RQs and connected historical-introduction style remain unchanged.

The Discussion will synthesize only the retained evidence against contextual-integrity, regression and locally randomized-reporting literature. Conclusions and abstract will be rewritten last so they make no claim dependent on an excluded experiment. AI acknowledgement remains truthful and explicit. The complete main PDF, including references, must remain at most ten pages without typography reductions. Only after root approves this selection will source rewriting, removal of obsolete supplement artifacts and a new one-output PDF build begin.

### Source checks for the selection

The principal retained evidence was checked in [pipeline comparison](pipeline-comparison-20261014.json) (`workload`, `models`, `paired`), [controlled studies](controlled-studies-20261014.md) and [their aggregate](controlled-studies-20261014.json) (`ablation`, `adaptation.policy`, `main`, summaries and paired contrasts), [final semantic evidence](final-semantic-evidence-20261014.json) (`rows`, `group_audit`, `metrics`, `uncertainty`, `paired_within_tier`, limitations), [installed-client record](installed-client-evidence-20261014.md) and [aggregate](installed-client-evidence-20261014.json) (selected correctness and complete cost study), and [telemetry record](telemetry-evidence-20261014.md) and [aggregate](telemetry-evidence-20261014.json) (finite audit, synthetic cells, ledger/selection and clarifications). The [installed-browser protocol](installed-browser-protocol.md) supplies observation boundaries. These are already generated aggregate/protocol records, not newly accessed protected examples. No scholarly source or measurement was added during selection.

**Stopping condition:** root accepts or amends the retain/drop map. Manuscript, PDFs and obsolete supplement artifacts remain unchanged until that response. Subsequent build/acceptance evidence will be appended here and written under a new ignored directory, `evaluation/results/rubric_no_appendix_20261017`, without replacing the previous validation record.


### NOAPPX17 approved selection and source checkpoint

Root accepted the seven-unit map and authorized sequential rewriting. Design, Methods, RQ1, RQ2, RQ3, Discussion/Conclusion and the abstract were revised in that order. The Introduction and its three RQs are unchanged. Related Work and the overview caption received necessary removal of excluded-study claims and companion pointers. This revision follows the approved selection without adding an empirical unit or measurement. The six tables are the study map, three retained results tables, promoted browser latency table and two previously reported telemetry utility cells; both ideal and finite equations now appear in the main paper. Exact policy exceptions were checked against `extension/client-runtime/src/classification/classification_policy.py`, including PU's non-restricted treatment and the S2 identity/location confidence exception.

The source contains no appendix, supplement, supporting-detail or supporting-figure pointer. Removed studies are exactly the families identified in the preceding drop map, including both favourable and unfavourable mismatched recognizer/category comparisons. Poor final specificity, cascade losses, all full-model guard rejections and telemetry estimation/accounting limitations remain visible. No new experiment, scoring, resampling or scholarly claim was introduced. Main PDF acceptance is pending the new build, complete-page inspection and root review.

The earlier two-document checkpoint is historical, superseded by this user correction. Its removed-artifact links are now explicitly historical paths, recoverable without changing the current checkout using `git show 075a0cd6:paper/supplement.tex` or `git show 075a0cd6:paper/supplement.pdf` (use a binary-safe Git export for the PDF). Git retains these artifacts; none is part of the current submission. Existing research records and reusable figures remain intact.


### NOAPPX17 final build, evidence audit and acceptance

**Result:** one self-contained ten-page paper, including all references, with no appendix or supplementary dependency. `paper/supplement.tex` and `paper/supplement.pdf` are deleted as obsolete submission artifacts. No excluded study was relocated under another heading or companion deliverable. The prior records and reusable figures remain historical research evidence. Root accepted the revised substantive source and independently inspected all ten new rendered pages, finding the six tables, equations, figure and ordinary IEEE typography readable without overlaps or clipping. Final delivered-file hash confirmation remains part of root's Git acceptance.

The PDF operation marker succeeded once for this revision with `--operation-kind edit --expected-output-count 1 --output-format pdf`. The Astra writer compiled with installed MiKTeX from `paper/`, using the same pdflatex/BibTeX/pdflatex/pdflatex sequence documented above, but writing only `main` into `evaluation/results/rubric_no_appendix_20261017`. Package installation and shell escape were disabled throughout. The initial sandbox compilation could not access MiKTeX registry/configuration; narrowly approved local compilation then succeeded, with all four passes exiting zero. The initial cleanup command used the wrong relative working directory and removed no supplement; this was corrected using verified absolute targets, and its empty accidental directory was removed. No package was installed and no research/application service was run.

The first completed build already fit ten pages; no typography reduction or additional page-fit deletion was necessary. Bundled Poppler rendered every page at 120 dpi. The writer inspected all ten full-page images; root independently inspected the same set. PDF descriptors, including the overview figure's nested resources, confirm 21 embedded fonts. Every page is 612 by 792 points (US Letter). The final log has no undefined references/citations or overfull boxes; its sole warning is the expected disabled-shell-escape notice. Source parsing confirms all local references/citation keys resolve and labels are unique. Both source and extracted PDF have zero matches for appendix/appendices, supplement, supporting detail or supporting figure. The complete Introduction, including all three RQs, is byte-identical to `075a0cd6`; the two displayed equations are byte-identical to their earlier main/supplement sources.

#### Numerical preservation and promoted origins

The previous two-document submission contained nine tables: four main and five supplementary. The new main contains six: a rewritten evidence map, three unchanged result tables, one promoted latency table and one table of existing telemetry examples. Counts below concern numeric tokens in data rows, excluding headings/captions, so a paired entry such as `266/693` contributes two tokens.

| Current table | Origin at `075a0cd6` or existing aggregate | Data-row check |
| --- | --- | --- |
| Full-product contextual results (`tab:pipeline_v1_v3`) | Original main table | 3 rows, 24 numeric tokens; identical in order and value. |
| Final semantic confusion counts (`tab:final_presence`) | Original main table | 3 rows, 24 numeric tokens; identical in order and value. |
| Matched continuation (`tab:matched_continuation`) | Original main table | 3 rows, 21 numeric tokens including seeds; identical in order and value. |
| Browser latency (`tab:browser_cost`) | Former supplement table, originating in installed-client evidence | 6 rows, 18 numeric tokens; identical in order and value. The former p99 header is now Max because these values are observed maxima. |
| Telemetry utility (`tab:telemetry_utility`) | `telemetry-evidence-20261014.json`, `synthetic_cells`: `e1-n80-uniform-primary_category` and `e1-n8000-uniform-primary_category`; already reported in the telemetry Markdown and former supplement prose | 2 rows, 12 numeric tokens; all values independently matched to existing aggregate fields at the displayed precision. Percentages are the existing clipping/incoherence fractions multiplied by 100. |

Thus the four retained pre-existing numerical tables preserve all 87 data-row numeric tokens, while the added utility table promotes twelve existing displayed values rather than a new experiment or estimate. The old related-functions, incompatible external-results, full selected-lineage and host-RPC-cost tables leave the submission; the question map is rewritten to describe the reduced selection. Their omission is deliberate and covered by the approved drop map, not numerical preservation failure. Existing paired gain/loss prose, adverse outcomes and uncertainty remain attached to the retained studies. The final PDF contains one unchanged overview figure and two equations; the removed diagrams/plots remain reusable repository assets but have no paper callout.

The machine-readable checks, extracted text, four compiler console logs, final log and all renders are retained in the new ignored build directory. `source-and-pdf-checks.json` binds source and delivered PDF, records the table audit and telemetry cell IDs, and verifies the build PDF is byte-identical to the delivered copy. It does not overwrite the earlier two-document acceptance record.

| Delivered artifact | SHA-256 |
| --- | --- |
| `paper/main.tex` | `7c23969bd9ab3a909b1f392d31a9d1e3eaaf8f30211a248ca8249716f8857037` |
| `paper/main.pdf` | `ee0ff71cf557bd564aa369449bf3127860e9a2cc2434e8a8615e2d83a54d1900` |

The AI statement remains: “AI assistance was used to produce provisional contextual labels and support manuscript drafting. GPT-6 Astra assisted manuscript review and rewriting. The provisional labels have not been established as independently adjudicated ground truth. Responsibility for the manuscript and its claims remains with the authors.” No unobserved human checking or label-generation model is asserted.

This revision improves the rubric's coherence, experimental relevance and self-contained presentation while preserving the scientific limits: contextual labels and policy are unvalidated; source grouping does not establish template independence; package contrasts are confounded; final specificity is poor; every matched full-model candidate fails the small guard; installed enforcement covers declared Linux/synthetic-receiver paths; semantic and incremental cost, human utility and deployment benefit are unmeasured; telemetry's finite content bound is conditional and excludes participation, delivery and metadata, with substantial estimator/selection error. The prescribed institutional template and exact AI declaration format remain unavailable. Appendices are now explicitly forbidden, and no uncertainty about supplement acceptance is used to justify one. No mark is guaranteed.

Only `paper/main.tex`, `paper/main.pdf`, this revision record and deletion of the two obsolete supplement artifacts belong to this change. No inference, training, tests, scoring, resampling or protected raw-data access occurred. No disposable scratch directory or live writer process remains; ignored build artifacts are retained validation evidence. Root owns final acceptance and scoped Git finalization. The writer does not commit or push and stops manuscript/PDF writes at this checkpoint.


**Final root acceptance:** Root independently confirmed the delivered ten-page PDF includes references, matches the build bytes and the source/PDF hashes above, and has no forbidden companion pointers. Its retained-table audit includes exact browser data-row equality; local references/citations resolve, compiler diagnostics show no overflow, undefined/multiply-defined references or missing glyphs, and binary-aware diff checking passes. Root independently viewed all ten final renders. The record's 22 current local Markdown links resolve after URL decoding; removed supplement links are explicitly historical. The five owned paths are stable and accepted for root's scoped commit. Writer edits have ceased.


## Template alignment follow-up — 17 October 2026

The subsequently supplied IEEEtran journal template has now been applied while preserving the seven-study scope, custom features and ten-page limit. See the [template alignment record](template-alignment-20261017.md) for the new source/PDF bindings, complete visual checks and retained customizations. Earlier statements above about an unavailable template describe the historical revision, not the current artifact.
