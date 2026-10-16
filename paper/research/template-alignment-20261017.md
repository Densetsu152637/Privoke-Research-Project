# Template alignment — 17 October 2026

**Record ID:** TEMPLATE-20261017. **User request:** “I have added in the template. Ensure the paper meets the template (but keep any custom things the paper has)”. **Input Git HEAD:** `6e95752752de6af10f0398d198508e9139bc27de`, branch `docs/paper`. The tracked checkout was clean; `paper/template.tex` was the user's untracked input. This record describes the resulting working artifacts, not the files at that input commit.

The goal was to apply the supplied template's relevant manuscript conventions without changing the scientific study or losing custom features. The complete 891-line [template](../template.tex), current source and PDF, [rewrite scope](../REWRITE_SCOPE.md) and [rubric review](../rubric-evaluation.md) were consulted. The accepted seven evidence units, exact RQs, negative outcomes and self-contained ten-page/no-appendix constraint remain authoritative. No new literature, measurements, experiments, inference, training, scoring, resampling or protected raw data were used.

## Applied requirements and retained customizations

| Supplied template convention | Applied treatment |
| --- | --- |
| Default `\documentclass{IEEEtran}` journal layout | Replaced the conference option with the template's default class. No font, margin or page-size reduction. Removed the conference-only command-lock override. |
| Journal author line and affiliation footnotes | Preserved all four names, affiliations and email addresses; converted the conference blocks into an inline author line and real affiliation footnotes. Corresponding-author and repository information remain. No IEEE membership or support claim was invented. |
| Mixed-case title and standalone abstract | Expanded title “LLMs” to “Large Language Models”; expanded the abstract's named entity recognition term. The abstract is one paragraph, 184 whitespace-counted words, with no citations, footnotes or displayed material. Its quantities, adverse findings and qualifications remain. |
| Alphabetical index terms | Sorted the same six keywords alphabetically. |
| Drop-cap introduction and defined abbreviations | Added `\IEEEPARstart`; expanded technical terms at first use where needed, including LLMs, NER, XHR, BERT, UTC, HTTPS, CPU, RSS/PSS, OS, RMSE and AI. gRPC-Web is introduced as a remote-procedure-call protocol. Existing model identifiers and study-arm names remain meaningful identifiers. |
| Equations and soft references | Retained both equations, numbers, labels and symbol definitions. Added terminal punctuation to the first equation; its mathematics is unchanged. Used `Fig.` for the figure callout. Existing Roman table numbers, table captions above and figure caption below remain appropriate. |
| IEEE references | Switched the bibliography formatter from `ieeetr` to `IEEEtran`, retaining all citation keys and the existing four bibliography inputs. Added hyphen line-break opportunities for long URLs after initial rendered reference overflow; no bibliography data were edited. |
| Figures, tables and readable typography | Preserved the overview vector graphic, six tables and two equations with normal IEEE typography. All twenty PDF font resources, including the graphic's Arial fonts, are embedded. |

The custom `\privoke` macro, T1 font encoding, citation/hyperlink support, existing graphic paths, `booktabs`, table/float support, listings and compatible `algorithm`/`algpseudocode` setup remain. A duplicate unused `comment` package declaration was removed; the retained declaration is unchanged. The template's sample `algorithmic` package was not added to conflict with the existing implementation. Custom `\raggedbottom` was preserved after reviewing journal layout, preventing unnecessary vertical stretching. Repository and corresponding-author footnotes remain, as do the AI Assistance statement and version-qualified source details.

Sample title, dummy author data, memberships, manuscript-received dates, funding, copyright notices, biographies and sample sections were not copied into the paper. Optional biographies are not treated as mandatory; the template's optional appendix example is overridden by the user's explicit prohibition. Graphic naming advice concerns publication-delivery packaging, so the requested custom asset paths were retained. No journal submission, external contact or publication action was authorized or taken. This is alignment to the applicable supplied manuscript conventions, not a claim of acceptance by an IEEE journal or guaranteed rubric marks.

## Preservation audit

The full six table environments are byte-identical as extracted from input HEAD and the current source. Their data-row numeric token counts are: question map 10; contextual product 24; final semantic presence 24; matched continuation 21; browser cost 18; telemetry utility 12. That is **109 tokens including the map, or 99 across the five result tables**. All figures, labels, citation-key sequences and the exact three RQ strings are preserved. Both displayed mathematical expressions match the input after allowing only the first equation's new terminal period. No study arm, seed, measurement, adverse finding or uncertainty was removed to fit the new layout. The retained full-pipeline and semantic-only boundaries remain distinct.

The main source and extracted final PDF contain no appendix, supplement or supporting-detail dependency. The rewrite scope and bibliography files were not modified. The AI statement still identifies provisional-label/drafting assistance, GPT-6 Astra review and rewriting, lack of independent label adjudication and author responsibility; expanding “AI” at first use does not assert any new activity.

## Build and visual validation

The PDF skill's operation marker ran once before authoring, for one edited PDF. Installed MiKTeX `pdflatex` and BibTeX were used with approved narrowly scoped configuration access; package installation and shell escape were disabled. Builds ran from `paper/` into the new ignored directory `evaluation/results/template_alignment_20261017`:

```text
pdflatex --disable-installer --no-shell-escape --interaction=nonstopmode --halt-on-error --output-directory=<build-directory> main.tex
bibtex --disable-installer <build-directory>/main
pdflatex --disable-installer --no-shell-escape --interaction=nonstopmode --halt-on-error --output-directory=<build-directory> main.tex
```

The initial build and bibliography pass completed; repeated LaTeX passes settled cross-references. Two long reference URLs initially exceeded their columns. Hyphen break opportunities repaired them. The final spacing pass restored the custom ragged-bottom setting, then recompilation and complete rendering were repeated. The final build is **pass7**, with all compiler invocations completing successfully. The final log has no overfull boxes, undefined or multiply-defined references, or missing-glyph diagnostics. Residual underfull horizontal boxes and the expected disabled-shell-escape warning are recorded; their rendered locations were inspected and remain readable. No package installation was attempted.

The final PDF has **ten US Letter pages, including all twenty references**, one overview figure, six tables and two equations. The 120-dpi Poppler render of every final page was inspected, including author/email footnotes, drop-cap opening, column transitions, tables, mathematical notation and wrapped reference URLs. No clipping, overlap or unreadable content was observed. All twenty font resources are embedded, and all local reference labels resolve. The final build was copied to `paper/main.pdf`; delivered and build PDF bytes match.

**Root visual and source acceptance:** Root independently inspected all ten final pass7 renders and the complete source diff in bounded reads, accepting the journal layout, retained custom spacing and format-only changes. Root found the author footnotes, six tables, overview, equations and references readable without clipping or overlap. Final independent hash/record acceptance and Git finalization remain root's responsibility.

Machine-readable bindings, preservation checks, extracted text, all build logs and the ten final renders are retained under the ignored build directory, including `source-and-pdf-checks.json`. This is new validation evidence; it does not overwrite or reuse the earlier NOAPPX17 acceptance record.

| Artifact | SHA-256 |
| --- | --- |
| `paper/template.tex` — unchanged user input | `e4ea281c35acf1028e726f0777f2b75817478824a6b6fa723bd8b85ae8d9c056` |
| `paper/main.tex` — final source | `df437e6c074fda23882040487268adb3db66a368fe75d0e9efdca32b94c4a7cb` |
| `paper/main.pdf` — delivered/build-identical PDF | `407b51a91dbed06a8db87c0636f560ae30a79f3794272f62c16ff2585ba155c4` |

The rubric review's template-related statements, input bindings and physical-page locators have been refreshed. Its scientific band judgments and six remaining improvement priorities have not been rerated. Provisional labels, limited guard/base, poor final specificity, measurement boundaries and absent human/deployment-benefit evidence remain empirical limits. The supplied template is no longer unavailable; a separate institution-specific AI declaration form remains unverified.

The owned deliverables are `paper/main.tex`, `paper/main.pdf`, `paper/rubric-evaluation.md`, this record and its short discovery link in the existing rewrite record. The user template remains unchanged and untracked. No disposable scratch or active writer process remains; ignored build outputs are retained evidence. The writer stops changes for root review and does not commit or push.
