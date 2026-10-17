# External-version expansion and original-format restoration

**Record:** LONG22. **Date:** 18 October 2026. **Input:** `33c5bf93dbfcb620539619a9a50b4dc989cce68f`, branch `docs/paper`. **Scope:** manuscript and editorial documentation only; no training, inference, scoring, resampling or new empirical results.

## Request and questions

Exact user request:

> Now, Please restore them, along with the format of the original template (not the Monash one, but from before that). Document that now the paper no longer has a page limit, and that the appendix section can be added back in. The original introduction can be merged with the current one, so that the introduction of PriVoke outlines the precedents and the variables which influenced the research. However, keep any changes you have made to the introduction (not reductions, but refactors). This can also be done for methodology and discussion, as nuance often requires more pages to expand

The immediate author-list context identifies the restored authors as Manpreet Sahadevan and Nixon Ngai. The required order is Nicholas Bisset, Manpreet Sahadevan, Nixon Ngai and Sanoop Mallissery. The questions for this revision were: which historical format preceded the journal conversion; which explanatory material can be merged without reversing later corrections; and which appendix details elaborate the authorized seven evidence units without reopening excluded experiments?

## Historical evidence and merge decisions

| Question | Evidence | Decision and boundary |
| --- | --- | --- |
| Original format and author block | Earliest manuscript `fd91b259`, preserved reference `26580f27:paper/old/reference.tex`, and `5e6b649b:paper/main.tex` use `IEEEtran[conference]`, author blocks and command-lockout override. `a70be124` switched to journal layout. | Restore conference class and historical four-author affiliation/email block. Keep the current title and omit the old placeholder submission date. The later `paper/template.tex` is not the original format source. |
| Original motivation and research influences | `d72075b35240b96a16cd062d5d3d91b0189d6f74:paper/main.tex` (parent of the first broad compression) and `5e6b649b` retain broader introduction/background, policy detail and methodological appendices. | Merge hosted/local choice, outgoing-versus-already-disclosed information, contextual attributes, detector composition, capacity/windows/pretraining/thresholds, update scope/exposure/retention and reporting admission/privacy/error into the current connected prose. Do not restore unsupported frontier-model parameter estimates, generalized provider policies or claims of autonomous learning. |
| Preserve later refactors | Current `33c5bf93` includes `28991071` prose refactors, later synthesis, standard V3 and controlled reporting evidence, and corrected WARN/request semantics. | Retain the abstract, four contribution items verbatim, RQs with only their labels bold, original main equations, result tables, current draw.io-derived architecture figure, V3/legacy distinction and all adverse findings. Contributions return to normal-size flowing text. |
| Restore useful appendices | Detailed policy and measurement explanations in `5e6b649b`; current policy implementation and retained evidence records. | Five appendices elaborate policy decision order, measurement definitions/dependence, candidate/guard/provenance, installed-browser boundaries, and telemetry estimation/admission. No excluded study, external numerical ranking, extra result catalogue or duplicate diagram is restored. |
| Source preservation | `33c5bf93` emptied `ref.bib`; its parent retains the corrected catalog from `c4b9b6d0`/`e6c177ff`. | Restore the parent's exact bytes: 76 records in `ref.bib`, 81 across the four databases. Preserve stable keys and metadata corrections. The archived `paper/old/Internal Submission.pdf` remains unchanged. |

The current [rewrite scope](../REWRITE_SCOPE.md) explicitly supersedes the ten-page cap and appendix prohibition. Historical revision records remain intact. The empirical seven-unit boundary remains in force; greater space permits explanation, not a larger experiment catalogue.

## Evidence ledger for restored claims and detail

- **L22-1, deployment choice:** `Llama2023`, original [arXiv abstract](https://arxiv.org/abs/2302.13971), opened 18 October. Supports the existence of research-released foundation models; no hosted/local ranking or numerical claim is imported.
- **L22-2, downstream reproduction:** `priyanshu2023chatbots`, original [arXiv abstract](https://arxiv.org/abs/2305.15008), opened 18 October. Supports input regurgitation and instructed output sanitization; neither proves that PriVoke prevents provider-side failures.
- **L22-3, existing precedents:** Current Casper/HaS/ProSan, contextual integrity, negative-flip and randomized-reporting citations remain within the attribution boundaries of [CITEMAP20](source-restoration-guide-20261017.md). Added compact-configuration motivation uses existing `turc2019WellReadStudents`; resource definitions use existing `LinuxCgroupV2Interfaces2026`.
- **L22-4, policy:** Read `extension/client-runtime/src/classification/classification_policy.py` at the input revision. Appendix A preserves low-confidence precedence, S0/empty handling, identifier/location conditions, PU handling and numeric-confidence qualification. No runtime behavior changed.
- **L22-5, retained methods:** [Controlled studies](controlled-studies-20261014.md), [standard V3 installed record](v3-standard-installed-evidence-20261017.md), [telemetry mechanism record](telemetry-evidence-20261014.md), current manuscript and historical methodological prose support the added definitions. New notation for existing scoring and inverse-response estimation adds no measurement. The matched treatment changes joint-gradient clipping as well as encoder optimization; guard eligibility remains distinct from publication.

The two restored citations are the only additions to the printed source set. The updated source guide accounts for all 81 keys: 19 numbered references, three linked model cards, 58 deferred sources and one formatting control. New appendices point to existing records without reproducing excluded experiments.

## Validation

Native MiKTeX compiled `paper/main.tex` in the isolated working directory `evaluation/results/external_expansion_20261018/`: `pdflatex -interaction=nonstopmode -halt-on-error`, `bibtex main`, and two further LaTeX passes. `TEXINPUTS` and `BIBINPUTS` were `.;D:/Git Repositories/Privoke-Research-Project/paper//;`, so fresh auxiliaries preceded stale manuscript auxiliaries. The initial sandbox launch failed at MiKTeX registry/configuration access; the approved narrow compiler escalation completed successfully. One overfull appendix locator was repaired with breakable `\path` formatting, followed by two successful passes.

The final output has **15 US-Letter pages, five appendices and 19 numbered references**. There are no undefined citations/references, duplicate labels, overfull boxes, bibliography warnings or pending rerun requests. The pre-existing architecture PDF-version warning and MiKTeX update-check notice remain; neither prevents compilation. The bibliography mapping is stable across the final passes. All 81 source keys are preserved and accounted for; `ref.bib` is byte-identical to `33c5bf93^:paper/ref.bib`.

Poppler rendered all fifteen final pages at 100 dpi to `page-01.png` through `page-15.png`; every page was visually inspected for clipping, overlaps, column flow, table/equation fit, figure legibility and reference rendering. No layout defects remain. Normal conference pagination leaves the last references on page 15. The contact sheet is `contact-sheet.png`; `artifact-hashes.json` binds every inspected PNG and the final source/PDF. No content was compressed to meet a page target.

Structural comparison against the input verifies that the title, abstract, all four contribution items, all three RQs, all eight result tables and both original main equations are unchanged. The current architecture asset was not edited. The complete archived `paper/old/Internal Submission.pdf` is byte-identical to the input revision. Text whitespace checks passed. The host's inherited `astextplain` PDF diff driver treats PDF streams as text, so the staged full check used the read-only command override `git -c diff.astextplain.binary=true diff --cached --check`; it passed without altering Git configuration. The staged PDF bytes match the inspected output exactly. No runtime or study tests were run because this change is documentation-only.

- Final PDF SHA-256: `4add581733429ec9cd74685cd674c5ab20594a7cfb73a97e166d3e27d4def9be`.
- Final TeX SHA-256: `dfb92bb08b90a89d64637568ce57110b5e017510b6bf3561c821ff39043c6299`.
- Contact sheet SHA-256: `e073a9e98608628219e6f91f607eaf31254d5ba203a8027067903ea800db8cf7`.
- Preserved internal PDF SHA-256: `5c1d9ab360cb0368f6214782543e7e9f80e0e1ce186ec2b31288f0b15ada9a4c`.

The output is `paper/main.pdf`. Source/data/model execution, publication and external collaboration remain outside this editorial task.

An independent review checked the new policy, measurement, browser and telemetry appendix details against implementation and retained records. Its precision correction is incorporated: Appendix E explicitly retains the finite-privacy excess rather than suggesting an exact nominal guarantee; Appendix C repeats the improved-joint/zero-action-harm guard criterion. Two final successful LaTeX passes and changed-page pixel inspection cover these corrections.
