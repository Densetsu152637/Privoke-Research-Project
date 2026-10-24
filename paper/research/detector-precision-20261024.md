# Detector precision: regex repairs, case-preserved input and NER post-filter

**Record:** DETPREC-20261024. **Date opened:** 24 October 2026. **Status:** scaffold; results pending (task `install-1`). **Paper input:** branch `docs/paper` at `2ab95a67`. **Scope:** manuscript evidence unit 8, detector layers only (see [REWRITE_SCOPE](../REWRITE_SCOPE.md#authorized-eighth-evidence-unit-24-october-2026)).

## Goal and exact prompt

The goal is to integrate the detector-precision findings into the paper and make them permanent in the system. The user's instruction of 24 October 2026, verbatim:

> It seems that this balances better specificity with lower recall. Integrate these findings into the paper and the system for permanent installation

The system half (making the configuration the runtime default and producing final numbers, including a one-shot held-out run) is performed by a parallel task. This record and the paper edits cover the documentation half. No number in this record or in `main.tex` was produced by the documentation task.

## Scope and assumptions

- Detector-layer evidence only: explicit layers regex and spaCy `en_core_web_sm` NER (`["regex","ner"]`), execution asserted. The semantic layer is never requested. The unit is not LLM-only, semantic-only or full-product evidence and is kept separate from units 1 to 7.
- Annotation presence is the target (a prediction is positive when any finding has nonzero sensitivity or a nonempty category set). It is not contextual authorization. S1 findings are positive, so downgrading a single uncorroborated name from S2 to S1 changes no confusion cell.
- Units 1 and 2 (full-product comparison, detector ablation), 4 (installed probes) and 6 (installed cost) were measured with the pre-change detector configuration and were not rerun. Units 3 and 5 use the sole-semantic path, whose lowercased input is unchanged, and were also not rerun. The paper states this where the claims could otherwise read as current behaviour. These earlier records are not overwritten; this record does not conflict with them because it measures a different layer set and target.
- The interim user reading ("better specificity with lower recall") rests on branch measurements listed below. The final paper statement must follow the final reruns, not that reading.

## Methods (as implemented on the source branch)

1. **Regex precision repairs.** Length-only narrative heuristic removed; possessive and context gates for kin, family, child, financial and location keywords; structured-identity values bounded to one short line; checksum and range validators for Presidio-derived rules (Luhn, IBAN mod-97, NHS mod-11, US SSN ranges) with word-bounded context; hygiene exclusions. Source: `docs/detectors/regex.md` (Precision Rules), `extension/client-runtime/src/regex/rule_validators.py`.
2. **Case-preserved detector input.** `normalize_with_offsets(text, lowercase=False)` feeds regex and NER; the semantic layer keeps lowercased input because its models were trained on lowercased `normalize_text` output. Regex rules are all case-insensitive. Source: `extension/client-runtime/src/detection/preprocessing.py`, `extension/client-runtime/src/pipeline.py` (about lines 173 to 185).
3. **NER post-filter.** Stage-1 span filters (placeholder, identifier, structural, short_acronym, common_phrase) and a stage-2 category-combination table (person_linked, place_org_linked, person_corroborated, relation_tied, relation_anchored, address_shape, weak_person, lone_place_org) following a quasi-identifier principle. Source: `extension/client-runtime/src/NER/ner_postfilter.py`, `src/NER/ner_detector.py`.
4. **Evaluation protocol.** Host Python; `pipeline.analyse_text(layers=["regex","ner"], regex_first=False)` per prompt; both layers asserted ok. The 502-row development set is split by `sha256(group_id) % 2` into dev-TUNE (267 rows, 148 positive) and dev-CHECK (235 rows, 116 positive). The personalized synthetic set has 2,000 rows (1,000 positive) and the OpenAI synthetic set 1,000 rows (500 positive). Rules were designed on dev-TUNE and personalized only, committed (freeze commit `6614ca80` per the source document; the same change is `50fc51e6` on the branch) before dev-CHECK or OpenAI was scored. A critic review with author-written probe sentences then produced v2; v2 dev-CHECK and OpenAI results are post-review. `final.jsonl` was not opened.

## Source revisions

Source worktree `D:/Git Repositories/Privoke-Research-Project-wt-regex-fp`, branch `fix/regex-fp-reduction`, commits after `e6c177ff` (oldest first):

| SHA | Subject |
| --- | --- |
| `ca565f191d188cd726aca759612c7218bc5be24d` | fix(regex): reduce false positives with context gates and checksum validators |
| `dad5f30b2dd1f9e8c21105a2c9b95a4bd2c838c8` | fix(regex): address review findings on precision rules |
| `8db88e061bf705836d587bd6717c667efbbd863a` | fix(regex): allow two modifiers before personal financial-state nouns |
| `f654477445c9b0167974b40c5e6e20d85164f6b3` | docs(regex): note two-modifier allowance for financial keywords |
| `a4bb58d18f2127815dccb0aaed2ba5e5a82fd655` | feat(runtime): add opt-in case-preserving normalization for regex and NER layers |
| `6cf8e1cdb76b662bbf22afc3a16070aa4394b4e3` | docs(experiments): record case-preservation ablation for regex and NER |
| `46d7cee81bf2423ff4711900c9304f757c793785` | docs(experiments): add no-ORG and PERSON-only case-preservation results |
| `50fc51e63a1d2740d5e81c965eda0e633b86fb3a` | feat(ner): add opt-in span filter and category-combination post-filter for NER output (v1 freeze) |
| `de7b5a1a0a8b92efa3f163e9a73dd8722d041ad4` | docs(experiments): record NER post-filter results on tuned, held-out and synthetic sets |
| `89996623ab1fd86bb259677597f42619354c1c9c` | fix(ner): apply review findings to the NER post-filter (v2) |
| `4c26b52caa2e0a4bc6032c4d503fc9a0c10a35f5` | feat(evaluation): add NER post-filter detector-layer comparison harness |
| `c4311b7455cdb546445295ee96eb56900fa7846e` | docs(experiments): record post-review v2 NER post-filter results beside v1 |

Source experiment documents (interim, opt-in flags default off at that time): `docs/experiments/case-preservation-ablation-20261024.md`, `docs/experiments/ner-postfilter-20261024.md`. Installed-default commit and the one-shot held-out run: TODO(install-1).

## Datasets

- `evaluation/results/locked-public/development.jsonl` (502 rows; dev-TUNE and dev-CHECK by group-id hash parity).
- `evaluation/datasets/privoke_personalized_synthetic.jsonl` (2,000 rows).
- `evaluation/datasets/privoke_openai_synthetic.jsonl` (1,000 rows).
- One-shot held-out set: TODO(install-1) identity, size, provenance, fingerprint and freeze time.
- Data used to design the regex repairs: TODO(install-1).

Harness: `evaluation/compare_ner_postfilter.py` (host environment `evaluation/.venv-v1-v3-pipeline`, spaCy `en_core_web_sm`).

## Results

TODO(install-1): fill from the final reruns. Required cells: regex, NER and union TP/TN/FP/FN for the pre-change and installed configurations on dev-TUNE, dev-CHECK (post-review), personalized, OpenAI (post-review) and the one-shot held-out set; recall and specificity; mean latency per prompt; rows changing confusion cell; any single-control arms to be reported. These cells map to `Table~\ref{tab:detprec}` and the prose of the subsection "Detector-Layer Precision Revision" in `paper/main.tex`.

## Limitations

Single small English spaCy model; English-only cue lists; annotation-presence label noise; S1 findings counted positive; dev-TUNE and personalized used for design; dev-CHECK and OpenAI scored before the v2 post-review revision; synthetic and benchmark-derived data; small splits (one prompt moves recall by about one point); pets, fictional or historical people and name-like organizations are not separable without world knowledge; no full-product, semantic or installed-client rerun.

## Paper passages affected

Added: macros `\todo` and `\pend`; subsection "Detector Precision Controls" in the system design; subsection "Detector Precision Protocol" in the evaluation method; subsection "Detector-Layer Precision Revision" and Table `tab:detprec` in the RQ1 results; Appendix "Detector Precision Rules and Reproduction"; limitations paragraph; question-map row. Edited: normalization and cascade paragraph; call-type sentence; comparison, ablation and installed-probe statements that those units ran with the pre-change configuration; RQ1 answer; RQ3 cost limitations; ablation discussion; artifact availability. Comments marked `TODO(install-1)` remain at the abstract and conclusion.

## Bibliography

No source was added. The BibTeX pool has no spaCy (`en_core_web_sm`), Gitleaks, Luhn or IBAN key; the only related keys are `PresidioNlpConfiguration2026` (`ref.bib`) and `SpacyLarge371Release2026` (`paper-completion-sources-20261014.bib`, the large model release). The text therefore cites none of them. Adding verified entries needs network access to the primary sources and was not done.
