# Detector precision: regex repairs, case-preserved input and NER post-filter

**Record:** DETPREC-20261024. **Date opened:** 24 October 2026. **Status:** results recorded (task `paper-2`, same day). **Paper input:** branch `docs/paper` at `2ab95a67`. **Scope:** manuscript evidence unit 8, detector layers only (see [REWRITE_SCOPE](../REWRITE_SCOPE.md#authorized-eighth-evidence-unit-24-october-2026)).

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

Source experiment documents (interim, opt-in flags default off at that time): `docs/experiments/case-preservation-ablation-20261024.md`, `docs/experiments/ner-postfilter-20261024.md`. Defaults-on freeze `6a0c9ca3` (`PRIVOKE_CASE_PRESERVING_DETECTORS` and `PRIVOKE_NER_POSTFILTER` default on; `0`/false/no disables; defined only in `src/config.py`); evaluation script `89c358fd`; evaluation record `ab647e45`. The post-filter freeze is `50fc51e6` (the source document's `6614ca80` was pre-rebase and is unreachable).

## Datasets

- `evaluation/results/locked-public/development.jsonl` (502 rows; dev-TUNE and dev-CHECK by group-id hash parity).
- `evaluation/datasets/privoke_personalized_synthetic.jsonl` (2,000 rows).
- `evaluation/datasets/privoke_openai_synthetic.jsonl` (1,000 rows).
- One-shot held-out set: the 498-row locked-public PIIMB final partition (236 positive), the endpoint already opened for unit 3; scored once for both configurations after the defaults freeze, aggregates only, no row inspected, nothing changed afterwards.
- Data used to design the regex repairs: not separately recorded.
- SHA-256: development `65bf02af1f9f7167a5aa5eaaa8aeac54111c90d009585ed36570d3ce0a635095`; personalized `fd045ac1bd77fa278ad207a1bc1208f71fced017b9ab4fc174a2074f7d8f1281`; openai `8e8e611b9d40f7d554726d577449585faefb9aec97f5dd4ffb051af1a6da2c3b`; final `613a78b9e5fa677904125b4c056fb8d57d15fb6ebd9c443a75f406ae3ac05515`.

Harnesses: `evaluation/evaluate_installed_detectors.py` (old = clean export of `e6c177ff`, new = `89c358fd`; flags observed and recorded) and, for development-only single-control arms, `evaluation/compare_ner_postfilter.py` (host environment `evaluation/.venv-v1-v3-pipeline`, spaCy `en_core_web_sm`). Source aggregates: `docs/experiments/detector-precision-installed-20261024.md` and `.json` (commit `ab647e45`), `case-preservation-ablation-20261024.md`, `ner-postfilter-20261024.md`.

## Results

Counts are TP/TN/FP/FN, old (pre-change) then new (installed). Held-out = final endpoint, 498 rows, 236 positive. Source: `docs/experiments/detector-precision-installed-20261024.json`.

| Split | Layer | Old | New | Recall old/new | Specificity old/new |
| --- | --- | --- | --- | --- | --- |
| held-out | regex | 154/258/4/82 | 151/261/1/85 | .653/.640 | .985/.996 |
| held-out | NER | 56/255/7/180 | 50/253/9/186 | .237/.212 | .973/.966 |
| held-out | union | 181/251/11/55 | 180/252/10/56 | .767/.763 | .958/.962 |
| dev (502) | regex | 172/231/7/92 | 169/234/4/95 | .652/.640 | .971/.983 |
| dev (502) | NER | 55/232/6/209 | 65/230/8/199 | .208/.246 | .975/.966 |
| dev (502) | union | 193/225/13/71 | 201/226/12/63 | .731/.761 | .945/.950 |
| personalized | regex | 1000/977/23/0 | 1000/1000/0/0 | 1.000/1.000 | .977/1.000 |
| personalized | NER | 800/1000/0/200 | 695/1000/0/305 | .800/.695 | 1.000/1.000 |
| openai | regex | 460/346/154/40 | 448/466/34/52 | .920/.896 | .692/.932 |
| openai | NER | 145/492/8/355 | 85/497/3/415 | .290/.170 | .984/.994 |
| openai | union | 471/343/157/29 | 459/463/37/41 | .942/.918 | .686/.926 |

The dev-TUNE, dev-CHECK, personalized union and remaining rows and the latency table are in the source record and in paper Table `tab:detprec`. Mean latency ms/prompt (one sequential pass): old 44.3 to 52.4, new 46.1 to 51.5 across splits; no meaningful difference.

Reading (evidence-faithful): the held-out result supports a regex specificity gain with a small recall cost; the held-out union is essentially unchanged; NER-only did not improve on held-out (FP 7 to 9, recall .237 to .212) and lost recall on the synthetic sets, so a net NER benefit is not established and the NER changes rest on design and development evidence with an off switch. Development-only single-control arms (case alone, lowercase plus post-filter, NER without organizations) are in Appendix F of the paper and are not held out.

## Limitations

Single small English spaCy model; English-only cue lists; annotation-presence label noise; S1 findings counted positive; dev-TUNE and personalized used for design; dev-CHECK and OpenAI scored before the v2 post-review revision; synthetic and benchmark-derived data; small splits (one prompt moves recall by about one point); pets, fictional or historical people and name-like organizations are not separable without world knowledge; no full-product, semantic or installed-client rerun; the held-out set has 236 positive and 262 negative rows, so its regex differences rest on three rows each; the held-out endpoint was already opened for unit 3; latency is a single sequential pass.

## Paper passages affected

Added: subsection "Detector Precision Controls" in the system design; subsection "Detector Precision Protocol" in the evaluation method; subsection "Detector-Layer Precision Revision" and Table `tab:detprec` in the RQ1 results; Appendix "Detector Precision Rules and Reproduction"; limitations paragraph; question-map row. Edited: normalization and cascade paragraph; call-type sentence; comparison, ablation and installed-probe statements that those units ran with the pre-change configuration; RQ1 answer; RQ3 cost limitations; ablation discussion; artifact availability. One numerical sentence was added to the abstract and one to the conclusion. All placeholders were replaced in `paper-2`.

## Bibliography

Added to `ref.bib` after opening the sources on 24 October 2026: `Honnibal2020SpaCy` (project CITATION.cff, DOI 10.5281/zenodo.1212303), `Luhn1960Patent` (US 2,950,048, Google Patents) and `ISO13616Part1_2020` (title from the EVS listing; the ISO page returned 403). No Presidio or Gitleaks entry was added: `PresidioNlpConfiguration2026` covers NLP configuration, not rule patterns. See the [source guide](source-restoration-guide-20261017.md#detector-precision-update-24-october-2026).

## Follow-up (24 October 2026)

Paired uncertainty, the `student_id` action-level repair and a full-product rerun of units 1 and 2 are recorded in [DETPREC-FOLLOWUP-20261024](detector-precision-followup-20261024.md). The held-out regex differences above are not statistically significant and the union shows no detectable change without equivalence. This record is otherwise unchanged.
