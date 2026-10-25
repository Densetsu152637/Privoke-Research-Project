# Detector precision: fresh held-out registrations, rework (K), supplementary checks

**Record:** DETPREC-HELDOUT-20261025. **Date opened:** 25 October 2026. **Status:** results recorded (task `paper-5`, same day). **Paper input:** branch `docs/paper` at `1c654c9a`. **Extends:** [DETPREC-20261024](detector-precision-20261024.md) and [DETPREC-FOLLOWUP-20261024](detector-precision-followup-20261024.md); neither is overwritten. **Scope:** evidence unit 8 and its follow-ups under the 24 and 25 October 2026 entries of [REWRITE_SCOPE](../REWRITE_SCOPE.md). **Everything here is detector-layer evidence** (explicit layers `["regex","ner"]`, `regex_first=False`, execution asserted; no semantic layer, no Docker). Nothing here is LLM-only, semantic-only or full-product, and none of it may be mixed with units 1 to 7. Every number was produced by the cited source tasks; the documentation task computed none.

## Goal and exact prompts

Integrate the settled follow-up results of the detector-precision programme into the paper, report negative and inconclusive outcomes plainly, and cite each result by branch and SHA.

Owner decisions of 25 October 2026 (verbatim, as recorded in `docs/research/preregistration-detector-v3-20261025.md` and the task brief):

> "Rework the regex rules that cost recall (validators that dropped real identifiers, driver-licence gate, child/family) with a general labelled-identifier rule, then test on a new registered draw of fresh positives. Waive the N+R doc check; hold lg for now."

(the option chosen by the owner under the name "Rework"; the doc-check waiver and the lg hold are part of the same option), followed by the owner's decision **"Ship the rework"** (the shipped configuration is K, pull request 5 head `c8ceaacc`).

Earlier authorization (24 October 2026): "Test all of these in parallel and integrate promising ones". Some source tasks also quote "you have my permission to download anything <5GB for testing" and "Ask me before any downloads"; the GLiNER and transformer downloads are in the source ledger.

Root assignment `paper-5` (25 October 2026), verbatim opening: "Task ID: paper-5 (integrate all follow-up results). Manager/acceptance owner: root (main conversation)." The assignment lists nine results to integrate: the shipped configuration K and the student-identifier record; fresh held-out v2 (F1); fresh held-out v3 (F4); span-level scoring; NER models and the NER role study; the robustness probe and fixes; latency; the annotation protocol (future work only); and keeping the earlier full-product rerun while stating that it predates K. It instructs: keep the evidence-unit structure (unit 8 and its follow-ups), report negative and inconclusive results plainly, take numbers only from the cited records, and revise the abstract and conclusion to the final shipped configuration without overclaiming.

## Configurations

| Label | Source | Content |
| --- | --- | --- |
| O | clean export of `e6c177ff` | original rules, lowercased detector input, unfiltered NER |
| N | `e70e3a2e` (`fix/regex-fp-reduction`) | rule repairs, validators, case-preserved input, NER post-filter, `student_id` rule (`55cbd1e5` plus `student_id`) |
| K | `b7e716c3` (tree `59b92ab9`; record `c8ceaacc`, PR #5 head) | N plus `labelled_identifier_sensitive` (S3) and `labelled_identifier_generic` (S2), checksum downgrades (`credit_card_unverified`, `iban_unverified`, `ssn_unverified`, `unverified_number_identifier`) |
| N+R, K+all | `research/w3-candidate` `058942e0`; `research/v3-candidate` `4e695783` | default-off canonicalisation flags (strip format characters, digits, e-mail words, caseless NER gate); not shipped |
| N+lg, N+trf | N with `PRIVOKE_NER_MODEL` | `en_core_web_lg` 3.7.1, `en_core_web_trf` 3.7.3; not shipped |

spaCy 3.7.5, `en_core_web_sm` 3.7.1, host Python 3.11.9. K rule vocabulary and exclusions: `extension/client-runtime/src/regex/rules_identifiers.py`, `rule_validators.py`, `docs/detectors/regex.md` on `fix/regex-fp-reduction` (read for the appendix). `child` and `family_disclosure` were reviewed and unchanged. The shipped configuration does not include the robustness flags or a larger NER model.

## Sources and revisions

| Result | Branch | Commit | Document |
| --- | --- | --- | --- |
| Rework K, development evidence | `fix/regex-fp-reduction` (PR #5) | `b7e716c3` (freeze), `c8ceaacc` (record) | `docs/experiments/regex-rework-20261025.md` |
| `student_id` rule record | `fix/regex-fp-reduction` | `42f8f529` (rule `e70e3a2e`) | `docs/experiments/student-id-identity-rule-20261024.md` |
| Fresh sets freeze (F1-F3) | `research/wt-f-fresh` | `57e3cb7b` | `docs/research/fresh-sets-freeze-20261024.md` |
| Registration v2 | `research/wt-f-fresh` / `research/wt-w3-score` | final `950ec0a7` (`50be1743`, `f57db6ec` amendments) | `docs/research/preregistration-detector-v2-20261024.md` |
| Freeze addendum, Wave 3 | `research/wt-w3-score` | `37b02251` | `docs/research/fresh-sets-freeze-addendum-20261024.md` |
| Fresh held-out v2 results | `research/wt-w3-score` | `1344070c` (first `e0b97cd7`) | `docs/experiments/fresh-heldout-results-20261024.md` and `.json` |
| Registration v3 | `research/wt-p-prereg3` | `8523fe5d` | `docs/research/preregistration-detector-v3-20261025.md` |
| F4 freeze | `research/wt-p-prereg3` | `8295a7ab` | `docs/research/fresh-sets-freeze-v3-20261025.md` |
| Freeze addendum v3 | `research/wt-v3-score` | `bf91b113` | `docs/research/fresh-sets-freeze-addendum-v3-20261025.md` |
| Fresh held-out v3 results (incl. section 8 critic summary) | `research/wt-v3-score` | `40b6ee61` (`77fdcd56`, `7eb0f4be`) | `docs/experiments/rework-heldout-results-20261025.md` and `.json` |
| Span-level scoring (development only) | `research/wt-s-spans` | `e829ad86` | `docs/experiments/span-scoring-20261024.md` |
| NER models | `research/wt-g-nermodels` | `70d1da09` (freeze `f4f07c3c`) | `docs/experiments/ner-models-20261024.md` |
| NER role | `research/wt-d-nerrole` | `3bd22f21` (option `ba660071`) | `docs/experiments/ner-role-20261024.md` |
| Robustness probe | `research/wt-c-robust` | `33b6e6b5` | `docs/experiments/detector-robustness-20261024.md` |
| Robustness fixes | `research/wt-r-robustfix` | `b3d11a50` (freeze `b1975bc2`, docs `3f9aa450`) | `docs/experiments/robustness-fixes-20261024.md` |
| Latency | `research/wt-l-latency` | `efe0e719` (`d2975d30`) | `docs/experiments/detector-latency-20261025.md`, `detector-latency-v3-20261025.md` |
| Annotation protocol (not run) | `research/wt-e-annot` | `d00baa11` | `docs/research/annotation-protocol-20261024.md` |

Source worktrees: `D:/Git-Worktrees/Privoke-Research-Project/wt-*`.

## Method summary

Data: PIIMB `data/test_sentences.jsonl` at revision `4a13e9ffe6fd0d275efbde8afd4d8d8f1ffc2133`. F1: 16,446 sentences (10,000 positive, 6,446 negative, 8,184 clusters). F3: 2,000 long positive documents (union recall 100.00 percent for every configuration, uninformative). F2: 6,000 unlabelled natural prompts (Dolly 1,500, oasst2 2,000, WildChat 2,500). F4: 8,646 positive sentences from 5,745 documents, seed 11102026, cap 3 per document, disjoint from every earlier group including F1; pool exhausted. Exclusion: development, final, training/validation/earlier-study groups. Hypotheses, margins and decision rules registered before scoring; data, trees and code frozen in committed records before any row was scored. Paired percentile bootstrap, 10,000 replicates, seed 20261024, whole `group_id` clusters; the lower limit of a non-inferiority interval is the one-sided 97.5 percent bound; exact McNemar on discordant rows. Sections of the source results marked REGISTERED are registered; sections marked EXPLORATORY (layer swaps, per-rule tables, strata, Privy analysis, critic recomputations) cannot satisfy or rescue a registered hypothesis. Row texts were never printed.

## Results

### v2: first revision N on F1 (REGISTERED; `1344070c`)

| Cell | Delta pt [95% CI] | Gained / lost | Verdict |
| --- | --- | --- | --- |
| H1 regex specificity N-O, F1 negatives | +1.75 [+1.42, +2.11] | 114 / 1 | pass |
| H2 union recall N-O, F1 positives (margin -1.0) | -1.37 [-1.95, -0.79] | 342 / 479 (p = 2.0e-6) | **fail** |
| H2b union specificity N-O (margin -1.0) | +3.32 [+2.60, +4.07] | 385 / 171 | pass on F1 (F2 part not evaluated) |
| regex recall N-O (side effect) | -2.18 [-2.47, -1.90] | 1 / 219 | reported |
| union `block` recall N-O (secondary) | -1.90 [-2.18, -1.63] | 0 / 190 | reported; all from the regex layer |
| H4 character coverage N-O (margin -1.0) / over-masking (margin +10 per 1,000) | +2.87 [+2.35, +3.40]; -12.75 [-16.69, -9.28] | | pass / pass |
| H3a, H3b, H3c N+lg vs N (union spec, NER-only spec, union recall) | +1.71 [+1.17, +2.24]; +1.60 [+1.01, +2.20]; +1.86 [+1.43, +2.30] | 205/95; 234/131; 336/150 | pass; heterogeneous by source; promotion held |
| N+trf vs N (descriptive) union spec / NER-only spec / union recall | +3.32 [+2.85, +3.80] / +4.05 [+3.52, +4.58] / -0.04 [-0.52, +0.43] | | not eligible (latency) |
| H5a-e flags on perturbed items (union recall vs N) | strip +9.11, digits +17.82, email +30.90, caseless +1.30, all +11.77 | | pass; largely circular |
| H6 flags on clean text | no union flip on F1, F3 | | pass; trivial (zero flips) |

Union recall by source (F1, N-O): ai4privacy +1.96 [+0.95, +2.92], Gretel -0.45 [-1.30, +0.37], Nemotron-PII -4.86 [-6.36, -3.38], Privy -6.57 [-8.29, -4.93]. Union specificity N-O is concentrated (Privy +19.04). N+lg vs N union specificity falls in Privy (-4.34 [-6.73, -1.91]). Exploratory layer swap (union recall vs O): O-regex + N-NER +0.08 [-0.43, +0.61]; N-regex + O-NER -1.49 [-1.73, -1.26]. Of 479 lost positives, 117 regex-only in O, 29 both, 333 NER-only; 146 regex-caused. Rules behind the regex-caused losses: weak driver-licence recogniser (63 rows containing it), `iban` (37), `family_disclosure` (22), `concentrated_sensitive_data` (18), `child` (10), weak card recogniser (10). BLOCK loss: 190 rows, 107 to WARN, 83 to ALLOW; S3 rules involved IBAN 139 rows, child 26, weak card 15, SSN rules 6 rows. Promotion verdict for N: not promoted (criterion 2). F2 flag rates (union, positive rule): O 24.4 percent (1,465), N 16.7 percent (1,001), N+lg 17.3 percent, N+trf 15.6 percent; descriptive only. Two segmentation faults and one empty-log exit occurred while scheduling four runs at once; no code changed; the affected configurations were rerun or resumed one at a time (details in the source record, section 1).

### v3: rework K on F4 (REGISTERED; `40b6ee61`)

| Cell | Delta pt [95% CI] | Gained / lost | Verdict |
| --- | --- | --- | --- |
| H7 union recall K-O, F4 (margin -1.0) | -1.05 [-1.70, -0.41] | 342 / 433 (McNemar p = 0.0012) | inconclusive; K significantly worse than O relative to zero |
| H8 union `block` recall K-O (margin -0.5) | +0.01 [-0.33, +0.35] | 104 / 103 | pass |
| union recall N-O (context) | -1.85 [-2.50, -1.21] | 308 / 468 | |
| union recall K-N (context) | +0.80 [+0.62, +0.99] | 69 / 0 | |
| union `block` recall K-N (context) | +1.56 [+1.29, +1.84] | 135 / 0 | |
| G1 union specificity K-O, F1 negatives (second look; margin -1.0) | +3.24 [+2.53, +3.98] | 385 / 176 | pass |
| G2 union specificity K-N (second look; margin -2.0, confirmed by root) | -0.08 [-0.15, -0.02] | 0 / 5 (p = 0.0625) | pass |

K is not promoted (criterion 1, H7, not met). Registered consequence: the trade-off (K buys union specificity +3.24, regex specificity +1.68, level BLOCK recall; costs union recall -1.05). Owner decision: ship the rework. F4 recall by configuration (point estimates, percent): union O 84.05, N 82.20, K 83.00, K+all 83.00; `block` O 50.71, N 49.16, K 50.72. K restores about 43 percent of N's union-recall loss and all of its BLOCK loss. Per source, K-O union recall: ai4privacy +2.41 [+1.32, +3.56], Gretel +0.52 [-0.28, +1.33], Privy -8.00 [-9.57, -6.41], Nemotron-PII (682 rows, reported only) -0.73 [-2.97, +1.49]; K-N in Privy +0.05 (one row). Source-standardised K-O: F1 mix -0.43 [-1.06, +0.24], equal weights -1.45 [-2.23, -0.67]. Exploratory: outside Privy K-O +1.25 [+0.59, +1.92]; layer swap on F4 (union recall vs O): O-regex + K-NER -0.28 [-0.88, +0.31]; K-regex + O-NER -0.59 [-0.84, -0.34]; NER-only K-O -4.58 [-5.67, -3.53]; within Privy 164 of 241 lost rows had O NER spans touching no annotated span, about 77 touched one; O's union flags 48 percent of Privy negatives on F1 (N and K 29 percent); strata: length Q4 (203+ characters) -3.21 [-4.46, -1.95]; categories LOCATION -9.62, NRP -10.27, PERSON -6.65, ORGANIZATION -7.32 lost, GIVENNAME +5.60, SURNAME +4.94 gained. F2 flag rates: K 16.7 percent (1,001), identical flag set to N; `block` O 130, N = K 65. K+all identical to K on every F4 row; one NER-only flip each on F1 and F2. Critic summary (verbatim in the source record, section 8): K's recall loss vs O "is real", BLOCK-level recall equal, "if PR #5 ships, ship K rather than N". Spans (secondary): F4 K-O overlap recall +2.93 [+2.48, +3.38], character coverage +5.00 [+4.43, +5.56]; K-N over-masking +10.82 [+9.95, +11.72] per 1,000 characters; F1 N union: any-hit recall 80.92 percent, every annotated span fully masked in 37.16 percent of prompts (O 37.31). K qualifier vocabulary mirrors development labels; `labelled_identifier_generic` fires at S2 on technical text (`user_id=12345`).

### Supplementary checks

- **Span-level scoring (development only, `e829ad86`):** new union masks every gold mention in 107 of 264 PII prompts (0.405) against any-hit recall 0.761 and covers 0.625 of gold characters; union overlap recall old to new +0.052 [+0.025, +0.079], over-masking share -0.069 [-0.200, +0.029]; P4 (NER extends masking only where regex fired) character recall regex 0.500, P4 0.552, union 0.625. Gold spans cover attribute families PriVoke has no category for (65 of 561).
- **NER models (`70d1da09`):** no post-filtered candidate gives a statistically reliable union gain (smallest p 0.125); `lg-pf1` best on post-review splits (dev-CHECK TP +5/-1, FP -4/+0; OpenAI TP +1/-0, FP -3/+0), neutral on design splits; GLiNER (frozen `core`, threshold 0.5, post-filter) NER recall -0.103 on dev-CHECK (p = 0.008), union lower, training data undocumented, dropped (weights to be deleted per the download ledger). Post-filter off raises recall and lowers specificity for every model. No NER model changes any BLOCK decision. NER latency median ms: sm 3.2, lg 3.4, trf 19.0, GLiNER core 26.5 (contended, order of magnitude only).
- **NER role (`3bd22f21`):** no cross-layer policy beat the shipped union on design splits; amplifier-only policies (P3, P4) cannot create positives; `PRIVOKE_NER_MODEL` option added default-off.
- **Robustness (`33b6e6b5`, `b3d11a50`):** digit obfuscation costs the revised union about 20 to 29 points (dev digits_dash -21.2, openai -28.6; digits_words -19.7, -25.8); zero-width -11.4 on dev; caseless NER; the repairs make openai regex recall worse than O under dashes (-34.4 vs -15.2). Four default-off flags remove clean-text side effects (all 60 clean cells +0/-0) and recover perturbed recall on development data; on F1 see H5 above. Documentation check unmet at `b1975bc2`, waived by the owner on 25 October 2026; flags remain off and outside K.
- **Latency (`efe0e719`):** combined median per prompt (ms): O 27.3, N 27.5; same-session N 27.77, K 27.76, K+all 27.83; K-N 0.00 ms median, K+all +0.06 ms, largest regression +0.4 percent; N+lg +0.07 ms median, resident +762 MB (387 to 1,149 MB); N+trf +50.1 ms median, +2.4 GB, mean 88.0 against O 28.3 ms (+211 percent; registered limit 20 percent: fails). Host-process, detector layers only, not an installed-browser measurement.
- **Annotation study (`d00baa11`):** protocol and tooling with hand-computed unit tests; not run. Mentioned in the paper only as future work.

## Limitations

F4 is positives only; K's specificity rests on F1 negatives scored for O and N before K was frozen and informing the rework, and on unlabelled F2 flag rates (F2 adjudication of the 2,449-prompt pool and the 200-row label-noise audit remain pending). The PIIMB pool is exhausted. PIIMB annotation is incomplete and contains attribute spans PriVoke does not detect (recall is far from 100 percent). F4 is Privy-heavy (25 percent) and Nemotron-light (8 percent). The H7 result is inconclusive against its margin, not a pass; shipping is an owner decision. Exploratory analyses were produced after the registered results. Single small English spaCy model; annotation-presence labels, not contextual authorization. The full-product rerun (`91b4ee83`) and the installed probes and cost studies predate K (and the student-identifier rule); K has not been run through the full product. H5 is circular and H6 trivial.

## Paper passages affected

Abstract; Section "Detector Precision Controls" (labelled identifiers, downgrades, configurations O/N/K); "Questions and Evidence Units" (new row); new "Fresh Held-Out Protocol"; "Detector-Layer Precision Revision" and "Full-Product Rerun" (pointers: student-identifier rule and K not included); new "Registered Fresh Held-Out Evaluation" with Table `tab:heldout` and "Supplementary Detector Checks"; "Answer to RQ1"; Discussion (placement, limitations, next steps); Conclusion; Appendix "Detector Precision Rules and Reproduction" (K rules, provenance) and new Appendix "Fresh Held-Out Details" with Table `tab:heldout_source`. Bibliography: `PIIMBPinned2026` reused; no new entry (GLiNER, Dolly, oasst2 and WildChat are named in this record only, not cited).
