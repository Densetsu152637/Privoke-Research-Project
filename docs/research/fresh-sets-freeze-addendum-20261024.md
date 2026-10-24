# Freeze addendum for the Wave 3 confirmatory scoring (2026-10-24)

Scope: detector layers only (regex, NER, regex OR NER). Not LLM-only, not semantic, not full-product. This addendum completes `docs/research/fresh-sets-freeze-20261024.md` (parent freeze commit `57e3cb7b`) as required by section 11 of `docs/research/preregistration-detector-v2-20261024.md` (open items: statistics code hash and label mapping). It is committed **before any fresh row is scored**. Machine-readable twin with every hash: `docs/research/fresh-sets-freeze-addendum-20261024.json`.

User instruction (24 Oct 2026): "Proceed with Wave 3 once S finishes and the addendum is committed; report natural-prompt flag rates descriptively and evaluate the natural-prompt hypotheses after human adjudication."

## 1. What was and was not observed about F1-F3 before this addendum

No detector, NER model or LLM has been run on any F1, F2 or F3 row. Row texts were not printed. What the author of this addendum looked at, in the course of preparing it, was limited to: the F1 and F3 gold **label strings with counts** (needed to complete the label mapping; no texts, offsets or ids), key names and value types of the first row of each fresh file, one F1 entity's label and offsets, the F1 source and partition counts, the number of F1 group ids ending `_sN`, three truncated F1 group ids, the F2 `source` value of its first row, and set equality of the F2 ids with the adjudication key and packets. The harness smoke tests ran only on development rows (`development.jsonl`, `dev_spans.jsonl`, `personalized`, `openai`) and on stand-in files derived from them.

## 2. Scoring code (sha256 of the LF-normalised git blobs; on-disk Windows bytes differ by design)

| File | sha256 | Note |
|---|---|---|
| `evaluation/detector_stats.py` | `c9b79a43e766021f2e1d083eb9db64fcc86d4db78b35f3ef27ad9b607127f60e` | identical to the freeze record (`bf5e24c1`) |
| `evaluation/span_scoring.py` | `7ab4995edb7bdefc9a84cd212211f6a539df191e716541840ec3f9def9942851` | `research/wt-s-spans` (`e829ad86`) plus a label-mapping extension (section 4) |
| `evaluation/evaluate_installed_detectors.py` | `35d74729c6c57701e05664a3d91d83cc5eef18632e86ada9a61199632cffd297` | per-row version of `research/wt-a-stats`. The freeze record lists `0261942a...` (the version at `e70e3a2e`); the per-row version only adds per-row output. The scoring driver imports `layer_row` and `union_row` from it. Recorded as a deviation from the freeze record. |
| `evaluation/robustness_probe.py` | `7dabcaa05050995bb35df2a569e2431e61ad343e805e7acb3a764d41ac63607f` | identical to the freeze record (`33b6e6b5`) |
| `evaluation/w3_scoring.py` | `12b1c596ce24cb4c5bd47e6ab009b20c6d46def847490dde69834bb13558e59a` | driver: run, equivalence check, F2 review pool |
| `evaluation/w3_analysis.py` | `1c12b4b8a413f538e65e676e88ca831c0c15891e5ea7c692d32e2b835fc03063` | all hypothesis tests, span study, rendering |
| `evaluation/w3_run.sh` | `a1caa8b86197aa50f4f606ae8813e6e4b6b1c6ca702509d04ef3fe68977099b5` | the exact stages |
| `docs/research/label-family-mapping-20261024.json` | `19cc6103d404484be3a3ef0a851edfa0ae1254859557ffc87921673b9b05e5f6` | effective mapping (dump of `span_scoring.LABEL_FAMILY` and `FAMILY_CATEGORIES`) |

Scripts commit: `7e946e62` on `research/wt-w3-score` (merged without rebase: `research/wt-s-spans` `e829ad86`, which contains A's `detector_stats.py`, then `research/wt-c-robust` `33b6e6b5`; both merges were conflict-free). Unit tests: 73 pass (`tests.test_w3_scoring`, `test_span_scoring`, `test_detector_stats`, `test_installed_detector_rows`, `test_robustness_probe`).

## 3. Candidate runtime tree and equivalence

- Trees are `git archive` exports of `extension/client-runtime` and `shared/python` (scratch directory `wave1/w3-score/trees/`): **O** = `e6c177ff` (digest `39a48a24...`), **N** = `e70e3a2e` (digest `4e6505d7...`), **C** = `research/w3-candidate` (digest `8537ac63...`).
- `research/w3-candidate` = `e70e3a2e` + merge of `research/wt-r-robustfix` (`b3d11a50`, contains the frozen `b1975bc2`) + merge of `research/wt-d-nerrole` (`3bd22f21`, contains `ba660071`, `PRIVOKE_NER_MODEL`). **Commit `058942e02866b621a2597df5341eb9c19b75561e`, git tree `50e0a8a63bd0302095f7da50b82d70f846534bf5`.** One conflict, `extension/client-runtime/src/config.py` (both branches appended a field block after `ner_postfilter`): both blocks kept. `ner_detector.py` merged automatically. Runtime detector tests on the candidate (host Python): `test_robustness_fixes` 35, `test_ner_model_option` 3, `test_case_preserving_detectors` 11, `test_ner_postfilter` 36, `test_detector_contract` 18, `test_detector_quality` 26, `test_pipeline` 3, `test_ner_pipeline_cache` 5: all OK.
- **Equivalence check (merge does not change N).** The candidate with every new flag off ("C0") and tree N were both run with the driver on `dev` (502), `dev_spans` (the same rows with spans, 502), `personalized` (2000) and `openai` (1000): all per-row regex, NER and union records (flags, max sensitivity, categories, runtime action) and all span records are **identical on every row** (0 mismatches in 4,004 rows and 4,004 span records). The driver's span records equal `span_scoring.extract_predictions` on tree N (502 of 502), and N's dev union TP/FP (201/12) equals `detector-precision-installed-20261024.json`. Consequently, O and N are scored from their own exports and every other configuration from tree C with the flags below.

## 4. Label mapping

F1 gold has 100 distinct label strings and F3 has 7. 12 F1 labels and 2 F3 labels were unmapped (the effective mapping is in the mapping JSON). Added by stated principle (semantic type, consistent with existing entries; `UNMAPPED` stays empty): `US_SSN`, `US_ITIN`, `national_id`, `ID_NUM` -> GOV_ID; `ipv6`, `IP_ADDRESS`, `IMEI`, `api_key` -> ACCOUNT_ID (network, device and credential identifiers, as `ipv4`, `mac_address`, `password`); `CREDIT_CARD`, `IBAN_CODE`, `US_BANK_NUMBER` -> FINANCIAL; `PHONE_NUM` -> CONTACT; `race_ethnicity` -> DEMOGRAPHIC (protected attribute with no PriVoke category, as `NRP`); `sexuality` -> new family SEXUAL, whose PriVoke category SEXUAL exists. After the extension no F1 or F3 label is unmapped. The primary H4 quantities do not use the mapping (scope `all`, character level); the mapping enters only category-typed and `core`-scope metrics, which are secondary.

## 5. Configurations and environments (exactly as pre-registered section 3)

| Code | Tree | Environment variables set | Python |
|---|---|---|---|
| O | O | none (flag variables unset) | `.venv-v1-v3-pipeline` |
| N | N | none | same |
| N+strip / N+digits / N+email / N+caseless | C | `PRIVOKE_STRIP_FORMAT_CHARS=1` / `PRIVOKE_CANONICALISE_DIGITS=1` / `PRIVOKE_CANONICALISE_EMAIL_WORDS=1` / `PRIVOKE_NER_CASELESS_GATE=1` | same |
| N+all | C | all four above | same |
| N+lg | C | `PRIVOKE_NER_MODEL=en_core_web_lg` | same |
| N+trf | C | `PRIVOKE_NER_MODEL=en_core_web_trf` | `.venv-ner-models` |

The driver clears every flag variable inherited from the shell, sets the table's variables, reads `GLOBAL_CONFIG` and **refuses to run** if the observed flags differ from the frozen expectation for the configuration (O and N: case-preserving and post-filter as in the original trees). spaCy 3.7.5 in both environments; models `en_core_web_sm` 3.7.1, `en_core_web_lg` 3.7.1, `en_core_web_trf` 3.7.3 (the pre-registration's "3.7.5" for sm is the spaCy version). Package digests, source URLs, licences and declared training sources are in the JSON. None of the declared model training sources is a PIIMB source. Explicit layers `["regex","ner"]`, `regex_first=False`, no semantic layer, no Docker, no network, a layer anomaly raises.

## 6. Perturbations (H5/H6)

Transforms: `zero_width`, `digits_space`, `digits_dot`, `digits_dash`, `digits_words`, `email_bracket`, `email_paren`, `email_word`, `lowercase`, `uppercase`, from `robustness_probe.TRANSFORMS` (sha above). Per-row generator: `random.Random(int.from_bytes(sha256("20261024:<transform>:<row id>")[:8],"big"))`. A perturbed item is an F1 positive row and a transform that changed its text. N and the five N+R configurations are scored on all items of all ten transforms (the O, N+lg and N+trf configurations are not part of H5). The H5 hypotheses (H5a `N+strip`/zero_width; H5b `N+digits`/the four digits transforms; H5c `N+email`/the three email transforms; H5d `N+caseless`/lowercase and uppercase; H5e `N+all`/all ten) use identical items for candidate and N. Other candidate-by-transform cells are exploratory. H6 uses the unperturbed scores of F1, F3 and (pending) F2.

## 7. Decisions where the pre-registration is silent (conservative; fixed now)

1. **Test definitions.** Non-inferiority passes when the lower limit of the 95 % two-sided percentile interval of the delta (the one-sided 97.5 % lower bound) exceeds -1.0 pt; a Wald paired bound (row-level and cluster-robust) is reported alongside and does not decide. For error terms that must not rise (H4 over-masking) the upper limit must stay below +1.0 pt. Superiority passes when delta > 0, the lower CI limit > 0 and the exact two-sided McNemar p (after Holm where registered) < 0.05; a CI that excludes 0 in the wrong direction is a failure.
2. **Multiplicity.** Holm within {H3a, H3b} (per NER configuration) and within {H5a..H5e} on the two-sided exact McNemar p-values; H1, H2, H2b, H4 at their own level; H3c and H6 conjuncts. H2b is treated as a co-requirement of the N promotion together with H2 (section 4 of the registration).
3. **H4.** Union spans, scope `all`, minimum sensitivity 0. Character leak = 1 - character recall (non-inferior if the lower CI limit of the change in character recall is above -1 pt). Over-masking = characters outside annotated spans per character of all F1 rows (positives and clean), i.e. `over_mask_chars_per_1k`/1000, margin 10 per 1000. All other scopes, minimum sensitivities, matching criteria, regex/NER/P4 results are secondary.
4. **P4.** Reported through `span_scoring.run_study` (P4 versus regex and versus union, for both the reference and the candidate) as descriptive, exploratory secondary results; no hypothesis, no promotion use. `SUBSETS` is replaced at run time by the single subset `all` (the source file is unchanged).
5. **Comparison structure.** Pairs: O to N, and N to each of N+strip, N+digits, N+email, N+caseless, N+all, N+lg, N+trf. Layers regex, NER, union; rules positive (primary), warn_or_block, block (secondary). F3 contains positives only, so only recall is defined there. Clusters are the registered `group_id` values as stored.
6. **F2.** Unlabelled. Reported only as descriptive flag rates (count, rate, Wilson 95 %, by source, all layers and rules) and paired flip counts versus N; no hypothesis verdict. H1b, H2b (F2 part), H3a' and the F2 cell of H6 are "not evaluated" until the human adjudication exists. The review pool is the union over the nine configurations of prompts flagged by the union layer under the positive rule, plus the first 400 items of the key's `audit_order` that no configuration flags (the audit rule of `packets_manifest.json`); packets contain only the opaque id and the text, in opaque-id order (the key's shuffled order), 100 per packet, under `f2_adjudication/pool/` (the coordinator membership and flag lists are separate and gitignored).
7. **Promotion.** Verdicts are computed per section 6 of the registration from the F1/F3 tests; criteria 4 (critic review) and 5 (latency) and every F2-dependent item stay "pending" and are reported as such. Historical clean-text numbers (personalized, openai) are context only and are taken from the cited records, not re-scored. For N+R the pre-declared check reports what exists at `b1975bc2` (unit tests yes; the flag documentation is added by the docs-only commit `3f9aa450`, which the report states).
8. **Not reported.** Latency (another step). The aggregate `elapsed_s` in run metadata is not a measurement and is not used.
9. **Single scoring.** The driver refuses to rescore a set whose output file exists. A crash is fixed without looking at labels and resumed only for sets without output. Bugs found after scoring starts are reported and not rerun.

## 8. Exact commands

Host Python only. `RESULTS=D:/Git Repositories/Privoke-Research-Project/evaluation/results/w3_scoring_20261024`, `TREES_ROOT` = the scratch `trees` directory (O, N, C exports).

```
# score: nine processes in parallel, one per configuration
evaluation/w3_run.sh score          # each: python evaluation/w3_scoring.py run --config <cfg> --trees-root TREES_ROOT --generated <main>/extension/client-runtime/generated --out RESULTS --sets f1 f3 f2
evaluation/w3_run.sh pool           # python evaluation/w3_scoring.py pool --results RESULTS --adjudication <fresh>/f2_adjudication --out <fresh>/f2_adjudication/pool
evaluation/w3_run.sh analyse        # w3_analysis.py analyse | compact | render  (10,000 replicates, seed 20261024, 8 span workers)
```

Equivalence (run before this commit, development sets only): `w3_scoring.py run --config N` and `--config C0` with `--sets dev personalized openai dev_spans`, then `w3_scoring.py equiv --a .../N --b .../C0 --sets dev personalized openai dev_spans`.
