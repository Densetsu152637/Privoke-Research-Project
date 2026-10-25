# v3 freeze addendum: configuration K, trees, scoring code and decisions (2026-10-25)

Scope: detector layers only (regex, NER, regex OR NER). Not LLM-only, not semantic, not full-product. This addendum fills the open K slot of `docs/research/preregistration-detector-v3-20261025.md` (section 9, item 2) and completes the freeze record `docs/research/fresh-sets-freeze-v3-20261025.md`. It is committed **before any F4 row is scored**; machine-readable twin with every hash: `docs/research/fresh-sets-freeze-addendum-v3-20261025.json`. The file name follows the registration (section 9) and the freeze record; the assignment text used the order `freeze-v3-addendum`, which is the same document.

**Root decision on the open question of the registration (G2).** G2 (union specificity of K versus N, margin 2.0 pt on S1) is **confirmed as written** by root (manager) on 25 Oct 2026 under the owner's instruction to proceed without intervention.

**State at this addendum:** no detector, NER model or LLM has been run on any F4 row. The F4 file was opened by this agent only to read the key names and value types of its first row and that row's non-text fields (id, group_id, categories, source); no F4 text was read or printed. All harness checks, the K to K+all equivalence run and the stand-in tests used development rows only (`development.jsonl`, `dev_spans`, personalized, openai and files derived from `dev_spans`). A note on K's own provenance is in section 1.

## 1. Configuration K (code freeze)

| Item | Value |
|---|---|
| K commit | `b7e716c354d1f772e638a54a7433b12371627912` (`research/wt-k-rework`), git tree `59b92ab9bf5cdaa33303626684fad1f91b8cc48f` |
| Base | `42f8f529` (tree `6cdbaba8...`), a docs-only commit over N = `e70e3a2e` (tree `338be806...`) |
| Development record | `docs/experiments/regex-rework-20261025.md` (+ `.json`) at `c8ceaacc` (a docs-only commit after the code freeze; sha256 of the LF blob `6e2903b6...`) |
| Attestation (from the record, not verified by this agent) | K was designed on dev-TUNE and the personalized set; dev-CHECK and openai are post-review (aggregate counts and rule names were seen, no rule tuned on them); `final.jsonl` and every fresh set were never read; the exploratory fresh analysis was not opened (the owner's summary only). The critic review (promotion criterion 4) must verify this |
| Files changed relative to `e70e3a2e` | `docs/detectors/regex.md`, `docs/experiments/student-id-identity-rule-20261024.md` (from `42f8f529`), `extension/client-runtime/src/regex/{rule_detector,rule_registry,rule_types,rule_validators,rules_financial,rules_identifiers,rules_identity}.py`, `extension/client-runtime/test/test_regex_identifier_rework.py` |
| Files changed relative to `42f8f529` | the same, without the student-ID experiment note |
| Scope check (registration section 5) | Every changed runtime file is in `extension/client-runtime/src/regex/` (rules, validators, registry, types, rule driver) or is its test or documentation. Nothing outside the regex layer changed: no component beyond the regex layer needs naming, and the NER layer, the case-preserving input and the post-filter are N's. K versus N is therefore a regex-layer difference, and the NER layer records of K and N are expected to be identical row by row (the analysis reports the check) |
| Unit tests on the exported tree (host Python) | 117 tests pass (`test_regex_identifier_rework`, `test_detector_quality`, `test_detector_contract`, `test_ner_postfilter`, `test_case_preserving_detectors`, `test_pipeline`, `test_gitleaks_rules`, `test_ner_pipeline_cache`) |

Reproduction check on development data (K exported tree through the v3 driver; the K record's numbers): dev union TP/FP 205/12, personalized 1000/0, openai 460/37, all as in the record.

## 2. Configuration K+all (scratch branch `research/v3-candidate`)

`research/v3-candidate` = `b7e716c3` merged (no fast-forward, **no conflicts**) with `research/w3-candidate` `058942e0` (tree `50e0a8a6...`; N plus the frozen robustness commit `b3d11a50`, which contains `b1975bc2`, plus the NER-model option). **Commit `4e6957833de8a2694d59271acedffe4059930252`, git tree `0cc4e67aff30357213912ac5df9a7d8a061fc1bd`.** Its `extension/` and `shared/` trees differ from `058942e0` in exactly the eight K regex files. The four flags `PRIVOKE_STRIP_FORMAT_CHARS`, `PRIVOKE_CANONICALISE_DIGITS`, `PRIVOKE_CANONICALISE_EMAIL_WORDS`, `PRIVOKE_NER_CASELESS_GATE` are all `=1` for K+all and unset otherwise.

- **Runtime detector tests on the exported tree: 155 pass** (the K modules plus `test_robustness_fixes` and `test_ner_model_option`).
- **Equivalence of the merge with all flags off to K (development data only).** The merged tree with every flag off ("KA0") and the K tree were both run through the v3 driver on `dev` (502), `dev_spans` (502, with spans), `personalized` (2000) and `openai` (1000): **0 row mismatches and 0 span mismatches in 4,004 rows**, and the per-row files are byte-identical. Report sha256 `b6d215cc...`.

## 3. Trees and digests (git-archive exports of `extension/client-runtime` and `shared/python`)

| Code | Tree dir | Export of | Digest (sha256 over sorted `path TAB file sha256` lines) |
|---|---|---|---|
| O | `O` | `e6c177ff` | `39a48a242b4f661261156b64672dc6a1fc22a23813fd19229c7b4765c7118d79` (reproduces the Wave 3 value) |
| N | `N` | `e70e3a2e` | `4e6505d7685256c86eb3241e8cc8da71cc8e5ac2adffadd83e7ef53c087c49a9` (reproduces the Wave 3 value) |
| K | `K` | `b7e716c3` | `4c7b0806af7d30443daabac4489a2a358a4d2b1b62052bb41c4db3b93376c2ce` (155 files) |
| K+all (and KA0) | `KA` | `4e695783` | `8cabadac2d88f0a6c3fc1d81af3052bd9e8a3c5641704d9672512bc53d17ed3e` (157 files) |

Trees live in the scratch directory `wave1/v3-score/trees`; the driver refuses to run when the observed configuration flags differ from the frozen expectation (O: all flag attributes absent; N and K: case-preserving and post-filter on, the rest absent; K+all: additionally the four flags on). Python 3.11.9 (`.venv-v1-v3-pipeline`), spaCy 3.7.5, `en_core_web_sm` 3.7.1, numpy 1.26.4, presidio-analyzer 2.2.363, torch 2.11.0+cpu, transformers 4.57.6. Explicit layers `["regex","ner"]`, `regex_first=False`, no semantic layer, no Docker, no network.

## 4. Scoring and analysis code (sha256 of the LF-normalised git blobs; commit `f1182a98` on `research/wt-v3-score`)

| File | sha256 | Note |
|---|---|---|
| `evaluation/detector_stats.py` | `c9b79a43e766021f2e1d083eb9db64fcc86d4db78b35f3ef27ad9b607127f60e` | unchanged |
| `evaluation/span_scoring.py` | `7ab4995edb7bdefc9a84cd212211f6a539df191e716541840ec3f9def9942851` | unchanged since Wave 3 |
| `evaluation/evaluate_installed_detectors.py` | `35d74729c6c57701e05664a3d91d83cc5eef18632e86ada9a61199632cffd297` | unchanged since Wave 3 (per-row version) |
| `evaluation/robustness_probe.py` | `7dabcaa05050995bb35df2a569e2431e61ad343e805e7acb3a764d41ac63607f` | imported by the driver; unchanged |
| `evaluation/w3_scoring.py` | `12b1c596ce24cb4c5bd47e6ab009b20c6d46def847490dde69834bb13558e59a` | unchanged; the Wave 3 driver |
| `evaluation/w3_analysis.py` | `1c12b4b8a413f538e65e676e88ca831c0c15891e5ea7c692d32e2b835fc03063` | unchanged; helpers reused by the v3 analysis |
| `evaluation/w3_run.sh` | `a1caa8b86197aa50f4f606ae8813e6e4b6b1c6ca702509d04ef3fe68977099b5` | unchanged |
| `evaluation/v3_scoring.py` | `39e4ecb4d8950e8953ebf3ca848c4b2d8d41a58cfa468adadd9fdf06102e9521` | new: registers set `f4` (sha256 checked before reading) and configurations `K`, `K+all`, `KA0` in the `w3_scoring` tables, then calls its `main` (no scoring semantics changed; `--no-perturbed` forced) |
| `evaluation/v3_analysis.py` | `91ae67252e9ee8f09cad563211698431208d8871d94da422cc7dbedce93f833f` | new: H7, H8, G1, G2, H9, per-source and standardised cells, exploratory tables, span studies, extra F2 packets |
| `evaluation/v3_run.sh` | `0ab4a02c48f33639f1a5513f53a84ee566ffcaee2ebf18374810586af6080a74` | new: the stages |
| `evaluation/tests/test_v3_scoring.py` | `1387b9fb42b0d8a687ec3038165f6e0c23de996418f95a5882a330c6a195261e` | new: 7 synthetic checks; 63 pass together with the Wave 3 and stats tests |
| `docs/research/label-family-mapping-20261024.json` | `19cc6103d404484be3a3ef0a851edfa0ae1254859557ffc87921673b9b05e5f6` | unchanged |

All Wave 3 hashes equal those of `docs/research/fresh-sets-freeze-addendum-20261024.json`. The scripts commit is `f1182a98` (feature commit `b562f929` and a one-line renderer fix, both before this addendum). The analysis was smoke-tested end to end on stand-in files derived from development rows (200- and 300-replicate runs; spans, strata, standardised bootstrap, the K-only extra F2 packets on a synthetic key). The stand-in outputs are not results.

## 5. Reused and fresh scoring

- **O and N reuse their Wave 3 per-row outputs for F1, F2 and F3** (registration section 8); their F4 outputs are scored fresh (they have never seen F4). Reused files (sha256 on disk): `O/f1.rows.jsonl` `a65c0fdc...`, `O/f2.rows.jsonl` `38c4a827...`, `O/f3.rows.jsonl` `2f5a4b02...`, `O/f1.spans.jsonl` `fff5e22b...`, `O/f3.spans.jsonl` `9dc59da9...`; `N/f1.rows.jsonl` `fbc24d2f...`, `N/f2.rows.jsonl` `36124d31...`, `N/f3.rows.jsonl` `53ddcd16...`, `N/f1.spans.jsonl` `09790a07...`, `N/f3.spans.jsonl` `f48a7b81...`. Full values in the JSON twin; the rows hashes equal the `rows_sha256` stored in the Wave 3 run metadata.
- **K and K+all** are scored once each on F4 (8,646), F1 (16,446: 10,000 positives and the 6,446 clean rows that form S1), F3 (2,000) and F2 (6,000). No perturbed items (H5/H6 are not part of v3).

## 6. Decisions where the registration is silent (conservative; fixed now)

1. **Verdict vocabulary.** Non-inferiority follows registration sections 6 and 7 and the Wave 3 addendum: pass iff the lower limit of the 95 % percentile interval exceeds the margin; fail iff the upper limit is at or below the margin; otherwise inconclusive (not a pass). The Wald bounds (row and cluster) are reported and do not decide.
2. **S1 subset cells.** G1, G2 and the H9 specificity cells are bootstrapped on the 6,446 clean F1 rows only (clusters are the stored `group_id` values); the F1 positives are reported separately as second-look recall cells.
3. **H9.** Reported for K against O and K against N (and N against O for context), layers regex, NER and union, rules `positive`, `warn_or_block`, `block`, with n, discordant counts, delta, interval and exact McNemar p.
4. **Per-source cells.** Sources are mapped by the `source_dataset` string (ai4privacy, Gretel, Nemotron-PII, Privy); cells for K-O, N-O, K-N under union `positive` and `block` and regex `positive`. The heterogeneity rule is applied to the union `positive` K-O interval: a source with at least 700 rows whose whole 95 % interval lies below -1.0 pt is a documented negative heterogeneity finding; Nemotron-PII (682 rows) is reported only.
5. **Source-standardised H7.** Union recall, `positive` rule; stratified cluster bootstrap with whole `group_id` clusters resampled within each source, 10,000 replicates, `numpy.random.default_rng(20261024)`, one shared stream for both weight vectors; reported for K-O, N-O and K-N. It is secondary and carries a non-inferiority verdict against -1.0 pt for information only.
6. **Promotion criterion 6** is evaluated from the K development record constants (personalized N 1.000, K 1.000; openai N 0.918, K 0.920): K is not more than 1 pt below N. **Criterion 5 (latency)** is not measured here (no latency claims) and stays "pending"; **criterion 4 (critic)** stays "pending".
7. **Spans.** Secondary, no hypothesis: `span_scoring.run_study` with the single subset `all` (both minimum sensitivities, all scopes) for F4 (O-K, N-K, O-N, K-K+all), F1 and F3 (O-K, N-K). F3 spans are informative only (recall is at the ceiling).
8. **Exploratory material** (labelled in the report): exact layer swapping on F4, per-rule tables of union and BLOCK flips from the span `source` fields, length quartiles and category strata (union recall K-O and N-O), the K to N NER-layer identity check, K+all versus K flips on every unperturbed set.
9. **F2.** Flag rates descriptive (Wilson 95 %, by source, all layers and rules) and paired flip counts; no verdict. The extra blinded packets contain every prompt K flags (union layer, positive rule) that the existing 2,449-prompt pool does not hold (same format: opaque id and text, 100 per packet, `pool-extra-packet-NNN.jsonl`; the coordinator files are separate). Prompts flagged only by K+all are counted but not packeted.
10. **Execution.** Two configurations run at a time in the background (K and K+all, then O and N); `PYTHONFAULTHANDLER=1` is set (diagnostic only). A crash is fixed without looking at labels and resumed only for sets without output (the driver never overwrites an output). Bugs found after scoring starts are reported, not fixed and rerun.
11. **Completeness before analysis:** F4 8,646 rows (positives only), F1 16,446 (10,000 / 6,446), F3 2,000, F2 6,000 for every configuration, identical id lists and labels across configurations; the analysis refuses to run otherwise.

## 7. Exact commands

Host Python only. `RESULTS=D:/Git Repositories/Privoke-Research-Project/evaluation/results/v3_scoring_20261025`, `TREES_ROOT` = the scratch `wave1/v3-score/trees` (O, N, K, KA).

```
TREES_ROOT=... evaluation/v3_run.sh score     # K and K+all (f4 f1 f3 f2) two at a time, then O and N (f4)
                                               # each: python evaluation/v3_scoring.py run --config <cfg> --trees-root TREES_ROOT --generated <main>/extension/client-runtime/generated --out RESULTS --sets <sets> --no-perturbed
evaluation/v3_run.sh pool                      # python evaluation/v3_analysis.py pool --results-v3 RESULTS --adjudication <fresh24>/f2_adjudication --out <fresh24>/f2_adjudication/pool_v3
evaluation/v3_run.sh analyse                   # python evaluation/v3_analysis.py analyse --results-w3 <w3 dir> --results-v3 RESULTS --f4-gold ... --f1-gold ... --f3-gold ... --workers 4 ; then render
```

Before this commit (development data only): `v3_scoring.py run --config K` and `--config KA0 --sets dev dev_spans personalized openai`, then `v3_scoring.py equiv --a K --b KA0 --sets dev dev_spans personalized openai`. Seeds: F4 draw 11102026; bootstrap and standardised bootstrap 20261024 with 10,000 replicates.

If K changes after this addendum, the registration is invalid for K (registration section 9).
