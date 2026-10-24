# Full-product rerun of RQ1 units 1 and 2 with the new detector defaults (2026-10-24)

**Scope: FULL-PRODUCT evidence (regex + NER + semantic cascade, actual cascade execution recorded). Not semantic-only, not LLM-only, not detector-layer-only.** Only the detector code/config differs between the two arms; the semantic input is lowercased in both, so the semantic layer is unchanged by construction (confirmed: semantic-only `[4]` outcomes are identical in old and new on all 1,560 cases).

## Instruction and authorization

User (24 Oct 2026): "Test all of these in parallel and integrate promising ones" ... "including the full-product rerun". This is a separately authorized product/detector-analysis scope under the project `AGENTS.md`; `--allow-product-pipeline` was passed for this purpose only. Downloads: none needed or made (all six packages, the AU3 FRESH inputs and spaCy `en_core_web_sm` 3.7.1 were already local).

## Question

The paper's unit 1 (historical V1 and updated V3 efficient/balanced/quality packages, 1,560 authored cases) and unit 2 (balanced V3 ablation `[2,3,4]`, `[3,4]`, `[2,4]`) were measured with pre-change detectors. Do their conclusions change with the new defaults (regex precision repairs, case-preserving regex/NER input, NER post-filter)?

## Method

- Inputs, packages and policy are the frozen historical PIPE3/AB14 ones: historical protocol `evaluation/results/pipeline_v1_v3_20261014/runs/cpu-01/protocol.json` (sha256 `938f626bec9b5810a34e6e9f33d1d28f0070fbc10ac6a570e568b41c39346ed7`), AU3 release-07 manifest `41cfd9e476f3d0a17c2a4997efab2afbb6b044c5fbd55217b0614525a2571fe0`, FRESH partition `e965c21a0d43babc0984f46eb70785c8d66d878e00e647eefb9565f219b2da0c`, ordered 1,560 rows sha256 `3461f4fc64433d49cf75976e3910e601363b8f6d611315e51e934b398bad554b`, package artifact checksums V3 efficient/balanced/quality `1f45a21b.../99b36171.../bb17d355...`, V1 `a78e4fc8.../8390b968.../76bc059f...` (asset hashes re-verified before every run). Regex FIRST, explicit layer lists, no visibility hints, no presence gate, one first pass per cell (the historical primary).
- Driver `evaluation/run-product-rerun.py` (new, same harness for both arms): host Python (`evaluation/.venv-v1-v3-pipeline`, Python 3.11.9, torch 2.11.0+cpu, spaCy 3.7.5, en_core_web_sm 3.7.1, identical environment record in both arms), an in-process loopback native gRPC runtime (`PrivokeRuntimeService`, same adapter and cache binding as PIPE3), hash-chained request/response journals. **No Docker or Compose was used**: the historical PIPE3/AB14 runs were host-native loopback servers, so containers are neither required nor comparable; hence no image digests exist.
- **old** = clean `git archive` of `e6c177ff` (flags absent; 297 regex rules, effective-rules sha256 `9b4dc9c1...6e1b`, identical to the historical protocol's); **new** = `55cbd1e5` (case-preserving and NER post-filter both default true, observed; rules sha256 `90c6b348...3edb`). Runtime source closure `f6217c97...0d97` (old) vs `6f2fa717...11d8` (new); the differing files are exactly the 15 detector files plus one test (list in the JSON). Env flags `PRIVOKE_CASE_PRESERVING_DETECTORS` / `PRIVOKE_NER_POSTFILTER` unset in both so tree defaults apply.
- Unit 1: 6 packages x 1,560 cases x 2 arms. Unit 2: balanced V3 with seven layer sets (`[2],[3],[4],[2,3],[3,4],[2,4],[2,3,4]`) x 2 arms. Total 2 x 13 x 1,560 = 40,560 scored requests, all status `ok`, zero errors. Both arms ran in parallel on one host (timings are not comparable and are not reported).
- Metrics: joint = exact sensitivity/visibility/category set + allowed action; allowed-action agreement; binary (non-S0 or non-empty categories). Paired gains/losses on the same cases; exact two-sided McNemar on discordant counts; paired 95% cluster-bootstrap rate intervals (2,000 draws, seed 42) by `family_id` (35 clusters; `group_id` equals `family_id` in this fixture, and the corrected audience-expression grouping used historically was not recomputed). Over-enforced ("unnecessary restriction") = action stricter than the strictest allowed action; under-enforced = looser than the loosest allowed.
- Aggregates: `product-rerun-20261024.json` (counts only; no text, no case ids). Raw journals and records are ignored under `evaluation/results/product_rerun_20261024_main/`.

## Validity check: old arm reproduces history exactly

For all six packages (unit 1) and all seven layer sets (unit 2) the old arm's classification and action equal the historical journals on every one of the 1,560 cases (zero discordant pairs). So any old-to-new difference is attributable to detector code/config, not to the harness or environment.

## Unit 1 results (full product, 1,560 cases: 810 sensitive, 750 clean)

Correct counts historical = old / new (new minus old paired improved/regressed in brackets, exact McNemar p).

| Package | Joint | Allowed action | Binary | Over-enforced | Under-enforced | Binary FP / FN |
|---|---|---|---|---|---|---|
| V1 efficient | 266 / 280 (17/3, p=.003) | 1029 / 1060 (32/1, p<.001) | 1038 / 1072 (38/4) | 297 / 267 | 234 / 233 | 256/266 -> 229/259 |
| V1 balanced | 160 / 155 (2/7, p=.18) | 1026 / 1037 (12/1, p=.003) | 1089 / 1086 (9/12, p=.66) | 405 / 396 | 129 / 127 | 432/39 -> 441/33 |
| V1 quality | 226 / 237 (16/5, p=.027) | 1073 / 1117 (45/1, p<.001) | 1066 / 1093 (35/8) | 251 / 218 | 236 / 225 | 282/212 -> 260/207 |
| V3 efficient | 693 / 702 (30/21, p=.26) | 1415 / 1443 (36/8, p<.001) | 1437 / 1461 (36/12) | 139 / 111 | 6 / 6 | 121/2 -> 97/2 |
| V3 balanced | 717 / 720 (28/25, p=.78) | 1409 / 1438 (36/7, p<.001) | 1433 / 1457 (36/12) | 139 / 110 | 12 / 12 | 119/8 -> 95/8 |
| V3 quality | 879 / 876 (32/35, p=.81) | 1421 / 1451 (36/6, p<.001) | 1451 / 1475 (36/12) | 139 / 109 | 0 / 0 | 109/0 -> 85/0 |

- **Shared unnecessary restrictions (over-enforced by all three V3 tiers): 139 -> 108** (union 139 -> 112). 103 of the new 108 are among the historical 139. The residual is not zero, so the over-enforcement is largely but not entirely a regex artefact.
- **Mechanism for V3 balanced** (same pattern at every tier): 36 cases moved BLOCK -> ALLOW (regex false-positive blocks removed; regex early-BLOCK skips fell 289 -> 253) and 7 clean cases moved ALLOW -> WARN because the NER layer now emits findings. The NER layer produced 0 converted findings historically and 48 now (all IDENTITY, `name`); regex layer findings fell 1,364 -> 1,328.
- Joint agreement is flat because two effects cancel: the regex repairs alone add 28 joint-correct cases (new no-NER vs old no-NER, 28/0), while the new NER findings alter the label set on 25 cases (product vs no-NER, 25/0 in favour of no-NER). The allowed-action and binary gains are real and driven by regex; the NER layer is a net negative at the label level on this fixture.
- **Updated (V3) versus historical (V1) packages, paired** (action improved/regressed, historical -> new detectors): efficient 389/3 -> 388/5; balanced 389/6 -> 413/12; quality 348/0 -> 337/3. Joint: efficient 484/57 -> 482/60; balanced 573/16 -> 581/16; quality 671/18 -> 659/20. V3 remains far ahead of V1 in every tier and metric; the ranking and size of the package effect are essentially unchanged.

## Unit 2 results (balanced V3, same package/inputs/policy)

| Configuration | Layers | Action correct hist=old / new | Joint hist=old / new | Under / over hist=old | Under / over new |
|---|---|---|---|---|---|
| Regex only | [2] | 1031 / 1067 | 295 / 313 | 390 / 139 | 390 / 103 |
| NER only | [3] | 840 / 840 | 125 / 123 | 720 / 0 | 720 / 0 |
| Semantic only | [4] | 1530 / 1530 | 972 / 972 | 30 / 0 | 30 / 0 |
| Remove regex | [3,4] | 1530 / 1523 | 972 / 942 | 30 / 0 | 30 / 7 |
| Remove NER | [2,4] | 1409 / 1445 | 717 / 745 | 12 / 139 | 12 / 103 |
| Full product | [2,3,4] | 1409 / 1438 | 717 / 720 | 12 / 139 | 12 / 110 |

Contrast "remove regex" versus full product (action; improved/regressed):
- historical = old: 139 / 18 (net +121, p=2.4e-24), under-enforcement 12 -> 30, over-enforcement 139 -> 0; family-cluster interval [0.035, 0.127].
- new: 103 / 18 (net +85, p=1.2e-15), under 12 -> 30, over 110 -> 7; family-cluster interval [0.024, 0.089].

Other unit-2 facts: NER-only recall on this fixture 36/810 positives with 12 false positives (historically 0 and 0); no-NER equals full product on 1,560/1,560 cases historically but only 1,526/1,560 now (34 cases differ: removing NER improves 7 action outcomes, 0 regressions, and 25 joint outcomes, 0 regressions). Semantic-only is bit-identical across arms. Unit-1 balanced and unit-2 full-product runs agree case for case (1,560/1,560) in both arms (determinism).

## Does any conclusion change?

Plain-language answer:
- **Unchanged:** the 1,409 -> 1,530 headline survives in direction and size order: removing regex still helps allowed-action agreement (1,438 -> 1,523, +85), and still loses exactly the same 18 correct actions and moves under-enforcement from 12 to 30. V3 beats V1 in every tier. The old numbers reproduce exactly with the old detectors.
- **Changed, quantitatively:** the new detectors recover 29 of the 139 shared unnecessary restrictions (to 110 for balanced; 108 shared by all V3 tiers), add 24 binary-correct cases per V3 package (false positives 119 -> 95 for balanced, no new misses), and raise allowed-action agreement by 29 (balanced). The full-product gap to semantic-only closes from 121 to 92 actions. Joint (label-and-action) agreement does not move significantly for V3 (p .26-.81) and drops by 5 for V1 balanced.
- **Changed, as a statement:** the paper's claim that NER removal is neutral because it yields zero converted NER findings no longer holds under the new defaults. With case-preserving input and the post-filter the NER layer converts 48 findings (NER-only: 36 of 810 sensitive-labelled cases and 12 of 750 clean cases carry a positive), makes 7 clean cases over-restricted and perturbs 25 label sets; removing NER is now slightly beneficial (7 gained, 0 lost). The "139 shared restrictions" figure should be described as historical; the current default leaves 108.
- Units 1 and 2 therefore should keep their historical framing, and a short note should report these reruns as current-default full-product measurements.

## Limitations

Same as the historical studies: reused assistant-provisional synthetic AU3 FRESH labels (no independently adjudicated truth), correlated families (35 clusters), one first pass per cell, single balanced package for the ablation, the detector changes were tuned on development/personalized sets, not on AU3 FRESH, but AU3 FRESH has now been scored twice (historical and this rerun), so it is not a fresh confirmation. Cluster intervals use `family_id` only. The old arm is a clean export, not the historical dirty tree; exact reproduction of all 1,560 x 13 outcomes shows this did not matter. Windows host, CPU, Python 3.11; timings not reported.

## Reproduction

```
PYTHONPATH=<main checkout>/extension/client-runtime/generated
python evaluation/run-product-rerun.py run --arm old --runtime-root <git archive of e6c177ff> --output <results> --allow-product-pipeline
python evaluation/run-product-rerun.py run --arm new --runtime-root <repo at 55cbd1e5> --output <results> --allow-product-pipeline
python evaluation/run-product-rerun.py analyze --runtime-root <repo> --output <results> --allow-product-pipeline
```
