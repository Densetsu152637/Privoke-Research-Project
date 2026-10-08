# Role-quota training results and model quality

The completed 12-attempt study did not meet the qualifying standard of at least 90% pipeline recall plus measured specificity improvement. Six head updates were accepted; all six last-block updates were rejected as worse on the held-out set. Zero candidates were eligible, the frozen selection has no winner, and no candidate was evaluated on development or the contextual fixture. No model was retained or promoted. The paper was not edited.

The [prospective protocol](role-quota-fuzzer-study-20261006.md) fixed independent copies of the exact live balanced `v0.3.0+train.2` base, 256 training rows, 16 whole-group held-out rows, learning rate .003, maximum aggregate delta .05, and the class-balanced mean-category objective. Both sampling modes were freshly fitted for heads and last block across seeds 42, 1337 and 2026. Quota sampling selected 32 authored sensitive, 32 authored clean and 192 public/bootstrap rows without normalized-text duplicates. The existing default sampler and paired held-out rows were preserved.

| Model/update | Semantic TP/TN/FP/FN | Semantic recall / specificity | Pipeline TP/TN/FP/FN | Pipeline recall / specificity |
| --- | --- | --- | --- | --- |
| Fresh original balanced base | 246 / 155 / 338 / 229 | 51.79% / 31.44% | 427 / 143 / 350 / 48 | 89.89% / 29.01% |
| Uniform heads, seed 42 | 245 / 156 / 337 / 230 | 51.58% / 31.64% | 427 / 144 / 349 / 48 | 89.89% / 29.21% |
| Uniform heads, seeds 1337 and 2026 | 246 / 157 / 336 / 229 | 51.79% / 31.85% | 427 / 145 / 348 / 48 | 89.89% / 29.41% |
| Quota heads, each of the three seeds | 246 / 156 / 337 / 229 | 51.79% / 31.64% | 427 / 144 / 349 / 48 | 89.89% / 29.21% |
| Last block, both modes and all seeds | Not scored after rejection | Unmeasured | Not scored after rejection | Unmeasured |

Validation has 475 positive and 493 negative rows. Eligibility required at least 428 true positives and more than the fresh base's 143 true negatives. Every accepted update remained at 427 true positives. Quota versus uniform corrected one semantic miss for seed 42 with no pipeline change; for seeds 1337 and 2026 it introduced one additional clean flag in both layers. These small exploratory differences do not establish statistical superiority or generalization.

The originating-dataset comparison below uses the fresh original pipeline and the accepted quota head model for seed 42. Complete tables for every accepted model and both layers are in the [measured quality report](role-quota-study-v1-quality-20261006.md).

| Dataset | Positive / negative support | Original pipeline recall / specificity | Quota seed 42 recall / specificity | Original FP / FN |
| --- | ---: | --- | --- | ---: |
| AI4Privacy/OpenPII | 133 / 39 | 93.23% / 33.33% | 93.23% / 33.33% | 26 / 9 |
| gretel | 98 / 54 | 96.94% / 20.37% | 96.94% / 20.37% | 43 / 3 |
| nemotron-pii | 206 / 384 | 84.95% / 29.17% | 84.95% / 29.43% | 272 / 31 |
| privy | 38 / 16 | 86.84% / 43.75% | 86.84% / 43.75% | 9 / 5 |

Gretel has the lowest sampled pipeline specificity; nemotron-pii contributes the largest absolute false-positive and false-negative counts and most negative support. This identifies model/source weaknesses in these samples, not defective datasets. Annotation presence does not establish contextual privacy, severity, visibility, policy action or complete span recovery. Unequal source supports matter when interpreting pooled results.

The model is a compact seeded transformer with 36,756 parameters, not a pretrained conversational LLM. Accepted head updates train 660 parameters while freezing the encoder. Semantic recall remains around 52%; regex/NER contributions account for the higher pipeline recall. The complete report records exact model identities, parameter trainability, confusion counts, precision, F1, balanced accuracy, source supports, paired prediction changes, measured service latency, objective losses, class-weight audits and actual sampling coverage. Rejected updates receive no invented accuracy. Losses on intentionally different training batches are not interchangeable measures of generalization.

Fresh validation predictions matched the preserved reference exactly on all 968 rows in both layers. The fresh original development counts were semantic 146/76/162/118 and pipeline 242/69/169/22, and all 48 fixture cases were recorded before the grid. They are reference measurements only; no candidate endpoint claim is made. Seven ambiguous fixture cases remain excluded from quantitative safety gates. Provisional targets, reused exploratory splits, seeded representation and unestablished calibration/production latency limit all conclusions. Protected final examples and labels remained uninspected and unscored.

Evidence is preserved in `evaluation/results/role_quota_fuzzer_20261006_v1/`: complete-quality.json, complete-quality.md, reporting-source.py, state.json, selection.json, sampling-preflight.json, frozen sources, exact bases, request/response records and raw measurements. Independent restoration receipts in the sibling preflight directory verify seven original model payloads and five original image IDs after inventories, baseline and candidates. Complete JSON SHA-256 is `7bed366e889352e268b19adcae014ed2a7805805caf424b86e1140fe470aa258`; Markdown is `fc772c4163be2800125ec042f8d2ccfa67df69b789ccad0b1758a2dfe0c3a8b1`; reporting source is `f73ec66951f2536ae92de4d67fb29845e1e213564f2c1e0c8dad1accb32dc872`.

The next hypothesis is bounded local SGD that recomputes gradients after each step, compared prospectively with one-step and matched nominal total-learning-rate controls. Changing gradients, clipping and rounding can change actual displacement, so this comparison does not isolate relinearization alone. Current code takes one direction at the immutable base; accepted head updates have not demonstrated clipping as the limiting factor. This follow-on is being prepared separately and has no measured improvement yet. Earlier completed studies remain separate immutable evidence.
