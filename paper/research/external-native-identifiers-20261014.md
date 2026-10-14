# EX14: AdvPIIBench official-category reference

Prospective freeze, 14 October 2026. Assignment scope: obtain an untouched mixed-class external reference using pinned public AdvPIIBench data, fixed balanced V1 and AU3 V3, explicit semantic-only requests, protected grouping, native baseline and paired uncertainty. No fitting, promotion, final-partition access or contextual truth claims. The machine-readable protocol is [external-native-identifiers-20261014.json](external-native-identifiers-20261014.json).

## Source audit and revised question

Official source: Roei Arpaly and Yoni Birman, *AdvPIIBench: The Adversarial Collapse of PII Detection in LLM Interactions*, 2026, Hugging Face dataset, CC BY 4.0. Card and release validator were fetched from the official dataset at revision `02741d9f99a91b8fdcf48f4316a2c73be7a7449a`; their SHA-256 values match the prior commitments in the protocol. [Pinned card](https://huggingface.co/datasets/roei-ar/AdvPIIBench/blob/02741d9f99a91b8fdcf48f4316a2c73be7a7449a/README.md), [pinned validator](https://huggingface.co/datasets/roei-ar/AdvPIIBench/blob/02741d9f99a91b8fdcf48f4316a2c73be7a7449a/validate_release.py). Exact copies remain in the local ignored run directory. Bibliography integration belongs to root; reuse `arpaly2026advpiibench` if present.

The card's Schema section explicitly defines three categories: injected positive, ordinary negative and PII-shaped hard negative. The Annotations section states that there is no human annotation step. Its limitations state that only the attacked identifier is labelled; other identifier-shaped strings can be intentionally absent from the spans. The validator checks exact source offsets and category/span consistency, then limited regex safety checks for card, email and SSN patterns. It does not establish exhaustive annotation for all five identifier types or broader privacy categories.

Therefore the original proposed exhaustive native-five-identifier presence endpoint is unsupported. This retained audit changes the question prospectively to **agreement with the official source binary category**. Source positives map to true, ordinary and hard negatives to false. Empty spans alone never establish a negative. PriVoke's broader semantic finding is an explicitly mismatched binary response proxy. A native Presidio reference is restricted to CREDIT_CARD, PHONE_NUMBER, IBAN_CODE, EMAIL_ADDRESS and US_SSN, without asserting that its ontology or source annotation is exhaustive. No source category is relabelled as broad privacy-clean truth.

## Prespecified preparation and analysis

Before candidate-row parsing, freeze 1,000 positive, 750 ordinary negative and 250 hard-negative rows, sampling seed 20261014, globally one row per connected component. Build closure over the whole source before filtering: source-namespaced parents, exact/normalized text and typed original injected values. Retain graph bridges from ineligible members. Exclude few-shot-safe members and complete protected/conflicting components. Allocate hard-negative, ordinary-negative and positive strata in that order using the protocol's SHA-256 ranking; tie selection uses hashed native UID. Stop before inference if any quota or the 200-components-per-binary-class minimum is unavailable. No outcome-dependent replacements or tuning.

Bind the existing verified protected union and opaque exclusion index; never read locked final contents. Add checks against current V3 training/reference manifests before inference. This protects declared IDs, groups and exact/normalized texts, not all semantic paraphrases, unknown templates or upstream pretraining. Preserve original strings and span coordinates; normalized copies serve grouping only. Bind model bytes, actual dirty-source closure, dependencies, explicit layer request/returned traces, empty hints and raw request/response protobuf receipts.

Report confusion matrices, errors, actual class/component supports, and ordinary/hard-negative rates separately. Retain all 2,000 requested rows in conservative denominators; errors invalidate comparative conclusions and also receive separate complete-case counts. Paired component bootstrap uses 2,000 resamples and seed 20261014 for V3-minus-V1 recall/specificity, percentile 95% intervals, at least 1,900 defined replicates. This is a fixed external source-category reference, not an author-defined heldout split, contextual evaluation, deployment result or improvement claim.

## Status

The protocol JSON retains its prospective bytes. Root and independent reviewer accepted the protocol, actual selection, and amended source/model/host seal before inference. All three fixed endpoints completed with zero errors. Independent reviewer R2 reconciled the final numerical and trace evidence; root accepted the completed endpoint and bounded interpretation.


## Completed fixed endpoint

On 14 October 2026, preparation scanned all 104,728 pinned rows and built 24,958 connected components before member exclusions. Source counts were 80,936 positive, 22,560 ordinary negative and 1,232 hard negative. The only structural member exclusion was the 14,496 `pi_few_shot_safe` rows. No component collided with the protected union, and no component had opposing native binary labels on the same declared normalized text. Eligible component capacities were 1,166 positive, 22,560 ordinary negative and 1,232 hard negative. The prescribed sample selected exactly 1,000 positive, 750 ordinary-negative and 250 hard-negative rows from 2,000 globally distinct components; all quotas and component floors passed.

The original opaque protection was extended with PH3 TRAIN/VAL (6,240/1,560 rows) and AU3 TRAIN/VAL (9,360/1,560 rows); EN3 reuses PH3 supervision. The resulting union contains 48,155 ID keys, 11,995 group keys and 36,483 exact and normalized text keys. A separate check verified that all 43 current V1 anchor texts occur in the original union by both exact and normalized keys. No locked final content was accessed. Keys are known-source exclusion evidence; upstream BERT pretraining, semantic paraphrases and undisclosed template families remain unexcludable.

Every semantic request supplied `layers=[4]`, the fixed model ID, an empty visibility hint and no presence gate. V3 additionally supplied its immutable checkpoint SHA. Every response was checked for exactly returned layer `[4]`, status `ok`, empty errors and all frozen model identity fields. Raw deterministic request/response protobufs remain with the selected source rows in the ignored local run directory. The binary prediction is any returned semantic finding, including WARN findings; it is not an action-agreement or attacked-span overlap metric.

| Fixed arm | TP | FN | TN | FP | Source-positive recall | Source-negative specificity |
|---|---:|---:|---:|---:|---:|---:|
| V1 balanced | 630 | 370 | 486 | 514 | 63.0% | 48.6% |
| AU3 V3 balanced | 929 | 71 | 5 | 995 | 92.9% | 0.5% |
| Presidio five-type lg, threshold 0.0 | 39 | 961 | 991 | 9 | 3.9% | 99.1% |

Each row of the table uses all 2,000 requests: 1,000 source positives and 1,000 source negatives. Every arm had zero positive-class and zero negative-class execution errors, so conservative all-row and complete-case estimates coincide. TP/TN/FP/FN here refer only to the official category proxy; an apparent semantic FP can be a finding in an unannotated broader category.

| Fixed arm | Ordinary negatives correctly unflagged / 750 | Hard negatives correctly unflagged / 250 |
|---|---:|---:|
| V1 balanced | 321 (42.8%) | 165 (66.0%) |
| AU3 V3 balanced | 5 (0.67%) | 0 (0.0%) |
| Presidio five-type lg, threshold 0.0 | 750 (100.0%) | 241 (96.4%) |

V3 minus V1 source-positive recall was +29.9 percentage points, with a paired component-bootstrap percentile 95% interval of [26.5599, 33.1623] points. Source-negative specificity was −48.1 points, with interval [−51.1334, −45.2096] points. Both intervals used all 2,000 prespecified resamples, seed 20261014, with zero undefined replicates. Components are paired across arms; because exactly one row was selected per component, resampling components is row resampling on this endpoint. The intervals describe this sampled synthetic reference and do not establish independent template families or variation across source populations.

The package comparison shows different recall/specificity behavior on the official categories. It does not support a blanket V3 improvement claim. Presidio's high source-negative specificity is accompanied by low attacked-positive recall. This configured reference is not an optimized strongest baseline; its five native entities and threshold are fixed, and no post-outcome changes were made.

## Native input and baseline details

Original text was sent verbatim. Maintained native preprocessing creates normalized copies internally; it changed 1,921/2,000 selected inputs. The unchanged V1 tokenizer exceeded its declared 96-token cap on 477 rows (417 positives, eight ordinary negatives and 52 hard negatives); V1 applied its native truncation. The V3 maximum was 285 tokens including specials, below its 512-token bound, with zero over-cap rows. The V1 maximum before truncation was 306 tokens including its initial token. These fixed representation/cap differences are part of the package comparison and prevent attributing differences solely to training or architecture. No source offsets were scored against normalized text.

Presidio used `presidio-analyzer 2.2.363`, `spaCy 3.7.5`, `en_core_web_lg 3.7.1`, language `en`, and `score_threshold=0.0`. Mapping was `credit_card_number→CREDIT_CARD`, `phone_number→PHONE_NUMBER`, `iban→IBAN_CODE`, `email→EMAIL_ADDRESS`, `ssn→US_SSN`. Its native registry supplied CreditCard, UsSsn, Email, Iban, Phone and Spacy recognizers for the requested entities. The exact recognizer patterns/contexts, supported entities, installed Presidio source hashes and lg model asset hashes were retained. This threshold-0.0 five-entity adversarial-source result is separate from the earlier AU3 recognizer reference at threshold 0.5; the tasks/results must not be pooled.

Inference used host Python 3.11.9 with NumPy 1.26.4, Torch 2.11.0+cpu, Transformers 4.57.6, tokenizers 0.22.2, safetensors 0.8.0, grpcio 1.82.1 and protobuf 7.35.1. CPU numeric thread settings were four. The fixed V1 file SHA is `dcacb490bf19cf771fe4084e7f3484d83daee040609c496c1aef04f0da779b51`, artifact checksum `8390b96871c6edd00916e3a6126da1b09c19f9fdbdda8214ebe667a893e5ee2c`, version `v0.3.0`, parameter fingerprint `fec1a27b2252e01f659b5b856e5bdb124ef79b72f28995c7b3599f5ce0bd44c6`. AU3 V3 manifest SHA is `99b36171056bb0398584a0b0556d9d7ff2640d0acac4b124a126327451a80589`, model blob `e48e7c1aa46310b3b7b1f6422f7aa8902c70cf6ff861f7540a7c4be151de4df2`. All fixed package assets and source bytes were checked before and after scientific inference; neither catalog nor weights were changed.

## Evidence and execution ledger

Durable restricted local outputs are under `evaluation/results/external_native_identifiers_20261014/` in the primary checkout. Public records expose aggregates/commitments, not selected prompt text. Decisive SHA-256 commitments:

| Artifact | SHA-256 |
|---|---|
| Prospective protocol JSON | `1023d0ab0fb17b69320f2c7515b9cd9c8140a4769467400521f70a5aa86373ef` |
| Initial implementation freeze | `203bf6bfc70b1163b5bfa700ea5becf7cbb47bddcfad50889bb2ba60f0f17f70` |
| Amended inference freeze | `a2e839a1e8da876bfffe659307d47ba1a52d2528ad03cc809fdb6c06d7b65d24` |
| Selected 2,000-row source file | `9af434b9f335121bdae081d430c942ce6c437225be84a895e4252ebe8228b7b9` |
| Selection/protection receipt | `59780f05848ff31d44e8b5fcb1df73f020dc33fe59c0f18a43cb0b2291054d16` |
| V1 2,000 protobuf receipts | `01ef0cad3700d33a7282e5a85d69e8dfabbbf352f08df59c96c9205a1aa04a32` |
| V3 2,000 protobuf receipts | `dab104d4eee02b6976e460969481e257b0a36b14ffd05e9b9fd324408777a0b0` |
| Presidio 2,000 finding receipts | `5b873caef962a2728e5cbb3e0cd779fab1b3362d0afd41b16c3e35e6699b79ea` |
| Numerical/protobuf audit | `1d5d8425df4447cba61a3ad97e9d14db90c6a1da892efa769636b71fef942617` |
| Root inference-release message | `a6298f75723578916799cf48af8e938dfec1a85b5c8c53f31306ce0dba76edc2` |

The inference seal was an immutable amendment after review identified a source-binding gap, before any scientific predictions. It binds all source/model/input/package/selection commitments at serve/evaluate/baseline/audit. Synthetic drift injections verified rejection of runtime-closure, dependency, model-entry, package-version and baseline-asset changes. All 163 bound source/dependency files were snapshotted by SHA; the original preparation controller was also preserved with its exact pre-amendment hash. The grouping/parser/structure helpers equal the previously pinned audited source. Original implementation/selection records were preserved, not overwritten. Four new helper tests plus 15 parser and 14 component tests passed.

Execution recovery was limited to startup mechanics: one hidden background-process attempt exited before readiness, with no candidate inference; a retained exec session then hosted V3 successfully. A shell PID inspection could not observe the retained session namespace and did not establish termination. Both actual owned server sessions were subsequently terminated through their session handles, and separate gRPC connection probes verified ports 50201 and 50202 unavailable. An immutable cleanup receipt corrects the earlier shell diagnostic. Two synthetic `Hello world.` readiness probes are retained separately and excluded from all scientific denominators. There were no scientific retries, row replacements, model fits, threshold changes, promotion, or locked-final access.

The closure's injected-identifier links use supplied original values after the declared NFKC/casefold/whitespace normalization. They do not certify equivalence across differently punctuated phone/card/SSN spellings, undisclosed identifiers, or templates. The external endpoint is synthetic English single-turn data and a task-mismatched official-category reference; independently reviewed contextual generalization remains unestablished.


Independent final review decoded all 4,000 semantic request/response pairs and checked exact source-text/UID/category/component joins, sole layer `[4]`, successful status, empty errors, native identities and finding-to-binary decisions. It checked all 2,000 Presidio receipts for the five requested types, finite scores in [0,1], original-text offset bounds and decisions. All three confusion matrices and stratum denominators reconciled; an independent calculation reproduced both paired bootstrap intervals within `1e-14`. Review did not reinterpret V3's 0.5% source-category specificity as an established 99.5% privacy false-alarm rate.

After completed independent reconciliation, the required Git whitespace check identified terminal blank lines in the controller and its test. Only those terminal newline bytes were removed. Both exact executed and final formatted source bytes remain snapshotted; `post-run-formatting-attestation.json` verifies their equality after stripping terminal newline bytes. The execution seal and original scientific audit remain unchanged; no scientific endpoint was rerun.
