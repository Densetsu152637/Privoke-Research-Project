# Results recalculated by originating dataset

Checkpoint: 6 October 2026 (Australia/Sydney). Reaggregation of preserved predictions, without new inference or changes to labels, models, thresholds, or paper files.

“Current selected” means the latest documented research selection in the preserved results. It is not a fresh observation of the running service. The tracked `models/privoke-balanced.json` contains original v0.3.0; live serving state was not queried.

## Main finding

The current selected full pipeline's weakest adequately supported clean-class rates are **Gretel specificity 25.00% (7/28)** and **PIIMB-origin Nemotron specificity 27.72% (51/184)**. AI4Privacy recall is **87.65% (71/81)** and Nemotron recall is **89.09% (98/110)**, despite pooled recall of 90.53%. Thus the pooled recall conceals below-target source rates, and the pooled specificity of 29.41% remains poor.

This identifies detector failure patterns on sampled strata, not intrinsically “bad datasets.” Annotation defects, contextual harm, deployment risk and causal explanations require other evidence. Privy and MAPA have only two clean-labelled sentences each and cannot support a reliable clean-class ranking.

## What was grouped

The main population is the same 502 English PIIMB development sentences used in the preserved experiments: 264 annotated-positive and 238 clean-labelled sentences, across 465 recorded source groups. These are **subsets of originating datasets within PIIMB**, not complete evaluations of each upstream corpus.

The saved `source_family` field actually uses PIIMB task names. The recalculation merges `ai4privacy-en` (80 positive/22 clean) and `ai4privacy-multi` (one positive/no clean) into the one AI4Privacy/OpenPII source dataset. The sole retained “multi” task sentence is from the English-filtered evaluation; it does not establish multilingual performance. Other task names identify the other four source strata. Group counts describe recorded grouping units, not proven independent real-world documents.

| Dataset source | Sentences | PII-labelled | Clean-labelled | Source groups |
| --- | ---: | ---: | ---: | ---: |
| AI4Privacy / OpenPII | 103 | 81 | 22 | 101 |
| Gretel (PIIMB origin) | 83 | 55 | 28 | 79 |
| MAPA EUR-LEX | 2 | 0 | 2 | 1 |
| Nemotron (PIIMB origin) | 294 | 110 | 184 | 264 |
| Privy | 20 | 18 | 2 | 20 |

Source composition and the shared AI4Privacy task origin are documented in the [PIIMB card](https://huggingface.co/datasets/piimb/pii-masking-benchmark), Tasks. The saved prediction source mapping is cross-checked against every example-ID task prefix; [reproduction details](evidence-and-reproduction.md) identify the local inputs and hashes.

## Current selected full pipeline

Counts are ordered **TP / TN / FP / FN**. Recall uses positive support; specificity and false-positive rate use clean support. A dash means the required class is absent, not a zero score.

| Dataset source | TP / TN / FP / FN | Recall | Specificity | False-positive rate | Balanced accuracy |
| --- | --- | ---: | ---: | ---: | ---: |
| AI4Privacy / OpenPII | 71 / 11 / 11 / 10 | 87.65% | 50.00% | 50.00% | 68.83% |
| Gretel (PIIMB origin) | 52 / 7 / 21 / 3 | 94.55% | 25.00% | 75.00% | 59.77% |
| MAPA EUR-LEX | 0 / 1 / 1 / 0 | — | 50.00% | 50.00% | — |
| Nemotron (PIIMB origin) | 98 / 51 / 133 / 12 | 89.09% | 27.72% | 72.28% | 58.40% |
| Privy | 18 / 0 / 2 / 0 | 100.00% | 0.00% | 100.00% | 50.00% |

“Clean” here means the preserved annotation-presence negative label, not independently established harmlessness under PriVoke's broader privacy policy. Predictions are sensitivity S1–S3 or any returned category, independent of ALLOW/WARN/BLOCK. One detected entity makes the whole sentence positive; these rates do not establish complete span recovery.

## Reading the failure pattern

- **AI4Privacy/OpenPII:** ten of 81 positives are missed and eleven of 22 clean-labelled sentences are flagged. Both sides need attention; its current recall is below the 90% development target.
- **Gretel:** three of 55 positives are missed, but 21 of 28 clean-labelled sentences are flagged. Its clean-class problem is more severe by rate than Nemotron's in this sample, although the denominators differ and uncertainty overlaps. This source is the PIIMB Gretel component, not the separate multilingual finance experiment.
- **Nemotron:** twelve of 110 positives are missed and 133 of 184 clean-labelled sentences are flagged. It supplies 133/168 = **79.17%** of current false positives, while already supplying 184/238 = **77.31%** of all clean examples. Its share of errors must be read alongside its much larger support. It also supplies 12/25 = **48.00%** of current misses. These counts justify investigation, not a claim that this corpus is uniquely defective.
- **Privy:** eighteen of eighteen positives are detected, and both clean examples are flagged. The observed specificity is 0%, but two examples are insufficient to characterize the source population.
- **MAPA:** there are no positive sentences here, so recall and balanced accuracy cannot be calculated. Specificity 1/2 = 50% is one outcome from two sentences in one group.

The clean-class deficit varies substantially by detector. This is evidence against attributing every source-level failure to a universally defective dataset. It remains possible that label construction, sentence segmentation, class composition, topic/style distributions or missing context contribute. No blinded annotation audit was performed here, so those explanations remain hypotheses.

## Matched configurations by dataset

The configurations below use identical development IDs, truth and groups. They retain different historical operating points. Presidio is the independently configured baseline with `en_core_web_sm` and threshold 0.5; it is not the strongest possible Presidio configuration.

| Dataset source | Configuration | TP / TN / FP / FN | Recall | Specificity | Balanced accuracy |
| --- | --- | --- | ---: | ---: | ---: |
| AI4Privacy / OpenPII | Original full pipeline | 75 / 6 / 16 / 6 | 92.59% | 27.27% | 59.93% |
| AI4Privacy / OpenPII | Configured independent Presidio | 69 / 15 / 7 / 12 | 85.19% | 68.18% | 76.68% |
| AI4Privacy / OpenPII | Contextual gate: efficient | 74 / 13 / 9 / 7 | 91.36% | 59.09% | 75.22% |
| Gretel (PIIMB origin) | Original full pipeline | 53 / 4 / 24 / 2 | 96.36% | 14.29% | 55.32% |
| Gretel (PIIMB origin) | Configured independent Presidio | 43 / 21 / 7 / 12 | 78.18% | 75.00% | 76.59% |
| Gretel (PIIMB origin) | Contextual gate: efficient | 53 / 18 / 10 / 2 | 96.36% | 64.29% | 80.32% |
| MAPA EUR-LEX | Original full pipeline | 0 / 1 / 1 / 0 | — | 50.00% | — |
| MAPA EUR-LEX | Configured independent Presidio | 0 / 1 / 1 / 0 | — | 50.00% | — |
| MAPA EUR-LEX | Contextual gate: efficient | 0 / 1 / 1 / 0 | — | 50.00% | — |
| Nemotron (PIIMB origin) | Original full pipeline | 101 / 36 / 148 / 9 | 91.82% | 19.57% | 55.69% |
| Nemotron (PIIMB origin) | Configured independent Presidio | 79 / 152 / 32 / 31 | 71.82% | 82.61% | 77.21% |
| Nemotron (PIIMB origin) | Contextual gate: efficient | 97 / 143 / 41 / 13 | 88.18% | 77.72% | 82.95% |
| Privy | Original full pipeline | 18 / 0 / 2 / 0 | 100.00% | 0.00% | 50.00% |
| Privy | Configured independent Presidio | 17 / 0 / 2 / 1 | 94.44% | 0.00% | 47.22% |
| Privy | Contextual gate: efficient | 18 / 0 / 2 / 0 | 100.00% | 0.00% | 50.00% |

The efficient gate has Nemotron recall **88.18% (97/110)** despite overall recall 91.67%. It improves clean-label handling but does not meet both 90% class-rate targets. It is an experimental gate, not the currently selected full pipeline.

The gate's ordinary control belongs to its own study and has **247/53/185/17**, while the older original-pipeline archive has **247/47/191/17**. Their rule/source checkpoints differ. For an intervention claim, compare the gate with its matched ordinary control, not with the older archive or the selected trained pipeline. The current and earlier selected models share a version string but have different artifact checksums; [the evidence record](evidence-and-reproduction.md) keeps their identities separate.

## Uncertainty and sparse coverage

| Current selected pipeline rate | Denominator | Descriptive 95% Wilson interval |
| --- | ---: | --- |
| AI4Privacy recall | 81 positives | 78.74%–93.15% |
| AI4Privacy specificity | 22 clean | 30.72%–69.28% |
| Nemotron recall | 110 positives | 81.90%–93.65% |
| Nemotron specificity | 184 clean | 21.76%–34.59% |
| Gretel specificity | 28 clean | 12.68%–43.36% |
| Privy specificity (0/2) | 2 clean | 0.00%–65.76% |

These newly calculated Wilson intervals are **descriptive row-level binomial intervals**. They do not account for source-group dependence, model/threshold selection, repeated development use or multiple comparisons. They supplement support counts and do not replace the archived source-group bootstrap analyses. Their overlap does not establish equivalence; their nominal bounds do not justify a dataset ranking. No new paired significance test or group-bootstrap interval was calculated here.

## All preserved development configurations

These pooled values are a reconciliation check on the same 502 sentences, rather than a substitute for dataset-stratified reporting. [All stratified tables](all-stratified-results.md) include the raw per-dataset counts for every configuration below.

| Configuration | TP / TN / FP / FN | Recall | Specificity | Balanced accuracy |
| --- | --- | ---: | ---: | ---: |
| Original NER | 55 / 232 / 6 / 209 | 20.83% | 97.48% | 59.16% |
| Original full pipeline | 247 / 47 / 191 / 17 | 93.56% | 19.75% | 56.65% |
| Original regex + NER | 198 / 203 / 35 / 66 | 75.00% | 85.29% | 80.15% |
| Original regex | 179 / 208 / 30 / 85 | 67.80% | 87.39% | 77.60% |
| Original semantic | 169 / 60 / 178 / 95 | 64.02% | 25.21% | 44.61% |
| Earlier selected full pipeline | 247 / 54 / 184 / 17 | 93.56% | 22.69% | 58.12% |
| Earlier selected regex | 172 / 231 / 7 / 92 | 65.15% | 97.06% | 81.11% |
| Current selected full pipeline | 239 / 70 / 168 / 25 | 90.53% | 29.41% | 59.97% |
| Current selected semantic | 140 / 77 / 161 / 124 | 53.03% | 32.35% | 42.69% |
| Configured independent Presidio | 208 / 189 / 49 / 56 | 78.79% | 79.41% | 79.10% |
| Sparse presence: efficient | 249 / 169 / 69 / 15 | 94.32% | 71.01% | 82.66% |
| Sparse presence: balanced | 247 / 181 / 57 / 17 | 93.56% | 76.05% | 84.81% |
| Sparse presence: quality | 247 / 189 / 49 / 17 | 93.56% | 79.41% | 86.49% |
| Contextual gate: efficient | 242 / 175 / 63 / 22 | 91.67% | 73.53% | 82.60% |
| Gate study: matched ordinary control | 247 / 53 / 185 / 17 | 93.56% | 22.27% | 57.91% |
| Contextual gate: balanced | 242 / 169 / 69 / 22 | 91.67% | 71.01% | 81.34% |
| Contextual gate: quality | 242 / 159 / 79 / 22 | 91.67% | 66.81% | 79.24% |

Sparse presence profiles use a separate binary annotation-presence endpoint and validation-selected thresholds. The contextual gates suppress only semantic findings; they retain regex/NER contributions. Neither supplies independent contextual/action truth. The later research used development feedback, so these comparisons are exploratory and do not establish untouched generalization or a causal capacity/training effect.

## Separate positive-only external source-heldout results

The expanded-data study measured sparse annotation-presence profiles on **official train-origin, source-heldout** sets: Nemotron 1,000 positives in 500 parent-UID groups, and Meddies English 999 positives in 36 coarse metadata families. These differ from the PIIMB sentence-level Nemotron stratum above.

| Source-heldout partition | Profile | Baseline TP / FN | Baseline recall | Expanded TP / FN | Expanded recall |
| --- | --- | --- | ---: | --- | ---: |
| Nemotron official train-origin | efficient | 956 / 44 | 95.60% | 1000 / 0 | 100.00% |
| Nemotron official train-origin | balanced | 919 / 81 | 91.90% | 1000 / 0 | 100.00% |
| Nemotron official train-origin | quality | 892 / 108 | 89.20% | 1000 / 0 | 100.00% |
| Meddies English train-origin | efficient | 998 / 1 | 99.90% | 999 / 0 | 100.00% |
| Meddies English train-origin | balanced | 997 / 2 | 99.80% | 999 / 0 | 100.00% |
| Meddies English train-origin | quality | 995 / 4 | 99.60% | 999 / 0 | 100.00% |

There are **no trusted negatives** in these source-heldout sets. Specificity, false-positive rate and balanced accuracy are unavailable for every row. Perfect observed recall cannot be compared with mixed-class specificity, establish population-level perfect detection, or prove clinical/contextual privacy safety. The corresponding row-level Wilson lower bounds are 99.62% for both 1,000/1,000 and 999/999, subject to the clustering caveat above. Meddies families are a coarse grouping proxy, not verified original document identity; those 999 examples do not represent 999 independent clinical records.

All 18 external validation/source-heldout runs reconcile to **17,802 archived successful prompt requests and zero errors**. No requests were sent during this recalculation. Validation has 968 rows/714 groups and was used for C/threshold selection; it is not a new independent test. The expanded study contains validation and source-heldout scoring, not a new expanded-model development result. The full validation/source-heldout strata are in [the detailed tables](all-stratified-results.md).

## What to take into a later discussion

Describe source-specific detector weaknesses with counts and support. Explain why a larger false-positive count is not automatically a worse error rate. Keep exact dataset/task origin and annotation presence distinct from contextual sensitivity and complete de-identification. Discuss the lack of negative examples in external heldout sets and thin MAPA/Privy coverage.

The next useful benchmarks would add independent, explicitly labelled entity relevance and contextual disclosure evidence; [the literature review](comparison-datasets.md) identifies candidates and restrictions. Rechecking this development sample must not be presented as fresh confirmation. The locked final partition remains uninspected and unscored.
