# Frozen-probe false-positive input audit

Audited 4 October 2026 at repository revision `ade0d6c7e10380f211f61d4df0137e653ee5bc32`.
This is an exploratory input-shape audit of the completed frozen-representation
diagnostic. It uses the 502 locked development rows only; it did not open or
score the locked final partition. The underlying probe is annotation-presence
fitting on the original frozen encoder, not a live detector or contextual
privacy policy.

## Matched error transitions

The audit joins predictions by ID and verifies truth and group against the
prepared development rows; every prediction has status `ok` and a Boolean
decision. On the same 502 rows, the original semantic reference scored
169/60/178/95 (TP/TN/FP/FN), the validation-selected probe scored
238/112/126/26, and the offline probe plus reused regex/NER union scored
250/108/130/14. Relative to the original semantic false positives, the probe
corrected 97, retained 81, and introduced 45 new false positives. The reused
union recovers 12 probe false negatives and adds four clean false positives;
the `regex-ner` output flags all four added errors and all 12 recovered misses.
These are row-level overlaps, not causal attribution to individual rules.

Probe false positives span 119 source groups; seven groups contain two such
rows, and none contain more than two. They are source-concentrated: the
`nemotron-pii` namespace accounts for 95/126 probe false positives and 294/502
development rows (95/184 clean rows misclassified). The `ai4privacy-en`
namespace has 15/22 clean rows misclassified, while `gretel` has 12/28. The
`mapa-eur-lex` and `privy` clean denominators are only two rows each, so their
2/2 rates are not useful source-level estimates. `mapa-eur-lex` has no rows in
prepared train or validation; its two development rows are both false
positives. `ai4privacy-multi` is represented in train and validation, but has
only one positive development row and no clean development denominator. These
tiny dev-only namespace counts caution against generalizing
the aggregate score. The keys below are namespace prefixes from `group_id`,
not a reconstructed row-level `source_dataset` field. Counts show the source
and truth composition of the actual prepared partitions:

| Group namespace | Train positive/clean | Validation positive/clean | Development positive/clean | Probe FP / development clean |
| --- | ---: | ---: | ---: | ---: |
| `ai4privacy-en` | 455/171 | 126/37 | 80/22 | 15/22 |
| `ai4privacy-multi` | 12/11 | 7/2 | 1/0 | — |
| `gretel` | 423/248 | 98/54 | 55/28 | 12/28 |
| `mapa-eur-lex` | 0/0 | 0/0 | 0/2 | 2/2 |
| `nemotron-pii` | 888/1,432 | 206/384 | 110/184 | 95/184 |
| `privy` | 147/45 | 38/16 | 18/2 | 2/2 |

Probe false positives have median length 66.5 characters (p90 127), compared
with 31 (p90 76) for probe true negatives (p90 uses the script's floor-index
over sorted lengths). Digits occur in 34/126 false
positives and 20/112 true negatives; they occur in 196/238 true positives.
Thus longer, number-bearing text is not sufficient to separate clean from
annotated examples. The development set has unique normalized text keys, and
false positives show little repeated-sibling concentration. These checks rule
out exact normalized duplicates within the prepared partition and show little
within-group error clustering; they do not rule out templates repeated across
different groups.

An exploratory token-overlap check found 76 alphabetic tokens that appeared in
at least two false-positive rows and at least two training rows of each truth
class. At least one such mixed-label training token occurs in 85/126 false
positive rows. The check tokenizes `training_text_key` output into alphabetic
tokens of length four or more, lowercases, removes the literal stopword set in
the audit script, and uses row-frequency thresholds of two. It emits no token
strings. This is a coarse overlap statistic, not a semantic or causal test; it
shows that recurring lexical cues in false alarms are also present in both
training classes.

## Next discriminating check

The next bounded input control is a text-only word/character-feature comparison
on the same protected train/validation/development partitions, with feature
settings and validation-only threshold selection recorded before any new
development score. Report source-namespace strata and matched error
transitions. A substantially better lexical control would show that input or
source style contributes to the observed within-corpus score; similarly poor
results would be consistent with shared data/task limitations. Neither result
alone identifies the frozen encoder as the cause, establishes contextual
privacy decisions, or justifies deployment. Treat this control as evidence for
designing a later bounded binary-head/update-interface study, not as a post hoc
pass/fail gate. The current reused-rule diagnostic remains below the 90%
specificity target, and final data remain unscored.

## Reproduction and provenance

From the repository root, reproduce the metadata-only calculations with:

```powershell
py -3 evaluation/results/text_control_input_audit_20261004/audit.py
```

The [audit script](../../evaluation/results/text_control_input_audit_20261004/audit.py)
writes [audit.json](../../evaluation/results/text_control_input_audit_20261004/audit.json).
It checks the 502-row ID join plus truth/group alignment and records SHA-256
digests for the prepared development, training and validation rows, preparation
manifest, selected fit and selection record, original semantic report, both
probe wrappers and reused-rule report. The preparation identifies its source revision as
`4a13e9ffe6fd0d275efbde8afd4d8d8f1ffc2133`; selected probe C and threshold are
0.1 and `0.3507067984215434`, frozen on validation before development scoring.
The prepared development SHA-256 is
`45f91e320482dde4d0724cdf42a341649d52e33aeae326f059c714edc97cc706`, fit report
SHA-256 is `d9ba9d2d1c11fdbe27681966cde1d7aac331d2d2f1288013b1f352557e1e592b`,
and original semantic reference SHA-256 is
`6108300098c2fd993393fbe1f6d29ef8ae30ac9ebe9a44e86743db636d6f0daa`. Exact
digests for all inputs and aggregate outputs are retained in the audit JSON.
The script reads text only from train and development partitions to calculate
length/token aggregates; it does not emit raw text or read the locked final
partition.

The same audit was independently executed in the Docker evaluator with:

```powershell
docker compose -f docker-compose.yml -f evaluation/compose.tests.yml -f evaluation/compose.public-negatives.yml run --rm --no-deps -T evaluation-tests python /workspace/evaluation/results/text_control_input_audit_20261004/audit.py
```

The container run exited 0; its numerical counts and recorded input digests
match the audit above. The captured run output is
[`evaluation/text-control-input-audit-docker.log`](../../evaluation/text-control-input-audit-docker.log).
This confirms the aggregate calculations and source/class table, not byte-for-
byte identity of the generated JSON across host/container line-ending formats.
