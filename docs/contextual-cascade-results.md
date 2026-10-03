# Contextual cascade results

## Status

**No valid cascade comparison has completed at this documentation checkpoint.** This file is a results scaffold, not evidence that the cascade improved performance or is safe. The core study and its independent evidence review are still pending. Failed attempts are preserved separately and are not accuracy evidence.

The protocol is [`contextual-cascade-protocol.md`](../paper/research/contextual-cascade-protocol.md). The study is a fixed, exploratory comparison of an annotation-presence gate that can suppress only semantic-layer findings. It is not a deployment change and cannot assign sensitivity, visibility, category, severity, or an action from the presence score.

## Fixed comparison scope

The three original-control comparisons are primary: original balanced v0.3.0 semantic artifact (SHA-256 `8390b96871c6edd00916e3a6126da1b09c19f9fdbdda8214ebe667a893e5ee2c`) paired with the efficient, balanced, and quality fitted presence profiles. The three comparisons against selected v0.3.0+train.1 (SHA-256 `8c139431ba8605a3d6817d24d233cce78fc22a086fdeb3ee99702ada86c80015`) are diagnostic because its public-negative curriculum overlaps validation (40 exact IDs, 40 normalized text keys, 190 declared source groups). They must not be described as held-out calibration.

The frozen inputs are validation 968 rows (475 present, 493 absent; prepared-v3 SHA-256 `d2d0c538e49f5bbc7a8f85887b9b8cfddb188a5ab9aae55c69ce26ae932be6d1`) and development 502 rows (264 present, 238 absent; SHA-256 `45f91e320482dde4d0724cdf42a341649d52e33aeae326f059c714edc97cc706`). Final 498 stays locked and unscored. The authored contextual fixture has 48 cases in 12 families; 7 are ambiguous exclusions. Labels are provisional assistant annotations pending professor confirmation, not independent human ground truth.

## Prespecified outcomes to populate after audit

| Context control | Presence profile | Validation calibration and exact parity | Development status and raw counts (TP/TN/FP/FN) | Action/context regressions | Runtime errors / identity / restoration |
| --- | --- | --- | --- | --- | --- |
| Original balanced | Efficient | Pending | Pending | Pending | Pending |
| Original balanced | Balanced | Pending | Pending | Pending | Pending |
| Original balanced | Quality | Pending | Pending | Pending | Pending |
| Selected trained | Efficient | Diagnostic pending | Pending | Pending | Pending |
| Selected trained | Balanced | Diagnostic pending | Pending | Pending | Pending |
| Selected trained | Quality | Diagnostic pending | Pending | Pending | Pending |

No thresholds, scores, or intervals are supplied here before a complete run. A final result record must bind every comparison to the frozen inputs, selected threshold, exact model checksums/fingerprints, source and container image IDs, per-row ID/truth/group joins, zero-error and live-vs-projection parity reports, and restoration evidence. Report intervention/action transitions independently of the binary annotation proxy; any missing class denominator remains null. Do not call runtime timing browser or bridge latency.

## Preserved unsuccessful attempts

- `evaluation/results/contextual_cascade_20261004_v1/study-run-manifest.json` records a failed pre-comparison attempt. It produced no valid scored comparison; its own manifest has `restoration_verified: false`. Any separate recovery evidence must be linked separately, not retroactively alter that manifest.
- `evaluation/results/contextual_cascade_20261004_v2/study-run-manifest.json` records a failed pre-comparison attempt after partial row collection, with zero completed comparison pairs and no valid scores. Its manifest records restoration verified. Preserve both attempts as execution failures, not as positive or negative performance findings.

The completed external positive-data study is reported separately in [`PII-dataset-analysis.md`](PII-dataset-analysis.md). Those binary annotation-presence results do not substitute for this contextual/action assessment. A successful cascade result would remain development evidence only: it cannot satisfy the broader evidence package, the independent human-label gate, final evaluation, measured enforcement/latency requirements, paper/figure reproduction, or professor/venue review by itself.