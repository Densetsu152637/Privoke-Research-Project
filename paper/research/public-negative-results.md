# Public-negative development results

Measured 3 October 2026 under the [prospective protocol](public-negative-protocol.md).
This custom within-corpus PIIMB study trains on previously unused source documents;
it is not an untouched official benchmark-test evaluation. Final498 remains
unscored. All detection measurements below use the same502 development rows,
264 annotated-positive and238 clean, with no runtime errors.

## Independent attempts

Source revision `2f1ec91d36fa223babbabfa4a0d98fee33d0d629` orchestrated the study.
The grouped curriculum/training-normalization fixes were committed as `4f224ba`.
Each independent seed starts from exact original v0.3.0 with revised rules.
Serving images remain unchanged across the batch. Calls use256 prompts, zero
transformations, max-gradient0.05 and the existing16-example internal guard.

| Rate | Seed | Semantic TP/TN/FP/FN | Pipeline TP/TN/FP/FN | Pipeline recall | Pipeline specificity | Selection |
| --- | --- | --- | --- | --- | --- | --- |
| Original | — | 169/60/178/95 | 247/53/185/17 | 93.56% | 22.27% | Same-source baseline |
| 0.03 | 42 | 140/77/161/124 | 239/70/168/25 | 90.53% | 29.41% | Selected by declared tie-break |
| 0.03 | 1337 | 140/77/161/124 | 239/70/168/25 | 90.53% | 29.41% | Eligible, tied pipeline counts |
| 0.03 | 2026 | 139/77/161/125 | 239/70/168/25 | 90.53% | 29.41% | Eligible, tied pipeline counts |
| 0.1 | 42 | 108/100/138/156 | 229/91/147/35 | 86.74% | 38.24% | Below90% recall floor |
| 0.1 | 1337 | 110/100/138/154 | 229/91/147/35 | 86.74% | 38.24% | Below90% recall floor |
| 0.1 | 2026 | 107/101/137/157 | 228/92/146/36 | 86.36% | 38.66% | Below90% recall floor |
| 0.3 | 42 | Not scored | Not scored | — | — | Held-out regression rejection |
| 0.3 | 1337 | Not scored | Not scored | — | — | Held-out regression rejection |
| 0.3 | 2026 | Not scored | Not scored | — | — | Held-out regression rejection |

Nine training attempts produced six accepted/scored candidates and three
pre-publication rejections. Rejected calls return FAILED_PRECONDITION with
“Candidate model is worse on the held-out evaluation set.” They remain in the
attempt denominator; no public score or published candidate is claimed for them.
The completed independent manifest records successful restoration of seed42/0.03.

Compared with the prior selected pipeline, TP247/TN54/FP184/FN17, the new selection
has16 fewer false positives and eight additional false negatives. Its specificity
gain is6.72 percentage points, satisfying the prospectively declared five-point
extension trigger. Its recall is only one positive above the exact minimum238/264.
Neither90% specificity nor sufficient overall evidence has been achieved.

## Paired interpretation

Against the same-source original baseline, seed42/0.03 corrects17 clean
predictions and loses eight positive detections. The paired source-cluster
bootstrap uses502 rows in465 groups,2,000 resamples and seed3102026. Pipeline
recall changes by−3.03 percentage points (95% interval−5.26 to−1.12), specificity
by+7.14 points (+4.00 to+10.48), and balanced accuracy by+2.06 points (+0.14 to+4.07).
These are descriptive development intervals for a searched/selected candidate,
not confirmatory significance or final generalization claims.

Semantic recall falls from64.02% to53.03%, a−10.98-point change (interval−14.82
to−7.38). Semantic specificity rises from25.21% to32.35%; semantic balanced
accuracy changes by−1.92 points (−4.44 to+0.54). Other layers preserve some
pipeline detections but do not erase this semantic regression. Larger rates
reduce false positives at the cost of too much recall. This experiment supports
a bounded tradeoff, not broad improvement in semantic understanding.

Twelve paired reports cover both layers for every scored independent candidate.
The comparison uses the same-source original, not the prior selected checkpoint;
do not interchange its17-clean difference with the16-clean extension trigger.

## Provenance and validation

Curriculum:2,400 public negatives from1,814 source groups plus43 original bootstrap
examples. Seed4102026 selects from38,000 eligible clean rows after locked-group/
ID/text and anchor exclusions, normalized deduplication and conflict exclusion.
Its SHA-256 is `61b0d5c5f06fe0d948092f86044eb21c64a08c5f6d4f60ec6ecfb1466d42ecda`.
Bootstrap source SHA-256:
`75422c421d1a80d0cc3321979fb049f1045f02f334586d6fe62d8832f8a5a7dd`.
Public S0/PU targets remain provisional annotation-presence training labels.

The initial Windows-path launch failed before training. Its incomplete manifest
and restoration record remain in `public_negative_study_20261003`; fresh prefix
`public_negative_v2_20261003` identifies the corrected complete study. This
infrastructure failure is separate from the nine candidate attempts.

The running study loaded its original size/error checker before an independent
audit identified a missing exact-ID/label/group selection check. Source `2e8ca5c`
adds matched-key and raw-count verification. After completion, that stricter
validator was applied independently to all six scored candidates before the
additional-cycle caller accepted the selection. No live process was restarted
or request ID reused to apply this validation.

Evidence paths under `evaluation/results/`:

- `public-negative-curriculum/`: prompts and source/exclusion manifest.
- `public_negative_v2_20261003/`: original snapshot, study log, selection manifest,
  starting/ending service images and12 paired reports.
- `public_negative_v2_20261003_lr003`, `_lr01`, `_lr03`: configurations, independent
  update responses, published snapshots and all three rejection files.
- Corresponding `_seedSEED_cycle1` directories: raw semantic/pipeline predictions
  and dataset/artifact/report hash manifests.

Relevant Docker checks pass: runtime83, fuzzer26 and evaluator50. The evaluator
checks include altered ID/label/group/count rejection, exact selection floors,
manifest tampering and accepted-but-unscored failure restoration. Computational
validation remains separate from professor confirmation and human labeling.

## Additional cycle and restored selection

Source `2e8ca5cb83d6e8c02c845fa9e9da7ce3512b71ff` calls cycle2 from seed42/0.03
cycle1, retaining the curriculum and service images. The service accepts the
update, but matched development scores are semantic128/85/153/136 and
pipeline236/78/160/28. Pipeline recall89.39% falls below90%, despite specificity
32.77%. Stop before cycle3 and restore cycle1, as the protocol requires.
This accepted update remains a scored but ineligible checkpoint.

Current selected artifact:
`evaluation/results/public_negative_v2_20261003_lr003/seed42-model.json`.

- Version: v0.3.0+train.1.
- Internal checksum: `8c139431ba8605a3d6817d24d233cce78fc22a086fdeb3ee99702ada86c80015`.
- Archived file SHA-256: `6f645057ad6cddfe6be3c00b85556ffda8c633834bda5e6a47ca2aee8babd921`.
- Runtime parameter fingerprint, including shapes:
  `3b9b63c14e5a5e3e3a82051cdc349a3c9d452b156f355594e5f7b49cb215758c`.
- Live restored file SHA-256:
  `e4363fc47b0b4663f92d923842e2bfe635b0d7b2b165c9cd4a8fb2f4a7e66d93`.

The live and archived files have identical parsed payloads and internal checksums;
their file hashes differ because atomic restoration serializes JSON and the
captured CLI snapshot includes formatting/newline differences. Both identities
are retained rather than claiming byte-identical restoration. The curve manifest
records `completed:true`, `selected_restored:true`, cycle1 and no execution error.

`public_negative_curve_20261003/` preserves the response, scored snapshot,
selection/stopping manifest, paired semantic/pipeline comparisons and a fresh read-only
SQLite backup. That backup contains32 receipts and passes `integrity_check`.
Its SHA-256 is `e74438c6d6668a15cf25cd501af76b747cee86553e66bf91a35f6e393c9836e4`;
the accompanying audit JSONL is
`7660cc0aca2b5981cdd89319327fc0cafae5a79add0cb5a06c88288165d71aab`.
The earlier25-row snapshot and artifact package remain intact.

The independent computational audit verified all six independent candidates'
matched predictions, all12 report hashes, candidate file/internal hashes,
float32 parameter fingerprints, prospective ranking, three rejection records and
unchanged persistent service images. This does not substitute for human review.

Further false-positive work should investigate discriminative training coverage
and the frozen representation, rather than interpreting stronger clean-class
updates as cost-free improvement. No scalar generation temperature is available
in this fuzzer. Any new experiment needs its own prospective question and stopping
rules; retain these tradeoffs and the final lock. Installed-extension enforcement,
client costs, artifact reproduction, final evaluation and manuscript/figure
integration remain pending.
