# Released-model profile comparison

Measured 3 October 2026 under the [prospective protocol](model-profile-protocol.md). This compares the original `v0.3.0` efficient, balanced and quality artifacts on the same 502 locked development rows (264 positive, 238 clean). Final 498 remains unscored. These are development measurements, not a final evaluation.

## Results

| Original profile | Parameters | Archived JSON bytes | Semantic TP/TN/FP/FN | Semantic recall | Semantic specificity | Pipeline TP/TN/FP/FN | Pipeline recall | Pipeline specificity |
| --- | ---: | ---: | --- | ---: | ---: | --- | ---: | ---: |
| Efficient | 19,028 | 409,822 | 158/61/177/106 | 59.85% | 25.63% | 236/60/178/28 | 89.39% | 25.21% |
| Balanced | 36,756 | 789,151 | 169/60/178/95 | 64.02% | 25.21% | 247/53/185/17 | 93.56% | 22.27% |
| Quality | 54,292 | 1,164,874 | 190/48/190/74 | 71.97% | 20.17% | 241/45/193/23 | 91.29% | 18.91% |

Recall is TP/264 and specificity is TN/238; percentages are recomputed from the displayed counts. Every profile had 502 matched development IDs, labels and source groups, zero prediction errors, and raw confusion counts matching its report metrics. Quality has the highest semantic recall, while original balanced has both higher pipeline recall and specificity than quality. The table therefore does not support prioritizing quality-profile training for the current pipeline false-positive problem.

## Runtime cost and configuration

Times are the evaluator's returned `elapsed_ms`; first request is shown separately from the all-request median and p95 (which include the first request). They exclude browser/native-messaging overhead and are not robust cold-start or deployment-latency estimates.

| Profile | Semantic first / median / p95 ms | Pipeline first / median / p95 ms | Encoder configuration; bootstrap-head epochs |
| --- | --- | --- | --- |
| Efficient | 27.80 / 6.45 / 7.58 | 260.21 / 229.48 / 289.24 | 1 layer, hidden 24, max tokens 64, vocabulary 512; 220 bootstrap-head epochs |
| Balanced | 56.03 / 13.45 / 16.91 | 283.74 / 267.21 / 338.31 | 2 layers, hidden 32, max tokens 96, vocabulary 512; 360 bootstrap-head epochs |
| Quality | 81.30 / 20.05 / 23.96 | 342.07 / 276.94 / 354.27 | 3 layers, hidden 32, max tokens 128, vocabulary 768; 520 bootstrap-head epochs |

The profiles also differ in initialization seed and bootstrap-head training epochs. This is a comparison of released configurations, not a size-only causal test. The frozen encoders are randomly initialized, not pretrained language models. Results do not establish robust cold-start behavior; request order, cache refresh and model-download work can affect the measured cost.

The recorded container host was x86_64 with Python 3.11.17, an Intel Core i7-13700KF and 24 visible CPUs; `cpu.max` and `memory.max` were unlimited and the effective cpuset was 0-23. Reported package versions were datasets 5.0.1, NumPy 1.26.4 and scikit-learn 1.9.1. The study ran sequentially. Hardware details are in [`hardware.json`](../../evaluation/results/model_profiles_20261003/hardware.json).

## Paired comparisons

The six pairwise reports compare all three profile pairs for semantic-only and full-pipeline output. For balanced versus quality, group-paired 95% bootstrap intervals (2,000 resamples, seed 3102026, 465 source groups) give:

| Layer and measure | Quality minus balanced | Descriptive 95% interval |
| --- | ---: | ---: |
| Pipeline recall | -2.27 pp | -5.77 to +1.47 pp |
| Pipeline specificity | -3.36 pp | -9.92 to +3.41 pp |
| Pipeline balanced accuracy | -2.82 pp | -6.56 to +1.11 pp |
| Semantic recall | +7.95 pp | 0.00 to +16.31 pp |
| Semantic specificity | -5.04 pp | -11.93 to +2.07 pp |
| Semantic balanced accuracy | +1.46 pp | -3.85 to +6.94 pp |

These intervals are descriptive development comparisons after preceding tuning. They do not establish statistical superiority, causal effects, or final generalization. The paired source files are [balanced-quality pipeline](../../evaluation/results/model_profiles_20261003/paired_privoke-balanced_privoke-quality_pipeline.json), [balanced-quality semantic](../../evaluation/results/model_profiles_20261003/paired_privoke-balanced_privoke-quality_semantic.json), plus the four efficient-versus-balanced/quality reports in the same directory.

## Provenance and interpretation

The completed [study summary](../../evaluation/results/model_profiles_20261003/summary.json) records source revision `b733960079babc9fc695fdc6ba836ac7ae87b86e`, zero error status, exact model identities and successful restoration. The selected trained balanced payload was restored with checksum `8c139431ba8605a3d6817d24d233cce78fc22a086fdeb3ee99702ada86c80015`. Serving image IDs were unchanged before and after the study. Each archived profile JSON and each semantic/pipeline report was checked against its recorded SHA-256; returned model IDs, versions, checksums and shape-inclusive float32 parameter fingerprints matched the corresponding archived artifact. Per-profile evidence is in [`efficient`](../../evaluation/results/model_profiles_20261003_privoke-efficient/), [`balanced`](../../evaluation/results/model_profiles_20261003_privoke-balanced/) and [`quality`](../../evaluation/results/model_profiles_20261003_privoke-quality/) result directories. The exact archived artifact file SHA-256 and internal model checksum pairs are:

| Profile | Artifact file SHA-256 | Model checksum | Semantic report SHA-256 | Pipeline report SHA-256 |
| --- | --- | --- | --- | --- |
| Efficient | `dba15180eb85c5ddfdb4b2a0d18c705d7384f199d1ed29385656582e3d439735` | `a78e4fc8837a50e3fc1e70044f71a1490f7524454f84e86e6a82531f4c8059fe` | `9bd42ed3fdfa186b3838cbbcc2904e91ba1dfac92a6ed85132a5e7813d40693a` | `0656e60255ecd1d737116072db6692933905dc9d0d5ca96a620b39b60237c488` |
| Balanced | `58f7344d68fbce690d511464df73d3f5ab18feb06654a3d09f75c1e0591744ea` | `8390b96871c6edd00916e3a6126da1b09c19f9fdbdda8214ebe667a893e5ee2c` | `5f8b65efe38b6615a7f761cb3c3fdd20e111043213fee237e431c8591a5439be` | `da1dd2f3573d6496be2712bd54c75f37a20557c54c0e79ebcf18f28ea3484def` |
| Quality | `697ce3d2284ec9ab84ca2d503edd0a5657c7bf6bdaa3184f1936068160ce1fe6` | `76bc059fee0d7d6dd2df02b05d8fee9f05ef0ddb949f74e69a0a38064bc644ab` | `4e8946cc634da4ce48b416eae82779b7c23f99e737582bcd3277462a6552452f` | `a5d4de886319f69917db55ed8179b024129f6730bb92e0666ab79094be13f9d2` |

Each profile `manifest.json` records the common locked-development dataset SHA-256 `65bf02af1f9f7167a5aa5eaaa8aeac54111c90d009585ed36570d3ce0a635095`, artifact and report hashes, observed v0.3.0 identity, and completed layers. The manifests are in their respective result directories linked above.

The original balanced profile above is not the current selected trained balanced checkpoint. The latter's full pipeline result is TP/TN/FP/FN `239/70/168/25`, recall 90.53% and specificity 29.41%; it remains below the 90% specificity target. The locked final set remains unscored. Given these results, the next investigation should follow the prospectively documented [frozen-representation diagnostic](representation-protocol.md) rather than assume that additional quality-profile training will improve the false-positive tradeoff.
