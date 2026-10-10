# Local development evidence package

## Online full-Tiny fuzzer mechanics — 10 October 2026

The [implementation record](../../docs/fuzzer-underlying-training-20261010.md) retains `RQ-FUZZER-FULL-ENCODER-20261010`, exact goal/prompt attribution, current contracts, mechanical results and failed-attempt limits. Local evidence is under `evaluation/results/fuzzer_underlying_training_20261010/FT5E/`: `FT5E-result.json` SHA-256 `07b3792fb83adc3f1911796ab1a5e46e1cf32ed2e3ba385699f67e63edf2c844` and `FT5E-evidence-manifest.json` SHA-256 `264af4759a2da599ff4d5bbd3f4399cc49f24646900e363c32306568fdd5bd64` bind 142 retained files. Runtime/fuzzer images use `98a59eebf9e897b656a392551ffa0a3913e715e3`, model/updater source remains `3d2490dfb773fc32824afd604c882e3eca2db68b`, and read-only helper source is `b509f0e355e98338c2c1730cf5a58a261623318d`.

Two actual publications demonstrate mechanics on a fixed synthetic fixture, not quality improvement. S0/S2 were streamed; S1 was reconstructed. All retained failures, the unproven SQLite precipitant, unit-only pending-FULL crash coverage and the missing original malformed-boundary error response remain disclosed. CI separation at `c7d8015447fcbade3cc20b2c2c26c2cc88622985` was followed by a three-line environment-context repair after run `38032270398` failed validation before jobs. [hosted run 38032520611](https://github.com/Densetsu152637/Privoke-Research-Project/actions/runs/38032520611) then passed on exact tested implementation revision `2ce3879c60c78fbc1c396b351043ccc880bbcc90`: five active jobs succeeded and the product job was skipped. `ft8-hosted-result.json` and the semantic job log retain this separate hosted evidence; the uploaded artifact ZIP was not independently decoded. This result does not assert that later documentation revisions passed CI. No cloud deployment or protected-final scoring is claimed; the historical evidence packages below are unchanged.

## Frozen pretrained contextual package — 10 October 2026

The [study record](../../docs/semantic-pretrained-context-study-20261010.md) preserves question `RQ-SEM-PRETRAINED-CONTEXT-20261010`, the original user prompts, prospective method, amendments and negative qualification decision. The [public evidence directory](../../docs/evidence/semantic-pretrained-20261010/README.md) contains allowlisted synthetic labels/actions, aggregate secondary counts, functional 512-token outcomes and a standard-library arithmetic reproducer. Its publication manifest binds delivered bytes; provenance hashes bind separate retained local receipts. No real public-development prompt text or raw response is redistributed.

Primary source `1064a9518b497186f6031698f43c47d6ea38a3be` and summary SHA-256 `2d673c73234b9d96a126847f3aa29fb971fae17c110ecf4a77f2d0126a1b7668` remain unchanged. The secondary-only scoring amendment and later runtime `fd0b507ddddd82ee88fb45e1249711738cc8f0c2` have separate provenance. Gains failed a serious-action veto; secondary credential harms and 256-token errors are retained. The subsequent nine-request 512-token check is functional evidence only. Public arithmetic reproduction does not rerun the model, verify unavailable raw archives or constitute independent human adjudication. Protected final data remain unscored.

## Profiles and frozen-representation diagnostic — 4 October 2026

The historical 4 October local package is
`evaluation/artifacts/research-20261004-profiles-representation.zip`
(32,120,849 bytes; SHA-256
`333e3fd6fb7891a64953b98dc954fabbff1e7edc95f6696aeefa42358b1bc207`).
[Its external manifest](profiles-representation-artifact-manifest.json) lists
886 file records and source revision
`4e675228cfb416c0f2f3ad6d74bd0a2a27342b9e`. ZIP integrity and every recorded
file hash were verified. The archive preserves the original-profile inference
study, offline frozen-representation v3 diagnostic and its pre-fit v1/v2
failures, predictions and scaler/selection artifacts, protected inputs, and
test logs. No final-scoring report is included. This is local evidence
preservation; it does not authorize external upload or redistribution of raw
benchmark examples, and it is not a clean-environment reproduction claim.
The earlier packages below remain unchanged.

## Public-negative study checkpoint

The subsequent local package is
`evaluation/artifacts/research-20261003-public-negative.zip` (18,021,592 bytes).
SHA-256: `be7feed5f913d2595445e17e32a54dcee49c5c6e7fe4bf6d962a5d90630237cf`.
[Its external manifest](public-negative-artifact-manifest.json) records766 files
and source revision `c035bc79a810df47c6dd75e88f44ce88fdd25062`. ZIP integrity and
every recorded file hash passed. It preserves the new curriculum, independent
attempts/rejections, stopped second cycle, matched/paired predictions, current
model snapshots,32-row receipt backup, validation logs and methodology draft.

The restored selected model has90.53% development recall and29.41% specificity.
See [public-negative results](public-negative-results.md) for its recall tradeoff,
custom within-corpus scope and provisional training labels. Final remains
unscored. This is local preservation, not clean-environment reproduction or
publication readiness. The earlier package below remains unchanged; no upload
or raw-data redistribution has occurred.

## Earlier template/rule checkpoint

The local package is `evaluation/artifacts/research-20261003-development.zip`
(14,617,326 bytes). Its SHA-256 is
`68f33923414a9186054ae6d255df41851069d30e339cb874b10727302eea5bc8`.
[The external manifest](artifact-manifest.json) lists 646 file records and exact
source revision `a14b0b93305c9ca652c601d51f3701a567d7c3f7`.
ZIP integrity and every archived file SHA-256 were checked after creation.
The external manifest and this locator are committed after the archived source;
the archive does not recursively include itself or its external manifest.

The package preserves source, original-source training context, selected and
rejected model snapshots, raw development predictions, run manifests, RPC failures,
paired comparisons from the initial study, validation logs and research records.
It also preserves the locked final input for reproducibility; **no final scoring
report exists**. Including the input does not authorize using it for development.

This is evidence preservation, not a successful clean-environment artifact
reproduction or a claim that all runtime dependencies are fully pinned. The
existing Docker images and isolated research volumes are retained locally.
Reproduction remains a completion-plan requirement, and remote CI remains unrun.
No upload or dataset redistribution has occurred. Audit upstream licenses and
attribution before sharing raw benchmark examples.

Use [the experiment record](false-positive-experiments.md) to distinguish primary
runs from invalidated pilots and unscored rejections; archiving an invalidated run
does not make it a valid result. That checkpoint's selected live pipeline has 93.56% recall and
22.69% specificity, so the research goal and final paper remain unfinished.
