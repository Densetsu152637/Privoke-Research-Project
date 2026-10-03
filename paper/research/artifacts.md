# Local development evidence package

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
