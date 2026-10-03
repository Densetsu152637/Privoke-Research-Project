# Prospective released-model profile comparison

Recorded 3 October 2026 following the user's request to test different model sizes.
Compare original v0.3.0 efficient, balanced and quality artifacts on the same502
locked development rows, with semantic-only and full-pipeline measurements.
Do not score final498, fit weights or select based on final outcomes.

Profiles differ in encoder depth, hidden size, context length, vocabulary size,
initialization seed and bootstrap-head training epochs. This is a comparison of
released configurations, not an isolated causal test of parameter count. The
larger profiles may improve accuracy, cost more, or both; no monotonic improvement
is assumed. The frozen encoders are randomly initialized, not pretrained language
models. Preserve the distinction between original balanced and the currently
selected trained balanced checkpoint.

First confirm all three catalog artifacts and unchanged serving images. Save
the currently selected balanced snapshot, ensure automatic startup training is
disabled, and temporarily restore original balanced v0.3.0. Efficient and quality
catalog payloads must match the checked-in originals. The evaluator requests each
explicit model ID through the existing semantic_model_id field. Verify returned
IDs, versions, checksums and parameter fingerprints against each archived artifact.
Recreate only the runtime between profiles to start with a fresh model cache;
do not rebuild images or change other detection layers. Restore the selected
balanced payload and serving services in a finally block, including after errors.

Archive all raw predictions, complete matched ID/truth/group checks, error counts,
configuration/source/image/artifact/report hashes and exact confusion counts.
Require zero errors and all502 development rows for a primary profile comparison.
Report recall/specificity together and per-profile parameter counts/JSON bytes.
Pair profile differences by source group with2,000 bootstrap resamples. These are
descriptive development comparisons after preceding tuning, not final confirmation.

For cost, report distributions of the evaluator's returned runtime elapsed_ms,
including median/p95 and the first request separately. Those values exclude
browser/native-messaging overhead and do not establish deployment latency or a
robust cold-start benchmark. Record actual container hardware limits and package
versions, run sequentially without concurrent feature exports or training, and
state that request order/cache refresh and model-download work can affect costs.

Use measured profile results to choose the next development investigation. Any
new training of a different profile requires its own configuration/update-gate
checks; larger-model inference results do not validate that update path. The
frozen-representation diagnostic may continue as independent implementation work,
but its execution must wait until this comparison stops to avoid cost contention.
