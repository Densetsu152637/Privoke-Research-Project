# Fuzzer study execution repairs — 6 October 2026

No paper files were changed. Preserve these administrative failures separately
from model rejection, accuracy, and safety outcomes.

- The initial host baseline failed before inference because its Python environment
  lacked evaluator dependencies. A separate Python 3.11 environment was created.
- The first baseline study (`contextual_fuzzer_20261006_v1`) completed one profile,
  then its verifier rejected the evaluator's `local-jsonl:` example-ID namespace.
  All 968 IDs, groups, labels and counts subsequently reconciled. The original
  catalog/images were restored. No fuzzer fit occurred in that execution.
- A validation-only parity check completed both batches and restored the catalog,
  but a post-check tried to use a closed log. Existing reports were independently
  reconciled without repeating inference: zero classification mismatches across
  968 rows for both semantic and pipeline, against the original live balanced
  model. The recovery and report hashes are preserved in preflight `parity.json`.
- Attempt 00 of the fresh fixed study (`contextual_fuzzer_20261006_v2`) passed
  fuzzer gates, was committed, and had a verified durable receipt. Before scoring,
  the runner compared two different fingerprint formats. Runtime training hashes
  frame float32 tensor values without shapes; serving identities additionally
  frame tensor shapes. Both are explicit repository contracts.

The latter correction changes the verifier, with an additional unchanged-shape
check. It does not change training data, sampling, weights, update gates, the
54-request grid, or selection criteria. The accepted artifact and original
receipt remain preserved; its training request is not repeated. Its validation
score is collected once after the correction. Original source snapshots and
failed state are preserved under `execution-revision-01`, alongside the amended
controller, source hashes, recovered record, and restoration checks. Original
attempt elapsed time was not checkpointed and remains unavailable.

After all 54 requests terminated, revision 02 corrected fixture evidence
collection. A regex BLOCK legitimately skips later layers with an explanation;
the collector had treated that explanation as an error. The repaired collector
also rejects invalid layer statuses, executed semantic layers without returned
results, wrong model identities, and a collection without any verified semantic
identity. Seven RPC-focused tests pass. The old controller/state are preserved;
sampling, training, selection and contextual retention rules are unchanged.

The first development assessment completed both 502-row live-balanced batches
with zero runtime errors, then failed ID verification. Unlike validation, this
input supplies explicit top-level `example_id` values. The dataset loader
preserves those values instead of generating `local-jsonl:<id>`. All saved IDs,
truth labels and source groups match the frozen development input exactly. The
controller and reporter now follow that deterministic loader rule. Two tests
cover the explicit override and generated fallback, including rejection of the
wrong namespace. Revision 03 preserves the failed state and old sources before
recovery. Recovery must bind and reuse the completed live reports, leave the
frozen selection unchanged, and collect only the still-unmeasured fixture and
winner endpoints. It must not repeat training or reference inference.

The repaired host suite passed 108 tests with 11 skips after temporary files
were directed into the workspace. An earlier run encountered 11 Windows
sandbox temporary-file replacement errors; that failed log remains separate.
The isolated Linux study suite passed all 19 tests. These execution repairs
are administrative evidence, not increases in model quality.

Revision 03 reconciled and reused both completed live-development reports, then
stopped on the second live fixture case. The collector's nonempty-results rule
was incorrect: the frozen streamed classifier explicitly returns an empty list
for S0/PU with no categories, and the pipeline marks that successful call `ok`.
One valid fixture observation was checkpointed; the failing call's raw response
was not saved. The failed recovery log, state and partial fixture remain evidence,
and all seven model files and five image IDs were independently verified restored.

Revision 04 corrects only evidence collection/reporting. Every returned identity
must match and each complete live/winner collection must contain identity
evidence. An empty successful response has no per-case model fingerprint; this
limitation is explicit in the quality report. Audited continuation validates and
reuses the exact completed prefix with its original path-derived request IDs.
It must disclose one repeated, unpersisted fixture request, collect remaining
cases, and preserve any further failure instead of automatically replaying it.
No training request or reference development inference is repeated. The corrected
host suite passed 114 tests with 11 skips; the Linux study suite passed 19.

The completed-study reporting audit later corrected the held-out metric label:
exact match, class recall/specificity and severity/action guards count rows and
do not apply example weights. Training losses do apply weights. No numeric
score, guard, selection or retention decision changed. Original exports and
reporter source remain preserved. Corrected exports are
`evaluation/results/contextual_fuzzer_20261006_v2/model-quality-corrected.json`
(SHA-256 `e0aa85d8cbcbdf3cf83a9a57ead8346a27d81d5413633dcf586ecd318f3fdeb7`)
and `model-quality-corrected.md`
(SHA-256 `6fefd3ba08b3e50945c7d2447b90a156f7d1f7a2ed36fb36160312e6aecfe5bc`).
Their preserved reporter is `reporting-source-corrected.py`
(SHA-256 `960aa454bbaa773c20bb20081dac9482505767aaedb6498cd074436d0e2c2846`).
