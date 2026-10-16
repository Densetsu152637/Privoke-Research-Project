# Standard V3 installed verification and controlled RQ3 cost

The maintained installed Chromium path loaded the selected AU3 V3 balanced model
through normal extension settings, native messaging launcher, supervisor, bridge,
Go package service and native CPU loader. All 480 timed default-balanced attempts
were ALLOW and reached the local receiver exactly once. Explicit efficient,
balanced and quality V3 selections, older V1 balanced, and return to default all
executed their exact pinned models successfully.

**Adverse finding:** V3 quality BLOCKed the fixed non-sensitive prompt on both
fetch and XHR during the ten separate profile checks. Both correctly forwarded
zero requests. This is one content example repeated across two transports, not an
estimated false-positive rate. The default-model choice follows bounded AU3
evidence and does not establish uniform privacy, retention or utility superiority.

## Scope and provenance

The prospective protocol was frozen before execution at source commit
`a77ab08d2f0935a4242a458c6c77c58aa1f929cd`, protocol SHA-256
`d486980d2f5615dfa2cfb2802e3f40d8c16194b28d42a34489153b6640d0d779`.
The immutable image was
`sha256:4382055242e3f4c9693a51a6f5edb20bc4349d96aa9685ca79553103bdb653a2`.
Image source hashes matched the frozen host sources; model weights were excluded
from images and mounted read-only. The one study attempt completed without repair
or rerun. The earlier V1 A/B/C protocol and evidence remain unchanged.

The fixed generated prompt was `Please explain the steps in this process.`
Four fresh browser/native profiles crossed fetch/XHR with two replicates. Each
profile had four arms: master enabled/all detectors off, regex+NER `[2,3]`,
semantic-only `[4]`, and full product `[2,3,4]`. Actual returned layers, successful
execution, unique IDs, model/manifest/blob/backbone/tokenizer identities and stable
browser/native/model-service process boundaries were asserted. Replicate 2
reversed arm order. Each arm used five warmups then thirty timed attempts.

Execution used Chromium `153.0.8010.12`, Playwright `1.63.0`, Node `24.20.0`,
Python `3.12.3`, Torch `2.11.0+cpu`, Transformers `4.57.6`, tokenizers `0.22.2`,
safetensors `0.8.0`, NumPy `1.26.4`, spaCy `3.7.5` and `en_core_web_sm 3.7.1`.
Every V3 semantic response attested CPU and actual four Torch threads. The
container saw 24 processors, CPU quota `max 100000` and memory limit `max`;
OMP/MKL threads were four. Other CPU-heavy checks and builds were paused during
timing. Telemetry was disabled. This was an isolated local prototype, not a
deployment or user-traffic study.

## Complete request accounting

| Category | Attempts | Treatment |
| --- | ---: | --- |
| New arm measurements | 480 | Included in timing cells below |
| Arm warmups | 80 | Excluded from timing cells |
| Startup scaffold | 144 | 4 first decisions, 20 warmups, 120 scaffold measurements; excluded |
| Post-cost profile checks | 10 | Run after all cost measurements; excluded |
| **Total fixture calls** | **714** | All unique IDs retained |

There were 574 actual AnalyzePrompt wire pairs: 284 regex+NER, 150 semantic-only,
and 140 full-pipeline. The 140 detector-off calls made no analysis RPC. Semantic
model counts were V3 balanced 284, efficient 2, quality 2 and older V1 balanced 2.
All 574 request/response/trailer pairs were decoded on the host and matched actual
execution and exact identities. There were zero execution errors and zero
observed external requests. Of 714 calls, 712 were ALLOW and forwarded unchanged
once; the two untimed quality BLOCKs reached no receiver. The raw artifact records
retain all outcomes and include the historical 120-entry scaffold-measurement
field separately from the complete 144-entry scaffold inventory.

## Resident request-to-receiver cost

Times below are page request through local receiver response completion, in ms.
Each transport/arm cell pools 60 timed attempts from two distinct profile clusters;
nearest-rank quantiles are descriptive. All timed requests were ALLOW/forwarded.

| Transport | Arm | n | p50 | p95 | Maximum |
| --- | --- | ---: | ---: | ---: | ---: |
| fetch | Detectors off | 60 | 3.2 | 4.0 | 4.3 |
| fetch | Regex + NER | 60 | 29.6 | 33.8 | 92.4 |
| fetch | Semantic V3 balanced `[4]` | 60 | 19.7 | 158.8 | 283.6 |
| fetch | Full product `[2,3,4]` | 60 | 35.4 | 172.8 | 202.1 |
| XHR | Detectors off | 60 | 3.3 | 5.0 | 7.4 |
| XHR | Regex + NER | 60 | 29.9 | 31.8 | 100.5 |
| XHR | Semantic V3 balanced `[4]` | 60 | 15.1 | 162.8 | 312.7 |
| XHR | Full product `[2,3,4]` | 60 | 35.9 | 175.8 | 341.0 |

Per-profile median differences from its own detector-off arm, in ms:

| Profile | Regex + NER increment | Semantic increment | Full-product increment |
| --- | ---: | ---: | ---: |
| fetch replicate 1 | 26.1 | 12.6 | 31.9 |
| XHR replicate 1 | 26.6 | 13.5 | 32.3 |
| fetch replicate 2 | 26.7 | 17.0 | 32.1 |
| XHR replicate 2 | 26.1 | 9.4 | 33.5 |

The baseline retains the instrumented extension and native infrastructure with
detectors disabled: these differences estimate detector activation increments,
not extension-absent or total-firewall overhead. Fixed warmups exclude initial
package download/model load from resident measurements; combined cold-download
and startup cost remains unmeasured here. High observed maxima and only two
clusters per cell do not establish a tail-latency guarantee, confidence interval
or user SLO. Comparison with historical V1 also changes product code, dependencies
and image; it is not a causal model-only speed or universal superiority result.
The prior isolated AU3 semantic-component measurement remains a separate boundary
and must not be added to these installed times.

## Evidence and cleanup

The matching JSON provides every profile's quantiles, all twelve median
differences, package pins, versions, source hashes and root's independent review.
Root independently recomputed the counts/quantiles and decoded all 574 raw wire
pairs, including trailer status and exact layer/model/CPU/thread identities.
Frozen package hashes were unchanged before/after and matched the original AU3
exports. All quality-tier BLOCKs were retained.

Raw receipt:
`evaluation/results/rq3-v3-installed-20261017/browser-capture/run-2026-10-16T22-55-51-377Z-eb826b13/receipt.json`,
SHA-256 `59222ee8588dd796f6f7ba76f32142296129d6f6e6ec3118be4a8cd3a9eec0dd`.
The ignored artifact manifest hashes every raw run file; reproducible host replay
is `evaluation/results/rq3-v3-installed-20261017/computation-sources/summarize.py`.
Console, resolved Compose, image/source attestation and actual container inspection
are retained beside the run. Focused pre-execution gates passed: five RQ3 Node
tests, 57 installed-evidence Node tests, host V3 six pass/one physical-symlink
privilege skip (reparse rejection passed), legacy 11, MiniLM 9, presence-gate 16,
runner syntax, merged Compose isolation and whitespace checks.

The container exited naturally with code zero, PID zero and no OOM; runtime
processes/listeners, receiver fixture and temporary certificates were verified
closed. Only project `privoke-rq3-v3-browser-20261017` was removed, leaving zero
owned containers. After root accepted the raw evidence, only the owned study image
`43820552...` and Go-check tooling image `3ff7c8da...` were removed with
`docker image rm --no-prune`, after exact-ID and zero-consumer checks. Cleanup
receipts retain both complete IDs and deletion output. Model packages, all
evidence, base images, unrelated resources and build cache are preserved. No deployment,
publication, new training, protected data decoding or real user traffic occurred.
