# Controlled RQ3 cost and telemetry mechanics evidence

Record ID: `RQ3-OPS-20261017`. Local date: 17 October 2026 (raw timestamps use UTC).
Status: all three controlled studies completed; deployment monitoring usefulness
and updated-model installed integration cost remain unmeasured.

The goal was to investigate RQ3 and telemetry's suitability for service performance
monitoring and development usage statistics. The user clarified, verbatim:
“results here cannot be generated as there are not enough concurrent users to
produce test results.” Accordingly, the new evidence concerns controlled prototype
behavior, not real-user monitoring accuracy, service SLOs, adoption or utility.
No new usefulness simulation, training, protected-partition decoding, real-provider
traffic or product feature change was performed.

The [prospective protocol](rq3-telemetry-protocol-20261017.md) was reviewed and
committed before execution at `bf24b1835a25e370cdd64dd26110c7786d59f0aa`;
SHA-256 `8d54d9f677b51f3a828845c1ba64fe453b647f0aa603f6273e23c5a00b143b48`.
The [aggregate JSON](rq3-telemetry-evidence-20261017.json) retains all eight browser
cells, twelve paired profile deltas, component clusters, counts, source closures,
checks and raw artifact hashes. Raw-response reconciliation and calculations are
retained in [the computation source](../../evaluation/results/rq3-telemetry-20261017/computation-sources/summarize.py);
replay it with host `evaluation/.venv-fuzzer-study/Scripts/python.exe` from the
repository root. Its assertions independently decode all 70 component protobuf
requests/responses, reconcile browser request/layer/model/body counts and ledger
totals, and reproduce nearest-rank percentiles and paired median differences.

## A: actual telemetry transport and accounting

[Attempt 2](../../evaluation/results/rq3-telemetry-20261017/telemetry-attempt-2/manifest.json)
completed using the actual reporter/randomizer/budget and a separate loopback host
collector process with the actual SQLite store. All inputs were generated
analysis-shaped fixtures; no detector was invoked. Twenty-three ledger fixtures
each retained nominal epsilon 8, independently confirmed by read-only SQLite queries:
184 epsilon-1 reservations from 308 report opportunities. Of these, 168 reports
were accepted, 16 submissions failed during the controlled collector outage, and
124 opportunities were suppressed before queueing. These are fixture counters,
not user counts or production usage estimates.

| Phase | Offered report opportunities | Additional accepted reports | Observation |
| --- | ---: | ---: | --- |
| A1 initial cap | 100 | 80 | Ten fresh ledgers admit eight reports each |
| A1 reopen | 20 | 0 | Durable cap survives reporter/process reopening |
| A2 ordered inputs | 160 | 80 | Eight ALLOW then eight BLOCK per ledger |
| A3 collector outage | 16 | 0 | Sixteen actual submission-failure log entries; reservations remain spent |
| A3 exhausted reopen | 4 | 0 | No replay or renewed budget after collector recovery |
| A3 fresh-ledger recovery | 8 | 8 | New WARN fixture reports reach the actual collector |
| Total | 308 | 168 | Invalid-packet, Health and Summary calls are separate |

A2 offered 80 ALLOW and 80 BLOCK inputs. The protocol-derived reserved input mix
was 80 ALLOW and zero BLOCK because the first eight opportunities exhausted each
ledger. This constructed input-order effect is not an estimate of deployment bias
and is not an instrumented observation of the hidden pre-randomization input.
The collector exposes randomized marginals, not those underlying action labels.

The malformed packet returned INVALID_ARGUMENT without changing count 168.
All five noisy marginal totals reconciled to accepted reports, with exact declared
unique dimensions/domains. Full noisy **and estimated** summaries were unchanged
across the A3 and A4 collector restarts. All three collector process generations
were reaped, and every reporter thread stopped.

The 308 synchronous `report()` calls had p50/p95/max **56.157/143.356/189.324 ms**.
The denominator includes accepted, suppressed and failed-delivery states; this is
the Windows host fixture's durable-ledger/randomization/queue-call cost, not a
production or browser latency median. Network submission runs in the background,
but budget reservation and randomization execute in the caller. In the runtime,
the analysis response's elapsed field is constructed before `report()` is called,
so that field excludes this synchronous reporting work. These measurements must
not be added to Linux browser or model-component timings from the other studies.

Nine Summary RPCs had p50/p95/max 2.522/3.845/3.845 ms. Controlled operator
stop-to-observed-unavailability took 506.345 ms; the unsuccessful Health call used
the predeclared 0.5-second deadline. Restart-to-SERVING took 489.713 ms. These are
explicit operator probes of the collector, not an autonomous production health
monitor. The largest of six batch start-to-terminal-outcome durations was
6,877.486 ms; it is not a per-report delivery-lag percentile.

## B: supported installed V1 runtime cost

[The complete browser receipt](../../evaluation/results/rq3-telemetry-20261017/browser-capture/run-2026-10-16T22-02-42-592Z-49e0514b/receipt.json)
retains four fresh Linux Chromium profiles: fetch/XHR by two replicates. All use
the same synthetic text and identical JSON body. Each profile kept its actual
browser-launched native supervisor/detector and Go model service resident while
running detector bypass, rules/NER [2,3], semantic [4] and full [2,3,4]. The
replicate-two arm order was reversed. All requested layers actually executed
successfully, with exact returned V1 balanced identity throughout. Every selected
semantic model was `privoke-balanced`, version `v0.3.0`, artifact checksum
`8390b96871c6edd00916e3a6126da1b09c19f9fdbdda8214ebe667a893e5ee2c`, fingerprint
`fec1a27b2252e01f659b5b856e5bdb124ef79b72f28995c7b3599f5ce0bd44c6`.

The new paired study comprises **480 measured requests and 80 warmups**. The reused
native-startup procedure adds 144 scaffolding requests (four first decisions,
twenty warmups and 120 historical-harness “measured” requests), which are excluded
from the new cost table. Total actual requests: **704**, all ALLOW, each forwarded
unchanged exactly once. There were **564** decoded AnalyzePrompt wires; 140 new
detector-bypass requests correctly produced no RPC. Zero outside-fixture attempts,
layer errors, reduced-layer fallbacks or missing outcomes were observed.

The table measures the instrumented page's request call to fetch response-body
completion or XHR loadend at the actual local receiver. Each row has sixty measured
requests in two profile clusters. Values are nearest-rank descriptive statistics;
the sample does not establish a confidence interval or deployment tail guarantee.

| Transport | Enabled detectors | p50 ms | p95 ms | Observed max ms |
| --- | --- | ---: | ---: | ---: |
| fetch | None | 3.6 | 4.7 | 5.4 |
| fetch | Rules + NER | 31.1 | 41.5 | 71.0 |
| fetch | Semantic | 20.5 | 106.7 | 154.6 |
| fetch | Full | 45.7 | 134.3 | 141.7 |
| XHR | None | 3.4 | 4.4 | 4.6 |
| XHR | Rules + NER | 31.6 | 39.4 | 57.4 |
| XHR | Semantic | 20.1 | 145.1 | 160.5 |
| XHR | Full | 45.7 | 128.7 | 134.1 |

Each following entry subtracts that profile's detector-bypass median from its
enabled-arm median. These are twelve paired profile differences, not a difference
between independently pooled distributions and not paired per-request effects.

| Profile | Rules/NER delta ms | Semantic delta ms | Full delta ms |
| --- | ---: | ---: | ---: |
| fetch replicate 1 | 27.9 | 16.9 | 42.5 |
| XHR replicate 1 | 28.2 | 16.8 | 44.0 |
| fetch replicate 2 | 26.9 | 16.6 | 40.5 |
| XHR replicate 2 | 28.2 | 16.2 | 41.2 |

The baseline keeps the extension's interception/background path and native
infrastructure resident, with all detectors disabled and the master enabled.
These differences therefore quantify **detector activation within that supported
instrumented path**, not extension-absent or total firewall overhead. The receiver
boundary is genuinely matched in this run because all frozen prompts forwarded.
Page decision timings are separately retained in the JSON. No per-arm CPU/memory
or pure model-time estimate is produced; the four startup resource windows are
explicitly excluded from the paired-arm costs. Measurements include this harness
and its observers, one fixed short synthetic input, and a local receiver.

This installed path uses the supported original V1 model. An existing research
adapter can admit updated AU3 findings into the native product cascade, but the
normal native supervisor launches `grpc_main.py` and ties its bridge upstream to
that spawned runtime's port. No existing independent configuration route was
found for installing the AU3 adapter through this lifecycle. The experiment did
not replace that lifecycle or add a product feature. Updated AU3 installed/full-
pipeline cost remains unmeasured, as do Windows/Opera and real-provider behavior.

## C: exact retained AU3 model, separate semantic component

[The component receipt](../../evaluation/results/rq3-telemetry-20261017/au3-component-attempt-1/receipt.json)
uses the exact selected AU3 balanced package from the retained paper results:
`models/experiments/audience_v3_20261013/runs/cpu-02/exports/balanced/selected`,
manifest SHA-256 `99b36171056bb0398584a0b0556d9d7ff2640d0acac4b124a126327451a80589`,
tensor blob `e48e7c1aa46310b3b7b1f6422f7aa8902c70cf6ff861f7540a7c4be151de4df2`.
The same native `RuntimeServer.AnalyzePrompt` executed on CPU, with immutable local
loading and only the inference service registered. The initial protocol draft's
EN3 ancestor was replaced by this exact compatible AU3 package **before inference**;
that prospective revision and its reason are recorded in the frozen protocol.

Two sequential fresh processes each performed five warmups and thirty measured
host gRPC calls on the same synthetic text as B: **70 calls, 60 measurements,
zero errors**. Explicit requested and returned sole [4], unique matching request
IDs and exact model/checkpoint/tensor identities passed for every call. Both
processes were reaped. Loading/readiness was outside the measured calls. Actual
Torch 2.11 CPU, Transformers 4.57.6, NumPy 1.26.4, four threads and native
deterministic preflight are retained with actual imported module paths.

| Fresh process | Measured calls | Host gRPC p50 ms | p95 ms | Max ms |
| --- | ---: | ---: | ---: | ---: |
| 1 | 30 | 2.684 | 4.381 | 4.430 |
| 2 | 30 | 2.606 | 4.138 | 4.293 |

The native elapsed field has median zero in both clusters; 27/30 and 28/30 fields
were zero. A separately retained [post-run clock diagnostic](../../evaluation/results/rq3-telemetry-20261017/au3-component-clock-diagnostic.json)
from the actual Python 3.11.9 base executable reports `time.monotonic` implemented
by GetTickCount64 with 0.015625-second resolution. The shipped native source uses
that clock for elapsed time. Host `perf_counter` uses QueryPerformanceCounter
with 1e-7-second resolution. This supports a coarse-clock qualification, not a
claim of zero inference cost. The diagnostic is post-run evidence, not a new
preregistered acceptance criterion. The useful reported distribution is the host
loopback RPC boundary, which includes transport/serialization. It is neither an
installed-browser measurement nor a speedup against B, and the two experiments'
timings must not be composed.

## What the telemetry evidence supports

The [event contract](../../shared/proto/privoke/v1/telemetry.proto),
[emitter](../../extension/client-runtime/src/telemetry/event_emitter.py),
[collector](../../services/telemetry-service/app/server.py) and
[store](../../services/telemetry-service/app/storage.py) support the following
implementation-bound conclusions:

| Intended question | Current capability / limitation |
| --- | --- |
| Are reports reaching a working collector? | Exact accepted-report count and an independent writable-store Health probe; controlled outage/recovery was observed |
| How many analyses or users were served? | Neither denominator is present; caps and failed deliveries separate accepted reports from opportunities |
| What are minute-level latency/error rates? | No latency, error, layer, target or queue/drop fields in the event channel; no interval query |
| What happened on a particular UTC day? | Randomized four-hour time-of-day domain has no date; storage/query retains lifetime marginals |
| Is action/category mix drifting? | Randomized categorical marginals exist, but deployment accuracy/usefulness is unmeasured, admission can select early inputs, and category precedence loses co-occurrence |
| Which updated model caused a change? | Public version domain is only `v0.3.0`/`OTHER`; arbitrary new checkpoint versions collapse to OTHER and joint event fields are not retained |

The controlled Health and client-duration observations are separate from the
randomized event channel. The previous [finite/privacy/estimation audit](telemetry-evidence-20261014.md)
continues to own its conditional privacy and synthetic uncertainty findings.
This study adds no anonymity, user-level privacy, deployment monitoring utility,
contextual accuracy, training benefit or human-benefit claim.

## Failure history, provenance, checks and cleanup

Telemetry [attempt 1](../../evaluation/results/rq3-telemetry-20261017/telemetry-attempt-1/manifest.json)
failed before its first report: the Windows virtual-environment redirector's
`Popen.pid` differed from the actual interpreter PID. Its failed receipt, frozen
protocol, database and source hashes remain unchanged; zero-opportunity failure
was not pooled into successful timings. The mechanical repair launches the same
Python 3.11 base executable directly while explicitly prepending the active venv's
site-packages. A real subprocess regression verifies exact Popen PID and dependency
paths/versions. Every successful service readiness receipt records the actual
base executable and imported grpc/protobuf paths; C additionally binds
Torch/Transformers/NumPy. Attempt-one launcher/interpreter PIDs were absent and
its port could be rebound before retry. This changed no question, counts or gate.

The successful A/C runs therefore use `bf24b183` **plus the recorded working-tree
Windows-launcher repair**. HEAD alone is not a byte-exact replay identity. Their
raw source manifests and aggregate closure hashes bind actual executed bytes.
B's source/protocol/image hashes remain separately bound. The final repository
commit containing the repair is supplied by root after reviewing this record.

Focused host checks passed: 11 collector/service tests, 14 client privacy tests,
6 existing finite-audit tests and 4 operational harness checks. Browser evidence
checks passed 57 Node tests, 54 old-sampler Python tests, 12 container-collector
Python tests and 2 new RQ3 Node checks. The existing container-collector test file
uses Python 3.12+ f-string syntax, so Python 3.11 could not parse it. Host Python
3.13 passed after TEMP/TMP were set to repository-owned `.tmp/rq3-host-tests`;
the first Python 3.13 attempt had default-TEMP permission failures. No runtime or
test-source repair was made for those environment issues. Syntax checks and
`git diff --check` passed. The final aggregate reconciliation passed.

Root independently accepted the raw evidence after reconciling A's counts,
restart-summary equality, artifact/current-source hashes and stopped children /
threads; B's records, receiver/wire counts, matched bytes/forwarding, per-profile
quantiles and container identity/isolation/exit; and all seventy C protobuf pairs'
explicit layer, exact checkpoint/fingerprint/request identities and successful
status. The pooled cells and twelve differences are also reproducible from the
separate retained aggregation script.

Exact main commands are the frozen protocol's A command (attempt 2), and:

```powershell
evaluation/.venv-v1-v3-pipeline/Scripts/python.exe evaluation/run-rq3-semantic-cost.py --protocol paper/research/rq3-telemetry-protocol-20261017.md --output evaluation/results/rq3-telemetry-20261017/au3-component-attempt-1
docker compose -p privoke-rq3-browser-20261017 -f docker-compose.yml -f evaluation/compose.browser-installed.yml -f evaluation/compose.rq3-browser.yml build installed-browser-evidence
$env:PRIVOKE_SOURCE_REVISION = 'bf24b1835a25e370cdd64dd26110c7786d59f0aa'
$env:PRIVOKE_INSTALLED_IMAGE_ID = 'sha256:e0570937442d2a12fd3186d81bd97a1a5736e3a0b62fe144f235f43cd0b26a1f'
docker compose -p privoke-rq3-browser-20261017 -f docker-compose.yml -f evaluation/compose.browser-installed.yml -f evaluation/compose.rq3-browser.yml up -d --no-build --no-deps installed-browser-evidence
```

The [browser preflight](../../evaluation/results/rq3-telemetry-20261017/browser-preflight.json)
binds that immutable image, source revision and resolved service configuration:
network `none`, no published ports, read-only root, temporary profiles and only
the new owned host output bind. A, then C, then image build, then B ran serially.
The [independent container closure](../../evaluation/results/rq3-telemetry-20261017/browser-container-closure.json)
records natural exit zero, PID zero and OOMKilled=false. The sole owned exited
container was then removed; the post-cleanup project-container listing is empty.
No shared volumes, historical outputs or unrelated resources were removed.
After root's independent raw-evidence acceptance, only the owned
`privoke-rq3-browser:20261017` image was removed, with exact image identity checked
before removal and tag absence verified afterward. The
[image-cleanup receipt](../../evaluation/results/rq3-telemetry-20261017/browser-image-cleanup.json)
retains that result. Parent images and build cache remain; local ignored evidence
and model assets remain preserved. No task-owned container or image is retained.

Decisive SHA-256 values:

| Artifact | SHA-256 |
| --- | --- |
| A attempt 2 manifest | `07b0c430e65aa3a498b3b69cc28a6659e06b0d651f2935fc39e481a853f10977` |
| B complete receipt | `4338547079f500a944838481806564830531970d426638567efe36806f51996b` |
| C component receipt | `702b72d478e9c44be8de78521ef3c0dd9b243fcc27c068094e7d5957e2d0c515` |

All other artifact hashes, exact unrounded statistics, source-closure hashes and
post-run diagnostics are retained in the aggregate JSON. No external source was
introduced; repository source and the actual controlled receipts support this record.
