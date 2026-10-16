# Controlled RQ3 cost and telemetry mechanics protocol

Version: `rq3-installed-cost-v1` / `telemetry-operational-controlled-v1` / `rq3-au3-component-v1`.
Frozen prospectively before main execution. Runner source hashes and this file's
SHA-256 are retained in each exclusive ignored attempt directory. A failed
attempt remains failed. No new training, held-out decoding, real user traffic,
provider contact, product feature change or deployment-usefulness claim is authorized.

## Questions and interpretation

The controlled experiments measure supported installed-runtime request cost,
updated-model semantic component cost, and actual telemetry transport/accounting
mechanics. They cannot establish real monitoring utility: there are insufficient
concurrent users or deployment traffic. Ledger instances below are test fixtures,
never simulated production users. No new usefulness simulation is run. The prior
finite arithmetic and 180-cell estimation audit remains the source of synthetic
estimation/privacy evidence; these experiments do not replace its assumptions.

The randomized event schema has action, risk bucket, primary category, public
model-version bucket and four-hour UTC time bucket, plus mechanism/epsilon.
Storage retains lifetime marginal aggregates, without receipt timestamps, dates,
per-event rows, user identity, offered-event denominator, error/latency/layer fields
or a time-window query. `Health` independently probes database writability.
The protocol records these capability limits rather than adding telemetry fields.

## A: host collector/reporter/ledger mechanics

Run `evaluation/run-telemetry-operational-study.py` with host
`evaluation/.venv-fuzzer-study/Scripts/python.exe` (Python 3.11). A separate host
process registers the unchanged `TelemetryCollector` and `TelemetryStore` on an
OS-assigned 127.0.0.1 port. It owns a fresh SQLite database under the attempt.
The host controller uses actual generated gRPC clients and actual
`TelemetryReporter`, `StructuredEventEmitter`, OS randomizer and durable budgets.
Only generated analysis-shaped action inputs with `result=None` are supplied;
this does not invoke or evaluate a detector. Event epsilon=1, daily epsilon=8,
queue defaults and one-second reporter RPC deadline remain unchanged. No retries.

1. A1: ten fresh ledger fixtures, ten ALLOW opportunities each. Expect 80 accepted
   reports from 100 opportunities. Reopen the same ledgers with two BLOCK
   opportunities each; count stays 80.
2. A2: ten fresh ledgers, eight ALLOW then eight BLOCK opportunities each.
   Expect 80 additional accepted reports, all reserved inputs ALLOW, although
   the 160 offered inputs are evenly split. This establishes constructed
   admission-order sensitivity, not a deployment-bias estimate.
3. A3: stop/reap only the owned collector; probe actual unavailability. Two new
   ledger fixtures each offer eight BLOCK inputs. Require 16 actual logged
   submission failures and exhausted budgets. Restart the same database/port,
   probe readiness and persistence (160 reports). Reopen both exhausted ledgers
   with two ALLOW inputs each: no replay or new reports. A fresh ledger offers
   eight WARN inputs and restores accepted count to 168.
4. A4: an invalid mechanism packet must return INVALID_ARGUMENT without changing
   count 168. Another owned process restart must retain the same count/marginals.

Integrity/local test targets, not user SLOs: readiness within ten seconds,
terminal reporter queue outcomes within twelve seconds after each offered batch,
all five observed noisy marginal totals equal accepted sample_count, exactly
168 accepted reports from 308 report opportunities, all reporter threads stopped,
owned child reaped and source/protocol hashes stable. Exceptions, missed targets,
unexpected accepted counts or unknown cleanup fail the attempt. Invalid packet
and Health/Summary RPCs are separate from report opportunities. Report-call,
Health and Summary client durations are descriptive host observations. Batch
start-to-drained time bounds terminal outcomes for that controlled batch; it is
not a per-report delivery-lag distribution. Process stop-to-unavailable and
restart-to-serving are explicit operator probes, not autonomous outage detection.
Default cap and lost reservations mean accepted count is not analysis count.
Reopened databases and separate collectors exercise real persistence/process
boundaries; no collector/store/reporter mock substitutes for these phases.

Commands (from repository root):

```powershell
evaluation/.venv-fuzzer-study/Scripts/python.exe evaluation/setup-host.py
evaluation/.venv-fuzzer-study/Scripts/python.exe evaluation/run-component-tests.py telemetry
evaluation/.venv-fuzzer-study/Scripts/python.exe evaluation/run-component-tests.py client-runtime -p test_telemetry_privacy.py
evaluation/.venv-fuzzer-study/Scripts/python.exe evaluation/run-component-tests.py evaluator -p test_telemetry_mechanism_audit.py
evaluation/.venv-fuzzer-study/Scripts/python.exe evaluation/run-component-tests.py evaluator -p test_telemetry_operational_study.py
evaluation/.venv-fuzzer-study/Scripts/python.exe evaluation/run-telemetry-operational-study.py --protocol paper/research/rq3-telemetry-protocol-20261017.md --output evaluation/results/rq3-telemetry-20261017/telemetry-attempt-1
```

## B: installed supported-runtime paired request cost

Run the existing installed-browser harness with `PRIVOKE_RQ3_COST=true` and its
new RQ3 module. Four fresh profiles are fetch/XHR x two replicates. Each profile
retains one actual browser-launched native supervisor/detector across four arms:
all layers disabled (detector bypass), explicit rules/NER [2,3], semantic [4],
and full [2,3,4]. The master remains enabled so the identical native processes
stay resident. The baseline retains interception/background messaging and measures
incremental detector-enabled cost within that supported product path; it does
not isolate the extension's own installation/interception cost.

The current supported model distribution is the original checked-in V1 balanced
artifact, pinned by source/model hashes and actual returned semantic identity.
An updated AU3 research adapter exists in `pipeline_v1_v3_serving.py`, but the
standard native supervisor launches `grpc_main.py`; bridge upstream and spawned
runtime share one configured port. No independently configurable installed AU3
distribution route was found in that concrete launch path. This test consequently
does not close updated-model installed/full-pipeline integration cost. It does
not replace the shipped runtime with the separate research adapter.

The original Go parameter service remains resident across all profiles/arms.
Exactly the frozen synthetic text `Please explain the steps in this process.`
and JSON request body are used. Receiver case IDs occur only in URL query strings.
Each arm has five warmups and thirty measured requests. Replicate one uses bypass,
rules/NER, semantic, full order; replicate two reverses it. Actual settings and
the five-second health cache settle outside timed probes. Real native process,
start-tick, command, listener and RUNNING boundaries must remain unchanged around
each arm. Request calls end at actual fetch body completion or XHR loadend,
including cancellation for BLOCK. Decision and runtime elapsed timings are
retained separately. Every selected layer must actually execute successfully;
semantic/full fallback or errors fail integrity. Nonempty requested layers and
actual execution are decoded from real gRPC-Web frames. Receiver bytes/counts,
page/runtime IDs and sequential terminal quiescence bind every probe.

Each profile first runs the unchanged 1 first-decision +5 warmup +30 measured
rules/NER scaffolding requests to reuse existing native-startup/resource guards.
Those 144 requests are outside the new paired study; their resource windows are
explicitly excluded from paired-arm performance. New paired study: 80 warmups
and 480 measurements; total fixture requests including scaffolding=704. No
matched per-arm CPU/memory estimate is produced. Earlier whole-container resource
evidence remains separate.

Acceptance is measurement integrity, not an arbitrary speed target. All 480
attempts must be accounted for; all successful protected probes must retain exact
requested/actual layers and stable semantic identity. Outcomes use actual action:
ALLOW/WARN forward unchanged once; BLOCK forwards zero times. A shared receiver-
completion delta is reported only if every frozen prompt forwards in every arm.
Otherwise costs describe submission attempts and the unmatched receiver-boundary
limitation is explicit; no prompt selection, dropping BLOCK cases or post-hoc
labeling is permitted. Report each profile's median paired difference and each
transport/arm's descriptive p50/p95/max. Two profile clusters do not establish
tail guarantees or independent-observation confidence intervals.

Isolation: standalone Compose project `privoke-rq3-browser-20261017`, service
`installed-browser-evidence`, files `docker-compose.yml` then
`evaluation/compose.browser-installed.yml` then `evaluation/compose.rq3-browser.yml`.
Its network namespace is `none`; no host ports, credentials or shared service
volumes. Only the new owned host directory
`evaluation/results/rq3-telemetry-20261017/browser-capture` is mounted at container
`/workspace/evaluation/results/installed-browser-results`; the historical host
installed-browser output directory is not mounted.
Linux headed bundled Chromium/Xvfb and the standard native-host installer are
used. The root records immutable image identity before execution. Raw synthetic
captures, source/protocol/model hashes, every failed attempt and owned process /
listener/profile cleanup remain retained. No real provider or Windows/Opera
deployment claim follows. Python unit/client tests run on the host; the container
hosts actual browser/native services and the resource observer only.

## C: updated AU3 native semantic component

Pre-execution protocol revision: the initial draft selected the EN3 ancestor;
before any component inference, root requested the exact updated package used in
the retained paper results. Manifest-only inspection established that selected
AU3 balanced uses the same supported `privoke_pretrained_bert_v3` architecture
and model ID. The component path/pins below replace that draft's EN3 selection.
No EN3 timing run or new training was performed.

Use host Python 3.11 environment `evaluation/.venv-v1-v3-pipeline` (Torch 2.11 CPU,
Transformers 4.57.6, NumPy 1.26.4). A separate loopback host service executes the
unchanged native `RuntimeServer.AnalyzePrompt` using a pinned, read-only local
selected AU3 balanced package. Only the inference gRPC service is registered.
The harness supplies immutable loading, as existing research wrappers do, without
opening datasets, revalidating/refitting training, modifying old evidence or
registering a training service. Manifest SHA256 is
`99b36171056bb0398584a0b0556d9d7ff2640d0acac4b124a126327451a80589`;
model ID `privoke-v3-balanced`, tensor blob
`e48e7c1aa46310b3b7b1f6422f7aa8902c70cf6ff861f7540a7c4be151de4df2`.
Manifest/config/vocabulary/tensor hashes and native dependency preflight must match.

Two sequential fresh service processes each perform five warmups then thirty
measured gRPC calls on the same frozen synthetic text as B. Every request explicitly
selects [4], exact model ID and checkpoint metadata; every response must return
sole successful [4], exact model identity and unique matching request ID. Errors
remain in the attempted denominator and fail integrity. Host RPC and server
elapsed times are descriptive component distributions, not installed-browser
latency, speedup, classification accuracy or a composition with B. Native loading
and service readiness are outside measured calls; four CPU threads and deterministic
native preflight are retained. Each child must be reaped. No production utility
or current installed AU3 integration claim is supported by this component test.
