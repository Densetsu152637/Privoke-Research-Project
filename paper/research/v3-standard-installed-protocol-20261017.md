# Prospective standard V3 installed verification and cost repeat

Status: **DRAFT FOR ROOT REVIEW; NOT FROZEN; NO STUDY EXECUTED.**

This is a new product verification/cost protocol following the user's explicit
request to make selected V3 packages standard and retain V1 as older models.
It does not revise the frozen V1 protocol, its A/B/C receipts, or historical
RQ1/RQ2 results. No training, protected data, real user/provider traffic, cloud
deployment, telemetry utility simulation, or distributional superiority test is
authorized here. All prompts are generated non-sensitive controlled fixtures.

## Product identity and boundary

Use the ordinary extension build, native messaging launcher, supervisor, bridge,
runtime `AnalyzePrompt`, maintained Go model service and native V3 cache/loader.
Do not use the research V3 servicer or a test adapter as product inference.
`latest` must resolve to selected AU3 V3 balanced. Freeze the implementation
commit, all relevant source hashes, protocol SHA-256, complete image ID, resolved
Compose isolation, dependency versions, browser revision, manifest/blob pins,
and model/runtime/native launch identities before measurements.

| Canonical model ID | Exact manifest SHA-256 |
| --- | --- |
| `privoke-v3-efficient` | `1f45a21bd7bd0c931dad215f823008193e7af7359bc68527c1f5dd4e7fbbeffd` |
| `privoke-v3-balanced` | `99b36171056bb0398584a0b0556d9d7ff2640d0acac4b124a126327451a80589` |
| `privoke-v3-quality` | `bb17d355fe1ad13c7052e922fb6de607d82cdafb1f4440fee1a47f35d42caf39` |

The original packages remain immutable. Mount the separately prepared
`models/standard-releases` store read-only; do not copy weights into images or Git.
Use CPU inference, explicit OMP/MKL thread settings, and attest actual Torch
threads. No CPU-heavy jobs run alongside cost measurements. A new isolated
Compose project has no published ports or external network; only the newly owned
result directory is write-mounted. No historical evidence is write-mounted.
Python test clients/scoring run on the host. The actual installed browser/native
runtime may run in the isolated browser container as product processes.

## Cost repeat

Retain the exact original fixed safe byte prompt:
`Please explain the steps in this process.`

Four fresh browser/native profiles: fetch replicate 1, XHR replicate 1, fetch
replicate 2, XHR replicate 2. In each profile, retain the same resident native
infrastructure and request/receiver boundary across four arms:

1. Master enabled, all detector layers disabled (no analysis RPC).
2. Explicit regex + NER `[2,3]`.
3. Explicit semantic-only `[4]` using default `latest` -> V3 balanced.
4. Explicit full product pipeline `[2,3,4]` using default V3 balanced.

Order is forward in replicate 1 and reversed in replicate 2, as in the V1 study.
Each arm has 5 warmups and 30 measured attempts per profile: **480 new measured
attempts + 80 warmups**. The existing cold-profile fixture scaffold adds exactly
**144** calls (4 first decisions + 20 warmups + 120 scaffold measurements), all
accounted separately and excluded from paired-arm cost distributions. The new
scaffold must preserve its fixed fixture bytes and existing integrity gates.
Before/after each arm assert stable process/native/model identity. Every semantic
call must bind the exact balanced manifest/blob/backbone/tokenizer/architecture;
assert actual returned layers, status, request IDs, terminal quiescence and wire
count. No empty protobuf layer selection is permitted.

Keep every attempt and failure. ALLOW/WARN must forward original request bytes
exactly once to the local receiver; BLOCK must forward zero times. If any arm
blocks or errors, retain it and qualify the unavailable matched receiver
comparison. Do not change prompts, select ALLOW cases, or remove failed samples
to obtain a timing result. Separate failure settlement time from successful
matched receiver latency. The resident detector-off arm estimates detector
activation increment, not extension-absent or total firewall overhead.

Report per profile and each of the eight transport/arm cells n, p50/p95/max,
actions, errors, forwarding counts, plus all twelve per-profile activation
median deltas. Only two profile clusters per cell: descriptive results, no
confidence interval, tail reliability, population or arbitrary speed/SLO gate.
Compare to historical V1 descriptively; code/dependency/image/model changes mean
this is not a causal model-only speed comparison. Keep semantic and full-pipeline
results distinct. Initial package download/startup is outside resident arm cost
and must be identified separately rather than folded into semantic inference.

## Installed profile/legacy verification

After the last measured arm, reuse that browser profile for **10 additional
untimed integrity probes**: fetch and XHR for default `latest`, each explicit V3
tier, and explicit older V1 balanced. This happens after all cost measurements,
so additional resident tiers cannot confound those distributions. Use the same
fixed safe prompt, explicit semantic-only `[4]`, and the normal popup settings.
Assert requested selection, canonical returned model, exact checksum/blob and
architecture on every response, including clean responses. Retain ALLOW/WARN/
BLOCK and verify correct forwarding/zero-forwarding without selecting outcomes.
Assert old V1 selection remains V1, and switching back to default returns V3
balanced. Record actual successful `[4]` execution and all failure attempts.
Prospective total is **714** fixture calls: 480 + 80 + 144 + 10. If the maintained
harness requires different scaffold mechanics, root must review and freeze the
revised exact counts before execution; do not silently alter this draft.

## Integrity, execution and stop conditions

Integrity gates concern protocol execution, exact model identity, request
accounting, layer isolation, no external contact and safe process/resource
ownership. They are not user SLOs or statistical utility criteria. Preserve raw
protobufs, browser observations, receiver captures, source/image/package hashes,
cleanup evidence and failed attempts under a new ignored run root. At most three
mechanical repair/rerun attempts; preserve each failed attempt and source closure.
Changes to questions, prompt bytes, sample counts, arms or gates require review
and a new freeze before execution.

Planned maintained runner extension: a distinct V3 mode in the installed-browser
harness and cost helper, a new isolated Compose override/output bind, and focused
integrity unit tests. The old V1 mode and historical receipts remain explicit.
Exact commands and final source/image identities are supplied with the executable
runner for root review/freeze; this draft is not execution authorization.
