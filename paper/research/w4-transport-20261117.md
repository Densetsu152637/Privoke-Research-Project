# W4 client transport: native messaging instead of the loopback bridge (W4-TRANSPORT-20261117)

**Status: partial.** The transport is built and unit-tested in the extension; the controller, protocol and fail-closed behaviour are tested in Rust. The study checks that need local browsers were not run to completion, because the coordinator withdrew local builds and browser runs on 17 November 2026 and asked for CI evidence instead. This record does not change `paper/main.tex` or any earlier record, and every existing evidence row stays a Python-bridge measurement.

## Done and where it is evidenced

- Extension: `npm test` 368/368 (baseline 335) including `native-port-transport.test.js` (Chromium and Firefox dialects, deadlines, abort, disconnect, malformed replies, no replay), `runtime-client.test.js` (same messages, 30 s and 35.5 s constants, WARN+MASK spans survive, no loopback use) and the updated launcher, failure-text and API tests.
- Controller: `tests/controller_session.rs` (16), `tests/real_worker.rs` (real Python worker under the pool sandbox, passed once locally), `tests/health.rs` (4); clippy `-D warnings` and `cargo fmt --check` were clean before the stop. The full `cargo test --workspace --locked` was not run locally; CI is the evidence.
- Smoke only (not a result): one Chrome 157 run and one Playwright Firefox 159 run through the temporary native-host registration answered ALLOW decisions end to end with no process of ours started by the study. Medians of 5 samples were 167 ms (Chrome) and 36 ms (Firefox) on a heavily loaded host. Registrations were removed afterwards; no listener on 8080, 50056 or 50057 and no PriVoke process remained.

## Pending (not run)

| Check | State |
| --- | --- |
| 73-probe study on Chrome and Firefox over native messaging, `run --transport native` | harness written (`evaluation/cross_platform_study.py`, `evaluation/w4_transport.py`), not run |
| No listening ports (`Get-NetTCPConnection` sampler in the harness) | not run; the Rust test `the_controller_and_its_worker_listen_on_no_port` checks the controller and worker |
| No orphan after browser close | harness check written, not run; Rust tests cover port close and controller kill |
| Latency against `tests/conformance/latency-baseline.json` | not captured. Two bridge attempts on this host were dominated by other jobs (run medians 56 to 174 ms, then 118 to 149 ms with two failed runs), so neither is committed as a baseline |
| Edge Copilot gap (EDGE-COPILOT-1) | out of scope, unchanged |

## Notes

- The existing website policy, warn and hand off when analysis cannot complete, is unchanged. The transport itself fails closed: a request resolves only on a well-formed success reply for its id.
- Native host name is `org.privoke.runtime_controller`, distinct from the Python launcher's registered name, which was not touched.
