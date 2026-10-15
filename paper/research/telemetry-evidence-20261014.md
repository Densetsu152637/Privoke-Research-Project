# Telemetry mechanism audit protocol and evidence (2026-10-14)

Status: completed host evidence; protocol frozen before execution and retained separately with its original bytes. Exact assignment: "Get data and rewrite all autonomous unfinished paper gaps", scoped by T1/T2 to finite telemetry sampling, synthetic estimator error/clipping bias, ledger persistence and reporting selection. No prompt datasets, human labels, model fitting or deployment monitoring are involved.

The implementation remains unchanged. Audit public event epsilon 0.5, 1 and 2; split equally among the actual five domains (K=3,4,11,2,6). Under independent uniform OS random bits, CPython SystemRandom draws J/2^53 and accepts J/2^53 < binary64 p. Compute m=ceil(2^53 p), exact rational P=m/2^53 and Q=(1-P)/(K-1); alternative choice is rejection sampled. Enumerate coordinate likelihood ratios and multiply exact maxima. Bound logarithms using correctly rounded 100-digit Decimal.ln with outward neighboring representables. These bounds characterize this fingerprinted host sampler implementation and declared configurations, conditional on ideal OS bits; they do not attest deployed binaries or OS entropy.

Synthetic workload: seed 20261014; 10,000 repetitions per cell; n=8,80,800,8000 contributing reports; all epsilon settings and all actual domains; uniform, point mass, and 1% rare first-value truth counts (integer counts allocated deterministically). Sample each true category's finite-kernel multinomial output, then apply the actual collector's nominal inverse-response formula and independent [0,n] clipping. Retain bias, RMSE, MAE, empirical 2.5/97.5 percentiles, clipping frequency, sum incoherence and Monte Carlo standard errors; compare untruncated mean/variance with analytical finite-kernel moments. For n=8 enumerate the binomial-convolution law to compute clipping expectation without Monte Carlo. Check selected synthetic rows against actual TelemetryStore.summary, including mixed epsilon strata.

Isolated real SQLite ledger checks: fixed UTC dates, default eight reservations, new process reopening, rollover, clock rollback, corruption, concurrent reservations, failed build/queue overflow/failed delivery consuming reservation. Synthetic reporting selection uses first-eight cap among32 events per installation, reversal of event order, input-independent 50% loss, and a deliberately output-dependent delivery counterexample. These observations explain excluded selection effects and are not violations of the explicitly bounded kernel claim.

Host execution only, using the primary checkout's evaluation/.venv-fuzzer-study/Scripts/python.exe and this clean worktree's sources. Record source hashes in raw bytes and canonical LF; interpreter/build/platform/random.py/math binary; exact commands, seed, protocol hash, output hashes, errors and limitations. Preserve raw per-cell synthetic trial arrays locally under evaluation/results/telemetry-mechanism-audit-20261014; publish compact aggregate JSON and this record. Existing client/collector telemetry component suites and focused new tests must pass. main.tex/claims integration belongs to the root author. No new monitoring usefulness, user-level/participation/transport, training privacy or human-label validity claim is authorized.

Exact user objective (verbatim, retained at integration): "Can you now get data and rewrite the sections of the paper for all the unfinished work that you can get yourself? First plan out an implementation that utilises the workflows effectively and then act on that implementation."

## Completed host evidence

Execution revision is clean mechanism source `65a7c78bac57113a31b9c81e88366d5b25edaa5a`, with new audit source bytes pinned in the run manifest. Host Python 3.11.9 and NumPy 1.26.4 were used. Attempt 1 stopped before experiments because Windows built-in `math` has no `__file__`; its failure and original protocol are retained. Attempt 2 fingerprints the built-in module origin and base Python DLLs and completed all 180 cells, 10,000 repetitions each (1.8 million synthetic histogram trials). The immutable pre-execution protocol is `frozen-protocol.md` in each attempt; this document appends results without replacing that record.

Commands from the worktree root, using `D:/Git Repositories/Privoke-Research-Project/evaluation/.venv-fuzzer-study/Scripts/python.exe`:

```text
evaluation/setup-host.py
-m unittest discover -s evaluation/tests -p test_telemetry_mechanism_audit.py -v
evaluation/run-component-tests.py client-runtime -p test_telemetry_privacy.py
evaluation/run-component-tests.py telemetry -p test_security_validation.py
evaluation/analysis/audit-telemetry-mechanism.py --output evaluation/results/telemetry-mechanism-audit-20261014-v2 --repetitions 10000
evaluation/analysis/verify-telemetry-audit-results.py evaluation/results/telemetry-mechanism-audit-20261014-v2
```

All completed commands exited 0: 6 focused tests, 14 runtime telemetry tests, 11 collector tests (including synthetic loopback gRPC). The run independently matched 26 actual collector estimates over mixed epsilon strata. Raw histogram reconciliation checked 3,744 metrics and every observed row sum. The maximum untruncated mean discrepancy from analytical finite-kernel expectation was 3.1903 Monte Carlo standard errors; the maximum n=8 clipped mean discrepancy from full binomial-convolution enumeration was 3.2360. Both fit a review-stage exploratory six-MCSE consistency envelope (chosen after simulation, without selecting or refitting any cell). This is numerical consistency validation, not a monitoring-utility acceptance threshold or a simultaneous coverage theorem. The maximum variance discrepancy was 4.658% and is descriptive; variance agreement was not separately certified. No failed experiment was discarded or replaced by an unrecorded retry.

### Finite randomness

Under fresh independent uniform OS bits, all actual coordinate outputs retain positive support. Exact rational likelihood maxima and outward Decimal log bounds give:

| Public nominal event epsilon | Actual maximum log ratio minus nominal epsilon |
| --- | --- |
| 0.5 | +1.29401639915755363849 x 10^-15 |
| 1 | +1.50276663649997089254 x 10^-15 |
| 2 | +1.22645138049457146320 x 10^-15 |

The JSON retains 100-digit lower and upper bounds, strictly above nominal epsilon in every case; `nominal_bound_holds` is false. This closes the finite-kernel question for these fingerprinted host settings, conditional on independent uniform entropy, without certifying the exact nominal bound, the operating-system generator, other epsilon configurations or deployed builds. Exact Fraction division is first enclosed by adjacent Decimal representables; monotonic logarithms at these endpoints are expanded by adjacent representables because Decimal.ln is correctly rounded. The original nominal algebra check remains unchanged.

The ledger accounts nominal epsilon, while emitted tuple composition uses these slightly larger actual losses. At default E=1 the eight-reservation nominal cap is 8; its corresponding conditional finite-kernel upper bound is approximately 8 + 1.20221331 x 10^-14. Failed reservations do not emit; failed builds, queue overflow and delivery consume nominal budget conservatively. This tiny arithmetic difference is disclosed rather than treated as an exact nominal guarantee.

### Synthetic estimator error and selection

The estimand is the fixed, realized histogram of contributing reports. It does not include additional population-sampling variation. Histograms use balanced integer allocation (`uniform`), all mass in the first value (`point_mass`), and a minimum-one first count targeting 1% (`rare_first`). The last workload has realized first fractions 12.5%, 1.25%, 1% and 1% at n=8,80,800,8000; at n=8/K=11 its first coordinate is not uniquely rare. Balanced integer counts also cannot be exactly uniform when n is indivisible by K. The JSON stores every realized true histogram. Large n represents pooled installation-days: a default installation-day contributes at most eight reservations, so n=8000 is not one installation-day.

The simulator passes binary64-rounded finite P,Q to NumPy multinomial; this numerically approximates the exact rational kernel and uses PCG64 pseudorandomness, not OS entropy. The analytical finite privacy calculation uses exact rationals and does not rely on simulation. Estimator inversion and clipping use the deployed collector's nominal binary64 p,q. The exact untruncated expectation therefore includes the tiny finite-kernel versus nominal correction mismatch; it is not asserted exactly unbiased. Every cell reports analytical variance, empirical variance, bias, MCSE, RMSE, MAE, central 95% error quantiles, clipping frequency and sum incoherence. Those quantiles describe simulated estimation errors, not confidence intervals supplied by the collector API.

Examples for event epsilon 1, primary category (K=11), first value, in count units:

| Workload | n | True count | Clipped bias | Clipped RMSE | Clipping fraction |
| --- | ---: | ---: | ---: | ---: | ---: |
| balanced | 80 | 7 | +22.84 | 42.32 | 85.62% |
| balanced | 8000 | 727 | +237.50 | 1028.47 | 28.32% |
| point mass | 80 | 80 | -33.79 | 49.81 | 85.94% |
| point mass | 8000 | 8000 | -558.69 | 987.32 | 49.94% |
| minimum-one 1% target | 80 | 1 | +27.93 | 45.16 | 86.23% |
| minimum-one 1% target | 8000 | 80 | +469.33 | 907.36 | 47.38% |

Absolute errors can rise with n while relative errors fall. Independently clipped marginal estimates need not sum to n: for the balanced K=11/E=1 workload this occurred in 99.99% of n=80 trials and 99.78% of n=8000 trials (1e-9 comparison tolerance). These declared synthetic results demonstrate clipping bias and high uncertainty for the measured workloads; no application-specific usefulness threshold or real deployment accuracy was measured.

Actual isolated SQLite tests accepted eight default reservations then denied the ninth, denied another reservation in a separate reopened Python process, allowed next UTC day reset, failed closed on rollback/corruption, and accepted exactly sixteen of forty concurrent epsilon-0.5 attempts. Actual TelemetryReporter.report/_run paths consumed the reservation despite synthetic build failure, queue overflow and delivery failure.

Selection examples are deliberately constructed, not empirical deployment traces. With the same 32 events containing 25% BLOCK and the same first-eight nominal cap, placing BLOCK first versus last produces 100% versus 0% BLOCK among contributors. Independent half-loss leaves the expected contributor fraction unchanged and yields four expected deliveries; this is an analytical expectation, not a measured loss simulation. A three-value field with nominal epsilon 0.2 and output-dependent delivery weights (1,0.1,0.1) has conditional maximum log ratio about 0.351040596. This illustrates why arbitrary delivered-only conditioning needs an additional privacy argument; it is not a discovered implementation violation of the explicitly restricted randomizer claim.

### Boundaries and retained artifacts

This evidence supports conditional event-tuple analysis at a fixed reporting opportunity with common public configuration. It does not protect report presence, accepted counts, timing or transport metadata; establish anonymous communication, user-level accounting across installations/days, secure clock/state retention, compliant hostile clients, monitoring usefulness or training privacy; or replace human labels. Model training remains separate.

Tracked [aggregate JSON](telemetry-evidence-20261014.json) contains all 180 first-coordinate summaries, full finite rational kernels/enclosures, ledger/selection observations, source fingerprints, output hashes and independent checks. All category-specific metrics and raw trial arrays, frozen protocol bytes, synthetic databases and failed attempt are retained under primary `evaluation/results/telemetry-mechanism-audit-20261014-t2/attempt-1` and `attempt-2`. `relocation-manifest.json` maps original worktree paths to durable primary paths and verifies every file's SHA-256 without changing sealed provenance. The worktree can be archived only after root verifies this durable copy. Exact computational script bytes are additionally retained in durable `computation-sources/`; final tracked scripts differ only in removal of an extra trailing blank line. No runtime or manuscript source was changed by this evidence stream.
