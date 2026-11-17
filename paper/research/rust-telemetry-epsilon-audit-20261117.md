# Rust telemetry kernel: exact finite-epsilon audit (RUST-S18, 2026-11-17)

Status: complete; T2 record, a new audit of a new kernel. It does not modify, reuse or supersede any value of C34 (`telemetry-evidence-20261014.*`), which keeps describing the audited CPython kernel only. Aggregate: [rust-telemetry-epsilon-audit-20261117.json](rust-telemetry-epsilon-audit-20261117.json). Scope: stage 18 of the Rust server rewrite (`docs/plans/rust-server-rewrite.md`), crate `rust/crates/privoke-telemetry-client`. No prompt data, labels, model fitting or deployment measurement is involved.

## What is audited

The Rust sampler (`privacy.rs`, `random.rs`) for a domain of `K` values at per-dimension epsilon `e/5`:

1. `grr_kernel` computes the binary64 threshold `p = exp(x) / ((exp(x) + K) - 1)` and `other = 1 / ((exp(x) + K) - 1)` (the same IEEE operations in the same order as Python's `grr_probabilities`).
2. The draw is seven operating-system bytes, big endian, low three bits dropped: an integer `J` in `[0, 2^53)`. The answer is truthful iff `J * 2^-53 < p`. The product is exact, so this is the exact comparison `J/2^53 < p`, that is `J < m` with `m = ceil(p * 2^53)`.
3. Otherwise one of the other `K - 1` values is chosen by rejection sampling of `bit_length(K - 1)` bits, which is exactly uniform (verified per `K` by exact rational series).

Under independent uniform input bytes, every coordinate has truthful probability `P = m/2^53` and every other output `Q = (1 - P)/(K - 1)`. For each of the five coordinates the audit enumerates all `K^3` likelihood ratios `Pr[y | a] / Pr[y | b]` in exact rational arithmetic (the maximum is `P/Q`), multiplies the five maxima of an event epsilon (sequential composition of the five coordinates), and encloses `ln` of the product between two 100-digit `Decimal` bounds (correctly rounded `Decimal.ln`, widened by one representable step each way).

Audited event epsilons: 0.5, 0.75, 1, 1.5 and 2 (C34 audited 0.5, 1 and 2). Domain sizes: action 3, risk bucket 4, primary category 11, model version 2, time bucket 6.

## How the thresholds are bound to the Rust build

`evaluation/audit_rust_telemetry_epsilon.py` evaluates the Rust formula with the host `math.exp` (Python 3.11.9, Windows) and commits the resulting threshold bits in the JSON. `rust/crates/privoke-telemetry-client/tests/audit_thresholds.rs` then recomputes every threshold with the crate's own `grr_kernel`, asserts bit equality with the record, recomputes `m` from the binary64 threshold (`ceil(p * 2^53)`, an exact operation) and drives the real sampler `generalized_randomized_response` at `J = 0`, `m - 1`, `m`, `m + 1` and `2^53 - 1` for all 25 cells, with noise in the dropped low bits. The record therefore applies to the Rust build on every platform where that test passes.

Result: the test passed in Rust CI run `44013270917` (commit `93b24fa`, branch `wt/rust-s18`; Linux, glibc, Rust 1.99.1): **the Rust thresholds on Linux are bit-identical to those computed by the Windows host Python formula, and so to the Python kernel's** (the script's per-cell comparison with the unmodified `privacy.py` found every truthful and other probability bit-identical). Platforms with a different `exp` (macOS libm, Windows MSVC runtime in Rust) are not covered by a CI result; the same test must pass there before the record is cited for them.

## Result

Actual maximum event-level log likelihood ratio minus the nominal epsilon (signed, 100-digit enclosure, both bounds shown to 22 digits; the full bounds are in the JSON):

| Public event epsilon | Excess over nominal | `nominal_bound_holds` |
| --- | --- | --- |
| 0.5 | +1.2940163991575536384922 x 10^-15 | false |
| 0.75 | +4.8815648952432772333476 x 10^-16 | false |
| 1 | +1.5027666364999708925351 x 10^-15 | false |
| 1.5 | +4.4273291138394008530598 x 10^-16 | false |
| 2 | +1.2264513804945714632032 x 10^-15 | false |

In every case the lower enclosure is strictly positive: **the Rust kernel's finite thresholds exceed the nominal event epsilon by 10^-16 to 10^-15 at the audited settings, as the CPython kernel does.** The excess is arithmetic (the finite 53-bit grid and binary64 rounding of `p`), conditional on ideal independent uniform input bytes.

## Equality with the Python kernel and with C34

- Per cell, the Rust thresholds and other-probabilities equal the Python kernel's bit for bit (JSON: `equals_python_kernel` true in all 25 cells; the CI test asserts the Rust side).
- At 0.5, 1 and 2 the new joint ratio (exact rational), the signed excess enclosures and the threshold bits are identical to the C34 record's (JSON: `c34_comparison`). The values are recomputed here by new code; they agree because the thresholds agree. 0.75 and 1.5 are new.
- Consequence for claims: C34's text describes the audited CPython kernel; the Rust kernel has its own record (this one) with the same numbers at 0.5, 1 and 2. Until the Rust reporter is the one deployed, C34 keeps its Python scope. This record does not change `claims.md`; integration belongs to the root author.

## Boundaries

Conditional on independent uniform input bytes; says nothing about the operating-system generator, other epsilons, other platforms' `exp`, report presence, counts, timing or transport metadata, user-level accounting across days, hostile clients, or the collector estimator. The ledger accounts nominal epsilon, so at the default event epsilon 1 and eight reservations the conditional finite-kernel bound is about 8 + 1.2022 x 10^-14, as in C34. Ledger, order and failure behaviour is tested in `tests/golden.rs` against the Python oracle, not by this audit.

## Reproduce

```text
python evaluation/audit_rust_telemetry_epsilon.py --output paper/research/rust-telemetry-epsilon-audit-20261117.json
python -m unittest discover -s evaluation/tests -p test_audit_rust_telemetry_epsilon.py
cargo test -p privoke-telemetry-client --test audit_thresholds --locked --manifest-path rust/Cargo.toml   # CI only
```

Python standard library only. The script pins its own source hash and `privacy.py`'s in the JSON `provenance` block (excluded from the equality comparison, which is host dependent).
