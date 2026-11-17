"""Exact finite-epsilon audit of the Rust telemetry kernel (RUST-S18, stage 18).

New audit, written for the Rust crate ``rust/crates/privoke-telemetry-client``. It does not read, reuse or modify the
code, values or files of the C34 audit (``evaluation/analysis/audit-telemetry-mechanism.py`` and
``paper/research/telemetry-evidence-20261014.*``); the one read-only contact with them is the final comparison of the
new numbers against the recorded C34 numbers.

What is audited. The Rust sampler, for a domain of ``K`` values and a per-dimension epsilon ``e / 5``:

1. computes the binary64 threshold ``p = exp(x) / (exp(x) + K - 1)`` and ``other = 1 / (exp(x) + K - 1)``
   (``privoke_telemetry_client::privacy::grr_kernel``), with the IEEE operations in that order;
2. draws ``J``, a uniform integer in ``[0, 2**53)`` (seven bytes, low three bits dropped), and answers truthfully iff
   ``J * 2**-53 < p``; the product is exact, so this is the exact rational comparison ``J / 2**53 < p``;
3. otherwise draws one of the ``K - 1`` other values by rejection sampling of ``bit_length(K - 1)`` bits, which is exactly
   uniform.

Under independent uniform input bytes the truthful probability is therefore ``P = m / 2**53`` with
``m = ceil(p * 2**53)`` and every other output has probability ``Q = (1 - P) / (K - 1)``. The audit enumerates every
coordinate likelihood ratio ``Pr[y | a] / Pr[y | b]`` exactly (rational arithmetic), multiplies the five coordinate
maxima of an event epsilon, and encloses the natural logarithm of the product between two 100-digit ``Decimal`` bounds
(correctly rounded ``Decimal.ln``, widened by one representable step each way).

Where the Rust thresholds come from. The thresholds in the record are this script's evaluation of the Rust formula
(step 1) with the host ``math.exp``. They are *committed values*: the Rust test
``rust/crates/privoke-telemetry-client/tests/audit_thresholds.rs`` recomputes the thresholds with the crate's own code
and asserts bit equality with the committed record, and drives the real sampler at ``J = m - 1`` and ``J = m`` for every
cell. The record is therefore an audit of the Rust kernel's actual thresholds exactly on the platforms where that test
passes (the CI run is named in the T2 record), and the equality statement with the Python kernel is made per platform.

Run (standard library only)::

    python evaluation/audit_rust_telemetry_epsilon.py \
        --output paper/research/rust-telemetry-epsilon-audit-20261117.json
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import math
import platform
import struct
import sys
from decimal import Decimal, localcontext
from fractions import Fraction
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
PRIVACY_PY = REPO / "extension" / "client-runtime" / "src" / "telemetry" / "privacy.py"
C34_RECORD = REPO / "paper" / "research" / "telemetry-evidence-20261014.json"

# Public event epsilons audited: the three of C34 and two interior values (all with at most six decimals).
EVENT_EPSILONS = (0.5, 0.75, 1.0, 1.5, 2.0)
# The five domains of the Rust crate, in its randomisation order, with the sizes of `privacy::domain`.
DIMENSIONS = (
    ("action", 3),
    ("risk_bucket", 4),
    ("primary_category", 11),
    ("model_version", 2),
    ("time_bucket", 6),
)
GRID = 1 << 53


def bits(value: float) -> str:
    return struct.pack(">d", value).hex()


def fraction_json(value: Fraction) -> dict:
    return {"numerator": str(value.numerator), "denominator": str(value.denominator)}


def rust_kernel(event_epsilon: float, size: int) -> tuple[float, float, float]:
    """The Rust ``grr_kernel`` arithmetic: per-dimension epsilon, truthful threshold, other probability."""
    epsilon = event_epsilon / len(DIMENSIONS)
    exp_epsilon = math.exp(epsilon)
    denominator = exp_epsilon + size - 1  # (exp + K) - 1, left to right, K converted to binary64
    return epsilon, exp_epsilon / denominator, 1.0 / denominator


def grid_points_below(threshold: float) -> int:
    """``m``: the count of integers ``J`` in ``[0, 2**53)`` with ``J / 2**53 < threshold``."""
    value = Fraction.from_float(threshold) * GRID
    m = -(-value.numerator // value.denominator)
    if not 0 < m < GRID:
        raise ValueError("threshold has degenerate finite support")
    return m


def log_enclosure(value: Fraction, precision: int = 100) -> tuple[str, str]:
    """Lower and upper 100-digit bounds of ``ln(value)`` (division rounded, then ``ln`` rounded, each widened)."""
    with localcontext() as context:
        context.prec = precision
        ratio = Decimal(value.numerator) / Decimal(value.denominator)
        return str(ratio.next_minus().ln().next_minus()), str(ratio.next_plus().ln().next_plus())


def rejection_probability(n: int) -> list[Fraction]:
    """Exact output law of ``_randbelow(n)``: draw ``bit_length(n)`` bits until the value is below ``n``."""
    k = n.bit_length()
    accept_round = Fraction(n, 1 << k)
    # P(output = j) = sum over rounds (1 - accept)^t * 2**-k = 2**-k / accept.
    return [Fraction(1, 1 << k) / accept_round for _ in range(n)]


def coordinate(event_epsilon: float, dimension: str, size: int, python_kernel) -> dict:
    epsilon, truthful, other = rust_kernel(event_epsilon, size)
    m = grid_points_below(truthful)
    p_exact = Fraction(m, GRID)
    q_exact = (1 - p_exact) / (size - 1)
    # The sampler's decision, in binary64, equals the exact comparison at the cells next to the threshold.
    for j in range(max(0, m - 3), min(GRID, m + 4)):
        assert (float(j) * 2.0**-53 < truthful) == (Fraction(j, GRID) < Fraction.from_float(truthful)) == (j < m)
    assert rejection_probability(size - 1) == [Fraction(1, size - 1)] * (size - 1)
    matrix = [[p_exact if left == right else q_exact for right in range(size)] for left in range(size)]
    assert all(sum(row) == 1 and all(entry > 0 for entry in row) for row in matrix)
    maximum = max(matrix[a][y] / matrix[b][y] for a in range(size) for b in range(size) for y in range(size))
    assert maximum == p_exact / q_exact
    nominal_ratio = math.exp(epsilon)
    py_truthful, py_other = python_kernel(event_epsilon, size)
    return {
        "event_epsilon": event_epsilon,
        "dimension": dimension,
        "domain_size": size,
        "per_dimension_epsilon_bits": bits(epsilon),
        "truthful_bits": bits(truthful),
        "other_bits": bits(other),
        "truthful_hex": truthful.hex(),
        "truthful_repr": repr(truthful),
        "grid_points_below_threshold": str(m),
        "P": fraction_json(p_exact),
        "Q": fraction_json(q_exact),
        "maximum_likelihood_ratio": fraction_json(maximum),
        "log_ratio_enclosure": list(log_enclosure(maximum)),
        "nominal_ratio_binary64": repr(nominal_ratio),
        "python_kernel_truthful_bits": bits(py_truthful),
        "python_kernel_other_bits": bits(py_other),
        "equals_python_kernel": bits(truthful) == bits(py_truthful) and bits(other) == bits(py_other),
        "_maximum": maximum,
    }


def load_python_kernel():
    """The unmodified Python kernel (``privacy.py`` needs only the standard library), as a function of (e, K)."""
    spec = importlib.util.spec_from_file_location("python_privacy", PRIVACY_PY)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert tuple(module.DIMENSIONS) == tuple(name for name, _ in DIMENSIONS)
    assert tuple(len(module.DOMAINS[name]) for name in module.DIMENSIONS) == tuple(size for _, size in DIMENSIONS)

    def kernel(event_epsilon: float, size: int) -> tuple[float, float]:
        domain = [f"v{index}" for index in range(size)]
        probabilities = module.grr_probabilities(domain[0], domain, event_epsilon / len(module.DIMENSIONS))
        return probabilities[domain[0]], probabilities[domain[1]]

    return kernel


def event_rows(python_kernel) -> list[dict]:
    rows = []
    for event_epsilon in EVENT_EPSILONS:
        coordinates = [coordinate(event_epsilon, name, size, python_kernel) for name, size in DIMENSIONS]
        joint = Fraction(1)
        for item in coordinates:
            joint *= item.pop("_maximum")
        lower, upper = log_enclosure(joint)
        with localcontext() as context:
            context.prec = 100
            excess = [str(Decimal(lower) - Decimal(repr(event_epsilon))), str(Decimal(upper) - Decimal(repr(event_epsilon)))]
        rows.append({
            "event_epsilon": event_epsilon,
            "event_epsilon_bits": bits(event_epsilon),
            "coordinates": coordinates,
            "joint_ratio": fraction_json(joint),
            "actual_epsilon_enclosure": [lower, upper],
            "signed_excess_over_nominal_enclosure": excess,
            "nominal_bound_holds": Decimal(upper) <= Decimal(repr(event_epsilon)),
            "excess_strictly_positive": Decimal(excess[0]) > 0,
            "equals_python_kernel_in_every_coordinate": all(item["equals_python_kernel"] for item in coordinates),
        })
    return rows


def c34_comparison(rows: list[dict]) -> dict:
    """Compare, read-only, the new excess enclosures with the C34 record's (the new values do not come from it)."""
    if not C34_RECORD.exists():
        return {"available": False}
    recorded = json.loads(C34_RECORD.read_text(encoding="utf-8"))["finite_audit"]
    by_epsilon = {entry["event_epsilon"]: entry for entry in recorded}
    comparison = []
    for row in rows:
        old = by_epsilon.get(row["event_epsilon"])
        if old is None:
            comparison.append({"event_epsilon": row["event_epsilon"], "in_c34": False})
            continue
        comparison.append({
            "event_epsilon": row["event_epsilon"],
            "in_c34": True,
            "signed_excess_identical": row["signed_excess_over_nominal_enclosure"] == old["signed_excess_enclosure"],
            "joint_ratio_identical": row["joint_ratio"] == old["joint_ratio"],
            "thresholds_identical": [item["truthful_bits"] for item in row["coordinates"]]
            == [struct.pack(">d", float.fromhex(field["threshold_hex"])).hex() for field in old["fields"]],
        })
    return {"available": True, "source": "paper/research/telemetry-evidence-20261014.json", "per_epsilon": comparison}


def sha256_lf(path: Path) -> str:
    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def build() -> dict:
    python_kernel = load_python_kernel()
    rows = event_rows(python_kernel)
    return {
        "scope": "exact finite-epsilon audit of the Rust telemetry kernel's binary64 thresholds, conditional on ideal "
        "independent uniform input bytes; not an audit of the operating-system generator, of other epsilons, or of a "
        "deployed binary",
        "status": "computed",
        "kernel": {
            "thresholds": "p = exp(e/5) / ((exp(e/5) + K) - 1), other = 1 / ((exp(e/5) + K) - 1), binary64, host math.exp",
            "decision": "truthful iff (J >> 0) * 2**-53 < p with J uniform in [0, 2**53); equals J < m, m = ceil(p * 2**53)",
            "alternatives": "uniform by rejection sampling of bit_length(K - 1) bits (exact, verified per K)",
            "sampler_checked_at_grid_points": "m-3 .. m+3 for every cell (binary64 comparison equals the exact one)",
        },
        "event_epsilons": rows,
        "c34_comparison": c34_comparison(rows),
        "provenance": {
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "libm": "host C runtime math.exp (not fingerprinted beyond the platform string)",
            "script_sha256_lf": sha256_lf(Path(__file__)),
            "privacy_py_sha256_lf": sha256_lf(PRIVACY_PY),
        },
    }


def comparable(document: dict) -> dict:
    """The record without the run provenance, for equality checks across hosts."""
    return {key: value for key, value in document.items() if key != "provenance"}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args(argv)
    document = build()
    text = json.dumps(document, indent=1, sort_keys=True, ensure_ascii=True) + "\n"
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_bytes(text.encode("utf-8"))
    for row in document["event_epsilons"]:
        print(f"epsilon {row['event_epsilon']}: excess in [{row['signed_excess_over_nominal_enclosure'][0][:24]}, "
              f"{row['signed_excess_over_nominal_enclosure'][1][:24]}] equals_python={row['equals_python_kernel_in_every_coordinate']}")
    print(f"wrote {arguments.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
