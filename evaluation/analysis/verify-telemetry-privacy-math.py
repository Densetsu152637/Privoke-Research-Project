"""Check nominal GRR equations; no runtime, ledger, RPC or utility measurements."""
from __future__ import annotations

import ast
from decimal import Decimal, localcontext
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PRIVACY = ROOT / "extension/client-runtime/src/telemetry/privacy.py"


def main():
    source = PRIVACY.read_bytes().replace(b"\r\n", b"\n")
    tree = ast.parse(source)
    domains = next(ast.literal_eval(node.value) for node in tree.body
                   if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name)
                   and node.target.id == "DOMAINS")
    sizes = {name: len(values) for name, values in domains.items()}
    assert sizes == {"action": 3, "risk_bucket": 4, "primary_category": 11,
                     "model_version": 2, "time_bucket": 6}
    results = []
    with localcontext() as context:
        context.prec = 70
        tolerance = Decimal("1e-65")
        for epsilon in map(Decimal, ("0.5", "1", "2")):
            field_epsilon = epsilon / 5
            exp_field = field_epsilon.exp()
            joint_max_ratio = Decimal(1)
            fields = {}
            for name, size in sizes.items():
                q = 1 / (exp_field + size - 1)
                p = exp_field * q
                assert abs(p + (size - 1) * q - 1) < tolerance
                # Enumerate ordered input/output triples without invoking the
                # implementation's sampler or probability helper.
                maximum = max((p if output == left else q) / (p if output == right else q)
                              for left in range(size) for right in range(size) for output in range(size))
                assert abs(maximum.ln() - field_epsilon) < tolerance
                joint_max_ratio *= maximum
                fields[name] = {"K": size, "p": str(p), "q": str(q), "p_minus_q": str(p - q)}
            assert abs(joint_max_ratio.ln() - epsilon) < tolerance
            results.append({"event_epsilon": str(epsilon), "field_epsilon": str(field_epsilon),
                            "maximum_joint_log_ratio": str(joint_max_ratio.ln()), "fields": fields})
    print(json.dumps({"status": "PASS", "scope": "nominal GRR algebra; not deployed sampler certification or utility",
                      "decimal_precision": 70, "privacy_source_canonical_lf_sha256": hashlib.sha256(source).hexdigest(),
                      "script_sha256": hashlib.sha256(Path(__file__).read_bytes().replace(b"\r\n", b"\n")).hexdigest(),
                      "results": results}, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
