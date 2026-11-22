"""Golden generator for the fuzzer's policy admission (`rust/services/fuzzer/src/policy.rs`, RUST-S21D).

The oracle is `privoke_model.contextual_training.training_policy_expectations` and `training_admission_metadata` (with the
`full_adam`, `window_training` and `sensitive_retention` expectations they call), run on the host over a fixed list of request
metadata: every valid policy (FULL Adam, window, ORIGINAL retention gate and hinge, objective-only, backtracking) and each way a
request can be invalid. No model, runtime or prompt data is involved.

Usage (host Python, for example `evaluation/.venv-v1-v3-pipeline`):
  python evaluation/generate_fuzzer_policy_golden.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "rust/services/fuzzer/tests/fixtures/policy_expectations_golden.json"
SHA = "a" * 64


def cases():
    from privoke_model import full_adam as adam, sensitive_retention as retention, window_training as window  # noqa: PLC0415
    from privoke_model import contextual_training as ct  # noqa: PLC0415

    adam_config = adam.canonical(adam.CONFIG)
    full = {"expected_contextual_training_objective": adam.OBJECTIVE, "expected_contextual_training_optimizer": adam.POLICY,
            "expected_contextual_candidate_eligibility": adam.ELIGIBILITY, "expected_full_projected_adam_config_v1": adam_config,
            "expected_contextual_training_scope": "full_encoder"}
    win = {"expected_contextual_training_optimizer": window.POLICY, "expected_contextual_training_objective": window.OBJECTIVE,
           "expected_contextual_candidate_eligibility": window.ELIGIBILITY, "expected_contextual_training_scope": "full_encoder",
           "expected_" + window.CONFIG_KEY: adam.canonical(window.CONFIG), "expected_" + window.WINDOW_KEY: SHA,
           "expected_" + window.REFERENCE_KEY: "b" * 64}

    def ret(policy):
        return {"expected_contextual_training_optimizer": policy, "expected_contextual_training_objective": retention.OBJECTIVES[policy],
                "expected_contextual_candidate_eligibility": retention.ELIGIBILITY, "expected_full_projected_adam_config_v1": adam_config,
                "expected_contextual_training_scope": "full_encoder", "expected_" + retention.MANIFEST_KEY: SHA}

    back = {"expected_contextual_training_objective": ct.CLASS_BALANCED_OBJECTIVE,
            "expected_contextual_training_diagnostics_policy": ct.TRAIN_DIAGNOSTICS_POLICY,
            "expected_contextual_training_backtracking_policy": ct.BACKTRACKING_POLICY,
            "expected_contextual_training_backtracking_preparation_sha256": SHA}
    yield "no policy", {"initiator": "param-update-service"}
    yield "FULL Adam, full encoder", full
    yield "FULL Adam, heads", {**full, "expected_contextual_training_scope": "heads"}
    yield "window", win
    yield "retention gate", ret(retention.GATE_POLICY)
    yield "retention hinge", ret(retention.HINGE_POLICY)
    yield "objective only, sum margin", {"expected_contextual_training_objective": ct.CLASS_BALANCED_SUM_CATEGORY_DECISION_MARGIN_OBJECTIVE}
    yield "objective only with diagnostics", {"expected_contextual_training_objective": ct.CLASS_BALANCED_SUM_CATEGORY_DECISION_MARGIN_OBJECTIVE,
                                              "expected_contextual_training_diagnostics_policy": ct.TRAIN_DIAGNOSTICS_POLICY}
    yield "objective only, legacy", {"expected_contextual_training_objective": ct.LEGACY_OBJECTIVE}
    yield "diagnostics only", {"expected_contextual_training_diagnostics_policy": ct.TRAIN_DIAGNOSTICS_POLICY}
    yield "backtracking", back
    yield "backtracking, sum margin", {**back, "expected_contextual_training_objective": ct.CLASS_BALANCED_SUM_CATEGORY_DECISION_MARGIN_OBJECTIVE}
    yield "backtracking without preparation", {k: v for k, v in back.items() if "preparation" not in k}
    yield "backtracking with a short preparation", {**back, "expected_contextual_training_backtracking_preparation_sha256": "abc"}
    yield "backtracking without diagnostics", {k: v for k, v in back.items() if "diagnostics" not in k}
    yield "backtracking with FULL Adam", {**full, **back}
    yield "unknown objective", {"expected_contextual_training_objective": "nonsense"}
    yield "unknown diagnostics", {"expected_contextual_training_diagnostics_policy": "nonsense"}
    yield "FULL Adam, wrong objective", {**full, "expected_contextual_training_objective": ct.CLASS_BALANCED_OBJECTIVE}
    yield "FULL Adam, wrong scope", {**full, "expected_contextual_training_scope": "everything"}
    yield "FULL Adam, wrong config", {**full, "expected_full_projected_adam_config_v1": "{}"}
    yield "FULL Adam, missing eligibility", {k: v for k, v in full.items() if "eligibility" not in k}
    yield "FULL Adam with diagnostics", {**full, "expected_contextual_training_diagnostics_policy": ct.TRAIN_DIAGNOSTICS_POLICY}
    yield "optimizer alone", {"expected_contextual_training_optimizer": adam.POLICY}
    yield "scope alone", {"expected_contextual_training_scope": "heads"}
    yield "window, missing pin", {k: v for k, v in win.items() if window.WINDOW_KEY not in k}
    yield "window, wrong scope", {**win, "expected_contextual_training_scope": "heads"}
    yield "orphan window pin", {"expected_" + window.WINDOW_KEY: SHA}
    yield "retention, wrong objective", {**ret(retention.GATE_POLICY), "expected_contextual_training_objective": retention.OBJECTIVES[retention.HINGE_POLICY]}
    yield "retention, bad pin", {**ret(retention.GATE_POLICY), "expected_" + retention.MANIFEST_KEY: "xyz"}
    yield "orphan retention pin", {"expected_" + retention.MANIFEST_KEY: SHA}


def build() -> dict:
    sys.path.insert(0, str(ROOT / "shared" / "python"))
    from privoke_model.contextual_training import training_admission_metadata, training_policy_expectations  # noqa: PLC0415

    records = []
    for label, metadata in cases():
        record = {"label": label, "metadata": metadata}
        try:
            expectations = training_policy_expectations(metadata)
            record["expectations"] = expectations
            header = training_admission_metadata(expectations)
            record["header"] = header[0][1] if header else None
        except ValueError as exc:
            record["error"] = str(exc)
        records.append(record)
    return {"schema": 1, "oracle": "privoke_model.contextual_training.training_policy_expectations / training_admission_metadata",
            "python": sys.version.split()[0], "cases": records}


def main() -> int:
    document = build()
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(document, indent=1, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    errors = sum("error" in case for case in document["cases"])
    print(json.dumps({"cases": len(document["cases"]), "errors": errors, "headers": sum(bool(case.get("header")) for case in document["cases"]),
                      "output": str(OUTPUT)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
