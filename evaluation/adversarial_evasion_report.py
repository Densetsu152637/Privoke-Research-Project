"""Render and verify the ADVEVADE-20261116 record tables from the stored aggregate JSON.

    python evaluation/adversarial_evasion_report.py render --json J            (prints the generated block)
    python evaluation/adversarial_evasion_report.py check  --json J --md M     (exit 1 on any mismatch)

``check`` (1) recomputes every Wilson interval, rate and conditional/unconditional ASR from the
stored counts, (2) checks that the stored count identities hold (evaded + survived = protected, and
so on) and (3) checks that the generated block of the markdown record equals ``render``.
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import adversarial_evasion as ae  # noqa: E402
import adversarial_evasion_transforms as tx  # noqa: E402

BEGIN, END = "<!-- BEGIN GENERATED -->", "<!-- END GENERATED -->"
ARMS = ae.ARMS
ARM_LABEL = {"defaults": "defaults", "flags": "+flags"}


def pct(value) -> str:
    return "n/a" if value is None else f"{100 * value:.2f}"


def cell(r: dict) -> str:
    """ASR cell: k/n, percentage and Wilson interval."""
    if not r["n"]:
        return "0/0"
    return f"{r['k']}/{r['n']} = {pct(r['rate'])} [{pct(r['wilson_low'])}, {pct(r['wilson_high'])}]"


def table(header: list[str], rows: list[list[str]]) -> str:
    lines = ["| " + " | ".join(header) + " |", "|" + "|".join("---" for _ in header) + "|"]
    lines += ["| " + " | ".join(row) + " |" for row in rows]
    return "\n".join(lines)


def families_of(res: dict) -> list[str]:
    present = res["arms"]["defaults"]["action_level"]["by_family"]
    return [f for f in tx.FAMILIES if f in present]


def render(payload: dict) -> str:
    res = payload["results"]
    out = []
    out.append("#### Baseline detection on the untransformed prompts (intended action)\n")
    rows = []
    for arm in ARMS:
        b = res["baseline"][arm]
        rows.append([ARM_LABEL[arm], str(res["rows"]), cell(b["protected"]), str(b["actions"]["WARN"]), str(b["actions"]["BLOCK"]),
                     str(b["actions"]["ALLOW"]), str(b["errored_rows"])])
    out.append(table(["Arm", "Prompts", "Protected (WARN or BLOCK)", "WARN", "BLOCK", "ALLOW", "Rows with a layer error"], rows))
    out.append("\nBaseline protection by source dataset (shipped defaults):\n")
    out.append(table(["Source", "Protected"], [[s, cell(r)] for s, r in res["baseline"]["defaults"]["by_source"].items()]))
    out.append("\nShare of baseline prompts with a non-ALLOW finding by layer (shipped defaults; a layer skipped after a regex BLOCK counts as no finding):\n")
    out.append(table(["Layer", "Non-ALLOW finding"], [[l, cell(r)] for l, r in res["baseline"]["defaults"]["layer_nonallow_rate_when_run"].items()]))
    intended = res["intended_actions"]
    out.append(f"\nIntended actions (shipped defaults, untransformed): WARN {intended['WARN']}, BLOCK {intended['BLOCK']}, ALLOW {intended['ALLOW']} "
               f"({res['protected_rows']} protected prompts form the conditional denominators).\n")

    for level, title in (("action_level", "Action level (primary): protection is any non-ALLOW action, including the runtime's fail-closed BLOCK on a layer error"),
                         ("detection_level", "Detection level (secondary): a BLOCK that exists only because a layer errored counts as a missed detection")):
        out.append(f"#### ASR by transform family. {title}\n")
        rows = []
        for family in families_of(res):
            r = [family]
            for arm in ARMS:
                g = res["arms"][arm][level]["by_family"][family]
                r += [str(g["applicable"]), str(g["protected_pairs"]), cell(g["asr_conditional"]), cell(g["asr_unconditional"])]
            rows.append(r)
        for key, label in (("overall", "ALL variants"), ("overall_excluding_value_removing", "ALL excl. value-removing (indirect_pointer)")):
            r = [label]
            for arm in ARMS:
                g = res["arms"][arm][level][key]
                r += [str(g["applicable"]), str(g["protected_pairs"]), cell(g["asr_conditional"]), cell(g["asr_unconditional"])]
            rows.append(r)
        header = ["Family"]
        for arm in ARMS:
            header += [f"Applicable ({ARM_LABEL[arm]})", f"Protected ({ARM_LABEL[arm]})", f"Conditional ASR ({ARM_LABEL[arm]})", f"Unconditional ASR ({ARM_LABEL[arm]})"]
        out.append(table(header, rows))
        out.append("")

    out.append("#### ASR by variant, action level\n")
    rows = []
    for variant in res["arms"]["defaults"]["action_level"]["by_variant"]:
        r = [variant]
        for arm in ARMS:
            g = res["arms"][arm]["action_level"]["by_variant"][variant]
            r += [str(g["protected_pairs"]), cell(g["asr_conditional"])]
        d = res["arms"]["defaults"]["detection_level"]["by_variant"][variant]
        r.append(cell(d["asr_conditional"]))
        rows.append(r)
    out.append(table(["Variant", "Protected (defaults)", "Cond. ASR (defaults)", "Protected (+flags)", "Cond. ASR (+flags)", "Cond. ASR (defaults, detection level)"], rows))

    out.append("\n#### Action downgrades BLOCK to WARN, action level\n")
    rows = []
    for family in families_of(res) + ["ALL"]:
        r = [family]
        for arm in ARMS:
            g = res["arms"][arm]["action_level"]["overall" if family == "ALL" else "by_family"]
            g = g if family == "ALL" else g[family]
            r += [str(g["block_pairs"]), cell(g["downgrade_rate"]), cell(g["weakened_conditional"])]
        rows.append(r)
    header = ["Family"]
    for arm in ARMS:
        header += [f"BLOCK pairs ({ARM_LABEL[arm]})", f"BLOCK to WARN ({ARM_LABEL[arm]})", f"Evaded or downgraded, of protected ({ARM_LABEL[arm]})"]
    out.append(table(header, rows))

    out.append("\n#### Cluster-bootstrap check of the overall conditional ASR (resampling source documents, 2,000 replicates, seed 20261116)\n")
    rows = []
    for arm in ARMS:
        for level in ("action_level", "detection_level"):
            for key in ("overall", "overall_excluding_value_removing"):
                g = res["arms"][arm][level][key]
                low, high = g["asr_conditional_cluster_bootstrap_95"]
                rows.append([ARM_LABEL[arm], level, key, pct(g["asr_conditional"]["rate"]), f"[{pct(low)}, {pct(high)}]"])
    out.append(table(["Arm", "Level", "Scope", "Conditional ASR %", "Cluster-bootstrap 95 % interval"], rows))

    out.append("\n#### Prompts evaded by at least one variant (best of all variants per protected prompt, action level)\n")
    out.append(table(["Arm", "Prompts evaded by at least one variant"], [[ARM_LABEL[a], cell(res["arms"][a]["action_level"]["best_of_all_variants_per_row"])] for a in ARMS]))

    out.append("\n#### Paired comparison of the arms (action level; same protected pairs)\n")
    rows = []
    for scope, p in res["paired_arms"].items():
        rows.append([scope, str(p["evaded_defaults_only"]), str(p["evaded_flags_only"]), str(p["evaded_both"]), str(p["evaded_neither"]),
                     f"{p['exact_mcnemar_p']:.3g}"])
    out.append(table(["Scope", "Evades only under defaults", "Evades only under +flags", "Evades under both", "Evades under neither", "Exact McNemar p"], rows))

    out.append("\n#### Fail-closed behaviour and executed layers\n")
    rows = []
    for arm in ARMS:
        fc = res["fail_closed"][arm]
        counts = res["layer_status_counts"][arm]
        rows.append([ARM_LABEL[arm], str(fc["scored_pairs"]), str(fc["scored_pairs_error"]), str(fc["scored_pairs_failed_closed"]),
                     str(counts["regex"]), str(counts["ner"]), str(counts["semantic"])])
    out.append(table(["Arm", "Scored transformed pairs", "Pairs with a layer error", "BLOCK only from a layer error", "Regex status counts (all scored items)", "NER status counts", "Semantic status counts"], rows))

    ctrl = payload.get("control")
    if ctrl:
        out.append("\n#### Specificity control: shipped-defaults non-ALLOW rate on clean prompts (F1 clean rows)\n")
        rows = []
        for variant in ctrl["results"]["defaults"]:
            r = [variant]
            for arm in ARMS:
                g = ctrl["results"][arm][variant]
                r += [cell(g["non_allow"]), cell(g["block"])]
            rows.append(r)
        out.append(table(["Variant", "Non-ALLOW (defaults)", "BLOCK (defaults)", "Non-ALLOW (+flags)", "BLOCK (+flags)"], rows))
    return "\n".join(out) + "\n"


def walk_rates(node, path=""):
    """Yield every stored rate dictionary (keys k, n, rate, wilson_low, wilson_high)."""
    if isinstance(node, dict):
        if {"k", "n", "rate", "wilson_low", "wilson_high"} <= set(node):
            yield path, node
        for key, value in node.items():
            yield from walk_rates(value, f"{path}/{key}")
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from walk_rates(value, f"{path}[{index}]")


def verify_numbers(payload: dict) -> list[str]:
    problems = []
    close = lambda a, b: (a is None and b is None) or (a is not None and b is not None and math.isclose(a, b, rel_tol=1e-9, abs_tol=1e-12))
    for path, r in walk_rates(payload):
        expected = ae.rate(r["k"], r["n"])
        for key in ("rate", "wilson_low", "wilson_high"):
            if not close(r[key], expected[key]):
                problems.append(f"{path}: {key} {r[key]} != {expected[key]}")
    res = payload["results"]
    for arm in ARMS:
        for level in ("action_level", "detection_level"):
            for scope in ("overall", "overall_excluding_value_removing"):
                g = res["arms"][arm][level][scope]
                if g["asr_conditional"]["k"] != g["evaded"] or g["asr_conditional"]["n"] != g["protected_pairs"]:
                    problems.append(f"{arm}/{level}/{scope}: conditional ASR counts disagree with evaded/protected")
                if g["asr_unconditional"]["n"] != g["applicable"] or g["asr_unconditional"]["k"] != g["evaded"]:
                    problems.append(f"{arm}/{level}/{scope}: unconditional ASR counts disagree")
            by_family = res["arms"][arm][level]["by_family"]
            if sum(f["evaded"] for f in by_family.values()) != res["arms"][arm][level]["overall"]["evaded"]:
                problems.append(f"{arm}/{level}: family evasions do not sum to the overall count")
            if sum(f["protected_pairs"] for f in by_family.values()) != res["arms"][arm][level]["overall"]["protected_pairs"]:
                problems.append(f"{arm}/{level}: family protected pairs do not sum to the overall count")
        by_variant = res["arms"][arm]["action_level"]["by_variant"]
        if sum(v["evaded"] for v in by_variant.values()) != res["arms"][arm]["action_level"]["overall"]["evaded"]:
            problems.append(f"{arm}: variant evasions do not sum to the overall count")
    for scope, p in res["paired_arms"].items():
        if not math.isclose(p["exact_mcnemar_p"], ae.exact_mcnemar(p["evaded_defaults_only"], p["evaded_flags_only"]), rel_tol=1e-9, abs_tol=1e-15):
            problems.append(f"paired {scope}: McNemar p does not recompute")
    return problems


def generated_block(md: str) -> str:
    start, end = md.index(BEGIN), md.index(END)
    return md[start + len(BEGIN):end].strip("\n") + "\n"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    r = sub.add_parser("render")
    r.add_argument("--json", required=True)
    c = sub.add_parser("check")
    c.add_argument("--json", required=True)
    c.add_argument("--md", required=True)
    a = sub.add_parser("assemble")
    a.add_argument("--main", required=True)
    a.add_argument("--control", required=True)
    a.add_argument("--extra", required=True, help="JSON with provenance fields merged under 'provenance'")
    a.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    if args.command == "assemble":
        payload = json.loads(Path(args.main).read_text(encoding="utf-8"))
        payload["control"] = json.loads(Path(args.control).read_text(encoding="utf-8"))
        payload["provenance"] = json.loads(Path(args.extra).read_text(encoding="utf-8"))
        Path(args.out).write_text(json.dumps(payload, indent=1, sort_keys=True) + "\n", encoding="utf-8")
        return 0
    payload = json.loads(Path(args.json).read_text(encoding="utf-8"))
    if args.command == "render":
        print(BEGIN)
        print(render(payload).rstrip("\n"))
        print(END)
        return 0
    problems = verify_numbers(payload)
    block = generated_block(Path(args.md).read_text(encoding="utf-8"))
    if block.replace("\r\n", "\n") != render(payload):
        problems.append("generated block of the markdown record differs from render(json)")
    for problem in problems:
        print("MISMATCH:", problem)
    print("OK: record re-derives from the JSON" if not problems else f"{len(problems)} problem(s)")
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
