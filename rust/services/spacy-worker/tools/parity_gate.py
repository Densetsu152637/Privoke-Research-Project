"""Runs the NER parity gate (and, with --smoke, the 200-document quick smoke test).

    python parity_gate.py --bundle rust/target/bundle/windows --work rust/target/parity [--smoke]

1. parity_sets.py extracts the recorded NER sets (read-only, by hash) into <work>/sets or <work>/smoke-sets.
2. reference_dump.py runs plain spaCy in the read-only reference environment, in parallel shards.
3. The parity-dump example sends the same documents through the bundle's worker pool (the real worker, the real pipe).
4. Every result is compared by SHA-256: the gate is 100 percent identical output, per set and per selection.

Output goes to <work>, which must be an ignored directory; nothing is written to the reference environment or to the
main checkout. The exit code is non-zero if any document differs or any document failed.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
RUST = HERE.parent.parent.parent
DEFAULT_REFERENCE = Path("D:/Git Repositories/Privoke-Research-Project/evaluation/.venv-v1-v3-pipeline/Scripts/python.exe")


def read_lines(path: Path) -> list[str]:
    return path.read_text(encoding="utf-8").splitlines() if path.exists() else []


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--smoke", action="store_true")
    parser.add_argument("--reference-python", type=Path, default=DEFAULT_REFERENCE)
    parser.add_argument("--source-root", type=Path, default=Path("D:/Git Repositories/Privoke-Research-Project"))
    parser.add_argument("--shards", type=int, default=4, help="parallel reference processes")
    parser.add_argument("--workers", type=int, default=4, help="worker processes in the bundle pool")
    parser.add_argument("--skip-reference", action="store_true", help="reuse <work>/reference from an earlier run")
    args = parser.parse_args()

    work = args.work.resolve() / ("smoke" if args.smoke else "full")
    sets, reference, bundle = work / "sets", work / "reference", work / "bundle"
    work.mkdir(parents=True, exist_ok=True)
    started = time.time()

    prepare = [sys.executable, str(HERE / "parity_sets.py"), "--source-root", str(args.source_root), "--out", str(sets)]
    subprocess.run(prepare + (["--smoke"] if args.smoke else []), check=True)
    manifest = json.loads((sets / "sets.json").read_text(encoding="utf-8"))

    if not args.skip_reference:
        procs = [
            subprocess.Popen([str(args.reference_python), "-I", "-B", str(HERE / "reference_dump.py"), "--impl", str(RUST / "services/spacy-worker/python/privoke_spacy_impl.py"),
                              "--sets", str(sets), "--out", str(reference), "--shard", str(k), "--shards", str(args.shards)])  # fmt: skip
            for k in range(args.shards)
        ]
        # The reference runs while the bundle runs: they are independent processes.
        bundle_run = subprocess.Popen(
            ["cargo", "run", "--release", "--locked", "--manifest-path", str(RUST / "Cargo.toml"), "-p", "privoke-spacy-worker", "--example", "parity-dump", "--",
             "--worker", str(args.bundle / "privoke-spacy-worker.exe"), "--sets", str(sets), "--out", str(bundle), "--workers", str(args.workers)]
        )  # fmt: skip
        codes = [p.wait() for p in procs] + [bundle_run.wait()]
        if any(codes):
            print(f"a run failed: exit codes {codes}", file=sys.stderr)
            return 2
    else:
        subprocess.run(["cargo", "run", "--release", "--locked", "--manifest-path", str(RUST / "Cargo.toml"), "-p", "privoke-spacy-worker", "--example", "parity-dump", "--",
                        "--worker", str(args.bundle / "privoke-spacy-worker.exe"), "--sets", str(sets), "--out", str(bundle), "--workers", str(args.workers)], check=True)  # fmt: skip

    report = {"mode": "smoke" if args.smoke else "full", "platform": sys.platform, "reference_identity": json.loads((reference / "identity.json").read_text()),
              "bundle_identity": json.loads((bundle / "identity.json").read_text()), "sets": {}}  # fmt: skip
    lemma_ref = read_lines(reference / "lemma_index.sha256")
    lemma_bundle = read_lines(bundle / "lemma_index.sha256")
    report["lemma_index_identical"] = lemma_ref == lemma_bundle and bool(lemma_ref)
    failed = not report["lemma_index_identical"]
    print(f"{'set':<14}{'selection':<10}{'documents':>10}{'identical':>11}{'different':>10}{'errors':>8}")
    totals = {"documents": 0, "identical": 0}
    for name in manifest["order"]:
        for selection in ("full", "tagger"):
            got = read_lines(bundle / f"{name}.{selection}.all.hashes")
            shards = [read_lines(reference / f"{name}.{selection}.{k}of{args.shards}.hashes") for k in range(args.shards)]
            want = [shards[i % args.shards][i // args.shards] if i // args.shards < len(shards[i % args.shards]) else None for i in range(len(got))]
            expected_documents = manifest["sets"][name]["documents"]
            errors = sum(line.startswith("ERROR") for line in got)
            different = [i for i, (g, w) in enumerate(zip(got, want, strict=True)) if g != w]
            identical = len(got) - len(different)
            row = {"documents": expected_documents, "compared": len(got), "identical": identical, "different": len(different), "errors": errors,
                   "first_different": different[:5], "first_error": next((g for g in got if g.startswith("ERROR")), None)}  # fmt: skip
            report["sets"][f"{name}/{selection}"] = row
            totals["documents"] += len(got)
            totals["identical"] += identical
            failed |= bool(different) or len(got) != expected_documents or errors > 0
            print(f"{name:<14}{selection:<10}{expected_documents:>10}{identical:>11}{len(different):>10}{errors:>8}")
    report["totals"] = totals
    report["passed"] = not failed
    report["seconds"] = round(time.time() - started)
    (work / "parity-report.json").write_text(json.dumps(report, indent=1), encoding="utf-8")
    print(f"total {totals['identical']} of {totals['documents']} identical; lemma index identical: {report['lemma_index_identical']}; "
          f"{'PASSED' if not failed else 'FAILED'} in {report['seconds']} s")  # fmt: skip
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
