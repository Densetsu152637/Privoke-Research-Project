"""Regenerate the package section of bundle.lock.txt from PyPI.

Run with any Python that has network access. The versions come from a closure JSON produced by closure.py in the reference
environment (read-only); the hashes are every wheel PyPI publishes for CPython 3.11 on win_amd64 and manylinux x86_64, plus
pure-Python wheels. The header of the lock (CPython and BLIS identity) is maintained by build_bundle.py --record-identity.
"""
from __future__ import annotations

import json
import sys
import urllib.request

PLATFORM_MARKERS = {"colorama": 'sys_platform == "win32"'}
SKIP = {"en-core-web-sm"}  # not on PyPI; recorded by hand under its release URL


def wheel_ok(name: str) -> bool:
    tags = name[:-4].split("-")[-3:]
    py, abi, plat = tags
    pure = plat == "any"
    cp311 = py in ("cp311", "cp310.cp311") or abi in ("abi3",) and py.startswith("cp3")
    if pure:
        return py.startswith(("py3", "py2.py3", "cp3")) or py == "py3"
    return cp311 and (plat.startswith("win_amd64") or ("manylinux" in plat and "x86_64" in plat))


def main(closure_json: str) -> None:
    closure = json.load(open(closure_json, encoding="utf-8"))
    out = []
    for name, version in sorted(closure.items()):
        if name in SKIP:
            continue
        with urllib.request.urlopen(f"https://pypi.org/pypi/{name}/{version}/json", timeout=60) as r:
            data = json.load(r)
        hashes = sorted({f["digests"]["sha256"] for f in data["urls"] if f["packagetype"] == "bdist_wheel" and wheel_ok(f["filename"])})
        if not hashes:
            raise SystemExit(f"no suitable wheel for {name}=={version}")
        marker = PLATFORM_MARKERS.get(name)
        line = f"{name}=={version}" + (f" ; {marker}" if marker else "")
        cont = " " + chr(92) + chr(10)
        out.append(line + cont + cont.join(f"    --hash=sha256:{h}" for h in hashes))
    sys.stdout.write("\n".join(out) + "\n")


if __name__ == "__main__":
    main(sys.argv[1])
