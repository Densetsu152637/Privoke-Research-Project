"""Print the installed dependency closure of spacy and en_core_web_sm as JSON (read-only; run with -I -B)."""
import json
import sys
from importlib import metadata

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

# click: spacy 3.7.5 imports it directly, but typer 0.27 no longer depends on it, so metadata alone misses it.
ROOTS = sys.argv[1:] or ["spacy", "en-core-web-sm", "click"]
seen: dict[str, str] = {}
stack = list(ROOTS)
while stack:
    name = canonicalize_name(stack.pop())
    if name in seen:
        continue
    try:
        dist = metadata.distribution(name)
    except metadata.PackageNotFoundError:
        seen[name] = "MISSING"
        continue
    seen[name] = dist.version
    for raw in dist.requires or []:
        req = Requirement(raw)
        if req.marker is not None and not req.marker.evaluate({"extra": ""}):
            continue
        stack.append(req.name)
print(json.dumps(dict(sorted(seen.items())), indent=1))
