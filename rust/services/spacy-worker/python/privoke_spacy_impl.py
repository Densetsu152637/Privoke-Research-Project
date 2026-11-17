"""Python side of the privoke-spacy-worker.

The worker binary embeds this file and calls it through PyO3. The reference environment imports the same file for
`analyze_body`, so the bytes that the parity gate compares come from one function in both places. Python objects never
leave this module: every result is a JSON string.

Nothing here prints. After `redirect_stdout` fd 1 points at stderr, so a stray print or a C library message cannot corrupt
the frames that the Rust side writes to its own duplicate of the original stdout.
"""

import hashlib
import json
import os
import re
import sys

TAGGER_PIPES = ("tok2vec", "tagger", "attribute_ruler", "lemmatizer")
PROTOCOL_VERSION = 1


class BundleError(Exception):
    """The installed bundle differs from bundle.lock.txt, or is not isolated from the host Python."""


def _dumps(value):
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), allow_nan=False)


def analyze_body(nlp, text, selection):
    """The `analyze` result as JSON text: the tokens with the plan's fields, and the entities.

    `selection` is "full" (whole pipeline) or "tagger" (the post-filter's sub-pipeline: tok2vec, tagger,
    attribute_ruler and lemmatizer, which has no entities).
    """
    if selection == "full":
        doc = nlp(text)
    elif selection == "tagger":
        with nlp.select_pipes(enable=[n for n in TAGGER_PIPES if n in nlp.pipe_names]):
            doc = nlp(text)
    else:
        raise ValueError("selection must be 'full' or 'tagger'")
    tokens = [
        [t.text, t.idx, t.whitespace_, t.is_alpha, t.lower_, t.tag_, t.pos_, t.lemma_, t.dep_, t.head.i] for t in doc
    ]
    ents = [[e.start_char, e.end_char, e.label_] for e in doc.ents]
    return _dumps({"tokens": tokens, "ents": ents})


def lemma_index_body(nlp):
    """The words of the rule lemmatizer's `lemma_index` table, sorted, as a JSON array (the post-filter's lexicon)."""
    words = set()
    if "lemmatizer" in nlp.pipe_names:
        lookups = getattr(nlp.get_pipe("lemmatizer"), "lookups", None)
        if lookups is not None and lookups.has_table("lemma_index"):
            for entries in lookups.get_table("lemma_index").values():
                words.update(w for w in entries if isinstance(w, str))
    return _dumps(sorted(words))


def redirect_stdout():
    """Points fd 1 and sys.stdout at stderr. The Rust side already holds its own duplicate of the original stdout."""
    sys.stdout.flush() if sys.stdout else None
    os.dup2(2, 1)
    sys.stdout = sys.stderr
    sys.stdin = None


def test_print():
    """Test hook: every way a stray message can reach stdout."""
    print("PRIVOKE-TEST-PRINT python print")
    sys.__stdout__.write("PRIVOKE-TEST-PRINT sys.__stdout__\n")
    sys.__stdout__.flush()
    os.write(1, b"PRIVOKE-TEST-PRINT raw fd 1 write\n")
    return "null"


# --- bundle check -------------------------------------------------------------------------------------------------


def _canon(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_lock(text):
    """Returns (header, packages): the `# privoke-lock: key = value` lines and {canonical name: version}."""
    header = {}
    packages = {}
    joined = text.replace("\\\r\n", " ").replace("\\\n", " ")
    for line in joined.splitlines():
        line = line.strip()
        match = re.match(r"^# privoke-lock: ([a-z0-9._-]+) = (.*)$", line)
        if match:
            header[match.group(1)] = match.group(2)
            continue
        if not line or line.startswith("#"):
            continue
        requirement = line.split(" --hash=")[0].strip()
        pinned = re.match(r"^([A-Za-z0-9_.-]+)==([^\s;]+)\s*(?:;\s*(.+))?$", requirement)
        if pinned:
            name, version, marker = pinned.groups()
            if marker:
                from packaging.markers import Marker

                if not Marker(marker).evaluate():
                    continue
            packages[_canon(name)] = version
            continue
        url = re.match(r"^([A-Za-z0-9_.-]+)\s*@\s*(\S+)$", requirement)
        if url:
            wheel = url.group(2).rsplit("/", 1)[-1]
            version = wheel.split("-")[1]
            packages[_canon(url.group(1))] = version
            continue
        raise BundleError(f"unrecognised line in bundle.lock.txt: {line[:80]!r}")
    return header, packages


def blis_target():
    """The BLIS CPU-dispatch sub-configuration this process selects (for example 'haswell').

    BLIS prints its choice to stderr when BLIS_ARCH_DEBUG is set, at its first initialisation, so the choice is read
    from a temporary stderr. It must run before anything imports blis.
    """
    import tempfile

    if "blis" in sys.modules:
        raise BundleError("blis was imported before the dispatch target was read")
    os.environ["BLIS_ARCH_DEBUG"] = "1"
    saved = os.dup(2)
    with tempfile.TemporaryFile() as capture:
        os.dup2(capture.fileno(), 2)
        try:
            import numpy
            from blis.py import gemm

            gemm(numpy.ones((4, 4), dtype="f"), numpy.ones((4, 4), dtype="f"))
        finally:
            os.dup2(saved, 2)
            os.close(saved)
        capture.seek(0)
        output = capture.read().decode("utf-8", "replace")
    match = re.search(r"selecting sub-configuration '([A-Za-z0-9_]+)'", output)
    if not match:
        raise BundleError(f"could not read the BLIS dispatch target from {output[:120]!r}")
    return match.group(1)


def cpython_identity():
    """The build identity the lock records: version string, hexversion and the build flags that change behaviour."""
    import sysconfig

    flags = [f"Py_DEBUG={sysconfig.get_config_var('Py_DEBUG')}", f"Py_GIL_DISABLED={sysconfig.get_config_var('Py_GIL_DISABLED')}"]
    return f"{sys.version} | hexversion={sys.hexversion:#x} | platform={sysconfig.get_platform()} | {' '.join(flags)}"


def check_isolation(bundle):
    """The interpreter must see only the bundle: no user site, no environment, every sys.path entry inside it."""
    root = os.path.normcase(os.path.realpath(bundle))
    problems = []
    for entry in sys.path:
        resolved = os.path.normcase(os.path.realpath(entry)) if entry else ""
        if not (resolved == root or resolved.startswith(root + os.sep)):
            problems.append(entry)
    if problems:
        raise BundleError(f"sys.path leaves the bundle: {problems}")
    if not (sys.flags.isolated and sys.flags.no_site and sys.flags.ignore_environment):
        raise BundleError("CPython is not isolated: the bundle's python311._pth file is not in effect")
    for prefix in (sys.prefix, sys.exec_prefix, sys.base_prefix):
        if os.path.normcase(os.path.realpath(prefix)) != root:
            raise BundleError(f"sys.prefix {prefix!r} is not the bundle")


def check_bundle(bundle, lock_path):
    """Compares the interpreter and every installed package with the whole lock. Returns the lock's SHA-256."""
    from importlib import metadata

    lock_bytes = open(lock_path, "rb").read()
    header, wanted = parse_lock(lock_bytes.decode("utf-8"))
    problems = []

    import platform

    if platform.python_version() != header.get("cpython-version"):
        problems.append(f"CPython {platform.python_version()} != locked {header.get('cpython-version')}")
    platform_key = "windows-x86_64" if sys.platform == "win32" else "linux-x86_64"
    identity = cpython_identity()
    locked_build = header.get(f"cpython-build.{platform_key}")
    if identity != locked_build:
        problems.append(f"CPython build {identity!r} != locked {locked_build!r} for {platform_key}")

    installed = {}
    for dist in metadata.distributions():
        name = dist.metadata["Name"]
        if name:
            installed[_canon(name)] = dist.version
    for name in sorted(set(wanted) | set(installed)):
        if name not in installed:
            problems.append(f"{name}=={wanted[name]} is locked but not installed")
        elif name not in wanted:
            problems.append(f"{name}=={installed[name]} is installed but not locked")
        elif installed[name] != wanted[name]:
            problems.append(f"{name} {installed[name]} != locked {wanted[name]}")

    target = blis_target()
    locked_target = header.get(f"blis-target.{platform_key}")
    if target != locked_target:
        problems.append(f"BLIS dispatch target {target!r} != locked {locked_target!r} for {platform_key}")

    if problems:
        raise BundleError("; ".join(problems))
    return hashlib.sha256(lock_bytes).hexdigest()


def startup(bundle, model, lock=None):
    """Checks the bundle, loads spaCy once and returns (nlp, ready-frame JSON text). `lock` is for tests only."""
    sys.dont_write_bytecode = True
    if hasattr(os, "add_dll_directory"):
        os.add_dll_directory(bundle)
    check_isolation(bundle)
    lock_sha256 = check_bundle(bundle, lock or os.path.join(bundle, "bundle.lock.txt"))
    import spacy

    nlp = spacy.load(model)
    meta = nlp.meta
    import platform

    info = {
        "type": "ready",
        "protocol": PROTOCOL_VERSION,
        "spacy": spacy.__version__,
        "model": meta.get("name"),
        "model_version": meta.get("version"),
        "python": platform.python_version(),
        "lock_sha256": lock_sha256,
    }
    return nlp, _dumps(info)
