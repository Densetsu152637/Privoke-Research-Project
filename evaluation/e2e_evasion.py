"""E2EEVADE: end-to-end evasion harness and variant set (Stage 13b-1).

Question: can a user rewrite a sensitive prompt so that it reaches the external receiver
unprotected? Each adversarial variant is sent from a provider page through the unmodified
installed extension to a synthetic loopback HTTPS receiver, with the real supervisor, bridge and
detector on loopback. The harness records whether the receiver got the request, whether the
payload arrived intact, the page's notice status, and the decision and executed layers read from a
recording tap in front of the real bridge (the bridge itself keeps no log).

Scope: PRODUCT PIPELINE, installed extension, end to end. Never LLM-only evidence. Requests carry
an explicit, non-empty layer list and every response's executed layers are asserted against the
configured set; a mismatch aborts the run. Nothing here contacts a real provider.

Sub-commands::

    e2e_evasion.py verify-templates --expected-sha256 H
    e2e_evasion.py build    --out DIR [--n-seed N] --exclude-ids FILE [--variants a,b]   # or --allow-no-exclude
    e2e_evasion.py size-seeds --plan PLAN --pilot-rows ROWS [--hours 8] [--floor 200]
    e2e_evasion.py detector --run-set FILE --out DIR --release-dir D --generated D
    e2e_evasion.py run      --run-set FILE --out DIR --runtime-python P [--browsers a,b] [--pilot] [--lock-held]
    e2e_evasion.py stack    [--out DIR --print-command]            # probe, or write the compose override
    e2e_evasion.py lock     acquire|release|show --stage 13b-2

The semantic layer is V3 balanced served by the LOCAL DOCKER SERVER STACK (model streaming on
127.0.0.1:50051), not a reduced arm. The harness never starts Docker. Stage 13b-2 runs, under the
host lock (``lock acquire --stage 13b-2``), from the worktree root::

    e2e_evasion.py stack --out <abs s13b dir> --print-command     # writes compose.release.yml and prints:
    docker compose -p privoke-s13b-e2e -f docker-compose.prod.yml -f evaluation/compose.localhost.yml \\
        -f <out>/compose.release.yml up -d --build --wait --wait-timeout 240 model-streaming-service

then ``run --lock-held`` (it checks the stack first), then
``docker compose -p privoke-s13b-e2e ... stop model-streaming-service`` and ``lock release``.
The override only re-points the release bind mount at the main checkout's
models/standard-releases. The container name ``model-streaming-service`` is fixed by the compose
file: stop any other stack that uses it first.

Prompt-bearing outputs (the run set, variants, receiver bodies) are written only under
``<local root>/s13b/`` (the Git-ignored ``evaluation/results/s13b`` of the main checkout, or
``$S13_LOCAL_INPUTS_ROOT/s13b``). Rows and plans hold ids, hashes and counts only. The scoring
reuses the Stage 3 functions of ``adversarial_evasion.py`` on the same applicable-pair set.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import http.client
import http.server
import json
import math
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from collections import Counter, defaultdict
from pathlib import Path
from urllib.parse import urlsplit

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
import adversarial_evasion as ae  # noqa: E402
import adversarial_evasion_transforms as stage3  # noqa: E402
import e2e_evasion_transforms as e2etx  # noqa: E402
from cross_platform_probes import FIXTURE_HOSTS  # noqa: E402

SCHEMA = "privoke-e2e-evasion-v1"
STUDY_PREFIX = "E2EEVADE"
SCOPE_LABEL = "product pipeline (installed extension, end to end)"
DETECTOR_SCOPE_LABEL = "product pipeline (in-process)"

# Stage 3 inputs, verified before anything is read (hashes are of the frozen on-disk bytes).
FROZEN_SET_SHA256 = "5e4eac4c7c3117adf81a013fa9e4572484c9b0f41ab4b4f217ca960a82b634c2"
F4_SOURCE_SHA256 = "d4bed756790c7b000fc5e8b6028e3f962c8dbfabe3f607a7180224d55356589d"
STAGE3_TRANSFORMS_SHA256 = "43aff01b693de027e59cb3bc78738a38500a80d6604e60fb4f2f80c665d7260b"
STAGE3_RECORD = "ADVEVADE-20261116"
STAGE3_GENERATOR_REVISION = "advevade-transforms-1"
DEFAULT_LOCAL_ROOT = Path("D:/Git Repositories/Privoke-Research-Project/evaluation/results")
DEFAULT_FROZEN_DIR = DEFAULT_LOCAL_ROOT / "adversarial_evasion_20261116" / "main"
ALLOWLIST = HERE / "s13_allowlist.json"
TEMPLATE_PIN_KEY = "evaluation/e2e_evasion_transforms.py"

SAMPLE_SEED = 20261126
PILOT_PROBES = 20
HOURS_PER_BROWSER = 8.0
SEED_FLOOR = 200
BASE_SHAPE = "chatgpt-conversation"
NOTICE_RENDERED = "RENDERED"
BASELINE = ae.BASELINE
ACTIONS = ae.ACTIONS
STAGE3_VARIANTS = tuple(stage3.VARIANTS)
E2E_VARIANTS = tuple(e2etx.E2E_VARIANTS)
ALL_VARIANTS = STAGE3_VARIANTS + E2E_VARIANTS

LAYER_ORDER = ("regex", "ner", "semantic")
LAYER_ENUM = {"regex": 2, "ner": 3, "semantic": 4}
ENUM_LAYER = {value: name for name, value in LAYER_ENUM.items()}
LAYER_PROTO_NAME = {"regex": "DETECTION_LAYER_REGEX", "ner": "DETECTION_LAYER_NER",
                    "semantic": "DETECTION_LAYER_SEMANTIC"}
FIRST_ORDER_REGEX = "regex"

EXPECTED_ROW_FIELDS = (
    "seed_id", "variant", "family", "value_removing", "applicable", "browser", "attended",
    "receiver_got", "payload_intact", "warn_shown", "decision", "layers_requested",
    "layers_executed", "error", "detector_level", "e2e_outcome", "scope_label",
)
EXTRA_ROW_FIELDS = ("failed_closed", "elapsed_ms", "inspection_unavailable", "request_disposition", "page_timeout")
DISPOSITION_HANDED_OFF = ("ORIGINAL_REQUEST_HANDED_OFF", "MASKED_REQUEST_HANDED_OFF")
SEMANTIC_CHECKSUM_KEY = "privoke.semantic.artifact_checksum"
# The local Docker server stack that serves V3 balanced to the client runtime (model streaming on loopback).
STACK_TARGET = "127.0.0.1:50051"
STACK_MODEL_ID = "privoke-v3-balanced"
STACK_COMPOSE_PROJECT = "privoke-s13b-e2e"
DEFAULT_RELEASE_ROOT = Path("D:/Git Repositories/Privoke-Research-Project/models/standard-releases")
SETTINGS_IN_PROFILE = {"warn_masking": False, "model_quality": "LATEST",
                       "source": "disposable profile: extension DEFAULT_SETTINGS (warnMasking false)"}
E2E_OUTCOMES = ("protected", "evaded", "downgraded", "fail_closed", "not_delivered_other")


class HarnessError(RuntimeError):
    """A refused or inconsistent configuration; the CLI exits with status 2."""


class LayerConfigError(HarnessError):
    pass


class HostRefusedError(HarnessError):
    pass


class LayerMismatchError(ae.LayerAssertionError):
    """Requested or executed layers differ from the configured set; the run aborts."""


class HostLockHeld(HarnessError):
    pass


# ---------------------------------------------------------------- paths, hashes and the host lock
def local_root() -> Path:
    return Path(os.environ.get("S13_LOCAL_INPUTS_ROOT") or DEFAULT_LOCAL_ROOT)


def ensure_out_dir(out: str | Path) -> Path:
    """Prompt-bearing output is allowed only under ``<local root>/s13b/``."""
    path = Path(out)
    if not path.is_absolute():
        raise HarnessError(f"--out must be an absolute path, got {out}")
    allowed = (local_root() / "s13b").resolve()
    resolved = path.resolve()
    if resolved != allowed and allowed not in resolved.parents:
        raise HarnessError(f"--out {resolved} is outside the Git-ignored directory {allowed}")
    resolved.mkdir(parents=True, exist_ok=True)
    return resolved


def lf_sha256(path: Path) -> str:
    return e2etx.lf_sha256(path)


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]


def write_json(path: Path, payload: dict) -> None:
    Path(path).write_text(json.dumps(payload, indent=1, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")


class HostLock:
    """The shared host lock of the Stage 13 plan: one host-heavy run at a time."""

    def __init__(self, stage: str, path: Path | None = None) -> None:
        self.stage = stage
        self.path = Path(path) if path else local_root() / "s13-host.lock"
        self.held = False

    def acquire(self) -> "HostLock":
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            descriptor = os.open(str(self.path), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError:
            try:
                holder = self.path.read_text(encoding="utf-8").strip()
            except OSError:
                holder = "unreadable"
            raise HostLockHeld(f"host lock {self.path} is held ({holder}); refusing to start") from None
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(json.dumps({"stage": self.stage, "pid": os.getpid(),
                                     "started": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}))
        self.held = True
        return self

    def verify_held(self) -> "HostLock":
        """Accept a lock the caller took with ``lock acquire`` for this stage (not released by this run)."""
        try:
            holder = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            raise HostLockHeld(f"--lock-held was given but {self.path} is missing or unreadable") from None
        if holder.get("stage") != self.stage:
            raise HostLockHeld(f"host lock is held by stage {holder.get('stage')!r}, not {self.stage!r}")
        return self

    def release(self) -> None:
        if self.held:
            try:
                self.path.unlink()
            except FileNotFoundError:
                pass
            self.held = False

    def __enter__(self) -> "HostLock":
        return self.acquire()

    def __exit__(self, *exc: object) -> None:
        self.release()


# ---------------------------------------------------------------- template freeze and input checks
def read_pin(allowlist: Path | None = None) -> str | None:
    path = Path(allowlist) if allowlist else ALLOWLIST
    if not path.is_file():
        return None
    data = json.loads(path.read_text(encoding="utf-8"))
    value = data.get(TEMPLATE_PIN_KEY)
    return value.lower() if isinstance(value, str) else None


def verify_templates(expected_sha256: str, template_path: Path | None = None, stage3_path: Path | None = None,
                     allowlist: Path | None = None) -> dict:
    """Checks that freeze the variant set. ``ok`` is the exit status of ``verify-templates``."""
    template = Path(template_path) if template_path else e2etx.template_file()
    stage3_module = Path(stage3_path) if stage3_path else Path(stage3.__file__)
    actual = lf_sha256(template)
    stage3_actual = lf_sha256(stage3_module)
    pin = read_pin(allowlist)
    checks = {
        "template_matches_expected": actual == expected_sha256.lower(),
        "template_matches_pin": pin is not None and actual == pin,
        "stage3_module_unchanged": stage3_actual == STAGE3_TRANSFORMS_SHA256,
        "stage3_generator_revision": stage3.GENERATOR_REVISION == STAGE3_GENERATOR_REVISION,
        "e2e_variants_registered": tuple(e2etx.E2E_VARIANTS) == ("fragmented_identifier", "mixed_language"),
    }
    return {"template_sha256": actual, "expected_sha256": expected_sha256.lower(), "pin": pin,
            "stage3_module_sha256": stage3_actual, "e2e_generator_revision": e2etx.GENERATOR_REVISION,
            "checks": checks, "ok": all(checks.values())}


def verify_frozen_inputs(frozen_dir: Path) -> dict:
    """Hash the frozen Stage 3 set first, then check its manifest and the F4 link. Returns the manifest."""
    frozen = Path(frozen_dir) / "frozen_set.jsonl"
    actual = ae.file_sha256(frozen)
    if actual != FROZEN_SET_SHA256:
        raise HarnessError(f"frozen set hash {actual} differs from the declared {FROZEN_SET_SHA256}; refusing to read it")
    manifest = json.loads((Path(frozen_dir) / "manifest.json").read_text(encoding="utf-8"))
    problems = []
    if manifest.get("frozen_set_sha256") != FROZEN_SET_SHA256:
        problems.append("manifest frozen_set_sha256")
    if manifest.get("seed_file_sha256") != F4_SOURCE_SHA256:
        problems.append("manifest F4 source hash")
    if manifest.get("record") != STAGE3_RECORD:
        problems.append("manifest record id")
    if manifest.get("generator_revision") != STAGE3_GENERATOR_REVISION:
        problems.append("manifest generator revision")
    if manifest.get("transform_module_sha256") != STAGE3_TRANSFORMS_SHA256:
        problems.append("manifest transform module hash")
    if problems:
        raise HarnessError("frozen-set manifest does not match the plan: " + ", ".join(problems))
    return manifest


# ---------------------------------------------------------------- seeds and variants
def stratified_seed_sample(row_source: dict[str, str], n_seed: int, seed: int = SAMPLE_SEED,
                           exclude: set[str] | None = None) -> list[str]:
    """Seeded sample of ``n_seed`` row ids, proportional to source size (largest remainder)."""
    exclude = exclude or set()
    by_source: dict[str, list[str]] = defaultdict(list)
    for row_id, source in row_source.items():
        if row_id not in exclude:
            by_source[source].append(row_id)
    total = sum(len(v) for v in by_source.values())
    n_seed = min(n_seed, total)
    sources = sorted(by_source)
    exact = {s: n_seed * len(by_source[s]) / total for s in sources} if total else {}
    quota = {s: min(len(by_source[s]), int(exact[s])) for s in sources}
    for s in sorted(sources, key=lambda s: (-(exact[s] - int(exact[s])), s)):
        if sum(quota.values()) >= n_seed:
            break
        if quota[s] < len(by_source[s]):
            quota[s] += 1
    chosen: list[str] = []
    for s in sources:
        ordered = sorted(by_source[s], key=lambda r: hashlib.sha256(f"{seed}:e2e-sample:{r}".encode()).hexdigest())
        chosen.extend(ordered[:quota[s]])
    return sorted(chosen)


def send_order(seed_ids: list[str], seed: int = SAMPLE_SEED) -> list[str]:
    return sorted(seed_ids, key=lambda r: hashlib.sha256(f"{seed}:e2e-order:{r}".encode()).hexdigest())


def variant_meta(name: str) -> tuple[str, bool]:
    family, _fn, removing = (stage3.VARIANTS.get(name) or e2etx.E2E_VARIANTS[name])
    return family, removing


def run_set_items(seed_id: str, row: dict, frozen_items: list[dict], manifest_variants: dict, variants: tuple[str, ...]) -> list[dict]:
    """Items of one seed: the baseline, the frozen Stage 3 variants as they are, and the new variants."""
    by_variant = {item["variant"]: item for item in frozen_items}
    baseline = by_variant.get(BASELINE)
    if baseline is None or baseline["text"] != row["text"]:
        raise HarnessError(f"seed {seed_id}: the frozen baseline differs from the F4 source row")
    items = [{"vid": f"{seed_id}::{BASELINE}", "seed_id": seed_id, "variant": BASELINE, "family": BASELINE,
              "value_removing": False, "applicable": True, "text": baseline["text"]}]
    for name in variants:
        family, removing = variant_meta(name)
        if name in stage3.VARIANTS:
            frozen = by_variant.get(name)
            if frozen is None:
                raise HarnessError(f"seed {seed_id}: frozen set lacks variant {name}")
            meta = manifest_variants[name]
            if meta["family"] != family or meta["value_removing"] != removing:
                raise HarnessError(f"variant {name}: manifest family or value_removing differs from the transform table")
            text, applicable = frozen["text"], bool(frozen["applicable"])
        else:
            produced = e2etx.apply_e2e_variant(name, row)
            applicable = produced is not None and produced != row["text"]
            text = produced if produced is not None else row["text"]
        items.append({"vid": f"{seed_id}::{name}", "seed_id": seed_id, "variant": name, "family": family,
                      "value_removing": removing, "applicable": applicable, "text": text})
    return items


def build_run_set(frozen_dir: Path, out_dir: Path, n_seed: int, exclude_ids: set[str] | None = None,
                  exclude_source: Path | None = None, variants: tuple[str, ...] = ALL_VARIANTS,
                  seed_file: Path | None = None, template_sha256: str | None = None) -> dict:
    """Verify the inputs, sample the seeds and write ``run_set.jsonl`` and ``run_plan.json``."""
    unknown = [v for v in variants if v not in ALL_VARIANTS]
    if unknown:
        raise HarnessError(f"unknown variants {unknown}")
    out = ensure_out_dir(out_dir)
    manifest = verify_frozen_inputs(frozen_dir)
    if exclude_ids is None:
        exclude_ids = set()
    sample = stratified_seed_sample(manifest["row_source"], n_seed, SAMPLE_SEED, exclude_ids)
    wanted = set(sample)
    frozen_by_seed: dict[str, list[dict]] = defaultdict(list)
    with (Path(frozen_dir) / "frozen_set.jsonl").open("r", encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            item = json.loads(line)
            if item["row_id"] in wanted:
                frozen_by_seed[item["row_id"]].append(item)
    source_path = Path(seed_file) if seed_file else Path(manifest["seed_file"])
    source_hash = ae.file_sha256(source_path)
    if source_hash != F4_SOURCE_SHA256:
        raise HarnessError(f"F4 source hash {source_hash} differs from the declared {F4_SOURCE_SHA256}")
    rows: dict[str, dict] = {}
    with source_path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                row = json.loads(line)
                if row["id"] in wanted:
                    rows[row["id"]] = row
    missing = wanted - set(rows)
    if missing:
        raise HarnessError(f"{len(missing)} sampled seeds are absent from the F4 source file")
    items: list[dict] = []
    ordered = send_order(sample)
    for seed_id in ordered:
        items.extend(run_set_items(seed_id, rows[seed_id], frozen_by_seed[seed_id], manifest["variants"], variants))
    payload ="\n".join(ae.canonical_line(item) for item in items) + "\n"
    run_set = out / "run_set.jsonl"
    if run_set.exists() and run_set.read_text(encoding="utf-8") != payload:
        raise HarnessError("run set exists and differs; refusing to overwrite")
    run_set.write_text(payload, encoding="utf-8", newline="\n")
    applicable = Counter(i["variant"] for i in items if i["applicable"] and i["variant"] != BASELINE)
    plan = {
        "schema": SCHEMA, "kind": "run_plan", "sample_seed": SAMPLE_SEED, "n_seed_requested": n_seed,
        "n_seed": len(sample), "seed_ids": ordered,
        "seed_source": {s: manifest["row_source"][s] for s in ordered},
        "seed_group": {s: manifest["row_group"][s] for s in ordered},
        "rows_by_source": dict(sorted(Counter(manifest["row_source"][s] for s in sample).items())),
        "excluded_ids": len(exclude_ids),
        "exclude_source_sha256": ae.file_sha256(exclude_source) if exclude_source else None,
        "frozen_set_sha256": FROZEN_SET_SHA256, "f4_source_sha256": source_hash,
        "stage3_transform_module_sha256": manifest["transform_module_sha256"],
        "stage3_generator_revision": STAGE3_GENERATOR_REVISION,
        "e2e_generator_revision": e2etx.GENERATOR_REVISION,
        "template_sha256": template_sha256 or lf_sha256(e2etx.template_file()),
        "variants": {name: dict(zip(("family", "value_removing"), variant_meta(name))) for name in variants},
        "applicable_by_variant": dict(sorted(applicable.items())),
        "items": len(items), "sends_planned": sum(1 for i in items if i["applicable"]),
        "run_set_sha256": ae.file_sha256(run_set),
    }
    write_json(out / "run_plan.json", plan)
    return plan


def pilot_items(items: list[dict], count: int = PILOT_PROBES) -> list[dict]:
    """The first ``count`` sendable items, in send order: the first seed's baseline and variants."""
    sendable = [i for i in items if i["applicable"]]
    return sendable[:count]


def plan_seed_count(seconds_per_send: float, sends_per_seed: float, hours: float = HOURS_PER_BROWSER,
                    floor: int = SEED_FLOOR, available: int | None = None) -> dict:
    """N_seed after the timing pilot: as many seeds as fit one browser's hours, never below the floor."""
    if seconds_per_send <= 0 or sends_per_seed <= 0:
        raise HarnessError("pilot timing and sends per seed must be positive")
    budget = int(math.floor(hours * 3600.0 / (seconds_per_send * sends_per_seed)))
    n_seed = max(floor, budget)
    if available is not None:
        n_seed = min(n_seed, available)
    return {"seconds_per_send": seconds_per_send, "sends_per_seed": sends_per_seed, "hours": hours, "floor": floor,
            "budget_seeds": budget, "n_seed": n_seed, "floor_binding": budget < floor,
            "estimated_hours": n_seed * sends_per_seed * seconds_per_send / 3600.0,
            "exceeds_budget": n_seed * sends_per_seed * seconds_per_send / 3600.0 > hours}


# ---------------------------------------------------------------- explicit layers and the assertion
def parse_layers(spec: str | list[str] | tuple[str, ...]) -> tuple[str, ...]:
    """The configured layer set. An empty list is refused: the runtime reads it as the whole pipeline."""
    names = [s.strip().lower() for s in (spec.split(",") if isinstance(spec, str) else spec) if str(s).strip()]
    if not names:
        raise LayerConfigError("an empty layer list is refused; name at least one layer explicitly")
    unknown = [n for n in names if n not in LAYER_ORDER]
    if unknown:
        raise LayerConfigError(f"unknown layers {unknown}; allowed {list(LAYER_ORDER)}")
    if len(set(names)) != len(names):
        raise LayerConfigError("duplicate layers")
    return tuple(layer for layer in LAYER_ORDER if layer in names)


def require_explicit_request_layers(values: list[int] | list[str]) -> list[str]:
    """Names of the layers of one request; an empty or unknown list is refused."""
    if not values:
        raise LayerConfigError("request carries no explicit layer list")
    names = []
    for value in values:
        name = ENUM_LAYER.get(value) if isinstance(value, int) else value
        if name not in LAYER_ENUM:
            raise LayerMismatchError(f"request layer {value!r} is not one of regex, ner, semantic")
        names.append(name)
    return names


def assert_requested_layers(requested: list[str], expected: tuple[str, ...]) -> None:
    """The extension may drop the semantic layer when streaming is unavailable; that must stop the run."""
    if not requested:
        raise LayerMismatchError("request carried no explicit layers")
    if set(requested) != set(expected) or len(requested) != len(set(requested)):
        raise LayerMismatchError(f"requested layers {requested} differ from the configured {list(expected)}")


def assert_executed_layers(layers: list[dict], expected: tuple[str, ...], expected_checksum: str | None = None,
                           metadata: dict | None = None) -> dict:
    """Generalised ``adversarial_evasion.assert_executed_layers`` for any non-empty configured set.

    ``layers`` is a list of ``{"layer": name, "status": s, "error": e, "results": [...]}``. A layer
    may be ``ok``, ``error`` (a recorded outcome: the runtime then fails closed) or ``skipped``,
    which the regex-first order allows only when regex was requested, ran, and every later layer
    was skipped together.
    """
    if not expected:
        raise LayerConfigError("an empty expected layer set is refused")
    names = [item["layer"] for item in layers]
    if names != list(expected):
        raise LayerMismatchError(f"executed layers {names} differ from the configured {list(expected)}")
    statuses = {item["layer"]: item["status"] for item in layers}
    for name, status in statuses.items():
        if status not in ("ok", "skipped", "error"):
            raise LayerMismatchError(f"layer {name} has status {status!r}")
    skipped = [name for name, status in statuses.items() if status == "skipped"]
    if "regex" in expected:
        if statuses["regex"] != "ok":
            raise LayerMismatchError("regex layer did not run")
        later = [name for name in expected if name != "regex"]
        if skipped and set(skipped) != set(later):
            raise LayerMismatchError("regex-first skip must skip every later layer")
    elif skipped:
        raise LayerMismatchError("a layer was skipped although regex was not requested")
    if statuses.get("semantic") == "ok" and expected_checksum is not None:
        if (metadata or {}).get(SEMANTIC_CHECKSUM_KEY) != expected_checksum:
            raise LayerMismatchError("semantic layer executed with an unexpected model identity")
    return statuses


def response_summary(response: dict) -> dict:
    """Detector-side facts of one response, as ``adversarial_evasion.score_record`` derives them."""
    layers = response["layers"]
    statuses = {item["layer"]: item["status"] for item in layers}
    per_layer = ae.layer_actions(layers)
    detect = max(per_layer.values(), key=ae.RANK.get) if per_layer else "ALLOW"
    errored = [name for name, status in statuses.items() if status == "error"]
    return {"action": response["action"], "detect_action": detect, "layer_status": statuses,
            "layer_action": per_layer, "errored": errored,
            "failed_closed": bool(errored) and detect == "ALLOW" and response["action"] != "ALLOW"}


# ---------------------------------------------------------------- gRPC-Web wire decoding (no generated stubs)
class WireError(ValueError):
    pass


def _varint(buf: bytes, pos: int) -> tuple[int, int]:
    shift = value = 0
    while True:
        if pos >= len(buf) or shift > 63:
            raise WireError("truncated varint")
        byte = buf[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, pos
        shift += 7


def parse_message(buf: bytes) -> list[tuple[int, int, object]]:
    pos, out = 0, []
    while pos < len(buf):
        key, pos = _varint(buf, pos)
        field, wire = key >> 3, key & 7
        if wire == 0:
            value, pos = _varint(buf, pos)
        elif wire == 1:
            value, pos = buf[pos:pos + 8], pos + 8
        elif wire == 2:
            length, pos = _varint(buf, pos)
            if pos + length > len(buf):
                raise WireError("truncated field")
            value, pos = buf[pos:pos + length], pos + length
        elif wire == 5:
            value, pos = buf[pos:pos + 4], pos + 4
        else:
            raise WireError(f"unsupported wire type {wire}")
        out.append((field, wire, value))
    return out


def _packed_varints(buf: bytes) -> list[int]:
    values, pos = [], 0
    while pos < len(buf):
        value, pos = _varint(buf, pos)
        values.append(value)
    return values


def decode_analyze_request(payload: bytes) -> dict:
    """text (1), request_id (5) and the repeated layers enum (7) of ``AnalyzePromptRequest``."""
    out = {"text": "", "request_id": "", "layer_values": []}
    for field, wire, value in parse_message(payload):
        if field == 1 and wire == 2:
            out["text"] = value.decode("utf-8")
        elif field == 5 and wire == 2:
            out["request_id"] = value.decode("utf-8")
        elif field == 7:
            out["layer_values"].extend(_packed_varints(value) if wire == 2 else [value])
    return out


def _decode_layer(payload: bytes) -> dict:
    layer = {"layer": "layer_0", "status": "", "error": "", "results": []}
    for field, wire, value in parse_message(payload):
        if field == 1 and wire == 0:
            layer["layer"] = ENUM_LAYER.get(value, f"layer_{value}")
        elif field == 2 and wire == 2:
            layer["status"] = value.decode("utf-8")
        elif field == 3 and wire == 2:
            action = ""
            for f2, w2, v2 in parse_message(value):
                if f2 == 2 and w2 == 2:
                    action = v2.decode("utf-8")
            layer["results"].append({"action": action})
        elif field == 4 and wire == 2:
            layer["error"] = value.decode("utf-8")
    return layer


def decode_analyze_response(payload: bytes) -> dict:
    """request_id (1), action (2), evidence (7), metadata (8), layers (10), error (12) of ``AnalyzePromptResponse``."""
    out = {"request_id": "", "action": "", "metadata": {}, "layers": [], "error": "", "evidence": None}
    for field, wire, value in parse_message(payload):
        if field == 1 and wire == 2:
            out["request_id"] = value.decode("utf-8")
        elif field == 2 and wire == 2:
            out["action"] = value.decode("utf-8")
        elif field == 7 and wire == 2:
            out["evidence"] = {"action": next((v.decode("utf-8") for f, w, v in parse_message(value) if f == 2 and w == 2), "")}
        elif field == 8 and wire == 2:
            key = val = ""
            for f2, w2, v2 in parse_message(value):
                if f2 == 1 and w2 == 2:
                    key = v2.decode("utf-8")
                elif f2 == 2 and w2 == 2:
                    val = v2.decode("utf-8")
            out["metadata"][key] = val
        elif field == 10 and wire == 2:
            out["layers"].append(_decode_layer(value))
        elif field == 12 and wire == 2:
            out["error"] = value.decode("utf-8")
    return out


def iter_grpc_web_frames(body: bytes):
    """Yield ``(flag, payload)`` for each gRPC-Web frame of a request or response body."""
    pos = 0
    while pos < len(body):
        if pos + 5 > len(body):
            raise WireError("truncated gRPC-Web frame header")
        flag, length = body[pos], int.from_bytes(body[pos + 1:pos + 5], "big")
        if pos + 5 + length > len(body):
            raise WireError("truncated gRPC-Web frame")
        yield flag, body[pos + 5:pos + 5 + length]
        pos += 5 + length


def grpc_status_of(body: bytes) -> int | None:
    for flag, payload in iter_grpc_web_frames(body):
        if flag & 0x80:
            for line in payload.decode("ascii", errors="replace").split("\r\n"):
                if line.lower().startswith("grpc-status:"):
                    return int(line.split(":", 1)[1].strip())
    return None


# ---------------------------------------------------------------- the bridge tap (the bridge keeps no log)
HOP_BY_HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailers",
              "transfer-encoding", "upgrade", "host", "content-length", "server", "date"}


class BridgeTap:
    """A loopback pass-through in front of the real gRPC-Web bridge that logs every AnalyzePrompt.

    The extension talks to ``127.0.0.1:8080``. The real supervisor starts the real bridge on
    ``upstream_port`` (``PRIVOKE_GRPC_WEB_PORT``) and the tap listens on 8080 and forwards every
    request unchanged, decoding the analysis request and response into hash-only entries.
    """

    def __init__(self, upstream_port: int, listen_port: int = 8080, host: str = "127.0.0.1",
                 log_path: Path | None = None) -> None:
        self.upstream_port = upstream_port
        self.entries: list[dict] = []
        self.lock = threading.Lock()
        self.log_path = Path(log_path) if log_path else None
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def _forward(self, method: str) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else b""
                headers = {k: v for k, v in self.headers.items() if k.lower() not in HOP_BY_HOP}
                connection = http.client.HTTPConnection("127.0.0.1", outer.upstream_port, timeout=60)
                try:
                    connection.request(method, self.path, body=body, headers=headers)
                    upstream = connection.getresponse()
                    data, status, reply_headers = upstream.read(), upstream.status, upstream.getheaders()
                except OSError as exc:
                    data, status, reply_headers = str(exc).encode(), 502, []
                finally:
                    connection.close()
                if method == "POST":
                    outer._record(self.path, body, status, data)
                self.send_response(status)
                for name, value in reply_headers:
                    if name.lower() not in HOP_BY_HOP:
                        self.send_header(name, value)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_POST(self) -> None:  # noqa: N802
                self._forward("POST")

            def do_OPTIONS(self) -> None:  # noqa: N802
                self._forward("OPTIONS")

            def log_message(self, *args: object) -> None:
                return

        self.server = http.server.ThreadingHTTPServer((host, listen_port), Handler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, name="e2e-bridge-tap", daemon=True)

    @property
    def port(self) -> int:
        return int(self.server.server_port)

    def start(self) -> None:
        self.thread.start()

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5.0)

    def mark(self) -> int:
        with self.lock:
            return len(self.entries)

    def since(self, mark: int) -> list[dict]:
        with self.lock:
            return [dict(entry) for entry in self.entries[mark:]]

    def _record(self, path: str, request_body: bytes, status: int, response_body: bytes) -> None:
        if not path.endswith("/AnalyzePrompt"):
            return
        entry: dict = {"path": path, "http_status": status, "request": None, "response": None,
                       "grpc_status": None, "error": None}
        try:
            payload = next(p for flag, p in iter_grpc_web_frames(request_body) if not flag & 0x80)
            request = decode_analyze_request(payload)
            entry["request"] = {
                "request_id": request["request_id"], "layer_values": request["layer_values"],
                "layers": [ENUM_LAYER.get(v, f"layer_{v}") for v in request["layer_values"]],
                "text_sha256": sha256_text(request["text"]), "text_chars": len(request["text"])}
        except (WireError, StopIteration, UnicodeDecodeError) as exc:
            entry["error"] = f"request_decode:{exc}"
        if status == 200:
            try:
                entry["grpc_status"] = grpc_status_of(response_body)
                data = next((p for flag, p in iter_grpc_web_frames(response_body) if not flag & 0x80), None)
                if data is not None:
                    entry["response"] = decode_analyze_response(data)
            except (WireError, UnicodeDecodeError) as exc:
                entry["error"] = f"response_decode:{exc}"
        else:
            entry["error"] = entry["error"] or f"http_{status}"
        with self.lock:
            entry["seq"] = len(self.entries)
            self.entries.append(entry)
            if self.log_path:
                with self.log_path.open("a", encoding="utf-8", newline="\n") as handle:
                    handle.write(json.dumps(entry, sort_keys=True) + "\n")


# ---------------------------------------------------------------- hosts
def host_of(value: str) -> str:
    return (urlsplit(value).hostname or "") if "://" in value else value.split(":")[0]


def require_fixture_host(value: str) -> str:
    host = host_of(value)
    if host not in FIXTURE_HOSTS:
        raise HostRefusedError(f"{host or value!r} is not a synthetic fixture host; refusing")
    return host


# ---------------------------------------------------------------- rows and outcome classification
def extract_prompt(body: bytes) -> str | None:
    """The prompt part of a ``chatgpt-conversation`` request body, or None when the shape differs."""
    try:
        return json.loads(body.decode("utf-8"))["messages"][0]["content"]["parts"][0]
    except (ValueError, KeyError, IndexError, TypeError, UnicodeDecodeError):
        return None


def interception_response(response: dict) -> tuple[str, bool]:
    """Port of ``interceptionResponse`` in ``extension/src/interception-failure.js``.

    Returns the action the page acts on and whether inspection is reported unavailable. A runtime
    fail-closed BLOCK (a layer errored and nothing else found a BLOCK) reaches the page as a
    fail-open WARN with ``inspectionUnavailable``. ``test_e2e_evasion`` runs the real function.
    """
    action = response.get("action", "").upper() if isinstance(response.get("action"), str) else ""
    if action not in ACTIONS:
        return "WARN", True
    layers = response.get("layers") or []
    failed = bool(response.get("error")) or any(l.get("status") == "error" or l.get("error") for l in layers)
    if not failed:
        return action, False
    evidence = response.get("evidence") or {}
    detected_block = (isinstance(evidence.get("action"), str) and evidence["action"].upper() == "BLOCK") or any(
        l.get("status") == "ok" and any(isinstance(r.get("action"), str) and r["action"].upper() == "BLOCK"
                                        for r in l.get("results") or []) for l in layers)
    return (action, False) if action == "BLOCK" and detected_block else ("WARN", True)


def build_row(item: dict, browser: str, attended: bool, expected: tuple[str, ...], reply: dict, captures: list,
              tap_entries: list[dict], elapsed_ms: float | None = None, expected_checksum: str | None = None) -> dict:
    """One row from what the page, the receiver and the tap saw. Raises on any layer mismatch.

    A variant that reaches the receiver intact with neither a page result nor a bridge request was
    forwarded without analysis (no extractable prompt, or an inspection error): it is an ALLOW, not
    an error row.
    """
    errors: list[str] = []
    outcome = reply.get("outcome") or {}
    driver_error = bool(reply.get("error") or "harnessError" in outcome or not outcome)
    if driver_error:
        errors.append("driver_error")
    if reply.get("url"):
        require_fixture_host(reply["url"])
    messages = outcome.get("messages", [])
    prompts = [m for m in messages if m.get("type") == "ANALYZE_PROMPT"]
    results = [m for m in messages if m.get("type") == "ANALYZE_RESULT"]
    outcomes = [m for m in messages if m.get("type") == "ANALYZE_OUTCOME"]
    disposition = outcomes[-1].get("disposition") if outcomes else None
    receiver_got = len(captures) > 0
    if len(captures) > 1:
        errors.append("multiple_receiver_posts")
    intact = False
    if captures:
        capture = captures[0]
        require_fixture_host(capture.host)
        intact = (capture.method == "POST" and reply.get("expectedBodySha256") == capture.sha256
                  and extract_prompt(capture.body) == item["text"])
    warn_shown = bool(results) and results[-1].get("noticeStatus") == NOTICE_RENDERED
    delivered = not driver_error and receiver_got and intact
    # The page analysed (one ANALYZE_PROMPT) but never got a result: its own timeout turned this into a
    # fail-open WARN (runtimeFailureResponse, with the page's unavailable notice) and the request went out.
    page_timeout = delivered and len(prompts) == 1 and not results
    without_analysis = delivered and not results and not tap_entries and not prompts
    if not without_analysis:
        if len(prompts) != 1:
            errors.append("page_analysis_count")
        elif (prompts[0].get("text") or "").strip() != item["text"].strip():
            errors.append("page_prompt_mismatch")

    decision, requested, executed, failed_closed, unavailable = None, [], {}, False, False
    if not tap_entries:
        if not without_analysis and not page_timeout:
            errors.append("no_bridge_request")
    else:
        if len(tap_entries) > 1:
            errors.append("multiple_bridge_requests")
        for entry in tap_entries:  # every request and response of this send is asserted, not only the last
            if entry.get("request") is None:
                errors.append(entry.get("error") or "bridge_request_undecoded")
                continue
            names = require_explicit_request_layers(entry["request"]["layer_values"])
            assert_requested_layers(names, expected)
            if entry["request"]["text_sha256"] not in (sha256_text(item["text"]), sha256_text(item["text"].strip())):
                errors.append("bridge_text_mismatch")
            response = entry.get("response")
            if response is not None and not (response["error"] and not response["layers"]):
                assert_executed_layers(response["layers"], expected, expected_checksum, response.get("metadata"))
        entry = tap_entries[-1]
        if entry.get("request") is not None:
            requested = require_explicit_request_layers(entry["request"]["layer_values"])
        response = entry.get("response")
        if response is None:
            if not page_timeout:
                errors.append(entry.get("error") or "no_bridge_response")
        elif response["error"] and not response["layers"]:
            if not page_timeout:
                errors.append("runtime_error")
        else:
            executed = assert_executed_layers(response["layers"], expected, expected_checksum, response.get("metadata"))
            summary = response_summary(response)
            decision, failed_closed = response["action"], summary["failed_closed"]
            expected_page_action, unavailable = interception_response(response)
            page_action = results[-1].get("action") if results else None
            if page_action and page_action != expected_page_action:
                errors.append("page_bridge_decision_mismatch")
    if page_timeout:
        # warn_shown is what the driver found in the DOM (#privoke-inspection-unavailable), not an assumption;
        # without the notice the request went out unwarned: an ALLOW, and an evasion for a protected baseline.
        warn_shown, failed_closed, unavailable = outcome.get("unavailableNotice") is True, True, True
    if (disposition == "BLOCKED_LOCALLY" and receiver_got) or (disposition in DISPOSITION_HANDED_OFF and not receiver_got):
        errors.append("disposition_receiver_mismatch")
    page_error = outcome.get("errorName")
    if page_error and not (decision == "BLOCK" and not receiver_got):
        errors.append(f"page_error:{page_error}")
    return {
        "seed_id": item["seed_id"], "variant": item["variant"], "family": item["family"],
        "value_removing": item["value_removing"], "applicable": item["applicable"], "browser": browser,
        "attended": attended, "receiver_got": receiver_got, "payload_intact": intact, "warn_shown": warn_shown,
        "decision": decision, "layers_requested": requested, "layers_executed": executed,
        "error": ";".join(errors) if errors else None, "failed_closed": failed_closed,
        "inspection_unavailable": unavailable, "request_disposition": disposition, "page_timeout": bool(page_timeout),
        "elapsed_ms": elapsed_ms, "detector_level": None, "e2e_outcome": None, "scope_label": SCOPE_LABEL,
    }


def delivered_without_analysis(row: dict) -> bool:
    return (not row["error"] and row["receiver_got"] and row["payload_intact"] and row["decision"] is None
            and not row["layers_requested"] and not row["failed_closed"])


def e2e_action(row: dict) -> str | None:
    """Observed end-to-end action, or None when the row cannot be classified.

    BLOCK: the receiver got nothing and the bridge decided BLOCK. WARN: delivered intact after the
    notice was shown. ALLOW: delivered intact with no notice, including a request forwarded without
    analysis. A runtime fail-closed decision that the page turned into a fail-open WARN (or a page-side
    analysis timeout) is observed as the WARN the user saw, not as the bridge's BLOCK; ``failed_closed``
    stays true so it is labelled ``fail_closed`` and a BLOCK baseline counts as a downgrade.
    Delivered but altered, or not delivered for any other reason, is unclassified.
    """
    if row["error"]:
        return None
    if not row["receiver_got"]:
        return "BLOCK" if row["decision"] == "BLOCK" else None
    if not row["payload_intact"]:
        return None
    return "WARN" if row["warn_shown"] else "ALLOW"


def baseline_key(row: dict) -> tuple:
    return (row["seed_id"], row["browser"], row["attended"])


def annotate_outcomes(rows: list[dict]) -> list[dict]:
    """Fill ``e2e_outcome`` of each variant row from its seed's end-to-end baseline (in place).

    null for baseline rows, rows that are not applicable, and rows whose baseline is unprotected,
    unclassified or fail-closed (such a seed is listed as excluded by the scoring, never as protected).
    """
    baselines: dict[tuple, dict] = {baseline_key(r): r for r in rows if r["variant"] == BASELINE}
    for row in rows:
        row["e2e_outcome"] = None
        if row["variant"] == BASELINE or not row["applicable"]:
            continue
        base = baselines.get(baseline_key(row))
        intended = e2e_action(base) if base else None
        if intended is None or intended == "ALLOW" or base["failed_closed"]:
            continue
        action = e2e_action(row)
        if action is None:
            row["e2e_outcome"] = "not_delivered_other"
        elif row["failed_closed"] and action != "ALLOW":
            row["e2e_outcome"] = "fail_closed"
        elif action == "ALLOW":
            row["e2e_outcome"] = "evaded"
        elif intended == "BLOCK" and action == "WARN":
            row["e2e_outcome"] = "downgraded"
        else:
            row["e2e_outcome"] = "protected"
    return rows


def attach_detector(rows: list[dict], detector: dict[str, dict]) -> list[dict]:
    """Join the in-process records (keyed by ``seed::variant``) into ``detector_level`` (in place)."""
    for row in rows:
        record = detector.get(f"{row['seed_id']}::{row['variant']}")
        row["detector_level"] = None if record is None else {
            "action": record["action"], "failed_closed": record["failed_closed"],
            "layers_executed": record["layer_status"]}
    return rows


# ---------------------------------------------------------------- scoring (Stage 3 functions, same pair set)
def _clean(value):
    if isinstance(value, float) and (math.isnan(value) or math.isinf(value)):
        return None
    if isinstance(value, dict):
        return {k: _clean(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_clean(v) for v in value]
    return value


def arm_tables(pairs: list[dict], removing: dict[str, bool], groups: dict[str, str]) -> dict:
    """Stage 3 summaries of one arm on its pairs, with and without the value-removing families."""
    keep = [p for p in pairs if not removing[p["variant"]]]
    overall, overall_keep = ae.summarise_pairs(pairs), ae.summarise_pairs(keep)
    overall["asr_conditional_cluster_bootstrap_95"] = list(ae.cluster_bootstrap(pairs, groups))
    overall_keep["asr_conditional_cluster_bootstrap_95"] = list(ae.cluster_bootstrap(keep, groups))
    return _clean({
        "overall": overall, "overall_excluding_value_removing": overall_keep,
        "by_family": {f: ae.summarise_pairs(g) for f, g in sorted(ae.group_pairs(pairs, "family").items())},
        "by_variant": {v: ae.summarise_pairs(g) for v, g in sorted(ae.group_pairs(pairs, "variant").items())},
        "best_of_all_variants_per_row": ae.per_row_any(pairs)})


def paired_conditional(e2e_pairs: list[dict], det_pairs: list[dict], removing: dict[str, bool] | None = None) -> dict:
    """Both arms on the intersection of their protected pairs, with an exact McNemar test."""
    det = {(p["row"], p["variant"]): p for p in det_pairs}
    b = c = both = neither = 0
    for pair in e2e_pairs:
        other = det[(pair["row"], pair["variant"])]
        if pair["before"] == "ALLOW" or other["before"] == "ALLOW":
            continue
        if removing is not None and removing[pair["variant"]]:
            continue
        e2e_ev, det_ev = pair["after"] == "ALLOW", other["after"] == "ALLOW"
        b += e2e_ev and not det_ev
        c += det_ev and not e2e_ev
        both += e2e_ev and det_ev
        neither += (not e2e_ev) and (not det_ev)
    n = b + c + both + neither
    return {"protected_in_both": n, "evaded_e2e_only": b, "evaded_detector_only": c, "evaded_both": both,
            "evaded_neither": neither, "asr_conditional_e2e": ae.rate(b + both, n),
            "asr_conditional_detector": ae.rate(c + both, n), "exact_mcnemar_p": ae.exact_mcnemar(b, c)}


def score_group(rows: list[dict], groups: dict[str, str] | None = None) -> dict:
    """Score one (browser, attended) group of rows. Needs ``detector_level`` joined into the rows."""
    groups = groups or {}
    by_vid = {f"{r['seed_id']}::{r['variant']}": r for r in rows}
    e2e_scores, det_scores = {}, {}
    for vid, row in by_vid.items():
        action = e2e_action(row)
        if action is not None:
            e2e_scores[vid] = {"action": action, "failed_closed": bool(row["failed_closed"])}
        if row["detector_level"] is not None:
            det_scores[vid] = {"action": row["detector_level"]["action"],
                               "failed_closed": bool(row["detector_level"]["failed_closed"])}
    seeds = sorted({r["seed_id"] for r in rows})
    intended = {"e2e": {}, "det": {}}
    seed_reasons: dict[str, list[str]] = {}
    for seed in seeds:
        vid = f"{seed}::{BASELINE}"
        reasons = []
        for arm, scores in (("e2e", e2e_scores), ("det", det_scores)):
            record = scores.get(vid)
            label = {"e2e": "e2e", "det": "detector"}[arm]
            if record is None:
                reasons.append(f"baseline_not_scored_{label}")
            elif record["failed_closed"]:
                reasons.append(f"baseline_failed_closed_{label}")
            else:
                intended[arm][seed] = record["action"]
        seed_reasons[seed] = reasons
    items, excluded = [], []
    for row in rows:
        if row["variant"] == BASELINE or not row["applicable"]:
            continue
        vid = f"{row['seed_id']}::{row['variant']}"
        reasons = list(seed_reasons[row["seed_id"]])
        if vid not in e2e_scores:
            reasons.append("variant_not_scored_e2e")
        if vid not in det_scores:
            reasons.append("variant_not_scored_detector")
        if reasons:
            excluded.append({"seed_id": row["seed_id"], "variant": row["variant"], "reasons": reasons})
        else:
            items.append({"vid": vid, "row_id": row["seed_id"], "variant": row["variant"], "family": row["family"],
                          "applicable": True})
    removing = {r["variant"]: bool(r["value_removing"]) for r in rows}
    seed_groups = {s: groups.get(s, s) for s in seeds}
    scored_seeds = [s for s in seeds if s in intended["e2e"] and s in intended["det"]]
    arms, pair_lists = {}, {}
    for arm, label, scores in (("e2e", "end_to_end", e2e_scores), ("det", "detector_level", det_scores)):
        arm_result = {"intended_actions": {a: sum(1 for s in scored_seeds if intended[arm][s] == a) for a in ACTIONS}}
        for level, detect in (("action_level", False), ("detection_level", True)):
            pairs = ae.evaluate_arm(items, intended[arm], scores, detect_level=detect)
            arm_result[level] = arm_tables(pairs, removing, seed_groups)
            pair_lists[(arm, level)] = pairs
        arm_result["protected_baselines"] = sum(1 for s in scored_seeds if intended[arm][s] != "ALLOW")
        arms[label] = arm_result
    e2e_pairs, det_pairs = pair_lists[("e2e", "action_level")], pair_lists[("det", "action_level")]
    outcomes = Counter(r["e2e_outcome"] for r in rows if r["e2e_outcome"])
    family_outcomes: dict[str, Counter] = defaultdict(Counter)
    for r in rows:
        if r["e2e_outcome"]:
            family_outcomes[r["family"]][r["e2e_outcome"]] += 1
        if r["page_timeout"]:
            family_outcomes[r["family"]]["page_timeout_fail_open"] += 1
    anomalies = {
        "delivered_despite_block": sum(1 for r in rows if r["decision"] == "BLOCK" and r["receiver_got"]
                                       and not r["failed_closed"]),
        "delivered_without_analysis": sum(1 for r in rows if delivered_without_analysis(r)),
        "page_timeout_fail_open": sum(1 for r in rows if r["page_timeout"]),
        "page_timeout_without_notice": sum(1 for r in rows if r["page_timeout"] and not r["warn_shown"]),
        "masked_request_handed_off": sum(1 for r in rows if r["request_disposition"] == "MASKED_REQUEST_HANDED_OFF"),
        "warn_decision_notice_not_shown": sum(1 for r in rows if r["decision"] == "WARN" and r["receiver_got"]
                                              and not r["warn_shown"]),
        "rows_with_error": sum(1 for r in rows if r["error"]),
        "failed_closed_rows": sum(1 for r in rows if r["failed_closed"]),
    }
    return _clean({
        "seeds": len(seeds), "seeds_scored_in_both_arms": len(scored_seeds),
        "applicable_pairs_sent": sum(1 for r in rows if r["variant"] != BASELINE and r["applicable"]),
        "pairs_scored_in_both": len(items), "pairs_excluded": len(excluded),
        "excluded_by_reason": dict(sorted(Counter(x for e in excluded for x in e["reasons"]).items())),
        "excluded_pairs": excluded,
        "arms": arms,
        "paired_conditional": {"all_families": paired_conditional(e2e_pairs, det_pairs),
                               "excluding_value_removing": paired_conditional(e2e_pairs, det_pairs, removing)},
        "e2e_outcomes": {name: outcomes.get(name, 0) for name in E2E_OUTCOMES},
        "outcomes_by_family": {f: {name: family_outcomes[f].get(name, 0) for name in E2E_OUTCOMES + ("page_timeout_fail_open",)}
                               for f in sorted(family_outcomes)},
        "anomalies": anomalies})


# ---------------------------------------------------------------- detector-level arm (in process)
def score_detector_items(items: list[dict], analyse, expected: tuple[str, ...], out_path: Path,
                         expected_checksum: str | None = None) -> int:
    """Score run-set items with an in-process client; resume-safe, never an empty layer list.

    ``analyse(text, request_id)`` is ``adversarial_evasion.Runtime.analyse``. The Stage 3 client
    always requests all three layers, so any other configured set is refused.
    """
    expected = parse_layers(expected)
    if expected != LAYER_ORDER:
        raise LayerConfigError("the Stage 3 in-process client requests regex, ner and semantic only")
    done = set(ae.load_scores(out_path)) if out_path.exists() else set()
    count = 0
    with out_path.open("a", encoding="utf-8", newline="\n") as handle:
        for item in items:
            if not item["applicable"] or item["vid"] in done:
                continue
            response = analyse(item["text"], item["vid"])
            assert_executed_layers(response["layers"], expected, expected_checksum, response.get("metadata"))
            summary = response_summary(response)
            record = {"vid": item["vid"], "action": summary["action"], "failed_closed": summary["failed_closed"],
                      "layer_status": summary["layer_status"], "layer_action": summary["layer_action"],
                      "errored": summary["errored"], "scope_label": DETECTOR_SCOPE_LABEL}
            handle.write(ae.canonical_line(record) + "\n")
            handle.flush()
            count += 1
    return count


# ---------------------------------------------------------------- the run (browsers, supervisor, receiver)
class RunAborted(RuntimeError):
    """The run stopped on a layer mismatch, a refused host or too many consecutive errors."""


def send_item(driver, receiver, tap, item: dict, browser: str, attended: bool, expected: tuple[str, ...],
              shape_url: str, send_id: str, timeout_ms: int = 120_000, expected_checksum: str | None = None) -> dict:
    """Send one item through the page and build its row. The driver, receiver and tap are injected."""
    require_fixture_host(shape_url)
    mark = tap.mark()
    started = time.monotonic()
    reply = driver.request("send", timeout=timeout_ms / 1000 + 30, prompt=item["text"], sendId=send_id,
                           shape=BASE_SHAPE, timeoutMs=timeout_ms)
    elapsed = (time.monotonic() - started) * 1000.0
    time.sleep(0.15)  # the bridge response and the receiver record land just after the page settles
    captures = receiver.captures_for(send_id)
    return build_row(item, browser, attended, expected, reply, captures, tap.since(mark), elapsed, expected_checksum)


def run_items(driver, receiver, tap, items: list[dict], browser: str, attended: bool, expected: tuple[str, ...],
              shape_url: str, rows_path: Path, max_consecutive_errors: int = 10, progress=None,
              expected_checksum: str | None = None) -> list[dict]:
    """Send every applicable item once, appending rows; resumes after a stop. Aborts on any layer mismatch."""
    done = set()
    if rows_path.exists():
        done = {(r["seed_id"], r["variant"]) for r in read_jsonl(rows_path)}
    rows, consecutive = [], 0
    with rows_path.open("a", encoding="utf-8", newline="\n") as handle:
        for index, item in enumerate(items):
            if not item["applicable"] or (item["seed_id"], item["variant"]) in done:
                continue
            send_id = f"s{index:07d}"
            try:
                row = send_item(driver, receiver, tap, item, browser, attended, expected, shape_url, send_id,
                                expected_checksum=expected_checksum)
            except (LayerMismatchError, LayerConfigError, HostRefusedError) as exc:
                raise RunAborted(f"{type(exc).__name__}: {exc}") from exc
            consecutive = consecutive + 1 if row["error"] else 0
            handle.write(json.dumps(row, sort_keys=True) + "\n")
            handle.flush()
            rows.append(row)
            if progress:
                progress(index, len(items), row)
            if consecutive >= max_consecutive_errors:
                raise RunAborted(f"{consecutive} consecutive rows with errors; last: {row['error']}")
    return rows


def _pilot_summary(rows: list[dict]) -> dict:
    times = [r["elapsed_ms"] for r in rows if r.get("elapsed_ms") is not None]
    return {"sends": len(rows), "mean_seconds_per_send": (sum(times) / len(times) / 1000.0) if times else None,
            "max_seconds": (max(times) / 1000.0) if times else None}


def release_identity(release_root: Path, model_id: str = STACK_MODEL_ID) -> dict:
    """The semantic artifact checksum (sha256 of the release manifest) the stack must serve."""
    manifest = Path(release_root) / model_id / "manifest.json"
    if not manifest.is_file():
        raise HarnessError(f"release manifest {manifest} is missing")
    return {"model_id": model_id, "artifact_checksum": ae.file_sha256(manifest), "release_dir": str(manifest.parent)}


def check_stack(health: dict, packages: dict[str, dict], identity: dict, target: str = STACK_TARGET) -> dict:
    """Model streaming must be SERVING and serve ``identity`` both by id and as the ``latest`` alias.

    ``packages`` maps the requested id ("" is the extension's default, the latest alias) to the
    package response fields ``model_id`` and ``manifest_sha256``.
    """
    problems = []
    if (health or {}).get("status") != "SERVING":
        problems.append(f"health is {(health or {}).get('status')!r}, not SERVING")
    for requested in (identity["model_id"], ""):
        package = packages.get(requested) or {}
        label = requested or "latest"
        if package.get("model_id") != identity["model_id"]:
            problems.append(f"{label} serves model {package.get('model_id')!r}, not {identity['model_id']!r}")
        if package.get("manifest_sha256") != identity["artifact_checksum"]:
            problems.append(f"{label} serves manifest {package.get('manifest_sha256')!r}, release has {identity['artifact_checksum']!r}")
    if problems:
        raise HarnessError("model streaming stack check failed: " + "; ".join(problems))
    return {"target": target, "model_id": identity["model_id"], "artifact_checksum": identity["artifact_checksum"],
            "health": health["status"], "served_as_latest": True}


def probe_stack(target: str, identity: dict, timeout: float = 15.0) -> dict:
    """Ask the running model-streaming service (gRPC, loopback) what it serves. Starts nothing."""
    import grpc
    for generated in (ROOT / "extension" / "runtime-supervisor" / "generated", HERE / "generated"):
        if generated.is_dir() and str(generated) not in sys.path:
            sys.path.append(str(generated))
    try:
        from privoke.v1 import parameters_pb2, parameters_pb2_grpc
    except ImportError as exc:
        raise HarnessError(f"generated gRPC clients are missing ({exc}); run evaluation/setup-host.py") from exc
    require_loopback_target(target)
    try:
        with grpc.insecure_channel(target) as channel:
            stub = parameters_pb2_grpc.ModelStreamingServiceStub(channel)
            health = stub.Health(parameters_pb2.HealthRequest(), timeout=timeout)
            packages = {}
            for requested in (identity["model_id"], ""):
                reply = stub.GetModelPackage(parameters_pb2.ModelParametersRequest(
                    consumer_id="e2e-evasion-stack-check", model_id=requested), timeout=timeout)
                packages[requested] = {"model_id": reply.model_id, "manifest_sha256": reply.manifest_sha256}
    except grpc.RpcError as exc:
        raise HarnessError(f"model streaming at {target} is not reachable: {exc.code().name}. Start the local Docker "
                           "server stack first (see --help).") from exc
    return check_stack({"status": health.status}, packages, identity, target)


def require_loopback_target(target: str) -> None:
    host = target.rsplit(":", 1)[0].strip("[]")
    if host not in ("127.0.0.1", "localhost", "::1"):
        raise HostRefusedError(f"stack target {target!r} is not a loopback address; refusing")


def stack_compose_override(release_root: Path) -> str:
    """Compose override that points the release bind mount at the main checkout's standard releases."""
    source = str(Path(release_root).as_posix())
    return ("services:\n  model-streaming-service:\n    volumes:\n      - type: bind\n"
            f"        source: \"{source}\"\n        target: /model-releases\n        read_only: true\n"
            "        bind: {create_host_path: false}\n")


def stack_compose_prefix(override: Path) -> str:
    return (f'docker compose -p {STACK_COMPOSE_PROJECT} -f docker-compose.prod.yml -f evaluation/compose.localhost.yml '
            f'-f "{Path(override).as_posix()}"')


def stack_up_command(override: Path) -> str:
    return f"{stack_compose_prefix(override)} up -d --build --wait --wait-timeout 240 model-streaming-service"


def stack_stop_command(override: Path) -> str:
    return f"{stack_compose_prefix(override)} stop model-streaming-service"


E2E_DRIVER = ROOT / "extension" / "test" / "e2e-evasion-driver.mjs"
WARMUP_TEXT = "Please explain the steps in this process."
WARMUP_SECONDS = 150.0
BRIDGE_PORT, UPSTREAM_BRIDGE_PORT, DETECTOR_PORT, STUDY_CONTROL_PORT, DECOY_CONTROL_PORT = 8080, 8081, 50057, 50066, 50056


class E2EDriver:
    """Newline-JSON client of ``e2e-evasion-driver.mjs`` (the Stage 11 driver is not edited)."""

    def __init__(self, node: str) -> None:
        self.process = subprocess.Popen([node, str(E2E_DRIVER)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, text=True, encoding="utf8", cwd=str(ROOT / "extension"))
        self.next_id = 0
        self.stderr_lines: list[str] = []
        threading.Thread(target=lambda: [self.stderr_lines.append(line) for line in self.process.stderr], daemon=True).start()

    def request(self, op: str, timeout: float = 180.0, **fields) -> dict:
        self.next_id += 1
        self.process.stdin.write(json.dumps({"id": self.next_id, "op": op, **fields}) + "\n")
        self.process.stdin.flush()
        holder: dict = {}

        def read() -> None:
            holder["line"] = self.process.stdout.readline()

        reader = threading.Thread(target=read, daemon=True)
        reader.start()
        reader.join(timeout)
        if reader.is_alive() or not holder.get("line"):
            return {"error": f"driver did not answer {op} within {timeout}s", "stderr": self.stderr_lines[-5:]}
        return json.loads(holder["line"])

    def close(self) -> None:
        try:
            self.request("close", timeout=20)
        except Exception:  # noqa: BLE001 - the process is killed next
            pass
        if self.process.poll() is None:
            self.process.kill()


def preflight(driver, tap, expected: tuple[str, ...], seconds: float = WARMUP_SECONDS, pause: float = 3.0,
              expected_checksum: str | None = None) -> dict:
    """Warm up and prove that the installed extension requests, and the runtime executes, the configured layers.

    The extension silently drops the semantic layer from its request while streaming is unavailable
    (``SemanticAvailability``), so this retries for ``seconds`` and then stops the run; it never
    continues with a smaller layer set.
    """
    started, attempts, last = time.monotonic(), 0, "no analysis request reached the bridge"
    while True:
        attempts += 1
        mark = tap.mark()
        driver.request("send", timeout=90, prompt=WARMUP_TEXT, sendId=f"warmup{attempts}", shape=BASE_SHAPE, timeoutMs=60_000)
        entries = tap.since(mark)
        entry = entries[-1] if entries else None
        if entry and entry.get("request") and entry.get("response") and not entry["response"]["error"]:
            requested = require_explicit_request_layers(entry["request"]["layer_values"])
            last = f"requested {requested}"
            if set(requested) == set(expected):
                assert_executed_layers(entry["response"]["layers"], expected, expected_checksum, entry["response"].get("metadata"))
                return {"ready": True, "attempts": attempts, "seconds": round(time.monotonic() - started, 1),
                        "layers_requested": requested}
        if time.monotonic() - started >= seconds:
            break
        time.sleep(pause)
    raise LayerMismatchError(f"the installed runtime did not request and execute {list(expected)} within {seconds:.0f}s "
                             f"({last}); the semantic layer may be unavailable. Stopping instead of dropping a layer.")


def _port_open(port: int) -> bool:
    import socket
    with socket.socket() as sock:
        sock.settimeout(0.5)
        return sock.connect_ex(("127.0.0.1", port)) == 0


@contextlib.contextmanager
def lock_scope(args):
    """Hold the host lock for a run: take it, or accept the caller's (``lock acquire``) without releasing it."""
    lock = HostLock(args.stage)
    if args.lock_held:
        yield lock.verify_held()
    else:
        with lock:
            yield lock


def start_supervisor(supervisor, xp, runtime_env: dict[str, str]) -> None:
    """Start the real supervisor (and through it the real bridge and detector) on non-default loopback ports."""
    env = dict(os.environ)
    env.update({"PRIVOKE_RUNTIME_PYTHON": supervisor.python, "PRIVOKE_RUNTIME_START_ENABLED": "true",
                "PRIVOKE_CONTROL_GRPC_PORT": str(STUDY_CONTROL_PORT),
                "PRIVOKE_GRPC_WEB_PORT": str(UPSTREAM_BRIDGE_PORT)})
    env.update(runtime_env)
    log = supervisor.log_path.open("ab", buffering=0)
    supervisor.process = subprocess.Popen(
        [supervisor.python, str(xp.SUPERVISOR_MAIN)], cwd=str(xp.SUPERVISOR_MAIN.parents[1]), env=env,
        stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW)


def execute_run(args) -> int:
    """Run the installed-extension sends for each browser. The host lock is held before the stack is probed."""
    parse_layers(args.layers)
    ensure_out_dir(args.out)
    if not args.stack and not args.expected_checksum:
        raise HarnessError("--no-stack needs --expected-checksum: both arms must be checked against one model")
    with lock_scope(args):
        return _execute_run(args)


def _execute_run(args) -> int:
    import cross_platform_study as xp
    from cross_platform_receiver import Receiver, generate_certificate
    from cross_platform_probes import load_shapes

    expected = parse_layers(args.layers)
    out = ensure_out_dir(args.out)
    all_items = read_jsonl(Path(args.run_set))
    items = pilot_items(all_items) if args.pilot else all_items
    browsers = [name.strip() for name in args.browsers.split(",") if name.strip()]
    unknown = [b for b in browsers if b not in xp.BROWSERS]
    if unknown:
        raise HarnessError(f"unknown browsers {unknown}")
    # The local stack setting points the supervisor's runtime at the loopback model-streaming service
    # (the Docker server stack); the stack check below proves it serves V3 balanced before any send.
    runtime_env = {"PRIVOKE_USE_LOCAL_STACK": "true", "PRIVOKE_LOCAL_MODEL_STREAMING_TARGET": args.stack_target,
                   "PRIVOKE_LLM_CHOICE": "streamed"}
    for pair in args.runtime_env:
        name, _, value = pair.partition("=")
        runtime_env[name] = value
    shape = next(s for s in load_shapes()["shapes"] if s["id"] == BASE_SHAPE)
    require_fixture_host(shape["url"])
    page_url = f"https://{host_of(shape['url'])}/"
    busy = [p for p in (BRIDGE_PORT, UPSTREAM_BRIDGE_PORT, DECOY_CONTROL_PORT, DETECTOR_PORT, STUDY_CONTROL_PORT,
                        args.receiver_port) if _port_open(p)]
    if busy:
        raise HarnessError(f"loopback ports already in use, refusing to touch another runtime: {busy}")
    stack_identity = None
    if args.stack:
        stack_identity = probe_stack(args.stack_target, release_identity(Path(args.release_root)))
    elif not args.expected_checksum:
        raise HarnessError("--no-stack needs --expected-checksum: both arms must be checked against one model")
    expected_checksum = args.expected_checksum or stack_identity["artifact_checksum"]

    class Supervisor(xp.Supervisor):
        def start(self) -> None:
            start_supervisor(self, xp, runtime_env)

        def wait_ready(self, timeout: float = 180.0) -> bool:
            return xp.wait_for(lambda: _port_open(UPSTREAM_BRIDGE_PORT) and _port_open(DETECTOR_PORT), timeout)

    meta: dict = {"schema": SCHEMA, "kind": "run_meta", "scope_label": SCOPE_LABEL, "stage": args.stage,
                  "layers": list(expected), "pilot": bool(args.pilot), "commands": [" ".join(sys.argv)],
                  "template_sha256": lf_sha256(e2etx.template_file()), "items_in_run_set": len(all_items),
                  "items_sent_planned": sum(1 for i in items if i["applicable"]), "browsers": [],
                  "runtime_env_keys": sorted(runtime_env), "aborted": None, "stack": stack_identity,
                  "expected_checksum": expected_checksum, "settings": dict(SETTINGS_IN_PROFILE),
                  "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    workdir = Path(args.workdir) if args.workdir else Path(tempfile.mkdtemp(prefix="e2e-evasion-"))
    workdir.mkdir(parents=True, exist_ok=True)
    node = shutil.which("node") or "node"
    cert, key, spki = generate_certificate(workdir / "cert", args.openssl)
    receiver = Receiver(cert, key, args.receiver_port)
    supervisor = Supervisor(args.runtime_python, workdir / "supervisor.log")
    tap = BridgeTap(UPSTREAM_BRIDGE_PORT, BRIDGE_PORT, log_path=out / "bridge_tap.jsonl")
    decoy = None
    outbound: list[str] = []
    foreign_driver: list[str] = []
    abort: Exception | None = None
    with contextlib.nullcontext():  # the host lock is held by execute_run
        try:
            receiver.start()
            tap.start()
            decoy = xp.HeldPort(DECOY_CONTROL_PORT)
            for key_name in browsers:
                spec = xp.BROWSERS[key_name]
                entry: dict = {"key": key_name, "browser": spec["label"], "family": spec["family"], "headless": True,
                               "attended": False}
                exe = next((p for p in spec["exe"] if Path(p).is_file()), None)
                dist = ROOT / "extension" / spec["dist"]
                if exe is None:
                    entry.update(status="not_run", reason="browser not installed on this host")
                elif not (dist / "manifest.json").is_file():
                    entry.update(status="not_run", reason=f"extension build missing at {dist}")
                else:
                    entry.update(executable=exe, file_version=xp.file_version(exe))
                    profile = Path(tempfile.mkdtemp(prefix=f"e2e-{key_name}-", dir=str(workdir)))
                    driver = E2EDriver(node)
                    try:
                        launched = driver.request("launch", family=spec["family"], exe=exe, userDataDir=str(profile),
                                                  extensionDir=str(dist), hosts=list(FIXTURE_HOSTS), spki=spki)
                        entry["launch"] = {k: v for k, v in launched.items() if k != "id"}
                        if launched.get("ok") is not True:
                            entry.update(status="not_run", reason="extension could not be loaded: " + str(launched.get("error")))
                        else:
                            entry["browser_version"] = launched.get("product")
                            if supervisor.process is None or supervisor.process.poll() is not None:
                                supervisor.start()
                            if not supervisor.wait_ready():
                                entry.update(status="not_run", reason="local runtime did not become ready")
                            else:
                                driver.request("open", url=page_url)
                                entry["preflight"] = preflight(driver, tap, expected, expected_checksum=expected_checksum)
                                receiver.captures.clear()
                                rows_path = out / f"rows_{key_name}.jsonl"
                                rows = run_items(driver, receiver, tap, items, key_name, False, expected, shape["url"],
                                                 rows_path, args.max_consecutive_errors,
                                                 expected_checksum=expected_checksum)
                                entry.update(status="run", rows_written=len(rows), rows_file=rows_path.name,
                                             **_pilot_summary(rows))
                                answered = driver.request("foreign")
                                entry["foreign_requests_measured"] = bool(answered.get("measured"))
                                foreign_driver += list(answered.get("requests", []))
                                pids = {supervisor.process.pid} if supervisor.process else set()
                                pids |= {pid for pid in (xp.listener_pid(DETECTOR_PORT), xp.listener_pid(UPSTREAM_BRIDGE_PORT)) if pid}
                                outbound += xp.outbound_connections(pids)
                    except (RunAborted, ae.LayerAssertionError, HarnessError) as exc:
                        entry.update(status="aborted", reason=f"{type(exc).__name__}: {exc}")
                        abort = exc
                    finally:
                        driver.close()
                        time.sleep(1)
                        shutil.rmtree(profile, ignore_errors=True)
                meta["browsers"].append(entry)
                if abort:
                    break
        finally:
            supervisor.stop()
            if decoy:
                decoy.close()
            tap.stop()
            receiver.stop()
            leftover = [p for p in (BRIDGE_PORT, UPSTREAM_BRIDGE_PORT, DECOY_CONTROL_PORT, DETECTOR_PORT,
                                    STUDY_CONTROL_PORT, args.receiver_port) if _port_open(p)]
            outside = list(receiver.foreign_hosts) + foreign_driver + outbound
            meta["host_guard"] = {
                "fixture_hosts": list(FIXTURE_HOSTS), "foreign_host_requests": list(receiver.foreign_hosts),
                "driver_foreign_requests": foreign_driver, "outbound_non_loopback_connections": outbound,
                "outside_lookups": len(outside)}
            meta["processes_started"] = ["runtime supervisor (real bridge and detector)", "bridge tap", "synthetic receiver",
                                        "decoy control port", "e2e driver and browser (one per browser)"]
            meta["leftover_ports_after_cleanup"] = leftover
            meta["unattributed_receiver_posts"] = len(receiver.unattributed())
            meta["host"] = {"platform": platform.platform(), "machine": platform.machine(),
                            "node": subprocess.run([node, "--version"], capture_output=True, text=True).stdout.strip(),
                            "python_driver": platform.python_version(),
                            "runtime_python": subprocess.run([args.runtime_python, "--version"], capture_output=True,
                                                             text=True).stdout.strip()}
            meta["extension_build"] = {"dist": xp.tree_hash(ROOT / "extension" / "dist") if (ROOT / "extension" / "dist").is_dir() else None,
                                       "dist_firefox": xp.tree_hash(ROOT / "extension" / "dist-firefox")
                                       if (ROOT / "extension" / "dist-firefox").is_dir() else None}
            meta["revision"] = xp.git("rev-parse", "HEAD")
            meta["branch"] = xp.git("rev-parse", "--abbrev-ref", "HEAD")
            meta["worktree_dirty"] = bool(xp.git("status", "--porcelain", "--untracked-files=no"))
            meta["finished_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            if abort:
                meta["aborted"] = f"{type(abort).__name__}: {abort}"
            write_json(out / ("pilot_meta.json" if args.pilot else "run_meta.json"), meta)
            log_path = workdir / "supervisor.log"
            if abort and log_path.is_file():
                shutil.copy2(log_path, out / "supervisor.log")  # kept under s13b for diagnosis; the workdir goes
            if not args.keep_workdir:
                shutil.rmtree(workdir, ignore_errors=True)  # supervisor.log, certificate and key
    if abort:
        raise RunAborted(meta["aborted"])
    return 0


def cmd_stack(args) -> int:
    identity = release_identity(Path(args.release_root))
    if args.print_command:
        out = ensure_out_dir(args.out)
        override = out / "compose.release.yml"
        override.write_text(stack_compose_override(Path(args.release_root)), encoding="utf-8", newline="\n")
        print(stack_up_command(override))
        print(stack_stop_command(override))
        return 0
    print(json.dumps(probe_stack(args.target, identity), indent=1, sort_keys=True))
    return 0


def cmd_lock(args) -> int:
    lock = HostLock(args.stage)
    if args.action == "acquire":
        lock.acquire()
        lock.held = False  # the file stays after this short process exits; ``lock release`` removes it
        print(f"host lock taken for {args.stage}: {lock.path}")
    elif args.action == "release":
        lock.verify_held()
        lock.path.unlink()
        print("host lock released")
    else:
        print(lock.path.read_text(encoding="utf-8") if lock.path.is_file() else "free")
    return 0


def cmd_verify_templates(args) -> int:
    result = verify_templates(args.expected_sha256)
    print(json.dumps(result, indent=1, sort_keys=True))
    return 0 if result["ok"] else 1


def cmd_build(args) -> int:
    if not args.exclude_ids and not args.allow_no_exclude:
        raise HarnessError("--exclude-ids FILE (the 13a seed ids) is required for disjointness from the 13a set; "
                           "pass --allow-no-exclude only for a pilot or smoke build")
    exclude = set()
    exclude_source = Path(args.exclude_ids) if args.exclude_ids else None
    if exclude_source:
        exclude = {line.strip() for line in exclude_source.read_text(encoding="utf-8").splitlines() if line.strip()}
    variants = tuple(v for v in args.variants.split(",") if v) if args.variants else ALL_VARIANTS
    plan = build_run_set(Path(args.frozen_dir), Path(args.out), args.n_seed, exclude, exclude_source, variants,
                         Path(args.seed_file) if args.seed_file else None)
    print(json.dumps({k: plan[k] for k in ("n_seed", "items", "sends_planned", "run_set_sha256", "template_sha256")}, indent=1))
    return 0


def cmd_size_seeds(args) -> int:
    plan = json.loads(Path(args.plan).read_text(encoding="utf-8"))
    pilot = _pilot_summary(read_jsonl(Path(args.pilot_rows)))
    if not pilot["mean_seconds_per_send"]:
        raise HarnessError("the pilot rows carry no timings")
    sends_per_seed = plan["sends_planned"] / plan["n_seed"]
    result = plan_seed_count(pilot["mean_seconds_per_send"], sends_per_seed, args.hours, args.floor)
    print(json.dumps({"pilot": pilot, **result}, indent=1, sort_keys=True))
    return 0


def cmd_detector(args) -> int:
    expected = parse_layers(args.layers)
    out = ensure_out_dir(args.out)
    items = read_jsonl(Path(args.run_set))
    runtime = ae.Runtime(Path(args.release_dir), "defaults", Path(args.generated))
    count = score_detector_items(items, runtime.analyse, expected, out / "detector_scores.jsonl",
                                 runtime.identity["artifact_checksum"])
    write_json(out / "detector_run_meta.json", {
        "scope_label": DETECTOR_SCOPE_LABEL, "layers": list(expected), "scored_this_run": count,
        "identity": runtime.identity, "release_files": runtime.release_files, "flags": runtime.flags})
    print(f"scored {count} items")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    v = sub.add_parser("verify-templates")
    v.add_argument("--expected-sha256", required=True)
    v.set_defaults(fn=cmd_verify_templates)
    b = sub.add_parser("build")
    b.add_argument("--out", required=True)
    b.add_argument("--n-seed", type=int, required=True)
    b.add_argument("--frozen-dir", default=str(DEFAULT_FROZEN_DIR))
    b.add_argument("--seed-file", default=None, help="F4 source file; defaults to the path in the Stage 3 manifest")
    b.add_argument("--exclude-ids", default=None, help="file of seed ids to exclude (the 13a set); required")
    b.add_argument("--allow-no-exclude", action="store_true", help="build without the 13a exclusion (pilot or smoke only)")
    b.add_argument("--variants", default=None, help="comma-separated subset; default every variant")
    b.set_defaults(fn=cmd_build)
    s = sub.add_parser("size-seeds")
    s.add_argument("--plan", required=True)
    s.add_argument("--pilot-rows", required=True)
    s.add_argument("--hours", type=float, default=HOURS_PER_BROWSER)
    s.add_argument("--floor", type=int, default=SEED_FLOOR)
    s.set_defaults(fn=cmd_size_seeds)
    d = sub.add_parser("detector")
    d.add_argument("--run-set", required=True)
    d.add_argument("--out", required=True)
    d.add_argument("--release-dir", required=True)
    d.add_argument("--generated", required=True)
    d.add_argument("--layers", default="regex,ner,semantic")
    d.set_defaults(fn=cmd_detector)
    st = sub.add_parser("stack", help="probe the running model-streaming stack, or write the compose override")
    st.add_argument("--target", default=STACK_TARGET)
    st.add_argument("--release-root", default=str(DEFAULT_RELEASE_ROOT))
    st.add_argument("--out", default=None)
    st.add_argument("--print-command", action="store_true", help="write compose.release.yml under --out and print the docker commands")
    st.set_defaults(fn=cmd_stack)
    lk = sub.add_parser("lock", help="take, show or release the shared host lock")
    lk.add_argument("action", choices=("acquire", "release", "show"))
    lk.add_argument("--stage", default="13b-2")
    lk.set_defaults(fn=cmd_lock)
    r = sub.add_parser("run")
    r.add_argument("--run-set", required=True)
    r.add_argument("--out", required=True)
    r.add_argument("--runtime-python", required=True)
    r.add_argument("--browsers", default="chrome,edge,firefox")
    r.add_argument("--layers", default="regex,ner,semantic")
    r.add_argument("--pilot", action="store_true", help=f"send only the first {PILOT_PROBES} items (timing pilot)")
    r.add_argument("--stage", default="13b-2", help="stage id written into the host lock")
    r.add_argument("--runtime-env", action="append", default=[], metavar="KEY=VALUE",
                   help="extra environment for the supervisor (default PRIVOKE_USE_LOCAL_STACK=true)")
    r.add_argument("--receiver-port", type=int, default=443)
    r.add_argument("--openssl", default="openssl")
    r.add_argument("--workdir", default=None)
    r.add_argument("--keep-workdir", action="store_true", help="keep the temporary workdir (log, certificate, key)")
    r.add_argument("--lock-held", action="store_true", help="the caller took the host lock with `lock acquire`")
    r.add_argument("--stack", action=argparse.BooleanOptionalAction, default=True,
                   help="check the local Docker model-streaming stack serves V3 balanced before any send (default on)")
    r.add_argument("--stack-target", default=STACK_TARGET)
    r.add_argument("--release-root", default=str(DEFAULT_RELEASE_ROOT))
    r.add_argument("--expected-checksum", default=None, help="semantic artifact checksum; derived from the stack check otherwise")
    r.add_argument("--max-consecutive-errors", type=int, default=10)
    r.set_defaults(fn=execute_run)
    args = parser.parse_args(argv)
    try:
        return args.fn(args)
    except (HarnessError, RunAborted, ae.LayerAssertionError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
