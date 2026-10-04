"""Pure eight-arm programme structure; never authorizes fitting or test access.

Trusted hashes must come from an independent raw-evidence consumer. Per-arm
references are canonical JSON structured-claim digests, not arbitrary raw-file
hashes; the consumer must join and verify the claims to raw evidence first. This module
checks supplied structured claims and their closed references, not files, RPCs,
review truth, source byte integrity, catalog quiescence or operator permission.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import math
import re
from collections.abc import Mapping

import numpy as np

ARM_KEYS = ("S0", "S1", "E-H", "E-F", "B-H", "B-F", "Q-H", "Q-F")
PAIRS = (("S1", "S0"), ("E-F", "E-H"), ("B-F", "B-H"), ("Q-F", "Q-H"))
PIN_ITEMS = (
    ("plan", "2dcaa5f98e3f8075bc11c7a2025b7e6e853a860819b9123f8fd319851b3dacbd"),
    ("protocol", "3991777aedadc8d50b7395a9ce8ef2aebfec946603229b823f1b6c118a16cbdf"),
    ("rubric", "203f37b4c77789a0f9c0838905954b9e1b76acf4f7906ab7717849e94616fcd7"),
    ("guide", "77c49fd5e650c9681a9766635104cb6d435bb8c9dbc7832e66ac523fcbad3ed2"),
    ("preparation", "b482e355f0689b319fd6f3ba2a69e02e0589f149a7483977526a2f45b3f0f3b0"),
    ("allocator", "a413c922d2f710f1e47e5013d42373bc42e1e695db34ed8844e1509c9402cc63"),
)
SOURCE_PIN = "02741d9f99a91b8fdcf48f4316a2c73be7a7449a"
EXTERNAL_HASH_KEYS = frozenset((
    "prepared_manifest", "historical_protection_artifact", "historical_protection_receipt",
    "fixture_addon_artifact", "fixture_addon_receipt", "combined_protected_keys",
    "fixture", "fixture_rubric", "fixture_review", "s0_fit_manifest", "s0_selection",
    "runtime_image", "evaluator_image", "training_image", "effective_configuration",
    "helper_sources", "dependency_lock", "programme_approval", "restoration_plan",
))
_ACTION = {"ALLOW": 0, "WARN": 1, "BLOCK": 2}
_HEX = re.compile(r"^[0-9a-f]{64}$")
_REV = re.compile(r"^[0-9a-f]{40}$")


class StudyContractError(ValueError):
    """Sanitized structural failure; input values never appear in errors."""


def _fail():
    raise StudyContractError("Eight-arm programme contract or evidence is invalid.")


def _closed(value, keys):
    if not isinstance(value, Mapping) or set(value) != set(keys):
        _fail()


def _hash(value):
    if type(value) is not str or not _HEX.fullmatch(value):
        _fail()
    return value


def _int(value, minimum=0):
    if type(value) is not int or value < minimum:
        _fail()
    return value


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                    ensure_ascii=False, allow_nan=False).encode()).hexdigest()


@dataclass(frozen=True)
class Arm:
    key: str
    model_id: str
    profile: str | None
    training_mode: str | None
    dimensions: tuple[int, ...]


ARMS = (Arm("S0", "privoke-presence-balanced", None, None, ()),
        Arm("S1", "privoke-presence-balanced", None, None, ())) + tuple(
    Arm(f"{letter}-{mode}", f"privoke-scratch-presence-{profile}-{suffix}", profile,
        training_mode, dimensions)
    for letter, profile, dimensions in (
        ("E", "efficient", (512, 24, 48, 64, 1, 2)),
        ("B", "balanced", (512, 32, 64, 96, 2, 4)),
        ("Q", "quality", (768, 32, 64, 128, 3, 4)))
    for mode, suffix, training_mode in (("H", "head-only", "head_only"),
                                      ("F", "full-encoder", "end_to_end")))


@dataclass(frozen=True)
class Identity:
    model_id: str
    version: str
    artifact_sha256: str
    artifact_checksum: str
    parameter_fingerprint: str


def _identity(value, model_id, version=None):
    _closed(value, Identity.__dataclass_fields__)
    if value["model_id"] != model_id or type(value["version"]) is not str:
        _fail()
    if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+(?:\+[a-z0-9.]+)?", value["version"]):
        _fail()
    if version is not None and value["version"] != version:
        _fail()
    for name in ("artifact_sha256", "artifact_checksum", "parameter_fingerprint"):
        _hash(value[name])
    return Identity(**dict(value))


@dataclass(frozen=True)
class ProgrammeContract:
    source_revision: str
    external_hashes: tuple[tuple[str, str], ...]
    original_contextual: Identity
    s0: Identity
    initialization_fingerprints: tuple[tuple[str, str], ...]
    numpy_version: str
    sha256: str


def freeze_programme(value: Mapping) -> ProgrammeContract:
    """Validate closed operator inputs and freeze independent immutable copies."""
    _closed(value, ("schema_version", "pins", "source_pin", "source_revision", "external_hashes",
                    "original_contextual", "s0", "initialization_fingerprints", "numpy_version"))
    if type(value["schema_version"]) is not int or value["schema_version"] != 1:
        _fail()
    if value["pins"] != dict(PIN_ITEMS) or value["source_pin"] != SOURCE_PIN:
        _fail()
    if type(value["source_revision"]) is not str or not _REV.fullmatch(value["source_revision"]):
        _fail()
    if value["numpy_version"] != np.__version__:
        _fail()
    _closed(value["external_hashes"], EXTERNAL_HASH_KEYS)
    external = tuple(sorted((k, _hash(v)) for k, v in value["external_hashes"].items()))
    original = _identity(value["original_contextual"], "privoke-balanced", "v0.3.0")
    if original.artifact_checksum != "8390b96871c6edd00916e3a6126da1b09c19f9fdbdda8214ebe667a893e5ee2c":
        _fail()
    s0 = _identity(value["s0"], "privoke-presence-balanced", "v1.0.0")
    _closed(value["initialization_fingerprints"], ("efficient", "balanced", "quality"))
    initial = tuple(sorted((k, _hash(v)) for k, v in value["initialization_fingerprints"].items()))
    return ProgrammeContract(value["source_revision"], external, original, s0, initial,
                             value["numpy_version"], _digest(dict(value)))


@dataclass(frozen=True)
class TrainingBudget:
    rows: int
    steps_per_epoch: int
    epochs: int
    total_steps: int


def training_budget(rows: int) -> TrainingBudget:
    """Only complete epochs, retaining the last partial batch within each epoch."""
    _int(rows, 1)
    steps = (rows + 15) // 16
    epochs = min(10, 2500 // steps)
    if epochs == 0:
        _fail()
    return TrainingBudget(rows, steps, epochs, epochs * steps)


def epoch_batches(profile: str, epoch: int, rows: int) -> tuple[tuple[int, ...], ...]:
    """Fresh per-profile RNG stream, identical order for its H/F pair.

    H/F callers supply the same profile. Epoch is one-based; replay prior RNG
    permutations rather than changing seeds or omitting incomplete batches.
    """
    if profile not in ("efficient", "balanced", "quality"):
        _fail()
    budget = training_budget(rows)
    _int(epoch, 1)
    if epoch > budget.epochs:
        _fail()
    rng = np.random.default_rng(12102026)
    for _ in range(epoch):
        order = rng.permutation(rows)
    return tuple(tuple(int(i) for i in order[start:start + 16]) for start in range(0, rows, 16))


def permutation_sha256(profile: str, epoch: int, rows: int) -> str:
    """Canonical JSON row-index order commitment, bound separately to row bytes."""
    return _digest([i for batch in epoch_batches(profile, epoch, rows) for i in batch])


def _ref(value, purpose, trusted, claim):
    _closed(value, ("purpose", "sha256"))
    if (value["purpose"] != purpose or _hash(value["sha256"]) != trusted.get(purpose)
            or value["sha256"] != _digest(claim)):
        _fail()


def _fixtures(rows):
    if type(rows) not in (list, tuple) or len(rows) != 48:
        _fail()
    result = {}
    for row in rows:
        _closed(row, ("case_sha256", "ambiguous", "required_sensitive", "required_action",
                      "visibility_hint", "ordinary_action", "action"))
        key = _hash(row["case_sha256"])
        if key in result or type(row["ambiguous"]) is not bool:
            _fail()
        if (type(row["action"]) is not str or type(row["ordinary_action"]) is not str
                or row["action"] not in _ACTION or row["ordinary_action"] not in _ACTION):
            _fail()
        if row["visibility_hint"] not in (None, "P0", "PU", "P4", "P3"):
            _fail()
        if row["ambiguous"]:
            if row["required_sensitive"] is not None or row["required_action"] is not None:
                _fail()
        elif type(row["required_sensitive"]) is not bool:
            _fail()
        elif row["required_action"] not in (("WARN", "BLOCK") if row["required_sensitive"] else ("ALLOW",)):
            _fail()
        result[key] = dict(row)
    if sum(r["ambiguous"] for r in result.values()) != 7:
        _fail()
    if sum(r["required_sensitive"] is True for r in result.values()) != 17:
        _fail()
    if sorted(r["visibility_hint"] for r in result.values() if r["visibility_hint"] is not None) != ["P0", "P3", "P4", "PU"]:
        _fail()
    return result


@dataclass(frozen=True)
class BarrierAssessment:
    contract_sha256: str
    pairwise_private_losses: tuple[tuple[str, int], ...]
    ordinary_private_losses: tuple[tuple[str, int], ...]
    baseline_private_failures: tuple[tuple[str, int], ...]
    evidence_sha256: str


def validate_pretest_barrier(contract: ProgrammeContract, records, trusted_reference_hashes: Mapping) -> BarrierAssessment:
    """Reject incomplete survivor programmes; compute fixture gates from actions.

    This is only a structural barrier. Even a returned assessment is NOT test
    authorization: a separate trusted consumer must verify referenced raw
    requests, byte commitments, truth/roles, identities and terminal restoration.
    """
    if type(contract) is not ProgrammeContract:
        _fail()
    if type(records) not in (list, tuple) or len(records) != 8:
        _fail()
    expected_references = {f"global/{key}" for key in EXTERNAL_HASH_KEYS} | {"global/original-contextual", "global/s0"}
    for arm in ARM_KEYS:
        expected_references.update(f"{arm}/{suffix}" for suffix in ("choice", "validation-rerun", "fixtures"))
        expected_references.update(f"{arm}/checkpoint/{epoch}" for epoch in ((0,) if arm.startswith("S") else range(1, 6)))
    _closed(trusted_reference_hashes, expected_references)
    for value in trusted_reference_hashes.values():
        _hash(value)
    for key, value in contract.external_hashes:
        if trusted_reference_hashes[f"global/{key}"] != value:
            _fail()
    if (trusted_reference_hashes["global/original-contextual"] != contract.original_contextual.artifact_sha256
            or trusted_reference_hashes["global/s0"] != contract.s0.artifact_sha256):
        _fail()
    reconstructed = freeze_programme({"schema_version": 1, "pins": dict(PIN_ITEMS), "source_pin": SOURCE_PIN,
        "source_revision": contract.source_revision, "external_hashes": dict(contract.external_hashes),
        "original_contextual": dict(vars(contract.original_contextual)), "s0": dict(vars(contract.s0)),
        "initialization_fingerprints": dict(contract.initialization_fingerprints), "numpy_version": contract.numpy_version})
    if reconstructed != contract:
        _fail()
    by_arm = {}
    for record in records:
        _closed(record, ("arm", "status", "contract_sha256", "checkpoints", "selected_epoch",
                         "selected_identity", "threshold", "choice_ref", "rerun_ref", "fixture_ref",
                         "validation_rows", "validation_errors", "parity_matched_rows",
                         "validation_recall", "fixture_errors", "fixtures"))
        arm = record["arm"]
        if arm not in ARM_KEYS or arm in by_arm or record["status"] != "complete":
            _fail()
        if record["contract_sha256"] != contract.sha256:
            _fail()
        if type(record["threshold"]) is not float or not math.isfinite(record["threshold"]) or not 0 <= record["threshold"] <= 1:
            _fail()
        if type(record["validation_recall"]) is not float or not math.isfinite(record["validation_recall"]) or not .9 <= record["validation_recall"] <= 1:
            _fail()
        for name, expected in (("validation_rows", 2000), ("validation_errors", 0),
                               ("parity_matched_rows", 2000), ("fixture_errors", 0)):
            if type(record[name]) is not int or record[name] != expected:
                _fail()
        claims = {
            "choice": {key: record[key] for key in ("arm", "contract_sha256", "selected_epoch", "selected_identity", "threshold")},
            "validation-rerun": {key: record[key] for key in ("arm", "contract_sha256", "selected_identity", "threshold", "validation_rows", "validation_errors", "parity_matched_rows", "validation_recall")},
            "fixtures": {key: record[key] for key in ("arm", "contract_sha256", "selected_identity", "threshold", "fixture_errors", "fixtures")},
        }
        for name, suffix in (("choice_ref", "choice"), ("rerun_ref", "validation-rerun"), ("fixture_ref", "fixtures")):
            _ref(record[name], f"{arm}/{suffix}", trusted_reference_hashes, claims[suffix])
        definition = ARMS[ARM_KEYS.index(arm)]
        expected_epochs = (0,) if arm.startswith("S") else tuple(range(1, training_budget(7832).epochs + 1))
        checkpoints = record["checkpoints"]
        if type(checkpoints) not in (list, tuple) or len(checkpoints) != len(expected_epochs):
            _fail()
        identities = {}
        for checkpoint, epoch in zip(checkpoints, expected_epochs):
            _closed(checkpoint, ("epoch", "steps", "identity", "initialization_sha256", "permutation_sha256", "evidence_ref",
                                 "validation_rows", "validation_errors", "gate_zero_parity_matched_rows"))
            if type(checkpoint["epoch"]) is not int or checkpoint["epoch"] != epoch:
                _fail()
            for name, expected in (("validation_rows", 2000), ("validation_errors", 0), ("gate_zero_parity_matched_rows", 2000)):
                if type(checkpoint[name]) is not int or checkpoint[name] != expected:
                    _fail()
            expected_steps = epoch * training_budget(7832).steps_per_epoch
            if type(checkpoint["steps"]) is not int or checkpoint["steps"] != expected_steps:
                _fail()
            identity = _identity(checkpoint["identity"], definition.model_id,
                                 f"v1.0.0+epoch.{epoch}" if epoch else "v1.0.0")
            if epoch:
                if checkpoint["initialization_sha256"] != dict(contract.initialization_fingerprints)[definition.profile]:
                    _fail()
                if checkpoint["permutation_sha256"] != permutation_sha256(definition.profile, epoch, 7832):
                    _fail()
            elif checkpoint["initialization_sha256"] is not None or checkpoint["permutation_sha256"] is not None:
                _fail()
            _ref(checkpoint["evidence_ref"], f"{arm}/checkpoint/{epoch}", trusted_reference_hashes,
                 {"arm": arm, "contract_sha256": contract.sha256,
                  **{key: value for key, value in checkpoint.items() if key != "evidence_ref"}})
            identities[epoch] = identity
        _int(record["selected_epoch"])
        selected = _identity(record["selected_identity"], definition.model_id)
        if identities.get(record["selected_epoch"]) != selected or (arm == "S0" and selected != contract.s0):
            _fail()
        by_arm[arm] = (_fixtures(record["fixtures"]), record)
    if set(by_arm) != set(ARM_KEYS):
        _fail()
    baseline_rows = by_arm["S0"][0]
    for rows, _ in by_arm.values():
        if set(rows) != set(baseline_rows):
            _fail()
        for key, row in rows.items():
            if any(row[field] != baseline_rows[key][field] for field in
                   ("ambiguous", "required_sensitive", "required_action", "visibility_hint", "ordinary_action")):
                _fail()
    def losses(rows, reference_field, reference_rows=None):
        return sum(1 for key, row in rows.items() if row["required_sensitive"] is True
                   and _ACTION[(reference_rows[key]["action"] if reference_rows else row[reference_field])]
                   >= _ACTION[row["required_action"]] > _ACTION[row["action"]])
    pairwise = tuple((arm, losses(by_arm[arm][0], "action", by_arm[reference][0])) for arm, reference in PAIRS)
    if any(count for _, count in pairwise):
        _fail()
    ordinary = tuple((arm, losses(by_arm[arm][0], "ordinary_action")) for arm in ARM_KEYS)
    failures = tuple((arm, sum(row["required_sensitive"] is True and
                              _ACTION[row["action"]] < _ACTION[row["required_action"]]
                              for row in by_arm[arm][0].values())) for arm in ARM_KEYS)
    return BarrierAssessment(contract.sha256, pairwise, ordinary, failures, _digest(records))
