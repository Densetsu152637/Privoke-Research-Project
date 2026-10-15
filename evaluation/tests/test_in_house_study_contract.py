"""Synthetic structural claims only; these hashes are NOT real study evidence."""
from __future__ import annotations
import copy
from dataclasses import FrozenInstanceError
import hashlib
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "evaluation"))
sys.path.insert(0, str(ROOT / "shared/python"))
import numpy as np
from privoke_eval import in_house_study_contract as c
from privoke_model.scratch_presence import SCRATCH_PRESENCE_MODEL_IDS, SCRATCH_PROFILES


def sha(name):
    return hashlib.sha256(name.encode()).hexdigest()


def identity(model_id, version, name):
    return {"model_id": model_id, "version": version, "artifact_sha256": sha(name + "file"),
            "artifact_checksum": sha(name + "checksum"), "parameter_fingerprint": sha(name + "params")}


def programme_input():
    original = identity("privoke-balanced", "v0.3.0", "original")
    original["artifact_checksum"] = "8390b96871c6edd00916e3a6126da1b09c19f9fdbdda8214ebe667a893e5ee2c"
    return {"schema_version": 1, "pins": dict(c.PIN_ITEMS), "source_pin": c.SOURCE_PIN,
            "source_revision": "a" * 40,
            "external_hashes": {key: sha(key) for key in c.EXTERNAL_HASH_KEYS},
            "original_contextual": original, "s0": identity("privoke-presence-balanced", "v1.0.0", "s0"),
            "initialization_fingerprints": {p: sha(p) for p in SCRATCH_PROFILES}, "numpy_version": np.__version__}


def fixtures():
    rows = []
    for i in range(48):
        sensitive = False if i < 24 else True if i < 41 else None
        ambiguous = i >= 41
        rows.append({"case_sha256": sha(str(i)), "ambiguous": ambiguous,
                     "required_sensitive": sensitive, "required_action": None if ambiguous else "WARN" if sensitive else "ALLOW",
                     "visibility_hint": ("P0", "PU", "P4", "P3")[i] if i < 4 else None,
                     "ordinary_action": "WARN" if sensitive else "ALLOW",
                     "action": "WARN" if sensitive else "ALLOW"})
    return rows


def bind(records, contract):
    """Synthetic trusted consumer emulator, never proof of real provenance."""
    trusted = {"global/" + k: v for k, v in contract.external_hashes}
    trusted["global/original-contextual"] = contract.original_contextual.artifact_sha256
    trusted["global/s0"] = contract.s0.artifact_sha256
    for r in records:
        arm = r["arm"]
        claims = {
            "choice": {k: r[k] for k in ("arm", "contract_sha256", "selected_epoch", "selected_identity", "threshold")},
            "validation-rerun": {k: r[k] for k in ("arm", "contract_sha256", "selected_identity", "threshold", "validation_rows", "validation_errors", "parity_matched_rows", "validation_recall")},
            "fixtures": {k: r[k] for k in ("arm", "contract_sha256", "selected_identity", "threshold", "fixture_errors", "fixtures")}}
        for field, suffix in (("choice_ref", "choice"), ("rerun_ref", "validation-rerun"), ("fixture_ref", "fixtures")):
            purpose = arm + "/" + suffix
            trusted[purpose] = c._digest(claims[suffix])
            r[field] = {"purpose": purpose, "sha256": trusted[purpose]}
        for cp in r["checkpoints"]:
            purpose = f"{arm}/checkpoint/{cp['epoch']}"
            claim = {"arm": arm, "contract_sha256": contract.sha256, **{k: v for k, v in cp.items() if k != "evidence_ref"}}
            trusted[purpose] = c._digest(claim)
            cp["evidence_ref"] = {"purpose": purpose, "sha256": trusted[purpose]}
    return trusted


def evidence(contract):
    records = []
    for arm in c.ARMS:
        cps = []
        for epoch in ((0,) if arm.profile is None else range(1, 6)):
            ident = dict(vars(contract.s0)) if arm.key == "S0" else identity(arm.model_id, "v1.0.0" if not epoch else f"v1.0.0+epoch.{epoch}", arm.key + str(epoch))
            cps.append({"epoch": epoch, "steps": epoch * 490, "identity": ident,
                        "initialization_sha256": None if not epoch else dict(contract.initialization_fingerprints)[arm.profile],
                        "permutation_sha256": None if not epoch else c.permutation_sha256(arm.profile, epoch, 7832),
                        "validation_rows": 2000, "validation_errors": 0, "gate_zero_parity_matched_rows": 2000})
        records.append({"arm": arm.key, "status": "complete", "contract_sha256": contract.sha256,
                        "checkpoints": cps, "selected_epoch": cps[-1]["epoch"], "selected_identity": copy.deepcopy(cps[-1]["identity"]),
                        "threshold": .5, "validation_rows": 2000, "validation_errors": 0, "parity_matched_rows": 2000,
                        "validation_recall": .9, "fixture_errors": 0, "fixtures": fixtures()})
    return records, bind(records, contract)


class StudyProgrammeTests(unittest.TestCase):
    def setUp(self):
        self.contract = c.freeze_programme(programme_input())
        self.records, self.trusted = evidence(self.contract)

    def test_exact_arms_modes_dimensions_and_immutable_input_copy(self):
        self.assertEqual(tuple(a.key for a in c.ARMS), ("S0", "S1", "E-H", "E-F", "B-H", "B-F", "Q-H", "Q-F"))
        self.assertEqual({a.model_id for a in c.ARMS[2:]}, set(SCRATCH_PRESENCE_MODEL_IDS))
        for a in c.ARMS[2:]:
            self.assertEqual(a.dimensions, SCRATCH_PROFILES[a.profile])
            self.assertEqual(a.training_mode, "head_only" if a.key.endswith("H") else "end_to_end")
        raw = programme_input(); frozen = c.freeze_programme(raw); raw["external_hashes"].clear()
        self.assertEqual(len(frozen.external_hashes), len(c.EXTERNAL_HASH_KEYS))
        with self.assertRaises(FrozenInstanceError): frozen.source_revision = "b" * 40

    def test_pins_closed_external_digests_and_identity_fail_closed(self):
        mutations = [lambda v: v.update(schema_version=True), lambda v: v.update(source_pin="b" * 40),
                     lambda v: v["pins"].update(plan=sha("wrong")), lambda v: v["external_hashes"].pop("fixture_addon_artifact"),
                     lambda v: v["external_hashes"].update(extra=sha("extra")), lambda v: v["external_hashes"].update(runtime_image=""),
                     lambda v: v["original_contextual"].update(version="latest"), lambda v: v["s0"].update(model_id="default"),
                     lambda v: v["initialization_fingerprints"].clear()]
        for mutate in mutations:
            raw = programme_input(); mutate(raw)
            with self.assertRaises(c.StudyContractError): c.freeze_programme(raw)

    def test_complete_epoch_budget_and_last_partial_batch(self):
        self.assertEqual(c.training_budget(7832), c.TrainingBudget(7832, 490, 5, 2450))
        batches = c.epoch_batches("balanced", 5, 7832)
        self.assertEqual(len(batches), 490); self.assertEqual(len(batches[-1]), 8)
        self.assertEqual(sorted(i for batch in batches for i in batch), list(range(7832)))
        for bad in (0, True, 1.0, 40001):
            with self.assertRaises(c.StudyContractError): c.training_budget(bad)
        with self.assertRaises(c.StudyContractError): c.epoch_batches("balanced", 6, 7832)
        with self.assertRaises(c.StudyContractError): c.epoch_batches("unknown", 1, 7832)

    def test_fixed_permutation_commitments_and_shared_profile_order(self):
        expected = ("bfd234f2d9400917b97794cc3efb9515e658c8f8a4a50176bf00c124625c6689", "4afbab4d527619fb6bed47a3c6f5e851ee7bef92a0b6a4cb8f56905b6cc0070b")
        for profile in SCRATCH_PROFILES:
            self.assertEqual(c.permutation_sha256(profile, 1, 7832), expected[0])
            self.assertEqual(c.permutation_sha256(profile, 5, 7832), expected[1])
        self.assertNotEqual(expected[0], expected[1])

    def test_complete_barrier_and_ordinary_losses_do_not_block_reference_pairs(self):
        for r in self.records:
            r["fixtures"][24]["action"] = "ALLOW"
        self.trusted = bind(self.records, self.contract)
        assessment = c.validate_pretest_barrier(self.contract, self.records, self.trusted)
        self.assertTrue(all(n == 0 for _, n in assessment.pairwise_private_losses))
        self.assertTrue(all(n == 1 for _, n in assessment.ordinary_private_losses))
        self.assertTrue(all(n == 1 for _, n in assessment.baseline_private_failures))

    def test_every_treatment_additional_private_loss_blocks_whole_programme(self):
        for arm, _ in c.PAIRS:
            records = copy.deepcopy(self.records); records[c.ARM_KEYS.index(arm)]["fixtures"][24]["action"] = "ALLOW"
            trusted = bind(records, self.contract)
            with self.assertRaises(c.StudyContractError): c.validate_pretest_barrier(self.contract, records, trusted)

    def test_missing_duplicate_failed_ineligible_arm_and_partial_inventory_block(self):
        for arm in c.ARM_KEYS:
            for status in ("failed", "ineligible", "pending"):
                records = copy.deepcopy(self.records); records[c.ARM_KEYS.index(arm)]["status"] = status
                with self.assertRaises(c.StudyContractError): c.validate_pretest_barrier(self.contract, records, self.trusted)
        for records in (self.records[:-1], self.records[:-1] + [self.records[0]]):
            with self.assertRaises(c.StudyContractError): c.validate_pretest_barrier(self.contract, records, self.trusted)
        records = copy.deepcopy(self.records); records[2]["checkpoints"].pop()
        with self.assertRaises(c.StudyContractError): c.validate_pretest_barrier(self.contract, records, bind(records, self.contract))

    def test_step_epoch_artifact_or_permutation_tamper_rejected_even_if_rebound(self):
        mutations = [lambda r: r[2]["checkpoints"][0].update(validation_errors=1),
                     lambda r: r[2]["checkpoints"][0].update(gate_zero_parity_matched_rows=1999),
                     lambda r: r[2]["checkpoints"][0].update(steps=491), lambda r: r[2]["checkpoints"][0].update(epoch=True),
                     lambda r: r[2]["checkpoints"][0].update(permutation_sha256=sha("wrong")),
                     lambda r: r[2]["selected_identity"].update(model_id="latest"), lambda r: r[2].update(selected_epoch=0),
                     lambda r: r[2]["selected_identity"].update(artifact_checksum=sha("other")),
                     lambda r: r[0]["selected_identity"].update(parameter_fingerprint=sha("other"))]
        for mutate in mutations:
            records = copy.deepcopy(self.records); mutate(records)
            with self.assertRaises(c.StudyContractError): c.validate_pretest_barrier(self.contract, records, bind(records, self.contract))

    def test_claims_cannot_reuse_trusted_hash_after_mutation_and_trust_is_closed(self):
        records = copy.deepcopy(self.records); records[3]["threshold"] = .6
        with self.assertRaises(c.StudyContractError): c.validate_pretest_barrier(self.contract, records, self.trusted)
        for trusted in ({}, {**self.trusted, "extra": sha("extra")}, {**self.trusted, "S0/choice": sha("wrong")}):
            with self.assertRaises(c.StudyContractError): c.validate_pretest_barrier(self.contract, self.records, trusted)

    def test_strict_types_counts_errors_and_shared_fixture_truth(self):
        mutations = [lambda r: r[0].update(threshold=True), lambda r: r[0].update(threshold=1),
                     lambda r: r[0].update(threshold=float("nan")), lambda r: r[0].update(validation_recall=.899),
                     lambda r: r[0].update(validation_errors=1), lambda r: r[0].update(parity_matched_rows=1999),
                     lambda r: r[0].update(fixture_errors=True), lambda r: r[0]["fixtures"].pop(),
                     lambda r: r[0]["fixtures"].__setitem__(0, copy.deepcopy(r[0]["fixtures"][1])),
                     lambda r: r[0]["fixtures"][41].update(required_sensitive=True),
                     lambda r: r[0]["fixtures"][24].update(required_action="BLOCK"),
                     lambda r: r[0]["fixtures"][0].update(visibility_hint="PU")]
        for mutate in mutations:
            records = copy.deepcopy(self.records); mutate(records)
            try:
                trusted = bind(records, self.contract)
            except ValueError:
                trusted = self.trusted  # Nonfinite values have no valid canonical receipt.
            with self.assertRaises(c.StudyContractError): c.validate_pretest_barrier(self.contract, records, trusted)

    def test_ambiguous_actions_never_enter_private_counts_and_errors_are_sanitized(self):
        for r in self.records:
            for row in r["fixtures"][41:]: row.update(action="ALLOW", ordinary_action="BLOCK")
        out = c.validate_pretest_barrier(self.contract, self.records, bind(self.records, self.contract))
        self.assertTrue(all(count == 0 for _, count in out.ordinary_private_losses))
        self.records[0]["arm"] = "PRIVATE_ERROR_MARKER"
        with self.assertRaises(c.StudyContractError) as error: c.validate_pretest_barrier(self.contract, self.records, self.trusted)
        self.assertNotIn("PRIVATE_ERROR_MARKER", str(error.exception))


if __name__ == "__main__": unittest.main()
