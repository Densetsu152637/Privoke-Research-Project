import hashlib
import json
import sqlite3
from contextlib import closing
import tempfile
import unittest
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
for path in (ROOT / "src", ROOT / "generated", ROOT.parents[1] / "shared/python"):
    sys.path.insert(0, str(path))

from privoke.v1 import parameters_pb2
from prompt_generation.curriculum import load_curriculum, reserve_batch, request_fingerprint
from fuzzer_service import FuzzerTrainingService
from config import FuzzerConfig


class CurriculumTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        splits = {}
        for split, count in (("train", 192), ("replay", 64), ("heldout", 16)):
            rows = []
            for index in range(count):
                role = ("grammar", "teacher", "evolved")[(index // 2) % 3] if split == "train" else split
                rows.append({"id": f"{split}-{index}", "text": f"{split} family {index} unique fact",
                             "classification": {"sensitivity": "S1" if index % 2 else "S0",
                                                "visibility": "P2", "categories": ["IDENTITY"] if index % 2 else []},
                             "metadata": {"group_id": f"{split}-family-{index // 2}",
                                          "parent_id": "", "generator": "fixture",
                                          "label_status": "assistant_provisional", "curriculum_role": role}})
            payload = "".join(json.dumps(row) + "\n" for row in rows).encode()
            (self.root / f"{split}.jsonl").write_bytes(payload)
            splits[split] = {"path": f"{split}.jsonl", "sha256": hashlib.sha256(payload).hexdigest()}
        self.manifest = {"schema_version": 1, "curriculum_id": "fixture", "splits": splits}
        self.path = self.root / "manifest.json"
        self.write_manifest()

    def write_manifest(self):
        self.path.write_text(json.dumps(self.manifest), encoding="utf-8")

    def request(self, identity="round1", **metadata):
        return parameters_pb2.FuzzerTrainingRequest(request_id=identity, source_id="study",
                                                    model_id="privoke-balanced", prompt_count=32,
                                                    seed=1337, metadata=metadata)

    def batch_signature(self, batch):
        return ([[(row.text, row.expected_packed_classification, row.metadata)
                  for row in rows] for rows in (batch.examples, batch.replay, batch.heldout)], batch.audit)

    def test_retry_survives_reload_and_next_request_advances(self):
        curriculum = load_curriculum(str(self.path))
        state = str(self.root / "cursor.sqlite3")
        first = reserve_batch(curriculum, state, self.request(), 32)
        retry = reserve_batch(load_curriculum(str(self.path)), state, self.request(), 32)
        next_batch = reserve_batch(curriculum, state, self.request("round2"), 32)
        self.assertEqual(first.audit, retry.audit)
        self.assertEqual([row.text for row in first.examples], [row.text for row in retry.examples])
        self.assertNotEqual(first.examples, next_batch.examples)
        self.assertEqual([row.text for row in first.heldout], [row.text for row in next_batch.heldout])
        self.assertEqual((len(first.examples), len(first.replay)), (24, 8))
        all_training = {row.text for row in (*first.examples, *first.replay)}
        self.assertFalse(all_training & {row.text for row in first.heldout})
        self.assertEqual(sum(row.expected_classification.is_sensitive() for row in first.examples), 12)

    def test_seeded_stream_reproducible_distinct_balanced_unique_and_restartable(self):
        curriculum = load_curriculum(str(self.path))
        def stream(seed, filename):
            state = str(self.root / filename)
            batches = []
            for index in range(10):  # Cross both train and replay epoch boundaries.
                request = self.request(f"round{index}", curriculum_sampler_policy="seeded_family_v1",
                                       curriculum_sampler_seed=str(seed))
                batch = reserve_batch(load_curriculum(str(self.path)), state, request, 32)
                retry = reserve_batch(curriculum, state, request, 32)
                self.assertEqual(self.batch_signature(batch), self.batch_signature(retry))
                texts = [row.text for row in (*batch.examples, *batch.replay)]
                self.assertEqual(len(texts), len(set(texts)))
                self.assertEqual(sum(row.expected_classification.is_sensitive() for row in batch.examples), 12)
                self.assertEqual(batch.audit["curriculum_sampler_seed"], str(seed))
                self.assertEqual(len(batch.examples), 24)
                batches.append(batch)
            return batches
        first = stream(42, "a.sqlite3")
        self.assertEqual([self.batch_signature(b) for b in first],
                         [self.batch_signature(b) for b in stream(42, "b.sqlite3")])
        self.assertNotEqual([r.text for r in first[0].examples],
                            [r.text for r in stream(43, "c.sqlite3")[0].examples])
        # No replacement during the first complete epoch of each stratum.
        first_epoch = [row.text for batch in first[:8] for row in batch.examples]
        self.assertEqual(len(first_epoch), len(set(first_epoch)))
        self.assertNotEqual([r.text for r in first[0].examples], [r.text for r in first[8].examples])

    def test_sampler_namespaces_do_not_reset_or_share_cursors(self):
        curriculum = load_curriculum(str(self.path))
        state = str(self.root / "shared.sqlite3")
        seeded = {"curriculum_sampler_policy": "seeded_family_v1", "curriculum_sampler_seed": "42"}
        first = reserve_batch(curriculum, state, self.request("a", **seeded), 32)
        reserve_batch(curriculum, state, self.request("b"), 32)
        next_batch = reserve_batch(curriculum, state, self.request("c", **seeded), 32)
        self.assertNotEqual([r.text for r in first.examples], [r.text for r in next_batch.examples])
        positions = json.loads(next_batch.audit["curriculum_sampler_positions"])
        self.assertTrue(all(value["start"] > 0 for value in positions.values()))
        with closing(sqlite3.connect(state)) as database:
            self.assertEqual(database.execute("SELECT COUNT(*) FROM cursors").fetchone()[0], 16)

    def test_seeded_identity_cannot_reuse_or_clobber_another_configuration(self):
        curriculum = load_curriculum(str(self.path))
        state = str(self.root / "cursor.sqlite3")
        request = self.request(curriculum_sampler_policy="seeded_family_v1", curriculum_sampler_seed="42")
        first = reserve_batch(curriculum, state, request, 32, fingerprint="caller")
        with self.assertRaisesRegex(ValueError, "different curriculum request"):
            reserve_batch(curriculum, state, request, 40, fingerprint="caller")
        with self.assertRaisesRegex(ValueError, "different curriculum request"):
            reserve_batch(curriculum, state, self.request(curriculum_sampler_policy="seeded_family_v1",
                          curriculum_sampler_seed="43"), 32, fingerprint="caller")
        self.assertEqual(self.batch_signature(first),
                         self.batch_signature(reserve_batch(curriculum, state, request, 32, fingerprint="caller")))

    def test_invalid_sampler_and_count_values_do_not_create_state(self):
        curriculum = load_curriculum(str(self.path))
        state = self.root / "invalid.sqlite3"
        for metadata in ({"curriculum_sampler_policy": "shuffle"},
                         {"curriculum_sampler_policy": "seeded_family_v1", "curriculum_sampler_seed": "-1"},
                         {"curriculum_sampler_policy": "seeded_family_v1", "curriculum_sampler_seed": str(2**32)},
                         {"curriculum_sampler_seed": "42"},
                         {"curriculum_sampler_seed": "nan"}):
            with self.subTest(metadata=metadata), self.assertRaises(ValueError):
                reserve_batch(curriculum, str(state), self.request(**metadata), 32)
        for count, fraction in ((0, .25), (True, .25), (32, float("nan")), (32, 1), (32, 0)):
            with self.subTest(count=count, fraction=fraction), self.assertRaises(ValueError):
                reserve_batch(curriculum, str(state), self.request(), count, fraction)
        self.assertFalse(state.exists())

    def test_conflicting_retry_does_not_allocate_another_batch(self):
        curriculum = load_curriculum(str(self.path))
        state = str(self.root / "cursor.sqlite3")
        reserve_batch(curriculum, state, self.request(), 32)
        with self.assertRaisesRegex(ValueError, "different curriculum request"):
            reserve_batch(curriculum, state, self.request(curriculum_stage="grammar"), 32)

    def test_mining_cannot_use_gate_replay_or_unknown_ids(self):
        curriculum = load_curriculum(str(self.path))
        for row_id in ("heldout-0", "replay-0", "unknown"):
            with self.subTest(row_id=row_id), self.assertRaisesRegex(ValueError, "TRAIN"):
                reserve_batch(curriculum, str(self.root / "cursor.sqlite3"),
                              self.request(curriculum_hard_ids=json.dumps([row_id])), 32)
        batch = reserve_batch(curriculum, str(self.root / "cursor.sqlite3"),
                              self.request(curriculum_hard_ids='["train-0"]'), 32)
        self.assertEqual(batch.examples[0].text, "train family 0 unique fact")

    def test_split_tamper_fails_closed(self):
        with (self.root / "train.jsonl").open("a") as target:
            target.write("{}\n")
        with self.assertRaisesRegex(ValueError, "hash"):
            load_curriculum(str(self.path))

    def test_missing_target_and_family_overlap_fail_closed(self):
        for field in ("classification", "metadata"):
            data = (self.root / "heldout.jsonl").read_text().splitlines()
            row = json.loads(data[0])
            if field == "classification":
                row[field].pop("visibility")
            else:
                row[field]["group_id"] = "train-family-0"
            data[0] = json.dumps(row)
            payload = ("\n".join(data) + "\n").encode()
            (self.root / "heldout.jsonl").write_bytes(payload)
            self.manifest["splits"]["heldout"]["sha256"] = hashlib.sha256(payload).hexdigest()
            self.write_manifest()
            with self.assertRaises(ValueError):
                load_curriculum(str(self.path))

    def test_manifest_digest_binds_receipt_identity(self):
        before = request_fingerprint(self.request(), load_curriculum(str(self.path)))
        self.manifest["curriculum_id"] = "other-immutable-release"
        self.write_manifest()
        after = request_fingerprint(self.request(), load_curriculum(str(self.path)))
        self.assertNotEqual(before, after)

    def test_replay_weight_configuration_default_override_and_invalid_values(self):
        with patch.dict("os.environ", {}, clear=True):
            default = FuzzerConfig.from_env()
            self.assertEqual(default.batch_training_config(42).golden_example_weight, .35)
        with patch.dict("os.environ", {"FUZZ_TRAINING_REPLAY_WEIGHT": "1.0"}, clear=True):
            config = FuzzerConfig.from_env()
            self.assertEqual(config.batch_training_config(42).golden_example_weight, 1.0)
            curriculum = load_curriculum(str(self.path))
            from dataclasses import asdict
            self.assertNotEqual(request_fingerprint(self.request(), curriculum, asdict(default.batch_training_config(42))),
                                request_fingerprint(self.request(), curriculum, asdict(config.batch_training_config(42))))
        for value in ("0", "-1", "1.1", "nan", "inf"):
            with patch.dict("os.environ", {"FUZZ_TRAINING_REPLAY_WEIGHT": value}, clear=True), self.assertRaises(ValueError):
                FuzzerConfig.from_env()

    def test_effective_settings_change_receipt_and_batch_identity(self):
        curriculum = load_curriculum(str(self.path))
        request = self.request()
        self.assertNotEqual(request_fingerprint(request, curriculum, {"learning_rate": .003}),
                            request_fingerprint(request, curriculum, {"learning_rate": .03}))
        state = str(self.root / "cursor.sqlite3")
        reserve_batch(curriculum, state, request, 32, .25)
        with self.assertRaisesRegex(ValueError, "different curriculum request"):
            reserve_batch(curriculum, state, request, 32, .5)

    def test_declared_manifest_mismatch_aborts_before_receipt_or_training(self):
        class Rejected(Exception):
            pass

        class Context:
            def abort(self, code, message):
                raise Rejected(message)

        config = SimpleNamespace(model_id="privoke-balanced", seed=1337,
                                 max_prompt_count=256, max_concurrent_cycles=1,
                                 curriculum_manifest_path=str(self.path))
        service = FuzzerTrainingService(config)
        with patch.object(service, "_previous_update_for_fingerprint") as receipts, \
                patch.object(service, "_train") as training:
            with self.assertRaisesRegex(Rejected, "differs"):
                service.RunTrainingCycle(self.request(curriculum_manifest_sha256="other"), Context())
            receipts.assert_not_called()
            training.assert_not_called()

    def test_real_preparer_package_loads_with_root_and_descendant_provenance(self):
        sys.path.insert(0, str(ROOT.parents[1] / "evaluation"))
        from privoke_eval.synthetic_curriculum import build_curriculum
        resource = json.loads((ROOT.parents[1] / "evaluation/datasets/synthetic-teacher-templates.json").read_text())
        pools = build_curriculum(resource, 1337)
        for split, rows in pools.items():
            payload = "".join(json.dumps(row) + "\n" for row in rows).encode()
            (self.root / f"{split}.jsonl").write_bytes(payload)
            self.manifest["splits"][split]["sha256"] = hashlib.sha256(payload).hexdigest()
        self.write_manifest()
        curriculum = load_curriculum(str(self.path))
        self.assertEqual({key: len(rows) for key, rows in curriculum.splits.items()},
                         {"train": 672, "replay": 64, "heldout": 16})
        batch = reserve_batch(curriculum, str(self.root / "cursor.sqlite3"), self.request(), 256)
        self.assertEqual((len(batch.examples), len(batch.replay)), (192, 64))
        request = self.request("seeded", curriculum_sampler_policy="seeded_family_v1", curriculum_sampler_seed="42")
        batch = reserve_batch(curriculum, str(self.root / "cursor.sqlite3"), request, 224)
        by_stratum = {}
        for example in batch.examples:
            key = example.metadata["curriculum_role"], example.expected_classification.is_sensitive()
            by_stratum.setdefault(key, []).append(example.metadata["group_id"])
        for groups in by_stratum.values():
            self.assertEqual((len(groups), len(set(groups))), (28, 28))


if __name__ == "__main__":
    unittest.main()
