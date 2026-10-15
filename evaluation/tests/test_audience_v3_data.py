"""Prediction-free AU3 data, automatic-consumption and v3 source boundaries."""
from __future__ import annotations
import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / p) for p in ("evaluation", "shared/python", "services/privoke-fuzzer/src",
    "services/privoke-fuzzer/generated", "extension/client-runtime/generated", "services/pretrained-v3/src", "services/param-update-service/app")]
from prompt_generation import audience_coverage as audience
from prompt_generation.generator import generate_training_partition
from privoke_eval import audience_v3_data as data
from training.trainer import iter_training_examples, train_parameter_batch
from training.parameter_updates import emit_training_update
from training.types import BatchTrainingConfig
from config import FuzzerConfig
from fuzzer_service import FuzzerTrainingService
from fuzzer_requests import FuzzerRequestConfig, build_training_request
from privoke.v1 import parameters_pb2
from fuzzer_training import schedule, validate_schedule
from privoke_model.v3_contract import POLICY
import importlib.util
_spec=importlib.util.spec_from_file_location("au3_updater_validation",ROOT/"services/param-update-service/app/validation.py")
_updater=importlib.util.module_from_spec(_spec);_spec.loader.exec_module(_updater)


class Context:
    def abort(self, code, message):
        raise ValueError(message)


class StopAfterConsumption(Exception):
    pass


class AudienceDataTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalogs = {role: json.loads((ROOT / path).read_bytes()) for role, path in data.CATALOGS.items()}
        cls.release = audience.load_release()

    def test_counts_categories_expression_coverage_and_unchanged_rehearsal(self):
        new = {role: audience.render_catalog(catalog) for role, catalog in self.catalogs.items()}
        pools = dict(new, train=list(self.release.rehearsal) + new["train"])
        summary = data.audit(pools, self.catalogs)
        self.assertEqual([summary[r]["rows"] for r in data.COUNTS], [9360, 1560, 1560])
        self.assertEqual([summary[r]["new_audience_expression_groups"] for r in data.COUNTS], [48, 24, 24])
        self.assertEqual(b"".join(audience.canonical(r) for r in self.release.rehearsal), (ROOT/data.OLD_TRAIN).read_bytes())
        for rows in new.values():
            for row in rows:
                if row["metadata"]["control"] == "actual_disclosure":
                    self.assertTrue(row["classification"]["categories"])
                elif not row["required_sensitive"]:
                    self.assertEqual(row["classification"]["categories"], [])

    def test_same_seed_and_actual_strata_across_supported_budgets(self):
        for count in (32, 64, 256):
            a, g = generate_training_partition(count, 16, 42, sampling_strategy=audience.STRATEGY, audience_release=self.release)
            b, h = generate_training_partition(count, 16, 42, sampling_strategy=audience.STRATEGY, audience_release=self.release)
            self.assertEqual([r.text for r in a], [r.text for r in b])
            self.assertEqual(len({r.metadata["example_id"] for r in a}), count)
            audit = audience.audit_originals(self.release, a, g, 42)
            self.assertEqual(audit["sampling_primary_categories"], "10")
            _updater._validate_metadata(audit)
            self.assertNotIn("sampling_selected_ids",audit)
            self.assertEqual(len(audit["sampling_selected_ids_sha256"]),64)
            expanded = list(iter_training_examples(a, (), BatchTrainingConfig(seed=42)))
            self.assertEqual(audience.audit_expanded(self.release, a, expanded, g, BatchTrainingConfig(seed=42))["sampling_expanded_exposures"], str(count*2))
        c, _ = audience.generate_partition(self.release, 43)
        self.assertNotEqual([r.text for r in a[:32]], [r.text for r in c])

    def test_incomplete_count_labels_pins_and_partition_fail_closed(self):
        for count in (0, 8, 31, 33, True):
            with self.assertRaises(ValueError): audience.validate_count(count)
        with self.assertRaises(ValueError): audience.load_release(expected_sha256="0"*64)
        for mutate in (lambda r:r["classification"].pop("visibility"), lambda r:r.update(packed=r["packed"]^1),
                       lambda r:r.update(partition="fresh_eval"), lambda r:r.update(ambiguous=True)):
            rows=copy.deepcopy(list(self.release.train[:1]));mutate(rows[0])
            with self.assertRaises(ValueError): audience.validate_rows(rows,"train")

    def test_valid_same_audience_role_swap_is_rejected(self):
        training,guard=audience.generate_partition(self.release,42)
        index=next(i for i,r in enumerate(training) if r.metadata.get("generator")==audience.VERSION
                   and r.metadata["primary_category"]!="NONE" and not r.expected_classification.is_sensitive())
        used={r.metadata["example_id"] for r in training};visibility=training[index].expected_classification.visibility().name
        substitute=next(r for r in self.release.train if r["classification"]["visibility"]==visibility
                        and r["metadata"]["control"]=="actual_disclosure" and r["id"] not in used)
        training[index]=audience.example(substitute,42,index)
        with self.assertRaisesRegex(ValueError,"role/rehearsal"):audience.audit_originals(self.release,training,guard,42)

    def test_trainer_retains_full_ids_and_publication_metadata_stays_bounded_at256(self):
        training,guard=audience.generate_partition(self.release,42,256)
        class Runtime:
            def compute_semantic_gradients(self, rows, **kwargs):
                return {"model_id":"fixture", "base_version":"v0", "gradients":{"head.fixture":(.01,)},
                        "shapes":{"head.fixture":(1,)},"metrics":{"examples":float(len(rows))},
                        "metadata":{"training_scope":"heads"},"execution_evidence":{"synthetic_unit_fixture":True}}
            compute_underlying_gradients=compute_semantic_gradients
        for scope in ("heads","full_encoder"):
            update=train_parameter_batch("fixture",training,heldout_examples=guard,config=BatchTrainingConfig(seed=42),
                                         runtime_client=Runtime(),training_scope=scope,audience_release=self.release)
            self.assertEqual(len(update.execution_evidence["audience_audit"]["selected_ids"]),256)
            def submit(target,payload,**kwargs):
                _updater._validate_metadata(payload.metadata)
                self.assertNotIn("sampling_selected_ids",payload.metadata)
                return "unit-validated"
            with patch("training.parameter_updates.emit_parameter_update",side_effect=submit):
                self.assertEqual(emit_training_update("unused","fixture",update),"unit-validated")

    def test_cross_split_authoring_mutants_rejected(self):
        catalogs=copy.deepcopy(self.catalogs)
        catalogs["fresh_eval"]["families"][0]["fact"]=catalogs["train"]["families"][0]["fact"]
        with self.assertRaises(ValueError): data.audit({r:audience.render_catalog(c) for r,c in catalogs.items()},catalogs)
        catalogs=copy.deepcopy(self.catalogs)
        catalogs["fresh_eval"]["audience"]["P4"][0]=catalogs["train"]["audience"]["P4"][0]
        with self.assertRaises(ValueError): data.audit({r:audience.render_catalog(c) for r,c in catalogs.items()},catalogs)

    def test_fresh_loader_blocks_before_any_file_read(self):
        with patch.object(Path,"read_bytes",side_effect=AssertionError("must not read")):
            with self.assertRaises(ValueError): data.load_partition("missing.json","fresh_eval")

    def test_production_default_and_explicit_legacy_source(self):
        with patch.dict(os.environ,{},clear=True):
            self.assertEqual(FuzzerConfig.from_env().contextual_sampling_strategy,audience.STRATEGY)
        with patch.dict(os.environ,{"FUZZ_PROMPT_DATASET_PATH":"explicit-legacy.json"},clear=True):
            self.assertEqual(FuzzerConfig.from_env().contextual_sampling_strategy,audience.LEGACY)
        with patch.dict(os.environ,{"FUZZ_AUDIENCE_MANIFEST_PATH":"partial"},clear=True):
            with self.assertRaises(ValueError): FuzzerConfig.from_env()

    def test_default_requester_consumes_real_sampler_in_both_stages_before_training(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ,{"PRIVOKE_FUZZER_DUMP_DIR":directory},clear=True):
            config=FuzzerConfig.from_env();request=build_training_request(FuzzerRequestConfig.from_env(),"automatic-au3")
            self.assertNotIn("contextual_sampling_strategy",request.metadata)
            service=FuzzerTrainingService(config)
            for scope in ("heads","full_encoder"):
                def consume(model_id, examples, heldout, seed, context, **kwargs):
                    self.assertEqual(len(examples),32);self.assertEqual(len(heldout),16)
                    self.assertEqual(kwargs["audience_release"].sha256,self.release.sha256)
                    self.assertEqual(sum(r.metadata.get("generator")==audience.VERSION for r in examples),24)
                    raise StopAfterConsumption()
                with patch.object(service,"_previous_update_for_fingerprint",return_value=parameters_pb2.ParameterUpdateStatus(found=False)),patch.object(service,"_train",side_effect=consume):
                    with self.assertRaises(StopAfterConsumption): service._run_training_cycle(request,Context(),training_scope=scope)

    def test_changed_implementation_rejects_before_receipt_lookup_or_retraining(self):
        with tempfile.TemporaryDirectory() as directory,patch.dict(os.environ,{"PRIVOKE_FUZZER_DUMP_DIR":directory},clear=True):
            config=FuzzerConfig.from_env();request=build_training_request(FuzzerRequestConfig.from_env(),"implementation-pin")
            service=FuzzerTrainingService(config)
            with patch.object(service,"_previous_update_for_fingerprint",return_value=parameters_pb2.ParameterUpdateStatus(found=False)),patch.object(service,"_train",side_effect=StopAfterConsumption):
                with self.assertRaises(StopAfterConsumption):service._run_training_cycle(request,Context())
            with patch.object(audience,"implementation_closure",return_value={"sha256":"0"*64,"files":{}}),patch.object(service,"_previous_update_for_fingerprint") as lookup,patch.object(service,"_train") as train:
                with self.assertRaisesRegex(ValueError,"different effective training settings"):service._run_training_cycle(request,Context())
                lookup.assert_not_called();train.assert_not_called()

    def test_v3_new_source_reconstructs_wires_and_rejects_mutants(self):
        policy=dict(POLICY,steps=2,window_batches=1,epochs=2)
        train,guard,source=schedule(42,policy,sampler="audience_common_frozen_stream_v1")
        self.assertEqual(len(train),64);self.assertEqual(len(guard),16)
        validate_schedule(train,guard,source,policy)
        for field,value in (("packed_target",0),("text","forged"),("group_id","borrowed")):
            changed=copy.deepcopy(source);changed["train_sidecar"][0][field]=value
            with self.assertRaises(ValueError): validate_schedule(train,guard,changed,policy)
        train[0].target.packed ^= 1
        with self.assertRaises(ValueError): validate_schedule(train,guard,source,policy)


if __name__ == "__main__":
    unittest.main()
