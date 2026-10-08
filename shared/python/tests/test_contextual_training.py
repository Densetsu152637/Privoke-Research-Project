import copy
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "shared/python"))
from privoke_model.artifact import ModelArtifactError, artifact_checksum, validate_artifact
from privoke_model.contextual_training import (HEAD_NAMES, LAST_BLOCK_STRATEGY, STRATEGY_KEY,
    OPTIMIZER_KEY, LOCAL_SGD_1, LOCAL_SGD_4, validate_contextual_training_optimizer,
    prepare_training_optimizer_artifact, contextual_trainable_names, prepare_contextual_training_artifact,
    prepare_training_objective_artifact, OBJECTIVE_KEY, CLASS_BALANCED_OBJECTIVE, CLASS_BALANCED_MEAN_CATEGORY_OBJECTIVE,
    CLASS_BALANCED_DECISION_MARGIN_OBJECTIVE, validate_decision_margin_config)


class ContextualTrainingContractTests(unittest.TestCase):
    def original(self, profile="balanced"):
        return json.loads((ROOT / f"models/privoke-{profile}.json").read_text(encoding="utf-8"))

    def test_preparer_freezes_embeddings_earlier_blocks_and_preserves_all_weights(self):
        for profile in ("efficient", "balanced", "quality"):
            base = self.original(profile)
            before = copy.deepcopy(base)
            result = prepare_contextual_training_artifact(base)
            self.assertEqual(base, before)
            self.assertEqual(result["model_id"], base["model_id"])
            self.assertEqual(result["version"], base["version"])
            self.assertNotEqual(result["checksum"], base["checksum"])
            names = contextual_trainable_names(result["config"], LAST_BLOCK_STRATEGY)
            self.assertEqual(len(names), 15)
            self.assertEqual({n for n,t in result["parameters"].items() if t["trainable"]}, names)
            for name,tensor in result["parameters"].items():
                self.assertEqual(tensor["values"], base["parameters"][name]["values"])
                if name in names:
                    self.assertLessEqual(len(tensor["values"]), 4096)
            validate_artifact(result)

    def test_strategies_and_flags_fail_closed(self):
        def resign(artifact):
            artifact["checksum"] = artifact_checksum({k:v for k,v in artifact.items() if k != "checksum"})
        changes = (
            lambda a: a["metadata"].update({STRATEGY_KEY: "unknown"}),
            lambda a: a["metadata"].update({STRATEGY_KEY: ""}),
            lambda a: a["parameters"]["token_embedding"].update(trainable=True),
            lambda a: a["parameters"]["head.category.bias"].update(trainable=1),
            lambda a: a["parameters"]["head.category.bias"].pop("trainable"),
            lambda a: a["parameters"]["layers.0.ffn.input.weight"].update(trainable=True),
            lambda a: a["parameters"].update(unsupported={"shape":[1], "values":[0.0], "trainable":False}),
            lambda a: a["parameters"].pop("layers.1.ffn.input.weight"),
        )
        for change in changes:
            artifact = prepare_contextual_training_artifact(self.original())
            change(artifact); resign(artifact)
            with self.assertRaises(ModelArtifactError): validate_artifact(artifact)
        base=self.original(); base["parameters"]["token_embedding"]["trainable"]=True; resign(base)
        with self.assertRaises(ModelArtifactError): validate_artifact(base)
        with self.assertRaises(ModelArtifactError): prepare_contextual_training_artifact(self.original(), "unknown")

    def test_objective_is_independent_and_uniform_control_restores_original(self):
        for profile in ("efficient", "balanced", "quality"):
            base = self.original(profile)
            for strategy in (None, LAST_BLOCK_STRATEGY):
                release = prepare_contextual_training_artifact(base, strategy)
                before = copy.deepcopy(release)
                balanced = prepare_training_objective_artifact(release, CLASS_BALANCED_OBJECTIVE)
                self.assertEqual(release, before)
                self.assertEqual(balanced["parameters"], release["parameters"])
                self.assertEqual(balanced["config"], release["config"])
                self.assertEqual(balanced["model_id"], release["model_id"])
                self.assertEqual(balanced["version"], release["version"])
                self.assertEqual(balanced["metadata"][OBJECTIVE_KEY], CLASS_BALANCED_OBJECTIVE)
                self.assertEqual(prepare_training_objective_artifact(balanced), release)
                validate_artifact(balanced)
                direct = prepare_contextual_training_artifact(base, strategy, objective=CLASS_BALANCED_OBJECTIVE)
                self.assertEqual(direct, balanced)

    def test_mean_category_objective_preserves_release_bytes_and_independent_strategy(self):
        from privoke_model import CLASS_BALANCED_MEAN_CATEGORY_OBJECTIVE as exported
        self.assertEqual(exported, CLASS_BALANCED_MEAN_CATEGORY_OBJECTIVE)
        for profile in ("efficient", "balanced", "quality"):
            base = self.original(profile)
            for strategy in (None, LAST_BLOCK_STRATEGY):
                release = prepare_contextual_training_artifact(base, strategy)
                before = copy.deepcopy(release)
                mean = prepare_training_objective_artifact(release, CLASS_BALANCED_MEAN_CATEGORY_OBJECTIVE)
                self.assertEqual(release, before)
                for key in ("parameters", "config", "model_id", "version"):
                    self.assertEqual(mean[key], release[key])
                self.assertEqual(mean["metadata"][OBJECTIVE_KEY], CLASS_BALANCED_MEAN_CATEGORY_OBJECTIVE)
                self.assertEqual(prepare_training_objective_artifact(mean), release)
                summed = prepare_training_objective_artifact(mean, CLASS_BALANCED_OBJECTIVE)
                self.assertEqual(summed, prepare_training_objective_artifact(release, CLASS_BALANCED_OBJECTIVE))
                self.assertEqual(mean, prepare_contextual_training_artifact(base, strategy, objective=CLASS_BALANCED_MEAN_CATEGORY_OBJECTIVE))
                validate_artifact(mean)

    def test_decision_margin_contract_preserves_weights_and_rejects_missing_reference(self):
        from privoke_model import CLASS_BALANCED_DECISION_MARGIN_OBJECTIVE as exported
        self.assertEqual(exported, CLASS_BALANCED_DECISION_MARGIN_OBJECTIVE)
        for profile in ("efficient", "balanced", "quality"):
            for strategy in (None, LAST_BLOCK_STRATEGY):
                release = prepare_contextual_training_artifact(self.original(profile), strategy)
                before = copy.deepcopy(release)
                result = prepare_training_objective_artifact(release, exported)
                self.assertEqual(release, before)
                for key in ("parameters", "config", "model_id", "version"):
                    self.assertEqual(result[key], release[key])
                self.assertEqual(prepare_training_objective_artifact(result), release)
                validate_artifact(result)
                for labels in (["S1", "S2", "S3"], ["S0"], ["S0", "S0"], None):
                    broken = copy.deepcopy(result)
                    broken["config"]["sensitivity_labels"] = labels
                    broken["checksum"] = artifact_checksum({k:v for k,v in broken.items() if k != "checksum"})
                    with self.assertRaisesRegex(ModelArtifactError, "S0 and non-S0"):
                        validate_artifact(broken)
        for threshold in (None, True, 0., 1., float("nan"), float("inf"), "0.38"):
            with self.assertRaises(ModelArtifactError):
                validate_decision_margin_config({"sensitivity_labels": ["S0", "S1"], "category_threshold": threshold})
        for threshold in (.38, .5, .9):
            validate_decision_margin_config({"sensitivity_labels": ["S1", "S0"], "category_threshold": threshold})

    def test_unknown_and_invalid_objective_types_fail_closed(self):
        for value in ("", "unknown", None, True, 1, [], {}):
            artifact = self.original()
            artifact["metadata"][OBJECTIVE_KEY] = value
            artifact["checksum"] = artifact_checksum({k:v for k,v in artifact.items() if k != "checksum"})
            with self.assertRaises(ModelArtifactError):
                validate_artifact(artifact)
            if value is not None:
                with self.assertRaises(ModelArtifactError):
                    prepare_training_objective_artifact(self.original(), value)

    def test_optimizer_is_independent_preserves_weights_and_can_restore_control(self):
        from privoke_model import prepare_training_optimizer_artifact as exported
        self.assertEqual(exported, prepare_training_optimizer_artifact)
        self.assertIsNone(validate_contextual_training_optimizer({}))
        for profile in ("efficient", "balanced", "quality"):
            for strategy in (None, LAST_BLOCK_STRATEGY):
                for objective in (None, CLASS_BALANCED_OBJECTIVE, CLASS_BALANCED_MEAN_CATEGORY_OBJECTIVE):
                    release = prepare_training_objective_artifact(
                        prepare_contextual_training_artifact(self.original(profile), strategy), objective)
                    before = copy.deepcopy(release)
                    for optimizer, steps in ((LOCAL_SGD_1, 1), (LOCAL_SGD_4, 4)):
                        prepared = prepare_training_optimizer_artifact(release, optimizer)
                        self.assertEqual(release, before)
                        for key in ("parameters", "config", "model_id", "version"):
                            self.assertEqual(prepared[key], release[key])
                        self.assertEqual(validate_contextual_training_optimizer(prepared["metadata"]), steps)
                        self.assertEqual(prepare_training_optimizer_artifact(prepared), release)
                        validate_artifact(prepared)

    def test_optimizer_unknown_or_invalid_types_fail_closed(self):
        for value in ("", "unknown", "local_sgd_2_v1", None, True, 1, [], {}):
            artifact = self.original()
            artifact["metadata"][OPTIMIZER_KEY] = value
            artifact["checksum"] = artifact_checksum({k:v for k,v in artifact.items() if k != "checksum"})
            with self.assertRaises(ModelArtifactError): validate_artifact(artifact)
            with self.assertRaises(ModelArtifactError): validate_contextual_training_optimizer({OPTIMIZER_KEY:value})

    def test_shared_go_fixture_and_legacy_names(self):
        fixture=json.loads((Path(__file__).parent / "fixtures/contextual-last-block.json").read_text())
        validate_artifact(fixture)
        self.assertEqual(sum(t["trainable"] for t in fixture["parameters"].values()),15)
        self.assertEqual(contextual_trainable_names({}),HEAD_NAMES)
        self.assertEqual(sum(t["trainable"] for t in self.original()["parameters"].values()),6)

if __name__ == "__main__": unittest.main()
