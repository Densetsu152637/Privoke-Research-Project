"""Synthetic closed pretrained contextual artifact and transport contracts."""
import json
import math
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from privoke_model.artifact import (ModelArtifactError, apply_parameter_update,
                                    load_artifact, validate_artifact)
from privoke_model.pretrained_context import (
    PRETRAINED_CONTEXT_MODEL_ID, build_head_artifact, default_config, head_tensor_shapes,
    validate_pretrained_stream,
)


def fixture():
    return build_head_artifact({name: [0.0] * math.prod(shape) for name, shape in head_tensor_shapes().items()},
                               version="v1.0.0+synthetic.1", generated_at_unix=1,
                               metadata={"purpose": "synthetic_contract_fixture_no_quality_claim"})


class PretrainedContextContractTests(unittest.TestCase):
    def test_shared_go_fixture_and_head_roundtrip(self):
        path = Path(__file__).parent / "fixtures/pretrained-context-minilm.json"
        artifact = load_artifact(path)
        self.assertEqual(artifact, fixture())
        self.assertEqual(sum(len(t["values"]) for t in artifact["parameters"].values()), 7700)
        self.assertTrue(all(t["trainable"] is False for t in artifact["parameters"].values()))
        with self.assertRaisesRegex(ModelArtifactError, "offline"):
            apply_parameter_update(artifact, base_version=artifact["version"],
                                   deltas={"head.sensitivity.bias": [0.] * 4}, source_id="test")

    def test_closed_config_and_exact_heads_reject_invalid_artifacts(self):
        mutations = [lambda a: a.update(model_id="privoke-balanced"),
                     lambda a: a.update(version="x" * 129),
                     lambda a: a.update(architecture="privoke_tiny_transformer_v1"),
                     lambda a: a["config"].update(tokenizer_sha256="f" * 64),
                     lambda a: a["config"].update(max_tokens=513),
                     lambda a: a["config"].update(hidden_size=True),
                     lambda a: a["config"].update(category_threshold=0),
                     lambda a: a["config"].update(extra=True),
                     lambda a: a["config"].update(category_semantics="topic_tags_v1"),
                     lambda a: a["config"]["sensitivity_labels"].reverse(),
                     lambda a: a["parameters"].pop("head.category.weight"),
                     lambda a: a["parameters"].update(extra={"shape": [1], "values": [0.], "trainable": False}),
                     lambda a: a["parameters"]["head.visibility.bias"].update(trainable=True),
                     lambda a: a["parameters"]["head.visibility.bias"].update(shape=[2, 3]),
                     lambda a: a["parameters"]["head.category.bias"]["values"].__setitem__(0, 1e100),
                     lambda a: a["metadata"].update(bad="\ud800"),
                     lambda a: a.update(extra=True)]
        for mutate in mutations:
            artifact = fixture()
            mutate(artifact)
            with self.subTest(mutate=mutate), self.assertRaises(ModelArtifactError):
                validate_artifact(artifact)

    def test_explicit_context_profiles_roundtrip_preserve_heads_and_default(self):
        original = fixture()
        parameters = {name: tensor["values"] for name, tensor in original["parameters"].items()}
        extended = build_head_artifact(parameters, version=original["version"], generated_at_unix=1,
                                       metadata=original["metadata"], max_tokens=512)
        self.assertEqual(original["config"]["max_tokens"], 256)
        self.assertEqual(extended["parameters"], original["parameters"])
        self.assertNotEqual(extended["checksum"], original["checksum"])
        with TemporaryDirectory() as temporary:
            for artifact in (original, extended):
                path = Path(temporary) / "artifact.json"
                path.write_text(json.dumps(artifact), encoding="utf-8")
                self.assertEqual(load_artifact(path), artifact)
        for value in (True, 256.0, 512.0, "512", None, 0, 255, 257, 511, 513):
            with self.subTest(value=value), self.assertRaises(ModelArtifactError):
                default_config(max_tokens=value)
            artifact = fixture()
            artifact["config"]["max_tokens"] = value
            with self.assertRaises(ModelArtifactError):
                validate_artifact(artifact)

    def test_duplicate_json_keys_cannot_hide_reserved_identity(self):
        raw = json.dumps(fixture())
        invalid = [raw.replace('"schema_version": 1', '"schema_version": 1, "schema_version": 1'),
                   raw.replace('"category_threshold": 0.5', '"category_threshold": 0.5, "category_threshold": 0.6'),
                   raw.replace('"architecture": "privoke_pretrained_context_v1"',
                               '"architecture": "privoke_pretrained_context_v1", "architecture": "privoke_tiny_transformer_v1"')]
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "artifact.json"
            for text in invalid:
                path.write_text(text, encoding="utf-8")
                with self.assertRaisesRegex(ModelArtifactError, "duplicate"):
                    load_artifact(path)

    def test_stream_requires_exact_identity_checksum_and_no_online_scope(self):
        metadata = {"architecture": "privoke_pretrained_context_v1", "model_config": json.dumps(default_config()),
                    "artifact_checksum": "a" * 64, "trainable_parameters": ""}
        self.assertEqual(validate_pretrained_stream(PRETRAINED_CONTEXT_MODEL_ID, metadata), default_config())
        for key, value in (("artifact_checksum", ""), ("trainable_parameters", "head.category.bias"),
                           ("model_config", '{"hidden_size":384,"hidden_size":384}')):
            with self.assertRaises(ModelArtifactError):
                validate_pretrained_stream(PRETRAINED_CONTEXT_MODEL_ID, dict(metadata, **{key: value}))
        with self.assertRaises(ModelArtifactError):
            validate_pretrained_stream("latest", metadata)

    def test_closed_ascii_release_versions_match_go(self):
        for version in ("", "has space", "café", ".leading", "x" * 129):
            artifact = fixture()
            artifact["version"] = version
            with self.subTest(version=version), self.assertRaisesRegex(ModelArtifactError, "version"):
                validate_artifact(artifact)


if __name__ == "__main__":
    unittest.main()
