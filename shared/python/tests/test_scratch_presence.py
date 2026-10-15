"""Synthetic schema/identity checks; no released artifacts or training data."""
import copy
import json
import math
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

from privoke_model.artifact import (ModelArtifactError, artifact_checksum, validate_artifact,
                                   load_artifact, apply_parameter_update, float32)
from privoke_model.fingerprint import parameter_fingerprint
from privoke_model.scratch_presence import *


def synthetic_artifact(profile="efficient", mode="head_only"):
    config = dict(CONSTANT_CONFIG, profile=profile, training_mode=mode, threshold=0.5)
    config.update(zip(DIMENSION_KEYS, SCRATCH_PROFILES[profile]))
    trainable = set(scratch_presence_trainable_names(config))
    parameters = {name: {"shape": list(shape), "values": [0.0]*math.prod(shape),
                         "trainable": name in trainable}
                  for name, shape in scratch_presence_tensor_shapes(config).items()}
    parameters["head.presence.weight"]["values"][:4] = [-0.0, float32(0.1), float32(1e-40), float32(1e30)]
    metadata = {key: "a"*64 for key in HASH_METADATA}
    metadata.update(training_route="offline_release_fit_v1", source_revision="b"*40,
                    checkpoint_epoch="1", training_steps="490", training_seed="12102026")
    artifact = dict(schema_version=1, model_id=scratch_model_id(config), version="v1.0.0+epoch.1",
                    generated_at_unix=1700000000, architecture=SCRATCH_PRESENCE_ARCHITECTURE,
                    config=config, parameters=parameters, metadata=metadata)
    artifact["checksum"] = artifact_checksum(artifact)
    return artifact


def resign(artifact):
    artifact["checksum"] = artifact_checksum({k:v for k,v in artifact.items() if k != "checksum"})


def stream_metadata(artifact):
    c = artifact["config"]
    result = dict(artifact["metadata"], served_by="model-streaming-service", consumer_id="synthetic-test",
                  architecture=artifact["architecture"], model_config=json.dumps(c),
                  artifact_checksum=artifact["checksum"], artifact_file_checksum="c"*64,
                  trainable_parameters=",".join(scratch_presence_trainable_names(c)))
    for key in ("task", "profile", "training_mode", "tokenizer", "pooling", "arithmetic"):
        result[key] = c[key]
    result["text_normalization"] = c["normalization"]
    return result


class ScratchSchemaTests(unittest.TestCase):
    def test_all_six_exact_profiles_and_modes(self):
        for profile, count in zip(SCRATCH_PROFILES, (18553,36129,53665)):
            for mode in SCRATCH_MODES.values():
                a = synthetic_artifact(profile, mode)
                validate_artifact(a)
                self.assertEqual(sum(len(t["values"]) for t in a["parameters"].values()),count)
                self.assertEqual(a["model_id"] in SCRATCH_PRESENCE_MODEL_IDS, True)

    def test_shape_flags_and_closed_contracts(self):
        mutations = [lambda a:a.update(schema_version=True),lambda a:a.update(generated_at_unix=True),
            lambda a:a.update(generated_at_unix=2**63),lambda a:a.update(extra=1),
            lambda a:a["config"].update(hidden_size=64),lambda a:a["config"].update(threshold=True),
            lambda a:a["config"].update(extra=1),lambda a:a["metadata"].update(extra="x"),
            lambda a:a["metadata"].update(training_steps="0490"),lambda a:a["metadata"].update(checkpoint_epoch="2"),
            lambda a:a["metadata"].update(source_revision="ÃƒÂ©"*40),lambda a:a.update(architecture="privoke_tiny_transformer_v1"),
            lambda a:a.update(model_id="privoke-balanced"),lambda a:a["parameters"]["token_embedding"].update(trainable=True),
            lambda a:a["parameters"]["token_embedding"].pop("trainable"),lambda a:a["parameters"]["head.presence.bias"].update(shape=[True]),
            lambda a:a["parameters"]["head.presence.bias"].update(extra=1)]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                a=synthetic_artifact();mutation(a);resign(a)
                with self.assertRaises(ModelArtifactError):validate_artifact(a)

    def test_finite_exact_float32_and_unicode(self):
        for value in (True,0.1,float("nan"),float("inf"),1e100,10**1000):
            a=synthetic_artifact();a["parameters"]["head.presence.bias"]["values"]=[value]
            with self.subTest(value_type=type(value).__name__), self.assertRaises(ModelArtifactError):
                validate_artifact(a)
        a=synthetic_artifact();a["metadata"]["source_revision"]="\ud800"
        with self.assertRaises(ModelArtifactError):validate_artifact(a)

    def test_stream_metadata_config_mode_and_exact_csv(self):
        a=synthetic_artifact();m=stream_metadata(a)
        config=validate_scratch_presence_stream_metadata(a["model_id"],a["version"],m)
        config["threshold"]=1
        self.assertEqual(a["config"]["threshold"],0.5)
        for key,value in (("training_mode","end_to_end"),("architecture","privoke_tiny_transformer_v1"),
                          ("trainable_parameters","head.presence.weight,head.presence.bias"),
                          ("artifact_checksum","A"*64),("initialization_sha256","x"),("consumer_id","bad\nconsumer"),("extra","x")):
            bad=dict(m);bad[key]=value
            with self.subTest(key=key), self.assertRaises(ModelArtifactError):
                validate_scratch_presence_stream_metadata(a["model_id"],a["version"],bad)
        bad=dict(m);bad["model_config"]=m["model_config"][:-1]+',"threshold":0.5}'
        with self.assertRaises(ModelArtifactError):validate_scratch_presence_stream_metadata(a["model_id"],a["version"],bad)

    def test_raw_duplicates_bytes_and_checksum(self):
        a=synthetic_artifact()
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/"a.json";raw=json.dumps(a)
            for bad in (raw[:-1]+',"schema_version":1}', raw.replace('"architecture": "privoke_scratch_presence_transformer_v1"', '"architecture": "privoke_scratch_presence_transformer_v1", "architecture": "privoke_tiny_transformer_v1"'),raw.replace('"trainable": true','"trainable": true, "trainable": true',1)," "*(8*1024*1024)+raw):
                p.write_text(bad,encoding="utf-8")
                with self.assertRaises(ModelArtifactError):load_artifact(p)
            p.write_text(raw,encoding="utf-8");self.assertEqual(load_artifact(p)["checksum"],a["checksum"])
            a["checksum"]="0"*64;p.write_text(json.dumps(a),encoding="utf-8")
            with self.assertRaises(ModelArtifactError):load_artifact(p)

    def test_offline_only_and_provenance_identity(self):
        for mode in SCRATCH_MODES.values():
            a=synthetic_artifact(mode=mode)
            with self.assertRaisesRegex(ModelArtifactError,"offline"):
                apply_parameter_update(a,base_version=a["version"],deltas={"head.presence.bias":[0]},source_id="synthetic")
        b=copy.deepcopy(a);b["metadata"]["prepared_manifest_sha256"]="d"*64;resign(b)
        fp=lambda x:parameter_fingerprint({k:t["values"] for k,t in x["parameters"].items()},{k:t["shape"] for k,t in x["parameters"].items()})
        self.assertEqual(fp(a),fp(b));self.assertNotEqual(a["checksum"],b["checksum"])
        self.assertEqual(math.copysign(1,a["parameters"]["head.presence.weight"]["values"][0]),-1)

    def test_oversize_raw_rejected_before_json_parser(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/"oversize.json"
            path.write_bytes(b" "*(8*1024*1024+1))
            with patch("privoke_model.artifact.json.loads", side_effect=AssertionError("parser must not run")) as parser:
                with self.assertRaisesRegex(ModelArtifactError,"8 MiB"):
                    load_artifact(path)
                parser.assert_not_called()

    def test_shared_cross_language_fixture(self):
        a=load_artifact(Path(__file__).parent/"fixtures"/"scratch-presence-efficient.json")
        self.assertEqual(a,synthetic_artifact())


if __name__ == "__main__":unittest.main()
