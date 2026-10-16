"""Pinned product package/cache and native parity on fixed non-sensitive probes."""
import hashlib
import io
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from privoke.v1 import parameters_pb2 as pb
from privoke_model.standard_v3 import STANDARD_PINS, ASSETS, admitted_manifest, verify_package, is_link
from src.LLM.privoke import v3_package as transport

ROOT = Path(__file__).resolve().parents[3]
RELEASES = ROOT / "models/standard-releases"
TEMP = ROOT / ".tmp/v3-standard-tests"
TEMP.mkdir(parents=True, exist_ok=True)


class StandardV3TransportTests(unittest.TestCase):
    def test_receive_asset_rejects_corruption_identity_order_size_and_truncation(self):
        identity = dict(model_id="privoke-v3-balanced", pin=STANDARD_PINS["privoke-v3-balanced"],
                        name="config.json", expected_sha=hashlib.sha256(b"abc").hexdigest(), expected_size=3)
        good = pb.ModelAssetChunk(model_id=identity["model_id"], manifest_sha256=identity["pin"],
            asset_name=identity["name"], sha256=identity["expected_sha"], offset=0, total_bytes=3, data=b"abc")
        outgoing = io.BytesIO()
        transport.receive_asset([good], outgoing, **identity)
        self.assertEqual(outgoing.getvalue(), b"abc")
        for field, value in (("model_id", "privoke-v3-quality"), ("manifest_sha256", "0"*64),
                ("asset_name", "../config.json"), ("sha256", "0"*64), ("offset", 1),
                ("total_bytes", 4), ("data", b"abd"), ("data", b""), ("data", b"abcd")):
            bad = pb.ModelAssetChunk(); bad.CopyFrom(good); setattr(bad, field, value)
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                transport.receive_asset([bad], io.BytesIO(), **identity)
        for chunks in ([], [good,good]):
            with self.assertRaises(ValueError): transport.receive_asset(chunks, io.BytesIO(), **identity)
        for changes in ({"expected_size":0},{"expected_size":80*1024*1024+1},{"name":"../config.json"}):
            with self.assertRaises(ValueError): transport.receive_asset([good],io.BytesIO(),**{**identity,**changes})

    def test_manifest_pins_reject_modified_or_wrong_requested_release(self):
        if not RELEASES.is_dir(): self.skipTest("local AU3 packages absent; CI mechanics do not claim native V3 parity")
        for model_id, pin in STANDARD_PINS.items():
            raw = (RELEASES/model_id/"manifest.json").read_bytes()
            self.assertEqual(hashlib.sha256(raw).hexdigest(), pin)
            self.assertEqual(admitted_manifest(raw, model_id)["model_id"], model_id)
            with self.assertRaises(ValueError): admitted_manifest(raw+b" ", model_id)
            with self.assertRaises(ValueError): admitted_manifest(raw, "privoke-v3-nonexistent")

    def test_download_cache_refresh_and_corrupted_cache_fail_closed(self):
        if not RELEASES.is_dir(): self.skipTest("local AU3 packages absent")
        model_id="privoke-v3-efficient"
        directory=RELEASES/model_id
        manifest=verify_package(directory, model_id)
        raw=(directory/"manifest.json").read_bytes()
        package=pb.ModelPackageResponse(model_id=model_id, architecture=manifest["architecture"],
            manifest_sha256=STANDARD_PINS[model_id], manifest_json=raw,
            assets=[pb.ModelPackageAsset(name=name, sha256=manifest[key], size_bytes=(directory/name).stat().st_size)
                    for name,key in ASSETS.items()])
        class Client:
            streams=0
            def GetModelPackage(self, request, timeout): return package
            def StreamModelAsset(self, request, timeout):
                self.streams+=1
                data=(directory/request.asset_name).read_bytes()
                for offset in range(0,len(data),1024*1024):
                    yield pb.ModelAssetChunk(model_id=model_id, manifest_sha256=STANDARD_PINS[model_id],
                        asset_name=request.asset_name, sha256=manifest[ASSETS[request.asset_name]],
                        offset=offset,total_bytes=len(data),data=data[offset:offset+1024*1024])
        client=Client(); request=pb.ModelParametersRequest(model_id="latest",consumer_id="unit")
        with tempfile.TemporaryDirectory(dir=TEMP) as temporary, patch.dict(os.environ,{"MODEL_PACKAGE_CACHE_DIR":temporary}):
            transport._PACKAGES.clear()
            snapshot=transport.fetch_package(client,request,target="unit",timeout=1)
            self.assertEqual(client.streams,4)
            self.assertIs(transport.fetch_package(client,request,target="unit",timeout=1),snapshot)
            self.assertEqual(client.streams,4, "TTL refresh must not redownload weights")
            (snapshot.directory/"manifest.json").write_bytes(b"corrupt")
            with self.assertRaises(ValueError): transport.fetch_package(client,request,target="unit",timeout=1)
            (snapshot.directory/"manifest.json").write_bytes(raw)
            (snapshot.directory/"config.json").write_bytes(b"corrupt")
            transport._PACKAGES.clear()
            with self.assertRaises(ValueError): transport.fetch_package(client,request,target="unit",timeout=1)

    def test_manifest_download_race_cannot_activate_package(self):
        if not RELEASES.is_dir(): self.skipTest("local AU3 packages absent")
        model_id="privoke-v3-efficient";directory=RELEASES/model_id
        manifest=verify_package(directory,model_id)
        package=pb.ModelPackageResponse(model_id=model_id,architecture=manifest["architecture"],
            manifest_sha256=STANDARD_PINS[model_id],manifest_json=(directory/"manifest.json").read_bytes(),
            assets=[pb.ModelPackageAsset(name=name,sha256=manifest[key],size_bytes=(directory/name).stat().st_size) for name,key in ASSETS.items()])
        class Client:
            calls=0
            def GetModelPackage(self,request,timeout):
                self.calls+=1
                result=pb.ModelPackageResponse();result.CopyFrom(package)
                if self.calls>1: result.manifest_sha256="0"*64
                return result
            def StreamModelAsset(self,request,timeout): raise AssertionError("existing verified assets should be reused")
        import shutil
        with tempfile.TemporaryDirectory(dir=TEMP) as temporary,patch.dict(os.environ,{"MODEL_PACKAGE_CACHE_DIR":temporary}):
            cache=Path(temporary)/model_id/STANDARD_PINS[model_id];cache.mkdir(parents=True)
            for name in ASSETS: shutil.copyfile(directory/name,cache/name)
            transport._PACKAGES.clear()
            with self.assertRaisesRegex(ValueError,"changed while"): transport.fetch_package(Client(),pb.ModelParametersRequest(model_id=model_id),target="race",timeout=1)
            self.assertFalse((cache/"manifest.json").exists())

    def test_private_cache_rejects_link_ancestor(self):
        with tempfile.TemporaryDirectory(dir=TEMP) as temporary:
            root=Path(temporary);(root/"real").mkdir()
            try: (root/"link").symlink_to(root/"real",target_is_directory=True)
            except OSError: self.skipTest("host symlink creation unavailable")
            with self.assertRaises(ValueError): transport.private_directory(root/"link"/"child")

    def test_windows_reparse_attribute_is_rejected_without_symlink_privileges(self):
        from types import SimpleNamespace
        with patch.object(Path,"lstat",return_value=SimpleNamespace(st_mode=0,st_file_attributes=0x400)):
            self.assertTrue(is_link("junction"))
            with self.assertRaises(ValueError): transport.private_directory(TEMP/"junction"/"child")


class StandardV3NativeParityTests(unittest.TestCase):
    def test_all_three_exact_packages_preserve_full_state_and_native_predictions(self):
        if not RELEASES.is_dir(): self.skipTest("local AU3 packages absent; native parity unverified")
        import torch
        from src.v3.model import PretrainedV3, inventory
        from src.LLM.privoke.streamed_model import StreamedModelCache
        torch.set_num_threads(4)
        probes=("Explain the water cycle for a public school lesson.",
                "Write a friendly invitation to a community picnic.")
        for model_id,pin in STANDARD_PINS.items():
            with self.subTest(model_id=model_id):
                directory=RELEASES/model_id;manifest=verify_package(directory,model_id)
                snapshot=transport.NativeV3Package(model_id,pin,directory,manifest)
                with patch.dict(os.environ,{"PRIVOKE_MODEL_DEVICE":"cpu"}):
                    product=transport.NativeV3PrivacyModel(snapshot)
                reference=PretrainedV3.load(manifest,directory/"model.safetensors",directory/"config.json",directory/"vocab.txt",device="cpu")
                self.assertEqual(inventory(product.model.state_dict()),manifest["tensors"])
                normalise=lambda rows: [(classification.pack(),confidence) for classification,confidence in rows]
                self.assertEqual(normalise(product.model.predictions(list(probes))),normalise(reference.predictions(list(probes))))
                for text in probes:
                    expected=reference.findings(text,{})
                    actual=product.classify(text)
                    self.assertEqual([(r.classification.pack(),r.confidence,r.span) for r in actual],
                                     [(r.classification.pack(),r.confidence,r.span) for r in expected])
                from src.pipeline import _semantic_snapshot_identity
                clean_identity=_semantic_snapshot_identity(product)
                self.assertEqual(clean_identity["backbone_sha256"],manifest["source"]["weights_sha256"])
                self.assertEqual(clean_identity["tokenizer_sha256"],manifest["vocab"])
                from privoke.v1 import runtime_pb2
                from src.hosting.grpc_server import PrivokeRuntimeService
                from src.LLM.privoke_classifier import PriVokeClassifier
                # In-process product boundary, not an installed-browser claim.
                for index,text in enumerate(probes):
                    request=runtime_pb2.AnalyzePromptRequest(text=text,request_id=f"standard-{model_id}-{index}",
                        semantic_model_id=model_id,layers=[runtime_pb2.DETECTION_LAYER_SEMANTIC])
                    with patch("src.pipeline.get_llm_choice",return_value=PriVokeClassifier(model_id=model_id)), \
                            patch("src.pipeline._streamed_model_for_semantic_detector",return_value=product):
                        response=PrivokeRuntimeService().AnalyzePrompt(request,None)
                    self.assertEqual(response.error,"")
                    self.assertEqual([(layer.layer,layer.status) for layer in response.layers],[(4,"ok")])
                    for key,value in clean_identity.items():
                        self.assertEqual(response.metadata["privoke.semantic."+key],value)
                self.assertEqual(snapshot.metadata["architecture"],"privoke_pretrained_bert_v3")
                self.assertEqual(snapshot.fingerprint,manifest["blob"])
                self.assertEqual(snapshot.version,pin)
                self.assertFalse(any(p.requires_grad for p in product.model.parameters()))
                cache=StreamedModelCache(0)
                with patch.object(cache,"_model_for_streamer",return_value=product):
                    streamer=type("Streamer",(),{"model_id":model_id})()
                    with self.assertRaisesRegex(ValueError,"legacy gradient"): cache.model_for_training(streamer)
                del product,reference


if __name__=="__main__": unittest.main()
