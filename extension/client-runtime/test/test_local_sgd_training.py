"""Transported local-SGD behavior; model calls use synthetic, offline unit inputs."""
import hashlib
import json
import math
import sys
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
for path in (ROOT, ROOT / "generated", ROOT.parents[1] / "shared/python"):
    sys.path.insert(0, str(path))
from privoke_model.artifact import apply_parameter_update, float32, updated_parameter_values
from privoke_model.fingerprint import parameter_fingerprint
from privoke_model.contextual_training import (OPTIMIZER_KEY, LOCAL_SGD_1, LOCAL_SGD_4,
    CLASS_BALANCED_OBJECTIVE, CLASS_BALANCED_MEAN_CATEGORY_OBJECTIVE, LAST_BLOCK_STRATEGY,
    prepare_contextual_training_artifact, prepare_training_objective_artifact,
    prepare_training_optimizer_artifact)
from src.LLM.privoke.streamed_model import GLOBAL_STREAMED_MODEL_CACHE, StreamedTransformerPrivacyModel
from src.LLM.privoke.training import (SemanticTrainingExample, compute_semantic_gradients,
    _local_sgd_updates, _local_training_losses, _parameter_fingerprint)
from src.LLM.privoke import training
from src.LLM.privoke.supervised_training import supervised_last_block_deltas
from src.classification import Sensitivity, Visibility, Category, initialise_unpacked
from test_training_adaptation import snapshot
try:
    import torch
except ImportError:
    torch = None


class LocalSGDTests(unittest.TestCase):
    def examples(self):
        clean = initialise_unpacked(Sensitivity.S0, Visibility.P0, [])
        private = initialise_unpacked(Sensitivity.S3, Visibility.PU, [Category.HEALTH])
        return (SemanticTrainingExample("Public weather bulletin", clean, .5),
                SemanticTrainingExample("My private cancer diagnosis", private, 2.),
                SemanticTrainingExample("Blank anonymous public form", clean, 1.25))

    def artifact(self, profile="balanced", objective=CLASS_BALANCED_MEAN_CATEGORY_OBJECTIVE,
                 strategy=None, optimizer=None):
        base = json.loads((ROOT.parents[1] / f"models/privoke-{profile}.json").read_text(encoding="utf-8"))
        release = prepare_training_objective_artifact(prepare_contextual_training_artifact(base, strategy), objective)
        return prepare_training_optimizer_artifact(release, optimizer)

    def batch(self, artifact, examples=None, rate=.003, bound=.05, heldout=()):
        wrapper = StreamedTransformerPrivacyModel(snapshot(artifact))
        with patch.object(GLOBAL_STREAMED_MODEL_CACHE, "model_for_training", return_value=wrapper):
            result = compute_semantic_gradients(examples or self.examples(), model_id=artifact["model_id"],
                learning_rate=rate, max_gradient=bound, heldout_examples=heldout)
        return result, wrapper

    def test_conditional_cache_binding_keeps_exact_absent_identity(self):
        artifact = self.artifact()
        base = snapshot(artifact)
        fields = {name: base.metadata.get(name) for name in (
            "architecture", "model_config", "trainable_parameters", "contextual_training_strategy",
            "contextual_training_objective")}
        digest = hashlib.sha256(json.dumps(fields, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
        self.assertEqual(base.cache_key, f"{base.model_id}:{base.version}:{base.fingerprint}:{digest}")
        keys = [base.cache_key]
        for optimizer in (LOCAL_SGD_1, LOCAL_SGD_4):
            opted = snapshot(prepare_training_optimizer_artifact(artifact, optimizer))
            self.assertEqual(opted.fingerprint, base.fingerprint)
            keys.append(opted.cache_key)
        self.assertEqual(len(set(keys)), 3)

    def test_absent_path_never_enters_local_loop(self):
        with patch("src.LLM.privoke.training._local_sgd_updates", side_effect=AssertionError("legacy local loop")):
            for objective in (None, CLASS_BALANCED_OBJECTIVE, CLASS_BALANCED_MEAN_CATEGORY_OBJECTIVE):
                batch, _ = self.batch(self.artifact(objective=objective))
                self.assertNotIn("contextual_optimizer_trace", batch.metadata)

    def test_one_step_nonsaturated_parity_all_profiles_and_objectives(self):
        for profile in ("efficient", "balanced", "quality"):
            for objective in (None, CLASS_BALANCED_OBJECTIVE, CLASS_BALANCED_MEAN_CATEGORY_OBJECTIVE):
                artifact = self.artifact(profile, objective)
                control, _ = self.batch(artifact)
                opted, _ = self.batch(prepare_training_optimizer_artifact(artifact, LOCAL_SGD_1))
                self.assertEqual(opted.gradients, control.gradients)
                self.assertEqual(opted.metrics, control.metrics)
                for key,value in control.metadata.items():
                    if key != "model_cache_key": self.assertEqual(opted.metadata[key], value)
                self.assertEqual(set(opted.metadata) - set(control.metadata), {"contextual_optimizer_trace"})

    def test_four_steps_relinearize_reduce_training_objective_and_preserve_frozen_tensors(self):
        for profile in ("efficient", "balanced", "quality"):
            artifact = self.artifact(profile, optimizer=LOCAL_SGD_4)
            heldout = tuple(replace(row, text=f"Heldout distinct phrase {i}") for i,row in enumerate(self.examples()[:2]))
            batch, wrapper = self.batch(artifact, heldout=heldout)
            before = {name: np.asarray(tensor["values"],dtype=np.float32).reshape(tensor["shape"])
                      for name,tensor in artifact["parameters"].items()}
            trace = json.loads(batch.metadata["contextual_optimizer_trace"])
            self.assertEqual(trace["steps"], 4)
            self.assertEqual(len(trace["loss"]), 5)
            self.assertEqual(len(trace["updates"]), 4)
            self.assertEqual(len(trace["state_parameter_fingerprints"]),5)
            self.assertEqual(trace["state_parameter_fingerprints"][0],wrapper.snapshot.fingerprint)
            self.assertLess(trace["loss"][-1][-1], trace["loss"][0][-1])
            self.assertLessEqual(len(batch.metadata["contextual_optimizer_trace"].encode()), 2048)
            self.assertNotEqual(trace["updates"][0][0], trace["updates"][1][0])
            for loss in trace["loss"]:
                self.assertAlmostEqual(math.fsum(loss[:3]), loss[3], places=12)
            one, _ = self.batch(prepare_training_optimizer_artifact(artifact, LOCAL_SGD_1), rate=.012)
            self.assertNotEqual(batch.gradients, one.gradients)
            published = apply_parameter_update(artifact, base_version=artifact["version"], deltas=batch.gradients, source_id="unit")
            params = {name:tuple(float32(v) for v in tensor["values"]) for name,tensor in published["parameters"].items()}
            self.assertEqual(batch.metadata["updated_parameter_fingerprint"], _parameter_fingerprint(params))
            self.assertEqual(trace["state_parameter_fingerprints"][-1],parameter_fingerprint(params,wrapper.snapshot.shapes))
            for name,tensor in artifact["parameters"].items():
                if not tensor["trainable"]: self.assertEqual(published["parameters"][name], tensor)
                np.testing.assert_array_equal(wrapper.model.parameters[name], before[name])
            final = training.TinyTransformerModel(wrapper.model.config, params, wrapper.snapshot.shapes, device=wrapper.model.compute_device)
            adjusted,_ = training._class_balanced_examples(tuple(replace(row,text=training.normalize_text(row.text)) for row in self.examples()))
            self.assertEqual(trace["loss"][-1], _local_training_losses(final, adjusted, CLASS_BALANCED_MEAN_CATEGORY_OBJECTIVE))
            self.assertEqual(batch.metrics["supervised_objective_loss"], trace["loss"][0][-1])

    def test_manual_four_step_ce_bce_derivatives_match_each_nonlinear_state(self):
        artifact=self.artifact(optimizer=LOCAL_SGD_4)
        batch,wrapper=self.batch(artifact)
        rows,_=training._class_balanced_examples(tuple(replace(row,text=training.normalize_text(row.text))
                                                     for row in self.examples()))
        total=math.fsum(row.weight for row in rows)
        names=sorted(batch.gradients)
        accumulated={name:tuple(0. for _ in wrapper.snapshot.parameters[name]) for name in names}
        parameters=wrapper.snapshot.parameters
        states=[parameter_fingerprint(parameters,wrapper.snapshot.shapes)]
        expected_updates=[]
        for step in range(4):
            model=training.TinyTransformerModel(wrapper.model.config,parameters,wrapper.snapshot.shapes,
                                               device=wrapper.model.compute_device)
            gradients={name:[0.]*len(accumulated[name]) for name in names}
            # Differentiate CE and BCE directly from probabilities; do not call
            # either runtime direction helper or the head-delta implementation.
            for row,prediction in zip(rows,model.predict_many(tuple(row.text for row in rows))):
                pooled=np.asarray(prediction.pooled,dtype=np.float32)
                for head in ("sensitivity","visibility","category"):
                    labels=getattr(model.config,f"{head}_labels")
                    if head=="category":
                        selected={category.name for category in row.target.categories()}
                        target=np.asarray([float(label in selected) for label in labels],dtype=np.float32)
                    else:
                        label=getattr(row.target,head)().name
                        target=np.asarray([float(item==label) for item in labels],dtype=np.float32)
                    probabilities=np.asarray(getattr(prediction,f"{head}_probabilities"),dtype=np.float32)
                    negative_error=target-probabilities
                    derivatives={f"head.{head}.weight":np.outer(pooled,negative_error).ravel(),
                                 f"head.{head}.bias":negative_error}
                    for name,values in derivatives.items():
                        for index,value in enumerate(values):
                            normalized=float(value)/len(labels) if head=="category" else float(value)
                            gradients[name][index]+=normalized*(row.weight/total)
            raw={name:tuple((value*.003 if step==0 else prior+value*.003)
                           for prior,value in zip(accumulated[name],gradients[name])) for name in names}
            norm=math.hypot(*(value for name in names for value in gradients[name]))
            rawmax=max(abs(value) for values in raw.values() for value in values)
            accumulated={name:tuple(float32(value) for value in values) for name,values in raw.items()}
            expected_updates.append([norm,rawmax,0,max(abs(value) for values in accumulated.values() for value in values)])
            parameters={name:tuple(float32(value) for value in updated_parameter_values(values,accumulated[name]))
                        if name in accumulated else tuple(float32(value) for value in values)
                        for name,values in wrapper.snapshot.parameters.items()}
            states.append(parameter_fingerprint(parameters,wrapper.snapshot.shapes))
        trace=json.loads(batch.metadata["contextual_optimizer_trace"])
        self.assertEqual(batch.gradients,accumulated)
        self.assertEqual(trace["state_parameter_fingerprints"],states)
        self.assertEqual(trace["updates"],expected_updates)

    def test_final_heldout_guard_receives_the_actual_publication_candidate(self):
        artifact=self.artifact(optimizer=LOCAL_SGD_4)
        heldout=tuple(replace(row,text=f"Separate reserved guard row {i}",weight=11.+i)
                      for i,row in enumerate(self.examples()[:2]))
        with patch("src.LLM.privoke.training._heldout_metrics", wraps=training._heldout_metrics) as guard:
            batch,wrapper=self.batch(artifact,heldout=heldout)
        self.assertEqual(guard.call_count,2)
        self.assertEqual(guard.call_args_list[0].args[1],wrapper.snapshot.parameters)
        published=apply_parameter_update(artifact,base_version=artifact["version"],deltas=batch.gradients,source_id="unit")
        candidate={name:tuple(float32(v) for v in tensor["values"]) for name,tensor in published["parameters"].items()}
        self.assertEqual(guard.call_args_list[1].args[1],candidate)
        self.assertEqual(guard.call_args_list[1].kwargs["reference_parameters"],wrapper.snapshot.parameters)
        self.assertEqual(guard.call_args_list[0].args[2],guard.call_args_list[1].args[2])
        self.assertEqual([row.weight for row in guard.call_args_list[1].args[2]],[11.,12.])

    def test_four_steps_preserve_legacy_and_summed_objective_definitions(self):
        for objective in (None, CLASS_BALANCED_OBJECTIVE):
            artifact=self.artifact(objective=objective,optimizer=LOCAL_SGD_4)
            batch,_=self.batch(artifact)
            trace=json.loads(batch.metadata["contextual_optimizer_trace"])
            self.assertEqual(trace["objective"],objective or "legacy_sum_category")
            self.assertEqual(trace["category_normalization"],"sum_labels")
            self.assertLess(trace["loss"][-1][-1],trace["loss"][0][-1])
            self.assertNotEqual(batch.metrics["average_loss"],trace["loss"][0][-1])

    def test_four_steps_common_weight_rescaling_and_global_denominator(self):
        rows = tuple(replace(row,weight=1.) for row in self.examples()[:2])
        artifact = self.artifact(optimizer=LOCAL_SGD_4)
        ordinary,_ = self.batch(artifact,rows)
        huge,_ = self.batch(artifact,tuple(replace(row,weight=8e307) for row in rows))
        self.assertEqual(ordinary.gradients, huge.gradients)
        self.assertEqual(ordinary.metadata["contextual_optimizer_trace"], huge.metadata["contextual_optimizer_trace"])
        self.assertEqual(huge.metrics["raw_total_weight"], 1.6e308)

    def test_explicit_targets_are_required_even_for_unbalanced_heads(self):
        for optimizer in (LOCAL_SGD_1, LOCAL_SGD_4):
            with self.assertRaisesRegex(ValueError,"explicit contextual targets"):
                self.batch(self.artifact(objective=None,optimizer=optimizer), (replace(self.examples()[0],target=None),))

    def toy_updates(self, initial, callback, rate=.1, bound=.5, optimizer=LOCAL_SGD_4):
        config = SimpleNamespace(category_labels=("a", "b"))
        class Toy:
            compute_device = "cpu"
            def __init__(self, config, parameters, shapes=None, device=None):
                self.config = config
                self.parameters = parameters
        base = {"x":(1.,)}
        visited=[]
        def direction(model,*args):
            visited.append(model.parameters["x"][0])
            return {"x":(callback(model.parameters["x"][0],len(visited)),)},1.
        with patch("src.LLM.privoke.training.TinyTransformerModel", Toy), \
             patch("src.LLM.privoke.training._local_training_losses",return_value=[0.,0.,0.,0.]), \
             patch("src.LLM.privoke.training._local_sgd_direction",side_effect=direction):
            result,trace = _local_sgd_updates(Toy(config,base),base,{"x":(1,)},self.examples(),{"x"},None,None,
                optimizer,rate,bound,{"x":(initial,)},1.)
        return result,json.loads(trace),visited

    def test_quadratic_relinearization_uses_transported_intermediate_candidates(self):
        result,trace,visited = self.toy_updates(-1.,lambda x,_: -x)
        expected=0.
        states=[]
        fingerprints=[parameter_fingerprint({"x":(1.,)},{"x":(1,)})]
        for step in range(4):
            theta=float32(updated_parameter_values((1.,),(expected,))[0])
            if step: states.append(theta)
            expected=float32(expected - .1*theta)
            transported={"x":(float32(updated_parameter_values((1.,),(expected,))[0]),)}
            fingerprints.append(parameter_fingerprint(transported,{"x":(1,)}))
        self.assertEqual(trace["state_parameter_fingerprints"],fingerprints)
        self.assertEqual(result["x"],(expected,))
        self.assertEqual(visited,states)
        self.assertNotEqual(result["x"],(float32(-.4),))
        self.assertEqual(trace["updates"][0][0],1.)

    def test_saturation_uses_raw_direction_and_strict_inward_float32_cap(self):
        result,trace,_ = self.toy_updates(100.,lambda x,_:100.,bound=.05)
        self.assertLessEqual(abs(result["x"][0]),.05)
        self.assertEqual(trace["updates"][0][0],100.)
        self.assertEqual(trace["updates"][0][1],10.)
        self.assertEqual(trace["updates"][0][2],1)
        self.assertEqual(trace["updates"][0][3],training._inward_float32_bound(.05))
        one,one_trace,_ = self.toy_updates(100.,lambda x,_:100.,bound=.05,optimizer=LOCAL_SGD_1)
        self.assertEqual(one,result)
        self.assertEqual(len(one_trace["loss"]),2)

    def test_saturated_increment_can_cancel_without_using_unclipped_accumulator(self):
        cap=training._inward_float32_bound(.05)
        result,trace,visited=self.toy_updates(100.,lambda x,i: -cap/.1 if i==1 else 0.,bound=.05)
        self.assertAlmostEqual(result["x"][0],0.,places=8)
        self.assertEqual(trace["updates"][0][2],1)
        self.assertEqual(trace["updates"][1][2],0)
        self.assertAlmostEqual(visited[1],1.,places=7)

    def test_nonfinite_increment_or_recomputed_direction_fails_before_clipping(self):
        for initial,callback in ((float("inf"),lambda x,_:0.),(1.,lambda x,_:float("nan"))):
            with self.assertRaisesRegex(ValueError,"remain finite"):
                self.toy_updates(initial,callback)
        with self.assertRaisesRegex(ValueError,"remain finite"):
            self.toy_updates(1e308,lambda x,_:0.,rate=10.)

    def test_real_saturated_head_update_obeys_transported_bound(self):
        artifact=self.artifact(optimizer=LOCAL_SGD_4)
        batch,_=self.batch(artifact,rate=10.,bound=.05)
        self.assertTrue(all(abs(value)<=.05 for values in batch.gradients.values() for value in values))
        trace=json.loads(batch.metadata["contextual_optimizer_trace"])
        self.assertGreater(sum(row[2] for row in trace["updates"]),0)
        self.assertTrue(all(row[3]<=.05 for row in trace["updates"]))

    def test_mean_quota_publication_metadata_fits_last_available_slot(self):
        heldout=tuple(replace(row,text=f"Reserved metadata-budget row {i}")
                      for i,row in enumerate(self.examples()[:2]))
        batch,_=self.batch(self.artifact(optimizer=LOCAL_SGD_4),heldout=heldout)
        submitted={**batch.metadata,**{key:str(value) for key,value in batch.metrics.items()},
            "new_examples":"256.0","golden_examples":"0.0","transformations_per_example":"0"}
        audit_keys=("contextual_sampling_strategy","sampling_training_rows","sampling_training_unique_texts",
            "sampling_authored_sensitive_rows","sampling_authored_clean_rows","sampling_public_negative_rows",
            "sampling_bootstrap_replay_rows","sampling_training_sensitive_rows","sampling_training_clean_rows",
            "sampling_authored_groups","sampling_authored_sensitive_groups","sampling_authored_clean_groups")
        submitted.update({key:"synthetic-count-budget" for key in audit_keys})
        submitted.update({key:"synthetic-publication-budget" for key in ("request_id","request_source_id",
            "requested_prompt_count","generated_prompt_count","training_pipeline","training_request_fingerprint")})
        self.assertEqual(len(submitted),64)
        self.assertLessEqual(len(submitted["contextual_optimizer_trace"].encode()),2048)
        self.assertNotIn(OPTIMIZER_KEY,submitted)

    def test_trace_size_budget_is_enforced_before_emission(self):
        with patch("src.LLM.privoke.training.json.dumps",return_value="x"*2049):
            with self.assertRaisesRegex(ValueError,"metadata byte budget"):
                self.toy_updates(-1.,lambda x,_:-x)

    @unittest.skipUnless(torch is not None,"opt-in Torch dependency unavailable on host")
    def test_last_block_step_one_nonsaturated_parity_all_profiles_and_objectives(self):
        cap=training._inward_float32_bound(.05)
        for profile in ("efficient", "balanced", "quality"):
            for objective in (None, CLASS_BALANCED_OBJECTIVE, CLASS_BALANCED_MEAN_CATEGORY_OBJECTIVE):
                with self.subTest(profile=profile,objective=objective):
                    artifact=self.artifact(profile,objective,LAST_BLOCK_STRATEGY)
                    # Prove this parity control is strictly below the new cap;
                    # saturation intentionally has different transport semantics.
                    before,_=self.batch(artifact,rate=1e-7)
                    self.assertTrue(all(abs(value)<cap for values in before.gradients.values() for value in values))
                    after,_=self.batch(prepare_training_optimizer_artifact(artifact,LOCAL_SGD_1),rate=1e-7)
                    self.assertEqual(before.gradients,after.gradients)

    @unittest.skipUnless(torch is not None,"opt-in Torch dependency unavailable on host")
    def test_last_block_saturation_preserves_nonsaturated_coordinates_and_exact_publication(self):
        cap=training._inward_float32_bound(.05)
        total_clipped=0
        for profile in ("efficient", "balanced", "quality"):
            for objective in (None, CLASS_BALANCED_OBJECTIVE, CLASS_BALANCED_MEAN_CATEGORY_OBJECTIVE):
                with self.subTest(profile=profile,objective=objective):
                    artifact=self.artifact(profile,objective,LAST_BLOCK_STRATEGY)
                    opted=prepare_training_optimizer_artifact(artifact,LOCAL_SGD_1)
                    captured=[]
                    def capture(*args,**kwargs):
                        result=supervised_last_block_deltas(*args,**kwargs)
                        captured.append(result[0])
                        return result
                    with patch("src.LLM.privoke.supervised_training.supervised_last_block_deltas",side_effect=capture):
                        before,_=self.batch(artifact,rate=.003)
                        after,wrapper=self.batch(opted,rate=.003)
                    self.assertEqual(len(captured),2)
                    self.assertEqual(captured[0],captured[1])
                    increments=[value*.003 for name in sorted(captured[1]) for value in captured[1][name]]
                    clipped=sum(abs(value)>cap for value in increments)
                    total_clipped+=clipped
                    for name in before.gradients:
                        for old,new in zip(before.gradients[name],after.gradients[name]):
                            if abs(old)<=cap:
                                self.assertEqual(new,old)
                            else:
                                self.assertEqual(new,math.copysign(cap,old))
                            self.assertLessEqual(abs(new),.05)
                    trace=json.loads(after.metadata["contextual_optimizer_trace"])
                    self.assertEqual(trace["transport_cap"],cap)
                    self.assertEqual(trace["updates"][0][2],clipped)
                    self.assertEqual(trace["updates"][0][1],max(map(abs,increments)))
                    self.assertEqual(trace["updates"][0][0],math.hypot(*(value for name in sorted(captured[1])
                                                                            for value in captured[1][name])))
                    self.assertEqual(trace["updates"][0][3],max(abs(value) for values in after.gradients.values() for value in values))
                    published=apply_parameter_update(opted,base_version=opted["version"],deltas=after.gradients,source_id="unit")
                    params={name:tuple(float32(value) for value in tensor["values"])
                            for name,tensor in published["parameters"].items()}
                    self.assertEqual(after.metadata["updated_parameter_fingerprint"],_parameter_fingerprint(params))
                    self.assertEqual(trace["state_parameter_fingerprints"][0],wrapper.snapshot.fingerprint)
                    self.assertEqual(trace["state_parameter_fingerprints"][-1],parameter_fingerprint(params,wrapper.snapshot.shapes))
                    for name,tensor in opted["parameters"].items():
                        if not tensor["trainable"]:
                            self.assertEqual(published["parameters"][name],tensor)
                        np.testing.assert_array_equal(wrapper.model.parameters[name],
                            np.asarray(tensor["values"],dtype=np.float32).reshape(tensor["shape"]))
        self.assertGreater(total_clipped,0,"This real-Torch fixture must exercise saturation at rate .003.")

    @unittest.skipUnless(torch is not None,"opt-in Torch dependency unavailable on host")
    def test_last_block_four_step_microbatch_invariance(self):
        for profile in ("efficient", "balanced", "quality"):
            artifact=self.artifact(profile,strategy=LAST_BLOCK_STRATEGY,optimizer=LOCAL_SGD_4)
            regular,wrapper=self.batch(artifact)
            def small(*args,**kwargs):
                return supervised_last_block_deltas(*args,**{**kwargs,"microbatch_size":1})
            with patch("src.LLM.privoke.supervised_training.supervised_last_block_deltas",side_effect=small):
                tiny,_=self.batch(artifact)
            for name in regular.gradients:
                np.testing.assert_allclose(tiny.gradients[name],regular.gradients[name],rtol=2e-5,atol=2e-9)
            published=apply_parameter_update(artifact,base_version=artifact["version"],deltas=regular.gradients,source_id="unit")
            for name,tensor in artifact["parameters"].items():
                if not tensor["trainable"]: self.assertEqual(published["parameters"][name],tensor)
            for loss in json.loads(regular.metadata["contextual_optimizer_trace"])["loss"]:
                self.assertTrue(all(math.isfinite(value) for value in loss))

if __name__ == "__main__":
    unittest.main()
