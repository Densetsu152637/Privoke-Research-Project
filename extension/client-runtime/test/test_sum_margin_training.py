"""SM01 semantic-only runtime math, admission, transport and compatibility witnesses."""
import copy,importlib.util,json,math,unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch
import numpy as np
import torch
from privoke_model.contextual_training import *
from privoke_model.fingerprint import parameter_fingerprint
from src.LLM.privoke.training import (_decision_margin_loss_and_head_deltas,_class_balanced_examples)
from src.LLM.privoke.supervised_training import supervised_last_block_deltas
from src.LLM.privoke.streamed_model import StreamedTransformerPrivacyModel,GLOBAL_STREAMED_MODEL_CACHE as CACHE
from src.LLM.privoke.parameter_stream import ParameterSnapshot
from src.LLM.privoke_classifier import PriVokeClassifier
from src.hosting.grpc_server import PrivokeRuntimeService
from src.detection.preprocessing import normalize_text
from privoke.v1 import runtime_pb2 as RP
from test_training_adaptation import snapshot
import test_training_backtracking as bs

NEW=CLASS_BALANCED_SUM_CATEGORY_DECISION_MARGIN_OBJECTIVE
ROOT=Path(__file__).resolve().parents[3]
OUT=Path('/out')

class SumMarginTrainingTests(unittest.TestCase):
    def setUp(self):
        self.f=bs.BacktrackingTests();self.f.setUp()

    def objective_header(self,diag=TRAIN_DIAGNOSTICS_POLICY):
        return training_admission_metadata({'expected_objective':NEW,'expected_diagnostics_policy':diag})

    def test_new_head_full_routes_schema_and_selected_transport(self):
        for scope,backtracking in [('heads',False),('heads',True),('full_encoder',False),('full_encoder',True)]:
            artifact=self.f.prepared(NEW) if backtracking else prepare_training_policy_artifact(self.f.artifact,objective=NEW,diagnostics=TRAIN_DIAGNOSTICS_POLICY)
            headers=self.objective_header() if scope=='heads' or not backtracking else None
            response,wrapper=self.f.call(artifact,head=scope=='heads',headers=headers)
            self.assertFalse(response.error,response.error)
            record=json.loads(response.metadata[DIAGNOSTICS_KEY]);self.assertEqual(record['schema'],2)
            self.assertEqual(record['loss_columns'],list(SUM_MARGIN_LOSS_COLUMNS))
            for losses in record['loss']:self.assertAlmostEqual(math.fsum(losses[:-1]),losses[-1],places=12)
            self.assertEqual(BACKTRACKING_TRACE_KEY in response.metadata,scope=='full_encoder' and backtracking)
            if scope=='heads':self.assertEqual({p.name for p in response.gradients},HEAD_NAMES)
            if scope=='full_encoder' and backtracking:
                header,trials=validate_backtracking_trace(response.metadata,examples=2,requested_rate=.003)
                self.assertEqual(header['schema'],2);self.assertEqual(trials[-1][1],record['loss'][1])

    def test_precompute_admission_matrix_and_null_means_disabled(self):
        plain=prepare_training_policy_artifact(self.f.artifact,objective=NEW)
        diag=prepare_training_policy_artifact(self.f.artifact,objective=NEW,diagnostics=TRAIN_DIAGNOSTICS_POLICY)
        backed=self.f.prepared(NEW)
        bad=[(plain,True,()),(plain,False,()),(diag,True,self.objective_header(None)),
             (plain,False,self.objective_header()),(backed,False,self.objective_header()),
             (backed,True,training_admission_metadata(self.f.expectations(backed))),
             (plain,True,((BACKTRACKING_HEADER,'{"schema":2,"expected_objective":"unknown","expected_diagnostics_policy":null}'),))]
        for artifact,head,headers in bad:
            with patch('src.LLM.privoke.supervised_training.supervised_last_block_deltas') as gradient,patch('src.model.TinyTransformerModel.predict_many') as predict:
                response,_=self.f.call(artifact,head=head,headers=headers)
            self.assertTrue(response.error);gradient.assert_not_called();predict.assert_not_called()
        for head in [True,False]:
            response,_=self.f.call(plain,head=head,headers=self.objective_header(None))
            self.assertFalse(response.error,response.error)
            self.assertNotIn(DIAGNOSTICS_KEY,response.metadata);self.assertNotIn(DIAGNOSTICS_POLICY_KEY,response.metadata)

    def test_checked_margin_winners_ties_threshold_neighbors_and_independent_head_gradient(self):
        cases=[('severity',.7,-2.,False),('category',-.5,.8,False),('severity_tie',0.,-2.,True),
               ('threshold_below',-1.,float(np.nextafter(np.float32(0),np.float32(-1))),True),
               ('threshold_equal',-1.,0.,True),('threshold_above',-1.,float(np.nextafter(np.float32(0),np.float32(1))),True)]
        for label,severity,category,nonsmooth in cases:
            artifact=prepare_training_policy_artifact(self.f.artifact,objective=NEW)
            artifact=copy.deepcopy(artifact);artifact['config']['category_threshold']=.5
            state=snapshot(artifact);params=dict(state.parameters)
            for head in ['sensitivity','visibility','category']:
                params[f'head.{head}.weight']=tuple(0. for _ in params[f'head.{head}.weight'])
            params['head.sensitivity.bias']=(0.,severity,-3.,-4.)
            params['head.category.bias']=(category,)+tuple(-2. for _ in params['head.category.bias'][1:])
            wrapper=StreamedTransformerPrivacyModel(replace(state,parameters=params));model=wrapper.model
            rows,_=_class_balanced_examples(tuple(replace(r,text=normalize_text(r.text)) for r in self.f.rows))
            original=model.predict;predictions=[];checked=[]
            def capture(text):
                p=original(text);predictions.append(p)
                if len(predictions)==2:
                    direction,loss=supervised_last_block_deltas(model,rows,HEAD_NAMES,objective=NEW)
                    expected={n:np.zeros_like(model.parameters[n]) for n in HEAD_NAMES};independent_loss=0.
                    for item,pred in zip(rows,predictions):
                        pooled=np.array(pred.pooled,dtype=np.float32)
                        logits={h:pooled@model.parameters[f'head.{h}.weight']+model.parameters[f'head.{h}.bias'] for h in ['sensitivity','visibility','category']}
                        probs={h:np.exp(z-z.max())/np.exp(z-z.max()).sum() for h,z in logits.items() if h!='category'}
                        sigmoid=1/(1+np.exp(-logits['category']))
                        errors={h:-v.astype(float) for h,v in probs.items()};errors['category']=np.array([float(c in {x.name for x in item.target.categories()}) for c in model.config.category_labels])-sigmoid
                        errors['sensitivity'][model.config.sensitivity_labels.index(item.target.sensitivity().name)]+=1
                        errors['visibility'][model.config.visibility_labels.index(item.target.visibility().name)]+=1
                        margins=np.concatenate((logits['sensitivity'][1:]-logits['sensitivity'][0],logits['category']))
                        winner=int(np.argmax(margins));m=float(margins[winner]);y=item.target.is_sensitive()
                        auxiliary=math.log1p(math.exp(-m if y else m))
                        auxloss,aux=_decision_margin_loss_and_head_deltas(model,pred,item.target)
                        self.assertAlmostEqual(auxloss,auxiliary,places=12)
                        error=(1/(1+math.exp(m))) if y else -1/(1+math.exp(-m))
                        ae={h:np.zeros(len(z)) for h,z in logits.items()}
                        if winner<3:ae['sensitivity'][winner+1]=error;ae['sensitivity'][0]=-error
                        else:ae['category'][winner-3]=error
                        for h in errors:
                            np.testing.assert_allclose(aux[f'head.{h}.bias'],ae[h],atol=2e-7,rtol=2e-6)
                            e=errors[h]+ae[h];w=item.weight/math.fsum(r.weight for r in rows)
                            expected[f'head.{h}.bias']+=e*w
                            expected[f'head.{h}.weight']+=np.outer(pooled,e)*w
                        ce=0.
                        for h,target in [('sensitivity',item.target.sensitivity().name),('visibility',item.target.visibility().name)]:
                            z=logits[h].astype(float);k=getattr(model.config,h+'_labels').index(target);a=max(z)
                            ce+=a-z[k]+math.log(math.fsum(math.exp(v-a) for v in z))
                        cats={x.name for x in item.target.categories()}
                        bce=math.fsum(max(float(z),0)-float(c in cats)*float(z)+math.log1p(math.exp(-abs(float(z)))) for z,c in zip(logits['category'],model.config.category_labels))
                        independent_loss+=(ce+bce+auxiliary)*item.weight/math.fsum(r.weight for r in rows)
                    self.assertAlmostEqual(loss,independent_loss,delta=2e-5)
                    for n in HEAD_NAMES:np.testing.assert_allclose(direction[n],expected[n].ravel(),atol=2e-5,rtol=2e-5)
                    if not nonsmooth:
                        # Smooth independent logit loss central difference along one bias coordinate.
                        target=rows[0].target;z=np.array(params['head.sensitivity.bias'],dtype=float);eps=1e-5
                        def scalar(z):
                            a=max(z);ce=a-z[0]+math.log(math.fsum(math.exp(v-a) for v in z))
                            m=max(max(z[1:]-z[0]),category);return ce+math.log1p(math.exp(m))
                        plus=z.copy();minus=z.copy();plus[1]+=eps;minus[1]-=eps
                        fd=(scalar(plus)-scalar(minus))/(2*eps)
                        # Clean-row analytic direction before class aggregation.
                        zprob=np.exp(z-z.max());zprob/=zprob.sum();m=max(max(z[1:]-z[0]),category)
                        expected_derivative=zprob[1]+(1/(1+math.exp(-m)) if max(z[1:]-z[0])>category else 0)
                        self.assertAlmostEqual(fd,expected_derivative,delta=2e-6)
                    checked.append(True)
                return p
            with patch('src.pipeline.get_llm_choice',return_value=PriVokeClassifier(model_id=state.model_id)),patch.object(CACHE,'semantic_model_for_streamer',return_value=wrapper),patch.object(model,'predict',side_effect=capture):
                for row in rows:
                    request=RP.AnalyzePromptRequest(text=row.text,semantic_model_id=state.model_id,layers=[RP.DETECTION_LAYER_SEMANTIC])
                    self.assertEqual(list(request.layers),[4]);response=self.f.server.AnalyzePrompt(request,None)
                    self.assertFalse(response.error,response.error);self.assertEqual([(x.layer,x.status,x.error) for x in response.layers],[(4,'ok','')])
            self.assertEqual(checked,[True])
            if label=='severity_tie':self.assertEqual(predictions[0].sensitivity,'S0');self.assertEqual(predictions[0].categories,())
            if label.startswith('threshold_'):self.assertIn(model.config.category_labels[0],predictions[0].categories)

    def test_actual_taxonomy_new_objective_head_full_wire(self):
        # Reuse the accepted full trainer→runtime→durable trace→publication witness with only the objective varied.
        with patch.object(bs,'CLASS_BALANCED_OBJECTIVE',NEW):
            self.f.test_actual_taxonomy_selected_head_full_wire_and_exact_selected_transport()

    def test_default_and_old_objectives_match_frozen_baseline(self):
        modules={}
        for name,file in [('training','training.py'),('supervised','supervised_training.py')]:
            path=OUT/'baseline/extension/client-runtime/src/LLM/privoke'/file
            spec=importlib.util.spec_from_file_location('src.LLM.privoke.sm01_baseline_'+name,path)
            module=importlib.util.module_from_spec(spec)
            import sys;sys.modules[spec.name]=module;spec.loader.exec_module(module);modules[name]=module
        for objective in [None,CLASS_BALANCED_OBJECTIVE,CLASS_BALANCED_MEAN_CATEGORY_OBJECTIVE,CLASS_BALANCED_DECISION_MARGIN_OBJECTIVE]:
            artifact=prepare_training_objective_artifact(self.f.artifact,objective)
            for head in [True,False]:
                current,_=self.f.call(artifact,head=head)
                alias='compute_semantic_gradients' if head else 'compute_underlying_model_gradients'
                with patch('src.hosting.grpc_server.'+alias,getattr(modules['training'],alias)),patch('src.LLM.privoke.supervised_training.supervised_last_block_deltas',modules['supervised'].supervised_last_block_deltas):
                    previous,_=self.f.call(artifact,head=head)
                self.assertFalse(current.error or previous.error,(current.error,previous.error))
                self.assertEqual(current.gradients,previous.gradients);self.assertEqual(current.metrics,previous.metrics)
                self.assertEqual(current.metadata['updated_parameter_fingerprint'],previous.metadata['updated_parameter_fingerprint'])
                self.assertEqual(current.executions,previous.executions)

    def test_worst_five_trial_no_improvement_schema_two(self):
        artifact=self.f.prepared(NEW)
        direction={n:tuple(0. for _ in t['values']) for n,t in artifact['parameters'].items()}
        direction['token_embedding']=(1.,)+direction['token_embedding'][1:]
        with patch('src.LLM.privoke.supervised_training.supervised_last_block_deltas',return_value=(direction,4.)) as gradient,patch('src.LLM.privoke.training._local_training_losses',return_value=[1.,1.,1.,1.,4.]):
            response,_=self.f.call(artifact)
        gradient.assert_called_once();self.assertEqual(response.error,BACKTRACKING_REJECTION)
        header,trials=validate_backtracking_trace(response.metadata,examples=2,requested_rate=.003,rejected=True)
        self.assertEqual(len(trials),5);self.assertEqual(header['schema'],2)
        self.assertTrue(all(len(v.encode())<=2048 for v in response.metadata.values()))
        print(json.dumps({'witness':'sm01_worst_five','trace_bytes':len(response.metadata[BACKTRACKING_TRACE_KEY].encode()),'trials_bytes':len(response.metadata[BACKTRACKING_TRIALS_KEY].encode())}))
