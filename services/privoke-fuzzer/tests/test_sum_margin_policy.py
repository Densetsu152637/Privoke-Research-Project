"""SM01 no-model durable identity, canonical null and postcompute admission fixtures."""
import base64,copy,json,os,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from privoke_model.contextual_training import *
from runtime_client import PrivokeRuntimeClient,RuntimeAnalysisError
from fuzzer_service import FuzzerTrainingService
from config import FuzzerConfig
from privoke.v1 import parameters_pb2
from test_taxonomy_coverage import Context,Aborted
import test_training_policy as prior
from training.types import BatchTrainingExample

NEW=CLASS_BALANCED_SUM_CATEGORY_DECISION_MARGIN_OBJECTIVE
class SumMarginPolicyTests(unittest.TestCase):
    def setUp(self):
        self.f=prior.TrainingPolicyTests();self.f.setUp();self.addCleanup(self.f.doCleanups)

    def response(self,scope,diag=True):
        response=self.f.response(scope);response.metadata[EXECUTED_OBJECTIVE_KEY]=NEW
        if diag:
            record=json.loads(response.metadata[DIAGNOSTICS_KEY]);record.update(schema=2,objective=NEW,
                loss_columns=list(SUM_MARGIN_LOSS_COLUMNS),loss=[[1,1,1,1,4]]*2)
            response.metadata[DIAGNOSTICS_KEY]=json.dumps(record,separators=(',',':'))
        else:
            del response.metadata[DIAGNOSTICS_KEY];del response.metadata[DIAGNOSTICS_POLICY_KEY]
        return response

    def compute(self,response,scope,diag=True):
        with patch('runtime_client.grpc.insecure_channel'),patch('runtime_client.runtime_pb2_grpc.PrivokeRuntimeServiceStub') as stub:
            method=stub.return_value.ComputeUnderlyingModelGradients if scope=='full_encoder' else stub.return_value.ComputeSemanticGradients
            method.return_value=response
            return PrivokeRuntimeClient('unused').compute_semantic_gradients(self.f.rows,
                heldout_examples=[BatchTrainingExample('guard',self.f.clean)],model_id='privoke-balanced',
                learning_rate=.03,max_gradient=.05,request_id='req',training_scope=scope,
                expected_objective=NEW,expected_diagnostics_policy=TRAIN_DIAGNOSTICS_POLICY if diag else None)

    def test_schema_two_raw_before_admission_and_scope_inventory(self):
        for scope in ['heads','full_encoder']:
            for diag in [True,False]:
                batch=self.compute(self.response(scope,diag),scope,diag)
                self.assertEqual(json.loads(batch['execution_evidence']['invocation_metadata'][0][1])['schema'],2)
                self.assertEqual(json.loads(json.dumps(batch['execution_evidence'])),batch['execution_evidence'])
        records=list(Path(self.f.directory.name).glob('backtracking-attempts/*/admission/attempts/*.json'))
        self.assertEqual(len(records),4)
        for path in records:
            verdict=json.loads(path.read_text());attempt=json.loads(Path(verdict['physical_attempt']).read_text())
            self.assertEqual(verdict['status'],'accepted');self.assertIsNone(attempt['gradient_fits'])
            names=set(verdict['raw_gradient_shapes'])
            expected=full_encoder_tensor_shapes(json.loads(self.response('full_encoder').metadata['model_config']))
            self.assertEqual(names,HEAD_NAMES if attempt['training_stage']=='heads' else set(expected))
            if attempt['training_stage']=='full_encoder':self.assertGreater(len(names),6)

    def test_spoof_rejection_malformed_aux_and_null_diagnostic_are_unadmitted(self):
        for scope in ['heads','full_encoder']:
            for kind in ['spoof_rejection','wrong_schema','missing_aux','wrong_total','overflow','hidden_diag']:
                response=self.response(scope);diag=True
                if kind=='spoof_rejection':response.error=BACKTRACKING_REJECTION
                elif kind=='hidden_diag':diag=False
                else:
                    record=json.loads(response.metadata[DIAGNOSTICS_KEY])
                    if kind=='wrong_schema':record['schema']=1
                    elif kind=='missing_aux':record['loss']=[[1,1,1,3]]*2
                    elif kind=='wrong_total':record['loss']=[[1,1,1,1,3]]*2
                    else:record['loss']=[[10**400,1,1,1,4]]*2
                    response.metadata[DIAGNOSTICS_KEY]=json.dumps(record,separators=(',',':'))
                with patch('training.parameter_updates.emit_parameter_update') as submit,self.assertRaises(RuntimeAnalysisError):
                    self.compute(response,scope,diag)
                submit.assert_not_called()
        records=list(Path(self.f.directory.name).glob('backtracking-attempts/*/admission/attempts/*.json'))
        self.assertEqual(len(records),12)
        for p in records:
            verdict=json.loads(p.read_text());self.assertEqual(verdict['status'],'unadmitted');self.assertIsNone(verdict['gradient_fits'])
            attempt=json.loads(Path(verdict['physical_attempt']).read_text())
            self.assertTrue(base64.b64decode(attempt['response_protobuf_base64']))
            self.assertEqual(attempt['compute_status'],'response_received_unadmitted')

    def test_objective_header_bound_before_lookup_and_committed_retry_zero_work(self):
        with patch.dict(os.environ,{"FUZZ_CONTEXTUAL_SAMPLING_STRATEGY": "legacy_random_v1"},clear=True):config=FuzzerConfig.from_env()
        service=FuzzerTrainingService(config)
        request=parameters_pb2.FuzzerTrainingRequest(request_id='sm01',source_id='test',prompt_count=32,
            metadata={'expected_contextual_training_objective':NEW})
        previous=parameters_pb2.ParameterUpdateStatus(found=True,base_version='v1',prompts_generated=32,
            ack=parameters_pb2.ParameterUpdateAck(accepted=True,model_id=config.model_id,applied_version='v2'))
        for _ in range(2):
            with patch.object(service,'_previous_update_for_fingerprint',return_value=previous),patch('fuzzer_service.generate_training_partition') as sample,patch.object(service,'_train') as fit:
                self.assertTrue(service.RunTrainingCycle(request,Context()).accepted)
            sample.assert_not_called();fit.assert_not_called()
        original=training_admission_metadata
        def different_header(expectations):
            headers=original(expectations);return tuple((k,v+' ') for k,v in headers)
        with patch('privoke_model.contextual_training.training_admission_metadata',side_effect=different_header),patch.object(service,'_previous_update_for_fingerprint') as lookup,self.assertRaisesRegex(Aborted,'different effective'):
            service.RunTrainingCycle(request,Context())
        lookup.assert_not_called()
        with patch.dict(os.environ,{'PRIVOKE_FUZZER_DUMP_DIR':''}),self.assertRaisesRegex(Aborted,'durable'):
            service.RunTrainingCycle(request,Context())
