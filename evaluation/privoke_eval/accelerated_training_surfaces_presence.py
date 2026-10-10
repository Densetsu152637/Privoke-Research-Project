"""Sparse presence adapter using explicit actual semantic network execution."""
from __future__ import annotations
import math
import time
from pathlib import Path
from privoke_eval.accelerated_training_surfaces_study import read,write,digest,validate_tensor_transition


def validate_presence_execution(response, expected, semantic):
    identity={k:getattr(response,k) for k in ('model_id','model_version','artifact_checksum','parameter_fingerprint')}
    if response.error or identity!=expected:
        raise ValueError('Presence response/model identity differs')
    traces=list(response.executions)
    if len(traces)!=1 or traces[0].layer!=semantic or traces[0].status!='ok' or traces[0].error:
        raise ValueError('Presence inference lacks actual semantic execution')
    # Identity is independently returned by the execution result as well.
    results=list(traces[0].results)
    if results and any(any(result.metadata.get(k)!=v for k,v in expected.items()) for result in results):
        raise ValueError('Presence execution identity differs')
    if not math.isfinite(response.probability) or not 0<=response.probability<=1 or not math.isfinite(response.threshold) or not 0<=response.threshold<=1:
        raise ValueError('Invalid presence probability/threshold')
    return identity


def measure_presence(client, rows, cell, identity):
    from privoke.v1 import runtime_pb2 as R
    from google.protobuf.json_format import MessageToDict
    predictions=[]
    for row in rows:
        request_id=digest([cell['id'],identity,row['id']])[:40]
        request=R.DetectAnnotationPresenceRequest(request_id=request_id,text=row['text'],model_id=cell['model_id'],layers=[R.DETECTION_LAYER_SEMANTIC])
        record={'id':row['id'],'group_id':row.get('group_id',row.get('family_id')),'target':row['present']}
        try:
            from privoke_eval.accelerated_training_surfaces_study import admit_network_text,CoverageError
            admit_network_text(row["text"],cell)
            response=client.runtime.DetectAnnotationPresence(request,timeout=120)
            validate_presence_execution(response,identity,R.DETECTION_LAYER_SEMANTIC)
            if response.request_id!=request_id:raise ValueError('Presence response request differs')
            expected_label=R.ANNOTATION_PRESENCE_PRESENT if response.probability>=response.threshold else R.ANNOTATION_PRESENCE_ABSENT
            if response.predicted_label!=expected_label:raise ValueError('Presence label/threshold disagreement')
            record.update(status='ok',predicted_present=response.predicted_label==R.ANNOTATION_PRESENCE_PRESENT,
                probability=response.probability,threshold=response.threshold,identity=identity,execution_mode='network_protobuf_v1',
                raw=MessageToDict(response,preserving_proto_field_name=True))
        except CoverageError as exc:
            record.update(status="error",error=str(exc),coverage_error=True)
        except ValueError:
            # Isolation and identity failures stop the study; never become scores.
            raise
        except Exception as exc:
            record.update(status='error',error=str(exc))
        predictions.append(record)
    return {'semantic':{'predictions':predictions}}


def run_presence(client, protocol, cell, directory, artifact, checkpoint_callback):
    import grpc
    from privoke.v1 import parameters_pb2 as P
    from google.protobuf.json_format import MessageToDict
    initial_path=directory/'snapshot-000.json'
    initial=read(initial_path) if initial_path.exists() else client.snapshot(cell['model_id'])
    write(initial_path,initial,immutable=True)
    checkpoint_callback(client,protocol,cell,directory,0,initial)
    allowed=[n for n in artifact['parameters'] if n.startswith('head.presence.')]
    for slot in range(1,97):
        path=directory/f'stage-{slot:03d}.json'
        if path.exists():continue
        pending=directory/f'pending-{slot:03d}.json'
        request=P.FuzzerTrainingRequest(request_id=f"{cell['project']}-{slot}",source_id=cell['project'],model_id=cell['model_id'],prompt_count=32,seed=cell['seed']+slot-1,
            metadata={'study_gate_diagnostics':'v1'})
        raw=request.SerializeToString(deterministic=True).hex()
        if pending.exists():
            reserved=read(pending)
            if reserved['request_hex']!=raw:raise ValueError('Presence pending request changed')
        else:
            reserved={'request_hex':raw,'base':client.snapshot(cell['model_id']),'physical_attempts':0,'transport_errors':[]}
            write(pending,reserved)
        response=None;error=None
        if reserved["physical_attempts"]>=3:raise RuntimeError("Durable presence request exhausted two recovery retries")
        for attempt in range(reserved["physical_attempts"],3):
            reserved['physical_attempts']+=1;write(pending,reserved)
            try:
                wire=client.fuzzer.RunPresenceTrainingCycle(request,timeout=300)
                response=MessageToDict(wire,preserving_proto_field_name=True)
                if not wire.accepted:raise ValueError('Presence endpoint returned nonaccepted response')
                break
            except grpc.RpcError as exc:
                if exc.code() in (grpc.StatusCode.FAILED_PRECONDITION,grpc.StatusCode.INVALID_ARGUMENT):
                    error=str(exc);break
                reserved['transport_errors'].append(str(exc));write(pending,reserved)
                if attempt==2:raise
                time.sleep(2)
        current=client.snapshot(cell['model_id'])
        accepted=error is None
        changed=validate_tensor_transition(reserved['base'],current,allowed,accepted=accepted)
        if accepted and (wire.base_version!=reserved['base']['identity']['model_version'] or wire.applied_version!=current['identity']['model_version']):
            raise ValueError('Presence publication chain differs')
        write(path,{'slot':slot,'stage':'presence','state':'accepted' if accepted else 'rejected','request_id':request.request_id,
            'request_hex':raw,'response':response,'error':error,'before_identity':reserved['base']['identity'],'snapshot':current,'changed_names':changed,
            'physical_attempts':reserved['physical_attempts'],'transport_errors':reserved['transport_errors']},immutable=True)
        if slot in protocol['checkpoint_slots']:
            time.sleep(2.1)
            checkpoint_callback(client,protocol,cell,directory,slot,current)
