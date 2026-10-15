"""Operative prepared-window service route, including terminal no-update receipts."""
from __future__ import annotations

from dataclasses import asdict
import json
import os
from pathlib import Path

import grpc

from privoke_model import window_training as contract
from privoke_model.full_adam import canonical
from prompt_generation import train_window, benign_coverage as benign
from prompt_generation.taxonomy_coverage import load_dataset
from runtime_client import PrivokeRuntimeClient
from .trainer import train_parameter_batch
from .evidence import (reserve_training_request, persist_cycle_evidence, cycle_identity, _write_atomic,
                       recover_cycle_evidence_ack)


def run(service,request,context,*,training_scope):
    from privoke.v1 import parameters_pb2 as pb
    from fuzzer_service import _resolve_cycle, build_training_response, validate_training_update
    config=service.config
    try:
        if training_scope!="full_encoder" or request.metadata.get("contextual_sampling_strategy")!=contract.SAMPLER:
            raise ValueError("Window sampler/optimizer requires explicit underlying FULL endpoint.")
        admission=contract.expectations(request.metadata)
        if admission is None or request.metadata.get("expected_contextual_training_backtracking_policy") or request.metadata.get("expected_contextual_training_diagnostics_policy"):
            raise ValueError("Window cycle requires exclusive explicit schema5 policy admission.")
        window=contract.validate_window(contract.read_pinned(config.window_path,config.window_manifest_sha256))
        release=contract.load_components(config.component_bank_path,config.component_reference_path,config.component_manifest_path,
            config.component_teacher_path,model_id=request.model_id,trusted_sha256=config.component_manifest_sha256,
            teacher_sha256=config.component_teacher_sha256)
        if (admission["expected_window_manifest_sha256"]!=config.window_manifest_sha256
                or admission["expected_component_manifest_sha256"]!=config.component_manifest_sha256
                or request.seed!=window["seed"] or request.prompt_count!=256 or config.heldout_prompt_count!=16
                or config.curriculum_manifest_path):
            raise ValueError("Window cycle request differs from frozen seed/256originals/pins/exclusive snapshots.")
        # Reconstruct source selection/transformations before reservation AND replay lookup.
        dataset=load_dataset(config.prompt_dataset_path)
        benign_release=benign.load_release(config.benign_pool_path,config.benign_manifest_path,config.benign_exclusion_proof_path,dataset)
        train_window.validate_sources(window,dataset,benign_release)
        training=config.batch_training_config(window["seed"],training_scope="full_encoder")
        if training.learning_rate!=.003 or training.max_gradient!=.05 or training.transformations_per_example!=1 or training.new_example_weight!=1:
            raise ValueError("Window service settings differ from prepared Adam/source contract.")
        directory=os.getenv("PRIVOKE_FUZZER_DUMP_DIR")
        if not directory:
            raise ValueError("Window service requires durable evidence and no-update receipts.")
        settings={"training":asdict(training),"window_sha256":config.window_manifest_sha256,
            "component_sha256":release.sha256,"admission":admission,"minimum_exact_match_rate":config.minimum_exact_match_rate}
        fingerprint=contract.sha256(canonical([request.SerializeToString(deterministic=True).hex(),settings]).encode())
        reserve_training_request(request,"full_encoder",fingerprint)
        outcome_path=Path(directory)/"window-outcomes"/(cycle_identity(request,"full_encoder")+".json")
        if outcome_path.exists():
            outcome=json.loads(outcome_path.read_text())
            if outcome["fingerprint"]!=fingerprint:
                raise ValueError("Known no-update receipt belongs to different effective settings.")
            return pb.FuzzerTrainingResponse(accepted=True,model_id=request.model_id,base_version=outcome["base_version"],
                applied_version=outcome["base_version"],prompts_generated=256,message="Known no_update; immutable BASE retained.",
                metadata={"window_outcome":"no_update","replayed":"true","reason":outcome["reason"]})
    except (ValueError,OSError,KeyError,TypeError) as exc:
        context.abort(grpc.StatusCode.FAILED_PRECONDITION,str(exc))
    cycle=_resolve_cycle(request,config)
    previous=service._previous_update_for_fingerprint(request,cycle,context,fingerprint)
    if previous.found:
        recover_cycle_evidence_ack(request,"full_encoder",previous)
        return pb.FuzzerTrainingResponse(accepted=previous.ack.accepted,model_id=previous.ack.model_id,
            base_version=previous.base_version,applied_version=previous.ack.applied_version,prompts_generated=previous.prompts_generated,
            message=previous.ack.message,metadata={"replayed":"true","window_outcome":"selected"})
    try:
        examples,guard=train_window.examples(window)
        update=train_parameter_batch(model_id=request.model_id,new_examples=examples,heldout_examples=guard,config=training,
            runtime_client=PrivokeRuntimeClient(config.privoke_runtime_target,timeout_seconds=config.timeout_seconds),
            training_scope="full_encoder",request_id=request.request_id,window_release=window,component_release=release,window_admission=admission)
        from .window_evidence import validate_update
        trace=validate_update(update)
        no_update=trace["status"]=="no_update" or update.metrics["candidate_train_exact_match_rate"]<=config.minimum_exact_match_rate
        persist_cycle_evidence(request,update,"full_encoder",gate_passed=not no_update)
        if no_update:
            reason=trace["reason"] if trace["status"]=="no_update" else "minimum_train_exact_gate"
            outcome_path.parent.mkdir(parents=True,exist_ok=True)
            _write_atomic(outcome_path,{"schema":1,"fingerprint":fingerprint,"base_version":update.base_version,"reason":reason,
                "trace_sha256":contract.sha256(update.metadata[contract.TRACE_KEY].encode())})
            return pb.FuzzerTrainingResponse(accepted=True,model_id=update.model_id,base_version=update.base_version,
                applied_version=update.base_version,prompts_generated=256,message="No update; immutable BASE retained.",
                metadata={"window_outcome":"no_update","reason":reason})
        validate_training_update(update,minimum_exact_match_rate=config.minimum_exact_match_rate)
        if not context.is_active():
            context.abort(grpc.StatusCode.CANCELLED,"Cancelled before selected checkpoint publication.")
        ack=service._submit_update(request,cycle,update,256,context,fingerprint=fingerprint)
        if not ack.accepted or ack.model_id!=update.model_id or not ack.applied_version:
            raise ValueError("Updater did not acknowledge selected checkpoint publication.")
        persist_cycle_evidence(request,update,"full_encoder",gate_passed=True,ack=ack)
        return build_training_response(ack,update,256)
    except (ValueError,OSError,KeyError,TypeError) as exc:
        context.abort(grpc.StatusCode.FAILED_PRECONDITION,str(exc))
    except grpc.RpcError:
        context.abort(grpc.StatusCode.UNAVAILABLE,"Window runtime/updater unavailable; unknown physical outcomes are never replayed.")
