"""gRPC orchestration for one bounded fuzzer training cycle."""

from __future__ import annotations

import logging
import math
import hashlib
import json
import os
from pathlib import Path
import threading
from dataclasses import asdict, dataclass, replace

import grpc
from config import FuzzerConfig
from privoke.v1 import parameters_pb2, parameters_pb2_grpc
from privoke_service import validate_text
from prompt_generation import generate_presence_training_partition, generate_training_partition
from prompt_generation.generator import (CONTEXTUAL_SAMPLING_STRATEGY_KEY,
    contextual_sampling_audit, validate_contextual_sampling_strategy)
from prompt_generation.curriculum import load_curriculum, reserve_batch, request_fingerprint, sampler_settings
from privoke_model.contextual_training import training_policy_expectations
from prompt_generation.taxonomy_coverage import (STRATEGY as TAXONOMY_STRATEGY, audit_originals,
    load_dataset as load_taxonomy_dataset, policy_contract as taxonomy_policy_contract)
from prompt_generation import anchor_rehearsal as rehearsal
from prompt_generation import benign_coverage as benign
from prompt_generation import audience_coverage as audience
from runtime_client import PrivokeRuntimeClient, RuntimeAnalysisError
from training import emit_training_update, train_parameter_batch, train_presence_batch
from training.types import BatchTrainingUpdate
from training.evidence import persist_cycle_evidence, recover_cycle_evidence_ack, reserve_training_request

LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class TrainingCycle:
    requested_prompt_count: int
    prompt_count: int
    model_id: str
    seed: int


class FuzzerTrainingService(parameters_pb2_grpc.FuzzerServiceServicer):
    def __init__(self, config: FuzzerConfig):
        self.config = config
        self._cycle_slots = threading.BoundedSemaphore(
            value=config.max_concurrent_cycles
        )

    def RunTrainingCycle(self, request, context):
        try:
            validate_training_request(request, self.config.model_id)
        except ValueError as exc:
            context.abort(grpc.StatusCode.INVALID_ARGUMENT, str(exc))
        if not self._cycle_slots.acquire(blocking=False):
            context.abort(
                grpc.StatusCode.RESOURCE_EXHAUSTED,
                "The maximum number of concurrent training cycles is already running.",
            )
        try:
            return self._run_training_cycle(request, context)
        finally:
            self._cycle_slots.release()

    def RunPresenceTrainingCycle(self, request, context):
        try:
            validate_presence_training_request(
                request, getattr(self.config, "presence_model_id", self.config.model_id)
            )
        except ValueError as exc:
            context.abort(grpc.StatusCode.INVALID_ARGUMENT, str(exc))
        if not self._cycle_slots.acquire(blocking=False):
            context.abort(grpc.StatusCode.RESOURCE_EXHAUSTED,
                          "The maximum number of concurrent training cycles is already running.")
        try:
            return self._run_presence_training_cycle(request, context)
        finally:
            self._cycle_slots.release()

    def RunUnderlyingTrainingCycle(self, request, context):
        try:
            validate_training_request(request, self.config.model_id)
        except ValueError as exc:
            context.abort(grpc.StatusCode.INVALID_ARGUMENT, str(exc))
        if not self._cycle_slots.acquire(blocking=False):
            context.abort(grpc.StatusCode.RESOURCE_EXHAUSTED,
                          "The maximum number of concurrent training cycles is already running.")
        try:
            return self._run_training_cycle(request, context, training_scope="full_encoder")
        finally:
            self._cycle_slots.release()

    def _run_presence_training_cycle(self, request, context):
        base_cycle = _resolve_cycle(request, self.config)
        cycle = TrainingCycle(
            requested_prompt_count=base_cycle.requested_prompt_count,
            prompt_count=base_cycle.prompt_count,
            model_id=request.model_id,
            seed=base_cycle.seed,
        )
        fingerprint = _presence_training_request_fingerprint(request)
        previous = self._previous_update_for_fingerprint(request, cycle, context, fingerprint)
        if previous.found:
            recover_cycle_evidence_ack(request, "presence", previous)
            return parameters_pb2.FuzzerTrainingResponse(
                accepted=previous.ack.accepted, model_id=previous.ack.model_id,
                base_version=previous.base_version, applied_version=previous.ack.applied_version,
                prompts_generated=previous.prompts_generated, message=previous.ack.message,
                metadata={"replayed": "true"},
            )
        dataset_path = getattr(self.config, "presence_dataset_path", None)
        try:
            examples, heldout = generate_presence_training_partition(
                cycle.prompt_count, self.config.heldout_prompt_count, cycle.seed, dataset_path
            )
        except (ValueError, FileNotFoundError) as exc:
            context.abort(grpc.StatusCode.FAILED_PRECONDITION, str(exc))
        if len(examples) != cycle.prompt_count or len(heldout) != self.config.heldout_prompt_count:
            context.abort(
                grpc.StatusCode.FAILED_PRECONDITION,
                "Presence sampler returned counts that do not match the requested partition.",
            )
        update = self._train_presence(cycle.model_id, examples, heldout, request, context)
        try:
            validate_presence_training_update(
                update,
                minimum_exact_match_rate=self.config.minimum_exact_match_rate,
                expected_examples=len(examples),
                expected_heldout_examples=len(heldout),
            )
        except ValueError as exc:
            persist_cycle_evidence(request, update, "presence", gate_passed=False, gate_diagnostics={"minimum_exact_match_rate": self.config.minimum_exact_match_rate, "metrics": dict(update.metrics), "error": str(exc)})
            LOGGER.warning("rejecting presence training update: %s", exc)
            context.abort(grpc.StatusCode.FAILED_PRECONDITION, str(exc))
        if not context.is_active():
            context.abort(grpc.StatusCode.CANCELLED,
                          "Training request was cancelled before update submission.")
        persist_cycle_evidence(request, update, "presence", gate_passed=True, gate_diagnostics={"minimum_exact_match_rate": self.config.minimum_exact_match_rate, "metrics": dict(update.metrics), "error": ""})
        ack = self._submit_presence_update(request, cycle, update, len(examples), fingerprint, context)
        persist_cycle_evidence(request, update, "presence", gate_passed=True, ack=ack, gate_diagnostics={"minimum_exact_match_rate": self.config.minimum_exact_match_rate, "metrics": dict(update.metrics), "error": ""})
        return build_training_response(ack, update, len(examples))

    def _train_presence(self, model_id, examples, heldout, request, context):
        try:
            return train_presence_batch(
                model_id=model_id, examples=examples, heldout_examples=heldout,
                config=self.config.presence_training_config(_resolve_cycle(request, self.config).seed),
                runtime_client=PrivokeRuntimeClient(
                    self.config.privoke_runtime_target,
                    timeout_seconds=self.config.timeout_seconds,
                ),
                request_id=request.request_id,
            )
        except ValueError as exc:
            context.abort(grpc.StatusCode.FAILED_PRECONDITION, str(exc))
        except (RuntimeAnalysisError, grpc.RpcError) as exc:
            LOGGER.warning("client runtime presence training failed: %s", exc)
            context.abort(grpc.StatusCode.UNAVAILABLE,
                          "Client runtime presence training evaluation is unavailable.")

    def _submit_presence_update(self, request, cycle, update, count, fingerprint, context):
        try:
            return emit_training_update(
                target=self.config.param_update_target, source_id=self.config.fuzzer_id,
                update=update,
                extra_metadata={
                    "request_id": request.request_id,
                    "request_source_id": request.source_id,
                    "requested_prompt_count": str(cycle.requested_prompt_count),
                    "generated_prompt_count": str(count),
                    "training_pipeline": "client_runtime_presence_gradients",
                    "task": "annotation_presence",
                    "training_request_fingerprint": fingerprint,
                },
                timeout_seconds=self.config.timeout_seconds,
            )
        except grpc.RpcError as exc:
            LOGGER.warning("presence parameter update submission failed code=%s", exc.code())
            context.abort(grpc.StatusCode.UNAVAILABLE, "Parameter update service is unavailable.")

    def _run_training_cycle(self, request, context, *, training_scope="heads"):
        if training_scope == "full_encoder":
            # Receipt and curriculum reservations cannot collide with a head or
            # presence request carrying the same caller-supplied identity.
            scoped = parameters_pb2.FuzzerTrainingRequest()
            scoped.CopyFrom(request)
            scoped.metadata["original_request_source_id"] = request.source_id
            scoped.source_id = hashlib.sha256(("underlying-v1:" + request.source_id).encode()).hexdigest()
            request = scoped
        from privoke_model import window_training as window_contract
        if (request.metadata.get("expected_contextual_training_optimizer") == window_contract.POLICY
                or request.metadata.get("contextual_sampling_strategy") == window_contract.SAMPLER):
            from training.window_cycle import run
            return run(self,request,context,training_scope=training_scope)
        cycle = _resolve_cycle(request, self.config)
        curriculum = None
        taxonomy_dataset = None
        rehearsal_manifest = None
        benign_release = None
        retention_release = None
        audience_release = None
        fingerprint = None
        try:
            policy_expectations = training_policy_expectations(request.metadata)
            from privoke_model import sensitive_retention as retention
            retention_mode = policy_expectations.get("expected_optimizer") in retention.POLICIES
            if "expected_optimizer" in policy_expectations and policy_expectations["expected_training_scope"] != training_scope:
                raise ValueError("FULL Adam request header scope differs before reservation.")
            if "expected_optimizer" in policy_expectations and training_scope == "full_encoder":
                from privoke_model.full_adam import CONFIG
                settings = self.config.batch_training_config(cycle.seed, training_scope=training_scope)
                if settings.learning_rate != CONFIG["eta"] or settings.max_gradient != CONFIG["delta_cap"]:
                    raise ValueError("FULL Adam fixed rate/cap must match before reservation or receipt recovery.")
            if policy_expectations.get("expected_backtracking_policy") and training_scope != "full_encoder":
                raise ValueError("Backtracking admission is FULL-only.")
            if policy_expectations and not os.getenv("PRIVOKE_FUZZER_DUMP_DIR"):
                raise ValueError("Training policy admission requires durable PRIVOKE_FUZZER_DUMP_DIR.")
            manifest_path = getattr(self.config, "curriculum_manifest_path", None)
            strategy = request.metadata.get(CONTEXTUAL_SAMPLING_STRATEGY_KEY)
            if strategy is None:
                strategy = getattr(self.config, "contextual_sampling_strategy", audience.LEGACY)
            if strategy == audience.LEGACY:
                strategy = None
            if strategy == audience.STRATEGY:
                if manifest_path or self.config.prompt_dataset_path or policy_expectations:
                    raise ValueError("Audience mode cannot override explicit legacy curriculum/dataset/policy.")
                audience.validate_count(cycle.prompt_count, self.config.heldout_prompt_count)
                audience_release = audience.load_release(getattr(self.config, "audience_manifest_path", None),
                                                         getattr(self.config, "audience_manifest_sha256", None))
                settings = {"training": asdict(self.config.batch_training_config(cycle.seed, training_scope=training_scope)),
                            "scope": training_scope, "prompt_count": cycle.prompt_count,
                            "heldout_count": self.config.heldout_prompt_count, "strategy": strategy,
                            "audience_manifest_sha256": audience_release.sha256,
                            "audience_implementation_sha256": audience.implementation_closure()["sha256"],
                            "minimum_exact_match_rate": self.config.minimum_exact_match_rate}
                fingerprint = hashlib.sha256(json.dumps([request.SerializeToString(deterministic=True).hex(), settings],
                    sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            if retention_mode and strategy != benign.STRATEGY:
                raise ValueError("ORIGINAL retention requires the unchanged BC01 main composition.")
            if strategy != rehearsal.STRATEGY and any(k in request.metadata for k in (rehearsal.BANK_KEY, rehearsal.MANIFEST_KEY)):
                raise ValueError("Orphan rehearsal pins require the explicit rehearsal strategy.")
            if strategy != benign.STRATEGY and any(k in request.metadata for k in (benign.POOL_KEY, benign.MANIFEST_KEY, benign.PROOF_KEY)):
                raise ValueError("Orphan benign pins require the explicit benign strategy.")
            if strategy in (TAXONOMY_STRATEGY, rehearsal.STRATEGY, benign.STRATEGY):
                if manifest_path:
                    raise ValueError("Taxonomy coverage cannot override a fixed curriculum.")
                if not os.getenv("PRIVOKE_FUZZER_DUMP_DIR"):
                    raise ValueError("Taxonomy coverage requires durable PRIVOKE_FUZZER_DUMP_DIR.")
                training_config = self.config.batch_training_config(cycle.seed, training_scope=training_scope)
                if cycle.prompt_count != 32 or self.config.heldout_prompt_count != 16 or training_config.transformations_per_example != 1:
                    raise ValueError("Taxonomy coverage requires 32 originals, 16 guard rows and one transformation.")
                taxonomy_dataset = load_taxonomy_dataset(self.config.prompt_dataset_path)
                expected = request.metadata.get("taxonomy_dataset_sha256")
                if expected is not None and expected != taxonomy_dataset.sha256:
                    raise ValueError("Requested taxonomy dataset hash differs from the server release.")
                if strategy == rehearsal.STRATEGY:
                    from privoke_model.full_adam import POLICY, ELIGIBILITY, CONFIG, OBJECTIVE, canonical
                    if (training_scope != 'full_encoder' or policy_expectations != {
                            'expected_objective': OBJECTIVE, 'expected_diagnostics_policy': None, 'expected_optimizer': POLICY,
                            'expected_candidate_eligibility': ELIGIBILITY, 'expected_optimizer_config': canonical(CONFIG),
                            'expected_training_scope': 'full_encoder'} or training_config.new_example_weight != 1.0):
                        raise ValueError("Rehearsal requires exact authenticated FULL Adam and unit raw weights before reservation.")
                    rehearsal_manifest = rehearsal.load_manifest(getattr(self.config, 'rehearsal_manifest_path', None), taxonomy_dataset)
                    rehearsal.validate_pins(request.metadata, rehearsal_manifest, taxonomy_dataset)
                    # Validate selected rows and unchanged guard before reservation AND receipt lookup.
                    rehearsal.generate_partition(taxonomy_dataset, rehearsal_manifest, cycle.seed)
                if strategy == benign.STRATEGY:
                    from privoke_model.full_adam import POLICY, ELIGIBILITY, CONFIG, OBJECTIVE, canonical
                    required_policy = {
                            'expected_objective': OBJECTIVE, 'expected_diagnostics_policy': None, 'expected_optimizer': POLICY,
                            'expected_candidate_eligibility': ELIGIBILITY, 'expected_optimizer_config': canonical(CONFIG),
                            'expected_training_scope': 'full_encoder'}
                    if retention_mode:
                        required_policy.update(expected_objective=retention.OBJECTIVES[policy_expectations['expected_optimizer']],
                            expected_optimizer=policy_expectations['expected_optimizer'], expected_candidate_eligibility=retention.ELIGIBILITY,
                            expected_retention_manifest_sha256=policy_expectations['expected_retention_manifest_sha256'])
                    if (training_scope != 'full_encoder' or policy_expectations != required_policy or training_config.new_example_weight != 1.0):
                        raise ValueError("Benign coverage requires exact authenticated FULL Adam and unit weights before reservation.")
                    benign_release = benign.load_release(self.config.benign_pool_path, self.config.benign_manifest_path,
                                                         self.config.benign_exclusion_proof_path, taxonomy_dataset)
                    benign.validate_pins(request.metadata, benign_release, taxonomy_dataset)
                    benign.generate_partition(taxonomy_dataset, benign_release, cycle.seed)
                    if retention_mode:
                        benign.validate_legacy_snapshot(taxonomy_dataset)
                        retention_release = retention.load_release(self.config.retention_bank_path, self.config.retention_reference_path,
                            self.config.retention_manifest_path, self.config.retention_teacher_path, model_id=cycle.model_id,
                            expected_sha256=policy_expectations['expected_retention_manifest_sha256'])
                        retention.validate_trusted_release(retention_release, model_id=cycle.model_id,
                            request_sha256=policy_expectations['expected_retention_manifest_sha256'],
                            trusted_sha256=self.config.retention_manifest_sha256)
                settings = {"training": asdict(training_config), "scope": training_scope,
                            "model_id": cycle.model_id, "prompt_count": cycle.prompt_count, "seed": cycle.seed,
                            "heldout_count": self.config.heldout_prompt_count,
                            "minimum_exact_match_rate": self.config.minimum_exact_match_rate,
                            "dataset_sha256": taxonomy_dataset.sha256, "policy": taxonomy_policy_contract()}
                if rehearsal_manifest is not None:
                    settings.update(sampling_strategy=strategy, rehearsal_manifest_sha256=rehearsal_manifest.sha256,
                                    rehearsal_bank_sha256=rehearsal_manifest.bank_sha256,
                                    rehearsal_manifest=json.loads(rehearsal_manifest.payload))
                if benign_release is not None:
                    settings.update(sampling_strategy=strategy, benign_pool_sha256=benign_release.pool.sha256,
                                    benign_manifest=json.loads(benign_release.payload),
                                    benign_exclusion_proof_sha256=benign_release.proof_sha256,
                                    benign_policy=benign.policy_contract())
                if retention_release is not None:
                    settings.update(original_train_retention_manifest=retention_release.manifest,
                                    original_train_retention_manifest_sha256=retention_release.sha256)
                fingerprint = hashlib.sha256(json.dumps([request.SerializeToString(deterministic=True).hex(), settings],
                    sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            if manifest_path:
                curriculum = load_curriculum(manifest_path)
                sampler_settings(request)
                for key, actual in (("curriculum_id", curriculum.curriculum_id),
                                    ("curriculum_manifest_sha256", curriculum.manifest_sha256)):
                    expected = request.metadata.get(key)
                    if expected is not None and expected != actual:
                        raise ValueError(f"Requested {key} differs from the server curriculum.")
                settings = {"training": asdict(self.config.batch_training_config(cycle.seed, training_scope=training_scope)),
                            "prompt_count": cycle.prompt_count, "model_id": cycle.model_id,
                            "replay_fraction": self.config.curriculum_replay_fraction,
                            "minimum_exact_match_rate": self.config.minimum_exact_match_rate,
                            "heldout_count": self.config.heldout_prompt_count}
                if training_scope == "full_encoder":
                    settings["training_scope"] = training_scope
                fingerprint = request_fingerprint(request, curriculum, settings)
        except (ValueError, OSError, KeyError, TypeError) as exc:
            context.abort(grpc.StatusCode.FAILED_PRECONDITION, str(exc))
        if policy_expectations or taxonomy_dataset is not None or audience_release is not None or training_scope == "full_encoder" or request.metadata.get("require_full_capability") == "true":
            try:
                if not curriculum and taxonomy_dataset is None and audience_release is None:
                    settings = {"training": asdict(self.config.batch_training_config(cycle.seed, training_scope=training_scope)),
                                "scope": training_scope, "prompt_count": cycle.prompt_count,
                                "heldout_count": self.config.heldout_prompt_count,
                                "minimum_exact_match_rate": self.config.minimum_exact_match_rate,
                                "dataset_sha256": (hashlib.sha256(Path(self.config.prompt_dataset_path).read_bytes()).hexdigest()
                                                   if self.config.prompt_dataset_path else "bundled_synthetic_generator_v1")}
                    if policy_expectations:
                        settings.update(model_id=cycle.model_id, seed=cycle.seed, policy_admission="artifact_policy_v1",
                                        expectations=policy_expectations,
                                        semantic_execution_contract="training_base_heldout_candidate_heldout_v1")
                    fingerprint = hashlib.sha256(json.dumps([request.SerializeToString(deterministic=True).hex(), settings],
                                                           sort_keys=True, separators=(",", ":")).encode()).hexdigest()
                from privoke_model.contextual_training import training_admission_metadata
                invocation_metadata = training_admission_metadata(policy_expectations)
                if invocation_metadata:
                    fingerprint = hashlib.sha256(json.dumps([fingerprint, invocation_metadata],
                        sort_keys=True, separators=(",", ":")).encode()).hexdigest()
                reserve_training_request(request, training_scope, fingerprint)
            except (ValueError, OSError) as exc:
                context.abort(grpc.StatusCode.FAILED_PRECONDITION, str(exc))
        previous = (self._previous_update_for_fingerprint(request, cycle, context, fingerprint)
                    if fingerprint is not None else self._previous_update(request, cycle, context))
        if previous.found:
            recover_cycle_evidence_ack(request, training_scope, previous)
            return parameters_pb2.FuzzerTrainingResponse(
                accepted=previous.ack.accepted,
                model_id=previous.ack.model_id,
                base_version=previous.base_version,
                applied_version=previous.ack.applied_version,
                prompts_generated=previous.prompts_generated,
                message=previous.ack.message,
                metadata={"replayed": "true"},
            )
        _log_cycle_started(request, cycle)
        sampling_strategy = strategy
        sampling_arguments = ({"sampling_strategy": sampling_strategy} if sampling_strategy is not None else {})
        if taxonomy_dataset is not None:
            sampling_arguments["taxonomy_dataset"] = taxonomy_dataset
        if rehearsal_manifest is not None:
            sampling_arguments["rehearsal_manifest"] = rehearsal_manifest
        if benign_release is not None:
            sampling_arguments["benign_release"] = benign_release
        if audience_release is not None:
            sampling_arguments["audience_release"] = audience_release
        sampling_audit = {}
        replay_examples = ()
        try:
            if curriculum:
                if sampling_strategy is not None:
                    raise ValueError("Contextual sampling strategy cannot override the fixed curriculum.")
                batch = reserve_batch(curriculum, self.config.curriculum_state_path, request,
                                      cycle.prompt_count, self.config.curriculum_replay_fraction,
                                      fingerprint=fingerprint, model_id=cycle.model_id)
                examples, heldout_examples, replay_examples = batch.examples, batch.heldout, batch.replay
                sampling_audit = batch.audit
                sampling_audit["curriculum_replay_weight"] = str(
                    self.config.batch_training_config(cycle.seed, training_scope=training_scope).golden_example_weight)
            else:
                examples, heldout_examples = generate_training_partition(
                    count=cycle.prompt_count,
                    heldout_count=self.config.heldout_prompt_count,
                    seed=cycle.seed,
                    dataset_path=self.config.prompt_dataset_path,
                    **sampling_arguments,
                )
                if sampling_strategy is not None:
                    sampling_audit = (audience.audit_originals(audience_release, examples, heldout_examples, cycle.seed)
                                      if audience_release is not None else benign.audit_originals(taxonomy_dataset, benign_release, examples, heldout_examples, cycle.seed)
                                      if benign_release is not None else rehearsal.audit_originals(taxonomy_dataset, rehearsal_manifest, examples, heldout_examples, cycle.seed)
                                      if rehearsal_manifest is not None else audit_originals(taxonomy_dataset, examples, heldout_examples)
                                      if taxonomy_dataset is not None else contextual_sampling_audit(examples))
        except (ValueError, OSError, KeyError, TypeError) as exc:
            context.abort(grpc.StatusCode.FAILED_PRECONDITION, str(exc))
        update = self._train(
            cycle.model_id,
            examples,
            heldout_examples,
            cycle.seed,
            context,
            training_scope=training_scope,
            request_id=request.request_id,
            require_full_capability=request.metadata.get("require_full_capability") == "true",
            **({"golden_examples": replay_examples} if curriculum else {}),
            **({"taxonomy_dataset": taxonomy_dataset} if taxonomy_dataset is not None else {}),
            **({"rehearsal_manifest": rehearsal_manifest} if rehearsal_manifest is not None else {}),
            **({"benign_release": benign_release} if benign_release is not None else {}),
            **({"audience_release": audience_release} if audience_release is not None else {}),
            **({"retention_release": retention_release} if retention_release is not None else {}),
            **policy_expectations,
        )
        if sampling_audit:
            update = replace(update, metadata={**update.metadata, **sampling_audit})
        if update.metadata.get("executed_contextual_training_optimizer") in ({"full_projected_adam64_v1"} | retention.POLICIES):
            from training.full_adam_evidence import gate_summary, GATE_KEY
            from privoke_model.full_adam import canonical
            update = replace(update, metadata={**update.metadata,
                GATE_KEY: canonical(gate_summary(update, self.config.minimum_exact_match_rate))})
        expected_base = request.metadata.get("expected_base_version")
        if expected_base and update.base_version != expected_base:
            context.abort(grpc.StatusCode.FAILED_PRECONDITION,
                          "Underlying stage base differs from the prior committed head stage.")
        if request.metadata.get("study_gate_diagnostics") == "v1":
            try:
                write_gate_diagnostics(request, update, self.config)
            except (OSError, ValueError) as exc:
                context.abort(grpc.StatusCode.FAILED_PRECONDITION, str(exc))
        try:
            validate_training_update(
                update,
                minimum_exact_match_rate=self.config.minimum_exact_match_rate,
            )
        except ValueError as exc:
            persist_cycle_evidence(request, update, training_scope, gate_passed=False)
            LOGGER.warning("rejecting training update: %s", exc)
            context.abort(grpc.StatusCode.FAILED_PRECONDITION, str(exc))
        if not context.is_active():
            context.abort(
                grpc.StatusCode.CANCELLED,
                "Training request was cancelled before update submission.",
            )
        generated_count = len(examples) + len(replay_examples)
        try:
            persist_cycle_evidence(request, update, training_scope, gate_passed=True)
        except (OSError, ValueError) as exc:
            context.abort(grpc.StatusCode.FAILED_PRECONDITION, str(exc))
        ack = self._submit_update(request, cycle, update, generated_count, context,
                                  **({"fingerprint": fingerprint} if fingerprint is not None else {}))
        if not ack.accepted or ack.model_id != update.model_id or not ack.applied_version:
            context.abort(grpc.StatusCode.FAILED_PRECONDITION, "Parameter updater did not acknowledge the selected model publication.")
        try:
            persist_cycle_evidence(request, update, training_scope, gate_passed=True, ack=ack)
        except OSError:
            # Prepared evidence and durable updater receipt remain available for
            # recovery; a missing acknowledgement must never trigger republication.
            LOGGER.exception("Committed training acknowledgement evidence persistence failed")
        LOGGER.info(
            "completed training request id=%r accepted=%s version=%r prompts=%s",
            request.request_id,
            ack.accepted,
            ack.applied_version,
            len(examples),
        )
        return build_training_response(ack, update, generated_count)

    def _previous_update(self, request, cycle, context):
        return self._previous_update_for_fingerprint(
            request, cycle, context, _training_request_fingerprint(request)
        )

    def _previous_update_for_fingerprint(self, request, cycle, context, fingerprint):
        try:
            with grpc.insecure_channel(self.config.param_update_target) as channel:
                return parameters_pb2_grpc.ParamUpdateServiceStub(channel).GetParameterUpdateStatus(
                    parameters_pb2.ParameterUpdateStatusRequest(
                        source_id=self.config.fuzzer_id,
                        request_id=request.request_id,
                        request_source_id=request.source_id,
                        model_id=cycle.model_id,
                        request_fingerprint=fingerprint,
                    ),
                    timeout=self.config.timeout_seconds,
                )
        except grpc.RpcError as exc:
            if exc.code() == grpc.StatusCode.ALREADY_EXISTS:
                context.abort(grpc.StatusCode.ALREADY_EXISTS, "request_id belongs to a different training request.")
            context.abort(grpc.StatusCode.UNAVAILABLE, "Parameter update receipts are unavailable.")

    def _train(self, model_id, examples, heldout_examples, seed: int, context, *, golden_examples=(),
               training_scope="heads", request_id="", require_full_capability=False, taxonomy_dataset=None, rehearsal_manifest=None, benign_release=None,
               expected_objective=None, expected_diagnostics_policy=None,
               expected_backtracking_policy=None, expected_backtracking_preparation_sha256=None,
               expected_optimizer=None, expected_candidate_eligibility=None, expected_optimizer_config=None,
               expected_training_scope=None, retention_release=None, expected_retention_manifest_sha256=None, audience_release=None) -> BatchTrainingUpdate:
        try:
            return train_parameter_batch(
                model_id=model_id,
                new_examples=examples,
                heldout_examples=heldout_examples,
                golden_examples=golden_examples,
                training_scope=training_scope,
                request_id=request_id,
                require_full_capability=require_full_capability,
                config=self.config.batch_training_config(seed, training_scope=training_scope),
                **({"taxonomy_dataset": taxonomy_dataset} if taxonomy_dataset is not None else {}),
                **({"rehearsal_manifest": rehearsal_manifest} if rehearsal_manifest is not None else {}),
                **({"benign_release": benign_release} if benign_release is not None else {}),
                **({"audience_release": audience_release} if audience_release is not None else {}),
                **({"retention_release": retention_release, "expected_retention_manifest_sha256": expected_retention_manifest_sha256} if retention_release is not None else {}),
                **({"expected_objective": expected_objective} if expected_objective is not None else {}),
                **({"expected_diagnostics_policy": expected_diagnostics_policy} if expected_diagnostics_policy is not None else {}),
                **({"expected_backtracking_policy": expected_backtracking_policy,
                    "expected_backtracking_preparation_sha256": expected_backtracking_preparation_sha256}
                   if expected_backtracking_policy is not None else {}),
                **({"expected_optimizer": expected_optimizer, "expected_candidate_eligibility": expected_candidate_eligibility,
                    "expected_optimizer_config": expected_optimizer_config, "expected_training_scope": expected_training_scope} if expected_optimizer is not None else {}),
                runtime_client=PrivokeRuntimeClient(
                    self.config.privoke_runtime_target,
                    timeout_seconds=self.config.timeout_seconds,
                ),
            )
        except ValueError as exc:
            context.abort(grpc.StatusCode.FAILED_PRECONDITION, str(exc))
        except (RuntimeAnalysisError, grpc.RpcError, OSError) as exc:
            LOGGER.warning("client runtime semantic training failed: %s", exc)
            context.abort(
                grpc.StatusCode.UNAVAILABLE,
                "Client runtime training evaluation is unavailable.",
            )

    def _submit_update(
        self,
        request,
        cycle: TrainingCycle,
        update: BatchTrainingUpdate,
        generated_count: int,
        context,
        *, fingerprint=None,
    ):
        try:
            return emit_training_update(
                target=self.config.param_update_target,
                source_id=self.config.fuzzer_id,
                update=update,
                extra_metadata={
                    "request_id": request.request_id,
                    "request_source_id": request.source_id,
                    "requested_prompt_count": str(cycle.requested_prompt_count),
                    "generated_prompt_count": str(generated_count),
                    "training_pipeline": "client_runtime_underlying_gradients" if update.metadata.get("training_scope") == "full_encoder" else "client_runtime_semantic_gradients",
                    "training_request_fingerprint": fingerprint or _training_request_fingerprint(request),
                },
                timeout_seconds=self.config.timeout_seconds,
            )
        except (ValueError, OSError) as exc:
            context.abort(grpc.StatusCode.FAILED_PRECONDITION, "Training publication evidence or metadata is invalid.")
        except grpc.RpcError as exc:
            LOGGER.warning(
                "parameter update submission failed code=%s",
                exc.code(),
            )
            if exc.code() in (grpc.StatusCode.INVALID_ARGUMENT, grpc.StatusCode.FAILED_PRECONDITION,
                              grpc.StatusCode.ALREADY_EXISTS):
                context.abort(exc.code(), "Parameter update service rejected the training stage.")
            context.abort(
                grpc.StatusCode.UNAVAILABLE,
                "Parameter update service is unavailable.",
            )

    def Health(self, request, context):
        return parameters_pb2.HealthResponse(
            service="privoke-fuzzer",
            status="SERVING",
        )


def validate_training_request(request, expected_model_id: str) -> None:
    validate_text(request.request_id, "request_id", required=True)
    validate_text(request.source_id, "source_id", required=True)
    validate_text(request.model_id, "model_id", required=False)
    if request.model_id and request.model_id != expected_model_id:
        raise ValueError(f"model_id must be {expected_model_id!r}.")
    if request.prompt_count <= 0:
        raise ValueError("prompt_count must be greater than zero.")
    if len(request.metadata) > 64:
        raise ValueError("metadata may contain at most 64 entries.")
    for key, value in request.metadata.items():
        validate_text(key, "metadata key", required=True, limit=128)
        validate_text(value, "metadata value", required=False, limit=2_048)
    if CONTEXTUAL_SAMPLING_STRATEGY_KEY in request.metadata:
        from privoke_model import window_training as window_contract
        strategy = request.metadata[CONTEXTUAL_SAMPLING_STRATEGY_KEY]
        if strategy == window_contract.SAMPLER:
            if request.prompt_count != 256:
                raise ValueError("Window sampling requires exactly 256 originals.")
            if window_contract.expectations(request.metadata) is None:
                raise ValueError("Window sampling requires its exact FULL policy and release pins.")
            if any(key in request.metadata for key in (
                    "expected_contextual_training_backtracking_policy",
                    "expected_contextual_training_diagnostics_policy")):
                raise ValueError("Window sampling excludes backtracking and diagnostics policies.")
        else:
            validate_contextual_sampling_strategy(strategy, request.prompt_count)


def _training_request_fingerprint(request) -> str:
    return hashlib.sha256(request.SerializeToString(deterministic=True)).hexdigest()


def gate_diagnostics(request, update, minimum):
    """Numeric, prompt-free record of the unchanged publication guard."""
    from training.full_adam_evidence import eligibility_metric, gate_summary
    selected_metric = eligibility_metric(update)
    candidate_route = selected_metric == "candidate_train_exact_match_rate"
    metrics = {key: value for key, value in update.metrics.items()
               if key in {"exact_match_rate", "heldout_exact_match_rate", "candidate_heldout_exact_match_rate",
                          "heldout_sensitive_recall", "candidate_heldout_sensitive_recall",
                          "heldout_clean_specificity", "candidate_heldout_clean_specificity",
                          "heldout_sensitive_examples", "heldout_clean_examples",
                          "candidate_heldout_safety_regression_rate"}
               or (candidate_route and key == "candidate_train_exact_match_rate")}
    # Invalid values remain explicit and serializable rather than becoming zero.
    metrics = {key: value if math.isfinite(value) else None for key, value in metrics.items()}
    failures = []
    try:
        validate_training_update(update, minimum_exact_match_rate=minimum)
    except ValueError as exc:
        failures.append({"predicate": "validation", "message": str(exc)})
    comparisons = (("training_exact_above_minimum", selected_metric, None),
                   ("heldout_exact_no_decline", "candidate_heldout_exact_match_rate", "heldout_exact_match_rate"),
                   ("heldout_recall_no_decline", "candidate_heldout_sensitive_recall", "heldout_sensitive_recall"),
                   ("heldout_specificity_no_decline", "candidate_heldout_clean_specificity", "heldout_clean_specificity"),
                   ("no_safety_regression", "candidate_heldout_safety_regression_rate", None))
    for predicate, key, reference in comparisons:
        value = metrics.get(key)
        base = metrics.get(reference) if reference else None
        failed = (value is None or (reference is not None and base is None))
        if not failed:
            failed = value <= minimum if key == selected_metric else (value > 0 if reference is None else value < base)
        if failed:
            failures.append({"predicate": predicate})
    identities = {key: update.metadata.get(key) for key in ("base_parameter_fingerprint", "updated_parameter_fingerprint")}
    if any(not isinstance(value, str) or len(value) != 64 for value in identities.values()):
        raise ValueError("Study gate diagnostics require exact base and candidate fingerprints.")
    return {"schema_version": 1, "request_id": request.request_id, "source_id": request.source_id,
            "request_sha256": _training_request_fingerprint(request), "model_id": update.model_id,
            "base_version": update.base_version, **identities, "minimum_exact_match_rate": minimum,
            **({"metric_role": "candidate_train", "gate_policy": gate_summary(update, minimum)} if candidate_route else {}),
            "metrics": metrics, "failed_predicates": failures, "gate_passed": not failures}


def write_gate_diagnostics(request, update, config):
    if not config.curriculum_state_path:
        raise ValueError("Study diagnostics require durable curriculum storage.")
    record = gate_diagnostics(request, update, config.minimum_exact_match_rate)
    directory = Path(config.curriculum_state_path).parent / "gate-diagnostics"
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / (record["request_sha256"] + ".json")
    if path.exists():
        if json.loads(path.read_text(encoding="utf-8")) != record:
            raise ValueError("Conflicting durable gate diagnostics for the same request.")
        return
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(record, sort_keys=True, allow_nan=False) + "\n", encoding="utf-8")
    temporary.replace(path)


def validate_training_update(
    update: BatchTrainingUpdate,
    *,
    minimum_exact_match_rate: float,
) -> None:
    from privoke_model import window_training as window
    if update.metadata.get("contextual_training_optimizer") == window.POLICY:
        from training.window_evidence import validate_update
        trace = validate_update(update)
        if trace["status"] != "selected" or update.metrics["candidate_train_exact_match_rate"] <= minimum_exact_match_rate:
            raise ValueError("Window policy has no publishable sensitive-progress checkpoint.")
        return
    if not math.isfinite(minimum_exact_match_rate) or not 0 <= minimum_exact_match_rate <= 1:
        raise ValueError("Minimum exact match rate must be finite and within [0, 1].")
    required_rates = (
        "exact_match_rate", "heldout_exact_match_rate", "candidate_heldout_exact_match_rate",
        "heldout_sensitive_recall", "candidate_heldout_sensitive_recall",
        "heldout_clean_specificity", "candidate_heldout_clean_specificity",
        "candidate_heldout_safety_regression_rate",
    )
    for name in required_rates:
        value = update.metrics.get(name)
        if value is None:
            raise ValueError(f"Training update did not report {name}.")
        if not math.isfinite(value) or not 0 <= value <= 1:
            raise ValueError(f"Training update {name} must be finite and within [0, 1].")
    for name in ("heldout_sensitive_examples", "heldout_clean_examples"):
        value = update.metrics.get(name, 0)
        if not math.isfinite(value) or value < 1 or value != int(value):
            raise ValueError("Held-out evaluation needs both clean and sensitive examples.")
    from training.full_adam_evidence import eligibility_metric
    from privoke_model import sensitive_retention as retention
    if update.metadata.get("contextual_training_optimizer") in retention.POLICIES:
        summary = json.loads(update.metadata[retention.SUMMARY_KEY])
        if summary["violations"] != 0:
            raise ValueError("ORIGINAL TRAIN target-capped per-row admission failed; no update published.")
    exact_match_rate = update.metrics.get(eligibility_metric(update))
    if exact_match_rate is None:
        raise ValueError("Training update did not report exact_match_rate.")
    if exact_match_rate <= minimum_exact_match_rate:
        raise ValueError(
            "Training update exact_match_rate "
            f"{exact_match_rate:.4f} must be greater than the minimum "
            f"{minimum_exact_match_rate:.4f}."
        )
    before_recall = update.metrics.get("heldout_sensitive_recall")
    candidate_recall = update.metrics.get("candidate_heldout_sensitive_recall")
    before_specificity = update.metrics.get("heldout_clean_specificity")
    candidate_specificity = update.metrics.get("candidate_heldout_clean_specificity")
    if None in (before_recall, candidate_recall, before_specificity, candidate_specificity):
        raise ValueError("Training update did not report held-out quality metrics.")
    if (
        candidate_recall < before_recall
        or candidate_specificity < before_specificity
        or update.metrics["candidate_heldout_exact_match_rate"] < update.metrics["heldout_exact_match_rate"]
        or update.metrics["candidate_heldout_safety_regression_rate"] > 0
    ):
        raise ValueError("Candidate model is worse on the held-out evaluation set.")


def validate_presence_training_request(request, expected_model_id: str) -> None:
    validate_text(request.request_id, "request_id", required=True)
    validate_text(request.source_id, "source_id", required=True)
    validate_text(request.model_id, "model_id", required=True)
    if request.model_id != expected_model_id:
        raise ValueError(f"model_id must be {expected_model_id!r}.")
    if request.prompt_count < 2:
        raise ValueError("Presence prompt_count must be at least two to train both binary classes.")
    if len(request.metadata) > 64:
        raise ValueError("metadata may contain at most 64 entries.")
    for key, value in request.metadata.items():
        validate_text(key, "metadata key", required=True, limit=128)
        validate_text(value, "metadata value", required=False, limit=2_048)


def _presence_training_request_fingerprint(request) -> str:
    payload = (b"RunPresenceTrainingCycle:annotation_presence:v1\0"
               + request.SerializeToString(deterministic=True))
    return hashlib.sha256(payload).hexdigest()


def validate_presence_training_update(
    update, *, minimum_exact_match_rate: float,
    expected_examples: int | None = None,
    expected_heldout_examples: int | None = None,
) -> None:
    if not math.isfinite(minimum_exact_match_rate) or not 0 <= minimum_exact_match_rate <= 1:
        raise ValueError("Minimum exact match rate must be finite and within [0, 1].")
    metrics = update.metrics
    required_counts = (
        "examples", "heldout_examples", "heldout_present_examples", "heldout_absent_examples",
        "candidate_heldout_examples", "candidate_heldout_present_examples",
        "candidate_heldout_absent_examples",
    )
    for name in required_counts:
        value = metrics.get(name)
        if (type(value) not in (int, float) or not math.isfinite(value)
                or value < 1 or value != int(value)):
            raise ValueError("Presence held-out evaluation needs positive integral counts in both strata.")
    if expected_examples is not None and metrics["examples"] != expected_examples:
        raise ValueError("Presence training example count does not match the submitted batch.")
    if expected_heldout_examples is not None and metrics["heldout_examples"] != expected_heldout_examples:
        raise ValueError("Presence held-out count does not match the submitted batch.")
    for suffix in ("examples", "present_examples", "absent_examples"):
        if metrics[f"candidate_heldout_{suffix}"] != metrics[f"heldout_{suffix}"]:
            raise ValueError("Presence candidate held-out counts do not match the baseline counts.")
    if metrics["heldout_examples"] != metrics["heldout_present_examples"] + metrics["heldout_absent_examples"]:
        raise ValueError("Presence held-out example counts are inconsistent.")
    average_loss = metrics.get("average_loss")
    if type(average_loss) not in (int, float) or not math.isfinite(average_loss) or average_loss < 0:
        raise ValueError("Presence training average_loss must be finite and non-negative.")
    rates = ("exact_match_rate", "heldout_exact_match_rate", "candidate_heldout_exact_match_rate",
             "heldout_present_recall", "candidate_heldout_present_recall",
             "heldout_absent_specificity", "candidate_heldout_absent_specificity")
    for name in rates:
        value = metrics.get(name)
        if type(value) not in (int, float):
            raise ValueError(f"Presence training update did not report {name}.")
        if not math.isfinite(value) or not 0 <= value <= 1:
            raise ValueError(f"Presence training update {name} must be finite and within [0, 1].")
    _require_integral_correct_count(metrics["exact_match_rate"], metrics["examples"], "training exact match")
    _validate_presence_rates(metrics, "heldout", "heldout_examples",
                             "heldout_present_examples", "heldout_absent_examples")
    _validate_presence_rates(metrics, "candidate_heldout", "candidate_heldout_examples",
                             "candidate_heldout_present_examples", "candidate_heldout_absent_examples")
    if metrics["exact_match_rate"] <= minimum_exact_match_rate:
        raise ValueError("Presence training exact_match_rate must be greater than the configured minimum.")
    if (metrics["candidate_heldout_exact_match_rate"] < metrics["heldout_exact_match_rate"]
            or metrics["candidate_heldout_present_recall"] < metrics["heldout_present_recall"]
            or metrics["candidate_heldout_absent_specificity"] < metrics["heldout_absent_specificity"]):
        raise ValueError("Candidate presence model is worse on the held-out evaluation set.")


def _require_integral_correct_count(rate: float, count: float, label: str) -> float:
    correct = rate * count
    nearest = round(correct)
    if abs(correct - nearest) > 1e-8:
        raise ValueError(f"Presence {label} rate is inconsistent with its example count.")
    return nearest


def _validate_presence_rates(metrics, prefix, total_key, present_key, absent_key) -> None:
    total = metrics[total_key]
    present = metrics[present_key]
    absent = metrics[absent_key]
    recall_key = f"{prefix}_present_recall"
    specificity_key = f"{prefix}_absent_specificity"
    exact_key = f"{prefix}_exact_match_rate"
    present_correct = _require_integral_correct_count(metrics[recall_key], present, recall_key)
    absent_correct = _require_integral_correct_count(metrics[specificity_key], absent, specificity_key)
    exact_correct = _require_integral_correct_count(metrics[exact_key], total, exact_key)
    if abs((present_correct + absent_correct) - exact_correct) > 1e-8:
        raise ValueError(f"Presence {exact_key} does not agree with its stratum rates.")


def _resolve_cycle(request, config: FuzzerConfig) -> TrainingCycle:
    requested_count = int(request.prompt_count)
    prompt_count = min(requested_count, config.max_prompt_count)
    if prompt_count < requested_count:
        LOGGER.info(
            "capped training prompt count requested=%s max=%s",
            requested_count,
            config.max_prompt_count,
        )
    return TrainingCycle(
        requested_prompt_count=requested_count,
        prompt_count=prompt_count,
        model_id=request.model_id or config.model_id,
        seed=int(request.seed) if request.seed else config.seed,
    )


def _log_cycle_started(request, cycle: TrainingCycle) -> None:
    message = (
        "starting automatic training run id=%r source=%r model=%r prompts=%s"
        if request.metadata.get("initiator") == "param-update-service"
        else "received training request id=%r source=%r model=%r prompts=%s"
    )
    LOGGER.info(
        message,
        request.request_id,
        request.source_id,
        cycle.model_id,
        cycle.prompt_count,
    )


def build_training_response(
    ack,
    update: BatchTrainingUpdate,
    prompts_generated: int,
):
    response_metadata = dict(update.metadata)
    response_metadata.update({key: str(value) for key, value in update.metrics.items()})
    return parameters_pb2.FuzzerTrainingResponse(
        accepted=ack.accepted,
        model_id=ack.model_id,
        base_version=update.base_version,
        applied_version=ack.applied_version,
        prompts_generated=prompts_generated,
        message=ack.message,
        metadata=response_metadata,
    )
