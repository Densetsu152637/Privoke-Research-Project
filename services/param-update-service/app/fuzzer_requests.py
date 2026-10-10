from __future__ import annotations

import logging
import math
import sys
import threading
import time
import uuid
from dataclasses import dataclass, replace
from pathlib import Path

SHARED_DIR = Path(__file__).resolve().parents[3] / "shared/python"
if SHARED_DIR.exists() and str(SHARED_DIR) not in sys.path:
    sys.path.insert(0, str(SHARED_DIR))

import grpc
from privoke.v1 import parameters_pb2, parameters_pb2_grpc
from privoke_service import env_float, env_int, env_string, validate_text
from training_cycles import TrainingCycles

LOGGER = logging.getLogger(__name__)


class StageRejected(RuntimeError):
    """A definite protocol rejection, rather than an uncertain transport outcome."""


def _underlying_enabled():
    value = env_string("FUZZER_TRAIN_UNDERLYING", "true").lower()
    if value not in ("true", "false"):
        raise ValueError("FUZZER_TRAIN_UNDERLYING must be true or false.")
    return value == "true"


@dataclass(frozen=True)
class FuzzerRequestConfig:
    target: str
    prompt_count: int
    model_id: str
    source_id: str
    timeout_seconds: float
    interval_seconds: float
    initial_delay_seconds: float
    retry_seconds: float
    max_attempts: int
    seed: int
    curriculum_sampler_policy: str = "deterministic_v1"
    curriculum_sampler_seed: int = 0
    train_underlying: bool = True
    state_path: str = "/data/training-cycles.sqlite3"

    @classmethod
    def from_env(cls) -> FuzzerRequestConfig:
        config = cls(
            target=env_string("FUZZER_TARGET", "privoke-fuzzer:50053", strip=True),
            prompt_count=env_int("FUZZER_PROMPT_COUNT", 32),
            model_id=env_string("MODEL_ID", "privoke-baseline", strip=True),
            source_id=env_string(
                "PARAM_UPDATE_SOURCE_ID",
                "param-update-service",
                strip=True,
            ),
            timeout_seconds=env_float("FUZZER_REQUEST_TIMEOUT_SECONDS", 30.0),
            interval_seconds=env_float("FUZZER_REQUEST_INTERVAL_SECONDS", 3600.0),
            initial_delay_seconds=env_float(
                "FUZZER_REQUEST_INITIAL_DELAY_SECONDS",
                2.0,
            ),
            retry_seconds=env_float("FUZZER_REQUEST_RETRY_SECONDS", 2.0),
            max_attempts=env_int("FUZZER_REQUEST_MAX_ATTEMPTS", 3),
            seed=env_int("FUZZER_REQUEST_SEED", 1337),
            curriculum_sampler_policy=env_string("FUZZER_CURRICULUM_SAMPLER_POLICY", "deterministic_v1", strip=True),
            curriculum_sampler_seed=env_int("FUZZER_CURRICULUM_SAMPLER_SEED", 0),
            train_underlying=_underlying_enabled(),
            state_path=env_string("FUZZER_CYCLE_STATE_PATH", "/data/training-cycles.sqlite3"),
        )
        config.validate()
        return config

    def validate(self) -> None:
        if type(self.train_underlying) is not bool or not self.state_path:
            raise ValueError("Automatic training requires a boolean stage selection and durable state path.")
        validate_text(self.target, "FUZZER_TARGET", required=True, limit=256)
        validate_text(self.model_id, "MODEL_ID", required=True)
        validate_text(self.source_id, "PARAM_UPDATE_SOURCE_ID", required=True)
        if self.prompt_count < 0:
            raise ValueError("FUZZER_PROMPT_COUNT must not be negative.")
        if self.max_attempts <= 0:
            raise ValueError("FUZZER_REQUEST_MAX_ATTEMPTS must be positive.")
        if not 0 <= self.seed <= 0xFFFFFFFF:
            raise ValueError("FUZZER_REQUEST_SEED must fit an unsigned 32-bit integer.")
        if self.curriculum_sampler_policy not in {"deterministic_v1", "seeded_family_v1"}:
            raise ValueError("Unknown FUZZER_CURRICULUM_SAMPLER_POLICY.")
        if not 0 <= self.curriculum_sampler_seed <= 0xFFFFFFFF:
            raise ValueError("FUZZER_CURRICULUM_SAMPLER_SEED must fit an unsigned 32-bit integer.")
        if self.curriculum_sampler_policy == "deterministic_v1" and self.curriculum_sampler_seed:
            raise ValueError("deterministic_v1 requires FUZZER_CURRICULUM_SAMPLER_SEED=0.")
        for name, value, allow_zero in (
            ("FUZZER_REQUEST_TIMEOUT_SECONDS", self.timeout_seconds, False),
            ("FUZZER_REQUEST_INTERVAL_SECONDS", self.interval_seconds, True),
            ("FUZZER_REQUEST_INITIAL_DELAY_SECONDS", self.initial_delay_seconds, True),
            ("FUZZER_REQUEST_RETRY_SECONDS", self.retry_seconds, True),
        ):
            if not math.isfinite(value) or value < 0 or (not allow_zero and value == 0):
                requirement = "non-negative" if allow_zero else "positive"
                raise ValueError(f"{name} must be finite and {requirement}.")


def start_fuzzer_requester(config: FuzzerRequestConfig) -> None:
    if config.prompt_count <= 0:
        return

    thread = threading.Thread(
        target=request_fuzzer_loop,
        args=(config,),
        daemon=True,
        name="fuzzer-training-requester",
    )
    thread.start()


def request_fuzzer_loop(config: FuzzerRequestConfig) -> None:
    if config.prompt_count <= 0:
        return
    if config.initial_delay_seconds > 0:
        time.sleep(config.initial_delay_seconds)
    journal = TrainingCycles(config.state_path)
    try:
        while True:
            cycle = journal.reserve(config)
            if cycle is None:
                return
            if cycle["state"] != "pending":
                remaining = cycle.get("finished_at", 0) + config.interval_seconds - time.time()
                if remaining > 0:
                    time.sleep(remaining)
                continue
            for stage in ("heads", "full_encoder") if config.train_underlying else ("heads",):
                state = cycle["stages"][stage]
                if state["state"] == "accepted":
                    continue
                stage_config = replace(config, seed=cycle["seed"])
                expected_base = cycle["stages"]["heads"].get("applied_version") if stage == "full_encoder" else None
                state["request_protobuf_hex"] = build_training_request(stage_config, state["request_id"], expected_base).SerializeToString(deterministic=True).hex()
                journal.save(cycle)
                for attempt in range(config.max_attempts):
                    try:
                        response = request_fuzzer_training(replace(config, seed=cycle["seed"]),
                            training_request_id=state["request_id"], training_scope=stage,
                            expected_base_version=expected_base)
                        if not response.accepted or response.model_id != config.model_id or not response.applied_version:
                            raise StageRejected("Fuzzer rejected the training stage or returned a mismatched publication.")
                        if expected_base and response.base_version != expected_base:
                            raise StageRejected("Underlying stage did not use the acknowledged head publication base.")
                        state.update(state="accepted", base_version=response.base_version,
                                     applied_version=response.applied_version,
                                     response_protobuf_hex=response.SerializeToString(deterministic=True).hex())
                        journal.save(cycle)
                        break
                    except (grpc.RpcError, RuntimeError) as exc:
                        terminal = isinstance(exc, StageRejected) or (isinstance(exc, grpc.RpcError) and exc.code() in (
                            grpc.StatusCode.FAILED_PRECONDITION, grpc.StatusCode.INVALID_ARGUMENT,
                            grpc.StatusCode.ALREADY_EXISTS))
                        state["last_error"] = str(exc)
                        if terminal:
                            state["state"] = "rejected"
                            cycle["state"] = "partial" if any(s["state"] == "accepted" for s in cycle["stages"].values()) else "rejected"
                            cycle["finished_at"] = time.time()
                        journal.save(cycle)
                        LOGGER.warning("automatic training cycle=%s stage=%s state=%s: %s", cycle["cycle_id"], stage, cycle["state"], exc)
                        if terminal or attempt + 1 == config.max_attempts:
                            break
                        time.sleep(config.retry_seconds)
                if state["state"] != "accepted":
                    break
            if all(s["state"] == "accepted" for s in cycle["stages"].values()):
                cycle["state"] = "complete"
                cycle["finished_at"] = time.time()
                journal.save(cycle)
            if config.interval_seconds <= 0:
                return
            time.sleep(config.interval_seconds)
            # Transient exhaustion remains pending and resumes identical stage
            # IDs; terminal safety rejection starts a fresh independent cycle.
    finally:
        journal.close()


def request_fuzzer_training(
    config: FuzzerRequestConfig,
    training_request_id: str | None = None,
    training_scope: str = "heads",
    expected_base_version: str | None = None,
):
    with grpc.insecure_channel(config.target) as channel:
        client = parameters_pb2_grpc.FuzzerServiceStub(channel)
        method = client.RunUnderlyingTrainingCycle if training_scope == "full_encoder" else client.RunTrainingCycle
        return method(build_training_request(config, training_request_id or request_id(config.source_id), expected_base_version),
                      timeout=config.timeout_seconds)


def build_training_request(config, training_request_id, expected_base_version=None):
    metadata = {"initiator": "param-update-service"}
    if config.train_underlying:
        metadata["require_full_capability"] = "true"
    if expected_base_version:
        metadata["expected_base_version"] = expected_base_version
    if config.curriculum_sampler_policy != "deterministic_v1":
        metadata.update(curriculum_sampler_policy=config.curriculum_sampler_policy,
                        curriculum_sampler_seed=str(config.curriculum_sampler_seed))
    return parameters_pb2.FuzzerTrainingRequest(
                request_id=training_request_id,
                source_id=config.source_id,
                model_id=config.model_id,
                prompt_count=config.prompt_count,
                seed=config.seed,
                metadata=metadata,
            )


def request_id(source_id: str) -> str:
    return f"{source_id}-{int(time.time())}-{uuid.uuid4().hex[:8]}"
