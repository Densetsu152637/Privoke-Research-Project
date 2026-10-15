from __future__ import annotations

import math
import os
import random
from collections.abc import Iterable, Sequence
from pathlib import Path

from privoke_service import env_float, env_string
from privoke_model.training_data import training_text_key
from runtime_client import PrivokeRuntimeClient

from .io import load_training_examples
from .transforms import random_pii_transform
from .types import BatchTrainingConfig, BatchTrainingExample, BatchTrainingUpdate


def train_parameter_batch_from_files(
    model_id: str,
    batch_path: str | Path,
    golden_batch_path: str | Path | None = None,
    config: BatchTrainingConfig | None = None,
    runtime_client: PrivokeRuntimeClient | None = None,
) -> BatchTrainingUpdate:
    golden_examples = (
        load_training_examples(golden_batch_path)
        if golden_batch_path is not None
        else []
    )
    return train_parameter_batch(
        model_id=model_id,
        new_examples=load_training_examples(batch_path),
        golden_examples=golden_examples,
        config=config,
        runtime_client=runtime_client,
    )


def train_parameter_batch(
    model_id: str,
    new_examples: Sequence[BatchTrainingExample],
    golden_examples: Sequence[BatchTrainingExample] = (),
    heldout_examples: Sequence[BatchTrainingExample] = (),
    config: BatchTrainingConfig | None = None,
    runtime_client: PrivokeRuntimeClient | None = None,
    training_scope: str = "heads",
    request_id: str = "",
    require_full_capability: bool = False,
    taxonomy_dataset=None,
    rehearsal_manifest=None,
    benign_release=None,
    expected_objective=None,
    expected_diagnostics_policy=None,
    expected_backtracking_policy=None,
    expected_backtracking_preparation_sha256=None,
    expected_optimizer=None,
    expected_candidate_eligibility=None,
    expected_optimizer_config=None,
    expected_training_scope=None,
    retention_release=None,
    expected_retention_manifest_sha256=None,
    window_release=None,
    component_release=None,
    window_admission=None,
    audience_release=None,
) -> BatchTrainingUpdate:
    """Prepare examples and delegate model execution and descent to client-runtime."""
    config = config or BatchTrainingConfig()
    _validate_config(config)
    if window_release is not None or component_release is not None or window_admission is not None:
        from privoke_model import window_training as window
        if (window_release is None or component_release is None or window_admission is None or golden_examples
                or training_scope != "full_encoder" or config.learning_rate != .003 or config.max_gradient != .05
                or config.transformations_per_example != 1 or config.new_example_weight != 1):
            raise ValueError("Frozen window trainer requires exclusive prepared FULL inputs and fixed source/rate/cap contract.")
        window.validate_request(window_release,new_examples,heldout_examples)
        runtime_client = runtime_client or _default_runtime_client()
        batch = runtime_client.compute_window_gradients(new_examples,heldout_examples=heldout_examples,model_id=model_id,
            request_id=request_id,window=window_release,release=component_release,admission=window_admission,
            learning_rate=config.learning_rate,max_gradient=config.max_gradient)
        return BatchTrainingUpdate(model_id=batch["model_id"],base_version=batch["base_version"],gradients=batch["gradients"],
            parameter_shapes=batch["shapes"],metrics=batch["metrics"],metadata=batch["metadata"],execution_evidence=batch["execution_evidence"])
    from privoke_model import sensitive_retention as retention
    retention_mode = expected_optimizer in retention.POLICIES
    if retention_mode:
        from prompt_generation.benign_coverage import validate_legacy_snapshot
        if (taxonomy_dataset is None or benign_release is None or rehearsal_manifest is not None or golden_examples
                or training_scope != "full_encoder"):
            raise ValueError("Retention requires exclusive BC01 permanent TRAIN snapshots and FULL scope.")
        validate_legacy_snapshot(taxonomy_dataset)
        retention.validate_trusted_release(retention_release, model_id=model_id,
            request_sha256=expected_retention_manifest_sha256, trusted_sha256=os.getenv("FUZZ_RETENTION_MANIFEST_SHA256"))
        retention.expectations({"expected_contextual_training_optimizer": expected_optimizer,
            "expected_contextual_training_objective": expected_objective,
            "expected_contextual_candidate_eligibility": expected_candidate_eligibility,
            "expected_full_projected_adam_config_v1": expected_optimizer_config,
            "expected_contextual_training_scope": expected_training_scope,
            "expected_original_train_retention_manifest_sha256": expected_retention_manifest_sha256,
            "expected_contextual_training_diagnostics_policy": expected_diagnostics_policy,
            "expected_contextual_training_backtracking_policy": expected_backtracking_policy})
    elif retention_release is not None or expected_retention_manifest_sha256 is not None:
        raise ValueError("Orphan ORIGINAL retention trainer snapshot/pin.")
    expanded_count = len(new_examples) * (config.transformations_per_example + 1)
    if expanded_count + len(golden_examples) + len(heldout_examples) > 1024:
        raise ValueError("Expanded training plus held-out examples must not exceed 1024.")
    trainer_examples = list(
        iter_training_examples(new_examples, golden_examples, config)
    )
    _validate_examples(trainer_examples)
    if {training_text_key(item.text) for item in trainer_examples}.intersection(
        training_text_key(item.text) for item in heldout_examples
    ):
        raise ValueError("Held-out examples overlap transformed training texts.")
    sampling_audit = {}
    audience_evidence = None
    if audience_release is not None:
        if golden_examples or taxonomy_dataset is not None or benign_release is not None or rehearsal_manifest is not None or config.new_example_weight != 1:
            raise ValueError("Audience coverage cannot mix legacy replay/policies or nonunit source weights.")
        from prompt_generation.audience_coverage import audit_expanded
        sampling_audit = audit_expanded(audience_release, new_examples, trainer_examples, heldout_examples, config)
        from prompt_generation.audience_coverage import implementation_closure
        audience_evidence = {"release_sha256": audience_release.sha256, "implementation": implementation_closure(),
                             "selected_ids": [r.metadata["example_id"] for r in new_examples],
                             "originals": [{"text": r.text, "packed": r.expected_packed_classification,
                                            "weight": r.weight, "metadata": r.metadata} for r in new_examples],
                             "guard_ids": [r.metadata["example_id"] for r in heldout_examples]}
    rehearsal_evidence = None
    benign_evidence = None
    rehearsal = rehearsal_manifest is not None or any(item.metadata.get("taxonomy_strategy") == "taxonomy_anchor_rehearsal_v1" for item in new_examples)
    benign_mode = benign_release is not None or any(item.metadata.get("taxonomy_strategy") == "taxonomy_benign_coverage_v1" for item in new_examples)
    if benign_mode:
        from privoke_model.full_adam import POLICY, ELIGIBILITY, CONFIG, OBJECTIVE, canonical
        if (taxonomy_dataset is None or benign_release is None or rehearsal or golden_examples or training_scope != "full_encoder"
                or (expected_optimizer != POLICY if not retention_mode else expected_optimizer not in retention.POLICIES)
                or expected_candidate_eligibility != (retention.ELIGIBILITY if retention_mode else ELIGIBILITY)
                or expected_optimizer_config != canonical(CONFIG) or expected_training_scope != "full_encoder"
                or expected_objective != (retention.OBJECTIVES[expected_optimizer] if retention_mode else OBJECTIVE) or config.learning_rate != CONFIG['eta']
                or config.max_gradient != CONFIG['delta_cap'] or expected_diagnostics_policy is not None
                or expected_backtracking_policy is not None):
            raise ValueError("Benign coverage requires exact authenticated FULL Adam and exclusive snapshots/unit-weight source rows.")
        from prompt_generation.benign_coverage import audit_expanded, persist_audit
        sampling_audit = audit_expanded(taxonomy_dataset, benign_release, new_examples, trainer_examples, heldout_examples, config)
        benign_evidence = persist_audit(benign_release, sampling_audit)
    elif rehearsal:
        from privoke_model.full_adam import POLICY, ELIGIBILITY, CONFIG, OBJECTIVE, canonical
        if (taxonomy_dataset is None or rehearsal_manifest is None or golden_examples or training_scope != "full_encoder"
                or expected_optimizer != POLICY or expected_candidate_eligibility != ELIGIBILITY
                or expected_optimizer_config != canonical(CONFIG) or expected_training_scope != "full_encoder"
                or expected_objective != OBJECTIVE or config.learning_rate != CONFIG['eta']
                or config.max_gradient != CONFIG['delta_cap'] or expected_diagnostics_policy is not None
                or expected_backtracking_policy is not None):
            raise ValueError("Rehearsal requires exact authenticated FULL Adam, snapshots and no extra replay/policy mixture.")
        from prompt_generation.anchor_rehearsal import audit_expanded
        sampling_audit = audit_expanded(taxonomy_dataset, rehearsal_manifest, new_examples, trainer_examples, heldout_examples, config)
        from prompt_generation.anchor_rehearsal import persist_audit
        rehearsal_evidence = persist_audit(rehearsal_manifest, sampling_audit)
    elif taxonomy_dataset is not None or any(item.metadata.get("taxonomy_strategy") == "taxonomy_coverage_v1" for item in new_examples):
        if taxonomy_dataset is None or golden_examples:
            raise ValueError("Taxonomy coverage requires its dataset snapshot and no extra replay rows.")
        from prompt_generation.taxonomy_coverage import audit_expanded
        sampling_audit = audit_expanded(taxonomy_dataset, new_examples, trainer_examples, heldout_examples, config)
    runtime_client = runtime_client or _default_runtime_client()
    retention_evidence = None
    if retention_mode:
        from .sensitive_retention_evidence import persist_release
        retention_evidence = persist_release(retention_release, model_id)
    method = (runtime_client.compute_underlying_gradients if training_scope == "full_encoder"
              else runtime_client.compute_semantic_gradients)
    batch = method(
        trainer_examples,
        heldout_examples=heldout_examples,
        model_id=model_id,
        learning_rate=config.learning_rate,
        max_gradient=config.max_gradient,
        request_id=request_id,
        require_full_capability=require_full_capability,
        **({"expected_objective": expected_objective} if expected_objective is not None else {}),
        **({"expected_diagnostics_policy": expected_diagnostics_policy} if expected_diagnostics_policy is not None else {}),
        **({"expected_backtracking_policy": expected_backtracking_policy,
            "expected_backtracking_preparation_sha256": expected_backtracking_preparation_sha256}
           if expected_backtracking_policy is not None else {}),
        **({"expected_optimizer": expected_optimizer, "expected_candidate_eligibility": expected_candidate_eligibility,
            "expected_optimizer_config": expected_optimizer_config, "expected_training_scope": expected_training_scope} if expected_optimizer is not None else {}),
        **({"retention_release": retention_release, "expected_retention_manifest_sha256": expected_retention_manifest_sha256} if retention_mode else {}),
    )
    metrics = dict(batch["metrics"])
    metrics.update(
        {
            "new_examples": float(len(new_examples)),
            "golden_examples": float(len(golden_examples)),
        }
    )
    metadata = dict(batch["metadata"])
    metadata.update(sampling_audit)
    metadata["transformations_per_example"] = str(config.transformations_per_example)
    return BatchTrainingUpdate(
        model_id=batch["model_id"],
        base_version=batch["base_version"],
        gradients=batch["gradients"],
        parameter_shapes=batch["shapes"],
        metrics=metrics,
        metadata=metadata,
        execution_evidence={**batch.get("execution_evidence", {}),
            **({'audience_audit': audience_evidence} if audience_evidence is not None else {}),
            **({'rehearsal_audit': rehearsal_evidence} if rehearsal_evidence is not None else {}),
            **({'benign_audit': benign_evidence} if benign_evidence is not None else {}),
            **({'retention_release': retention_evidence} if retention_evidence is not None else {})},
    )


def _default_runtime_client() -> PrivokeRuntimeClient:
    return PrivokeRuntimeClient(
        env_string("PRIVOKE_RUNTIME_TARGET", "client-runtime:50054"),
        timeout_seconds=env_float("FUZZ_TIMEOUT_SECONDS", 10.0),
    )


def _validate_examples(examples: Sequence[BatchTrainingExample]) -> None:
    if not examples:
        raise ValueError("At least one training example is required.")
    if any(
        not math.isfinite(example.weight) or example.weight <= 0 for example in examples
    ):
        raise ValueError("Training example weights must be finite and positive.")


def iter_training_examples(
    new_examples: Sequence[BatchTrainingExample],
    golden_examples: Sequence[BatchTrainingExample],
    config: BatchTrainingConfig,
) -> Iterable[BatchTrainingExample]:
    rng = random.Random(config.seed)  # nosec B311
    for example in new_examples:
        yield example.with_text_and_weight(
            example.text,
            example.weight * config.new_example_weight,
        )
        for _ in range(max(0, config.transformations_per_example)):
            yield example.with_text_and_weight(
                random_pii_transform(example.text, rng),
                example.weight * config.new_example_weight,
            )
    for example in golden_examples:
        yield example.with_text_and_weight(
            example.text,
            example.weight * config.golden_example_weight,
        )


def _validate_config(config: BatchTrainingConfig) -> None:
    if type(config.transformations_per_example) is not int or not 0 <= config.transformations_per_example <= 1023:
        raise ValueError("transformations_per_example must be an integer between 0 and 1023.")
    if not math.isfinite(config.learning_rate) or config.learning_rate <= 0:
        raise ValueError("learning_rate must be finite and greater than zero.")
    if not math.isfinite(config.max_gradient) or config.max_gradient <= 0:
        raise ValueError("max_gradient must be finite and greater than zero.")
