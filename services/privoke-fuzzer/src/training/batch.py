from __future__ import annotations

import hashlib
import json
import random
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Sequence, Tuple

from client_runtime_imports import import_client_module


JsonMapping = Mapping[str, Any]
ParameterDict = Dict[str, Tuple[float, ...]]


@dataclass(frozen=True)
class BatchTrainingConfig:
    learning_rate: float = 0.03
    max_gradient: float = 0.05
    new_example_weight: float = 1.0
    golden_example_weight: float = 0.35
    transformations_per_example: int = 1
    seed: int = 42


@dataclass(frozen=True)
class BatchTrainingExample:
    text: str
    sensitivity: str | None = None
    visibility: str | None = None
    categories: Tuple[str, ...] = ()
    weight: float = 1.0
    metadata: Dict[str, str] = field(default_factory=dict)

    @property
    def has_explicit_target(self) -> bool:
        return bool(self.sensitivity or self.visibility or self.categories)

    def with_text_and_weight(self, text: str, weight: float) -> "BatchTrainingExample":
        return BatchTrainingExample(
            text=text,
            sensitivity=self.sensitivity,
            visibility=self.visibility,
            categories=self.categories,
            weight=weight,
            metadata=dict(self.metadata),
        )


@dataclass(frozen=True)
class BatchTrainingUpdate:
    model_id: str
    base_version: str
    gradients: ParameterDict
    updated_parameters: ParameterDict
    metrics: Dict[str, float]
    metadata: Dict[str, str]

    @property
    def updated_fingerprint(self) -> str:
        return parameter_fingerprint(self.updated_parameters)


def load_training_examples(path: str | Path) -> List[BatchTrainingExample]:
    batch_path = Path(path)
    if not batch_path.exists():
        raise FileNotFoundError(f"Training batch does not exist: {batch_path}")

    if batch_path.suffix.lower() == ".jsonl":
        items = [
            json.loads(line)
            for line in batch_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
    else:
        payload = json.loads(batch_path.read_text(encoding="utf-8"))
        if isinstance(payload, dict):
            items = (
                payload.get("examples")
                or payload.get("samples")
                or payload.get("data")
                or []
            )
        else:
            items = payload

    if not isinstance(items, list):
        raise ValueError("Training batch must be a list or contain examples/samples/data.")

    return [training_example_from_mapping(item) for item in items]


def training_example_from_mapping(item: JsonMapping) -> BatchTrainingExample:
    if not isinstance(item, Mapping):
        raise ValueError("Each training example must be a JSON object.")

    text = item.get("text") or item.get("prompt") or item.get("input")
    if not isinstance(text, str) or not text:
        raise ValueError("Each training example needs a non-empty text/prompt/input field.")

    classification = _classification_payload(item)
    sensitivity = _first_text(
        item.get("sensitivity"),
        item.get("expected_sensitivity"),
        classification.get("sensitivity"),
    )
    visibility = _first_text(
        item.get("visibility"),
        item.get("expected_visibility"),
        classification.get("visibility"),
    )

    return BatchTrainingExample(
        text=text,
        sensitivity=sensitivity,
        visibility=visibility,
        categories=_category_names(
            item.get("categories")
            or item.get("expected_categories")
            or classification.get("categories")
        ),
        weight=float(item.get("weight", 1.0)),
        metadata=_string_metadata(item.get("metadata", {})),
    )


def train_parameter_batch_from_files(
    snapshot: Any,
    batch_path: str | Path,
    golden_batch_path: str | Path | None = None,
    config: BatchTrainingConfig | None = None,
) -> BatchTrainingUpdate:
    golden_examples = (
        load_training_examples(golden_batch_path)
        if golden_batch_path is not None
        else []
    )
    return train_parameter_batch(
        snapshot=snapshot,
        new_examples=load_training_examples(batch_path),
        golden_examples=golden_examples,
        config=config,
    )


def train_parameter_batch(
    snapshot: Any,
    new_examples: Sequence[BatchTrainingExample],
    golden_examples: Sequence[BatchTrainingExample] = (),
    config: BatchTrainingConfig | None = None,
) -> BatchTrainingUpdate:
    config = config or BatchTrainingConfig()
    if config.learning_rate <= 0:
        raise ValueError("learning_rate must be greater than zero.")
    if config.max_gradient <= 0:
        raise ValueError("max_gradient must be greater than zero.")

    client_snapshot = _snapshot_with_trainable_parameters(snapshot)
    parameters = dict(client_snapshot.parameters)
    trainer_examples = list(_iter_training_examples(new_examples, golden_examples, config))
    if not trainer_examples:
        raise ValueError("At least one training example is required.")

    streamed_model = import_client_module("LLM.privoke.streamed_model")
    model = streamed_model.ParameterBackedPrivacyModel(client_snapshot)

    gradients = {name: [0.0 for _ in values] for name, values in parameters.items()}
    total_weight = 0.0
    total_loss = 0.0
    exact_matches = 0

    for example in trainer_examples:
        target = target_classification_for_example(example)
        predicted = _predict_classification(model, example.text)
        loss = _classification_loss(target, predicted)
        if target.pack() == predicted.pack():
            exact_matches += 1

        _accumulate_gradient(
            gradients=gradients,
            parameters=parameters,
            text=example.text,
            target=target,
            predicted=predicted,
            weight=example.weight,
        )
        total_loss += loss * example.weight
        total_weight += example.weight

    gradient_parameters = {
        name: tuple(
            _clamp(
                (value / total_weight) * config.learning_rate,
                -config.max_gradient,
                config.max_gradient,
            )
            for value in values
        )
        for name, values in gradients.items()
    }
    updated_parameters = add_parameter_delta(parameters, gradient_parameters)

    metrics = {
        "examples": float(len(trainer_examples)),
        "new_examples": float(len(new_examples)),
        "golden_examples": float(len(golden_examples)),
        "average_loss": total_loss / total_weight,
        "exact_match_rate": exact_matches / len(trainer_examples),
        "total_weight": total_weight,
    }
    metadata = {
        "strategy": "client_semantic_batch_training",
        "base_parameter_fingerprint": parameter_fingerprint(parameters),
        "updated_parameter_fingerprint": parameter_fingerprint(updated_parameters),
        "learning_rate": str(config.learning_rate),
        "max_gradient": str(config.max_gradient),
        "transformations_per_example": str(config.transformations_per_example),
    }

    return BatchTrainingUpdate(
        model_id=client_snapshot.model_id,
        base_version=client_snapshot.version,
        gradients=gradient_parameters,
        updated_parameters=updated_parameters,
        metrics=metrics,
        metadata=metadata,
    )


def target_classification_for_example(example: BatchTrainingExample):
    if example.has_explicit_target:
        return _explicit_target_classification(example)
    return _semantic_target_classification(example.text)


def random_pii_transform(text: str, rng: random.Random | None = None) -> str:
    rng = rng or random.Random()
    transforms = (
        lambda value: value,
        lambda value: f"Please review this prompt: {value}",
        _redact_common_name,
        _synthetic_common_name,
        _redact_email,
        _synthetic_phone,
    )
    return rng.choice(transforms)(text)


def add_parameter_delta(
    parameters: ParameterDict,
    delta: ParameterDict,
) -> ParameterDict:
    updated = {}
    for name, values in parameters.items():
        update_values = delta.get(name, tuple(0.0 for _ in values))
        if len(update_values) != len(values):
            raise ValueError(f"Parameter shape mismatch for {name}.")
        updated[name] = tuple(
            float(value) + float(update_values[index])
            for index, value in enumerate(values)
        )
    return updated


def diff_parameters(
    base_parameters: ParameterDict,
    updated_parameters: ParameterDict,
) -> ParameterDict:
    delta = {}
    for name, values in updated_parameters.items():
        base_values = base_parameters.get(name, ())
        if len(base_values) != len(values):
            raise ValueError(f"Parameter shape mismatch for {name}.")
        delta[name] = tuple(
            float(value) - float(base_values[index])
            for index, value in enumerate(values)
        )
    return delta


def parameter_fingerprint(parameters: ParameterDict) -> str:
    digest = hashlib.sha256()
    for name in sorted(parameters):
        digest.update(name.encode("utf-8"))
        for value in parameters[name]:
            digest.update(repr(float(value)).encode("utf-8"))
    return digest.hexdigest()[:16]


def _iter_training_examples(
    new_examples: Sequence[BatchTrainingExample],
    golden_examples: Sequence[BatchTrainingExample],
    config: BatchTrainingConfig,
) -> Iterable[BatchTrainingExample]:
    rng = random.Random(config.seed)

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


def _snapshot_with_trainable_parameters(snapshot: Any):
    parameter_stream = import_client_module("LLM.privoke.parameter_stream")
    client_snapshot = _to_client_snapshot(snapshot)
    if client_snapshot.parameters:
        return client_snapshot

    classification = import_client_module("classification")
    fallback_parameters = {
        "classifier.bias": (0.0,),
        "semantic.category_weights": tuple(0.0 for _ in classification.Category),
    }
    return parameter_stream.ParameterSnapshot(
        model_id=client_snapshot.model_id,
        version=client_snapshot.version,
        generated_at_unix=client_snapshot.generated_at_unix,
        parameters=fallback_parameters,
        metadata=dict(client_snapshot.metadata),
    )


def _to_client_snapshot(snapshot: Any):
    parameter_stream = import_client_module("LLM.privoke.parameter_stream")
    raw_parameters = getattr(snapshot, "parameters", {})

    if isinstance(raw_parameters, Mapping):
        parameters = {
            str(name): tuple(float(value) for value in values)
            for name, values in raw_parameters.items()
        }
    else:
        parameters = {
            parameter.name: tuple(float(value) for value in parameter.values)
            for parameter in raw_parameters
        }

    return parameter_stream.ParameterSnapshot(
        model_id=str(getattr(snapshot, "model_id", "privoke-baseline")),
        version=str(getattr(snapshot, "version", "unknown")),
        generated_at_unix=int(getattr(snapshot, "generated_at_unix", 0)),
        parameters=parameters,
        metadata=dict(getattr(snapshot, "metadata", {})),
    )


def _predict_classification(model: Any, text: str):
    classification = import_client_module("classification")
    results = model.classify(text)
    if not results:
        return classification.initialise_unpacked(
            classification.Sensitivity.S0,
            classification.Visibility.PU,
            [],
        )
    return classification.merge_classifications(
        result.classification for result in results
    )


def _explicit_target_classification(example: BatchTrainingExample):
    classification = import_client_module("classification")
    sensitivity = _enum_by_name(
        classification.Sensitivity,
        example.sensitivity,
        classification.Sensitivity.S0,
    )
    visibility = _enum_by_name(
        classification.Visibility,
        example.visibility,
        classification.Visibility.PU,
    )
    categories = [
        _enum_by_name(classification.Category, category, None)
        for category in example.categories
    ]
    return classification.initialise_unpacked(
        sensitivity,
        visibility,
        [category for category in categories if category is not None],
    )


def _semantic_target_classification(text: str):
    classification = import_client_module("classification")
    semantic_features = import_client_module("LLM.privoke.semantic_features")
    signals = semantic_features.extract_semantic_signals(text)

    categories = _dedupe_categories(
        signal.category for signal in signals if signal.category is not None
    )
    sensitivity = semantic_features.strongest_sensitivity(signals)
    visibility = semantic_features.strongest_visibility(signals)

    if not categories and visibility == classification.Visibility.PU:
        sensitivity = classification.Sensitivity.S0

    return classification.initialise_unpacked(sensitivity, visibility, categories)


def _classification_loss(target: Any, predicted: Any) -> float:
    classification = import_client_module("classification")
    semantic_features = import_client_module("LLM.privoke.semantic_features")
    target_categories = set(target.categories())
    predicted_categories = set(predicted.categories())

    sensitivity_loss = (
        abs(target.sensitivity().value - predicted.sensitivity().value) / 3.0
    )
    visibility_loss = (
        abs(
            semantic_features.visibility_rank(target.visibility())
            - semantic_features.visibility_rank(predicted.visibility())
        )
        / semantic_features.visibility_rank(classification.Visibility.P4)
    )
    category_loss = len(target_categories ^ predicted_categories) / max(
        1,
        len(list(classification.Category)),
    )
    return sensitivity_loss + 0.5 * visibility_loss + 0.25 * category_loss


def _accumulate_gradient(
    gradients: Dict[str, List[float]],
    parameters: ParameterDict,
    text: str,
    target: Any,
    predicted: Any,
    weight: float,
) -> None:
    classification = import_client_module("classification")
    semantic_features = import_client_module("LLM.privoke.semantic_features")
    categories = list(classification.Category)
    text_categories = {
        signal.category
        for signal in semantic_features.extract_semantic_signals(text)
        if signal.category is not None
    }
    target_categories = set(target.categories())
    predicted_categories = set(predicted.categories())
    missed_categories = target_categories - predicted_categories
    extra_categories = predicted_categories - target_categories

    sensitivity_delta = (
        target.sensitivity().value - predicted.sensitivity().value
    ) / 3.0
    visibility_delta = (
        semantic_features.visibility_rank(target.visibility())
        - semantic_features.visibility_rank(predicted.visibility())
    ) / semantic_features.visibility_rank(classification.Visibility.P4)

    for name, values in parameters.items():
        lower_name = name.lower()
        for index, _ in enumerate(values):
            if "bias" in lower_name or len(values) == 1:
                update_signal = sensitivity_delta * 0.8 + visibility_delta * 0.2
            else:
                category = categories[index % len(categories)]
                update_signal = sensitivity_delta * 0.20 + visibility_delta * 0.05
                if category in missed_categories:
                    update_signal += 1.0
                if category in extra_categories:
                    update_signal -= 0.7
                if category in target_categories:
                    update_signal += sensitivity_delta * 0.25
                if category in text_categories:
                    update_signal += sensitivity_delta * 0.15

            gradients[name][index] += update_signal * weight


def _classification_payload(item: JsonMapping) -> JsonMapping:
    for key in ("classification", "expected_classification", "target"):
        payload = item.get(key)
        if isinstance(payload, Mapping):
            return payload
    return {}


def _category_names(raw_categories: Any) -> Tuple[str, ...]:
    if raw_categories is None:
        return ()
    if isinstance(raw_categories, str):
        raw_values = re.split(r"[,|\s]+", raw_categories)
    elif isinstance(raw_categories, Sequence):
        raw_values = raw_categories
    else:
        return ()

    return tuple(
        str(value).strip().upper()
        for value in raw_values
        if str(value).strip()
    )


def _string_metadata(raw_metadata: Any) -> Dict[str, str]:
    if not isinstance(raw_metadata, Mapping):
        return {}
    return {str(key): str(value) for key, value in raw_metadata.items()}


def _first_text(*values: Any) -> str | None:
    for value in values:
        if isinstance(value, str) and value.strip():
            return value.strip().upper()
    return None


def _enum_by_name(enum_type: Any, value: Any, default: Any):
    if value is None:
        return default
    if isinstance(value, enum_type):
        return value

    key = str(value).strip().upper()
    return enum_type.__members__.get(key, default)


def _dedupe_categories(categories: Iterable[Any]) -> List[Any]:
    classification = import_client_module("classification")
    category_set = set(categories)
    return [category for category in classification.Category if category in category_set]


def _redact_common_name(text: str) -> str:
    return re.sub(r"\bJohn Doe\b", "[REDACTED_NAME]", text, flags=re.IGNORECASE)


def _synthetic_common_name(text: str) -> str:
    return re.sub(r"\bJohn Doe\b", "Alex Smith", text, flags=re.IGNORECASE)


def _redact_email(text: str) -> str:
    return re.sub(
        r"\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b",
        "[REDACTED_EMAIL]",
        text,
    )


def _synthetic_phone(text: str) -> str:
    return re.sub(
        r"\b(?:\+?\d[\d .()-]{7,}\d)\b",
        "0400 000 000",
        text,
    )


def _clamp(value: float, lower: float, upper: float) -> float:
    return max(lower, min(upper, value))
