from __future__ import annotations

from dataclasses import dataclass, field

from privoke_contracts.classification import Classification


@dataclass(frozen=True)
class PromptSeed:
    template: str
    classification: Classification
    metadata: dict[str, str] = field(default_factory=dict)

    @property
    def packed_classification(self) -> int:
        return int(self.classification.pack())
