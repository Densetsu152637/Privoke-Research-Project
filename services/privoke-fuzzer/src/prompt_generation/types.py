from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict

from privoke_client_runtime.classification import Classification


@dataclass(frozen=True)
class PromptSeed:
    template: str
    classification: Classification
    metadata: Dict[str, str] = field(default_factory=dict)

    @property
    def packed_classification(self) -> int:
        return int(self.classification.pack())
