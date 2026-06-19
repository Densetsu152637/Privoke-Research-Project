from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict


@dataclass(frozen=True)
class PromptSeed:
    template: str
    classification: Any
    metadata: Dict[str, str] = field(default_factory=dict)

    @property
    def packed_classification(self) -> int:
        return int(self.classification.pack())
