from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict

from ..classification import Visibility


@dataclass(frozen=True)
class PromptInspectionRequest:
    text: str
    source: str | None = None
    visibility_hint: Visibility | None = None
    target_app: str | None = None
    request_id: str | None = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class RequestValidationError(ValueError):
    def __init__(self, message: str, status_code: int = 400):
        super().__init__(message)
        self.status_code = status_code
