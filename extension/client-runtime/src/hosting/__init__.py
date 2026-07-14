"""Local Server Hosting for the PriVoke client runtime."""

from .models import PromptInspectionRequest, RequestValidationError
from .serialization import parse_prompt_request, serialize_analysis_response
from .server import create_server, run_server

__all__ = [
    "PromptInspectionRequest",
    "RequestValidationError",
    "analyse_prompt_request",
    "create_server",
    "parse_prompt_request",
    "run_server",
    "serialize_analysis_response",
]


def analyse_prompt_request(request: PromptInspectionRequest):
    from .analyzer import analyse_prompt_request as _analyse_prompt_request

    return _analyse_prompt_request(request)
