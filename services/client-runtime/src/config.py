from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from enum import Enum

import multiprocessing


def _default_device() -> str:
    try:
        import torch
    except ModuleNotFoundError:
        return "cpu"

    return "cuda" if torch.cuda.is_available() else "cpu"

class LLMChoice(Enum):

    Streamed = 0
    Local = 1
    Open = 2

@dataclass
class GlobalConfig:
    """Global configuration"""

    wait_for_regex: bool = True
    llm_choice: LLMChoice = LLMChoice.Streamed
    device: str = _default_device()
    threadpool = ThreadPoolExecutor(max_workers = multiprocessing.cpu_count())





GLOBAL_CONFIG = GlobalConfig()
