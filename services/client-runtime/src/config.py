from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from enum import Enum

import torch
import multiprocessing

class LLMChoice(Enum):

    Streamed = 0
    Local = 1
    Open = 2

@dataclass
class GlobalConfig:
    """Global configuration"""

    wait_for_regex: bool = True
    llm_choice: LLMChoice = LLMChoice.Streamed
    device: str = "cuda" if torch.cuda.is_available() else "cpu"
    threadpool = ThreadPoolExecutor(max_workers = multiprocessing.cpu_count())





GLOBAL_CONFIG = GlobalConfig()
