
import importlib.util, subprocess, sys
from typing import Dict, List

def require_package(package: str, name: str | None = None):
    name = package if name is None else name
    if importlib.util.find_spec(name) is None:
        print(f"Installing missing package: {package}")
        subprocess.check_call([sys.executable, "-m", "pip", "install", package])

def typeof(obj) -> str:
    return obj.__class__.__name__

def pretty_print_dict(d: Dict) -> str:
    pass