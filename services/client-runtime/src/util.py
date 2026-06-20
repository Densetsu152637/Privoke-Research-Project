import json
from typing import Dict, List

def typeof(obj) -> str:
    return obj.__class__.__name__

def pretty_print_dict(d: Dict) -> str:
    return json.dumps(d, indent=2)
