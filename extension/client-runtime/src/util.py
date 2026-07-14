import json
from typing import Dict

def pretty_print_dict(d: Dict) -> str:
    return json.dumps(d, indent=2)
