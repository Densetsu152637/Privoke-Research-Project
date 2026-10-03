"""Central test invocation; component sources and training loops stay in place."""
from pathlib import Path
import subprocess
import sys
ROOT = Path(__file__).resolve().parents[1]
SUITES = {"client-runtime": "extension/client-runtime/test", "supervisor": "extension/runtime-supervisor/test", "fuzzer": "services/privoke-fuzzer/tests", "param-update": "services/param-update-service/tests", "telemetry": "services/telemetry-service/tests", "shared": "shared/python/tests", "evaluator": "evaluation/tests"}
SMOKES = {"stack-smoke": "extension/client-runtime/test/stack_smoke.py", "deployment-smoke": "deploy/gce/tests/smoke.py"}
def main():
    if len(sys.argv) < 2 or sys.argv[1] not in SUITES.keys() | SMOKES.keys():
        raise SystemExit("Select a suite: " + ", ".join([*SUITES, *SMOKES]))
    name, *arguments = sys.argv[1:]
    if name in SMOKES:
        script = ROOT / SMOKES[name]
        command = [sys.executable, str(script), *arguments]
        directory = script.parent.parent
    else:
        suite = ROOT / SUITES[name]
        command = [sys.executable, "-m", "unittest", "discover", "-s", str(suite), "-v", *arguments]
        directory = suite.parent
    return subprocess.run(command, cwd=directory).returncode
if __name__ == "__main__":
    raise SystemExit(main())
