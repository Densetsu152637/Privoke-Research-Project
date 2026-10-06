"""Generate local gRPC clients after installing the host requirements."""
from __future__ import annotations

import subprocess
import sys

from host_environment import GENERATED, ROOT


def main() -> int:
    proto_root = ROOT / "shared/proto"
    destinations = (GENERATED, ROOT / "extension/runtime-supervisor/generated",
                    ROOT / "services/privoke-fuzzer/generated",
                    ROOT / "services/param-update-service/generated",
                    ROOT / "services/telemetry-service/generated")
    for destination in destinations:
        destination.mkdir(parents=True, exist_ok=True)
        command = [sys.executable, "-m", "grpc_tools.protoc", "-I", str(proto_root),
                   f"--python_out={destination}", f"--grpc_python_out={destination}"]
        command.extend(str(proto_root / "privoke/v1" / name)
                       for name in ("parameters.proto", "runtime.proto", "telemetry.proto"))
        result = subprocess.run(command, cwd=ROOT)
        if result.returncode:
            return result.returncode
    print("Generated localhost gRPC clients for runtime, supervisor and Python services.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
