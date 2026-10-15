"""Run fuzzer health, prompt probes or a training cycle from the host."""
from __future__ import annotations

import argparse
import os
import subprocess
import sys

from host_environment import FUZZER_TARGET, ROOT, RUNTIME_TARGET, configure_imports, python_environment


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("health", "test-prompts", "train"))
    parser.add_argument("--target", default=os.getenv("FUZZER_TARGET", FUZZER_TARGET),
                        help="Fuzzer gRPC target (health and training).")
    parser.add_argument("--runtime-target", default=os.getenv("PRIVOKE_RUNTIME_TARGET", RUNTIME_TARGET))
    args, extra = parser.parse_known_args(argv)
    if args.command == "health":
        if extra:
            parser.error("health does not accept extra arguments")
        configure_imports()
        import grpc
        from privoke.v1 import parameters_pb2, parameters_pb2_grpc

        try:
            with grpc.insecure_channel(args.target) as channel:
                response = parameters_pb2_grpc.FuzzerServiceStub(channel).Health(
                    parameters_pb2.HealthRequest(), timeout=5)
        except grpc.RpcError as exc:
            print(f"Fuzzer RPC to {args.target} failed ({exc.code().name}): {exc.details()}", file=sys.stderr)
            return 1
        if response.service != "privoke-fuzzer" or response.status != "SERVING":
            print(f"Unexpected fuzzer health response: {response.service} {response.status}", file=sys.stderr)
            return 1
        print(f"Fuzzer at {args.target} is SERVING.")
        return 0

    source = ROOT / "services/privoke-fuzzer/src"
    command = [sys.executable, str(source / "cli.py"), args.command]
    environment = python_environment(source)
    if args.command == "train":
        command.extend(["--target", args.target, "--model-id", environment["MODEL_ID"]])
    else:
        command.extend(["--runtime-target", args.runtime_target])
        environment.setdefault("PRIVOKE_FUZZER_DUMP_DIR", str(ROOT / "dumps/privoke-fuzzer"))
    command.extend(extra)
    return subprocess.run(command, cwd=ROOT, env=environment).returncode


if __name__ == "__main__":
    raise SystemExit(main())
