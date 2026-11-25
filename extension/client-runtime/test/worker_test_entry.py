"""Worker entry used only by tests: applies one named patch, then runs the real worker main.

Keeps test-only behaviour (a stray ``print``, a refusing socket layer, a slow handler) out
of the production worker.
"""
import os
import sys
import time

from src import worker_main

patch = os.environ.get("PRIVOKE_WORKER_TEST_PATCH", "")

if patch == "stray-output":
    original = worker_main.Dispatcher.handle

    def noisy(self, request):
        print("STRAY PRINT inside the worker")
        sys.stdout.write("stray partial line without newline")
        os.write(1, b"\x00\x00\x00\x05raw C-level write to fd 1\n")
        return original(self, request)

    worker_main.Dispatcher.handle = noisy
    redirect = worker_main._redirect_standard_streams

    def redirect_then_print():
        redirect()
        print("STRAY PRINT during startup")
        os.write(1, b"raw startup write to fd 1\n")

    worker_main._redirect_standard_streams = redirect_then_print
elif patch == "sockets-refused":
    def refuse(family, kind):
        raise PermissionError("socket creation refused by the sandbox layer")

    worker_main._open_socket = refuse
elif patch == "slow-handler":
    from src.hosting.grpc_server import PrivokeRuntimeService
    original_health = PrivokeRuntimeService.Health

    def slow_health(self, request, context):
        time.sleep(float(os.environ.get("PRIVOKE_WORKER_TEST_DELAY", "1.5")))
        return original_health(self, request, context)

    PrivokeRuntimeService.Health = slow_health
elif patch == "crashing-handler":
    def crash(self, request):
        raise MemoryError("simulated handler fault")

    worker_main.Dispatcher.handle = crash

raise SystemExit(worker_main.main())
