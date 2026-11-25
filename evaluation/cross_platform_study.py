"""Cross-platform installed-extension study on the Windows host (XPLAT-20261117).

Runs the unmodified extension build in each installed browser against a local
synthetic HTTPS receiver and the real supervisor/bridge/detector on loopback,
with every hostname other than the synthetic fixture hosts unresolvable inside
the browser. Nothing is sent to a real provider.

    python cross_platform_study.py run  --out results.json [--browsers chrome,edge,firefox]
    python cross_platform_study.py derive results.json
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import platform
import re
import shutil
import socket
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from cross_platform_probes import (  # noqa: E402
    CASES, CATEGORY_DECISION, CATEGORY_FAILURE, CATEGORY_NEGATIVE, CATEGORY_PROVIDER_SHAPE,
    FIXTURE_HOSTS, PROVIDER_HOSTS, REPO_ROOT, coverage_status, ProbeDef, build_catalogue, build_failure_probes, dump_bodies,
    load_shapes, score_probe, sha256_hex, summarise,
)
from cross_platform_receiver import Receiver, generate_certificate  # noqa: E402
import w4_transport as w4  # noqa: E402

SCHEMA = "privoke-cross-platform-v1"
STUDY_ID = "XPLAT-20261117"
DRIVER = REPO_ROOT / "extension" / "test" / "cross-platform-driver.mjs"
SUPERVISOR_MAIN = REPO_ROOT / "extension" / "runtime-supervisor" / "src" / "main.py"
BRIDGE_PORT, CONTROL_PORT, DETECTOR_PORT = 8080, 50056, 50057
# The study's supervisor uses a different private control port; the default one is
# held by a decoy for the whole run so a registered native launcher cannot start a
# second supervisor while the study's runtime is deliberately stopped.
STUDY_CONTROL_PORT = 50066

BROWSERS = {
    "chrome": {"label": "Google Chrome", "family": "chromium", "dist": "dist",
               "exe": [r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                       r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"]},
    "edge": {"label": "Microsoft Edge", "family": "chromium", "dist": "dist",
             "exe": [r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
                     r"C:\Program Files\Microsoft\Edge\Application\msedge.exe"]},
    "firefox": {"label": "Mozilla Firefox", "family": "firefox", "dist": "dist-firefox",
                "exe": [r"C:\Program Files\Mozilla Firefox\firefox.exe",
                        r"C:\Program Files (x86)\Mozilla Firefox\firefox.exe"]},
}


PLAYWRIGHT_FIREFOX = "firefox-playwright"


def port_open(port: int) -> bool:
    with socket.socket() as sock:
        sock.settimeout(0.5)
        return sock.connect_ex(("127.0.0.1", port)) == 0


def wait_for(predicate, timeout: float, interval: float = 0.5) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return False


class Supervisor:
    """The real extension supervisor, started the documented manual way."""

    def __init__(self, python: str, log_path: Path) -> None:
        self.python = python
        self.log_path = log_path
        self.process: subprocess.Popen | None = None
        self.bridge_pid: int | None = None

    def start(self) -> None:
        env = dict(os.environ)
        env.update({
            "PRIVOKE_RUNTIME_PYTHON": self.python,
            # Loopback-only stack: the streamed-model health check targets 127.0.0.1:50051
            # (nothing listens), so no cloud endpoint is contacted. Regex+NER remain active.
            "PRIVOKE_USE_LOCAL_STACK": "true",
            "PRIVOKE_RUNTIME_START_ENABLED": "true",
            "PRIVOKE_CONTROL_GRPC_PORT": str(STUDY_CONTROL_PORT),
        })
        log = self.log_path.open("ab", buffering=0)
        self.process = subprocess.Popen(
            [self.python, str(SUPERVISOR_MAIN)], cwd=str(SUPERVISOR_MAIN.parents[1]), env=env,
            stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW)

    def wait_ready(self, timeout: float = 120.0) -> bool:
        return wait_for(lambda: port_open(BRIDGE_PORT) and port_open(DETECTOR_PORT), timeout)

    def running(self) -> bool:
        return self.process is not None and self.process.poll() is None

    def pids(self) -> set[int]:
        pids = {self.process.pid} if self.process else set()
        detector = listener_pid(DETECTOR_PORT)
        if detector:
            pids.add(detector)
        return pids

    def stop(self, wait: bool = True) -> None:
        if self.process and self.process.poll() is None:
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(self.process.pid)],
                           capture_output=True, check=False)
        self.process = None
        if wait:
            wait_for(lambda: not (port_open(BRIDGE_PORT) or port_open(DETECTOR_PORT)
                                  or port_open(STUDY_CONTROL_PORT)), 20)

    def _suspend_op(self, name: str) -> None:
        # The venv python.exe is a launcher; the bridge lives in the process that owns port 8080.
        if self.bridge_pid is None:
            self.bridge_pid = listener_pid(BRIDGE_PORT)
        if self.bridge_pid is None:
            raise OSError("no process owns the bridge port")
        handle = ctypes.windll.kernel32.OpenProcess(0x0800, False, self.bridge_pid)
        if not handle:
            raise OSError("OpenProcess(PROCESS_SUSPEND_RESUME) failed")
        try:
            status = getattr(ctypes.windll.ntdll, name)(handle)
            if status != 0:
                raise OSError(f"{name} returned {status:#x}")
        finally:
            ctypes.windll.kernel32.CloseHandle(handle)

    def suspend(self) -> None:
        self.bridge_pid = None
        self._suspend_op("NtSuspendProcess")

    def resume(self) -> None:
        self._suspend_op("NtResumeProcess")
        self.bridge_pid = None


class HeldPort:
    """Occupies the control port so a registered native launcher cannot start a second supervisor.

    Binding is retried tightly right after the supervisor is killed: a browser whose
    native host is registered can start its own supervisor within that window.
    """

    def __init__(self, port: int, timeout: float = 10.0) -> None:
        deadline = time.monotonic() + timeout
        while True:
            self.sock = socket.socket()
            try:
                self.sock.bind(("127.0.0.1", port))
                break
            except OSError:
                self.sock.close()
                if time.monotonic() > deadline:
                    holders = subprocess.run(["netstat", "-ano", "-p", "tcp"], capture_output=True, text=True).stdout
                    raise OSError(f"cannot bind {port}: " + " | ".join(
                        line.strip() for line in holders.splitlines() if f":{port} " in line))
                time.sleep(0.005)
        self.sock.listen(8)

    def close(self) -> None:
        self.sock.close()


class Driver:
    def __init__(self, node: str) -> None:
        self.process = subprocess.Popen([node, str(DRIVER)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, text=True, encoding="utf8", cwd=str(REPO_ROOT / "extension"))
        self.next_id = 0
        self.stderr_lines: list[str] = []
        threading.Thread(target=lambda: [self.stderr_lines.append(line) for line in self.process.stderr],
                         daemon=True).start()

    def request(self, op: str, timeout: float = 180.0, **fields: Any) -> dict[str, Any]:
        self.next_id += 1
        payload = json.dumps({"id": self.next_id, "op": op, **fields})
        self.process.stdin.write(payload + "\n")
        self.process.stdin.flush()
        holder: dict[str, Any] = {}

        def read() -> None:
            holder["line"] = self.process.stdout.readline()

        reader = threading.Thread(target=read, daemon=True)
        reader.start()
        reader.join(timeout)
        if reader.is_alive() or not holder.get("line"):
            return {"error": f"driver did not answer {op} within {timeout}s", "stderr": self.stderr_lines[-5:]}
        return json.loads(holder["line"])

    def close(self) -> None:
        try:
            self.request("close", timeout=20)
        except Exception:  # noqa: BLE001
            pass
        if self.process.poll() is None:
            self.process.kill()


def file_version(path: str) -> str:
    result = subprocess.run(
        ["powershell", "-NoProfile", "-Command", f"(Get-Item -LiteralPath '{path}').VersionInfo.ProductVersion"],
        capture_output=True, text=True, check=False)
    return result.stdout.strip()


def git(*args: str) -> str:
    return subprocess.run(["git", *args], cwd=str(REPO_ROOT), capture_output=True, text=True, check=False).stdout.strip()


def tree_hash(directory: Path) -> dict[str, str]:
    return {path.name: sha256_hex(path.read_bytes()) for path in sorted(directory.iterdir())
            if path.is_file() and not path.name.endswith(".map")}


def outbound_connections(pids: set[int]) -> list[str]:
    output = subprocess.run(["netstat", "-ano", "-p", "tcp"], capture_output=True, text=True, check=False).stdout
    external = []
    for line in output.splitlines():
        parts = line.split()
        if len(parts) == 5 and parts[0] == "TCP" and parts[4].isdigit() and int(parts[4]) in pids:
            remote = parts[2].rsplit(":", 1)[0]
            if remote not in {"127.0.0.1", "[::1]", "0.0.0.0", "[::]"}:
                external.append(line.strip())
    return external


def foreign_runtime_processes() -> list[dict[str, Any]]:
    """Supervisor/runtime processes not started by this study (for example by a registered native host)."""
    script = ("Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -match "
              "'python.*extension.(runtime-supervisor|client-runtime).src' } | "
              "Select-Object ProcessId,ParentProcessId,CommandLine | ConvertTo-Json -Compress")
    output = subprocess.run(["powershell", "-NoProfile", "-Command", script], capture_output=True,
                            text=True, check=False).stdout.strip()
    if not output:
        return []
    rows = json.loads(output)
    rows = rows if isinstance(rows, list) else [rows]
    # The study's own command line names the runtime interpreter; never match itself or its driver.
    return [row for row in rows if "cross_platform" not in row["CommandLine"]
            and "cross-platform-driver" not in row["CommandLine"] and "/tmp/t.py" not in row["CommandLine"]
            and "t.py" not in row["CommandLine"]]


def reap_foreign_runtime(own_pid: int | None, kill: bool = False) -> list[dict[str, Any]]:
    """Report (and, only when `kill` is set) stop runtime trees that this study did not start."""
    rows = foreign_runtime_processes()
    ids = {row["ProcessId"] for row in rows}
    found = []
    for row in rows:
        if row["ParentProcessId"] in ids or row["ProcessId"] == own_pid:
            continue
        found.append({"pid": row["ProcessId"], "command": row["CommandLine"][:200], "killed": kill})
        if kill:
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(row["ProcessId"])], capture_output=True, check=False)
    return found


def listener_pid(port: int) -> int | None:
    output = subprocess.run(["netstat", "-ano", "-p", "tcp"], capture_output=True, text=True, check=False).stdout
    for line in output.splitlines():
        parts = line.split()
        if len(parts) == 5 and parts[3] == "LISTENING" and parts[1].endswith(f":{port}"):
            return int(parts[4])
    return None


def unit_harness(node: str) -> dict[str, Any]:
    """Page-interceptor harness run over the synthetic request-shape fixtures."""
    result = subprocess.run([node, "--test", "--test-reporter=tap", "test/provider-shapes.test.js"],
                            cwd=str(REPO_ROOT / "extension"), capture_output=True, text=True, check=False)
    shapes = [shape["id"] for shape in load_shapes()["shapes"]]
    per_shape = {shape: {"passed": 0, "failed": 0} for shape in shapes}
    for line in result.stdout.splitlines():
        match = re.match(r"^(ok|not ok) \d+ - ([a-z0-9-]+):", line)
        if match and match.group(2) in per_shape:
            per_shape[match.group(2)]["passed" if match.group(1) == "ok" else "failed"] += 1
    totals = {key: int(value) for key, value in re.findall(r"^# (tests|pass|fail) (\d+)", result.stdout, re.M)}
    return {"command": "node --test test/provider-shapes.test.js", "exit_code": result.returncode,
            "totals": totals, "per_shape": per_shape}


class Study:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.workdir = Path(args.workdir).resolve()
        self.workdir.mkdir(parents=True, exist_ok=True)
        self.node = shutil.which("node") or "node"
        self.python = args.runtime_python
        self.bodies = dump_bodies(self.node)
        cert, key, self.spki = generate_certificate(self.workdir / "cert", args.openssl)
        self.receiver = Receiver(cert, key, args.receiver_port)
        self.transport = getattr(args, "transport", "bridge")
        if self.transport == "native":
            identities = json.loads((REPO_ROOT / "extension" / "extension-identities.json").read_text(encoding="utf8"))
            self.supervisor = w4.NativeRuntime(Path(args.controller_exe), self.workdir, identities)
            # The browser starts the controller, which inherits the browser's environment.
            os.environ.update({"PRIVOKE_RUNTIME_PYTHON": self.python, "PRIVOKE_USE_LOCAL_STACK": "true",
                               "PRIVOKE_REPOSITORY_ROOT": str(REPO_ROOT)})
        else:
            self.supervisor = Supervisor(self.python, self.workdir / "supervisor.log")
        self.native_launches: list[dict[str, Any]] = []
        self.reap = False
        self.decoy = None

    # --- helpers
    def run_probe(self, driver: Driver, state: dict[str, Any], probe: ProbeDef, stage: str) -> dict[str, Any]:
        if state.get("page") != probe.page_url:
            opened = driver.request("open", url=probe.page_url)
            state["page"] = probe.page_url
            if opened.get("ok") is not True:
                return {"id": probe.id, "stage": stage, "category": probe.category, "passed": False,
                        "failed_checks": ["open_page"], "receiver_count": 0, "error": opened}
        answered = driver.request("run", timeout=probe.timeout_ms / 1000 + 30, spec=probe.to_spec(),
                                  timeoutMs=probe.timeout_ms)
        outcome = answered.get("outcome") or {"harnessError": answered.get("error", "no outcome")}
        time.sleep(0.15)
        captures = self.receiver.captures_for(probe.id)
        record = score_probe(probe, outcome, captures)
        record["stage"] = stage
        record["raw"] = {key: outcome.get(key) for key in
                         ("status", "errorName", "errorMessage", "events", "readyState", "elapsedMs", "messages")}
        return record

    def warm_up(self, driver: Driver, state: dict[str, Any]) -> dict[str, Any]:
        base = next(p for p in self.catalogue if p.shape_id == "chatgpt-conversation"
                    and p.transport == "fetch" and p.expected_action == "ALLOW")
        started = time.monotonic()
        attempts = 0
        while time.monotonic() - started < 150:
            attempts += 1
            probe = ProbeDef(**{**base.__dict__, "id": f"warmup.{attempts}"})
            if state.get("page") != probe.page_url:
                driver.request("open", url=probe.page_url)
                state["page"] = probe.page_url
            answered = driver.request("run", spec=probe.to_spec(), timeoutMs=60_000, timeout=90)
            outcome = answered.get("outcome") or {}
            results = [m for m in outcome.get("messages", []) if m.get("type") == "ANALYZE_RESULT"]
            if results and results[-1].get("action") == "ALLOW":
                return {"ready": True, "attempts": attempts, "seconds": round(time.monotonic() - started, 1)}
            time.sleep(3)
        return {"ready": False, "attempts": attempts, "seconds": round(time.monotonic() - started, 1)}

    def run_group(self, driver: Driver, state: dict[str, Any], probes: list[ProbeDef], stage: str) -> list[dict[str, Any]]:
        probes = sorted(probes, key=lambda p: (p.page_url, p.id))
        return [self.run_probe(driver, state, probe, stage) for probe in probes]

    def page_coverage(self, driver: Driver, state: dict[str, Any]) -> list[dict[str, Any]]:
        """Whether the page hook is active on each provider page, and whether a gap is surfaced."""
        hooked = "!/native code/.test(Function.prototype.toString.call(window.fetch))"
        badge = ("chrome.tabs.query({}).then((tabs) => Promise.all(tabs.filter((t) => t.url === %s)"
                 ".map((t) => chrome.action.getBadgeText({ tabId: t.id })))).then((texts) => texts[0] ?? null)")
        rows = []
        for host in PROVIDER_HOSTS:
            url = f"https://{host}/"
            driver.request("open", url=url)
            state["page"] = url
            time.sleep(3)  # the background retries the content-script ping for about one second
            active = driver.request("eval", expression=hooked).get("value")
            text = driver.request("extension-eval", expression=badge % json.dumps(url)).get("value")
            rows.append({"host": host, "page_hook_active": active, "action_badge": text,
                         "status": coverage_status(active, text)})
        return rows

    def ensure_runtime(self) -> bool:
        if not self.supervisor.running():
            self.supervisor.start()
        return self.supervisor.wait_ready()

    # --- one browser
    def run_browser(self, key: str) -> dict[str, Any]:
        spec = BROWSERS[key]
        exe = next((path for path in spec["exe"] if Path(path).is_file()), None)
        entry: dict[str, Any] = {"browser": spec["label"], "key": key, "family": spec["family"]}
        if exe is None:
            entry.update(status="not_run", reason="browser not installed on this host")
            return entry
        version = file_version(exe)
        entry.update(executable=exe, file_version=version)
        dist = REPO_ROOT / "extension" / spec["dist"]
        if not (dist / "manifest.json").is_file():
            entry.update(status="not_run", reason=f"extension build missing at {dist}")
            return entry
        profile = Path(tempfile.mkdtemp(prefix=f"xplat-{key}-", dir=str(self.workdir)))
        driver = Driver(self.node)
        state: dict[str, Any] = {}
        try:
            self.receiver.captures.clear()
            launched = driver.request(
                "launch", family=spec["family"], exe=exe, userDataDir=str(profile),
                extensionDir=str(dist), hosts=list(FIXTURE_HOSTS), spki=self.spki)
            entry["launch"] = {k: v for k, v in launched.items() if k != "id"}
            if launched.get("ok") is not True:
                entry.update(status="not_run", reason="extension could not be loaded in this browser: "
                                                      + str(launched.get("error")))
                return entry
            entry["browser_version"] = launched.get("product")
            entry["user_agent"] = launched.get("userAgent")
            entry["extension_id"] = launched.get("extensionId")
            if not self.ensure_runtime():
                entry.update(status="not_run", reason="local runtime did not become ready")
                return entry
            entry["warm_up"] = self.warm_up(driver, state)
            if not entry["warm_up"]["ready"]:
                entry.update(status="failed", reason="extension never produced a successful ALLOW decision")
                return entry
            entry["page_coverage"] = self.page_coverage(driver, state)
            records = self.run_group(driver, state, self.catalogue, "steady-state")
            if not self.args.skip_faults:
                records += self.fault_stages(driver, state)
            entry.update(status="run", probes=records, summary=summarise(records))
            entry["unattributed_receiver_posts"] = len(self.receiver.unattributed())
            return entry
        finally:
            driver.close()
            time.sleep(1)
            shutil.rmtree(profile, ignore_errors=True)

    def native_smoke(self, key: str) -> dict[str, Any]:
        """Start no runtime: let the extension's native launcher (if registered for this browser) start one."""
        spec = BROWSERS[key]
        exe = next((path for path in spec["exe"] if Path(path).is_file()), None)
        entry: dict[str, Any] = {"browser": spec["label"], "key": key}
        if exe is None:
            return {**entry, "status": "not_run", "reason": "browser not installed on this host"}
        dist = REPO_ROOT / "extension" / spec["dist"]
        busy = [port for port in (BRIDGE_PORT, CONTROL_PORT, DETECTOR_PORT) if port_open(port)]
        if busy:
            return {**entry, "status": "not_run", "reason": f"ports already in use: {busy}"}
        # The launched supervisor inherits this environment, which keeps it loopback-only.
        os.environ["PRIVOKE_USE_LOCAL_STACK"] = "true"
        profile = Path(tempfile.mkdtemp(prefix=f"xplat-native-{key}-", dir=str(self.workdir)))
        driver = Driver(self.node)
        state: dict[str, Any] = {}
        started = time.monotonic()
        try:
            launched = driver.request("launch", family=spec["family"], exe=exe, userDataDir=str(profile),
                                      extensionDir=str(dist), hosts=list(FIXTURE_HOSTS), spki=self.spki)
            if launched.get("ok") is not True:
                return {**entry, "status": "not_run", "reason": str(launched.get("error"))}
            entry["browser_version"] = launched.get("product")
            base = next(p for p in self.catalogue if p.shape_id == "chatgpt-conversation"
                        and p.transport == "fetch" and p.expected_action == "ALLOW")
            first_bridge = first_allow = None
            attempts = 0
            while time.monotonic() - started < 120:
                attempts += 1
                probe = ProbeDef(**{**base.__dict__, "id": f"native-warmup.{attempts}"})
                if state.get("page") != probe.page_url:
                    driver.request("open", url=probe.page_url)
                    state["page"] = probe.page_url
                answered = driver.request("run", spec=probe.to_spec(), timeoutMs=60_000, timeout=90)
                results = [m for m in (answered.get("outcome") or {}).get("messages", [])
                           if m.get("type") == "ANALYZE_RESULT"]
                if first_bridge is None and port_open(BRIDGE_PORT):
                    first_bridge = round(time.monotonic() - started, 1)
                if results and results[-1].get("action") == "ALLOW":
                    first_allow = round(time.monotonic() - started, 1)
                    break
                time.sleep(2)
            pids = {pid for pid in (listener_pid(BRIDGE_PORT), listener_pid(DETECTOR_PORT)) if pid}
            entry.update(bridge_listener_seen_s=first_bridge, first_allow_decision_s=first_allow,
                         launched_runtime=foreign_runtime_processes() and [
                             {"pid": row["ProcessId"], "command": row["CommandLine"][:200]}
                             for row in foreign_runtime_processes()],
                         non_loopback_connections=outbound_connections(pids))
            if first_allow is not None:
                block = self.run_probe(driver, state, next(
                    p for p in self.catalogue if p.id == "chatgpt-conversation.fetch.block"), "native-launch")
                entry["block_after_native_launch"] = {"passed": block["passed"], "receiver_count": block["receiver_count"]}
            entry["status"] = "run" if first_allow is not None else "no_runtime_started"
            return entry
        finally:
            driver.close()
            time.sleep(1)
            entry["reaped"] = reap_foreign_runtime(None)
            shutil.rmtree(profile, ignore_errors=True)
            os.environ.pop("PRIVOKE_USE_LOCAL_STACK", None)

    def check_orphans(self, wait: float = 20.0) -> dict[str, Any]:
        """What of PriVoke is still running after the browser closed (native transport only)."""
        if self.transport != "native":
            return {"checked": False}
        started = time.monotonic()
        remaining = w4.privoke_processes(self.supervisor.exe)
        while remaining and time.monotonic() - started < wait:
            time.sleep(0.5)
            remaining = w4.privoke_processes(self.supervisor.exe)
        return {"checked": True, "waited_s": round(time.monotonic() - started, 1), "orphans": remaining}

    def latency_run(self, key: str, index: int) -> dict[str, Any]:
        spec = BROWSERS[key]
        exe = next((path for path in spec["exe"] if Path(path).is_file()), None)
        if exe is None:
            return {"status": "not_run", "reason": "browser not installed on this host"}
        dist = REPO_ROOT / "extension" / spec["dist"]
        profile = Path(tempfile.mkdtemp(prefix=f"latency-{key}-", dir=str(self.workdir)))
        driver = Driver(self.node)
        state: dict[str, Any] = {}
        try:
            launched = driver.request("launch", family=spec["family"], exe=exe, userDataDir=str(profile),
                                      extensionDir=str(dist), hosts=list(FIXTURE_HOSTS), spki=self.spki)
            if launched.get("ok") is not True:
                return {"status": "not_run", "reason": str(launched.get("error"))}
            if not self.ensure_runtime():
                return {"status": "not_run", "reason": "local runtime did not become ready"}
            warm = self.warm_up(driver, state)
            if not warm["ready"]:
                return {"status": "failed", "reason": "no successful ALLOW decision", "warm_up": warm}
            base = next(p for p in self.catalogue if p.shape_id == "chatgpt-conversation"
                        and p.transport == "fetch" and p.expected_action == "ALLOW")
            # Untimed settling samples first, so lazy start-up costs are not in the measurement.
            for settle in range(self.args.settle_samples):
                self.run_probe(driver, state, ProbeDef(**{**base.__dict__, "id": f"latency.{index}.settle.{settle}"}), "latency")
            values, failed = [], 0
            for sample in range(self.args.samples):
                record = self.run_probe(driver, state, ProbeDef(**{**base.__dict__, "id": f"latency.{index}.{sample}"}),
                                        "latency")
                elapsed = (record.get("raw") or {}).get("elapsedMs")
                if record["passed"] and isinstance(elapsed, (int, float)):
                    values.append(float(elapsed))
                else:
                    failed += 1
            return {"status": "run", "run": index, "warm_up": warm, "failed_samples": failed,
                    "summary": w4.latency_summary(values), "samples_ms": [round(v, 2) for v in values]}
        finally:
            driver.close()
            time.sleep(1)
            shutil.rmtree(profile, ignore_errors=True)
            # Independent runs: a fresh runtime (and, natively, a fresh controller) each time.
            self.supervisor.stop()
            if self.transport == "native":
                self.supervisor.start()

    def latency(self) -> dict[str, Any]:
        self.catalogue = build_catalogue(self.bodies)
        self.receiver.start()
        retired = (BRIDGE_PORT, CONTROL_PORT, DETECTOR_PORT, STUDY_CONTROL_PORT)
        busy = [port for port in retired if port_open(port)]
        if busy:
            raise SystemExit(f"loopback ports already in use, refusing to touch another runtime: {busy}")
        self.decoy = HeldPort(CONTROL_PORT) if self.transport == "bridge" else None
        key = self.args.browsers[0]
        runs = []
        started = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        try:
            for index in range(self.args.runs):
                runs.append(self.latency_run(key, index))
        finally:
            self.supervisor.stop()
            if self.decoy:
                self.decoy.close()
            self.receiver.stop()
        medians = [run["summary"]["median_ms"] for run in runs if run.get("status") == "run" and run["summary"]["count"]]
        result: dict[str, Any] = {
            "schema": "privoke-latency-v1", "transport": self.transport, "browser": key, "started_utc": started,
            "revision": git("rev-parse", "HEAD"),
            "method": ("End-to-end page latency of one synthetic ALLOW prompt: time from the page's fetch() call "
                       "(intercepted by the extension, analysed by the local runtime with the regex and NER layers, "
                       "then forwarded to the loopback receiver) to the response, measured in the page with "
                       "performance.now(). Each run is a fresh browser profile and a fresh runtime; the run "
                       "median is the median of the timed samples; run-to-run spread is the range of run medians."),
            "settle_samples": self.args.settle_samples, "samples_per_run": self.args.samples,
            "host": {"platform": platform.platform(), "machine": platform.machine()},
            "runs": runs, "run_medians_ms": medians,
            "median_of_run_medians_ms": round(statistics.median(medians), 2) if medians else None,
            "run_spread_ms": [round(min(medians), 2), round(max(medians), 2)] if medians else None,
        }
        if self.args.baseline and medians:
            baseline = json.loads(Path(self.args.baseline).read_text(encoding="utf8"))
            result["against_baseline"] = {"file": str(self.args.baseline), "baseline_transport": baseline["transport"],
                                          **w4.spread_verdict(baseline["run_medians_ms"], medians)}
        return result

    def fault_stages(self, driver: Driver, state: dict[str, Any]) -> list[dict[str, Any]]:
        groups = build_failure_probes(self.bodies)
        records: list[dict[str, Any]] = []
        # Runtime unreachable. Hold 50056 so a registered native launcher cannot revive it.
        self.supervisor.stop()
        self.native_launches += [dict(event, stage="fault-unavailable-start") for event in reap_foreign_runtime(None, self.reap)]
        records += self.run_group(driver, state, groups["unavailable"], "fault-unavailable")
        self.native_launches += [dict(event, stage="fault-unavailable-end") for event in reap_foreign_runtime(None, self.reap)]
        self.ensure_runtime()
        self.warm_up(driver, state)
        records += self.run_group(driver, state, groups["recovered"], "recovered-after-unavailable")
        # Runtime hung: bridge process suspended, so RPCs neither fail nor answer.
        self.supervisor.suspend()
        try:
            records += self.run_group(driver, state, groups["suspended"], "fault-suspended")
        finally:
            self.supervisor.resume()
        self.warm_up(driver, state)
        records += self.run_group(driver, state, groups["resumed"], "recovered-after-suspend")
        return records

    def run(self) -> dict[str, Any]:
        self.catalogue = build_catalogue(self.bodies)
        self.receiver.start()
        busy = [port for port in (BRIDGE_PORT, CONTROL_PORT, DETECTOR_PORT, STUDY_CONTROL_PORT) if port_open(port)]
        if busy:
            raise SystemExit(f"loopback ports already in use, refusing to touch another runtime: {busy}")
        native = self.transport == "native"
        self.decoy = None if native else HeldPort(CONTROL_PORT)
        sampler = w4.ListenSampler(self.supervisor.exe) if native else None
        if sampler:
            sampler.start()
        started = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        results: list[dict[str, Any]] = []
        outbound: list[str] = []
        results_native: list[dict[str, Any]] = []
        try:
            for key in self.args.browsers:
                entry = self.run_browser(key)
                results.append(entry)
                if not native:
                    outbound += outbound_connections(self.supervisor.pids()) if self.supervisor.running() else []
                entry["after_browser_close"] = self.check_orphans()
            self.supervisor.stop()
            if self.decoy:
                self.decoy.close()
                self.decoy = None
            for key in self.args.native_smoke:
                results_native.append(self.native_smoke(key))
        finally:
            self.supervisor.stop()
            if self.decoy:
                self.decoy.close()
            self.receiver.stop()
        listening = sampler.finish() if sampler else None
        if listening:
            outbound += listening["non_loopback_connections_of_controller_tree"]
        harness = unit_harness(self.node)
        return {
            "schema": SCHEMA, "study_id": STUDY_ID, "started_utc": started,
            "revision": git("rev-parse", "HEAD"), "worktree_dirty": bool(git("status", "--porcelain", "--untracked-files=no")),
            "host": {"platform": platform.platform(), "machine": platform.machine(),
                     "node": subprocess.run([self.node, "--version"], capture_output=True, text=True).stdout.strip(),
                     "python_driver": platform.python_version(),
                     "runtime_python": subprocess.run([self.python, "--version"], capture_output=True, text=True).stdout.strip()},
            "extension_build": {"dist": tree_hash(REPO_ROOT / "extension" / "dist"),
                                "dist_firefox": tree_hash(REPO_ROOT / "extension" / "dist-firefox")},
            "receiver": {"hosts": list(FIXTURE_HOSTS), "port": self.args.receiver_port,
                         "foreign_host_requests": list(self.receiver.foreign_hosts),
                         "tls": "self-signed, SPKI pinned in Chromium; acceptInsecureCerts in Firefox"},
            "native_launcher_events": self.native_launches,
            "native_launch_smoke": results_native,
            "runtime": ({"mode": "native messaging: the browser starts the Rust controller and the controller starts "
                                 "its sandboxed Python worker; no PriVoke process is started by the study; the "
                                 "native-host registration is temporary",
                         "transport": "native", "controller": str(self.supervisor.exe), "local_stack": True,
                         "outbound_non_loopback_connections": outbound, "listening_ports": listening}
                        if native else
                        {"mode": "manual supervisor start (documented development path); native messaging not used for probes",
                         "transport": "bridge", "local_stack": True, "outbound_non_loopback_connections": outbound}),
            "cases": CASES,
            "browsers": results,
            "page_hook_harness": harness,
            "blocked": [
                "Live-provider validation (real ChatGPT/Claude/Gemini/Copilot/OpenAI traffic) is blocked pending user approval.",
            ],
        }


def derive(path: Path) -> None:
    data = json.loads(path.read_text(encoding="utf8"))
    print(f"revision {data['revision']}  study {data['study_id']}")
    for browser in data["browsers"]:
        if browser["status"] != "run":
            print(f"{browser['browser']}: {browser['status']} - {browser.get('reason')}")
            continue
        summary = summarise(browser["probes"])
        print(f"{browser['browser']} {browser.get('browser_version')}: {summary['passed']}/{summary['total']} passed")
        for category, bucket in sorted(summary["by_category"].items()):
            print(f"  {category}: {bucket['passed']}/{bucket['total']}")
        for row in browser.get("page_coverage", []):
            if row["status"] != "covered":
                print(f"  coverage {row['host']}: {row['status']}")
        failed = [p["id"] for p in browser["probes"] if not p["passed"]]
        if failed:
            print("  failed:", failed)
    print("page-hook harness:", data["page_hook_harness"]["totals"])
    for shape, counts in data["page_hook_harness"]["per_shape"].items():
        print(f"  {shape}: {counts}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run")
    run.add_argument("--out", required=True)
    run.add_argument("--browsers", default="chrome,edge,firefox")
    run.add_argument("--workdir", default=str(Path(tempfile.gettempdir()) / "privoke-xplat"))
    run.add_argument("--runtime-python", required=True, help="Python with the client-runtime dependencies")
    run.add_argument("--openssl", default="openssl")
    run.add_argument("--receiver-port", type=int, default=443)
    run.add_argument("--native-smoke", default="", help="browsers to try the registered native launcher with")
    run.add_argument("--skip-faults", action="store_true")
    run.add_argument("--baseline", default=None)
    run.add_argument("--transport", choices=("bridge", "native"), default="bridge",
                     help="bridge: the Python supervisor and gRPC-Web bridge on 8080 (oracle); native: the Rust "
                          "controller started by the browser over native messaging (stage W4)")
    run.add_argument("--controller-exe", default=str(REPO_ROOT / "rust" / "target" / "release" / "privoke-supervisor.exe"))
    latency = sub.add_parser("latency", help="run-to-run end-to-end latency of one synthetic ALLOW prompt")
    latency.add_argument("--out", required=True)
    latency.add_argument("--browsers", default="chrome", help="the first browser is measured")
    latency.add_argument("--workdir", default=str(Path(tempfile.gettempdir()) / "privoke-latency"))
    latency.add_argument("--runtime-python", required=True)
    latency.add_argument("--openssl", default="openssl")
    latency.add_argument("--receiver-port", type=int, default=443)
    latency.add_argument("--transport", choices=("bridge", "native"), default="bridge")
    latency.add_argument("--controller-exe", default=str(REPO_ROOT / "rust" / "target" / "release" / "privoke-supervisor.exe"))
    latency.add_argument("--runs", type=int, default=5)
    latency.add_argument("--samples", type=int, default=40)
    latency.add_argument("--settle-samples", type=int, default=5)
    latency.add_argument("--baseline", default=None, help="a baseline file to compare the run medians with")
    latency.add_argument("--playwright-firefox", default=None)
    run.add_argument("--playwright-firefox", default=None,
                     help="path to a Playwright-managed firefox.exe, enabling the 'firefox-playwright' entry")
    derive_parser = sub.add_parser("derive")
    derive_parser.add_argument("results")
    args = parser.parse_args()
    if args.command == "derive":
        derive(Path(args.results))
        return
    args.browsers = [name.strip() for name in args.browsers.split(",") if name.strip()]
    args.native_smoke = [name.strip() for name in getattr(args, "native_smoke", "").split(",") if name.strip()]
    if args.playwright_firefox:
        BROWSERS[PLAYWRIGHT_FIREFOX] = {"label": "Firefox (Playwright-managed build, not the installed browser)",
                                        "family": "firefox", "dist": "dist-firefox",
                                        "exe": [args.playwright_firefox]}
    study = Study(args)
    if args.command == "latency":
        payload = study.latency()
        Path(args.out).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf8")
        print(json.dumps({key: payload[key] for key in ("transport", "run_medians_ms", "median_of_run_medians_ms",
                                                         "run_spread_ms", "against_baseline") if key in payload}, indent=2))
        return
    payload = study.run()
    Path(args.out).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf8")
    derive(Path(args.out))


if __name__ == "__main__":
    main()
