import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const testFile = fileURLToPath(new URL("../extension/test/installed-browser-evidence.test.mjs", import.meta.url));
const result = spawnSync(process.execPath, ["--test", testFile], {
  stdio: "inherit",
  env: process.env,
});
if (result.error) throw result.error;
if (result.signal) throw new Error(`installed browser evidence tests terminated by ${result.signal}`);
if (result.status !== 0) process.exitCode = result.status ?? 1;
if (process.exitCode) process.exit(process.exitCode);

const pythonTest = fileURLToPath(new URL("../extension/test/installed-browser-resources.test.py", import.meta.url));
const python = process.env.PRIVOKE_HOST_PYTHON;
if (!python) throw new Error("Set PRIVOKE_HOST_PYTHON to a compatible host Python executable.");
if (process.env.PRIVOKE_INSTALLED_EVIDENCE_IN_CONTAINER === "true") {
  throw new Error("Python unit tests must run on the host, outside the browser infrastructure image.");
}
const pythonResult = spawnSync(python, [pythonTest], { stdio: "inherit", env: process.env });
if (pythonResult.error) throw pythonResult.error;
if (pythonResult.signal) throw new Error(`installed browser resource tests terminated by ${pythonResult.signal}`);
if (pythonResult.status !== 0) process.exitCode = pythonResult.status ?? 1;
