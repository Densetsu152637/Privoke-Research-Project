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
