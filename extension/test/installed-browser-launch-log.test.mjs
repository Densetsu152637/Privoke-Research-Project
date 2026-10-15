import assert from "node:assert/strict";
import test from "node:test";
import { mkdtempSync, readFileSync, unlinkSync, rmdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { sanitizeBrowserLaunchLine, installBrowserLaunchLog } from "./installed-browser-launch-log.mjs";
test("launch diagnostics remove command text while retaining stderr and exit observations", () => {
  const launch = sanitizeBrowserLaunchLine("pw:browser <launching> chrome --token=synthetic-secret");
  assert.equal(launch.kind, "launch_command");
  assert.ok(!JSON.stringify(launch).includes("synthetic-secret"));
  assert.match(launch.sha256, /^[0-9a-f]{64}$/);
  assert.match(sanitizeBrowserLaunchLine("pw:browser [pid=61] process did exit: exitCode=1").line, /exitCode=1/);
});

test("fragmented launch commands are redacted before either durable or forwarded output", async () => {
  const directory = mkdtempSync(join(tmpdir(), "privoke-launch-log-"));
  const path = join(directory, "launch.jsonl");
  const forwarded = [];
  const stream = { write(chunk) { forwarded.push(String(chunk)); return true; } };
  const original = stream.write;
  try {
    const restore = installBrowserLaunchLog(path, stream);
    stream.write("pw:browser <launching> chrome --token=synthetic-");
    stream.write("secret\n");
    stream.write("pw:browser process did exit: exitCode=1\n");
    restore();
    assert.equal(stream.write, original);
    assert.ok(!readFileSync(path, "utf8").includes("synthetic-secret"));
    assert.ok(!forwarded.join("").includes("synthetic-secret"));
    assert.match(readFileSync(path, "utf8"), /exitCode=1/);
  } finally { unlinkSync(path); rmdirSync(directory); }
});
