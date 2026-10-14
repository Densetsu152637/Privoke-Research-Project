import { appendFileSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";

export function sanitizeBrowserLaunchLine(line) {
  const clean = line.replace(/\u001b\[[0-9;]*m/g, "");
  const sha256 = createHash("sha256").update(clean).digest("hex");
  if (clean.includes("<launching>")) return { kind: "launch_command", sha256, line: "<launching> command retained as SHA256 only" };
  return { kind: "browser_stderr", sha256, line: clean.slice(0, 8192), truncated: clean.length > 8192 };
}

export function installBrowserLaunchLog(path, stream = process.stderr) {
  writeFileSync(path, "", { flag: "wx" });
  const original = stream.write;
  let pending = "";
  const emit = (line) => {
    const record = sanitizeBrowserLaunchLine(line);
    appendFileSync(path, `${JSON.stringify({ at: new Date().toISOString(), ...record })}\n`);
    original.call(stream, `${record.line}\n`);
  };
  stream.write = function (chunk, encoding, callback) {
    pending += Buffer.isBuffer(chunk) ? chunk.toString(typeof encoding === "string" ? encoding : "utf8") : String(chunk);
    if (pending.length > 512 * 1024) throw new Error("browser stderr buffering exceeded its bound");
    let end;
    while ((end = pending.indexOf("\n")) >= 0) { emit(pending.slice(0, end)); pending = pending.slice(end + 1); }
    const done = typeof encoding === "function" ? encoding : callback;
    if (typeof done === "function") queueMicrotask(done);
    return true;
  };
  return () => { if (pending) { emit(pending); pending = ""; } stream.write = original; };
}
