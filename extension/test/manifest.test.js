import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { manifestForTarget } from "../scripts/manifest-target.mjs";

const manifest = JSON.parse(await readFile(new URL("../manifest.json", import.meta.url)));
const identities = JSON.parse(
  await readFile(new URL("../extension-identities.json", import.meta.url)),
);

test("uses a Chromium-compatible Manifest V3 background declaration", () => {
  assert.equal(manifest.manifest_version, 3);
  assert.equal(manifest.background.service_worker, "background.js");
  assert.equal(manifest.background.scripts, undefined);
});

test("generates a Firefox-compatible Manifest V3 background declaration", () => {
  const firefoxManifest = manifestForTarget(manifest, "firefox");

  assert.deepEqual(firefoxManifest.background.scripts, ["background.js"]);
  assert.equal(firefoxManifest.background.service_worker, undefined);
  assert.equal(firefoxManifest.key, undefined);
});

test("pins stable Chromium-family and Firefox identities", () => {
  assert.equal(manifest.key, identities.chromium_public_key);
  assert.equal(
    manifest.browser_specific_settings.gecko.id,
    identities.firefox_extension_id,
  );
  assert.match(identities.chromium_extension_id, /^[a-p]{32}$/);
  const digest = createHash("sha256")
    .update(Buffer.from(identities.chromium_public_key, "base64"))
    .digest()
    .subarray(0, 16);
  const computedId = [...digest]
    .map((byte) => "abcdefghijklmnop"[byte >> 4] + "abcdefghijklmnop"[byte & 15])
    .join("");
  assert.equal(computedId, identities.chromium_extension_id);
});

test("declares only WebExtensions permissions", () => {
  assert.deepEqual(manifest.permissions.sort(), ["nativeMessaging", "storage"]);
});
