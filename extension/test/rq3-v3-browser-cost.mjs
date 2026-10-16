// Exact selected AU3 packages through the maintained installed product path.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { RQ3_MODEL_IDENTITY, RQ3_MODES, startRq3Model } from "./rq3-browser-cost.mjs";

const ARCHITECTURE = "privoke_pretrained_bert_v3";
const VOCAB = "07eced375cec144d27c900241f3e339478dec958f92fddbc551f295c992038a3";
const pin = (model_id, manifest, blob, backbone) => Object.freeze({ model_id,
  model_version: manifest, artifact_checksum: manifest, parameter_fingerprint: blob,
  architecture: ARCHITECTURE, backbone_sha256: backbone, tokenizer_sha256: VOCAB,
  compute_device: "cpu", torch_threads: "4" });
export const V3_IDENTITIES = Object.freeze({
  "privoke-v3-efficient": pin("privoke-v3-efficient",
    "1f45a21bd7bd0c931dad215f823008193e7af7359bc68527c1f5dd4e7fbbeffd",
    "dc623640400b268a2a490c214dad872de49d047c01b4d5cd1e361f70741d93c2",
    "2e37a60f99c30c244da3a2ada3653faf378689783c5b6500d7291acc2516e199"),
  "privoke-v3-balanced": pin("privoke-v3-balanced",
    "99b36171056bb0398584a0b0556d9d7ff2640d0acac4b124a126327451a80589",
    "e48e7c1aa46310b3b7b1f6422f7aa8902c70cf6ff861f7540a7c4be151de4df2",
    "67b710645b099510dba08b7605a60859fff59714628e1d9d1ffa9e0956b51783"),
  "privoke-v3-quality": pin("privoke-v3-quality",
    "bb17d355fe1ad13c7052e922fb6de607d82cdafb1f4440fee1a47f35d42caf39",
    "f9d64c3436b44488c8d94233355a12afb1da56c719b3e000e6580ab9e578c26d",
    "1be1c8c6a57894a139fdf526fb8435f6acb6ea01600569a4ac3cfd405dc5f875"),
});
export const V3_BALANCED = V3_IDENTITIES["privoke-v3-balanced"];
const semantic = { layers: { regex: false, ner: false, llm: true },
  expected: ["DETECTION_LAYER_SEMANTIC"], verification: true };
export const V3_VERIFICATION_PROFILES = Object.freeze([
  ...Object.entries(V3_IDENTITIES).map(([id, identity]) => ({ ...semantic,
    id: `verify-${id}`, modelQuality: id.replace("privoke-", ""), modelIdentity: identity, semanticModelId: id })),
  { ...semantic, id: "verify-older-v1-balanced", modelQuality: "legacy-balanced",
    modelIdentity: { ...RQ3_MODEL_IDENTITY, architecture: "privoke_tiny_transformer_v1" }, semanticModelId: "privoke-balanced" },
  { ...semantic, id: "verify-return-to-default", modelQuality: "latest", modelIdentity: V3_BALANCED, semanticModelId: "" },
]);

export function v3SessionOptions(index) {
  assert.ok(Number.isInteger(index) && index >= 0 && index < 4);
  return { modelQuality: "latest", modelIdentity: V3_BALANCED, semanticModelId: "",
    verificationProfiles: index === 3 ? V3_VERIFICATION_PROFILES : [] };
}

const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
export async function verifyV3ReleaseStore(directory) {
  const packages = [];
  for (const [id, identity] of Object.entries(V3_IDENTITIES)) {
    const raw = await readFile(join(directory, id, "manifest.json"));
    assert.equal(digest(raw), identity.artifact_checksum, "mounted package manifest differs from exact AU3 pin");
    const manifest = JSON.parse(raw);
    assert.equal(manifest.model_id, id);
    assert.equal(manifest.architecture, ARCHITECTURE);
    assert.equal(manifest.blob, identity.parameter_fingerprint);
    assert.equal(manifest.source.weights_sha256, identity.backbone_sha256);
    assert.equal(manifest.vocab, VOCAB);
    const assets = {};
    for (const [name, key] of Object.entries({ "model.safetensors": "blob", "config.json": "config", "vocab.txt": "vocab", "evidence.json": "evidence" })) {
      const bytes = await readFile(join(directory, id, name));
      assert.ok(bytes.length > 0 && bytes.length <= 80 * 1024 * 1024);
      assert.equal(digest(bytes), manifest[key], "mounted package asset hash differs");
      assets[name] = { sha256: digest(bytes), bytes: bytes.length };
    }
    packages.push({ modelId: id, manifestSha256: identity.artifact_checksum, assets });
  }
  return { packages, preparationSha256: digest(await readFile(join(directory, "preparation.json"))) };
}

export async function startRq3V3Model(output) {
  return startRq3Model(output, { MODEL_LATEST_ID: "privoke-v3-balanced", MODEL_RELEASE_DIR: "/model-releases" });
}

export function assertV3Accounting(receipt) {
  assert.equal(receipt.rq3Sessions.length, 4);
  for (const [index, session] of receipt.rq3Sessions.entries()) {
    assert.equal(session.transport, index % 2 ? "xhr" : "fetch");
    assert.equal(session.replicate, Math.floor(index / 2) + 1);
    for (const mode of RQ3_MODES) {
      const rows = session.records.filter((record) => record.mode === mode.id);
      assert.equal(rows.filter((record) => record.phase === "warmup").length, 5);
      assert.equal(rows.filter((record) => record.phase === "measured").length, 30);
    }
    assert.equal(session.records.filter((record) => record.phase === "verification").length, index === 3 ? 10 : 0);
  }
  const records = receipt.rq3Sessions.flatMap((session) => session.records);
  const counts = Object.fromEntries(["warmup", "measured", "verification"].map((phase) =>
    [phase, records.filter((record) => record.phase === phase).length]));
  assert.deepEqual(counts, { warmup: 80, measured: 480, verification: 10 });
  assert.equal(receipt.caseRecords.length, 120, "historical scaffold measured field must remain explicit");
  assert.equal(receipt.startupScaffoldRecords.length, 144, "startup scaffold calls must not disappear from accounting");
  assert.deepEqual(Object.fromEntries(["firstDecision", "warmup", "measured"].map((phase) =>
    [phase, receipt.startupScaffoldRecords.filter((record) => record.phase === phase).length])),
    { firstDecision: 4, warmup: 20, measured: 120 });
  assert.deepEqual(receipt.caseRecords.map((record) => record.caseId).sort(),
    receipt.startupScaffoldRecords.filter((record) => record.phase === "measured").map((record) => record.caseId).sort());
  assert.equal(records.length + receipt.startupScaffoldRecords.length, 714);
  assert.equal(new Set([...records, ...receipt.startupScaffoldRecords].map((record) => record.caseId)).size, 714);
  assert.equal(receipt.rpcEvents.filter((rpc) => rpc.method === "AnalyzePrompt").length, 574);
  assert.equal(receipt.providerCaptures.length,
    receipt.startupScaffoldRecords.length + records.filter((record) => record.action !== "BLOCK").length,
    "receiver count must include all scaffold and non-blocked controlled actions");
  return { totalFixtureCalls: 714, measured: 480, armWarmups: 80, scaffold: 144,
    postCostVerification: 10, analyzePromptWires: 574, receiverCaptures: receipt.providerCaptures.length };
}
