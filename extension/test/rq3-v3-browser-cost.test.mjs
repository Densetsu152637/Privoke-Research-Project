import test from "node:test";
import assert from "node:assert/strict";
import { assertRq3SemanticIdentity, RQ3_MODEL_IDENTITY, RQ3_MODES } from "./rq3-browser-cost.mjs";
import { V3_IDENTITIES, V3_BALANCED, V3_VERIFICATION_PROFILES, v3SessionOptions, assertV3Accounting } from "./rq3-v3-browser-cost.mjs";

test("V3 uses default latest and adds tier/legacy probes only after final costs", () => {
  assert.equal(RQ3_MODEL_IDENTITY.model_id,"privoke-balanced");
  for (let index=0;index<4;index++) {
    const options=v3SessionOptions(index);
    assert.equal(options.modelQuality,"latest");assert.equal(options.semanticModelId,"");
    assert.equal(options.modelIdentity,V3_BALANCED);
    assert.equal(options.verificationProfiles.length,index===3?5:0);
  }
  assert.equal(V3_VERIFICATION_PROFILES.every((p)=>p.verification && p.expected.length===1 && p.expected[0]==="DETECTION_LAYER_SEMANTIC"),true);
  assert.deepEqual(V3_VERIFICATION_PROFILES.map((p)=>p.semanticModelId),[...Object.keys(V3_IDENTITIES),"privoke-balanced",""]);
});

test("clean V3 envelopes require exact manifest/blob/architecture/thread and actual popup selector", () => {
  const rpc={request:{semanticModelId:""},response:{decoded:{layers:[{results:[]}],metadata:
    Object.fromEntries(Object.entries(V3_BALANCED).map(([key,value])=>[`privoke.semantic.${key}`,value]))}}};
  assertRq3SemanticIdentity(rpc,V3_BALANCED,"");
  for (const key of ["model_id","artifact_checksum","parameter_fingerprint","architecture","backbone_sha256","tokenizer_sha256","compute_device","torch_threads"]) {
    const bad=structuredClone(rpc);bad.response.decoded.metadata[`privoke.semantic.${key}`]="wrong";
    assert.throws(()=>assertRq3SemanticIdentity(bad,V3_BALANCED,""));
  }
  assert.throws(()=>assertRq3SemanticIdentity(rpc,V3_BALANCED,"privoke-v3-balanced"));
});

test("714-call accounting retains scaffold, blocking and every post-cost verification", () => {
  const sessions=Array.from({length:4},(_,index)=>({transport:index%2?"xhr":"fetch",replicate:Math.floor(index/2)+1,
    records:RQ3_MODES.flatMap((mode)=>Array.from({length:35},(_,i)=>({caseId:`new-${index}-${mode.id}-${i}`,mode:mode.id,phase:i<5?"warmup":"measured",action:"ALLOW"})))}));
  sessions[3].records.push(...Array.from({length:10},(_,i)=>({caseId:`verification-${i}`,phase:"verification",action:i===9?"BLOCK":"ALLOW"})));
  const receipt={rq3Sessions:sessions,
    caseRecords:Array.from({length:120},(_,index)=>({caseId:`scaffold-${index+24}`})),
    startupScaffoldRecords:Array.from({length:144},(_,index)=>({caseId:`scaffold-${index}`,phase:index<4?"firstDecision":index<24?"warmup":"measured"})),
    rpcEvents:Array.from({length:574},()=>({method:"AnalyzePrompt"})),providerCaptures:Array.from({length:713},()=>({}))};
  assert.equal(assertV3Accounting(receipt).receiverCaptures,713);
  const missing=structuredClone(receipt);missing.rq3Sessions[0].records.pop();assert.throws(()=>assertV3Accounting(missing));
  const scaffold=structuredClone(receipt);scaffold.startupScaffoldRecords.pop();assert.throws(()=>assertV3Accounting(scaffold));
  const duplicate=structuredClone(receipt);duplicate.startupScaffoldRecords[0].caseId=duplicate.rq3Sessions[0].records[0].caseId;assert.throws(()=>assertV3Accounting(duplicate));
  const wire=structuredClone(receipt);wire.rpcEvents.pop();assert.throws(()=>assertV3Accounting(wire));
});
