"""Shared signed-chain fixtures for the V3 publication statement (stage V3-R2 of docs/plans/v3-routine-training.md).

One deterministic fixture set, replayed by every consumer: the contracts crate (`rust/services/param-update/tests/v3_signed_chain.rs`), the param-update
publisher (R2), model-streaming (R3), the supervisor's lineage admission (R4a and R4b) and `evaluation/update_security.py`.
It holds, on a toy checkpoint (manifests that satisfy the manifest contract with a stand-in tensor inventory; no weights):

  ORIGINAL -> HEADS (sequence 1) -> FULL (2) -> rollback to the ORIGINAL (3) -> a HEADS version signed by the second key (4)

and the forged variants of a statement: a bad signature, an unknown key, a non-canonical encoding, a statement for another
model, a lower sequence, the same sequence for another manifest, a lineage that differs from the manifest's own, and a
statement attached to another manifest. The ORIGINAL of the toy chain is not the compiled tier pin (the real pinned manifests
are not in the repository), so a consumer of lineage admission must take the tier pin as a parameter and use `original_pin` here.

The keys are the deterministic test keys of `privoke_contracts::publication::test_keys` (seed = SHA-256 of
`privoke-v3-test-key\\n<key id>\\n`). Ed25519 is implemented here from RFC 8032 so that no package is needed; it is checked
against the RFC test vector before anything is signed. Run with any Python 3:

  python evaluation/generate_v3_signed_chain_fixtures.py
"""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUTPUT = ROOT / "rust" / "crates" / "privoke-contracts" / "tests" / "fixtures" / "v3_signed_chain" / "chain.json"

# --- Ed25519 (RFC 8032, the reference algorithm) ------------------------------------------------------------------------------
P = 2**255 - 19
Q = 2**252 + 27742317777372353535851937790883648493


def inv(x):
    return pow(x, P - 2, P)


D = -121665 * inv(121666) % P
I = pow(2, (P - 1) // 4, P)


def recover_x(y):
    xx = (y * y - 1) * inv(D * y * y + 1)
    x = pow(xx, (P + 3) // 8, P)
    if (x * x - xx) % P != 0:
        x = x * I % P
    return P - x if x % 2 else x


BY = 4 * inv(5)
B = (recover_x(BY) % P, BY % P)


def add(a, b):
    x1, y1 = a
    x2, y2 = b
    t = D * x1 * x2 * y1 * y2
    return ((x1 * y2 + x2 * y1) * inv(1 + t) % P, (y1 * y2 + x1 * x2) * inv(1 - t) % P)


def mult(point, e):
    if e == 0:
        return (0, 1)
    half = mult(point, e // 2)
    half = add(half, half)
    return add(half, point) if e & 1 else half


def encode(point):
    x, y = point
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def hint(message):
    return int.from_bytes(hashlib.sha512(message).digest(), "little")


def secret_scalar(seed):
    digest = hashlib.sha512(seed).digest()
    return (int.from_bytes(digest[:32], "little") & ((1 << 254) - 8)) | (1 << 254), digest[32:]


def public_key(seed):
    return encode(mult(B, secret_scalar(seed)[0]))


def sign(seed, message):
    a, prefix = secret_scalar(seed)
    public = encode(mult(B, a))
    r = hint(prefix + message) % Q
    point = encode(mult(B, r))
    s = (r + hint(point + public + message) * a) % Q
    return point + s.to_bytes(32, "little")


# RFC 8032 section 7.1, test 1.
_SEED = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
assert public_key(_SEED).hex() == "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
assert sign(_SEED, b"").hex() == ("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46b"
                                  "d25bf5f0595bbe24655141438e7a100b")

# --- The statement and the chain -----------------------------------------------------------------------------------------------
TAG = "privoke-v3-publication-v1"
PRIMARY, SECONDARY = "test-publication-1", "test-publication-2"
MODEL = "privoke-v3-efficient"
PARAMETERS = 4785044
SOURCE = {"repository": "google/bert_uncased_L-4_H-128_A-2", "revision": "c29bee83fc7f003ac8c5e6e135529da4ecddb7c3",
          "weights_sha256": "2e37a60f99c30c244da3a2ada3653faf378689783c5b6500d7291acc2516e199",
          "config_sha256": "191ec8105cc6eb8ce2d64c117f7c5830f6028c06da4d7a0d3672414f2c77ad98",
          "vocab_sha256": "07eced375cec144d27c900241f3e339478dec958f92fddbc551f295c992038a3"}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False) + "\n").encode()


def seed_of(key_id):
    return hashlib.sha256(f"privoke-v3-test-key\n{key_id}\n".encode()).digest()


def manifest(label, scope, parent="", original="", model="privoke-v3-efficient"):
    tier = model.removeprefix("privoke-v3-")
    document = {"schema": 1, "architecture": "privoke_pretrained_bert_v3", "model_id": model, "tier": tier, "parent": parent,
                "original": original, "blob": sha(b"blob " + label.encode()), "config": SOURCE["config_sha256"],
                "vocab": SOURCE["vocab_sha256"], "source": SOURCE,
                "tensors": {"encoder.stand_in.weight": {"shape": [PARAMETERS], "dtype": "F32", "sha256": sha(b"tensor " + label.encode())}},
                "parameter_count": PARAMETERS, "scope": scope, "evidence": sha(b"evidence " + label.encode()) if scope != "original" else ""}
    raw = canonical(document)
    return {"label": label, "manifest_b64": base64.b64encode(raw).decode(), "manifest_sha": sha(raw), "parent": parent, "original": original}


def statement(entry, key_id, sequence, model=MODEL, **overrides):
    fields = {"tag": TAG, "key_id": key_id, "model_id": model, "manifest_sha": entry["manifest_sha"], "parent": entry["parent"],
              "original": entry["original"], "sequence": sequence}
    fields.update(overrides)
    return fields


def signed(fields, key_id=None):
    signature = sign(seed_of(key_id or fields["key_id"]), canonical(fields))
    return canonical(dict(fields, signature=signature.hex())).decode()


def main():
    original = manifest("original", "original")
    heads = manifest("heads", "heads", original["manifest_sha"], original["manifest_sha"])
    full = manifest("full", "full_encoder", heads["manifest_sha"], original["manifest_sha"])
    next_heads = manifest("heads-after-rollback", "heads", original["manifest_sha"], original["manifest_sha"])
    other_original = manifest("other-original", "original")
    wrong_original = manifest("wrong-original-heads", "heads", other_original["manifest_sha"], other_original["manifest_sha"])
    manifests = [original, heads, full, next_heads, other_original, wrong_original]

    valid = [
        {"name": "heads", "manifest": "heads", "statement": signed(statement(heads, PRIMARY, 1))},
        {"name": "full", "manifest": "full", "statement": signed(statement(full, PRIMARY, 2))},
        {"name": "rollback-to-original", "manifest": "original", "statement": signed(statement(original, PRIMARY, 3))},
        {"name": "rotation-second-key", "manifest": "heads-after-rollback", "statement": signed(statement(next_heads, SECONDARY, 4))},
    ]
    good = valid[0]["statement"]
    at = good.index("signature") + 12
    flipped = good[:at] + ("0" if good[at] != "0" else "1") + good[at + 1:]
    # The same signature with S replaced by S + L: it satisfies the verification equation, and a verifier that does not require S < L
    # accepts it as a second valid signature of the same message.
    at_r = good.index("signature") + 12
    original_signature = bytes.fromhex(good[at_r:at_r + 128])
    malleable = original_signature[:32] + (int.from_bytes(original_signature[32:], "little") + Q).to_bytes(32, "little")
    forged = [
        {"name": "malleable-signature", "manifest": "heads", "statement": good[:at_r] + malleable.hex() + good[at_r + 128:], "verify": "bad_signature"},
        {"name": "bad-signature", "manifest": "heads", "statement": flipped, "verify": "bad_signature"},
        {"name": "unknown-key", "manifest": "heads", "statement": signed(statement(heads, "test-publication-3", 1), PRIMARY), "verify": "unknown_key"},
        {"name": "not-canonical", "manifest": "heads", "statement": good.replace(',"manifest_sha"', ', "manifest_sha"'), "verify": "malformed"},
        {"name": "another-model", "manifest": "heads", "statement": signed(statement(heads, PRIMARY, 1, model="privoke-v3-balanced")),
         "verify": "ok", "lineage": "refused: the statement names another model"},
        {"name": "lower-sequence-replay", "manifest": "heads", "statement": valid[0]["statement"], "verify": "ok",
         "lineage": "refused after sequence 3 was seen: replay of a lower sequence"},
        {"name": "same-sequence-other-manifest", "manifest": "full", "statement": signed(statement(full, PRIMARY, 1)), "verify": "ok",
         "lineage": "refused after heads at sequence 1 was seen: the same sequence for another manifest"},
        {"name": "parent-differs-from-manifest", "manifest": "full",
         "statement": signed(statement(full, PRIMARY, 5, parent=original["manifest_sha"])), "verify": "ok",
         "lineage": "refused: the statement parent is not the manifest parent"},
        {"name": "original-differs-from-manifest", "manifest": "full",
         "statement": signed(statement(full, PRIMARY, 5, original=other_original["manifest_sha"])), "verify": "ok",
         "lineage": "refused: the statement original is not the manifest original"},
        {"name": "statement-for-another-manifest", "manifest": "full", "statement": valid[0]["statement"], "verify": "ok",
         "lineage": "refused: the statement names another manifest than the one fetched"},
        {"name": "wrong-original", "manifest": "wrong-original-heads", "statement": signed(statement(wrong_original, PRIMARY, 5)),
         "verify": "ok", "lineage": "refused: the manifest descends from an ORIGINAL that is not the tier pin"},
    ]
    keys = {key_id: public_key(seed_of(key_id)).hex() for key_id in (PRIMARY, SECONDARY)}
    document = {"schema": 1, "tag": TAG, "model_id": MODEL, "original_pin": original["manifest_sha"], "keys": keys,
                "manifests": manifests, "chain": valid, "forged": forged}
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(document, indent=1, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps({"manifests": len(manifests), "chain": len(valid), "forged": len(forged), "output": str(OUTPUT)}))


if __name__ == "__main__":
    main()
