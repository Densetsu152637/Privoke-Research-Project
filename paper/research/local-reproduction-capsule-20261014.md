# RP14 local source/model reproduction capsule, 14 October 2026

## Question and authorized scope

Can the actual frozen local source closure and all six original V1/AU3 model bundles reproduce the already completed four invented semantic-only probe outputs from an isolated source copy?

Exact user objective: “Can you now get data and rewrite the sections of the paper for all the unfinished work that you can get yourself? First plan out an implementation that utilises the workflows effectively and then act on that implementation.” Root scoped RP14 to local reproduction evidence only. This record does not run protected final evaluation, training, tuning, selection, promotion, or product-pipeline ablation.

## Prospective preparation

The durable local capsule is `models/experiments/paper_reproduction_20261014/capsule-03/` in the primary checkout. Its immutable `manifest.json` has SHA256 `10925240bdf7e7b6337a40a17c826b80cf30bbd015ec6700e7e7bc02cf2dc127`. It pins 195 files: 168 source files, 18 original model assets, seven original synthetic receipt files, and two dependency-version files. The source closure comprises all 158 entries actually present in FN14 freeze03, five frozen evidence executables, three package/setup/requirements files, and the new controller and tests. The assignment initially named 154 dependencies; direct enumeration of freeze03 gives 158, and every entry is copied and verified. The separate historical clean-checkout comparison retains its own 154-file inventory.

The canonical path-to-hash source map has SHA256 `85646a5ca16d2bd9532af60ece67868968446507d0947874573b3b9a20e2b818`. Model assets are independently copied to `models/ORIGINAL/<package>/`, totaling 130,676,181 bytes. Every source/model copy is checked against its source hash; original assets remain untouched. Only bounded source files and declared model assets are copied, excluding credentials, environment files, private corpora, and protected final inputs/wires.

Historical inputs are FN14 freeze03 SHA256 `655798df22d0dd817873b0554d5b4de084dec669354ae2c616f7dd06eaceda00` and synthetic probe02 analysis SHA256 `a7fb790f0c30d8db2e125ccd07d778c1098e521916e2041d48c0f905d77ecab7`. Six raw probe journals are copied and checked against that analysis's commitments. The frozen final evaluator is retained as source provenance but never imported or executed by this synthetic-only controller.

The host interpreter is the maintained primary `evaluation/.venv-v1-v3-pipeline/Scripts/python.exe`: Python 3.11.9, CPU Torch 2.11.0+cpu. Its Python version and all 11 named frozen dependencies match; 74 distribution versions are retained in `environment/versions.json` and `requirements-versions.txt`. These are version records, not complete wheel-hash locks or evidence of a new installation.

Every process uses Python `-I -B`, with source imports explicitly inserted from the capsule and cwd set to `capsule-03/source`. Actual module-file and package-search origins must stay within that source root or the interpreter environment. The preflight attestation SHA256 is `549b33315c8b9bd0b2d5c5da6c00f3088a8eb89dca8dcb46beaa61d37ac7e95b`; it records 67 real project source modules and no stored Torch virtual origins. R2 independently verified the 195 pins, attestation, synthetic-only request gate, raw failure retention, and eight focused integrity tests before root release.

## Bounded replay protocol

Six fresh, inference-only host processes serve the copied original bundles sequentially on loopback ports 50211 (V1) and 50212 (V3), with four CPU threads, offline transformer loading, a pinned semantic cache, no remote fallback, and disabled training RPCs. Each server admits only the same four invented texts from historical synthetic probe02. Requests explicitly select `[4]`; each returned response must execute the sole successful semantic layer `[4]` and return the exact model ID, model version, artifact checksum, and parameter fingerprint. No visibility hint or presence gate is supplied.

The client replays the original 24 request protobufs, retaining each reservation and response protobuf/hash before checking normalized output. Transport and response-validation errors receive terminal records. Comparison covers category/sensitivity/visibility, action, sole actual layer and four package identity fields. Latency, timestamps and complete wire-byte equality are deliberately excluded. Pins are reverified after replay. Server ready and stopped receipts attest actual imports before and after inference; PID terminal receipts establish owned-process cessation.

## Revision and failed-attempt history

- Capsule01: preflight failed before any RPC because `getattr(module, '__file__')` triggered lazy Torch namespaces and manufactured `_classes.py` / `_ops.py` values. The original failure receipt and an additive diagnosis correction are retained. Real stored dictionaries contain no file origins for those dynamic namespaces.
- Capsule02: corrected stored-`ModuleType` origin attestation passed; no inference was run. Independent review required received wire retention before response validation, so this entire capsule remains unchanged as an unrun intermediate revision. Its first dependency comparison also mis-normalized underscore spaCy distribution names; capsule03 records the PEP503-normalized correction without changing dependencies.
- Capsule03: final source revision includes wire-before-validation retention and transport-error terminalization, covered by two additional regression checks. Eight focused host tests pass. All earlier capsules and original assets are preserved.

## Result and interpretation

The released replay passed: **24/24 normalized outputs matched** the historical synthetic probe across all six packages, with zero runtime errors. All requests executed sole layer `[4]` successfully and returned all four pinned model identity fields. Independent R2 review reconstructed every original/replay protobuf pair, confirmed identical request bytes and classification protobuf bytes/action outputs, rehashed all 195 manifest pins after inference, and checked all 12 ready/stopped import attestations. These checks provide bounded replay evidence; no case was scored for accuracy.

The retained analysis SHA256 is `2a4b817d5147551337a25a2adc51178fd38b35d53ae521c647aa0cf3a5982d41` at `capsule-03/attempts/synthetic-replay-01/analysis.json`. All six server terminal receipts have exit code zero. The separate process check found all six owned PIDs absent and no listeners on ports 50211/50212. The complete capsule inventory contains 234 files and 132,754,206 bytes excluding its seal; inventory SHA256 is `34170c3b40b61e3eb5282151461ea973ab25af065cbe6eb60022d2ddf84dd96f`, and seal SHA256 is `e201cf0dfe791596f06ad278ea29b197a17bbb956194f5ebfd56ce5d1b56355a`. The accompanying tracked JSON records source/model identities, raw receipt commitments, environment checks, and these results.

Git stores the new controller and tests with LF line endings while their executed capsule copies have CRLF endings. A direct byte check confirms that CRLF-to-LF normalization is the only difference; the exact executed source bytes remain retained and hash-pinned in the capsule. For local integrity verification, use that frozen capsule controller directly:

```powershell
& 'D:\Git Repositories\Privoke-Research-Project\evaluation\.venv-v1-v3-pipeline\Scripts\python.exe' -I -B `
  'D:\Git Repositories\Privoke-Research-Project\models\experiments\paper_reproduction_20261014\capsule-03\source\evaluation\local_reproduction_capsule.py' `
  verify --capsule 'D:\Git Repositories\Privoke-Research-Project\models\experiments\paper_reproduction_20261014\capsule-03'
```

The retained capsule can serve/replay from its own source and original model directories after task worktrees are retired; it depends on the maintained host interpreter, rather than importing project source from that interpreter's primary checkout. To request a later replay, use a new output directory under `capsule-03/attempts`; existing attempt paths are refused.

This is a local artifact capsule in ignored experiment storage, using an existing maintained host environment. The successful output replay establishes only bounded local source/model reproduction on four invented prompts per package. It would not make a public Git checkout independently runnable, certify artifact/data redistribution or licenses, prove protected-final reproducibility, establish accuracy/safety/generalization, or validate deployment latency.
