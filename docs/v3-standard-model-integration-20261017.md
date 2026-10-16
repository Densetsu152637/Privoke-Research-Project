# Standard V3 model integration: implementation checkpoint

Checkpoint 1, 2026-10-17. Product implementation and focused local checks only;
installed V3 browser verification, resident timing and deployment remain unrun.
The existing V1 A/B/C study and exact AU3 experiments remain immutable. Source
closure and complete changed surfaces are in the matching JSON record.

`latest` now resolves to selected AU3 `privoke-v3-balanced`. Explicit efficient,
balanced and quality V3 IDs load the exact selected package pins through additive
binary package/asset RPCs in the maintained Go service. The product native cache
loads complete pretrained BERT encoder/pooler and fitted heads strictly, with no
random initialization or Tiny fallback. The normal browser launcher, bridge and
supervisor entrypoints are unchanged. This route does not import research servers.

The package registry, preparation tool and Go service bind all three canonical
IDs and exact manifest pins. The local ignored read-only release store preserves
the original bytes and source-file provenance. Four asset names are allowlisted;
ordered chunks bind model/pin/name/hash/offset/size, with 1 MiB chunks, 80 MiB assets
and 256 KiB manifests. The client rejects malformed, mixed, incomplete or corrupt
streams and changed manifests before cache admission. Initial asset writes and
the final manifest use private exclusive temporary files. File/path checks reject
symlinks and Windows reparse points. Refresh checks the small manifest; weights
are not fetched or reconstructed on every TTL poll. Native model reload verifies
the complete tensor inventory and all asset hashes again.

Standard inference is CPU-only, with maintained Torch 2.11.0 CPU, Transformers
4.57.6, tokenizers 0.22.2, safetensors 0.8.0 and NumPy 1.26.4 requirements. Explicit
V3 CUDA/MPS requests fail clearly. Legacy V1 retains its GPU/NumPy routes and
original float limits. Legacy saved quality strings and model IDs migrate to
labeled older V1 profiles; missing/latest settings follow V3 balanced. MiniLM's
separate explicit-only guard and the V1-calibrated presence gate remain intact.

Base/dev/GCE configuration agrees on V3 balanced and read-only release storage.
Normal initialization copies legacy seeds without bootstrapping/training.
Fuzzer/updater services require explicit `legacy-training`; their bootstrap and
gradient/update paths remain legacy-only. V3 legacy-gradient calls reject clearly.
The Go standard alias is configuration-owned, not a legacy publication pointer;
mutable V1 JSON cannot replace the pinned read-only V3 store. Explicit legacy-only
server alias configuration remains supported. GCE requires separately staged
packages and freezes the release-store path/latest alias in release.env for
rollback. No weights are included in Git or Docker context; no deploy was run.

Focused checks passed:

- Host Python 3.11.9 new V3 suite: 7 tests, 6 passed, 1 physical symlink test skipped
  because Windows denies symlink creation. A separate Windows reparse-attribute
  rejection test passed. All three real local packages passed complete state
  inventory, packed classification/confidence and finding parity against
  `PretrainedV3`; actual in-process product AnalyzePrompt returned sole `[4]`,
  successful status and exact identity. This is not installed-browser validation.
- Host existing streamed transformer 11, MiniLM 9 and semantic presence gate 16
  tests passed. These cover explicit legacy tiers and preserve the MiniLM guard.
- Go `go test -race ./...` passed with the three real read-only release packages:
  actual gRPC asset streaming, ordered hash/size verification, default alias,
  explicit legacy control, unchanged alias, missing-store and symlink/traversal/
  unpinned-manifest rejection. Go ran in a scoped development image; Python
  tests and loops ran on the host.
- All 100 browser Node unit checks passed; Chromium and Firefox standard builds
  passed. Normal build regenerated the tracked popup and runtime codec. The codec
  includes pre-existing schema drift (presence/cascade messages); it was generated
  from current source rather than manually trimmed.
- Base/dev/GCE and explicit legacy CI Compose models validate; training services
  are absent by default. Python compilation and Git whitespace checks passed.

Failures were retained in the checkpoint record: an initial parity test compared
Classification object identity rather than packed value; a Go test Compose mount
omitted historical legacy fixture files; MiniLM's pre-existing subclass omitted
the base prediction_observer field. The first two were test setup repairs; the
third adds `None` in its constructor and its nine-test compatibility gate passed.
No failed measurements were discarded: no V3 timing study has begun.

CI's historical product/TLS training checks now explicitly select legacy V1 and
the opt-in training profile, replacing the unused V3 bind with an empty owned
volume. They require no ignored AU3 weights and do not claim V3 installed coverage.
Asset-dependent native V3 tests explicitly skip when packages are absent; local
focused checks above actually used all three packages. Hosted CI, cloud smoke,
deployment, actionlint and shellcheck remain unrun here; no corresponding local
tools were available. Existing historical CI container Python drivers were not
executed in this work.

The prospective installed/cost protocol is a separate draft at
`paper/research/v3-standard-installed-protocol-20261017.md`. Root review and a
source/protocol freeze precede actual E2E execution. V3 default selection reflects
bounded AU3 evidence; it does not establish universal privacy/retention superiority.
