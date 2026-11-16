# Guarded-update and authentication security tests (2026-11-16)

Record: [paper/research/update-security-20261116.md](../../paper/research/update-security-20261116.md) (stable ID UPDSEC-20261116) with data in [update-security-20261116.json](../../paper/research/update-security-20261116.json).

Instruction: the supervisor's request to "intentionally attempt stale-model updates, replayed updates, duplicate submissions, malformed tensors, NaN/Inf values, incorrect shapes, excessive parameter changes, interrupted updates, and unauthorized publication", and to "test invalid credentials/certificates, expired credentials, impersonation attempts, replayed requests, and unauthorized model retrieval/update"; scope authorised by the 16 November 2026 entry of `paper/REWRITE_SCOPE.md`; plan Stage 4, goals G7 and G8.

## Procedure

1. `python evaluation/setup-host.py` generates the host gRPC clients (gitignored).
2. Build the Go streaming image from the checkout: `docker build -f services/model-streaming-service/Dockerfile --target development -t privoke-updsec-model-dev:20261116 .`
3. `python evaluation/update_security.py --release-dir models/standard-releases` hosts, on loopback ports chosen at run time, the real `param-update-service` as a host process (private copy of `privoke-balanced`, prepared with its own `bootstrap.py`) and the Go `model-streaming-service` with `docker run` (artifact directory and standard releases mounted read-only). It runs 91 rows, snapshots the model before and after each, and writes the JSON. All Python test code runs on the host; no test runs in a container.
4. `python evaluation/update_security_report.py` renders the tables into the record from the JSON.
5. `python -m unittest discover -s evaluation/tests -p test_update_security.py` checks the harness contracts, an in-process run of the real servicer against stale, replayed, duplicate, malformed, non-finite, wrong-shape and excessive requests, the PKI helper, and that the stored summary and the rendered tables re-derive from the JSON.

## What was changed

Only new files: the harness, its PKI and report helpers, its tests, and the two records. No service, shared-library, deployment or extension code was modified; the accepted attacks are absent mechanisms and are recorded as unmet properties rather than patched.

## Outcome summary

Seven of nine guarded-update classes met their property in every row (stale, replayed, duplicate, malformed tensors, NaN/Inf, wrong shape, interrupted). Excessive change is bounded per coordinate only, and unauthorized publication succeeds for any peer that can reach the service port; both are recorded as gaps. Certificate-class negative tests passed against a stand-in mutual-TLS terminator; the services themselves have no credentials, expiry, per-installation identity or retrieval authentication, and revocation is not configured. See the record for the per-attack table and limitations (notably that the production nginx ingress was not executed).
