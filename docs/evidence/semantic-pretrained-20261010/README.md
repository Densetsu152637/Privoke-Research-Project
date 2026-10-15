# Frozen pretrained contextual study: public evidence

Research ID: `RQ-SEM-PRETRAINED-CONTEXT-20261010`. The [study record](../../semantic-pretrained-context-study-20261010.md) defines the question, provisional labels, frozen protocol, amendments and limitations. Synthetic gains passed the gain criteria, but the serious-action veto failed. No model was promoted.

From the repository root, run:

```powershell
python docs/evidence/semantic-pretrained-20261010/reproduce.py
```

This uses only Python's standard library. It verifies delivered file hashes and recomputes primary counts, paired gains, casewise harms, operational gates, secondary coverage/confusion counts and nine functional token-limit outcomes. It performs no inference, fitting, downloads or protected-final access. It is arithmetic reproduction of the published projection, not an independent model rerun or validation of unavailable raw receipts.

| File | Scope |
|---|---|
| [primary.json](primary.json) | All 960 synthetic assessment labels/actions, model identities, paired metrics, selections and short-workload operational measurements |
| [secondary.json](secondary.json) | Seven reused comparisons, successful-response counts, explicit errors/coverage, historical hint caveat and credential harm IDs |
| [context512.json](context512.json) | Nine functional requests, token counts, boundary outcomes and short-input parity; no quality or latency qualification |
| [provenance.json](provenance.json) | SHA-256 commitments to retained local source receipts and the explicit projection boundary |
| [publication-hashes.json](publication-hashes.json) | Hashes of delivered JSON and the reproducer; distinct from hashes of raw receipts |

The export uses an explicit field allowlist. It includes synthetic row IDs and targets/predictions, but no prompt text, real public-development row labels, raw RPC responses, logits or real PII. Secondary IDs identify the disclosed failure cases without reproducing their content. The original failed secondary receipt, primary freeze/summary, secondary amendment and two functional-check harness failures remain in the local archive. Their failure descriptions are in the study record; they are not relabeled as model outcomes.

`--publish-local` regenerates these projections only when the already-retained ignored receipts are present. It does not create missing evidence. Full model reproduction additionally requires pinned assets, frozen source/data/artifact identities, the isolated semantic-only service configuration and the recorded environment. Recreate a dedicated Python 3.13.2 environment from `extension/client-runtime/requirements-pretrained-context.txt` (NumPy 2.2.6, ONNX Runtime 1.23.2, Tokenizers 0.22.1 and pinned runtime dependencies). Do not combine it with the ordinary host evaluation requirements, which constrain NumPy below 2. The ignored study virtual environment is disposable; public arithmetic verification does not require it.

The 256-token primary study and later explicit 512-token functional extension remain separate. Same-seed repetitions do not turn one scenario into independent harms. Source-family holdout still shares abstract contexts and assistant-authored framing; no general LLM accuracy or deployment claim follows.
