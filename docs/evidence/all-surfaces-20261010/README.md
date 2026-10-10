# Accelerated all-surface training evidence

The [study record](../../accelerated-training-surfaces-study-20261010.md) reports every one of the 56 configurations and all 168 trajectories (seeds 42/43/44; 111 online and 57 offline). **None qualified under the frozen gain/harm rules.** Fifty configurations were gain-eligible; six scratch configurations lacked specificity headroom. No model was promoted and protected final data were not scored.

Both maintained commands completed raw archive audits and produced byte-identical aggregate SHA-256 `ec530e92d01f5f1f6747549c84a7315db521cf8fdcb99be794ea311f0abe9b63`. The independent standard-library checker reconciled 168 cells, 56 decisions and 600 primary/secondary endpoint pairs, including errors, casewise harms and subgroup gains. All training/evaluation execution was explicitly semantic-only with actual execution assertions.

## Files and provenance

- [summary.json](summary.json): every configuration decision, fixed-final paired metrics, component outcomes, harms, coverage, errors and descriptive uncertainty.
- [protocol.json](protocol.json): public frozen matrix and computation-source commitments.
- [audit.json](audit.json): aggregate raw-audit and archive hash commitments.
- [independent-check.json](independent-check.json): independent arithmetic-check result and checker hash.
- [bindings.json](bindings.json): exact hashes of eight accepted raw inputs: protocol, audit, summary, four chained amendments and independent reconciliation.
- [publication-hashes.json](publication-hashes.json): hashes of the seven other public files, raw bindings and source revisions.
- [reproduce.py](reproduce.py): deterministic projection from the retained raw inputs.
- [independent-check.py](independent-check.py): independent count reconciliation against retained raw endpoint predictions.

The five source roles remain separate: fitting `0b469c7a5972beee4f64544f5c0f33337923fc85`, precision audit `f3650a3445ec26d17e8bba57da7cf7d7807b31ab`, worker import environment `7be337e704ade2773dd8b533ad0be2a454b06c11`, scoring mounts `236328d04a1673902375d91b0624265d2aa36f05`, and report schema `ad9241a86ba39e4d594b17eda67137807b7f632f`. The amendments preserve the original protocol, fitting, qualification rules, completed receipts and failed-attempt evidence. They do not reset transport retry allowances. The raw protocol SHA-256 is `aadcef30cd3fabb595cf076ce8beeb9c9bbc9159bfd44899dd0ede0fbc76e797`.

The frozen ledger declares own-baseline-to-final endpoint descriptors and no cross-cell reference IDs. Its `controlled_contrasts` output is therefore empty. Cross-configuration summaries are descriptive package comparisons.

## Reproduction

Run from the repository root with Python 3.11 or later and the retained local raw evidence at the documented path. Output paths must not already exist.

```text
python docs/evidence/all-surfaces-20261010/reproduce.py evaluation/results/accelerated_all_surfaces_20261010 docs/evidence/all-surfaces-20261010/bindings.json .tmp/all-surfaces-reproduced
python docs/evidence/all-surfaces-20261010/independent-check.py evaluation/results/accelerated_all_surfaces_20261010/execution-study-v3 .tmp/all-surfaces-independent.json
```

The first command regenerates the eight machine-readable/source files byte for byte; compare them using `publication-hashes.json` and compare the manifest itself with the committed copy. This README and the study's all-configuration Markdown table are separate Git-tracked documentation. The second command recomputes independent arithmetic from raw endpoint rows. The projector verifies accepted bindings but does not rerun model inference or the complete raw archive auditor. A complete raw audit additionally requires the exact final reporter checkout and its chained source/worker commitments; a later documentation revision does not satisfy that strict source gate.

Raw prompts, per-example predictions, tensors, SQLite state, host paths, ports, operational logs and full archive inventories are retained locally rather than redistributed here. The public package alone cannot reconstruct model fitting or establish the raw rows' correctness. Task-owned temporary projects, volumes and five final study image tags were removed after exact artifacts were archived; unrelated containers were preserved.

## Interpretation limits

Contextual labels are assistant-provisional, secondary data were reused, seed plans share procedural pool membership, and architectures/cohorts/capacities and accepted exposure differ. Paired family/source-group intervals describe scenario sampling, not independent seed confidence. Sparse solver duplicates remain disclosed. Historical annotation scoring retains 714 overlength error observations across 18 unique case IDs with fixed denominators and vetoes. Primary, annotation-transfer and fixture errors were zero. The study does not establish a prompt-revision effect, long-context accuracy, causal variance/pretraining gains, independently reviewed generalization or deployment readiness. Experimental Tiny input capacity was 256 tokens with matched baselines; shipped defaults were unchanged.
