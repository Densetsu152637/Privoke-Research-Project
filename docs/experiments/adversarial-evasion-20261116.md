# Adversarial privacy-evasion experiment (ADVEVADE-20261116)

**Scope: PRODUCT PIPELINE (regex + NER + semantic V3 balanced), through the client runtime's native servicer on the host. Not LLM-only evidence.** Full record with every table, limitation and command: [paper/research/adversarial-evasion-20261116.md](../../paper/research/adversarial-evasion-20261116.md) (numbers in [the JSON](../../paper/research/adversarial-evasion-20261116.json)).

Goal: G6 of the [ASIACCS 2027 revision plan](../plans/asiaccs-2027-revision.md), Stage 3. Supervisor request: transform sensitive prompts (Unicode substitutions, inserted spaces, spelling perturbations, paraphrasing, indirect references, encoded identifiers, long-context placement, multilingual variants) and measure how often PriVoke fails to trigger the intended action.

What was run: 8,646 labelled-sensitive F4 rows (disjoint from every set used to design the default-off robustness flags) x 20 deterministic seeded variants (169,371 applicable pairs, frozen set sha256 `5e4eac4c...b634c2` committed before scoring), scored under two paired arms (shipped defaults; defaults plus the four robustness flags) with explicit `[regex, ner, semantic]` layers and an asserted layer list on every response, plus a 1,000-row clean-prompt specificity control.

Headline (action level, conditional on baseline protection, Wilson 95 %):

| Scope | Defaults | +flags |
|---|---|---|
| Baseline protection of untransformed prompts | 8,299/8,646 = 95.99 % | same |
| Overall conditional ASR | 4,864/162,712 = 2.99 % [2.91, 3.07] | 4,282/162,712 = 2.63 % [2.55, 2.71] |
| Indirect reference | 13.22 % | 13.22 % |
| Long context (action level; detection level 21.05 %) | 3.76 % | 3.76 % |
| Encoded identifiers | 2.81 % | 1.45 % |
| Unicode | 2.52 % | 0.82 % |
| Paraphrase | 1.86 % | 1.86 % |
| Inserted spaces | 0.76 % | 0.76 % |
| Spelling | 0.49 % | 0.49 % |
| Multilingual | 0.25 % | 0.25 % |

Negative and qualifying results, stated plainly: the product also flags 65.5 % of clean control prompts, so low ASR does not show that identifiers were recognised; an 800-character benign padding inside the semantic window lets 15.05 % of sensitive prompts through; over-length input is blocked indiscriminately (fail-closed), which is the only reason long-context action-level ASR is zero; the robustness flags help only zero-width and spelled-digit attacks; 37.6 % of protected prompts are evaded by at least one fixed variant. Transforms are fixed templates, not an adaptive attacker.

Reproduce: `evaluation/adversarial_evasion.py` (`build`, `score`, `analyse`), `evaluation/adversarial_evasion_report.py` (`assemble`, `render`, `check`), tests `evaluation/tests/test_adversarial_evasion*.py`; exact commands are in the record.
