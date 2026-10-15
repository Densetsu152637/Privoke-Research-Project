# Literature-informed manuscript revision — 15 October 2026

## Goal and scope

Goal: revise the current manuscript using the accepted literature review to
(1) sharpen the contribution around guarded version-bound updates, publication,
client refresh and measured gains/regressions; (2) compare sanitization,
response recovery, acknowledged warnings, original forwarding and blocking;
(3) qualify literature versions, metrics and evaluated populations; and
(4) state the practical-utility gap. This is a source-grounded editorial revision,
not a new study, reproduction or claim of new response fields.

Authoritative input: [literature-baseline-review-20261015.md](literature-baseline-review-20261015.md),
record LBR-20261015, including its source locators and bibliography. Manuscript
input snapshot: paper/main.tex, SHA-256
09bfbcd21bc416aa70bf407ad5a7e47aca7c1283284574f2a1c825ebbd8a3763.
The working primary bibliography was dirty and preserved. Casper v1's separate
key is included from literature-baseline-sources-20261015.bib; no entry was
added to the primary bibliography.

## Requirements and changes

| Requirement | Manuscript change |
| --- | --- |
| Bound the contribution to what is distinctive and measured. | Introduction centers the guarded update lifecycle, versioned publication, client refresh, retention checks, and observed gains and regressions. The contributions list names version-bound updates, admission/publication checks, refresh, and paired gains and regressions. It recognizes precedent for local inspection and local model training. |
| Make functional differences explicit. | Related Work adds a compact interaction table: Casper identifier substitution/restoration and warning acknowledgement; HaS local response recovery; ProSan selective rewriting and utility proxies; PriVoke's original ALLOW/WARN forwarding, non-awaited notice, and BLOCK cancellation. The prose says WARN communicates risk but does not itself prevent disclosure or establish informed consent. |
| Qualify version, metric and population. | Related Work distinguishes Casper 2024 v1 from the 2025 abstract and names the GPT-4-Turbo-generated workloads and NER supports. It states HaS's 1.7B black-box attacker, keeps 0.4070 as a whole-text recovery-similarity proxy distinct from entity protection, and notes unspecified exact test support. It names ProSan's three datasets, test counts, item-replacement proxy and unspecified exact item count; a sentence records the reviewed v1's WordNet criterion. No cross-study ranking is inferred. |
| Name missing practical evidence. | Limitations state that authorized task completion, unnecessary restrictions, warning comprehension and reformulation effort were not measured. Extensions call for measuring them with users and distinguish task-essential from authorized content. |

The 2025 Casper abstract row remains separate from the v1 preprint row.
No paper source was rerun, no result was added, and no new method or implementation
behavior is claimed. A separate code phase is planned to report ephemeral
client-observation notice status and request disposition, with a correlated local
outcome event where available. Those fields are not yet implemented or validated,
and cannot establish provider delivery, task completion, warning comprehension
or consent. Any later manuscript wording must follow the tested contract and keep
those limits explicit.

## Validation and handoff

Completed: inspect the accepted review and pinned source boundaries; check the
changed manuscript passages against that review; preserve the pre-existing
paper/ref.bib changes; add the review bibliography file to the manuscript's
bibliography list; locally reduce interaction-table column padding; and run
whitespace/citation-reference checks.

Pending for the integrated manuscript: response-code contract alignment and
final compilation after that code is tested. No PDF was generated or overwritten
in this revision phase. Final validation, commit integration and publication
decisions remain with the coordinating agent.
