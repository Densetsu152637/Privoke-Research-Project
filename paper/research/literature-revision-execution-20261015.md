# Literature-informed manuscript revision — 15 October 2026

## Goal and scope

User-selected scope: “Paper revisions plus response additions.” The original
request set a light ceiling for one goal:

> Can you make these revisions then (using a light ceiling for this one goal):
>
> 1. Sharpen the contribution statement. Emphasize version-bound updates, publication guards, client refresh and measured gains/regressions. Avoid implying that training elsewhere and running locally is itself new.
> 2. Expand the functional comparison. Distinguish sanitization, response recovery, acknowledged warnings, original-body forwarding and blocking. A correct WARN is not a prevented disclosure.
> 3. Qualify the literature table. Identify variants, metric definitions and evaluated populations.
> 4. Make practical utility an explicit gap. PriVoke still needs evidence about task completion, unnecessary restrictions, warning comprehension and reformulation effort. Detection and action agreement alone cannot establish usefulness. (these can be derived from additions to the responses that the PriVoke pipelines can make)

This is source-grounded manuscript work, not a new study or user-utility
experiment.

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
No paper source was rerun, no literature result was added, and no user-utility
outcome is claimed. A separate implementation now reports ephemeral
client-observation notice status and request disposition, with a correlated local
outcome event. The Methods description follows the tested contract while stating
that it cannot establish provider receipt, task completion, warning comprehension
or consent.

## Validation and handoff

Implementation alignment: code commit
1aefd62ef6197d39a7475964576804eb4fd2103c adds the client observation schema and
its contract at [utility-observations.md](../../docs/runtime/utility-observations.md).
The extension build passed. The scoped page-interceptor and content-script tests
passed 53/53 with exit code zero. These checks validate mechanics, not user
utility or a new browser study.

Completed: inspect the accepted review and pinned source boundaries; check the
changed manuscript passages against that review and the implemented contract;
preserve the pre-existing paper/ref.bib changes; add the review bibliography
file to the manuscript's bibliography list; locally reduce interaction-table
column padding; and run whitespace/citation-reference checks.

Final integrated acceptance: four compiler passes succeeded, all 13 rendered
pages passed both worker and coordinating-agent visual review, and all 22 font
entries are embedded without Type 3 fonts. The new PDF and its source, code,
test and rendering bindings are recorded in
[literature-revision-validation-20261015.json](literature-revision-validation-20261015.json).
The 53 focused host tests and extension build passed; no installed-browser,
performance or user-utility remeasurement was performed. Existing PDF evidence
and all earlier result history remain unchanged.
