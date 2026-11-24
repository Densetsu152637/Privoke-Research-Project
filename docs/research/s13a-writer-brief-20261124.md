# Stage 13a writer brief (draft, 24 November 2026)

Status: **provisional.** Decisions D1 (source of the prompts), D2 (annotators) and D4 (ethics) are unanswered. This brief applies only if the user chooses recruited writers (D1). It is committed before any writer starts, and the pin of its committed bytes is in `evaluation/s13_allowlist.json`. If the user revises it, a dated revision supersedes this file and root updates the pin in the same commit.

The brief contains no example prompt. Do not ask anyone to write one for it.

## Who writes

Writers are neither annotators nor PriVoke developers. A writer must not read PriVoke code, datasets, rubrics, labels, model outputs or any earlier evaluation set, and must not use a detector, a search engine or a language model to write or to check a prompt. Each writer signs the declaration at the end before delivering prompts. The coordinator keeps the list of people outside the repository.

## What to write

Write short prompts of the kind a person might type into a chat assistant, in English, one or a few sentences each, with **invented people and invented values only**. Never use a real person, a real account, a real number or a real address, including your own. Do not copy text from any source.

Each prompt carries four declared values, which the coordinator uses to check the quotas. The declared values are the writer's intent, not the final label: the annotators label every prompt independently.

| Column | Values |
| --- | --- |
| `text` | the prompt |
| `category` | `HEALTH`, `POLITICS`, `RELIGION`, `CRIMINAL`, `FINANCIAL`, `SEXUAL`, `CHILD`, `LOCATION`, `IDENTITY`, `THIRD_PARTY`, or `NONE` |
| `audience` | `P0` (unrestricted public), `P1` (broad semi-public community), `P2` (needs authentication, no closed recipient set), `P3` (closed invited group that includes other readers), `P4` (only the writer), `PU` (no audience stated) |
| `sensitive` | `yes` if the prompt discloses (invented) personal information that would be harmful to send to an outside provider; `no` otherwise |

## Quotas

The coordinator checks these with `fresh_set.py --check-quotas` after duplicates and contaminated prompts are removed:

- at least **390 usable prompts** in total (360 main items plus a 30-item pilot). Deliver at least **450** so that removals do not push the set under 390;
- at least **45% of the usable prompts** declared `sensitive = yes`;
- at least **20 usable prompts for each of the ten categories**, counting every prompt whose declared category is that category (`NONE` is not a category for this rule);
- spread the prompts across all six audience values, and across both `sensitive` values inside each category. The coordinator reports the counts per category, audience and sensitivity. No other minimum is enforced.

Benign prompts (`sensitive = no`) should be realistic and should include prompts that sit close to a sensitive topic without disclosing anything, so that the set tests judgement and not keywords. Vary length, tone and wording; do not reuse templates.

## Delivery

Deliver one file per writer, CSV or JSONL, with the four columns above, to the coordinator's Git-ignored folder. Do not put prompts in Git, e-mail, issue trackers or chat threads that the project stores. Writers receive no PriVoke output about their prompts at any time.

## Writer declaration (template, one per writer)

I confirm that:

1. I did not write any PriVoke code, dataset, rubric or label, and I did not read PriVoke data, rubrics or outputs for this task.
2. Every person, account, number and address in my prompts is invented and none is real.
3. I did not copy any prompt from another source and I did not use a detector, search engine or language model to write or check a prompt.
4. I understand that the prompts will be labelled by other people and scored against a software system, and that my name will not be published.

Writer (private list, not in Git): ____________________  Date: ____________
