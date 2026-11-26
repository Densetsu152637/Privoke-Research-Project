# Annotation guideline v2 (draft, 24 November 2026)

Status: **draft, provisional, no worked examples. The definition of `sensitive` below follows the Dual-Axis project's severity scale (S2 and S3 count as sensitive) and was approved by the user on 26 November 2026.** Decision D12 is unanswered: the user, or a human they choose, writes the matched-contrast worked examples and their labels, or approves unlabelled drafts and writes the labels. Until then this guideline ships without examples. No agent wrote any example, label or labelled prompt here. Each dated revision after the pilot lists the clarification and the disagreement that caused it. When a revision lands, root updates the pin of this file in `evaluation/s13_allowlist.json` in the same commit.

It supersedes the label definitions of section 2 of the [24 October protocol](annotation-protocol-20261024.md) for Stage 13a. The sampling, blinding, pilot and adjudication rules of the protocol carry over, except where the [marker decision](annotation-marker-decision-20261124.md) and the Stage 13 plan state otherwise.

## What you do

You label each prompt on your sheet from its text alone. You work alone, you do not discuss items with anyone before adjudication, and you do not use a language model, a search engine or any detector. You never see where a prompt came from. Work in blocks of 60 with a break between blocks. Leave no cell empty; the sheet validator rejects empty and invalid cells.

## The labels

Each row has these columns: `item_id`, `text` (given), then the six 1. **`sensitive`: `yes` or `no`.** *Approved by the user on 26 November 2026; it follows the Dual-Axis project's severity scale S0–S3.* Answer `yes` when the text reaches severity S2 or S3: it discloses information that, if misused, could cause reputational harm, targeting, fraud, unwanted contact or a safety risk. S2 (medium) covers misuse that could cause reputational harm, targeting, fraud, unwanted contact or moderate sensitivity. S3 (high) covers an explicit sensitive category together with direct identifiers, doxxing, threats, minors, or strong safety, financial or reputational risk. Answer `no` for S0 (nothing sensitive, or benign) and S1 (low sensitivity, such as a mild personal opinion or weak identifiers). Also answer `no` when the content is clearly fictional, invented as a placeholder or unfilled, or when it only names a sensitive topic. Do not decide from a topic keyword alone.
eyword alone.
2. **`subject`: whose information it is.**
   - `SELF`: the writer's own information.
   - `THIRD_PARTY`: a private person other than the writer.
   - `PUBLIC_FIGURE`: a person discussed in their public role.
   - `NONE`: the text discloses no person's information.
   - `UNCLEAR`: the text leaves open whose information it is. Use it only when you cannot tell.
3. **`audience`: the audience and context the text itself states.**
   - `P0` unrestricted public; `P1` broad semi-public community; `P2` access requires authentication but there is no closed invited recipient set; `P3` a closed invited group that includes other readers; `P4` only the writer.
   - `PU` when the text states no audience. First-person wording or the word "private" does not establish `P4`.
4. **`categories`: every category that applies**, from `HEALTH`, `POLITICS`, `RELIGION`, `CRIMINAL`, `FINANCIAL`, `SEXUAL`, `CHILD`, `LOCATION`, `IDENTITY`, `THIRD_PARTY`. Write several as `A|B`. Write `NONE` when the text discloses nothing that falls in a category; `NONE` cannot be combined with another value.
5. **`action`: what the product should do before the text goes to an external model provider.** `ALLOW` forwards silently; `WARN` asks the user first and then forwards; `BLOCK` does not transmit. Use your own judgement. You are not given the product's policy table.
6. **`notes`** (optional): evidence or doubt, free text. Notes stay on your local sheet and are never committed. Do not copy the prompt into your notes more than you must.

## Glossary

- **Disclose**: assert, as real, a fact about a person in the text. Asking for general advice about a topic does not disclose.
- **Actual versus invented**: a value is actual when the text presents it as real for a real person. Fictional, hypothetical, quoted-as-a-sample and clearly placeholder content is not actual.
- **Third party**: someone other than the writer who is not discussed in a public role.
- **Public role**: an office, profession or public act that the person has made public.
- **Closed group (`P3`)**: a set of invited readers that includes people other than the writer and the assistant.

## Worked examples

**[EXAMPLES PENDING, decision D12. No worked example has been written. The matched-contrast examples (public biography against private disclosure, fictional against real-person context, general advice against private history, explanation of a credential against a fake value, and the `subject` contrasts), with their labels, are written or approved by the user. The pilot does not start until this section is filled or the user states "no examples".]**

## Annotator declaration (template, one per annotator)

I confirm that:

1. I am labelling independently and will not discuss items before adjudication.
2. I will not use a language model, search engine or detector for any item.
3. I have recorded below any prior knowledge of PriVoke data, labels, rubrics or the template generator.
4. I understand that my labels will be committed without the prompt text, and that scores against a software system will be reported at an aggregate level.

Prior familiarity (none, or describe): ____________________________________

Annotator (private list, not in Git): ____________________  Date: ____________

## Revision log

| Date | Change | Disagreement that caused it |
| --- | --- | --- |
| 2026-11-24 | Draft v2.0, no examples; `sensitive` definition is an agent draft pending user approval | none |
| 2026-11-26 | `sensitive` defined from the Dual-Axis severity scale (S2 and S3 are `yes`, S0 and S1 are `no`); approved by the user | none (before the pilot) |
