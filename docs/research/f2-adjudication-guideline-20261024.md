# F2 adjudication guideline (frozen with the fresh sets, 2026-10-24)

Scope: labels for the natural-prompt set F2 (`docs/research/preregistration-detector-v2-20261024.md`, section 2; protocol `docs/research/fresh-evaluation-sources-20261024.md`, section 4.1). F2 is **unlabelled until a human completes this adjudication**. Raters see only an opaque item id and the prompt text, in shuffled order. They never see detector output, configuration names, the source dataset or any dataset-native flag.

## Question

Does the prompt contain personal data of an identifiable (real or plausibly real) person, of a type in the PriVoke taxonomy?

## Labels

- **P** (personal data present): the prompt contains at least one of: a person's full name or a name plus another identifier; a contact detail (email address, phone number, postal or street address) of a person or household; a government, tax, financial-account, card, insurance or medical-record number tied to a person; login credentials or an account handle tied to a person; a precise date of birth, location history or health, legal, religious, sexual or other sensitive attribute attributed to a named or otherwise identifiable person. The data may be of the writer or a third party.
- **N** (not present): none of the above. Includes generic questions about personal data, descriptions of data types without values, public-figure facts that are common knowledge (a celebrity or politician named in a question), company or product names, and code or text strings that only resemble identifiers.
- **U** (ambiguous): cannot be decided from the text. Includes placeholder or example values (`john.doe@example.com`, `555-0100`, "John Smith" style teaching examples), fictional characters, obviously fabricated test data, and public figures with attributes beyond common knowledge. U is analysed both ways (counted benign, excluded).

## Boundary rules

1. A bare first name or a single common surname alone is N. A first plus last name of a private-looking individual is P only if the prompt gives it as a real person's identity; a name in a clearly fictional story or role-play is U.
2. A public figure's name is N; a public figure's private contact detail is P.
3. Email, phone and address values are P unless they are placeholders or reserved example values (U).
4. Numbers that merely have an identifier-like format (dates, order numbers, version strings, IP addresses of servers, arithmetic) are N unless the prompt says they identify a person or account.
5. Pasted documents (CVs, emails, chat logs, forms): P if any person's identifying detail is present.
6. When unsure between P and U, choose U; when unsure between N and U, choose U. Do not use detector behaviour, length or topic as evidence.

## Rating record

One row per item: `item`, `label` in {P, N, U}, optional `note` (a category word only, never a quotation of personal data). Two independent raters; the user adjudicates every disagreement. If a model-assisted second rating is used it is recorded as such, uses a prompt unrelated to any detector, and the human adjudicates all disagreements plus a 10 % random sample of agreements. Cohen's kappa is reported on P versus not-P.

## Pool and audit sample

The review pool is the union of prompts flagged by any frozen configuration plus an audit sample: the first 400 items in the coordinator's seeded `audit_order` that no frozen configuration flags. The coordinator hands raters only the pooled items, repacked from the blinded packets. Prompts adjudicated P are reported as real-prompt detections, never as specificity.

## Privacy

Adjudication is local. Prompts that contain real-looking personal data are not quoted in any document, issue or paper; only opaque ids, labels and hashes leave the review environment. No re-identification attempt of any kind.
