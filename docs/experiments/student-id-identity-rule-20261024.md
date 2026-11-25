# Student-ID identity rule after the CHILD-category regression

Scope: detector layer (regex and NER, explicit layers `["regex","ner"]`, `regex_first=False`). Not LLM-only or full-product evidence.

## Trigger

Paired action-level analysis of the installed defaults (`research/wt-a-stats` bf5e24c1, `docs/experiments/detector-uncertainty-20261024.md`) found 72 personalized-synthetic positives moving from BLOCK to WARN under the new defaults because the regex layer no longer returned the CHILD category. BLOCK-only recall on that set fell from 1.000 to 0.928 (exact McNemar p < 0.001).

## Diagnosis

- All 72 rows come from one `school_form` template naming a student with an ID and a date of birth. The dates of birth (1956–2003) make them adult students. No personalized positive expects CHILD.
- The old regex gave S3 CHILD only from the bare word "student", so BLOCK was reached by an incorrect category. The new child rule (repair R4, commits ca565f19/dad5f30b) correctly requires a concrete fact about a minor, leaving only the S2 date-of-birth field and so WARN.
- The product rubric (`paper/research/clean-augmentation-rubric.json`) defines CHILD as a concrete fact about a particular child or minor. A student record with an identifier is identity information, which matches the rows' expected categories (full name, student ID, date of birth).

## Repair

Commit e70e3a2e adds `student_id`, an S3 IDENTITY rule in `extension/client-runtime/src/regex/rules_identity.py`. It needs a value of at least four characters containing a digit, either directly after "student ID/number" or after ", ID" / "(ID" within 60 characters of "student". The child rule is unchanged. Tests use author-written sentences, including the negatives "every student must show their ID", "student ID format", "student, ID required" and "user ID".

## Measurement (before = 55cbd1e5 defaults, after = e70e3a2e)

| Split | Rule | Before recall | After recall | FP before → after |
|---|---|---|---|---|
| personalized | BLOCK-only | 928/1000 | 1000/1000 | 0 → 0 |
| personalized | positive | 1000/1000 | 1000/1000 | 0 → 0 |
| dev-TUNE | BLOCK-only | 51/148 | 51/148 | 1 → 1 |
| dev-CHECK | BLOCK-only | 50/116 | 50/116 | 0 → 0 |
| openai | BLOCK-only | 373/500 | 373/500 | 30 → 30 |
| openai | positive (union) | 459/500 | 459/500 | 37 → 37 |

Personalized gained 72 BLOCK decisions and lost none (exact McNemar p = 4.2e-22). No other split changed, and no false positive was added anywhere.

## Limitations

- The recovery comes from one template: it confirms the mechanism, not that the rule generalises. Development and OpenAI rows did not change, so they give no independent support.
- Four OpenAI BLOCK losses (student mentions without an identifier) and four development BLOCK losses with another cause remain.
- The rule was added after the PIIMB final endpoint was scored, so held-out numbers describe the configuration without it.
