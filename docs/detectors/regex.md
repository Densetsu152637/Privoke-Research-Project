# Regex Rule Detector

> Source area: `extension/client-runtime/src/regex`. Commands retain their original working-directory assumptions; follow explicit directory instructions, or use this source area for component-local commands.

This directory contains layer 1 of the PriVoke client-runtime detector pipeline: deterministic regex and heuristic detection.

`RuleDetector.analyze(text)` returns `list[ClassificationResult]`. It does not merge its matches. The client runtime combines classifications while retaining one primary evidence span and all per-layer findings.

## Files

- `rule_detector.py`: compiles rules, collects matches, adds heuristics, deduplicates matches, and converts them to `ClassificationResult`.
- `rule_types.py`: `RuleDefinition`, `Downgrade`, `CompiledRule`, and `RuleMatch`.
- `rule_registry.py`: deterministic rule ordering.
- `rule_validators.py`: checksum and context validators attached to rules, and the context/shape tests used by validator downgrades.
- `rule_heuristics.py`: synthetic matches derived from aggregate match/text properties.
- `rules_visibility.py`: visibility-only cues.
- `rules_identity.py`: direct and structured identity patterns.
- `rules_identifiers.py`: labelled identifier values (`<qualifier> ID/number/no./#/code` followed by a value).
- `rules_location.py`: precise and quasi-location patterns.
- `rules_health.py`: medical and mental-health patterns.
- `rules_financial.py`: account, card, money, income, debt, and asset patterns.
- `rules_sensitive.py`: politics, religion, criminal, sexual, child, and third-party cues.
- `rules_context.py`: family, workplace, and timestamp context.

## Output Contract

Each regex or heuristic hit becomes:

```python
ClassificationResult(
    classification=Classification(...),
    section_of_text=matched_text,
    reasoning="Matched rule '<rule_name>'",
    span=(start, end),
    confidence=0.95,
    metadata={"rule_name": "<rule_name>"},
)
```

Heuristic matches use lower confidence values.

Rules map directly to `Sensitivity`, `Visibility`, and `Category` values. They should not return legacy severity/category strings.

## Current Heuristics

`rule_heuristics.py` adds synthetic matches for (prompt length alone is not evidence and is never used):

- two or more structured identity fields, as `S2` `IDENTITY`,
- short prompts with high-confidence `S3` matches, as concentrated sensitive data.

## Precision Rules

- Kin terms and `family` (`family_disclosure`) need a possessive determiner (my/our/his/her/their), optionally with up to two hyphen- or space-joined modifier words (`ex-wife`, `soon-to-be ex-husband`, `step-daughter`). Non-possessive self-statements such as "I have two kids" are intentionally not matched. `child` needs a possessive plus child noun, `aged N` (1-17), a possessive before `N-year-old`, or `N-year-old` followed by a person noun (son, girl, toddler, pupil...); object ages (`a 5-year-old laptop`) do not match, and bare "student"/"minor" no longer count.
- `financial_keyword` covers personal financial-state nouns only (salary, income, loan, mortgage, debt, balance, savings, net worth, credit score/history/report) after my/his/her/their with up to two modifier words (`my monthly salary`, `my bank account balance`); bare "my account"/"my bank" does not.
- `location_keyword` needs its connector (`live in/on/at/near`, `address is`, `address:`, `location in`) followed by a capture that is not a closed-class word (articles, pronouns, prepositions, conjunctions, auxiliaries).
- `student_id` (`S3` `IDENTITY`) needs an identifier value (4+ characters containing a digit) directly after `student ID/number`, or after `, ID`/`(ID` within 60 characters of `student` on the same sentence. It exists because bare "student" is not `CHILD` (students are often adults, and the `CHILD` rubric needs information about a particular child or minor): an identified student record is an identity disclosure, and a student who is explicitly a minor is still `CHILD` through the age cues. Generic mentions ("every student must show their ID", "student ID format") do not match.
- `structured_identity` values stay on one line and capture at most five tokens; a `phone` label needs a value starting with a digit, `+` or `(`.
- Validators reject shape-only hits: Luhn for card numbers, mod-97 for IBANs, mod-11 for NHS numbers, and issuable area/group/serial ranges for US SSNs (native and Presidio-derived rules). The Presidio alphanumeric driver-licence pattern needs five digits or a whole-word licence context term (`license`, `licence`, `lic`, `dl`, `cdl`); the ambiguous noun "driver" is not context. Context matching is word-bounded, never substring. The Presidio `mm/yy` date needs a date context word, so ratings like `7/10` do not match. A rule may also list `Downgrade`s (`rule_types.py`): when the checksum fails, the first downgrade whose test passes keeps the hit under its own rule name and a lower or context-conditioned sensitivity instead of dropping it. Luhn failure with a card word in context stays `S3` (`credit_card_unverified`); mod-97 failure with a banking word stays `S3` (`iban_unverified`), and otherwise a long number-like token (8+ characters, 5+ digits, at least one letter) is kept as `S2` `IDENTITY` (`unverified_number_identifier`); SSN failure with an SSN word stays `S3` (`ssn_unverified`). Short or mostly-letter tokens (`ab12cd`) and unlabelled digit runs are still dropped. The detector sees canonical text in which spaces between digits are already removed, so `4111 1111 1111 1111` reaches the rules as one digit run.
- Labelled identifiers (`labelled_identifier_sensitive` `S3`, `labelled_identifier_generic` `S2`, both `IDENTITY`, `rules_identifiers.py`): a value of identifier shape introduced by an explicit label. The label is a qualifier plus an identifier noun (`id`, `number`, `no.`, `num`, `code`, `ref`, `#`), also in `snake_case`/`camelCase`/key-value forms (`customer_id: ...`, `"passport_number": "..."`), a self-labelling document with a colon (`Passport: ...`, `ID card: ...`) or an identifier acronym (`SSN`, `TFN`, `MRN`). Government, health-insurance and payment qualifiers (passport, licence, national/identity, tax, social security, patient, medical record, health plan, insurance, beneficiary, bank, card) are `S3`; customer, client, account, member, employee, user, policy, claim, registration, plate, store/loyalty cards and reference qualifiers are `S2`. The value has a digit, 5-24 characters, is not a date, and its first token carries a digit (a letter-only first token must be a 1-3 letter prefix followed by a digit group), so `number is required` or `customer ID format` do not match. Any value shape is accepted, so identifiers in formats no checksum or country pattern recognises are found. Software licence names (`License: Apache-2.0`), order, build, ticket, part and promo codes are not qualifiers. This is also what recovers real labelled identifiers that the gated Presidio alphanumeric driver-licence pattern (above) no longer reports.
- `child` and `family_disclosure` were reviewed in the rework and left unchanged: no development row contains a first-person parenthood statement or a person-subject age statement that the possessive and `N-year-old <person noun>` cues miss, and restoring bare kin/child nouns would reintroduce the hits that were attributed to the wrong category. See [regex rework](../experiments/regex-rework-20261025.md).
- `password_assignment` ignores placeholder values (required, optional, none, null, true, false and similar); `social_handle` ignores chat mentions (`@here`, `@everyone`, `@channel`, `@all`); `license_plate` ignores standards identifiers such as `rfc-`, `cve-` and `iso-` numbers.
- Case handling: regex matching is case-insensitive (every rule compiles with `re.IGNORECASE`, `rule_types.py`, with no per-rule override), so capital-letter classes in patterns do not gate matches and capitalisation cannot distinguish proper nouns (`street_address`, `route_or_commute`, `vin`, `passport`). The default case-preserving input (`PRIVOKE_CASE_PRESERVING_DETECTORS`, on; `0` lowercases) therefore changes regex results not at all today (the case ablation found zero regex flips); it exists for NER. The semantic/LLM layer always receives lowercased text. See [installed detector precision](../experiments/detector-precision-installed-20261024.md).

## Visibility Rules

Workplace matching requires a personal employer/workplace declaration or a
structured employment field. Generic discussion of work, companies, or managers
does not by itself establish identity disclosure.

Amount and coarse-location rules likewise require a personal declaration or a
relevant labeled field. Public prices, generic origins and venue descriptions
do not alone establish a person's financial or residential disclosure. Direct
account, card, street-address and coordinate patterns remain separate rules.

Visibility-only rules use `Sensitivity.S0` and no categories. The hosted pipeline retains these `ALLOW` findings and combines their strongest known visibility with sensitive evidence. Request-level `visibility_hint` can further increase privacy restrictions without weakening an existing decision.

## Subagent Tasks

Rule-detector subagents should:

- add missing patterns in the concern-specific `rules_*.py` module,
- add false-positive counterexamples,
- keep rule definitions small and auditable,
- preserve enum-backed `Classification` mappings,
- add tests around both direct `RuleDetector` output and hosted `/analyze` behavior when selection semantics matter.
