# NER post-filter: span cleaning and category combination (detector layers)

Detector-layer experiment (regex and spaCy `en_core_web_sm` NER). This is not LLM-only or semantic evidence.

Change: `PRIVOKE_NER_POSTFILTER=1` (`GLOBAL_CONFIG.ner_postfilter`, default off; now default on since 6a0c9ca3) routes spaCy entities through
`extension/client-runtime/src/NER/ner_postfilter.py`, then emits only the surviving entities with a rule-decided sensitivity
(`metadata["postfilter_rule"]` records the deciding rule). It composes with `PRIVOKE_CASE_PRESERVING_DETECTORS`; with the flag off the
NER output is unchanged.

## Method and anti-overfitting protocol

- `development.jsonl` (502 rows) is split by `sha256(group_id) % 2`: dev-TUNE (parity 0, 267 rows, 148 positive) and dev-CHECK
  (parity 1, 235 rows, 116 positive). Rules were designed looking only at dev-TUNE and the personalized synthetic set. They were
  committed (freeze commit `50fc51e6`) before any dev-CHECK or openai number was computed, and no rule was changed afterwards.
  `final.jsonl` was not opened. This document describes two versions: **v1** (frozen commit `50fc51e6`, results below under "Results v1") and
  **v2** (post-review revision, section "Post-review revision v2"). v2 was changed after a critic review using author-written probe sentences, not
  dev-CHECK/openai rows; but because those sets were already measured, **v2 dev-CHECK and openai numbers are post-review and no longer strictly held-out**.
- Evaluation: host Python, `pipeline.analyse_text(layers=["regex","ner"], regex_first=False)` per prompt, asserting both layers ran
  with status ok. Positive = any hit with sensitivity != S0 or categories. NER-only = ner-layer hits; union = regex or NER. Regex output is
  unchanged by the flag. Mean latency for regex+NER stays 28 to 34 ms/prompt in every config.
- Downgrading: under this positive definition S1 counts as positive, so downgrading an uncorroborated single name to S1 changes no confusion
  cell; only dropping (S0) moves the metrics. `postfilter(..., weak_person=Sensitivity.S1)` keeps the S1 variant available.

## Stage 1: per-span rules (v2; general principles, none names a token or phrase)

| Rule | Principle |
|---|---|
| `placeholder` | masking conventions: letters collapse to one repeated letter (`XXXX`), a span with no letters, a capitalised single letter pluralised with a lower-case `s` (`Xs`, `Ns`, `Zs`: any letter), or a span inside `[..]`, `<..>`, `{..}` template delimiters |
| `identifier` | e-mail/URL/underscore span, or a token with >= 2 digits and >= 2 letters (code-like); structured identifiers belong to the regex layer |
| `structural` | span in a markdown heading line, or in a title-case line with >= 2 other words, no verb, no digits, no `:` and no sentence-final punctuation (a heading has no sentence context). Multi-token or cue-introduced PERSON spans are exempt (a name inside a heading is still a name); inert on lowercase text |
| `short_acronym` | place <= 3 letters, or organisation <= 4 letters, needs a locating/affiliation preposition (or a `State:`-style field label for places) just before it |
| `common_phrase` | single-token PERSON only: the word is in the model's installed lemma-index word list (offline) and the tagger reads the lower-cased token, in isolation, without a proper-noun reading, and no context cue corroborates it |

Word-list source: the `lemma_index` table of spaCy `en_core_web_sm`'s rule lemmatizer (WordNet-derived, already installed, no network).
It also contains many proper nouns, which is why the lower-cased POS reading is required in addition. The word list is cached per model
identity (`meta` language, name, version), not per object.

## Stage 2: category-combination table (v2; `COMBINATION_RULES`, first matching rule decides)

"Independently corroborated" means evidence about the entity itself: a PERSON that is multi-token, cue-introduced or recurring; a place/organisation
with a personal-relation cue. A bare locating preposition does not count.

| Order | Rule | Principle | Result |
|---|---|---|---|
| 1 | `person_linked` | a person co-occurring with a place or organisation, when either side is independently corroborated | S2 |
| 2 | `place_org_linked` | a place or organisation co-occurring with a person, when either side is independently corroborated | S2 |
| 3 | `person_corroborated` | multi-token, cue-introduced or recurring name. Cues: self-introduction, salutation/sign-off, honorific, a possessed role noun (list plus dependency check: apposition/compound of a role noun carrying `my/our/his/her/their`), labelled field (`Name:`, `X (patient)`), possessor of a personal-data noun, speaker label (line-initial name, colon, quote or running sentence) | S2 |
| 4 | `relation_tied` | place/organisation tied to a person by a relation cue: "I live in", "I'm from", "I work at", `my/our/his/her/their` + home/office/employer/school/clinic, "I am a `<role>` at/for/with", "my `<role>` at" | default (place S2, ORG S1) |
| 5 | `relation_anchored` | place/organisation in the same prompt as a relation-tied one (employer plus city) | default |
| 6 | `address_shape` | FAC/LOC span directly beside a number (street plus house number) | S2 |
| 7 | `weak_person` | single uncorroborated PERSON token | **S1** (v1: dropped); `weak_person=None` drops it |
| 8 | `lone_place_org` | lone place or organisation | dropped (S0) |

A `place_cluster` rule (two distinct places) was drafted and removed during v1 design: it kept generic geography facts such as
"Berlin is the capital of Germany" and had no benefit on dev-TUNE.

Cross-layer combination (person plus a regex contact/ID category) was not implemented: layers run independently in
`pipeline.analyse_text` and the NER detector sees no regex output. In the regex+NER union it is implicit, since any regex hit already makes the
prompt positive. The post-filter carries its own small generic cue set.

## Results v1 (frozen commit `50fc51e6`; all detector-layer results)

Configs: lowercase = current default; case-preserving = `PRIVOKE_CASE_PRESERVING_DETECTORS=1`; "+ postfilter" adds `PRIVOKE_NER_POSTFILTER=1`.
dev-TUNE and personalized were used to design the rules; dev-CHECK and openai were not.

**NER layer only**

| Split | n (pos) | Config | TP | TN | FP | FN | Recall | Specificity |
|---|---|---|---|---|---|---|---|---|
| dev-TUNE | 267 (148) | lowercase (default) | 35 | 117 | 2 | 113 | 0.236 | 0.983 |
| dev-TUNE | 267 (148) | case-preserving | 71 | 100 | 19 | 77 | 0.480 | 0.840 |
| dev-TUNE | 267 (148) | case-preserving + postfilter | 33 | 117 | 2 | 115 | 0.223 | 0.983 |
| dev-TUNE | 267 (148) | lowercase + postfilter | 18 | 119 | 0 | 130 | 0.122 | 1.000 |
| dev-CHECK | 235 (116) | lowercase (default) | 20 | 115 | 4 | 96 | 0.172 | 0.966 |
| dev-CHECK | 235 (116) | case-preserving | 50 | 101 | 18 | 66 | 0.431 | 0.849 |
| dev-CHECK | 235 (116) | case-preserving + postfilter | 23 | 118 | 1 | 93 | 0.198 | 0.992 |
| dev-CHECK | 235 (116) | lowercase + postfilter | 10 | 118 | 1 | 106 | 0.086 | 0.992 |
| personalized | 2000 (1000) | lowercase (default) | 800 | 1000 | 0 | 200 | 0.800 | 1.000 |
| personalized | 2000 (1000) | case-preserving | 871 | 919 | 81 | 129 | 0.871 | 0.919 |
| personalized | 2000 (1000) | case-preserving + postfilter | 693 | 1000 | 0 | 307 | 0.693 | 1.000 |
| personalized | 2000 (1000) | lowercase + postfilter | 520 | 1000 | 0 | 480 | 0.520 | 1.000 |
| openai | 1000 (500) | lowercase (default) | 145 | 492 | 8 | 355 | 0.290 | 0.984 |
| openai | 1000 (500) | case-preserving | 241 | 434 | 66 | 259 | 0.482 | 0.868 |
| openai | 1000 (500) | case-preserving + postfilter | 79 | 499 | 1 | 421 | 0.158 | 0.998 |
| openai | 1000 (500) | lowercase + postfilter | 58 | 499 | 1 | 442 | 0.116 | 0.998 |

**regex + NER union**

| Split | n (pos) | Config | TP | TN | FP | FN | Recall | Specificity |
|---|---|---|---|---|---|---|---|---|
| dev-TUNE | 267 (148) | lowercase (default) | 112 | 115 | 4 | 36 | 0.757 | 0.966 |
| dev-TUNE | 267 (148) | case-preserving | 127 | 98 | 21 | 21 | 0.858 | 0.824 |
| dev-TUNE | 267 (148) | case-preserving + postfilter | 114 | 115 | 4 | 34 | 0.770 | 0.966 |
| dev-TUNE | 267 (148) | lowercase + postfilter | 107 | 117 | 2 | 41 | 0.723 | 0.983 |
| dev-CHECK | 235 (116) | lowercase (default) | 79 | 113 | 6 | 37 | 0.681 | 0.950 |
| dev-CHECK | 235 (116) | case-preserving | 95 | 99 | 20 | 21 | 0.819 | 0.832 |
| dev-CHECK | 235 (116) | case-preserving + postfilter | 82 | 116 | 3 | 34 | 0.707 | 0.975 |
| dev-CHECK | 235 (116) | lowercase + postfilter | 77 | 116 | 3 | 39 | 0.664 | 0.975 |
| personalized | 2000 (1000) | lowercase (default) | 1000 | 1000 | 0 | 0 | 1.000 | 1.000 |
| personalized | 2000 (1000) | case-preserving | 1000 | 919 | 81 | 0 | 1.000 | 0.919 |
| personalized | 2000 (1000) | case-preserving + postfilter | 1000 | 1000 | 0 | 0 | 1.000 | 1.000 |
| personalized | 2000 (1000) | lowercase + postfilter | 1000 | 1000 | 0 | 0 | 1.000 | 1.000 |
| openai | 1000 (500) | lowercase (default) | 463 | 458 | 42 | 37 | 0.926 | 0.916 |
| openai | 1000 (500) | case-preserving | 471 | 407 | 93 | 29 | 0.942 | 0.814 |
| openai | 1000 (500) | case-preserving + postfilter | 459 | 465 | 35 | 41 | 0.918 | 0.930 |
| openai | 1000 (500) | lowercase + postfilter | 456 | 465 | 35 | 44 | 0.912 | 0.930 |

**NER entity counts by label (entities emitted by the NER layer)**

| Split | Config | PERSON | ORG | GPE | LOC | FAC |
|---|---|---|---|---|---|---|
| tune | lowercase (default) | 24 | 10 | 7 | 0 | 0 |
| tune | case-preserving | 51 | 51 | 20 | 3 | 5 |
| tune | case-preserving + postfilter | 35 | 12 | 5 | 2 | 5 |
| tune | lowercase + postfilter | 19 | 1 | 0 | 0 | 0 |
| check | lowercase (default) | 15 | 9 | 3 | 1 | 0 |
| check | case-preserving | 39 | 46 | 6 | 4 | 1 |
| check | case-preserving + postfilter | 25 | 3 | 3 | 3 | 1 |
| check | lowercase + postfilter | 11 | 0 | 0 | 1 | 0 |
| personalized | lowercase (default) | 662 | 209 | 228 | 1 | 1 |
| personalized | case-preserving | 776 | 808 | 332 | 1 | 92 |
| personalized | case-preserving + postfilter | 696 | 145 | 126 | 0 | 87 |
| personalized | lowercase + postfilter | 520 | 1 | 79 | 0 | 1 |
| openai | lowercase (default) | 89 | 28 | 65 | 3 | 2 |
| openai | case-preserving | 111 | 229 | 88 | 2 | 9 |
| openai | case-preserving + postfilter | 58 | 6 | 18 | 0 | 8 |
| openai | lowercase + postfilter | 44 | 1 | 18 | 1 | 0 |

On the held-out sets (dev-CHECK, openai), case-preserving + postfilter keeps most of case-preservation's recall gain over lowercase in the union
(dev-CHECK 0.707 vs 0.681 lowercase and 0.819 unfiltered case; openai 0.918 vs 0.926 and 0.942) while specificity is higher than both
(dev-CHECK 0.975 vs 0.950 and 0.832; openai 0.930 vs 0.916 and 0.814). The cost is NER-only recall, which falls to 0.198 (dev-CHECK) and
0.158 (openai) because lone ORG/GPE/single names are no longer sensitive on their own. On personalized the union is 1.000/1.000 in both
filtered configs: the regex layer alone already covers all of its positives.

## Per-rule ablation v1 (case-preserving, held-out sets)

Each cell is the change in FP / TP when that rule alone is switched off: positive FP means the rule was removing false positives, negative TP
means it was preserving true positives (a keeping rule that is switched off falls through to `weak_person` or `lone_place_org`). Stage-1 rules
are ablated inside a span-only configuration (all combination rules off); combination rules inside the full configuration.
Reference points (FP / TP): dev-CHECK raw NER 18 / 50 (union 20 / 95), span-only NER 6 / 34 (union 8 / 90), full NER 1 / 23 (union 3 / 82);
openai raw NER 66 / 241 (union 93 / 471), span-only NER 16 / 133 (union 49 / 464), full NER 1 / 79 (union 35 / 459).

| Rule | dev-CHECK NER FP / TP | dev-CHECK union FP / TP | openai NER FP / TP | openai union FP / TP |
|---|---|---|---|---|
| -placeholder | +0 / +0 | +0 / +0 | +0 / +2 | +0 / +0 |
| -identifier | +0 / +2 | +0 / +0 | +1 / +41 | +1 / +3 |
| -structural | +0 / +0 | +0 / +0 | +0 / +0 | +0 / +0 |
| -short_acronym | +4 / +5 | +4 / +3 | +47 / +8 | +41 / +0 |
| -common_phrase | +3 / +7 | +3 / +2 | +1 / +7 | +1 / +0 |
| -person_linked | +0 / +0 | +0 / +0 | +0 / +0 | +0 / +0 |
| -place_org_linked | +0 / +0 | +0 / +0 | +0 / +0 | +0 / +0 |
| -person_corroborated | +0 / -17 | +0 / -5 | +0 / -49 | +0 / -8 |
| -relation_tied | +0 / +0 | +0 / +0 | +0 / -16 | +0 / -3 |
| -relation_anchored | +0 / +0 | +0 / +0 | +0 / +0 | +0 / +0 |
| -address_shape | -1 / +0 | -1 / +0 | +0 / -7 | +0 / +0 |
| -weak_person | +0 / +1 | +0 / +1 | +2 / +5 | +2 / +0 |
| -lone_place_org | +5 / +10 | +5 / +7 | +13 / +49 | +12 / +5 |

Row-level metrics understate `person_linked` and `place_org_linked`: when disabled, a person-linked place is dropped but the prompt stays positive
through the person. Their effect is on emitted entities. Entities emitted by each keeping rule (case-preserving + postfilter):

| Split | person_linked | place_org_linked | person_corroborated | relation_tied | relation_anchored | address_shape |
|---|---|---|---|---|---|---|
| tune | 14 | 22 | 21 | 0 | 0 | 2 |
| check | 7 | 9 | 18 | 0 | 0 | 1 |
| personalized | 213 | 354 | 483 | 0 | 0 | 4 |
| openai | 8 | 7 | 50 | 17 | 1 | 7 |

On the design sets, `placeholder` (30 FP) and `short_acronym` (27 FP) remove all of personalized's span-level false positives (mask runs and short
country acronyms); the same two rules do nothing on dev-CHECK (`placeholder`) or are weakly useful there.

## Residual false positives (v1, case-preserving)

- openai: union FP 35, of which 34 are regex-only (unchanged here). The single NER-only FP row is a pair of pet names ("Sparky" PERSON plus
  "Fluffy" tagged ORG) linked by `person_linked`. dev-CHECK: union FP 3, one NER-only (a table cell "Asia" tagged LOC beside a digit, via `address_shape`).
- Classes the rules cannot see: capitalised non-person names used as names (pets, products), table cells in non-prose layouts where the tagger's
  lower-cased reading is unreliable, and organisation/place names that look like given names.

## Residual false negatives (v1, cost of the filter)

- Lone places/organisations in records (`State: MD`, a first name alone in a table row) and uncorroborated single names ("reported to X at ...")
  are dropped by design; this is where dev-TUNE/CHECK NER-only recall is lost.
- Lexicon collisions: names and cities that the installed word list and tagger read as ordinary words in isolation (for example lower-cased
  "denver" or "austin") lose place status when no locating preposition precedes them; a two-word name of ordinary words ("Rose Baker") is
  dropped unless a cue or recurrence corroborates it.
- Lowercase input: title-case heading detection is inert and all-caps reasoning is unavailable; remaining rules still apply, but NER-only recall is lower
  (lowercase + postfilter union recall 0.664 dev-CHECK, 0.912 openai).

## Post-review revision v2

Critic findings (from author-written probe sentences) were applied after the v1 freeze. Changes:

1. `weak_person` keeps uncorroborated single names at S1 instead of dropping them (third-party names such as "a reference letter for Hannah" stay flagged).
   Under the positive definition S1 counts as positive, so this restores some false positives; it is a recall-first choice.
2. One shared possessive set (`my/our/his/her/their`) for person, place and organisation cues; new role-affiliation cues ("I am a nurse at X", "my doctor at X");
   the kinship list was replaced by a broad role-noun list plus a dependency check (apposition/compound/modifier of a role noun that carries a possessive).
3. `common_phrase` applies to single-token PERSON only.
4. `structural` exempts multi-token or cue-introduced PERSON spans.
5. `person_linked` / `place_org_linked` need at least one side independently corroborated ("Napoleon was defeated at Waterloo" no longer lifts both).
6. The lexicon cache is keyed by model meta, not by object identity.
7. De-templating: the `Xs` mask is now described and tested as a general masking convention (any capitalised letter, pluralised); the `(full name)` and
   `Name: "` cues were replaced by general labelled-field and speaker-label handling. The dev-TUNE name used in an earlier test was replaced by an author-chosen one.
8. Recall-guard, lexicon-cache and `analyse_text` (both flags) tests were added (35 tests in `test_ner_postfilter.py`).
9. The measurement harness is committed as `evaluation/compare_ner_postfilter.py` (see Reproduction).

v2 dev-CHECK and openai numbers are **post-review** and no longer strictly held-out. No rule was tuned on their rows.

### v1 vs v2

**regex + NER union: v1 (frozen, `50fc51e6`) vs v2 (revised)** (TP/TN/FP/FN, recall, specificity)

| Split | Config | v1 | v1 rec | v1 spec | v2 | v2 rec | v2 spec |
|---|---|---|---|---|---|---|---|
| dev-TUNE | case-preserving + postfilter | 114/115/4/34 | 0.770 | 0.966 | 118/113/6/30 | 0.797 | 0.950 |
| dev-TUNE | lowercase + postfilter | 107/117/2/41 | 0.723 | 0.983 | 109/117/2/39 | 0.736 | 0.983 |
| dev-CHECK (post-review) | case-preserving + postfilter | 82/116/3/34 | 0.707 | 0.975 | 83/113/6/33 | 0.716 | 0.950 |
| dev-CHECK (post-review) | lowercase + postfilter | 77/116/3/39 | 0.664 | 0.975 | 77/116/3/39 | 0.664 | 0.975 |
| personalized | case-preserving + postfilter | 1000/1000/0/0 | 1.000 | 1.000 | 1000/1000/0/0 | 1.000 | 1.000 |
| personalized | lowercase + postfilter | 1000/1000/0/0 | 1.000 | 1.000 | 1000/1000/0/0 | 1.000 | 1.000 |
| openai (post-review) | case-preserving + postfilter | 459/465/35/41 | 0.918 | 0.930 | 459/463/37/41 | 0.918 | 0.926 |
| openai (post-review) | lowercase + postfilter | 456/465/35/44 | 0.912 | 0.930 | 457/463/37/43 | 0.914 | 0.926 |

**NER layer only: v1 (frozen, `50fc51e6`) vs v2 (revised)** (TP/TN/FP/FN, recall, specificity)

| Split | Config | v1 | v1 rec | v1 spec | v2 | v2 rec | v2 spec |
|---|---|---|---|---|---|---|---|
| dev-TUNE | case-preserving + postfilter | 33/117/2/115 | 0.223 | 0.983 | 41/115/4/107 | 0.277 | 0.966 |
| dev-TUNE | lowercase + postfilter | 18/119/0/130 | 0.122 | 1.000 | 22/119/0/126 | 0.149 | 1.000 |
| dev-CHECK (post-review) | case-preserving + postfilter | 23/118/1/93 | 0.198 | 0.992 | 24/115/4/92 | 0.207 | 0.966 |
| dev-CHECK (post-review) | lowercase + postfilter | 10/118/1/106 | 0.086 | 0.992 | 11/118/1/105 | 0.095 | 0.992 |
| personalized | case-preserving + postfilter | 693/1000/0/307 | 0.693 | 1.000 | 695/1000/0/305 | 0.695 | 1.000 |
| personalized | lowercase + postfilter | 520/1000/0/480 | 0.520 | 1.000 | 555/1000/0/445 | 0.555 | 1.000 |
| openai (post-review) | case-preserving + postfilter | 79/499/1/421 | 0.158 | 0.998 | 85/497/3/415 | 0.170 | 0.994 |
| openai (post-review) | lowercase + postfilter | 58/499/1/442 | 0.116 | 0.998 | 64/497/3/436 | 0.128 | 0.994 |

### Full v2 tables

**NER layer only**

| Split | n (pos) | Config | TP | TN | FP | FN | Recall | Specificity |
|---|---|---|---|---|---|---|---|---|
| tune | 267 (148) | lowercase | 35 | 117 | 2 | 113 | 0.236 | 0.983 |
| tune | 267 (148) | case-preserving | 71 | 100 | 19 | 77 | 0.480 | 0.840 |
| tune | 267 (148) | case-preserving + postfilter | 41 | 115 | 4 | 107 | 0.277 | 0.966 |
| tune | 267 (148) | lowercase + postfilter | 22 | 119 | 0 | 126 | 0.149 | 1.000 |
| check | 235 (116) | lowercase | 20 | 115 | 4 | 96 | 0.172 | 0.966 |
| check | 235 (116) | case-preserving | 50 | 101 | 18 | 66 | 0.431 | 0.849 |
| check | 235 (116) | case-preserving + postfilter | 24 | 115 | 4 | 92 | 0.207 | 0.966 |
| check | 235 (116) | lowercase + postfilter | 11 | 118 | 1 | 105 | 0.095 | 0.992 |
| personalized | 2000 (1000) | lowercase | 800 | 1000 | 0 | 200 | 0.800 | 1.000 |
| personalized | 2000 (1000) | case-preserving | 871 | 919 | 81 | 129 | 0.871 | 0.919 |
| personalized | 2000 (1000) | case-preserving + postfilter | 695 | 1000 | 0 | 305 | 0.695 | 1.000 |
| personalized | 2000 (1000) | lowercase + postfilter | 555 | 1000 | 0 | 445 | 0.555 | 1.000 |
| openai | 1000 (500) | lowercase | 145 | 492 | 8 | 355 | 0.290 | 0.984 |
| openai | 1000 (500) | case-preserving | 241 | 434 | 66 | 259 | 0.482 | 0.868 |
| openai | 1000 (500) | case-preserving + postfilter | 85 | 497 | 3 | 415 | 0.170 | 0.994 |
| openai | 1000 (500) | lowercase + postfilter | 64 | 497 | 3 | 436 | 0.128 | 0.994 |

**regex + NER union**

| Split | n (pos) | Config | TP | TN | FP | FN | Recall | Specificity |
|---|---|---|---|---|---|---|---|---|
| tune | 267 (148) | lowercase | 112 | 115 | 4 | 36 | 0.757 | 0.966 |
| tune | 267 (148) | case-preserving | 127 | 98 | 21 | 21 | 0.858 | 0.824 |
| tune | 267 (148) | case-preserving + postfilter | 118 | 113 | 6 | 30 | 0.797 | 0.950 |
| tune | 267 (148) | lowercase + postfilter | 109 | 117 | 2 | 39 | 0.736 | 0.983 |
| check | 235 (116) | lowercase | 79 | 113 | 6 | 37 | 0.681 | 0.950 |
| check | 235 (116) | case-preserving | 95 | 99 | 20 | 21 | 0.819 | 0.832 |
| check | 235 (116) | case-preserving + postfilter | 83 | 113 | 6 | 33 | 0.716 | 0.950 |
| check | 235 (116) | lowercase + postfilter | 77 | 116 | 3 | 39 | 0.664 | 0.975 |
| personalized | 2000 (1000) | lowercase | 1000 | 1000 | 0 | 0 | 1.000 | 1.000 |
| personalized | 2000 (1000) | case-preserving | 1000 | 919 | 81 | 0 | 1.000 | 0.919 |
| personalized | 2000 (1000) | case-preserving + postfilter | 1000 | 1000 | 0 | 0 | 1.000 | 1.000 |
| personalized | 2000 (1000) | lowercase + postfilter | 1000 | 1000 | 0 | 0 | 1.000 | 1.000 |
| openai | 1000 (500) | lowercase | 463 | 458 | 42 | 37 | 0.926 | 0.916 |
| openai | 1000 (500) | case-preserving | 471 | 407 | 93 | 29 | 0.942 | 0.814 |
| openai | 1000 (500) | case-preserving + postfilter | 459 | 463 | 37 | 41 | 0.918 | 0.926 |
| openai | 1000 (500) | lowercase + postfilter | 457 | 463 | 37 | 43 | 0.914 | 0.926 |

**NER entities by label**

| Split | Config | PERSON | ORG | GPE | LOC | FAC |
|---|---|---|---|---|---|---|
| tune | lowercase | 24 | 10 | 7 | 0 | 0 |
| tune | case-preserving | 51 | 51 | 20 | 3 | 5 |
| tune | case-preserving + postfilter | 44 | 14 | 3 | 2 | 5 |
| tune | lowercase + postfilter | 23 | 0 | 0 | 0 | 0 |
| check | lowercase | 15 | 9 | 3 | 1 | 0 |
| check | case-preserving | 39 | 46 | 6 | 4 | 1 |
| check | case-preserving + postfilter | 33 | 4 | 2 | 3 | 1 |
| check | lowercase + postfilter | 12 | 0 | 0 | 1 | 0 |
| personalized | lowercase | 662 | 209 | 228 | 1 | 1 |
| personalized | case-preserving | 776 | 808 | 332 | 1 | 92 |
| personalized | case-preserving + postfilter | 716 | 277 | 244 | 0 | 87 |
| personalized | lowercase + postfilter | 555 | 2 | 112 | 0 | 1 |
| openai | lowercase | 89 | 28 | 65 | 3 | 2 |
| openai | case-preserving | 111 | 229 | 88 | 2 | 9 |
| openai | case-preserving + postfilter | 67 | 8 | 20 | 0 | 8 |
| openai | lowercase + postfilter | 51 | 2 | 17 | 1 | 0 |

### v2 per-rule ablation (case-preserving, post-review sets)

Same convention as the v1 ablation. With `weak_person` at S1, disabling a keeping rule no longer removes a prompt from the positives (the name falls to S1),
so those rules now differ in sensitivity (S2 versus S1) rather than at row level.

**Ablation, check (case-preserving; delta when the rule is switched off)**

| Rule | NER dFP | NER dTP | union dFP | union dTP |
|---|---|---|---|---|
| -placeholder | +0 | +0 | +0 | +0 |
| -identifier | +0 | +2 | +0 | +0 |
| -structural | +0 | +0 | +0 | +0 |
| -short_acronym | +7 | +6 | +7 | +3 |
| -common_phrase | +2 | +2 | +2 | +0 |
| -person_linked | +0 | +0 | +0 | +0 |
| -place_org_linked | +0 | +0 | +0 | +0 |
| -person_corroborated | +0 | +0 | +0 | +0 |
| -relation_tied | +0 | +0 | +0 | +0 |
| -relation_anchored | +0 | +0 | +0 | +0 |
| -address_shape | -1 | +0 | -1 | +0 |
| -weak_person | +0 | +0 | +0 | +0 |
| -lone_place_org | +5 | +15 | +5 | +9 |

**Ablation, openai (case-preserving; delta when the rule is switched off)**

| Rule | NER dFP | NER dTP | union dFP | union dTP |
|---|---|---|---|---|
| -placeholder | +0 | +2 | +0 | +0 |
| -identifier | +1 | +41 | +1 | +3 |
| -structural | +0 | +0 | +0 | +0 |
| -short_acronym | +48 | +34 | +42 | +3 |
| -common_phrase | +1 | +1 | +1 | +0 |
| -person_linked | +0 | +0 | +0 | +0 |
| -place_org_linked | +0 | +0 | +0 | +0 |
| -person_corroborated | +0 | +0 | +0 | +0 |
| -relation_tied | +0 | -14 | +0 | -3 |
| -relation_anchored | +0 | +0 | +0 | +0 |
| -address_shape | +0 | -7 | +0 | +0 |
| -weak_person | +0 | +0 | +0 | +0 |
| -lone_place_org | +13 | +54 | +12 | +5 |

Entities emitted per deciding rule, and their sensitivity (v2, case-preserving + postfilter):

| Split | S2 entities | S1 entities | person_linked | place_org_linked | person_corroborated | relation_tied | relation_anchored | address_shape | weak_person |
|---|---|---|---|---|---|---|---|---|---|
| tune | 57 | 11 | 10 | 19 | 25 | 1 | 1 | 3 | 9 |
| check | 38 | 5 | 6 | 8 | 22 | 0 | 0 | 2 | 5 |
| personalized | 1322 | 2 | 335 | 604 | 379 | 0 | 0 | 4 | 2 |
| openai | 87 | 16 | 7 | 6 | 50 | 18 | 5 | 7 | 10 |

### Critic probe set (34 author-written sentences: 18 personal, 16 benign; NER layer through `analyse_text`)

| Version | Personal sentences flagged | Benign sentences flagged |
|---|---|---|
| raw NER, case-preserving (no postfilter) | 14 / 18 | 13 / 16 |
| case-preserving + postfilter v1 | 10 / 18 | 2 / 16 |
| case-preserving + postfilter v2 | 14 / 18 | 3 / 16 |
| lowercase + postfilter v1 | 8 / 18 | 1 / 16 |
| lowercase + postfilter v2 | 10 / 18 | 2 / 16 |

v2 personal misses (4) are sentences where spaCy produced no entity at all (so no post-filter rule could keep them). v2 benign flags: "My dog Max ..." (S1 `weak_person`,
a pet name read as a person), "Napoleon was defeated at Waterloo ..." (S1 `weak_person`; no longer a linked S2 pair), and "Tell me about Abraham Lincoln ..." (S2, a multi-token
historical person; unchanged between v1 and v2).

## Limitations

- v2 dev-CHECK/openai are post-review sets. Pets and fictional or historical people are indistinguishable from private people without world knowledge, so the S1 weak-person tier trades specificity for recall.
- One small model (`en_core_web_sm`); dev-TUNE/CHECK are 267/235 prompts, so one prompt moves recall by about 0.9 points.
- Datasets are synthetic or benchmark-derived. `relation_tied` fires on only 17 entities (all openai); `structural` had no measurable effect on the
  held-out sets, so its value is supported by design-set evidence only.
- Cue lists (honorifics, kinship nouns, relation verbs) are English-only.
- No semantic/LLM layer, Docker or download was used.

## Reproduction

Tables are produced by `evaluation/compare_ner_postfilter.py` (host Python; explicit layers `["regex","ner"]`; refuses any path named like `final`; `--ablation`
adds the per-rule deltas), run with the host evaluation environment (`evaluation/.venv-v1-v3-pipeline`, spaCy `en_core_web_sm`):

`python evaluation/compare_ner_postfilter.py tune check personalized openai --ablation --data-root <checkout with the datasets> --generated <generated protobuf dir> --out <dir>`

The v1 tables were produced by an earlier scratch harness with the same layer calls at commit `50fc51e6`; the committed script reproduces the v2 numbers.

Unit tests (host Python, `PYTHONPATH` including `shared/python` and the generated protobuf directory):
`python -m unittest discover -s extension/client-runtime/test -p test_ner_postfilter.py`
(also run and passing: `test_detector_quality`, `test_gitleaks_rules`, `test_pipeline`, `test_case_preserving_detectors`,
`test_ner_pipeline_cache`, `test_detector_contract`, `test_security_boundaries`).
