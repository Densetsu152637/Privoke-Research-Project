# Prospective broad whole-prompt presence labeling

**Status: draft rubric, prepared before candidate-row access.** No AdvPIIBench rows have been downloaded, viewed, labeled, or scored under this rubric. The JSON file is the normative machine-readable annotation contract: [`clean-augmentation-rubric.json`](clean-augmentation-rubric.json), version `1.0.0-draft`. It binds to the prospective protocol's canonical LF SHA-256 `3991777aedadc8d50b7395a9ce8ef2aebfec946603229b823f1b6c118a16cbdf` (CRLF-to-LF text normalization only). Independent conceptual review and Professor confirmation remain pending. This is a proposed research annotation scope, not a certified ground-truth standard.

## Target and distinction from detector output

The unit is the complete prompt exactly as stored by the source. Mark binary presence when at least one concrete item fits any of the ten contract categories in the JSON. Record supported categories separately. The target is content presence only: it does not say whether information is private, harmful, linked to the author, highly sensitive, visible to a provider, or appropriate to transmit. It never supplies ALLOW/WARN/BLOCK, sensitivity, or visibility labels.

The runtime's `Classification.is_sensitive()` definition is detector-side behavior: it returns true for non-S0 sensitivity or any category bit. It is not the annotation rule and must not be used to label candidate prompts. Reviewers cannot see detector predictions, fits, thresholds, model vocabularies, or train/validation/test assignment.

Concrete, valid identifiers count as content presence even when synthetic, fictional, or public; unknown author linkage does not make them absent. Conversely, a generic term such as “email,” general medical advice, a placeholder, or a topic discussion is not by itself an instance of a category. A PII-shaped string is not positive solely from its shape: review its stated function and the rest of the prompt. If it could be a real category item or an unrelated lookalike and the text cannot resolve that distinction, mark uncertain and exclude rather than calling it clean.

## Native source mapping

The pinned AdvPIIBench schema labels five injected identifier types. The rubric maps them as follows:

| Native span type | Contract category |
| --- | --- |
| `credit_card_number` | `FINANCIAL` |
| `phone_number` | `IDENTITY` |
| `iban` | `FINANCIAL` |
| `email` | `IDENTITY` |
| `ssn` | `IDENTITY` |

Native `positive`, `negative`, and `hard_negative` labels describe the source's scope; they are not substituted for the broader target. A valid positive native span supports the mapped category, but the prompt still receives whole-prompt review for other categories. A source negative or hard negative becomes eligible as a target negative only after a reviewer establishes that the complete prompt contains none of the ten categories. Empty spans do not establish absence. Preserve native labels and spans separately; validate offsets against the exact unnormalized source string and keep normalization only for deduplication and exclusion keys.

The category definitions cover HEALTH, POLITICS, RELIGION, CRIMINAL, FINANCIAL, SEXUAL, CHILD, LOCATION, IDENTITY, and THIRD_PARTY. They follow the repository contract wording in [`prompt.py`](../../extension/client-runtime/src/LLM/prompt.py) and are cross-checked against the enum in [`classification.py`](../../shared/python/privoke_contracts/classification.py). The synthetic prompt generator's category mappings are supporting context, not ground truth for public-source rows.

## Decisions and eligibility

- **Present:** at least one concrete content item in the prompt fits a category. Mark each supported category. Do not infer extra categories from the binary result.
- **Absent:** after reviewing the complete prompt, no item fits any category and there is no unresolved positive native annotation, malformed or unmatched positive span, missing text, or other contradiction. This is the only eligible negative decision.
- **Uncertain:** text is incomplete; the function of a possible lookalike is unresolved; source-positive annotation is malformed, unmatched, or unmappable; reviewers disagree; or a concrete item cannot be classified under the definitions. Exclude it from primary binary fitting/scoring and retain a reason. Never coerce uncertain to absent.

The broad task concerns whether covered content occurs, not whether it identifies the prompt author. If author linkage is unknown but a valid category item is present, label content present and leave personal linkage unasserted. `THIRD_PARTY` is an additional subject relation only when covered information is explicitly about someone other than the speaker. Public or fictional status does not erase content presence. Privacy risk, contextual appropriateness, sensitivity level, visibility, and action need separate annotations and evidence.

## Review and provenance record

Before accessing candidate rows, freeze this rubric version, the source pin, native-span rules, inclusion rules, group/duplicate procedure, and complete protected-key union. After authorized row access, reviewers should inspect the complete prompt and native annotations while blinded to all model outputs, fitting, scores, thresholds, and prospective partition roles. An assistant's annotations are provisional; a separate conceptual review and Professor confirmation are still required.

For each later private review record, bind the restricted row and parent/family identifiers, exact-text hash, rubric ID/version/hash, reviewer and timestamp, blinding attestation, native-label/span validation, decision, supported categories, offsets into the original text, uncertainty/exclusion reason, and independent-review/adjudication status. Store text, identifiers, offsets, and review notes only in restricted ignored evidence. Do not put examples, spans, or per-row labels into this document, logs, or a public artifact.

The pinned [source card](https://huggingface.co/datasets/roei-ar/AdvPIIBench/blob/02741d9f99a91b8fdcf48f4316a2c73be7a7449a/README.md) identifies the dataset as synthetic, lists a poster presentation, and says a full paper is forthcoming; this draft does not treat that forthcoming paper as published validation. See the [prospective clean-augmentation protocol](clean-augmentation-protocol.md) for the frozen split/exclusion and execution gates. The current rubric itself authorizes no row access, fitting, or scoring.
