# Provisional contextual-cascade fixture rubric

Status: assistant-authored provisional case review; professor confirmation is pending. This is not human annotation, inter-annotator agreement, validated contextual truth, or a deployment claim.

## What the labels mean

`required_sensitive` is a provisional contextual truth label, separate from PIIMB's source annotation-presence label. `false` means the text is a control for the contextual disclosure task, `true` means a disclosure candidate, and `null` means the case is ambiguous and excluded from primary contextual-truth and action-accuracy denominators. The reviewed fixture has 24 controls, 17 disclosure candidates, and 7 ambiguous cases.

`expected_sensitivity`, `text_visibility`, `expected_visibility`, and `expected_categories` are descriptive provisional reviewer labels, not existing runtime output and not certified ground truth. `text_visibility` records what the prompt itself states. `visibility_hint` appears only on the four explicitly supplied hint cases. `expected_visibility` is the reviewed effective visibility after that hint; otherwise it is the text-level visibility. Unknown visibility is `PU`, never inferred from the word “private.”

## Action scoring

`allowed_actions` controls exact action accuracy on eligible cases. The 24 controls allow only `ALLOW`; this provides the false-alarm check that a minimum-action threshold alone cannot provide. Fifteen unambiguous disclosure candidates allow `WARN` or `BLOCK` and have `minimum_action: WARN`. The two synthetic asserted-credential cases allow only `BLOCK` and have `minimum_action: BLOCK`. The seven ambiguous cases have `allowed_actions`, `expected_action`, and `minimum_action` set to `null`; their review intention is not scored.

`expected_action` is populated only when the allowed action set has one value: `ALLOW` for controls and `BLOCK` for asserted credentials. It is `null` for disclosure candidates that allow both `WARN` and `BLOCK`. This makes exact action accuracy and minimum-action attainment distinct measurements. A low-confidence moderation result is recorded separately; it does not redefine the provisional label.

The existing runtime policy in `extension/client-runtime/src/classification/classification_policy.py` maps S3 to BLOCK, S2 to WARN, and qualifying S1 identity/location results to WARN. These contextual labels intentionally distinguish topic/category presence from disclosure/action: an S0 or S1 topic control may include HEALTH, FINANCIAL, IDENTITY, or LOCATION while still allowing only ALLOW. The fixture evaluates whether a contextual gate reduces action on controls without losing required disclosure action; do not relabel PIIMB positives as private disclosures.

## Eligibility and limitations

The fixture rows carry `context_truth_eligible` and `action_accuracy_eligible`; both are false on all seven ambiguous rows. Report their count and descriptive anchors separately. All annotations have `label_status: assistant_provisional_professor_pending`; no professor or second human has confirmed them.

The 48 cases form 12 family groups and are a small software-regression pilot. The four `long_context` prompts are short: they do not test a 96-token window or truncation. Do not claim long-context coverage. Any new long-context cases must be authored and frozen separately, with tokenizer-counted harmless filler and matched short versions before scoring.

The corrected cases were checked with `shared/python/privoke_model/training_data.py:training_text_key` against prepared train, validation, and locked development. All 48 normalized keys are unique and zero overlap was found. The final partition was not opened. Keep the original unscored draft and its review artifacts unchanged; this corrected fixture is a separate version. Do not score the provisional labels as confirmed contextual truth or use these cases to make generalization, privacy, or publication-readiness claims.
