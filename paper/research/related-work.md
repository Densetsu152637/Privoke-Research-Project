# Closest-work verification record

Search/access checkpoint: 3 October 2026. Scoped search terms: Casper prompt
privacy sanitization; exact HaS/ProSan titles from `paper/ref.bib`; Presidio NLP
configuration; PIIMB dataset provenance. This is an initial closest-work matrix,
not an exhaustive literature review or proof that a feature is absent elsewhere.
Primary paper HTML was opened; published revisions and runnable artifacts still
need verification before submission. No unmatched published metric is treated as
a benchmark against PriVoke.

| Work / source locator | Verified method and overlap | Implication for PriVoke |
| --- | --- | --- |
| [Casper, arXiv v1](https://arxiv.org/html/2408.07004v1), sections 5–7 | Local browser extension combines rules, NER and local semantic topic identification. It substitutes identifiers and restores placeholders, while topic warnings require acknowledgment. Its evaluation uses synthesized prompts and specified MacBook/Chrome configurations. | Layered client-side detection is prior work. PriVoke currently warns or blocks original requests without substitution. Controlled updates and their observed generalization may distinguish the study, but improvement must be demonstrated. Its reported rates use different data/tasks and cannot establish comparative superiority. |
| [Hide and Seek, arXiv v1](https://arxiv.org/html/2309.03057v1), sections 3–4 | Local anonymization and de-anonymization use generative or NER-based hiding, a small recovery model and black/white-box attack evaluation. Translation/classification utility is assessed. | This is a privacy/utility anonymization study, not a matched prompt-presence detector baseline. PriVoke's action policy does not implement the same output recovery. The linked preprint was submitted September 2023; `HaS2024` currently has inconsistent year metadata. Verify any later published version before correcting citation metadata. |
| [ProSan, arXiv v1](https://arxiv.org/html/2406.14318v1), abstract | Prompt Privacy Sanitizer removes contextual private content using anonymized readable prompts, with protection strength tied to word importance and leakage risk. Evaluation includes downstream tasks. | PriVoke should not equate detection/blocking with anonymization utility. A task-matched comparison would need output-utility and privacy-risk evaluation, rather than copying a published aggregate rate. |
| [Presidio configuration](https://github.com/data-privacy-stack/presidio/blob/main/docs/analyzer/customizing_nlp_models.md), NLP-engine configuration | Supports configured NLP engines and recognizers. Default documentation describes a large English spaCy model. | The independent baseline uses unchanged upstream recognizers with explicitly disclosed `en_core_web_sm` and threshold 0.5. It excludes PriVoke rule imports and runtime aggregation; some underlying NLP/rule technologies still overlap. |

Provisional contribution: a reproducible measurement of controlled semantic head
updates, layer interaction and bounded request enforcement. This is a candidate
contribution, not an established novelty claim. If updates fail, retain the null
finding and seek professor assessment of whether the comparative insight is
strong enough for the intended track. Do not claim prior systems are universally
static, ineffective or unable to adapt from this bounded search.
