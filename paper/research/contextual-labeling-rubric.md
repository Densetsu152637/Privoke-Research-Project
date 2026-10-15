# Provisional contextual labeling rubric

For professor confirmation; not an independently validated dataset or a user study.
Use invented identifiers and supplied context. Never collect real private prompts
solely to fill this set. Keep annotator labels separate until adjudication.

Label these dimensions separately:

1. PII annotation presence: does text contain a specific identifier or person-linked
   attribute? Public identifiers still count as present; fictional placeholders
   require an explicit convention and a separate flag.
2. Disclosure sensitivity: S0 ordinary general information; S1 low-risk identifying
   attributes; S2 sensitive personal information; S3 credentials, secrets or highly
   sensitive linked details. Record the evidence span and rationale. Do not infer
   secrecy solely from a topic keyword.
3. Visibility: use the supplied provenance/context. Public quotation may be public;
   first-person wording alone does not establish permission or confidentiality.
   If no reliable context is given, use unknown. Do not force a precise class.
4. Category: multiple labels allowed; specify identifier, financial, health,
   location, credential or other category according to the documented label map.
5. Desired action: evaluate the configured sensitivity/visibility policy separately
   from the labels. ALLOW/WARN/BLOCK is policy-dependent; WARN forwards content.

Include matched contrasts: public biography versus private personal disclosure;
fictional narrative versus linked real-person context; quoted text with explicit
permission versus unknown permission; general medical advice versus private health
history; workplace discussion versus a named private employer relationship;
credential explanation versus a fake credential value. Preserve source families
across splits. Review transformations for label preservation before evaluating.

Two people should label blinded to detector output and to each other. Report raw
agreement, disagreement types and an appropriate chance-corrected statistic with
denominators. Adjudication must preserve both original labels and the reason for
the final decision. With only agent labels, report illustrative case analysis and
remove claims of validated contextual/action accuracy. `git4san` confirmation and
a second independent human pass remain pending.
