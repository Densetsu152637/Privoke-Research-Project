# Candidate contribution and threat model

Candidate research question: what do controlled synthetic head updates and layer
aggregation actually contribute to a locally executed prompt-privacy prototype?
The contribution is conditional on reproducible evidence, not on combining
familiar detectors or successfully transporting model deltas.

Closest overlap: Casper already provides a local browser extension with rules,
NER and semantic topic identification. PriVoke differs in its risk/action policy,
streamed compact model, bounded update path and private event telemetry. None of
these integration differences alone establishes publication novelty. That historical
selected-update comparison's public development evidence shows only one clean correction from the selected
training update; it does not establish useful adaptation generalization. See
`false-positive-experiments.md` for all attempts and unchanged pipeline recall.

## Deployment boundary

Assume a trusted workstation, browser/extension configuration, supervisor,
detector runtime and authenticated model/update service. The user intends to
submit prompts to a hosted LLM but may inadvertently include private information.
The provider is assumed to serve the tested request paths normally; retention or
downstream reuse after transmission is a concern. Exclude a compromised browser,
malicious page code actively replacing hooks or forging page-message decisions,
compromised runtime, malicious model publisher and adversarial local processes.
Those excluded actors can undermine the interception or classification boundary.

Supported request interception controls outgoing fetch/XHR prompt POSTs on
recognized endpoints and body formats. ALLOW and WARN forward the original
content. BLOCK cancels a protected request. Master/layer toggles can explicitly
bypass protection. Unsupported transports and unmatched requests are outside the
claim. Malicious prompt evasion and accidental disclosure need separate evaluation.

The current browser guide/source uses fail-closed handling for unavailable
analysis/bridge paths. Streaming unavailability can fall back to other enabled
layers; this preserves their detection coverage, not semantic coverage. A lone
unavailable semantic layer blocks. These statements have source/regression support;
native full-extension outage captures remain pending. The Chromium fixture tests
the actual page hook with a controlled broker and receiver, not native messaging
or a real provider page.

The measured semantic backend is streamed parameters with local CPU execution.
The optional hosted semantic backend changes the prompt-disclosure boundary and
is outside these measurements. Synthetic fuzzer training sends generated examples
to the research runtime, then bounded parameter deltas to the update service.
It does not aggregate user gradients or implement federated/private training.

## Claim boundaries

- PIIMB annotation-presence scores do not validate contextual sensitivity,
  visibility inference, action correctness or prevention of transmission.
- Browser fixture capture validates only its stated page-hook transport cases;
  a high detector score cannot extend that coverage.
- Runtime `elapsed_ms` excludes browser/native messaging/bridge overhead. Fixture
  decision durations use a controlled broker and are not deployment latency.
- Telemetry's event-level LDP covers the mechanism's fixed randomized fields under
  its budget/ledger/emitter assumptions. It does not hide event presence, report
  counts or network metadata, and does not privatize model training.
- No measured usability, broad deployment-monitoring utility, superiority to
  Casper or guaranteed IEEE acceptance is established.

Professor [git4san](https://github.com/git4san) should confirm whether the final
comparative insight is a sufficient contribution and whether the threat model
matches the intended application. Agent assessment remains provisional.
