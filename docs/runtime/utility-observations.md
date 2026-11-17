# Extension utility observations

The browser extension reports two page-visible, per-request observations over its existing `privoke-extension-v1` window-message channel. These fields describe client behavior that the analysis runtime cannot observe; the observations themselves do not change detection, warning, or blocking policy. The opt-in WARN+MASK setting (below) changes what a WARN request transmits.

`ANALYZE_RESULT` keeps its existing `action` and `requestId` fields and adds an optional observation:

```json
{
  "channel": "privoke-extension-v1",
  "type": "ANALYZE_RESULT",
  "requestId": "ephemeral-request-uuid",
  "action": "WARN",
  "observation": {
    "schema_version": 1,
    "notice_status": "RENDERED"
  }
}
```

`notice_status` is `NOT_REQUESTED` when no warning or block notice is needed, `RENDERED` only after the notice has been appended to the page, `FAILED` when an attempted notice render throws, and `UNKNOWN` when the client cannot establish what happened. A rendered notice does not show that a person saw or understood it.

After the interceptor acts, it emits a separate `ANALYZE_OUTCOME` message correlated by the same short-lived `requestId`. Its `observation.request_disposition` is `BLOCKED_LOCALLY` when a block decision or analysis-watchdog fallback prevents the native request, `ORIGINAL_REQUEST_HANDED_OFF` when the native fetch or XHR send call returns with the original body, `MASKED_REQUEST_HANDED_OFF` when it returns with a rewritten body under WARN+MASK, and `UNKNOWN` when cancellation, an XHR timeout before decision, or a synchronous native-send failure leaves the disposition uncertain. A malformed `ANALYZE_RESULT` action from the page-visible channel is normalized to a fail-closed `BLOCK` with `notice_status: UNKNOWN`, while the local block remains observable. A successful handoff does not establish server receipt or task success. The action is omitted when cancellation or another no-result path leaves no valid analysis decision; analysis-watchdog fallback decisions retain `BLOCK` because the client does locally block that request.

```json
{
  "channel": "privoke-extension-v1",
  "type": "ANALYZE_OUTCOME",
  "requestId": "ephemeral-request-uuid",
  "action": "WARN",
  "observation": {
    "schema_version": 1,
    "notice_status": "RENDERED",
    "request_disposition": "ORIGINAL_REQUEST_HANDED_OFF"
  }
}
```

The event contains no prompt, detector evidence, secret, or target-app name. It is sent only through the existing local page-extension channel. The extension does not persist it or send it to a server. The channel is visible to page scripts and is not tamper-proof: a hostile page can forge or suppress these observations. Treat them as diagnostic and test observations, not signed or audit-authoritative records.

A consumer that needs to assess observation completeness should separately note the ephemeral IDs from `ANALYZE_PROMPT` and match them to `ANALYZE_OUTCOME`. If an outcome is missing, retain it as `UNKNOWN` or missing coverage; never infer success or an `ALLOW` action from its absence. Keep only the request ID for this join; the prompt message itself contains raw prompt text.

The observation denominator is the set of `ANALYZE_OUTCOME` messages: targeted fetch/XHR requests for which the interceptor extracted a prompt and initiated runtime analysis. Ordinary non-prompt pass-through, unsupported/unreadable bodies that fail before prompt extraction, and requests outside supported target routes have no event and are outside this denominator; their absence does not establish a clean or successful task. Once runtime analysis starts, cancellation, XHR timeout before a decision, and other no-result paths produce an `UNKNOWN` disposition. The shared analysis-watchdog timeout uses the existing fail-closed `BLOCK` fallback for fetch and XHR, so its observed disposition is `BLOCKED_LOCALLY` even though `notice_status` is `UNKNOWN`. Keep unknown outcomes in the denominator rather than counting them as allowed or as unnecessary restrictions.

These observations can distinguish requested actions from local notice and handoff behavior in controlled browser tests. Utility analysis still needs independently labelled expected action and authorization. With those labels, action/handoff counts can characterize restrictions and failures; the runtime's existing response timing can be joined to the request. Action counts alone cannot establish that a restriction was unnecessary. Task completion requires a task rubric or follow-up outcome, comprehension requires direct user assessment, and reformulation effort requires task interaction measurements or self-report. Preserve missing labels and observations as unknown/NA; do not convert them to false outcomes or zero effort.

Older extension responses containing only `action` remain valid; the interceptor reports `UNKNOWN` notice status for those responses. Consumers can ignore the optional observation and the separate outcome event without changing their existing action handling.

## Opt-in WARN+MASK handoff

The extension setting `warnMasking` (default `false`, `extension/src/settings.js`) replaces
the prompt with a masked copy before a WARN request is sent. It has no popup control; it is
set through the settings message or extension storage. When it is on and the action is
`WARN`, the background script collects every positive detector result that carries a
character span (`collectMaskSpans` in `extension/src/redaction.js`, called from
`background.js`) and returns the offsets and category names as `maskSpans` on the
`ANALYZE_RESULT` message. These spans contain no prompt text, but they are visible on the
same page-readable channel. The page interceptor then replaces each merged span with a typed
placeholder and rewrites the single prompt string inside the JSON request body
(`maskText`, `rewritePromptBody`), and reports `MASKED_REQUEST_HANDED_OFF` when the native
fetch or XHR send returns with that body.

When the body cannot be rewritten (form-encoded, multi-part, Blob or other non-JSON bodies,
or a prompt not found as a single string value), when no span was found, or when the action
is not `WARN`, the original request is handed off and the disposition is
`ORIGINAL_REQUEST_HANDED_OFF`. `BLOCK` is unchanged. A masked handoff means the rewritten
body was handed to the native call; it does not establish server receipt, that the target
application used the masked text, or that the mask covered all sensitive content.

Measured behaviour is recorded in
[WARNINT-20261116](../../paper/research/warn-intervention-20261116.md). On 264 sensitive
development prompts through the regex and NER layers only (the semantic layer was not run),
WARN+MASK lowered the share sent with an intact gold span from 0.587 to 0.455 relative to
plain WARN, altered 63 sensitive and 10 of 238 clean prompts, and 41.7 percent of the
masked characters lay outside any gold span. The rewrite was verified by harness tests, not
against live target-application traffic. That record states the limits of these figures.
