# Extension utility observations

The browser extension reports two page-visible, per-request observations over its existing `privoke-extension-v1` window-message channel. These fields describe client behavior that the analysis runtime cannot observe; they do not change detection, warning, or blocking policy.

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

After the interceptor acts, it emits a separate `ANALYZE_OUTCOME` message correlated by the same short-lived `requestId`. Its `observation.request_disposition` is `BLOCKED_LOCALLY` when a block decision or analysis-watchdog fallback prevents the native request, `ORIGINAL_REQUEST_HANDED_OFF` when the native fetch or XHR send call returns, and `UNKNOWN` when cancellation, an XHR timeout before decision, or a synchronous native-send failure leaves the disposition uncertain. A malformed `ANALYZE_RESULT` action from the page-visible channel is normalized to a fail-closed `BLOCK` with `notice_status: UNKNOWN`, while the local block remains observable. A successful handoff does not establish server receipt or task success. The action is omitted when cancellation or another no-result path leaves no valid analysis decision; analysis-watchdog fallback decisions retain `BLOCK` because the client does locally block that request.

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
