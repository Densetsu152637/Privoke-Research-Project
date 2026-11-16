export function runtimeFailureResponse(error) {
  const name = typeof error?.name === "string" ? error.name : "";
  const message = typeof error === "string" ? error : typeof error?.message === "string" ? error.message : "";
  let reason = "PriVoke could not complete analysis.";
  if (/extension context invalidated|receiving end does not exist|message (?:port|channel) closed|could not establish connection/i.test(message)) {
    reason = "PriVoke lost its extension connection. Reload this AI page and try again.";
  } else if (name === "TimeoutError" || /timed? out|timeout|deadline[_ ]exceeded|missed its .{0,20}deadline/i.test(message)) {
    reason = "PriVoke analysis timed out. Check the runtime status in the PriVoke popup and try again.";
  } else if (/failed to fetch|networkerror|network error|load failed|connection refused|econnrefused|runtime bridge returned HTTP 50[234]|controller (?:disconnected|did not answer)|reach the PriVoke controller|native messaging host|client runtime (?:is not running|was stopped)|worker failed|no worker is ready/i.test(message)) {
    reason = "PriVoke could not reach its local runtime. Open the PriVoke popup to check that it is running, then try again.";
  }
  return {
    action: "WARN",
    inspectionUnavailable: true,
    reason: `${reason} Your prompt will be sent without a complete privacy check.`,
  };
}

export function interceptionResponse(response) {
  const action = typeof response?.action === "string" ? response.action.toUpperCase() : "";
  if (!["ALLOW", "WARN", "BLOCK"].includes(action)) return runtimeFailureResponse();
  const layers = Array.isArray(response.layers) ? response.layers : [];
  const failed = Boolean(response.error) || layers.some((layer) => layer.status === "error" || layer.error);
  if (!failed) return { ...response, action };
  // A working detector's BLOCK is still authoritative if another layer failed.
  const detectedBlock = (typeof response.evidence?.action === "string" && response.evidence.action.toUpperCase() === "BLOCK")
    || layers.some((layer) => layer?.status === "ok" && Array.isArray(layer.results)
      && layer.results.some((result) => typeof result?.action === "string" && result.action.toUpperCase() === "BLOCK"));
  return action === "BLOCK" && detectedBlock ? { ...response, action } : runtimeFailureResponse();
}
