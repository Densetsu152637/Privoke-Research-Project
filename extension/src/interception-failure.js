export function runtimeFailureResponse(error) {
  const name = typeof error?.name === "string" ? error.name : "";
  const message = typeof error === "string" ? error : typeof error?.message === "string" ? error.message : "";
  let reason = "PriVoke could not analyze this prompt safely.";
  if (/extension context invalidated|receiving end does not exist|message (?:port|channel) closed|could not establish connection/i.test(message)) {
    reason = "PriVoke lost its extension connection. Reload this AI page and try again.";
  } else if (name === "TimeoutError" || /timed? out|timeout|deadline exceeded/i.test(message)) {
    reason = "PriVoke analysis timed out. Check the runtime status in the PriVoke popup and try again.";
  } else if (/failed to fetch|networkerror|network error|load failed|connection refused|econnrefused|runtime bridge returned HTTP 50[234]/i.test(message)) {
    reason = "PriVoke could not reach its local runtime. Open the PriVoke popup to check that it is running, then try again.";
  }
  return {
    action: "BLOCK",
    reason,
  };
}
