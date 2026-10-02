export function runtimeFailureResponse() {
  return {
    action: "BLOCK",
    reason: "PriVoke could not analyze this prompt safely.",
  };
}