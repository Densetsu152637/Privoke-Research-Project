export const STREAMING_HEALTH_TIMEOUT_MS = 3_500;
export const ANALYSIS_TIMEOUT_MS = 30_000;
// Health selection precedes analysis. Leave time for both and the message relay.
export const RESPONSE_TIMEOUT_MS = STREAMING_HEALTH_TIMEOUT_MS + ANALYSIS_TIMEOUT_MS + 2_000;
