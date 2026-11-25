// The controller is started by the browser when the native-messaging port opens, so "ensuring" it is asking it for
// its status over the port. A host that is not installed will not appear by waiting, so that fails at once with the
// install hint; any other failure (the controller still starting, a port that dropped) is retried briefly.

const DEFAULT_ATTEMPTS = 8;
const DEFAULT_RETRY_DELAY_MS = 250;
const STATUS_TIMEOUT_MS = 5_000;

export async function ensureSupervisorRunning(
  runtimeClient,
  {
    attempts = DEFAULT_ATTEMPTS,
    retryDelayMs = DEFAULT_RETRY_DELAY_MS,
  } = {},
) {
  let lastError;
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    try {
      return await runtimeClient.runtimeStatus({
        signal: AbortSignal.timeout(STATUS_TIMEOUT_MS),
      });
    } catch (error) {
      lastError = error;
      if (error?.permanent) {
        throw new Error(
          `The PriVoke native messaging host is not available: ${errorMessage(error)}. `
          + "Install the PriVoke native messaging host for this extension.",
        );
      }
      if (attempt + 1 < attempts) await delay(retryDelayMs);
    }
  }

  throw new Error(`The PriVoke controller could not be reached: ${errorMessage(lastError)}`);
}

function delay(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function errorMessage(error) {
  return error instanceof Error ? error.message : String(error);
}
