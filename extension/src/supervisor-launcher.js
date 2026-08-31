import { sendNativeMessage } from "./webextension-api.js";

export const NATIVE_LAUNCHER_HOST = "org.privoke.runtime_launcher";

const DEFAULT_ATTEMPTS = 24;
const DEFAULT_RETRY_DELAY_MS = 250;

export async function ensureSupervisorRunning(
  runtimeClient,
  {
    launch = launchSupervisorNativeHost,
    attempts = DEFAULT_ATTEMPTS,
    retryDelayMs = DEFAULT_RETRY_DELAY_MS,
  } = {},
) {
  try {
    return await runtimeClient.runtimeStatus({
      signal: AbortSignal.timeout(1_500),
    });
  } catch (initialError) {
    let launchResult;
    try {
      launchResult = await launch();
    } catch (launchError) {
      throw new Error(
        `The PriVoke supervisor is not running and its native launcher could not be reached: ${errorMessage(launchError)}. `
        + "Install the PriVoke native messaging host for this extension.",
      );
    }

    if (!launchResult?.ok) {
      throw new Error(
        launchResult?.message
        || `The PriVoke supervisor could not be launched: ${errorMessage(initialError)}`,
      );
    }
  }

  let lastError;
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    try {
      return await runtimeClient.runtimeStatus({
        signal: AbortSignal.timeout(1_500),
      });
    } catch (error) {
      lastError = error;
      if (attempt + 1 < attempts) await delay(retryDelayMs);
    }
  }

  throw new Error(
    `The PriVoke supervisor was launched but its bridge did not become ready: ${errorMessage(lastError)}`,
  );
}

export function launchSupervisorNativeHost() {
  return sendNativeMessage(NATIVE_LAUNCHER_HOST, { action: "ensure_supervisor" });
}

function delay(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function errorMessage(error) {
  return error instanceof Error ? error.message : String(error);
}
