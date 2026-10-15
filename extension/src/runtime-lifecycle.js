import { ensureSupervisorRunning } from "./supervisor-launcher.js";

export async function restoreConfiguredRuntime(
  runtimeClient,
  settings,
  { ensureSupervisor = ensureSupervisorRunning } = {},
) {
  if (!settings.enabled) return null;

  await ensureSupervisor(runtimeClient);
  const runtime = await runtimeClient.setRuntimeEnabled(true, {
    signal: AbortSignal.timeout(36_000),
    useLocalStack: settings.useLocalStack ?? false,
  });
  if (!runtime.enabled) {
    throw new Error(runtime.message || "The client runtime failed to start.");
  }
  return runtime;
}
