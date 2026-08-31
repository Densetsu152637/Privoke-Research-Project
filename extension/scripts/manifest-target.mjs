export function manifestForTarget(sourceManifest, target) {
  const manifest = structuredClone(sourceManifest);

  if (target === "firefox") {
    manifest.background = { scripts: [sourceManifest.background.service_worker] };
    delete manifest.key;
  }

  return manifest;
}
