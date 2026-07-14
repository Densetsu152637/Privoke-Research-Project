import { cp, mkdir, rm } from "node:fs/promises";
import { watch } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import * as esbuild from "esbuild";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const dist = join(root, "dist");
const watchMode = process.argv.includes("--watch");

async function copyStaticFiles() {
  await mkdir(dist, { recursive: true });
  await Promise.all([
    cp(join(root, "manifest.json"), join(dist, "manifest.json")),
    cp(join(root, "popup.html"), join(dist, "popup.html")),
    cp(join(root, "popup.css"), join(dist, "popup.css")),
  ]);
}

await rm(dist, { recursive: true, force: true });
await copyStaticFiles();

const context = await esbuild.context({
  entryPoints: {
    popup: join(root, "src", "popup.js"),
    background: join(root, "src", "background.js"),
    "content-script": join(root, "src", "content-script.js"),
    "page-interceptor": join(root, "src", "page-interceptor.js"),
  },
  bundle: true,
  outdir: dist,
  format: "iife",
  platform: "browser",
  target: "chrome120",
  loader: { ".proto": "text" },
  sourcemap: true,
  logLevel: "info",
});

if (watchMode) {
  await context.watch();
  watch(root, { recursive: false }, (_event, filename) => {
    if (["manifest.json", "popup.html", "popup.css"].includes(filename)) {
      copyStaticFiles().catch(console.error);
    }
  });
  console.log(`Watching extension sources; load unpacked from ${dist}`);
} else {
  await context.rebuild();
  await context.dispose();
}
