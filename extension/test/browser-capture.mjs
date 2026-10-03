import assert from 'node:assert/strict';
import { createServer } from 'node:https';
import { mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { createHash } from 'node:crypto';
const require = createRequire(import.meta.url);
const { chromium } = require('playwright');

// Local receiver with a provider-shaped hostname and path; no provider is contacted.
// Decisions are controlled fixtures. This tests the page hook, not extension installation,
// native messaging, model quality, or the supervisor's actual bridge.
const certificates = await mkdtemp('/tmp/privoke-capture-');
const { execFileSync } = await import('node:child_process');
execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
  '-subj', '/CN=chatgpt.com', '-keyout', certificates + '/key.pem', '-out', certificates + '/cert.pem'], { stdio: 'ignore' });
const tls = { key: await readFile(certificates + '/key.pem'), cert: await readFile(certificates + '/cert.pem') };
const received = [];
const sourceHashes = {};
const server = createServer(tls, async (request, response) => {
  if (request.method === 'POST') {
    let body = '';
    for await (const chunk of request) body += chunk;
    received.push({ path: request.url, body });
    response.writeHead(200, { 'content-type': 'application/json' });
    response.end('{"ok":true}');
    return;
  }
  if (/^\/src\/[a-z-]+\.js$/.test(request.url)) {
    const content = await readFile(new URL('../' + request.url.slice(1), import.meta.url));
    sourceHashes[request.url] = createHash('sha256').update(content).digest('hex');
    response.writeHead(200, { 'content-type': 'application/javascript' });
    response.end(content);
    return;
  }
  response.end('<!doctype html><title>PriVoke controlled request receiver</title>');
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
const base = `https://chatgpt.com:${server.address().port}`;
const browser = await chromium.launch({ args: [
  '--no-proxy-server', '--host-resolver-rules=MAP chatgpt.com 127.0.0.1',
] });
const records = [];
try {
  for (const transport of ['fetch', 'xhr']) {
    for (const decision of ['ALLOW', 'WARN', 'BLOCK', 'BRIDGE_SILENT']) {
      const page = await browser.newPage({ ignoreHTTPSErrors: true });
      await page.goto(base);
      await page.evaluate(async decision => {
        window.addEventListener('message', event => {
          if (event.source !== window || event.data?.type !== 'ANALYZE_PROMPT') return;
          if (decision !== 'BRIDGE_SILENT') window.postMessage({ ...event.data,
            type: 'ANALYZE_RESULT', action: decision }, '*');
        });
        await import('/src/page-interceptor.js');
      }, decision);
      const marker = `FAKE_PRIVATE_MARKER_${transport}_${decision}`;
      const startCount = received.length;
      const outcome = await page.evaluate(async ({ transport, marker }) => {
        const start = performance.now();
        const body = JSON.stringify({ prompt: marker });
        const url = '/backend-api/conversation';
        let result;
        if (transport === 'fetch') {
          try { result = { status: (await fetch(url, { method: 'POST', body })).status }; }
          catch (error) { result = { error: error.name, message: error.message }; }
        } else {
          result = await new Promise(resolve => {
            const xhr = new XMLHttpRequest();
            xhr.open('POST', url);
            xhr.onloadend = () => resolve({ status: xhr.status, readyState: xhr.readyState });
            xhr.send(body);
          });
        }
        return { ...result, elapsed_ms: performance.now() - start };
      }, { transport, marker });
      const captures = received.slice(startCount);
      const expectedForwarded = decision === 'ALLOW' || decision === 'WARN';
      assert.equal(captures.length, Number(expectedForwarded), `${transport}/${decision}`);
      if (expectedForwarded) assert.equal(JSON.parse(captures[0].body).prompt, marker);
      else if (transport === 'fetch') assert.equal(outcome.error, 'TypeError');
      else { assert.equal(outcome.status, 0); assert.equal(outcome.readyState, 4); }
      records.push({ transport, decision, expectedForwarded, captures, outcome });
      console.log(JSON.stringify({ transport, decision, received: captures.length }));
      await page.close();
    }
  }
  const report = { browser: 'Chromium', version: browser.version(), playwright: require('playwright/package.json').version,
    scope: 'Native page-hook fetch/XHR and real loopback receiver; controlled decision broker; not full installed extension',
    environment: 'Linux Docker, headless, network disabled except loopback; self-signed HTTPS fixture with certificate checks disabled only in fixture',
    sourceHashes, records };
  await writeFile('/workspace/evaluation/results/browser-capture.json', JSON.stringify(report, null, 2));
} finally {
  await browser.close();
  await new Promise(resolve => server.close(resolve));
}
