# Cross-platform and provider-shape validation of the installed extension (XPLAT-20261117)

**Record:** XPLAT-20261117. **Date run:** 16 November 2026 (record named for the plan's 17 November stage). **Numbers:** [cross-platform-20261117.json](cross-platform-20261117.json) (every count below re-derives from its per-probe records; `python evaluation/cross_platform_study.py derive paper/research/cross-platform-20261117.json`). **Source revision:** `fb1b3175d858b00305f339a7f456bec34311f9c7` (tracked tree clean; new files uncommitted at run time, committed on `wt/cross-platform`). **Scope label: INSTALLED-EXTENSION ENFORCEMENT ON WINDOWS 11 WITH SYNTHETIC RECEIVER AND REGEX+NER RUNTIME; NO REAL PROVIDER.** Plan goal G15, Stage 11 of [the ASIACCS plan](../../docs/plans/asiaccs-2027-revision.md). Experiment summary: [docs/experiments/cross-platform-20261117.md](../../docs/experiments/cross-platform-20261117.md).

## Goal and request

Supervisor request (17 Oct, recorded in the plan): "Cross-platform/provider validation" as an evaluation subsection. G15 asks for (a) the installed extension on Windows across Chrome, Edge and Firefox against a synthetic receiver, and (b) page-hook compatibility with the request shapes of the supported providers using recorded or synthesized fixtures. Any live-provider run is blocked until the user approves sending traffic to real providers. The task brief for this record added: do not send any request to a real provider, do not use the user's accounts, state any software installed, report missing or unrunnable browsers as not run.

Prior records consulted: [installed-client-evidence-20261014](installed-client-evidence-20261014.md) (Linux Chromium, thirty-three correctness probes, synthetic HTTPS receiver; explicitly "not a cross-browser/platform, Windows ... result") and [v3-standard-installed-evidence-20261017](v3-standard-installed-evidence-20261017.md). This record does not change or supersede them; it adds the Windows and per-browser dimension with an equivalent probe set (not the identical 33-probe matrix; see Limitations).

## Method

- **Extension.** Unmodified build from this revision: `npm ci`, `npm run build` (Chromium `dist`), `npm run build:firefox` (`dist-firefox`). Loaded unpacked in disposable profiles (Chromium family: `Extensions.loadUnpacked` over `--remote-debugging-pipe` with `--enable-unsafe-extension-debugging`, headless=new; Firefox: Marionette `Addon:Install` temporary add-on, headless). `--load-extension` was not used.
- **Runtime.** The real extension supervisor, gRPC-Web bridge (127.0.0.1:8080) and detector child (127.0.0.1:50057), started by hand (the documented "development without native messaging" path) from this worktree with the maintained host client-runtime venv (Python 3.11.9). `PRIVOKE_USE_LOCAL_STACK=true`, so the streamed-model health check targets 127.0.0.1:50051 (nothing listens) and the effective layers are the extension's regex + NER; the semantic layer was unavailable by design and no cloud endpoint was contacted. The study's control port is 50066; the default control port 50056 was held by a decoy listener for the whole run so that a registered native launcher could not start a second supervisor while the runtime was deliberately stopped.
- **Receiver.** One Python TLS server on 127.0.0.1:443 with a freshly generated self-signed certificate whose SANs are the six supported provider hosts plus `example.com`. Chromium maps those hosts to 127.0.0.1 and every other name to NOTFOUND (`--host-resolver-rules`), and pins the certificate's SPKI hash (`--ignore-certificate-errors-spki-list`; general certificate errors are not ignored). Firefox maps hosts with `network.dns.localDomains`, sends everything else to a dead loopback proxy and uses `acceptInsecureCerts`. The receiver records the exact body bytes of every POST. Outside-fixture requests: 0. Non-loopback connections of the supervisor and detector (sampled by `netstat` after each browser): 0.
- **Probes (73 per browser run).** Prompts are the frozen synthetic ones of the Linux evidence: ALLOW "Please explain the steps in this process.", WARN "My profile handle is @privoke_fixture.", BLOCK "Contact alex@example.com about the draft." The expected action is what the real detector returned (asserted, not injected).
  - *decision* (6): ChatGPT-shaped POST, {fetch, XHR} x {ALLOW, WARN, BLOCK}.
  - *provider-shape* (54): nine further synthetic shapes x {fetch, XHR} x {ALLOW, WARN, BLOCK} (table below).
  - *negative-control* (3): metadata-only ChatGPT body, unsupported path on a supported host, unsupported host; no analysis may occur and the request must arrive once, unchanged.
  - *failure-handling* (10): runtime unreachable (supervisor killed) with a BLOCK-worthy prompt, fetch and XHR, must fail open once with a rendered warning; recovery after restart (BLOCK still blocks, ALLOW forwards); runtime hung (bridge process suspended with `NtSuspendProcess`): caller cancellation after 1.5 s (fetch abort, XHR abort) must send nothing, and the unmodified deadline (about 30 s) must fail open once, unchanged; recovery after resume.
  - Pass criteria per probe: exactly one analysis request with the exact prompt and expected `targetApp`; observed action equals expected; ALLOW/WARN arrive at the receiver exactly once with byte-identical body (SHA-256), POST, same path/query and host; BLOCK arrives zero times, fetch rejects with `TypeError` "Prompt blocked by PriVoke." and XHR ends at status 0, readyState 4 with `error` and `loadend`.
- **Provider shapes.** Synthetic bodies in `extension/test/fixtures/provider-shapes.json`, written from the endpoint patterns and extraction rules in `extension/src/prompt-interception.js` and the manifest host list; none was captured from a provider or account. The same JS builder produces the bytes for both the page-hook harness test and the browser probes.
- **Page-hook harness.** `extension/test/provider-shapes.test.js` runs the real `page-interceptor.js` source in a VM with a scripted decision: 166 tests (per shape: prompt extraction; fetch with string/Blob/Uint8Array/ArrayBuffer bodies x ALLOW/WARN/BLOCK; asynchronous XHR x 3 actions; Request-object input; plus three negative controls, a GET control and a fixture-provenance check). It establishes extraction and hook enforcement, not detector output.
- **Software installed.** None system-wide. Playwright-managed Firefox 159.0 (build 20261030233356) was downloaded with `npx playwright-core install firefox` (playwright-core 1.65.1, Playwright CDN) into the agent scratch directory only (no Playwright API is used to drive it; it is launched like any Firefox through Marionette). `npm ci` populated the worktree's gitignored `extension/node_modules`. No registry or native-host registration was created or changed by this work.

## Per-browser results

| Browser | Version | Engine/driver | Extension loaded | Probes passed | decision | provider-shape | negative | failure |
|---|---|---|---|---:|---:|---:|---:|---:|
| Google Chrome (installed) | 157.0.8103.51 | headless=new, CDP pipe | yes | 73/73 | 6/6 | 54/54 | 3/3 | 10/10 |
| Microsoft Edge (installed) | 157.0.4341.60 | headless=new, CDP pipe | yes | 61/73 | 6/6 | 42/54 | 3/3 | 10/10 |
| Mozilla Firefox (installed) | 134.0.2 | Marionette | **no, not run**: `Addon:Install: ... add-on privoke-local@privoke is not compatible with application version. add-on minVersion: 142.0.` | not run | | | | |
| Firefox (Playwright-managed, not the installed browser) | 159.0 | headless, Marionette | yes | 73/73 | 6/6 | 54/54 | 3/3 | 10/10 |

Enforcement counts (probes outside failure handling, passing): Chrome ALLOW 20 / WARN 20 / BLOCK 20 (ALLOW and WARN forwarded unchanged exactly once; BLOCK zero sends); Edge 16/16/16 (the 4 missing per action are the Copilot shapes, below); Firefox 159 20/20/20. The failure-handling probes are identical in outcome across the three runs (fail open once, unchanged, with a rendered warning when the runtime is unreachable or hung; no send on cancellation; full recovery). Fail-open latency differed by engine: Firefox 159 produced the fail-open result for the unreachable runtime after about 2.0 to 7.5 s and for the hung XHR after about 5.8 s, versus 5 to 18 ms (unreachable) and 30.0 to 31.8 s (hung) in Chromium; all passed the same checks and the cause was not investigated.

**Edge finding (real defect or platform limit, not fixed).** On `copilot.microsoft.com` Edge 157 never ran the extension's content scripts: `window.fetch` stayed native (`function fetch() { [native code] }`), no analysis request was produced, and BLOCK-worthy prompts reached the receiver unchanged (12/12 Copilot probes failed: the two Copilot shapes x 6). The same build on `chatgpt.com` in the same Edge instance installed the hook. The manifest lists `https://copilot.microsoft.com/*`, and Chrome and Firefox 159 intercept it. The cause (an Edge restriction on extension access to Microsoft-owned origins, versus another reason) was not determined; the observable result is that Copilot prompts are unprotected and un-warned in Edge. No source was changed.

**Native launcher smoke (registered host, no probes counted).** The host already has the project's native-messaging host registered (written by the user's earlier install; it points at the main checkout). With no runtime running and the decoy removed, an extension loaded in Chrome 157.0.8103.51 and, separately, Edge 157.0.4341.60 obtained a runtime through that registration: bridge listener seen after 4.3 s (Chrome) and 4.4 s (Edge), first ALLOW decision after 16.1 s and 16.7 s, and a BLOCK probe afterwards produced zero receiver requests in both. The launched supervisor and detector (four processes) came from the main checkout, not this revision; they showed no non-loopback connections (they inherited `PRIVOKE_USE_LOCAL_STACK=true` from the browser environment) and were stopped by the study afterwards. That Edge used the registration is an observation; its mechanism (for example Edge reading the Chrome registry location) was not examined. No registration exists for Firefox, so no Firefox native launch was attempted; Firefox 159 used the manual supervisor.

## Provider request-shape results

Passing probes, with the browser runs counting every probe of that shape (the ChatGPT-conversation row also contains the 6 decision and 10 failure probes). The last column is the page-hook harness (166 tests in total, all passing).

| Shape (host, extractor target) | Chrome 157 | Edge 157 | Firefox 159 (PW) | Page-hook harness |
|---|---:|---:|---:|---:|
| chatgpt-conversation (chatgpt.com, `messages[].content.parts`) | 16/16 | 16/16 | 16/16 | 17/17 |
| chatgpt-f-conversation-author (`/backend-api/f/conversation`, `author.role`) | 6/6 | 6/6 | 6/6 | 17/17 |
| chatgpt-legacy-host-prompt (chat.openai.com, `prompt`) | 6/6 | 6/6 | 6/6 | 17/17 |
| claude-completion (claude.ai, `prompt`) | 6/6 | 6/6 | 6/6 | 17/17 |
| gemini-stream-generate (gemini.google.com, form `f.req` nested JSON) | 6/6 | 6/6 | 6/6 | 8/8 |
| copilot-chat-message (copilot.microsoft.com `/c/api/chat`, `message.content`) | 6/6 | **0/6** | 6/6 | 17/17 |
| copilot-send-event (copilot `.../message`, `content[].text`) | 6/6 | **0/6** | 6/6 | 17/17 |
| openai-chat-completions (api.openai.com, `messages[]`) | 6/6 | 6/6 | 6/6 | 17/17 |
| openai-responses-items (`input[].content[].text`) | 6/6 | 6/6 | 6/6 | 17/17 |
| openai-responses-string (`input` string) | 6/6 | 6/6 | 6/6 | 17/17 |

The harness runs fewer body encodings for the form-encoded Gemini shape (string only), hence 8. All five extractor targets (`chatgpt`, `claude`, `gemini`, `copilot`, `openai_api`) and all six manifest hosts are covered. Extraction recovered the exact prompt in every shape in both the harness and the browsers.

## Blocked and not run

- **Live-provider validation: blocked pending user approval.** No traffic was sent to ChatGPT, Claude, Gemini, Copilot or the OpenAI API, no account was used, and the browsers could not resolve those names to anything but the local receiver. Whether current production request bodies still match the synthetic shapes is therefore not established.
- Installed Firefox 134.0.2: not run (incompatible with the manifest's `strict_min_version` 142.0). The Firefox 159 result comes from a Playwright-managed build, not the installed browser.
- Opera GX (the user's primary browser per the docs) and the Windows store/packaged extension were out of the requested set and were not run.
- Semantic (streamed LLM) and V3 inference layers: not exercised (no model server).

## Limitations

- Equivalent, not identical, to the Linux probe set: 73 probes per browser (6 decision, 54 shape, 3 negative, 10 failure) rather than the 33-probe, 465-request matrix; no latency, resource or cost measurement is made or comparable (headless, other processes running; elapsed times in the JSON are descriptive only).
- Headless only (Chromium headless=new, Firefox `-headless`); headed behavior, popups and the user-visible notice rendering were not tested. Warnings are asserted through the page message `noticeStatus`, not a screenshot.
- Extension loaded as an unpacked or temporary add-on, not a store package. The Firefox run used the tracked `extension/dist-firefox/manifest.json` and `popup.css` (line endings and one CSS line differ from a fresh build) with freshly built JavaScript; the JavaScript is byte-identical to the build. Build hashes are in the JSON.
- Runtime is a manual supervisor start; native launch was observed only in a separate smoke, for Chrome and Edge, against the user's pre-existing registration and the main checkout's code.
- Fixtures are synthetic. They test the shapes the code handles, not the shapes providers currently send; ChatGPT/Claude/Gemini/Copilot may have changed.
- One run per browser; probe order is fixed; a single-run pass is not an estimate of failure rate. Fault stages use `taskkill` and `NtSuspendProcess`, which are not identical to the Linux SIGSTOP/CDP-pause faults.
- Firefox 159 is a Playwright-built Firefox with patched components, so it is a proxy for release Firefox 142 or later, not the installed release.

## Commands

All from the worktree root `D:/Git-Worktrees/Privoke-Research-Project/wt-cross-platform` (host Python venv `evaluation/.venv` of the main checkout; runtime venv `extension/client-runtime/.venv` of the main checkout; protobuf-generated directories copied from the main checkout; Node v24.21.0):

```
cd extension && npm ci && npm run build && npm run build:firefox && npm test            # 324 tests pass (158 existing + 166 new)
cd evaluation && <evaluation venv python> -m unittest discover -s tests -p test_cross_platform.py   # 15 tests
PW=<scratch>/pw/browsers/firefox-1572/firefox/firefox.exe
<evaluation venv python> evaluation/cross_platform_study.py run \
  --browsers chrome,edge,firefox,firefox-playwright --native-smoke chrome,edge \
  --playwright-firefox "$PW" --runtime-python <client-runtime venv python> \
  --out paper/research/cross-platform-20261117.json --workdir <scratch>
<evaluation venv python> evaluation/cross_platform_study.py derive paper/research/cross-platform-20261117.json
```

Earlier development runs of the same harness (a Chrome-only run, and runs in which the fault stage and the Firefox driver were repaired: a native launcher race on the control port, a launcher-versus-listener PID mix-up in the hang fault, Firefox certificate trust) are not pooled and are not retained; only the final complete run is this record.
