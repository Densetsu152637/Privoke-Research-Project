# Cross-platform and provider-shape experiment (XPLAT-20261117)

**Scope: INSTALLED-EXTENSION ENFORCEMENT ON WINDOWS 11, SYNTHETIC HTTPS RECEIVER, REGEX+NER RUNTIME, NO REAL PROVIDER.** Full record with tables, limitations and commands: [paper/research/cross-platform-20261117.md](../../paper/research/cross-platform-20261117.md); numbers in [the JSON](../../paper/research/cross-platform-20261117.json). Goal G15, Stage 11 of the [ASIACCS plan](../plans/asiaccs-2027-revision.md). Source revision `fb1b3175d858b00305f339a7f456bec34311f9c7`.

Question: does the unmodified extension intercept, decide and enforce on Windows in Chrome, Edge and Firefox the way the Linux Chromium evidence showed, and does the page hook handle every supported provider request shape?

What was run: per browser, 73 probes (ALLOW unchanged send, WARN forwarding, BLOCK zero-send, negative controls, runtime-unreachable/hung/cancel failure handling and recovery) through the real supervisor, bridge and detector on loopback, against a local synthetic receiver that stood in for all six supported provider hosts; plus a 166-test page-interceptor harness over ten synthetic provider request shapes.

| Browser | Version | Result |
|---|---|---|
| Chrome (installed) | 157.0.8103.51 | 73/73 |
| Edge (installed) | 157.0.4341.60 | 61/73; all 12 failures are Copilot probes: the extension's content scripts did not run on copilot.microsoft.com, so BLOCK-worthy prompts were sent unchanged and un-warned (cause not determined) |
| Firefox (installed) | 134.0.2 | not run: manifest requires Firefox 142.0 or later and the add-on was rejected as incompatible |
| Firefox (Playwright-managed build) | 159.0 | 73/73 (not the installed browser) |

Provider shapes: ChatGPT (three shapes, two hosts), Claude, Gemini, Copilot (two), OpenAI Chat Completions and Responses (two) all extract the exact prompt and are enforced in the harness (166/166) and in Chrome and Firefox 159 (every shape 6/6); Edge fails only the two Copilot shapes. A registered native launcher (pre-existing user installation) also started a runtime on demand in Chrome and Edge, observed separately.

Blocked: live-provider validation (no traffic to real providers; needs user approval). Qualifications: headless, unpacked/temporary extension, one run per browser, synthetic fixtures, not the 33-probe Linux matrix and not a latency or resource comparison.

Reproduce: `evaluation/cross_platform_study.py run|derive`, `extension/test/provider-shapes.test.js`, `evaluation/tests/test_cross_platform.py`; exact commands are in the record.
