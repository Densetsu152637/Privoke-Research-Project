# Addendum to XPLAT-20261117: why the extension does not run on Copilot in Edge (EDGE-COPILOT-1)

**Record:** addendum to [XPLAT-20261117](cross-platform-20261117.md); that record is not modified. **Date run:** 16 November 2026. **Base revision:** `1af8491` plus the uncommitted changes later committed on `fix/edge-copilot`. **Scope label: ROOT CAUSE AND COVERAGE-GAP SIGNAL FOR ONE BROWSER/HOST PAIR, WINDOWS 11, SYNTHETIC RECEIVER, NO REAL PROVIDER.**

## Question

XPLAT-20261117 found that in Edge 157.0.4341.60 the extension's content scripts never ran on `copilot.microsoft.com`: `fetch` stayed native and all 12 Copilot probes failed, with BLOCK-worthy prompts reaching the receiver unchanged and without a warning. The same build hooked `chatgpt.com` in the same Edge instance, and Chrome 157 and Firefox 159 passed the Copilot probes. Cause not determined there.

## Root cause

Edge 157 puts `copilot.microsoft.com` on Chromium's restricted-URL list, the same list as its own add-on store, so the browser refuses every extension script on that host. This is browser behaviour, not a PriVoke defect, and an extension cannot override it.

Evidence (temporary profiles, headless, unpacked, same host mapping and receiver as XPLAT; nothing sent to real hosts):

1. **Minimal extension.** MV3, `host_permissions: ["https://*/*"]`, `scripting` and `tabs`, one MAIN-world and one isolated-world content script at `document_start` for the provider hosts, one `<all_urls>` script, and a service worker that runs `chrome.scripting.executeScript` in both worlds on every loaded tab and reports the result to the local receiver.

| Host | Edge 157 content scripts | Edge 157 `executeScript` | Chrome 157 |
|---|---|---|---|
| `chatgpt.com`, `claude.ai`, `example.com` | run | runs | runs |
| `copilot.microsoft.com` | none run, including `<all_urls>` | `The extensions gallery cannot be scripted.` (both worlds) | runs |
| `microsoftedge.microsoft.com` (Edge add-ons) | none run | same error | runs |
| `chromewebstore.google.com`, `chrome.google.com` | none run | same error | same error |
| `copilot.cloud.microsoft`, `m365.cloud.microsoft`, `www.bing.com`, `www.microsoft.com` | `<all_urls>` runs | runs | runs |

`chrome.permissions.contains` returned `true` for `copilot.microsoft.com` in Edge, so the host permission is granted and then overridden. The error string is Chromium's restricted-URL message for the extension gallery, the same one Chrome gives for its own Web Store. Edge applies that class to `copilot.microsoft.com`; Chrome does not.

2. **Override attempt.** Relaunching Edge with `--allow-scripting-gallery` gave the same result. No Edge policy was set on this host apart from `HubsSidebarEnabled = 0` (registry read only), so there is no `ExtensionSettings`/`runtime_blocked_hosts` entry.

3. **Candidates ruled out.** The manifest `matches` include `https://copilot.microsoft.com/*` and work in Chrome and Firefox. The page loads from the synthetic receiver at the right URL (`location.href` checked, the receiver logs the GET), so host mapping and DNS are not the cause. The minimal extension's isolated-world script, which CSP and Trusted Types do not affect, is refused too, so CSP, Trusted Types and injection timing are ruled out.

4. **External corroboration (unofficial, not verified here).** Community reports describe Edge blocking all extensions on `copilot.microsoft.com` and, from Edge 150, on some `*.cloud.microsoft` hosts. A third-party vendor note says Microsoft does not allow third-party extensions on `copilot.microsoft.com` in Edge. We found no official Microsoft release note. In this Edge 157 build, `copilot.cloud.microsoft` and `m365.cloud.microsoft` were not restricted.

## Product behaviour

The extension cannot hook the page, so it cannot enforce there. The safest available behaviour is to make the gap visible instead of silent:

- The content script answers a coverage ping. After each supported provider tab loads, the background pings it three times, 500 ms apart. If it gets no answer, it sets a red `!` action badge and the title "PriVoke cannot inspect this page. ... prompts sent here are not checked, warned or blocked." The popup shows the same warning for the active tab.
- The six provider hosts are now also explicit `host_permissions`. Chromium gives the background a tab's URL only for explicit host permissions, not for content-script matches; without them the check could not see the URL, which was verified in Edge. This adds no install warning beyond the existing content-script hosts.
- Not adopted: blocking Copilot traffic with `declarativeNetRequest`, which would break the service and was not tested against the restricted host, and claiming coverage. The documentation tells users who need enforcement on Copilot to use Chrome or Firefox.

This is a detection signal, not enforcement: G1 still does not hold for Copilot in Edge.

## Rerun with the existing driver

`extension/test/cross-platform-driver.mjs` gained an `extension-eval` op that reads the badge from the extension service worker. `cross_platform_study.py` gained a `page_coverage` stage that records, per provider host, whether the page hook is active and the action badge (`covered`, `gap_surfaced`, `silent_gap`). Build: `npm run build` of this branch.

| Browser | Copilot probes (12) | `copilot.microsoft.com` coverage | Other five provider hosts |
|---|---|---|---|
| Edge 157.0.4341.60 | 0/12 pass, unchanged from XPLAT: no analysis; the ALLOW, WARN and BLOCK bodies each reached the receiver once | `gap_surfaced`: hook inactive, badge `!` | `covered`, no badge |
| Chrome 157.0.8103.51 (control) | not rerun (see below) | `covered`, no badge | `covered`, no badge |

The rerun used the study's own probe catalogue, driver, receiver and `score_probe`, limited to the Copilot shapes, plus the coverage stage. The full 73-probe `cross_platform_study.py run` was **not** rerun. Its loopback ports (8080, 50056, 50057) were held by a supervisor and runtime tree that the user's registered native launcher started during this session's probes (created 20:18:39 local time; parent launcher already exited). The study refuses to run over another runtime, and stopping that process tree was outside this task's permission, so it is left for the user. The Edge Copilot probes need no runtime because they never reach analysis. Chrome's Copilot probes would have sent analysis to that foreign runtime, so only the Chrome coverage stage was run. No request reached a host outside the fixture set (`foreign_host_requests` empty in both runs).

## Limitations

Headless, unpacked extension, one Edge build, one run. The popup warning is unit-tested but was not opened in a live browser; the badge was read live. Whether a later Edge build lifts the restriction is unknown; the coverage check would then report `covered` without any code change.

## Reproduce

```
cd extension && npm ci && npm run build && npm test   # 335 tests
cd evaluation && .venv/Scripts/python.exe -m unittest tests.test_cross_platform   # 17 tests
evaluation/cross_platform_study.py run --out <out.json> --browsers edge --runtime-python <client-runtime venv python>
```

The full `run` records `page_coverage` per browser and prints non-covered hosts in `derive`.
