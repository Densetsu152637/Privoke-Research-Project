# Plan: ASIACCS Stage 13, supervisor experiments for submission

Revision: 2026-11-24 r4 (r3 applied the round-2 findings O1–O6 and two nits; r4 applied the round-3 findings N1–N4; r5 applied N5; r6 applied N6; r7 applied N7; r8 applied N8; r9 applied N9; r10 is the improvement pass after the gate converged; r11 wires `--stage` into every G8 command). This is a planning document. It is based on `369fe0f` on `feat/nick-branch`, branch `plan/asiaccs-stage13`. The Rust facts were checked with `git show` against `origin/feat/rust-rewrite` at `4d838fd`. r2 applies the 16 plan-gate findings and the minor notes that root accepted.

This plan implements [Stage 13 of the ASIACCS plan](asiaccs-2027-revision.md#stage-13-supervisor-experiments-for-submission-queued-19-nov-2026-last-in-the-roadmap). That section holds the settled requirement verbatim:

- the question and method of each sub-stage;
- the priority order 13a > 13b > 13c > 13d > 13e > 13f;
- the chain Threat → Defense → Experiment → Metric → Evidence;
- the rule that no experiment is added only to increase the result count.

This document says how to carry the requirement out. Writing it changed no code, started no service and ran no experiment.

## Goals

Each goal is boolean. Commands run from the repository root of the worktree that owns the stage.

**Interpreters and tools.** The Python environments are Git-ignored and exist only in the main checkout. Every stage uses them by absolute path:

| Name | Path or command | Used for |
| --- | --- | --- |
| `PY` | `"D:/Git Repositories/Privoke-Research-Project/evaluation/.venv/Scripts/python.exe"` | Harnesses, reports and tests |
| `PYNP` | `"D:/Git Repositories/Privoke-Research-Project/evaluation/.venv-fuzzer-study/Scripts/python.exe"` | Anything that needs NumPy |
| `PYPIPE` | `"D:/Git Repositories/Privoke-Research-Project/evaluation/.venv-v1-v3-pipeline/Scripts/python.exe"` | The in-process product client of `score_privoke.py`, `layer_ablation.py` and the 13b detector-level arm, as Stage 3 used it |
| `RUSTDOCK` | `MSYS_NO_PATHCONV=1 docker run --rm --cpus=8 -e CARGO_TARGET_DIR=target-docker -v <wt>:/work -w /work/rust rust:1.99.1-bookworm` | Rust tests |

**Host protobuf clients.** Every worktree that runs a Python gRPC client generates the clients once with `$PY evaluation/setup-host.py`. The script already compiles `privoke/v1/{parameters,runtime,telemetry}.proto` and `privoke/experimental/v3.proto`. 13d needs the `experimental/v3.proto` clients for `CheckpointService`. 13a, 13b and 13e pass `--generated <extension/client-runtime/generated>`, as Stage 3 did.

- **S13-G1 (13a): a human-annotated, independent test set is scored.** One of two outcomes holds.
  - **(a) Run:**
    - `paper/research/human-annotated-eval-<date>.json` exists.
    - `$PY evaluation/annotation/human_eval_report.py --check paper/research/human-annotated-eval-<date>.json` exits 0. The script re-derives every kappa and every score from the committed label files.
    - `$PY evaluation/annotation/check_order.py` exits 0. It checks that the set-manifest commit and the packet-manifest commit, which records the blank-sheet hashes, are ancestors of the first label commit. The label commit must also be an ancestor of the record commit.
    - The record states how many people annotated, and that no agent produced a label.
  - **(b) "13a not run":** `paper/main.tex` contains the 13a limitation paragraph, and the packet is listed in the artifact. See [13-P](#stage-13-p-paper-integration-and-stage-9-repeat).
- **S13-G2 (13b): end-to-end evasion is recorded.**
  - `paper/research/e2e-evasion-<date>.json` exists.
  - `$PY evaluation/e2e_evasion_report.py --check <json>` exits 0. The script re-derives the conditional and unconditional end-to-end ASR and the detector-level ASR on the same applicable pairs.
  - Every browser is either run or listed with a reason.
  - `live_provider_runs` is empty, or names the user's approval.
- **S13-G3 (13c): every listed update attack has an observed outcome on the real V3 path.**
  - `paper/research/v3-update-attacks-<date>.json` has at least one row for each of the 11 attack classes in [13c](#stage-13c-active-attacks-on-the-v3-guarded-update-path).
  - Every variant that `rust/services/param-update/tests/s13c_rows.json` marks `wire_path: true`, and that is not CI-only, has a `leg:"container"` row against the real param-update and model-streaming containers. Each such row includes an observation of the version that model-streaming serves, or carries a `not_run_reason`. Crash points (C10) and at-rest corruption (C9e, C9f) are `wire_path: false`.
  - Each row names its rejecting check and records the active model before and after.
  - `$PY evaluation/v3_update_attacks_report.py --check <json>` exits 0.
  - `RUSTDOCK cargo test -p privoke-param-update --release --locked --test s13c_update_attacks` exits 0.
  - `RUSTDOCK cargo test -p privoke-runtime-supervisor --release --locked --test s13c_client_admission` exits 0.
- **S13-G4 (13d): every listed authentication attack has a denial outcome and a denying layer.**
  - `paper/research/authn-authz-<date>.json` exists.
  - `$PY evaluation/update_security_report.py --record <json> --document <md>` reproduces the generated tables.
  - `$PY evaluation/update_security_report.py --record <json> --check-s13d-coverage` exits 0.
  - `$PY -m unittest discover -s evaluation/tests -p "test_update_security*.py"` passes.
- **S13-G5 (13e, if time allows): seven layer configurations are scored with the executed layers asserted.**
  - `$PY evaluation/layer_ablation_report.py --check paper/research/layer-ablation-<date>.json` exits 0.
  - The check fails if any configuration has an empty `layers_requested`, or if its executed layers differ from the expected set.
- **S13-G6 (13f, if time allows): overhead is recorded, or the limit is stated.** One of two holds.
  - `$PY evaluation/e2e_overhead_report.py --check paper/research/e2e-overhead-<date>.json` exits 0, with 5 arms and p50, p95 and p99 for each arm.
  - Or `paper/main.tex` contains the single-platform or single-interface limitation paragraph that 13-P names.
- **S13-G7: the paper integrates the results and Stage 9 is repeated.**
  - `$PY paper/scripts/check_pages.py` prints PASS.
  - `$PY paper/scripts/check_anonymity.py` reports 0 matches.
  - The G1–G5, G12, G13 and G14 checks of the [ASIACCS plan](asiaccs-2027-revision.md#goals) hold.
  - Every new row of `tab:security_goals` and `tab:threat_defense` cites a Stage 13 record.
- **S13-G8: no forbidden material is committed.** For every stage diff, on either branch, root runs `$PY evaluation/check_s13_commit_hygiene.py --repo <stage worktree> --range <stage-base>..<stage-head> --stage <stage id>` from the `feat/nick-branch` tree, and it exits 0. Root passes `--stage` on every stage diff. A run without `--stage`, which allows any pin change, is reserved for root's final integration check in 13-P. The script is built in [13-H](#stage-13-h-commit-hygiene-check-agent-first). Over `git -C <repo> diff --name-only <range>`, it checks all of the following:
  - No committed JSON or CSV has a `text`, `prompt`, `body` or `notes` field or column.
  - No line that the range **adds** to a file other than source code contains any 8-gram of a prompt from the local inputs.
    - For a modified file, the scanned lines are the added lines of `git -C <repo> diff -U0 <range>`.
    - For a newly added file, the whole content is scanned.
    - Unchanged old lines are not scanned.
    - The name, key and weight rules are unchanged.
    - **What is scanned:** every file except `*.py`, `*.rs` and `*.mjs`. That includes `*.json`, `*.jsonl`, `*.csv`, `*.txt`, and `*.md` and `*.tex` anywhere in the repository.
    - **`*.py`, `*.rs` and `*.mjs`** are checked only by the name, key and weight rules, so harness code and templates do not cause false positives.
    - **Allowlisted files** are exempt from the 8-gram rule only while their sha256 matches the pin in `evaluation/s13_allowlist.json`. A pinned file whose hash differs fails the check.

    The local inputs are defined as follows. By default (`--local-inputs` omitted) these are every `D:/Git Repositories/Privoke-Research-Project/evaluation/results/s13*/` directory of the main checkout. The scan runs over those local files and reports counts only. If the default matches no directory, the script exits 0 and reports `local_inputs: 0` in its JSON. With `--require-local-inputs`, it exits 2 instead. Root passes that flag for the stage diffs that produce or consume prompt data (13a-3, 13a-5, 13b-2, 13b-3, 13e, 13f-1 and 13f-2), so the scan cannot be silently skipped there. `S13_LOCAL_INPUTS_ROOT` overrides the default scan root in normal runs as well as in tests.
  - No `*.safetensors`, `*.onnx`, `*.bin`, `*.pt` or `*.pth` file is added.
  - No line matches the key patterns:
    - `BEGIN (EC |RSA |OPENSSH |ENCRYPTED |)PRIVATE KEY`;
    - a 64-hex token on a line that names `seed`, `secret` or `private`. A 64-hex Ed25519 seed has the same format as a sha256 digest, so the line context decides.
  - Every prompt-bearing output path passes `git check-ignore`.

## Scope and non-goals

- **Scope:** the six sub-stages 13a–13f, the 13a prerequisite (the `fresh_eval-folio-NN` partition leak), paper integration and the Stage 9 repeat.
- **No padding.** An experiment, arm or row is added only if it answers its sub-stage's question. A 13c signature or lineage row is included only when it shows whether an attack can change the model that clients run.
- **Agents never annotate.**
  - Agents never write 13a prompts, never label, never adjudicate and never synthesize labels. They never write labelled worked examples.
  - Agents read the completed sheets only through `compute_iaa.py` and the adjudication export. They never open the sheets themselves.
  - Agents run PriVoke on no 13a item before the freeze commit.
- **No real provider traffic** without the user's explicit approval for that run (13b, 13f).
- **No empty layer list.** Every analysis request in 13a, 13b, 13e and 13f names its layers explicitly, and the harness asserts the layers that executed on every response.
- **No tuning against PriVoke outputs.** This covers the templates, the writer brief and any thresholds.
- **No change to the measured product**, except the harness seams that a stage names. A stage records any defect it finds. It fixes the defect only if the fix is small, covered by a test and reported (the Stage 4 rule).
- **Not in scope:** merging PR #6, uploading the artifact, deploying, and using the production publication key.

## Assumptions

- **Queue.** Stage 13 waits for the Rust rewrite and the Stage 9 repeat. Both are done: V3-R8b merged at `c89b42a`, and the Stage 9 repeat finished on 23 Nov.
- **Deadline.** The deadline is 11 December 2026. 13a fits only if the people are recruited by about 28 November. Otherwise the "13a not run" outcome applies.
- **Local inputs.** Some inputs are Git-ignored and exist only in the main checkout `D:/Git Repositories/Privoke-Research-Project`:
  - `models/standard-releases/`;
  - the frozen Stage 3 set, `evaluation/results/adversarial_evasion_20261116/main/frozen_set.jsonl`, sha256 `5e4eac4c7c3117adf81a013fa9e4572484c9b0f41ab4b4f217ca960a82b634c2`;
  - the AU3 data.

  Worktrees refer to them by absolute path or mount them read-only, and never commit them.
- **Docker** is available with `--cpus=8`. One Compose stack runs at a time.
- **Publication key.** Only test publication keys are used. The production key is never read.

## Relevant paths

| Area | Path (branch) |
| --- | --- |
| Requirement | `docs/plans/asiaccs-2027-revision.md` "Stage 13" (nick) |
| Annotation tooling | `evaluation/annotation/`; the blinding pattern is `DATASET_MARKER` in `sample_annotation.py` (nick) |
| Annotation protocol and status | `docs/research/annotation-protocol-20261024.md`, `docs/research/annotation-packet-status-20261116.md` |
| Stage 3 evasion harness | `evaluation/adversarial_evasion.py` (`assert_executed_layers`, `evaluate_arm`, `summarise_pairs`, `wilson`, `BASELINE = "baseline"`), `evaluation/adversarial_evasion_transforms.py`, `evaluation/adversarial_evasion_report.py`, `paper/research/adversarial-evasion-20261116.*` |
| Stage 11 browser harness | `evaluation/cross_platform_study.py`, `cross_platform_receiver.py`, `cross_platform_probes.py`, `extension/test/cross-platform-driver.mjs` |
| Extension layer contract | `extension/src/analysis-request.js` (`requireExplicitLayers`); `extension/src/background.js` (`disabledLayersResponse`: when no layer is enabled, no request is sent) |
| Historical ablation and latency | `evaluation/run-controlled-product-ablation.py` (AB14; legacy and guarded, not used); `evaluation/detector_latency.py` |
| V3 store and gates | `rust/services/param-update/src/v3_store/{store,service,evidence,mod}.rs`, `src/v3_policy.rs`, `src/v3_guard.rs`, `src/v3_retention.rs`, `src/v3_publish.rs`, `src/main.rs` (`open_checkpoint`), `src/config.rs` (`V3Config`), `src/journal.rs` (`JournalAllocations`), `src/server.rs` (`policy()`), `rust/services/param-update/config/v3-drift-bounds.toml` (rust) |
| V3 test fixtures | `rust/services/param-update/tests/golden_world/mod.rs` (V3 store world); `tests/v3_guard.rs`, `tests/scheduler_chain.rs`, `tests/v3_publication.rs`, `tests/v3_signed_chain.rs`, `tests/checkpoint_mtls.rs`; the client side is in `rust/services/runtime-supervisor/tests/{lineage_fetch,lineage_chain,fetch}.rs` (rust) |
| Client admission | `rust/crates/privoke-contracts/src/{v3,model_cache,publication}.rs`, `rust/services/runtime-supervisor/src/fetch.rs` (`verify_package`), `rust/services/model-streaming/src/published.rs` (rust) |
| Transport and PKI | `rust/crates/privoke-transport/src/{tls,authz,registry,reload,identity}.rs`, `rust/tools/privoke-pki/`, `deploy/gce/tests/make_test_pki.py` (rust) |
| Rust security harness | `evaluation/update_security.py --target rust`, `evaluation/update_security_pki.py` (OpenSSL), `evaluation/update_security_report.py`, `paper/research/update-security-20261117.*` (rust only) |
| Paper | `paper/main.tex`, `paper/research/claims.md`, `paper/REWRITE_SCOPE.md`, `paper/scripts/check_pages.py`, `paper/scripts/check_anonymity.py` (nick) |

## Related docs

- [ASIACCS plan, Stage 13](asiaccs-2027-revision.md#stage-13-supervisor-experiments-for-submission-queued-19-nov-2026-last-in-the-roadmap) wins on the requirement. This plan wins on how it is carried out.
- [REWRITE_SCOPE](../../paper/REWRITE_SCOPE.md) wins on paper scope. The [evidence ledger](../../paper/research/claims.md) wins on numbers.
- On `origin/feat/rust-rewrite`:
  - `docs/plans/v3-routine-training.md` wins on V3 update behaviour;
  - `docs/plans/rust-server-rewrite.md` wins on transport and PKI;
  - `docs/runtime/v3-publication.md` documents publication.
- [Annotation protocol](../research/annotation-protocol-20261024.md): its sizing, blinding and adjudication rules carry over to 13a, except where 13a-1 states otherwise.

## Branch strategy and coordination (decision record)

**Problem.** The paper, the ASIACCS plan and this plan live on `feat/nick-branch`, which has 13 commits that `feat/rust-rewrite` lacks. The Rust services, including V3, which is now the only guarded update path, live on `feat/rust-rewrite`. That branch is 312 commits ahead of the merge base `972578c`. The Rust plan lands PR #6 after submission and never rebuilds the artifact from the Rust tree.

**Decision: split by the build under test, and import the records.**

| Sub-stage | Build measured | Code branch (one worktree each) | Records committed on |
| --- | --- | --- | --- |
| 13a, 13b, 13e, 13f | Submission build: the Python runtime, extension and supervisor of `feat/nick-branch`, as in Stages 3, 5 and 11 | `feat/asiaccs-s13a`, `-s13b`, `-s13e`, `-s13f` from `origin/feat/nick-branch` | The same branches; root merges them into `feat/nick-branch` |
| 13-H | None; this is the commit-hygiene tool | `feat/asiaccs-s13h` from `origin/feat/nick-branch` | No records; root merges it into `feat/nick-branch` first |
| 13c, 13d | Rust build: param-update V3 store, model-streaming, transport | `feat/asiaccs-s13c` and `-s13d` from `origin/feat/rust-rewrite` | The same branches; root merges them into `feat/rust-rewrite`, then imports the records |

**Coordination rules.**

- **This plan is not on `feat/rust-rewrite`.** Root passes it to the 13c and 13d leaves by absolute path, read-only. Leaves on the Rust line never edit or copy it.
- **Root is the only writer of stage status**, at every transition (pending, in progress, done or blocked, and the outcome), in this plan and in the Stage 13 section of the ASIACCS plan. Leaves report through their results only.
- **Root syncs** this plan and the Stage 13 section to `docs/roadmap` after each status change, in the same way as the other plans.
- **Merge style.** Root merges every stage branch with a `--no-ff` merge commit, never a squash or a rebase. The ordering proofs of 13a (`check_order.py`) and 13b (the template-hash ancestry check) rely on the stage commits keeping their identities. Before merging 13a or 13b, root runs these checks on the stage branch:
  - `$PY evaluation/annotation/check_order.py`;
  - `$PY evaluation/e2e_evasion.py verify-templates --expected-sha256 <hash>`;
  - the template ancestry check.

  The merge happens only if all three pass.
- **G8 on every stage.** Root runs the S13-G8 command on each stage diff before merging, including the 13c and 13d diffs on the Rust line.

**Record import (13c, 13d).**

1. After a Rust stage merges, root creates `docs/asiaccs-s13-records` from `feat/nick-branch`.
2. Run `git checkout <rust-merge-sha> -- paper/research/<stem>.md paper/research/<stem>.json docs/experiments/<stem>.md`.
3. Commit with the message `docs(research): import <ID> from feat/rust-rewrite <sha>`.
4. Verify that `git diff <rust-merge-sha> HEAD -- <those paths>` is empty.

The imported files are new and byte-identical on both branches, so PR #6 cannot conflict on them. Only `feat/nick-branch` edits `claims.md`, `REWRITE_SCOPE.md` and `main.tex`. Each Rust record states `build.branch`, `build.sha` and `build.clean`, and states that the V3 update path exists only in the Rust build.

**Rejected alternatives.**

- **Merge PR #6 into the submission line first.** This changes the build behind every earlier result 17 days before the deadline. It also contradicts the Rust plan's sequencing and its artifact rule. Revisit under D9.
- **Run all of Stage 13 on `feat/rust-rewrite`.** The paper and the nick-only commits are missing there, and 13b and 13e would compare against Stage 3 across two builds.
- **Run 13c and 13d from `feat/nick-branch` against Rust images.** The harness would be separated from the code it tests. The Rust tests must live beside their crates.

**Consequences.** The paper reports results from two builds and labels each result with its build. The 13c and 13d harness is not in the anonymous artifact that is exported from `feat/nick-branch` (D10).

## Shared conventions for every stage

- **Record IDs and files.** `<date>` is the run date. Records are only added; existing records are never edited.

  | Sub-stage | ID | Files |
  | --- | --- | --- |
  | 13a | `HUMANEVAL-<date>` | `paper/research/human-annotated-eval-<date>.{md,json}` |
  | 13b | `E2EEVADE-<date>` | `paper/research/e2e-evasion-<date>.{md,json}` |
  | 13c | `V3UPDATK-<date>` | `paper/research/v3-update-attacks-<date>.{md,json}` |
  | 13d | `AUTHZ-<date>` | `paper/research/authn-authz-<date>.{md,json}` |
  | 13e | `LAYERABL-<date>` | `paper/research/layer-ablation-<date>.{md,json}` |
  | 13f | `E2EOVH-<date>` | `paper/research/e2e-overhead-<date>.{md,json}` |

  Each record also has a `docs/experiments/<stem>.md` summary.
- **Record header** (in both the Markdown and the JSON) has these fields:
  - `schema` and `study_id`;
  - `chain: {threat, defense, experiment, metric, evidence}`;
  - `build: {branch, sha, clean}`;
  - `host`, `run_dates` and `commands`;
  - `scope_label`;
  - `not_established`;
  - `user_actions`.
- **`scope_label` vocabulary.** Every row and every arm takes exactly one of these values:
  - `product pipeline (in-process)`;
  - `product pipeline (installed extension, end to end)`;
  - `LLM-only (semantic)`;
  - `update path (Rust V3)`;
  - `transport (Rust)`;
  - `human ground truth`.
- **Re-derivation.** Every number in the Markdown comes from the JSON. Each record has a report script with a `--check` mode that recomputes every aggregate from the per-row data. A unittest runs `--check` on the committed record.
- **Layer assertion (13a, 13b, 13e, 13f).**
  - Requests carry an explicit, non-empty list drawn from {`DETECTION_LAYER_REGEX` (2), `DETECTION_LAYER_NER` (3), `DETECTION_LAYER_SEMANTIC` (4)}.
  - The harness asserts the executed layers of every response with a generalised form of `assert_executed_layers` (`evaluation/adversarial_evasion.py`). The expected set comes from the configuration, and the regex-first skip rule applies only when regex was requested.
  - A response whose executed layers differ from the expected set aborts the run.
  - Each harness refuses an empty list before sending it, and a test covers that refusal.
- **Prompt-bearing data.** Every prompt-bearing `s13*` output is written to the main checkout, at `D:/Git Repositories/Privoke-Research-Project/evaluation/results/s13<x>/`, whichever worktree runs the stage. That covers raw prompts, variants, sheets with text, the adjudication export, receiver bodies and per-item outputs. Each harness takes the directory as `--out <absolute path>`, so the G8 default scan root always sees it. `evaluation/.gitignore` (`results/`) ignores these directories. Commits carry only hashes, counts, opaque ids and labels.

  The plan defines these directories:

  | Directory | Holds |
  | --- | --- |
  | `s13a/` | `raw/`, `packet/` and `returned/` |
  | `s13b/` | `pilot/` (the 20-probe timing pilot) and `run/` |
  | `s13e/` | per-item ablation outputs |
  | `s13f/` | timing samples |

  `s13-host.lock` is a file, not a directory, so the scan glob `s13*/` never matches it.
- **"Unchanged" means the authority, not the blob directory.** The store is unchanged when its `current` row, its `versions`, its `publications` (row count and highest sequence), the receipt of that request id, the version model-streaming serves and the client high-water mark are all unchanged. Rejected candidates can leave orphan blobs, because `stage` puts the payload before admission (`store.rs` `stage` → `put`, then `admit_candidate`). Records report orphan blobs but do not count them as a change.
- **Host Python, Docker only for hosting.** Python clients and scoring run on the host. Docker hosts the services and the Rust tests, never test drivers.
- **Host-heavy runs share one lock.** 13a-5 (PriVoke scoring), 13b-2, 13b-3, 13c-2, 13d-1b and 13d-2, 13e, 13f-1 and 13f-2 each acquire `D:/Git Repositories/Privoke-Research-Project/evaluation/results/s13-host.lock` (Git-ignored in the main checkout, shared by every worktree). Each run writes its stage id and process id into the lock and removes it on exit. A run refuses to start while the lock is held.
- **Process cleanup.** Every stage stops the services, browsers and containers it started, and lists them in its handoff.
- **Hygiene evidence.** Each stage handoff records the JSON output of its G8 run: `range`, `files_checked`, `local_inputs` and `violations`. For a user stage with no diff, the handoff records "n/a, no stage diff" instead.

## Time plan (estimates)

Host-heavy runs take the host lock one at a time. The **default order** is 13c-2 → 13d-1b and 13d-2 → 13b-2 → 13a-5 scoring → 13e → 13b-3 → 13f-1 → 13f-2. It is a default, not a hard sequence:
- A run that is ready takes the next free slot.
- When several runs are ready, the earlier one in the default order goes first, with one exception: **13a-5 scoring outranks 13b-2** when both are ready, because 13a is the highest-priority sub-stage.
- Nothing ever runs in parallel under the lock.

Work that does not need the host, such as harness code and CI-only tests, runs in parallel.

| Window | Agent work | User work |
| --- | --- | --- |
| 24–28 Nov | 13-H; 13a-0, 13a-1; 13c-1 (CI); 13d-1a; 13b-1 | Answer D1–D4, D6 and D9; recruit people; check ethics; supply or approve the worked examples |
| 28 Nov – 2 Dec | 13a-3 when prompts arrive; under the host lock: 13c-2 (28 Nov – 1 Dec), then 13d-1b and 13d-2 (1–2 Dec) | Writers deliver prompts (13a-2); annotators run the pilot and the main round (13a-4) |
| 2–5 Dec | under the host lock, in whatever order the runs become ready: 13b-2 (about 1 day), 13a-5 scoring as soon as the labels are frozen (about half a day; it goes before 13b-2 if both are waiting), then 13e if 13a is frozen (about half a day) | Adjudication (13a-4) by 3 Dec; 13b-3 (5 Dec, host lock) |
| 5–6 Dec | 13f-1 (host lock, idle host) | 13f-2 (host lock) |
| 6–10 Dec | 13-P paper integration; Stage 9 repeat | Review the paper; approve the push |

**Go or no-go (D11).** 13e and 13f start only if the 13a–13d records are `ready for review` by 4 December. If 13a is not frozen by 6 December, the "13a not run" outcome applies (13-P).

### Resume queue (paused 25 Nov 2026 for usage)

Work paused after 13d-1a, because the weekly usage limit was nearly reached. It resumes in a new session after the weekly usage reset (Sunday 03:00), starting from the queue below. The windows above still apply. If the pause pushes 13c-2 past 1 December, re-check D11.

**State at pause:**
- All branches are pushed: `feat/nick-branch` `1f3f421`, `feat/rust-rewrite` `1edb6be`, `feat/asiaccs-s13a` `cd157aa`, `feat/asiaccs-s13d` `4462ee4`.
- CI is green on `feat/rust-rewrite` at `1edb6be`.
- The stage worktrees were removed. Recreate them from their branches under `F:/Git-Worktrees/Privoke-Research-Project`.
- Long-lived worktrees `wt-asiaccs-s9` and `wt-rust-integrate` are kept. `wt-rust-integrate` holds the local goldens.

**Cross-session hardware rule (workflow change, 25 Nov 2026).** Before any host-lock run, which is a heavy timing, container or browser run, root asks the other active Claude sessions whether they plan to use the host. If any does, root waits for its permission. The rule is in the workflow guide validation.md, section Shared hardware tests. The host lock file still serializes runs within this project.

**Agent queue, in order:**
1. **13c-2.** Branch from `feat/rust-rewrite`; host lock.
2. **13b-1.** Branch `feat/asiaccs-s13b` from `feat/nick-branch`; no host lock. It can run in parallel with 13c-2 (agent cap 4 since 25 Nov 2026).
3. **13d-1b.** On `feat/asiaccs-s13d`, after 13c-2. Covers CK8, the three positive controls and `TL1-candidate`.
4. **13d-2.** Host lock.
5. **13b-2.** Host lock.
6. **`score_privoke.py --smoke`.** Runs under the host lock before 13a-5.

**Blocked on the user:**
- **13a-3, 13a-5, 13e:** need D1, D2, D4, D9 and D12, approval of the `sensitive` definition, and delivered prompts and labels (13a-2, 13a-4).
- **13e and 13f:** also need the D11 go decision.
- **13-P:** comes last.

---

## Stage 13-H: Commit-hygiene check (agent, first)

- **Objective:** build the S13-G8 check before any stage commits.
- **Paper question:** none. This stage protects the constraints that cover every sub-stage: no study prompt text, no weights and no private keys in Git.
  - **T→D→E→M→E:**
    - **Threat:** prompt text, weights or keys leak through a commit.
    - **Defense:** Git-ignored output paths and a diff scan.
    - **Experiment:** the scan, run on every stage diff.
    - **Metric:** the number of violations (required: 0).
    - **Evidence:** the exit status, recorded in each stage handoff.
- **Depends on:** none. Branch `feat/asiaccs-s13h` from `origin/feat/nick-branch`. Root merges it before any other stage.
- **Work:**
  - Write `evaluation/check_s13_commit_hygiene.py --repo <path> --range <a..b> [--local-inputs <dir>...] [--stage <id>]`.
  - **Default inputs.** `--local-inputs` defaults to every `D:/Git Repositories/Privoke-Research-Project/evaluation/results/s13*/` directory of the main checkout. The 8-gram prompt scan therefore always runs from the standard G8 command. The environment variable `S13_LOCAL_INPUTS_ROOT` overrides the default root, in normal runs and in tests.
  - **No local data.** When nothing matches, the script exits 0 and reports `local_inputs: 0`. This is the normal case for 13-H, 13a-0, 13a-1, 13c and 13d. `--require-local-inputs` turns that case into exit 2, and root passes it for 13a-3, 13a-5, 13b-2, 13b-3, 13e, 13f-1 and 13f-2.
  - **Stages without the flag.**
    - 13a-2 and 13a-4 are user stages with no commit, so G8 is "n/a, no stage diff" there.
    - 13b-1 commits only harness code. Its pilot data in `s13b/pilot/` is still scanned whenever the default root finds it.
  - It applies the S13-G8 rules to `git -C <path> diff --name-only <a..b>` and the file contents in that range.
  - **Wrapped prompts.** Before taking 8-grams, the script joins consecutive added lines of the same hunk with single spaces, so that a prompt wrapped across lines in `.md` or `.tex` is still matched. A newly added file is read as one text.
  - **8-gram lines.** The 8-gram rule reads only what the range adds. For a modified file, these are the `+` lines of `git -C <repo> diff -U0 <a..b> -- <file>`. For a newly added file (`--diff-filter=A`), it is the whole content. Old lines that the range leaves unchanged are never scanned. The name, key and weight rules are unchanged.
  - **8-gram scope.** The 8-gram rule applies to every file except `*.py`, `*.rs` and `*.mjs`. That includes `*.json`, `*.jsonl`, `*.csv`, `*.txt`, and `*.md` and `*.tex` anywhere. The exempt source files are checked only by the name, key and weight rules.
  - **Declared allowlist.** The pins live in a separate file, `evaluation/s13_allowlist.json` (`{path: sha256}`). 13-H creates the file and owns its format. 13a-1 and 13b-1 also own it, each only to add the pin for the file it creates.
    - **Which pins apply.** The script reads the pins from the tip of the target range, `git -C <repo> show <b>:evaluation/s13_allowlist.json`, not from the nick tree. A pin added on a stage branch therefore applies before that branch is merged. A missing file counts as `{}`.
    - **Review.** Root reviews every pin change as part of the stage diff.
    - **Guideline revisions.** When the user's dated guideline revisions land (13a-4), root updates the guideline-v2 pin in the same commit.
    - **Entries:**
      - `evaluation/e2e_evasion_transforms.py` (the 13b template module);
      - `docs/research/s13a-writer-brief-<date>.md`;
      - `docs/research/annotation-guideline-v2-<date>.md`.
    - **Pin-edit scope (`--stage <id>`).** The script's config maps each stage to the pin paths it may add or change:
      - 13a-1: the writer brief and guideline v2;
      - 13b-1: `evaluation/e2e_evasion_transforms.py`;
      - every other stage id (13-H, 13a-0, 13a-3, 13a-5, 13b-2, 13b-3, 13c-1, 13c-2, 13d-1, 13d-2, 13e, 13f-1, 13f-2, 13-P) has an **empty** scope, so any pin change it makes fails;
      - an unknown stage id is an error (exit 2), not an empty scope;
      - only root's final 13-P integration check runs without `--stage`, and it may touch any pin.

      A pin change in the range outside the scope of the given `--stage` is a violation, `rule: pin_scope`.

    Each pin is added by the stage that creates the file. An allowlisted path that is in the range and whose hash differs from its pin is a violation (`rule: allowlist_pin`).
  - **Speed.** The 8-grams of all local inputs are built once, as a set of 64-bit hashes of normalised token 8-grams. Each scanned file is then checked by set lookup, without comparing it pairwise with the prompts.
  - Root runs it from the nick tree, so it also checks the Rust-line stages. It imports nothing from the target repository.
- **Owned paths:** `evaluation/check_s13_commit_hygiene.py`, `evaluation/s13_allowlist.json` (created empty, `{}`), `evaluation/tests/test_check_s13_commit_hygiene.py`.
- **Interfaces and data shapes:** the script prints `{range, files_checked, local_inputs, violations:[{file, rule, line}]}` as JSON. It exits 1 on any violation, and 2 when `--require-local-inputs` is set and `local_inputs` is 0.
- **Acceptance checks:**
  - **Fixture tests pass:** `$PY -m unittest discover -s evaluation/tests -p test_check_s13_commit_hygiene.py`. The fixture repositories include:
    - a `text` field;
    - a planted 8-gram passed through `--local-inputs`;
    - a template `.py` that shares an 8-gram with a local variant **passes**, because source files skip the 8-gram rule;
    - a record JSON under `paper/research/` with a planted prompt **fails**;
    - a `docs/research/*.md` file with a planted prompt **fails**;
    - a `paper/main.tex` line with a planted prompt **fails**;
    - an old, unchanged line of a modified file that matches a local prompt **passes**;
    - a newly added line of that same file that matches **fails**;
    - a prompt wrapped over three consecutive added lines of a `.md` file **fails**;
    - a pin change outside the `--stage` scope (for example 13b-1 changing the guideline pin) **fails** with `pin_scope`, and the same change without `--stage` passes;
    - a pin added only at the range tip is honoured (the allowlist is read from `<b>`);
    - an allowlisted file whose hash differs from its pin **fails** with `allowlist_pin`, and one that matches its pin passes;
    - a planted prompt caught **through the default**: the test points `S13_LOCAL_INPUTS_ROOT` at a fixture root and calls the script without `--local-inputs`;
    - a glob test: under a fixture root with one planted prompt in each of `s13a/raw/`, `s13a/packet/`, `s13a/returned/`, `s13b/pilot/`, `s13b/run/`, `s13e/` and `s13f/`, plus a `s13-host.lock` file, the default scan finds all seven directories and ignores the lock file;
    - a `.safetensors` file;
    - each key pattern (OPENSSH, ENCRYPTED, and a line with a 64-hex seed);
    - a sha256 on a line that is not about a key, which must not be flagged;
    - an ignored output path;
    - no matching local inputs and no flag: exit 0 with `local_inputs: 0`;
    - no matching local inputs with `--require-local-inputs`: exit 2.
  - **The stage's own diff is clean:** `$PY evaluation/check_s13_commit_hygiene.py --repo . --range origin/feat/nick-branch..HEAD --stage 13-H` exits 0.
- **User dependency:** none.
- **Status:** done. Outcome: merged at `fe67f08` (implementation `176c096`..`3cd43e4`; 51 tests OK; G8 self-scan 0 violations). Implementation gate: 4 rounds, 10 findings accepted (UTF-16/NUL, Unicode and escape normalisation, BOM field checks, ignore probes, empty-input guard, a vacuous test, per-commit history scan, intermediate pins, padded UTF-16), 0 rejected; improvements declined (speculative or covered).
- **Handoff notes:**
  - Every later stage lists the G8 line among its acceptance checks.
  - Root runs that line, because the leaf's branch (for example a Rust-line branch) may not contain the script.

## Stage 13a-0: Resolve the `fresh_eval-folio-NN` partition leak (prerequisite)

- **Objective:** settle the Stage 8 finding before any annotation work.
  - Every one of the 1,560 AU3 `fresh_eval` texts contains a `fresh_eval-folio-NN` token.
  - The token names the partition, and its 24 values follow the audience-expression groups.
- **Paper question:** this is a precondition of 13a. Blinding fails if the text shown to annotators names the source or hints at a label.
  - **T→D→E→M→E:**
    - **Threat:** a marker in the text biases the annotators.
    - **Defense:** a blinding audit.
    - **Experiment:** scan every annotator-facing sheet with `DATASET_MARKER`.
    - **Metric:** the number of items with a marker (required: 0).
    - **Evidence:** `key/manifest.json` `blinding_audit`, plus the decision note.
- **Resolution (D5):**
  1. **Record that AU3 `fresh_eval` is ineligible as the 13a set.** 13a requires prompts that were never used in development, tuning or earlier evaluation, and `fresh_eval` is the RQ1 AU3 evaluation set. 13a uses a new set, so the leak cannot reach it.
  2. **For the deferred AU3 provisional-target packet**, record a normalisation rule to apply whenever it is run:
     - Before pre-registration, replace every whole `fresh_eval-folio-NN` token with the constant `folio`.
     - Apply the replacement identically for every annotator, and record both set hashes.
     - Run any PriVoke scoring against the normalised text.
  3. **Make the sampler's check a hard gate:** `sample_annotation.py --fail-on-marker` exits non-zero on any `DATASET_MARKER` match.
     - The pattern is `fresh_eval|release-\d+|AU3|folio-\d+` at line 122 of `sample_annotation.py`.
     - After normalisation, the `folio-\d+` alternative no longer matches, and the `fresh_eval` alternative still catches any partial replacement. The whole pattern is therefore the complete gate.
     - A test asserts that a normalised fixture matches no alternative, and that a fixture with a partial replacement fails.
     - `--marker-pattern` adds the source names that the 13a-1 contamination step finds.
- **Depends on:** none.
- **Owned paths:**
  - `evaluation/annotation/sample_annotation.py`: the `--fail-on-marker`, `--marker-pattern` and `--normalise-marker folio` flags;
  - `evaluation/annotation/tests/test_sampling.py`;
  - `docs/research/annotation-marker-decision-<date>.md` (new).
- **Interfaces and data shapes:** `key/manifest.json` gains:

  ```
  blinding_audit: {patterns, items_checked, items_with_marker,
                   normalisation: null | {pattern, replacement, original_sha256, normalised_sha256}}
  ```
- **Acceptance checks:**
  - **G8 hygiene (root runs it):** `$PY evaluation/check_s13_commit_hygiene.py --repo <stage worktree> --range <stage-base>..HEAD --stage 13a-0` exits 0.
  - **The sampling tests pass:** `$PY -m unittest discover -s evaluation/annotation/tests -p test_sampling.py`. This includes the new gate, normalisation and partial-replacement tests.
  - **The decision note exists:** `test -f docs/research/annotation-marker-decision-<date>.md`.
- **User dependency:** USER confirms D5. If the user does not answer, the default stands and the note records it as provisional.
- **Status:** done (D5 provisional, default applied). Outcome: `05651f9`, merged at `59510e0`; sampling tests OK; G8 0 violations.
- **Handoff notes:**
  - The protocol's step 9 commits annotator sheets, which contain text. Stage 13 commits label-only files instead; the note records this deviation.
  - The AU3 input exists only in the main checkout. Pass it with `--input`.

## Stage 13a-1: Packet for the independent human-annotated set (agent)

- **Objective:** build everything that the humans need for 13a, so that their time goes only to writing and labelling.
- **Paper question:** does PriVoke's accuracy hold against ground truth that no developer label influenced? (RQ1, `sec:final_annotation`.)
  - **T→D→E→M→E:**
    - **Threat:** developer-made labels inflate the measured protection, and under-enforcement goes unseen.
    - **Defense:** the shipped PriVoke pipeline and policy.
    - **Experiment:** score PriVoke on a fresh, blind, human-labelled set.
    - **Metric:** kappa per field; precision, recall, specificity and F1; under- and over-enforcement.
    - **Evidence:** the HUMANEVAL record, the set hash and the commit that froze the labels.
- **Depends on:** 13a-0.
- **Work:**
  1. **Writer brief** (`docs/research/s13a-writer-brief-<date>.md`), used if D1 chooses writers:
     - quotas over category × audience × sensitive or benign, with at least 45% sensitive and at least 20 per category;
     - invented people and values only;
     - writers must not read PriVoke code, data, rubrics or outputs.
     The brief has no example taken from a repository dataset, and it is committed before any writer starts.
  2. **Freezing the set** (`evaluation/annotation/fresh_set.py`):
     - Reads the user-supplied raw prompts from a Git-ignored path and normalises whitespace only.
     - Assigns opaque ids and removes exact duplicates.
     - Runs a contamination check. It looks for exact matches and for 8-gram Jaccard ≥ 0.5 against:
       - every prompt-bearing file in `evaluation/datasets/`;
       - `evaluation/results/` in the main checkout, including the frozen Stage 3 set;
       - the fuzzer curricula.
       It also runs the marker scan.
     - Writes `set_manifest.json`, with no text: `{schema, n, sha256_jsonl, source_kind, contamination: {sources_checked, exact, near, removed_ids}, quota_counts}`.
     - Flags: `--dry-run` reports counts only, and `--check-quotas` exits non-zero when the brief's quotas are unmet.
  3. **Schema v2** (`annotation_schema.py`, `SCHEMA_VERSION = 2`; v1 stays readable):
     - Fields:
       - `sensitive` (`yes`/`no`);
       - `subject`, meaning whose information it is (`SELF`, `THIRD_PARTY`, `PUBLIC_FIGURE`, `NONE`, `UNCLEAR`);
       - `audience`, the intended audience and context (`P0`–`P4`, `PU`, with the v1 visibility definitions);
       - `categories` (the 10 v1 categories, or `NONE`);
       - `action` (`ALLOW`, `WARN`, `BLOCK`);
       - `notes`.
     - `notes` stays in the local sheet only. It is never copied into a committed file, because it can quote the text.
     - A command-line validator: `python annotation_schema.py --validate <sheet.csv> --schema 2` exits non-zero on an empty or invalid cell.
  4. **Guideline v2** (`docs/research/annotation-guideline-v2-<date>.md`):
     - definitions for each field, a glossary and the annotator declaration form;
     - **no labelled worked examples written by an agent**.
     The matched-contrast worked examples (protocol section 2 plus `subject`) are either written by the user or another human, or drafted unlabelled by an agent with the user writing and approving the labels (USER, D12). Until then, the guideline ships without examples, and the packet status says so.
  5. **Sampling and blinding.** Use `sample_annotation.py` with `--stratify-by quota_cell` and `--fail-on-marker`. The size is 360 main items plus a 30-item pilot (D3). The seed is pre-registered.
     - The sampler writes `packet_manifest.json`: the sha256 of every blank sheet and of the key. These values contain no text.
     - New flag `--verify-against <packet_manifest.json>`: resample into a scratch directory, compare every hash, and exit non-zero on any difference.
  6. **Agreement** (`compute_iaa.py`):
     - add Fleiss' kappa (three or more annotators) next to Cohen's kappa per pair and per field;
     - categories use per-category binary kappa, exact-set agreement and Jaccard;
     - Krippendorff's alpha stays;
     - the bootstrap resamples `quota_cell` clusters;
     - `to_adjudicate.csv` contains text, so it is written only under `D:/Git Repositories/Privoke-Research-Project/evaluation/results/s13a/returned/`.
     - New flags:
       - `--min-kappa <x> --fields <f1,f2,..>` exits non-zero when any listed field's kappa is below `x`;
       - `--check-adjudication <adjudicated.csv>` exits non-zero unless every disagreement has a `resolution` and an `adjudicator`.
  7. **Scoring** (`evaluation/annotation/score_privoke.py`, run with `$PYPIPE`):
     - It refuses to run unless the freeze record exists and its hashes match (see 13a-5).
     - It runs two separately labelled arms (D6):
       - `product`, with layers [2, 3, 4], V3 balanced and the shipped defaults. Its `scope_label` is `product pipeline (in-process)`. The justification is the explicit request for PriVoke's accuracy in the supervisor request relayed by the user on 19 Nov 2026 (ASIACCS plan, Stage 13 "Source").
       - `semantic_only`, with layer [4] and scope `LLM-only (semantic)`.
     - The positive class is `sensitive = yes`. PriVoke's prediction counts as positive when its action is WARN or BLOCK.
     - Under-enforcement is a PriVoke action less strict than the reference label; over-enforcement is a stricter one.
     - Intervals are Wilson and cluster bootstrap.
  8. **Reports and order check:**
     - `human_eval_report.py --check` re-derives every kappa and score.
     - `check_order.py` verifies with `git merge-base --is-ancestor` that the set-manifest commit is an ancestor of the packet-manifest commit, which is an ancestor of the first label commit, which is an ancestor of the record commit.
     - The pre-registration template (`docs/research/s13a-preregistration-<date>.md`) lists the seed, sizes, fields, metrics, arms and analysis order.
  9. **Interface.** A CSV checked by the validator. A local HTML form is optional.
- **Owned paths:**
  - `evaluation/annotation/{fresh_set.py,score_privoke.py,human_eval_report.py,check_order.py}` (new);
  - `evaluation/s13_allowlist.json`: only the pins for the writer brief and guideline v2;
  - `evaluation/annotation/{annotation_schema.py,compute_iaa.py,agreement.py,sample_annotation.py}`;
  - `evaluation/annotation/tests/test_{fresh_set,fleiss,score_privoke,human_eval_report,check_order,sampling,agreement}.py`;
  - `docs/research/s13a-*.md` and `docs/research/annotation-guideline-v2-<date>.md`.
- **Interfaces and data shapes:**
  - The local sheet has the columns `item_id,text,sensitive,subject,audience,categories,action,notes`.
  - The committed label file has the columns `item_id,sensitive,subject,audience,categories,action`: no `text`, no `notes`.
  - The record JSON is:

    ```
    {schema:"privoke-s13a-v1", study_id, chain, build, scope_label,
     set:{sha256, n, source_kind, contamination},
     annotators:{count, familiarity_declared},
     pilot:{iaa},
     iaa:{<field>:{cohen:[{pair, kappa, ci95, n}], fleiss?, alpha, ci95}},
     adjudication:{items, resolution_counts, disagreement_types},
     freeze:{set_manifest_commit, packet_manifest_commit, label_commit, files:{name: sha256}},
     arms:[{arm, scope_label, justification, layers_requested, layers_executed_ok,
            metrics:{precision, recall, specificity, f1, under_enforcement, over_enforcement},
            per_category, per_audience}],
     not_established}
    ```

    Each metric is `{value, ci95, num, den}`.
- **Acceptance checks:**
  - **G8 hygiene (root runs it):** `$PY evaluation/check_s13_commit_hygiene.py --repo <stage worktree> --range <stage-base>..HEAD --stage 13a-1` exits 0.
  - **The annotation tests pass:** `$PY -m unittest discover -s evaluation/annotation/tests`. They cover:
    - kappa and Fleiss against hand-computed fixtures;
    - the scorer refusing to run without a freeze and refusing an empty layer list;
    - the contamination check flagging a planted duplicate;
    - the validator rejecting an invalid cell;
    - `check_order.py` failing on a fixture repository with the wrong order;
    - `sample_annotation.py --verify-against` failing on a changed sheet;
    - `compute_iaa.py --min-kappa/--fields` failing below the bar;
    - `compute_iaa.py --check-adjudication` failing on a missing resolution.
  - **No labels are committed:** `git ls-files docs/research/s13a/labels` prints nothing on this stage branch.
- **User dependency:** USER answers D1–D4 and D6, and writes or approves the worked examples (D12).
- **Status:** done (agent part). Outcome: `11b4ac5`, `5cbf68b`, `cd157aa`, merged at `59510e0`; 124 annotation tests OK; G8 0 violations. Implementation gate: 3 rounds, 9 findings accepted (sampler output confinement, the `sensitive` definition flagged for user approval and rephrased around harm, contamination containment, short prompts and empty sources, adjudication coverage, scorer layer errors, freeze gate binding, conditional enforcement rates, a multi-commit label regression, and an environment test switch), 0 rejected. Open before 13a-3: the user approves the `sensitive` definition and supplies worked examples (D12); `score_privoke.py --smoke` runs under the host lock before 13a-5; `fuzzer_curricula` is not a separate default (fuzzer outputs are covered through `results/`).
- **Handoff notes:** record the `$PYPIPE` interpreter path and the generated-client directory in the record. V3 balanced is read from the main checkout.

## Stage 13a-2: Recruit, write and deliver the fresh prompts (USER)

- **Objective:** produce the fresh set. No agent writes any of it.
- **Depends on:** 13a-1 (the brief).
- **Owned paths:** none in Git. The prompts are delivered to `D:/Git Repositories/Privoke-Research-Project/evaluation/results/s13a/raw/`, which is Git-ignored.
- **Acceptance checks:**
  - **G8 hygiene:** n/a, no stage diff (a user stage with no commit).
  - **The quotas are met:** `$PY evaluation/annotation/fresh_set.py --input <raw> --dry-run --check-quotas` exits 0 and prints the quota counts.
  - **The declarations are in:** the user confirms in chat that every writer signed the declaration.
- **User dependency:** USER does all of the following:
  - settles D4 (ethics);
  - recruits the writers, who are neither annotators nor developers (D1);
  - hands out the brief and collects the prompts at the path above;
  - keeps a private list of the people involved, outside the repository.
- **Status:** pending.
- **Handoff notes:** if D1 chooses a public corpus instead, this stage becomes:
  - a licence and ethics check by the user;
  - an agent sampling script with a recorded seed and the same contamination check.

  Real personal data stays local.

## Stage 13a-3: Freeze, sample and blind (agent)

- **Objective:** turn the raw prompts into a frozen set and blinded sheets, in an order that the commit history proves.
- **Depends on:** 13a-2.
- **Work:**
  1. Run `fresh_set.py`. Root commits `docs/research/s13a/set_manifest.json` on `feat/asiaccs-s13a` together with the filled pre-registration. `feat/asiaccs-s13a` is the branch on which `check_order.py` evaluates the order. The label and record commits of 13a-5 land on the same branch.
  2. Sample with `--fail-on-marker` into `--out D:/Git Repositories/Privoke-Research-Project/evaluation/results/s13a/packet/`.
  3. Root commits `docs/research/s13a/packet_manifest.json`, which holds the blank-sheet and key hashes, on `feat/asiaccs-s13a`. Only then does the user send out the sheets.
- **Owned paths:**
  - `docs/research/s13a/set_manifest.json`;
  - `docs/research/s13a/packet_manifest.json`;
  - `docs/research/s13a-preregistration-<date>.md`.
- **Acceptance checks:**
  - **G8 hygiene (root runs it):** `$PY evaluation/check_s13_commit_hygiene.py --repo <stage worktree> --range <stage-base>..HEAD --stage 13a-3 --require-local-inputs` exits 0.
  - **The set manifest came first:** `git merge-base --is-ancestor $(git log -1 --format=%H -- docs/research/s13a/set_manifest.json) $(git log -1 --format=%H -- docs/research/s13a/packet_manifest.json)` exits 0.
  - **The blinding audit is clean:** `$PY -c "import json,sys; m=json.load(open(sys.argv[1])); sys.exit(m['blinding_audit']['items_with_marker'])" "D:/Git Repositories/Privoke-Research-Project/evaluation/results/s13a/packet/key/manifest.json"` exits 0.
  - **The sheets are deterministic:** a second sampler run into a scratch directory gives the same hashes as `packet_manifest.json` (`$PY evaluation/annotation/sample_annotation.py ... --verify-against docs/research/s13a/packet_manifest.json` exits 0).
- **User dependency:** USER sends each annotator only their own `sheets/*_<annotator>.csv`. The coordinator keeps the key.
- **Status:** pending.
- **Handoff notes:** agents never open a completed sheet. They read the sheets only through `compute_iaa.py` and the adjudication export.

## Stage 13a-4: Annotate, calibrate and adjudicate (USER)

- **Objective:** human labels, agreement figures and adjudicated reference labels.
- **Depends on:** 13a-3.
- **Owned paths:** none in Git. Completed sheets and the adjudication file go to `D:/Git Repositories/Privoke-Research-Project/evaluation/results/s13a/returned/`.
- **Work:**
  - Follow steps 3–8 of the [runbook](../research/annotation-packet-status-20261116.md#3-runbook-for-two-human-annotators-and-a-coordinator), with the v2 fields.
  - Agents run `compute_iaa.py` for the pilot and the main round when asked, and write `to_adjudicate.csv` locally. That file is never committed, because it holds text.
  - A human adjudicator decides every item.
- **Acceptance checks:**
  - **G8 hygiene:** n/a, no stage diff (a user stage with no commit).
  - **The sheets are valid:** `$PY evaluation/annotation/annotation_schema.py --validate <sheet> --schema 2` exits 0 for every returned sheet.
  - **The pilot agrees well enough:** in `pilot_iaa.json`, the kappa for `sensitive`, `audience` and `action` is at least 0.6. If not, there is one revision and a repeat. The check is `$PY evaluation/annotation/compute_iaa.py ... --min-kappa 0.6 --fields sensitive,audience,action`, which exits non-zero below the bar.
  - **Adjudication is complete:** `$PY evaluation/annotation/compute_iaa.py --check-adjudication <adjudicated.csv>` exits 0. Every disagreement must have a `resolution` and an `adjudicator`.
- **User dependency:** USER runs the training, keeps the annotators independent, collects the sheets, organises the adjudication, dates every guideline revision, and reports any annotator who already knew PriVoke data.
- **Status:** pending.
- **Handoff notes:** about 19 hours of human time for 390 items and 2 annotators (protocol section 8).

## Stage 13a-5: Freeze the labels, score and record (agent)

- **Objective:** freeze the labels, then score PriVoke and write the HUMANEVAL record.
- **Depends on:** 13a-4, and the host lock for PriVoke scoring. When both are ready, 13a-5 goes before 13b-2.
- **Work:**
  1. Write the label-only CSVs (no `text`, no `notes`) for each annotator and for the adjudicated set into `docs/research/s13a/labels/`.
  2. Root commits them with `iaa.json` and their sha256 values. This is the freeze commit, and it comes before any PriVoke run on these items.
  3. Run `score_privoke.py` for both arms.
  4. Write the record and a draft ledger row. The ledger itself changes in 13-P.
- **Owned paths:**
  - `docs/research/s13a/labels/*.csv`;
  - `docs/research/s13a/iaa.json`;
  - `paper/research/human-annotated-eval-<date>.{md,json}`;
  - `docs/experiments/human-annotated-eval-<date>.md`.
- **Acceptance checks:**
  - **G8 hygiene (root runs it):** `$PY evaluation/check_s13_commit_hygiene.py --repo <stage worktree> --range <stage-base>..HEAD --stage 13a-5 --require-local-inputs` exits 0.
  - **S13-G1(a) holds:** `human_eval_report.py --check` and `check_order.py` both exit 0.
- **User dependency:** none.
- **Status:** pending.
- **Handoff notes:** use the protocol's wording, "agree at the reported rate with adjudicated labels from N annotators", and never "validated".

---

## Stage 13b-1: End-to-end evasion harness and variant set (agent)

- **Objective:** a harness that sends each adversarial variant through the installed extension to the local synthetic HTTPS receiver, and records whether the receiver got it.
- **Paper question:** can a user rewrite a sensitive prompt so that it reaches the external receiver unprotected? (`sec:eval_evasion`.)
  - **T→D→E→M→E:**
    - **Threat:** a user or a tool rewrites a prompt to evade detection.
    - **Defense:** in-page interception, then detection, then BLOCK or WARN.
    - **Experiment:** declared transforms sent through the installed extension to the synthetic receiver.
    - **Metric:** conditional and unconditional end-to-end ASR, beside the detector-level ASR on the same applicable pairs.
    - **Evidence:** the E2EEVADE record.
- **Depends on:** none.
- **Work:**
  1. **Seeds.** A stratified sample, with a recorded seed, from the frozen Stage 3 set at `D:/Git Repositories/Privoke-Research-Project/evaluation/results/adversarial_evasion_20261116/main/frozen_set.jsonl` (sha256 `5e4eac4c7c3117adf81a013fa9e4572484c9b0f41ab4b4f217ca960a82b634c2`). The harness verifies this hash before it reads anything.
     - **Link to F4, and disjointness.**
       - The Stage 3 build manifest is `D:/Git Repositories/Privoke-Research-Project/evaluation/results/adversarial_evasion_20261116/main/manifest.json`. It records `record: ADVEVADE-20261116` and `frozen_set_sha256: 5e4eac4c…`.
       - It names its source as `seed_file: …/evaluation/results/fresh_sets_20261025/f4_piimb/piimb_fresh_f4.jsonl`, with `seed_file_sha256: d4bed756790c7b000fc5e8b6028e3f962c8dbfabe3f607a7180224d55356589d`.
       - The [F4 freeze record](../research/fresh-sets-freeze-v3-20261025.md) lists that same file and hash. It also records that F4 is disjoint from the flag-design sets: `development.jsonl` (dev-TUNE and dev-CHECK), the personalised synthetic set and the OpenAI synthetic set.
       - The harness checks that `frozen_set.jsonl` hashes to `5e4eac4c…` and that the manifest's `seed_file_sha256` equals `d4bed756…`. It stops if either check fails.
     - **Disjointness from 13a.** The sample must also be disjoint from the 13a set. The 13a contamination check confirms this.
     - **Size.** `N_seed` is fixed after a 20-probe timing pilot so that one browser takes at most 8 hours, with a floor of 200. The pilot writes to `--out D:/Git Repositories/Privoke-Research-Project/evaluation/results/s13b/pilot/`.
     - **Re-use.** Reusing the frozen Stage 3 items keeps the variant text identical to Stage 3.
  2. **Variants.**
     - The Stage 3 families come from `adversarial_evasion_transforms.py`, unchanged, at its recorded revision.
     - `fragmented_identifier` and `mixed_language` are declared templates in a new `evaluation/e2e_evasion_transforms.py`.
     - Freeze the template hash before the first scored run, and verify it with `$PY evaluation/e2e_evasion.py verify-templates --expected-sha256 <hash>` (exit 0). Never edit the templates after any PriVoke output has been seen.
  3. **Runner** (`evaluation/e2e_evasion.py`), following Stage 11:
     - the unmodified extension in disposable profiles;
     - only the fixture hosts resolve;
     - the synthetic receiver, and the real supervisor and bridge on loopback.
     For each seed, the runner sends the untransformed `baseline` item end to end (Stage 3 calls this variant `BASELINE = "baseline"`), then every applicable variant. For each send it records:
     - whether the receiver got a request;
     - whether the variant payload arrived intact;
     - the page's `noticeStatus`;
     - the decision and the executed layers, from the bridge log.
  4. **Detector-level arm.** Score the same items with the Stage 3 in-process product client (`$PYPIPE`, layers [2, 3, 4]).
  5. **Scoring.** Both arms are scored with the Stage 3 functions `evaluate_arm` and `summarise_pairs`, imported from `adversarial_evasion.py`, on the **same applicable-pair set**: the pairs that both arms scored. The record lists any pairs that are excluded.
     - **Applicable:** the transform changed the text (Stage 3 definition).
     - **Intended action:** the action on the `baseline` item. The end-to-end arm uses its own end-to-end baseline, and the detector-level arm uses the in-process baseline.
     - **Protected:** the intended action is WARN or BLOCK, as in Stage 3. On the end-to-end side, BLOCK means the receiver got nothing, and WARN means the notice was shown before sending.
     - **Evasion:** a protected pair whose variant is delivered intact with no BLOCK and no WARN.
     - **Downgrade:** BLOCK becomes WARN.
     - **Fail-closed:** counted separately, never as protection.
     - **Conditional ASR** = evasions / protected applicable pairs. Each arm's denominator is its own baseline-protected set, so the denominators differ, and the record states both. **Unconditional ASR** = evasions / all applicable pairs.
     - **Paired conditional ASR.** Both arms are also scored on the intersection of their protected pairs (baseline protected end to end and at detector level), with an exact McNemar test on the discordant pairs.
     - **Value-removing families** (`indirect_pointer`, flagged `True` in the transform table) may leave the prompt no longer sensitive. They are reported separately, and every overall rate is given with and without them, using Stage 3's `overall_excluding_value_removing` key. A delivery of an `indirect_pointer` variant is never reported as a leak of the original value.
  6. **Expected executed layers.** Every end-to-end and detector-level response must execute [regex, ner, semantic], subject to the regex-first skip rule.
     - If the installed runtime cannot run the semantic layer, the run stops; it never silently drops a layer. This happened in Stage 11, where `PRIVOKE_USE_LOCAL_STACK=true` made the semantic layer unavailable.
     - Root then decides between making V3 balanced available locally (the default) and running a separately labelled regex+NER arm.
- **Owned paths:**
  - `evaluation/e2e_evasion.py`, `evaluation/e2e_evasion_transforms.py`, `evaluation/e2e_evasion_report.py`;
  - `evaluation/s13_allowlist.json`: only the pin for `evaluation/e2e_evasion_transforms.py`;
  - `extension/test/e2e-evasion-driver.mjs` (new; the Stage 11 driver is not edited);
  - `evaluation/tests/test_e2e_evasion*.py`.
- **Interfaces and data shapes:** one row per item and browser, holding ids only:

  ```
  {seed_id, variant, family, value_removing, applicable, browser, attended,
   receiver_got, payload_intact, warn_shown, decision,
   layers_requested, layers_executed, error,
   detector_level:{action, failed_closed, layers_executed},
   e2e_outcome: protected | evaded | downgraded | fail_closed | not_delivered_other,
   scope_label: "product pipeline (installed extension, end to end)"}
  ```

  Prompt text is stored only under `D:/Git Repositories/Privoke-Research-Project/evaluation/results/s13b/run/` (passed as `--out`).
- **Acceptance checks:**
  - **G8 hygiene (root runs it):** `$PY evaluation/check_s13_commit_hygiene.py --repo <stage worktree> --range <stage-base>..HEAD --stage 13b-1` exits 0.
  - **The harness tests pass:** `$PY -m unittest discover -s evaluation/tests -p "test_e2e_evasion*.py"`. They cover:
    - outcome classification;
    - matching Stage 3's `summarise_pairs` on a fixture;
    - the value-removing split;
    - refusing an empty layer list;
    - refusing a host that is not a fixture;
    - stopping on a layer mismatch.
  - **The templates are frozen before scoring:** `$PY evaluation/e2e_evasion.py verify-templates --expected-sha256 <hash>` exits 0. The template-hash commit must also be an ancestor of the first scored-run record (`git merge-base --is-ancestor`).
- **User dependency:** none.
- **Status:** pending.
- **Handoff notes:** take the request layers from the bridge log. `requireExplicitLayers` (`extension/src/analysis-request.js`) enforces a non-empty list in the extension.

## Stage 13b-2: Headless installed-extension run (agent)

- **Objective:** the main end-to-end run in Chrome, Edge and Firefox on Windows, headless and in disposable profiles. This is the agent-run method of Stage 11.
- **Depends on:** 13b-1, and the host lock (order: after 13d-2).
- **Owned paths:**
  - `paper/research/e2e-evasion-<date>.{md,json}`;
  - `docs/experiments/e2e-evasion-<date>.md`.
- **Acceptance checks:**
  - **G8 hygiene (root runs it):** `$PY evaluation/check_s13_commit_hygiene.py --repo <stage worktree> --range <stage-base>..HEAD --stage 13b-2 --require-local-inputs` exits 0.
  - **S13-G2 holds:** `$PY evaluation/e2e_evasion_report.py --check <json>` exits 0. The check fails if a browser is neither run nor listed with a reason.
  - **No outside host was contacted:** the record's `host_guard.outside_lookups` is 0, which `--check` verifies.
- **User dependency:** none.
- **Status:** pending.
- **Handoff notes:** release the host lock, and stop the supervisor, bridge, receiver and browsers.
- **User decision, 26 Nov 2026:** "the V3 balanced model not only lives locally on the machine, but also should be available through a local docker spin up test of the server stack."
  - 13b-2 measures the full three-layer product, with V3 balanced served by the local Docker server stack on loopback. It is not a reduced regex+NER arm.
  - Under the host lock, 13b-2 starts that stack and passes the harness `--stack` preflight before sending anything. The preflight checks that model streaming serves privoke-v3-balanced with the pinned checksum.
  - 13b-2 tears the stack down afterwards.
  - Before the run, apply the cross-session hardware rule.

## Stage 13b-3: Attended real-browser subset (USER)

- **Objective:** confirm the headless outcomes in the user's installed, headed browser for a stratified subset (D8). Here the native host launches normally and the notices are visible.
- **Depends on:** 13b-2, and the host lock.
- **Owned paths:** rows with `attended: true` added to the same record.
- **Acceptance checks:**
  - **G8 hygiene (root runs it):** `$PY evaluation/check_s13_commit_hygiene.py --repo <stage worktree> --range <stage-base>..HEAD --stage 13b-3 --require-local-inputs` exits 0.
  - **the attended rows check out:** `$PY evaluation/e2e_evasion_report.py --check <json> --require-attended` exits 0. It requires the attended rows to have the full row fields and reports any disagreement with the headless rows.
- **User dependency:** USER runs the provided script, which opens the fixture page in the user's browser with the installed extension. The user submits each listed variant when prompted, and leaves the machine otherwise idle. No real provider is involved.
- **Status:** pending.
- **Handoff notes:** a `live` addendum is possible only with D7 approval, and then only with non-sensitive synthetic seeds.

---

## Stage 13c: Active attacks on the V3 guarded update path

### 13c-1: Attack matrix in CI (agent)

- **Objective:** drive each attack against the real V3 commit path, on `feat/asiaccs-s13c` (from `feat/rust-rewrite`), and record the rejecting check and the active model before and after.
- **Paper question:** can an invalid, stale, replayed or behaviourally unsafe update replace the active model? (RQ2, `sec:eval_update`.)
  - **T→D→E→M→E:**
    - **Threat:** a compromised or faulty trainer (a principal with the `trainer` or `publisher` role), or a corrupted transfer or store, supplies a bad candidate.
    - **Defense:**
      1. Admission (`admit_candidate`).
      2. The observer `prepare` steps, run **before** the compare-and-swap transaction, in this order: DriftGate, GuardGate, RetentionGate, then the Publisher's staging.
      3. Inside the `BEGIN IMMEDIATE` transaction: the compare-and-swap with request-id idempotence, the `stale_base` and trainer-evidence guard checks, then signing and the `publications` insert (the Publisher's `before_swap`).
      4. After the commit: the Publisher's rename and pointer move.
      5. model-streaming serves only signed versions.
      6. Clients apply `admit_lineage` and `verify_package`.
    - **Experiment:** the attack matrix below.
    - **Metric:** for each attack, whether the active model is unchanged in the sense of "Shared conventions" (required), or recovered with `applied_recovered`, plus the rejecting check.
    - **Evidence:** the V3UPDATK record.
- **Depends on:** none.
- **Harness seam.** Move the observer construction out of `open_checkpoint` in `rust/services/param-update/src/main.rs` (at `4d838fd`) into `src/lib.rs`:

  ```rust
  pub fn build_observers(
      config: &V3Config,
      sources: Arc<PinnedSources>,
      allocations: Arc<dyn Allocations>,
      crash: CrashHook,
      guard_scorer: Option<Arc<dyn GuardScorer>>,
      retention_scorer: Option<Arc<dyn RetentionScorer>>,
  ) -> Result<(Vec<Arc<dyn CommitObserver>>, Option<Arc<Publisher>>)>
  ```

  - **Order.** The function builds the observers in the same order as `main.rs` today:
    - `DriftGate`;
    - `GuardGate::new(..)` with `.with_scorer(s)` when a scorer is given;
    - `RetentionGate::new(..)` with `.with_scorer(s)` when the config has retention;
    - `Publisher::new(.., crash)` when the config has publication.
  - **`main.rs`** passes `JournalAllocations`, `no_crash()`, `None` and `None` (the real scorers).
  - **Contract.** The seam changes no behaviour. The existing `tests/v3_deployment.rs` and `tests/scheduler_chain.rs` still pass.
- **Harness.**
  - **Location.** A Rust integration test, `rust/services/param-update/tests/s13c_update_attacks.rs`. It builds its store world from the V3 fixtures in `tests/golden_world/mod.rs` and the toy-candidate pattern of `tests/scheduler_chain.rs`. It does not use the V1-oriented `tests/common`, apart from that file's PKI and mutual-TLS helpers.
  - **Checkpoints and keys.** Checkpoints are generated in test code: stand-in weights with the fixture `config.json` and `vocab.txt`. **No weights are committed.**
  - **Scorers.** `Fixed` is private to `tests/v3_guard.rs`, so the test writes its own `GuardScorer` and `RetentionScorer` doubles, modelled on `Fixed` in `tests/v3_guard.rs` and on `Better` and `Retains` in `tests/scheduler_chain.rs`.
  - **Wiring.** Observers come from `build_observers` with a test publication key and a recording `CrashHook`. The store is seeded with `bootstrap_pinned`, uses `rust/services/param-update/config/v3-drift-bounds.toml` and the committed retention references, and the allocations come from a test `Allocations`.
  - **Transport.** Calls go through the real `CheckpointService` over mutual TLS (pattern of `tests/checkpoint_mtls.rs`), as the `trainer` principal.
  - **Observation.**
    - The store authority is read directly.
    - The served version comes from the `published.rs` library API of model-streaming, over the same store and publish root. `privoke-model-streaming` is already a normal dependency of param-update (`rust/services/param-update/Cargo.toml`).
  - **Client checks.** The client-side checks (`admit_lineage`, and `verify_package` in `rust/services/runtime-supervisor/src/fetch.rs`) are tested in **runtime-supervisor**, not in param-update, because runtime-supervisor is not a dependency of param-update. The test is `rust/services/runtime-supervisor/tests/s13c_client_admission.rs`, built on the synthetic efficient-tier chain of `tests/lineage_fetch.rs` and `privoke-contracts/tests/fixtures/v3_signed_chain/chain.json`.
  - **Outputs.**
    - With `S13C_OUT` set, both tests write their rows as JSON. They assert each row's expected outcome, so CI fails on any regression.
    - CI bundles use stand-in weights and test scorers, so they are **not** used against the containers. 13c-2 builds the container-leg candidates.
  - **Allocation format (defined once, here).** `S13C_ALLOCATIONS` is a JSON array of objects that mirror the `v3_allocations` columns:
    - `{request_id, cycle, model_id, stage: "heads"|"full_encoder", attempt, sampler, seed, expected_base, source_commitment, state: "allocated"}`;
    - `candidate` and `reason` are omitted, because they are written only when a request is settled.

    The `s13c_journal_seed` helper (13c-2) and every 13d Python allocation writer use exactly this format, and the helper rejects unknown or missing fields. The schema is checked in `evaluation/tests/test_v3_update_attacks_report.py`.
  - **Row manifest.** `rust/services/param-update/tests/s13c_rows.json` lists every variant id with these fields: `{id, attack_class, expected, chain, surface: param-update|model-streaming|client|store, wire_path, legs, ci_only_reason}`.
    - **`wire_path: false` rows:**
      - the crash points (C10a–e, surface `store`);
      - at-rest corruption: C9e (surface `store`), C9f-serve (surface `model-streaming`) and C9f-client (surface `client`);
      - the client-only rows C2c, C2d, C4f and CS1–CS4 (surface `client`, except CS1, which is `model-streaming` serving a planted directory). These run in the CI legs only: `s13c_client_admission` and the in-process model-streaming read.
    - **CI-only rows.** These have `legs: ["ci"]` and a written `ci_only_reason`, and are not run in the container leg:
      - **C1b:** it needs two distinct genuine candidates on one base, and the real leg builds only one.
      - **C1d:** it needs a deployment without the Publisher, and the container leg runs the `main.rs` chain with publication configured.
    - **`wire_path: true` rows:** every other variant, with surface `param-update` or `model-streaming`.
    - **Readers.** The param-update tests read the manifest. `s13c_client_admission` (runtime-supervisor) reads the same file by path: `CARGO_MANIFEST_DIR/../param-update/tests/s13c_rows.json`, using its `surface: client` rows. `v3_update_attacks_report.py --check` reads it too.
    - **`--check` fails** when a manifest id has no row, when a row has no manifest id, or when a `wire_path: true` row that is not CI-only has neither a `container` row nor a `not_run_reason`.
- **Attack-to-check map.** Every check named here was read with `git show origin/feat/rust-rewrite:<path>`. `store.rs` means `rust/services/param-update/src/v3_store/store.rs`, and `v3.rs` means `rust/crates/privoke-contracts/src/v3.rs`.
  - **Reason order.** Admission errors come first. They raise `INVALID_ARGUMENT` before any transaction and leave no receipt; this includes `validate_execution` and the commit-identity check. Next, the observer refusals in `prepare` are computed. Inside the transaction, the receipt reason is `stale_base` first, then `guard_rejected` (`v3::publication_passes`), and only then the first `prepare` refusal.
  - **Isolation.** Each row isolates one fault. Rows that combine faults are labelled `combined`.
  - **Expected values:**
    - `rejected_unchanged`;
    - `noop_unchanged`: the stored receipt is returned and nothing is swapped;
    - `applied_recovered`: the authority applied the candidate before the crash. The served version is the old complete version or the new complete signed one, never partial, and after `reconcile` the authority and the served version agree;
    - `accepted_by_design`.

  | # | Attack | Variants | Rejecting check (file → symbol / message or reason) | Expected |
  | --- | --- | --- | --- | --- |
  | 1 | Stale parent | **C1a:** the candidate's parent was current, then another candidate on the same base was applied. **C1b:** two distinct candidates, each with its own evidence and request id, race on one base. **C1c:** `RollbackModel` to a manifest that was never committed for the model. **C1d** (chain `no_publisher`: `main.rs` without V3 publication config): `RollbackModel` to a version that went live unsigned | `store.rs` `commit` compare-and-swap → receipt `rejected`/`stale_base`. The race loser never reaches `Publisher::before_swap`, so it gets no `publications` row. `store.rs` `rollback` → "Rollback target is not in the history of this model." (C1c), and "Rollback target was never published." (C1d). The main chain cannot produce an unsigned live version, so C1d exists only for the `no_publisher` deployment | `rejected_unchanged` |
  | 2 | Replay | **C2a:** the same request id and content after a later update. **C2b:** the same id with different content. **C2c:** the client is served an older signed statement. **C2d:** the client is served the unsigned pin after a signed version | `store.rs` `replay`/`replayed` returns the stored receipt (C2a records `receipt_status=applied`, `expected=noop_unchanged`); "Request ID reused with different commit content." (C2b); `v3.rs` `admit_lineage` → `LineageError::Replay` (C2c), `LineageError::Downgrade` (C2d) | C2a `noop_unchanged`; the rest `rejected_unchanged` |
  | 3 | Duplicate | **C3a:** a candidate that is already current is committed again under a new request id. **C3b:** the same candidate is staged twice | `store.rs` `commit` requires `evidence["request_id"] == request.request_id` before the transaction → `INVALID_ARGUMENT` "Commit identity differs from candidate/fit evidence.", with no receipt (C3a). `put` is content-addressed, so the second stage is idempotent (C3b). `stale_base` with a distinct candidate is C1b | at most one application and one `publications` row; `rejected_unchanged` |
  | 4 | Wrong model or version id | **C4a:** `Commit.model_id` differs from the manifest. **C4b:** the manifest `model_id`, `tier`, `config` or `vocab` differs from the parent. **C4c:** a wrong `original`. **C4d:** `expected_base` differs from the manifest's `parent`. **C4e:** scope `original`. **C4f:** the client receives a statement for another model or manifest | `store.rs` `commit` → "Commit identity differs from candidate/fit evidence." (C4a, C4d); `admit_candidate` → "Candidate changed immutable model provenance/config." (C4b), "Candidate ORIGINAL binding mismatch." (C4c), "Candidates cannot claim ORIGINAL scope." (C4e); `v3.rs` `LineageError::StatementModel` / `StatementManifest` / `WrongOriginal` (C4f) | `rejected_unchanged` |
  | 5 | Wrong tensor name | **C5a:** a tensor renamed in both the manifest and the blob. **C5b:** the manifest inventory differs from the blob | `store.rs` `admit_candidate` → "Candidate changed admitted tensor inventory." (C5a); `verify_checkpoint` → "Safetensors inventory differs from manifest." (C5b) | `rejected_unchanged` |
  | 6 | Wrong tensor shape | **C6a:** the shape changed in both the manifest and the blob. **C6b:** the shape changed only in the blob | The same two checks; `inventory` compares shape and dtype | `rejected_unchanged` |
  | 7 | NaN or Inf | **C7a–c:** NaN, +Inf and −Inf in one heads coordinate | `rust/crates/privoke-semantic/src/safetensors.rs` finite check, called from `store.rs` `verify_checkpoint` → "Snapshot tensors must be finite float32." | `rejected_unchanged` |
  | 8 | Excessive parameter change | **C8a:** one update above `max_update_l2`. **C8b:** a run of updates each under the per-update bound until the cumulative cap of 100. **C8c:** a HEADS candidate that changes encoder bytes, with honest evidence. **C8d:** the same with dishonest `changed_tensors` / `changes` | `rust/services/param-update/src/v3_policy.rs` `DriftGate::prepare` → `drift_exceeded` (C8a, C8b; cumulative from `DriftGate::root`). C8c: `v3.rs` `validate_execution` → "HEADS changed pretrained encoder." (`tensor_changes` counts every `encoder.*` tensor, embeddings and pooler included). C8d: `store.rs` `admit_candidate` → "Reported changes differ from actual checkpoint tensors.". The store's own "HEADS candidate changed pretrained encoder/pooler bytes." cannot be reached after these two checks, so no row targets it | C8a and C8b `rejected_unchanged` with receipt `drift_exceeded`; C8c and C8d `INVALID_ARGUMENT`, unchanged |
  | 9 | Truncated or corrupted artifact | **C9a:** the stream ends early. **C9b:** an offset gap. **C9c:** the declared sha256 differs from the bytes. **C9d:** the manifest `blob` differs from the uploaded bytes. **C9e:** a store blob is corrupted at rest before commit. **C9f:** a published asset is corrupted at rest before serving | `rust/services/param-update/src/v3_store/service.rs` `stage_checkpoint` → "Incomplete/corrupt checkpoint upload." / "Invalid bounded ordered checkpoint upload."; `store.rs` `stage` → "Candidate snapshot identity mismatch."; `read` → "Immutable blob hash mismatch."; `rust/services/model-streaming/src/published.rs` `stream_asset` re-hash; `rust/services/runtime-supervisor/src/fetch.rs` `verify_package` (C9f client side) | `rejected_unchanged`; C9e and C9f are labelled at-rest defence in depth |
  | 10 | Interrupted publication | **C10a:** `staged`. **C10b:** `signed`. **C10c:** `committed`. **C10d:** `renamed`. **C10e:** `pointer`. Each is a `CrashHook` failure (`rust/services/param-update/src/v3_publish.rs`), followed by a restart and `Publisher::reconcile` | `staged` (`prepare`) and `signed` (`before_swap`, inside the transaction): the commit errors and the transaction rolls back. `committed`, `renamed` and `pointer` (after the transaction): the authority is already applied, and `reconcile` promotes or rebuilds, repairs the pointer and quarantines | C10a and C10b `rejected_unchanged`; C10c–e `applied_recovered` |
  | 11 | Better aggregate but broken guard cases | **C11a:** honest evidence of a guard harm. **C11b:** evidence claims a pass, but the recomputed guard fails. **C11c:** substituted guard rows. **C11d:** a trainer-chosen source or seed. **C11e:** an unallocated request id. **C11f:** reference rows regress beyond the 5% allowance. **C11g:** the boundary, exactly the allowance (7, 9 or 10 rows) | `store.rs` `commit` via `v3::publication_passes` → `guard_rejected`; `rust/services/param-update/src/v3_guard.rs` `GuardGate` → `guard_recomputed`, `guard_rows_differ`, `commitment_mismatch`, `request_not_allocated` / `allocation_mismatch`; `rust/services/param-update/src/v3_retention.rs` `RetentionGate` → `retention_regressed` | C11a–f `rejected_unchanged`; **C11g `accepted_by_design`**, reported as a documented limit |
  | S | Client signature and lineage (included because the question covers the model that clients run) | **CS1:** a version directory placed in the publish root with no authority row. **CS2:** an unknown key. **CS3:** a tampered statement. **CS4:** an unsigned manifest that is not the pin | `published.rs` `is_published` (authority only); `rust/crates/privoke-contracts/src/publication.rs` verification → `LineageError::Publication`; `v3.rs` `LineageError::Unsigned` | not served, or refused by the client; the client mark is unchanged |

  **C8b.** It needs about 25 updates, each just under the per-update bound, to reach the cumulative cap of 100. It runs **synthetically in CI only**, with stand-in weights and the test scorers. The real-weight leg records it as `not_run` with that reason.
- **Owned paths:**
  - `rust/services/param-update/src/{lib.rs,main.rs}` (the `build_observers` seam only);
  - `rust/services/param-update/tests/s13c_update_attacks.rs` and `tests/s13c_rows.json` (new);
  - `rust/services/runtime-supervisor/tests/s13c_client_admission.rs` (new);
  - `evaluation/v3_update_attacks_report.py` and `evaluation/tests/test_v3_update_attacks_report.py` (new).
- **Interfaces and data shapes:** one row per attack variant:

  ```
  {id, attack_class: 1..11 | "S", variant, combined, chain: "main" | "no_publisher",
   leg: "ci" | "real" | "container", surface: stage | commit | rollback | serve | client,
   identity, attempted:{request_id, model_id, expected_base, candidate_sha, mutation},
   expected: rejected_unchanged | noop_unchanged | applied_recovered | accepted_by_design,
   observed:{grpc_code, receipt_status, receipt_reason, message},
   rejecting_check:{file, symbol, reason},
   active_before:{store_current, versions_count, max_sequence, served_manifest, client_mark},
   active_after:{...}, orphan_blobs, property_met, not_run_reason}
  ```
- **Acceptance checks:**
  - **G8 hygiene (root runs it):** `$PY evaluation/check_s13_commit_hygiene.py --repo <stage worktree> --range <stage-base>..HEAD --stage 13c-1` exits 0.
  - **The param-update attack test passes:** `RUSTDOCK cargo test -p privoke-param-update --release --locked --test s13c_update_attacks` exits 0.
  - **The rest of param-update still passes:** `RUSTDOCK cargo test -p privoke-param-update --release --locked` exits 0. This includes `v3_deployment` and `scheduler_chain`, which show the seam changed no behaviour.
  - **The client admission test passes:** `RUSTDOCK cargo test -p privoke-runtime-supervisor --release --locked --test s13c_client_admission` exits 0.
  - **The report tests pass:** `$PY -m unittest discover -s evaluation/tests -p test_v3_update_attacks_report.py`.
- **User dependency:** none.
- **Status:** done. Outcome: merged into `feat/rust-rewrite` at `bc6be30` (`f116284`, `6d45538`, `e05ba63`): 50 manifest rows, 43 wire and store rows in `s13c_update_attacks` plus 7 client rows, all passing in Docker; full param-update package and clippy clean; G8 0 violations. Implementation gate: 2 rounds, 4 findings accepted. Deviations recorded: C3b is `noop_unchanged` (the second stage is idempotent and returns OK); C10c serves `refused:UNAVAILABLE` until `reconcile` (fail closed, never partial); C11c and C11d are labelled defence in depth, because CI stubs admission source validation and production refuses them at stage with INVALID_ARGUMENT (13c-2 records that admission-level refusal next to the CI GuardGate row); the retention branch of `build_observers` is untested in CI (no bank fixture), and the test inserts its own RetentionGate with the committed allowances.
- **Handoff notes:**
  - The V1 rows of `update_security.py --target rust --rust-service param-update` (A1–E7, R1, R2, R5) only show that `SubmitParameterUpdate` is `UNIMPLEMENTED`. They are not 13c evidence.
  - Never use `PRODUCTION_KEYS` or the production key. Test keys enter only through dev-dependencies, which CI's `cargo tree` check enforces.

### 13c-2: Real-weight and container legs, and the record (agent)

- **Objective:**
  - Repeat the scorer-dependent rows (C11b, C11f, C11g) with the real Rust V3 encoder and the efficient-tier release.
  - Run every `wire_path: true` variant of `s13c_rows.json` against the Compose `v3-training` containers on loopback (test PKI, test publication key). Observe the served version through model-streaming `GetModelPackage` in those runs.
  - Write the V3UPDATK record.
- **Depends on:** 13c-1, and the host lock (first in the order).
- **Work:**
  - **Real-weight leg.** An env-gated test, `s13c_update_attacks_real.rs`, following the pattern of `rust/services/v3-fuzzer/tests/scheduler_real.rs`. Docker mounts `models/standard-releases` and the ORIGINAL read-only.
  - **Container-leg candidates.** The containers run the real GuardGate and RetentionGate scorers against the real release. CI stand-in bundles would therefore fail there for the wrong reason: on parent or ORIGINAL binding, `guard_recomputed` or `retention_regressed`. Two kinds of candidate are used instead.
    - **Rejection-only rows.**
      - Derived from the real efficient release: parent = the pin, `original` = its ORIGINAL, with synthetic evidence, then mutated per row.
      - Each is designed to fail at an admission check or an early gate, before any gate that uses a real scorer.
    - **Genuine candidate.**
      - One real-weight candidate that the real gates accept.
      - Built in the real leg by a real routine fit, following `rust/services/v3-fuzzer/tests/scheduler_real.rs`, and written with `S13C_EXPORT_CANDIDATES=<scratch dir>`.
      - It drives the positive controls (publisher commit applied, runtime stage accepted, and the 13d controls).
      - It drives C2a over the wire.
      - The late-gate rows (C1a, C3a, C8a and C11) are mutations of it. C1b is CI-only.
    - **Order of the genuine-candidate sequence on one container stack.** Let P be the pin (current at start) and G the genuine candidate, with parent P and evidence naming request `r1`. All allocations go in with `s13c_journal_seed` before the run.
      1. **Positive control.** Commit G as `r1` (expected base P) → `applied`. The current version becomes G, and the served version is G with a new sequence.
      2. **C3a.** Commit G again under a new id `r4` with G's own evidence, which still names `r1` → `INVALID_ARGUMENT` "Commit identity differs from candidate/fit evidence.". No receipt; unchanged.
      3. **C1a.** G′ is G's blob with its evidence rewritten to name request `r3` (a new evidence blob and manifest; parent P; allocation `r3` with expected base P). Commit G′ as `r3` → `rejected`/`stale_base`, because the current version is G, not P. Unchanged.
         - **Staging order.** First stage the canonically re-serialised evidence blob, a manifest-free `StageCheckpoint`. Then stage the blob with the new manifest, `StageCheckpoint` with `manifest_json`. `commit` reads the manifest from the store, so both must be stored before the commit.
         - **Expected path.** `RetentionGate::prepare` returns `Ok(None)` because the current version is not the expected base. The `stale_base` receipt therefore comes from the transaction's compare-and-swap, not from a gate.
      4. **Rollback control (this is "the later update").** `RollbackModel` to P as `publisher`, request `r2` → `applied`. The current version becomes P, at a higher sequence.
      5. **C2a.** Resend the exact `r1` commit → the stored receipt (`receipt_status=applied`) and no swap. The current version stays P, so the expected value is `noop_unchanged`.
      6. **C8a and C11.** Run the late-gate mutations of G from base P (allocations with expected base P). Each must be rejected with P unchanged.
    - **If the genuine build fails** (for example `guard_rejected` by the trainer-evidence rule, as happened in V3-R6 and V3-R7):
      - those rows become `not_run`, with the reason and the failed request id recorded;
      - they are never replaced with stand-in bundles.
  - **Allocations.**
    - **Who owns the journal.** It belongs to the param-update scheduler: the SQLite file that `rust/services/param-update/src/journal.rs` `Journal::open` creates. GuardGate reads it through `JournalAllocations`. It has two tables:
      - `v3_cycles`;
      - `v3_allocations`, with the columns `request_id, cycle, model_id, stage, attempt, sampler, seed, expected_base, source_commitment, state, candidate, reason`.
    - **Scheduler off.** The container leg runs param-update with `FUZZER_PROMPT_COUNT=0`. `main.rs` starts the scheduler only when that count is above 0, so the scheduler does not run.
    - **Writing allocations.** The leg writes them only through a Rust helper: the env-gated test `s13c_journal_seed` in `s13c_update_attacks_real.rs`. It calls `Journal::open` and `Journal::allocate`, and runs only while the param-update container is stopped. Host Python calls it as:
      ```
      RUSTDOCK cargo test -p privoke-param-update --release --locked --test s13c_update_attacks_real s13c_journal_seed
      ```
      with `S13C_JOURNAL=<mounted file>` and `S13C_ALLOCATIONS=<json>`.
    - **Reuse.** 13d-1b reuses this harness seam, in the allocation format defined in 13c-1.
  - **Container leg.**
    - The same test, with `S13C_ENDPOINT` set.
    - It runs against param-update and model-streaming, started from `docker compose --profile v3-training up`.
    - The stack is torn down afterwards.
- **Owned paths:**
  - `rust/services/param-update/tests/s13c_update_attacks_real.rs`;
  - the `s13c_journal_seed` helper in that test;
  - the record field `fit_timings: [{request_id, tier, scope, wall_seconds, cpus, outcome}]`, holding the wall-clock time of every real-leg fit, successful or not (for planning; it is not a result).
  - `paper/research/v3-update-attacks-<date>.{md,json}`;
  - `docs/experiments/v3-update-attacks-<date>.md`.
- **Acceptance checks:**
  - **G8 hygiene (root runs it):** `$PY evaluation/check_s13_commit_hygiene.py --repo <stage worktree> --range <stage-base>..HEAD --stage 13c-2` exits 0.
  - **S13-G3 holds.** `$PY evaluation/v3_update_attacks_report.py --check <json>` exits 0. Among other things, `--check` fails when a class with a wire path has neither a `container` row with `active_after.served_manifest` nor a `not_run_reason`.
- **User dependency:** none.
- **Status:** pending.
- **Handoff notes:** the record reaches `feat/nick-branch` only through the record import.

---

## Stage 13d: Authentication and authorisation against the Rust stack

### 13d-1: Row families and PKI (agent; parts 13d-1a and 13d-1b)

- **Objective:** extend `evaluation/update_security.py --target rust` to answer the 13d question against the current Rust services, including the V3 `CheckpointService` and publication.
- **Paper question:** can an unauthorised identity retrieve protected resources, submit updates or publish a candidate model? (RQ2 attack resistance, `sec:eval_auth`.)
  - **T→D→E→M→E:**
    - **Threat:** an attacker with no credentials, wrong credentials or stolen low-privilege credentials.
    - **Defense:** mutual TLS with the rustls verifier and CRL hot reload; the registry; the role policy; the RPC surface; and the V3 store's application checks.
    - **Experiment:** negative rows from a host Python client against the containers.
    - **Metric:** for each attack, denial (required) and the denying layer.
    - **Evidence:** the AUTHZ record.
- **Parts and dependencies:**
  - **13d-1a (24–28 Nov)** covers every row that needs no candidate:
    - the PKI;
    - CK1–CK7 and CK9;
    - the TL rows;
    - the re-run families;
    - the `denied_by` field and the coverage checks.

    It depends on nothing.
  - **13d-1b (after 13c-2, under the host lock)** covers CK8 and the positive controls.
    - They need the genuine real-weight candidate and its rejection-only derivatives, exported by 13c-2, plus the `s13c_journal_seed` allocation helper.
    - Without a genuine candidate, these rows are `not_run`, with the reason from 13c-2.
- **Work:**
  1. **PKI.**
     - **Legitimate principals come from `privoke-pki`:**
       - `init-ca` for the client CA and the server CA;
       - `issue-server`;
       - `sign-service` for `publisher`, `trainer` and `runtime`;
       - `enrol`, then `sign`, then `install-cert` for installations;
       - `issue-reporter`;
       - `revoke`, then `crl`.

       Confirm the subcommand spellings with `privoke-pki --help`.
     - **Deliberately invalid credentials come from the OpenSSL helper** in `update_security_pki.py`: expired, not yet valid, no client-auth EKU, a foreign CA, and self-signed. `privoke-pki` will not mint these.
     - Each row records `credential_issuer`.
  2. **`CK` rows for `CheckpointService`**, following the policy in `rust/services/param-update/src/server.rs` `policy()`:

     | Row | Attempt | Expected |
     | --- | --- | --- |
     | CK1 | `CommitCandidate` as `runtime` | `PERMISSION_DENIED` |
     | CK2 | `RollbackModel` as `trainer` | `PERMISSION_DENIED` |
     | CK3 | `CommitCandidate` with a registered installation certificate | `PERMISSION_DENIED` |
     | CK4 | `CommitCandidate` with the reporter credential | `PERMISSION_DENIED` |
     | CK5 | `StageCheckpoint` with no certificate | handshake failure |
     | CK6 | `CommitCandidate` from a revoked trainer, after a CRL swap | handshake failure, no restart |
     | CK7 | `CommitCandidate` from a deny-listed trainer on an open connection | `PERMISSION_DENIED` |
     | CK8 | `CommitCandidate` from a valid trainer, carrying a valid 13c candidate, with an unallocated request id | `rejected`/`request_not_allocated` (application layer; cross-identity misuse) |
     | CK9 | An unlisted RPC | `UNIMPLEMENTED` |

     **Positive controls:**
     - a `publisher` commit of an allocated valid candidate, applied;
     - a `publisher` rollback to the pin, applied;
     - a `runtime` stage, accepted.

     CK8 and these positive controls belong to 13d-1b. They use the 13c-2 candidates and the `s13c_journal_seed` helper. 13d's Python side writes its allocations as `S13C_ALLOCATIONS` JSON in the 13c-1 format and passes them to that helper.
  3. **`TL` rows (TLS level):**
     - **TL1:** replay the captured TLS 1.3 bytes of an authenticated `CommitCandidate` on a new connection. Expected: no receipt.
     - **TL2:** flip one bit through a loopback TCP proxy. Expected: the connection aborts, and there is no receipt.
     - **TL3:** a man in the middle presents a server certificate that is not from the server CA. Expected: the client refuses.

     Application-level replay is covered by 13c rows C2a and C2b, which AUTHZ cross-references.
  4. **Re-run the existing Rust families with the V3 packages present**, without `--no-v3`: T, R3, R4, R7, R8, R9, X8, X13 live, R6 and R10. This makes the 9 rows that are `not_run` in UPDSEC-20261117 run: T7, T9, T10, R8-wrong-pin, R8-not-allowlisted, I3, X1, X1b and X1c.
  5. **`denied_by` on every row.** The values are:
     - `tls_handshake`;
     - `revocation`;
     - `registry`;
     - `role_policy`;
     - `rpc_surface`;
     - `application`;
     - `client_admission`;
     - `not_denied`.

     R9-submit-update gets `rpc_surface`, because it returns `UNIMPLEMENTED`.
  6. **`--check-s13d-coverage`** in `update_security_report.py` fails unless every attack in the map below has at least one row with a `denied_by` value. A `not_denied` row counts and is reported as an unmet property.
- **Attack-to-row map (13d list):**

  | Attack | Rows |
  | --- | --- |
  | Invalid credentials | R3-*, R4, self-signed |
  | Expired certificate | R3-expired, R3-not-yet-valid |
  | Missing credentials | R7-no-cert, R8-no-cert, CK5, R10-no-cert |
  | Wrong client identity | R7-unregistered, CK3, X8 |
  | Unauthorised model retrieval | R7-*, R8-*, T rows |
  | Unauthorised update submission | CK1, CK3, CK4, R9-submit-update |
  | Unauthorised publication | CK2, CK6, CK7 |
  | Replayed authenticated request | TL1; 13c C2 |
  | Tampered request | TL2, TL3; 13c C9 |
  | Cross-identity misuse | CK2, CK4, CK8, R7-reporter, R10-installation |
- **Owned paths:**
  - `evaluation/update_security.py`, `evaluation/update_security_pki.py`, `evaluation/update_security_report.py` (new families and flags; the legacy target is unchanged);
  - `evaluation/tests/test_update_security*.py`.
- **Interfaces and data shapes:** the existing `update_security.py` row schema, plus `denied_by`, `credential_issuer` and `identity`.
- **Acceptance checks:**
  - **G8 hygiene (root runs it):** `$PY evaluation/check_s13_commit_hygiene.py --repo <stage worktree> --range <stage-base>..HEAD --stage 13d-1` exits 0.
  - **The tests pass:** `$PY -m unittest discover -s evaluation/tests -p "test_update_security*.py"`. New tests cover the CK and TL families, the `denied_by` vocabulary and `--check-s13d-coverage`.
  - **The legacy record still reproduces:** `$PY evaluation/update_security_report.py --record paper/research/update-security-20261117.json --document paper/research/update-security-20261117.md` reproduces it unchanged.
- **User dependency:** none.
- **Status:** 13d-1a done; 13d-1b pending (after 13c-2). Outcome 13d-1a: `1d898df`, `593ab4b`, `494ccfd`, `4462ee4`, merged into `feat/rust-rewrite` at `1edb6be`; 113 tests OK; live Docker check: CK1–CK7 and CK9 denied at their claimed layers, TL1 and TL3 refused, TL2 3 of 3 request-bearing records aborted (`TL2-handshake` reported separately); G8 0 violations. Implementation gate: 2 rounds, 6 findings accepted (TL1 empty-reply and liveness, vacuous store checks marked until 13d-1b, TL3 attempt and control, TL2 abort rule, evidence-based `denied_by`, coverage counting), 0 rejected. Root decision on TL2: a tampered request record aborts only if the client sees UNAVAILABLE or UNKNOWN, the server alerts or closes before any answer-sized record, and a clean control then returns NOT_FOUND; the tamper set is the request-bearing type-23 records; the clients disable gRPC retries. Pending for 13d-1b: CK8, the three positive controls, `TL1-candidate`.
- **Handoff notes:** generate the host clients first (`$PY evaluation/setup-host.py`, which includes `experimental/v3.proto`). Keep the PKI in a scratch directory, delete it after the run, and never commit a key.

### 13d-2: Run and record (agent)

- **Objective:** run every family against the Rust containers on loopback with the local V3 packages, and write AUTHZ.
- **Depends on:** 13d-1a and 13d-1b, and the host lock (after 13c-2).
- **Owned paths:**
  - `paper/research/authn-authz-<date>.{md,json}`;
  - `docs/experiments/authn-authz-<date>.md`.
- **Acceptance checks:**
  - **G8 hygiene (root runs it):** `$PY evaluation/check_s13_commit_hygiene.py --repo <stage worktree> --range <stage-base>..HEAD --stage 13d-2` exits 0.
  - **S13-G4 holds.** This includes `$PY evaluation/update_security_report.py --record <json> --check-s13d-coverage`, which must exit 0.
  - **The record cross-references UPDSEC-20261116 and UPDSEC-20261117:** `--check` verifies that both IDs appear in its gap table.
- **User dependency:** none.
- **Status:** pending.
- **Handoff notes:** the record reaches `feat/nick-branch` through the import.

---

## Stage 13e: Detector-layer ablation (agent; if time allows)

- **Objective:** score the seven layer configurations on the 13a labels.
- **Paper question:** what does each detector layer contribute, and where do the trade-offs come from? (`sec:detector_ablation`.)
  - **T→D→E→M→E:**
    - **Threat:** a single-layer failure mode that leaks or over-blocks.
    - **Defense:** layered detection.
    - **Experiment:** 7 configurations on the same items.
    - **Metric:** precision, recall, specificity, F1, and under- and over-enforcement for each configuration, plus exact McNemar tests against `full`.
    - **Evidence:** the LAYERABL record.
- **Scope label:** `product pipeline (in-process)`. This is an explicitly requested detector ablation, kept separate from LLM-only results. The semantic-only configuration is not reported as LLM-only evidence.
- **Depends on:**
  - the host lock (after 13a-5 scoring);
  - 13a-5 (frozen labels);
  - or, under the D11 fallback, the Stage 3 declared split with its provisional targets, which are labelled as provisional.
- **Work:**
  - `evaluation/layer_ablation.py` (`$PYPIPE`) uses the in-process client of `adversarial_evasion.py`.
  - The configurations are `{regex:[2], ner:[3], semantic:[4], regex+ner:[2,3], regex+semantic:[2,4], ner+semantic:[3,4], full:[2,3,4]}`. This is the AB14 mapping, but the legacy command and its `--allow-product-pipeline` flag are not used.
  - The executed layers are asserted for each configuration.
- **Owned paths:**
  - `evaluation/layer_ablation.py`, `evaluation/layer_ablation_report.py`, `evaluation/tests/test_layer_ablation*.py`;
  - `paper/research/layer-ablation-<date>.{md,json}`, `docs/experiments/layer-ablation-<date>.md`.
- **Interfaces and data shapes:**
  - Rows: `{item_id, config, layers_requested, layers_executed, action, per_layer_action, error}`. Per-item outputs go to `--out D:/Git Repositories/Privoke-Research-Project/evaluation/results/s13e/`.
  - Each configuration's aggregates have the same form as the 13a arm metrics.
- **Acceptance checks:**
  - **G8 hygiene (root runs it):** `$PY evaluation/check_s13_commit_hygiene.py --repo <stage worktree> --range <stage-base>..HEAD --stage 13e --require-local-inputs` exits 0.
  - **S13-G5 holds.**
  - **The ablation tests pass:** `$PY -m unittest discover -s evaluation/tests -p "test_layer_ablation*.py"`. They cover empty-list refusal, aborting on an executed-layer mismatch, and the McNemar fixture.
- **User dependency:** none, apart from D11.
- **Status:** pending.
- **Handoff notes:** the historical AB14 results stay separate and are not merged with these.

---

## Stage 13f: End-to-end runtime overhead and deployment breadth (if time allows)

### 13f-1: Harness and headless timing (agent)

- **Objective:** measure what PriVoke costs a user, from submit until the request reaches the receiver (or until the block decision), in five arms.
- **Paper question:** what does PriVoke cost a user in practice? (RQ3 and `sec:cross_platform`.)
  - **T→D→E→M→E:**
    - **Threat:** protection that costs too much leads users to turn it off, which is a bypass driven by usability.
    - **Defense:** local inference and configurable layers.
    - **Experiment:** browser timing in 5 arms.
    - **Metric:** p50, p95 and p99 latency, and CPU and memory where measurable.
    - **Evidence:** the E2EOVH record.
- **Arms**, all set through the extension's own settings:

  | Arm | Configuration | Expected executed layers |
  | --- | --- | --- |
  | A0 | No extension | — |
  | A1 | Every layer toggle off. `background.js` `disabledLayersResponse` sends no request, so no empty list ever exists | none; no request is sent |
  | A2 | Regex and NER | [regex, ner] |
  | A3 | Semantic only | [semantic] |
  | A4 | Full pipeline | [regex, ner, semantic] |

  The harness checks the bridge log for each arm: A1 must send no request, and A2–A4 must execute exactly their layers.
- **Depends on:** 13b-1 (driver and receiver), and the host lock (after 13b-3).
- **Work:**
  - **Driver.** `extension/test/e2e-overhead-driver.mjs` measures from the page submit event to the receiver's arrival timestamp, on one host clock. It uses a fixed, frozen mix of benign and sensitive prompts, and samples CPU and memory for each process.
  - **Host guard.** Before each run, the guard requires no other Python, cargo or Docker workload, and system CPU load of at most 25% (the detector-latency precedent).
  - **Repeats.** 5 per arm, with the arms in randomised order.
  - **Breadth:**
    - Chrome, Edge and Firefox on Windows;
    - headless Chromium in a Linux container, as the second platform;
    - at least two Stage 11 provider-shape fixture interfaces.
- **Owned paths:**
  - `evaluation/e2e_overhead.py`, `evaluation/e2e_overhead_report.py`, `evaluation/tests/test_e2e_overhead*.py`;
  - `extension/test/e2e-overhead-driver.mjs`;
  - `paper/research/e2e-overhead-<date>.{md,json}`, `docs/experiments/e2e-overhead-<date>.md`.
- **Interfaces and data shapes:**
  - Samples go to `--out D:/Git Repositories/Privoke-Research-Project/evaluation/results/s13f/`. Each sample: `{arm, browser, platform, interface, repeat, attended, prompt_id, t_submit_ms, t_receiver_ms|null, decision, layers_executed, request_sent, cpu_pct, rss_mb, host_load_before}`.
  - p50, p95 and p99 with bootstrap intervals for each arm, browser and interface.
- **Acceptance checks:**
  - **G8 hygiene (root runs it):** `$PY evaluation/check_s13_commit_hygiene.py --repo <stage worktree> --range <stage-base>..HEAD --stage 13f-1 --require-local-inputs` exits 0.
  - **S13-G6 holds**, in its first form. `--check` also fails on any `host_load_before` above 25%, or on overlapping lock intervals.
  - **The overhead tests pass:** `$PY -m unittest discover -s evaluation/tests -p "test_e2e_overhead*.py"`.
- **User dependency:** the user leaves the machine idle during the timing window that root agrees with them.
- **Status:** pending.
- **Handoff notes:** nothing else runs while the host lock is held.

### 13f-2: Attended headed timing subset and breadth (USER)

- **Objective:** headed timing in the user's installed browser, with the native host launched normally, for A0, A1 and A4. Optionally, a second machine, OS or LLM interface.
- **Depends on:** 13f-1, and the host lock.
- **Owned paths:** rows with `attended: true` in the same record.
- **Acceptance checks:**
  - **G8 hygiene (root runs it):** `$PY evaluation/check_s13_commit_hygiene.py --repo <stage worktree> --range <stage-base>..HEAD --stage 13f-2 --require-local-inputs` exits 0.
  - **the attended rows check out:** `$PY evaluation/e2e_overhead_report.py --check <json> --require-attended` exits 0.
- **User dependency:** USER runs the provided script during an agreed idle window with other applications closed. Optionally, the user runs it on a second machine. Live interfaces need D7 approval.
- **Status:** pending.
- **Handoff notes:** if 13f is dropped (D11), 13-P writes the limitation paragraph and cites XPLAT-20261117 for what was covered.

---

## Stage 13-P: Paper integration and Stage 9 repeat

- **Objective:**
  - Fold each finished record into the paper within the page limits, in the T→D→E→M→E structure.
  - Label each result with the build it measured.
  - Repeat Stage 9 of the ASIACCS plan.
- **Paper question:** the questions of 13a–13f.
- **Depends on:** the finished records, imported into `feat/nick-branch`, and D9.
- **Work:**
  1. **Scope entry.** Add an entry to `paper/REWRITE_SCOPE.md` that authorises the Stage 13 evidence units, including the description of the Rust V3 guarded-update path and the per-build labels. This needs D9.
  2. **Placement:**

     | Record | Section |
     | --- | --- |
     | 13a | `sec:final_annotation` |
     | 13b | `sec:eval_evasion`, beside `tab:asr` |
     | 13c | `sec:eval_update`, citing the guarded-update predicate |
     | 13d | `sec:eval_auth` |
     | 13e | `sec:detector_ablation` |
     | 13f | RQ3 and `sec:cross_platform` |

     Update `tab:security_goals`, `tab:threat_defense` and Threats to Validity. Properties that are not met stay visible, including C11g and any `not_denied` row.
  3. **"13a not run" outcome.** If 13a is not frozen by 6 December:
     - Threats to Validity states that the independent human-annotated evaluation was prepared but not run, and why.
     - The packet (brief, guideline, schema, scripts, pre-registration and set manifest) ships in the anonymous artifact as a ready-to-run protocol.
     - The paper claims no 13a result.
  4. **Claims ledger.** Add a `claims.md` row for each record, with its scope label.
  5. **Page budget.** Offset every addition with cuts or moves to the appendix, and rerun `check_pages.py` after each fold-in.
  6. **Stage 9 repeat.**
     - G1–G5, G12 (failing-id sets compared against `bca457df`, including the new test files), G13 and G14.
     - `check_anonymity.py` reports 0 matches.
     - The export is verified with `evaluation/export_anonymous_artifact.py`, plus a second export of the measured Rust revision under D10.
     - Root dispatches the implementation-gate critic.
- **Owned paths:**
  - `paper/main.tex`, `paper/research/claims.md`, `paper/REWRITE_SCOPE.md`;
  - `paper/figures/` and `paper/scripts/` (figure scripts only).

  Status fields in this plan and in the ASIACCS plan are written by root (see "Coordination rules").
- **Acceptance checks:**
  - **G8 hygiene (root runs it):** `$PY evaluation/check_s13_commit_hygiene.py --repo <stage worktree> --range <stage-base>..HEAD --stage 13-P` exits 0.
  - **S13-G7 and S13-G8 hold.**
  - **Final integration check (root runs it, the only run without `--stage`):** `$PY evaluation/check_s13_commit_hygiene.py --repo . --range 369fe0f..HEAD` exits 0 on `feat/nick-branch` after every Stage 13 merge.
  - **The paper builds:** `latexmk -pdf main.tex` exits 0 in `paper/`.
  - **The page check passes:** `$PY paper/scripts/check_pages.py` prints PASS.
  - **The anonymity check is clean:** `$PY paper/scripts/check_anonymity.py` reports 0 matches.
- **User dependency:** USER approves the REWRITE_SCOPE entry (D9), reviews the paper text and approves the push. Root pushes; the user uploads the artifact.
- **Status:** pending.
- **Handoff notes:** paper stages run strictly in order, with one writer on `paper/main.tex` at a time.

---

## Open decisions (user only)

"**Holds**" means that nothing that depends on the decision starts until the user answers. Root does not apply a default silently. "Default" means that root applies the recommendation after the date and records that it did so.

| ID | Decision | Recommendation | Rule | Needed by |
| --- | --- | --- | --- | --- |
| D1 | Source of the fresh 13a prompts | 2–3 recruited writers who are neither developers nor annotators, working from the frozen brief, with invented people only. Alternatives: a licensed public prompt corpus (needs licence, ethics and PII handling), or agent-generated prompts with a recorded generator (weaker independence; not recommended) | Holds | 26 Nov |
| D2 | Number and identity of annotators | 2 annotators and 1 adjudicator, none of whom wrote PriVoke labels or rubrics. Cohen's kappa per field, and Fleiss' kappa if 3 or more | Holds | 26 Nov |
| D3 | 13a set size | 360 main items plus a 30-item pilot (protocol sizing, kappa half-width ≤ 0.10) | Default | 26 Nov |
| D4 | Human-ethics approval and consent | The user confirms with the supervisor whether institutional approval is needed. No external person is involved until this is confirmed | Holds | 26 Nov |
| D5 | `fresh_eval-folio-NN` leak | `fresh_eval` is ineligible for 13a. For the deferred AU3 packet, normalise the token to `folio` and record both hashes. The AU3 packet is not run in Stage 13 | Default | 26 Nov |
| D6 | Configurations scored in 13a | Both `product` [regex, NER, semantic] and `semantic_only` [semantic], reported separately | Default | 26 Nov |
| D7 | Real-provider traffic (13b, 13f) | Not approved. Use the synthetic receiver and fixtures only. Any live run needs its own approval naming the provider, the account and the exact non-sensitive prompts | Default (no traffic) | before 13b-3 |
| D8 | Attended real-browser subsets | 13b: 60 stratified pairs in one browser. 13f: A0, A1 and A4, 5 repeats each. Skip both if the user cannot attend by 5 Dec | Default | 28 Nov |
| D9 | The paper describes 13c and 13d as measured on the Rust build, with per-build labels, under a new REWRITE_SCOPE entry; PR #6 is not merged before submission | Approve the entry. PR #6 waits until after submission | Holds (13c and 13d may run; 13-P cannot fold them in) | 26 Nov |
| D10 | Artifact coverage of the 13c and 13d harness | A second anonymous export of the measured Rust revision, not uploaded | Default | before 13-P |
| D11 | 13e and 13f go or no-go | Go only if the 13a–13d records are `ready for review` by 4 Dec. Otherwise 13f becomes the limitation paragraph and 13e is dropped; 13e may run on provisional Stage 3 targets only if labelled as such | Default | 4 Dec |
| D12 | 13a worked examples | The user, or a human they choose, writes the matched-contrast examples and their labels, or approves unlabelled drafts and writes the labels. Until then, the guideline ships with no examples | Holds (13a-3 cannot start without either examples or the user's explicit "no examples") | 27 Nov |
