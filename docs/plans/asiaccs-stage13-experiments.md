# Plan: ASIACCS Stage 13, supervisor experiments for submission

Revision: 2026-11-24 (planning only; base `369fe0f` on `feat/nick-branch`, branch `plan/asiaccs-stage13`; Rust facts read from `origin/feat/rust-rewrite` at `4d838fd`)

This plan implements [Stage 13 of the ASIACCS plan](asiaccs-2027-revision.md#stage-13-supervisor-experiments-for-submission-queued-19-nov-2026-last-in-the-roadmap). That section holds the settled requirement: the questions, the methods, the priority order 13a > 13b > 13c > 13d > 13e > 13f, the Threat → Defense → Experiment → Metric → Evidence chain and the no-padding rule. This document says how to carry it out. Nothing here changes code, starts a service or runs an experiment.

## Goals

Each goal is boolean. Commands run from the repository root of the worktree that owns the stage. `PY` is `evaluation/.venv/Scripts/python.exe`. `PYNP` is `evaluation/.venv-fuzzer-study/Scripts/python.exe` (it has NumPy). `RUSTDOCK` is the Docker parity pattern: `MSYS_NO_PATHCONV=1 docker run --rm --cpus=8 -e CARGO_TARGET_DIR=target-docker -v <wt>:/work -w /work/rust rust:1.99.1-bookworm`.

- **S13-G1 (13a). A human-annotated, independent test set has been scored.**
  - `paper/research/human-annotated-eval-<date>.json` exists.
  - `$PY evaluation/annotation/human_eval_report.py --check paper/research/human-annotated-eval-<date>.json` exits 0. It re-derives every kappa and every score from the committed label files and the record.
  - The record names the set hash, which was committed before annotation began. Its commit precedes the commit of the first label file: `git log --format=%H -- <file>` gives the order.
  - The record says how many people annotated, and states that no agent produced a label.
- **S13-G2 (13b). End-to-end evasion is recorded.**
  - `paper/research/e2e-evasion-<date>.json` exists.
  - `$PY evaluation/e2e_evasion_report.py --check <json>` exits 0.
  - The record reports conditional and unconditional end-to-end ASR with Wilson intervals, per transform family. Next to each, it gives the detector-level ASR on the same variants.
  - Every browser is either run or listed as not run, with its reason.
  - The record contains no traffic to a real provider, or names the user approval that allowed it.
- **S13-G3 (13c). Every listed update attack has an observed outcome on the real V3 path.**
  - `paper/research/v3-update-attacks-<date>.json` has at least one row for each of the 11 attack classes in [13c](#stage-13c-active-attacks-on-the-v3-guarded-update-path).
  - Each row names its rejecting check and records the active model before and after.
  - `$PY evaluation/v3_update_attacks_report.py --check <json>` exits 0.
  - `RUSTDOCK cargo test -p privoke-param-update --release --locked --test s13c_update_attacks` exits 0.
- **S13-G4 (13d). Every listed authentication attack has an observed denial outcome and a denying layer.**
  - `paper/research/authn-authz-<date>.json` exists.
  - `$PY evaluation/update_security_report.py --record <json> --document <md>` reproduces the generated tables.
  - `$PY -m unittest discover -s evaluation/tests -p "test_update_security*.py"` passes.
  - No V3 row is `not_run` unless the record gives a reason.
- **S13-G5 (13e, if time allows). Seven configurations are scored with layers asserted.**
  - `paper/research/layer-ablation-<date>.json` has 7 configurations.
  - Each configuration has `layers_requested` non-empty, and `layers_executed` matches the expected set.
  - `$PY evaluation/layer_ablation_report.py --check <json>` exits 0.
- **S13-G6 (13f, if time allows). Overhead and breadth are recorded or stated as limits.**
  - Either `paper/research/e2e-overhead-<date>.json` exists with 5 arms and p50, p95 and p99 per arm, and `$PY evaluation/e2e_overhead_report.py --check <json>` exits 0;
  - or `paper/main.tex` contains the single-platform or single-interface limitation paragraph that Stage 13-P names.
- **S13-G7. The paper integrates the results, and Stage 9 has been repeated.**
  - `paper/scripts/check_pages.py` prints PASS.
  - `$PY paper/scripts/check_anonymity.py` reports 0 matches.
  - The G1–G5, G12, G13 and G14 checks of the [ASIACCS plan](asiaccs-2027-revision.md#goals) hold.
  - Every new row in the security-goals and attack/defense tables cites a Stage 13 record.
- **S13-G8. No forbidden material is committed.**
  - `git diff --name-only <stage-base>..HEAD` lists no file that holds study prompt text, weights or private keys.
  - `git grep -nE "BEGIN (EC |RSA |)PRIVATE KEY"` is empty.
  - Every prompt-bearing output lives under a Git-ignored path (`evaluation/results/s13*/`; `git check-ignore` confirms each one).

## Scope and non-goals

- **Scope:** the six sub-stages 13a–13f, the 13a prerequisite (the `fresh_eval-folio-NN` partition leak), paper integration and the repeat of Stage 9.
- **No padding.** No experiment, arm or row is added unless it answers its sub-stage's question. A 13c signature or lineage row is included only when it shows whether an attack can change the model that clients actually run.
- **Agents never annotate.** No agent writes prompts for 13a or labels them; no agent adjudicates and no agent synthesizes labels. Agents build the packet, run the scripts and score the results.
- **No real provider traffic** without the user's explicit approval for that run (13b, 13f).
- **No empty layer list.** Every analysis request in 13a, 13b, 13e and 13f names its layers explicitly, and every response is checked for the layers that actually executed.
- **No tuning against PriVoke outputs**, at any point. This covers the transform templates, the writer brief and the thresholds.
- **No change to the measured product** except harness-only seams that the stage names. If a stage finds a defect, it records the defect as a finding. It fixes the defect only if the fix is small, covered by a test, and reported, which is the Stage 4 rule.
- **Not in scope:** merging PR #6, uploading the artifact, and any production deployment or use of the production publication key.

## Assumptions

- **Queue position.** Stage 13 starts after the Rust rewrite and the repeat of Stage 9. Both are done: V3-R8b merged at `c89b42a`, and the Stage 9 repeat was done on 23 Nov.
- **Deadline.** The deadline is 11 December 2026. Under the time plan below, 13a–13d fit only if the people for 13a are recruited by about 28 November.
- **Local inputs.** The standard V3 releases (`models/standard-releases/`), the frozen Stage 3 set and the AU3 data are Git-ignored and exist only in the main checkout (`D:/Git Repositories/Privoke-Research-Project`). Worktrees pass these as absolute paths or mount them read-only. They are never copied into a commit.
- **Docker** is available on the Windows host for the Rust services and the Rust tests, with `--cpus=8`.
- **Publication key.** Only test publication keys are used. The production key (`C:/Users/Nicholas/.privoke/v3-publication.key`) is never read.

## Relevant paths

| Area | Path (branch) |
| --- | --- |
| Requirement | `docs/plans/asiaccs-2027-revision.md` "Stage 13" (nick) |
| Annotation tooling | `evaluation/annotation/` (both branches; the 13a work happens on nick) |
| Annotation protocol and status | `docs/research/annotation-protocol-20261024.md`, `docs/research/annotation-packet-status-20261116.md` |
| Stage 3 evasion harness | `evaluation/adversarial_evasion.py`, `evaluation/adversarial_evasion_transforms.py`, `paper/research/adversarial-evasion-20261116.*` |
| Stage 11 browser harness | `evaluation/cross_platform_study.py`, `evaluation/cross_platform_receiver.py`, `evaluation/cross_platform_probes.py`, `extension/test/cross-platform-driver.mjs` |
| Extension layer contract | `extension/src/analysis-request.js` (`requireExplicitLayers`); `extension/src/background.js` (`disabledLayersResponse`: no layers enabled means no request is sent) |
| Earlier detector ablation (historical) | `evaluation/run-controlled-product-ablation.py` (AB14; a legacy command guarded by `--allow-product-pipeline`, which Stage 13 does not use) |
| Detector latency (historical) | `evaluation/detector_latency.py`, `docs/experiments/detector-latency-20261025.md` |
| V3 store and gates | `rust/services/param-update/src/v3_store/{store,service,evidence,mod}.rs`, `src/v3_policy.rs`, `src/v3_guard.rs`, `src/v3_retention.rs`, `src/v3_publish.rs`, `src/main.rs`, `src/server.rs`, `config/v3-drift-bounds.toml` (rust) |
| Client admission | `rust/crates/privoke-contracts/src/{v3,model_cache,publication}.rs`, `rust/services/runtime-supervisor/src/fetch.rs`, `rust/services/model-streaming/src/published.rs` (rust) |
| Transport and PKI | `rust/crates/privoke-transport/src/{tls,authz,registry,reload,identity}.rs`, `rust/tools/privoke-pki/`, `deploy/gce/tests/make_test_pki.py` (rust) |
| Rust security harness | `evaluation/update_security.py --target rust`, `evaluation/update_security_pki.py`, `evaluation/update_security_report.py`, `paper/research/update-security-20261117.*` (rust only) |
| Paper | `paper/main.tex`, `paper/research/claims.md`, `paper/REWRITE_SCOPE.md`, `paper/scripts/check_pages.py`, `paper/scripts/check_anonymity.py` (nick) |

## Related docs

- [ASIACCS plan, Stage 13](asiaccs-2027-revision.md#stage-13-supervisor-experiments-for-submission-queued-19-nov-2026-last-in-the-roadmap) wins on the requirement. This plan wins on how it is carried out.
- [REWRITE_SCOPE](../../paper/REWRITE_SCOPE.md) wins on paper scope. The [evidence ledger](../../paper/research/claims.md) wins on numbers.
- On `origin/feat/rust-rewrite`:
  - `docs/plans/v3-routine-training.md` wins on V3 update-path behaviour;
  - `docs/plans/rust-server-rewrite.md` wins on transport and PKI;
  - `docs/runtime/v3-publication.md` documents publication.
- [Annotation protocol](../research/annotation-protocol-20261024.md): its sizing, blinding and adjudication rules carry over to 13a, except where 13a-1 states otherwise.

## Branch strategy (decision record)

**Problem.** The paper, the ASIACCS plan and the 13 commits that `feat/rust-rewrite` lacks are on `feat/nick-branch`. The Rust services, including the only guarded update path that still exists (V3), are on `feat/rust-rewrite`, which is 312 commits ahead of the merge base `972578c`. The Rust plan lands PR #6 after submission, and it does not rebuild the artifact from the Rust tree.

**Decision: split the work by the build under test, and import the records.**

| Sub-stage | Build measured | Code branch (one worktree each, from the named base) | Where the records are committed |
| --- | --- | --- | --- |
| 13a, 13b, 13e, 13f | Submission build: Python runtime, the extension and the supervisor of `feat/nick-branch` (the same build as Stages 3, 5 and 11) | `feat/asiaccs-s13a`, `-s13b`, `-s13e`, `-s13f` from `origin/feat/nick-branch` | The same branches, merged into `feat/nick-branch` by root |
| 13c, 13d | Rust build: param-update V3 store, model-streaming, transport | `feat/asiaccs-s13c` and `-s13d` from `origin/feat/rust-rewrite` | The same branches, merged into `feat/rust-rewrite` by root, then imported into `feat/nick-branch` |

**Record import (13c, 13d).**

1. After root merges a Rust stage, root (or an assigned leaf) creates `docs/asiaccs-s13-records` from `feat/nick-branch`.
2. Run `git checkout <rust-merge-sha> -- paper/research/<record>.md paper/research/<record>.json docs/experiments/<record>.md`.
3. Commit with the message `docs(research): import <ID> from feat/rust-rewrite <sha>`.
4. Verify the import: `git diff <rust-merge-sha> HEAD -- <those paths>` is empty.

The imported files are new and byte-identical on both branches, so the later PR #6 merge cannot conflict on them.

Only `feat/nick-branch` edits `claims.md`, `REWRITE_SCOPE.md` and `main.tex`, because these files exist on both branches. Each Rust record states its measured revision (`build.branch`, `build.sha` and `build.clean`). It also states that the V3 update path exists only in the Rust build.

**Rejected alternatives.**

- **Merge PR #6 into the submission line before Stage 13.** This changes the build behind every earlier result in the paper 17 days before the deadline. It contradicts the Rust plan's sequencing (the PR lands after submission) and its rule that the artifact is not rebuilt from the Rust tree. Revisit if the user decides to submit the Rust build (open decision D9).
- **Run all of Stage 13 on `feat/rust-rewrite`.** The paper and the nick-only commits are not there. 13a, 13b, 13e and 13f would then measure a different runtime from Stages 3, 5 and 11, so the paired comparisons that 13b and 13e need would mix builds.
- **Run 13c and 13d from `feat/nick-branch` against images built from the Rust branch.** This splits the harness from the code it tests. The Rust tests (`cargo test`) must live beside the crates they test, and CI already runs there.

**Consequences.** The paper reports results from two builds and must say so (the paper stage owns this). The 13c and 13d harness code is not in the anonymous artifact that is exported from `feat/nick-branch`. Open decision D10 covers a second export.

## Shared conventions for every stage

- **Record IDs and files.**

  | Sub-stage | ID | Files |
  | --- | --- | --- |
  | 13a | `HUMANEVAL-<date>` | `paper/research/human-annotated-eval-<date>.{md,json}` |
  | 13b | `E2EEVADE-<date>` | `paper/research/e2e-evasion-<date>.{md,json}` |
  | 13c | `V3UPDATK-<date>` | `paper/research/v3-update-attacks-<date>.{md,json}` |
  | 13d | `AUTHZ-<date>` | `paper/research/authn-authz-<date>.{md,json}` |
  | 13e | `LAYERABL-<date>` | `paper/research/layer-ablation-<date>.{md,json}` |
  | 13f | `E2EOVH-<date>` | `paper/research/e2e-overhead-<date>.{md,json}` |

  Each record also has a `docs/experiments/<same-stem>.md` summary. `<date>` is the run date. Records are only ever added; earlier records are never edited.
- **Record header** (Markdown and JSON):
  - `schema` and `study_id`;
  - the T→D→E→M→E row as `chain: {threat, defense, experiment, metric, evidence}`;
  - `build: {branch, sha, clean}`;
  - `host` (OS, CPU, cores and RAM);
  - `run_dates` and `commands`;
  - `scope_label`: one of `product pipeline`, `LLM-only (semantic)`, `update path (Rust V3)`, `transport (Rust)` or `human ground truth`;
  - `not_established`: a list of what the record does not establish;
  - `user_actions`: what the user did, with dates, or `none`.
- **Re-derivation.** Every number in the Markdown comes from the JSON. Each record has a report script with `--check`, which recomputes every aggregate from the per-row data and fails on any difference, plus a unittest that runs `--check` on the committed record.
- **Layer assertion (13a, 13b, 13e, 13f).**
  - Requests carry an explicit, non-empty list from {`DETECTION_LAYER_REGEX` (2), `DETECTION_LAYER_NER` (3), `DETECTION_LAYER_SEMANTIC` (4)}.
  - The harness asserts the executed layers of every response with a generalised form of `assert_executed_layers` in `evaluation/adversarial_evasion.py`. The expected set comes from the configuration, and the regex-first skip rule applies only when regex is requested.
  - Any response whose executed layers differ from the expected set aborts the run. It is never silently scored.
  - An empty list is impossible by construction: each harness rejects one before it sends, with a test.
- **Prompt-bearing data** go under `evaluation/results/s13<x>/`, which is ignored through `evaluation/.gitignore` `results/`. This covers raw prompts, variants, annotator sheets with text, and receiver bodies. Commits carry only hashes, counts, opaque item ids and labels.
- **Host Python.** Python clients, harnesses and scoring run on the host, never with `docker compose run`. Docker only hosts services and the Rust tests. One Compose stack runs at a time.
- **Process cleanup.** Every stage stops the services, browsers and containers it started, and lists them in its handoff.

## Time plan (estimates)

| Window | Agent work | User work |
| --- | --- | --- |
| 24–28 Nov | 13a-0, 13a-1; 13c-1; 13d-1; 13b-1 | Answer D1–D5; recruit writers and annotators; check ethics |
| 28 Nov – 3 Dec | 13a-3 once prompts arrive; 13c-2; 13d-2; 13b-2 | Writers deliver prompts (13a-2); annotators do the pilot and the main round (13a-4); 13b-3 attended subset |
| 3–6 Dec | 13a-5; 13e (if 13a is frozen); 13f-1 (serialised, nothing else running on the host) | Adjudication (13a-4); 13f-2 attended subset |
| 6–10 Dec | 13-P paper integration; Stage 9 repeat | Review the paper; approve the push |

Go or no-go for 13e and 13f: they start only when the 13a–13d records are `ready for review` by 4 December (D11). Otherwise 13f becomes the limitation paragraph, and 13e is dropped or run on provisional labels (D11).

---

## Stage 13a-0: Resolve the `fresh_eval-folio-NN` partition leak (prerequisite)

- **Objective:** settle the Stage 8 finding before any annotation work starts. Every AU3 `fresh_eval` text (1,560 of them) contains a `fresh_eval-folio-NN` token. The token names the dataset partition, and its 24 values follow the audience-expression groups, so it can cue the visibility label.
- **Paper question:** a precondition of 13a. Blinding fails if annotator-facing text names the data source or cues a label.
  - **T→D→E→M→E:** annotator cueing biases the ground truth → blinding audit → marker scan over every annotator-facing sheet → count of items with a marker (required: 0) → `key/manifest.json` `blinding_audit` plus the decision note.
- **Resolution (recommended, D5):**
  1. Record that the AU3 `fresh_eval` set is **ineligible as the 13a set**. 13a requires prompts that were never used in development, tuning or earlier evaluation, and `fresh_eval` is the RQ1 AU3 evaluation set. 13a therefore uses a newly sourced set (13a-1, 13a-2), and the leak cannot affect it.
  2. For the deferred AU3 provisional-target packet (Stage 8, G10), record a documented normalisation for the time it is run: before pre-registration, every `fresh_eval-folio-NN` occurrence is replaced by one constant neutral token, `folio`. That removes both the partition name and the group cue. The replacement is applied identically for every annotator. Both the original and the normalised set hashes are recorded. Any PriVoke scoring against those labels runs on the normalised text the annotators saw.
  3. Turn the sampler's marker warning into a hard gate for 13a: `sample_annotation.py --fail-on-marker` exits non-zero when any annotator-facing text matches the blinding-audit pattern. It extends to `--marker-pattern` values that the 13a-1 contamination step derives from the source names in the repository.
- **Depends on:** none.
- **Owned paths:**
  - `evaluation/annotation/sample_annotation.py`: the `--fail-on-marker` and `--marker-pattern` flags, and the optional `--normalise-marker folio`;
  - `evaluation/annotation/tests/test_sampling.py`;
  - `docs/research/annotation-marker-decision-<date>.md` (new).
- **Interfaces and data shapes:** `key/manifest.json` gains `blinding_audit: {patterns: [..], items_checked, items_with_marker, normalisation: null | {pattern, replacement, original_sha256, normalised_sha256}}`.
- **Acceptance checks:**
  - **The tests pass:** `$PY -m unittest discover -s evaluation/annotation/tests`. They include two new tests: `--fail-on-marker` exits non-zero on a fixture with a marker, and the normalisation is identical across annotators and records both hashes.
  - **The decision note exists** and states three things: the eligibility ruling, the normalisation rule, and that no label was produced.
  - **No prompt text is committed:** `git diff --stat` shows no data file.
- **User dependency:** USER — confirm D5. Without an answer, the default applies, and the note records the default as provisional.
- **Status:** pending.
- **Handoff notes:**
  - The protocol's step 9 commits the annotator sheets, but those sheets contain text. Under Stage 13, only label-only files are committed; see 13a-5. Record this deviation in the decision note.
  - The pinned AU3 input exists only in the main checkout. Pass it to the sampler with `--input`.

## Stage 13a-1: Packet for the independent human-annotated set (agent)

- **Objective:** build everything that humans need for 13a, so that their time goes only to writing and labelling.
- **Paper question:** does PriVoke's accuracy hold against ground truth that no developer label influenced? (RQ1, `sec:final_annotation`.)
  - **T→D→E→M→E:**
    - **Threat:** labels written by the developers inflate the measured protection, and under-enforcement is missed.
    - **Defense:** the shipped PriVoke pipeline and policy.
    - **Experiment:** score PriVoke on a fresh, blind, human-labelled set.
    - **Metric:** kappa per field; precision, recall, specificity and F1; under- and over-enforcement.
    - **Evidence:** HUMANEVAL record, with the set hash and the label-freeze commit.
- **Depends on:** 13a-0.
- **Work:**
  1. **Writer brief** (`docs/research/s13a-writer-brief-<date>.md`), used if D1 keeps its default:
     - quotas over privacy category × audience × sensitive/benign, with at least 45% sensitive and every category at least 20 times;
     - a rule that only invented people and values are used;
     - a ban on reading PriVoke code, its data, rubrics or outputs.
     The brief is frozen and committed before any writer starts. It contains no example taken from a repository dataset.
  2. **Ingest and freeze** (`evaluation/annotation/fresh_set.py`):
     - reads the user-supplied raw prompts from a Git-ignored path;
     - normalises whitespace only;
     - assigns opaque ids and removes exact duplicates;
     - runs a contamination check: exact match and 8-gram Jaccard ≥ 0.5 against every prompt-bearing file in `evaluation/datasets/`, `evaluation/results/` (main checkout) and the fuzzer curricula, plus a marker scan;
     - writes `set_manifest.json` (no text): `{schema, n, sha256_jsonl, source_kind, contamination: {sources_checked, exact, near, removed_ids}, quota_counts}`.
     Root commits `set_manifest.json` under `docs/research/s13a/` **before** sampling.
  3. **Schema v2** (`annotation_schema.py`, `SCHEMA_VERSION = 2`), keeping v1 readable. The fields are:
     - `sensitive` (`yes`/`no`);
     - `subject`, meaning whose information (`SELF`, `THIRD_PARTY`, `PUBLIC_FIGURE`, `NONE`, `UNCLEAR`);
     - `audience`, the intended audience and context (`P0`–`P4`, `PU`, with the v1 visibility definitions);
     - `categories` (the 10 v1 categories, or `NONE`);
     - `action` (`ALLOW`, `WARN`, `BLOCK`);
     - `notes`.
  4. **Guideline v2** (`docs/research/annotation-guideline-v2-<date>.md`):
     - definitions for each field;
     - a glossary;
     - one invented worked example per matched contrast (from protocol section 2 plus the `subject` field);
     - a declaration form for each annotator.
  5. **Sampling and blinding.** Reuse `sample_annotation.py` with `--stratify-by quota_cell` and `--fail-on-marker`. The defaults are 360 main items plus a disjoint 30-item pilot (D3), and the seed is recorded in the pre-registration.
  6. **Agreement** (`compute_iaa.py`):
     - add Fleiss' kappa for three or more annotators, and Cohen's kappa per pair and per field;
     - categories use a per-category binary kappa plus exact-set agreement and Jaccard;
     - keep Krippendorff's alpha;
     - intervals come from a bootstrap over the `quota_cell` clusters.
  7. **Scoring** (`evaluation/annotation/score_privoke.py`). It refuses to run unless the label-freeze record (13a-5) exists and its hashes match. It runs two arms, separately labelled (D6):
     - `product`: layers [2, 3, 4], with the in-process client of `adversarial_evasion.py`, V3 balanced, shipped defaults;
     - `semantic_only`: layers [4].
     The positive class is `sensitive = yes`, and PriVoke is positive when its action is WARN or BLOCK. Under-enforcement is a PriVoke action less strict than the reference action; over-enforcement is a stricter one. The script reports Wilson and cluster-bootstrap intervals.
  8. **Report** (`evaluation/annotation/human_eval_report.py --check`), and a pre-registration template (`docs/research/s13a-preregistration-<date>.md`) that names the seed, the sizes, the fields, the metrics, the arms and the analysis order.
  9. **Interface.** The default is a CSV with validated columns, using the existing validator. A local HTML form is optional and not required.
- **Owned paths:**
  - `evaluation/annotation/{fresh_set.py,score_privoke.py,human_eval_report.py}` (new);
  - `evaluation/annotation/{annotation_schema.py,compute_iaa.py,agreement.py,sample_annotation.py}`;
  - `evaluation/annotation/tests/test_{fresh_set,fleiss,score_privoke,human_eval_report}.py`;
  - `docs/research/s13a-*.md` and `docs/research/annotation-guideline-v2-<date>.md`.
- **Interfaces and data shapes:**
  - Sheet columns: `item_id,text,sensitive,subject,audience,categories,action,notes`.
  - The label-only file committed later has the same columns without `text`.
  - Record JSON:

    ```text
    {schema:"privoke-s13a-v1", study_id, chain, build, set:{sha256, n, source_kind, contamination},
     annotators:{count, familiarity_declared:[..]}, pilot:{iaa}, iaa:{<field>:{cohen:[{pair,kappa,ci95,n}], fleiss?, alpha, ci95}},
     adjudication:{items, resolution_counts, disagreement_types}, freeze:{commit, files:{name:sha256}},
     arms:[{arm, scope_label, layers_requested, layers_executed_ok:true, metrics:{precision,recall,specificity,f1,
     under_enforcement,over_enforcement each {value,ci95,num,den}}, per_category, per_audience}], not_established}
    ```
- **Acceptance checks:**
  - **The annotation tests pass:** `$PY -m unittest discover -s evaluation/annotation/tests`. Kappa and Fleiss are checked against hand-computed fixtures, and the scorer must refuse to run when no freeze record exists.
  - **The scorer refuses an empty layer list:** `$PY -m unittest evaluation.annotation.tests.test_score_privoke` includes this case.
  - **The contamination check flags a planted duplicate** in a fixture.
  - **No label exists in the repository**, apart from fixtures inside the test code.
- **User dependency:** USER — answer D1–D4 and D6. Nothing else is needed for 13a-1.
- **Status:** pending.
- **Handoff notes:**
  - Pick the client environment for `score_privoke.py` the way Stage 3 did, with `evaluation/.venv-v1-v3-pipeline`. Record the interpreter path in the record.
  - The V3 balanced release is read from the main checkout.

## Stage 13a-2: Recruit, write and deliver the fresh prompts (USER)

- **Objective:** produce the fresh prompt set without any agent writing it.
- **Paper question and chain:** as in 13a-1.
- **Depends on:** 13a-1 (writer brief).
- **Owned paths:** none in Git. Prompts are delivered to `evaluation/results/s13a/raw/` in the main checkout, which is Git-ignored.
- **Acceptance checks:**
  - **The prompts arrive:** the raw file exists, and `fresh_set.py --dry-run` reports the quota counts.
  - **The writers sign their declarations:** none read PriVoke data or outputs, and only invented people appear.
- **User dependency:** USER does all of the following:
  - confirm whether human-ethics approval is needed (D4), and obtain it if so;
  - recruit the writers, who are neither annotators nor developers (D1);
  - hand them the brief;
  - collect the prompts and place them at the path above;
  - record the names of the writers, annotators and adjudicator in a private, unshared list (not in the repository).
- **Status:** pending.
- **Handoff notes:** if D1 chooses a public corpus instead, this stage becomes:
  - **user:** a licence and ethics check;
  - **agent:** a sampling script with a recorded seed, plus contamination and PII handling rules. Prompts that contain real personal data stay local.

## Stage 13a-3: Freeze, sample and blind (agent)

- **Objective:** turn the raw prompts into a frozen set and blinded sheets.
- **Depends on:** 13a-2.
- **Work:**
  1. Run `fresh_set.py`.
  2. Root commits `docs/research/s13a/set_manifest.json` (no text).
  3. Commit the pre-registration with the seed.
  4. Run the sampler with `--fail-on-marker`, writing to `evaluation/results/s13a/packet/`.
- **Owned paths:** `docs/research/s13a/set_manifest.json` and `docs/research/s13a-preregistration-<date>.md` (filled in).
- **Acceptance checks:**
  - **The manifest was committed first:** `git log` shows the manifest commit before any sheet exists.
  - **The blinding audit is clean:** `blinding_audit.items_with_marker == 0`.
  - **Sampling is deterministic:** a rerun of the sampler gives byte-identical sheets (compare the hashes).
- **User dependency:** USER — receive `sheets/*_<annotator>.csv` and send each annotator only their own sheet. The key stays with the coordinator.
- **Status:** pending.
- **Handoff notes:** the agent never opens the completed sheets until 13a-5.

## Stage 13a-4: Annotate, calibrate and adjudicate (USER)

- **Objective:** human labels, agreement and adjudicated reference labels.
- **Depends on:** 13a-3.
- **Owned paths:** none in Git. Completed sheets and the adjudication file go to `evaluation/results/s13a/returned/`.
- **Work:** steps 3–8 of the [runbook](../research/annotation-packet-status-20261116.md#3-runbook-for-two-human-annotators-and-a-coordinator), with the v2 fields. Agents run `compute_iaa.py` for the pilot and the main round when asked, and produce `to_adjudicate.csv`. The human adjudicator decides every item.
- **Acceptance checks:**
  - **The sheets are valid:** the validator accepts every returned sheet.
  - **The pilot clears the bar:** kappa is at least 0.6 for `sensitive`, `audience` and `action`. Otherwise there is one guideline revision and a repeat, as the protocol allows.
  - **Adjudication is complete:** every disagreement has a `resolution` and an `adjudicator`.
- **User dependency:** USER does all of the following:
  - run the training;
  - make sure the annotators work independently;
  - collect the sheets;
  - organise the adjudication;
  - record dated guideline revisions;
  - report any annotator who knew PriVoke data.
- **Status:** pending.
- **Handoff notes:** the effort estimate is about 19 hours of human time for 360 + 30 items with 2 annotators (protocol section 8).

## Stage 13a-5: Freeze labels, score and record (agent)

- **Objective:** freeze the labels, then score PriVoke and write HUMANEVAL.
- **Depends on:** 13a-4.
- **Work:**
  1. Write label-only CSVs (no `text`) for each annotator and for the adjudicated set to `docs/research/s13a/labels/`.
  2. Root commits them, together with `iaa.json` and their SHA-256 values, **before** any PriVoke run on these items. This is the freeze commit.
  3. Run `score_privoke.py`, both arms, with the layer assertion on every response.
  4. Write the record and the claims-ledger row draft (the ledger itself is edited in 13-P).
- **Owned paths:**
  - `docs/research/s13a/labels/*.csv`, `docs/research/s13a/iaa.json`;
  - `paper/research/human-annotated-eval-<date>.{md,json}`;
  - `docs/experiments/human-annotated-eval-<date>.md`.
- **Acceptance checks:**
  - **S13-G1 holds.**
  - **The freeze came before scoring:** `git log --format=%H` places the label commit before the record commit.
  - **The arms are labelled:** the record shows `product` and `semantic_only` as separate sections with separate scope labels.
- **User dependency:** none.
- **Status:** pending.
- **Handoff notes:** use the protocol's report wording. The record says "agree at the reported rate with adjudicated labels from N annotators", and does not say "validated".

---

## Stage 13b-1: End-to-end evasion harness and variant set (agent)

- **Objective:** a harness that sends each adversarial variant through the installed extension to the local synthetic HTTPS receiver, and records whether the receiver got it.
- **Paper question:** can a user rewrite a sensitive prompt so that it reaches the external receiver unprotected? (`sec:eval_evasion`.)
  - **T→D→E→M→E:**
    - **Threat:** a user or a tool rewrites a prompt to evade detection.
    - **Defense:** in-page interception, then detection, then BLOCK or WARN.
    - **Experiment:** declared transforms through the installed extension to the synthetic receiver.
    - **Metric:** end-to-end ASR, conditional and unconditional, next to the detector-level ASR of the same variants.
    - **Evidence:** E2EEVADE record.
- **Depends on:** none (the Stage 3 and Stage 11 code is present).
- **Work:**
  1. **Seeds.** Draw a stratified sample of seeds from the frozen Stage 3 set (sha256 `5e4eac4c...b634c2`) with a recorded seed.
     - The sample must be disjoint from the 13a set and from the sets that were used to design the robustness flags.
     - Size `N_seed` is fixed after a 20-probe timing pilot so that one browser run takes 8 hours or less. The floor is 200 seeds.
  2. **Variants.**
     - Use `adversarial_evasion_transforms.py` **unchanged**, imported at its recorded revision, for the Stage 3 families.
     - Add `fragmented_identifier` and `mixed_language` as declared templates in a new module, `evaluation/e2e_evasion_transforms.py`.
     - The hash of the template file is frozen and committed before the first scored run, and the templates are never edited after any PriVoke output has been seen.
  3. **Runner** (`evaluation/e2e_evasion.py`). It reuses the Stage 11 method:
     - the unmodified extension build, loaded in disposable profiles;
     - only the fixture hosts resolve;
     - the synthetic receiver;
     - the real supervisor and bridge on loopback.
     For each seed and each variant, it types or pastes the text into a provider-shape fixture page and submits it. It records:
     - whether the receiver got a request;
     - whether the receiver body contains the variant payload intact;
     - the page `noticeStatus` (whether a WARN was shown);
     - the decision and the executed layers, from the bridge response log.
  4. **Paired detector-level arm.** Run the same variants through the Stage 3 in-process product client with explicit layers [2, 3, 4].
  5. **Definitions** (written into the record):
     - **protected seed:** an untransformed seed that is not delivered (BLOCK), or delivered only after a WARN was shown;
     - **evasion:** a protected seed whose variant is delivered intact with no BLOCK and no WARN;
     - **downgrade:** BLOCK falls to WARN;
     - **conditional ASR:** evasions divided by protected seed-variant pairs;
     - **unconditional ASR:** evasions divided by all pairs.
     Fail-closed errors are counted separately and are never counted as protection.
- **Owned paths:**
  - `evaluation/e2e_evasion.py`, `evaluation/e2e_evasion_transforms.py`, `evaluation/e2e_evasion_report.py`;
  - `extension/test/e2e-evasion-driver.mjs` (new; the Stage 11 driver is not edited);
  - `evaluation/tests/test_e2e_evasion*.py`.
- **Interfaces and data shapes:**
  - Per-pair row: `{seed_id, family, variant_id, browser, receiver_got, payload_intact, warn_shown, decision, layers_requested, layers_executed, error, detector_level:{action, layers_executed}, e2e_outcome: protected|evaded|downgraded|fail_closed|not_delivered_other}`. Prompt text is stored only in `evaluation/results/s13b/`.
  - The record holds ids and hashes only.
- **Acceptance checks:**
  - **The harness tests pass:** `$PY -m unittest discover -s evaluation/tests -p "test_e2e_evasion*.py"`. They cover outcome classification, the ASR formulas, Wilson intervals, refusal of an empty layer list, and refusal of any non-fixture host.
  - **The template hash is committed** before the first scored run.
- **User dependency:** none for 13b-1.
- **Status:** pending.
- **Handoff notes:**
  - Stage 11 ran with only regex and NER available, because `PRIVOKE_USE_LOCAL_STACK=true` made the semantic layer unavailable. 13b must make the semantic layer available locally (the V3 balanced release from the main checkout) and assert that it executed. If it cannot, the record states the scope label "regex+NER runtime" and the paper says so.
  - The extension enforces `requireExplicitLayers` (`extension/src/analysis-request.js`). Capture the request layers from the bridge log rather than assuming them.

## Stage 13b-2: Headless installed-extension run (agent)

- **Objective:** the main end-to-end run in Chrome, Edge and Firefox on the Windows host, headless, with disposable profiles. This is the agent-run method of Stage 11.
- **Depends on:** 13b-1.
- **Owned paths:** `paper/research/e2e-evasion-<date>.{md,json}` and `docs/experiments/e2e-evasion-<date>.md`.
- **Acceptance checks:**
  - **S13-G2 holds.**
  - **Every browser is accounted for:** each is run or listed as not run with its reason.
  - **No other host is contacted:** the hostname guard shows zero lookups outside the fixture hosts.
- **User dependency:** none.
- **Status:** pending.
- **Handoff notes:**
  - Do not run this at the same time as 13f timing.
  - Stop the supervisor, the bridge, the receiver and the browsers when the run ends.

## Stage 13b-3: Attended real-browser subset (USER)

- **Objective:** confirm on the user's installed, headed browser (native-host launch, visible notices) that the headless outcomes hold for a stratified subset. The default is 60 pairs (D8).
- **Depends on:** 13b-2.
- **Owned paths:** an addendum section and rows in the same record (`attended: true`).
- **Acceptance checks:** **the attended rows are labelled.** Each one has the same fields and the flag `attended`. Any disagreement with the headless run is reported.
- **User dependency:** USER does all of the following:
  - run the provided script, which opens the fixture page in the user's browser with the installed extension;
  - submit each listed variant when prompted;
  - leave the machine otherwise idle.
  No real provider is involved.
- **Status:** pending.
- **Handoff notes:** if D7 approves live-provider runs, a separate `live` addendum may follow, using only non-sensitive synthetic seeds. Without that approval, it is blocked.

---

## Stage 13c: Active attacks on the V3 guarded update path

### 13c-1: Attack matrix in CI (agent)

- **Objective:** drive each attack against the real V3 commit path, on a branch from `feat/rust-rewrite`, and record the rejecting check and the active model before and after.
- **Paper question:** can an invalid, stale, replayed or behaviourally unsafe update replace the active model? (RQ2, `sec:eval_update`.)
  - **T→D→E→M→E:**
    - **Threat:** a compromised or faulty trainer (a principal with the `trainer` or `publisher` role), or a corrupted transfer or store, submits a bad candidate.
    - **Defense:** the V3 checkpoint store, in this order: admission → compare-and-swap with request-id idempotence → DriftGate → GuardGate → RetentionGate → signed Publisher. Then model-streaming serves only signed versions, and the client applies `admit_lineage`.
    - **Experiment:** the attack matrix below, run against the real path.
    - **Metric:** for each attack, whether the active model is unchanged (required) at the store, at model-streaming and at the client, plus the check that rejected the attack.
    - **Evidence:** V3UPDATK record.
- **Depends on:** none (`feat/rust-rewrite` at its current head).
- **Harness design.**
  - **Location.** A Rust integration test, `rust/services/param-update/tests/s13c_update_attacks.rs`, built on `tests/common` and the fixtures of `scheduler_chain.rs`, `v3_guard.rs`, `v3_publication.rs` and `v3_signed_chain.rs`.
  - **Wiring.** It must use exactly the observer chain that `main.rs` installs. Add one harness seam: move the observer construction in `src/main.rs` (lines 131–150 at `4d838fd`) into a `pub fn build_observers(..)` in `src/lib.rs`, which both `main.rs` and the test call. This is a refactor with no behaviour change, covered by the existing `v3_deployment.rs`.
  - **Transport.** It calls the real `CheckpointService` over mutual TLS (as `checkpoint_mtls.rs` does) as the `trainer` principal.
  - **Store and publishing.** The store is seeded with `bootstrap_pinned`, uses the drift bounds of `rust/services/param-update/config/v3-drift-bounds.toml`, and the committed retention references. The Publisher has a **test** key.
  - **Client side.** model-streaming `published.rs` is read through its library API over the same store. The client leg is `admit_lineage` with the test key as its key set.
  - **Fixed scorer.** In CI, the guard and retention scorers use the fixed-scorer test doubles that already exist. The real-encoder leg is 13c-2.
  - **Output.** With `S13C_OUT` set, the test writes the rows as JSON. It asserts each row's expected outcome, so CI fails on any regression.
- **Attack-to-check map.** Every check named here is in the current source of `origin/feat/rust-rewrite`. `store.rs` means `rust/services/param-update/src/v3_store/store.rs`, and `v3.rs` means `rust/crates/privoke-contracts/src/v3.rs`.
  - **Order of reasons.** In `CheckpointStore::commit`, the receipt reason is `stale_base` first, then `guard_rejected` (trainer evidence, `v3::publication_passes`), then the first observer refusal (Drift, then Guard, then Retention). Admission errors come before all of these, as `INVALID_ARGUMENT` with no receipt.
  - **Isolation.** Each row therefore isolates one fault. Rows with combined faults are labelled `combined`.

  | # | Attack (13c list) | Variants (row ids) | Expected rejecting check (file → symbol / reason) | Expected outcome |
  | --- | --- | --- | --- | --- |
  | 1 | Stale parent | C1a: the candidate's parent was current, then another candidate was applied. C1b: two candidates race on one base. C1c: `RollbackModel` to a version that was never published | `store.rs` `commit`, CAS inside `BEGIN IMMEDIATE` → receipt `rejected`/`stale_base`; the loser of the race is never signed (`v3_publish.rs` `before_swap` is never reached); `store.rs` `rollback` → "Rollback target was never published." | rejected, model unchanged; `publications` has no row for the loser |
  | 2 | Replay | C2a: the same request id and content after a later update. C2b: the same id with different content. C2c: the client is served an older signed statement (sequence below the high-water mark). C2d: the client is served the unsigned pin after a signed version | `store.rs` `replay`/`replayed` → stored receipt, no swap; "Request ID reused with different commit content."; `v3.rs` `admit_lineage` → `LineageError::Replay`; `LineageError::Downgrade` | no-op or rejected; the store, the served version and the client mark are unchanged |
  | 3 | Duplicate | C3a: a candidate that is already current is committed again under a new request id. C3b: the same candidate is staged twice | `store.rs` `commit` → `stale_base` (its parent is no longer current); `put` is content-addressed (the second stage is idempotent) | at most one application; one `publications` row |
  | 4 | Wrong model or version id | C4a: `Commit.model_id` differs from the manifest. C4b: the manifest `model_id`, `tier`, `config` or `vocab` differs from the parent. C4c: `original` is not the parent's ORIGINAL. C4d: `expected_base` is not the manifest's `parent`. C4e: the candidate claims scope `original`. C4f: the client receives a statement for another model or manifest | `store.rs` `commit` → "Commit identity differs from candidate/fit evidence."; `admit_candidate` → "Candidate changed immutable model provenance/config.", "Candidate ORIGINAL binding mismatch.", "Candidates cannot claim ORIGINAL scope."; `v3.rs` `LineageError::StatementModel`, `StatementManifest`, `WrongOriginal` | `INVALID_ARGUMENT` or client refusal; unchanged |
  | 5 | Wrong tensor name | C5a: a renamed tensor in the manifest and the blob. C5b: the manifest inventory differs from the blob | `store.rs` `admit_candidate` → "Candidate changed admitted tensor inventory."; `verify_checkpoint` → "Safetensors inventory differs from manifest." | `INVALID_ARGUMENT`; unchanged |
  | 6 | Wrong tensor shape | C6a: the shape changes in both the manifest and the blob. C6b: the shape changes only in the blob | the same two checks (the inventory includes shape and dtype) | `INVALID_ARGUMENT`; unchanged |
  | 7 | NaN or Inf values | C7a: NaN. C7b: +Inf. C7c: −Inf, each in one coordinate of a heads tensor | `rust/crates/privoke-semantic/src/safetensors.rs` finite check, reached through `store.rs` `verify_checkpoint` → "Snapshot tensors must be finite float32." | `INVALID_ARGUMENT` at stage or commit; unchanged |
  | 8 | Excessive parameter change | C8a: one update above `max_update_l2` for the tier and scope. C8b: a sequence of updates each under the per-update bound until the cumulative bound of 100 is crossed. C8c: a HEADS-scope candidate that changes encoder bytes. C8d: `changed_tensors` misreported | `rust/services/param-update/src/v3_policy.rs` `DriftGate::prepare` → `drift_exceeded` (per-update and cumulative from `DriftGate::root`); `store.rs` → "HEADS candidate changed pretrained encoder/pooler bytes.", "Reported changes differ from actual checkpoint tensors." | `rejected`/`drift_exceeded` or `INVALID_ARGUMENT`; unchanged. C8b records the update at which the bound triggers |
  | 9 | Truncated or corrupted artifact | C9a: the stream ends early. C9b: a chunk offset gap. C9c: the declared sha does not match the bytes. C9d: the manifest `blob` digest does not match the uploaded bytes. C9e: a store blob is corrupted at rest before commit. C9f: a published asset is corrupted at rest before it is served | `rust/services/param-update/src/v3_store/service.rs` `stage_checkpoint` → "Incomplete/corrupt checkpoint upload.", "Invalid bounded ordered checkpoint upload."; `store.rs` `stage` → "Candidate snapshot identity mismatch."; `read` → "Immutable blob hash mismatch."; `rust/services/model-streaming/src/published.rs` `stream_asset` re-hash; the client `rust/services/runtime-supervisor/src/fetch.rs` `verify_package` | rejected; unchanged. C9e and C9f are labelled as at-rest defence in depth |
  | 10 | Interrupted publication | C10a–e: the crash hook fires at `staged`, `signed`, `committed`, `renamed` and `pointer`, then restart and `Publisher::reconcile` | `rust/services/param-update/src/v3_publish.rs` `CrashHook`, `reconcile` (promote or rebuild, repair the pointer, quarantine) | before reconcile, the served version is the old version or the complete new signed one, never a partial or unsigned one; after reconcile, the store authority and the served version agree |
  | 11 | Update that improves the aggregate but breaks guard cases | C11a: honest evidence showing a guard harm. C11b: evidence that claims a pass, while the recomputed guard fails. C11c: substituted guard rows. C11d: a trainer-chosen source or seed. C11e: an unallocated request id. C11f: a better aggregate that regresses reference rows beyond the 5% allowance. C11g: the boundary case, which regresses exactly the allowance (7, 9 or 10 rows) | `store.rs` `commit` via `v3::publication_passes` → `guard_rejected`; `rust/services/param-update/src/v3_guard.rs` `GuardGate` → `guard_recomputed`, `guard_rows_differ`, `commitment_mismatch`, `request_not_allocated`/`allocation_mismatch`; `rust/services/param-update/src/v3_retention.rs` `RetentionGate` → `retention_regressed` | C11a–f rejected, model unchanged. **C11g is accepted by design.** It is reported as a boundary row and a documented limit, not as a pass |
  | S | Signature and lineage at the client (included because the question includes the model clients run) | CS1: a version directory dropped into the publish root with no authority row. CS2: a statement signed by an unknown key. CS3: a tampered statement. CS4: an unsigned non-pin manifest | `published.rs` (authority only, `is_published`); `rust/crates/privoke-contracts/src/publication.rs` verify → `LineageError::Publication`; `v3.rs` `LineageError::Unsigned` | not served, or refused by the client; the client mark is unchanged |

- **Owned paths:**
  - `rust/services/param-update/tests/s13c_update_attacks.rs` (new);
  - `rust/services/param-update/src/{lib.rs,main.rs}` (the `build_observers` seam only);
  - `evaluation/v3_update_attacks_report.py` and `evaluation/tests/test_v3_update_attacks_report.py` (new).
- **Interfaces and data shapes.** Each row:

  ```text
  {id, attack_class:1..11|S, variant, combined:false, leg:"ci"|"real"|"container", surface:stage|commit|rollback|serve|client,
   identity:"trainer"|"publisher", attempted:{request_id, model_id, expected_base, candidate_sha, mutation},
   expected:"rejected_unchanged"|"noop_unchanged"|"accepted_by_design", observed:{grpc_code, receipt_status, receipt_reason, message},
   rejecting_check:{file, symbol, reason}, active_before:{store_current, max_sequence, served_manifest, client_mark},
   active_after:{...}, property_met:bool}
  ```
- **Acceptance checks:**
  - **The CI matrix passes:** `RUSTDOCK cargo test -p privoke-param-update --release --locked --test s13c_update_attacks` exits 0.
  - **The rest of the crate is unaffected:** `RUSTDOCK cargo test -p privoke-param-update --release --locked` exits 0.
  - **The report tests pass:** `$PY -m unittest discover -s evaluation/tests -p test_v3_update_attacks_report.py`.
  - **Every attack class has a row:** each of the 11 classes has at least one row with `rejecting_check` set, or with `accepted_by_design` and its reason.
- **User dependency:** none.
- **Status:** pending.
- **Handoff notes:**
  - The V1 rows of `update_security.py --target rust --rust-service param-update` (A1–E7, R1, R2, R5) now only show that `SubmitParameterUpdate` is `UNIMPLEMENTED`. They are not 13c evidence.
  - Never use `PRODUCTION_KEYS` or the production key. The test key reaches the build only through dev-dependencies, which CI's `cargo tree` check enforces.

### 13c-2: Real-weight and container legs, and the record (agent)

- **Objective:** repeat the rows that depend on the scorer (C11b, C11f, C11g) with the real Rust V3 encoder and the real efficient-tier release. Run the matrix's wire-level rows against the Compose `v3-training` stack on loopback (with a test PKI and a test publication key). Then write V3UPDATK.
- **Depends on:** 13c-1.
- **Work:**
  - **Real-weight leg.** An env-gated test, `s13c_update_attacks_real.rs`, follows the pattern of `rust/services/v3-fuzzer/tests/scheduler_real.rs`. It runs in Docker with `models/standard-releases` and the ORIGINAL mounted read-only.
  - **Container leg.** A host Rust client or the same test runs with `S13C_ENDPOINT` set against `docker compose --profile v3-training up` on loopback.
  - **One stack at a time**, torn down after the run.
- **Owned paths:**
  - `rust/services/param-update/tests/s13c_update_attacks_real.rs`;
  - `paper/research/v3-update-attacks-<date>.{md,json}`;
  - `docs/experiments/v3-update-attacks-<date>.md`.
- **Acceptance checks:**
  - **S13-G3 holds.**
  - **The legs are labelled:** each row carries its `leg`.
  - **The record lists what did not run**, with reasons.
- **User dependency:** none.
- **Status:** pending.
- **Handoff notes:** the record goes to `feat/nick-branch` only through the record import (see "Branch strategy").

---

## Stage 13d: Authentication and authorisation against the Rust stack

### 13d-1: Row families and PKI (agent)

- **Objective:** extend `evaluation/update_security.py --target rust` so that it answers the 13d question against the current Rust services, including the V3 `CheckpointService` and the publication path.
- **Paper question:** can an unauthorised identity retrieve protected resources, submit updates or publish a candidate model? (RQ2 attack resistance, `sec:eval_auth`.)
  - **T→D→E→M→E:**
    - **Threat:** an attacker with no credentials, wrong credentials or stolen low-privilege credentials.
    - **Defense:** mutual TLS (the rustls verifier with CRL hot reload), the registry, the role policy and the RPC surface, plus the application identity checks of the V3 store.
    - **Experiment:** negative rows from a host Python client against the containers.
    - **Metric:** for each attack, whether it was denied (required) and the layer that denied it.
    - **Evidence:** AUTHZ record.
- **Depends on:** none (`feat/rust-rewrite` at its current head).
- **Work:**
  1. **PKI.**
     - **Legitimate principals** are issued with the real operator tool, `privoke-pki`:
       - `init-ca` for the client CA and the server CA;
       - `issue-server`;
       - `sign-service --role publisher|trainer|runtime`;
       - `enrol`, then `sign`, then `install-cert` for installations;
       - `issue-reporter`;
       - `revoke`, then `crl`.
     - **Deliberately invalid credentials** come from the existing OpenSSL helper in `update_security_pki.py`: expired, not yet valid, no client-auth EKU, foreign CA, self-signed. `privoke-pki` will not mint these by design.
     - Each row records which tool issued its credential.
  2. **New row family `CK`** for `CheckpointService` (policy in `rust/services/param-update/src/server.rs` `policy()`):
     - CK1: `CommitCandidate` as `runtime` → `PERMISSION_DENIED`.
     - CK2: `RollbackModel` as `trainer` → `PERMISSION_DENIED`.
     - CK3: `CommitCandidate` with a registered installation certificate → `PERMISSION_DENIED`.
     - CK4: `CommitCandidate` with the reporter credential → `PERMISSION_DENIED`.
     - CK5: `StageCheckpoint` with no certificate → handshake failure.
     - CK6: `CommitCandidate` as a revoked trainer, after a CRL swap → handshake failure without a restart.
     - CK7: `CommitCandidate` as a deny-listed trainer, on an open connection → `PERMISSION_DENIED`.
     - CK8: `CommitCandidate` as a valid trainer with an unallocated request id → `rejected`/`request_not_allocated`. This is an application-layer row, and it is the cross-identity misuse case.
     - CK9: an unlisted RPC → `UNIMPLEMENTED`.
     - Positive controls: `publisher` commit and rollback, and `runtime` stage are accepted.
  3. **TLS-level rows `TL`** (replayed or tampered requests):
     - TL1: replay the captured TLS 1.3 bytes of an authenticated `CommitCandidate` to a new connection → handshake or record failure, and no receipt.
     - TL2: flip one bit in the application data, using a loopback TCP proxy → the connection aborts (`bad_record_mac`), and no receipt.
     - TL3: a man-in-the-middle with a server certificate that is not from the server CA → the client refuses.
     - The application-level replay is covered by 13c C2a and C2b. AUTHZ cross-references those rows rather than repeating them.
  4. **Re-run the existing Rust families with the V3 packages present.** These are T, R3, R4, R7, R8, R9, X8, X13 live, R6 and R10, run without `--no-v3`. The goal is that the 9 rows that are `not_run` in UPDSEC-20261117 (T7, T9, T10, R8-wrong-pin, R8-not-allowlisted, I3, X1, X1b and X1c) run.
  5. **`denied_by` field on every row:** `tls_handshake | revocation | registry | role_policy | rpc_surface | application | client_admission | not_denied`.
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
  | Replayed authenticated request | TL1, plus a pointer to 13c C2 |
  | Tampered request | TL2, TL3, plus a pointer to 13c C9 |
  | Cross-identity misuse | CK2, CK4, CK8, R7-reporter, R10-installation |
- **Owned paths:**
  - `evaluation/update_security.py`, `evaluation/update_security_pki.py`, `evaluation/update_security_report.py` (new families; the legacy target is unchanged);
  - `evaluation/tests/test_update_security*.py`.
- **Interfaces and data shapes:** the existing row schema of `update_security.py`, plus `denied_by`, `credential_issuer: privoke-pki|openssl-helper` and `identity`.
- **Acceptance checks:**
  - **The update-security tests pass:** `$PY -m unittest discover -s evaluation/tests -p "test_update_security*.py"`. New tests cover the presence of the CK and TL families and the `denied_by` vocabulary.
  - **The legacy record still reproduces:** `$PY evaluation/update_security_report.py --record paper/research/update-security-20261117.json --document paper/research/update-security-20261117.md` reproduces it unchanged.
- **User dependency:** none.
- **Status:** pending.
- **Handoff notes:**
  - `update_security_pki.py` currently uses OpenSSL for every credential. Only the CI smoke test (`deploy/gce/tests/make_test_pki.py`) uses `privoke-pki`.
  - Keep the generated PKI in a scratch directory and delete it after the run. Never commit a key.

### 13d-2: Run and record (agent)

- **Objective:** run every family against the Rust containers on loopback with the local V3 packages, and write AUTHZ.
- **Depends on:** 13d-1.
- **Owned paths:** `paper/research/authn-authz-<date>.{md,json}` and `docs/experiments/authn-authz-<date>.md`.
- **Acceptance checks:**
  - **S13-G4 holds.**
  - **Every 13d attack has a result:** each attack in the map has at least one row with a `denied_by` value or `not_denied`. A `not_denied` row is reported as an unmet property.
  - **The record cross-references UPDSEC-20261116 and UPDSEC-20261117** for the gaps that are now closed.
- **User dependency:** none.
- **Status:** pending.
- **Handoff notes:**
  - Run 13d-2 and 13c-2 one after the other, never at the same time: both use Docker on one host.
  - The record goes to `feat/nick-branch` through the import.

---

## Stage 13e: Detector-layer ablation (agent; if time allows)

- **Objective:** score the seven layer configurations on the 13a labels.
- **Paper question:** what does each detector layer contribute, and where do the trade-offs come from? (`sec:detector_ablation`.)
  - **T→D→E→M→E:**
    - **Threat:** a single-layer failure mode, either leaking or over-blocking.
    - **Defense:** layered detection.
    - **Experiment:** the 7 configurations, run on identical items.
    - **Metric:** precision, recall, specificity, F1, under-enforcement and over-enforcement for each configuration, with paired comparisons against the full pipeline.
    - **Evidence:** LAYERABL record.
- **Scope label:** an explicitly requested detector ablation, which is product-pipeline evidence. It is kept separate from LLM-only results, and the semantic-only configuration is not reported as an LLM-only result.
- **Depends on:** 13a-5 (frozen labels). If D11 chooses the fallback, it depends instead on the Stage 3 declared split with its provisional targets, which the record labels as provisional.
- **Work:**
  - A new harness, `evaluation/layer_ablation.py`, uses the in-process client of `adversarial_evasion.py`.
  - The configurations are `{regex:[2], ner:[3], semantic:[4], regex+ner:[2,3], regex+semantic:[2,4], ner+semantic:[3,4], full:[2,3,4]}`. This is the AB14 mapping, but the legacy `run-controlled-product-ablation.py` command and the `--allow-product-pipeline` flag are not used.
  - The executed layers are asserted for each configuration.
  - Paired comparisons against `full` use exact McNemar tests on the same items.
- **Owned paths:**
  - `evaluation/layer_ablation.py`, `evaluation/layer_ablation_report.py`, `evaluation/tests/test_layer_ablation*.py`;
  - `paper/research/layer-ablation-<date>.{md,json}`, `docs/experiments/layer-ablation-<date>.md`.
- **Interfaces and data shapes:**
  - Per item and configuration: `{item_id, config, layers_requested, layers_executed, action, per_layer_action, error}`.
  - Aggregates for each configuration, as in the 13a arm metrics.
- **Acceptance checks:**
  - **S13-G5 holds.**
  - **The harness tests pass:** `$PY -m unittest discover -s evaluation/tests -p "test_layer_ablation*.py"`. They cover an empty-list refusal, a mismatched executed set that aborts the run, and the McNemar check against a fixture.
- **User dependency:** none, apart from D11.
- **Status:** pending.
- **Handoff notes:**
  - The historical AB14 results stay historical. Do not merge them with these results.

---

## Stage 13f: End-to-end runtime overhead and deployment breadth (if time allows)

### 13f-1: Harness and headless timing (agent)

- **Objective:** measure what PriVoke costs a user, from submit to the request reaching the receiver (or to the block decision), in five arms.
- **Paper question:** what does PriVoke cost a user in practice? (RQ3 and `sec:cross_platform`.)
  - **T→D→E→M→E:**
    - **Threat:** protection that is too costly leads users to disable it, which is a usability-driven bypass.
    - **Defense:** local inference and configurable layers.
    - **Experiment:** browser timing in 5 arms.
    - **Metric:** p50, p95 and p99 latency, and CPU and memory where measurable.
    - **Evidence:** E2EOVH record.
- **Arms**, all configured through the extension's own settings:
  - A0: browser without the extension.
  - A1: extension installed with every layer toggle off. `background.js` `disabledLayersResponse` sends no analysis request, so no empty list ever exists.
  - A2: regex and NER.
  - A3: semantic only.
  - A4: the full pipeline.
  The harness asserts, from the bridge log, that A1 sent no request and that A2–A4 executed exactly their layers.
- **Depends on:** 13b-1, for the driver and the receiver.
- **Work:**
  - A timing driver, `extension/test/e2e-overhead-driver.mjs`, measures from the page submit event to the receiver's arrival timestamp, read with the same clock on one host. The prompts are a fixed, frozen benign and sensitive mix.
  - CPU and memory come from per-process sampling of the browser, supervisor and detector.
  - **Serialisation.** Before each run, a guard requires that no other Python, cargo or Docker workload is running and that system CPU load is at most 25% (the detector-latency precedent). The run acquires a host lock file, `evaluation/results/s13f/.timing.lock`, and root dispatches nothing else to the host while it holds the lock.
  - There are 5 repeats per arm, and the arms run in randomised order.
  - **Breadth:**
    - Chrome, Edge and Firefox on Windows;
    - headless Chromium in a Linux container (a second platform);
    - at least two provider-shape fixture interfaces from Stage 11.
- **Owned paths:**
  - `evaluation/e2e_overhead.py`, `evaluation/e2e_overhead_report.py`, `evaluation/tests/test_e2e_overhead*.py`;
  - `extension/test/e2e-overhead-driver.mjs`;
  - `paper/research/e2e-overhead-<date>.{md,json}`, `docs/experiments/e2e-overhead-<date>.md`.
- **Interfaces and data shapes:**
  - Per sample: `{arm, browser, platform, interface, repeat, prompt_id, t_submit_ms, t_receiver_ms|null, decision, layers_executed, cpu_pct, rss_mb, host_load_before}`.
  - Aggregates: p50, p95 and p99 with bootstrap intervals for each arm, browser and interface.
- **Acceptance checks:**
  - **S13-G6 holds**, in its first form.
  - **The serialisation guard holds:** the record shows `host_load_before` at or below 25% for every run, and there is one lock holder.
  - **The harness tests pass:** `$PY -m unittest discover -s evaluation/tests -p "test_e2e_overhead*.py"`.
- **User dependency:** none for the headless runs. The user should not use the machine during a timing window. Root agrees the window with the user.
- **Status:** pending.
- **Handoff notes:** never time while 13b, 13c or 13d runs are active.

### 13f-2: Attended headed timing subset and breadth (USER)

- **Objective:** headed timing on the user's installed browser, with the native host launched normally, for arms A0, A1 and A4. Optionally, a second LLM web interface or platform that the user has.
- **Depends on:** 13f-1.
- **Owned paths:** rows with `attended: true` in the same record.
- **Acceptance checks:** **the attended rows are labelled and reported separately.**
- **User dependency:** USER does all of the following:
  - run the provided script during an agreed idle window;
  - leave other applications closed;
  - optionally run it on a second machine or OS;
  - approve live-interface timing (D7), if wanted.
- **Status:** pending.
- **Handoff notes:** if 13f is dropped (D11), 13-P writes the single-platform or single-interface limitation paragraph, citing XPLAT-20261117 for what was covered.

---

## Stage 13-P: Paper integration and Stage 9 repeat

- **Objective:**
  - Fold each finished record into the paper under the page limits, in the T→D→E→M→E structure.
  - State which build each result measured.
  - Then repeat Stage 9 of the ASIACCS plan.
- **Paper question:** none of its own. It carries the questions of 13a–13f.
- **Depends on:** the records of whichever sub-stages are done, imported into `feat/nick-branch`; D9 for the scope entry.
- **Work:**
  1. **Scope.** Add a `paper/REWRITE_SCOPE.md` entry that authorises the Stage 13 evidence units. It must cover the description of the Rust V3 guarded-update path and the per-build labels.
  2. **Placement:**

     | Record | Section |
     | --- | --- |
     | 13a | RQ1, `sec:final_annotation` |
     | 13b | `sec:eval_evasion`, next to `tab:asr` |
     | 13c | RQ2, `sec:eval_update`, citing the guarded-update predicate |
     | 13d | `sec:eval_auth` |
     | 13e | `sec:detector_ablation` |
     | 13f | RQ3 and `sec:cross_platform` |

     Update `tab:security_goals` and `tab:threat_defense`, so that each new row cites its record, and update the "does not establish" items in Threats to Validity. Properties that are not met stay visible, including C11g and any `not_denied` row.
  3. **Claims ledger.** Add rows to `paper/research/claims.md`, one for each record, with scope labels.
  4. **Page budget.** Offset any added content with equal cuts or moves to the appendix. Rerun `check_pages.py` after each fold-in.
  5. **Stage 9 repeat.**
     - G1–G5, G12 (failing-id sets compared with `bca457df`, including the new test files), G13 and G14;
     - `check_anonymity.py` at 0 matches;
     - the anonymous export verified with `evaluation/export_anonymous_artifact.py`, and a second export of the measured Rust revision if D10 chooses it;
     - the implementation-gate critic, dispatched by root.
- **Owned paths:**
  - `paper/main.tex`, `paper/research/claims.md`, `paper/REWRITE_SCOPE.md`;
  - `paper/figures/` and `paper/scripts/` (figure scripts only);
  - this plan's status fields;
  - the Stage 13 section of `docs/plans/asiaccs-2027-revision.md` (status only).
- **Acceptance checks:**
  - **S13-G7 and S13-G8 hold.**
  - **The paper builds:** `latexmk -pdf main.tex` exits 0 in `paper/`.
  - **The pages check passes:** `$PY paper/scripts/check_pages.py` prints PASS.
  - **The anonymity check is clean:** `$PY paper/scripts/check_anonymity.py` reports 0 matches.
  - **Every security-goals row has evidence:** each row cites a `\label` and a record.
- **User dependency:** USER does all of the following:
  - approve the REWRITE_SCOPE entry (D9);
  - review the paper text;
  - approve the push. Root pushes, and the user uploads the artifact.
- **Status:** pending.
- **Handoff notes:** the paper stages run strictly in order, one writer at a time on `paper/main.tex`.

---

## Open decisions (user only)

Each decision has a recommended default. Root applies the default if the user has not answered by the date shown, and records that the default was used.

| ID | Decision | Recommended default | Needed by |
| --- | --- | --- | --- |
| D1 | Source of the fresh 13a prompts | Newly written by 2–3 recruited writers who are not developers and not annotators, using the frozen brief, with invented persons only. Alternatives: a licensed public prompt corpus (needs licence, ethics and PII handling), or prompts generated by an agent with a recorded generator (weaker independence; not recommended) | 26 Nov |
| D2 | Number and identity of annotators | 2 annotators and 1 adjudicator, none of whom wrote PriVoke labels or rubrics. Cohen's kappa per field; Fleiss' kappa if 3 or more | 26 Nov |
| D3 | 13a set size | 360 main items plus a 30-item pilot (the protocol's sizing; kappa half-width ≤ 0.10) | 26 Nov |
| D4 | Human-ethics approval and consent | The user confirms with the supervisor whether institutional approval is needed before recruiting anyone. Nothing involving external people starts until this is confirmed | 26 Nov |
| D5 | `fresh_eval-folio-NN` leak | `fresh_eval` is ineligible for 13a. For the deferred AU3 packet: normalise the token to the constant `folio` before pre-registration, recording both hashes. The AU3 packet itself is not run in Stage 13 | 26 Nov |
| D6 | Configurations scored in 13a | Both: `product` [regex, NER, semantic] and `semantic_only` [semantic], reported separately with their scope labels | 26 Nov |
| D7 | Real-provider traffic (13b, 13f) | Not approved. Use the synthetic receiver and provider-shape fixtures only. Any live run needs a separate approval that names the provider, the account and the exact non-sensitive prompts | before 13b-3 |
| D8 | Attended real-browser subsets | 13b: 60 stratified pairs in one browser. 13f: arms A0, A1 and A4, 5 repeats each. Skip both if the user cannot attend by 5 Dec | 28 Nov |
| D9 | The paper describes 13c and 13d measured on the Rust build (where V3 updates exist), with per-build labels, under a new REWRITE_SCOPE entry; PR #6 is not merged before submission | Approve the scope entry. Keep PR #6 after submission | before 13-P |
| D10 | Artifact coverage of the 13c and 13d harness | Make a second anonymous export of the measured Rust revision with the same exporter. Do not upload it; the user uploads | before 13-P |
| D11 | 13e and 13f go or no-go | Go only if the 13a–13d records are `ready for review` by 4 Dec. Otherwise 13f becomes the limitation paragraph, and 13e is dropped. 13e may run on provisional Stage 3 targets only if they are labelled as such | 4 Dec |
