# Roadmap

This docs-only branch (`docs/roadmap`) holds the project roadmap so collaborators can read, comment on and edit the plans without the code branches.

| Plan | What it covers | Where the work lands |
| ---- | -------------- | -------------------- |
| [rust-server-rewrite.md](rust-server-rewrite.md) | Rust rewrite of the server stack, deployment and CI | `feat/rust-rewrite` (draft PR #6) |
| [asiaccs-2027-revision.md](asiaccs-2027-revision.md) | ASIACCS 2027 paper revision, including the Stage 13 submission experiments | `feat/nick-branch` |
| [v3-routine-training.md](v3-routine-training.md) | Routine training retargeted to the three V3 models; V1 kept for detection only (user decision 23 Nov 2026) | `feat/rust-rewrite` |

Order of work: the Rust rewrite, including the V3 routine-training retarget, then the remaining ASIACCS stages, with Stage 13 last.

The copies here were taken on 19 November 2026 from `feat/rust-rewrite` (rust plan) and `feat/nick-branch` (ASIACCS plan). Status lines are updated on the code branches as stages land; resync this branch from them before editing, and propose roadmap changes as PRs against `docs/roadmap`.
