# F4 build and freeze record for the v3 registration (2026-10-25)

Scope: data for the detector-layer registration `docs/research/preregistration-detector-v3-20261025.md` (regex, NER, regex OR NER; configuration K versus O). Not LLM-only or semantic-layer evidence. Machine-readable twin: `docs/research/fresh-sets-freeze-v3-20261025.json` (every hash below). Parent records: `docs/research/fresh-sets-freeze-20261024.md` (F1 to F3) and its addendum.

**State at freeze: no detector, NER model or LLM has been run on any F4 row, and no F4 row text was read or printed.** Configuration K does not exist yet as a frozen commit: its slot (K commit SHA and git tree, scope, tests, development attestation, trees, scoring-script hashes) is filled by a v3 freeze addendum that is committed **before any F4 row is scored** (registration section 9). What was observed about F4: row, group and entity counts, source mix, per-document multiplicity, text-length summary (median, p90, max), hashes, and automated integrity checks (all rows positive, unique ids, no group in the exclusion union, zero shared groups, ids and text hashes with F1). F1 was read for group ids, ids and text hashes only (text is hashed inside the process and never printed). The F4 builders' author did not look at any F1 or F4 text.

## 1. Inputs (no new download)

| Input | Value |
|---|---|
| PIIMB `data/test_sentences.jsonl` at `4a13e9ffe6fd0d275efbde8afd4d8d8f1ffc2133` | 60,412,185 bytes, sha256 `5ff46f3a80316318794f94596fa374060d70f2f32a85909f958cbabc70bae41f` (checked by the draw before reading; CC BY-NC 4.0) |
| F1 file (group ids only, for exclusion and the overlap check) | `evaluation/results/fresh_sets_20261024/f1_piimb/piimb_fresh_f1.jsonl`, sha256 `4ff0832331f0b3f8d58026cca5cb26fd25833f98864b5822fb7c8d21172a9167` |
| v2 exclusion union (locked development and final groups plus the 24 Oct scan) | `.../fresh_sets_20261024/exclusion_union.json`, sha256 `b31bc6eba7e0cd45eeed9bd112847a672a205fb9a915d2c39a1813bc167f6518` (13,240 raw tokens) |
| Python | `evaluation/.venv-fresh-data` (Python 3.11.9; pyarrow 26.0.0, Faker 40.43.0, pandas 3.1.0, numpy 2.4.6; the draw uses the standard library only), run with `-I` |

## 2. Exclusion set for F4

- Rescan (25 Oct) of `evaluation/` and `models/` of the main checkout, with exactly the skips of the 24 Oct scan (`final.jsonl` never opened; external-data, `fresh_sets_20261024`, `fresh_sets_20261025`, the v123 benchmark tree and `models/experiments/ner-models-20261024` not entered; virtual environments, `.git`, caches pruned): 213,224 text data files read (63 more than on 24 Oct), 0 unreadable, 21,473 raw group tokens, sha256 `10ba3884a259c4c9e78918ef0dc2b5516f9ea5de6d7c9f1803eff8f887618f71`. Counted but not read: 1 parquet and the binary weight files, as before. Summary: `scan_summary_v3.json`.
- Union written to `exclusion_union_v3.json` = v2 union (13,240) plus rescan (21,473) plus every F1 group (8,184 raw): 21,473 raw tokens (the rescan already contained the other two, because the Wave 3 outputs store F1 group ids; the new tokens relative to the v2 union are exactly the F1 groups and their `_sN` forms, 8,233), file sha256 `a07c4c3d28bdf780450e903bfd140a9e621f3dc5af91dc01e28463ba6586a621`.
- Normalised (the draw strips `_sN`): **21,399 groups, sha256 `4017ce4d21c64b694db55b7b88e5dd109cdcd2c29405c2085694d8f186fec53e`**.
- Limits are those of the v2 record: groups used in artifacts the scan does not read (parquet, binary), and artifacts that store PIIMB rows without a group token, are not covered. Worktrees under `D:/Git-Worktrees` were not scanned (they hold git-tracked files and development-set derivatives, whose groups are in the locked development set already excluded).

## 3. The draw

```
python -I evaluation/fresh_set_plan.py scan <main>/evaluation <main>/models --output exclusion_scan_groups_v3.json --summary scan_summary_v3.json --workers 12 --skip <main>/evaluation/results/locked-public/final.jsonl --skip-dir <external-data> <fresh_sets_20261024> <fresh_sets_20261025> <results/v123_comparison_20261013/benchmark> <models/experiments/ner-models-20261024>
python -I evaluation/fresh_set_plan.py draw --count-only --sentences <piimb> --exclude exclusion_union_v3.json --seed 11102026 --positives 0 --negatives 0 --max-per-group {1,2,3}
python -I evaluation/fresh_set_plan.py draw --sentences <piimb> --exclude exclusion_union_v3.json --seed 11102026 --positives 8646 --negatives 0 --max-per-group 3 --name piimb_fresh_f4 --output f4_piimb
python -I evaluation/fresh_set_plan.py disjoint <F1 file> f4_piimb/piimb_fresh_f4.jsonl
python -I evaluation/fresh_set_plan.py ni-power --n 8646 ...   (four calls; outputs power_h7*.json, power_h8*.json)
```

- Seed 11102026 (v2 seeds: 8102026 F1, 9102026 F2, 10102026 F3). Rank order is `sha256(seed:key)`, as in v2. Quota 8,646 positives is the whole cap-3 pool, chosen because cap 1 (5,745) and cap 2 (7,535) fall short of the 7,849 target of registration 3.3; therefore the seed does not choose a subset.
- Pool (positives only; identical at the three caps for groups): cap 1 5,745 rows, cap 2 7,535, cap 3 8,646, always 5,745 documents; clean rows 0. By source at cap 3: ai4privacy 2,950 (1,813 documents), Gretel 2,863 (1,616), Nemotron-PII 682 (245), Privy 2,151 (2,071). Population counters: 150,022 rows seen, 27,180 non-English, 15,274 duplicates, 80 conflicting duplicates, 98,117 rows in excluded groups, 9,451 eligible rows, all positive (every clean row of the pool lies in an excluded group). The cap of 3 per document keeps 8,646 of them.
- Result: **8,646 rows, all positive, 5,745 source documents (3,955 with one sentence, 679 with two, 1,111 with three), 23,534 entity spans (ai4privacy 10,823, Gretel 6,493, Privy 4,922, Nemotron-PII 1,296), text length median 126, p90 332, max 1,433 characters, 4 ids disambiguated by a text-hash suffix (PIIMB uids are not unique), 0 rows without a span.** The manifest has no clean class.
- Overlap check with F1 (counts only): left 8,181 and right 5,745 normalised groups, **0 shared groups, 0 shared ids, 0 shared text hashes**.
- **Regression check of the draw code.** With the modified `fresh_set_plan.py` the F1 draw (seed 8102026, quotas 10,000 / 6,446, cap 3, shared classes, the v2 exclusion) reproduces the recorded manifest `output_sha256` `8ba37b336a321981544d4743c4e6784b03c32132ee44be7bc154b6c1488902fa` exactly. The added options (`--count-only`, `disjoint`, `ni-power`) do not change the draw path.

## 4. Files (under `D:/Git Repositories/Privoke-Research-Project/evaluation/results/fresh_sets_20261025/`, gitignored)

| File | Bytes | sha256 (bytes on disk) |
|---|---|---|
| `f4_piimb/piimb_fresh_f4.jsonl` | 5,438,592 | `d4bed756790c7b000fc5e8b6028e3f962c8dbfabe3f607a7180224d55356589d` |
| `f4_piimb/manifest.json` | 1,427 | `b27b169f18d379933eb216d9edf599d4d67ea3e9bd81deaf3f0126073d12c355` |
| `exclusion_union_v3.json` (= `exclusion_scan_groups_v3.json`) | 849,070 | `a07c4c3d28bdf780450e903bfd140a9e621f3dc5af91dc01e28463ba6586a621` |
| `scan_summary_v3.json` | 11,017 | `c32c96736cb1e3d11abaaa9a9ffaa4174cc15757402e32a8c7d5641066743c65` |
| `power_h7.json` | 1,897 | `8a45c6bb42e8e911817069950c2ea0e3bcee721df5190c59b07fc8c3a88d1718` |
| `power_h7_de1.2.json` | 1,623 | `44fb2a9f79a498925a937f677b4aeb988788d05d4646084ab051569482bad83e` |
| `power_h8.json` | 1,697 | `feb254bc45d21d801b0dbcddc8023b696d38b709096770dc568a9020bf41defa` |
| `power_h8_de1.2.json` | 1,090 | `1774437b6e1284f559e1c4a0768864eaace3632a74e2fbedb8488f9e874d00c9` |

The manifest's `output_sha256` (`8c3da51b79daaa5215a62554af1f3f1d50b56e96ed439d883747783d6bac5f54`) covers the LF-normalised content and differs from the on-disk (Windows newline) hash above by design, as in v2. The manifest's `script_sha256` (`5bcd61a1...`) is the on-disk working-copy bytes of `fresh_set_plan.py` (mixed line endings under `core.autocrlf`); the git blob hash is in section 5.

## 5. Code and document hashes (sha256 of the LF-normalised git blobs)

| File | sha256 |
|---|---|
| `evaluation/fresh_set_plan.py` (commit `ffd43fb6`) | `02865ca4c25cd060812d82940688a33e31f5047c75baded9d7d39b48d37f375e` |
| `evaluation/tests/test_fresh_set_plan.py` (commit `ffd43fb6`; 16 tests pass) | `b11469c3e3e0e6a0e87f8850b2faae921bb444de77725994fa629bf14100cdb3` |
| `evaluation/build_fresh_sets.py` (unchanged) | `73cf3c1f903a2ce1beb72ecb19e32c181636ed7ee82d509e0755399026b4308e` |
| `evaluation/requirements-fresh-data.txt` (unchanged) | `2daf35926753e73d1b7cd12724db7b5b35cdd3e4cc4cf33c690006552af4486d` |
| `docs/research/preregistration-detector-v3-20261025.md` (commit `8523fe5d`) | `afcd2bd96b3e6cdc5b40f56f7f50409fd28f968f15a9933164eca0e9b487d186` |
| `docs/experiments/fresh-heldout-results-20261024.md` (with the new section 7, commit `8523fe5d`) | `411dd604da8ad7f263ba107c16a95fb1c4130bd0fdd667d3f9ecc51b754280b0` |
| `docs/research/preregistration-detector-v2-20261024.md` (current blob) | `f97b8b5da50f163febde19d8b9395a6f88d2a361f142b4ae54fd931c92f48e1d` (it was `1dd0ef30...` at the v2 freeze; later amendments are recorded in the v2 addendum history) |
| `evaluation/detector_stats.py` (unchanged since `bf5e24c1`) | `c9b79a43e766021f2e1d083eb9db64fcc86d4db78b35f3ef27ad9b607127f60e` |
| `docs/research/label-family-mapping-20261024.json` | `19cc6103d404484be3a3ef0a851edfa0ae1254859557ffc87921673b9b05e5f6` |

## 6. Frozen analysis parameters (copied from the registration)

Configurations O, N, K, K+all; hypotheses H7 (union recall, `positive` rule, margin -1.0 pt), H8 (union recall, `block` rule, margin -0.5 pt), H9 and guards G1 (margin -1.0 pt, K vs O) and G2 (margin -2.0 pt, K vs N) on the F1 clean second look; one-sided 97.5 % bound from the 95 % percentile paired grouped bootstrap, 10,000 replicates, seed 20261024, clusters = `group_id`; per-source cells for ai4privacy, Gretel, Nemotron-PII, Privy; standardised weights (0.3374, 0.3325, 0.1687, 0.1614) and (0.25, 0.25, 0.25, 0.25); heterogeneity rule (a source whose whole interval lies below -1.0 pt, sources under 700 rows reported only). Power at n = 8,646: H7 90.1 % at true delta 0 and psi 8.2 % (36.8 % at -0.5 pt; 25,737 positives would be needed); H8 92.1 % at psi 1.9 %.

## 7. Open slot

The K freeze addendum (`docs/research/fresh-sets-freeze-addendum-v3-20261025.md` and `.json`) is **not yet written**. It must record the items of registration section 9, item 2, and must be committed before the first F4 row is scored. Until then no scoring script may be run on F4, and this record plus the registration are the only frozen items.
