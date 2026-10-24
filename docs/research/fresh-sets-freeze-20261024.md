# Fresh sets F1-F3: build and freeze record (2026-10-24)

Scope: data for the detector-layer pre-registration `docs/research/preregistration-detector-v2-20261024.md` (regex, NER, regex OR NER). Not LLM-only or semantic-layer evidence. Machine-readable twin: `docs/research/fresh-sets-freeze-20261024.json` (every hash below, plus per-file hashes). Exclusion coverage: `docs/research/fresh-sets-exclusion-scan-20261024.json`.

**State at freeze: no detector, NER model or LLM has been run on any F1, F2 or F3 row, and no row text was read or printed by the builders' authors.** What was observed: row and group counts, source mix, text-length summaries, hashes, and automated integrity checks (span bounds, id uniqueness, no group in the exclusion union, no F1 text equal to a development text). F2 is **unlabelled; human blind adjudication is pending**. This freeze and the finalised pre-registration are committed before any scoring.

## 1. Downloads (official sources, all under 5 GB, none gated; local, gitignored)

Root: `D:/Git Repositories/Privoke-Research-Project/evaluation/results/external-data/<dataset>/<revision>/` with `provenance.json` in each.

| Dataset | Revision | File | Bytes | sha256 | Licence |
|---|---|---|---|---|---|
| piimb | `4a13e9ffe6fd0d275efbde8afd4d8d8f1ffc2133` | `test_sentences.jsonl` | 60,412,185 | `5ff46f3a80316318794f94596fa374060d70f2f32a85909f958cbabc70bae41f` (matches the recorded LFS oid) | CC BY-NC 4.0 (sources CC BY 4.0, Apache 2.0, MIT) |
| oasst2 | `179dd21fc55192153d94adb0e0ce8f69e222bf75` | `2023-11-05_oasst2_prompts.messages.jsonl.gz` | 15,560,794 | `087bb0de13a9491eca7e940378aefd24a6bd92d79da31b7495bb1df4ae7b7a02` | Apache 2.0 |
| dolly15k | `bdd27f4d94b9c1f951818a7da7fd7aeea5dbff1a` | `databricks-dolly-15k.jsonl` | 13,085,339 | `2df9083338b4abd6bceb5635764dab5d833b393b55759dffb0959b6fcbf794ec` | CC BY-SA 3.0 |
| wildchat-1m | `7d6490e462285cf85d91eabea0f9a954fbddcd1f` | `train-00000-of-00014.parquet` | 230,786,095 | `abec2a13129db8c0e6a2d3a51ff12644873c748205a6fdf6551fbcb34430e51c` | ODC-BY |
| spy | `093be5a0235c9e15bc1c364f10ac48b9563de34c` | `legal_questions_placeholders.jsonl` | 45,690,405 | `bb1337d1b289e3da63accc032d614330313fd700612792094a482266fcc389d9` | CC BY 4.0 |
| spy | same | `medical_consultations_placeholders.jsonl` | 44,188,672 | `230f508921503c1ec6e352c420d639458d89c6cf658b9f0d8ea75bf014c6e15b` | CC BY 4.0 |
| spy | same | `SPY.py` (read, not executed) | 5,959 | `dfcaffb309dcd37549e240782cc56ffcc8bad052263533d5b215da0aeabb6032` | CC BY 4.0 |

Not downloaded: TAB (F4 not built), Gretel finance, Nemotron-PII train (the PIIMB pool filled the positive quota; the clean shortfall is a property of the labelled-clean sentences, not recoverable from Nemotron-PII positives-only data). Python packages only in the new venv `evaluation/.venv-fresh-data` (Python 3.11), pinned in `evaluation/requirements-fresh-data.txt` (pyarrow 26.0.0, Faker 40.43.0, pandas 3.1.0, numpy 2.4.6).

## 2. Exclusion set

- Locked development plus final: 929 groups, sha256 `16e2006bfa5a4dff86e0bd8a77d0bc43f831bb407c9f988257f36d953da78b45` (from the authorised id/group-only derivation recorded in `fresh-evaluation-sources-20261024.md`; `final.jsonl` was not opened here).
- Scan (`fresh_set_plan.py scan`, tokens only, never text) of `evaluation/` and `models/`: 213,161 text data files read (212,564 `.json`, 596 `.jsonl`, 1 `.csv`), 0 unreadable, 0 over the 500 MB limit. Counted but not read: 1 `.parquet`, binary weights (`.bin` 178, `.npy` 7, `.npz` 588, `.onnx` 1, `.pt` 252, `.safetensors` 132, `.whl` 1). Skipped on purpose: `final.jsonl`; `evaluation/results/external-data` (the raw downloads) and `fresh_sets_20261024` (this output); `evaluation/results/v123_comparison_20261013/benchmark` (a runtime memory/latency benchmark tree with a very large file count; its accuracy cases are the locked development rows); `models/experiments/ner-models-20261024` (model-weight caches of another agent); virtual environments, `.git`, `__pycache__`, `node_modules`, Hugging Face `snapshots` and `blobs` directories.
- Result: 13,240 group tokens (sha256 `f61c404635bbd510889a1a7a0c47553029190267397aafd18c698732da9387fd`), including all 929 locked groups. Of these, 10,544 are Nemotron-PII documents, 1,055 Gretel, 990 ai4privacy-en, 614 Privy, 35 ai4privacy-multi and 2 MAPA. The draw normalises `_sN` suffixes (13,218 groups, sha256 `fd4bd41548cbf883d84c2fccb0f719315f05e0fe3ac43de75048e5b7af91d957`).
- Limit: groups used in artifacts the scan does not read (parquet, binary), and any artifact that stores PIIMB rows without a group token, are not covered.  The single unread parquet file was not inspected.

## 3. Sets

| Set | File (under `evaluation/results/fresh_sets_20261024/`) | Rows | sha256 of file |
|---|---|---|---|
| F1 | `f1_piimb/piimb_fresh_f1.jsonl` (+ `manifest.json`) | 16,446 = 10,000 PII + 6,446 clean; 24,134 entity spans; 8,184 groups | `4ff0832331f0b3f8d58026cca5cb26fd25833f98864b5822fb7c8d21172a9167` |
| F2 | `f2_natural_prompts/f2_natural_prompts.jsonl` (+ `manifest_f2.json`, `f2_dataset_native_hints.jsonl`) | 6,000 (oasst2 2,000, WildChat 2,500, Dolly 1,500), unlabelled | `6cbf0a5ae551e4148a569c87d5e4308d5ffc8803ec69d161ed392b7ede093914` |
| F3 | `f3_spy/f3_spy.jsonl` (+ `manifest_f3.json`) | 2,000 (1,000 legal, 1,000 medical), 13,522 spans, positives only | `42b2747af71c5db552ffc1c7b2082f039a0a3e1cbd4b4e512890d6f23c3a34ee` |
| F4 | not built | | |
| dev spans | `dev_spans.jsonl` | 502 (development partition re-joined with PIIMB by id; spans recovered for all rows; for span-harness development, **not held out**) | in the JSON |
| F2 packets | `f2_adjudication/packets/packet-001..060.jsonl`, `f2_adjudication/coordinator/{adjudication_key.json,packets_manifest.json}` | 6,000 blinded items (opaque id and text only) in 60 packets of 100 | key `aba4ac5a650697bc793508137acbf8dff3cb3ca678461fb05549e8bd5e3d8aae` |

Hashes in the manifests labelled `output_sha256` cover the LF-normalised content and differ from the on-disk (Windows newline) file hashes above by design.

### F1
- Draw: `fresh_set_plan.py draw`, seed 8102026, quotas 10,000 and 6,600 requested, `--max-per-group 3 --share-groups-across-classes`, 6,446 clean obtained (the maximum the pool allows). Rank order is `sha256(seed:key)`. Pool after exclusion: 36,899 eligible rows; 70,669 rows removed by the exclusion; 27,180 non-English; 15,274 duplicates; 80 conflicting duplicates; 38 ids disambiguated by a text-hash suffix (PIIMB `uid` values are not unique).
- Cap relaxation (pre-registered rule ran out): disjoint classes could fill at most 1,547 / 2,255 / 2,505 clean rows at cap 1 / 2 / 3, and sharing documents across classes gave 3,818 / 5,491 / 6,474 clean rows at cap 1 / 2 / 3 before the privy-id fix (6,446 at cap 3 after it). The cap was held at 3 (the registered ceiling) and classes may share a document (1,313 documents do). The clean count is 6,446, 2.3 % below plan; all tests use whole-document clusters.
- Source mix (rows): ai4privacy-OpenPII 3,374 PII / 1,504 clean; Gretel 3,325 / 2,024; Nemotron-PII 1,687 / 2,088; Privy 1,614 / 830. Nemotron-PII is no longer dominant, because its documents were the most used elsewhere in the repository.

### F2
- Seed 9102026. Filters: English (oasst2 `lang=en` initial prompter turns; Dolly instruction; WildChat first user turn with language English, non-toxic), length at most 433 characters (the 99th percentile of 122,842 English PIIMB sentences; longer prompts excluded, not truncated), identical texts removed. Funnel and selected length summary (median 74, p90 254, max 433 characters) are in the manifest. The cap removes 915 of 23,680 oasst2, 61 of 15,011 Dolly and 10,730 of 28,175 English WildChat prompts, so F2 describes **short prompts**; false-positive rates on long pasted documents are not measured by it.
- Dataset-native flags (oasst2 `pii` reviewer value, WildChat `redacted`) live in a separate hints file and are coordinator-only stratification hints.
- Adjudication workload (not done): the review pool is the union of prompts flagged by any frozen configuration plus a 400-item audit sample. With the 4 to 10 % union flag rates seen on PIIMB clean rows and about 10 configurations, I expect 700 to 1,500 flagged prompts plus 400 audit items, about 1,100 to 1,900 prompts (planning figure 1,500) at an estimated 10 to 15 s each for these short prompts: 3 to 8 hours per rater, two raters, plus the owner's disagreement resolution. Rating all 6,000 would be 17 to 25 hours per rater and is the upper bound. The pool cannot be fixed until Wave 3 flags are known; the coordinator repacks only the pooled items from the blinded packets.

### F3
- Seed 10102026. SPY placeholder rows ranked by `sha256(seed:domain:index)`, 1,000 per domain. Placeholders (single B- tags; there are no I- tags) are replaced by Faker 40.43.0 (en_US) values: one value per entity type per row (as in `SPY.py`), the value function chosen per row from the `SPY.py` function lists by a seeded RNG, the Faker instance seeded per row. `SPY.py` uses an unseeded `random.shuffle`, so exact SPY values are not reproduced; the entity values are synthetic. Spans are character offsets into the stored text; automated check: 0 invalid or overlapping spans in 2,000 rows. Texts are long documents (median 3,015 characters, p90 3,739, max 10,209), so F3 is prompt-style by topic rather than by length.

### Development spans
`dev_spans.jsonl` joins `development.jsonl` ids (never `final.jsonl`) to PIIMB by uid and the identical normalised text (12 uids occur in several PIIMB rows with different text; the matching row is selected by text). 502 of 502 joined, labels agree, 561 spans on 264 positive rows. Use: develop and test the span harness; these are development rows and give no held-out evidence.

## 4. Generation commands (host Python = `evaluation/.venv-fresh-data`, run from the worktree)

```
python evaluation/fresh_set_plan.py scan <main>/evaluation <main>/models --output exclusion_scan_groups.json --summary scan_summary.json --workers 8 --skip <main>/evaluation/results/locked-public/final.jsonl --skip-dir <external-data> <fresh_sets_20261024> <results/v123_comparison_20261013/benchmark> <models/experiments/ner-models-20261024>
python evaluation/fresh_set_plan.py draw --share-groups-across-classes --sentences <piimb>/test_sentences.jsonl --exclude exclusion_union.json --seed 8102026 --positives 10000 --negatives 6446 --max-per-group 3 --name piimb_fresh_f1 --output f1_piimb
python evaluation/build_fresh_sets.py f2 --oasst2 ... --dolly ... --wildchat ... --piimb-sentences ... --output f2_natural_prompts
python evaluation/build_fresh_sets.py adjudication --f2 f2_natural_prompts/f2_natural_prompts.jsonl --output f2_adjudication
python evaluation/build_fresh_sets.py f3 --legal ... --medical ... --output f3_spy
python evaluation/build_fresh_sets.py dev-spans --development <main>/evaluation/results/locked-public/development.jsonl --sentences ... --output dev_spans.jsonl
```

`exclusion_union.json` is the union of the 929 locked groups and the scan output (identical to the scan output). F2, the packets, F3 and the dev spans were built twice with identical outputs (determinism check). The scan ran with the version of `fresh_set_plan.py` at commit `d6f738b0` (the scan function has not changed since); the F1 draw ran with the file whose sha256 is below.

## 5. Code and document hashes (sha256)

| File | sha256 |
|---|---|
| `evaluation/fresh_set_plan.py` | `4e804f6f01536778aa0b534223333881f9fe009ad34b43c075a16f1f8dd85837` |
| `evaluation/build_fresh_sets.py` | `d2cd1aeafeff94141b2dc700f1aba1b3195615496123d864e0492ce735fb8378` |
| `evaluation/requirements-fresh-data.txt` | `938142a14cc7b83820dd345f5b423095ffe92af1004e0aa17f42c31d45a2abe5` |
| `docs/research/preregistration-detector-v2-20261024.md` | `1dd0ef309f35450ff14815e9c7d9bd54c93a6d47107b83f6fe979492928e0b8d` |
| `docs/research/f2-adjudication-guideline-20261024.md` | `7908d5f087cbed5852833b5e29f8bbedc9d903eea7f91a1a11ee74a67440ad6c` |
| `evaluation/detector_stats.py` at `bf5e24c1` (`research/wt-a-stats`) | `c9b79a43e766021f2e1d083eb9db64fcc86d4db78b35f3ef27ad9b607127f60e` |
| `evaluation/evaluate_installed_detectors.py` at `e70e3a2e` | `0261942aa1f48ed6e436e8b555baa9bbf96adde1f3dcc4de34fb29a9a16997a9` |
| `evaluation/robustness_probe.py` at `33b6e6b5` (`research/wt-c-robust`) | `7dabcaa05050995bb35df2a569e2431e61ad343e805e7acb3a764d41ac63607f` |

Code under test (SHAs): O = clean export of `e6c177ff`; N = `e70e3a2e`; N+R = `b1975bc2`; N+lg and N+trf = `research/wt-g-nermodels` `f4f07c3c`; statistics `bf5e24c1`. The numeric margins, alpha levels, bootstrap replicates (10,000) and seed (20261024) are those of section 5 of the pre-registration.

## 6. Pre-registration changes in this record

Finalised: F1 and F3 sizes, F4 not built, exclusion coverage and cap relaxation (section 2.1 of the registration), H2 margin kept at 1.0 pt, open items (section 11 of the registration: category mapping file and statistics-code hash as a freeze addendum; F2 labels pending). Owner decision on configuration N: commit `e1ed0490`. Robustness hypotheses H5 and H6: `50be1743`. NER configurations N+lg and N+trf and restated H3: `f57db6ec`. None of these changed after data were drawn except the section 2 sizes and notes, which record the draw.
