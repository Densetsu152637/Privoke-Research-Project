# Anonymous code artifact for double-blind review

The review venue is double-blind. The code artifact is uploaded to the anonymous OpenScience
platform and must carry no author, institution, account or repository identity. Upload is a manual
step by an author; the exporter never uploads anything.

## Export

Run from the repository root in the host Python environment (standard library only):

```
python evaluation/export_anonymous_artifact.py --revision <commit> --dest <directory outside the repository>
```

- Default destination: `anonymous-artifact` under the system temporary directory. A destination
  inside the repository or any of its worktrees is refused. A non-empty destination is refused unless
  it holds a previous export manifest and `--clean` is given.
- The copy is built with `git archive`: tracked files at the chosen revision only. It has no `.git`
  directory, no remote URL, no history and no untracked or ignored files.
- Exit status: 0 when verification finds nothing, 1 when it finds a match (do not upload the tree),
  2 for an invocation or Git error.

## What the export changes

1. **Excluded files** (`DEFAULT_EXCLUDES` in the script; add more with `--exclude GLOB`): LaTeX build
   outputs of `paper/main`, `paper/old/` (pre-anonymization submissions), third-party source PDFs
   under `paper/sources/`, and the exporter, its test and the pattern file, because those must name
   the identity strings in order to find them. Every excluded path is listed in the manifest.
2. **Rewrites** of text files: author names, institution names, e-mail addresses, account handles
   and URLs under the author accounts are replaced by neutral placeholders (`Anonymous Author`,
   `Anonymous Institution`, `anonymous@example.invalid`, `https://anonymous.invalid/repository`).
   Copyright lines in `LICENSE`, `LICENCE`, `COPYING` and `NOTICE` files become
   `Copyright (c) Anonymous Authors`. Binary files are copied unchanged.
3. **Verification** of the whole exported tree, file names included, with the shared pattern file
   `paper/scripts/anonymity-patterns.txt`. It holds one case-insensitive regular expression per line
   and `#` comments, and the same file checks the paper. Text files are scanned line by line. Binary
   files cannot be rewritten, so their raw bytes are scanned instead and listed under
   `binary_files` in the manifest. Compressed streams inside PDFs and archives are not decoded, so a
   clean byte scan is weaker evidence for those; the default export contains none of the excluded
   PDFs. A match in any file, file name or binary fails verification.

## Manifest

`ARTIFACT-MANIFEST.json` is written into the destination. It records: file count; the SHA-256 of the
sorted `<file sha256>  <path>` list (the manifest itself excluded); the exclusion globs and excluded
files; redaction counts per file; the pattern-file hash and count; verification results (files
scanned, text matches as file and line numbers, name matches, binary files, byte-scan matches); and a
SHA-256 commitment to the source commit. It records neither the source path nor the commit hash,
because a commit hash could be used to look the repository up. The manifest is scanned with the same
patterns.

## Before upload

1. Export from the final submission commit and require exit status 0.
2. Re-run the pattern file against the destination yourself, for example
   `grep -rIiE -f <patterns without comments> <destination>`.
3. Read `paper/` in the export: the exporter rewrites identity text but does not typeset the paper,
   so the anonymous `main.tex` from the paper branch is the authoritative source.
4. Upload the directory by hand to the anonymous platform. Do not use a personal account that is
   linked to the authors, and do not attach the `.git` directory.

Tests: `python -m unittest evaluation/tests/test_export_anonymous_artifact.py`.
