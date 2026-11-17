"""v3 scoring driver: the Wave 3 driver extended for the F4 set and the K / K+all trees (detector-layer scope).

Scope: NOT LLM-only, NOT semantic-layer, NOT full-product. Rows are analysed with
``pipeline.analyse_text(layers=["regex", "ner"], regex_first=False)`` (explicit, non-empty layer list, no
semantic layer, no Docker, no network), exactly as ``w3_scoring.py``. This module changes no scoring
semantics: it registers the extra set ``f4`` and the extra configurations in the ``w3_scoring`` tables and then
calls its unchanged ``main``. Governing documents: ``docs/research/preregistration-detector-v3-20261025.md``,
``docs/research/fresh-sets-freeze-v3-20261025.md`` and the v3 freeze addendum (which records the sha256 of this
file). Nothing here may change after scoring starts.

Additions
---------
* set ``f4``: the registered file ``fresh_sets_20261025/f4_piimb/piimb_fresh_f4.jsonl`` (sha256 checked by the
  driver before reading);
* configurations: ``K`` (tree ``K``, export of the K freeze), ``K+all`` (tree ``KA``, K merged with the frozen
  robustness commit, four flags on) and ``KA0`` (tree ``KA`` with every flag off; equivalence check only);
  ``O`` and ``N`` are the unchanged Wave 3 configurations (trees ``O`` and ``N``).

Usage is that of ``w3_scoring.py run`` (``--config``, ``--trees-root``, ``--generated``, ``--out``, ``--sets``).
The driver never rescored a set whose output exists; perturbed items are not part of v3 (``--no-perturbed`` is
forced).
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import w3_scoring as w3  # noqa: E402

FRESH_DIR_V3 = "evaluation/results/fresh_sets_20261025"
F4_REL = f"{FRESH_DIR_V3}/f4_piimb/piimb_fresh_f4.jsonl"
F4_SHA256 = "d4bed756790c7b000fc5e8b6028e3f962c8dbfabe3f607a7180224d55356589d"

# K is the N code (e70e3a2e, via 42f8f529) plus the regex rework: none of the four robustness flags nor the NER
# model option exists in its tree, so the observed flag record equals N's.
_K_EXPECT = dict(w3._N_EXPECT)
V3_CONFIGS = {
    "K": {"tree": "K", "env": {}, "expect": _K_EXPECT},
    "K+all": {"tree": "KA", "env": {"PRIVOKE_STRIP_FORMAT_CHARS": "1", "PRIVOKE_CANONICALISE_DIGITS": "1",
                                    "PRIVOKE_CANONICALISE_EMAIL_WORDS": "1", "PRIVOKE_NER_CASELESS_GATE": "1"},
              "expect": w3._expect(strip=True, digits=True, email=True, caseless=True)},
    # equivalence check only: the merged tree with every new flag off (must equal K row by row)
    "KA0": {"tree": "KA", "env": {}, "expect": w3._expect()},
}
V3_SCORED_CONFIGS = ["O", "N", "K", "K+all"]


def register() -> None:
    w3.REGISTERED_SETS["f4"] = (F4_REL, F4_SHA256)
    w3.CONFIGS.update(V3_CONFIGS)


def main(argv=None) -> None:
    register()
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "run" and "--no-perturbed" not in argv:
        argv.append("--no-perturbed")
    w3.main(argv)


if __name__ == "__main__":
    main()
