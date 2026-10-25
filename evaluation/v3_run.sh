#!/bin/bash
# v3 confirmatory run (detector-layer scope). Frozen with the v3 freeze addendum; see
# docs/research/fresh-sets-freeze-addendum-v3-20261025.md. Stages: score | pool | analyse.
#   TREES_ROOT  directory holding the O, N, K and KA exports (each with extension/client-runtime and shared/python)
#   RESULTS     output directory for the v3 per-row outputs (gitignored)
# Scoring runs two configurations at a time (the Wave 3 run segfaulted under four-way parallelism).
set -u
MAIN="D:/Git Repositories/Privoke-Research-Project"
EV="$(cd "$(dirname "$0")" && pwd)"
RESULTS="${RESULTS:-$MAIN/evaluation/results/v3_scoring_20261025}"
W3="${W3:-$MAIN/evaluation/results/w3_scoring_20261024}"
GEN="$MAIN/extension/client-runtime/generated"
PY="$MAIN/evaluation/.venv-v1-v3-pipeline/Scripts/python.exe"
FRESH24="$MAIN/evaluation/results/fresh_sets_20261024"
FRESH25="$MAIN/evaluation/results/fresh_sets_20261025"

score_one() {  # config, sets...
  local cfg="$1"; shift
  mkdir -p "$RESULTS/logs"
  PYTHONFAULTHANDLER=1 "$PY" "$EV/v3_scoring.py" run --config "$cfg" --trees-root "${TREES_ROOT:?set TREES_ROOT}" --generated "$GEN" \
    --out "$RESULTS" --sets "$@" > "$RESULTS/logs/score_${cfg//+/_}.log" 2>&1
}

stage="${1:?stage: score|pool|analyse}"
case "$stage" in
  score)
    status=0
    # wave A: the two K configurations (F4 first, then the F1/F3/F2 second looks)
    score_one K f4 f1 f3 f2 & pa=$!
    score_one "K+all" f4 f1 f3 f2 & pb=$!
    wait $pa || status=1; wait $pb || status=1
    # wave B: O and N on F4 (their F1/F2/F3 outputs are the Wave 3 files, reused)
    score_one O f4 & pc=$!
    score_one N f4 & pd=$!
    wait $pc || status=1; wait $pd || status=1
    echo "score finished, status=$status"; exit $status ;;
  pool)
    "$PY" "$EV/v3_analysis.py" pool --results-v3 "$RESULTS" --adjudication "$FRESH24/f2_adjudication" \
      --out "$FRESH24/f2_adjudication/pool_v3" ;;
  analyse)
    "$PY" "$EV/v3_analysis.py" analyse --results-w3 "$W3" --results-v3 "$RESULTS" \
      --f4-gold "$FRESH25/f4_piimb/piimb_fresh_f4.jsonl" --f1-gold "$FRESH24/f1_piimb/piimb_fresh_f1.jsonl" \
      --f3-gold "$FRESH24/f3_spy/f3_spy.jsonl" --out "$RESULTS/analysis_full.json" --workers 4 || exit 1
    "$PY" "$EV/v3_analysis.py" render --input "$RESULTS/analysis_full.json" --output "$RESULTS/analysis_tables.md" ;;
  *) echo "unknown stage"; exit 2 ;;
esac
