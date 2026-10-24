#!/bin/bash
# Wave 3 confirmatory run (detector-layer scope). Frozen with the addendum; see
# docs/research/fresh-sets-freeze-addendum-20261024.md. Stages: score | pool | analyse.
#   TREES_ROOT  directory holding the O, N and C exports (each with extension/client-runtime and shared/python)
#   RESULTS     output directory (gitignored per-row outputs)
set -u
MAIN="D:/Git Repositories/Privoke-Research-Project"
EV="$(cd "$(dirname "$0")" && pwd)"
RESULTS="${RESULTS:-$MAIN/evaluation/results/w3_scoring_20261024}"
TREES_ROOT="${TREES_ROOT:?set TREES_ROOT}"
GEN="$MAIN/extension/client-runtime/generated"
PY_SM="$MAIN/evaluation/.venv-v1-v3-pipeline/Scripts/python.exe"   # O, N, N+R, N+lg
PY_TRF="$MAIN/evaluation/.venv-ner-models/Scripts/python.exe"      # N+trf
FRESH="$MAIN/evaluation/results/fresh_sets_20261024"
CONFIGS=("O" "N" "N+strip" "N+digits" "N+email" "N+caseless" "N+all" "N+lg" "N+trf")

stage="${1:?stage: score|pool|analyse}"
case "$stage" in
  score)
    mkdir -p "$RESULTS/logs"
    pids=()
    for cfg in "${CONFIGS[@]}"; do
      py="$PY_SM"; [ "$cfg" = "N+trf" ] && py="$PY_TRF"
      "$py" "$EV/w3_scoring.py" run --config "$cfg" --trees-root "$TREES_ROOT" --generated "$GEN" \
        --out "$RESULTS" --sets f1 f3 f2 > "$RESULTS/logs/score_${cfg//+/_}.log" 2>&1 &
      pids+=($!)
    done
    status=0
    for pid in "${pids[@]}"; do wait "$pid" || status=1; done
    echo "score finished, status=$status"; exit $status ;;
  pool)
    "$PY_SM" "$EV/w3_scoring.py" pool --results "$RESULTS" --adjudication "$FRESH/f2_adjudication" \
      --out "$FRESH/f2_adjudication/pool" ;;
  analyse)
    "$PY_SM" "$EV/w3_analysis.py" analyse --results "$RESULTS" \
      --f1-gold "$FRESH/f1_piimb/piimb_fresh_f1.jsonl" --f3-gold "$FRESH/f3_spy/f3_spy.jsonl" \
      --out "$RESULTS/analysis_full.json" --repo "$MAIN" --workers 8 || exit 1
    "$PY_SM" "$EV/w3_analysis.py" compact --input "$RESULTS/analysis_full.json" --output "$RESULTS/analysis_compact.json" || exit 1
    "$PY_SM" "$EV/w3_analysis.py" render --input "$RESULTS/analysis_full.json" --output "$RESULTS/analysis_tables.md" ;;
  *) echo "unknown stage"; exit 2 ;;
esac
