#!/usr/bin/env bash
# Rerun the ThreatRank pipeline from the recorded scanner output and regenerate every result.
#
#   ./reproduce.sh quick    parsers, remediation plan and tables, about 1 minute
#   ./reproduce.sh          everything, including the learned models, about 20 minutes
#
# Results are written over the copies committed in data/figures/, so `git status` afterwards
# shows what, if anything, differs from the recorded run. `python3 tests/check_results.py`
# compares the numbers.

set -uo pipefail
MODE="${1:-full}"
PY="${PYTHON:-python3}"
cd "$(dirname "$0")/data"

GRAPH="--graph ../mulval/cases/lab3/out --topology topology_lab3.json"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
FAILED=0

step() {
    local name="$1"; shift
    local start=$SECONDS
    printf '%-46s' "$name"
    if "$@" > "$TMP/$(echo "$name" | tr -c 'a-zA-Z0-9' '_').log" 2>&1; then
        printf 'ok    %4ss\n' "$((SECONDS - start))"
    else
        printf 'FAIL  %4ss\n' "$((SECONDS - start))"
        tail -20 "$TMP/$(echo "$name" | tr -c 'a-zA-Z0-9' '_').log"
        FAILED=1
    fi
}

same() {  # the parser output must match the committed CSV byte for byte
    cmp -s "$1" "$2" || { echo "differs: $1 vs $2"; return 1; }
}

parse_openvas() { $PY parse_openvas.py raw/openvas/2026-09-08_openvas_B_group-b-old-images.xml \
                      --offline -o "$TMP/ov.csv" && same "$TMP/ov.csv" processed/findings_openvas_b2.csv; }
parse_nessus()  { $PY fetch_nessus.py --from-raw raw/nessus/2026-09-29_nessus_B_group-b-nessus.json \
                      --group B --offline -o "$TMP/ne.csv" && same "$TMP/ne.csv" processed/findings_nessus_b2.csv; }
parse_qualys()  { $PY parse_qualys.py raw/qualys/2026-10-06_qualys_lab3.xml --group b2 \
                      -o "$TMP/qb.csv" && same "$TMP/qb.csv" processed/findings_qualys_b2.csv; }

echo "== 1. Parse the raw scanner reports and compare with data/processed/"
step "OpenVAS XML  -> findings_openvas_b2.csv" parse_openvas
step "Nessus JSON  -> findings_nessus_b2.csv"  parse_nessus
step "Qualys XML   -> findings_qualys_b2.csv"  parse_qualys

echo "== 2. Prioritise: the remediation plan (Experiment 1)"
step "prioritise.py, two scanners, correlated" $PY prioritise.py $GRAPH \
    --findings processed/findings_openvas_b2.csv --findings processed/findings_nessus_b2.csv \
    --correlate -o processed/plan_merged.csv

echo "== 3. Tables (Experiments 3 and 4, corpus)"
step "corpus_table.py"      $PY corpus_table.py -o figures/tab_corpus.tex
step "graph_rank_table.py"  $PY graph_rank_table.py $GRAPH --findings processed/findings_openvas_b2.csv -o figures/tab_graphrank.tex
step "robustness_table.py"  $PY robustness_table.py $GRAPH -o figures/tab_robustness.tex

if [ "$MODE" != "quick" ]; then
    echo "== 4. Learned components (Experiment 2)"
    step "likelihood.py   (exploit likelihood)"   $PY likelihood.py
    step "impact.py       (CVSS impact)"          $PY impact.py
    step "transfer.py     (distribution shift)"   $PY transfer.py
    step "scanner_count.py (scanner ablation)"    $PY scanner_count.py
    step "sensitivity.py  (surrogate vs plan)"    $PY sensitivity.py $GRAPH --findings processed/findings_openvas_b2.csv
    echo "== 5. Figures"
    step "make_figures.py" $PY make_figures.py $GRAPH --findings processed/findings_openvas_b2.csv \
        --goals 'execCode(vmApp, _)' --goals 'execCode(vmWeb, _)' --png
fi

echo
if [ "$FAILED" = 0 ]; then
    echo "All steps succeeded. Check the numbers with:  python3 tests/check_results.py"
else
    echo "Some steps failed; see the log lines above."
fi
exit "$FAILED"
