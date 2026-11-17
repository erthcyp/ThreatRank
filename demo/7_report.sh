#!/usr/bin/env bash
# Step 7: the output an analyst reads.
source "$(dirname "$0")/_common.sh"
title "Step 7  Report" \
      "The plan becomes an HTML report with an adjustable budget, and the attack graph an interactive page (zoom, pick the goal, see what the budget cuts)."
code "data/render_plan.py:105   data/render_graph.py:69"

[ -f "$OUT/plan.csv" ] || $PY prioritise.py "${GRAPH[@]}" --findings processed/findings_openvas_b2.csv -o "$OUT/plan.csv" > /dev/null
live "render both pages"
run $PY render_plan.py "$OUT/plan.csv" --budget 0.05 -o "$OUT/plan_report.html"
run $PY render_graph.py "${GRAPH[@]}" --findings processed/findings_openvas_b2.csv --plan "$OUT/plan.csv" -o "$OUT/attack_graph.html"

echo
for page in plan_report attack_graph; do
    echo "open: $OUT/$page.html"
    if command -v xdg-open >/dev/null && [ -n "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ]; then
        xdg-open "$OUT/$page.html" >/dev/null 2>&1 &
    fi
done
