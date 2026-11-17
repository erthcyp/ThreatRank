#!/usr/bin/env bash
# Step 6: greedy selection by risk removed per unit cost, under a budget.
source "$(dirname "$0")/_common.sh"
title "Step 6  Budget-constrained prioritisation" \
      "Actions are taken greedily by R / cost until the budget runs out. Every baseline uses the same selector; only the ordering differs. KEV is the answer key, never an input."
code "data/prioritise.py:166 (plan)   data/prioritise.py:211 (report)"

live "build the plan and grade it against the baselines"
run $PY prioritise.py "${GRAPH[@]}" --findings processed/findings_openvas_b2.csv -o "$OUT/plan.csv" | sed -n '1,/out of 100%/p'

printf '\n%sthe plan at a 5%% budget (3.4 of 68 cost units):%s\n' "$B" "$N"
$PY - "$OUT/plan.csv" <<'PY'
import csv, sys
rows = list(csv.DictReader(open(sys.argv[1])))
print(f"{'rank':>4s}  {'host':14s} {'port':9s} {'product':22s} {'cost':>4s} {'closes':>6s} {'KEV':>3s}  reaches goal")
for r in rows:
    if float(r["cumulative_cost"]) > 0.05 * 68:
        break
    print(f"{r['rank']:>4s}  {r['host']:14s} {r['port']:9s} {r['product'][:22]:22s} {r['cost']:>4s} "
          f"{r['findings_closed']:>6s} {r['known_exploited']:>3s}  {r['reaches_goal']}")
PY
