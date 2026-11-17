#!/usr/bin/env bash
# Step 1: merge findings from different scanners that describe the same problem.
source "$(dirname "$0")/_common.sh"
title "Step 1  Correlate across scanners" \
      "Findings are keyed by host, port and NVD's affected product, so OpenVAS and Nessus findings on the same product become one job."
code "data/correlate.py:68 (product_key)   data/correlate.py:135 (merge)"

live "correlate OpenVAS and Nessus findings for group B"
run $PY correlate.py --findings processed/findings_openvas_b2.csv --findings processed/findings_nessus_b2.csv -o "$OUT/canon.csv"
