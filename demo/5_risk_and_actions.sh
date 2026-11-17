#!/usr/bin/env bash
# Step 5: R = L x C, grouped into remediation actions.
source "$(dirname "$0")/_common.sh"
title "Step 5  Risk and remediation actions" \
      "R = L x C per finding. Findings one upgrade would close are grouped into a single action; its cost is its tier (patch 1, configuration 2, replacement 5)."
code "data/prioritise.py:302 (R = L x C)   data/prioritise.py:136 (build_actions)   data/prioritise.py:85 (tier)"

live "compute R and group into actions"
$PY "$ROOT/demo/show.py" risk
