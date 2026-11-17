#!/usr/bin/env bash
# Step 4: consequence C from the attack graph.
source "$(dirname "$0")/_common.sh"
title "Step 4  Attack graph and consequence (C)" \
      "MulVAL derives every way an attacker can chain the findings to the goal. C = 1 if a finding lies on such a path, else 0."
code "data/consequence.py:69 (read_graph)   data/consequence.py:119 (distances_to)   data/prioritise.py:298-299 (C)"

$PY "$ROOT/demo/show.py" graph
