#!/usr/bin/env bash
# Step 3: what a finding grants an attacker (CVSS C / I / A), the input to the attack graph.
source "$(dirname "$0")/_common.sh"
title "Step 3  Impact classification" \
      "The published NVD vector is used when it exists; otherwise a gradient-boosting classifier estimates confidentiality, integrity and availability impact."
code "data/impact.py:106 (model)   data/findings_to_mulval.py:156 (cvss_properties)   mulval/cases/lab3/input.P"

$PY "$ROOT/demo/show.py" impact
