#!/usr/bin/env bash
# Step 2: exploit likelihood L for every finding.
source "$(dirname "$0")/_common.sh"
title "Step 2  Exploit likelihood (L)" \
      "A finding with a CVE takes its EPSS score; one without a CVE gets an estimate from a gradient-boosting surrogate trained on report features."
code "data/likelihood.py:123 (target_for)   data/likelihood.py:178 (featurise)   data/prioritise.py:282-301 (where L is assigned)"

live "score the 229 findings on the three attack-graph hosts"
$PY "$ROOT/demo/show.py" likelihood
