#!/usr/bin/env bash
# Step 0: each scanner's raw report -> one unified CSV schema.
source "$(dirname "$0")/_common.sh"
title "Step 0  Parse and normalise" \
      "One parser per scanner turns its raw report (XML / JSON) into the same CSV columns."
code "data/parse_openvas.py:143 (parse_report)   data/fetch_nessus.py:101 (build_rows)   data/parse_qualys.py:75 (parse)"

live "parse the raw OpenVAS XML and check it reproduces the committed CSV byte for byte"
run $PY parse_openvas.py raw/openvas/2026-09-08_openvas_B_group-b-old-images.xml --offline -o "$OUT/openvas.csv" | tail -3
cmp -s "$OUT/openvas.csv" processed/findings_openvas_b2.csv && echo "${G}identical to data/processed/findings_openvas_b2.csv${N}"

live "parse the raw Nessus JSON the same way"
run $PY fetch_nessus.py --from-raw raw/nessus/2026-09-29_nessus_B_group-b-nessus.json --group B --offline -o "$OUT/nessus.csv" | tail -2
cmp -s "$OUT/nessus.csv" processed/findings_nessus_b2.csv && echo "${G}identical to data/processed/findings_nessus_b2.csv${N}"

printf '\n%sthe unified schema (OpenVAS, group B):%s\n' "$B" "$N"
$PY "$ROOT/demo/show.py" parse "$OUT/openvas.csv"
