# Shared by the numbered demo steps. Source it; do not run it.
set -euo pipefail
DEMO="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$DEMO")"
PY="${PYTHON:-python3}"
OUT="$DEMO/out"            # live outputs go here (gitignored); committed files are never touched
mkdir -p "$OUT"
cd "$ROOT/data"
GRAPH=(--graph ../mulval/cases/lab3/out --topology topology_lab3.json)

B=$'\e[1m'; D=$'\e[2m'; C=$'\e[36m'; Y=$'\e[33m'; G=$'\e[32m'; N=$'\e[0m'

title() { printf '\n%s%s%s\n' "$B$C" "== $1" "$N"; printf '%s\n\n' "$D$2$N"; }
code()  { printf '%scode:%s %s\n' "$D" "$N" "$*"; }
run()   { printf '\n%s$ %s%s\n' "$Y" "$*" "$N"; "$@"; }
live()  { printf '\n%s[LIVE]%s %s\n' "$G" "$N" "$1"; }
