#!/usr/bin/env bash
# Run every step in order, pausing between them (press Enter to continue).
cd "$(dirname "$0")"
for s in [0-7]_*.sh; do
    ./"$s"
    [ "${1:-}" = "--no-pause" ] || read -rp $'\n-- press Enter for the next step --'
done
