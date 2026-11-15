#!/usr/bin/env python3
"""Compare the results a run produced with the recorded ones.

Run after ./reproduce.sh. Every number the scripts write to data/figures/ (JSON results and
LaTeX tables) and the remediation plan in data/processed/plan_merged.csv is compared with the
copy recorded in tests/expected/. Numbers may differ by at most TOLERANCE; any other text must
match exactly. Figures (PDF/PNG) are not compared, since their bytes depend on fonts and
timestamps.

    python3 tests/check_results.py            compare
    python3 tests/check_results.py --quick    only what `./reproduce.sh quick` regenerates

Exit status 0 means every compared result matches.
"""

import argparse
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXPECTED = os.path.join(ROOT, "tests", "expected")
TOLERANCE = 0.005

QUICK = ["figures/tab_corpus.tex", "figures/tab_graphrank.tex",
         "figures/tab_robustness.tex", "processed/plan_merged.csv"]
FULL = QUICK + ["figures/impact.json", "figures/transfer.json",
                "figures/sensitivity.json", "figures/tables.md"]
NUMBER = re.compile(r"-?\d+\.\d+|-?\d+")


def flatten(value, path=""):
    if isinstance(value, dict):
        for k, v in value.items():
            yield from flatten(v, f"{path}.{k}")
    elif isinstance(value, list):
        for i, v in enumerate(value):
            yield from flatten(v, f"{path}[{i}]")
    else:
        yield path, value


def compare_json(got, want):
    a, b = dict(flatten(got)), dict(flatten(want))
    problems = [f"missing {k}" for k in b if k not in a]
    problems += [f"unexpected {k}" for k in a if k not in b]
    for k in set(a) & set(b):
        x, y = a[k], b[k]
        if isinstance(x, (int, float)) and isinstance(y, (int, float)):
            if abs(x - y) > TOLERANCE:
                problems.append(f"{k}: got {x}, expected {y}")
        elif x != y:
            problems.append(f"{k}: got {x!r}, expected {y!r}")
    return problems


def compare_text(got, want):
    problems = []
    gl, wl = got.splitlines(), want.splitlines()
    if len(gl) != len(wl):
        return [f"{len(gl)} lines, expected {len(wl)}"]
    for n, (g, w) in enumerate(zip(gl, wl), 1):
        if NUMBER.sub("#", g) != NUMBER.sub("#", w):
            problems.append(f"line {n}: got {g.strip()!r}, expected {w.strip()!r}")
            continue
        for x, y in zip(NUMBER.findall(g), NUMBER.findall(w)):
            if abs(float(x) - float(y)) > TOLERANCE:
                problems.append(f"line {n}: got {x}, expected {y}")
                break
    return problems


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--quick", action="store_true")
    args = ap.parse_args()

    failed = 0
    for rel in (QUICK if args.quick else FULL):
        got_path = os.path.join(ROOT, "data", rel)
        want_path = os.path.join(EXPECTED, rel)
        if not os.path.exists(got_path):
            print(f"FAIL  {rel}: not produced")
            failed += 1
            continue
        got = open(got_path, encoding="utf-8").read()
        want = open(want_path, encoding="utf-8").read()
        problems = (compare_json(json.loads(got), json.loads(want)) if rel.endswith(".json")
                    else compare_text(got, want))
        if problems:
            failed += 1
            print(f"FAIL  {rel}")
            for p in problems[:10]:
                print(f"        {p}")
        else:
            print(f"ok    {rel}")

    print()
    if failed:
        print(f"{failed} result file(s) differ from the recorded run.")
        sys.exit(1)
    print("Every compared result matches the recorded run.")


if __name__ == "__main__":
    main()
