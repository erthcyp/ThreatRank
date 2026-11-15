#!/usr/bin/env python3
"""Does the attack graph fail when it ought to?

A graph that derives the goal proves nothing on its own: a derivation that fires no
matter what it is given would also derive it. What can be measured is whether the graph
is *sensitive to the facts it claims to depend on*. Each check below removes or changes
one input, states in advance what the engine must then do, and records whether it did.

These are falsification tests, so a check that passes is a chance to be wrong that was
taken and survived. They measure three things together -- the translator that writes the
facts, the environment description, and the engine's use of both -- and they do not
measure whether any of it matches the world. Nothing here shows that a listed weakness
can actually be exploited; only the laboratory can show that.

The number to report is how many predictions held, out of how many were made.

USAGE

    export MULVALROOT=$HOME/mulval
    export PATH=$MULVALROOT/utils:$HOME/XSB/bin:$PATH
    python3 graph_checks.py --topology topology_lab3.json \
        --input ../mulval/cases/lab3/input.P
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

import consequence as C


def run(case_dir, text, goal):
    """Write an input, derive from it, and report whether the goal comes out."""
    with open(os.path.join(case_dir, "input.P"), "w", encoding="utf-8") as fh:
        fh.write(text)
    for stale in ("VERTICES.CSV", "ARCS.CSV"):
        p = os.path.join(case_dir, stale)
        if os.path.exists(p):
            os.remove(p)
    gen = shutil.which("graph_gen.sh")
    if gen is None:
        sys.exit("graph_gen.sh is not on PATH; see mulval/README.md")
    subprocess.run([gen, "input.P", "-v", "-p"], cwd=case_dir,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    if not os.path.exists(os.path.join(case_dir, "VERTICES.CSV")):
        return False, 0
    vertices, _ = C.read_graph(case_dir)
    return bool(C.goal_vertex(vertices, goal)), len(vertices)


def drop_lines(text, pattern):
    """Every line the pattern matches, removed, with a count of how many went."""
    rx = re.compile(pattern)
    kept = [ln for ln in text.splitlines(keepends=True) if not rx.search(ln)]
    return "".join(kept), len(text.splitlines()) - len(kept)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--topology", required=True, metavar="JSON")
    ap.add_argument("--input", required=True, metavar="FILE")
    ap.add_argument("-o", "--out", metavar="JSON", default="figures/graph_checks.json")
    args = ap.parse_args()

    topology = json.load(open(args.topology, encoding="utf-8"))
    goal = topology["goal"]
    source = open(args.input, encoding="utf-8").read()

    # Each entry: what is done to the input, what the engine must then do, and why that
    # is the right prediction. A check whose prediction is "reached" guards against a
    # graph that collapses whenever anything is touched; one whose prediction is
    # "not reached" guards against a graph that concludes regardless of its facts.
    checks = [
        ("control, nothing changed", None, True,
         "the recorded graph derives the goal, so anything else here would be a broken run"),
        ("attacker position removed", r"^\s*attackerLocated\(", False,
         "with no attacker anywhere, no chain can start"),
        ("attacker's entry edge removed", r"^\s*hacl\(\s*internet\s*,", False,
         "the attacker reaches only the web tier, so removing that edge strands them"),
        ("last hop to the database removed", r"^\s*hacl\(\s*vmApp\s*,\s*vmDb\s*,", False,
         "the goal is on vmDb and the application tier is the only declared way in"),
        ("middle hop removed", r"^\s*hacl\(\s*vmWeb\s*,\s*vmApp\s*,", False,
         "the chain is three tiers and this is the second of them"),
        ("every weakness on the app tier removed", r"^\s*vulExists\(\s*vmApp\s*,", False,
         "the attacker must execute code on vmApp to reach the database from it"),
        ("every weakness on the web tier removed", r"^\s*vulExists\(\s*vmWeb\s*,", False,
         "the attacker's only entry is the web tier, so nothing follows without it"),
        ("every weakness on the database removed", r"^\s*vulExists\(\s*vmDb\s*,", False,
         "the goal is code execution on the database itself"),
        ("service descriptions removed", r"^\s*networkServiceInfo\(", False,
         "a remote exploit rule needs the service it runs against"),
        ("unrelated hop removed", r"^\s*hacl\(H, H,", True,
         "the self-reachability line is not on the path, so removing it must change nothing"),
    ]

    work = tempfile.mkdtemp(prefix="graph_checks_")
    results, held = [], 0
    try:
        for name, pattern, expect, why in checks:
            if pattern is None:
                text, removed = source, 0
            else:
                text, removed = drop_lines(source, pattern)
                if removed == 0:
                    print(f"  SKIP  {name}: the pattern matched no line")
                    continue
            reached, size = run(work, text, goal)
            ok = reached == expect
            held += ok
            results.append({"check": name, "lines_removed": removed,
                            "expected_goal": expect, "goal_reached": reached,
                            "vertices": size, "held": ok, "because": why})
            got = "reached" if reached else "not reached"
            want = "reached" if expect else "not reached"
            print(f"  {'PASS' if ok else 'FAIL'}  {name}")
            print(f"        -{removed} lines, predicted {want}, got {got}"
                  f"{f', {size} vertices' if size else ''}")
    finally:
        shutil.rmtree(work, ignore_errors=True)

    total = len(results)
    print(f"\n  {held} of {total} predictions held")
    if held < total:
        print("  A failed prediction means the graph is not sensitive to a fact it is "
              "documented as depending on. Do not report the graph's other numbers "
              "until it is understood.")

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump({"goal": goal, "held": held, "total": total,
                   "checks": results}, fh, indent=1)
    print(f"  wrote {args.out}")


if __name__ == "__main__":
    main()
