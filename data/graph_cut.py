#!/usr/bin/env python3
"""Does a remediation plan actually disconnect the attacker from the goal?

Every other number in this project grades an ordering by how much of something it
removes -- exposure, known-exploited findings, wasted budget. None of them answers the
question a defender actually asks, which is whether the attacker can still get in after
the work is done. That question has a yes or no answer and it is decidable, because the
attack graph is a derivation: remove the facts a plan remediates, run the engine again,
and see whether the goal is still derived.

WHAT THIS MEASURES, AND WHAT IT DOES NOT

It measures whether a plan is a cut set of the derivation. It does not measure whether
the derivation matches the world; MulVAL guarantees only that its conclusions follow
from its facts, and the facts come from a scanner and from a topology we declared. So a
plan that cuts the graph has been shown to cut *the model*. What makes the comparison
fair rather than circular is that the same referee grades every ordering, and none of
the orderings can see it: no selector here has any notion of a cut set, and the graph is
not consulted when the plan is built beyond the reachability indicator that every
ordering except ours ignores entirely.

The number to report is the cheapest budget at which each ordering first disconnects the
goal. A defender reading the table learns what fraction of full remediation buys the
property they care about, rather than a percentage of a score this project invented.

USAGE

    export MULVALROOT=$HOME/mulval
    export PATH=$MULVALROOT/utils:$HOME/XSB/bin:$PATH
    python3 graph_cut.py --graph ../mulval/cases/lab3/out \
        --topology topology_lab3.json \
        --input ../mulval/cases/lab3/input.P \
        --findings processed/findings_openvas_b2.csv
"""

import argparse
import csv
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

import consequence as C
import prioritise as P

BUDGETS = (0.01, 0.02, 0.03, 0.05, 0.10, 0.25, 0.50, 1.00)


def remediated_keys(actions):
    """The (host atom, vulnerability id) pairs a set of actions closes."""
    return {(r["atom"], r["vuln_id"]) for a in actions for r in a["members"]}


def filtered_input(source, drop):
    """The MulVAL input with the vulExists fact of every remediated finding removed.

    Only vulExists is dropped, never vulProperty. vulProperty is keyed on the
    vulnerability id alone, so the same line serves every host carrying that finding;
    removing it because one host was patched would silently patch the others too. A
    vulProperty with no surviving vulExists cannot fire any rule, so leaving it is inert.
    """
    kept, removed = [], 0
    for line in source.splitlines(keepends=True):
        m = re.match(r"\s*vulExists\(\s*([A-Za-z0-9_']+)\s*,\s*'([^']+)'", line)
        if m and (m.group(1), m.group(2)) in drop:
            removed += 1
            continue
        kept.append(line)
    return "".join(kept), removed


def goal_reached(case_dir, goal):
    """Run the engine on a prepared case and report whether the goal is still derived."""
    gen = shutil.which("graph_gen.sh")
    if gen is None:
        sys.exit("graph_gen.sh is not on PATH; see mulval/README.md")
    subprocess.run([gen, "input.P", "-v", "-p"], cwd=case_dir,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    vertices_path = os.path.join(case_dir, "VERTICES.CSV")
    if not os.path.exists(vertices_path):
        # The engine writes nothing when it derives nothing. That is the answer, not an
        # error -- but it is also what a missing XSB looks like, which is why the caller
        # checks the unremediated case first.
        return False, 0
    vertices, _ = C.read_graph(case_dir)
    return bool(C.goal_vertex(vertices, goal)), len(vertices)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--graph", required=True, metavar="DIR")
    ap.add_argument("--topology", required=True, metavar="JSON")
    ap.add_argument("--input", required=True, metavar="FILE",
                    help="the input.P the recorded graph was derived from")
    ap.add_argument("--findings", required=True, action="append", metavar="CSV")
    ap.add_argument("--weights", default="1,2,5", metavar="P,C,R")
    ap.add_argument("--budgets", metavar="LIST",
                    help="comma-separated fractions of total cost, in place of the "
                         "default grid. A fine grid locates the budget at which an "
                         "ordering first cuts the graph; the coarse default only says "
                         "which decade it falls in.")
    ap.add_argument("-o", "--out", metavar="JSON", default="figures/graph_cut.json")
    args = ap.parse_args()

    budgets = (tuple(float(x) for x in args.budgets.split(","))
               if args.budgets else BUDGETS)
    patch, config, replace = (float(x) for x in args.weights.split(","))
    cost = {P.PATCH: patch, P.CONFIG: config, P.REPLACE: replace}

    kept, actions, topology = P.score(args.graph, args.topology, args.findings)
    goal = topology["goal"]
    total = sum(cost[a["tier"]] for a in actions)
    source = open(args.input, encoding="utf-8").read()

    print(f"  {len(kept)} findings, {len(actions)} actions, {total:g} cost units")
    print(f"  goal: {goal}")

    work = tempfile.mkdtemp(prefix="graph_cut_")
    try:
        # Control. If the goal is not derived with nothing remediated, the run is broken
        # rather than informative, and every later "disconnected" would be that fault.
        shutil.copy(args.input, os.path.join(work, "input.P"))
        reached, size = goal_reached(work, goal)
        if not reached:
            sys.exit("the goal is not derived even before remediation; check XSB is on "
                     "PATH and that --input matches --graph")
        print(f"  control: goal reached, {size} vertices\n")

        results = {}
        selectors = P.orderings(actions, cost)
        for name, select in selectors.items():
            row = {}
            for frac in budgets:
                chosen = select(frac * total)
                drop = remediated_keys(chosen)
                text, removed = filtered_input(source, drop)
                with open(os.path.join(work, "input.P"), "w", encoding="utf-8") as fh:
                    fh.write(text)
                for stale in ("VERTICES.CSV", "ARCS.CSV"):
                    p = os.path.join(work, stale)
                    if os.path.exists(p):
                        os.remove(p)
                reached, size = goal_reached(work, goal)
                row[frac] = {"goal_reached": reached, "vertices": size,
                             "facts_removed": removed, "actions": len(chosen)}
                print(f"  {name:14s} {frac:5.0%}  {len(chosen):3d} actions, "
                      f"{removed:3d} facts removed -> "
                      f"{'goal still reached' if reached else 'GOAL DISCONNECTED'}")
            results[name] = row
            print()
    finally:
        shutil.rmtree(work, ignore_errors=True)

    print("  cheapest budget that disconnects the goal")
    print("  " + "-" * 46)
    summary = {}
    for name, row in results.items():
        cut = [f for f in budgets if not row[f]["goal_reached"]]
        summary[name] = min(cut) if cut else None
        shown = f"{min(cut):.0%}" if cut else "never, even at full remediation"
        print(f"  {name:14s} {shown}")

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump({"goal": goal, "total_cost": total, "actions": len(actions),
                   "findings": len(kept),
                   "cheapest_cut": {k: v for k, v in summary.items()},
                   "detail": {k: {str(f): d for f, d in r.items()}
                              for k, r in results.items()}}, fh, indent=1)
    print(f"\n  wrote {args.out}")


if __name__ == "__main__":
    main()
