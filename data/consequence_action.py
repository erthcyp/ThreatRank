#!/usr/bin/env python3
"""Attack consequence measured by what a fix removes, not by how close a finding sits.

`consequence.py` scores a finding by its derivation distance to the goal, C = 1/d. Measured
on the three-tier lab that measure takes one value per host: every finding on the web tier
is ten steps from the goal, every finding on the database tier is two, and nothing
distinguishes findings on the same machine. Multiplying likelihood by a per-host constant
sorts hosts, so the ranking it produced was worse than using likelihood alone.

The defect is not the multiplication. It is that distance answers the wrong question.

WHAT THIS MEASURES INSTEAD

    if this were fixed, what would the attacker lose?

For each remediation action, its facts are removed from the graph and the derivation is
recomputed. Two numbers come out:

    cuts_goal    the goal is no longer derivable at all. The action is a chokepoint.
    removed      the share of everything the attacker could derive that is now out of
                 reach, from 0 to 1

That is the question a remediation plan exists to answer, and unlike distance it is a
property of the fix rather than of the machine the fix happens to be on.

WHY THE UNIT IS AN ACTION AND NOT A FINDING

Removing one Apache CVE from the web tier changes nothing, because 125 other Apache CVEs
derive the same code execution. Scored per finding, every one of them looks worthless, and
their total looks worthless too, which is plainly false: upgrading Apache closes all 126 at
once. The counterfactual is only meaningful on the unit that is actually acted on, which is
why `fix_actions.py` exists and why its grouping is reused here.

HOW THE RECOMPUTATION WORKS

MulVAL's output is an AND/OR derivation graph: a LEAF is a primitive fact, an AND node is a
rule that fires only when every input holds, an OR node is a fact derivable if any incoming
rule fires. Removing a set of leaves and taking the least fixed point gives exactly the set
of facts that survive. No re-run of MulVAL is needed, because the graph already contains
every derivation it found.

    python3 consequence_action.py --graph ~/mulval/testcases/lab3 \\
                                  --topology topology_lab3.json \\
                                  --findings processed/findings_openvas_b2.csv
"""

import argparse
import collections
import csv
import json
import os
import sys

import consequence as C
from fix_actions import product_of


def derivable(vertices, incoming, removed):
    """Least fixed point: every fact and rule that still holds once `removed` is gone.

    LEAF holds unless removed. AND holds when all its inputs hold. OR holds when any one
    of its inputs holds. Iterating to a fixed point rather than walking the graph once
    matters because a fact can be reached by several rules of different depths.
    """
    holds = {v for v, (_, kind) in vertices.items()
             if kind == "LEAF" and v not in removed}
    changed = True
    while changed:
        changed = False
        for v, (_, kind) in vertices.items():
            if v in holds or kind == "LEAF":
                continue
            inputs = incoming.get(v, ())
            if not inputs:
                continue
            ok = all(i in holds for i in inputs) if kind == "AND" \
                else any(i in holds for i in inputs)
            if ok:
                holds.add(v)
                changed = True
    return holds


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--graph", required=True, metavar="DIR")
    ap.add_argument("--topology", required=True, metavar="JSON")
    ap.add_argument("--findings", required=True, action="append", metavar="CSV")
    ap.add_argument("-o", "--out", metavar="CSV", help="write C per finding here")
    args = ap.parse_args()

    topology = json.load(open(args.topology, encoding="utf-8"))
    vertices, edges = C.read_graph(args.graph)
    goals = set(C.goal_vertex(vertices, topology["goal"]))
    leaves = C.finding_leaves(vertices)
    rows = C.load_findings(args.findings, topology)

    incoming = collections.defaultdict(set)
    for src, dsts in edges.items():
        for dst in dsts:
            incoming[dst].add(src)

    base = derivable(vertices, incoming, set())
    derived_total = {v for v in base if vertices[v][1] == "OR"}
    if not goals & base:
        sys.exit("the goal is not derivable even with every fact present; check the graph")

    # One action is one (host, port, product). The remediation text that fix_actions.py
    # also keys on lives in the raw reports, which this repository does not carry, so the
    # grouping here is the coarser one: upgrade this product on this host.
    actions = collections.defaultdict(list)
    for r in rows:
        actions[(r["host"], r.get("port", ""), product_of(r["nvt_name"]))].append(r)

    print(f"graph             : {len(vertices)} vertices, {len(derived_total)} derived facts")
    print(f"goal              : {topology['goal']}")
    print(f"findings          : {len(rows)} grouped into {len(actions)} fix actions\n")

    results = []
    for key, members in actions.items():
        removed = {leaves[(m["atom"], m["vuln_id"])] for m in members
                   if (m["atom"], m["vuln_id"]) in leaves}
        if not removed:
            results.append((key, members, False, 0.0))
            continue
        surviving = derivable(vertices, incoming, removed)
        cuts = not (goals & surviving)
        lost = len(derived_total - surviving) / max(1, len(derived_total))
        results.append((key, members, cuts, lost))

    results.sort(key=lambda t: (-t[2], -t[3]))
    cutting = [r for r in results if r[2]]

    print(f"  actions that cut the goal entirely: {len(cutting)} of {len(actions)}")
    print(f"  {'host':16s} {'port':10s} {'product':26s} {'cuts':>5} {'removed':>8} {'findings':>9}")
    print("  " + "-" * 80)
    for key, members, cuts, lost in results[:15]:
        host, port, product = key
        print(f"  {host:16s} {port:10s} {product[:24]:26s} {'yes' if cuts else 'no':>5} "
              f"{lost:8.3f} {len(members):9d}")
    if len(results) > 15:
        print(f"  ... {len(results)-15} more")

    spread = {round(lost, 3) for _, _, _, lost in results}
    print(f"\n  distinct values of removed: {len(spread)} across {len(actions)} actions")
    if len(spread) <= len(topology["hosts"]):
        print("  WARNING: no more distinct values than there are hosts. This measure is")
        print("  separating machines rather than fixes, which is the fault it replaced.")

    if args.out:
        per_finding = {}
        for key, members, cuts, lost in results:
            for m in members:
                per_finding[id(m)] = (key, cuts, lost)
        with open(args.out, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["host", "nvt_name", "action_product", "cuts_goal",
                        "removed_share", "consequence"])
            for r in rows:
                key, cuts, lost = per_finding[id(r)]
                w.writerow([r["host"], r["nvt_name"], key[2], int(cuts),
                            f"{lost:.6f}", f"{lost:.6f}"])
        print(f"\nwrote {args.out}")


if __name__ == "__main__":
    main()
