#!/usr/bin/env python3
"""Render a readable slice of the real MulVAL attack graph, with its actual nodes.

The full graph is 357 vertices and is an unreadable hairball drawn in full, which is why
the paper's other view condenses it to conclusions. This draws the opposite: the real
backbone -- the shortest derivation from the attacker to the goal -- with every node it
passes through kept as it is in the graph, plus the leaf facts each rule on that backbone
consumes. Nothing is invented; every node and edge is taken from VERTICES.CSV and
ARCS.CSV, and the labels are MulVAL's own.

Node kinds carry their shape: a LEAF fact is a box, an AND rule an ellipse, an OR
conclusion a rounded box. The goal is filled.

    python3 real_graph.py --graph ../mulval/cases/lab3/out \
        --goal 1 -o figures/fig_real_graph
"""

import argparse
import collections
import csv
import os
import re
import subprocess
import sys


def load(graph):
    V = {}
    for r in csv.reader(open(os.path.join(graph, "VERTICES.CSV"))):
        V[r[0].strip()] = (r[1].strip().strip('"'), r[2].strip().strip('"'))
    out = collections.defaultdict(list)
    for r in csv.reader(open(os.path.join(graph, "ARCS.CSV"))):
        out[r[0].strip()].append(r[1].strip())  # conclusion -> premise
    return V, out


def backbone(V, out, goal):
    """Shortest derivation path from the goal down to the attacker's position."""
    start = next(v for v, (t, _) in V.items() if t.startswith("attackerLocated"))
    q = collections.deque([[goal]])
    seen = {goal}
    while q:
        path = q.popleft()
        if path[-1] == start:
            return path
        for n in out[path[-1]]:
            if n not in seen:
                seen.add(n)
                q.append(path + [n])
    sys.exit("no path from goal to the attacker; is --goal a real OR vertex?")


def short(txt):
    """MulVAL's label, trimmed to what reads in a box."""
    txt = txt.replace("'", "")
    if txt.startswith("RULE"):
        # "RULE 2 (remote exploit of a server program)" -> two lines
        num, _, desc = txt.partition(" (")
        return num + "\\n" + desc.rstrip(")")
    # predicate(args) -> predicate over its args
    head, _, rest = txt.partition("(")
    return head + "\\n" + rest.rstrip(")")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--graph", required=True)
    ap.add_argument("--goal", default="1", help="OR vertex id of the goal")
    ap.add_argument("-o", "--out", default="figures/fig_real_graph")
    args = ap.parse_args()

    V, out = load(args.graph)
    spine = backbone(V, out, args.goal)
    keep = set(spine)
    # each rule on the backbone also draws in its leaf facts; keep those, so a rule is
    # shown firing from real findings rather than floating.
    for n in spine:
        if V[n][1] == "AND":
            for p in out[n]:
                if V[p][1] == "LEAF":
                    keep.add(p)

    # edges among kept nodes, drawn premise -> conclusion so arrows point at the goal
    edges = []
    for c in keep:
        for p in out[c]:
            if p in keep:
                edges.append((p, c))

    # number the kept nodes 1..N by their MulVAL id, the way the native output does,
    # so the nodes carry only a number and a legend maps each number to its fact.
    num = {v: i + 1 for i, v in enumerate(sorted(keep, key=int))}

    # MulVAL's own shapes: OR conclusion a diamond, AND rule an ellipse, LEAF fact a box.
    shape = {"OR": "diamond", "AND": "ellipse", "LEAF": "box"}
    lines = ['digraph G {', '  rankdir=LR;', '  ranksep=0.32;', '  nodesep=0.16;',
             '  node [fontname="Times", fontsize=11, width=0.32, height=0.32, '
             'fixedsize=false];',
             '  edge [color="#8a8f9a", arrowsize=0.6];', '  bgcolor="white";']
    for v in keep:
        kind = V[v][1]
        fill = "#eef3fb" if kind == "OR" else ("white" if kind == "AND" else "#f3f4f6")
        col = "#1d5fa8" if kind in ("OR", "AND") else "#9aa0a8"
        if v == args.goal:
            fill, col = "#fdece6", "#d24a1f"
        lines.append(f'  n{v} [label="{num[v]}", shape={shape[kind]}, '
                     f'style=filled, fillcolor="{fill}", color="{col}"];')
    for p, c in edges:
        lines.append(f'  n{p} -> n{c};')
    lines.append("}")
    dot = "\n".join(lines)

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    open(args.out + ".dot", "w").write(dot)
    for ext in ("pdf", "png"):
        r = subprocess.run(["dot", f"-T{ext}", args.out + ".dot", "-o", f"{args.out}.{ext}"],
                           capture_output=True, text=True)
        if r.returncode != 0:
            sys.exit(f"dot failed: {r.stderr}")

    # legend: number -> fact, as a LaTeX tabular the figure places beside the graph.
    def tex_escape(t):
        t = t.replace("'", "")
        # the range/loss pair is the same on every vulExists and is explained in the
        # data-model figure, so drop it from the legend rather than overflow the column.
        t = re.sub(r",(remoteExploit|remoteClient|localExploit),\w+\)", ")", t)
        return t.replace("_", "\\_").replace("&", "\\&")
    items = sorted(keep, key=lambda x: num[x])
    leg = ["% generated by real_graph.py", "\\scriptsize",
           "\\textbf{$\\Diamond$ conclusion \\quad $\\bigcirc$ rule \\quad $\\Box$ fact}",
           "\\vspace{2pt}\\\\", "\\begin{tabular}{rl}"]
    for v in items:
        leg.append(f"{num[v]} & \\texttt{{{tex_escape(V[v][0])}}} \\\\")
    leg.append("\\end{tabular}")
    open(args.out + "_legend.tex", "w").write("\n".join(leg))
    print(f"  wrote {args.out}.pdf/.png and _legend.tex  ({len(keep)} nodes, {len(edges)} edges)")


if __name__ == "__main__":
    main()
