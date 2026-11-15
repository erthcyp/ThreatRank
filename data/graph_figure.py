#!/usr/bin/env python3
"""The attack graph as something a person can read.

MulVAL's output for this lab is 357 vertices and 676 arcs. Drawn as it stands it is an
unreadable mat of lines, which is why attack-graph papers so often show a toy example instead
of the graph they actually analysed. The structure that carries the meaning is much smaller:

    190  LEAF   input facts -- the findings, and the topology they were placed in
    188  AND    applications of a rule
      9  OR     the conclusions the graph reaches

Only the nine conclusions matter to a reader, and the rules between them are plumbing. This
condenses `OR -> AND -> OR` into `OR -> OR`, keeps the count of input facts feeding each
step, and lays the result out by distance from the attacker's goal. Nine nodes, read in a
few seconds, with every number taken from the graph rather than drawn by hand.

WHAT THE PICTURE IS FOR

It answers two questions an examiner asks before any score is discussed. What did the attacker
have to chain together to get to the thing being defended, and how much of the scan actually
took part? The second is the one that matters to this project: 190 input facts feed nine
conclusions, and the findings that feed none of them are the work the consequence term
excludes.

    python3 graph_figure.py --graph ~/mulval/testcases/lab3 --goal 'execCode(vmDb, _)'
"""

import argparse
import collections
import os
import re
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch

import consequence as C
import make_figures as F

HERE = os.path.dirname(os.path.abspath(__file__))


def condense(vertices, edges, goals):
    """Derived facts only, with the rules between them collapsed into direct edges."""
    derived = {v for v, (_, kind) in vertices.items() if kind == "OR"}
    leaves = {v for v, (_, kind) in vertices.items() if kind == "LEAF"}

    # edges maps source -> {destinations}; a source feeds its destinations.
    direct = collections.defaultdict(set)
    support = collections.defaultdict(set)
    for src, dests in edges.items():
        for dst in dests:
            if src in derived and dst in derived:
                direct[src].add(dst)
                continue
            if vertices.get(dst, ("", ""))[1] != "AND":
                continue
            for onward in edges.get(dst, ()):
                if onward in derived:
                    if src in derived:
                        direct[src].add(onward)
                    elif src in leaves:
                        # Distinct findings, not leaf-to-rule incidences. Each finding
                        # contributes two facts, vulExists and vulProperty, into the same
                        # rule, so counting incidences reported twice the real number and
                        # gave a figure whose totals could exceed the whole graph's.
                        if vertices[src][0].startswith("vulExists"):
                            support[onward].add(vertices[src][0])
    return derived, direct, support


def layers(derived, direct, goals):
    """Distance from each conclusion to the goal, following edges forwards."""
    depth = {g: 0 for g in goals if g in derived}
    frontier = list(depth)
    back = collections.defaultdict(set)
    for src, dests in direct.items():
        for d in dests:
            back[d].add(src)
    while frontier:
        nxt = []
        for v in frontier:
            for p in back.get(v, ()):
                if p not in depth:
                    depth[p] = depth[v] + 1
                    nxt.append(p)
        frontier = nxt
    for v in derived:
        depth.setdefault(v, max(depth.values(), default=0) + 1)
    return depth


def shorten(fact):
    """`execCode(vmDb,root)` stays; a long rule name is trimmed to fit a box."""
    fact = re.sub(r"\s+", " ", fact).strip()
    return fact if len(fact) <= 34 else fact[:31] + "..."


def draw(vertices, derived, direct, support, goals):
    """The condensed graph as a figure. Separated from main so make_figures.py can
    place it beside the other stages' figures without shelling out to this script.
    """
    F.style()
    depth = layers(derived, direct, goals)
    by_depth = collections.defaultdict(list)
    for v in derived:
        by_depth[depth[v]].append(v)
    width = max(len(g) for g in by_depth.values())
    height = len(by_depth)
    # Boxes nearly fill the column pitch of 1.0. A narrower box clipped the longest fact,
    # `execCode(vmWeb,'www-data')`, which at this type size needs most of the column.
    fig, ax = plt.subplots(figsize=(7.0, 0.8 + 0.75 * height))
    pos, BW, BH = {}, 0.86, 0.34

    # Deepest layer at the top: the attacker starts far from the goal and works down.
    for d in sorted(by_depth, reverse=True):
        row = sorted(by_depth[d], key=lambda v: -len(support[v]))
        for i, v in enumerate(row):
            pos[v] = ((i + 0.5) / len(row) * width, d)

    for src, dests in direct.items():
        for dst in dests:
            if src not in pos or dst not in pos:
                continue
            (x0, y0), (x1, y1) = pos[src], pos[dst]
            if y0 == y1:
                # Side to side, and curved, so the arrowhead is visible outside the boxes.
                side = BW / 2 if x1 > x0 else -BW / 2
                a, b = (x0 + side, y0), (x1 - side, y1)
                style = "arc3,rad=-0.25"
            else:
                a, b = (x0, y0 - BH / 2), (x1, y1 + BH / 2)
                style = "arc3,rad=0"
            ax.add_patch(FancyArrowPatch(
                a, b, connectionstyle=style,
                arrowstyle="-|>", mutation_scale=9, linewidth=0.8,
                color="#8a8f9a", shrinkA=1, shrinkB=1, zorder=1))

    for v, (x, y) in pos.items():
        goal = v in goals
        n = len(support[v])
        # Two kinds of step, and the difference is the whole point of the figure: a
        # reachability step is asserted by the operator and no scan can remove it, while a
        # code-execution step rests on findings and every one of them is remediable. Drawn
        # differently so a reader can see which parts of the chain remediation can reach.
        declared = n == 0 and not goal
        face = "#fdece6" if goal else ("#f4f5f7" if declared else "#eef3fb")
        edge = (F.COLOUR["EPSS"] if goal
                else ("#9aa0ac" if declared else F.COLOUR["R = L x C"]))
        ax.add_patch(FancyBboxPatch((x - BW / 2, y - BH / 2), BW, BH,
                                    boxstyle="round,pad=0.015,rounding_size=0.03",
                                    facecolor=face, edgecolor=edge,
                                    linewidth=1.4 if goal else 0.9,
                                    linestyle="--" if declared else "-", zorder=2))
        ax.text(x, y + 0.055, shorten(vertices[v][0]), ha="center", va="center",
                fontsize=6.8, zorder=3)
        if goal:
            note = "the goal"
        elif declared:
            note = "declared, not scanned"
        else:
            note = f"{n} finding" + ("s" if n != 1 else "")
        ax.text(x, y - 0.075, note, ha="center", va="center", fontsize=6.0,
                color="#333333", zorder=3)

    ax.set_xlim(-0.42, width + 0.12)
    ax.set_ylim(-0.42, max(by_depth) + 0.42)
    ax.axis("off")
    ax.text(-0.3, max(by_depth), "further from\nthe goal", fontsize=6.2,
            color="#555555", ha="left", va="center")
    ax.text(-0.3, 0, "the goal", fontsize=6.2, color="#555555",
            ha="left", va="center")
    return fig


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--graph", required=True, metavar="DIR")
    ap.add_argument("--goal", required=True, metavar="FACT")
    ap.add_argument("-o", "--out", metavar="PDF",
                    default=os.path.join(HERE, "figures", "fig10_attack_graph.pdf"))
    args = ap.parse_args()

    vertices, edges = C.read_graph(args.graph)
    goals = set(C.goal_vertex(vertices, args.goal))
    if not goals:
        sys.exit(f"no vertex matches {args.goal!r}; nothing to draw.")
    derived, direct, support = condense(vertices, edges, goals)
    depth = layers(derived, direct, goals)

    kinds = collections.Counter(k for _, k in vertices.values())
    print(f"graph             : {len(vertices)} vertices, "
          f"{sum(len(d) for d in edges.values())} arcs")
    print(f"  {kinds.get('LEAF', 0)} input facts, {kinds.get('AND', 0)} rule applications, "
          f"{kinds.get('OR', 0)} conclusions")
    print(f"  goal            : {args.goal}, matched by {len(goals)} vertex\n")
    for v in sorted(derived, key=lambda v: (depth[v], v)):
        n = len(support[v])
        print(f"  depth {depth[v]}  {shorten(vertices[v][0]):36s} "
              f"{n:3d} findings" + ("   (declared, not scanned)" if n == 0 else ""))

    fig = draw(vertices, derived, direct, support, goals)
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    fig.savefig(args.out)
    print(f"\n  wrote {args.out}")


if __name__ == "__main__":
    main()
