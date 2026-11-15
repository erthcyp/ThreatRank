#!/usr/bin/env python3
"""The two structural diagrams, generated rather than drawn.

A rendered diagram is correct on the day it is exported and silent afterwards. The previous
system diagram claimed a CWE classifier, a learning-to-rank ordering, a learned risk fusion and
XGBoost; all four were measured and none survived, and none could be corrected without the tool
that produced the image. These are produced by this script, so a change in the system is a change in the picture.

**No corpus counts appear in either figure.** A diagram describes the architecture; how many
findings took each of the three classification routes is a property of one scan of one host set
and belongs in the text, where it can be qualified.

    fig_system.pdf       the seven stages, coloured by where each stage's values come from
    fig_graphmodel.pdf   how one finding becomes a conclusion in the attack graph

WHICH OF THESE THE PAPER ACTUALLY USES

`fig_graphmodel.pdf` is the one in the paper, and this script is its source: change the system
and change it here. **`fig_system.pdf` is not.** The system diagram in the paper is drawn by
hand in Canva, and what this script produces is a reference rendering -- correct, plain, and
there so that the hand-drawn version has something accurate to be checked against. Editing the
system diagram here changes nothing the reader sees.

So: to change the system figure, edit it in Canva and export over
`threatrank/D3/ThreatRank/figures/fig_system.pdf`. To change the data model figure, edit this
file and copy the output across.

    python3 diagrams.py
"""

import argparse
import os
import subprocess

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Ellipse, FancyArrowPatch, FancyBboxPatch

import make_figures as F

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "figures")

# Where a stage's values come from, which is the one thing the diagram exists to show.
LOOKUP = "#eef3fb"
LEARNED = "#fdf0e2"
LOGIC = "#eaf5ee"
INK = "#12141a"
MUTED = "#585c66"


def box(ax, x, y, w, h, face, edge, lw=0.9):
    ax.add_patch(FancyBboxPatch((x - w / 2, y - h / 2), w, h,
                                boxstyle="round,pad=0.008,rounding_size=0.04",
                                facecolor=face, edgecolor=edge, linewidth=lw, zorder=2))


def arrow(ax, a, b, colour="#8a8f9a", style="-|>", dotted=False):
    ax.add_patch(FancyArrowPatch(a, b, arrowstyle=style, mutation_scale=8,
                                 linewidth=0.7, color=colour, shrinkA=2, shrinkB=2,
                                 linestyle=":" if dotted else "-", zorder=1))


def system_diagram(path):
    """Seven stages over two rows, coloured by where each stage's values come from.

    One row was tried first and does not fit: seven boxes wide enough for `Consequence` leave
    no room for the input and output beside them, and the labels overlapped. Two rows give each
    stage about an inch and a half, which is what the longest label needs.
    """
    stages = [
        ("1. Parse",       "one schema",      LOOKUP,  "both tools,\nLog kept"),
        ("2. Classify",    "properties",      LEARNED, "CVSS impact: published,\nelse estimated,\nelse assumed"),
        ("3. Correlate",   "one job each",    LOOKUP,  "NVD product,\nnot check title"),
        ("4. Likelihood",  "L, EPSS or model",LEARNED, "EPSS where a CVE\nhas one, else a\nlearned estimate"),
        ("5. Consequence", "C, graph, 0 or 1",LOGIC,   "MulVAL over a\ndeclared goal.\nC = 0 drops the job"),
        ("6. Risk",        "R = L x C",       LOOKUP,  "arithmetic,\nnot a model"),
        ("7. Prioritise",  "under a budget",  LOOKUP,  "greedy over\nactions, cost from\nsolution type"),
    ]
    F.style()
    fig, ax = plt.subplots(figsize=(7.0, 3.7))
    w, h, pitch = 1.32, 0.40, 1.62
    rows = [stages[:4], stages[4:]]
    y_of = {0: 1.30, 1: -0.55}
    centre = {}

    for r, row in enumerate(rows):
        y = y_of[r]
        offset = 0 if r == 0 else 0.81
        for i, (title, sub, face, note) in enumerate(row):
            x = offset + i * pitch
            edge = "#c07a2e" if face == LEARNED else ("#2f7a52" if face == LOGIC else "#2a78d6")
            box(ax, x, y, w, h, face, edge, lw=1.3 if face == LEARNED else 0.9)
            ax.text(x, y + 0.075, title, ha="center", va="center", fontsize=7.4,
                    fontweight="bold", color=INK, zorder=3)
            ax.text(x, y - 0.085, sub, ha="center", va="center", fontsize=6.4,
                    color=MUTED, zorder=3)
            ax.text(x, y - 0.26, note, ha="center", va="top", fontsize=5.5, color=MUTED,
                    linespacing=1.35)
            centre[title] = (x, y)
            if i:
                arrow(ax, (x - pitch + w / 2, y), (x - w / 2, y))

    # The turn from the end of the first row to the start of the second.
    x0, y0 = centre["4. Likelihood"]
    x1, y1 = centre["5. Consequence"]
    arrow(ax, (x0, y0 - h / 2 - 0.42), (x1, y1 + h / 2), colour="#8a8f9a")

    ax.text(-1.28, 1.30, "VA scanners\nXML, API", ha="center", va="center", fontsize=6.8,
            color=MUTED,
            bbox=dict(boxstyle="round,pad=0.35", facecolor="#f4f4f5",
                      edgecolor="#babcc4", linestyle="--", linewidth=0.7))
    arrow(ax, (-0.95, 1.30), (-w / 2, 1.30))

    ax.text(centre["5. Consequence"][0], 0.42, "declared topology and goal",
            ha="center", va="center", fontsize=6.4, color=MUTED,
            bbox=dict(boxstyle="round,pad=0.3", facecolor="#f4f4f5",
                      edgecolor="#babcc4", linestyle="--", linewidth=0.7))
    arrow(ax, (centre["5. Consequence"][0] + 0.62, 0.42),
          (centre["5. Consequence"][0] + 0.62, -0.35), dotted=True)

    xo = centre["7. Prioritise"][0]
    ax.text(xo + 1.62, -0.55, "ordered actions,\nwith the evidence", ha="center",
            va="center", fontsize=6.8, color=MUTED,
            bbox=dict(boxstyle="round,pad=0.35", facecolor="#f4f4f5",
                      edgecolor="#babcc4", linestyle="--", linewidth=0.7))
    arrow(ax, (xo + w / 2, -0.55), (xo + 1.26, -0.55))

    # One legend entry per line. Laid out side by side, the first label ran into the second
    # swatch; three short rows cost less vertical space than the collision costs readability.
    for i, (face, edge, label) in enumerate((
            (LEARNED, "#c07a2e", "a model, and only where a published catalogue is silent"),
            (LOOKUP, "#2a78d6", "a lookup, or arithmetic"),
            (LOGIC, "#2f7a52", "a logical derivation"))):
        y = -1.44 - i * 0.20
        box(ax, -1.75, y, 0.20, 0.13, face, edge)
        ax.text(-1.60, y, label, ha="left", va="center", fontsize=6.0, color=MUTED)

    ax.set_xlim(-2.0, 7.3)
    ax.set_ylim(-2.02, 1.82)
    ax.axis("off")
    fig.savefig(path)
    plt.close(fig)
    return path


def graph_model_diagram(path):
    """The data model in variables, drawn in the attack graph's own node style (Graphviz).

    A schema, not a run: arguments are the predicate variables (H, Perm, Prog, VulID, Proto,
    Port). The conclusion sits on top, the rule below it, and the four premise facts in one row
    beneath. vulExists is a single box, highlighted, because it is the one predicate that admits
    an uncatalogued finding -- its VulID a CVE, or the scanner's own id when there is none.
    Rendered with Graphviz so the shapes match the attack-graph figures: a rounded filled box for
    a conclusion or derived fact, an ellipse for a rule, square boxes for leaf facts, and open
    arrowheads pointing at the goal.
    """
    OR_FILL, OR_EDGE = "#dce6f5", "#2060a8"       # conclusion / derived (OR) fact
    LEAF_FILL, LEAF_EDGE = "#eaedf2", "#6f7d90"   # catalogued leaf fact
    VX_FILL, VX_EDGE = "#fcf0d6", "#bf8a2a"       # vulExists, the uncatalogued-capable one
    dot = f'''digraph G {{
  rankdir=BT;
  bgcolor="white";
  nodesep=0.28;
  ranksep=0.52;
  node [fontname="Helvetica", fontsize=17, margin="0.24,0.12", penwidth=1.7];
  edge [color="#616d7c", penwidth=1.7, arrowhead=empty, arrowsize=1.0];

  exec [label="execCode\\nH, Perm", shape=box, style="rounded,filled",
        fillcolor="{OR_FILL}", color="{OR_EDGE}", penwidth=3, fontsize=19];
  rule [label="RULE\\nremote exploit of a server program", shape=ellipse,
        style=filled, fillcolor="white", color="{OR_EDGE}", penwidth=2.2];

  vulexists [label="vulExists\\nH, VulID, Prog", shape=box, style=filled,
             fillcolor="{VX_FILL}", color="{VX_EDGE}", penwidth=2.4];
  vulprop   [label="vulProperty\\nVulID, Range, Loss", shape=box, style=filled,
             fillcolor="{LEAF_FILL}", color="{LEAF_EDGE}"];
  netsvc    [label="networkServiceInfo\\nH, Prog, Proto, Port, Perm", shape=box,
             style=filled, fillcolor="{LEAF_FILL}", color="{LEAF_EDGE}"];
  netaccess [label="netAccess\\nH, Proto, Port", shape=box, style="rounded,filled",
             fillcolor="{OR_FILL}", color="{OR_EDGE}", penwidth=2.4];

  note [label="VulID: a CVE, or the\\nscanner's id if none", shape=plaintext,
        fontname="Helvetica", fontsize=14, fontcolor="{VX_EDGE}"];

  {{ rank=same; vulexists; vulprop; netsvc; netaccess; }}

  vulexists -> rule;
  vulprop   -> rule;
  netsvc    -> rule;
  netaccess -> rule;
  rule      -> exec;
  note -> vulexists [style=dashed, color="{VX_EDGE}", arrowhead=none];
}}'''
    ext = os.path.splitext(path)[1].lstrip(".") or "pdf"
    subprocess.run(["dot", f"-T{ext}", "-o", path], input=dot, text=True, check=True)
    return path


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default=OUT, metavar="DIR")
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)
    for name, fn in (("fig_system", system_diagram),
                     ("fig_graphmodel", graph_model_diagram)):
        for ext in ("pdf", "png"):
            fn(os.path.join(args.out, f"{name}.{ext}"))
        print(f"  wrote {os.path.join(args.out, name)}.pdf and .png")


if __name__ == "__main__":
    main()
