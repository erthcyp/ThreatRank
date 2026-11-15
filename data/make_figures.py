#!/usr/bin/env python3
"""The paper's figures and tables, drawn from the pipeline rather than retyped from it.

Every figure here calls the same functions `prioritise.py` prints its tables from, and every
table is written out as both a LaTeX fragment and plain text. Nothing is transcribed. A
figure built by copying numbers out of a terminal is correct exactly once: the next time the
scoring changes, the paper keeps the old picture and nothing catches it.

WHAT IT WRITES

    figures/fig1_budget_risk.pdf        risk removed against budget
    figures/fig2_budget_kev.pdf         known-exploited findings closed against budget
    figures/fig3_unreachable.pdf        budget spent on work that cannot reach the goal
    figures/fig4_cross_tool.pdf         findings per host, both scanners
    figures/tables.tex                  booktabs fragments, one per table
    figures/tables.txt                  the same tables as text, to read in a terminal
    figures/all_figures.pdf             every figure in one file, for reading on screen

Vector PDF, not PNG: IEEE templates take `\\includegraphics` of a PDF directly, and a raster
figure in a two-column paper is visibly worse than the text beside it.

    python3 make_figures.py --graph ~/mulval/testcases/lab3 \\
                            --topology topology_lab3.json \\
                            --findings processed/findings_openvas_b2.csv
"""

import argparse
import collections
import csv
import glob
import json
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.backends.backend_pdf import PdfPages
from scipy.stats import spearmanr

import consequence as C
import likelihood as L
import prioritise as P

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "figures")

# Budgets are read at a tenth of a percent and at the whole list alike, because the two ends
# answer different questions: the low end is where a small team actually operates and where
# the orderings separate, and the high end is where the reachability filter starts to bite.
BUDGETS = [1, 2, 3, 5, 10, 25, 50, 100]

# Four orderings are drawn against ThreatRank: a published threat-tier method (SSVC), published
# exploit prediction (EPSS), and the naive severity sort. VMC's two gate configurations produce
# the same ordering as SSVC on this corpus -- all three are threat-then-severity tier rules -- so
# drawing them would stack three lines in one place; they share SSVC's curve and are reported in
# the budget table. `most findings`, `ungrouped R`, and `ungrouped sev` are tabulated too.
DRAWN = ["R = L x C", "SSVC", "EPSS", "severity"]
# Short enough to sit two-across under a one-column figure.
LABEL = {"R = L x C": "ThreatRank",
         "SSVC": "SSVC / VMC",
         "EPSS": "EPSS",
         "KEV-EPSS-CVSS": "KEV-EPSS-CVSS",
         "severity": "Severity, grouped",
         "ungrouped sev": "Severity list"}
# The documented categorical palette. ThreatRank/EPSS/severity keep slots 1--3; SSVC takes the
# amber slot, and KEV-EPSS-CVSS a violet so its legend entry is readable even where its line sits
# on EPSS. Dash and draw order (below) do the rest of the separation.
COLOUR = {"R = L x C": "#2a78d6", "SSVC": "#eda100", "EPSS": "#eb6834",
          "severity": "#1baf7a", "KEV-EPSS-CVSS": "#7a4fbf", "ungrouped sev": "#eda100"}
# (linewidth, linestyle, zorder). Secondary encoding so identity never rests on colour alone:
# ThreatRank solid and heaviest and on top; the two published baselines dashed; EPSS solid beneath
# the KEV-EPSS-CVSS dash that rides on it; the naive sort dotted.
STYLE = {"R = L x C": (2.0, "solid", 7),
         "SSVC": (1.4, (0, (5, 2)), 4),
         "KEV-EPSS-CVSS": (1.5, (0, (4, 2)), 6),
         "EPSS": (1.4, "solid", 3),
         "severity": (1.4, (0, (1, 1)), 3)}


def style():
    plt.rcParams.update({
        # Match IEEEtran's Times. Liberation Serif is a metric-compatible Times clone;
        # STIX supplies Times-like math so figure text matches the paper body.
        "font.family": "serif",
        "font.serif": ["Liberation Serif", "STIXGeneral", "DejaVu Serif"],
        "mathtext.fontset": "stix",
        "font.size": 8.5,
        "axes.labelsize": 8.5,
        "axes.titlesize": 9,
        "legend.fontsize": 7.5,
        "xtick.labelsize": 7.5,
        "ytick.labelsize": 7.5,
        "axes.spines.top": False,
        "axes.spines.right": False,
        "axes.edgecolor": "#5a5a5a",
        "axes.linewidth": 0.6,
        "grid.color": "#dddddd",
        "grid.linewidth": 0.5,
        "figure.dpi": 150,
        "savefig.bbox": "tight",
        "savefig.pad_inches": 0.02,
    })


def curve(actions, cost, value):
    """One row of a table: the chosen value at each budget, for each drawn ordering."""
    total = sum(cost[a["tier"]] for a in actions)
    orders = P.orderings(actions, cost)
    return {name: [value(orders[name](total * b / 100.0)) for b in BUDGETS]
            for name in DRAWN}


def line_figure(series, ylabel, ymax=None, pct=False):
    """One panel, with no caption drawn inside it.

    The explanation belongs in the LaTeX `\\caption{}`: a caption rendered into the image
    collides with the axis label, cannot be edited when the wording changes, and sets its
    own type in a size the template never chose.
    """
    # Taller than it needs to be for the plot alone, because the legend sits below the axes
    # rather than inside them. Inside, it covered the part of the curve the reader is there
    # to look at: these lines climb through the upper left, which is where a legend would
    # otherwise go.
    fig, ax = plt.subplots(figsize=(3.4, 2.75))
    ax.set_xscale("log")
    ax.grid(True, which="major", axis="both", zorder=0)
    ax.set_axisbelow(True)
    for name in DRAWN:
        lw, ls, zo = STYLE[name]
        ax.plot(BUDGETS, series[name], marker="o", markersize=3.2,
                linewidth=lw, linestyle=ls, color=COLOUR[name], label=LABEL[name],
                zorder=zo, markeredgecolor="white", markeredgewidth=0.6)
    ax.set_xticks(BUDGETS)
    ax.set_xticklabels([f"{b}" for b in BUDGETS])
    ax.minorticks_off()
    # A plain per-cent sign. Matplotlib is not running LaTeX here, so the escaped form is
    # drawn literally, backslash and all.
    ax.set_xlabel("Budget (% of total remediation cost)")
    ax.set_ylabel(ylabel)
    if ymax:
        ax.set_ylim(0, ymax * 1.06)
    if pct:
        ax.set_yticks([0, 25, 50, 75, 100])
    ax.legend(frameon=False, loc="upper center", bbox_to_anchor=(0.5, -0.30),
              ncol=2, handlelength=1.7, columnspacing=1.4, handletextpad=0.5,
              borderaxespad=0.0)
    return fig


# Short, honest display names for the products the top actions touch, so the y-axis labels fit a
# one-column figure. Anything not listed falls back to its first word, title-cased.
PLAN_PRODUCT = {
    "apache http server": "Apache",
    "oracle mysql server": "MySQL",
    "wordpress": "WordPress",
    "php": "PHP",
}


def plan_figure(actions, cost, topology):
    """The top of the plan as a chart, replacing the plan table.

    Each of the five highest-ranked actions is a bar of the findings it closes, split into the
    share on a path to the goal and the rest, with the known-exploited count called out. The
    ranking is $R = L \\times C$ per unit cost, so the longest bar is deliberately not the first:
    reachability and exploitation, not the raw count of findings, decide the order, and the split
    bar is there to show it.
    """
    hosts = topology.get("hosts", topology)
    ranked = sorted(actions, key=lambda a: -(a["risk"] / cost[a["tier"]]))[:5]
    labels, onp, offp, kev = [], [], [], []
    for a in ranked:
        host, _port, prod = a["key"]
        atom = hosts.get(host, {}).get("atom", host)
        labels.append(f"{atom}  {PLAN_PRODUCT.get(prod, prod.split()[0].title())}")
        on = sum(1 for r in a["members"] if r["consequence"] > 0)
        onp.append(on)
        offp.append(a["size"] - on)
        kev.append(a["kev"])
    y = list(range(len(ranked)))[::-1]          # rank 1 on top
    fig, ax = plt.subplots(figsize=(3.4, 2.4))
    on_c, off_c = COLOUR["R = L x C"], "#bcd4f0"
    ax.barh(y, onp, color=on_c, zorder=3, edgecolor="white", linewidth=1.0,
            label="On a path to the goal")
    ax.barh(y, offp, left=onp, color=off_c, zorder=3, edgecolor="white", linewidth=1.0,
            label="Not on a path")
    xmax = max(a["size"] for a in ranked)
    for yi, on, off, k in zip(y, onp, offp, kev):
        total = on + off
        tag = f"{total}" + (f"   KEV×{k}" if k else "")
        ax.text(total + xmax * 0.015, yi, tag, va="center", ha="left", fontsize=7)
    ax.set_yticks(y)
    ax.set_yticklabels(labels)
    ax.set_xlabel("Findings closed")
    ax.set_xlim(0, xmax * 1.20)
    ax.tick_params(axis="y", length=0)
    ax.grid(True, which="major", axis="x", zorder=0)
    ax.set_axisbelow(True)
    # Below the axes, so it never crosses a bar or its label; the bars climb across the whole
    # width here, which leaves no in-plot corner a legend could sit in cleanly.
    ax.legend(frameon=False, loc="upper center", bbox_to_anchor=(0.5, -0.22),
              ncol=2, fontsize=7, handlelength=1.3, columnspacing=1.6, handletextpad=0.5,
              borderaxespad=0.0)
    return fig


def cross_tool_figure(pattern):
    """Findings per host from each scanner, straight out of the processed CSVs.

    Deduplicated on `(host, check name, scanner)`, which is the rule `tool_agreement.py`
    applies. Counting rows instead put 18 findings on .103 where the agreement table put
    10, and a paper that carries two numbers for one quantity is one a reader stops
    trusting at the first table.
    """
    per = collections.defaultdict(lambda: collections.defaultdict(int))
    seen = set()
    for path in expand(pattern):
        with open(path, encoding="utf-8") as fh:
            for r in csv.DictReader(fh):
                if r.get("threat") == "Log":
                    continue
                tool = (r.get("scanner") or "").lower()
                if tool not in ("openvas", "nessus"):
                    continue
                key = (r["host"], r["nvt_name"], tool)
                if key in seen:
                    continue
                seen.add(key)
                per[r["host"]][tool] += 1
    hosts = sorted(h for h in per if per[h]["openvas"] and per[h]["nessus"])
    if not hosts:
        return None, hosts, per

    fig, ax = plt.subplots(figsize=(7.0, 2.6))
    x = range(len(hosts))
    w = 0.38
    ov = [per[h]["openvas"] for h in hosts]
    ne = [per[h]["nessus"] for h in hosts]
    ax.bar([i - w / 2 for i in x], ov, w, color=COLOUR["R = L x C"],
           label="OpenVAS", zorder=3)
    ax.bar([i + w / 2 for i in x], ne, w, color=COLOUR["EPSS"],
           label="Nessus", zorder=3)
    for i, (a, b) in enumerate(zip(ov, ne)):
        ax.text(i - w / 2, a + 2, str(a), ha="center", fontsize=6.5, color="#444444")
        ax.text(i + w / 2, b + 2, str(b), ha="center", fontsize=6.5, color="#444444")
    ax.set_xticks(list(x))
    ax.set_xticklabels(["." + h.split(".")[-1] for h in hosts])
    ax.set_xlabel("Host, last octet of 172.18.0.0/16")
    ax.set_ylabel("Findings, Log excluded")
    ax.grid(True, axis="y", zorder=0)
    ax.set_axisbelow(True)
    ax.legend(frameon=False, loc="upper right")
    # The one host where the order reverses is the whole point: if one tool led everywhere
    # the finding would be that it is more verbose, not that a single tool misses work.
    flipped = [i for i, (a, b) in enumerate(zip(ov, ne)) if b > a]
    for i in flipped:
        ax.annotate("Nessus leads", xy=(i, max(ov[i], ne[i])),
                    xytext=(i, max(ov) * 0.30), ha="center", fontsize=6.5,
                    color="#b3391f",
                    arrowprops=dict(arrowstyle="-", color="#b3391f", linewidth=0.6))
    return fig, hosts, per


def cwe_tail_figure(nvd_path, finding_paths):
    """Why the weakness classifier was dropped, in one picture.

    Findings per CWE, sorted. The argument against a learned classifier here is not that the
    model was poor; it is that 129 classes over 410 findings leaves most classes with one
    example. A reader sees that from the shape of this curve faster than from the sentence.
    """
    nvd = json.load(open(nvd_path, encoding="utf-8"))
    counts = collections.Counter()
    seen = set()
    for path in finding_paths:
        with open(path, encoding="utf-8") as fh:
            for r in csv.DictReader(fh):
                if r.get("threat") == "Log":
                    continue
                key = (r["host"], r["nvt_name"])
                if key in seen:
                    continue
                seen.add(key)
                for c in (r.get("cves") or "").split(";"):
                    for w in nvd.get(c.strip(), {}).get("cwes", []):
                        counts[w] += 1
    if not counts:
        return None, counts
    ordered = [n for _, n in counts.most_common()]
    singles = sum(1 for n in ordered if n == 1)

    fig, ax = plt.subplots(figsize=(3.4, 2.3))
    ax.bar(range(len(ordered)), ordered, width=1.0,
           color=COLOUR["R = L x C"], linewidth=0, zorder=3)
    ax.set_yscale("log")
    ax.set_xlabel(f"CWE class, ranked ({len(ordered)} in all)")
    ax.set_ylabel("Findings")
    ax.grid(True, axis="y", zorder=0)
    ax.set_axisbelow(True)
    ax.axhline(1.5, color="#b3391f", linewidth=0.8, linestyle="--", zorder=4)
    ax.annotate(f"{singles} classes hold one finding",
                xy=(len(ordered) * 0.42, 1.05), fontsize=6.8, color="#b3391f")
    return fig, counts


def agreement_figure(pattern):
    """What each scanner saw that the other did not, counted in CVEs.

    The stacked bar is the point of the correlation stage: the shared block is small and the
    two private blocks are not, so merging matters for coverage rather than for removing
    duplicates.
    """
    per = {"openvas": set(), "nessus": set()}
    for path in expand(pattern):
        with open(path, encoding="utf-8") as fh:
            for r in csv.DictReader(fh):
                if r.get("threat") == "Log":
                    continue
                tool = (r.get("scanner") or "").lower()
                if tool not in per:
                    continue
                for c in (r.get("cves") or "").split(";"):
                    if c.strip().startswith("CVE-"):
                        per[tool].add(c.strip())
    ov, ne = per["openvas"], per["nessus"]
    if not ov or not ne:
        return None, (0, 0, 0)
    only_ov, both, only_ne = len(ov - ne), len(ov & ne), len(ne - ov)

    fig, ax = plt.subplots(figsize=(3.4, 1.5))
    left = 0
    for value, colour, name in ((only_ov, COLOUR["R = L x C"], "OpenVAS only"),
                                (both, COLOUR["severity"], "Both"),
                                (only_ne, COLOUR["EPSS"], "Nessus only")):
        ax.barh([0], [value], left=left, color=colour, label=f"{name} ({value})",
                height=0.55, zorder=3)
        left += value
    ax.set_yticks([])
    ax.set_xlabel("Distinct CVE identifiers")
    ax.spines["left"].set_visible(False)
    ax.grid(True, axis="x", zorder=0)
    ax.set_axisbelow(True)
    ax.legend(frameon=False, loc="upper center", bbox_to_anchor=(0.5, -0.55),
              ncol=3, handlelength=1.2, columnspacing=1.0, handletextpad=0.4,
              borderaxespad=0.0)
    return fig, (only_ov, both, only_ne)


def goal_figure(graph, actions, cost, goals):
    """How much of the work is irrelevant, for each thing an operator might be defending.

    Action grouping does not depend on the goal, so the graph is read once and only the
    reachable set is recomputed. A finding with no leaf in the graph is unreachable, which
    is the same rule the scoring applies.
    """
    vertices, edges = C.read_graph(graph)
    leaves = C.finding_leaves(vertices)
    labels, counts, costs = [], [], []
    for goal in goals:
        targets = C.goal_vertex(vertices, goal)
        if not targets:
            continue
        dist = C.distances_to(targets, edges, vertices)
        unreachable = [a for a in actions
                       if all(dist.get(leaves.get((r["atom"], r["vuln_id"]))) is None
                              for r in a["members"])]
        labels.append(goal.replace("execCode(", "").replace(", _)", "").replace(",_)", ""))
        counts.append(len(unreachable))
        costs.append(sum(cost[a["tier"]] for a in unreachable))
    if not labels:
        return None, []

    fig, ax = plt.subplots(figsize=(3.4, 2.3))
    x = range(len(labels))
    w = 0.38
    ax.bar([i - w / 2 for i in x], counts, w, color=COLOUR["R = L x C"],
           label=f"Actions (of {len(actions)})", zorder=3)
    ax.bar([i + w / 2 for i in x], costs, w, color=COLOUR["EPSS"],
           label=f"Cost units (of {sum(cost[a['tier']] for a in actions):g})", zorder=3)
    for i, (a, b) in enumerate(zip(counts, costs)):
        ax.text(i - w / 2, a + 0.4, str(a), ha="center", fontsize=6.8, color="#444444")
        ax.text(i + w / 2, b + 0.4, f"{b:g}", ha="center", fontsize=6.8, color="#444444")
    ax.set_xticks(list(x))
    ax.set_xticklabels(labels)
    ax.set_xlabel("Declared goal")
    ax.set_ylabel("Unreachable from the goal")
    ax.grid(True, axis="y", zorder=0)
    ax.set_axisbelow(True)
    ax.legend(frameon=False, loc="upper center", bbox_to_anchor=(0.5, -0.32),
              ncol=2, handlelength=1.2, columnspacing=1.2, handletextpad=0.4,
              borderaxespad=0.0)
    return fig, list(zip(labels, counts, costs))


def concentration_figure(actions, cost):
    """How much of the corpus a handful of jobs closes, in the plan's own order.

    The unit the pipeline ranks is a job, and the case for that unit is this curve: a list of
    findings has no way to say that ten entries account for half the corpus.
    """
    ordered = sorted(actions, key=lambda a: -(a["risk"] / cost[a["tier"]]))
    total = sum(a["size"] for a in ordered)
    cum, run = [], 0
    for a in ordered:
        run += a["size"]
        cum.append(100 * run / max(total, 1))

    fig, ax = plt.subplots(figsize=(3.4, 2.3))
    ax.plot(range(1, len(cum) + 1), cum, linewidth=1.6,
            color=COLOUR["R = L x C"], zorder=3)
    ax.fill_between(range(1, len(cum) + 1), cum, color=COLOUR["R = L x C"],
                    alpha=0.12, zorder=2)
    if len(cum) >= 10:
        ax.plot([10], [cum[9]], "o", markersize=4, color="#b3391f", zorder=4)
        ax.annotate(f"10 jobs close {cum[9]:.0f}%", xy=(10, cum[9]),
                    xytext=(len(cum) * 0.3, max(cum[9] - 28, 8)), fontsize=6.8,
                    color="#b3391f",
                    arrowprops=dict(arrowstyle="-", color="#b3391f", linewidth=0.6))
    ax.set_xlabel(f"Remediation jobs done, in plan order (of {len(ordered)})")
    ax.set_ylabel("Findings closed (%)")
    ax.set_ylim(0, 104)
    ax.grid(True, zorder=0)
    ax.set_axisbelow(True)
    return fig, cum


def expand(pattern):
    """Files matching a comma-separated list of globs, relative to this directory."""
    return [p for part in pattern.split(",") for p in sorted(glob.glob(os.path.join(HERE, part)))]


def surrogate_figure(finding_paths):
    """Predicted against published EPSS, out of fold.

    Cross-validated and grouped by the CVE that supplied the target, which is the split the
    headline number is reported under. An in-sample scatter would be a picture of the model
    reciting its training set. Both axes are logarithmic because EPSS is: most of the mass
    sits below 0.01, and on a linear axis the whole corpus would be one blot at the origin.
    """
    from sklearn.model_selection import GroupKFold, cross_val_predict
    # Read the named files rather than calling likelihood's own loader, which takes no
    # arguments and reads its own default set: the figure has to describe the corpus this
    # run was given, not whatever that default happens to point at.
    rows, seen = [], set()
    for path in finding_paths:
        with open(path, encoding="utf-8") as fh:
            for r in csv.DictReader(fh):
                if r.get("threat") == "Log":
                    continue
                key = (r["host"], r["nvt_name"])
                if key in seen:
                    continue
                seen.add(key)
                rows.append(r)
    epss = L.epss_lookup()
    train = [(r,) + L.target_for(r, epss) for r in rows]
    train = [(r, y, c) for r, y, c in train if y is not None]
    if len(train) < 30:
        return None, float("nan")

    X = L.build_matrix([r for r, _, _ in train])
    y_raw = np.array([y for _, y, _ in train])
    y = np.log10(np.maximum(y_raw, L.FLOOR))
    groups = np.array([c for _, _, c in train])
    folds = min(5, len(set(groups)))
    pred = cross_val_predict(L.model(), X, y, groups=groups,
                             cv=GroupKFold(n_splits=folds))
    rho = spearmanr(y, pred).statistic

    shown = np.clip(10 ** pred, L.FLOOR, 1.0)

    # The limits come from the data. They used to be fixed at 1e-5, which is the floor
    # EPSS can report rather than anything this corpus contains, so the points sat in the
    # top-right corner and three quarters of the panel was empty. One range is used for
    # both axes so that the dashed diagonal still means "predicted equals published";
    # separate ranges would tilt it and it would stop being a reference line.
    lo = min(y_raw.min(), shown.min()) / 2.0
    hi = max(y_raw.max(), shown.max()) * 1.6
    fig, ax = plt.subplots(figsize=(3.4, 2.6))
    ax.plot([lo, hi], [lo, hi], linewidth=0.8, color="#999999",
            linestyle="--", zorder=2)
    ax.scatter(y_raw, shown, s=9, alpha=0.45,
               color=COLOUR["R = L x C"], linewidths=0, zorder=3)
    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.set_xlim(lo, hi)
    ax.set_ylim(lo, hi)
    ax.set_xlabel("Published EPSS")
    ax.set_ylabel("Surrogate estimate")
    ax.grid(True, which="major", zorder=0)
    ax.set_axisbelow(True)
    # Axes fractions, so the note stays put whatever the limits turn out to be.
    ax.annotate(f"Spearman {rho:.3f}, out of fold\n{len(train)} findings, "
                f"{folds} CVE-grouped folds",
                xy=(0.97, 0.04), xycoords="axes fraction",
                ha="right", va="bottom", fontsize=6.8, color="#444444")
    return fig, rho


def graph_validation_figure():
    """The falsification battery as predicted-vs-observed, the way it was actually run.

    Each of ten input changes had its outcome fixed in advance -- the goal must stay derivable,
    or must not -- and the engine was then rerun. What the figure shows is that the predicted and
    the observed outcome agree on every one: the point is not a vertex count but that the graph
    behaves as a correct derivation should when its inputs are removed. Read from the pipeline's
    recorded output, not retyped.
    """
    import json
    from matplotlib.lines import Line2D
    d = json.load(open(os.path.join(OUT, "graph_checks.json")))
    label = {
        "control, nothing changed": "nothing changed (control)",
        "unrelated hop removed": "off-path edge removed",
        "attacker position removed": "attacker position removed",
        "attacker's entry edge removed": "entry edge removed",
        "middle hop removed": "middle hop removed",
        "last hop to the database removed": "last hop to database removed",
        "every weakness on the web tier removed": "web-tier weaknesses removed",
        "every weakness on the app tier removed": "app-tier weaknesses removed",
        "every weakness on the database removed": "database weaknesses removed",
        "service descriptions removed": "service descriptions removed",
    }
    # reachable-expected first, then cut-expected, each in the order above
    order = list(label)
    by = {c["check"]: c for c in d["checks"]}
    rows = [by[k] for k in order if k in by]
    rows.sort(key=lambda c: (not c["expected_goal"]))  # stable: reachable group on top

    reach_c = COLOUR["R = L x C"]
    cut_c = COLOUR["EPSS"]

    def mark(ax, x, y, reachable):
        if reachable:
            ax.scatter([x], [y], s=42, marker="o", color=reach_c, zorder=4)
        else:
            ax.scatter([x], [y], s=52, marker="X", color=cut_c, zorder=4)

    style()
    fig, ax = plt.subplots(figsize=(3.4, 3.0))
    xp, xo = 0.40, 0.62
    n = len(rows)
    for i, c in enumerate(rows):
        y = n - 1 - i
        ax.plot([xp, xo], [y, y], color="#d7dbe0", linewidth=0.8, zorder=2)
        mark(ax, xp, y, c["expected_goal"])
        mark(ax, xo, y, c["goal_reached"])
    # divider between the two expectation groups
    split = sum(1 for c in rows if c["expected_goal"])
    ax.axhline(n - split - 0.5, color="#c9ced4", linewidth=0.6, linestyle=":", zorder=1)

    ax.set_yticks([n - 1 - i for i in range(n)])
    ax.set_yticklabels([label[c["check"]] for c in rows], fontsize=6.6)
    ax.set_xticks([xp, xo])
    ax.set_xticklabels(["predicted", "observed"], fontsize=7.2)
    ax.set_xlim(0.28, 0.74)
    ax.set_ylim(-0.6, n - 0.4)
    ax.tick_params(length=0)
    for sp in ax.spines.values():
        sp.set_visible(False)
    ax.text(0.51, n - 0.35, "the two agree in every row",
            ha="center", va="bottom", fontsize=6.6, color="#333333", fontstyle="italic")
    handles = [Line2D([0], [0], marker="o", color="none", markerfacecolor=reach_c,
                      markersize=7, label="goal reachable"),
               Line2D([0], [0], marker="X", color="none", markerfacecolor=cut_c,
                      markersize=7, label="goal disconnected")]
    ax.legend(handles=handles, loc="lower center", bbox_to_anchor=(0.51, -0.16),
              ncol=2, frameon=False, fontsize=6.6, handletextpad=0.2, columnspacing=1.0)
    return fig


def ml_vs_baseline_figure():
    """Each learned component beside the baseline that would replace it, one panel, no budget.

    The rest of the evaluation reads risk under a budget, which mixes the model with the greedy
    selector and the graph. This figure isolates the two learned stages and asks one question:
    does the model beat the baseline a team would use instead? Higher is better on both metrics,
    and both run from 0 to 1, so the two are shown on one axis with the metric named per group.
    Numbers are read from the pipeline's own recorded output, not retyped.
    """
    import json
    imp = json.load(open(os.path.join(OUT, "impact.json")))
    tr = json.load(open(os.path.join(OUT, "transfer.json")))
    fl = json.load(open(os.path.join(OUT, "feed_likelihood.json")))

    model_c = COLOUR["R = L x C"]
    text_c = "#7a4fbf"
    base_c = "#b9c0cc"
    # Each group is (label, metric, [(value, colour, legend key)]). The likelihood group has only
    # its naive baseline; the three impact groups add the published text classifier between the
    # model and the naive answer, so the figure shows what the structured features buy over words.
    L_KEY = "Naive baseline"
    groups = [
        ("Exploit\nlikelihood", "Spearman",
         [(tr["CVE-grouped split, the headline"][0], model_c, "ThreatRank"),
          (fl["severity_baseline"], base_c, L_KEY)]),
    ]
    for f in ("confidentiality", "integrity", "availability"):
        groups.append((f"Impact:\n{f}", "macro-F1",
                       [(imp[f]["macro_f1"], model_c, "ThreatRank"),
                        (imp[f]["macro_f1_text"], text_c, "Text classifier"),
                        (imp[f]["macro_f1_majority"], base_c, L_KEY)]))

    style()
    fig, ax = plt.subplots(figsize=(3.4, 2.7))
    w = 0.26
    seen = {}
    for i, (_lab, _metric, bars) in enumerate(groups):
        n = len(bars)
        for j, (v, c, key) in enumerate(bars):
            xi = i + (j - (n - 1) / 2) * w
            h = ax.bar(xi, v, w, color=c, zorder=3)
            seen.setdefault(key, h)
            ax.text(xi, v + 0.015, f"{v:.2f}", ha="center", va="bottom", fontsize=6.0,
                    color=(model_c if c == model_c else "#333333"),
                    fontweight=("bold" if c == model_c else "normal"), zorder=4)
    x = np.arange(len(groups))
    ax.set_xticks(x)
    ax.set_xticklabels([g[0] for g in groups], fontsize=6.6)
    for xi, g in zip(x, groups):
        ax.text(xi, -0.145, f"({g[1]})", ha="center", va="top", fontsize=5.8,
                color="#333333", transform=ax.get_xaxis_transform())
    ax.set_ylim(0, 1.0)
    ax.set_ylabel("Score (higher is better)")
    ax.grid(True, axis="y", zorder=0)
    ax.set_axisbelow(True)
    order = ["ThreatRank", "Text classifier", L_KEY]
    ax.legend([seen[k] for k in order if k in seen],
              [k for k in order if k in seen],
              loc="upper right", fontsize=6.4, frameon=False, ncol=1)
    return fig


def latex_table(label, caption, header, rows, aligns=None):
    aligns = aligns or ("l" + "r" * (len(header) - 1))
    out = ["\\begin{table}[t]", "\\caption{" + caption + "}",
           "\\label{" + label + "}", "\\centering",
           "\\begin{tabular}{" + aligns + "}", "\\toprule",
           " & ".join(header) + " \\\\", "\\midrule"]
    for r in rows:
        out.append(" & ".join(str(c) for c in r) + " \\\\")
    out += ["\\bottomrule", "\\end{tabular}", "\\end{table}", ""]
    return "\n".join(out)


def plain(cell):
    """LaTeX markup out, so the same rows can be written as Markdown or as text."""
    return (str(cell).replace("\\%", "%").replace("$", "")
            .replace("\\times", "×").replace("\\_", "_"))


def md_table(caption, header, rows):
    """Markdown, for reading the results in an editor's preview rather than in LaTeX.

    The same rows as the .tex fragment, from the same list, so the three renderings cannot
    disagree with one another.
    """
    head = [plain(h) for h in header]
    aligns = ["---"] + ["---:"] * (len(head) - 1)
    out = ["### " + plain(caption), "",
           "| " + " | ".join(head) + " |",
           "| " + " | ".join(aligns) + " |"]
    for r in rows:
        out.append("| " + " | ".join(plain(c) for c in r) + " |")
    out.append("")
    return "\n".join(out)


def text_table(caption, header, rows):
    widths = [max(len(str(header[i])), max((len(str(r[i])) for r in rows), default=0))
              for i in range(len(header))]
    line = "  ".join("-" * w for w in widths)
    out = [caption, line, "  ".join(str(header[i]).ljust(widths[i])
                                    for i in range(len(header))), line]
    for r in rows:
        out.append("  ".join(str(r[i]).ljust(widths[i]) for i in range(len(header))))
    out += [line, ""]
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--graph", required=True, metavar="DIR")
    ap.add_argument("--topology", required=True, metavar="JSON")
    ap.add_argument("--findings", required=True, action="append", metavar="CSV")
    ap.add_argument("--weights", default="1,2,5", metavar="P,C,R")
    ap.add_argument("--png", action="store_true",
                    help="also write each figure as PNG and point tables.md at it, "
                         "so the Markdown preview renders the figures")
    # Named explicitly: a findings_*2.csv glob also matches the later Qualys robustness scan,
    # which the paper does not use as a training input (see transfer.py).
    ap.add_argument("--corpus",
                    default="processed/findings_openvas_[ab]2.csv,processed/findings_nessus_[ab]2.csv",
                    metavar="GLOB[,GLOB]",
                    help="which processed CSVs the cross-tool and surrogate figures read")
    ap.add_argument("--goals", action="append", metavar="GOAL",
                    help="alternative goals for the sensitivity figure; repeatable")
    args = ap.parse_args()

    os.makedirs(OUT, exist_ok=True)
    style()

    # The declared goal always appears first, so the sensitivity figure is read against the
    # configuration everything else on the page was computed under.
    declared = json.load(open(args.topology, encoding="utf-8"))["goal"]
    args.goals = [declared] + [g for g in (args.goals or []) if g != declared]

    print("scoring ...")
    kept, actions, topology = P.score(args.graph, args.topology, args.findings)
    weights = [float(x) for x in args.weights.split(",")]
    cost = dict(zip((P.PATCH, P.CONFIG, P.REPLACE), weights))
    total_cost = sum(cost[a["tier"]] for a in actions)
    total_risk = sum(a["risk"] for a in actions)
    kev_total = sum(1 for r in kept if P.in_kev(r))
    unreachable = {a["key"] for a in actions
                   if all(r["consequence"] == 0.0 for r in a["members"])}
    unreachable_cost = sum(cost[a["tier"]] for a in actions if a["key"] in unreachable)

    print(f"  {len(kept)} findings, {len(actions)} actions, {total_cost:g} cost units, "
          f"{kev_total} known-exploited")

    risk = curve(actions, cost,
                 lambda ch: 100 * sum(a["risk"] for a in ch) / max(total_risk, 1e-9))
    kev = curve(actions, cost, lambda ch: sum(a["kev"] for a in ch))
    unre = curve(actions, cost,
                 lambda ch: sum(cost[a["tier"]] for a in ch if a["key"] in unreachable))

    figs = []
    # Y labels stay short. A one-column figure is 3.4 inches wide and the label is set
    # sideways in that height; a sentence there is clipped, and what it would have said
    # belongs in the caption anyway.
    figs.append(("fig_plan", plan_figure(actions, cost, topology)))
    f1 = line_figure(risk, "Risk removed (%)", ymax=100, pct=True)
    figs.append(("fig1_budget_risk", f1))
    f2 = line_figure(kev, f"Exploited closed (of {kev_total})",
                     ymax=max(kev_total, 1))
    figs.append(("fig2_budget_kev", f2))
    f3 = line_figure(unre, f"Wasted budget (of {unreachable_cost:g})",
                     ymax=max(unreachable_cost, 1))
    figs.append(("fig3_unreachable", f3))
    f4, hosts, per = cross_tool_figure(args.corpus)
    if f4 is not None:
        figs.append(("fig4_cross_tool", f4))
    else:
        print("  no host carries findings from both scanners; figure 4 skipped")

    # One figure per pipeline stage, so that a stage with nothing to show is visible as a
    # gap rather than hidden among the stages that do. Each returns None when its input is
    # missing, and says so, instead of drawing an empty panel.
    f5, cwe_counts = cwe_tail_figure(os.path.join(HERE, "cwe_map.json"), args.findings)
    if f5 is not None:
        figs.append(("fig5_cwe_tail", f5))
    else:
        print("  no CWE assignments reachable; classification figure skipped")
    f6, split = agreement_figure(args.corpus)
    if f6 is not None:
        figs.append(("fig6_agreement", f6))
    else:
        print("  only one scanner in the corpus; agreement figure skipped")
    f7, goal_rows = goal_figure(args.graph, actions, cost, args.goals)
    if f7 is not None:
        figs.append(("fig7_goal_sensitivity", f7))
    else:
        print("  none of the requested goals exist in the graph; goal figure skipped")
    f8, cum = concentration_figure(actions, cost)
    figs.append(("fig8_concentration", f8))
    # The surrogate is evaluated over the whole corpus, not over the subset the attack graph
    # was built for. The prioritisation figures are necessarily lab-specific -- there is one
    # graph and one goal -- but a likelihood number computed on three hosts and a transfer
    # number computed on nine would sit adjacent in the same document disagreeing about the
    # same quantity, which is the defect this file already fixed once for the per-host counts.
    corpus_files = expand(args.corpus) or args.findings
    f9, rho = surrogate_figure(corpus_files)
    # The attack graph drawn as its nine conclusions rather than its 357 vertices. Built by
    # graph_figure.py, which is also runnable on its own for a single PDF to show someone.
    try:
        import graph_figure as G
        vertices, edges = C.read_graph(args.graph)
        goal_vs = set(C.goal_vertex(vertices, topology["goal"]))
        derived, direct, support = G.condense(vertices, edges, goal_vs)
        f10 = G.draw(vertices, derived, direct, support, goal_vs)
        graph_stats = (len(vertices), sum(len(d) for d in edges.values()),
                       collections.Counter(k for _, k in vertices.values()))
    except Exception as exc:
        f10, graph_stats = None, None
        print(f"  attack-graph figure skipped: {exc}")
    if f9 is not None:
        figs.append(("fig9_surrogate", f9))
    else:
        print("  too few scored findings to cross-validate; surrogate figure skipped")
    figs.append(("fig_ml_baseline", ml_vs_baseline_figure()))
    figs.append(("fig_graph_validation", graph_validation_figure()))
    if f10 is not None:
        figs.append(("fig10_attack_graph", f10))

    # PDF is what the paper includes. PNG exists because a Markdown preview
    # will not render an embedded PDF, and tables.md is how this work gets
    # looked at between runs; it also lets a reviewer see a figure without a
    # PDF viewer. The paper never references the PNG.
    for name, fig in figs:
        path = os.path.join(OUT, name + ".pdf")
        fig.savefig(path)
        print(f"  wrote {path}")
        if args.png:
            fig.savefig(os.path.join(OUT, name + ".png"), dpi=200)

    with PdfPages(os.path.join(OUT, "all_figures.pdf")) as pdf:
        for _, fig in figs:
            pdf.savefig(fig)
    print(f"  wrote {os.path.join(OUT, 'all_figures.pdf')}")
    for _, fig in figs:
        plt.close(fig)

    tiers = collections.Counter(a["tier"] for a in actions)
    # Each table declares which pipeline stage it belongs to, and the Markdown writer groups
    # by that. A stage with no table is then a visible heading with nothing under it, which
    # is the state of the work rather than something to tidy away.
    tables = []

    tables.append((
        "Setup", "tab:corpus", "Corpus and cost model for the evaluated lab.",
        ["Quantity", "Value"],
        [["Findings, Log excluded", len(kept)],
         ["Hosts", len(topology["hosts"])],
         ["Remediation actions", len(actions)],
         ["Findings per action", f"{len(kept)/max(len(actions),1):.2f}"],
         ["Actions, vendor patch", tiers.get(P.PATCH, 0)],
         ["Actions, configuration", tiers.get(P.CONFIG, 0)],
         ["Actions, no fix available", tiers.get(P.REPLACE, 0)],
         ["Total cost, units", f"{total_cost:g}"],
         ["Known-exploited findings", kev_total],
         ["Actions unreachable from the goal", f"{len(unreachable)} / {len(actions)}"]]))

    if cwe_counts:
        ranked = [n for _, n in cwe_counts.most_common()]
        tables.append((
            "Classification", "tab:cwe",
            "Why a learned weakness classifier was specified and then dropped.",
            ["Quantity", "Value"],
            [["Distinct CWE classes", len(ranked)],
             ["Classes holding one finding", sum(1 for n in ranked if n == 1)],
             ["Largest class", max(ranked)],
             ["Share in the largest class",
              f"{100*max(ranked)/max(sum(ranked),1):.0f}%"]]))

    if hosts:
        tables.append((
            "Correlation", "tab:crosstool",
            "Findings per host, both scanners, same day.",
            ["Host", "OpenVAS", "Nessus"],
            [[h, per[h]["openvas"], per[h]["nessus"]] for h in hosts]))
    if split != (0, 0, 0):
        only_ov, both, only_ne = split
        tables.append((
            "Correlation", "tab:agreement",
            "CVE identifiers each scanner reported, and the overlap between them.",
            ["Quantity", "Value"],
            [["OpenVAS only", only_ov], ["Reported by both", both],
             ["Nessus only", only_ne],
             ["Overlap, Jaccard",
              f"{100*both/max(only_ov+both+only_ne,1):.1f}%"]]))

    if graph_stats:
        total_v, total_a, kinds = graph_stats
        tables.append((
            "Attack graph", "tab:graph",
            "What MulVAL derived from the findings and the topology.",
            ["Quantity", "Value"],
            [["Vertices", total_v], ["Arcs", total_a],
             ["Input facts (LEAF)", kinds.get("LEAF", 0)],
             ["Rule applications (AND)", kinds.get("AND", 0)],
             ["Conclusions reached (OR)", kinds.get("OR", 0)],
             ["Findings that reach the goal",
              f"{sum(1 for r in kept if r['consequence'] == 1.0)} / {len(kept)}"]]))

    if goal_rows:
        tables.append((
            "Attack graph", "tab:goal",
            "Work that cannot reach the goal, for each thing an operator might defend.",
            ["Declared goal", "Unreachable actions", "Cost units"],
            [[g, f"{c} / {len(actions)}", f"{k:g} / {total_cost:g}"]
             for g, c, k in goal_rows]))

    if rho == rho:
        tables.append((
            "Likelihood", "tab:surrogate",
            "The surrogate against published EPSS, cross-validated and grouped by CVE.",
            ["Configuration", "Spearman"],
            [["Surrogate, CVE-grouped split", f"{rho:.3f}"],
             ["Registered threshold", f"{L.THRESHOLD:.2f}"]]))
    # The transfer evaluation is the answer to the first question anyone asks about this
    # stage, so it is reported beside the headline rather than left in the notebook. Run
    # separately because it fits several models; `--transfer` picks it up when it exists.
    transfer_path = os.path.join(OUT, "transfer.json")
    if os.path.exists(transfer_path):
        t = json.load(open(transfer_path, encoding="utf-8"))
        # Both files compute a CVE-grouped split. If they disagree they were run over
        # different corpora, and printing both without a word is how a document ends up
        # carrying two values for one quantity.
        headline = next((v[0] for k, v in t.items() if k.startswith("CVE-grouped")), None)
        if headline is not None and rho == rho and abs(headline - rho) > 0.005:
            print(f"  WARNING: the surrogate table says {rho:.3f} and transfer.json says "
                  f"{headline:.3f} for the same split.")
            print(f"           They were computed over different corpora. Re-run "
                  f"transfer.py with --findings '{args.corpus}'.")
        tables.append((
            "Likelihood", "tab:transfer",
            "Does the surrogate survive the shift between the population it trains on and "
            "the one it serves? The random hold-out separates the cost of the shift from "
            "the cost of a smaller test set.",
            ["Evaluation", "Spearman", "n"],
            [[k, f"{v[0]:.3f}", v[1]] for k, v in t.items()]))

    tables.append((
        "Prioritisation", "tab:budget",
        "Risk removed, as a percentage of the total, against budget.",
        ["Ordering"] + [f"{b}\\%" for b in BUDGETS],
        [[LABEL[n]] + [f"{v:.0f}" for v in risk[n]] for n in DRAWN]))

    tables.append((
        "Prioritisation", "tab:kev",
        f"Known-exploited findings closed, of {kev_total}.",
        ["Ordering"] + [f"{b}\\%" for b in BUDGETS],
        [[LABEL[n]] + [f"{v:.0f}" for v in kev[n]] for n in DRAWN]))

    tables.append((
        "Prioritisation", "tab:unreachable",
        f"Budget spent on actions that cannot reach the goal, of {unreachable_cost:g} units.",
        ["Ordering"] + [f"{b}\\%" for b in BUDGETS],
        [[LABEL[n]] + [f"{v:.0f}" for v in unre[n]] for n in DRAWN]))

    marks = [1, 5, 10, 20]
    tables.append((
        "Remediation", "tab:concentration",
        "Share of the corpus closed after the first few jobs, in plan order.",
        ["Jobs done", "Findings closed"],
        [[m, f"{cum[m-1]:.0f}%"] for m in marks if m <= len(cum)]))

    with open(os.path.join(OUT, "tables.tex"), "w", encoding="utf-8") as fh:
        fh.write("% Generated by make_figures.py. Do not edit; regenerate.\n"
                 "% Requires \\usepackage{booktabs}.\n\n")
        for _, label, cap, head, rows in tables:
            fh.write(latex_table(label, cap, head, rows))

    # Every stage of the pipeline gets a heading, including the ones with nothing under
    # them: the point of reading this file is to see which stages have been evaluated.
    stages = ["Setup", "Classification", "Correlation", "Attack graph", "Likelihood",
              "Prioritisation", "Remediation"]
    figures_by_stage = {
        "Classification": ["fig5_cwe_tail"],
        "Correlation": ["fig4_cross_tool", "fig6_agreement"],
        "Attack graph": ["fig10_attack_graph", "fig7_goal_sensitivity"],
        "Likelihood": ["fig9_surrogate"],
        "Prioritisation": ["fig1_budget_risk", "fig2_budget_kev", "fig3_unreachable"],
        "Remediation": ["fig8_concentration"],
    }
    drawn = {name for name, _ in figs}
    with open(os.path.join(OUT, "tables.md"), "w", encoding="utf-8") as fh:
        fh.write("# ThreatRank results\n\nGenerated by `make_figures.py`. Do not edit this "
                 "file; regenerate it. Figures sit beside it as PDF.\n\n")
        for stage in stages:
            fh.write(f"## {stage}\n\n")
            here = [t for t in tables if t[0] == stage]
            pics = [f for f in figures_by_stage.get(stage, []) if f in drawn]
            if not here and not pics:
                fh.write("_Nothing measured for this stage yet._\n\n")
                continue
            for f in pics:
                # PNG when it was written, because a preview cannot show a PDF.
                ext = "png" if args.png else "pdf"
                fh.write(f"![{f}]({f}.{ext})\n\n")
            for _, _, cap, head, rows in here:
                fh.write(md_table(cap, head, rows) + "\n")
    with open(os.path.join(OUT, "tables.txt"), "w", encoding="utf-8") as fh:
        for stage, _, cap, head, rows in tables:
            fh.write(text_table(f"[{stage}] " + plain(cap), [plain(h) for h in head],
                                [[plain(c) for c in r] for r in rows]) + "\n")
    print(f"  wrote {os.path.join(OUT, 'tables.tex')}, tables.md and tables.txt "
          f"({len(tables)} tables over {len(stages)} stages)")
    missing = [s for s in stages
               if not any(t[0] == s for t in tables)
               and not [f for f in figures_by_stage.get(s, []) if f in drawn]]
    if missing:
        print("  stages with nothing to show: " + ", ".join(missing))


if __name__ == "__main__":
    main()
