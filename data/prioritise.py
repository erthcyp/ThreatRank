#!/usr/bin/env python3
"""The remediation plan: which fixes to do first, and what a budget buys.

The last stage, and the one the project is named for. Everything before it produces a score
per finding; this turns scores into a list of jobs an analyst can work through in order, and
measures whether that order is better than the orders they already have.

WHAT IS RANKED IS A FIX, NOT A FINDING

A ranked list of 229 findings is not a plan. Upgrading Apache on one host closes thirty of
them at once, so a list that names those thirty separately spends thirty slots on one job.
Findings are therefore grouped into actions, `(host, port, product)` as `fix_actions.py`
derives them, and the plan is a list of actions.

    value of an action   the risk it removes, summed over the findings it closes
    cost of an action    from the scanner's own solution type, in three tiers

Summing rather than averaging is deliberate: an action closing thirty findings removes
thirty findings' worth of exposure, and a plan that ignores that is a plan that does the
small jobs first.

THE COST TIERS ARE A DECLARED PARAMETER

    VendorFix                  a published patch exists          1
    Mitigation, Workaround     configuration change              w_m
    WillNotFix, NoneAvailable  replace or remove the component   w_n

Nothing external states what a configuration change costs relative to a patch, so the
weights are ours and are swept rather than asserted. `--sweep` reports how much the plan
changes across them; if the answer is "not much", the choice did not matter, and that is
worth knowing rather than assuming.

SELECTION IS GREEDY, AND SAYS SO

Value per unit cost, taken until the budget is spent. This is the standard heuristic for a
knapsack and it is not optimal. It is used because the optimum is not the point: the
question is whether ordering by predicted risk beats ordering by what an analyst already
has, and both sides of that comparison use the same selector.

WHAT IT IS GRADED AGAINST

CISA KEV, which is external and is never a feature anywhere upstream. At a given budget, how
many of the findings CISA has observed being exploited does the plan close? Baselines are
the orderings available without this pipeline: the scanner's own severity, the published
EPSS score, and the number of findings an action closes, which is what an analyst optimising
for visible progress would do.

    python3 prioritise.py --graph ~/mulval/testcases/lab3 \\
                          --topology topology_lab3.json \\
                          --findings processed/findings_openvas_b2.csv
"""

import argparse
import collections
import csv
import json
import os
import sys

import numpy as np

import consequence as C
import findings_to_mulval as M
import likelihood as L
from correlate import product_key
from fix_actions import product_of

HERE = os.path.dirname(os.path.abspath(__file__))

PATCH, CONFIG, REPLACE = "patch available", "configuration change", "no fix available"
TIER_OF = {"VendorFix": PATCH,
           "Mitigation": CONFIG, "Workaround": CONFIG,
           "WillNotFix": REPLACE, "NoneAvailable": REPLACE}


# What an action costs when no member states how it is fixed. `solution_type` is an OpenVAS
# field and Nessus exposes nothing equivalent, so an action built only from Nessus findings
# arrives with no tier at all. The middle tier is the assumption, and `--tier-fallback` exists
# so the plan can be recomputed under the other two: an assumption that changes the answer
# should be visible as a number rather than defended in prose.
FALLBACK = "config"
FALLBACK_TIERS = {"patch": PATCH, "config": CONFIG, "replace": REPLACE}


def tier(rows):
    """The cheapest tier any finding in the action admits.

    One patch that closes a finding closes it however the others are classified, so an
    action is as cheap as its cheapest member rather than as dear as its dearest. An action
    where no member states a solution type falls back, and `untiered` counts those.
    """
    tiers = {TIER_OF.get(r.get("solution_type", ""), "") for r in rows}
    for t in (PATCH, CONFIG, REPLACE):
        if t in tiers:
            return t
    return FALLBACK_TIERS[FALLBACK]


# Set by --vulncheck to the wider catalogue's CVE set. Empty means the registered label,
# which is what the findings already carry from parse time.
WIDER = None


def load_vulncheck(path):
    """The CVE set VulnCheck marks as exploited, from the pinned snapshot.

    Used as a second label, never as the first. CISA KEV was registered before any of these
    results existed and stays the headline; this one says whether the conclusions survive a
    catalogue three times the size. Attribution: VulnCheck KEV, snapshot recorded in the file.
    """
    blob = json.load(open(path, encoding="utf-8"))
    out = set()
    for rec in blob["records"]:
        cves = rec.get("cve") or []
        for c in (cves if isinstance(cves, list) else [cves]):
            if c:
                out.add(c)
    return out, blob.get("_timestamp", "")


def in_kev(row):
    if WIDER is not None:
        return any(c.strip() in WIDER for c in (row.get("cves") or "").split(";")
                   if c.strip().startswith("CVE-"))
    return bool((row.get("kev_cves") or "").strip()) or \
        str(row.get("has_kev", "")).strip().lower() in ("1", "true", "yes")


def severity_of(row):
    try:
        return float(row.get("severity") or 0)
    except ValueError:
        return 0.0


def build_actions(rows, nvd=None):
    """Group findings into jobs.

    With `nvd`, the product comes from the affected product NVD publishes for the CVEs a
    finding cites -- a name neither scanner wrote -- and falls back to the parsed title only
    where no CVE is usable. Without it, the title is parsed as before. The first is what the
    correlation stage produces and what a plan spanning two scanners needs; the second is kept
    so every earlier number in `scans.md` can still be reproduced from this file.
    """
    key_of = ((lambda r: product_key(r, nvd)[0]) if nvd
              else (lambda r: product_of(r["nvt_name"])))
    grouped = collections.defaultdict(list)
    for r in rows:
        grouped[(r["host"], r.get("port", ""), key_of(r))].append(r)
    actions = []
    for key, members in grouped.items():
        actions.append({
            "key": key,
            "members": members,
            "tier": tier(members),
            "risk": sum(r["risk"] for r in members),
            "severity": max((severity_of(r) for r in members), default=0.0),
            "epss": max((r["likelihood"] if r["l_source"] == "epss" else 0.0)
                        for r in members),
            "kev": sum(1 for r in members if in_kev(r)),
            "size": len(members),
        })
    return actions


def plan(actions, order_key, budget, cost):
    """Greedy: take actions by the given key, value per unit cost, until the budget is out."""
    ranked = sorted(actions, key=lambda a: -(order_key(a) / cost[a["tier"]]))
    chosen, spent = [], 0.0
    for a in ranked:
        c = cost[a["tier"]]
        if spent + c > budget:
            continue
        chosen.append(a)
        spent += c
    return chosen, spent


def plan_ungrouped(actions, finding_key, budget, cost):
    """What a conventional pipeline hands over: a ranked list of findings, worked top down.

    Every tool in this space ranks findings. The analyst starts at the top and fixes them in
    order, and whichever action closes the finding at the top gets done first, whether or not
    that action is a good use of the budget. Other findings that the same action happens to
    close come along for free, so this baseline is credited with them; it simply does not get
    to choose on that basis.

    This is the comparison that isolates what the grouping is worth, because the score and
    the cost model are identical on both sides. Only the unit of ranking differs.
    """
    owner = {}
    for a in actions:
        for r in a["members"]:
            owner[id(r)] = a
    ranked = sorted((r for a in actions for r in a["members"]),
                    key=lambda r: -finding_key(r))
    chosen, spent, taken = [], 0.0, set()
    for r in ranked:
        a = owner[id(r)]
        if a["key"] in taken:
            continue
        c = cost[a["tier"]]
        if spent + c > budget:
            continue
        taken.add(a["key"])
        chosen.append(a)
        spent += c
    return chosen, spent


def report(actions, cost, kev_total, findings_total):
    total_cost = sum(cost[a["tier"]] for a in actions)
    # The first four rank actions; the last two rank findings and take whatever action sits
    # under the top one, which is what a tool that ranks findings leaves an analyst to do.
    orders = orderings(actions, cost)
    # Fine at the low end, because that is where a budget binds and where the orderings
    # separate on known-exploited findings, and out to the whole list, because that is
    # where the reachability filter starts to bite. An earlier version stopped at a tenth
    # and reported R = L x C as identical to EPSS at every budget; the two are identical
    # only while the budget is too small to reach the unreachable work.
    fractions = [0.01, 0.02, 0.03, 0.05, 0.10, 0.25, 0.50, 1.00]

    def table(title, value, of):
        print(f"\n  {title}")
        print(f"  {'ordering':14s} " + "  ".join(f"{int(f*100):>4d}%" for f in fractions))
        print("  " + "-" * (16 + 6 * len(fractions)))
        for name, select in orders.items():
            cells = []
            for f in fractions:
                cells.append(value(select(total_cost * f)))
            print(f"  {name:14s} " + "  ".join(f"{c:5.0f}" if isinstance(c, float)
                                               else f"{c:5d}" for c in cells))
        print(f"  out of {of}")

    table("known-exploited findings closed",
          lambda ch: sum(a["kev"] for a in ch), kev_total)
    # Risk removed, not findings closed. Counting findings makes `most findings` win by
    # construction, since that ordering optimises the metric directly; the quantity the
    # pipeline exists to reduce is exposure, and that is what this measures.
    total_risk = sum(a["risk"] for a in actions)
    table("risk removed, percent of the total",
          lambda ch: 100 * sum(a["risk"] for a in ch) / max(total_risk, 1e-9), "100%")
    table("findings closed",
          lambda ch: sum(a["size"] for a in ch), findings_total)
    # What the consequence term is for, and it is not the top of the list. An action whose
    # findings cannot reach the attacker's goal is work that buys no reduction in exposure,
    # and reachability is MulVAL's answer from the topology, not ours from the score, so
    # counting it against a score that ignores it is a fair question rather than a circular
    # one. R = L x C cannot buy these at all, since C = 0 sets their value to zero.
    unreachable = {a["key"] for a in actions if all(r["consequence"] == 0.0
                                                   for r in a["members"])}
    table(f"budget spent on unreachable work, of {len(unreachable)} such actions",
          lambda ch: sum(cost[a["tier"]] for a in ch if a["key"] in unreachable),
          f"{sum(cost[a['tier']] for a in actions if a['key'] in unreachable):g} cost units")
    kev_unreachable = sum(a["kev"] for a in actions if a["key"] in unreachable)
    print(f"\n  of {kev_total} known-exploited findings, {kev_unreachable} sit in work the "
          f"graph calls unreachable,")
    print("  so the filter discards "
          f"{sum(a['size'] for a in actions if a['key'] in unreachable)} of "
          f"{findings_total} findings without discarding any of them." if kev_unreachable == 0
          else f"  so the filter is not safe on this label and the claim must say so.")


def score(graph, topology_path, finding_paths, nvd=None):
    """Findings with a likelihood, a consequence and a risk, and the actions they group into.

    Pulled out of main so the figure script runs the same code the tables were printed from.
    A figure built from numbers retyped out of a terminal drifts from the pipeline the first
    time the pipeline changes, and nothing catches it.
    """
    topology = json.load(open(topology_path, encoding="utf-8"))
    vertices, edges = C.read_graph(graph)
    goals = C.goal_vertex(vertices, topology["goal"])
    dist = C.distances_to(goals, edges, vertices)
    leaves = C.finding_leaves(vertices)
    emitted = C.emitted_facts(graph)
    rows = C.load_findings(finding_paths, topology)
    epss = L.epss_lookup()

    # Consequence as an indicator, and likelihood from EPSS or the surrogate, exactly as
    # risk.py computes them.
    scored = [(r, L.target_for(r, epss)[0]) for r in rows]
    have = [(r, y) for r, y in scored if y is not None]
    missing = [r for r, y in scored if y is None]
    by_id = {}
    if missing:
        fitted = L.model().fit(L.build_matrix([r for r, _ in have]),
                               np.log10(np.maximum([y for _, y in have], L.FLOOR)))
        guessed = np.clip(10 ** fitted.predict(L.build_matrix(missing)), 0.0, 1.0)
        by_id = {id(r): v for r, v in zip(missing, guessed)}

    kept = []
    for r, y in scored:
        key = (r["atom"], r["vuln_id"])
        vid = leaves.get(key)
        if vid is None and emitted is not None and key not in emitted:
            continue
        reaches = vid is not None and dist.get(vid) is not None
        r["consequence"] = 1.0 if reaches else 0.0
        r["likelihood"] = float(y) if y is not None else float(by_id[id(r)])
        r["l_source"] = "epss" if y is not None else "surrogate"
        r["risk"] = r["likelihood"] * r["consequence"]
        # The properties the classification stage derived, carried through so the written
        # plan can explain itself. Same function the MulVAL input is built from, so the
        # explanation and the graph cannot disagree about a finding.
        if nvd:
            rng, cons = M.cvss_properties(r, nvd)
            r["range"], r["consequence_class"] = rng or "", cons or ""
        kept.append(r)
    return kept, build_actions(kept, nvd), topology


# -- Two published prioritisation methods, reproduced as action-level selectors so the budget
# comparison can include them. Each returns a single value that plan() takes greedily per unit
# remediation cost, exactly as for the severity and EPSS baselines. --

def ssvc_tier(a):
    """SSVC deployer-tree priority (Act=4, Attend=3, Track*=2, Track=1) from scan evidence only.

    Following Spring et al.'s decision tree, reduced to the inputs a scan carries: exploitation is
    active when any member is known-exploited, "poc" at an action EPSS of 0.10 or above, and none
    otherwise; technical impact is total at CVSS severity 7 or above, partial below. The
    Automatable and Mission/Well-being points need information a scan does not supply and are held
    constant. 0.10 and 7 are declared parameters.
    """
    expl = 2 if a["kev"] > 0 else (1 if a["epss"] >= 0.10 else 0)
    total = a["severity"] >= 7.0
    if expl == 2 and total:
        return 4
    if expl == 2 or (expl == 1 and total):
        return 3
    if expl == 1 or total:
        return 2
    return 1


VMC_EPSS_GATE = 0.088   # the exploit-probability gate of Shimizu and Hashimoto's VMC
VMC_SEV_GATE = 7.0      # and its CVSS action threshold


def vmc_tier(a, use_kev=True):
    """Vulnerability Management Chaining priority, as its paper specifies it.

    VMC filters first by threat and then by severity: a finding is acted on when it is known to be
    exploited or its exploit probability clears a gate (EPSS >= 0.088), and its CVSS base score is
    high (>= 7.0). The tiers are: both gates met (2), the threat gate only (1), and neither (0).
    The ``use_kev`` switch is the paper's two configurations -- the full threat gate, and the
    EPSS-only gate that drops the known-exploited term. Either way the gate needs a CVE to carry an
    EPSS or KEV record, so an uncatalogued finding can never leave tier 0: VMC cannot prioritize it.
    """
    threat = (use_kev and a["kev"] > 0) or (a["epss"] >= VMC_EPSS_GATE)
    if not threat:
        return 0
    return 2 if a["severity"] >= VMC_SEV_GATE else 1


def vmc_value(a, use_kev=True):
    # 100**tier so the gate structure dominates the per-cost division plan() applies, with CVSS
    # ordering findings inside a tier, as the paper sorts by severity after the gate.
    return 100.0 ** vmc_tier(a, use_kev) + a["severity"]


def orderings(actions, cost):
    """The selectors the evaluation compares, as {name: select(budget) -> actions}.

    Shared with the figure script so a curve drawn and a row printed cannot disagree.
    """
    return {
        "R = L x C": lambda b: plan(actions, lambda a: a["risk"], b, cost)[0],
        "SSVC": lambda b: plan(actions, lambda a: float(10 ** ssvc_tier(a)), b, cost)[0],
        "VMC (full)": lambda b: plan(actions, lambda a: vmc_value(a, True), b, cost)[0],
        "VMC (EPSS gate)": lambda b: plan(actions, lambda a: vmc_value(a, False), b, cost)[0],
        "severity": lambda b: plan(actions, lambda a: a["severity"], b, cost)[0],
        "EPSS": lambda b: plan(actions, lambda a: a["epss"], b, cost)[0],
        "most findings": lambda b: plan(actions, lambda a: a["size"], b, cost)[0],
        "ungrouped R": lambda b: plan_ungrouped(actions, lambda r: r["risk"], b, cost)[0],
        "ungrouped sev": lambda b: plan_ungrouped(
            actions, lambda r: severity_of(r), b, cost)[0],
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--graph", required=True, metavar="DIR")
    ap.add_argument("--topology", required=True, metavar="JSON")
    ap.add_argument("--findings", required=True, action="append", metavar="CSV")
    ap.add_argument("--weights", default="1,2,5", metavar="P,C,R",
                    help="cost of a patch, a configuration change and a replacement")
    ap.add_argument("--correlate", nargs="?", const=os.path.join(HERE, "cwe_map.json"),
                    metavar="JSON",
                    help="group actions on NVD's affected product rather than on the "
                         "scanner's check title; required for a plan spanning two scanners")
    ap.add_argument("--tier-fallback", choices=("patch", "config", "replace"),
                    default="config",
                    help="what an action costs when no member states a solution type")
    ap.add_argument("--vulncheck", nargs="?", const=os.path.join(HERE, "vulncheck_kev.json"),
                    metavar="JSON",
                    help="grade against VulnCheck KEV instead of the registered CISA label")
    ap.add_argument("--sweep", action="store_true",
                    help="repeat across several weightings and show whether they matter")
    ap.add_argument("-o", "--out", metavar="CSV", help="write the ordered plan here")
    args = ap.parse_args()

    globals()["FALLBACK"] = args.tier_fallback
    nvd = None
    if args.correlate:
        nvd = json.load(open(args.correlate, encoding="utf-8"))
        nvd = nvd.get("cves", nvd)
        print(f"grouping          : NVD affected product, {len(nvd)} CVEs cached")

    if args.vulncheck:
        global WIDER
        WIDER, stamp = load_vulncheck(args.vulncheck)
        print(f"label             : VulnCheck KEV, {len(WIDER)} CVEs, snapshot {stamp[:10]}")
        print(f"                    secondary; CISA KEV remains the registered label\n")

    kept, actions, topology = score(args.graph, args.topology, args.findings, nvd)

    scanners = collections.Counter(r.get("scanner", "") for r in kept)
    if len(scanners) > 1:
        print("scanners          : " + ", ".join(f"{k} {v}" for k, v in scanners.most_common()))
    untiered = sum(1 for a in actions
                   if not any(TIER_OF.get(r.get("solution_type", ""), "")
                              for r in a["members"]))
    if untiered:
        print(f"untiered actions  : {untiered} of {len(actions)} state no solution type "
              f"and fall back to `{args.tier_fallback}`")

    kev_total = sum(1 for r in kept if in_kev(r))
    weights = [float(x) for x in args.weights.split(",")]
    cost = dict(zip((PATCH, CONFIG, REPLACE), weights))

    print(f"findings          : {len(kept)} on {len(topology['hosts'])} hosts")
    print(f"actions           : {len(actions)}, {len(kept)/len(actions):.2f} findings each")
    tiers = collections.Counter(a["tier"] for a in actions)
    for t in (PATCH, CONFIG, REPLACE):
        print(f"    {tiers.get(t, 0):4d}  {t:22s} cost {cost[t]:g}")
    print(f"known exploited   : {kev_total} findings, the label this is graded against")
    print(f"total cost        : {sum(cost[a['tier']] for a in actions):g} units\n")

    if kev_total == 0:
        print("No finding here is in KEV, so the orderings cannot be graded. Report the")
        print("plan and claim nothing about its quality.")
    else:
        report(actions, cost, kev_total, len(kept))

    if args.sweep:
        # A budget expressed as a fraction of the total moves when the weights move,
        # because the total is computed from them. Holding the number of actions fixed
        # instead asks the question the sweep is for: does the weighting change which
        # fixes get chosen, not how many.
        print("\nacross weightings, holding the plan at 6 actions:")
        for w in ("1,1,1", "1,2,5", "1,3,10", "1,5,20"):
            c = dict(zip((PATCH, CONFIG, REPLACE), [float(x) for x in w.split(",")]))
            ranked = sorted(actions, key=lambda a: -(a["risk"] / c[a["tier"]]))[:6]
            keys = {a["key"] for a in ranked}
            print(f"  weights {w:9s} {sum(a['kev'] for a in ranked)} of {kev_total} "
                  f"known-exploited, {sum(a['size'] for a in ranked):3d} findings, "
                  f"cost {sum(c[a['tier']] for a in ranked):5.1f}")
            if w == "1,1,1":
                base = keys
            elif keys != base:
                print(f"    {len(keys - base)} of 6 differ from the unweighted plan")

    if args.out:
        total_cost = sum(cost[a["tier"]] for a in actions)
        ordered = sorted(actions, key=lambda a: -(a["risk"] / cost[a["tier"]]))
        # Everything after `risk_removed` is already computed upstream and was being thrown
        # away at the last step. A plan that says only what to do can be obeyed or ignored;
        # one that says why can be argued with, and an analyst who disagrees with the order
        # is a better outcome than one who cannot tell whether to.
        with open(args.out, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["rank", "host", "port", "product", "tier", "cost",
                        "findings_closed", "known_exploited", "risk_removed",
                        "cumulative_cost", "remote_exploit", "priv_escalation",
                        "reaches_goal", "likelihood_from", "scanners", "top_finding"])
            spent = 0.0
            for i, a in enumerate(ordered, 1):
                spent += cost[a["tier"]]
                members = a["members"]
                remote = sum(1 for r in members
                             if (r.get("range") or "") == "remoteExploit")
                privesc = sum(1 for r in members
                              if (r.get("consequence_class") or "") == "privEscalation")
                reaches = sum(1 for r in members if r.get("consequence") == 1.0)
                sources = collections.Counter(r.get("l_source", "") for r in members)
                tools = sorted({r.get("scanner", "") for r in members if r.get("scanner")})
                worst = max(members, key=lambda r: r.get("risk", 0.0))
                w.writerow([i, a["key"][0], a["key"][1], a["key"][2], a["tier"],
                            f"{cost[a['tier']]:g}", a["size"], a["kev"],
                            f"{a['risk']:.4f}", f"{spent:g}",
                            remote if remote else "",
                            privesc if privesc else "",
                            f"{reaches}/{a['size']}",
                            "+".join(f"{k} {v}" for k, v in sources.most_common() if k),
                            "+".join(tools),
                            worst["nvt_name"][:70]])
        print(f"\nwrote {args.out}: {len(ordered)} actions, "
              f"{total_cost:g} cost units in total")
        print("  columns after risk_removed explain the ranking rather than state it: how "
              "many\n  of the findings are remotely reachable, how many grant code "
              "execution, how many\n  reach the goal, where the likelihood came from, and "
              "which tools saw it.")


if __name__ == "__main__":
    main()
