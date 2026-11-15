#!/usr/bin/env python3
"""R = L x C, ranked, and compared against the orderings it has to beat.

The first script that runs the pipeline end to end. It takes exploit likelihood from
likelihood.py and attack consequence from consequence.py, multiplies them, and asks the
only question that matters for a prioritisation method: does the resulting order put the
findings that matter higher than the orders an analyst already has for free?

WHAT COUNTS AS BETTER, AND WHO DECIDES

CISA KEV. A finding whose CVE appears in the Known Exploited Vulnerabilities catalogue is
one that someone has been observed exploiting in the wild. That judgement is made outside
this project, which is the point: a ranking graded against a metric the project invented
would prove nothing. KEV is the label here and is never a feature; nothing upstream of this
file may read it.

THE BASELINES

    severity        sort by the CVSS base score the scanner already prints
    EPSS            sort by the published exploit probability, where one exists
    L alone         the likelihood head with no consequence, to isolate what C contributes

A method that cannot beat sorting by severity has not earned the pipeline in front of it.
Reporting the comparison is therefore not optional, and a loss is a result.

HOW THE ORDERS ARE COMPARED

Precision at k, for small k, because the output is a remediation plan under a budget and
what matters is what reaches the top of a short list. Also the rank of the first KEV
finding, which answers a blunter question: how far down does an analyst read before
reaching something known to be exploited?

WHY C IS AN INDICATOR AND NOT A DISTANCE

The first version of this used C = 1/d, the derivation distance to the goal. Measured on
the three-tier lab that takes exactly one value per host, so multiplying by it sorted hosts:
every database finding was boosted fivefold over every web finding, the top of the ranking
filled with MySQL findings that nobody has ever been observed exploiting, and precision at
five fell from 0.60 to 0.00 against likelihood alone.

The cause is visible in the graph. Its 188 rules derive only 9 distinct facts: code
execution at two privilege levels on each of three hosts, and network access to each. Every
finding that leads anywhere leads to one of those nine, so no per-finding ordering can be
recovered from the structure, and removing any single fix leaves the rest deriving the same
nine.

What the graph does support is the distinction it was built to make: whether the goal
follows from this finding at all. C is therefore 1 or 0, which keeps R = L x C exactly as
written while using only what was measured. The distance was our invention; reachability is
the graph's own answer.

WHAT L IS FOR A FINDING WITH NO CVE

Measured, and the measurement is not flattering. The learned surrogate reaches Spearman
0.418 against held-out EPSS under a CVE-grouped split, while the severity column alone
reaches 0.492. The registered condition was that the surrogate must clear 0.3 **and** beat
the baselines; it failed the second. `--surrogate severity` is therefore the default, and
`--surrogate model` is offered so the difference in the final ranking can be reported
rather than assumed.

    python3 risk.py --graph ~/mulval/testcases/lab3 \\
                    --topology topology_lab3.json \\
                    --findings processed/findings_openvas_b2.csv
"""

import argparse
import csv
import json
import os
import sys

import numpy as np

import consequence as C
import likelihood as L

HERE = os.path.dirname(os.path.abspath(__file__))


def kev_set(rows):
    """Findings whose CVEs appear in CISA KEV, taken from the parser's own column."""
    out = set()
    for i, r in enumerate(rows):
        flag = str(r.get("has_kev", "")).strip().lower()
        if flag in ("1", "true", "yes") or (r.get("kev_cves") or "").strip():
            out.add(i)
    return out


def severity_of(row):
    try:
        return float(row.get("severity") or 0)
    except ValueError:
        return 0.0


def precision_at(order, positives, k):
    top = order[:k]
    return sum(1 for i in top if i in positives) / max(1, len(top))


def first_hit(order, positives):
    for rank, i in enumerate(order, 1):
        if i in positives:
            return rank
    return None


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--graph", required=True, metavar="DIR")
    ap.add_argument("--topology", required=True, metavar="JSON")
    ap.add_argument("--findings", required=True, action="append", metavar="CSV")
    ap.add_argument("--consequence", choices=("binary", "distance"), default="binary",
                    help="binary: C is 1 when the goal is derivable from the finding and 0 "
                         "otherwise. distance: C = 1/d, kept so the two can be compared")
    ap.add_argument("--surrogate", choices=("severity", "scaled", "model"),
                    default="scaled",
                    help="how a finding with no published EPSS gets its likelihood")
    ap.add_argument("-o", "--out", metavar="CSV", help="write the ranked plan here")
    args = ap.parse_args()

    topology = json.load(open(args.topology, encoding="utf-8"))
    vertices, edges = C.read_graph(args.graph)
    goals = C.goal_vertex(vertices, topology["goal"])
    dist = C.distances_to(goals, edges, vertices)
    leaves = C.finding_leaves(vertices)
    emitted = C.emitted_facts(args.graph)
    rows = C.load_findings(args.findings, topology)

    epss = L.epss_lookup()

    # Consequence, exactly as consequence.py computes it.
    kept = []
    for r in rows:
        key = (r["atom"], r["vuln_id"])
        vid = leaves.get(key)
        if vid is None:
            if emitted is not None and key not in emitted:
                continue
            reach, d = False, None
        else:
            d = dist.get(vid)
            reach = d is not None
        r["reaches"] = reach
        r["consequence"] = ((1.0 if reach else 0.0) if args.consequence == "binary"
                            else (1.0 / d if reach else 0.0))
        kept.append(r)

    # Likelihood. EPSS where it exists; otherwise whichever surrogate was asked for.
    scored = [(r, L.target_for(r, epss)[0]) for r in kept]
    have = [(r, y) for r, y in scored if y is not None]
    missing = [r for r, y in scored if y is None]

    if args.surrogate == "model" and missing:
        fitted = L.model().fit(
            L.build_matrix([r for r, _ in have]),
            np.log10(np.maximum([y for _, y in have], L.FLOOR)))
        guessed = np.clip(10 ** fitted.predict(L.build_matrix(missing)), 0.0, 1.0)
    elif args.surrogate == "severity":
        # Dividing by ten puts severity in [0,1] but not on the EPSS scale: measured here,
        # severity/10 has median 0.50 against a real EPSS median of 0.136. Findings scored
        # this way are then four times overvalued against every finding holding a published
        # score, and they crowd the top of a list they should not reach. Kept only so the
        # difference can be reported.
        guessed = np.array([severity_of(r) / 10.0 for r in missing])
    else:
        # Rank mapping. A finding's severity percentile among all findings is read off as
        # the EPSS value at that same percentile among the findings that have one, so the
        # ordering severity gives is preserved while the scale becomes the one the rest of
        # the list is on. No model, and nothing fitted.
        known = np.sort(np.array([y for _, y in have], dtype=float))
        all_sev = np.sort(np.array([severity_of(r) for r, _ in scored], dtype=float))
        guessed = np.array([
            known[min(len(known) - 1,
                      int(np.searchsorted(all_sev, severity_of(r)) / max(1, len(all_sev))
                          * len(known)))]
            for r in missing])

    by_id = {id(r): v for r, v in zip(missing, guessed)}
    for r, y in scored:
        r["likelihood"] = float(y) if y is not None else float(by_id[id(r)])
        r["risk"] = r["likelihood"] * r["consequence"]
        r["l_source"] = "epss" if y is not None else args.surrogate

    positives = kev_set(kept)
    print(f"findings          : {len(kept)} on {len(topology['hosts'])} hosts")
    print(f"  known exploited : {len(positives)} in CISA KEV, the label for this comparison")
    print(f"  likelihood from : {sum(1 for r in kept if r['l_source'] == 'epss')} EPSS, "
          f"{len(missing)} {args.surrogate}")
    print(f"  consequence     : {args.consequence}, "
          f"{sum(1 for r in kept if r['consequence'] == 0)} findings scored zero and drop "
          f"out of the plan\n")

    def table(scope_idx, title, note):
        """Precision at k over one scope, with the orderings recomputed inside it.

        The scope has to be applied before ranking, not after. Ranking the whole list and
        then counting hits among a subset would let findings outside the scope push scoped
        findings down the list, which is the exact effect being controlled for.
        """
        pos = {i for i in scope_idx if i in positives}
        print(f"\n{title}")
        print(f"  {note}")
        if not pos:
            print("  no finding in this scope is in KEV, so there is nothing to grade "
                  "against here")
            return
        orders = {
            "R = L x C": sorted(scope_idx, key=lambda i: -kept[i]["risk"]),
            "L alone": sorted(scope_idx, key=lambda i: -kept[i]["likelihood"]),
            "severity": sorted(scope_idx, key=lambda i: -severity_of(kept[i])),
            "EPSS only": sorted(scope_idx,
                                key=lambda i: -(L.target_for(kept[i], epss)[0] or 0.0)),
        }
        ks = [k for k in (5, 10, 20, 50) if k <= len(scope_idx)]
        print(f"  {'ordering':12s} " + "  ".join(f"P@{k}" for k in ks) + "   first KEV")
        print("  " + "-" * (14 + 6 * len(ks) + 12))
        for name, order in orders.items():
            cells = "  ".join(f"{precision_at(order, pos, k):.2f}" for k in ks)
            print(f"  {name:12s} {cells}   {first_hit(order, pos)}")

    everything = list(range(len(kept)))
    with_cve = [i for i in everything if L.target_for(kept[i], epss)[0] is not None]
    without = [i for i in everything if i not in set(with_cve)]

    table(with_cve, f"SCOPED TO THE {len(with_cve)} FINDINGS THAT CARRY A CVE",
          "the only scope KEV can grade: a finding with no CVE can never appear in it, "
          "so\n  including one is a free negative for any method that ranks it low")
    table(everything, f"THE WHOLE LIST, ALL {len(everything)} FINDINGS",
          "reported for contrast only. Do not choose between methods on this number.")

    print(f"\nCOVERAGE, which needs no label at all")
    print(f"  EPSS can score      {len(with_cve)}/{len(kept)} "
          f"({100*len(with_cve)/len(kept):.1f}%)")
    print(f"  ThreatRank scores   {len(kept)}/{len(kept)} (100.0%)")
    if without:
        print(f"  the {len(without)} EPSS cannot score, by severity:")
        for i in sorted(without, key=lambda i: -severity_of(kept[i]))[:5]:
            print(f"    {severity_of(kept[i]):4.1f}  {kept[i]['nvt_name'][:60]}")

    print("\n  P@k is the share of the top k that CISA has observed being exploited.")
    print("  first KEV is how far an analyst reads before meeting one.")

    if args.out:
        order = sorted(range(len(kept)), key=lambda i: -kept[i]["risk"])
        with open(args.out, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["rank", "host", "nvt_name", "likelihood", "l_source",
                        "consequence", "risk", "in_kev"])
            for rank, i in enumerate(order, 1):
                r = kept[i]
                w.writerow([rank, r["host"], r["nvt_name"], f"{r['likelihood']:.6f}",
                            r["l_source"], f"{r['consequence']:.4f}", f"{r['risk']:.6f}",
                            int(i in positives)])
        print(f"\nwrote {args.out}")


if __name__ == "__main__":
    main()
