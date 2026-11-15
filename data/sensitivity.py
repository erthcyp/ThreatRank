#!/usr/bin/env python3
"""How much do the surrogate's likelihoods move the remediation plan?

The surrogate exists for findings that have no published EPSS score, and the one question its
accuracy figures cannot answer is whether its values change what gets fixed. No label exists for
those findings, so this does not ask whether the values are right. It asks whether they matter:
the surrogate's value for every finding without an EPSS score is replaced by an alternative that
uses no learning, the plan is rebuilt with everything else held fixed, and the result is compared
with the plan the pipeline actually produces.

Alternatives, each applied only to the findings the surrogate scores:

    surrogate     what the pipeline does; the reference plan
    median        the median published EPSS of the findings that have one
    severity      the scanner's CVSS base score divided by ten
    zero          as if the finding had no likelihood at all (lower bound)
    one           as if every such finding were certain to be exploited (upper bound)
    shuffled      the surrogate's own values, permuted among the same findings (seed 0)

Graded at the budgets the paper reports, on the ordering R = L x C, by three quantities:

    KEV closed        CISA KEV findings inside the chosen actions; external label
    plan overlap      Jaccard similarity of the chosen actions with the reference plan
    exposure removed  share of the REFERENCE plan's exposure the alternative plan removes, so
                      every alternative is scored on one common scale

Registered before the first run, 15 November 2026: the plan is called INSENSITIVE to the
surrogate if, at every budget up to 10 per cent, every alternative closes the same number of KEV
findings as the reference and its plan overlaps the reference by a Jaccard of at least 0.80.
Anything else is reported as SENSITIVE, with the budgets and alternatives where it differs.

    python3 sensitivity.py --graph ../mulval/cases/lab3/out --topology topology_lab3.json \\
        --findings processed/findings_openvas_b2.csv
"""

import argparse
import json
import os
import statistics

import numpy as np

import prioritise as P

HERE = os.path.dirname(os.path.abspath(__file__))
BUDGETS = [0.01, 0.02, 0.03, 0.05, 0.10, 0.25]
JACCARD_MIN = 0.80
REGISTERED_UP_TO = 0.10


def variants(kept):
    """{name: {id(row): likelihood}} for every row the surrogate scores."""
    sur = [r for r in kept if r["l_source"] == "surrogate"]
    epss = [r["likelihood"] for r in kept if r["l_source"] == "epss"]
    med = statistics.median(epss) if epss else 0.0
    own = [r["likelihood"] for r in sur]
    rng = np.random.default_rng(0)
    perm = list(rng.permutation(own)) if own else []
    return {
        "surrogate": {id(r): r["likelihood"] for r in sur},
        "median": {id(r): med for r in sur},
        "severity": {id(r): min(max(P.severity_of(r) / 10.0, 0.0), 1.0) for r in sur},
        "zero": {id(r): 0.0 for r in sur},
        "one": {id(r): 1.0 for r in sur},
        "shuffled": {id(r): float(v) for r, v in zip(sur, perm)},
    }


def rebuild(kept, values):
    """Actions with the surrogate's values swapped for `values`; every other input unchanged."""
    rows = []
    for r in kept:
        s = dict(r)
        if id(r) in values:
            s["likelihood"] = values[id(r)]
        s["risk"] = s["likelihood"] * s["consequence"]
        s["_ref"] = r["risk"]
        rows.append(s)
    return P.build_actions(rows)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--graph", required=True, metavar="DIR")
    ap.add_argument("--topology", required=True, metavar="JSON")
    ap.add_argument("--findings", required=True, action="append", metavar="CSV")
    ap.add_argument("--weights", default="1,2,5", metavar="P,C,R")
    ap.add_argument("-o", "--out", metavar="JSON",
                    default=os.path.join(HERE, "figures", "sensitivity.json"))
    args = ap.parse_args()

    kept, actions, _topology = P.score(args.graph, args.topology, args.findings)
    cost = dict(zip((P.PATCH, P.CONFIG, P.REPLACE),
                    [float(x) for x in args.weights.split(",")]))
    total_cost = sum(cost[a["tier"]] for a in actions)

    sur = [r for r in kept if r["l_source"] == "surrogate"]
    on_path = [r for r in sur if r["consequence"] > 0]
    touched = [a for a in actions if any(r["l_source"] == "surrogate" for r in a["members"])]
    only = [a for a in touched if all(r["l_source"] == "surrogate" for r in a["members"])]
    print(f"findings          : {len(kept)}, of which {len(sur)} are scored by the surrogate "
          f"({len(on_path)} on a path to the goal)")
    print(f"actions           : {len(actions)}; {len(touched)} contain a surrogate-scored "
          f"finding, {len(only)} contain nothing else")
    print(f"known exploited   : {sum(a['kev'] for a in actions)}")
    print(f"budgets           : {', '.join(f'{int(b*100)}%' for b in BUDGETS)} of "
          f"{total_cost:g} cost units\n")

    vals = variants(kept)
    ref_total = sum(r["risk"] for r in kept) or 1e-9
    ref_plans = {}
    results = {}
    for name, values in vals.items():
        acts = rebuild(kept, values)
        rows = []
        for b in BUDGETS:
            chosen, _spent = P.plan(acts, lambda a: a["risk"], total_cost * b, cost)
            keys = {a["key"] for a in chosen}
            if name == "surrogate":
                ref_plans[b] = keys
            ref = ref_plans[b]
            jac = len(keys & ref) / len(keys | ref) if keys | ref else 1.0
            exposure = sum(m["_ref"] for a in chosen for m in a["members"]) / ref_total
            rows.append({"budget": b, "kev": sum(a["kev"] for a in chosen),
                         "jaccard": round(jac, 3), "exposure": round(100 * exposure, 1)})
        results[name] = rows

    for title, field, fmt in (("KEV closed", "kev", "{:5d}"),
                              ("plan overlap with the reference (Jaccard)", "jaccard", "{:5.2f}"),
                              ("exposure removed, % of the reference total", "exposure",
                               "{:5.1f}")):
        print(f"  {title}")
        print(f"  {'likelihood':12s}" + "".join(f"{int(b*100):>6d}%" for b in BUDGETS))
        print("  " + "-" * (12 + 7 * len(BUDGETS)))
        for name, rows in results.items():
            print(f"  {name:12s}" + "".join(" " + fmt.format(r[field]).rjust(6) for r in rows))
        print()

    ref_kev = {r["budget"]: r["kev"] for r in results["surrogate"]}
    breaches = [(name, r["budget"]) for name, rows in results.items() if name != "surrogate"
                for r in rows if r["budget"] <= REGISTERED_UP_TO
                and (r["kev"] != ref_kev[r["budget"]] or r["jaccard"] < JACCARD_MIN)]
    if not breaches:
        verdict = "INSENSITIVE"
        print(f"VERDICT: INSENSITIVE. Up to a {int(REGISTERED_UP_TO*100)}% budget, every "
              f"alternative closes the same KEV findings and overlaps the plan by at least "
              f"{JACCARD_MIN:.2f}. On this corpus the surrogate's values do not change what is "
              f"fixed; its role is to give those findings a value, not to reorder the plan.")
    else:
        verdict = "SENSITIVE"
        where = ", ".join(f"{n} at {int(b*100)}%" for n, b in breaches)
        print(f"VERDICT: SENSITIVE. The registered condition fails for: {where}.")

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    json.dump({"verdict": verdict, "surrogate_findings": len(sur),
               "surrogate_on_path": len(on_path), "actions": len(actions),
               "actions_touched": len(touched), "actions_surrogate_only": len(only),
               "results": results}, open(args.out, "w", encoding="utf-8"), indent=1)
    print(f"  wrote {args.out}")


if __name__ == "__main__":
    main()
