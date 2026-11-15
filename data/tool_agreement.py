#!/usr/bin/env python3
"""How much two scanners agree about the same host, measured three ways.

The advisor's second question on Deliverable 2 was what happens when two tools report the
same underlying weakness. The paper answered it by design, merge before scoring, and the
answer was argued rather than shown, because only two of eleven hosts had been scanned by
both tools. This measures it on nine.

MATCHING ON CVE ALONE UNDERSTATES AGREEMENT

A finding is not a CVE. OpenVAS may list ten CVEs against one Apache check where Nessus
lists two for the same flaw, so counting shared CVEs counts the vendors' citation habits as
much as their findings. Three views are therefore reported:

  by CVE          shared CVE identifiers. The strictest, and the one that flatters neither
                  tool
  by product      the same software named on the same host and port. What a remediation
                  action is grouped by, so this is the view that decides whether two tools
                  produce one job or two
  by host         whether both tools found anything at all on the machine

The middle one is the number that matters for this pipeline, because the plan is a list of
actions and an action is a product on a host.

    python3 tool_agreement.py --openvas processed/findings_openvas_a2.csv \\
                              --nessus  processed/findings_nessus_a2.csv
"""

import argparse
import collections
import csv
import json
import os
import sys

from correlate import product_key
from fix_actions import product_of

HERE = os.path.dirname(os.path.abspath(__file__))


def load(paths):
    """Non-Log findings, deduplicated on (host, title), from one or more CSVs."""
    rows, seen = [], set()
    for path in paths:
        with open(path, encoding="utf-8") as fh:
            for r in csv.DictReader(fh):
                if r.get("threat") == "Log":
                    continue
                key = (r["host"], r["nvt_name"])
                if key in seen:
                    continue
                seen.add(key)
                rows.append(r)
    return rows


def cves(rows):
    return {c.strip() for r in rows
            for c in (r.get("cves") or "").split(";")
            if c.strip().startswith("CVE-")}


def products(rows, nvd=None):
    """(host, port, product), keyed the way the correlation stage keys a remediation action.

    With NVD's affected-product data the key is `vendor:product`, which neither vendor wrote;
    without it the key falls back to a product parsed out of the check title. Both are
    reported, because the difference between them is the measurement: an overlap computed on
    parsed titles cannot separate two tools that disagree from two tools that describe the
    same thing in different words.
    """
    if nvd is None:
        return {(r["host"], r.get("port", ""), product_of(r["nvt_name"])) for r in rows}
    return {(r["host"], r.get("port", ""), product_key(r, nvd)[0]) for r in rows}


def jaccard(a, b):
    return len(a & b) / len(a | b) if (a | b) else 0.0


def line(label, a, b):
    print(f"  {label:14s} {len(a):5d} {len(b):6d} {len(a & b):6d} "
          f"{len(a - b):7d} {len(b - a):7d} {100*jaccard(a, b):7.1f}%")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--openvas", required=True, action="append", metavar="CSV")
    ap.add_argument("--nessus", required=True, action="append", metavar="CSV")
    args = ap.parse_args()

    ov, ne = load(args.openvas), load(args.nessus)
    hosts = sorted({r["host"] for r in ov} | {r["host"] for r in ne})
    shared = sorted({r["host"] for r in ov} & {r["host"] for r in ne})
    if not shared:
        sys.exit("the two inputs share no host, so there is nothing to compare. This "
                 "refusal exists because a stale file once compared two different machines.")

    # Resolved before anything is printed, so every view below is keyed the same way.
    nvd_path = os.path.join(HERE, "cwe_map.json")
    nvd = json.load(open(nvd_path, encoding="utf-8")) if os.path.exists(nvd_path) else {}
    key = nvd if any(v.get("cpes") for v in nvd.values()) else None

    print(f"hosts             : {len(hosts)}, both tools reached {len(shared)}")
    print(f"findings          : OpenVAS {len(ov)}, Nessus {len(ne)}, Log excluded\n")

    print(f"  {'view':14s} {'openvas':>5} {'nessus':>6} {'both':>6} "
          f"{'ov only':>7} {'ne only':>7} {'overlap':>8}")
    print("  " + "-" * 60)
    line("by CVE", cves(ov), cves(ne))
    line("by product, title", products(ov), products(ne))
    if key:
        line("by product, NVD", products(ov, key), products(ne, key))
    else:
        print("  (no affected-product data cached; run fetch_labels.py --cwe)")
    line("by host", {r["host"] for r in ov}, {r["host"] for r in ne})

    print("\n  overlap is the Jaccard index: agreed over everything either tool reported\n")

    print(f"  {'host':16s} {'openvas':>8} {'nessus':>7} {'products both':>14}")
    for h in shared:
        o = [r for r in ov if r["host"] == h]
        n = [r for r in ne if r["host"] == h]
        both = len(products(o, key) & products(n, key))
        print(f"  {h:16s} {len(o):8d} {len(n):7d} {both:14d}")

    # The claim the pipeline rests on: a weakness seen by both tools must become one action
    # rather than two, and the size of that effect is the number of shared products.
    overlap_products = products(ov, key) & products(ne, key)
    union_products = products(ov, key) | products(ne, key)
    print(f"\n  a plan built from one tool alone would contain "
          f"{len(products(ov))} or {len(products(ne))} actions.")
    print(f"  built from both and merged, it contains {len(union_products)}, not "
          f"{len(products(ov)) + len(products(ne))},")
    print(f"  because {len(overlap_products)} products are reported by both and are one job.")

    if overlap_products:
        print("\n  reported by both:")
        for host, port, prod in sorted(overlap_products)[:10]:
            print(f"    {host:16s} {port:10s} {prod[:40]}")


if __name__ == "__main__":
    main()
