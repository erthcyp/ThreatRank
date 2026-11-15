#!/usr/bin/env python3
"""One job per component, however many tools and checks reported it.

The stage between parsing and scoring, and the one the advisor asked about: when two tools
report the same weakness, what happens? The design said merge before scoring. This is the
merge, and the question it turns on is what counts as "the same".

WHY THE SCANNER'S TITLE CANNOT BE THE KEY

Actions were keyed on a product parsed out of the check title with a regex. Titles are prose
written by each vendor, so that key fails in both directions:

    within one tool   `php` and `php 5.x` became two jobs on the same host and port, and the
                      remediation plan listed "patch Apache" twice, once as `apache http
                      server` and once as `apache http server options memory leak
                      vulnerability (optionsbleed)`
    across two tools  of 138 product keys over nine hosts scanned by both, three matched

The second number reads as two scanners that agree about almost nothing. Some of that
disagreement is real -- on one host OpenVAS identified the web server and Nessus identified
the language runtime behind it, and neither saw the other -- but some of it is our regex
reading someone else's sentence.

THE KEY USED HERE

Both tools cite CVE identifiers, and NVD states which products each CVE affects. Routing
through that gives a key neither vendor wrote:

    finding -> its CVEs -> NVD's affected products -> `vendor:product`

Versions are dropped, because the fix is an upgrade of one component and carrying `5.6.40`
would fragment the job by the versions the upgrade removes.

WHAT HAS NO SUCH KEY

A finding citing no CVE has no route into NVD, and 35 of 410 in this corpus cite none. Those
keep the parsed title, and are marked `title` in the output so that every number computed
downstream can be split by how its key was derived. Findings without a CVE are already the
hard case for scoring; that they are also the hard case for grouping is worth stating rather
than hiding behind a single merged count.

    python3 correlate.py --findings processed/findings_openvas_b2.csv -o processed/canon_b2.csv
"""

import argparse
import collections
import csv
import json
import os
import sys

from fix_actions import product_of
from parse_openvas import CSV_FIELDS

HERE = os.path.dirname(os.path.abspath(__file__))
EXTRA = ["canon_key", "key_source", "canon_members", "canon_scanners"]

# Above this many affected products, a CVE is naming a class of systems and not a product.
# Swept rather than asserted: --max-products reports how the grouping moves with it.
MAX_PRODUCTS = 20


def cve_list(row):
    return [c.strip() for c in (row.get("cves") or "").split(";")
            if c.strip().startswith("CVE-")]


def product_key(row, nvd):
    """`vendor:product` from NVD where a CVE allows it, else the parsed title.

    A finding may cite several CVEs naming several products. The one cited by the most of
    them wins, which keeps a check about Apache from being filed under a library Apache
    happens to bundle, and ties break alphabetically so the choice does not depend on the
    order the scanner listed them in.

    Applications outrank operating systems absolutely, not by count. NVD lists the platform
    a vulnerable application runs on beside the application itself, and on this corpus the
    platform is cited more often: a first version of this function counted all parts equally
    and produced a remediation group called `debian:debian_linux` on port 80, holding 26
    Apache findings. Nobody can do that job. An operating system becomes the key only when
    no application is named at all, which is right for a kernel or a base-image finding.

    Among applications, a product the check's own title names beats one it does not, and
    only then does citation count decide. Counting alone gave `netapp:active_iq_unified_
    manager` eleven findings on the MySQL host: NetApp ships MySQL inside several products,
    so every MySQL CVE lists each of them, and the bundler outvotes the thing that is
    actually installed. NVD is authoritative about which products a CVE touches and says
    nothing about which one this scanner looked at; the title says exactly that and is
    unreliable on its own. Used together, each supplies what the other lacks.
    """
    by_part = collections.defaultdict(collections.Counter)
    for cve in cve_list(row):
        cpes = nvd.get(cve, {}).get("cpes") or []
        # A CVE naming this many products is describing a class of systems rather than a
        # product. CVE-1999-0524, the ICMP timestamp disclosure, lists every operating
        # system that answers an ICMP request, and taking its most-cited entry filed six of
        # nine Linux hosts under `apple:mac_os_x`. This is the mirror of the rule already
        # applied to findings: one that cites too many CVEs is treated as generic.
        if len(cpes) > MAX_PRODUCTS:
            continue
        for cpe in cpes:
            part, _, name = cpe.partition(":")
            if name:
                by_part[part][name] += 1

    title = (row.get("nvt_name") or "").lower()

    def named_in_title(candidate):
        """Whether the check's title mentions this product, by product name or by vendor."""
        vendor, _, product = candidate.partition(":")
        return any(word and word in title
                   for word in (product.replace("_", " "), vendor.replace("_", " ")))

    for part in ("a", "o", "h"):
        counts = by_part.get(part)
        if not counts:
            continue
        named = {c: n for c, n in counts.items() if named_in_title(c)}
        # An application may be taken on citation count when the title names none of the
        # candidates, because the title often describes the flaw rather than the component.
        # An operating system may not: `CVE-1999-0524`, the ICMP timestamp disclosure, lists
        # fourteen platforms and the check that reports it is called "ICMP Timestamp Reply
        # Information Disclosure", which names no platform at all. Taking the most-cited
        # entry there filed six Linux hosts under `apple:mac_os_x` and made the two scanners
        # look as though they agreed about something. Where nothing confirms which platform
        # is meant, the scanner's own wording is the better key.
        pool = named if (named or part != "a") else counts
        if not pool:
            continue
        best = max(pool.values())
        return sorted(c for c, n in pool.items() if n == best)[0], "nvd"
    return product_of(row["nvt_name"]), "title"


def merge(rows, nvd):
    """Group by (host, port, product). Members keep their own rows; the group carries one key."""
    groups = collections.defaultdict(list)
    sources = {}
    for r in rows:
        prod, src = product_key(r, nvd)
        key = (r["host"], r.get("port", ""), prod)
        groups[key].append(r)
        # A group reached by a CVE from any member is an NVD group; only a group where no
        # member cited a usable CVE falls back to the title.
        if src == "nvd" or key not in sources:
            sources[key] = src
    return groups, sources


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--findings", required=True, action="append", metavar="CSV")
    ap.add_argument("--nvd", default=os.path.join(HERE, "cwe_map.json"), metavar="JSON")
    ap.add_argument("--max-products", type=int, default=MAX_PRODUCTS, metavar="N",
                    help="a CVE naming more products than this identifies none")
    ap.add_argument("-o", "--out", metavar="CSV", help="write canonical findings here")
    args = ap.parse_args()

    globals()["MAX_PRODUCTS"] = args.max_products
    nvd = json.load(open(args.nvd, encoding="utf-8"))
    broad = sum(1 for v in nvd.values()
                if len(v.get("cpes") or []) > args.max_products)
    have_cpe = sum(1 for v in nvd.values() if v.get("cpes"))
    if have_cpe == 0:
        sys.exit(f"{args.nvd} carries no affected-product data. Run "
                 "`python3 fetch_labels.py --cwe` first; without it every group would fall "
                 "back to the parsed title and the merge would measure nothing new.")

    rows, seen = [], set()
    for path in args.findings:
        for r in csv.DictReader(open(path, encoding="utf-8")):
            if r.get("threat") == "Log":
                continue
            k = (r["host"], r["nvt_name"], r.get("scanner", ""))
            if k in seen:
                continue
            seen.add(k)
            rows.append(r)

    groups, sources = merge(rows, nvd)
    by_title = collections.defaultdict(list)
    for r in rows:
        by_title[(r["host"], r.get("port", ""), product_of(r["nvt_name"]))].append(r)

    scanners = sorted({r.get("scanner", "") for r in rows if r.get("scanner")})
    print(f"nvd cache         : {have_cpe} of {len(nvd)} CVEs name an affected product, "
          f"{broad} name more than {args.max_products} and are ignored as generic")
    print(f"findings          : {len(rows)} from {', '.join(scanners) or 'one scanner'}")
    print(f"groups by title   : {len(by_title)}")
    print(f"groups by product : {len(groups)}, "
          f"{len(by_title) - len(groups):+d} against the title key")
    src = collections.Counter(sources.values())
    print(f"    {src.get('nvd', 0):4d} keyed on NVD's affected product")
    print(f"    {src.get('title', 0):4d} keyed on the scanner's title, no usable CVE\n")

    if len(scanners) > 1:
        both = [k for k, m in groups.items()
                if len({r.get("scanner") for r in m}) > 1]
        print(f"reported by more than one scanner: {len(both)} of {len(groups)} groups")
        for k in sorted(both)[:12]:
            m = groups[k]
            per = collections.Counter(r.get("scanner") for r in m)
            print(f"    {k[0]:14s} {k[1]:12s} {k[2][:30]:30s} "
                  + ", ".join(f"{s} {n}" for s, n in sorted(per.items())))
        print()

    biggest = sorted(groups.items(), key=lambda kv: -len(kv[1]))[:8]
    print("largest groups, each one job:")
    for k, m in biggest:
        print(f"    {len(m):4d}  {k[0]:14s} {k[1]:12s} {k[2][:40]}")

    if args.out:
        with open(args.out, "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=CSV_FIELDS + EXTRA, extrasaction="ignore")
            w.writeheader()
            for key, members in sorted(groups.items()):
                for r in members:
                    out = dict(r)
                    out["canon_key"] = f"{key[0]}|{key[1]}|{key[2]}"
                    out["key_source"] = sources[key]
                    out["canon_members"] = len(members)
                    out["canon_scanners"] = ";".join(
                        sorted({x.get("scanner", "") for x in members}))
                    w.writerow(out)
        print(f"\nwrote {args.out}: {len(rows)} findings tagged with {len(groups)} group keys")


if __name__ == "__main__":
    main()
