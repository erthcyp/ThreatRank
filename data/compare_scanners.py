#!/usr/bin/env python3
"""
ThreatRank - cross-scanner comparison

Reads the CSVs produced by parse_openvas.py and parse_nessus.py and reports how
much the two scanners agree on the same host.

Matching is done at **CVE level only**, deliberately. OpenVAS identifies checks by
NVT OID and Nessus by plugin ID; the two namespaces have nothing in common, and
finding names are written differently by each vendor. CVE IDs are the only shared
vocabulary, so they are the only defensible join key without hand-built mappings.

The consequence is itself a result worth reporting: findings without a CVE cannot
be matched across scanners at all, and on the first target that was two thirds of
everything OpenVAS reported - including both of its highest-severity findings.

Optionally checks whether a specific CVE was detected, which is how a known-vulnerable
vulhub target turns into a false-negative measurement.

Examples:
    python3 compare_scanners.py
    python3 compare_scanners.py --expect CVE-2016-3088
    python3 compare_scanners.py --host 172.18.0.17 --expect CVE-2016-3088
"""

import argparse
import csv
import os
import sys
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))


def load(path):
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def cve_set(rows):
    out = set()
    for r in rows:
        for c in r["cves"].split(";"):
            if c:
                out.add(c)
    return out


def bucket_by_host(rows):
    d = defaultdict(list)
    for r in rows:
        d[r["host"]].append(r)
    return d


def pct(part, whole):
    return f"{100 * part / whole:.1f}%" if whole else "n/a"


def main():
    ap = argparse.ArgumentParser(description="Compare OpenVAS and Nessus findings")
    # No defaults. A default pointed at a generic filename once caused this script to
    # compare two different machines and print plausible numbers without erroring:
    # see "Defect A" in scans.md, 5 Sep 2026. Both inputs must now be named.
    ap.add_argument("--openvas", required=True,
                    help="OpenVAS findings CSV, e.g. processed/findings_openvas.csv")
    ap.add_argument("--nessus", required=True,
                    help="Nessus findings CSV for THE SAME host, "
                         "e.g. processed/findings_nessus_a.csv")
    ap.add_argument("--host", help="restrict to one host IP")
    ap.add_argument("--expect", action="append", default=[],
                    help="CVE that should be detected (repeatable); "
                         "a miss is a measured false negative")
    args = ap.parse_args()

    ov = load(args.openvas)
    ne = load(args.nessus)
    if not ov and not ne:
        sys.exit("no input CSVs found - run the parsers first")

    if args.host:
        ov = [r for r in ov if r["host"] == args.host]
        ne = [r for r in ne if r["host"] == args.host]

    # Cross-scanner agreement only means anything on the same machine. If the two
    # inputs cover different hosts, every "only OpenVAS saw this" is an artefact of
    # comparing unrelated scans, not a measurement.
    ov_hosts, ne_hosts = set(bucket_by_host(ov)), set(bucket_by_host(ne))
    if ov and ne:
        shared = ov_hosts & ne_hosts
        if not shared:
            sys.exit(
                "refusing to compare: the inputs cover no host in common.\n"
                f"  OpenVAS {sorted(ov_hosts)}  from {args.openvas}\n"
                f"  Nessus  {sorted(ne_hosts)}  from {args.nessus}\n"
                "Name the pair that scanned the same machine.")
        if ov_hosts != ne_hosts:
            print(f"WARNING: inputs cover different hosts. OpenVAS only "
                  f"{sorted(ov_hosts - shared)}, Nessus only {sorted(ne_hosts - shared)}. "
                  f"Restricting to the {len(shared)} host(s) in common.", file=sys.stderr)
            ov = [r for r in ov if r["host"] in shared]
            ne = [r for r in ne if r["host"] in shared]

    hosts = sorted(set(bucket_by_host(ov)) | set(bucket_by_host(ne)))

    print("=" * 64)
    print("Cross-scanner comparison")
    print("=" * 64)
    print(f"hosts covered : {len(hosts)}")
    print(f"  OpenVAS     : {len(bucket_by_host(ov))} hosts, {len(ov)} findings")
    print(f"  Nessus      : {len(bucket_by_host(ne))} hosts, {len(ne)} findings")

    # --- volume -----------------------------------------------------------
    print("\n--- findings per scanner ---")
    for name, rows in (("OpenVAS", ov), ("Nessus", ne)):
        if not rows:
            print(f"  {name:<8}: no data")
            continue
        with_cve = sum(1 for r in rows if r["has_cve"] == "True")
        print(f"  {name:<8}: {len(rows):>4} findings   "
              f"with CVE {with_cve:>3} ({pct(with_cve, len(rows))})   "
              f"unique CVEs {len(cve_set(rows))}")

    # --- agreement at CVE level -------------------------------------------
    ov_cves, ne_cves = cve_set(ov), cve_set(ne)
    both = ov_cves & ne_cves
    only_ov = ov_cves - ne_cves
    only_ne = ne_cves - ov_cves
    union = ov_cves | ne_cves

    print("\n--- CVE-level agreement ---")
    print(f"  reported by both     : {len(both):>4}  ({pct(len(both), len(union))} of union)")
    print(f"  OpenVAS only         : {len(only_ov):>4}")
    print(f"  Nessus only          : {len(only_ne):>4}")
    print(f"  union                : {len(union):>4}")
    if union:
        print(f"\n  Jaccard similarity   : {len(both) / len(union):.3f}")
        print("  (1.0 = identical, 0.0 = no overlap at all)")

    if only_ov:
        print(f"\n  CVEs only OpenVAS saw ({len(only_ov)}):")
        for c in sorted(only_ov):
            print(f"    {c}")
    if only_ne:
        print(f"\n  CVEs only Nessus saw ({len(only_ne)}):")
        for c in sorted(only_ne):
            print(f"    {c}")

    # --- unmatchable findings ---------------------------------------------
    print("\n--- findings that cannot be matched at all ---")
    for name, rows in (("OpenVAS", ov), ("Nessus", ne)):
        if not rows:
            continue
        no_cve = [r for r in rows if r["has_cve"] != "True"]
        sev = [r for r in no_cve if r["threat"] in ("Critical", "High")]
        print(f"  {name:<8}: {len(no_cve):>4} without CVE ({pct(len(no_cve), len(rows))})"
              f"   of which Critical/High: {len(sev)}")
        for r in sev:
            print(f"             [{r['threat']}] {r['nvt_name'][:60]}")
    print("\n  These carry no CVE, so no cross-scanner join is possible and no")
    print("  CVE-based scoring system (CVSS lookup, EPSS, KEV) can rank them.")

    # --- expected CVEs ----------------------------------------------------
    if args.expect:
        print("\n--- expected CVEs (ground truth from the target) ---")
        for want in args.expect:
            in_ov = "FOUND" if want in ov_cves else "MISSED"
            in_ne = "FOUND" if want in ne_cves else "MISSED"
            verdict = ("detected by at least one scanner"
                       if want in union else "MISSED BY BOTH SCANNERS")
            print(f"  {want}")
            print(f"    OpenVAS: {in_ov}")
            print(f"    Nessus : {in_ne}")
            print(f"    -> {verdict}")

    # --- per host ---------------------------------------------------------
    if len(hosts) > 1:
        print("\n--- per host ---")
        ovh, neh = bucket_by_host(ov), bucket_by_host(ne)
        print(f"  {'host':<16} {'OpenVAS':>8} {'Nessus':>8} {'shared CVEs':>12}")
        for h in hosts:
            a, b = cve_set(ovh.get(h, [])), cve_set(neh.get(h, []))
            print(f"  {h:<16} {len(ovh.get(h, [])):>8} {len(neh.get(h, [])):>8} "
                  f"{len(a & b):>12}")


if __name__ == "__main__":
    main()
