#!/usr/bin/env python3
"""How much of a host's exposure is held in place by an end-of-life condition.

An end-of-life finding carries no CVE. EPSS cannot score it, KEV can never list it, and a
prioritisation pipeline keyed on CVE identifiers drops it silently. It is also, on the one
host measured here, the single condition that makes seventy scored vulnerabilities
unfixable. This script measures that, so the claim rests on a count rather than on an
appeal to intuition.

    importance of an end-of-life finding
      = CVEs present on that host, for the software it covers,
        published after the vendor stopped issuing fixes

Every input comes from outside this project. The end-of-life date is reported by the
scanner, which reads it from the vendor: Greenbone's own output gives
`cpe:/a:php:php:5.6.30`, `EOL date: 2018-12-31` and `cpe:/o:debian:debian_linux:8`,
`EOL date: 2020-06-30`. Publication dates come from NVD and scores from FIRST. There is no
parameter here that this project can tune, which is the whole reason for choosing this
measure over anything the team would have to judge.

WHY THE DATES ARE ARGUMENTS

They appear in the scanner's description text, which the parser does not carry into
`processed/findings_*.csv`. Passing them explicitly follows `verify_backport.py`, which
takes scan-time package versions the same way and for the same reason: a value that was
observed at scan time should be stated, not reconstructed later from whatever the host
looks like now.

TWO LOCKS ON ONE HOST DO NOT ADD UP

A host running PHP 5.6 on Debian 8 is locked twice. The operating system's end of life
covers every package on the machine from its own date; the PHP end of life covers PHP from
an earlier one. A PHP vulnerability published after both is held by both, and summing the
two counts reports it twice. The output therefore partitions rather than totals.

    python3 eol_lock.py --host 172.18.0.110 \\
        --eol php=2018-12-31 --eol os=2020-06-30 \\
        --findings processed/findings_openvas_b2.csv
"""

import argparse
import collections
import csv
import json
import os
import statistics
import sys

from fix_actions import product_of

HERE = os.path.dirname(os.path.abspath(__file__))


def load(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def kev_ids(path):
    """Every CVE in the pinned CISA KEV snapshot, whatever shape the file nests them in."""
    out = set()

    def walk(node):
        if isinstance(node, dict):
            if "cveID" in node:
                out.add(node["cveID"])
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)

    walk(load(path))
    return out


def epss_scores():
    path = os.path.join(HERE, "epss_lookup.csv")
    with open(path, encoding="utf-8") as fh:
        rows = csv.DictReader(line for line in fh if not line.startswith("#"))
        return {r["cve"]: float(r["epss"]) for r in rows}


def findings(paths, host):
    rows, seen = [], set()
    for path in paths:
        with open(path, encoding="utf-8") as fh:
            for r in csv.DictReader(fh):
                if r["host"] != host or r.get("threat") == "Log":
                    continue
                key = (r["host"], r["nvt_name"])
                if key in seen:
                    continue
                seen.add(key)
                rows.append(r)
    return rows


def cves_of(rows):
    out = set()
    for r in rows:
        out.update(c.strip() for c in (r.get("cves") or "").split(";")
                   if c.strip().startswith("CVE-"))
    return out


def describe(label, cves, epss, published):
    scored = [epss[c] for c in cves if c in epss]
    high = sum(1 for x in scored if x > 0.1)
    if not cves:
        print(f"  {label:34s} {0:4d}")
        return
    line = f"  {label:34s} {len(cves):4d} CVE   above 0.1 EPSS {high:3d}"
    if scored:
        line += f"   median {statistics.median(scored):.4f}   max {max(scored):.4f}"
    print(line)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", required=True, help="the host carrying the EOL finding")
    ap.add_argument("--findings", required=True, action="append", metavar="CSV")
    ap.add_argument("--eol", required=True, action="append", metavar="SCOPE=DATE",
                    help="an end-of-life date the scanner reported, as reported. Use "
                         "'os' for a whole-host end of life, or a product substring such "
                         "as 'php' for one package. Repeatable")
    ap.add_argument("--cvss", default=os.path.join(HERE, "cwe_map.json"), metavar="JSON")
    ap.add_argument("--kev", default=os.path.join(HERE, "kev_catalog.json"), metavar="JSON")
    args = ap.parse_args()

    cwe = load(args.cvss)
    epss = epss_scores()
    kev = kev_ids(args.kev) if os.path.exists(args.kev) else set()
    rows = findings(args.findings, args.host)
    if not rows:
        sys.exit(f"no findings for {args.host} in the files given")

    published = {c: (cwe.get(c, {}).get("published") or "") for c in cves_of(rows)}
    everything = cves_of(rows)

    scopes = {}
    for spec in args.eol:
        if "=" not in spec:
            sys.exit(f"--eol wants SCOPE=DATE, got {spec}")
        scope, date = spec.split("=", 1)
        covered = everything if scope == "os" else cves_of(
            [r for r in rows if scope.lower() in product_of(r["nvt_name"])])
        scopes[scope] = {c for c in covered if published.get(c, "") > date}

    print(f"host              : {args.host}")
    print(f"findings          : {len(rows)}, Log excluded, deduplicated")
    print(f"CVEs present      : {len(everything)}")
    for spec in args.eol:
        scope, date = spec.split("=", 1)
        print(f"end of life       : {scope} from {date}, as the scanner reported it")
    print()

    names = list(scopes)
    if len(names) == 2:
        a, b = names
        print("held in place by, counted without overlap:")
        describe(f"{a} alone", scopes[a] - scopes[b], epss, published)
        describe(f"{b} alone", scopes[b] - scopes[a], epss, published)
        describe("both at once", scopes[a] & scopes[b], epss, published)
    else:
        print("held in place by:")
        for scope, cves in scopes.items():
            describe(scope, cves, epss, published)

    union = set().union(*scopes.values()) if scopes else set()
    share = 100 * len(union) / max(1, len(everything))
    print()
    describe("union, nothing counted twice", union, epss, published)
    print(f"\n  {len(union)} of {len(everything)} CVEs on this host ({share:.1f}%) were "
          f"published after\n  the software carrying them stopped receiving fixes.")

    locked_kev = union & kev
    if kev:
        print(f"  {len(locked_kev)} of them are in CISA KEV: CISA has observed them being "
              f"exploited,\n  and on this host they cannot be patched.")

    if union:
        print("\n  highest scored, of those:")
        for c in sorted(union, key=lambda c: -epss.get(c, 0.0))[:5]:
            mark = "  KEV" if c in kev else ""
            print(f"    {c:18s} EPSS {epss.get(c, 0.0):.4f}   published "
                  f"{published.get(c, '')[:10]}{mark}")

    # An earlier version of this line claimed none of these CVEs was scored or listed.
    # That was false and the output above disproves it: they carry EPSS scores near 1.0 and
    # several are in KEV. What carries no score is the end-of-life finding itself, and the
    # difference between those two statements is the difference between an overclaim and
    # the actual argument.
    print("\n  The end-of-life finding that holds these in place carries no CVE. EPSS")
    print("  cannot score it, KEV cannot list it, and a pipeline keyed on CVE identifiers")
    print("  never sees the one condition that makes the rest unfixable.")


if __name__ == "__main__":
    main()
