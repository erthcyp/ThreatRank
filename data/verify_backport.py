#!/usr/bin/env python3
"""
ThreatRank - decide which scanner findings are backporting false positives

A version-inference check reads a service banner, sees an old upstream version, and
reports every CVE fixed since. On a distribution that backports, the fixes are already
present and the version number never moved, so the finding is wrong.

Deciding that requires two things, and the first attempt at this analysis had only one:

  1. the set of CVEs the distribution says it fixed in a package  (from the changelog)
  2. **the package version that was installed at the moment of the scan**

Without (2) the comparison is against whatever the host looks like today. On 19 Aug 2026
`target-b1` ran unattended-upgrades *during* its own scan, so openssh moved from
4ubuntu0.5 to 4ubuntu0.13 mid-scan. Comparing the scan against the 0.13 changelog marked
seven genuine findings as false. This script exists so that cannot happen silently again:
scan-time versions are an explicit input, not an assumption.

A CVE counts as already fixed only when the changelog stanza that names it carries a
version less than or equal to the scan-time version, compared with `dpkg --compare-versions`
rather than string ordering.

Verdicts:
  FALSE POSITIVE  every CVE the finding cites was already fixed at scan time
  TRUE POSITIVE   at least one cited CVE was not fixed until after the scan
  UNDETERMINED    the cited CVEs do not appear in the changelog at all

UNDETERMINED is not "probably fine". Ubuntu ships only the last 10 changelog stanzas, so
fixes older than that are invisible here. The false-positive count this produces is a
lower bound.

Usage:
    python3 verify_backport.py --findings processed/findings_openvas_b.csv \\
        --changelog-dir evidence \\
        --version apache2=2.4.41-4ubuntu3.23 \\
        --version openssh-server=1:8.2p1-4ubuntu0.5 \\
        --version libssl1.1=1.1.1f-1ubuntu2.17
"""

import argparse
import collections
import csv
import gzip
import os
import re
import subprocess
import sys

STANZA = re.compile(r"^[a-z0-9.+-]+ \(([^)]+)\)")
CVE = re.compile(r"CVE-\d{4}-\d+")

# Which package a finding is about, inferred from the check name. Deliberately crude:
# anything it cannot place becomes UNDETERMINED rather than being guessed at.
PACKAGE_HINTS = [
    ("apache2", ("apache", "http server")),
    ("openssh-server", ("openssh", "ssh")),
    ("libssl1.1", ("ssl", "tls")),
]


def version_le(a, b):
    """True if version a <= b, using dpkg's own comparison rules."""
    return subprocess.run(["dpkg", "--compare-versions", a, "le", b]).returncode == 0


def load_changelog(path):
    """Map each CVE to the earliest package version whose stanza mentions it."""
    fixed_in = {}
    version = None
    opener = gzip.open if path.endswith(".gz") else open
    with opener(path, "rt", errors="replace") as fh:
        for line in fh:
            m = STANZA.match(line)
            if m:
                version = m.group(1)
                continue
            if version is None:
                continue
            for cve in CVE.findall(line):
                if cve not in fixed_in or version_le(version, fixed_in[cve]):
                    fixed_in[cve] = version
    return fixed_in


def package_of(nvt_name):
    low = nvt_name.lower()
    for pkg, hints in PACKAGE_HINTS:
        if any(h in low for h in hints):
            return pkg
    return None


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--findings", required=True, help="CSV from parse_openvas.py")
    ap.add_argument("--changelog-dir", default="evidence", metavar="DIR",
                    help="directory holding <package>.changelog.gz. The changelogs are "
                         "scan-time evidence captured from the lab hosts and live only in "
                         "the private paper repository, so point this at that checkout")
    ap.add_argument("--version", action="append", default=[], metavar="PKG=VERSION",
                    help="package version installed AT SCAN TIME; repeatable")
    ap.add_argument("--by-qod", action="store_true",
                    help="cross-tabulate the verdicts against QoD")
    args = ap.parse_args()

    if not args.version:
        sys.exit("give at least one --version PKG=VERSION (scan-time, not today's)")

    # The changelogs are scan-time evidence and are not carried in this repository. Saying
    # so is the difference between a clear stop and a run that quietly verifies nothing.
    if not os.path.isdir(args.changelog_dir):
        sys.exit(f"no changelog directory at {args.changelog_dir}\n"
                 f"These are scan-time package changelogs captured from the lab hosts.\n"
                 f"They live beside this script, for example\n"
                 f"  --changelog-dir evidence")

    scan_time = dict(v.split("=", 1) for v in args.version)

    already, later, fixed_in = {}, {}, {}
    for pkg, installed in scan_time.items():
        path = os.path.join(args.changelog_dir, f"{pkg}.changelog.gz")
        if not os.path.exists(path):
            sys.exit(f"missing changelog: {path}")
        fixed_in[pkg] = load_changelog(path)
        already[pkg] = {c for c, v in fixed_in[pkg].items() if version_le(v, installed)}
        later[pkg] = set(fixed_in[pkg]) - already[pkg]
        print(f"{pkg:16} scan-time {installed:24} "
              f"changelog CVEs {len(fixed_in[pkg]):3}  "
              f"fixed by then {len(already[pkg]):3}  after {len(later[pkg]):3}")

    verdicts, rows_out = collections.Counter(), []
    with open(args.findings, encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            if row["has_cve"] != "True":
                continue
            pkg = package_of(row["nvt_name"])
            cves = [c for c in row["cves"].split(";") if c]
            known = [c for c in cves if pkg and c in fixed_in.get(pkg, {})]
            if not pkg or not known:
                verdict = "UNDETERMINED"
            elif any(c in later[pkg] for c in known):
                verdict = "TRUE POSITIVE"
            else:
                verdict = "FALSE POSITIVE"
            verdicts[verdict] += 1
            rows_out.append((verdict, row["threat"], row["severity"],
                             row["qod"], row["nvt_name"]))

    print()
    for v, n in verdicts.most_common():
        print(f"  {n:3}  {v}")

    sev = [r for r in rows_out if r[1] in ("Critical", "High")]
    decided = [r for r in sev if r[0] != "UNDETERMINED"]
    print(f"\nCritical/High: {len(sev)} total, {len(decided)} with a verdict, "
          f"{sum(1 for r in decided if r[0] == 'FALSE POSITIVE')} false, "
          f"{sum(1 for r in decided if r[0] == 'TRUE POSITIVE')} true")

    if args.by_qod:
        table = collections.defaultdict(collections.Counter)
        for verdict, _, _, qod, _ in rows_out:
            if verdict != "UNDETERMINED":
                table[qod][verdict] += 1
        print("\nverdict against QoD (the claim that QoD flags false positives):")
        print(f"{'QoD':>5} {'false':>7} {'true':>6}")
        for qod in sorted(table, key=int):
            print(f"{qod:>5} {table[qod]['FALSE POSITIVE']:>7} "
                  f"{table[qod]['TRUE POSITIVE']:>6}")

    print()
    for r in sorted(rows_out, key=lambda r: (r[0], -float(r[2] or 0))):
        if r[0] != "UNDETERMINED":
            print(f"  {r[0]:14} {r[1]:8} sev={r[2]:>4} qod={r[3]:>3}  {r[4][:58]}")


if __name__ == "__main__":
    main()
