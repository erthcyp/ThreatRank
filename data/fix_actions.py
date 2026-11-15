#!/usr/bin/env python3
"""What is a remediation action, how many are there, and what does one cost?

The D2 feedback asked what the remediation budget is measured in. The paper said
"cost per action" and "pick within budget" without naming a unit or a source, which is
not a cost model. This script supplies both, from data already held, and it is written
so the definition can be checked rather than believed.

THE UNIT IS AN ACTION, NOT MONEY AND NOT HOURS

Money and person-hours are properties of the organisation doing the work. They cannot be
observed in a laboratory and inventing them would be the project grading itself against a
metric it made up. An action count is exact, reproducible from the reports, and is what an
analyst actually schedules.

WHAT COUNTS AS ONE ACTION

    (host, port, product, remediation text with version numbers normalised)

Every part except the normalisation comes from the scanner. The product is the leading
words of the check title, before any version or comparison operator. The normalisation
exists because Greenbone writes "Update to version 2.4.30 or later" and "Update to version
2.4.41 or later" as separate remediations for the same component, and they are one upgrade.

Both halves of that key were arrived at by measuring, and both corrections matter:

  exact remediation text only          333 actions, 1.22 findings each, over-counted
  dropping the product from the key    132 actions, 3.07 findings each, under-counted
  the key above                        183 actions, 2.21 findings each

Under-counting was the worse error and is why `product` is in the key. Without it the
largest single "action" merged 42 findings across Apache HTTP Server, PHP and WordPress on
one port, which is three upgrades, not one.

WHAT AN ACTION COSTS

From `solution_type`, which Greenbone publishes per check and which is therefore a
statement about remediation effort made outside this team:

    VendorFix                  a published patch exists          cost 1
    Mitigation, Workaround     configuration change, no patch    cost w_m
    WillNotFix, NoneAvailable  replace or remove the component   cost w_n

with 1 <= w_m <= w_n. **The weights are a declared parameter, not a measurement**, and
results must be reported across a sweep of them, in the same way the environment
description for the attack graph is declared rather than inferred. An action takes the
cheapest tier any of its findings admits, because one patch that fixes a finding fixes it
however the other findings on the same component are classified.

USAGE

    python3 fix_actions.py                  the whole corpus
    python3 fix_actions.py --by-host        one line per host

Reads raw OpenVAS XML because the remediation text is not carried into
processed/findings_*.csv. Adding a `solution` column to the parser would remove that
dependency and is the obvious next change.
"""

import argparse
import collections
import csv
import glob
import os
import re
import xml.etree.ElementTree as ET

HERE = os.path.dirname(os.path.abspath(__file__))

VERSION = re.compile(r"\d+(?:\.\d+)+[a-z0-9\-]*")
# A check title runs "<product> <comparison> <version> <what is wrong>". Cutting at the
# first comparison, version, or dash keeps the product and discards the rest.
PRODUCT_END = re.compile(r"\s*(?:<=|<|>=|>|\d+\.\d|\bversion\b|\bmultiple\b|\b-\s)", re.I)

TIERS = [("VendorFix",), ("Mitigation", "Workaround"), ("WillNotFix", "NoneAvailable")]
TIER_NAME = ["patch available", "configuration change", "no fix available"]


def product_of(title):
    return PRODUCT_END.split(title, 1)[0].strip(" -,:").lower() or title.lower()


def solution_types():
    """(host, check title) -> solution_type, from the parser's output."""
    out = {}
    for path in glob.glob(os.path.join(HERE, "processed", "findings_*.csv")):
        with open(path, encoding="utf-8") as fh:
            for row in csv.DictReader(fh):
                out.setdefault((row["host"], row["nvt_name"]), row.get("solution_type", ""))
    return out


def findings():
    """Non-Log findings from the unauthenticated reports, deduplicated on (host, title).

    The credentialed and re-scan reports are excluded for the same reason every other
    measurement in this project excludes them: they repeat one machine and would make the
    corpus a description of that machine.
    """
    rows, seen = [], set()
    for path in sorted(glob.glob(os.path.join(HERE, "raw", "openvas", "*.xml"))):
        if "auth" in os.path.basename(path) or "patched" in os.path.basename(path):
            continue
        for result in ET.parse(path).getroot().findall(".//results/result"):
            if (result.findtext("threat") or "") == "Log":
                continue
            host = (result.findtext("host") or "").strip().split("\n")[0]
            title = (result.findtext("nvt/name") or "").strip()
            if (host, title) in seen:
                continue
            seen.add((host, title))
            remediation = next(((s.text or "").strip() for s in result.iter("solution")), "")
            rows.append({
                "host": host,
                "port": (result.findtext("port") or "").strip(),
                "title": title,
                "remediation": re.sub(r"\s+", " ", remediation),
            })
    return rows


def actions(rows):
    """Group findings into actions and give each the cheapest tier its members admit."""
    st = solution_types()
    grouped = collections.defaultdict(list)
    for r in rows:
        key = (r["host"], r["port"], product_of(r["title"]),
               VERSION.sub("<v>", r["remediation"])[:300])
        grouped[key].append(r)

    out = []
    for key, members in grouped.items():
        kinds = {st.get((m["host"], m["title"]), "") for m in members}
        tier = next((i for i, names in enumerate(TIERS) if kinds & set(names)), None)
        out.append({"key": key, "members": members, "tier": tier})
    return out


def report(acts, rows):
    n = len(rows)
    print(f"{n} findings on {len({r['host'] for r in rows})} hosts, Log excluded, "
          f"deduplicated on (host, title)")
    print(f"{len(acts)} remediation actions, {n / len(acts):.2f} findings each\n")

    sizes = sorted((len(a["members"]) for a in acts), reverse=True)
    print("  the work is concentrated:")
    for k in (5, 10, 20, 40):
        cleared = sum(sizes[:k])
        print(f"    the {k:3d} largest actions clear {cleared:4d} findings "
              f"({100 * cleared / n:4.1f}%) and are {100 * k / len(acts):4.1f}% of the plan")

    print("\n  cost tier, from the scanner's own solution_type:")
    tally = collections.Counter(a["tier"] for a in acts)
    for i, name in enumerate(TIER_NAME):
        print(f"    {tally.get(i, 0):4d}  {name}")
    if tally.get(None):
        print(f"    {tally[None]:4d}  the scanner states nothing, tier cannot be assigned")

    print("\n  largest actions:")
    for a in sorted(acts, key=lambda a: -len(a["members"]))[:8]:
        host, port, prod, rem = a["key"]
        print(f"    {len(a['members']):4d}  {host:15s} {port:10s} {prod[:28]:30s} {rem[:38]}")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--by-host", action="store_true", help="one line per host")
    args = ap.parse_args()

    rows = findings()
    acts = actions(rows)
    if args.by_host:
        per = collections.Counter(a["key"][0] for a in acts)
        cnt = collections.Counter(r["host"] for r in rows)
        print(f"  {'host':16s} {'findings':>9} {'actions':>8} {'each':>6}")
        for host in sorted(per, key=lambda h: -cnt[h]):
            print(f"  {host:16s} {cnt[host]:9d} {per[host]:8d} {cnt[host]/per[host]:6.2f}")
        return
    report(acts, rows)


if __name__ == "__main__":
    main()
