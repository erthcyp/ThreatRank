#!/usr/bin/env python3
"""Reduce MITRE's CWE catalogue to the one thing this project uses: a pillar per weakness.

The classifier's job, as the advisor settled it on 29 September, is to put a category on a
finding for a person to read, not to feed a score. That needs a taxonomy with few enough
classes to be legible and enough authority to be defensible, and it must not be the
scanner's own. Greenbone's families are Greenbone's: `Web Servers`, `Web application
abuses`, `General`. Nessus names its families differently, so a report merging two tools has
no shared category at all unless one is brought in from outside.

CWE's pillars are that taxonomy. There are roughly ten, they are MITRE's rather than ours,
and every CWE in the research view rolls up to exactly one.

WHY A PILLAR AND NOT A CLASS

Measured on this corpus on 8 September, over 410 findings:

    Variant, as NVD assigns   161 classes   47% singletons
    Class                      64 classes   22% singletons
    Pillar                     11 classes    9% singletons

Class was chosen then, and pillar rejected, because the top five pillars cover 90% of
findings and a model that always predicts the commonest would score well without learning
anything. That objection was about **evaluating a predictor**. It does not apply to
**labelling a report**: a reader wants ten categories they can hold in their head, not
sixty-four, and a category that is common is not thereby useless to print.

WHAT NEEDS NO MODEL

Most findings do not need predicting at all. NVD already publishes a CWE for the CVEs they
cite, so their pillar is a lookup. Only findings with no CVE need a prediction, and those
are 35 of 410 here. The output of this script is what makes that division possible.

    python3 cwe_pillars.py            build cwe_pillars.json from the newest catalogue

The catalogue itself is 18 MB of text this project reads four attributes of, so it is not
committed. The extracted map is, together with the catalogue version it came from, which is
what a reader needs to reproduce it.
"""

import argparse
import collections
import datetime
import glob
import json
import os
import re
import sys
import xml.etree.ElementTree as ET

HERE = os.path.dirname(os.path.abspath(__file__))
RESEARCH_VIEW = "1000"


def strip_ns(tag):
    return tag.rsplit("}", 1)[-1]


def newest_catalogue():
    files = sorted(glob.glob(os.path.join(HERE, "cwec_v*.xml")))
    if not files:
        sys.exit("no cwec_v*.xml in data/. Fetch and unpack it with:\n"
                 "  curl -L -o cwec_latest.xml.zip "
                 "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip\n"
                 "  python3 -c \"import zipfile; "
                 "zipfile.ZipFile('cwec_latest.xml.zip').extractall('.')\"")
    return files[-1]


def read_catalogue(path):
    """Every weakness as id -> (name, abstraction, primary parent in the research view).

    A weakness can be a child of several others. Only the relation MITRE marks Primary is
    followed, and only within view 1000, so the walk is over MITRE's own idea of the tree
    rather than over a path this project chose.
    """
    weaknesses = {}
    for _, el in ET.iterparse(path, events=("end",)):
        if strip_ns(el.tag) != "Weakness":
            continue
        cid = el.get("ID")
        parents = []
        for rel in el.iter():
            if strip_ns(rel.tag) != "Related_Weakness":
                continue
            if rel.get("Nature") != "ChildOf" or rel.get("View_ID") != RESEARCH_VIEW:
                continue
            parents.append((rel.get("Ordinal") == "Primary", rel.get("CWE_ID")))
        parents.sort(key=lambda t: not t[0])          # Primary first
        weaknesses[cid] = {
            "name": el.get("Name", ""),
            "abstraction": el.get("Abstraction", ""),
            "parent": parents[0][1] if parents else None,
        }
        el.clear()
    return weaknesses


def pillar_of(cid, weaknesses, seen=None):
    """Walk up the primary ChildOf chain until a Pillar, or give up honestly."""
    seen = seen or set()
    node = weaknesses.get(cid)
    while node:
        if node["abstraction"] == "Pillar":
            return cid
        if cid in seen or not node["parent"]:
            return None
        seen.add(cid)
        cid = node["parent"]
        node = weaknesses.get(cid)
    return None


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--xml", help="CWE catalogue; defaults to the newest in data/")
    ap.add_argument("-o", "--out", default=os.path.join(HERE, "cwe_pillars.json"))
    args = ap.parse_args()

    path = args.xml or newest_catalogue()
    version = (re.search(r"cwec_v([\d.]+)\.xml", os.path.basename(path)) or [None, "?"])[1]
    weaknesses = read_catalogue(path)

    pillars = {cid: w["name"] for cid, w in weaknesses.items()
               if w["abstraction"] == "Pillar"}
    mapping, orphans = {}, []
    for cid in weaknesses:
        p = pillar_of(cid, weaknesses)
        if p:
            mapping[f"CWE-{cid}"] = f"CWE-{p}"
        else:
            orphans.append(cid)

    payload = {
        "catalogue_version": version,
        "extracted": datetime.date.today().isoformat(),
        "source": os.path.basename(path),
        "view": RESEARCH_VIEW,
        "pillar_names": {f"CWE-{k}": v for k, v in sorted(pillars.items(), key=lambda t: int(t[0]))},
        "pillar_of": dict(sorted(mapping.items(), key=lambda t: int(t[0].split("-")[1]))),
    }
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=1, sort_keys=False)

    print(f"catalogue         : {os.path.basename(path)}, version {version}")
    print(f"weaknesses        : {len(weaknesses)}")
    print(f"pillars           : {len(pillars)}")
    for cid, name in sorted(pillars.items(), key=lambda t: int(t[0])):
        n = sum(1 for v in mapping.values() if v == f"CWE-{cid}")
        print(f"    CWE-{cid:<5} {n:4d} weaknesses roll up here   {name}")
    print(f"mapped            : {len(mapping)}")
    print(f"no pillar reached : {len(orphans)}  (deprecated entries and ones outside "
          f"view {RESEARCH_VIEW})")
    print(f"wrote             : {args.out} "
          f"({os.path.getsize(args.out)/1024:.0f} KB)")


if __name__ == "__main__":
    main()
