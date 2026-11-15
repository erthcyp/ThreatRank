#!/usr/bin/env python3
"""A scanner's own checks as training data, independent of anything it ever found.

The models in this project learn to map a scanner's wording onto a value some catalogue
publishes. Until now the only source of that wording was our own scan results: 375 findings
from eleven hosts running about nine distinct products, which is why leave-one-family-out sits
at the severity baseline. A check carries its title, its description and its CVE references
whether or not it ever matched a host, so the scanner's plugin corpus is the same kind of text
in far greater quantity. The OpenVAS feed holds 95,102 checks, 80,555 of which reference a CVE.

WHY THIS AND NOT NVD's OWN DESCRIPTIONS

NVD publishes a description for every CVE and there are hundreds of thousands of them, which
looks like the obvious corpus and is the wrong one. At inference the findings that need an
estimate are exactly those with no CVE, so no NVD description exists to feed the model: it
would be trained on text written by CNAs and used on text written by a scanner vendor. Here
the training text and the serving text are the same kind of thing, and NVD stays where it
belongs, supplying the label and never the input.

That makes the method scanner-agnostic by construction. Point this at whichever scanner's
plugin corpus you have; the pipeline learns that scanner's vocabulary. A closed feed -- Nessus
Essentials does not expose its plugins -- cannot be parsed this way, and the cross-scanner
measurement is what covers that case: a model trained on one tool's wording already carries to
another's.

OUTPUT

The same schema `parse_openvas.py` writes, so every downstream script reads these rows without
changing a line. `severity` comes from the check's own `cvss_base` rather than from a scan, and
`qod` is left empty: the feed states a QoD *type* rather than a number, and the cross-scanner
run measured QoD as contributing almost nothing.

    docker cp <container>:/var/lib/openvas/plugins /tmp/plugins
    python3 parse_nvt.py --plugins /tmp/plugins -o processed/nvt_corpus.csv
"""

import argparse
import csv
import os
import re
import sys

from parse_openvas import CSV_FIELDS, one_line

# script_tag(name:"summary", value:"... possibly spanning lines, with \" inside ...")
TAG = re.compile(r'script_tag\s*\(\s*name\s*:\s*"([^"]+)"\s*,\s*'
                 r'value\s*:\s*"((?:[^"\\]|\\.)*)"', re.DOTALL)
NAME = re.compile(r'script_name\s*\(\s*"((?:[^"\\]|\\.)*)"', re.DOTALL)
FAMILY = re.compile(r'script_family\s*\(\s*"((?:[^"\\]|\\.)*)"', re.DOTALL)
OID = re.compile(r'script_oid\s*\(\s*"([^"]+)"')
CVE_CALL = re.compile(r'script_cve_id\s*\((.*?)\)', re.DOTALL)
CVE = re.compile(r'CVE-\d{4}-\d{4,}')

# The description fields the parser already learned to value. The title names a product and a
# version range; these say what the weakness allows, which is the feature that moved the
# likelihood surrogate from losing to the severity baseline to beating it.
DESC_TAGS = ("summary", "impact", "insight")


def parse(text):
    tags = {}
    for key, value in TAG.findall(text):
        if key not in tags:
            tags[key] = value.replace('\\"', '"')

    name = NAME.search(text)
    if not name:
        return None
    cves = []
    for call in CVE_CALL.findall(text):
        cves.extend(CVE.findall(call))

    family = FAMILY.search(text)
    oid = OID.search(text)
    description = " ".join(tags[t] for t in DESC_TAGS if tags.get(t))
    severity = tags.get("cvss_base", "")
    try:
        float(severity)
    except ValueError:
        severity = ""

    return {
        "source_file": "nvt-feed",
        "group": "feed",
        "scanner": "openvas",
        "host": "",
        "hostname": "",
        "port": "",
        "nvt_oid": oid.group(1) if oid else "",
        "nvt_name": one_line(name.group(1).replace('\\"', '"')),
        "nvt_family": family.group(1) if family else "",
        "threat": "",
        "severity": severity,
        "qod": "",
        "solution_type": tags.get("solution_type", ""),
        "cve_count": len(cves),
        "cves": ";".join(dict.fromkeys(cves)),
        "has_cve": bool(cves),
        "generic_nvt": False,
        "kev_cves": "",
        "has_kev": False,
        "cert_ref_count": 0,
        "description": one_line(description),
        "solution": one_line(tags.get("solution", "")),
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--plugins", required=True, metavar="DIR",
                    help="a copy of the scanner's plugin directory")
    ap.add_argument("--require-cve", action="store_true",
                    help="keep only checks that reference a CVE, which are the trainable ones")
    ap.add_argument("-o", "--out", required=True, metavar="CSV")
    args = ap.parse_args()

    if not os.path.isdir(args.plugins):
        sys.exit(f"{args.plugins} is not a directory. Copy the feed out of the container "
                 f"first:\n  docker cp <container>:/var/lib/openvas/plugins {args.plugins}")

    files = []
    for root, _, names in os.walk(args.plugins):
        files.extend(os.path.join(root, n) for n in names if n.endswith(".nasl"))
    print(f"checks found      : {len(files)}")

    rows, no_name, no_cve = [], 0, 0
    for i, path in enumerate(files, 1):
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                row = parse(fh.read())
        except OSError:
            continue
        if row is None:
            no_name += 1
            continue
        if not row["cves"]:
            no_cve += 1
            if args.require_cve:
                continue
        rows.append(row)
        if i % 20000 == 0:
            print(f"  {i}/{len(files)} read")

    with_desc = sum(1 for r in rows if r["description"].strip())
    families = len({r["nvt_family"] for r in rows})
    print(f"parsed            : {len(rows)} checks")
    print(f"  no script_name   : {no_name}, skipped")
    print(f"  no CVE reference : {no_cve}"
          f"{', skipped' if args.require_cve else ', kept'}")
    print(f"  with a description: {with_desc}")
    print(f"  distinct families : {families}")

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=CSV_FIELDS, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)
    print(f"\nwrote {args.out}")
    print(f"  the scan corpus has 8 families; this has {families}, which is the gap "
          f"leave-one-family-out\n  has been measuring.")


if __name__ == "__main__":
    main()
