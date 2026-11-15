#!/usr/bin/env python3
"""The label cache reduced to what a classifier reads, so it fits in memory.

`nvd_bulk.json` is 259 MB and carries every field the yearly feeds publish: descriptions,
weakness lists, affected products, publication dates. Loading it as a Python dictionary
expands it several times over, and on a machine with 4 GB free that alone exhausted memory
before any model was fitted -- both training runs were killed by the system, not by an error
in them.

The classifier reads four values per CVE. Keeping those and discarding the rest turns 259 MB
into a file small enough to hold beside a feature matrix. Nothing is lost that can't be
recovered by re-running `fetch_nvd_bulk.py`, which is why that file is the one excluded from
the repository and this one is cheap to rebuild.

Rows whose only vector is CVSS v2 are dropped rather than carried: PARTIAL and COMPLETE are a
different vocabulary from LOW and HIGH, and mixing them put a three-example class into a
confusion matrix once already.

    python3 slim_labels.py --in nvd_bulk.json --out nvd_impact.json
"""

import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
KEEP = ("confidentiality", "integrity", "availability", "attackVector")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--in", dest="src", default="nvd_bulk.json", metavar="JSON")
    ap.add_argument("--out", dest="dst", default="nvd_impact.json", metavar="JSON")
    args = ap.parse_args()

    src = os.path.join(HERE, args.src)
    if not os.path.exists(src):
        sys.exit(f"{src} is missing. Build it with:\n  python3 fetch_nvd_bulk.py")

    blob = json.load(open(src, encoding="utf-8"))
    cves = blob.get("cves", blob)
    out, dropped_v2, no_impact = {}, 0, 0
    for cid, rec in cves.items():
        vector = rec.get("cvss") or {}
        version = vector.get("version", "")
        if not version.startswith(("3", "4")):
            dropped_v2 += 1
            continue
        if not vector.get("confidentiality"):
            no_impact += 1
            continue
        out[cid] = {k: vector.get(k, "") for k in KEEP}
        out[cid]["version"] = version

    dst = os.path.join(HERE, args.dst)
    with open(dst, "w", encoding="utf-8") as fh:
        json.dump(out, fh, separators=(",", ":"))
    before = os.path.getsize(src) / 1e6
    after = os.path.getsize(dst) / 1e6
    print(f"read   {len(cves)} CVEs from {args.src} ({before:.0f} MB)")
    print(f"  dropped, v2 only          {dropped_v2}")
    print(f"  dropped, no impact metrics {no_impact}")
    print(f"wrote  {len(out)} CVEs to {args.dst} ({after:.0f} MB, "
          f"{100*after/before:.0f}% of the original)")


if __name__ == "__main__":
    main()
