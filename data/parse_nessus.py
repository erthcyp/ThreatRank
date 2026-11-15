#!/usr/bin/env python3
"""
ThreatRank - Nessus .nessus report parser

Companion to parse_openvas.py. Emits the same CSV schema so findings from both
scanners can sit in one table and be compared directly.

Nessus stores findings as <ReportItem> elements under <ReportHost>, with CVE
references as repeated <cve> child elements. The severity scale is 0-4
(Info/Low/Medium/High/Critical) rather than OpenVAS's threat strings, so it is
mapped onto the same vocabulary here.

Nessus has no per-finding equivalent of OpenVAS's QoD, so that column is left
empty for Nessus rows. That asymmetry is itself worth reporting: QoD is a
report-level signal available from one scanner but not the other.

Standard library only.

Examples:
    python3 parse_nessus.py "raw/nessus/*.nessus"
    python3 parse_nessus.py "raw/nessus/*.nessus" --exclude-log --drop-generic-cves
"""

import argparse
import csv
import glob
import os
import sys
import xml.etree.ElementTree as ET

# Reuse the shared pieces so both scanners stay in step.
from parse_openvas import (CSV_FIELDS, apply_policy, infer_meta, load_kev, one_line,
                           print_summary, summarise)

# Nessus severity integer -> the threat vocabulary used by the OpenVAS parser.
SEVERITY_MAP = {
    "0": "Log",        # Info in Nessus; the same "not a vulnerability" bucket
    "1": "Low",
    "2": "Medium",
    "3": "High",
    "4": "Critical",
}


def parse_report(path, kev_cves, max_cves):
    """Extract every ReportItem from one .nessus file."""
    group, scanner = infer_meta(path)
    tree = ET.parse(path)
    root = tree.getroot()

    rows = []
    for host in root.iter("ReportHost"):
        host_ip = host.get("name", "")
        hostname = ""
        # Host-level metadata lives in <HostProperties><tag name="...">
        props = host.find("HostProperties")
        if props is not None:
            for tag in props.findall("tag"):
                if tag.get("name") in ("host-fqdn", "hostname"):
                    hostname = (tag.text or "").strip()
                    break

        for item in host.findall("ReportItem"):
            cves = [(c.text or "").strip()
                    for c in item.findall("cve") if c.text]
            kev_hits = sorted(c for c in cves if c in kev_cves)

            sev = item.get("severity", "0")
            cvss = (item.findtext("cvss3_base_score")
                    or item.findtext("cvss_base_score") or "0.0")

            # Nessus splits CERT-style references across several elements.
            cert_refs = sum(len(item.findall(t))
                            for t in ("cert", "cert-bund", "dfn-cert", "iava", "iavb"))

            rows.append({
                "source_file": os.path.basename(path),
                "group": group,
                "scanner": scanner,
                "host": host_ip,
                "hostname": hostname,
                "port": f"{item.get('port', '0')}/{item.get('protocol', 'tcp')}",
                "nvt_oid": item.get("pluginID", ""),
                "nvt_name": item.get("pluginName", ""),
                "nvt_family": item.get("pluginFamily", ""),
                "threat": SEVERITY_MAP.get(sev, "Log"),
                "severity": cvss,
                "qod": "",            # Nessus exposes no QoD equivalent
                "solution_type": "",  # nor a solution-type taxonomy
                "cve_count": len(cves),
                "cves": ";".join(cves),
                "has_cve": bool(cves),
                "generic_nvt": len(cves) > max_cves,
                "kev_cves": ";".join(kev_hits),
                "has_kev": bool(kev_hits),
                "cert_ref_count": cert_refs,
                # Nessus splits what Greenbone writes as one description across a synopsis
                # and a longer description. Both are kept, synopsis first, because the
                # synopsis is the sentence that names what the weakness allows and the
                # models read this field for exactly that.
                "description": one_line(" ".join(
                    t for t in (item.findtext("synopsis"),
                                item.findtext("description")) if t)),
                "solution": one_line(item.findtext("solution") or ""),
            })
    return rows


def main():
    ap = argparse.ArgumentParser(
        description="Convert Nessus .nessus reports to the shared CSV schema")
    ap.add_argument("files", nargs="+", help=".nessus files (globs accepted)")
    ap.add_argument("-o", "--out", required=True,
                    help="output CSV. Required, and name the host or group in it "
                         "(e.g. processed/findings_nessus_a.csv). See Defect A in scans.md")
    ap.add_argument("--exclude-log", action="store_true",
                    help="drop Info/Log-level findings")
    ap.add_argument("--min-qod", type=float, default=0,
                    help="accepted for symmetry; Nessus rows carry no QoD")
    ap.add_argument("--max-cves", type=int, default=3,
                    help="more than N CVEs on one finding marks a generic plugin")
    ap.add_argument("--drop-generic-cves", action="store_true",
                    help="ignore CVEs from generic plugins")
    ap.add_argument("--offline", action="store_true",
                    help="do not fetch the KEV catalog; use cache only")
    args = ap.parse_args()

    paths = sorted({p for pat in args.files for p in glob.glob(pat)})
    if not paths:
        sys.exit("no files matched")

    print(f"{len(paths)} file(s) found")
    kev = load_kev(offline=args.offline)

    raw = []
    for p in paths:
        found = parse_report(p, kev, args.max_cves)
        print(f"  {os.path.basename(p)}: {len(found)} findings")
        raw.extend(found)

    rows = apply_policy(raw, args.exclude_log, args.min_qod, args.drop_generic_cves)
    print_summary(summarise(rows, "Nessus"))

    out = args.out
    if not os.path.isabs(out):
        out = os.path.join(os.path.dirname(os.path.abspath(__file__)), out)
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=CSV_FIELDS)
        w.writeheader()
        w.writerows(rows)
    print(f"\nCSV written: {out}  ({len(rows)} rows)")


if __name__ == "__main__":
    main()
