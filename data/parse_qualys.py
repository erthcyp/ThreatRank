#!/usr/bin/env python3
"""Turn a Qualys VM scan XML into the same finding schema the OpenVAS/Nessus parsers emit.

The robustness experiment (risk.py per scanner) needs every scanner's findings in one
canonical shape so the identical ranking and the identical KEV grading run on each. OpenVAS
and Nessus already produce that shape; this does the same for a Qualys ``Scan Results`` XML
(``<SCAN><IP><CAT><VULN|PRACTICE|INFO|SERVICE .../></CAT></IP></SCAN>``).

Mapping, and the one honest approximation:
  * CVEs come from the ``cveid`` attribute on the finding element (comma separated), which is
    complete, rather than the frequently empty ``<CVE_ID_LIST>`` body.
  * ``severity`` is Qualys' 1-5 scale mapped to a CVSS-like 2-10 so it shares a range with the
    other scanners' CVSS. Only the *order* is used by the severity baseline, and the mapping is
    monotone, so no ranking is changed by it; it is written down because it is an assumption.
  * ``qod`` has no Qualys equivalent and is left blank. It is a feature of the likelihood
    surrogate, not of the risk.py ranking (which takes L from EPSS for CVE-bearing findings),
    so it does not affect this experiment.
  * ``kev_cves`` / ``has_kev`` are computed here from the same ``kev_catalog.json`` the other
    parsers use, so the label is identical across scanners.

Only VULN and PRACTICE carry CVEs and matter to the CVE-scoped grading; INFO/SERVICE are kept
too (they become no-CVE findings, exactly as the other scanners' informational rows do).

    python3 parse_qualys.py raw/qualys/Scan_Results_*_65501.xml --group d -o processed/findings_qualys_d.csv
"""

import argparse
import csv
import json
import os
import xml.etree.ElementTree as ET

HERE = os.path.dirname(os.path.abspath(__file__))
KEV_CACHE = os.path.join(HERE, "kev_catalog.json")

COLUMNS = ["source_file", "group", "scanner", "host", "hostname", "port", "nvt_oid",
           "nvt_name", "nvt_family", "threat", "severity", "qod", "solution_type",
           "cve_count", "cves", "has_cve", "generic_nvt", "kev_cves", "has_kev",
           "cert_ref_count", "description", "solution"]

SEV_TO_CVSS = {"1": "2.0", "2": "4.0", "3": "6.0", "4": "8.0", "5": "10.0"}
SEV_TO_THREAT = {"1": "Low", "2": "Low", "3": "Medium", "4": "High", "5": "High"}


def load_kev():
    with open(KEV_CACHE, encoding="utf-8") as fh:
        data = json.load(fh)
    cves = {v["cveID"] for v in data.get("vulnerabilities", [])}
    print(f"  KEV: {len(cves)} CVEs from {os.path.basename(KEV_CACHE)}")
    return cves


def cves_of(elem):
    raw = elem.get("cveid", "") or ""
    out = []
    for c in raw.split(","):
        c = c.strip()
        if c.upper().startswith("CVE-"):
            out.append(c.upper())
    # fallback: CVE_ID_LIST body, in case an element carries them there instead
    if not out:
        for cid in elem.iter("CVE_ID"):
            t = (cid.findtext("ID") or cid.text or "").strip()
            if t.upper().startswith("CVE-"):
                out.append(t.upper())
    # de-duplicate, keep order
    seen, uniq = set(), []
    for c in out:
        if c not in seen:
            seen.add(c)
            uniq.append(c)
    return uniq


def parse(path, group, scanner, kev):
    root = ET.parse(path).getroot()
    src = os.path.basename(path)
    rows, seen = [], set()
    for ip in root.findall("IP"):
        host = ip.get("value", "")
        hostname = ip.get("name", "") if ip.get("name", "") != "No registered hostname" else ""
        for cat in ip.iter("CAT"):
            family = cat.get("value", "")
            port = cat.get("port", "") or ""
            proto = cat.get("protocol", "tcp")
            port_field = f"{port}/{proto}" if port else "general/tcp"
            for tag in ("VULN", "PRACTICE", "INFO", "SERVICE"):
                for v in cat.findall(tag):
                    qid = v.get("number", "")
                    title = (v.findtext("TITLE") or "").strip()
                    key = (host, title)                  # same dedup rule as the other parsers
                    if key in seen:
                        continue
                    seen.add(key)
                    cves = cves_of(v)
                    kev_hits = sorted(c for c in cves if c in kev)
                    sev = v.get("severity", "")
                    diag = (v.findtext("DIAGNOSIS") or v.findtext("CONSEQUENCE") or "").strip()
                    sol = (v.findtext("SOLUTION") or "").strip()
                    rows.append({
                        "source_file": src, "group": group, "scanner": scanner,
                        "host": host, "hostname": hostname, "port": port_field,
                        "nvt_oid": f"qualys:{qid}", "nvt_name": title, "nvt_family": family,
                        # INFO and SERVICE are Qualys' informational types, with no vulnerability
                        # asserted; they are marked "Log" so the Log-excluded corpus counts treat
                        # them exactly as OpenVAS/Nessus informational rows. VULN and PRACTICE keep
                        # their severity-derived threat. CVE-scoped grading is unaffected either way.
                        "threat": "Log" if tag in ("INFO", "SERVICE")
                                  else SEV_TO_THREAT.get(sev, ""),
                        "severity": SEV_TO_CVSS.get(sev, "0.0"),
                        "qod": "", "solution_type": "",
                        "cve_count": len(cves), "cves": ";".join(cves),
                        "has_cve": bool(cves),
                        "generic_nvt": False,
                        "kev_cves": ";".join(kev_hits), "has_kev": bool(kev_hits),
                        "cert_ref_count": 0,
                        "description": diag[:2000], "solution": sol[:1000],
                    })
    return rows


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("xml", nargs="+", help="Qualys Scan Results XML file(s)")
    ap.add_argument("--group", required=True, help="corpus group label, e.g. d or b2")
    ap.add_argument("--scanner", default="qualys")
    ap.add_argument("-o", "--out", required=True)
    args = ap.parse_args()

    kev = load_kev()
    all_rows = []
    for p in args.xml:
        r = parse(p, args.group, args.scanner, kev)
        print(f"  {os.path.basename(p)}: {len(r)} findings")
        all_rows += r

    with open(args.out, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=COLUMNS)
        w.writeheader()
        w.writerows(all_rows)
    cve = sum(1 for r in all_rows if r["has_cve"])
    kevn = sum(1 for r in all_rows if r["has_kev"])
    print(f"wrote {args.out}: {len(all_rows)} findings, {cve} with a CVE, {kevn} in KEV")


if __name__ == "__main__":
    main()
